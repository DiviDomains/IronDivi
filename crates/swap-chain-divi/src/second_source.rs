// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Reconciling a swap-relevant read made on two DIVI endpoints (`[divi].fallback_rpc_url`).
//!
//! Rule (docs/plans/swap-poc/single-source-design.md, DIVI): two endpoints that disagree on a
//! read are never a decision. The answer is `SwapError::Held`, which the engine retries like
//! `Transient` and, in front of a refund, reads on the primary alone once the refund's deadline
//! passes (`divi_swap` `hold.rs`, EV); a fallback that fails is the same hold, a primary that
//! fails stays `Transient`.
//! Where the two agree the combined answer is the more conservative of the two, so a single
//! liar can lower a number but never raise one.

use divi_swap::backend::TipHeader;
use divi_swap::{LockedOutput, SpendInfo, SpendScan, SwapError};
use serde_json::Value;

type Result<T> = std::result::Result<T, SwapError>;

/// Confirmation counts that differ by more than this are a disagreement. One block of
/// difference is ordinary tip lag between two nodes; the lower count is used.
pub const CONFIRMATION_TOLERANCE: u32 = 1;

/// Median-time-past values that differ by more than this many seconds are a disagreement.
/// Ten minutes is ten DIVI blocks: far wider than tip lag, far narrower than a lie that moves
/// a timelock decision. The lower value is used.
pub const MTP_TOLERANCE_SECS: u32 = 600;

/// Tip heights that differ by more than this many blocks are a disagreement. Two endpoints
/// behind different proxies are routinely one block apart (a block lands between the two
/// reads), and two blocks apart is still lag. The lower height is used, so a lag or a lie can
/// only move the answer down: the one decision that reads the tip (where the maker starts
/// looking for the taker's claim) is safe at a lower height, never at a higher one.
pub const TIP_TOLERANCE_BLOCKS: u64 = 2;

fn disagree(op: &str, detail: String) -> SwapError {
    tracing::warn!(
        op,
        "DIVI endpoints disagree, holding the read for the second source: {detail}"
    );
    SwapError::Held(format!("{op}: DIVI endpoints disagree: {detail}"))
}

/// Join the two endpoints' results. Both answered: their answers. The fallback failed: the
/// read is held (`Held`; one view is not enough). The primary failed: `Transient` (the
/// primary alone has no answer either). Both failed: the primary's error, unchanged.
pub(crate) fn pair<T>(op: &str, primary: Result<T>, fallback: Result<T>) -> Result<(T, T)> {
    match (primary, fallback) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(e), Err(f)) => {
            tracing::warn!(op, "fallback endpoint also failed: {f}");
            Err(e)
        }
        (Err(e), Ok(_)) => {
            tracing::warn!(op, "primary DIVI endpoint failed, fallback answered: {e}");
            Err(SwapError::Transient(format!(
                "{op}: DIVI endpoints disagree: primary endpoint failed: {e}"
            )))
        }
        (Ok(_), Err(e)) => Err(disagree(op, format!("fallback endpoint failed: {e}"))),
    }
}

fn agree_count(op: &str, a: u32, b: u32) -> Result<u32> {
    if a.abs_diff(b) > CONFIRMATION_TOLERANCE {
        return Err(disagree(op, format!("confirmations {a} vs {b}")));
    }
    Ok(a.min(b))
}

pub(crate) fn agree_confirmations(a: Option<u32>, b: Option<u32>) -> Result<Option<u32>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) => agree_count("confirmations", a, b).map(Some),
        (a, b) => Err(disagree(
            "confirmations",
            format!("transaction known to one endpoint only ({a:?} vs {b:?})"),
        )),
    }
}

pub(crate) fn agree_htlc_output(
    a: Option<LockedOutput>,
    b: Option<LockedOutput>,
) -> Result<Option<LockedOutput>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) => {
            if a.amount != b.amount {
                return Err(disagree(
                    "htlc_output",
                    format!("amount {} vs {}", a.amount, b.amount),
                ));
            }
            Ok(Some(LockedOutput {
                amount: a.amount,
                confirmations: agree_count("htlc_output", a.confirmations, b.confirmations)?,
            }))
        }
        (a, b) => Err(disagree(
            "htlc_output",
            format!(
                "output seen by one endpoint only (primary {}, fallback {})",
                a.is_some(),
                b.is_some()
            ),
        )),
    }
}

pub(crate) fn agree_spend(a: Option<SpendInfo>, b: Option<SpendInfo>) -> Result<Option<SpendInfo>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) => {
            if a.txid != b.txid || a.input_index != b.input_index || a.script_sig != b.script_sig {
                return Err(disagree(
                    "find_spend",
                    format!("spend {} vs {}", a.txid, b.txid),
                ));
            }
            // Same spend. One endpoint may still see it in the mempool while the other has it
            // in a block; report the block, which is the stronger fact.
            Ok(Some(if a.height.is_some() { a } else { b }))
        }
        (a, b) => Err(disagree(
            "find_spend",
            format!(
                "spend seen by one endpoint only (primary {}, fallback {})",
                a.is_some(),
                b.is_some()
            ),
        )),
    }
}

/// One endpoint's answer to one spend-scan pass, with every block that pass verified.
///
/// `blocks` holds `(height, hash)` for the mark the pass resumed at (when it starts at the
/// mark) and for each block it read, in order. Each block named the one before it as its
/// parent, so the list is one branch. It is empty for a reorg or a spend, which
/// [`agree_scan`] joins without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointScan {
    pub(crate) scan: SpendScan,
    pub(crate) blocks: Vec<(u64, String)>,
}

/// Join the two endpoints' answers to one spend-scan pass (P7), both read from the same start
/// and the same mark.
///
/// - A reorg under the mark on either side voids it for both: [`SpendScan::Reorged`].
/// - A spend on either side is joined as [`agree_spend`] joins it (seen by one only: held).
/// - Neither saw a spend and both stopped at one block: that mark, `complete` only if both
///   reached their tip. Two different blocks at one height are a disagreement (held).
/// - Both stopped at different heights (one endpoint's tip is behind the other's, so that
///   pass reached its tip early). Heights further apart than [`TIP_TOLERANCE_BLOCKS`] are a
///   tip disagreement (held), as for [`agree_tip_height`]. Within it, the endpoint that read
///   higher must have verified, in this same pass, the very block the lower one stopped at:
///   - The same block there: the lower mark, never `complete`, so no no-spend decision is
///     taken until both name the same last block.
///   - Another block there: the two read different branches. That is a disagreement (held),
///     and no mark is saved.
///   - That height not among the blocks it verified: `Transient`, and no mark is saved.
///
/// The check is what makes the lower mark safe to save. Both passes started at the same
/// height (or the same mark), and every block in each pass named the block before it as its
/// parent. A block hash commits to its parent's hash (SHA-256), so one hash at the lower
/// height means both endpoints read the same blocks from the start through that height. So
/// whichever endpoint is honest read every transaction in every block under the saved mark.
/// The next pass resumes there and checks only the mark's hash, which is then enough. That
/// holds even if the honest endpoint was on a short-lived fork during this pass and has since
/// moved back to the branch the other endpoint named. It costs no extra RPC: the hashes are
/// the ones each pass already read.
///
/// Without the check a liar could hide a claim. Say a lying endpoint names the real chain to
/// height `h` but leaves the claim out of a block, while the honest endpoint is briefly on a
/// fork to `h + 1`. Their marks would join at the liar's `(h, hash)`. Once the honest
/// endpoint returns to the real chain, its block at `h` matches the mark, so the next pass
/// would never read the forked-over blocks again.
pub(crate) fn agree_scan(a: EndpointScan, b: EndpointScan) -> Result<SpendScan> {
    match (a.scan, b.scan) {
        (SpendScan::Reorged, _) | (_, SpendScan::Reorged) => Ok(SpendScan::Reorged),
        (
            SpendScan::NotYet {
                through: Some(x),
                complete: ca,
            },
            SpendScan::NotYet {
                through: Some(y),
                complete: cb,
            },
        ) => {
            if x.height == y.height {
                if x.hash != y.hash {
                    return Err(disagree(
                        "find_spend",
                        format!(
                            "two blocks at height {}: {} and {}",
                            x.height, x.hash, y.hash
                        ),
                    ));
                }
                return Ok(SpendScan::NotYet {
                    through: Some(x),
                    complete: ca && cb,
                });
            }
            if x.height.abs_diff(y.height) > TIP_TOLERANCE_BLOCKS {
                return Err(disagree(
                    "find_spend",
                    format!("scans ended at heights {} vs {}", x.height, y.height),
                ));
            }
            let (low, high_blocks) = if x.height < y.height {
                (x, &b.blocks)
            } else {
                (y, &a.blocks)
            };
            let Some((_, high_hash)) = high_blocks.iter().find(|(h, _)| *h == low.height) else {
                return Err(SwapError::Transient(
                    "find_spend: lower mark height missing from higher scan pass".into(),
                ));
            };
            if *high_hash != low.hash {
                return Err(disagree(
                    "find_spend",
                    format!(
                        "two blocks at height {}: {} and {high_hash}",
                        low.height, low.hash
                    ),
                ));
            }
            Ok(SpendScan::NotYet {
                through: Some(low),
                complete: false,
            })
        }
        // A DIVI pass always names the last block it read.
        (SpendScan::NotYet { through: None, .. }, SpendScan::NotYet { .. })
        | (SpendScan::NotYet { .. }, SpendScan::NotYet { through: None, .. }) => Err(
            SwapError::Transient("find_spend: a spend scan named no block".into()),
        ),
        (a, b) => Ok(match agree_spend(a.into_spend(), b.into_spend())? {
            Some(s) => SpendScan::Spent(s),
            // Unreachable: at least one side is a spend, and one-sided spends are held.
            None => SpendScan::NotYet {
                through: None,
                complete: false,
            },
        }),
    }
}

pub(crate) fn agree_mtp(a: u32, b: u32) -> Result<u32> {
    if a.abs_diff(b) > MTP_TOLERANCE_SECS {
        return Err(disagree("median_time_past", format!("{a} vs {b}")));
    }
    Ok(a.min(b))
}

pub(crate) fn agree_tip_height(a: u64, b: u64) -> Result<u64> {
    if a.abs_diff(b) > TIP_TOLERANCE_BLOCKS {
        return Err(disagree("tip_height", format!("{a} vs {b}")));
    }
    Ok(a.min(b))
}

/// Two endpoints on different tips name different hashes without either lying, so a difference
/// is reported as a disagreement and retried; a tip that is stable for a moment agrees.
pub(crate) fn agree_tip_hash(a: String, b: String) -> Result<String> {
    if a != b {
        return Err(disagree("tip_hash", format!("{a} vs {b}")));
    }
    Ok(a)
}

/// The best block, as two endpoints name it: the same block or a disagreement (retried, as
/// for [`agree_tip_hash`]).
pub(crate) fn agree_tip_header(a: TipHeader, b: TipHeader) -> Result<TipHeader> {
    if a != b {
        return Err(disagree(
            "tip_header",
            format!("{} at {} vs {} at {}", a.hash, a.height, b.hash, b.height),
        ));
    }
    Ok(a)
}

/// Whether a block is on the main chain, as two endpoints answer: the same or a disagreement.
pub(crate) fn agree_in_best_chain(a: bool, b: bool) -> Result<bool> {
    if a != b {
        return Err(disagree("in_best_chain", format!("{a} vs {b}")));
    }
    Ok(a)
}

/// The transactions in one block, as two endpoints list them: identical or a disagreement.
pub(crate) fn agree_block_txids(a: Vec<String>, b: Vec<String>) -> Result<Vec<String>> {
    if a != b {
        return Err(disagree(
            "block_txids",
            format!("{} vs {} transactions", a.len(), b.len()),
        ));
    }
    Ok(a)
}

/// What the wallet learns from a transaction: its id, the outpoints it spends and its outputs
/// (index, script, value). Fields the wallet never reads (confirmations, size) may differ.
type WalletView = (
    Option<String>,
    Vec<(String, u64)>,
    Vec<(u64, String, Option<u64>)>,
);

fn wallet_view(tx: &Value) -> WalletView {
    let txid = tx["txid"].as_str().map(String::from);
    let vin = tx["vin"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| Some((i["txid"].as_str()?.to_string(), i["vout"].as_u64()?)))
        .collect();
    let vout = tx["vout"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|o| {
            let value = o["valueSat"]
                .as_u64()
                .or_else(|| o["value"].as_f64().map(|v| (v * 1e8).round() as u64));
            (
                o["n"].as_u64().unwrap_or(0),
                o["scriptPubKey"]["hex"].as_str().unwrap_or("").to_string(),
                value,
            )
        })
        .collect();
    (txid, vin, vout)
}

/// A transaction the wallet will learn coins and spends from: the two views must be identical.
pub(crate) fn agree_wallet_tx(a: Value, b: Value) -> Result<Value> {
    if wallet_view(&a) != wallet_view(&b) {
        let id = a["txid"].as_str().unwrap_or("?").to_string();
        return Err(disagree("wallet_tx", format!("transaction {id} differs")));
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_swap::{ScanMark, Txid};

    fn at(height: u64, branch: u8) -> ScanMark {
        ScanMark {
            height,
            hash: format!("{branch:02x}{height:062x}"),
        }
    }

    /// One endpoint's pass: `scan`, having verified the blocks of `branch` at `heights`.
    fn pass(scan: SpendScan, branch: u8, heights: std::ops::RangeInclusive<u64>) -> EndpointScan {
        EndpointScan {
            scan,
            blocks: heights.map(|h| (h, at(h, branch).hash)).collect(),
        }
    }

    /// A pass that read `from..=m.height` on `m`'s branch and stopped at `m`.
    fn not_yet_from(from: u64, m: ScanMark, complete: bool) -> EndpointScan {
        let branch = u8::from_str_radix(&m.hash[..2], 16).unwrap();
        let end = m.height;
        pass(
            SpendScan::NotYet {
                through: Some(m),
                complete,
            },
            branch,
            from..=end,
        )
    }

    fn not_yet(m: ScanMark, complete: bool) -> EndpointScan {
        not_yet_from(5, m, complete)
    }

    fn bare(scan: SpendScan) -> EndpointScan {
        EndpointScan {
            scan,
            blocks: Vec::new(),
        }
    }

    fn spent(height: Option<u64>, script: u8) -> EndpointScan {
        bare(SpendScan::Spent(SpendInfo {
            txid: Txid([5; 32]),
            input_index: 0,
            height,
            script_sig: vec![script],
            witness: vec![],
        }))
    }

    fn held(r: &Result<SpendScan>) -> bool {
        matches!(r, Err(SwapError::Held(m)) if m.contains("disagree"))
    }

    fn joined(m: ScanMark, complete: bool) -> SpendScan {
        SpendScan::NotYet {
            through: Some(m),
            complete,
        }
    }

    #[test]
    fn one_scan_pass_on_two_endpoints_is_joined_conservatively() {
        // The same last block: that mark, complete only if both reached their tip.
        for (ca, cb) in [(true, true), (true, false), (false, true), (false, false)] {
            assert_eq!(
                agree_scan(not_yet(at(9, 0), ca), not_yet(at(9, 0), cb)).unwrap(),
                joined(at(9, 0), ca && cb)
            );
        }
        // One endpoint behind on the same branch: the lower mark, never complete, whichever
        // side is lower.
        for behind in 1..=TIP_TOLERANCE_BLOCKS {
            let hi = at(9 + behind, 0);
            assert_eq!(
                agree_scan(not_yet(at(9, 0), true), not_yet(hi.clone(), true)).unwrap(),
                joined(at(9, 0), false)
            );
            assert_eq!(
                agree_scan(not_yet(hi, true), not_yet(at(9, 0), true)).unwrap(),
                joined(at(9, 0), false)
            );
        }
        // Further apart than the tip tolerance, or two blocks at one height: held.
        assert!(held(&agree_scan(
            not_yet(at(9, 0), true),
            not_yet(at(9 + TIP_TOLERANCE_BLOCKS + 1, 0), true)
        )));
        assert!(held(&agree_scan(
            not_yet(at(9, 0), true),
            not_yet(at(9, 1), true)
        )));
        // A reorg on either side voids the mark for both, whatever the other saw.
        for other in [
            not_yet(at(9, 0), true),
            spent(Some(9), 1),
            bare(SpendScan::Reorged),
        ] {
            assert_eq!(
                agree_scan(bare(SpendScan::Reorged), other.clone()).unwrap(),
                SpendScan::Reorged
            );
            assert_eq!(
                agree_scan(other, bare(SpendScan::Reorged)).unwrap(),
                SpendScan::Reorged
            );
        }
        // A spend on one side only, or two different spends: held. The same spend: the block.
        assert!(held(&agree_scan(
            spent(Some(9), 1),
            not_yet(at(9, 0), true)
        )));
        assert!(held(&agree_scan(not_yet(at(9, 0), false), spent(None, 1))));
        assert!(held(&agree_scan(spent(Some(9), 1), spent(Some(9), 2))));
        assert_eq!(
            agree_scan(spent(None, 1), spent(Some(9), 1)).unwrap(),
            SpendScan::Spent(SpendInfo {
                txid: Txid([5; 32]),
                input_index: 0,
                height: Some(9),
                script_sig: vec![1],
                witness: vec![],
            })
        );
        // A pass that names no block is not evidence.
        let none = bare(SpendScan::NotYet {
            through: None,
            complete: true,
        });
        assert!(matches!(
            agree_scan(none.clone(), not_yet(at(9, 0), true)),
            Err(SwapError::Transient(_))
        ));
        assert!(matches!(
            agree_scan(not_yet(at(9, 0), true), none),
            Err(SwapError::Transient(_))
        ));
    }

    /// F1: marks within the tip tolerance join at the lower one only when the endpoint that
    /// read higher verified that very block in the same pass; another block there (it read
    /// another branch) is held, and a height it did not verify is `Transient`. Both orders.
    #[test]
    fn a_lower_mark_joins_only_if_the_higher_pass_read_the_same_block_there() {
        type Join = fn(EndpointScan, EndpointScan) -> Result<SpendScan>;
        let orders: [(&str, Join); 2] = [
            ("low first", |lo, hi| agree_scan(lo, hi)),
            ("high first", |lo, hi| agree_scan(hi, lo)),
        ];
        for (order, join) in orders {
            for apart in 1..=TIP_TOLERANCE_BLOCKS {
                let (low, high) = (150, 150 + apart);
                // The higher pass read the same branch through the lower mark.
                assert_eq!(
                    join(
                        not_yet_from(100, at(low, 0), true),
                        not_yet_from(100, at(high, 0), true)
                    )
                    .unwrap(),
                    joined(at(low, 0), false),
                    "{order}, {apart} apart, same branch"
                );
                // It also joins when the higher pass forked off just above the lower mark.
                let mut above = not_yet_from(100, at(high, 1), true);
                above.blocks[(low - 100) as usize] = (low, at(low, 0).hash);
                assert_eq!(
                    join(not_yet_from(100, at(low, 0), true), above).unwrap(),
                    joined(at(low, 0), false),
                    "{order}, {apart} apart, fork above the lower mark"
                );
                // The higher pass read another block at the lower height: held, for a fork at
                // that height or any height below it in the pass.
                for fork in [low - 1, low] {
                    let mut forked = not_yet_from(100, at(high, 1), true);
                    for (h, hash) in forked.blocks.iter_mut() {
                        if *h < fork {
                            *hash = at(*h, 0).hash;
                        }
                    }
                    let r = join(not_yet_from(100, at(low, 0), true), forked);
                    assert!(held(&r), "{order}, {apart} apart, fork at {fork}: {r:?}");
                }
                // The lower height is not among the blocks the higher pass verified.
                let mut short = not_yet_from(100, at(high, 0), true);
                short.blocks.retain(|(h, _)| *h != low);
                assert!(
                    matches!(
                        join(not_yet_from(100, at(low, 0), true), short),
                        Err(SwapError::Transient(ref m)) if m.contains("missing")
                    ),
                    "{order}, {apart} apart, missing"
                );
                let empty = bare(SpendScan::NotYet {
                    through: Some(at(high, 0)),
                    complete: true,
                });
                assert!(
                    matches!(
                        join(not_yet_from(100, at(low, 0), true), empty),
                        Err(SwapError::Transient(_))
                    ),
                    "{order}, {apart} apart, no blocks"
                );
            }
            // A resumed pass verified the mark it resumed at: an endpoint that read no new
            // block still joins one that read one more.
            let resumed_low = pass(joined(at(150, 0), true), 0, 150..=150);
            let resumed_high = pass(joined(at(151, 0), true), 0, 150..=151);
            assert_eq!(
                join(resumed_low, resumed_high).unwrap(),
                joined(at(150, 0), false),
                "{order}, resumed"
            );
        }
    }
}
