// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Reconciling a claim- or refund-relevant read made on the primary and the secondary Esplora
//! (`[btc].quorum_reads`).
//!
//! Rule (docs/plans/swap-poc/single-source-design.md section 5, BTC; the same as DIVI's
//! `second_source`): two endpoints that disagree on a read are never a decision. The answer is
//! `SwapError::Held`, which the engine retries like `Transient` and, in front of a refund,
//! reads on the primary alone once the refund's deadline passes (`divi_swap` `hold.rs`, EV);
//! a secondary that fails is the same hold, a primary that fails stays `Transient`. Where the two agree on what exists, a
//! confirmation count is the lower of the two, so a single liar can lower a count but never
//! raise one; endpoints a block apart are ordinary lag, not a disagreement. The tip reads
//! follow the same rule: the lower tip height and median time, the header of the lower tip
//! once the other endpoint names the same block at that height, and a block status both
//! endpoints give. Funding reads (EO): only the wallet coins both endpoints list.

use divi_swap::backend::TipHeader;
use divi_swap::{LockedOutput, SpendInfo, SpendScan, SwapError};

use crate::tx::Coin;

type Result<T> = std::result::Result<T, SwapError>;

pub(crate) fn disagree(op: &str, detail: String) -> SwapError {
    tracing::warn!(
        op,
        "Esplora endpoints disagree, holding the read for the second source: {detail}"
    );
    SwapError::Held(format!("{op}: Esplora endpoints disagree: {detail}"))
}

/// Join the two endpoints' results. Both answered: their answers. The secondary failed: the
/// read is held (`Held`; one view is not enough, quorum mode fails closed). The primary
/// failed: `Transient` (the primary alone has no answer either). Both failed: the primary's
/// error, unchanged.
pub(crate) fn pair<T>(op: &str, primary: Result<T>, secondary: Result<T>) -> Result<(T, T)> {
    match (primary, secondary) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(e), Err(f)) => {
            tracing::warn!(op, "secondary Esplora also failed: {f}");
            Err(e)
        }
        (Err(e), Ok(_)) => {
            tracing::warn!(op, "primary Esplora failed, secondary answered: {e}");
            Err(SwapError::Transient(format!(
                "{op}: Esplora endpoints disagree: primary failed: {e}"
            )))
        }
        (Ok(_), Err(e)) => Err(disagree(op, format!("secondary failed: {e}"))),
    }
}

pub(crate) fn agree_confirmations(a: Option<u32>, b: Option<u32>) -> Result<Option<u32>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) => Ok(Some(a.min(b))),
        (a, b) => Err(disagree(
            "confirmations",
            format!("transaction known to one endpoint only (primary {a:?}, secondary {b:?})"),
        )),
    }
}

fn describe_output(o: &Option<LockedOutput>) -> String {
    match o {
        Some(o) => format!("{} sat", o.amount.to_sat()),
        None => "no such HTLC output".into(),
    }
}

pub(crate) fn agree_htlc_output(
    a: Option<LockedOutput>,
    b: Option<LockedOutput>,
) -> Result<Option<LockedOutput>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(x), Some(y)) if x.amount == y.amount => Ok(Some(LockedOutput {
            amount: x.amount,
            confirmations: x.confirmations.min(y.confirmations),
        })),
        (a, b) => Err(disagree(
            "htlc_output",
            format!(
                "primary {}, secondary {}",
                describe_output(&a),
                describe_output(&b)
            ),
        )),
    }
}

fn describe_spend(s: &Option<SpendInfo>) -> String {
    match s {
        Some(s) => format!("spent by {} input {}", s.txid, s.input_index),
        None => "unspent".into(),
    }
}

pub(crate) fn agree_spend(a: Option<SpendInfo>, b: Option<SpendInfo>) -> Result<Option<SpendInfo>> {
    match (a, b) {
        (None, None) => Ok(None),
        (Some(x), Some(y))
            if x.txid == y.txid
                && x.input_index == y.input_index
                && x.script_sig == y.script_sig
                && x.witness == y.witness =>
        {
            // Same spend. One endpoint may still see it in the mempool while the other has it
            // in a block; report the block, which is the stronger fact.
            Ok(Some(if x.height.is_some() { x } else { y }))
        }
        (Some(x), Some(y)) if x.txid == y.txid => Err(disagree(
            "find_spend",
            format!(
                "both spent by {}, but input or witness differs (primary {}, secondary {})",
                x.txid,
                describe_spend(&Some(x.clone())),
                describe_spend(&Some(y))
            ),
        )),
        (a, b) => Err(disagree(
            "find_spend",
            format!(
                "primary {}, secondary {}",
                describe_spend(&a),
                describe_spend(&b)
            ),
        )),
    }
}

/// How one endpoint produced its spend-scan answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanSource {
    /// `/tx/:txid/outspend/:vout` index answer, or a reorg / spend that needs no block list.
    Indexed,
    /// `scan_blocks` saw `tip < from_height` and read zero blocks at or above `from_height`.
    BelowStart { tip: u64 },
    /// `scan_blocks` read `blocks` (`from_height..=last`) in parent-linked order.
    Blocks(Vec<(u64, String)>),
}

/// One endpoint's answer to one spend-scan pass, tagged with how it was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointScan {
    pub(crate) scan: SpendScan,
    pub(crate) source: ScanSource,
}

impl EndpointScan {
    /// An `/outspend` index answer, a reorg, or a spend.
    pub(crate) fn bare(scan: SpendScan) -> Self {
        EndpointScan {
            scan,
            source: ScanSource::Indexed,
        }
    }

    /// `scan_blocks` when the endpoint's tip has not yet reached `from_height`.
    pub(crate) fn below_start(tip: u64) -> Self {
        EndpointScan {
            scan: SpendScan::NotYet {
                through: None,
                complete: true,
            },
            source: ScanSource::BelowStart { tip },
        }
    }

    /// `scan_blocks` with every `(height, hash)` read in full, in parent-linked order.
    pub(crate) fn blocks(scan: SpendScan, blocks: Vec<(u64, String)>) -> Self {
        EndpointScan {
            scan,
            source: ScanSource::Blocks(blocks),
        }
    }
}

/// Join two endpoints' answers to one spend-scan pass (H2). A spend on either side is joined
/// as [`agree_spend`] joins it. A reorg seen by either side voids the mark for both. Without
/// either, the pass reaches only as far as both read:
///
/// - Both block scans saw `tip < from_height` (`BelowStart`): neither reached `from_height`,
///   no mark is saved. If only one side is `BelowStart`, the endpoints disagree on whether the
///   chain has reached `from_height` and the read is held (`SwapError::Held`), never mistaken
///   for an `/outspend` index answer covering the other endpoint's blocks.
/// - An `/outspend` index answer (`Indexed`, no mark, `complete`) covers whatever the other
///   side read: its mark.
/// - Both block scans stopped at one height: that mark. Two different blocks there are a
///   disagreement (held), so `hold::scan_spend` can fall back to the primary alone at the
///   refund deadline instead of the read staying pending.
/// - The block scans stopped at different heights: the lower mark, but only if the endpoint
///   that read higher read that very block in this same pass. Another block there (it read
///   another branch) is held; the height not among its blocks is `Transient`. No mark is
///   saved in either case.
///
/// Both passes start at the same height, and each block read names the block before it as
/// its parent, which its hash commits to. So one hash at the lower height means both
/// endpoints read the same blocks from the start through it, and an honest endpoint read
/// every transaction under the saved mark.
pub(crate) fn agree_scan(a: EndpointScan, b: EndpointScan) -> Result<SpendScan> {
    let EndpointScan {
        scan: sa,
        source: src_a,
    } = a;
    let EndpointScan {
        scan: sb,
        source: src_b,
    } = b;
    match (sa, sb) {
        (SpendScan::Reorged, _) | (_, SpendScan::Reorged) => Ok(SpendScan::Reorged),
        (
            SpendScan::NotYet {
                through: ta,
                complete: ca,
            },
            SpendScan::NotYet {
                through: tb,
                complete: cb,
            },
        ) => match (src_a, src_b) {
            (ScanSource::BelowStart { .. }, ScanSource::BelowStart { .. }) => {
                if ta.is_some() || tb.is_some() {
                    return Err(SwapError::Transient(
                        "find_spend: below-start scan named a block".into(),
                    ));
                }
                Ok(SpendScan::NotYet {
                    through: None,
                    complete: ca && cb,
                })
            }
            (ScanSource::BelowStart { tip }, _) | (_, ScanSource::BelowStart { tip }) => {
                Err(disagree(
                    "find_spend",
                    format!("one endpoint is at tip {tip}, below scan start"),
                ))
            }
            (ScanSource::Indexed, ScanSource::Indexed) => {
                if ta.is_some() || tb.is_some() {
                    return Err(SwapError::Transient(
                        "find_spend: indexed scan named a block".into(),
                    ));
                }
                Ok(SpendScan::NotYet {
                    through: None,
                    complete: ca && cb,
                })
            }
            (ScanSource::Indexed, ScanSource::Blocks(_)) => {
                let (None, Some(y)) = (ta, tb) else {
                    return Err(SwapError::Transient(
                        "find_spend: inconsistent indexed and block-scan marks".into(),
                    ));
                };
                Ok(SpendScan::NotYet {
                    through: ca.then_some(y),
                    complete: ca && cb,
                })
            }
            (ScanSource::Blocks(_), ScanSource::Indexed) => {
                let (Some(x), None) = (ta, tb) else {
                    return Err(SwapError::Transient(
                        "find_spend: inconsistent block-scan and indexed marks".into(),
                    ));
                };
                Ok(SpendScan::NotYet {
                    through: cb.then_some(x),
                    complete: ca && cb,
                })
            }
            (ScanSource::Blocks(ba), ScanSource::Blocks(bb)) => {
                let (Some(x), Some(y)) = (ta, tb) else {
                    return Err(SwapError::Transient(
                        "find_spend: block scan named no block".into(),
                    ));
                };
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
                let (low, high_blocks) = if x.height < y.height {
                    (x, &bb)
                } else {
                    (y, &ba)
                };
                let Some((_, high_hash)) = high_blocks.iter().find(|(h, _)| *h == low.height)
                else {
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
        },
        (a, b) => Ok(match agree_spend(a.into_spend(), b.into_spend())? {
            Some(s) => SpendScan::Spent(s),
            None => SpendScan::NotYet {
                through: None,
                complete: false,
            },
        }),
    }
}

/// `low` is the lower endpoint's tip; `ahead_hash` is the other endpoint's block at that
/// height (its own tip when both are at one height). Two blocks at one height are `Transient`.
pub(crate) fn agree_block_at(low: TipHeader, ahead_hash: String) -> Result<TipHeader> {
    if ahead_hash == low.hash {
        Ok(low)
    } else {
        Err(disagree(
            "tip_header",
            format!(
                "two blocks at height {}: {} and {ahead_hash}",
                low.height, low.hash
            ),
        ))
    }
}

pub(crate) fn agree_in_best_chain(hash: &str, a: bool, b: bool) -> Result<bool> {
    if a == b {
        Ok(a)
    } else {
        Err(disagree(
            "in_best_chain",
            format!("block {hash}: primary in_best_chain {a}, secondary {b}"),
        ))
    }
}

/// The coins both endpoints list for the wallet: same outpoint and value, confirmed only if
/// both say so. A coin one endpoint lists and the other does not (spent, unknown, or at
/// another value) is left out of funding and the balance, not an error: the wallet funds from
/// what both agree on, and finds itself short rather than spending a coin that may not exist.
pub(crate) fn agree_coins(a: Vec<Coin>, b: Vec<Coin>) -> Vec<Coin> {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for x in &a {
        match b
            .iter()
            .find(|y| y.outpoint == x.outpoint && y.value == x.value)
        {
            Some(y) => kept.push(Coin {
                confirmed: x.confirmed && y.confirmed,
                ..*x
            }),
            None => dropped.push(format!("{} ({} sat) primary only", x.outpoint, x.value)),
        }
    }
    for y in &b {
        if !kept
            .iter()
            .any(|k| k.outpoint == y.outpoint && k.value == y.value)
        {
            dropped.push(format!("{} ({} sat) secondary only", y.outpoint, y.value));
        }
    }
    if !dropped.is_empty() {
        tracing::warn!(
            "Esplora endpoints list different wallet coins, funding without them: {}",
            dropped.join(", ")
        );
    }
    kept
}
