// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Reconciling a swap-relevant read made on two DIVI endpoints (`[divi].fallback_rpc_url`).
//!
//! Rule (docs/plans/swap-poc/single-source-design.md, DIVI): two endpoints that disagree on a
//! read are never a decision. The answer is `SwapError::Transient`, which the engine retries.
//! Where the two agree the combined answer is the more conservative of the two, so a single
//! liar can lower a number but never raise one.

use divi_swap::{LockedOutput, SpendInfo, SwapError};
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
        "DIVI endpoints disagree, treating the read as transient: {detail}"
    );
    SwapError::Transient(format!("{op}: DIVI endpoints disagree: {detail}"))
}

/// Join the two endpoints' results. Both answered: their answers. Exactly one failed: the read
/// is `Transient` (one view is not enough). Both failed: the primary's error, unchanged.
pub(crate) fn pair<T>(op: &str, primary: Result<T>, fallback: Result<T>) -> Result<(T, T)> {
    match (primary, fallback) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(e), Err(f)) => {
            tracing::warn!(op, "fallback endpoint also failed: {f}");
            Err(e)
        }
        (Err(e), Ok(_)) => Err(disagree(op, format!("primary endpoint failed: {e}"))),
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
