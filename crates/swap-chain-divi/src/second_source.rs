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

type Result<T> = std::result::Result<T, SwapError>;

/// Confirmation counts that differ by more than this are a disagreement. One block of
/// difference is ordinary tip lag between two nodes; the lower count is used.
pub const CONFIRMATION_TOLERANCE: u32 = 1;

/// Median-time-past values that differ by more than this many seconds are a disagreement.
/// Ten minutes is ten DIVI blocks: far wider than tip lag, far narrower than a lie that moves
/// a timelock decision. The lower value is used.
pub const MTP_TOLERANCE_SECS: u32 = 600;

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
