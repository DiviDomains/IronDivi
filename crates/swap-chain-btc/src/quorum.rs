// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
//! `SwapError::Transient`, which the engine retries. Where the two agree on what exists, a
//! confirmation count is the lower of the two, so a single liar can lower a count but never
//! raise one; endpoints a block apart are ordinary lag, not a disagreement. The tip reads
//! follow the same rule: the lower tip height and median time, the header of the lower tip
//! once the other endpoint names the same block at that height, and a block status both
//! endpoints give. Funding reads (EO): only the wallet coins both endpoints list.

use divi_swap::backend::TipHeader;
use divi_swap::{LockedOutput, SpendInfo, SwapError};

use crate::tx::Coin;

type Result<T> = std::result::Result<T, SwapError>;

pub(crate) fn disagree(op: &str, detail: String) -> SwapError {
    tracing::warn!(
        op,
        "Esplora endpoints disagree, treating the read as transient: {detail}"
    );
    SwapError::Transient(format!("{op}: Esplora endpoints disagree: {detail}"))
}

/// Join the two endpoints' results. Both answered: their answers. Exactly one failed: the read
/// is `Transient` (one view is not enough; quorum mode fails closed). Both failed: the
/// primary's error, unchanged.
pub(crate) fn pair<T>(op: &str, primary: Result<T>, secondary: Result<T>) -> Result<(T, T)> {
    match (primary, secondary) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(e), Err(f)) => {
            tracing::warn!(op, "secondary Esplora also failed: {f}");
            Err(e)
        }
        (Err(e), Ok(_)) => Err(disagree(op, format!("primary failed: {e}"))),
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
