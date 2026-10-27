// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The bound on a spend a backend holds for its second source ([`SwapError::Held`]).
//!
//! A backend with an opt-in cross-check refuses to build a claim or refund while its second
//! source is down or disagrees. Held past the locktime it races, that turns a possible false
//! alarm into a certain loss, so the hold ends at a deadline in the chain's own time (MTP):
//!
//! - a claim whose preimage is already public (the taker's in `Claimed`, the maker's of the
//!   taker leg): once less than the chain's claim margin is left before the counterparty's
//!   refund locktime — the moment the taker stops starting a first claim
//!   ([`crate::ClaimDeadline::check`]) — it is built on the primary alone;
//! - a refund: one claim margin after its locktime, it is built on the primary alone.
//!
//! Past either deadline the cross-check protects nothing: the preimage is out, or the coins
//! go back to our own key, and the signature commits to the amount and the chain's branch
//! (ZIP 244, BIP 143), so a lying primary can only make the spend fail to land, which is what
//! holding gives too. The taker's **first** claim, which would reveal the preimage, never comes
//! here: it is declined at its margin and both legs refund (`taker.rs`). Only if the chain's
//! MTP cannot be read (a two-source MTP whose second source is down) is the wall clock used,
//! which runs ahead of MTP and so can only bring a deadline earlier.

use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::types::{Amount, Outpoint, SignedTx};

/// First chain time at which a held claim of an HTLC with `locktime` is built on the primary
/// alone: less than `margin` seconds are left (where [`crate::ClaimDeadline::check`] fails).
pub(crate) fn claim_deadline(locktime: u32, margin: u32) -> i64 {
    i64::from(locktime) - i64::from(margin) + 1
}

/// First chain time at which a held refund of an HTLC with `locktime` is built on the
/// primary alone: one `margin` after the locktime.
pub(crate) fn refund_deadline(locktime: u32, margin: u32) -> i64 {
    i64::from(locktime) + i64::from(margin)
}

/// The time a deadline is judged by: `mtp` if it could be read, else `wall` (unix seconds),
/// with the name of the clock used.
pub(crate) fn judge_time(mtp: Result<u32>, wall: u64) -> (i64, &'static str) {
    match mtp {
        Ok(m) => (i64::from(m), "mtp"),
        Err(_) => (i64::try_from(wall).unwrap_or(i64::MAX), "wall clock"),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The primary-only view of `backend` if the hold reported by `why` has reached `deadline`,
/// logged at error level; `Err(Held(why))` (keep holding) otherwise.
pub(crate) async fn past_deadline(
    backend: &dyn ChainBackend,
    why: String,
    deadline: i64,
    swap: &str,
    what: &str,
    locktime: u32,
) -> Result<std::sync::Arc<dyn ChainBackend>> {
    let Some(view) = backend.primary_only() else {
        return Err(SwapError::Held(why));
    };
    let (now, clock) = judge_time(backend.median_time_past().await, unix_now());
    if now < deadline {
        return Err(SwapError::Held(why));
    }
    tracing::error!(
        swap,
        chain = %backend.chain(),
        what,
        locktime,
        deadline,
        now,
        clock,
        held = %why,
        "{what} held by the second source until its deadline: building it on the primary \
         source alone"
    );
    Ok(view)
}

/// What a record says once a spend was built on the primary alone.
pub(crate) fn note(what: &str, why: &str) -> String {
    format!("{what} built on the primary source alone at its hold deadline (held: {why})")
}

/// [`ChainBackend::build_refund`], built on the primary alone once a hold reaches the refund
/// deadline ([`refund_deadline`] with the chain's claim `margin`); `last_error` then names it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_refund(
    backend: &dyn ChainBackend,
    htlc: &HtlcParams,
    at: &Outpoint,
    amount: Amount,
    margin: u32,
    swap: &str,
    last_error: &mut Option<String>,
) -> Result<SignedTx> {
    let why = match backend.build_refund(htlc, at, amount).await {
        Err(SwapError::Held(why)) => why,
        other => return other,
    };
    let deadline = refund_deadline(htlc.locktime, margin);
    let view = past_deadline(
        backend,
        why.clone(),
        deadline,
        swap,
        "refund",
        htlc.locktime,
    )
    .await?;
    let tx = view.build_refund(htlc, at, amount).await?;
    *last_error = Some(note("refund", &why));
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadlines_sit_on_the_claim_margin_and_one_margin_past_the_refund() {
        // A claim may still start with exactly the margin left; one second later it may not.
        let d = crate::ClaimDeadline::builtin(crate::Chain::Btc);
        let (l, m) = (1_800_000_000, d.margin_secs());
        let c = claim_deadline(l, m);
        assert!(d.check(crate::Chain::Btc, (c - 1) as u32, l).is_ok());
        assert!(d.check(crate::Chain::Btc, c as u32, l).is_err());
        assert_eq!(refund_deadline(l, m), i64::from(l) + 3600);
    }

    #[test]
    fn an_unreadable_mtp_falls_back_to_the_wall_clock() {
        assert_eq!(judge_time(Ok(1_800_000_000), 5), (1_800_000_000, "mtp"));
        assert_eq!(
            judge_time(
                Err(SwapError::Transient("fallback down".into())),
                1_790_000_000
            ),
            (1_790_000_000, "wall clock")
        );
    }
}
