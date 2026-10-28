// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The bound on a spend a backend holds for its second source ([`SwapError::Held`]).
//!
//! A backend with an opt-in cross-check refuses to build a claim or refund, or to answer a
//! spend read, while its second source is down or disagrees. Refunds have a deadline in the
//! chain's own time (MTP); a claim whose preimage is public does not (Manager ruling
//! 2026-10-27 19:40Z, EU):
//!
//! - a refund: one claim margin after its locktime, it is built on the primary alone; and the
//!   spend read a refund waits on (`find_spend`: was the lock claimed, with which preimage?)
//!   is read on the primary alone from the same deadline;
//! - a claim whose preimage is already public (the taker's in `Claimed`, the maker's of the
//!   taker leg) has no refund path left: it keeps holding, never built on the primary alone.
//!   Once less than the chain's claim margin is left before the counterparty's refund
//!   locktime (its old deadline, where [`crate::ClaimDeadline::check`] fails) the hold is
//!   logged once at error level and `last_error` says it needs a human
//!   ([`NO_REFUND_PATH`]); the two-source build is still retried every tick.
//!
//! Past a refund deadline the cross-check protects nothing: the coins go back to our own key
//! and the signature commits to the amount and the chain's branch (ZIP 244, BIP 143), so a
//! lying primary can only make the refund fail to land, which is what holding gives too. A
//! preimage read on the primary alone is checked against the hash. The taker's **first**
//! claim, which would reveal the preimage, is declined at its margin and both legs refund
//! (`taker.rs`). Only if the chain's MTP cannot be read (a two-source MTP whose second source
//! is down) is the wall clock used, which runs ahead of MTP and so can only bring a deadline
//! earlier.
//!
//! Reads (EV): a two-source read (BTC `[btc].quorum_reads`, the USDC quorum, DIVI
//! `fallback_rpc_url`) is `Held` the same way. Beyond the spend read above ([`find_spend`]),
//! the other reads in front of a refund (the taker's `taker_leg_refundable` and the lock's
//! confirmations and tip in `taker_leg_lost`, the maker's lock confirmations and
//! `maker_leg_timed_out`, both refunds' confirmation) are made on the primary alone from the
//! same refund deadline ([`confirmations`], [`tip_height`], [`median_time_past`]); the taker's claim already broadcast in `Claimed` reads on
//! the primary alone from the claim deadline so its fee escalation runs (fee only, no new
//! spend). A claim after the reveal is never read or built here.

use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::types::{Amount, Outpoint, SignedTx, SpendInfo, Txid};

/// What `last_error` says of a public-preimage claim held past its old deadline.
pub(crate) const NO_REFUND_PATH: &str = "held claim, no refund path: needs a human";

/// The old deadline of a held claim of an HTLC with `locktime`: less than `margin` seconds are
/// left (where [`crate::ClaimDeadline::check`] fails). From it on the hold needs a human.
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

pub(crate) fn unix_now() -> u64 {
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
    past(backend, why, deadline, swap, what, locktime, "building it").await
}

/// [`past_deadline`] for a read: the log says the read is made on the primary alone.
pub(crate) async fn read_past_deadline(
    backend: &dyn ChainBackend,
    why: String,
    deadline: i64,
    swap: &str,
    what: &str,
    locktime: u32,
) -> Result<std::sync::Arc<dyn ChainBackend>> {
    past(backend, why, deadline, swap, what, locktime, "reading it").await
}

async fn past(
    backend: &dyn ChainBackend,
    why: String,
    deadline: i64,
    swap: &str,
    what: &str,
    locktime: u32,
    act: &str,
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
        "{what} held by the second source until its deadline: {act} on the primary source \
         alone"
    );
    Ok(view)
}

/// Whether this is the first time (in this process) that `swap`'s held claim passed its old
/// deadline: the error line is written once, not every tick.
fn first_report(swap: &str) -> bool {
    static SEEN: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    SEEN.get_or_init(Default::default)
        .lock()
        .insert(swap.to_owned())
}

/// A public-preimage claim the backend holds (`why`): it keeps holding (no refund path, so
/// nothing moves without a human). From its old `deadline` on, the hold is logged once at
/// error level and the returned `Held` says it needs a human ([`NO_REFUND_PATH`]).
pub(crate) async fn keep_holding(
    backend: &dyn ChainBackend,
    why: String,
    deadline: i64,
    swap: &str,
    locktime: u32,
) -> SwapError {
    let (now, clock) = judge_time(backend.median_time_past().await, unix_now());
    if now < deadline {
        return SwapError::Held(why);
    }
    if first_report(swap) {
        tracing::error!(
            swap,
            chain = %backend.chain(),
            what = "claim",
            locktime,
            deadline,
            now,
            clock,
            held = %why,
            "{NO_REFUND_PATH}: a claim with a public preimage is held by the second source \
             past its deadline; it is never built on the primary alone"
        );
    }
    SwapError::Held(format!("{NO_REFUND_PATH}: {why}"))
}

/// The deadline a held read in front of a refund waits for: the refund deadline
/// ([`refund_deadline`]) of the HTLC with `locktime`, for swap `swap`.
pub(crate) struct RefundRead<'a> {
    pub deadline: i64,
    pub locktime: u32,
    pub swap: &'a str,
}

impl RefundRead<'_> {
    /// The primary-only view for a read `what` held for `why`, once the deadline is reached.
    async fn view(
        &self,
        backend: &dyn ChainBackend,
        why: String,
        what: &str,
    ) -> Result<std::sync::Arc<dyn ChainBackend>> {
        read_past_deadline(backend, why, self.deadline, self.swap, what, self.locktime).await
    }
}

/// [`ChainBackend::confirmations`] in front of a refund: held for the second source, it is
/// read on the primary alone from the refund deadline (`Held` until then).
pub(crate) async fn confirmations(
    backend: &dyn ChainBackend,
    txid: &Txid,
    at: &RefundRead<'_>,
    what: &str,
) -> Result<Option<u32>> {
    match backend.confirmations(txid).await {
        Err(SwapError::Held(why)) => at.view(backend, why, what).await?.confirmations(txid).await,
        other => other,
    }
}

/// [`ChainBackend::tip_height`] in front of a refund, as [`confirmations`].
pub(crate) async fn tip_height(
    backend: &dyn ChainBackend,
    at: &RefundRead<'_>,
    what: &str,
) -> Result<u64> {
    match backend.tip_height().await {
        Err(SwapError::Held(why)) => at.view(backend, why, what).await?.tip_height().await,
        other => other,
    }
}

/// [`ChainBackend::median_time_past`] in front of a refund, as [`confirmations`]; the
/// deadline itself is then judged on the wall clock ([`judge_time`]).
pub(crate) async fn median_time_past(
    backend: &dyn ChainBackend,
    at: &RefundRead<'_>,
    what: &str,
) -> Result<u32> {
    match backend.median_time_past().await {
        Err(SwapError::Held(why)) => at.view(backend, why, what).await?.median_time_past().await,
        other => other,
    }
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

/// [`ChainBackend::find_spend`] for a read a refund of the HTLC with `locktime` waits on:
/// held reads are read on the primary alone from the refund deadline ([`refund_deadline`]
/// with the chain's claim `margin`); `last_error` then names it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn find_spend(
    backend: &dyn ChainBackend,
    at: &Outpoint,
    from_height: u64,
    locktime: u32,
    margin: u32,
    swap: &str,
    last_error: &mut Option<String>,
) -> Result<Option<SpendInfo>> {
    let why = match backend.find_spend(at, from_height).await {
        Err(SwapError::Held(why)) => why,
        other => return other,
    };
    let deadline = refund_deadline(locktime, margin);
    let view = past_deadline(backend, why.clone(), deadline, swap, "spend read", locktime).await?;
    let spend = view.find_spend(at, from_height).await?;
    *last_error = Some(format!(
        "spend read on the primary source alone at its hold deadline (held: {why})"
    ));
    Ok(spend)
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
    fn a_held_claim_past_its_deadline_is_reported_once_per_swap() {
        assert!(first_report("eu-once-a"));
        assert!(!first_report("eu-once-a"));
        assert!(first_report("eu-once-b"));
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
