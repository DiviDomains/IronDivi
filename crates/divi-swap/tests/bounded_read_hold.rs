// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A two-source *read* (`find_spend`, `confirmations`, `tip_height`, `median_time_past`)
//! whose second source is down or disagrees ([`SwapError::Held`]: BTC `[btc].quorum_reads`,
//! the USDC quorum, DIVI `fallback_rpc_url`) is held only until EM's deadline in chain time
//! where a refund path exists (`docs/plans/swap-poc/status/engine.md`, EV round; Manager
//! ruling 2026-10-27 19:40Z):
//!
//! - H5/H6, the reads in front of a refund: on the primary alone one claim margin after the
//!   refund's locktime, so the refund is built and its confirmation seen;
//! - the taker's `Claimed` claim, already broadcast: its reads go to the primary alone once
//!   less than the claim margin is left, so the fee escalation runs (fee only);
//! - H1, the taker's first claim: a maker-leg MTP that cannot be read is judged on the wall
//!   clock; the claim is declined at its margin, never built on one source, and both legs
//!   refund;
//! - H3/H4, the maker's claim after the reveal (no refund path): its reads keep holding at
//!   any deadline and nothing is read or built on the primary alone.
//!
//! Each refund deadline is checked at its boundary (one second before: held; at it: acted on)
//! for a second source that is down and one that disagrees. An MTP that cannot be read is
//! judged on the wall clock, which can only bring a deadline earlier.

use divi_swap::api::{Direction, Offer, SwapView};
use divi_swap::mock::{MockBackend, MockChain, TxKind};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, FeeBump, Maker, Profile, Store, SwapConfig,
    SwapError, SwapState, Taker, TakerState,
};
use std::sync::Arc;

/// Chain time well ahead of the wall clock: a deadline judged on the wall clock is never
/// reached.
const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;

/// What BTC quorum reads say with the secondary down.
const UNAVAILABLE: &str = "find_spend: Esplora endpoints disagree: secondary failed: \
     http://127.0.0.1:1/tx/aa/outspend/0: connection refused";
/// What they say when the two endpoints disagree.
const DISAGREE: &str = "find_spend: Esplora endpoints disagree: primary unspent, secondary \
     spent by bb input 0";
const HOLDS: [&str; 2] = [UNAVAILABLE, DISAGREE];

struct World {
    divi: MockChain,
    btc: MockChain,
    mdivi: MockBackend,
    mbtc: MockBackend,
    tdivi: MockBackend,
    tbtc: MockBackend,
}

fn world_at(t0: u32) -> World {
    let divi = MockChain::new(Chain::Divi, t0, 60);
    let btc = MockChain::new(Chain::Btc, t0, 600);
    World {
        mdivi: divi.backend(1, Amount(FUNDS)),
        mbtc: btc.backend(2, Amount(FUNDS)),
        tdivi: divi.backend(3, Amount(FUNDS)),
        tbtc: btc.backend(4, Amount(FUNDS)),
        divi,
        btc,
    }
}

fn world() -> World {
    world_at(T0)
}

/// Chain time thirty days behind the wall clock: every deadline of a swap started there has
/// long passed on the wall clock.
fn past_t0() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    u32::try_from(now - 30 * 86_400).unwrap()
}

fn taker(w: &World, store: &Store) -> Taker {
    Taker::new(
        Arc::new(w.tdivi.clone()),
        Arc::new(w.tbtc.clone()),
        store.clone(),
    )
}

/// The taker pays DIVI (taker leg), the maker locks BTC (maker leg).
fn maker(w: &World, store: &Store) -> Maker {
    Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.mdivi.clone()),
        Arc::new(w.mbtc.clone()),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysDivi,
            counter_chain: Chain::Btc,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap()
}

fn btc_margin() -> u32 {
    ClaimDeadline::builtin(Chain::Btc).margin_secs()
}

fn divi_margin() -> u32 {
    ClaimDeadline::builtin(Chain::Divi).margin_secs()
}

fn set_mtp(chain: &MockChain, mtp: u32) {
    assert!(chain.mtp() <= mtp, "MTP {} already past {mtp}", chain.mtp());
    chain.advance_time(mtp - chain.mtp());
}

/// Hold every two-source read of `chain` but its MTP: `find_spend` (EU's
/// [`MockChain::hold_reads`]) and `confirmations`/`tip_height`.
fn hold_reads(chain: &MockChain, why: Option<&str>) {
    chain.hold_reads(why);
    chain.hold_confirmations(why);
}

/// Nothing was read on `chain` through a primary-only view.
fn no_primary_reads(chain: &MockChain) -> bool {
    chain.primary_only_reads() == 0 && chain.primary_only_read_log().is_empty()
}

fn view(maker: &Maker, mid: &str) -> SwapView {
    maker.view(mid).unwrap().unwrap()
}

fn maker_locktime(v: &SwapView) -> u32 {
    v.maker_leg.as_ref().unwrap().htlc.locktime
}

fn taker_locktime(v: &SwapView) -> u32 {
    v.taker_leg.htlc.locktime
}

fn assert_held<T: std::fmt::Debug>(r: Result<T, SwapError>, why: &str) {
    match r {
        Err(SwapError::Held(m)) => assert_eq!(m, why),
        other => panic!("expected the hold, got {other:?}"),
    }
}

async fn tstep(
    taker: &Taker,
    maker: &Maker,
    tid: &str,
    mid: &str,
) -> divi_swap::Result<TakerState> {
    let v = maker.view(mid).unwrap();
    taker.step(tid, v.as_ref()).await
}

/// Run the swap until the maker's BTC lock is confirmed (taker away).
async fn to_maker_lock_confirmed(w: &World, maker: &Maker, taker: &Taker) -> (String, String) {
    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    for _ in 0..20 {
        w.divi.mine(1);
        w.btc.mine(1);
        maker.tick().await.unwrap();
        if view(maker, &mid).state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(view(maker, &mid).state, SwapState::MakerLockConfirmed);
    (tid, mid)
}

/// The taker locks DIVI and the maker never locks. Returns (taker id, taker-leg locktime).
async fn taker_locked_alone(w: &World, maker: &Maker, taker: &Taker) -> (String, u32) {
    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    taker.lock(&tid).await.unwrap();
    assert_eq!(taker.step(&tid, None).await.unwrap(), TakerState::Locked);
    w.divi.mine(3);
    (tid, v.taker_leg.htlc.locktime)
}

// ---- H5: the reads in front of the taker's refund ----------------------------------------

#[tokio::test]
async fn h5_a_held_read_before_the_taker_refund_ends_one_margin_after_the_locktime() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, locktime) = taker_locked_alone(&w, &maker, &taker).await;

        // `taker_leg_lost` (confirmations, tip, find_spend) runs before the refund is built.
        hold_reads(&w.divi, Some(why));
        set_mtp(&w.divi, locktime + 1);
        assert_held(taker.step(&tid, None).await, why);
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Refunded, "{why}");
        assert!(rec.taker_leg_refund.is_none());
        set_mtp(&w.divi, locktime + divi_margin() - 1);
        assert_held(taker.step(&tid, None).await, why);
        assert!(no_primary_reads(&w.divi), "{why}: read early");
        assert!(store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .taker_leg_refund
            .is_none());

        // At the deadline the reads go to the primary alone: the refund is built and sent.
        w.divi.advance_time(1);
        assert_eq!(
            taker.step(&tid, None).await.unwrap(),
            TakerState::Refunded,
            "{why}"
        );
        let refund = store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .taker_leg_refund
            .expect("refund built at the deadline");
        assert!(w.divi.contains(&refund.txid), "{why}: refund not sent");
        assert!(
            w.divi.primary_only_reads() > 0,
            "{why}: spend not read on the primary"
        );
        // Nothing held the build itself: it was made the normal way.
        assert!(w.divi.primary_only_builds().is_empty());

        // Its confirmation is read on the primary alone too.
        w.divi.mine(1);
        assert_eq!(taker.step(&tid, None).await.unwrap(), TakerState::Done);
        assert!(w.divi.balance(&w.tdivi.pubkey()).0 > FUNDS - 1_000_000);
    }
}

/// An MTP that cannot be read (DIVI fallback, USDC quorum) is judged on the wall clock,
/// never on the primary's word: with the wall clock behind the deadline the refund stays
/// held even where the primary's MTP is long past it; with the wall clock past it, the
/// refund goes at once although the chain's MTP has not reached it (earlier, never later).
#[tokio::test]
async fn h5_an_unreadable_mtp_judges_the_refund_deadline_on_the_wall_clock() {
    for why in HOLDS {
        // Wall clock behind the deadline.
        {
            let w = world();
            let store = Store::in_memory().unwrap();
            let (maker, taker) = (maker(&w, &store), taker(&w, &store));
            let (tid, locktime) = taker_locked_alone(&w, &maker, &taker).await;
            w.divi.hold_mtp(Some(why));
            set_mtp(&w.divi, locktime + 10 * divi_margin());
            assert_held(taker.step(&tid, None).await, why);
            assert_eq!(
                store.get_taker_swap(&tid).unwrap().unwrap().state,
                TakerState::Locked,
                "{why}"
            );
            assert!(no_primary_reads(&w.divi), "{why}");
        }

        // Wall clock past the deadline, chain MTP one second past the locktime.
        let w = world_at(past_t0());
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, locktime) = taker_locked_alone(&w, &maker, &taker).await;
        w.divi.hold_mtp(Some(why));
        set_mtp(&w.divi, locktime + 1);
        assert_eq!(
            taker.step(&tid, None).await.unwrap(),
            TakerState::Refunded,
            "{why}"
        );
        let refund = store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .taker_leg_refund
            .expect("refund built");
        assert!(w.divi.contains(&refund.txid), "{why}");
        assert!(w.divi.primary_only_read_log().contains(&"median_time_past"));
        w.divi.mine(1);
        assert_eq!(taker.step(&tid, None).await.unwrap(), TakerState::Done);
    }
}

// ---- H6: the reads in front of the maker's refund ----------------------------------------

#[tokio::test]
async fn h6_a_held_read_before_the_maker_refund_ends_one_margin_after_the_locktime() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (_tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        let locktime = maker_locktime(&view(&maker, &mid));

        // `revealed_preimage` (find_spend) runs before the locktime check and the refund.
        hold_reads(&w.btc, Some(why));
        set_mtp(&w.btc, locktime + 1);
        maker.tick().await.unwrap();
        let v = view(&maker, &mid);
        assert_eq!(v.state, SwapState::MakerLockConfirmed, "{why}");
        assert!(
            v.last_error.as_deref().is_some_and(|e| e.contains(why)),
            "{v:?}"
        );
        set_mtp(&w.btc, locktime + btc_margin() - 1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::MakerLockConfirmed);
        assert!(no_primary_reads(&w.btc), "{why}: read early");

        w.btc.advance_time(1);
        maker.tick().await.unwrap();
        assert_eq!(
            view(&maker, &mid).state,
            SwapState::MakerRefundable,
            "{why}"
        );
        let refund = store
            .get_maker_swap(&mid)
            .unwrap()
            .unwrap()
            .maker_leg_refund
            .expect("refund built at the deadline");
        assert!(w.btc.contains(&refund.txid), "{why}: refund not sent");
        assert!(w.btc.primary_only_reads() > 0);
        assert!(w.btc.primary_only_builds().is_empty());
        w.btc.mine(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::Done, "{why}");
        assert!(w.btc.balance(&w.mbtc.pubkey()).0 > FUNDS - 1_000_000);
    }
}

/// Guard: a second source back before the deadline resumes the two-source refund.
#[tokio::test]
async fn h6_a_second_source_back_before_the_deadline_refunds_on_both() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (_tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        let locktime = maker_locktime(&view(&maker, &mid));
        hold_reads(&w.btc, Some(why));
        set_mtp(&w.btc, locktime + btc_margin() - 1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::MakerLockConfirmed);
        hold_reads(&w.btc, None);
        maker.tick().await.unwrap();
        w.btc.mine(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::Done, "{why}");
        assert!(no_primary_reads(&w.btc));
    }
}

// ---- H1: the taker's first claim (preimage secret) ---------------------------------------

/// The maker leg's MTP cannot be read (its quorum's second source is down or disagrees)
/// once the taker has verified the lock. The claim margin is judged on the wall clock: past
/// it the claim is declined, never built on one source, and both legs refund.
#[tokio::test]
async fn h1_an_unreadable_maker_leg_mtp_declines_the_first_claim_and_both_legs_refund() {
    for why in HOLDS {
        let w = world_at(past_t0());
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        taker.halt_after(Some(TakerState::MakerLockConfirmed));
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::MakerLockConfirmed
        );
        taker.halt_after(None);

        w.btc.hold_mtp(Some(why));
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::MakerLockConfirmed,
            "{why}"
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let reason = rec.claim_declined.clone().expect("declined");
        assert!(reason.contains(why), "{why}: {reason}");
        assert!(rec.maker_leg_claim.is_none());

        // Both legs refund: the taker's on DIVI (healthy), the maker's BTC refund once its
        // locktime passes (the wall clock is past its deadline).
        let v = view(&maker, &mid);
        set_mtp(&w.btc, maker_locktime(&v) + 1);
        set_mtp(&w.divi, taker_locktime(&v) + 1);
        for _ in 0..20 {
            w.divi.mine(1);
            w.btc.mine(1);
            maker.tick().await.unwrap();
            let _ = tstep(&taker, &maker, &tid, &mid).await;
        }
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Done, "{why}");
        assert!(rec.taker_leg_refund.is_some() && rec.maker_leg_claim.is_none());
        let mv = view(&maker, &mid);
        assert_eq!(mv.state, SwapState::Done, "{why}: maker refund still held");
        assert!(mv.preimage.is_none(), "the preimage was never revealed");
        let at = mv.maker_leg.as_ref().unwrap().outpoint.unwrap();
        assert_eq!(w.btc.tx_counts(&at).claim_attempts, 0, "no claim was sent");
        assert!(!w.btc.primary_only_builds().contains(&TxKind::Claim));
        assert_eq!(w.btc.balance(&w.tbtc.pubkey()).0, FUNDS, "taker got no BTC");
    }
}

/// Guard: with the wall clock still before the claim margin, an unreadable maker-leg MTP
/// neither claims nor declines; nothing is read or built on the primary alone.
#[tokio::test]
async fn h1_an_unreadable_maker_leg_mtp_before_the_margin_holds_without_claiming() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        taker.halt_after(Some(TakerState::MakerLockConfirmed));
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::MakerLockConfirmed
        );
        taker.halt_after(None);
        w.btc.hold_mtp(Some(why));
        set_mtp(&w.btc, maker_locktime(&view(&maker, &mid)) + 1);
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.claim_declined.is_none() && rec.maker_leg_claim.is_none());
        assert!(no_primary_reads(&w.btc));
        assert!(w.btc.primary_only_builds().is_empty());
    }
}

// ---- The taker's `Claimed` claim, already broadcast: escalation (EM left (iii)) ----------

#[tokio::test]
async fn a_held_post_broadcast_read_lets_the_claim_escalate_at_the_claim_deadline() {
    for why in HOLDS {
        let w = world();
        w.btc.set_fee_bump(FeeBump::Rbf);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let (first, base) = (rec.maker_leg_claim.unwrap(), rec.claim_feerate.unwrap());
        let locktime = maker_locktime(&view(&maker, &mid));

        // `confirmations` after the resend is held: no escalation before the deadline.
        hold_reads(&w.btc, Some(why));
        set_mtp(&w.btc, locktime - btc_margin());
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.maker_leg_claim.as_ref().unwrap().txid, first.txid);
        assert_eq!(rec.claim_feerate, Some(base), "{why}: bumped early");
        assert!(no_primary_reads(&w.btc));

        // At the deadline the read goes to the primary alone and the claim escalates.
        w.btc.advance_time(1);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed,
            "{why}"
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let bumped = rec.maker_leg_claim.clone().unwrap();
        assert!(rec.claim_feerate.unwrap() > base, "{why}: not escalated");
        assert_ne!(bumped.txid, first.txid);
        assert!(w.btc.contains(&bumped.txid), "{why}: replacement not sent");
        assert!(w.btc.primary_only_read_log().contains(&"confirmations"));

        // The next step reads the replaced versions on the primary alone too, and the
        // replacement's confirmation ends the claim.
        w.btc.advance_time(60);
        let _ = tstep(&taker, &maker, &tid, &mid).await.unwrap();
        w.btc.mine(1);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Done,
            "{why}"
        );
    }
}

// ---- H3/H4: the maker's claim after the reveal keeps holding (ruling 19:40Z) ------------

#[tokio::test]
async fn a_held_read_before_the_maker_claim_keeps_holding_past_the_claim_deadline() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed
        );
        w.btc.mine(1);
        for _ in 0..5 {
            maker.tick().await.unwrap();
            if view(&maker, &mid).state == SwapState::MakerClaimed {
                break;
            }
            w.btc.mine(1);
        }
        assert_eq!(view(&maker, &mid).state, SwapState::MakerClaimed);
        let locktime = taker_locktime(&view(&maker, &mid));

        // `confirmations` before the resend (and `replaced_confirmed`) hold, at the claim
        // deadline and well past it: nothing goes through the primary alone.
        hold_reads(&w.divi, Some(why));
        for mtp in [
            locktime - divi_margin(),
            locktime - divi_margin() + 1,
            locktime + 2 * divi_margin(),
        ] {
            set_mtp(&w.divi, mtp);
            maker.tick().await.unwrap();
            let v = view(&maker, &mid);
            assert_eq!(v.state, SwapState::MakerClaimed, "{why} at {mtp}");
            assert!(
                v.last_error.as_deref().is_some_and(|e| e.contains(why)),
                "{v:?}"
            );
        }
        assert!(no_primary_reads(&w.divi), "{why}");
        assert!(w.divi.primary_only_builds().is_empty(), "{why}");
    }
}

// ---- Opt-ins off: nothing on the primary alone --------------------------------------------

/// Guard: without a hold a swap and a refund complete and nothing is read or built on the
/// primary alone, on either chain.
#[tokio::test]
async fn without_a_hold_nothing_is_read_on_the_primary_alone() {
    let w = world();
    let store = Store::in_memory().unwrap();
    let (maker, taker) = (maker(&w, &store), taker(&w, &store));
    let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
    for _ in 0..20 {
        let _ = tstep(&taker, &maker, &tid, &mid).await;
        maker.tick().await.unwrap();
        w.divi.mine(1);
        w.btc.mine(1);
    }
    assert_eq!(
        store.get_taker_swap(&tid).unwrap().unwrap().state,
        TakerState::Done
    );
    assert_eq!(view(&maker, &mid).state, SwapState::Done);

    let (tid, locktime) = taker_locked_alone(&w, &maker, &taker).await;
    set_mtp(&w.divi, locktime + 1);
    for _ in 0..3 {
        let _ = taker.step(&tid, None).await;
        w.divi.mine(1);
    }
    assert_eq!(
        store.get_taker_swap(&tid).unwrap().unwrap().state,
        TakerState::Done
    );
    for c in [&w.btc, &w.divi] {
        assert!(no_primary_reads(c));
        assert!(c.primary_only_builds().is_empty());
    }
}

// ---- FC: the maker-lock read fails while the maker leg's MTP is held ----------------------

/// What a maker-lock read says while it keeps failing (EX: a second source down).
const LOCK_UNREAD: &str = "htlc_output: second source unavailable: connection refused";

fn lock_unread() -> SwapError {
    SwapError::Transient(LOCK_UNREAD.into())
}

/// The maker's lock cannot be read (EX) and the maker leg's MTP is held for its second
/// source (EV). The claim deadline is judged on the wall clock, as for the first claim: past
/// it the claim is declined for good, naming the lock read and the hold, nothing is revealed,
/// and the taker leg refunds at its locktime.
#[tokio::test]
async fn fc_an_unread_maker_lock_with_a_held_mtp_declines_the_claim_and_the_taker_refunds() {
    for why in HOLDS {
        let w = world_at(past_t0());
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        w.btc.fail_lock_reads(Some(lock_unread()));
        w.btc.hold_mtp(Some(why));

        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Locked,
            "{why}"
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let reason = rec.claim_declined.clone().expect("declined");
        assert!(reason.contains(LOCK_UNREAD), "{why}: {reason}");
        assert!(reason.contains(why), "{why}: {reason}");
        assert!(rec.maker_leg_htlc.is_none() && rec.maker_leg_claim.is_none());

        // Nothing is claimed before the taker leg's locktime, nor revealed.
        let v = view(&maker, &mid);
        set_mtp(&w.divi, taker_locktime(&v) - 1);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Locked
        );
        assert!(store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .taker_leg_refund
            .is_none());

        set_mtp(&w.divi, taker_locktime(&v) + 1);
        for _ in 0..20 {
            w.divi.mine(1);
            let _ = tstep(&taker, &maker, &tid, &mid).await;
        }
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Done, "{why}");
        assert!(rec.taker_leg_refund.is_some() && rec.maker_leg_claim.is_none());
        let mv = view(&maker, &mid);
        assert!(mv.preimage.is_none(), "the preimage was never revealed");
        let at = mv.maker_leg.as_ref().unwrap().outpoint.unwrap();
        assert_eq!(w.btc.tx_counts(&at).claim_attempts, 0, "no claim was sent");
        assert!(w.btc.primary_only_builds().is_empty());
        assert!(no_primary_reads(&w.btc));
        assert_eq!(w.btc.balance(&w.tbtc.pubkey()).0, FUNDS, "taker got no BTC");
    }
}

/// Guard: with the wall clock still before the claim margin, an unread maker lock with a
/// held MTP keeps the retry (the lock read's error) and declines nothing.
#[tokio::test]
async fn fc_an_unread_maker_lock_with_a_held_mtp_before_the_margin_retries() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        w.btc.fail_lock_reads(Some(lock_unread()));
        w.btc.hold_mtp(Some(why));
        set_mtp(&w.btc, maker_locktime(&view(&maker, &mid)) + 1);
        match tstep(&taker, &maker, &tid, &mid).await {
            Err(SwapError::Transient(m)) => assert_eq!(m, LOCK_UNREAD),
            other => panic!("{why}: expected the lock read's error, got {other:?}"),
        }
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.claim_declined.is_none() && rec.maker_leg_claim.is_none());
        assert!(no_primary_reads(&w.btc));
    }
}

/// Control: an MTP that fails with a plain error (not a hold) keeps the retry, as before,
/// even with the wall clock long past the claim margin.
#[tokio::test]
async fn fc_an_unread_maker_lock_with_a_plain_mtp_error_retries() {
    let w = world_at(past_t0());
    let store = Store::in_memory().unwrap();
    let (maker, taker) = (maker(&w, &store), taker(&w, &store));
    let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
    w.btc.fail_with(Some(lock_unread()));
    for _ in 0..3 {
        match tstep(&taker, &maker, &tid, &mid).await {
            Err(SwapError::Transient(m)) => assert_eq!(m, LOCK_UNREAD),
            other => panic!("expected the lock read's error, got {other:?}"),
        }
    }
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.state, TakerState::Locked);
    assert!(rec.claim_declined.is_none() && rec.maker_leg_claim.is_none());
}
