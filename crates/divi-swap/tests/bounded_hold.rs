// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A claim or refund a backend holds because its second source is down or disagrees
//! ([`SwapError::Held`]) (`docs/plans/swap-poc/status/engine.md`, EM and EU rounds):
//!
//! - the taker's first claim (the preimage still secret) is declined at the claim margin and
//!   both legs refund; nothing is ever built on the primary alone for it;
//! - a claim whose preimage is already public (the taker's in `Claimed`, the maker's of the
//!   taker leg) has no refund path left, so it keeps holding (Manager ruling 2026-10-27
//!   19:40Z): never built on the primary alone, at its old deadline (less than the claim
//!   margin left) or after it. From that deadline on, `last_error` says it needs a human,
//!   and the two-source build is retried every tick;
//! - a refund, or a spend read (`find_spend`) a refund waits on, is built or read on the
//!   primary alone ([`ChainBackend::primary_only`]) one claim margin after it became final.
//!
//! Each deadline is checked at its boundary (one second before: held; at it: acted on, or for
//! a public-preimage claim still held), for a second source that is down and for one that
//! disagrees, on a BTC-like and an LTC counter chain. A source back resumes the normal path,
//! and without a hold nothing is built on the primary alone.

use divi_swap::api::{Direction, Offer, SwapView};
use divi_swap::mock::{MockBackend, MockChain, TxKind};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, Maker, Profile, Store, SwapConfig, SwapError,
    SwapState, Taker, TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;

/// What a backend whose second source is down says (as the ZEC cross-check does).
const UNAVAILABLE: &str = "zec tip cross-check unavailable (http://127.0.0.1:1: tip: refused); \
     primary http://primary.test:9067, second operator http://127.0.0.1:1";
/// What a backend whose second source disagrees says.
const DISAGREE: &str = "zec tip cross-check FAILED at height 40: primary lightwalletd \
     http://primary.test:9067 says aa, second operator http://second.test:9067 says bb";
/// What the LTC claim cross-check says when its source disagrees (an LTC source that is down
/// holds nothing: the claim is built on the primary with a warning, ED/EI).
const LTC_DISAGREE: &str = "ltc cross-check FAILED at height 2999999: primary \
     https://primary.test/api has aa, blockbook has bb; claim of 0909…:1 held \
     (primary https://primary.test/api, blockbook https://source.test)";

/// Each counter chain with each hold its backend can report.
const CASES: [(Chain, &str); 3] = [
    (Chain::Btc, UNAVAILABLE),
    (Chain::Btc, DISAGREE),
    (Chain::Ltc, LTC_DISAGREE),
];

/// What `last_error` says once a public-preimage claim is held past its old deadline.
const NEEDS_HUMAN: &str = "held claim, no refund path: needs a human";

struct World {
    divi: MockChain,
    /// The counter chain (the maker leg): BTC or LTC.
    ctr: MockChain,
    ctr_chain: Chain,
    mdivi: MockBackend,
    mctr: MockBackend,
    tdivi: MockBackend,
    tctr: MockBackend,
}

fn world_on(ctr_chain: Chain) -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let block_secs = if ctr_chain == Chain::Ltc { 150 } else { 600 };
    let ctr = MockChain::new(ctr_chain, T0, block_secs);
    World {
        mdivi: divi.backend(1, Amount(FUNDS)),
        mctr: ctr.backend(2, Amount(FUNDS)),
        tdivi: divi.backend(3, Amount(FUNDS)),
        tctr: ctr.backend(4, Amount(FUNDS)),
        divi,
        ctr,
        ctr_chain,
    }
}

fn taker(w: &World, store: &Store) -> Taker {
    Taker::new(
        Arc::new(w.tdivi.clone()),
        Arc::new(w.tctr.clone()),
        store.clone(),
    )
}

/// The taker pays DIVI (taker leg), the maker locks the counter chain (maker leg).
fn maker(w: &World, store: &Store) -> Maker {
    Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.mdivi.clone()),
        Arc::new(w.mctr.clone()),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysDivi,
            counter_chain: w.ctr_chain,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap()
}

/// Claim margin of the counter chain (the maker leg's chain).
fn ctr_margin(w: &World) -> u32 {
    ClaimDeadline::builtin(w.ctr_chain).margin_secs()
}

/// DIVI claim margin (the taker leg's chain).
fn divi_margin() -> u32 {
    ClaimDeadline::builtin(Chain::Divi).margin_secs()
}

/// Move `chain`'s MTP forward to exactly `mtp`.
fn set_mtp(chain: &MockChain, mtp: u32) {
    assert!(chain.mtp() <= mtp, "MTP {} already past {mtp}", chain.mtp());
    chain.advance_time(mtp - chain.mtp());
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
        w.ctr.mine(1);
        maker.tick().await.unwrap();
        if maker.view(&mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(
        maker.view(&mid).unwrap().unwrap().state,
        SwapState::MakerLockConfirmed
    );
    (tid, mid)
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

/// The taker's step with the maker's current view.
async fn tstep(
    taker: &Taker,
    maker: &Maker,
    tid: &str,
    mid: &str,
) -> divi_swap::Result<TakerState> {
    let v = maker.view(mid).unwrap();
    taker.step(tid, v.as_ref()).await
}

/// The taker has verified the maker's lock and holds its first claim (preimage still
/// secret). Returns (taker id, maker id, maker-leg locktime).
async fn first_claim_held(
    w: &World,
    maker: &Maker,
    taker: &Taker,
    why: &str,
) -> (String, String, u32) {
    let (tid, mid) = to_maker_lock_confirmed(w, maker, taker).await;
    taker.halt_after(Some(TakerState::MakerLockConfirmed));
    assert_eq!(
        tstep(taker, maker, &tid, &mid).await.unwrap(),
        TakerState::MakerLockConfirmed
    );
    taker.halt_after(None);
    w.ctr.hold_spends(Some(why));
    assert_held(tstep(taker, maker, &tid, &mid).await, why);
    let locktime = maker_locktime(&view(maker, &mid));
    (tid, mid, locktime)
}

// ---- H1: the taker's first claim (secret preimage): decline, never primary-only ----------

#[tokio::test]
async fn a_held_first_claim_declines_at_the_claim_margin_and_both_legs_refund() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid, locktime) = first_claim_held(&w, &maker, &taker, why).await;

        // One second before the deadline (exactly the margin left): still held, not declined.
        set_mtp(&w.ctr, locktime - ctr_margin(&w));
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.claim_declined.is_none(), "{why}: declined early");
        assert!(rec.last_error.as_deref().is_some_and(|e| e.contains(why)));

        // At the deadline: declined for good, the reason naming the hold and both sources.
        w.ctr.advance_time(1);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::MakerLockConfirmed
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let reason = rec
            .claim_declined
            .clone()
            .expect("declined at the deadline");
        assert!(
            reason.contains(why),
            "{why}: reason lacks the hold: {reason}"
        );
        assert!(rec.maker_leg_claim.is_none());

        // The hold stays: both legs still refund (the maker's BTC refund on the primary
        // alone once its own deadline passes), and no claim was ever built or sent.
        w.ctr.advance_time(4 * 3600);
        w.divi.advance_time(7 * 3600);
        for _ in 0..20 {
            w.divi.mine(1);
            w.ctr.mine(1);
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
        assert_eq!(w.ctr.tx_counts(&at).claim_attempts, 0, "no claim was sent");
        assert!(
            !w.ctr.primary_only_builds().contains(&TxKind::Claim),
            "{why}: a secret-preimage claim was built on the primary alone"
        );
        assert_eq!(w.ctr.primary_only_builds(), [TxKind::Refund]);
        assert_eq!(w.ctr.balance(&w.tctr.pubkey()).0, FUNDS, "taker got no BTC");
    }
}

/// Guard: the second source answering again before the deadline resumes the normal path.
#[tokio::test]
async fn a_second_source_back_before_the_deadline_resumes_the_normal_claim() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid, locktime) = first_claim_held(&w, &maker, &taker, why).await;
        set_mtp(&w.ctr, locktime - ctr_margin(&w));
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        w.ctr.hold_spends(None);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.claim_declined.is_none() && rec.last_error.is_none());
        assert!(w.ctr.primary_only_builds().is_empty());
    }
}

/// Guard (opt-in off pinned): without a hold a whole swap completes and nothing is ever
/// built on the primary alone, on either chain.
#[tokio::test]
async fn without_a_hold_nothing_is_built_on_the_primary_alone() {
    for ctr in [Chain::Btc, Chain::Ltc] {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        for _ in 0..20 {
            let _ = tstep(&taker, &maker, &tid, &mid).await;
            maker.tick().await.unwrap();
            w.divi.mine(1);
            w.ctr.mine(1);
        }
        assert_eq!(
            store.get_taker_swap(&tid).unwrap().unwrap().state,
            TakerState::Done
        );
        assert_eq!(view(&maker, &mid).state, SwapState::Done);
        assert!(w.ctr.primary_only_builds().is_empty());
        assert!(w.divi.primary_only_builds().is_empty());
        assert_eq!(w.ctr.primary_only_reads() + w.divi.primary_only_reads(), 0);
    }
}

// ---- H2: the taker's claim in `Claimed` (preimage public) --------------------------------

/// A public-preimage claim held past its old deadline: still `Held`, naming the hold, and
/// saying it needs a human.
fn assert_held_for_a_human<T: std::fmt::Debug>(r: Result<T, SwapError>, why: &str) {
    match r {
        Err(SwapError::Held(m)) => {
            assert!(m.contains(why) && m.contains(NEEDS_HUMAN), "{m}");
        }
        other => panic!("expected the hold, got {other:?}"),
    }
}

/// `last_error` names the hold, and says it needs a human exactly when `human`.
fn assert_last_error(last_error: Option<&str>, why: &str, human: bool) {
    let e = last_error.unwrap_or_default();
    assert!(e.contains(why), "last_error lacks the hold: {e:?}");
    assert_eq!(e.contains(NEEDS_HUMAN), human, "{e:?}");
}

/// The chain times a public-preimage claim is checked at around its old deadline (less than
/// the claim margin left before `locktime`): one second before it, at it, and well past the
/// locktime itself.
fn around_the_old_deadline(locktime: u32, margin: u32) -> [(u32, bool); 3] {
    let deadline = locktime - margin + 1;
    [
        (deadline - 1, false),
        (deadline, true),
        (locktime + 4 * 3600, true),
    ]
}

#[tokio::test]
async fn a_held_taker_claim_after_the_reveal_keeps_holding_past_its_old_deadline() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        // The first claim is signed (the preimage is out of our hands) and refused for good:
        // forgotten, to be re-signed on the next step.
        w.ctr.reject_next_broadcast();
        assert!(matches!(
            tstep(&taker, &maker, &tid, &mid).await,
            Err(SwapError::Rejected(_))
        ));
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Claimed);
        assert!(rec.maker_leg_claim.is_none());

        w.ctr.hold_spends(Some(why));
        let locktime = maker_locktime(&view(&maker, &mid));
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        for (at, human) in around_the_old_deadline(locktime, ctr_margin(&w)) {
            set_mtp(&w.ctr, at);
            let r = tstep(&taker, &maker, &tid, &mid).await;
            if human {
                assert_held_for_a_human(r, why);
            } else {
                assert_held(r, why);
            }
            let rec = store.get_taker_swap(&tid).unwrap().unwrap();
            assert_eq!(rec.state, TakerState::Claimed, "{why} at {at}");
            assert!(rec.maker_leg_claim.is_none(), "{why} at {at}: claim built");
            assert_last_error(rec.last_error.as_deref(), why, human);
            assert!(
                w.ctr.primary_only_builds().is_empty(),
                "{why} at {at}: claim built on the primary alone"
            );
        }

        // The two-source build is retried every tick: the source back, the claim goes out.
        w.ctr.hold_spends(None);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed,
            "{why}"
        );
        let claim = store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .maker_leg_claim
            .expect("signed once the source is back");
        assert!(w.ctr.contains(&claim.txid), "{why}: claim not sent");
        assert!(w.ctr.primary_only_builds().is_empty());
    }
}

// ---- H3/H4: the maker's claim of the taker leg (preimage public) ------------------------

/// The taker claims the maker leg (revealing the preimage); the maker's DIVI claim of the
/// taker leg is held from its first signing. Returns (maker id, taker-leg locktime).
async fn maker_claim_held(
    w: &World,
    store: &Store,
    maker: &Maker,
    taker: &Taker,
    why: &str,
) -> (String, u32) {
    let (tid, mid) = to_maker_lock_confirmed(w, maker, taker).await;
    assert_eq!(
        tstep(taker, maker, &tid, &mid).await.unwrap(),
        TakerState::Claimed
    );
    w.ctr.mine(1);
    w.divi.hold_spends(Some(why));
    for _ in 0..5 {
        maker.tick().await.unwrap();
        if view(maker, &mid).state == SwapState::TakerClaimed {
            break;
        }
        w.ctr.mine(1);
    }
    let v = view(maker, &mid);
    assert_eq!(v.state, SwapState::TakerClaimed);
    assert!(
        v.last_error.as_deref().is_some_and(|e| e.contains(why)),
        "{v:?}"
    );
    assert!(store
        .get_maker_swap(&mid)
        .unwrap()
        .unwrap()
        .taker_leg_claim
        .is_none());
    (mid.clone(), taker_locktime(&v))
}

/// The maker's held claim of the taker leg at each time [`around_the_old_deadline`]: still
/// in `state`, nothing signed, nothing built on the primary alone.
async fn maker_claim_keeps_holding(
    w: &World,
    store: &Store,
    maker: &Maker,
    mid: &str,
    state: SwapState,
    why: &str,
) {
    let locktime = taker_locktime(&view(maker, mid));
    for (at, human) in around_the_old_deadline(locktime, divi_margin()) {
        set_mtp(&w.divi, at);
        maker.tick().await.unwrap();
        let v = view(maker, mid);
        assert_eq!(v.state, state, "{why} at {at}");
        assert_last_error(v.last_error.as_deref(), why, human);
        assert!(
            store
                .get_maker_swap(mid)
                .unwrap()
                .unwrap()
                .taker_leg_claim
                .is_none(),
            "{why} at {at}: claim built"
        );
        assert!(
            w.divi.primary_only_builds().is_empty(),
            "{why} at {at}: claim built on the primary alone"
        );
    }
    // Retried every tick: the source back, the claim goes out and the swap completes.
    w.divi.hold_spends(None);
    maker.tick().await.unwrap();
    assert_eq!(view(maker, mid).state, SwapState::MakerClaimed, "{why}");
    w.divi.mine(1);
    maker.tick().await.unwrap();
    assert_eq!(view(maker, mid).state, SwapState::Done, "{why}");
    assert!(w.divi.primary_only_builds().is_empty());
}

#[tokio::test]
async fn a_held_maker_claim_keeps_holding_past_its_old_deadline() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (mid, _) = maker_claim_held(&w, &store, &maker, &taker, why).await;
        maker_claim_keeps_holding(&w, &store, &maker, &mid, SwapState::TakerClaimed, why).await;
    }
}

#[tokio::test]
async fn a_held_maker_re_sign_after_a_refusal_keeps_holding_past_its_old_deadline() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed
        );
        w.ctr.mine(1);
        for _ in 0..5 {
            maker.tick().await.unwrap();
            if view(&maker, &mid).state == SwapState::MakerClaimed {
                break;
            }
            w.ctr.mine(1);
        }
        assert_eq!(view(&maker, &mid).state, SwapState::MakerClaimed);
        // The claim falls out of the mempool and its resend is refused for good: forgotten.
        let first = store
            .get_maker_swap(&mid)
            .unwrap()
            .unwrap()
            .taker_leg_claim
            .unwrap();
        assert!(w.divi.drop_from_mempool(&first.txid));
        w.divi.reject_next_broadcast();
        maker.tick().await.unwrap();
        assert!(store
            .get_maker_swap(&mid)
            .unwrap()
            .unwrap()
            .taker_leg_claim
            .is_none());

        w.divi.hold_spends(Some(why));
        maker.tick().await.unwrap();
        let v = view(&maker, &mid);
        assert_last_error(v.last_error.as_deref(), why, false);
        maker_claim_keeps_holding(&w, &store, &maker, &mid, SwapState::MakerClaimed, why).await;
    }
}

// ---- H5/H6: refunds ----------------------------------------------------------------------

#[tokio::test]
async fn a_held_taker_refund_is_built_on_the_primary_alone_one_margin_after_the_locktime() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        // The taker locks; the maker never does.
        let q = maker.quote("o", 1_000_000).await.unwrap();
        let (tid, req) = taker.prepare(&q).await.unwrap();
        let v = maker.accept(req).await.unwrap();
        taker.accepted(&tid, &v).await.unwrap();
        taker.lock(&tid).await.unwrap();
        assert_eq!(taker.step(&tid, None).await.unwrap(), TakerState::Locked);
        w.divi.mine(3);
        let locktime = v.taker_leg.htlc.locktime;

        w.divi.hold_spends(Some(why));
        set_mtp(&w.divi, locktime + 1);
        assert_held(taker.step(&tid, None).await, why);
        assert_eq!(
            store.get_taker_swap(&tid).unwrap().unwrap().state,
            TakerState::Refunded
        );
        set_mtp(&w.divi, locktime + divi_margin() - 1);
        assert_held(taker.step(&tid, None).await, why);
        assert!(
            w.divi.primary_only_builds().is_empty(),
            "{why}: acted early"
        );

        w.divi.advance_time(1);
        assert_eq!(
            taker.step(&tid, None).await.unwrap(),
            TakerState::Refunded,
            "{why}"
        );
        assert_eq!(w.divi.primary_only_builds(), [TxKind::Refund], "{why}");
        w.divi.mine(1);
        assert_eq!(taker.step(&tid, None).await.unwrap(), TakerState::Done);
        assert!(w.divi.balance(&w.tdivi.pubkey()).0 > FUNDS - 1_000_000);
    }
}

#[tokio::test]
async fn a_held_maker_refund_is_built_on_the_primary_alone_one_margin_after_the_locktime() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (_tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        let locktime = maker_locktime(&view(&maker, &mid));

        w.ctr.hold_spends(Some(why));
        set_mtp(&w.ctr, locktime + 1);
        maker.tick().await.unwrap();
        let v = view(&maker, &mid);
        assert_eq!(v.state, SwapState::MakerRefundable, "{why}");
        assert!(
            v.last_error.as_deref().is_some_and(|e| e.contains(why)),
            "{v:?}"
        );
        set_mtp(&w.ctr, locktime + ctr_margin(&w) - 1);
        maker.tick().await.unwrap();
        assert!(w.ctr.primary_only_builds().is_empty(), "{why}: acted early");

        w.ctr.advance_time(1);
        maker.tick().await.unwrap();
        assert_eq!(w.ctr.primary_only_builds(), [TxKind::Refund], "{why}");
        w.ctr.mine(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::Done, "{why}");
        assert!(w.ctr.balance(&w.mctr.pubkey()).0 > FUNDS - 1_000_000);
    }
}

// ---- H5/H6: a refund behind a held spend read (`find_spend`) -----------------------------

/// The taker's refund reads the spend of its own lock first (was it claimed with our
/// preimage?). A source that disagrees on that read holds it like a held refund: read on the
/// primary alone one claim margin after the locktime, then refunded.
#[tokio::test]
async fn a_taker_refund_behind_a_held_spend_read_reads_the_primary_alone_one_margin_after() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        // The taker locks; the maker never does.
        let q = maker.quote("o", 1_000_000).await.unwrap();
        let (tid, req) = taker.prepare(&q).await.unwrap();
        let v = maker.accept(req).await.unwrap();
        taker.accepted(&tid, &v).await.unwrap();
        taker.lock(&tid).await.unwrap();
        assert_eq!(taker.step(&tid, None).await.unwrap(), TakerState::Locked);
        w.divi.mine(3);
        let locktime = v.taker_leg.htlc.locktime;

        w.divi.hold_reads(Some(why));
        set_mtp(&w.divi, locktime + 1);
        assert_held(taker.step(&tid, None).await, why);
        set_mtp(&w.divi, locktime + divi_margin() - 1);
        assert_held(taker.step(&tid, None).await, why);
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.taker_leg_refund.is_none(), "{why}: refunded early");
        assert_eq!(w.divi.primary_only_reads(), 0, "{why}: read early");

        w.divi.advance_time(1);
        assert_eq!(
            taker.step(&tid, None).await.unwrap(),
            TakerState::Refunded,
            "{why}"
        );
        assert!(w.divi.primary_only_reads() > 0, "{why}");
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.taker_leg_refund.is_some(), "{why}: no refund");
        assert!(rec
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains(why) && e.contains("primary source alone")));
        w.divi.mine(1);
        assert_eq!(taker.step(&tid, None).await.unwrap(), TakerState::Done);
        assert!(w.divi.balance(&w.tdivi.pubkey()).0 > FUNDS - 1_000_000);
    }
}

/// The maker's refund reads the spend of its lock first (did a late claim reveal the
/// preimage?). A source that disagrees on that read holds it until one claim margin after
/// the locktime; then the primary's answer is used and the refund goes out.
#[tokio::test]
async fn a_maker_refund_behind_a_held_spend_read_reads_the_primary_alone_one_margin_after() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (_tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        let locktime = maker_locktime(&view(&maker, &mid));

        w.ctr.hold_reads(Some(why));
        set_mtp(&w.ctr, locktime + 1);
        maker.tick().await.unwrap();
        set_mtp(&w.ctr, locktime + ctr_margin(&w) - 1);
        maker.tick().await.unwrap();
        let v = view(&maker, &mid);
        assert!(
            v.last_error.as_deref().is_some_and(|e| e.contains(why)),
            "{v:?}"
        );
        assert!(
            store
                .get_maker_swap(&mid)
                .unwrap()
                .unwrap()
                .maker_leg_refund
                .is_none(),
            "{why}: refunded early"
        );
        assert_eq!(w.ctr.primary_only_reads(), 0, "{why}: read early");

        w.ctr.advance_time(1);
        maker.tick().await.unwrap();
        assert!(w.ctr.primary_only_reads() > 0, "{why}");
        assert!(
            store
                .get_maker_swap(&mid)
                .unwrap()
                .unwrap()
                .maker_leg_refund
                .is_some(),
            "{why}: no refund at the deadline"
        );
        assert!(w.ctr.primary_only_builds().is_empty(), "built normally");
        w.ctr.mine(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::Done, "{why}");
        assert!(w.ctr.balance(&w.mctr.pubkey()).0 > FUNDS - 1_000_000);
    }
}

/// A read a refund does not wait on stays held with no deadline: before the locktime the
/// maker watching its lock for a claim keeps retrying and never reads on the primary alone.
#[tokio::test]
async fn a_held_spend_read_before_the_locktime_is_never_read_on_the_primary_alone() {
    for (ctr, why) in CASES {
        let w = world_on(ctr);
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (_tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        let locktime = maker_locktime(&view(&maker, &mid));
        w.ctr.hold_reads(Some(why));
        set_mtp(&w.ctr, locktime - 1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::MakerLockConfirmed);
        assert_eq!(w.ctr.primary_only_reads(), 0, "{why}");
    }
}
