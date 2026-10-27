// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A claim or refund a backend holds because its second source is down or disagrees
//! ([`SwapError::Held`]) is held only until a deadline in chain time, never past the
//! locktime it races (`docs/plans/swap-poc/status/engine.md`, EM round):
//!
//! - the taker's first claim (the preimage still secret) is declined at the claim margin and
//!   both legs refund; nothing is ever built on the primary alone for it;
//! - a claim whose preimage is already public (the taker's in `Claimed`, the maker's of the
//!   taker leg) is built on the primary alone ([`ChainBackend::primary_only`]) once less than
//!   the chain's claim margin is left before the counterparty's refund locktime;
//! - a refund is built on the primary alone one claim margin after it became final.
//!
//! Each deadline is checked at its boundary (one second before: held; at it: acted on), for a
//! second source that is down and for one that disagrees. A source back before the deadline
//! resumes the normal path, and without a hold nothing is built on the primary alone.

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
const HOLDS: [&str; 2] = [UNAVAILABLE, DISAGREE];

struct World {
    divi: MockChain,
    btc: MockChain,
    mdivi: MockBackend,
    mbtc: MockBackend,
    tdivi: MockBackend,
    tbtc: MockBackend,
}

fn world() -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let btc = MockChain::new(Chain::Btc, T0, 600);
    World {
        mdivi: divi.backend(1, Amount(FUNDS)),
        mbtc: btc.backend(2, Amount(FUNDS)),
        tdivi: divi.backend(3, Amount(FUNDS)),
        tbtc: btc.backend(4, Amount(FUNDS)),
        divi,
        btc,
    }
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

/// BTC claim margin (the maker leg's chain).
fn btc_margin() -> u32 {
    ClaimDeadline::builtin(Chain::Btc).margin_secs()
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
        w.btc.mine(1);
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
    w.btc.hold_spends(Some(why));
    assert_held(tstep(taker, maker, &tid, &mid).await, why);
    let locktime = maker_locktime(&view(maker, &mid));
    (tid, mid, locktime)
}

// ---- H1: the taker's first claim (secret preimage): decline, never primary-only ----------

#[tokio::test]
async fn a_held_first_claim_declines_at_the_claim_margin_and_both_legs_refund() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid, locktime) = first_claim_held(&w, &maker, &taker, why).await;

        // One second before the deadline (exactly the margin left): still held, not declined.
        set_mtp(&w.btc, locktime - btc_margin());
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.claim_declined.is_none(), "{why}: declined early");
        assert!(rec.last_error.as_deref().is_some_and(|e| e.contains(why)));

        // At the deadline: declined for good, the reason naming the hold and both sources.
        w.btc.advance_time(1);
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
        w.btc.advance_time(4 * 3600);
        w.divi.advance_time(7 * 3600);
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
        assert!(
            !w.btc.primary_only_builds().contains(&TxKind::Claim),
            "{why}: a secret-preimage claim was built on the primary alone"
        );
        assert_eq!(w.btc.primary_only_builds(), [TxKind::Refund]);
        assert_eq!(w.btc.balance(&w.tbtc.pubkey()).0, FUNDS, "taker got no BTC");
    }
}

/// Guard: the second source answering again before the deadline resumes the normal path.
#[tokio::test]
async fn a_second_source_back_before_the_deadline_resumes_the_normal_claim() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid, locktime) = first_claim_held(&w, &maker, &taker, why).await;
        set_mtp(&w.btc, locktime - btc_margin());
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        w.btc.hold_spends(None);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.claim_declined.is_none() && rec.last_error.is_none());
        assert!(w.btc.primary_only_builds().is_empty());
    }
}

/// Guard (opt-in off pinned): without a hold a whole swap completes and nothing is ever
/// built on the primary alone, on either chain.
#[tokio::test]
async fn without_a_hold_nothing_is_built_on_the_primary_alone() {
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
    assert!(w.btc.primary_only_builds().is_empty());
    assert!(w.divi.primary_only_builds().is_empty());
}

// ---- H2: the taker's claim in `Claimed` (preimage public) --------------------------------

#[tokio::test]
async fn a_held_taker_claim_after_the_reveal_is_built_on_the_primary_alone_at_the_margin() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        // The first claim is signed (the preimage is out of our hands) and refused for good:
        // forgotten, to be re-signed on the next step.
        w.btc.reject_next_broadcast();
        assert!(matches!(
            tstep(&taker, &maker, &tid, &mid).await,
            Err(SwapError::Rejected(_))
        ));
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Claimed);
        assert!(rec.maker_leg_claim.is_none());

        w.btc.hold_spends(Some(why));
        let locktime = maker_locktime(&view(&maker, &mid));
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        set_mtp(&w.btc, locktime - btc_margin());
        assert_held(tstep(&taker, &maker, &tid, &mid).await, why);
        assert!(store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .maker_leg_claim
            .is_none());
        assert!(w.btc.primary_only_builds().is_empty(), "{why}: acted early");

        w.btc.advance_time(1);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Claimed,
            "{why}"
        );
        assert_eq!(w.btc.primary_only_builds(), [TxKind::Claim], "{why}");
        let claim = store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .maker_leg_claim
            .expect("signed on the primary alone");
        assert!(w.btc.contains(&claim.txid), "{why}: claim not sent");
        w.btc.mine(1);
        assert_eq!(
            tstep(&taker, &maker, &tid, &mid).await.unwrap(),
            TakerState::Done
        );
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
    w.btc.mine(1);
    w.divi.hold_spends(Some(why));
    for _ in 0..5 {
        maker.tick().await.unwrap();
        if view(maker, &mid).state == SwapState::TakerClaimed {
            break;
        }
        w.btc.mine(1);
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

#[tokio::test]
async fn a_held_maker_claim_is_built_on_the_primary_alone_at_the_margin() {
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (mid, locktime) = maker_claim_held(&w, &store, &maker, &taker, why).await;

        set_mtp(&w.divi, locktime - divi_margin());
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::TakerClaimed, "{why}");
        assert!(
            w.divi.primary_only_builds().is_empty(),
            "{why}: acted early"
        );

        w.divi.advance_time(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::MakerClaimed, "{why}");
        assert_eq!(w.divi.primary_only_builds(), [TxKind::Claim]);
        w.divi.mine(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::Done, "{why}");
    }
}

#[tokio::test]
async fn a_held_maker_re_sign_after_a_refusal_is_built_on_the_primary_alone_at_the_margin() {
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
        assert!(
            v.last_error.as_deref().is_some_and(|e| e.contains(why)),
            "{v:?}"
        );
        let locktime = taker_locktime(&v);
        set_mtp(&w.divi, locktime - divi_margin());
        maker.tick().await.unwrap();
        assert!(
            w.divi.primary_only_builds().is_empty(),
            "{why}: acted early"
        );

        w.divi.advance_time(1);
        maker.tick().await.unwrap();
        assert_eq!(w.divi.primary_only_builds(), [TxKind::Claim], "{why}");
        w.divi.mine(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::Done, "{why}");
    }
}

// ---- H5/H6: refunds ----------------------------------------------------------------------

#[tokio::test]
async fn a_held_taker_refund_is_built_on_the_primary_alone_one_margin_after_the_locktime() {
    for why in HOLDS {
        let w = world();
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
    for why in HOLDS {
        let w = world();
        let store = Store::in_memory().unwrap();
        let (maker, taker) = (maker(&w, &store), taker(&w, &store));
        let (_tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        let locktime = maker_locktime(&view(&maker, &mid));

        w.btc.hold_spends(Some(why));
        set_mtp(&w.btc, locktime + 1);
        maker.tick().await.unwrap();
        let v = view(&maker, &mid);
        assert_eq!(v.state, SwapState::MakerRefundable, "{why}");
        assert!(
            v.last_error.as_deref().is_some_and(|e| e.contains(why)),
            "{v:?}"
        );
        set_mtp(&w.btc, locktime + btc_margin() - 1);
        maker.tick().await.unwrap();
        assert!(w.btc.primary_only_builds().is_empty(), "{why}: acted early");

        w.btc.advance_time(1);
        maker.tick().await.unwrap();
        assert_eq!(w.btc.primary_only_builds(), [TxKind::Refund], "{why}");
        w.btc.mine(1);
        maker.tick().await.unwrap();
        assert_eq!(view(&maker, &mid).state, SwapState::Done, "{why}");
        assert!(w.btc.balance(&w.mbtc.pubkey()).0 > FUNDS - 1_000_000);
    }
}
