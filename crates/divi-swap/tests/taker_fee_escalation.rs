// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Fee escalation of a maker-leg claim that is not confirming. On a chain that relays
//! replacements (BTC) the taker re-signs the claim at rising feerates and the new version
//! replaces the old one; on a chain that does not but mines by ancestor package (LTC) it
//! adds CPFP children; both climb only inside the escalation window and never past the
//! cap. Where the backend cannot bump, or escalation is off, the claim is resent unchanged.

use divi_swap::api::{Direction, Offer, SwapView};
use divi_swap::mock::{MockBackend, MockChain, MOCK_FEERATE, MOCK_VSIZE};
use divi_swap::{
    Amount, Chain, ChainBackend, FeeBump, FeeEscalation, Maker, Profile, Store, SwapConfig,
    SwapState, Taker, TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;

struct World {
    divi: MockChain,
    ml: MockChain,
    mdivi: MockBackend,
    mml: MockBackend,
    tdivi: MockBackend,
    tml: MockBackend,
    chain: Chain,
}

/// The taker pays DIVI, so the maker leg (the one the taker claims) is on `chain`.
fn world(chain: Chain, block_secs: u32, bump: FeeBump) -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let ml = MockChain::new(chain, T0, block_secs);
    ml.set_fee_bump(bump);
    World {
        mdivi: divi.backend(1, Amount(FUNDS)),
        mml: ml.backend(2, Amount(FUNDS)),
        tdivi: divi.backend(3, Amount(FUNDS)),
        tml: ml.backend(4, Amount(FUNDS)),
        divi,
        ml,
        chain,
    }
}

fn taker(w: &World, store: &Store) -> Taker {
    Taker::new(
        Arc::new(w.tdivi.clone()),
        Arc::new(w.tml.clone()),
        store.clone(),
    )
}

fn maker(w: &World, store: &Store) -> Maker {
    Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.mdivi.clone()),
        Arc::new(w.mml.clone()),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysDivi,
            counter_chain: w.chain,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap()
}

/// Run the swap to the taker's first claim (broadcast, unconfirmed), returning the taker's
/// local id and the maker's view.
async fn to_claimed(w: &World, maker: &Maker, taker: &Taker) -> (String, SwapView) {
    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    for _ in 0..20 {
        w.divi.mine(1);
        w.ml.mine(1);
        maker.tick().await.unwrap();
        if maker.view(&mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    let view = maker.view(&mid).unwrap().unwrap();
    assert_eq!(view.state, SwapState::MakerLockConfirmed);
    let mut state = TakerState::Locked;
    for _ in 0..3 {
        state = taker.step(&tid, Some(&view)).await.unwrap();
        if state == TakerState::Claimed {
            break;
        }
    }
    assert_eq!(state, TakerState::Claimed);
    (tid, view)
}

fn locktime(view: &SwapView) -> u32 {
    view.maker_leg.as_ref().unwrap().htlc.locktime
}

/// One step per `step_secs` of maker-leg MTP with nothing mined, from now to the locktime.
/// Returns the claim feerate after each step, with the seconds left.
async fn ride_to_locktime(
    w: &World,
    store: &Store,
    taker: &Taker,
    tid: &str,
    view: &SwapView,
    step_secs: u32,
) -> Vec<(i64, u64)> {
    let mut seen = Vec::new();
    while w.ml.mtp() + step_secs < locktime(view) {
        w.ml.advance_time(step_secs);
        let _ = taker.step(tid, Some(view)).await;
        let rec = store.get_taker_swap(tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Claimed);
        let left = i64::from(locktime(view)) - i64::from(w.ml.mtp());
        seen.push((
            left,
            rec.claim_feerate
                .expect("a bumpable claim records its feerate"),
        ));
    }
    seen
}

/// The claim's feerate stays at `base` until the window, climbs to at most the fixed cap
/// until `cap_secs_left`, and, still unconfirmed after that, climbs past the cap towards the
/// post-leak ceiling (a share of the 1M sat leg; each claim and child is `MOCK_VSIZE`).
fn assert_climbs_inside_the_window(seen: &[(i64, u64)], esc: FeeEscalation, base: u64) {
    let cap = esc.cap(base);
    let mut last = base;
    for &(left, rate) in seen {
        assert!(rate >= last, "never falls: {seen:?}");
        if left >= i64::from(esc.cap_secs_left) {
            assert!(
                rate <= cap,
                "the fixed cap {cap} holds until the cap point: {seen:?}"
            );
        }
        assert!(
            rate * MOCK_VSIZE < 1_000_000,
            "never the whole leg: {seen:?}"
        );
        if left >= i64::from(esc.start_secs_left) {
            assert_eq!(rate, base, "no bump before the window: {seen:?}");
        }
        last = rate;
    }
    assert!(last > cap, "past the cap {cap} by the locktime: {seen:?}");
}

#[tokio::test]
async fn btc_claim_is_replaced_at_rising_feerates_up_to_the_cap_and_past_it_late() {
    let w = world(Chain::Btc, 600, FeeBump::Rbf);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.claim_base_feerate, Some(MOCK_FEERATE));
    let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
    let first = rec.maker_leg_claim.clone().unwrap();
    assert_eq!(w.ml.spender(&at), Some(first.txid));

    let esc = FeeEscalation::builtin(Chain::Btc).unwrap();
    let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 300).await;
    assert_climbs_inside_the_window(&seen, esc, MOCK_FEERATE);

    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let claim = rec.maker_leg_claim.clone().unwrap();
    assert!(rec.claim_replaced.len() >= 3, "{:?}", rec.claim_replaced);
    assert!(rec.claim_children.is_empty());
    assert_eq!(rec.claim_replaced[0], (first, MOCK_FEERATE));
    for pair in rec.claim_replaced.windows(2) {
        assert!(pair[1].1 > pair[0].1, "each replacement pays more");
    }
    assert_eq!(
        w.ml.spender(&at),
        Some(claim.txid),
        "the latest version won"
    );
    assert_eq!(w.ml.feerate_of(&claim.txid), rec.claim_feerate);
    for (old, _) in &rec.claim_replaced {
        assert_eq!(w.ml.feerate_of(&old.txid), None, "evicted");
    }
    assert_eq!(w.ml.tx_counts(&at).claims, 1);

    w.ml.mine(1);
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
    let paid = rec.claim_feerate.unwrap() * MOCK_VSIZE;
    assert_eq!(
        w.ml.balance(&w.tml.pubkey()).0,
        FUNDS + 1_000_000 - paid,
        "only the winning version's fee is paid"
    );
}

#[tokio::test]
async fn ltc_claim_gets_cpfp_children_at_rising_package_feerates() {
    let w = world(Chain::Ltc, 150, FeeBump::Cpfp);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let esc = FeeEscalation::builtin(Chain::Ltc).unwrap();
    let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 150).await;
    assert_climbs_inside_the_window(&seen, esc, MOCK_FEERATE);

    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let claim = rec.maker_leg_claim.clone().unwrap();
    assert!(rec.claim_replaced.is_empty(), "LTC relays no replacement");
    let n = rec.claim_children.len();
    assert!((3..=18).contains(&n), "{n} children");
    // The package (claim and every child) pays at least the recorded feerate.
    let mut fee = w.ml.feerate_of(&claim.txid).unwrap() * MOCK_VSIZE;
    for child in &rec.claim_children {
        fee += w.ml.feerate_of(&child.txid).expect("child relayed") * MOCK_VSIZE;
    }
    let vsize = MOCK_VSIZE * (n as u64 + 1);
    assert!(
        fee >= rec.claim_feerate.unwrap() * vsize - MOCK_VSIZE,
        "{fee} over {vsize}"
    );
    // The post-leak ceiling bounds the fee of the whole package, not just the child.
    assert!(fee < 1_000_000, "{fee} for the package");

    w.ml.mine(1);
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
}

#[tokio::test]
async fn nothing_is_bumped_where_the_backend_cannot_or_escalation_is_off() {
    for off in [false, true] {
        let bump = if off { FeeBump::Rbf } else { FeeBump::None };
        let w = world(Chain::Btc, 600, bump);
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store);
        let mut taker = taker(&w, &store);
        if off {
            taker = taker.with_fee_escalation(Chain::Btc, None);
        }
        let (tid, view) = to_claimed(&w, &maker, &taker).await;
        let first = store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .maker_leg_claim
            .unwrap();
        while w.ml.mtp() + 300 < locktime(&view) {
            w.ml.advance_time(300);
            let _ = taker.step(&tid, Some(&view)).await;
        }
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.maker_leg_claim, Some(first), "off={off}");
        assert!(rec.claim_replaced.is_empty() && rec.claim_children.is_empty());
        assert_eq!(rec.claim_feerate, None, "nothing to escalate from");
    }
}

#[tokio::test]
async fn a_refused_rebroadcast_keeps_the_version_the_mempool_holds() {
    let w = world(Chain::Btc, 600, FeeBump::Rbf);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
    let esc = FeeEscalation::builtin(Chain::Btc).unwrap();
    // Into the window: one bump.
    w.ml.advance_time(locktime(&view) - w.ml.mtp() - esc.start_secs_left + 900);
    taker.step(&tid, Some(&view)).await.unwrap();
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.claim_replaced.len(), 1);
    let bumped = rec.maker_leg_claim.clone().unwrap();
    assert_eq!(w.ml.spender(&at), Some(bumped.txid));

    // A refused rebroadcast of the bumped claim, which the mempool holds: kept as is
    // (before the fix the taker went back to the replaced claim, which then conflicted
    // with the bumped one, was forgotten, re-signed at the base feerate and refused again,
    // so the claim never climbed again).
    w.ml.reject_next_broadcast();
    assert!(taker.step(&tid, Some(&view)).await.is_err());
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.state, TakerState::Claimed);
    assert_eq!(rec.maker_leg_claim.as_ref(), Some(&bumped));
    assert_eq!(rec.claim_replaced.len(), 1);

    // And it keeps climbing.
    w.ml.advance_time(1800);
    taker.step(&tid, Some(&view)).await.unwrap();
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.claim_replaced.len(), 2);
    assert!(rec.claim_feerate.unwrap() > rec.claim_replaced[1].1);
    assert_eq!(w.ml.spender(&at), rec.maker_leg_claim.map(|c| c.txid));
}

#[tokio::test]
async fn a_replacement_the_chain_never_took_falls_back_to_the_one_it_holds() {
    let w = world(Chain::Btc, 600, FeeBump::Rbf);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
    let first = store
        .get_taker_swap(&tid)
        .unwrap()
        .unwrap()
        .maker_leg_claim
        .unwrap();
    let esc = FeeEscalation::builtin(Chain::Btc).unwrap();
    w.ml.advance_time(locktime(&view) - w.ml.mtp() - esc.start_secs_left + 900);
    taker.step(&tid, Some(&view)).await.unwrap();
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let bumped = rec.maker_leg_claim.clone().unwrap();
    assert_ne!(bumped.txid, first.txid);
    // As if the bump never reached the chain (lost by the relay) while the first claim
    // stayed: the chain holds the first, and the bumped one is refused.
    w.ml.forget(&bumped.txid);
    w.tml.broadcast(&first).await.unwrap();
    assert_eq!(w.ml.spender(&at), Some(first.txid));
    w.ml.reject_next_broadcast();

    assert!(taker.step(&tid, Some(&view)).await.is_err());
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.maker_leg_claim.as_ref(), Some(&first));
    assert_eq!(rec.claim_feerate, Some(MOCK_FEERATE));
    assert!(rec.claim_replaced.is_empty());
}
