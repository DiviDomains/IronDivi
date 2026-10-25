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
//! bumps through a CPFP child, adding one per bump (or, switched on, replacing the child
//! where the node takes that and adding one where it does not); both climb only inside the escalation window, never past the
//! cap until the cap point and never past the post-leak ceiling. Where the backend cannot
//! bump, or escalation is off, the claim is resent unchanged.

use divi_swap::api::{Direction, Offer, SwapView};
use divi_swap::mock::{MockBackend, MockChain, MOCK_FEERATE, MOCK_VSIZE};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, FeeBump, FeeEscalation, Maker, Profile, Store,
    SwapConfig, SwapState, Taker, TakerState,
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

/// Each step's package (`vsize` vbytes at the recorded feerate) pays at most the post-leak
/// ceiling for the seconds left then (taken with no dust and no step, so a little above
/// the taker's own).
fn assert_under_the_ceiling(seen: &[(i64, u64)], chain: Chain, vsize: u64) {
    let window = ClaimDeadline::builtin(chain).margin_secs();
    for &(left, rate) in seen {
        let ceiling = FeeEscalation::ceiling_fee(1_000_000, 0, 0, left, window);
        assert!(
            rate * vsize <= ceiling,
            "{rate}/vB over {vsize} vB at {left}s left passes the ceiling {ceiling}: {seen:?}"
        );
    }
}

/// How many times the feerate rose with fewer than `cap_secs_left` seconds left.
fn bumps_past_the_cap_point(seen: &[(i64, u64)], esc: FeeEscalation) -> usize {
    seen.windows(2)
        .filter(|w| w[1].0 < i64::from(esc.cap_secs_left) && w[1].1 > w[0].1)
        .count()
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
    assert_under_the_ceiling(&seen, Chain::Btc, MOCK_VSIZE);

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
async fn ltc_claim_replaces_its_one_child_and_steps_past_the_cap_at_most_four_times() {
    let w = world(Chain::Ltc, 150, FeeBump::Cpfp);
    w.ml.set_child_replacement(true);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let esc = FeeEscalation {
        replace_cpfp_child: true,
        ..FeeEscalation::builtin(Chain::Ltc).unwrap()
    };
    let taker = taker(&w, &store).with_fee_escalation(Chain::Ltc, Some(esc));
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 150).await;
    assert_climbs_inside_the_window(&seen, esc, MOCK_FEERATE);
    assert_under_the_ceiling(&seen, Chain::Ltc, 2 * MOCK_VSIZE);
    assert!(
        w.ml.longest_unconfirmed_chain() <= 2,
        "the package stays claim and one child: {} deep, {seen:?}",
        w.ml.longest_unconfirmed_chain()
    );
    let late = bumps_past_the_cap_point(&seen, esc);
    assert!(
        (1..=4).contains(&late),
        "{late} bumps past the cap point: {seen:?}"
    );

    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let claim = rec.maker_leg_claim.clone().unwrap();
    assert!(
        rec.claim_replaced.is_empty(),
        "the claim itself is never replaced"
    );
    assert_eq!(rec.claim_children.len(), 1, "each bump replaced the child");
    let child = &rec.claim_children[0];
    let fee = (w.ml.feerate_of(&claim.txid).unwrap()
        + w.ml.feerate_of(&child.txid).expect("child relayed"))
        * MOCK_VSIZE;
    assert!(fee >= rec.claim_feerate.unwrap() * 2 * MOCK_VSIZE, "{fee}");
    assert!(fee < 1_000_000, "{fee} for the package");

    w.ml.mine(1);
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
}

#[tokio::test]
async fn ltc_claim_adds_a_child_per_bump_where_the_node_takes_no_child_replacement() {
    // Switched on, each replacement is refused and a child is added instead.
    for replace in [false, true] {
        let w = world(Chain::Ltc, 150, FeeBump::Cpfp);
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store);
        let esc = FeeEscalation {
            replace_cpfp_child: replace,
            ..FeeEscalation::builtin(Chain::Ltc).unwrap()
        };
        let taker = taker(&w, &store).with_fee_escalation(Chain::Ltc, Some(esc));
        let (tid, view) = to_claimed(&w, &maker, &taker).await;
        let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 150).await;
        assert_climbs_inside_the_window(&seen, esc, MOCK_FEERATE);
        let late = bumps_past_the_cap_point(&seen, esc);
        assert!(
            (1..=4).contains(&late),
            "replace={replace}: {late} bumps past the cap point: {seen:?}"
        );

        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let claim = rec.maker_leg_claim.clone().unwrap();
        assert!(rec.claim_replaced.is_empty(), "LTC relays no replacement");
        let n = rec.claim_children.len();
        assert!((3..=12).contains(&n), "replace={replace}: {n} children");
        assert_eq!(w.ml.longest_unconfirmed_chain(), n as u64 + 1);
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
        let left = seen.last().unwrap().0;
        let window = ClaimDeadline::builtin(Chain::Ltc).margin_secs();
        assert!(
            fee <= FeeEscalation::ceiling_fee(1_000_000, 0, 0, left, window),
            "{fee} for the package"
        );

        w.ml.mine(1);
        assert_eq!(
            taker.step(&tid, Some(&view)).await.unwrap(),
            TakerState::Done
        );
    }
}

#[tokio::test]
async fn ltc_claim_keeps_climbing_after_a_crash_between_a_bumps_write_ahead_and_its_broadcast() {
    // The built-in LTC schedule adds a child per bump rather than replacing one.
    assert!(
        !FeeEscalation::builtin(Chain::Ltc)
            .unwrap()
            .replace_cpfp_child
    );
    let w = world(Chain::Ltc, 150, FeeBump::Cpfp);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let (tid, view, held) = {
        let taker = taker(&w, &store);
        let (tid, view) = to_claimed(&w, &maker, &taker).await;
        // Ride to the first child, which the node holds.
        while store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .claim_children
            .is_empty()
        {
            assert!(w.ml.mtp() + 150 < locktime(&view));
            w.ml.advance_time(150);
            taker.step(&tid, Some(&view)).await.unwrap();
        }
        let held = store.get_taker_swap(&tid).unwrap().unwrap().claim_children;
        assert!(held.iter().all(|c| w.ml.feerate_of(&c.txid).is_some()));
        // The next bump is written ahead and never sent: the process dies in between.
        w.ml.lose_next_new_broadcast();
        loop {
            assert!(w.ml.mtp() + 150 < locktime(&view));
            w.ml.advance_time(150);
            let _ = taker.step(&tid, Some(&view)).await;
            let rec = store.get_taker_swap(&tid).unwrap().unwrap();
            if rec
                .claim_children
                .iter()
                .any(|c| w.ml.feerate_of(&c.txid).is_none())
            {
                break;
            }
        }
        (tid, view, held)
    };
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let at_crash = rec.claim_feerate.unwrap();

    // Restart on the same store; the climb resumes on top of the child the node holds.
    let taker = taker(&w, &store);
    let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 150).await;
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let after = rec.claim_feerate.unwrap();
    assert!(
        after > at_crash,
        "{after} after the restart, {at_crash} at the crash: {seen:?}"
    );
    let n = rec.claim_children.len();
    assert!(
        n >= held.len() + 2,
        "{n} children, {} before the crash: {seen:?}",
        held.len()
    );
    for (i, child) in rec.claim_children.iter().enumerate() {
        assert!(
            w.ml.feerate_of(&child.txid).is_some(),
            "child {i} of {n} not relayed"
        );
    }
    for child in &held {
        assert!(
            rec.claim_children.contains(child),
            "the held child stays in the package"
        );
    }
    assert_eq!(w.ml.longest_unconfirmed_chain(), n as u64 + 1);

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

/// Geth's replacement floor (`core/txpool/legacypool/list.go`, `list.Add`, default
/// `PriceBump` 10): strictly more, and at least `old * 110 / 100`.
fn geth_floor(old: u64) -> u64 {
    (old * 110 / 100).max(old + 1)
}

/// An EVM (USDC) claim stuck in the mempool is replaced by re-signing the same call at the
/// same nonce with higher fees (the mock's same-nonce conflict is the HTLC outpoint): each
/// version clears geth's price bump over the one it replaces, the feerate climbs only
/// inside the window, and the fixed cap holds to the locktime (no post-leak ceiling: the fee
/// is paid in ETH, the leg is USDC).
#[tokio::test]
async fn usdc_claim_is_replaced_at_the_same_nonce_up_to_the_fixed_cap() {
    let w = world(Chain::Usdc, 12, FeeBump::SameNonce);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.claim_base_feerate, Some(MOCK_FEERATE));
    let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
    let first = rec.maker_leg_claim.clone().unwrap();

    let esc = FeeEscalation::builtin(Chain::Usdc).expect("USDC claims escalate");
    let cap = esc.cap(MOCK_FEERATE);
    let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 300).await;
    let mut last = MOCK_FEERATE;
    for &(left, rate) in &seen {
        assert!(rate >= last, "never falls: {seen:?}");
        assert!(
            rate <= cap,
            "the fixed cap {cap} holds to the end: {seen:?}"
        );
        if left >= i64::from(esc.start_secs_left) {
            assert_eq!(rate, MOCK_FEERATE, "no bump before the window: {seen:?}");
        }
        last = rate;
    }
    assert_eq!(last, cap, "at the cap by the locktime: {seen:?}");

    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let claim = rec.maker_leg_claim.clone().unwrap();
    assert!(rec.claim_replaced.len() >= 3, "{:?}", rec.claim_replaced);
    assert!(rec.claim_children.is_empty());
    assert_eq!(rec.claim_replaced[0], (first, MOCK_FEERATE));
    let mut rates: Vec<u64> = rec.claim_replaced.iter().map(|(_, f)| *f).collect();
    rates.push(rec.claim_feerate.unwrap());
    for pair in rates.windows(2) {
        assert!(
            pair[1] >= geth_floor(pair[0]),
            "under geth's bump: {rates:?}"
        );
    }
    assert_eq!(
        w.ml.spender(&at),
        Some(claim.txid),
        "the latest version won"
    );
    assert_eq!(w.ml.feerate_of(&claim.txid), rec.claim_feerate);
    assert_eq!(w.ml.tx_counts(&at).claims, 1);

    w.ml.mine(1);
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
}

/// Into the window with one same-nonce replacement sent: returns the first claim and the
/// replacement.
async fn usdc_bumped_once(
    w: &World,
    store: &Store,
    taker: &Taker,
    tid: &str,
    view: &SwapView,
) -> (divi_swap::SignedTx, divi_swap::SignedTx) {
    let first = store
        .get_taker_swap(tid)
        .unwrap()
        .unwrap()
        .maker_leg_claim
        .unwrap();
    let esc = FeeEscalation::builtin(Chain::Usdc).unwrap();
    w.ml.advance_time(locktime(view) - w.ml.mtp() - esc.start_secs_left + 900);
    taker.step(tid, Some(view)).await.unwrap();
    let rec = store.get_taker_swap(tid).unwrap().unwrap();
    assert_eq!(rec.claim_replaced.len(), 1, "one replacement");
    let bumped = rec.maker_leg_claim.unwrap();
    assert_ne!(bumped.txid, first.txid);
    (first, bumped)
}

/// The original claim is mined while its replacement is in flight (the replacement never
/// reached the miner, and on an EVM node it is now refused: "nonce too low"). The swap is
/// done: the original paid out.
#[tokio::test]
async fn usdc_original_mined_while_its_replacement_is_in_flight_is_success() {
    let w = world(Chain::Usdc, 12, FeeBump::SameNonce);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
    let (first, bumped) = usdc_bumped_once(&w, &store, &taker, &tid, &view).await;
    w.ml.forget(&bumped.txid);
    w.tml.broadcast(&first).await.unwrap();
    w.ml.mine(1);
    assert_eq!(w.ml.spender(&at), Some(first.txid));
    // The replacement is now refused for good: the slot is taken by the mined original.
    assert!(w.tml.broadcast(&bumped).await.is_err());

    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
    assert!(w.tml.confirmations(&first.txid).await.unwrap() >= Some(1));
    assert_eq!(w.ml.tx_counts(&at).claims, 1, "only the original");
}

/// A node with a stricter price bump than geth's default refuses the replacement as
/// "replacement transaction underpriced". The taker goes back to the version the mempool
/// holds, keeps it, and replaces it later at a feerate the node takes.
#[tokio::test]
async fn usdc_underpriced_replacement_falls_back_to_the_held_claim_and_climbs_on() {
    let w = world(Chain::Usdc, 12, FeeBump::SameNonce);
    w.ml.set_price_bump(1000);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
    let (first, bumped) = usdc_bumped_once(&w, &store, &taker, &tid, &view).await;
    assert_eq!(w.ml.spender(&at), Some(first.txid), "refused: underpriced");
    let err = w.tml.broadcast(&bumped).await.unwrap_err();
    assert!(err.to_string().contains("underpriced"), "{err}");

    // Next step: the replacement is refused again and not held; back to the first claim.
    assert!(taker.step(&tid, Some(&view)).await.is_err());
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.state, TakerState::Claimed);
    assert_eq!(rec.maker_leg_claim.as_ref(), Some(&first));
    assert_eq!(rec.claim_feerate, Some(MOCK_FEERATE));
    assert!(rec.claim_replaced.is_empty());

    // The node relaxes to geth's default; the next bump replaces the held claim.
    w.ml.set_price_bump(10);
    w.ml.advance_time(1800);
    taker.step(&tid, Some(&view)).await.unwrap();
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.claim_replaced.len(), 1);
    assert!(rec.claim_feerate.unwrap() >= geth_floor(MOCK_FEERATE));
    assert_eq!(w.ml.spender(&at), rec.maker_leg_claim.map(|c| c.txid));
}

/// The claim's nonce was taken by a different transaction: the claim is refused and the
/// chain holds no version of it. It is re-signed as a fresh claim (a fresh nonce on EVM) at a
/// higher feerate, within the cap, and sent at once.
#[tokio::test]
async fn usdc_claim_whose_nonce_was_taken_is_re_signed_fresh() {
    let w = world(Chain::Usdc, 12, FeeBump::SameNonce);
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
    w.ml.forget(&first.txid);
    w.ml.reject_next_broadcast();

    assert!(taker.step(&tid, Some(&view)).await.is_ok());
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let fresh = rec.maker_leg_claim.clone().unwrap();
    assert_ne!(fresh.txid, first.txid);
    assert_eq!(rec.claim_replaced, vec![(first, MOCK_FEERATE)]);
    let esc = FeeEscalation::builtin(Chain::Usdc).unwrap();
    let rate = rec.claim_feerate.unwrap();
    assert!(
        rate > MOCK_FEERATE && rate <= esc.cap(MOCK_FEERATE),
        "{rate}"
    );
    assert_eq!(w.ml.spender(&at), Some(fresh.txid));

    w.ml.mine(1);
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
}

/// Advance the maker-leg MTP to the first point of the USDC window where the escalation
/// first asks for a bump from the base: a step of 2 wei per gas over 10, which clears geth's
/// default 10% (11) but not a 30% node's (13).
fn usdc_to_the_first_step(w: &World, view: &SwapView, esc: FeeEscalation) {
    let left = (0..esc.start_secs_left)
        .rev()
        .find(|&l| {
            esc.should_bump(
                MOCK_FEERATE,
                MOCK_FEERATE,
                esc.target(MOCK_FEERATE, l.into()),
            )
        })
        .unwrap();
    assert_eq!(esc.target(MOCK_FEERATE, left.into()), 12);
    w.ml.advance_time(locktime(view) - w.ml.mtp() - left);
}

/// A node run with a 30% price bump refuses the first replacement (a 20% step, signed for
/// geth's default 10%) as underpriced, at every try. After two refusals at that step the
/// taker doubles the step (10 + 2·2 = 14), which the node takes: the claim is replaced at
/// its nonce with no time having passed, within the cap, and the refusal count clears.
#[tokio::test]
async fn usdc_claim_replacement_doubles_its_step_after_two_underpriced_refusals() {
    let w = world(Chain::Usdc, 12, FeeBump::SameNonce);
    w.ml.set_price_bump(30);
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
    let esc = FeeEscalation::builtin(Chain::Usdc).unwrap();
    usdc_to_the_first_step(&w, &view, esc);
    let rec_of = || store.get_taker_swap(&tid).unwrap().unwrap();

    for refusals in 1..=2u32 {
        // The step sends the 12 wei version; the node refuses it.
        taker.step(&tid, Some(&view)).await.unwrap();
        let rec = rec_of();
        assert_eq!(rec.claim_feerate, Some(12), "refusals {refusals}");
        assert_eq!(w.ml.spender(&at), Some(first.txid), "underpriced");
        // The next step finds it refused and not held: back to the held claim, counted.
        assert!(taker.step(&tid, Some(&view)).await.is_err());
        let rec = rec_of();
        assert_eq!(rec.maker_leg_claim.as_ref(), Some(&first));
        assert_eq!(rec.claim_feerate, Some(MOCK_FEERATE));
        assert_eq!(rec.claim_underpriced, refusals);
    }

    taker.step(&tid, Some(&view)).await.unwrap();
    let rec = rec_of();
    let claim = rec.maker_leg_claim.clone().unwrap();
    assert_eq!(rec.claim_feerate, Some(14), "the step doubled");
    assert!(rec.claim_feerate.unwrap() <= esc.cap(MOCK_FEERATE));
    assert_eq!(w.ml.spender(&at), Some(claim.txid), "the node took it");
    assert_eq!(rec.claim_replaced, vec![(first, MOCK_FEERATE)]);
    assert_eq!(rec.claim_underpriced, 0, "cleared once taken");

    w.ml.mine(1);
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
}

/// With the chain's price bump configured to the node's 30%, the taker never sends a
/// replacement the node refuses: it keeps the claim while the target is under 30% more and
/// replaces it once the target clears that.
#[tokio::test]
async fn usdc_configured_price_bump_matches_the_node_and_is_never_refused() {
    let w = world(Chain::Usdc, 12, FeeBump::SameNonce);
    w.ml.set_price_bump(30);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let esc = FeeEscalation::builtin(Chain::Usdc)
        .unwrap()
        .with_price_bump(30);
    let taker = taker(&w, &store).with_fee_escalation(Chain::Usdc, Some(esc));
    let (tid, view) = to_claimed(&w, &maker, &taker).await;
    let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
    let first = store
        .get_taker_swap(&tid)
        .unwrap()
        .unwrap()
        .maker_leg_claim
        .unwrap();
    usdc_to_the_first_step(&w, &view, esc);
    taker.step(&tid, Some(&view)).await.unwrap();
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(
        rec.maker_leg_claim.as_ref(),
        Some(&first),
        "12 is under 30%"
    );
    assert!(rec.claim_replaced.is_empty());

    let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 120).await;
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.claim_underpriced, 0, "never refused: {seen:?}");
    let claim = rec.maker_leg_claim.clone().unwrap();
    assert_eq!(w.ml.spender(&at), Some(claim.txid));
    assert_eq!(rec.claim_replaced[0], (first, MOCK_FEERATE));
    let mut rates: Vec<u64> = rec.claim_replaced.iter().map(|(_, f)| *f).collect();
    rates.push(rec.claim_feerate.unwrap());
    for pair in rates.windows(2) {
        assert!(pair[1] * 100 >= pair[0] * 130, "under 30%: {rates:?}");
    }
    // Within the cap, and short of it only by less than one 30% bump (a last step the
    // node would refuse is not sent).
    let last = rec.claim_feerate.unwrap();
    let cap = esc.cap(MOCK_FEERATE);
    assert!(last <= cap && last * 130 / 100 > cap, "{rates:?}");
}

/// No version of a USDC claim ever pays over the cap, whatever the node's price bump and
/// whatever cap the chain is configured with, through every refusal and doubling to the
/// locktime; and wherever the node's floor fits under the cap the claim it holds climbs.
#[tokio::test]
async fn usdc_claim_never_goes_over_the_cap_for_any_node_price_bump() {
    let builtin = FeeEscalation::builtin(Chain::Usdc).unwrap();
    for esc in [builtin, builtin.with_cap_feerate(40)] {
        let cap = esc.cap(MOCK_FEERATE);
        for node_bump in [0u64, 10, 25, 30, 50, 100, 400] {
            let w = world(Chain::Usdc, 12, FeeBump::SameNonce);
            w.ml.set_price_bump(node_bump);
            let store = Store::in_memory().unwrap();
            let maker = maker(&w, &store);
            let taker = taker(&w, &store).with_fee_escalation(Chain::Usdc, Some(esc));
            let (tid, view) = to_claimed(&w, &maker, &taker).await;
            let at = view.maker_leg.as_ref().unwrap().outpoint.unwrap();
            let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 120).await;
            let ctx = format!("cap {cap}, node bump {node_bump}: {seen:?}");
            for &(_, rate) in &seen {
                assert!(rate <= cap, "{ctx}");
            }
            let rec = store.get_taker_swap(&tid).unwrap().unwrap();
            for (_, rate) in &rec.claim_replaced {
                assert!(*rate <= cap, "{ctx}");
            }
            let held = w.ml.spender(&at).expect("a claim is held");
            let held_rate = w.ml.feerate_of(&held).unwrap();
            assert!(held_rate <= cap, "{ctx}");
            let node_floor = (MOCK_FEERATE * (100 + node_bump) / 100).max(MOCK_FEERATE + 1);
            if node_floor <= cap {
                assert!(
                    held_rate >= node_floor,
                    "climbed past the node's floor: {ctx}"
                );
            } else {
                assert_eq!(held_rate, MOCK_FEERATE, "nothing fits under the cap: {ctx}");
            }
        }
    }
}

#[tokio::test]
async fn ltc_claim_replacing_its_child_keeps_climbing_after_a_crash_where_the_node_takes_no_child_replacement(
) {
    // Switched on, on a node that refuses child replacements (the mock's default): the
    // crash loses the replacement after the record dropped the child it replaced.
    let esc = FeeEscalation {
        replace_cpfp_child: true,
        ..FeeEscalation::builtin(Chain::Ltc).unwrap()
    };
    let w = world(Chain::Ltc, 150, FeeBump::Cpfp);
    w.ml.set_child_replacement(false);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let (tid, view, held) = {
        let taker = taker(&w, &store).with_fee_escalation(Chain::Ltc, Some(esc));
        let (tid, view) = to_claimed(&w, &maker, &taker).await;
        // Ride to the first child, which the node holds.
        while store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .claim_children
            .is_empty()
        {
            assert!(w.ml.mtp() + 150 < locktime(&view));
            w.ml.advance_time(150);
            taker.step(&tid, Some(&view)).await.unwrap();
        }
        let held = store.get_taker_swap(&tid).unwrap().unwrap().claim_children;
        assert!(held.iter().all(|c| w.ml.feerate_of(&c.txid).is_some()));
        // The next bump, a replacement of the held child, is written ahead and never sent.
        w.ml.lose_next_new_broadcast();
        loop {
            assert!(w.ml.mtp() + 150 < locktime(&view));
            w.ml.advance_time(150);
            let _ = taker.step(&tid, Some(&view)).await;
            let rec = store.get_taker_swap(&tid).unwrap().unwrap();
            if rec
                .claim_children
                .iter()
                .any(|c| w.ml.feerate_of(&c.txid).is_none())
            {
                break;
            }
        }
        (tid, view, held)
    };
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let at_crash = rec.claim_feerate.unwrap();

    // Restart on the same store; the refused replacement gives the held child back and the
    // climb resumes on top of it.
    let taker = taker(&w, &store).with_fee_escalation(Chain::Ltc, Some(esc));
    let seen = ride_to_locktime(&w, &store, &taker, &tid, &view, 150).await;
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let after = rec.claim_feerate.unwrap();
    assert!(
        after > at_crash,
        "{after} after the restart, {at_crash} at the crash: {seen:?}"
    );
    let n = rec.claim_children.len();
    assert!(
        n >= held.len() + 2,
        "{n} children, {} before the crash: {seen:?}",
        held.len()
    );
    for (i, child) in rec.claim_children.iter().enumerate() {
        assert!(
            w.ml.feerate_of(&child.txid).is_some(),
            "child {i} of {n} not relayed: {seen:?}"
        );
    }
    for child in &held {
        assert!(
            rec.claim_children.contains(child),
            "the held child stays in the package"
        );
    }
    assert_eq!(w.ml.longest_unconfirmed_chain(), n as u64 + 1);

    w.ml.mine(1);
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::Done
    );
}
