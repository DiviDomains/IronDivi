// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The maker states the MTP it locked at (`SwapView::maker_mtp_at_lock`); a taker with a
//! profile floor then checks the maker-leg locktime against `stated_mtp + maker_timeout`
//! exactly, in both directions. A maker that states nothing keeps today's tolerant floor.

use divi_swap::api::{Direction, LegView, Offer, SwapView};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, HtlcParams, Maker, Profile, Store, SwapConfig, SwapState, Taker,
    TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
const PROFILE: Profile = Profile::Testnet;

struct World {
    divi: MockChain,
    ltc: MockChain,
    mdivi: MockBackend,
    mltc: MockBackend,
    tdivi: MockBackend,
    tltc: MockBackend,
    dir: Direction,
}

impl World {
    fn new(dir: Direction) -> World {
        let divi = MockChain::new(Chain::Divi, T0, 60);
        let ltc = MockChain::new(Chain::Ltc, T0, 150);
        World {
            mdivi: divi.backend(1, Amount(FUNDS)),
            mltc: ltc.backend(2, Amount(FUNDS)),
            tdivi: divi.backend(3, Amount(FUNDS)),
            tltc: ltc.backend(4, Amount(FUNDS)),
            divi,
            ltc,
            dir,
        }
    }
    fn maker_chain(&self) -> &MockChain {
        match self.dir {
            Direction::TakerPaysBtc => &self.divi,
            Direction::TakerPaysDivi => &self.ltc,
        }
    }
    fn taker_chain(&self) -> &MockChain {
        match self.dir {
            Direction::TakerPaysBtc => &self.ltc,
            Direction::TakerPaysDivi => &self.divi,
        }
    }
    /// The maker's and the taker's backend on the maker-leg chain.
    fn maker_leg_backends(&self) -> (&MockBackend, &MockBackend) {
        match self.dir {
            Direction::TakerPaysBtc => (&self.mdivi, &self.tdivi),
            Direction::TakerPaysDivi => (&self.mltc, &self.tltc),
        }
    }
}

fn maker(w: &World, store: &Store) -> Maker {
    Maker::new(
        SwapConfig::profile(PROFILE),
        Arc::new(w.mdivi.clone()),
        Arc::new(w.mltc.clone()),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: w.dir,
            counter_chain: Chain::Ltc,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap()
}

fn taker(w: &World, store: &Store, floor: Option<Profile>) -> Taker {
    let t = Taker::new(
        Arc::new(w.tdivi.clone()),
        Arc::new(w.tltc.clone()),
        store.clone(),
    );
    match floor {
        Some(p) => t.with_profile_floor(p),
        None => t,
    }
}

/// Quote, accept and lock the taker leg; returns (taker swap id, maker swap id).
async fn through_taker_lock(w: &World, maker: &Maker, taker: &Taker) -> (String, String) {
    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    w.taker_chain().mine(1);
    (tid, mid)
}

/// The maker locks by hand at `locktime`, claiming to have read `stated_mtp` (or saying
/// nothing); returns the view the taker would fetch.
async fn hand_locked_view(
    w: &World,
    maker: &Maker,
    store: &Store,
    tid: &str,
    mid: &str,
    locktime: u32,
    stated_mtp: Option<u32>,
) -> SwapView {
    let rec = store.get_taker_swap(tid).unwrap().unwrap();
    let (mb, tb) = w.maker_leg_backends();
    let htlc = HtlcParams {
        hash: rec.hash,
        claim_pubkey: tb.pubkey(),
        refund_pubkey: mb.pubkey(),
        locktime,
        script_version: Default::default(),
    };
    let funding = mb
        .build_funding(&htlc, rec.quote.maker_leg_amount())
        .await
        .unwrap();
    mb.broadcast(&funding.tx).await.unwrap();
    w.maker_chain().mine(5);
    w.taker_chain().mine(1);
    let mut view = maker.view(mid).unwrap().unwrap();
    view.maker_leg = Some(LegView {
        htlc,
        amount: funding.amount,
        outpoint: Some(funding.outpoint),
        spend_txid: None,
    });
    view.maker_mtp_at_lock = stated_mtp;
    view
}

fn maker_timeout(store: &Store, tid: &str) -> u32 {
    store
        .get_taker_swap(tid)
        .unwrap()
        .unwrap()
        .quote
        .maker_timeout_secs
}

const BOTH: [Direction; 2] = [Direction::TakerPaysBtc, Direction::TakerPaysDivi];

#[tokio::test]
async fn an_honest_maker_states_its_mtp_and_completes_under_the_exact_floor_in_both_directions() {
    for dir in BOTH {
        let w = World::new(dir);
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store);
        let taker = taker(&w, &store, Some(PROFILE));
        let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
        let mt = maker_timeout(&store, &tid);
        let mut stated_seen = false;
        for _ in 0..60 {
            w.divi.mine(1);
            w.ltc.mine(1);
            maker.tick().await.unwrap();
            let v = maker.view(&mid).unwrap();
            if let Some(leg) = v.as_ref().and_then(|v| v.maker_leg.as_ref()) {
                let stated = v.as_ref().unwrap().maker_mtp_at_lock;
                assert_eq!(stated, Some(leg.htlc.locktime - mt), "{dir:?}");
                stated_seen = true;
            }
            let _ = taker.step(&tid, v.as_ref()).await;
            if store.get_taker_swap(&tid).unwrap().unwrap().state == TakerState::Done
                && maker.view(&mid).unwrap().unwrap().state == SwapState::Done
            {
                break;
            }
        }
        assert!(stated_seen, "{dir:?}: maker stated its MTP");
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Done, "{dir:?}");
        assert!(
            rec.claim_declined.is_none(),
            "{dir:?}: {:?}",
            rec.claim_declined
        );
        assert!(rec.maker_leg_claim.is_some(), "{dir:?}");
    }
}

#[tokio::test]
async fn a_maker_that_states_its_mtp_but_locks_short_inside_the_old_tolerance_is_now_declined() {
    for dir in BOTH {
        let w = World::new(dir);
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store);
        let taker = taker(&w, &store, Some(PROFILE));
        let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
        let mt = maker_timeout(&store, &tid);
        let mtp = w.maker_chain().mtp();
        // 600 s short: inside the 1800 s accept tolerance plus the MTP lag of the tolerant floor.
        let view =
            hand_locked_view(&w, &maker, &store, &tid, &mid, mtp + mt - 600, Some(mtp)).await;

        let st = taker.step(&tid, Some(&view)).await.unwrap();
        assert_eq!(st, TakerState::Locked, "{dir:?}");
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let reason = rec.claim_declined.clone().expect("decision recorded");
        assert!(reason.contains("exact"), "{dir:?}: {reason}");
        assert!(reason.contains(&(mtp + mt - 600).to_string()), "{reason}");
        assert!(reason.contains(&(mtp + mt).to_string()), "{reason}");
        assert!(rec.last_error.is_none());
        assert!(rec.maker_leg_htlc.is_none() && rec.maker_leg_claim.is_none());

        // Decided once: quiet across steps and a restart.
        let taker = self::taker(&w, &store, Some(PROFILE));
        for _ in 0..3 {
            assert_eq!(
                taker.step(&tid, Some(&view)).await.unwrap(),
                TakerState::Locked
            );
            let rec = store.get_taker_swap(&tid).unwrap().unwrap();
            assert_eq!(rec.claim_declined.as_deref(), Some(reason.as_str()));
            assert!(rec.maker_leg_claim.is_none());
        }
    }
}

#[tokio::test]
async fn the_same_short_lock_without_a_stated_mtp_keeps_the_tolerant_floor() {
    for dir in BOTH {
        let w = World::new(dir);
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store);
        let taker = taker(&w, &store, Some(PROFILE));
        let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
        let mt = maker_timeout(&store, &tid);
        let mtp = w.maker_chain().mtp();
        let view = hand_locked_view(&w, &maker, &store, &tid, &mid, mtp + mt - 600, None).await;
        // An old maker: AA's floor passes it exactly as before, so the taker claims.
        let st = taker.step(&tid, Some(&view)).await.unwrap();
        assert_eq!(st, TakerState::Claimed, "{dir:?}");
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert!(rec.claim_declined.is_none() && rec.maker_leg_claim.is_some());
    }
}

#[tokio::test]
async fn the_tolerant_floor_still_declines_a_very_short_lock_in_both_directions() {
    for dir in BOTH {
        for stated in [false, true] {
            let w = World::new(dir);
            let store = Store::in_memory().unwrap();
            let maker = maker(&w, &store);
            let taker = taker(&w, &store, Some(PROFILE));
            let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
            let mtp = w.maker_chain().mtp();
            let view = hand_locked_view(
                &w,
                &maker,
                &store,
                &tid,
                &mid,
                mtp + 3600,
                stated.then_some(mtp),
            )
            .await;
            assert_eq!(
                taker.step(&tid, Some(&view)).await.unwrap(),
                TakerState::Locked
            );
            let rec = store.get_taker_swap(&tid).unwrap().unwrap();
            let reason = rec.claim_declined.expect("decision recorded");
            assert!(reason.contains("floor"), "{dir:?} {stated}: {reason}");
            assert!(rec.maker_leg_claim.is_none());
        }
    }
}

#[tokio::test]
async fn an_implausible_stated_mtp_is_refused_with_a_named_reason() {
    for dir in BOTH {
        for (delta, word) in [
            (-10_000i64, "implausibly low"),
            (10_000, "implausibly high"),
        ] {
            let w = World::new(dir);
            let store = Store::in_memory().unwrap();
            let maker = maker(&w, &store);
            let taker = taker(&w, &store, Some(PROFILE));
            let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
            let mt = maker_timeout(&store, &tid);
            let mtp = w.maker_chain().mtp();
            let stated = (mtp as i64 + delta) as u32;
            // The locktime is consistent with the lie and passes the tolerant floor either way
            // (the high case is longer than honest; the low case is the honest locktime).
            let locktime = if delta > 0 { stated + mt } else { mtp + mt };
            let view =
                hand_locked_view(&w, &maker, &store, &tid, &mid, locktime, Some(stated)).await;
            assert_eq!(
                taker.step(&tid, Some(&view)).await.unwrap(),
                TakerState::Locked
            );
            let rec = store.get_taker_swap(&tid).unwrap().unwrap();
            let reason = rec.claim_declined.expect("decision recorded");
            assert!(reason.contains(word), "{dir:?}: {reason}");
            assert!(reason.contains(&stated.to_string()), "{reason}");
            assert!(rec.maker_leg_claim.is_none());
        }
    }
}

#[tokio::test]
async fn without_a_profile_floor_a_stated_mtp_changes_nothing() {
    for dir in BOTH {
        let w = World::new(dir);
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store);
        let taker = taker(&w, &store, None);
        let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
        let mt = maker_timeout(&store, &tid);
        let mtp = w.maker_chain().mtp();
        let view =
            hand_locked_view(&w, &maker, &store, &tid, &mid, mtp + mt - 600, Some(mtp)).await;
        assert_eq!(
            taker.step(&tid, Some(&view)).await.unwrap(),
            TakerState::Claimed,
            "{dir:?}"
        );
    }
}

#[tokio::test]
async fn the_wire_field_is_optional_and_absent_before_the_maker_locks() {
    let w = World::new(Direction::TakerPaysBtc);
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store, Some(PROFILE));
    let (_tid, mid) = through_taker_lock(&w, &maker, &taker).await;
    let before = serde_json::to_value(maker.view(&mid).unwrap().unwrap()).unwrap();
    assert!(before.get("maker_mtp_at_lock").is_none(), "{before}");
    for _ in 0..10 {
        w.divi.mine(1);
        w.ltc.mine(1);
        maker.tick().await.unwrap();
    }
    let mut after = serde_json::to_value(maker.view(&mid).unwrap().unwrap()).unwrap();
    let stated = after["maker_mtp_at_lock"]
        .as_u64()
        .expect("stated after lock");
    assert!(stated > 0);
    // An old maker's JSON (no field) parses to None.
    after
        .as_object_mut()
        .unwrap()
        .shift_remove("maker_mtp_at_lock");
    let old: SwapView = serde_json::from_value(after).unwrap();
    assert_eq!(old.maker_mtp_at_lock, None);
}
