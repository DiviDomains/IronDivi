// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The claim-deadline margin is per chain: on a BTC maker leg (10-minute blocks) the taker
//! does not broadcast its first claim with 40 minutes left before the maker's locktime,
//! although that is more than the 30 minutes a 1-minute-block DIVI leg needs. It records the
//! decision, waits for its own refund, and the swap ends in refunds on both sides, from both
//! the "first sight of the lock" path and the "lock already verified" path.

use divi_swap::api::{Direction, Offer, SwapView};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, Maker, Profile, Store, SwapConfig, SwapState,
    Taker, TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
/// Left before the BTC maker-leg locktime when the taker looks: above the old global
/// 1800 s margin, below six BTC blocks.
const LEFT_SECS: u32 = 2400;

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

fn maker(w: &World, store: &Store) -> Maker {
    // The taker pays DIVI, so the maker leg (the one the taker claims) is on BTC.
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

/// Run the swap until the maker's BTC lock is confirmed (taker away), returning the taker's
/// local id, the maker's swap id and its view.
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

fn maker_locktime(view: &SwapView) -> u32 {
    view.maker_leg.as_ref().unwrap().htlc.locktime
}

/// Both timelocks pass: the maker refunds its BTC, the taker its DIVI; nobody claimed.
async fn both_refund(w: &World, store: &Store, maker: &Maker, taker: &Taker, tid: &str, mid: &str) {
    w.btc.advance_time(4 * 3600);
    w.divi.advance_time(7 * 3600);
    for _ in 0..20 {
        w.divi.mine(1);
        w.btc.mine(1);
        maker.tick().await.unwrap();
        let v = maker.view(mid).unwrap();
        let _ = taker.step(tid, v.as_ref()).await;
        let t = store.get_taker_swap(tid).unwrap().unwrap().state;
        if t == TakerState::Done && maker.view(mid).unwrap().unwrap().state == SwapState::Done {
            break;
        }
    }
    let rec = store.get_taker_swap(tid).unwrap().unwrap();
    assert_eq!(rec.state, TakerState::Done);
    assert!(rec.taker_leg_refund.is_some() && rec.maker_leg_claim.is_none());
    let mv = maker.view(mid).unwrap().unwrap();
    assert_eq!(mv.state, SwapState::Done);
    assert!(mv.preimage.is_none(), "the preimage was never revealed");
    assert_eq!(w.btc.balance(&w.tbtc.pubkey()).0, FUNDS, "taker got no BTC");
    let at = mv.maker_leg.as_ref().unwrap().outpoint.unwrap();
    assert_eq!(
        w.btc.tx_counts(&at).claim_attempts,
        0,
        "no claim was ever broadcast"
    );
}

#[tokio::test]
async fn first_sight_of_a_btc_lock_with_40_minutes_left_declines() {
    let w = world();
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
    let view = maker.view(&mid).unwrap().unwrap();
    let locktime = maker_locktime(&view);
    w.btc.advance_time(locktime - w.btc.mtp() - LEFT_SECS);

    let state = taker.step(&tid, Some(&view)).await.unwrap();
    assert_eq!(
        state,
        TakerState::Locked,
        "no claim with 40 minutes of BTC left"
    );
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let reason = rec.claim_declined.clone().expect("decision recorded");
    assert!(reason.contains("not claiming"), "{reason}");
    assert!(rec.last_error.is_none());
    both_refund(&w, &store, &maker, &taker, &tid, &mid).await;
}

#[tokio::test]
async fn verified_btc_lock_with_40_minutes_left_declines_and_records_it() {
    let w = world();
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store);
    let taker = taker(&w, &store);
    let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
    let view = maker.view(&mid).unwrap().unwrap();
    // The taker verifies the lock with hours to spare, then stops before claiming.
    taker.halt_after(Some(TakerState::MakerLockConfirmed));
    assert_eq!(
        taker.step(&tid, Some(&view)).await.unwrap(),
        TakerState::MakerLockConfirmed
    );
    taker.halt_after(None);
    let locktime = maker_locktime(&view);
    w.btc.advance_time(locktime - w.btc.mtp() - LEFT_SECS);

    for _ in 0..3 {
        assert_eq!(
            taker.step(&tid, Some(&view)).await.unwrap(),
            TakerState::MakerLockConfirmed,
            "no claim with 40 minutes of BTC left"
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        let reason = rec.claim_declined.clone().expect("decision recorded");
        assert!(reason.contains("not claiming"), "{reason}");
        assert!(rec.last_error.is_none() && rec.maker_leg_claim.is_none());
        w.btc.mine(1);
    }
    both_refund(&w, &store, &maker, &taker, &tid, &mid).await;
}

/// The block arm on its own: with the seconds floor lowered to 10 minutes, 40 minutes is
/// still only four 10-minute blocks, short of six, so the taker declines; at 61 minutes
/// (six blocks) the same taker claims.
#[tokio::test]
async fn too_few_blocks_declines_even_when_the_seconds_are_there() {
    let deadline = ClaimDeadline {
        block_secs: 600,
        min_blocks: 6,
        min_secs: 600,
    };
    for (left, claims) in [(LEFT_SECS, false), (3660, true)] {
        let w = world();
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store);
        let taker = taker(&w, &store).with_claim_deadline(Chain::Btc, deadline);
        assert_eq!(taker.claim_deadline(Chain::Btc), deadline);
        assert_eq!(
            taker.claim_deadline(Chain::Divi),
            ClaimDeadline::builtin(Chain::Divi)
        );
        let (tid, mid) = to_maker_lock_confirmed(&w, &maker, &taker).await;
        let view = maker.view(&mid).unwrap().unwrap();
        let locktime = maker_locktime(&view);
        w.btc.advance_time(locktime - w.btc.mtp() - left);
        let state = taker.step(&tid, Some(&view)).await.unwrap();
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        if claims {
            assert_eq!(state, TakerState::Claimed, "six blocks left: claim");
            assert!(rec.claim_declined.is_none());
        } else {
            assert_eq!(state, TakerState::Locked, "four blocks left: no claim");
            let reason = rec.claim_declined.expect("decision recorded");
            assert!(reason.contains("~4 btc blocks"), "{reason}");
            both_refund(&w, &store, &maker, &taker, &tid, &mid).await;
        }
    }
}
