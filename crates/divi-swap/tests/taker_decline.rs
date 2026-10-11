// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A taker that first sees the maker's lock too close to its locktime declines to claim for
//! good (no error on every step), and the swap ends in refunds on both sides.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::taker::TAKER_SAFETY_MARGIN_SECS;
use divi_swap::{
    Amount, Chain, ChainBackend, Maker, Profile, Store, SwapConfig, SwapState, Taker, TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;

struct World {
    divi: MockChain,
    ltc: MockChain,
    mdivi: MockBackend,
    mltc: MockBackend,
    tdivi: MockBackend,
    tltc: MockBackend,
}

fn world() -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let ltc = MockChain::new(Chain::Ltc, T0, 150);
    World {
        mdivi: divi.backend(1, Amount(FUNDS)),
        mltc: ltc.backend(2, Amount(FUNDS)),
        tdivi: divi.backend(3, Amount(FUNDS)),
        tltc: ltc.backend(4, Amount(FUNDS)),
        divi,
        ltc,
    }
}

fn taker(w: &World, store: &Store) -> Taker {
    Taker::new(
        Arc::new(w.tdivi.clone()),
        Arc::new(w.tltc.clone()),
        store.clone(),
    )
}

#[tokio::test]
async fn taker_declines_a_maker_lock_too_close_to_its_locktime() {
    let w = world();
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.mdivi.clone()),
        Arc::new(w.mltc.clone()),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Ltc,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();
    let mut taker = taker(&w, &store);

    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;

    // The maker locks DIVI and it confirms, but the taker is away (no steps).
    for _ in 0..20 {
        w.divi.mine(1);
        w.ltc.mine(1);
        maker.tick().await.unwrap();
        if maker.view(&mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    let view = maker.view(&mid).unwrap().unwrap();
    assert_eq!(view.state, SwapState::MakerLockConfirmed);
    // The DIVI chain moves on until less than the safety margin is left before the maker's
    // locktime (but the maker's refund is not mature yet).
    let locktime = view.maker_leg.as_ref().unwrap().htlc.locktime;
    w.divi
        .advance_time(locktime - w.divi.mtp() - TAKER_SAFETY_MARGIN_SECS / 2);
    assert!(w.divi.mtp() < locktime);

    // The taker now sees the lock: a decision, not an error, and it is persisted.
    let state = taker.step(&tid, Some(&view)).await.unwrap();
    assert_eq!(state, TakerState::Locked);
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let reason = rec.claim_declined.clone().expect("decision recorded");
    assert!(reason.contains("not claiming"), "{reason}");
    assert!(rec.last_error.is_none(), "no error left on the swap");
    assert!(rec.maker_leg_htlc.is_none() && rec.maker_leg_claim.is_none());

    // Repeated steps, and a restart, stay quiet and never claim.
    for i in 0..3 {
        if i == 1 {
            taker = self::taker(&w, &store);
        }
        w.divi.mine(1);
        w.ltc.mine(1);
        assert_eq!(
            taker.step(&tid, Some(&view)).await.unwrap(),
            TakerState::Locked
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.claim_declined.as_deref(), Some(reason.as_str()));
        assert!(rec.last_error.is_none() && rec.maker_leg_claim.is_none());
    }

    // Both timelocks pass: the maker refunds its DIVI, the taker its LTC; nobody claimed.
    w.divi.advance_time(TAKER_SAFETY_MARGIN_SECS);
    w.ltc.advance_time(7 * 3600);
    for _ in 0..20 {
        w.divi.mine(1);
        w.ltc.mine(1);
        maker.tick().await.unwrap();
        let v = maker.view(&mid).unwrap();
        let _ = taker.step(&tid, v.as_ref()).await;
        let t = store.get_taker_swap(&tid).unwrap().unwrap().state;
        if t == TakerState::Done && maker.view(&mid).unwrap().unwrap().state == SwapState::Done {
            break;
        }
    }
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.state, TakerState::Done);
    assert!(rec.taker_leg_refund.is_some() && rec.maker_leg_claim.is_none());
    let mv = maker.view(&mid).unwrap().unwrap();
    assert_eq!(mv.state, SwapState::Done);
    assert!(mv.preimage.is_none(), "the preimage was never revealed");
    assert!(w.divi.balance(&w.mdivi.pubkey()).0 >= FUNDS - 2_000);
    assert!(w.ltc.balance(&w.tltc.pubkey()).0 >= FUNDS - 2_000);
    assert_eq!(
        w.divi.balance(&w.tdivi.pubkey()).0,
        FUNDS,
        "taker got no DIVI"
    );
}
