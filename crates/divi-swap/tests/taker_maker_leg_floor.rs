// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A taker with a profile floor declines, before revealing the preimage, a maker that quoted
//! strong terms but locked its leg with a shorter real locktime than the quote implies; an
//! honest maker still completes.

use divi_swap::api::{Direction, LegView, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, HtlcParams, Maker, Profile, Store, SwapConfig, SwapState, Taker,
    TakerState,
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

fn maker(w: &World, store: &Store, p: Profile) -> Maker {
    Maker::new(
        SwapConfig::profile(p),
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

/// Quote, accept and lock the taker leg; returns (taker, maker swap id, taker swap id).
async fn through_taker_lock(w: &World, maker: &Maker, taker: &Taker) -> (String, String) {
    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    w.ltc.mine(1);
    (tid, mid)
}

#[tokio::test]
async fn an_honest_maker_still_completes_under_a_profile_floor() {
    for p in [Profile::Testnet, Profile::Mainnet] {
        let w = world();
        let store = Store::in_memory().unwrap();
        let maker = maker(&w, &store, p);
        let taker = taker(&w, &store, Some(p));
        let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
        for _ in 0..60 {
            w.divi.mine(1);
            w.ltc.mine(1);
            maker.tick().await.unwrap();
            let v = maker.view(&mid).unwrap();
            let _ = taker.step(&tid, v.as_ref()).await;
            if store.get_taker_swap(&tid).unwrap().unwrap().state == TakerState::Done
                && maker.view(&mid).unwrap().unwrap().state == SwapState::Done
            {
                break;
            }
        }
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.state, TakerState::Done, "{p}");
        assert!(
            rec.claim_declined.is_none(),
            "{p}: {:?}",
            rec.claim_declined
        );
        assert!(
            rec.maker_leg_claim.is_some(),
            "{p}: taker claimed the maker leg"
        );
        assert_eq!(
            maker.view(&mid).unwrap().unwrap().state,
            SwapState::Done,
            "{p}"
        );
    }
}

#[tokio::test]
async fn a_maker_that_quotes_strong_but_locks_short_is_declined_and_refunded() {
    let w = world();
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store, Profile::Testnet);
    let taker = taker(&w, &store, Some(Profile::Testnet));
    let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let quote_maker_timeout = rec.quote.maker_timeout_secs;

    // The maker does not tick; it locks DIVI itself, by hand, one hour out instead of the
    // quoted `maker_timeout_secs`. That passes the old MTP + 1800 s check.
    let short = HtlcParams {
        hash: rec.hash,
        claim_pubkey: w.tdivi.pubkey(),
        refund_pubkey: w.mdivi.pubkey(),
        locktime: w.divi.mtp() + 3600,
        script_version: Default::default(),
    };
    assert!(short.locktime - w.divi.mtp() < quote_maker_timeout);
    let funding = w
        .mdivi
        .build_funding(&short, rec.quote.maker_leg_amount())
        .await
        .unwrap();
    w.mdivi.broadcast(&funding.tx).await.unwrap();
    w.divi.mine(5);
    w.ltc.mine(1);
    let mut view = maker.view(&mid).unwrap().unwrap();
    view.maker_leg = Some(LegView {
        htlc: short,
        amount: funding.amount,
        outpoint: Some(funding.outpoint),
        spend_txid: None,
    });

    // Decided once, persisted, named term and both values; no claim, no error.
    let st = taker.step(&tid, Some(&view)).await.unwrap();
    assert_eq!(st, TakerState::Locked);
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let reason = rec.claim_declined.clone().expect("decision recorded");
    assert!(reason.contains("maker-leg locktime"), "{reason}");
    assert!(reason.contains(&short.locktime.to_string()), "{reason}");
    assert!(reason.contains("floor"), "{reason}");
    assert!(rec.last_error.is_none());
    assert!(rec.maker_leg_htlc.is_none() && rec.maker_leg_claim.is_none());

    // Repeated steps and a restart stay quiet and never claim.
    let taker = self::taker(&w, &store, Some(Profile::Testnet));
    for _ in 0..3 {
        w.divi.mine(1);
        w.ltc.mine(1);
        assert_eq!(
            taker.step(&tid, Some(&view)).await.unwrap(),
            TakerState::Locked
        );
        let rec = store.get_taker_swap(&tid).unwrap().unwrap();
        assert_eq!(rec.claim_declined.as_deref(), Some(reason.as_str()));
        assert!(rec.maker_leg_claim.is_none());
    }

    // The taker-leg timelock passes: the taker refunds, and the preimage never surfaced.
    w.ltc.advance_time(7 * 3600);
    for _ in 0..20 {
        w.ltc.mine(1);
        let _ = taker.step(&tid, Some(&view)).await;
        if store.get_taker_swap(&tid).unwrap().unwrap().state == TakerState::Done {
            break;
        }
    }
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!(rec.state, TakerState::Done);
    assert!(rec.taker_leg_refund.is_some() && rec.maker_leg_claim.is_none());
    assert!(w.ltc.balance(&w.tltc.pubkey()).0 >= FUNDS - 2_000);
    assert_eq!(
        w.divi.balance(&w.tdivi.pubkey()).0,
        FUNDS,
        "taker got no DIVI"
    );
}

#[tokio::test]
async fn without_a_profile_floor_a_short_maker_lock_is_unchanged() {
    let w = world();
    let store = Store::in_memory().unwrap();
    let maker = maker(&w, &store, Profile::Testnet);
    let taker = taker(&w, &store, None);
    let (tid, mid) = through_taker_lock(&w, &maker, &taker).await;
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let short = HtlcParams {
        hash: rec.hash,
        claim_pubkey: w.tdivi.pubkey(),
        refund_pubkey: w.mdivi.pubkey(),
        locktime: w.divi.mtp() + 3600,
        script_version: Default::default(),
    };
    let funding = w
        .mdivi
        .build_funding(&short, rec.quote.maker_leg_amount())
        .await
        .unwrap();
    w.mdivi.broadcast(&funding.tx).await.unwrap();
    w.divi.mine(5);
    let mut view = maker.view(&mid).unwrap().unwrap();
    view.maker_leg = Some(LegView {
        htlc: short,
        amount: funding.amount,
        outpoint: Some(funding.outpoint),
        spend_txid: None,
    });
    let st = taker.step(&tid, Some(&view)).await.unwrap();
    // Today's behaviour: no quote-relative check, so the taker goes on to claim.
    assert_eq!(st, TakerState::Claimed);
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    assert!(rec.claim_declined.is_none() && rec.maker_leg_claim.is_some());
}
