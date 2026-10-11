// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI against counter chains other than BTC, and records persisted by the v0.2.5 daemon.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::store::{MakerRecord, TakerRecord};
use divi_swap::{
    Amount, Chain, ChainBackend, Maker, Profile, Store, SwapConfig, SwapState, Taker, TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const COUNTER_SATS: u64 = 1_000_000;
const DIVI_SATS: u64 = 500_000_000;
const FUNDS: u64 = 2_000_000_000;
const FEE: u64 = 1_000;

fn offer(id: &str, dir: Direction, counter: Chain) -> Offer {
    Offer {
        id: id.into(),
        direction: dir,
        counter_chain: counter,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }
}

/// One DIVI chain and one counter chain, a maker and a taker with keys on both.
struct World {
    divi: MockChain,
    counter: MockChain,
    mdivi: MockBackend,
    mcounter: MockBackend,
    tdivi: MockBackend,
    tcounter: MockBackend,
}

impl World {
    fn new(counter: Chain, block_secs: u32) -> Self {
        let divi = MockChain::new(Chain::Divi, T0, 60);
        let counter = MockChain::new(counter, T0, block_secs);
        World {
            mdivi: divi.backend(1, Amount(FUNDS)),
            mcounter: counter.backend(2, Amount(FUNDS)),
            tdivi: divi.backend(3, Amount(FUNDS)),
            tcounter: counter.backend(4, Amount(FUNDS)),
            divi,
            counter,
        }
    }

    fn mine(&self) {
        self.divi.mine(1);
        self.counter.mine(1);
    }
}

/// Quote → accept → lock → claim → claim on `MockChain`s, until both sides are `Done`.
/// Checks each side got the other's leg and that the maker selected coins once, on the
/// maker-leg chain.
async fn full_swap(counter: Chain, block_secs: u32, dir: Direction) {
    let w = World::new(counter, block_secs);
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.mdivi.clone()),
        Arc::new(w.mcounter.clone()),
        store.clone(),
        vec![offer("o", dir, counter)],
    )
    .unwrap();
    let taker = Taker::new(
        Arc::new(w.tdivi.clone()),
        Arc::new(w.tcounter.clone()),
        store.clone(),
    );

    let quote = maker.quote("o", COUNTER_SATS).await.unwrap();
    assert_eq!(quote.counter_chain, counter);
    assert_eq!(quote.maker_btc_pubkey, w.mcounter.pubkey());
    let want_confs = SwapConfig::profile(Profile::Testnet).confirmations(counter);
    assert_eq!(quote.btc_confirmations, want_confs);
    let (tid, req) = taker.prepare(&quote).await.unwrap();
    assert_eq!(req.taker_btc_pubkey, w.tcounter.pubkey());
    let view = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &view).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&view.id, notice).await.unwrap().id;

    for _ in 0..60 {
        maker.tick().await.unwrap();
        let v = maker.view(&mid).unwrap();
        let _ = taker.step(&tid, v.as_ref()).await;
        w.mine();
        let m = store.get_maker_swap(&mid).unwrap().unwrap().state;
        let t = store.get_taker_swap(&tid).unwrap().unwrap().state;
        if m == SwapState::Done && t == TakerState::Done {
            break;
        }
    }
    let m = store.get_maker_swap(&mid).unwrap().unwrap();
    let t = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!((m.state, t.state), (SwapState::Done, TakerState::Done));
    assert!(m.preimage.is_some());
    assert_eq!(m.quote.counter_chain, counter);

    // Each side received the other's leg less one claim fee, on the right chain.
    let (maker_gets, taker_gets) = match dir {
        Direction::TakerPaysBtc => (
            w.counter.balance(&w.mcounter.pubkey()).0 - FUNDS,
            w.divi.balance(&w.tdivi.pubkey()).0 - FUNDS,
        ),
        Direction::TakerPaysDivi => (
            w.divi.balance(&w.mdivi.pubkey()).0 - FUNDS,
            w.counter.balance(&w.tcounter.pubkey()).0 - FUNDS,
        ),
    };
    let (taker_leg, maker_leg) = match dir {
        Direction::TakerPaysBtc => (COUNTER_SATS, DIVI_SATS),
        Direction::TakerPaysDivi => (DIVI_SATS, COUNTER_SATS),
    };
    assert_eq!(maker_gets, taker_leg - FEE);
    assert_eq!(taker_gets, maker_leg - FEE);
    let (on_maker_leg, on_taker_leg) = match dir {
        Direction::TakerPaysBtc => (&w.mdivi, &w.mcounter),
        Direction::TakerPaysDivi => (&w.mcounter, &w.mdivi),
    };
    assert_eq!(on_maker_leg.funding_calls(), 1);
    assert_eq!(on_taker_leg.funding_calls(), 0);
}

#[tokio::test]
async fn mock_swap_ltc_forward() {
    full_swap(Chain::Ltc, 150, Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn mock_swap_ltc_reverse() {
    full_swap(Chain::Ltc, 150, Direction::TakerPaysDivi).await;
}

#[tokio::test]
async fn mock_swap_zec_forward() {
    full_swap(Chain::Zec, 75, Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn mock_swap_zec_reverse() {
    full_swap(Chain::Zec, 75, Direction::TakerPaysDivi).await;
}

/// One maker serves BTC, LTC and ZEC offers at once; each quote carries the right chain and
/// key, and offers without a backend are refused up front.
#[tokio::test]
async fn one_maker_many_counter_chains() {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let counters: Vec<MockBackend> = [(Chain::Btc, 600), (Chain::Ltc, 150), (Chain::Zec, 75)]
        .into_iter()
        .enumerate()
        .map(|(i, (c, secs))| MockChain::new(c, T0, secs).backend(10 + i as u8, Amount(FUNDS)))
        .collect();
    let offers = vec![
        offer("divi-btc", Direction::TakerPaysBtc, Chain::Btc),
        offer("ltc-divi", Direction::TakerPaysDivi, Chain::Ltc),
        offer("divi-zec", Direction::TakerPaysBtc, Chain::Zec),
    ];
    let dyn_counters = || {
        counters
            .iter()
            .map(|b| Arc::new(b.clone()) as Arc<dyn ChainBackend>)
            .collect::<Vec<_>>()
    };
    let maker = Maker::with_counters(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, Amount(FUNDS))),
        dyn_counters(),
        Store::in_memory().unwrap(),
        offers.clone(),
    )
    .unwrap();
    for (o, b) in offers.iter().zip(&counters) {
        let q = maker.quote(&o.id, COUNTER_SATS).await.unwrap();
        assert_eq!(q.counter_chain, o.counter_chain);
        assert_eq!(q.maker_btc_pubkey, b.pubkey());
    }

    // An offer on a chain with no backend cannot build an engine.
    let r = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, Amount(FUNDS))),
        Arc::new(counters[0].clone()),
        Store::in_memory().unwrap(),
        vec![offer("divi-ltc", Direction::TakerPaysBtc, Chain::Ltc)],
    );
    assert!(r.is_err());
    // Neither can two backends for one chain, or DIVI as a counter chain.
    let mut twice = dyn_counters();
    twice.push(Arc::new(counters[1].clone()));
    assert!(Maker::with_counters(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, Amount(FUNDS))),
        twice,
        Store::in_memory().unwrap(),
        vec![],
    )
    .is_err());
    assert!(Maker::with_counters(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, Amount(FUNDS))),
        vec![Arc::new(divi.backend(2, Amount(FUNDS)))],
        Store::in_memory().unwrap(),
        vec![offer("divi-divi", Direction::TakerPaysBtc, Chain::Divi)],
    )
    .is_err());

    // A taker without an LTC key cannot take an LTC quote.
    let q = maker.quote("ltc-divi", COUNTER_SATS).await.unwrap();
    let btc_only = Taker::new(
        Arc::new(divi.backend(3, Amount(FUNDS))),
        Arc::new(counters[0].clone()),
        Store::in_memory().unwrap(),
    );
    assert!(btc_only.prepare(&q).await.is_err());
}

const MAKER_FWD: &str = include_str!("fixtures/v0.2.5/maker-forward-done.json");
const MAKER_REV: &str = include_str!("fixtures/v0.2.5/maker-reverse-done.json");
const TAKER_FWD: &str = include_str!("fixtures/v0.2.5/taker-forward-done.json");
const TAKER_REV: &str = include_str!("fixtures/v0.2.5/taker-reverse-done.json");

/// Records persisted by the deployed v0.2.5 daemon and taker CLI (no `counter_chain`; the
/// forward ones also predate `direction`) load as BTC swaps in the right direction, keep
/// their wire names when written back, and stay `Done` under the new engines.
#[tokio::test]
async fn v025_records_still_load() {
    let makers: Vec<(MakerRecord, Direction)> = [
        (MAKER_FWD, Direction::TakerPaysBtc),
        (MAKER_REV, Direction::TakerPaysDivi),
    ]
    .into_iter()
    .map(|(j, d)| {
        let raw: serde_json::Value = serde_json::from_str(j).unwrap();
        assert!(raw["quote"].get("counter_chain").is_none());
        (serde_json::from_str(j).unwrap(), d)
    })
    .collect();
    let takers: Vec<(TakerRecord, Direction)> = [
        (TAKER_FWD, Direction::TakerPaysBtc),
        (TAKER_REV, Direction::TakerPaysDivi),
    ]
    .into_iter()
    .map(|(j, d)| (serde_json::from_str(j).unwrap(), d))
    .collect();

    for (r, dir) in &makers {
        assert_eq!(r.quote.counter_chain, Chain::Btc);
        assert_eq!(r.quote.direction, *dir);
        assert_eq!(r.state, SwapState::Done);
        assert!(r.maker_leg_funding.is_some() && r.taker_leg_outpoint.is_some());
        let (tc, mc) = match dir {
            Direction::TakerPaysBtc => (Chain::Btc, Chain::Divi),
            Direction::TakerPaysDivi => (Chain::Divi, Chain::Btc),
        };
        assert_eq!((r.quote.taker_chain(), r.quote.maker_chain()), (tc, mc));
        // Wire names are unchanged when the record is written back.
        let out = serde_json::to_value(&r.quote).unwrap();
        for k in [
            "btc_amount",
            "maker_btc_pubkey",
            "btc_confirmations",
            "divi_amount",
        ] {
            assert!(out.get(k).is_some(), "quote lost {k}");
        }
        assert_eq!(out["counter_chain"], "btc");
    }
    for (r, dir) in &takers {
        assert_eq!(r.quote.counter_chain, Chain::Btc);
        assert_eq!(r.quote.direction, *dir);
        assert_eq!(r.state, TakerState::Done);
        assert!(r.maker_leg_claim.is_some() && r.taker_leg_funding.is_some());
    }

    // Through the store and the engines (BTC counter backend): terminal swaps stay put.
    let w = World::new(Chain::Btc, 600);
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.mdivi.clone()),
        Arc::new(w.mcounter.clone()),
        store.clone(),
        vec![],
    )
    .unwrap();
    let taker = Taker::new(
        Arc::new(w.tdivi.clone()),
        Arc::new(w.tcounter.clone()),
        store.clone(),
    );
    for (r, _) in &makers {
        store.put_maker_swap(r).unwrap();
        assert_eq!(store.get_maker_swap(&r.id).unwrap().as_ref(), Some(r));
        assert_eq!(maker.step(&r.id).await.unwrap(), SwapState::Done);
        assert_eq!(
            maker.view(&r.id).unwrap().unwrap().quote.counter_chain,
            Chain::Btc
        );
    }
    for (r, _) in &takers {
        store.put_taker_swap(r).unwrap();
        assert_eq!(store.get_taker_swap(&r.id).unwrap().as_ref(), Some(r));
        assert_eq!(taker.step(&r.id, None).await.unwrap(), TakerState::Done);
    }
    maker.tick().await.unwrap();
}
