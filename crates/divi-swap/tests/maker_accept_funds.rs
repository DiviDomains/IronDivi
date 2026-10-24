// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `Maker::accept` refuses a swap whose maker leg the maker cannot fund, before it writes
//! anything and without selecting coins.

use divi_swap::api::{AcceptRequest, Direction, Offer, Quote};
use divi_swap::mock::{MockBackend, MockChain, MOCK_FEE};
use divi_swap::{Amount, Chain, Maker, Profile, Store, SwapConfig, SwapError, Taker};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const BTC_SATS: u64 = 1_000_000;

struct W {
    maker: Maker,
    taker: Taker,
    store: Store,
    divi: MockChain,
    mdivi: MockBackend,
}

/// The maker pays DIVI (the maker leg) and starts with `maker_divi`.
fn world(maker_divi: u64) -> W {
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let mdivi = divi.backend(1, Amount(maker_divi));
    let mbtc = btc.backend(2, Amount(0));
    let tdivi = divi.backend(3, Amount(0));
    let tbtc = btc.backend(4, Amount(10_000_000));
    let store = Store::in_memory().unwrap();
    let offer = Offer {
        id: "o1".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    };
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(mdivi.clone()),
        Arc::new(mbtc),
        store.clone(),
        vec![offer],
    )
    .unwrap()
    .with_clock(Arc::new(|| T0 as u64));
    let taker = Taker::new(Arc::new(tdivi), Arc::new(tbtc), store.clone());
    W {
        maker,
        taker,
        store,
        divi,
        mdivi,
    }
}

async fn request(w: &W) -> (Quote, AcceptRequest) {
    let q = w.maker.quote("o1", BTC_SATS).await.unwrap();
    let req = w.taker.prepare(&q).await.unwrap().1;
    (q, req)
}

/// Set the maker's DIVI balance (same key as `world`'s seed 1).
fn fund_maker(w: &W, sats: u64) {
    w.divi.backend(1, Amount(sats));
}

#[tokio::test]
async fn accept_refuses_a_swap_the_maker_cannot_fund() {
    let w = world(0);
    let (q, req) = request(&w).await;
    assert_eq!(q.maker_chain(), Chain::Divi);
    let need = q.maker_leg_amount();
    fund_maker(&w, need.0 - 1);

    let r = w.maker.accept(req.clone()).await;
    assert!(matches!(r, Err(SwapError::InsufficientFunds(_))), "{r:?}");
    assert!(
        !w.store.get_quote(&q.id).unwrap().unwrap().used,
        "quote still usable"
    );
    assert!(
        w.store.list_maker_swaps().unwrap().is_empty(),
        "no swap row"
    );
    assert_eq!(w.mdivi.funding_calls(), 0, "no coin selection at accept");

    // Funded, the same quote is accepted.
    fund_maker(&w, need.0 + MOCK_FEE.0);
    w.maker.accept(req).await.unwrap();
    assert_eq!(w.store.list_maker_swaps().unwrap().len(), 1);
    assert_eq!(w.mdivi.funding_calls(), 0, "no coin selection at accept");
}
