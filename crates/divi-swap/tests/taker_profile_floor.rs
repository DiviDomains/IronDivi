// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A taker with a profile floor refuses a maker quote weaker than that profile in
//! `prepare`, before it generates a preimage, persists anything or signs/funds anything.

use divi_swap::api::{Direction, Offer, Quote};
use divi_swap::mock::MockChain;
use divi_swap::{Amount, Chain, Maker, Profile, Store, SwapConfig, Taker};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;

async fn quote_from(profile: Profile, counter: Chain, dir: Direction) -> Quote {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let other = MockChain::new(counter, T0, 150);
    let maker = Maker::new(
        SwapConfig::profile(profile),
        Arc::new(divi.backend(1, Amount(FUNDS))),
        Arc::new(other.backend(2, Amount(FUNDS))),
        Store::in_memory().unwrap(),
        vec![Offer {
            id: "o".into(),
            direction: dir,
            counter_chain: counter,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();
    maker.quote("o", 1_000_000).await.unwrap()
}

fn taker(counter: Chain, floor: Option<Profile>) -> (Taker, Store) {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let other = MockChain::new(counter, T0, 150);
    let store = Store::in_memory().unwrap();
    let t = Taker::new(
        Arc::new(divi.backend(3, Amount(FUNDS))),
        Arc::new(other.backend(4, Amount(FUNDS))),
        store.clone(),
    );
    (
        match floor {
            Some(p) => t.with_profile_floor(p),
            None => t,
        },
        store,
    )
}

#[tokio::test]
async fn mainnet_taker_refuses_a_testnet_maker_in_either_direction() {
    for counter in [Chain::Ltc, Chain::Zec] {
        for dir in [Direction::TakerPaysBtc, Direction::TakerPaysDivi] {
            let q = quote_from(Profile::Testnet, counter, dir).await;
            let (t, _) = taker(counter, Some(Profile::Mainnet));
            let e = t.prepare(&q).await.unwrap_err().to_string();
            assert!(
                e.contains("below the") && e.contains("--profile mainnet"),
                "{e}"
            );
        }
    }
}

#[tokio::test]
async fn refusal_happens_before_anything_is_persisted() {
    let q = quote_from(Profile::Testnet, Chain::Ltc, Direction::TakerPaysBtc).await;
    let (t, store) = taker(Chain::Ltc, Some(Profile::Mainnet));
    assert!(t.prepare(&q).await.is_err());
    assert!(store.list_taker_swaps().unwrap().is_empty());
}

#[tokio::test]
async fn taker_accepts_a_maker_on_its_own_profile() {
    for p in [Profile::Testnet, Profile::Mainnet] {
        let q = quote_from(p, Chain::Ltc, Direction::TakerPaysBtc).await;
        let (t, _) = taker(Chain::Ltc, Some(p));
        t.prepare(&q).await.unwrap();
    }
}

#[tokio::test]
async fn testnet_taker_accepts_a_stronger_mainnet_maker() {
    let q = quote_from(Profile::Mainnet, Chain::Ltc, Direction::TakerPaysBtc).await;
    let (t, _) = taker(Chain::Ltc, Some(Profile::Testnet));
    t.prepare(&q).await.unwrap();
}

#[tokio::test]
async fn a_taker_without_a_floor_takes_the_terms_as_offered() {
    let q = quote_from(Profile::Testnet, Chain::Ltc, Direction::TakerPaysBtc).await;
    let (t, _) = taker(Chain::Ltc, None);
    t.prepare(&q).await.unwrap();
}
