// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! An XMR taker with a profile floor refuses a maker quote weaker than that profile in
//! `prepare`, before it generates a key, Paillier primes or persists anything.

use std::sync::Arc;

use divi_swap::api::{Direction, Offer, Quote};
use divi_swap::{Chain, Profile, Store};
use divi_swap_xmr::mock::{MockDiviChain, MockMoneroChain};
use divi_swap_xmr::{XmrConfig, XmrMaker, XmrTaker};

const T0: u32 = 1_800_000_000;

fn offer() -> Offer {
    Offer {
        id: "divi-xmr-stagenet".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Xmr,
        divi_sats_per_btc: 5_000 * 100_000_000,
        min_btc_sats: 100_000,
        max_btc_sats: 100_000_000,
    }
}

async fn quote_from(cfg: XmrConfig) -> Quote {
    let divi = MockDiviChain::new(T0, 60);
    let xmr = MockMoneroChain::new();
    let maker = XmrMaker::new(
        cfg,
        Arc::new(divi.wallet(1)),
        Arc::new(xmr.wallet("maker", 0)),
        Store::in_memory().unwrap(),
        vec![offer()],
    )
    .unwrap();
    maker.quote("divi-xmr-stagenet", 1_000_000).await.unwrap()
}

/// A taker whose own engine config is `cfg` (the mock numbers) and, optionally, a floor.
fn taker(cfg: XmrConfig, floor: Option<Profile>) -> (XmrTaker, Store) {
    let divi = MockDiviChain::new(T0, 60);
    let xmr = MockMoneroChain::new();
    let store = Store::in_memory().unwrap();
    let t = XmrTaker::new(
        cfg,
        Arc::new(divi.wallet(2)),
        Arc::new(xmr.wallet("taker", 1_000_000_000_000)),
        store.clone(),
    )
    .unwrap()
    // Cheap stand-in: a refused `prepare` never reaches the prime generator, an accepted
    // one is not driven past it here.
    .with_primes(Arc::new(|| {
        panic!("primes are generated only after the floor check")
    }));
    (
        match floor {
            Some(p) => t.with_profile_floor(p),
            None => t,
        },
        store,
    )
}

/// The prime generator panics; the engine reports that as an error from its blocking task.
/// Seeing it proves `prepare` got past the floor check.
fn assert_reached_primes(e: Option<impl std::fmt::Display>) {
    let e = e
        .expect("prepare cannot succeed with the stand-in primes")
        .to_string();
    assert!(
        e.contains("primes are generated only after the floor check"),
        "refused before the prime generator: {e}"
    );
}

fn docs(store: &Store) -> usize {
    store
        .list_docs::<serde_json::Value>(divi_swap_xmr::taker::KIND)
        .map(|d| d.len())
        .unwrap_or(0)
}

#[tokio::test]
async fn mainnet_floor_refuses_a_testnet_maker_naming_the_term() {
    let q = quote_from(XmrConfig::testnet()).await;
    let (t, _) = taker(XmrConfig::testnet(), Some(Profile::Mainnet));
    let e = t.prepare(&q).await.unwrap_err().to_string();
    assert!(e.contains("below the") && e.contains("floor"), "{e}");
}

#[tokio::test]
async fn refusal_happens_before_anything_is_persisted() {
    let q = quote_from(XmrConfig::testnet()).await;
    let (t, store) = taker(XmrConfig::testnet(), Some(Profile::Mainnet));
    assert!(t.prepare(&q).await.is_err());
    assert_eq!(docs(&store), 0);
}

#[tokio::test]
async fn a_weak_quote_is_refused_even_when_the_taker_config_itself_is_weak() {
    // The taker engine runs the testnet numbers but is started under --profile mainnet:
    // the floor is the profile's, not the engine config's.
    let q = quote_from(XmrConfig::testnet()).await;
    let (t, _) = taker(XmrConfig::testnet(), Some(Profile::Mainnet));
    assert!(t.prepare(&q).await.is_err());
}

#[tokio::test]
async fn a_taker_without_a_floor_takes_the_terms_as_offered() {
    // Past the floor check, prepare needs primes: reaching the generator proves it passed.
    let q = quote_from(XmrConfig::testnet()).await;
    let (t, _) = taker(XmrConfig::testnet(), None);
    assert_reached_primes(t.prepare(&q).await.err());
}

#[tokio::test]
async fn a_taker_at_its_own_profile_passes_the_floor() {
    for p in [Profile::Testnet, Profile::Mainnet] {
        let cfg = XmrConfig::for_profile(p);
        let q = quote_from(cfg.clone()).await;
        let (t, _) = taker(cfg, Some(p));
        assert_reached_primes(t.prepare(&q).await.err());
    }
}

#[tokio::test]
async fn a_testnet_floor_accepts_the_stronger_mainnet_maker() {
    let q = quote_from(XmrConfig::mainnet()).await;
    let (t, _) = taker(XmrConfig::testnet(), Some(Profile::Testnet));
    assert_reached_primes(t.prepare(&q).await.err());
}
