// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `Maker::quote` refuses a price whose DIVI amount does not fit in a `u64`, rather than
//! quoting the wrapped remainder.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::MockChain;
use divi_swap::{Amount, Chain, Maker, Profile, Store, SwapConfig, SwapError};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;

#[tokio::test]
async fn quote_refuses_a_divi_amount_that_overflows() {
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let offer = Offer {
        id: "o1".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: u64::MAX,
        min_btc_sats: 1,
        max_btc_sats: u64::MAX,
    };
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, Amount(0))),
        Arc::new(btc.backend(2, Amount(0))),
        Store::in_memory().unwrap(),
        vec![offer],
    )
    .unwrap()
    .with_clock(Arc::new(|| T0 as u64));

    let r = maker.quote("o1", u64::MAX).await;
    assert!(matches!(r, Err(SwapError::InvalidParams(_))), "{r:?}");
    // The largest amount that fits is still quoted, exactly.
    let q = maker.quote("o1", 100_000_000).await.unwrap();
    assert_eq!(q.divi_amount, Amount(u64::MAX));
}
