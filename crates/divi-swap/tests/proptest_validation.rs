// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Property tests over the amount, timelock and fee edges of quote and accept validation:
//! zero, one, dust, `u32::MAX`/`u64::MAX` and random values. No input panics (tests build with
//! overflow checks) or wraps, and each refusal is monotone in the direction that makes a swap
//! safer: more spendable, a longer taker timeout, deeper confirmations, a later maker
//! locktime.

use divi_swap::api::{Direction, Offer};
use divi_swap::config::{
    check_maker_leg_locktime, check_maker_leg_locktime_exact, check_terms_against_profile,
    ChainParams, OfferedTerms,
};
use divi_swap::mock::MockChain;
use divi_swap::{Amount, Chain, Maker, Profile, Store, SwapConfig, SwapError, Taker};
use proptest::prelude::*;
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const COIN: u64 = 100_000_000;
/// BTC's P2PKH dust limit, for the "dust" edge.
const DUST: u64 = 546;

fn edge_u64() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1),
        Just(DUST),
        Just(COIN),
        Just(1 << 63),
        Just(u64::MAX - 1),
        Just(u64::MAX),
        0..=10 * COIN,
        any::<u64>(),
    ]
}

fn edge_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1),
        Just(3600),
        Just(3 * 3600),
        Just(u32::MAX / 2),
        Just(u32::MAX - 1),
        Just(u32::MAX),
        0..=7 * 24 * 3600u32,
        any::<u32>(),
    ]
}

/// A timeout, mostly near the profiles' (hours to two days) so that some terms pass.
fn timeout() -> impl Strategy<Value = u32> {
    prop_oneof![edge_u32(), 0..=48 * 3600u32]
}

fn confirmations() -> impl Strategy<Value = u32> {
    prop_oneof![edge_u32(), 0..=40u32]
}

fn profile() -> impl Strategy<Value = Profile> {
    prop_oneof![Just(Profile::Mainnet), Just(Profile::Testnet)]
}

fn chain() -> impl Strategy<Value = Chain> {
    proptest::sample::select(Chain::ALL.to_vec())
}

fn terms() -> impl Strategy<Value = OfferedTerms> {
    (timeout(), timeout(), confirmations(), confirmations()).prop_map(|(t, m, c, d)| OfferedTerms {
        taker_timeout_secs: t,
        maker_timeout_secs: m,
        counter_confirmations: c,
        divi_confirmations: d,
    })
}

fn offer(rate: u64, min: u64, max: u64) -> Offer {
    Offer {
        id: "o1".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: rate,
        min_btc_sats: min,
        max_btc_sats: max,
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct W {
    maker: Maker,
    taker: Taker,
    divi: MockChain,
}

/// A maker paying the DIVI leg (seed 1, `maker_divi` spendable) and a taker, on mock chains.
fn world(o: Offer, maker_divi: u64) -> W {
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, Amount(maker_divi))),
        Arc::new(btc.backend(2, Amount(0))),
        store.clone(),
        vec![o],
    )
    .unwrap()
    .with_clock(Arc::new(|| T0 as u64));
    let taker = Taker::new(
        Arc::new(divi.backend(3, Amount(0))),
        Arc::new(btc.backend(4, Amount(0))),
        store,
    );
    W { maker, taker, divi }
}

/// Accept a swap whose maker leg is `need` sats, with `pending` sats of an accepted, not yet
/// funded swap already drawing on the maker's coins, and `funds` spendable.
async fn accept_with(pending: u64, need: u64, funds: u64) -> Result<(), SwapError> {
    // 1 DIVI per BTC: the maker (DIVI) leg is exactly the requested sats.
    let w = world(offer(COIN, 1, u64::MAX), u64::MAX);
    if pending > 0 {
        let q = w.maker.quote("o1", pending).await?;
        let req = w.taker.prepare(&q).await?.1;
        w.maker.accept(req).await?;
    }
    w.divi.backend(1, Amount(funds));
    let q = w.maker.quote("o1", need).await?;
    assert_eq!(q.maker_leg_amount(), Amount(need));
    let req = w.taker.prepare(&q).await?.1;
    w.maker.accept(req).await.map(|_| ())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// `checked_divi_for` is the exact rounded-down quotient or `None`; `divi_for` is it or
    /// `u64::MAX`. Neither wraps.
    #[test]
    fn divi_for_never_wraps(rate in edge_u64(), btc in edge_u64()) {
        let o = offer(rate, 0, u64::MAX);
        let exact = u128::from(btc) * u128::from(rate) / u128::from(COIN);
        match o.checked_divi_for(btc) {
            Some(a) => prop_assert_eq!(u128::from(a.0), exact),
            None => prop_assert!(exact > u128::from(u64::MAX)),
        }
        prop_assert_eq!(u128::from(o.divi_for(btc).0), exact.min(u128::from(u64::MAX)));
    }

    /// The required timeout gap is `max(3 h, 2 × max lag + margin)` with no wrap (saturating
    /// at `u32::MAX`), and `validate` passes only a gap that covers it exactly. So a smaller
    /// lag or margin never turns a valid config invalid.
    #[test]
    fn required_gap_is_exact(
        btc_lag in edge_u32(),
        ltc_lag in edge_u32(),
        margin in edge_u32(),
        taker in edge_u32(),
        maker in edge_u32(),
    ) {
        let mut c = SwapConfig::profile(Profile::Testnet);
        c.btc_mtp_lag_secs = btc_lag;
        c.chains.insert(Chain::Ltc, ChainParams { confirmations: 1, mtp_lag_secs: ltc_lag });
        c.claim_margin_secs = margin;
        c.taker_timeout_secs = taker;
        c.maker_timeout_secs = maker;
        let lag = Chain::ALL.into_iter().map(|ch| c.chain_params(ch).mtp_lag_secs).max().unwrap();
        let need = (2 * u64::from(lag) + u64::from(margin))
            .max(u64::from(SwapConfig::MIN_TIMEOUT_GAP_SECS));
        prop_assert_eq!(u64::from(c.required_gap_secs()), need.min(u64::from(u32::MAX)));
        let ok = c.validate().is_ok();
        prop_assert_eq!(ok, u64::from(taker) >= u64::from(maker) + need);
        if ok {
            let mut smaller = c.clone();
            smaller.btc_mtp_lag_secs = btc_lag / 2;
            smaller.claim_margin_secs = margin / 2;
            prop_assert!(smaller.validate().is_ok());
        }
    }

    /// The taker's profile check never panics, and raising the taker timeout, either
    /// confirmation count, or both timeouts by the same amount never turns an accept into a
    /// refusal. (Raising the maker timeout alone shrinks the gap and may refuse: by design.)
    #[test]
    fn terms_check_is_monotone(
        p in profile(),
        tc in chain(),
        mc in chain(),
        t in terms(),
        d in edge_u32(),
    ) {
        let ok = |t: &OfferedTerms| check_terms_against_profile(p, (tc, mc), t).is_ok();
        if ok(&t) {
            let taker = t.taker_timeout_secs.saturating_add(d);
            let longer = OfferedTerms { taker_timeout_secs: taker, ..t };
            prop_assert!(ok(&longer));
            let c = t.counter_confirmations.saturating_add(d);
            let deeper = OfferedTerms { counter_confirmations: c, ..t };
            prop_assert!(ok(&deeper));
            let dc = t.divi_confirmations.saturating_add(d);
            let deeper = OfferedTerms { divi_confirmations: dc, ..t };
            prop_assert!(ok(&deeper));
            if let (Some(taker), Some(maker)) = (
                t.taker_timeout_secs.checked_add(d),
                t.maker_timeout_secs.checked_add(d),
            ) {
                let both = OfferedTerms { taker_timeout_secs: taker, maker_timeout_secs: maker, ..t };
                prop_assert!(ok(&both));
            }
        }
    }

    /// The tolerant maker-leg floor never panics; a later maker locktime or a wider tolerance
    /// never refuses more.
    #[test]
    fn maker_leg_floor_is_monotone(
        p in profile(),
        tc in chain(),
        mc in chain(),
        t in terms(),
        tl in edge_u32(),
        ml in edge_u32(),
        tol in edge_u32(),
        d in edge_u32(),
    ) {
        let ok = |ml: u32, tol: u32| {
            check_maker_leg_locktime(p, (tc, mc), &t, tl, ml, tol).is_ok()
        };
        if ok(ml, tol) {
            prop_assert!(ok(ml.saturating_add(d), tol));
            prop_assert!(ok(ml, tol.saturating_add(d)));
        }
    }

    /// The exact maker-leg floor never panics; a later maker locktime or a later observed
    /// maker-chain MTP never refuses more.
    #[test]
    fn exact_maker_leg_floor_is_monotone(
        p in profile(),
        tc in chain(),
        mc in chain(),
        t in terms(),
        tl in edge_u32(),
        ml in edge_u32(),
        stated in edge_u32(),
        observed in edge_u32(),
        tol in edge_u32(),
        d in edge_u32(),
    ) {
        let ok = |ml: u32, observed: u32| {
            check_maker_leg_locktime_exact(p, (tc, mc), &t, tl, ml, stated, observed, tol).is_ok()
        };
        if ok(ml, observed) {
            prop_assert!(ok(ml.saturating_add(d), observed));
            prop_assert!(ok(ml, observed.saturating_add(d)));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// `quote` never panics: it quotes exactly `checked_divi_for` (non-zero) for an amount in
    /// the offer's range, and refuses anything else with `InvalidParams`.
    #[test]
    fn quote_is_exact_or_refused(
        rate in edge_u64(),
        min in edge_u64(),
        max in edge_u64(),
        btc in edge_u64(),
        inside in any::<bool>(),
    ) {
        // Half the cases pick an amount inside the range, if there is one.
        let btc = if inside && min <= max {
            let span = u128::from(max - min) + 1;
            min + u64::try_from(u128::from(btc) % span).unwrap()
        } else {
            btc
        };
        rt().block_on(async {
            let o = offer(rate, min, max);
            let w = world(o.clone(), 0);
            match w.maker.quote("o1", btc).await {
                Ok(q) => {
                    prop_assert!(min <= btc && btc <= max);
                    prop_assert_eq!(q.btc_amount, Amount(btc));
                    prop_assert_eq!(Some(q.divi_amount), o.checked_divi_for(btc));
                    prop_assert!(q.divi_amount.0 > 0);
                }
                Err(e) => {
                    prop_assert!(matches!(e, SwapError::InvalidParams(_)), "{:?}", e);
                    let fits = o.checked_divi_for(btc).is_some_and(|a| a.0 > 0);
                    prop_assert!(!(min <= btc && btc <= max && fits), "{:?}", e);
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// accept's funds check is exact: with `pending` sats promised to an accepted, unfunded
    /// swap, a new `need`-sat maker leg is accepted iff spendable covers both, summed without
    /// wrapping or saturating. So more spendable never turns an accept into a refusal.
    #[test]
    fn accept_funds_check_is_exact_and_monotone(
        pending in edge_u64(),
        need in edge_u64(),
        have in edge_u64(),
        more in edge_u64(),
    ) {
        prop_assume!(need > 0);
        let covers = |funds: u64| u128::from(funds) >= u128::from(pending) + u128::from(need);
        rt().block_on(async {
            let low = accept_with(pending, need, have).await;
            let high = accept_with(pending, need, have.saturating_add(more)).await;
            for (funds, r) in [(have, &low), (have.saturating_add(more), &high)] {
                match r {
                    Ok(()) => prop_assert!(covers(funds)),
                    Err(SwapError::InsufficientFunds(_)) => prop_assert!(!covers(funds)),
                    Err(e) => prop_assert!(false, "unexpected {:?}", e),
                }
            }
            if low.is_ok() {
                prop_assert!(high.is_ok());
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}
