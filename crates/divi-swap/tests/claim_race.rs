// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The claim-vs-refund race on the maker leg. Once the taker's claim is in a mempool the
//! preimage is out and the maker claims the taker leg; the taker keeps the maker leg only if
//! its claim confirms before the maker-leg locktime, after which the maker's refund wins (a
//! hostile maker sends one although it saw the claim, paying far more).
//!
//! Random fee markets drive the mock: per block, a block floor (feerate below which nothing
//! is mined) and a mempool floor (below which claims are evicted and refused), each up to
//! twice the fixed escalation cap, and a fee estimate the first claim trusts.
//!
//! Property: with fee escalation on and the claim-deadline margin held, `Lost` is
//! unreachable on BTC (RBF) and LTC (CPFP), floors above the fixed cap included: once the
//! preimage is out the fee ceiling is a share of the maker leg, not the fixed cap. The same
//! market with escalation off loses. A floor that would cost more than half the leg before
//! anything is revealed is declined and refunded instead.
//! USDC (same nonce, gas paid in ETH, so no share-of-leg ceiling) holds the same property
//! for floors at or below `cap_feerate`, a first claim priced down to 1 gwei included: past
//! the cap point the multiple of the first feerate gives way to `cap_feerate`.
//! ZEC (and DIVI) cannot bump at all (no replacement, CPFP inert): the margin is all they
//! have, so there the test is only that a claim paying the block floor confirms in time.
//!
//! `PROPTEST_CASES=5000` runs a longer search than the default.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, FeeBump, FeeEscalation, Maker, Profile, Store, SwapConfig,
    SwapState, Taker, TakerState,
};
use proptest::prelude::*;
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
const SATS: u64 = 1_000_000;

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

#[derive(Debug, Clone)]
struct Market {
    chain: Chain,
    /// What `claim_feerate` reports, the first claim's feerate.
    estimate: u64,
    /// Seconds of maker-leg time that pass before the taker first looks.
    delay_secs: u32,
    /// Per maker-leg block: block floor and mempool floor, as fractions (per mille) of
    /// the fixed escalation cap (`FeeEscalation::cap`; on USDC of `cap_feerate`). Repeats
    /// its last entry once exhausted.
    floors: Vec<(u16, u16)>,
    /// What the maker's refund of its leg pays. `market()` draws it at least twice the BTC
    /// fixed cap, so above every floor: the hostile refund always gets mined once the
    /// locktime passes, the worst case for the taker. A maker refund under the floor is
    /// drawn by `low_refund_market()` and its own tests below, not dropped.
    refund_feerate: u64,
}

fn market() -> impl Strategy<Value = Market> {
    (
        prop_oneof![Just(Chain::Btc), Just(Chain::Ltc)],
        1u64..60,
        0u32..7200,
        // Up to twice the fixed cap: at most 2000 sat/vB on BTC, a fifth of the 1M sat leg
        // over the mock's 100 vB claim, so always under the half-leg ceiling the taker may
        // pay once the preimage is out. A floor above that ceiling is lost by design.
        proptest::collection::vec((0u16..=2000, 0u16..=2000), 1..40),
        2000u64..20_000,
    )
        .prop_map(
            |(chain, estimate, delay_secs, floors, refund_feerate)| Market {
                chain,
                estimate,
                delay_secs,
                floors,
                refund_feerate,
            },
        )
}

/// The USDC schedule at the mock's scale: one mock unit stands for one gwei, so the
/// builtin 500 gwei cap is 500 (the mock pays a claim's fee out of the 1M unit leg, where a
/// wei-denominated fee would not fit). Every rule of the schedule is a ratio.
const USDC_GWEI_CAP: u64 = 500;

/// The taker's schedule for `chain`: the builtin one, on USDC at the mock's scale.
fn schedule(chain: Chain) -> Option<FeeEscalation> {
    let esc = FeeEscalation::builtin(chain)?;
    Some(match chain {
        Chain::Usdc => esc.with_cap_feerate(USDC_GWEI_CAP),
        _ => esc,
    })
}

/// USDC markets: a first claim priced at 1 to 19 gwei (so the 50x multiple binds, under the
/// 500 gwei `cap_feerate`, about half the time), floors at or below `cap_feerate`, so up to
/// 500 times the first feerate and far above its fixed cap.
fn usdc_market() -> impl Strategy<Value = Market> {
    (
        1u64..20,
        0u32..7200,
        proptest::collection::vec((0u16..=1000, 0u16..=1000), 1..40),
        2000u64..20_000,
    )
        .prop_map(|(estimate, delay_secs, floors, refund_feerate)| Market {
            chain: Chain::Usdc,
            estimate,
            delay_secs,
            floors,
            refund_feerate,
        })
}

/// `market()` with the maker's refund drawn under the floors: it may never be mined.
fn low_refund_market() -> impl Strategy<Value = Market> {
    (market(), 1u64..2000).prop_map(|(m, refund_feerate)| Market {
        refund_feerate,
        ..m
    })
}

fn block_secs(chain: Chain) -> u32 {
    match chain {
        Chain::Btc => 600,
        Chain::Ltc => 150,
        Chain::Zec => 75,
        Chain::Usdc => 12,
        _ => 60,
    }
}

fn bump(chain: Chain) -> FeeBump {
    match chain {
        Chain::Btc => FeeBump::Rbf,
        Chain::Ltc => FeeBump::Cpfp,
        Chain::Usdc => FeeBump::SameNonce,
        _ => FeeBump::None,
    }
}

#[derive(Debug)]
struct Outcome {
    taker: TakerState,
    maker: SwapState,
    /// The taker's maker-leg claim confirmed.
    claimed: bool,
    /// The preimage was out (a claim reached a mempool) before the end.
    leaked: bool,
    /// The taker recorded `claim_declined`.
    declined: bool,
}

/// One swap through `m`, the taker paying DIVI so the maker leg is on `m.chain`.
async fn race(m: &Market, escalation: bool) -> Outcome {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let ml = MockChain::new(m.chain, T0, block_secs(m.chain));
    ml.set_fee_bump(bump(m.chain));
    ml.set_fee_estimate(m.estimate);
    ml.set_refund_feerate(m.refund_feerate);
    let (mdivi, mml): (MockBackend, MockBackend) =
        (divi.backend(1, Amount(FUNDS)), ml.backend(2, Amount(FUNDS)));
    let hostile = mml.clone();
    let (tdivi, tml) = (divi.backend(3, Amount(FUNDS)), ml.backend(4, Amount(FUNDS)));
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(mdivi),
        Arc::new(mml),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysDivi,
            counter_chain: m.chain,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();
    let esc = schedule(m.chain);
    let taker = Taker::new(Arc::new(tdivi), Arc::new(tml.clone()), store.clone())
        .with_fee_escalation(m.chain, esc.filter(|_| escalation));
    // The floors' scale: the fixed cap, and on USDC (no post-leak ceiling) `cap_feerate`.
    let cap = match (m.chain, esc) {
        (Chain::Usdc, Some(e)) => e.cap_feerate,
        (_, e) => e.map_or(m.estimate, |e| e.cap(m.estimate)),
    };

    let q = maker.quote("o", SATS).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    for _ in 0..20 {
        divi.mine(1);
        ml.mine(1);
        maker.tick().await.unwrap();
        if maker.view(&mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(
        maker.view(&mid).unwrap().unwrap().state,
        SwapState::MakerLockConfirmed
    );
    ml.advance_time(m.delay_secs);
    divi.advance_time(m.delay_secs);

    let secs = block_secs(m.chain);
    // One block per round, and on USDC (12 s blocks) one round a minute: a block a minute
    // gets the claim mined, the rest of the minute passes with nothing mined.
    let round = secs.max(60);
    let at = |f: u16| cap * u64::from(f) / 1000;
    let mut leaked = false;
    for i in 0..400usize {
        let (bf, mf) = m.floors[i.min(m.floors.len() - 1)];
        let block_floor = at(bf).max(1);
        ml.set_block_floor(block_floor);
        ml.set_mempool_floor(at(mf).min(block_floor));
        let view = maker.view(&mid).unwrap();
        let _ = taker.step(&tid, view.as_ref()).await;
        let _ = maker.tick().await;
        let mrec = store.get_maker_swap(&mid).unwrap().unwrap();
        if let (Some(htlc), Some(f)) = (mrec.maker_leg_htlc, mrec.maker_leg_funding) {
            if ml.mtp() >= htlc.locktime {
                if let Ok(tx) = hostile.build_refund(&htlc, &f.outpoint, f.amount).await {
                    let _ = hostile.broadcast(&tx).await;
                }
            }
        }
        leaked |= store
            .get_taker_swap(&tid)
            .unwrap()
            .unwrap()
            .maker_leg_claim
            .is_some();
        if round > secs {
            ml.advance_time(round - secs);
        }
        ml.mine(1);
        divi.mine(1);
        divi.advance_time(round.saturating_sub(60));
        let t = store.get_taker_swap(&tid).unwrap().unwrap().state;
        let mk = maker.view(&mid).unwrap().unwrap().state;
        if t.is_terminal() && mk == SwapState::Done {
            break;
        }
    }
    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let mut claimed = false;
    for c in rec
        .maker_leg_claim
        .iter()
        .chain(rec.claim_replaced.iter().map(|(c, _)| c))
    {
        claimed |= tml
            .confirmations(&c.txid)
            .await
            .unwrap()
            .is_some_and(|n| n >= 1);
    }
    Outcome {
        taker: rec.state,
        maker: maker.view(&mid).unwrap().unwrap().state,
        claimed,
        leaked,
        declined: rec.claim_declined.is_some(),
    }
}

fn run(m: &Market, escalation: bool) -> Outcome {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(race(m, escalation))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn with_escalation_and_the_margin_held_lost_is_unreachable(m in market()) {
        let o = run(&m, true);
        prop_assert_ne!(o.taker, TakerState::Lost, "{:?} {:?}", m, o);
        prop_assert!(o.taker.is_terminal() && o.maker == SwapState::Done, "{:?} {:?}", m, o);
        // Claimed whenever the preimage was out; otherwise declined and refunded.
        prop_assert_eq!(o.claimed, o.leaked, "{:?} {:?}", m, o);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn a_maker_refund_under_the_floor_never_costs_the_taker_its_leg(m in low_refund_market()) {
        // The maker may be left waiting on a refund that is never mined; the taker still
        // ends, never `Lost`, and has claimed exactly when the preimage was out.
        let o = run(&m, true);
        prop_assert_ne!(o.taker, TakerState::Lost, "{:?} {:?}", m, o);
        prop_assert!(o.taker.is_terminal(), "{:?} {:?}", m, o);
        prop_assert_eq!(o.claimed, o.leaked, "{:?} {:?}", m, o);
    }
}

fn congested(chain: Chain) -> Market {
    Market {
        chain,
        estimate: 10,
        delay_secs: 0,
        // The block floor sits at 40% of the cap throughout: far above the first claim,
        // well within reach of the escalation. The mempool takes the first claim (the
        // preimage is out), then its floor rises to the block floor and evicts it.
        floors: vec![(400, 0), (400, 1000)],
        refund_feerate: 5000,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn usdc_with_escalation_and_floors_under_cap_feerate_lost_is_unreachable(m in usdc_market()) {
        let o = run(&m, true);
        prop_assert_ne!(o.taker, TakerState::Lost, "{:?} {:?}", m, o);
        prop_assert!(o.taker.is_terminal() && o.maker == SwapState::Done, "{:?} {:?}", m, o);
        prop_assert_eq!(o.claimed, o.leaked, "{:?} {:?}", m, o);
    }
}

#[test]
fn a_usdc_floor_above_the_fifty_x_cap_after_the_leak_is_outbid_up_to_cap_feerate() {
    // First claim at 2 gwei (fixed cap 100), held out of the first block by a 100 gwei
    // floor (the preimage is out); then the block floor sits at 300 gwei. Past the cap
    // point `cap_feerate` (500) binds and the claim confirms; without escalation it never
    // does and the hostile refund takes the leg.
    let m = Market {
        chain: Chain::Usdc,
        estimate: 2,
        delay_secs: 0,
        floors: vec![(200, 0), (600, 0)],
        refund_feerate: 5000,
    };
    let on = run(&m, true);
    assert_eq!(
        (on.taker, on.claimed, on.leaked),
        (TakerState::Done, true, true),
        "{on:?}"
    );
    let off = run(&m, false);
    assert_eq!(
        (off.taker, off.claimed, off.leaked),
        (TakerState::Lost, false, true),
        "{off:?}"
    );
}

#[test]
fn a_congested_btc_market_is_won_with_escalation_and_lost_without() {
    let on = run(&congested(Chain::Btc), true);
    assert_eq!((on.taker, on.claimed), (TakerState::Done, true), "{on:?}");
    let off = run(&congested(Chain::Btc), false);
    assert_eq!(
        (off.taker, off.claimed, off.leaked),
        (TakerState::Lost, false, true),
        "{off:?}"
    );
}

#[test]
fn a_congested_ltc_market_is_won_with_escalation_and_lost_without() {
    let on = run(&congested(Chain::Ltc), true);
    assert_eq!((on.taker, on.claimed), (TakerState::Done, true), "{on:?}");
    let off = run(&congested(Chain::Ltc), false);
    assert_eq!(
        (off.taker, off.claimed, off.leaked),
        (TakerState::Lost, false, true),
        "{off:?}"
    );
}

#[test]
fn without_a_bump_a_zec_claim_paying_the_block_floor_confirms_in_time() {
    // No escalation exists for ZEC (the cap is the first claim's feerate), so the block
    // floor here equals what the first claim pays.
    let mut m = congested(Chain::Zec);
    m.floors = vec![(1000, 0)];
    let o = run(&m, true);
    assert_eq!((o.taker, o.claimed), (TakerState::Done, true), "{o:?}");
}

#[test]
fn a_block_floor_above_the_fixed_cap_after_the_leak_is_outbid_on_btc_and_ltc() {
    // The first claim (10) reaches the mempool, so the preimage is out. Then the block floor
    // sits at 1.5x the fixed cap (750 against 500) and the mempool floor at the cap, which
    // evicts the first claim. A taker held to the fixed cap cannot get mined: BTC loses to
    // the maker's refund and LTC sits unconfirmed at the cap. The post-leak ceiling (half
    // the leg, rising towards all of it) outbids the floor.
    for chain in [Chain::Btc, Chain::Ltc] {
        let mut m = congested(chain);
        m.floors = vec![(400, 0), (1500, 1000)];
        let o = run(&m, true);
        assert_eq!(
            (o.taker, o.claimed, o.leaked),
            (TakerState::Done, true, true),
            "{chain}: {o:?}"
        );
    }
}

#[test]
fn a_floor_above_half_the_leg_is_declined_before_the_preimage_is_revealed() {
    // The leg is 1M sat and the mock claim 100 vB: an estimate of 6000/vB is a 600 000 sat
    // claim, more than half the leg. Nothing has been revealed, so the taker declines and
    // both legs refund (the taker ends `Done` through `Refunded`). At 4900/vB (490 000 sat, under half) it still claims.
    for chain in [Chain::Btc, Chain::Ltc] {
        let mut m = congested(chain);
        m.estimate = 6000;
        m.floors = vec![(0, 0)];
        let o = run(&m, true);
        assert_eq!(
            (o.taker, o.declined, o.leaked, o.claimed),
            (TakerState::Done, true, false, false),
            "{chain}: {o:?}"
        );
        assert_eq!(o.maker, SwapState::Done, "{chain}: {o:?}");

        m.estimate = 4900;
        let o = run(&m, true);
        assert_eq!(
            (o.taker, o.declined, o.claimed),
            (TakerState::Done, false, true),
            "{chain}: {o:?}"
        );
    }
}

#[test]
fn a_declined_swap_leaves_a_maker_refund_under_the_floor_waiting_not_mined() {
    // Declined as above, but the block floor (the cap, here the 6000/vB estimate) stays
    // above what the maker's refund pays. The taker still refunds its own leg and ends
    // `Done`; the maker's refund is held back rather than lost track of, and the maker
    // waits in `MakerRefundable` with its leg unspent. Paying over the floor, it is mined.
    for chain in [Chain::Btc, Chain::Ltc] {
        let mut m = congested(chain);
        m.estimate = 6000;
        m.floors = vec![(1000, 0)];
        m.refund_feerate = 100;
        let o = run(&m, true);
        assert_eq!(
            (o.taker, o.declined, o.leaked, o.claimed, o.maker),
            (
                TakerState::Done,
                true,
                false,
                false,
                SwapState::MakerRefundable
            ),
            "{chain}: {o:?}"
        );

        m.refund_feerate = 20_000;
        let o = run(&m, true);
        assert_eq!(
            (o.taker, o.declined, o.maker),
            (TakerState::Done, true, SwapState::Done),
            "{chain}: {o:?}"
        );
    }
}

#[test]
fn a_maker_refund_under_the_floor_after_the_leak_is_outbid_by_the_claim() {
    // The leak of the floor-above-the-cap test, with the maker's refund paying 100/vB, under
    // every floor: it can never be mined, and the taker's claim confirms.
    for chain in [Chain::Btc, Chain::Ltc] {
        let mut m = congested(chain);
        m.floors = vec![(400, 0), (1500, 1000)];
        m.refund_feerate = 100;
        let o = run(&m, true);
        assert_eq!(
            (o.taker, o.claimed, o.leaked),
            (TakerState::Done, true, true),
            "{chain}: {o:?}"
        );
    }
}
