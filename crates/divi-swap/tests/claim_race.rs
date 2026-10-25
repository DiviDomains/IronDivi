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
//! is mined) and a mempool floor (below which claims are evicted and refused), both at most
//! the escalation cap, and a fee estimate the first claim trusts.
//!
//! Property: with fee escalation on and the claim-deadline margin held, `Lost` is
//! unreachable on BTC (RBF) and LTC (CPFP). The same market with escalation off loses.
//! ZEC (and DIVI) cannot bump at all (no replacement, CPFP inert): the margin is all they
//! have, so there the test is only that a claim paying the block floor confirms in time.
//!
//! `PROPTEST_CASES=2000` runs a longer search than the default.

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
    /// the escalation cap. Repeats its last entry once exhausted.
    floors: Vec<(u16, u16)>,
    /// What the maker's refund of its leg pays.
    refund_feerate: u64,
}

fn market() -> impl Strategy<Value = Market> {
    (
        prop_oneof![Just(Chain::Btc), Just(Chain::Ltc)],
        1u64..60,
        0u32..7200,
        proptest::collection::vec((0u16..=1000, 0u16..=1000), 1..40),
        1000u64..20_000,
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

fn block_secs(chain: Chain) -> u32 {
    match chain {
        Chain::Btc => 600,
        Chain::Ltc => 150,
        Chain::Zec => 75,
        _ => 60,
    }
}

fn bump(chain: Chain) -> FeeBump {
    match chain {
        Chain::Btc => FeeBump::Rbf,
        Chain::Ltc => FeeBump::Cpfp,
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
    let mut taker = Taker::new(Arc::new(tdivi), Arc::new(tml.clone()), store.clone());
    if !escalation {
        taker = taker.with_fee_escalation(m.chain, None);
    }
    let cap = FeeEscalation::builtin(m.chain).map_or(m.estimate, |e| e.cap(m.estimate));

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
        ml.mine(1);
        divi.mine(1);
        divi.advance_time(secs.saturating_sub(60));
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
