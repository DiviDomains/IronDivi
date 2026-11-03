// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The claim-vs-refund race on the taker leg, the maker's side of `claim_race`. The taker
//! claims the maker leg (DIVI) at a drawn time up to its claim deadline, which puts the
//! preimage out; from then on the maker keeps the taker leg only if its claim confirms
//! before the taker-leg locktime, after which a hostile taker sends its refund (paying far
//! more) although its own claim already won.
//!
//! Random fee markets drive the taker-leg chain from the reveal on: per block, a block
//! floor and a mempool floor, and a fee estimate the maker's first claim trusts. BTC and
//! LTC floors go up to twice the fixed escalation cap, a fifth of the leg, under the
//! post-leak ceiling (half the leg and more); USDC floors go up to `cap_feerate`, with a
//! first claim priced down to 1 gwei, or within one price bump of `cap_feerate`.
//!
//! Property: with fee escalation on and every floor at or below the ceiling, the maker never
//! ends `Lost` on BTC (RBF), LTC (CPFP) or USDC (same nonce), and its claim confirms
//! whenever the preimage was out. A floor above the ceiling ends it `Lost`, the taker's
//! refund recorded: that is the bound ("detected, not prevented").
//!
//! `PROPTEST_CASES=5000` runs a longer search than the default.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, FeeBump, FeeEscalation, Maker, Profile, Store,
    SwapConfig, SwapState, Taker, TakerState,
};
use proptest::prelude::*;
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
const SATS: u64 = 1_000_000;

/// The USDC schedule at the mock's scale: one mock unit stands for one gwei, so the
/// builtin 500 gwei cap is 500 (the mock pays a claim's fee out of the 1M unit leg, where a
/// wei-denominated fee would not fit). Every rule of the schedule is a ratio.
const USDC_GWEI_CAP: u64 = 500;

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

#[derive(Debug, Clone)]
struct Market {
    chain: Chain,
    /// What `claim_feerate` reports, the maker's first claim's feerate.
    estimate: u64,
    /// When the taker reveals, per mille of the way from the maker's lock confirming to the
    /// taker's claim deadline on the maker leg (1000: at the deadline).
    reveal: u16,
    /// Per taker-leg block from the reveal on: block floor and mempool floor (feerates).
    /// Repeats its last entry once exhausted.
    floors: Vec<(u64, u64)>,
    /// What the hostile taker's refund of the taker leg pays: above every floor, so it is
    /// mined once the locktime passes, the worst case for the maker.
    refund_feerate: u64,
}

fn market() -> impl Strategy<Value = Market> {
    (
        prop_oneof![Just(Chain::Btc), Just(Chain::Ltc), Just(Chain::Usdc)],
        1u64..60,
        0u16..=1000,
        proptest::collection::vec((0u16..=2000, 0u16..=2000), 1..40),
        2000u64..20_000,
        prop_oneof![Just(None), (440u64..=USDC_GWEI_CAP).prop_map(Some)],
    )
        .prop_map(
            |(chain, estimate, reveal, floors, refund_feerate, near_cap)| {
                // Drawn per mille of the fixed cap (BTC, LTC: up to twice it) or of
                // `cap_feerate` (USDC: up to it).
                let esc = schedule(chain);
                // USDC: a first claim at 1 to 19 gwei, so the 50x multiple binds (under the
                // 500 gwei `cap_feerate`) about half the time; or, half the time, at 440 to 500
                // gwei, across the band within one price bump of `cap_feerate` (456 to 499 at
                // geth's 10%), where a version could never be replaced within the cap.
                let estimate = match (chain, near_cap) {
                    (Chain::Usdc, Some(near)) => near,
                    (Chain::Usdc, None) => 1 + estimate % 19,
                    _ => estimate,
                };
                let (cap, scale) = match chain {
                    Chain::Usdc => (esc.cap_feerate, 2000),
                    _ => (esc.cap(estimate), 1000),
                };
                // A first claim near the cap: floors between it and `cap_feerate`, the only
                // ones that hold it out of a block.
                let low = match (chain, near_cap) {
                    (Chain::Usdc, Some(_)) => estimate.min(cap),
                    _ => 0,
                };
                let at = |f: u16| low + (cap - low) * u64::from(f) / scale;
                let floors = floors.into_iter().map(|(b, m)| (at(b), at(m))).collect();
                Market {
                    chain,
                    estimate,
                    reveal,
                    floors,
                    refund_feerate,
                }
            },
        )
}

fn bump(chain: Chain) -> FeeBump {
    match chain {
        Chain::Btc => FeeBump::Rbf,
        Chain::Ltc => FeeBump::Cpfp,
        Chain::Usdc => FeeBump::SameNonce,
        _ => FeeBump::None,
    }
}

fn block_secs(chain: Chain) -> u32 {
    ClaimDeadline::builtin(chain).block_secs
}

/// The maker's schedule for `chain`: the builtin one, on USDC at the mock's scale.
fn schedule(chain: Chain) -> FeeEscalation {
    let esc = FeeEscalation::builtin(chain).unwrap();
    match chain {
        Chain::Usdc => esc.with_cap_feerate(USDC_GWEI_CAP),
        _ => esc,
    }
}

#[derive(Debug)]
struct Outcome {
    maker: SwapState,
    taker: TakerState,
    /// The taker claimed the maker leg (the preimage was out).
    leaked: bool,
    /// A maker claim of the taker leg confirmed.
    claimed: bool,
    /// The hostile refund of the taker leg confirmed, with its txid.
    refunded: Option<String>,
    /// The maker's `last_error`.
    last_error: Option<String>,
    /// The feerate the maker's claim (with its CPFP children) paid last, and how many
    /// children it had.
    fees: (Option<u64>, usize),
}

/// One swap through `m`, the taker paying `m.chain` so the maker claims the taker leg there.
async fn race(m: &Market) -> Outcome {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let tl = MockChain::new(m.chain, T0, block_secs(m.chain));
    tl.set_fee_bump(bump(m.chain));
    tl.set_fee_estimate(m.estimate);
    tl.set_refund_feerate(m.refund_feerate);
    let (mdivi, mtl): (MockBackend, MockBackend) =
        (divi.backend(1, Amount(FUNDS)), tl.backend(2, Amount(FUNDS)));
    let (tdivi, ttl) = (divi.backend(3, Amount(FUNDS)), tl.backend(4, Amount(FUNDS)));
    let hostile = ttl.clone();
    let store = Store::in_memory().unwrap();
    let esc = schedule(m.chain);
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(mdivi),
        Arc::new(mtl),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: m.chain,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap()
    .with_fee_escalation(m.chain, Some(esc));
    let taker = Taker::new(Arc::new(tdivi), Arc::new(ttl), store.clone());

    let q = maker.quote("o", SATS).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    for _ in 0..40 {
        divi.mine(1);
        tl.mine(1);
        maker.tick().await.unwrap();
        if maker.view(&mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    let view = maker.view(&mid).unwrap().unwrap();
    assert_eq!(view.state, SwapState::MakerLockConfirmed);

    // The taker reveals at the drawn point up to its claim deadline on the maker leg.
    let maker_locktime = view.maker_leg.as_ref().unwrap().htlc.locktime;
    let deadline = maker_locktime - ClaimDeadline::builtin(Chain::Divi).margin_secs();
    let span = deadline.saturating_sub(divi.mtp());
    let wait = (u64::from(span) * u64::from(m.reveal) / 1000) as u32;
    divi.advance_time(wait);
    tl.advance_time(wait);
    for _ in 0..3 {
        if taker.step(&tid, Some(&view)).await.ok() == Some(TakerState::Claimed) {
            break;
        }
    }
    let leaked = store
        .get_taker_swap(&tid)
        .unwrap()
        .unwrap()
        .maker_leg_claim
        .is_some();

    let rec = store.get_maker_swap(&mid).unwrap().unwrap();
    let (taker_htlc, at, amount) = (
        rec.taker_leg_htlc,
        rec.taker_leg_outpoint.unwrap(),
        rec.taker_leg_locked.unwrap(),
    );
    let secs = block_secs(m.chain);
    // One block per round, and on USDC (12 s blocks) one round a minute: a block a minute
    // gets the claim mined, the rest of the minute passes with nothing mined.
    let round = secs.max(60);
    let mut refund = None;
    for i in 0..1000usize {
        let (bf, mf) = m.floors[i.min(m.floors.len() - 1)];
        let block_floor = bf.max(1);
        tl.set_block_floor(block_floor);
        tl.set_mempool_floor(mf.min(block_floor));
        let _ = taker.step(&tid, Some(&view)).await;
        let _ = maker.tick().await;
        if refund.is_none() && tl.mtp() >= taker_htlc.locktime {
            if let Ok(tx) = hostile.build_refund(&taker_htlc, &at, amount).await {
                if hostile.broadcast(&tx).await.is_ok() {
                    refund = Some(tx.txid);
                }
            }
        }
        if round > secs {
            tl.advance_time(round - secs);
        }
        tl.mine(1);
        divi.advance_time(round.saturating_sub(60));
        divi.mine(1);
        let mk = maker.view(&mid).unwrap().unwrap().state;
        if mk.is_terminal() || tl.mtp() > taker_htlc.locktime + 7200 {
            break;
        }
    }
    let refunded = match refund {
        Some(id) => hostile
            .confirmations(&id)
            .await
            .unwrap()
            .is_some_and(|c| c >= 1)
            .then(|| id.to_string()),
        None => None,
    };
    let rec = store.get_maker_swap(&mid).unwrap().unwrap();
    let f = &rec.claim_fees;
    let mut claimed = false;
    for c in rec
        .taker_leg_claim
        .iter()
        .chain(f.claim_replaced.iter().map(|(c, _)| c))
    {
        claimed |= hostile
            .confirmations(&c.txid)
            .await
            .unwrap()
            .is_some_and(|n| n >= 1);
    }
    Outcome {
        maker: rec.state,
        taker: store.get_taker_swap(&tid).unwrap().unwrap().state,
        leaked,
        claimed,
        refunded,
        last_error: rec.last_error.clone(),
        fees: (f.claim_feerate, f.claim_children.len()),
    }
}

fn run(m: &Market) -> Outcome {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(race(m))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn with_escalation_and_floors_under_the_ceiling_the_maker_is_never_lost(m in market()) {
        let o = run(&m);
        prop_assert_ne!(o.maker, SwapState::Lost, "{:?} {:?}", m, o);
        prop_assert!(o.refunded.is_none(), "{:?} {:?}", m, o);
        // Revealed: the maker's claim confirmed and the swap is done.
        if o.leaked {
            prop_assert!(o.claimed && o.maker == SwapState::Done, "{:?} {:?}", m, o);
        }
    }
}

/// Found by the property at 5000 cases: the maker's USDC claim first priced at 14 gwei
/// (fixed cap 500, `cap_feerate`) under a 488 gwei block floor stopped at 487, from where
/// the step to 500 is under geth's 10% bump: never replaced, never mined, `Lost`.
#[test]
fn a_usdc_maker_claim_one_bump_short_of_the_cap_still_reaches_it() {
    let o = run(&Market {
        chain: Chain::Usdc,
        estimate: 14,
        reveal: 78,
        floors: vec![(488, 44)],
        refund_feerate: 2000,
    });
    assert_eq!(
        (o.maker, o.claimed, o.refunded.is_none()),
        (SwapState::Done, true, true),
        "{o:?}"
    );
}

/// Found by the property at 5000 cases: the maker's USDC claim first priced at 1 gwei
/// (fixed cap 50) under a 371 gwei block floor and a 128 gwei mempool floor, climbing to
/// `cap_feerate` only at the locktime, was short of the floor when the refund came.
#[test]
fn a_usdc_maker_claim_reaches_cap_feerate_blocks_before_the_locktime() {
    let o = run(&Market {
        chain: Chain::Usdc,
        estimate: 1,
        reveal: 101,
        floors: vec![(371, 128)],
        refund_feerate: 2000,
    });
    assert_eq!(
        (o.maker, o.claimed, o.refunded.is_none()),
        (SwapState::Done, true, true),
        "{o:?}"
    );
}

/// The maker's first USDC claim at the 475 gwei estimate: the next version would need 522
/// (geth's 10% bump), over the 500 gwei `cap_feerate`, so it could never be replaced. The
/// mempool takes it and the block floor sits at 490, under the cap.
#[test]
fn a_usdc_maker_first_claim_within_one_bump_of_the_cap_still_reaches_it() {
    let o = run(&Market {
        chain: Chain::Usdc,
        estimate: 475,
        reveal: 500,
        floors: vec![(490, 0)],
        refund_feerate: 2000,
    });
    assert_eq!(
        (o.maker, o.claimed, o.refunded.is_none()),
        (SwapState::Done, true, true),
        "{o:?}"
    );
}

/// A first claim at 455 gwei (replaceable once, to 500) refused by a 480 mempool floor is
/// re-signed one unit higher at a fresh nonce per refusal; taken at 480, inside the band,
/// it could never be replaced, under a 490 block floor.
#[test]
fn a_usdc_maker_claim_re_signed_into_the_band_after_a_refusal_still_reaches_the_cap() {
    let o = run(&Market {
        chain: Chain::Usdc,
        estimate: 455,
        reveal: 500,
        floors: vec![(490, 480)],
        refund_feerate: 2000,
    });
    assert_eq!(
        (o.maker, o.claimed, o.refunded.is_none()),
        (SwapState::Done, true, true),
        "{o:?}"
    );
}

/// The accepted analogue of residual path 1: a first claim near the cap under a 600 gwei
/// block floor, above `cap_feerate`, is never mined, and the hostile refund takes the leg.
#[test]
fn a_usdc_floor_above_cap_feerate_ends_a_maker_claim_near_the_cap_lost() {
    let o = run(&Market {
        chain: Chain::Usdc,
        estimate: 475,
        reveal: 500,
        floors: vec![(USDC_GWEI_CAP + 100, 0)],
        refund_feerate: 2000,
    });
    assert_eq!((o.maker, o.claimed), (SwapState::Lost, false), "{o:?}");
    assert!(o.refunded.is_some(), "{o:?}");
}

/// Revealed at the deadline, a first claim at 2, and from the reveal on a block floor of
/// `block_floor` and a mempool floor of `mempool_floor`.
fn floor_at(chain: Chain, block_floor: u64, mempool_floor: u64) -> Market {
    Market {
        chain,
        estimate: 2,
        reveal: 1000,
        floors: vec![(block_floor, mempool_floor)],
        refund_feerate: 20_000,
    }
}

/// A floor above the ceiling is the accepted bound: the maker's claim cannot pay it, the
/// mempool evicts it and the hostile refund (which takes the whole leg as its fee in the
/// mock, so meets the floor) confirms, and the maker ends `Lost` with the refund named in
/// `last_error`. BTC and LTC:
/// the post-leak ceiling tops out at the leg less one step (9999/vB on the mock's 1M sat
/// leg and 100 vB claim), so a 10 000/vB floor is above it. USDC: 600 gwei is above
/// `cap_feerate`. The same markets with the floor at the top of the property's range (twice
/// the fixed cap of 100; `cap_feerate` on USDC) are won. The ceiling is per vbyte of the
/// whole package: an LTC claim nine CPFP children deep is 1000 vB, so its ceiling there is
/// under 1000/vB, and a floor of 1000/vB is already above it (it tops out at 936).
#[test]
fn a_floor_above_the_ceiling_ends_the_maker_lost_with_the_refund_recorded() {
    for (chain, above, within) in [
        (Chain::Btc, 10_000u64, 200u64),
        (Chain::Ltc, 10_000, 200),
        (Chain::Usdc, USDC_GWEI_CAP + 100, USDC_GWEI_CAP),
    ] {
        let o = run(&floor_at(chain, above, above));
        let ctx = format!("{chain} at {above}: {o:?}");
        assert!(o.leaked, "{ctx}");
        assert_eq!(o.maker, SwapState::Lost, "{ctx}");
        assert!(!o.claimed, "{ctx}");
        let refund = o.refunded.clone().expect(&ctx);
        let err = o.last_error.clone().unwrap_or_default();
        assert!(err.starts_with("lost: ") && err.contains(&refund), "{ctx}");
        assert_eq!(o.taker, TakerState::Done, "{ctx}");

        let o = run(&floor_at(chain, within, 0));
        assert_eq!(
            (o.maker, o.claimed, o.refunded.is_none()),
            (SwapState::Done, true, true),
            "{chain} at {within}: {o:?}"
        );
    }
}

/// Residual path 5 of design note 4, pinned: on LTC (no replacement) a claim the mempool
/// never evicts, under a block floor above the ceiling, never mines, and the taker's refund
/// cannot replace it. The maker is neither paid nor `Lost`: it waits in `MakerClaimed`
/// (on a real node until the claim expires from the mempool, about two weeks).
#[test]
fn an_ltc_claim_never_evicted_under_a_floor_above_the_ceiling_waits_unresolved() {
    let o = run(&floor_at(Chain::Ltc, 10_000, 0));
    assert_eq!(
        (o.leaked, o.maker, o.claimed, o.refunded.is_none()),
        (true, SwapState::MakerClaimed, false, true),
        "{o:?}"
    );
    assert!(o.fees.1 > 0, "the maker kept bumping by CPFP: {o:?}");
}
