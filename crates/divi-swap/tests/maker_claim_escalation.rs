// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Fee escalation of the maker's taker-leg claim. The taker reveals the preimage as late as
//! its claim deadline allows; from then on the maker keeps the taker leg only if its claim
//! confirms before the taker-leg locktime, after which the taker's refund takes the leg back
//! (a hostile taker sends one although its own claim of the maker leg already won, paying
//! far more). A block floor above the first claim's feerate but under the fixed cap holds
//! the claim out of every block unless it is bumped: with escalation on the maker wins on
//! BTC (RBF), LTC (CPFP) and USDC (same nonce); with it off the taker refunds and the maker
//! has paid out both legs.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain, MOCK_FEERATE};
use divi_swap::store::ClaimFees;
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, FeeBump, FeeEscalation, Maker, Profile, Store,
    SwapConfig, SwapState, Taker, TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
const SATS: u64 = 1_000_000;

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

struct Outcome {
    /// The maker's final state.
    maker: SwapState,
    /// The maker's balance on the taker-leg chain gained the leg (less fees).
    maker_gained: bool,
    /// The hostile taker's refund of the taker leg confirmed.
    refunded: bool,
    /// The maker's persisted claim fee history.
    fees: ClaimFees,
}

/// One swap with the taker paying `chain` (the maker claims on `chain`), revealed at the
/// taker's claim deadline, the taker-leg chain mining nothing under `floor` from then on.
async fn race(chain: Chain, escalation: bool) -> Outcome {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let tl = MockChain::new(chain, T0, block_secs(chain));
    tl.set_fee_bump(bump(chain));
    let esc = FeeEscalation::builtin(chain).unwrap();
    let floor = (MOCK_FEERATE * 10).min(esc.cap(MOCK_FEERATE) / 2);
    assert!(floor > MOCK_FEERATE && floor < esc.cap(MOCK_FEERATE));
    tl.set_refund_feerate(esc.cap(MOCK_FEERATE) * 4);
    let (mdivi, mtl): (MockBackend, MockBackend) =
        (divi.backend(1, Amount(FUNDS)), tl.backend(2, Amount(FUNDS)));
    let (tdivi, ttl) = (divi.backend(3, Amount(FUNDS)), tl.backend(4, Amount(FUNDS)));
    let hostile = ttl.clone();
    let maker_pk = mtl.pubkey();
    let store = Store::in_memory().unwrap();
    let mut maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(mdivi),
        Arc::new(mtl),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: chain,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();
    if !escalation {
        maker = maker.with_fee_escalation(chain, None);
    }
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

    // The taker waits until just inside its own claim deadline on the maker leg (DIVI).
    let maker_locktime = view.maker_leg.as_ref().unwrap().htlc.locktime;
    let reveal_at = maker_locktime - ClaimDeadline::builtin(Chain::Divi).margin_secs() - 120;
    let wait = reveal_at.saturating_sub(divi.mtp());
    divi.advance_time(wait);
    tl.advance_time(wait);
    let mut state = TakerState::Locked;
    for _ in 0..3 {
        state = taker.step(&tid, Some(&view)).await.unwrap();
        if state == TakerState::Claimed {
            break;
        }
    }
    assert_eq!(state, TakerState::Claimed);
    tl.set_block_floor(floor);

    let rec = store.get_maker_swap(&mid).unwrap().unwrap();
    let (taker_htlc, at, amount) = (
        rec.taker_leg_htlc,
        rec.taker_leg_outpoint.unwrap(),
        rec.taker_leg_locked.unwrap(),
    );
    let before = tl.balance(&maker_pk).0;
    let mut refund = None;
    for _ in 0..200 {
        let _ = taker.step(&tid, Some(&view)).await;
        let _ = maker.tick().await;
        if refund.is_none() && tl.mtp() >= taker_htlc.locktime {
            if let Ok(tx) = hostile.build_refund(&taker_htlc, &at, amount).await {
                if hostile.broadcast(&tx).await.is_ok() {
                    refund = Some(tx.txid);
                }
            }
        }
        tl.advance_time(300u32.saturating_sub(block_secs(chain)));
        tl.mine(1);
        divi.advance_time(240);
        divi.mine(1);
        let mk = maker.view(&mid).unwrap().unwrap().state;
        if mk == SwapState::Done || tl.mtp() > taker_htlc.locktime + 7200 {
            break;
        }
    }
    let refunded = match refund {
        Some(id) => hostile
            .confirmations(&id)
            .await
            .unwrap()
            .is_some_and(|c| c >= 1),
        None => false,
    };
    Outcome {
        maker: maker.view(&mid).unwrap().unwrap().state,
        maker_gained: tl.balance(&maker_pk).0 > before,
        refunded,
        fees: store.get_maker_swap(&mid).unwrap().unwrap().claim_fees,
    }
}

async fn wins_with_escalation(chain: Chain) {
    let o = race(chain, true).await;
    assert!(!o.refunded, "{chain}: the taker refunded the taker leg");
    assert!(o.maker_gained, "{chain}: the maker's claim never paid out");
    assert_eq!(o.maker, SwapState::Done, "{chain}");
    let f = &o.fees;
    assert_eq!(f.claim_base_feerate, Some(MOCK_FEERATE), "{chain}");
    assert!(
        f.claim_feerate.unwrap() >= (MOCK_FEERATE * 10),
        "{chain}: {f:?}"
    );
    match bump(chain) {
        FeeBump::Cpfp => assert!(!f.claim_children.is_empty() && f.claim_replaced.is_empty()),
        _ => assert!(!f.claim_replaced.is_empty() && f.claim_children.is_empty()),
    }
}

#[tokio::test]
async fn a_stuck_btc_maker_claim_is_replaced_and_beats_the_taker_refund() {
    wins_with_escalation(Chain::Btc).await;
}

#[tokio::test]
async fn a_stuck_ltc_maker_claim_is_bumped_by_cpfp_and_beats_the_taker_refund() {
    wins_with_escalation(Chain::Ltc).await;
}

#[tokio::test]
async fn a_stuck_usdc_maker_claim_is_replaced_at_its_nonce_and_beats_the_taker_refund() {
    wins_with_escalation(Chain::Usdc).await;
}

#[tokio::test]
async fn without_escalation_the_stuck_maker_claim_loses_the_taker_leg() {
    let o = race(Chain::Btc, false).await;
    assert!(o.refunded, "the hostile taker's refund confirmed");
    assert!(!o.maker_gained, "the maker got nothing for its leg");
}
