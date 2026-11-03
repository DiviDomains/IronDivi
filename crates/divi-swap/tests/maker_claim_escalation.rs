// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
use divi_swap::store::{ClaimFees, MakerRecord};
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
    /// The maker's persisted record at the end.
    record: MakerRecord,
    /// The maker's state in `Maker::list`, and the `state` of its JSON view.
    listed: (SwapState, String),
    /// Spend broadcasts on the taker-leg chain at the end, and after 20 more rounds of ticks.
    broadcasts: (u64, u64),
    /// `Maker::step` and the record's state after those 20 rounds.
    after: (SwapState, SwapState),
}

/// One swap with the taker paying `chain` (the maker claims on `chain`), revealed at the
/// taker's claim deadline, the taker-leg chain mining nothing under `floor` from then on.
async fn race(chain: Chain, escalation: bool) -> Outcome {
    let esc = FeeEscalation::builtin(chain).unwrap();
    let floor = (MOCK_FEERATE * 10).min(esc.cap(MOCK_FEERATE) / 2);
    assert!(floor > MOCK_FEERATE && floor < esc.cap(MOCK_FEERATE));
    let refund_feerate = esc.cap(MOCK_FEERATE) * 4;
    race_with(
        chain,
        escalation.then_some(esc),
        MOCK_FEERATE,
        floor,
        refund_feerate,
    )
    .await
}

/// [`race`] with the maker's schedule `esc` (`None`: off), its first claim priced at
/// `base`, the block floor `floor` from the reveal on and the hostile refund paying
/// `refund_feerate`.
async fn race_with(
    chain: Chain,
    esc: Option<FeeEscalation>,
    base: u64,
    floor: u64,
    refund_feerate: u64,
) -> Outcome {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let tl = MockChain::new(chain, T0, block_secs(chain));
    tl.set_fee_bump(bump(chain));
    tl.set_fee_estimate(base);
    tl.set_refund_feerate(refund_feerate);
    let (mdivi, mtl): (MockBackend, MockBackend) =
        (divi.backend(1, Amount(FUNDS)), tl.backend(2, Amount(FUNDS)));
    let (tdivi, ttl) = (divi.backend(3, Amount(FUNDS)), tl.backend(4, Amount(FUNDS)));
    let hostile = ttl.clone();
    let maker_pk = mtl.pubkey();
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
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
    .unwrap()
    .with_fee_escalation(chain, esc);
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
        if mk.is_terminal() || tl.mtp() > taker_htlc.locktime + 7200 {
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
    let record = store.get_maker_swap(&mid).unwrap().unwrap();
    let listed = maker.list().unwrap();
    let listed = listed.iter().find(|v| v.id == mid).unwrap();
    let json = serde_json::to_value(listed).unwrap();
    let listed = (listed.state, json["state"].as_str().unwrap().to_string());
    let sent = tl.spend_broadcasts();
    let maker_state = maker.view(&mid).unwrap().unwrap().state;
    // Keep the watcher running: nothing may be resent or move once the swap is terminal.
    for _ in 0..20 {
        let _ = maker.tick().await;
        tl.advance_time(300u32.saturating_sub(block_secs(chain)));
        tl.mine(1);
        divi.mine(1);
    }
    let stepped = maker.step(&mid).await.unwrap();
    let after = (stepped, store.get_maker_swap(&mid).unwrap().unwrap().state);
    Outcome {
        maker: maker_state,
        maker_gained: tl.balance(&maker_pk).0 > before,
        refunded,
        fees: record.claim_fees.clone(),
        record,
        listed,
        broadcasts: (sent, tl.spend_broadcasts()),
        after,
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

/// The maker twin of `taker_fee_escalation::usdc_claim_after_the_leak_outbids_a_floor_above_the_fifty_x_cap`:
/// the maker's USDC claim of the taker leg, first priced at 2 gwei (mock units as gwei,
/// `cap_feerate` 500), meets a 300 gwei floor from the reveal on. Past the cap point the
/// 50x cap (100 gwei) no longer binds; the claim climbs to `cap_feerate` and beats the
/// hostile taker's refund.
#[tokio::test]
async fn a_usdc_maker_claim_after_the_leak_outbids_a_floor_above_the_fifty_x_cap() {
    let esc = FeeEscalation::builtin(Chain::Usdc)
        .unwrap()
        .with_cap_feerate(500);
    assert_eq!(esc.cap(2), 100);
    let o = race_with(Chain::Usdc, Some(esc), 2, 300, 9000).await;
    let f = &o.fees;
    let ctx = format!("{:?} {f:?} {:?}", o.maker, o.record.last_error);
    assert!(!o.refunded, "the taker refunded the taker leg: {ctx}");
    assert!(o.maker_gained, "the maker's claim never paid out: {ctx}");
    assert_eq!(o.maker, SwapState::Done, "{ctx}");
    assert_eq!(f.claim_base_feerate, Some(2), "{ctx}");
    assert!(
        f.claim_feerate.is_some_and(|r| (300..=500).contains(&r)),
        "{ctx}"
    );
    assert!(f.claim_replaced.iter().all(|(_, r)| *r <= 500), "{ctx}");
}

#[tokio::test]
async fn without_escalation_the_stuck_maker_claim_loses_the_taker_leg() {
    let o = race(Chain::Btc, false).await;
    assert!(o.refunded, "the hostile taker's refund confirmed");
    assert!(!o.maker_gained, "the maker got nothing for its leg");
    // The loss is recorded on the swap, not only returned as an error.
    assert_eq!(o.maker, SwapState::Lost, "{:?}", o.record.last_error);
    assert_eq!(o.record.state, SwapState::Lost);
    let err = o.record.last_error.as_deref().unwrap_or_default();
    assert!(err.starts_with("lost: "), "{err}");
    assert!(err.contains("refunded"), "{err}");
    // The never-confirmed claim is no longer reported as the taker leg's spend.
    assert!(o.record.taker_leg_claim.is_none());
    assert_eq!(o.listed, (SwapState::Lost, "Lost".to_string()));
    // Terminal: the watcher stops resending and nothing moves it.
    assert_eq!(o.broadcasts.0, o.broadcasts.1, "claim resent after Lost");
    assert_eq!(o.after, (SwapState::Lost, SwapState::Lost));
}

#[tokio::test]
async fn a_won_claim_stays_done_and_is_not_resent() {
    let o = race(Chain::Btc, true).await;
    assert_eq!(o.maker, SwapState::Done);
    assert_eq!(o.listed, (SwapState::Done, "Done".to_string()));
    assert_eq!(o.broadcasts.0, o.broadcasts.1);
    assert_eq!(o.after, (SwapState::Done, SwapState::Done));
}

#[tokio::test]
async fn an_ltc_maker_claim_replacing_its_child_keeps_climbing_after_a_crash_where_the_node_takes_no_child_replacement(
) {
    // Switched on, on a node that refuses child replacements: the crash loses the
    // replacement after the record dropped the child it replaced.
    let chain = Chain::Ltc;
    let esc = FeeEscalation {
        replace_cpfp_child: true,
        ..FeeEscalation::builtin(chain).unwrap()
    };
    let step = block_secs(chain);
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let tl = MockChain::new(chain, T0, step);
    tl.set_fee_bump(FeeBump::Cpfp);
    tl.set_child_replacement(false);
    let (tdivi, ttl) = (divi.backend(3, Amount(FUNDS)), tl.backend(4, Amount(FUNDS)));
    let mtl = tl.backend(2, Amount(FUNDS));
    let mdivi = divi.backend(1, Amount(FUNDS));
    let store = Store::in_memory().unwrap();
    let new_maker = || {
        Maker::new(
            SwapConfig::profile(Profile::Testnet),
            Arc::new(mdivi.clone()),
            Arc::new(mtl.clone()),
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
        .unwrap()
        .with_fee_escalation(chain, Some(esc))
    };
    let taker = Taker::new(Arc::new(tdivi), Arc::new(ttl), store.clone());
    let fees = |mid: &str| store.get_maker_swap(mid).unwrap().unwrap().claim_fees;

    let (mid, locktime, held) = {
        let maker = new_maker();
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
        let mut state = TakerState::Locked;
        for _ in 0..3 {
            state = taker.step(&tid, Some(&view)).await.unwrap();
            if state == TakerState::Claimed {
                break;
            }
        }
        assert_eq!(state, TakerState::Claimed);
        // From here nothing on the taker-leg chain is mined until the end.
        divi.mine(1);
        for _ in 0..3 {
            let _ = maker.tick().await;
        }
        let rec = store.get_maker_swap(&mid).unwrap().unwrap();
        assert_eq!(rec.state, SwapState::MakerClaimed);
        let locktime = rec.taker_leg_htlc.locktime;
        // Ride to the first child, which the node holds.
        while fees(&mid).claim_children.is_empty() {
            assert!(tl.mtp() + step < locktime);
            tl.advance_time(step);
            maker.step(&mid).await.unwrap();
        }
        let held = fees(&mid).claim_children;
        assert!(held.iter().all(|c| tl.feerate_of(&c.txid).is_some()));
        // The next bump, a replacement of the held child, is written ahead and never sent.
        tl.lose_next_new_broadcast();
        loop {
            assert!(tl.mtp() + step < locktime);
            tl.advance_time(step);
            let _ = maker.step(&mid).await;
            if fees(&mid)
                .claim_children
                .iter()
                .any(|c| tl.feerate_of(&c.txid).is_none())
            {
                break;
            }
        }
        (mid, locktime, held)
    };
    let at_crash = fees(&mid).claim_feerate.unwrap();

    // Restart on the same store; the climb resumes on top of the held child.
    let maker = new_maker();
    let mut seen = Vec::new();
    while tl.mtp() + step < locktime {
        tl.advance_time(step);
        let _ = maker.step(&mid).await;
        let rec = store.get_maker_swap(&mid).unwrap().unwrap();
        assert_eq!(rec.state, SwapState::MakerClaimed);
        seen.push(rec.claim_fees.claim_feerate.unwrap());
    }
    let f = fees(&mid);
    let after = f.claim_feerate.unwrap();
    assert!(
        after > at_crash,
        "{after} after the restart, {at_crash} at the crash: {seen:?}"
    );
    let n = f.claim_children.len();
    assert!(n >= held.len() + 2, "{n} children: {seen:?}");
    for (i, child) in f.claim_children.iter().enumerate() {
        assert!(
            tl.feerate_of(&child.txid).is_some(),
            "child {i} of {n} not relayed: {seen:?}"
        );
    }
    for child in &held {
        assert!(
            f.claim_children.contains(child),
            "the held child stays in the package"
        );
    }
    assert_eq!(tl.longest_unconfirmed_chain(), n as u64 + 1);

    tl.mine(1);
    assert_eq!(maker.step(&mid).await.unwrap(), SwapState::Done);
}
