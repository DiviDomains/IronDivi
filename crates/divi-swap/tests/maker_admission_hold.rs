// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify it under the terms
// of the GNU Affero General Public License as published by the Free Software Foundation,
// version 3.

//! An admission hold on the counter chain stops new swaps and never strands a signed lock.
//! A maker lock persisted before its `maker_lock_sent` marker may already have been
//! broadcast (crash between the send and the marker) and an endpoint can lag in showing it:
//! an absent observation is "unknown", so under a hold it is neither aborted nor released
//! nor first-broadcast; a lock the chain shows is marked sent and claims/refunds run on.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, HtlcParams, InputReservations, Maker, Outpoint, Profile, Store,
    SwapConfig, SwapState, Taker, TakerState, Txid,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
const COINS: [Outpoint; 2] = [coin(0xc1), coin(0xc2)];

const fn coin(n: u8) -> Outpoint {
    Outpoint {
        txid: Txid([n; 32]),
        vout: 0,
    }
}

struct World {
    divi: MockChain,
    btc: MockChain,
    res: InputReservations,
    /// The maker-leg (DIVI) backend; also what a restarted maker is rebuilt over.
    mdivi: MockBackend,
    mbtc: MockBackend,
    store: Store,
    maker: Maker,
    taker: Taker,
    mid: String,
    tid: String,
}

fn offers() -> Vec<Offer> {
    vec![Offer {
        id: "o".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }]
}

impl World {
    /// Drop the maker and rebuild it over the same database and backends, as after a
    /// crash, with the BTC counter chain held (`held`) or not.
    fn restart(&mut self, held: bool) {
        let have = self.divi.balance(&self.mdivi.pubkey());
        self.mdivi = self
            .divi
            .backend(1, have)
            .with_input_reservations(self.res.clone(), &COINS);
        let m = Maker::new(
            SwapConfig::profile(Profile::Testnet),
            Arc::new(self.mdivi.clone()),
            Arc::new(self.mbtc.clone()),
            self.store.clone(),
            offers(),
        )
        .unwrap();
        self.maker = if held {
            m.with_admission_hold(Chain::Btc, "advisory")
        } else {
            m
        };
    }

    fn rec(&self) -> divi_swap::store::MakerRecord {
        self.store.get_maker_swap(&self.mid).unwrap().unwrap()
    }

    async fn round(&self) {
        self.divi.mine(1);
        self.btc.mine(1);
        let _ = self.maker.tick().await;
        let view = self.maker.view(&self.mid).unwrap();
        let _ = self.taker.step(&self.tid, view.as_ref()).await;
    }

    /// A second daemon on the same reservation table: which coin does it get?
    async fn other_daemon_coin(&self) -> Outpoint {
        let have = self.divi.balance(&self.mdivi.pubkey());
        let other = self
            .divi
            .backend(1, have)
            .with_input_reservations(self.res.clone(), &COINS);
        self.next_coin(&other).await
    }

    async fn next_coin(&self, backend: &MockBackend) -> Outpoint {
        let mut htlc: HtlcParams = self.rec().maker_leg_htlc.unwrap();
        htlc.hash = [0x99; 32];
        let f = backend
            .build_funding(&htlc, Amount(1_000_000))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&f.tx.raw).unwrap();
        let ins: Vec<Outpoint> = serde_json::from_value(v["Fund"]["inputs"].clone()).unwrap();
        ins[0]
    }
}

/// Maker leg on DIVI, taker leg on BTC. Halts with the maker's lock persisted and unsent
/// (`stop` = `MakerLocked`), or right after `accept` (`Accepted`).
async fn world(stop: SwapState) -> World {
    world_on(stop, Chain::Btc).await
}

async fn world_on(stop: SwapState, counter: Chain) -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let btc = MockChain::new(counter, T0, 600);
    let res = InputReservations::in_memory().unwrap();
    let mdivi = divi
        .backend(1, Amount(FUNDS))
        .with_input_reservations(res.clone(), &COINS);
    let mbtc = btc.backend(1, Amount(FUNDS));
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(mdivi.clone()),
        Arc::new(mbtc.clone()),
        store.clone(),
        vec![Offer {
            counter_chain: counter,
            ..offers().remove(0)
        }],
    )
    .unwrap();
    let taker = Taker::new(
        Arc::new(divi.backend(3, Amount(FUNDS))),
        Arc::new(btc.backend(4, Amount(FUNDS))),
        store.clone(),
    );
    let q = maker.quote("o", 1_000_000).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let mut mid = v.id.clone();
    if matches!(stop, SwapState::TakerLockConfirmed | SwapState::MakerLocked) {
        let notice = taker.lock(&tid).await.unwrap();
        mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    }
    let w = World {
        divi,
        btc,
        res,
        mdivi,
        mbtc,
        store,
        maker,
        taker,
        mid,
        tid,
    };
    if matches!(stop, SwapState::TakerLockConfirmed | SwapState::MakerLocked) {
        w.maker.halt_after(Some(stop));
        for _ in 0..20 {
            w.divi.mine(1);
            w.btc.mine(1);
            let _ = w.maker.step(&w.mid).await;
            if w.rec().state == stop {
                break;
            }
        }
        w.maker.halt_after(None);
        assert_eq!(w.rec().state, stop);
        assert!(!w.rec().maker_lock_sent);
    }
    w
}

#[tokio::test]
async fn a_held_maker_refuses_quote_and_accept_and_aborts_an_unlocked_swap() {
    let mut w = world(SwapState::Accepted).await;
    let q = w.maker.quote("o", 1_000_000).await.unwrap();
    let (_, req) = w.taker.prepare(&q).await.unwrap();
    w.restart(true);
    assert!(w.maker.quote("o", 1_000_000).await.is_err());
    assert!(w.maker.accept(req).await.is_err());
    w.maker.tick().await.unwrap();
    assert_eq!(w.rec().state, SwapState::Aborted);
}

/// The signed lock is persisted, nothing shows it on the chain (a send that never happened,
/// or one an endpoint does not see yet): under the hold it stays exactly as it was, however
/// often it is re-read, with its coin still reserved and nothing sent. Without the hold the
/// same record is sent.
#[tokio::test]
async fn an_unseen_signed_lock_is_kept_unsent_and_unreleased_under_a_hold() {
    let mut w = world(SwapState::MakerLocked).await;
    let before = w.rec();
    let txid = before.maker_leg_funding.clone().unwrap().tx.txid;
    w.restart(true);
    for _ in 0..3 {
        w.maker.tick().await.unwrap();
        w.divi.mine(1);
    }
    let after = w.rec();
    assert_eq!(after.state, SwapState::MakerLocked);
    assert!(!after.maker_lock_sent);
    assert_eq!(after.maker_leg_funding.unwrap().tx.txid, txid);
    assert!(!w.divi.contains(&txid), "no first broadcast under a hold");
    assert_ne!(
        w.next_coin(&w.mdivi).await,
        COINS[0],
        "before first broadcast the restarted maker restores its local input reservation"
    );

    // A failing read is retried, not read as "never sent".
    w.divi
        .fail_with(Some(divi_swap::SwapError::Transient("down".into())));
    let _ = w.maker.tick().await;
    w.divi.fail_with(None);
    assert_eq!(w.rec().state, SwapState::MakerLocked);

    // Hold lifted (the explicit new-broadcast policy): the persisted lock goes out.
    w.restart(false);
    w.maker.tick().await.unwrap();
    assert!(w.divi.contains(&txid));
    assert!(w.rec().maker_lock_sent);
}

/// Crash between the broadcast and the marker, and the endpoint cannot see the lock yet
/// (`blind`): the hold neither aborts it nor releases its coin.
#[tokio::test]
async fn an_ambiguous_send_is_never_aborted_under_a_hold() {
    let mut w = world(SwapState::MakerLocked).await;
    let f = w.rec().maker_leg_funding.unwrap();
    w.mdivi.broadcast(&f.tx).await.unwrap();
    w.divi.blind(&f.tx.txid);
    w.restart(true);
    for _ in 0..3 {
        w.maker.tick().await.unwrap();
    }
    assert_eq!(w.rec().state, SwapState::MakerLocked);
    assert!(w.rec().last_error.is_none(), "{:?}", w.rec().last_error);
    assert_ne!(w.other_daemon_coin().await, COINS[0]);
}

/// Crash after the broadcast, the chain shows the lock: under the hold it is marked sent
/// and the swap runs to the end, the taker's claim and the maker's claim included.
#[tokio::test]
async fn a_lock_the_chain_shows_runs_on_under_a_hold() {
    let mut w = world(SwapState::MakerLocked).await;
    let f = w.rec().maker_leg_funding.unwrap();
    w.mdivi.broadcast(&f.tx).await.unwrap();
    w.restart(true);
    w.maker.tick().await.unwrap();
    assert!(w.rec().maker_lock_sent);
    for _ in 0..60 {
        w.round().await;
        let t = w.store.get_taker_swap(&w.tid).unwrap().unwrap().state;
        if t == TakerState::Done && w.rec().state == SwapState::Done {
            return;
        }
    }
    panic!(
        "not done: maker {:?} ({:?})",
        w.rec().state,
        w.rec().last_error
    );
}

#[tokio::test]
async fn maker_first_send_requires_bound_counter_but_observed_funding_recovers() {
    use divi_swap::backend::UsdcAdmission;
    let w = world_on(SwapState::MakerLocked, Chain::Usdc).await;
    let mut rec = w.rec();
    assert_eq!(rec.usdc_admission, Some(UsdcAdmission::Mock));
    let funding = rec.maker_leg_funding.clone().unwrap();
    for binding in [None, Some(UsdcAdmission::Evm(84532))] {
        rec.usdc_admission = binding;
        w.store.put_maker_swap(&rec).unwrap();
        assert!(w.maker.step(&w.mid).await.is_err());
        assert!(!w.rec().maker_lock_sent);
        assert!(!w.divi.contains(&funding.tx.txid));
    }
    w.mdivi.broadcast(&funding.tx).await.unwrap();
    w.maker.step(&w.mid).await.unwrap();
    assert!(w.rec().maker_lock_sent);
}

#[tokio::test]
async fn maker_skips_divi_coin_selection_for_unbound_usdc() {
    let w = world_on(SwapState::TakerLockConfirmed, Chain::Usdc).await;
    let mut rec = w.rec();
    rec.usdc_admission = None;
    w.store.put_maker_swap(&rec).unwrap();
    let calls = w.mdivi.funding_calls();
    assert!(w
        .maker
        .step(&w.mid)
        .await
        .unwrap_err()
        .to_string()
        .contains("fresh quote"));
    assert_eq!(w.mdivi.funding_calls(), calls);
    assert!(w.rec().maker_leg_funding.is_none());
}

#[tokio::test]
async fn usdc_pending_locks_keep_both_roles_reservations_past_expiry() {
    let w = world_on(SwapState::MakerLocked, Chain::Usdc).await;
    let maker = w.rec();
    let funding = maker.maker_leg_funding.unwrap();
    let deadline = maker.maker_leg_htlc.unwrap().locktime;
    w.res
        .reserve(Chain::Divi, &funding.tx.txid, &[COINS[0]])
        .unwrap();
    let mut taker = w.store.get_taker_swap(&w.tid).unwrap().unwrap();
    // A second, local DIVI payer also crashed between its send and its marker.
    taker.quote.direction = Direction::TakerPaysDivi;
    taker.taker_leg_sent = false;
    taker.state = TakerState::Locked;
    let other = taker.taker_leg_funding.as_ref().unwrap().tx.txid;
    w.res.reserve(Chain::Divi, &other, &[COINS[1]]).unwrap();
    let end = deadline.max(taker.taker_leg_htlc.unwrap().locktime);
    w.store.put_taker_swap(&taker).unwrap();
    w.divi.advance_time(end - w.divi.mtp() + 1);
    for _ in 0..20 {
        w.divi.mine(1);
        let now = w.divi.mtp();
        assert_eq!(
            w.res
                .release_expired_swaps(&w.store, &w.mdivi, now)
                .await
                .unwrap(),
            0
        );
        assert_eq!(w.res.list_all().unwrap().len(), 2);
    }
    // With a persisted send marker the ordinary six-block expiry policy applies.
    taker.taker_leg_sent = true;
    w.store.put_taker_swap(&taker).unwrap();
    for _ in 0..12 {
        w.divi.mine(1);
        w.res
            .release_expired_swaps(&w.store, &w.mdivi, w.divi.mtp())
            .await
            .unwrap();
    }
    let rows = w.res.list_all().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reserved_by, funding.tx.txid);
}
