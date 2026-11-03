// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A maker lock that loses the coin race to another daemon on the same reservation table.
//! The table refuses the persisted funding before anything reaches the chain. Inside the
//! lock window the maker builds a new funding from other coins and locks. Past it, the swap
//! ends as for a maker that never locked. A refusal from the chain, or a send whose outcome
//! is unknown, keeps the persisted funding. Run with the maker leg on DIVI and on BTC.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain, TxKind};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, InputReservations, Maker, Outpoint, Profile,
    SignedTx, Store, SwapConfig, SwapError, SwapState, Taker, TakerState, Txid,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
/// The maker's wallet coins, in selection order.
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
    /// The maker's swap database's reservation table, shared by every daemon on it.
    res: InputReservations,
    /// The maker-leg backend of the maker under test.
    mk: MockBackend,
    store: Store,
    maker: Maker,
    taker: Taker,
    mid: String,
    tid: String,
}

impl World {
    /// The maker-leg chain.
    fn ml(&self, dir: Direction) -> &MockChain {
        match dir {
            Direction::TakerPaysBtc => &self.divi,
            Direction::TakerPaysDivi => &self.btc,
        }
    }

    /// The taker-leg chain.
    fn tl(&self, dir: Direction) -> &MockChain {
        match dir {
            Direction::TakerPaysBtc => &self.btc,
            Direction::TakerPaysDivi => &self.divi,
        }
    }

    fn mine(&self) {
        self.divi.mine(1);
        self.btc.mine(1);
    }

    fn rec(&self) -> divi_swap::store::MakerRecord {
        self.store.get_maker_swap(&self.mid).unwrap().unwrap()
    }

    fn funding(&self) -> Funding {
        self.rec().maker_leg_funding.expect("a persisted funding")
    }

    /// Another daemon on the same wallet key: its own backend on the maker-leg chain over
    /// `res` (the same table, or none in common) and `coins`.
    fn daemon(&self, dir: Direction, res: InputReservations, coins: &[Outpoint]) -> MockBackend {
        let chain = self.ml(dir);
        let have = chain.balance(&self.mk.pubkey());
        chain.backend(1, have).with_input_reservations(res, coins)
    }

    /// One round: blocks on both chains, a maker tick, a taker step on the maker's view.
    async fn round(&self) {
        self.mine();
        self.maker.tick().await.unwrap();
        let view = self.maker.view(&self.mid).unwrap();
        let _ = self.taker.step(&self.tid, view.as_ref()).await;
    }

    async fn run_to_done(&self) {
        for _ in 0..60 {
            self.round().await;
            let t = self.store.get_taker_swap(&self.tid).unwrap().unwrap().state;
            if t == TakerState::Done && self.rec().state == SwapState::Done {
                return;
            }
        }
        panic!(
            "not done: maker {:?} ({:?}), taker {:?}",
            self.rec().state,
            self.rec().last_error,
            self.store.get_taker_swap(&self.tid).unwrap().unwrap().state
        );
    }
}

/// Up to the maker's persisted lock: the taker locked and it confirmed, the maker selected
/// a coin and wrote the funding ahead, and halted there (nothing sent yet).
async fn locked_unsent(dir: Direction) -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let res = InputReservations::in_memory().unwrap();
    let (mdivi, mbtc) = (
        divi.backend(1, Amount(FUNDS)),
        btc.backend(1, Amount(FUNDS)),
    );
    let (mdivi, mbtc, mk) = match dir {
        Direction::TakerPaysBtc => {
            let m = mdivi.with_input_reservations(res.clone(), &COINS);
            (m.clone(), mbtc, m)
        }
        Direction::TakerPaysDivi => {
            let m = mbtc.with_input_reservations(res.clone(), &COINS);
            (mdivi, m.clone(), m)
        }
    };
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(mdivi),
        Arc::new(mbtc),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: dir,
            counter_chain: Chain::Btc,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
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
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    let w = World {
        divi,
        btc,
        res,
        mk,
        store,
        maker,
        taker,
        mid,
        tid,
    };
    w.maker.halt_after(Some(SwapState::MakerLocked));
    for _ in 0..20 {
        w.mine();
        let _ = w.maker.step(&w.mid).await;
        if w.rec().state == SwapState::MakerLocked {
            break;
        }
    }
    w.maker.halt_after(None);
    assert_eq!(w.rec().state, SwapState::MakerLocked);
    assert_eq!(w.mk.funding_calls(), 1);
    let f = w.funding();
    assert_eq!(inputs_of(&f.tx), vec![COINS[0]]);
    assert!(!w.ml(dir).contains(&f.tx.txid), "not sent yet");
    w
}

/// The coins a mock funding spends.
fn inputs_of(tx: &SignedTx) -> Vec<Outpoint> {
    let v: serde_json::Value = serde_json::from_slice(&tx.raw).unwrap();
    serde_json::from_value(v["Fund"]["inputs"].clone()).unwrap_or_default()
}

/// The other daemon's lock for its own swap, from `b`'s first free coin, sent.
async fn other_lock(w: &World, b: &MockBackend) -> Funding {
    let mut htlc: HtlcParams = w.rec().maker_leg_htlc.unwrap();
    htlc.hash = [0x99; 32];
    let f = b.build_funding(&htlc, Amount(1_000_000)).await.unwrap();
    b.broadcast(&f.tx).await.unwrap();
    f
}

/// Rows of the shared table on `chain`, as (input, reserving tx).
fn rows(w: &World, chain: Chain) -> Vec<(Outpoint, Txid)> {
    w.res
        .list_all()
        .unwrap()
        .into_iter()
        .filter(|r| r.chain == chain)
        .map(|r| (r.input, r.reserved_by))
        .collect()
}

fn maker_chain(dir: Direction) -> Chain {
    match dir {
        Direction::TakerPaysBtc => Chain::Divi,
        Direction::TakerPaysDivi => Chain::Btc,
    }
}

async fn lost_race_inside_the_window_reselects_and_locks(dir: Direction) {
    let w = locked_unsent(dir).await;
    let refused = w.funding();
    // A second daemon on the same table and wallet selected the same coin and sent first.
    let other = other_lock(&w, &w.daemon(dir, w.res.clone(), &COINS)).await;
    assert_eq!(inputs_of(&other.tx), vec![COINS[0]]);
    let funds_sent = w.ml(dir).attempts(TxKind::Fund);

    // The next tick: the table refuses the persisted funding (nothing sent), so the maker
    // builds a new one from the other coin and locks with it.
    w.maker.tick().await.unwrap();
    let r = w.rec();
    assert_eq!(r.state, SwapState::MakerLocked, "{:?}", r.last_error);
    assert!(r.last_error.is_none(), "{:?}", r.last_error);
    let new = r.maker_leg_funding.clone().unwrap();
    assert_ne!(new.tx.txid, refused.tx.txid);
    assert_eq!(inputs_of(&new.tx), vec![COINS[1]], "never the refused coin");
    assert_eq!(w.mk.funding_calls(), 2);
    assert!(w.ml(dir).contains(&new.tx.txid), "the new lock is sent");
    assert!(
        !w.ml(dir).contains(&refused.tx.txid),
        "the refused one never was"
    );
    assert_eq!(
        w.ml(dir).attempts(TxKind::Fund),
        funds_sent + 1,
        "only the new lock reached the chain"
    );
    let mut held = rows(&w, maker_chain(dir));
    held.sort_by_key(|(i, _)| i.txid.0);
    assert_eq!(
        held,
        vec![(COINS[0], other.tx.txid), (COINS[1], new.tx.txid)],
        "no row for the refused funding"
    );
    // The view now names the new lock; its HTLC was built afresh by the same code.
    let view = w.maker.view(&w.mid).unwrap().unwrap();
    assert_eq!(view.maker_leg.unwrap().outpoint, Some(new.outpoint));

    // The swap completes on the new lock.
    w.run_to_done().await;
    let r = w.rec();
    assert!(r.preimage.is_some(), "the taker claimed the new lock");
    assert_eq!(r.maker_leg_funding.unwrap().tx.txid, new.tx.txid);
    assert_eq!(w.mk.funding_calls(), 2);
}

async fn lost_race_past_the_window_aborts_like_a_maker_that_never_locked(dir: Direction) {
    let w = locked_unsent(dir).await;
    let other = other_lock(&w, &w.daemon(dir, w.res.clone(), &COINS)).await;
    // The taker leg's window is now too short to lock (testnet: 21,600 s, the maker needs
    // 10,800 + 1,800 of it), as in `maker_aborts_when_taker_window_too_short`.
    w.tl(dir).advance_time(9_500);
    let funds_sent = w.ml(dir).attempts(TxKind::Fund);

    w.maker.tick().await.unwrap();
    let r = w.rec();
    assert_eq!(r.state, SwapState::Aborted, "{:?}", r.last_error);
    assert_eq!(
        r.last_error.as_deref(),
        Some("aborted: taker-leg window too short to lock safely")
    );
    assert!(r.maker_leg_funding.is_none(), "no lock left on the swap");
    assert!(w.maker.view(&w.mid).unwrap().unwrap().maker_leg.is_none());
    assert_eq!(w.mk.funding_calls(), 1, "no new selection");
    assert_eq!(w.ml(dir).attempts(TxKind::Fund), funds_sent, "nothing sent");
    assert_eq!(rows(&w, maker_chain(dir)), vec![(COINS[0], other.tx.txid)]);

    // No error loop: further ticks change nothing.
    for _ in 0..3 {
        w.mine();
        w.maker.tick().await.unwrap();
        assert!(w.rec() == r, "unchanged");
    }

    // The taker refunds its lock after its timeout, as against any maker that never locked.
    w.tl(dir).advance_time(7 * 3600);
    for _ in 0..30 {
        w.round().await;
        if w.store.get_taker_swap(&w.tid).unwrap().unwrap().state == TakerState::Done {
            break;
        }
    }
    let t = w.store.get_taker_swap(&w.tid).unwrap().unwrap();
    assert_eq!(t.state, TakerState::Done);
    assert!(t.taker_leg_refund.is_some() && t.maker_leg_claim.is_none());
    assert!(w.rec() == r, "the maker swap stays as it ended");
}

async fn a_chain_refusal_keeps_the_persisted_funding(dir: Direction) {
    let w = locked_unsent(dir).await;
    let persisted = w.funding();
    // Something outside this table (another wallet on the same key) spent the coin: the
    // table takes the maker's funding, the chain refuses it after the bytes went out.
    let outside = w.daemon(dir, InputReservations::in_memory().unwrap(), &COINS[..1]);
    other_lock(&w, &outside).await;

    for _ in 0..3 {
        w.mine();
        w.maker.tick().await.unwrap();
        let r = w.rec();
        assert_eq!(r.state, SwapState::MakerLocked);
        assert_eq!(r.maker_leg_funding.as_ref(), Some(&persisted), "kept");
        let err = r.last_error.unwrap_or_default();
        assert!(err.contains("missingorspent"), "{err}");
    }
    assert_eq!(w.mk.funding_calls(), 1, "never re-selected");
    assert_eq!(
        rows(&w, maker_chain(dir)),
        vec![(COINS[0], persisted.tx.txid)],
        "the refused bytes keep their row"
    );
}

async fn an_unknown_send_outcome_keeps_the_persisted_funding(dir: Direction) {
    let w = locked_unsent(dir).await;
    let persisted = w.funding();
    // The send times out: the maker cannot know whether the node took it.
    w.ml(dir)
        .fail_broadcasts_with(Some(SwapError::Transient("timeout".into())));
    for _ in 0..3 {
        w.maker.tick().await.unwrap();
        let r = w.rec();
        assert_eq!(r.state, SwapState::MakerLocked);
        assert_eq!(r.maker_leg_funding.as_ref(), Some(&persisted));
    }
    w.ml(dir).fail_broadcasts_with(None);
    w.run_to_done().await;
    assert_eq!(w.rec().maker_leg_funding.unwrap(), persisted, "same bytes");
    assert_eq!(w.mk.funding_calls(), 1);
}

/// A table refusal of bytes the chain already holds (its row was released while it stayed
/// in the mempool, and another lock took the coin): something was sent, so no re-selection.
async fn a_table_refusal_of_a_lock_the_chain_holds_keeps_it(dir: Direction) {
    let w = locked_unsent(dir).await;
    let persisted = w.funding();
    w.maker.tick().await.unwrap();
    assert!(w.ml(dir).contains(&persisted.tx.txid), "sent");
    let c = maker_chain(dir);
    w.res.release_tx(c, &persisted.tx.txid).unwrap();
    w.res.reserve(c, &Txid([0x77; 32]), &[COINS[0]]).unwrap();

    for _ in 0..3 {
        w.maker.tick().await.unwrap();
        let r = w.rec();
        assert_eq!(r.state, SwapState::MakerLocked);
        assert_eq!(r.maker_leg_funding.as_ref(), Some(&persisted), "kept");
    }
    assert_eq!(w.mk.funding_calls(), 1, "never re-selected");
}

/// F2: a confirmed lock reorged out whose coin another lock then took. The re-send of the
/// persisted bytes is refused by the table: the lock is reported dropped, as before, and
/// nothing is re-selected.
async fn a_dropped_confirmed_lock_refused_by_the_table_is_not_reselected(dir: Direction) {
    let w = locked_unsent(dir).await;
    let persisted = w.funding();
    for _ in 0..10 {
        w.mine();
        w.maker.tick().await.unwrap();
        if w.rec().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(w.rec().state, SwapState::MakerLockConfirmed);
    // The first confirmation released its row; a reorg then drops it for good.
    assert!(rows(&w, maker_chain(dir)).is_empty());
    w.ml(dir).forget(&persisted.tx.txid);
    let other = other_lock(&w, &w.daemon(dir, w.res.clone(), &COINS)).await;
    assert_eq!(inputs_of(&other.tx), vec![COINS[0]]);

    for _ in 0..3 {
        w.maker.tick().await.unwrap();
        let r = w.rec();
        assert_eq!(r.state, SwapState::MakerLockConfirmed);
        assert!(r.maker_lock_dropped, "reported dropped");
        assert_eq!(r.maker_leg_funding.as_ref(), Some(&persisted), "kept");
        let err = r.last_error.unwrap_or_default();
        assert!(err.contains("maker lock dropped by a reorg"), "{err}");
    }
    assert_eq!(w.mk.funding_calls(), 1, "never re-selected");
}

/// After a restart, a `MakerLocked` swap whose funding was persisted but not yet broadcast has
/// no row in `InputReservations` yet. Starting a fresh `Maker` on the store must re-reserve its
/// inputs in memory immediately so a second swap locking first (newest-first in `tick`, or via
/// `notify_lock`) selects another coin instead of building a double spend.
async fn restart_rereserves_unsent_maker_locked_coin_before_a_second_swap_locks(dir: Direction) {
    let w = locked_unsent(dir).await;
    let first_funding = w.funding();
    assert_eq!(inputs_of(&first_funding.tx), vec![COINS[0]]);
    assert!(
        rows(&w, maker_chain(dir)).is_empty(),
        "unsent MakerLocked swap has no SQLite reservation row yet"
    );

    // Simulate a daemon restart: fresh backend instances (empty in-memory state) over the same
    // chains, reservation table, and persistent store.
    let (rdivi, rbtc) = (
        w.divi.backend(1, w.divi.balance(&w.mk.pubkey())),
        w.btc.backend(1, w.btc.balance(&w.mk.pubkey())),
    );
    let (rdivi, rbtc) = match dir {
        Direction::TakerPaysBtc => (rdivi.with_input_reservations(w.res.clone(), &COINS), rbtc),
        Direction::TakerPaysDivi => (rdivi, rbtc.with_input_reservations(w.res.clone(), &COINS)),
    };
    let restarted = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(rdivi),
        Arc::new(rbtc),
        w.store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: dir,
            counter_chain: Chain::Btc,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();

    // A second swap locks and confirms on the taker leg, then steps BEFORE the first swap
    // broadcasts (e.g. via `notify_lock` or newest-first ordering in `list_maker_swaps`).
    let q2 = restarted.quote("o", 1_000_000).await.unwrap();
    let (tid2, req2) = w.taker.prepare(&q2).await.unwrap();
    let v2 = restarted.accept(req2).await.unwrap();
    w.taker.accepted(&tid2, &v2).await.unwrap();
    let notice2 = w.taker.lock(&tid2).await.unwrap();
    let mid2 = restarted.notify_lock(&v2.id, notice2).await.unwrap().id;
    for _ in 0..20 {
        w.mine();
        let st = restarted.step(&mid2).await.unwrap();
        if matches!(st, SwapState::MakerLocked | SwapState::MakerLockConfirmed) {
            break;
        }
    }
    let second_rec = w.store.get_maker_swap(&mid2).unwrap().unwrap();
    let second_funding = second_rec
        .maker_leg_funding
        .expect("second swap built funding");
    assert_eq!(
        inputs_of(&second_funding.tx),
        vec![COINS[1]],
        "restarted maker must not reuse the unsent MakerLocked swap's coin"
    );

    // Now the first swap broadcasts cleanly with its original COINS[0] funding — no coin race!
    restarted.step(&w.mid).await.unwrap();
    let first_after = w.rec();
    assert_eq!(first_after.maker_leg_funding.unwrap(), first_funding);
    assert!(w.ml(dir).contains(&first_funding.tx.txid));
    assert!(w.ml(dir).contains(&second_funding.tx.txid));
}

/// Gate G4 (`ded2768f`): an unsent `MakerLocked` swap whose broadcast is rejected by the chain
/// stays `MakerLocked` inside its window, then aborts once its maker-leg locktime passes instead
/// of looping on `broadcast` forever. Its SQLite input reservation is kept until the 6-block
/// expiry sweep proves the lock absent, while the taker refunds cleanly.
async fn a_rejected_unsent_maker_lock_aborts_once_its_timeout_passes(dir: Direction) {
    let w = locked_unsent(dir).await;
    let persisted = w.funding();
    let locktime = w.rec().maker_leg_htlc.unwrap().locktime;
    let outside = w.daemon(dir, InputReservations::in_memory().unwrap(), &COINS[..1]);
    other_lock(&w, &outside).await;

    // Inside the window: kept in MakerLocked with the rejection recorded.
    w.mine();
    w.maker.tick().await.unwrap();
    assert_eq!(w.rec().state, SwapState::MakerLocked);
    assert!(w
        .rec()
        .last_error
        .unwrap_or_default()
        .contains("missingorspent"));

    // Advance the maker leg past its HTLC locktime: the next tick aborts instead of wedging.
    let delta = locktime.saturating_sub(w.ml(dir).mtp()) + 60;
    w.ml(dir).advance_time(delta);
    w.maker.tick().await.unwrap();
    let r = w.rec();
    assert_eq!(r.state, SwapState::Aborted, "{:?}", r.last_error);
    let err = r.last_error.clone().unwrap_or_default();
    assert!(
        err.starts_with("aborted: maker lock broadcast rejected:")
            && err.contains("missingorspent"),
        "{err}"
    );
    assert_eq!(w.mk.funding_calls(), 1, "never re-selected");

    // Further ticks are a no-op (no infinite error loop).
    for _ in 0..3 {
        w.mine();
        w.maker.tick().await.unwrap();
        assert!(w.rec() == r, "unchanged");
    }

    // `release_finished_swaps` does NOT drop the reservation without the 6-block absence proof;
    // `release_expired_swaps_and_bookings` releases it once EXPIRY_ABSENT_BLOCKS blocks pass.
    let chain = maker_chain(dir);
    assert_eq!(w.res.release_finished_swaps(&w.store, chain).unwrap(), 0);
    assert_eq!(rows(&w, chain), vec![(COINS[0], persisted.tx.txid)]);
    let start = divi_swap::reservation::ExpiryStart::Tip;
    assert_eq!(
        w.res
            .release_expired_swaps_and_bookings(&w.store, &w.mk, w.ml(dir).mtp(), start)
            .await
            .unwrap(),
        0
    );
    w.ml(dir).mine(divi_swap::reservation::EXPIRY_ABSENT_BLOCKS);
    assert_eq!(
        w.res
            .release_expired_swaps_and_bookings(&w.store, &w.mk, w.ml(dir).mtp(), start)
            .await
            .unwrap(),
        1
    );
    assert!(rows(&w, chain).is_empty());

    // The taker refunds its lock once its taker-leg timeout passes.
    w.tl(dir).advance_time(7 * 3600);
    for _ in 0..30 {
        w.round().await;
        if w.store.get_taker_swap(&w.tid).unwrap().unwrap().state == TakerState::Done {
            break;
        }
    }
    let t = w.store.get_taker_swap(&w.tid).unwrap().unwrap();
    assert_eq!(t.state, TakerState::Done);
    assert!(t.taker_leg_refund.is_some() && t.maker_leg_claim.is_none());
}

/// A transient broadcast failure past the maker-leg timeout neither aborts nor enters
/// `MakerRefundable` before the node answers; once the node answers again, the lock lands and the
/// maker refunds cleanly to `Done`.
async fn an_unknown_send_outcome_past_timeout_waits_for_the_node_then_refunds(dir: Direction) {
    let w = locked_unsent(dir).await;
    let persisted = w.funding();
    let locktime = w.rec().maker_leg_htlc.unwrap().locktime;
    w.ml(dir)
        .fail_broadcasts_with(Some(SwapError::Transient("timeout".into())));
    let delta = locktime.saturating_sub(w.ml(dir).mtp()) + 60;
    w.ml(dir).advance_time(delta);
    for _ in 0..3 {
        w.maker.tick().await.unwrap();
        let r = w.rec();
        assert_eq!(r.state, SwapState::MakerLocked);
        assert_eq!(r.maker_leg_funding.as_ref(), Some(&persisted));
    }
    w.ml(dir).fail_broadcasts_with(None);
    w.tl(dir).advance_time(7 * 3600);
    w.run_to_done().await;
    let r = w.rec();
    assert_eq!(r.state, SwapState::Done);
    assert!(r.maker_leg_refund.is_some());
}

macro_rules! on_both_chains {
    ($divi:ident, $btc:ident, $body:ident) => {
        #[tokio::test]
        async fn $divi() {
            $body(Direction::TakerPaysBtc).await;
        }
        #[tokio::test]
        async fn $btc() {
            $body(Direction::TakerPaysDivi).await;
        }
    };
}

on_both_chains!(
    divi_lost_race_inside_the_window_reselects_and_locks,
    btc_lost_race_inside_the_window_reselects_and_locks,
    lost_race_inside_the_window_reselects_and_locks
);
on_both_chains!(
    divi_lost_race_past_the_window_aborts_like_a_maker_that_never_locked,
    btc_lost_race_past_the_window_aborts_like_a_maker_that_never_locked,
    lost_race_past_the_window_aborts_like_a_maker_that_never_locked
);
on_both_chains!(
    divi_a_chain_refusal_keeps_the_persisted_funding,
    btc_a_chain_refusal_keeps_the_persisted_funding,
    a_chain_refusal_keeps_the_persisted_funding
);
on_both_chains!(
    divi_an_unknown_send_outcome_keeps_the_persisted_funding,
    btc_an_unknown_send_outcome_keeps_the_persisted_funding,
    an_unknown_send_outcome_keeps_the_persisted_funding
);
on_both_chains!(
    divi_a_table_refusal_of_a_lock_the_chain_holds_keeps_it,
    btc_a_table_refusal_of_a_lock_the_chain_holds_keeps_it,
    a_table_refusal_of_a_lock_the_chain_holds_keeps_it
);
on_both_chains!(
    divi_a_dropped_confirmed_lock_refused_by_the_table_is_not_reselected,
    btc_a_dropped_confirmed_lock_refused_by_the_table_is_not_reselected,
    a_dropped_confirmed_lock_refused_by_the_table_is_not_reselected
);
on_both_chains!(
    divi_restart_rereserves_unsent_maker_locked_coin_before_a_second_swap_locks,
    btc_restart_rereserves_unsent_maker_locked_coin_before_a_second_swap_locks,
    restart_rereserves_unsent_maker_locked_coin_before_a_second_swap_locks
);
on_both_chains!(
    divi_a_rejected_unsent_maker_lock_aborts_once_its_timeout_passes,
    btc_a_rejected_unsent_maker_lock_aborts_once_its_timeout_passes,
    a_rejected_unsent_maker_lock_aborts_once_its_timeout_passes
);
on_both_chains!(
    divi_an_unknown_send_outcome_past_timeout_waits_for_the_node_then_refunds,
    btc_an_unknown_send_outcome_past_timeout_waits_for_the_node_then_refunds,
    an_unknown_send_outcome_past_timeout_waits_for_the_node_then_refunds
);
