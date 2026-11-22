// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify it under the terms
// of the GNU Affero General Public License as published by the Free Software Foundation,
// version 3.

//! The taker-side counterpart of `maker_admission_hold.rs`: an admission hold on the quote's
//! counter chain must stop [`Taker::lock`] from building the *first* funding of a new swap
//! — on either leg, whichever the direction funds first (`TakerPaysBtc` puts it on the
//! counter chain, `TakerPaysDivi` on DIVI; the hold is always keyed by `counter_chain`, never
//! by which one that is) — and must never strand a signed lock or block a refund/claim.
//!
//! Before this fix `Taker::lock` had no hold at all: `Cmd::Lock` on the CLI never called
//! `require_usdc_admission` (only `accept`/`run` did, and only before a maker was even
//! contacted), so a pre-hold `Accepted` session resumed with `lock` built and broadcast its
//! first funding regardless. Keying the hold by `cli.counter_chain` would still miss it for
//! `TakerPaysDivi`: that direction never touches the counter-chain backend for its first
//! funding at all, and a CLI flag can disagree with a persisted swap's own quote. The engine
//! now checks `r.quote.counter_chain` directly, independent of the CLI invocation.
//!
//! A `Locked` funding tx persisted before its `taker_leg_sent` marker (write-ahead: the tx is
//! signed and written before it can reach the network) may already have been broadcast
//! (crash between the send and the marker), and an endpoint can lag in showing it: an absent
//! observation is "unknown", so under a hold it is neither resent nor abandoned; seen, it is
//! marked sent and the (idempotent) broadcast proceeds as normal — and a lock already marked
//! sent is never blocked by a later hold, whichever way it is observed.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain};
use divi_swap::{
    Amount, Chain, ChainBackend, Maker, Profile, Store, SwapConfig, SwapError, SwapState, Taker,
    TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 2_000_000_000;
/// Stands in for a held `Usdc` counter chain: the hold logic is chain-agnostic, keyed by
/// whatever `Chain` the quote names, and `Chain::Btc` lets this run fully non-networked
/// (`MockChain`), unlike `tests/usdc.rs`'s real `UsdcBackend`-over-anvil coverage.
const HELD: Chain = Chain::Btc;

fn offer(dir: Direction) -> Offer {
    Offer {
        id: "o".into(),
        direction: dir,
        counter_chain: HELD,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }
}

/// Where [`world`] stopped building the swap.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// `accept` is done; nothing has funded anything yet.
    Accepted,
    /// The signed funding tx is persisted as `Locked`, `taker_leg_sent` still `false` — a
    /// crash right after the write-ahead write, before `lock` ever reached the broadcast
    /// (modelled with `Taker::halt_after`, same technique `maker_admission_hold.rs` uses).
    LockedUnsent,
    /// `lock` ran to completion once already, broadcast included: `taker_leg_sent` is
    /// `true`, the baseline a later hold must never block.
    LockedSent,
}

struct World {
    divi: MockChain,
    btc: MockChain,
    store: Store,
    maker: Maker,
    taker_divi: MockBackend,
    taker_btc: MockBackend,
    taker: Taker,
    tid: String,
    mid: String,
}

impl World {
    fn rec(&self) -> divi_swap::store::TakerRecord {
        self.store.get_taker_swap(&self.tid).unwrap().unwrap()
    }

    /// The taker-leg backend for a swap in `dir`: DIVI for `TakerPaysDivi`, the (held) counter
    /// chain otherwise.
    fn taker_leg(&self, dir: Direction) -> &MockBackend {
        match dir {
            Direction::TakerPaysDivi => &self.taker_divi,
            Direction::TakerPaysBtc => &self.taker_btc,
        }
    }

    /// The chain the taker-leg backend above posts to.
    fn taker_leg_chain(&self, dir: Direction) -> &MockChain {
        match dir {
            Direction::TakerPaysDivi => &self.divi,
            Direction::TakerPaysBtc => &self.btc,
        }
    }

    /// Drop the taker and rebuild it over the same database and backends, as after a crash,
    /// with `HELD` held (standing in for a held `--usdc-network`) or not.
    fn restart(&mut self, held: bool) {
        let t = Taker::new(
            Arc::new(self.taker_divi.clone()),
            Arc::new(self.taker_btc.clone()),
            self.store.clone(),
        );
        self.taker = if held {
            t.with_admission_hold(HELD, "advisory")
        } else {
            t
        };
    }
}

async fn world(dir: Direction, stop: Stop) -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, Amount(FUNDS))),
        Arc::new(btc.backend(1, Amount(FUNDS))),
        store.clone(),
        vec![offer(dir)],
    )
    .unwrap();
    let taker_divi = divi.backend(3, Amount(FUNDS));
    let taker_btc = btc.backend(4, Amount(FUNDS));
    let taker = Taker::new(
        Arc::new(taker_divi.clone()),
        Arc::new(taker_btc.clone()),
        store.clone(),
    );
    let q = maker.quote("o", 1_000_000).await.unwrap();
    assert_eq!(q.counter_chain, HELD);
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    let mut mid = v.id.clone();
    taker.accepted(&tid, &v).await.unwrap();
    match stop {
        Stop::Accepted => {}
        Stop::LockedUnsent => {
            taker.halt_after(Some(TakerState::Locked));
            let err = taker.lock(&tid).await.unwrap_err();
            assert!(err.to_string().contains("halted"), "{err}");
            taker.halt_after(None);
        }
        Stop::LockedSent => {
            // Tell the maker too, as the real CLI does right after `Taker::lock`
            // (`flow::lock`), so a later test can run this swap to `Done` on both sides.
            let notice = taker.lock(&tid).await.unwrap();
            mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
        }
    }
    let w = World {
        divi,
        btc,
        store,
        maker,
        taker_divi,
        taker_btc,
        taker,
        tid,
        mid,
    };
    match stop {
        Stop::Accepted => {
            assert_eq!(w.rec().state, TakerState::Accepted);
            assert!(w.rec().taker_leg_funding.is_none());
        }
        Stop::LockedUnsent => {
            assert_eq!(w.rec().state, TakerState::Locked);
            assert!(!w.rec().taker_leg_sent);
            assert!(!w
                .taker_leg_chain(dir)
                .contains(&w.rec().taker_leg_funding.unwrap().tx.txid));
        }
        Stop::LockedSent => {
            assert_eq!(w.rec().state, TakerState::Locked);
            assert!(w.rec().taker_leg_sent);
        }
    }
    w
}

/// A pre-hold `Accepted` session, resumed under a hold (the restart the CLI's `Cmd::Lock`
/// models): the first funding is refused outright, on either leg the direction funds first,
/// and nothing is built or sent.
async fn held_accepted_refuses_the_first_funding(dir: Direction) {
    let mut w = world(dir, Stop::Accepted).await;
    w.restart(true);
    let err = w.taker.lock(&w.tid).await.unwrap_err();
    assert!(err.to_string().contains("held"), "{err}");
    assert_eq!(w.rec().state, TakerState::Accepted);
    assert!(
        w.rec().taker_leg_funding.is_none(),
        "no funding built while held"
    );
}

#[tokio::test]
async fn a_held_taker_refuses_an_accepted_swap_paying_btc() {
    held_accepted_refuses_the_first_funding(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn a_held_taker_refuses_an_accepted_swap_paying_divi() {
    held_accepted_refuses_the_first_funding(Direction::TakerPaysDivi).await;
}

/// A signed lock persisted but never shown on chain (truly new, or an endpoint lagging):
/// under a hold it stays exactly as it was, not re-sent, its state untouched.
async fn held_unseen_lock_is_kept_unsent(dir: Direction) {
    let mut w = world(dir, Stop::LockedUnsent).await;
    let txid = w.rec().taker_leg_funding.clone().unwrap().tx.txid;
    w.restart(true);
    let err = w.taker.lock(&w.tid).await.unwrap_err();
    assert!(
        matches!(err, SwapError::Transient(_)),
        "an absent observation is retried, not treated as final: {err}"
    );
    let after = w.rec();
    assert_eq!(after.state, TakerState::Locked);
    assert!(!after.taker_leg_sent);
    assert_eq!(after.taker_leg_funding.unwrap().tx.txid, txid);
    assert!(
        !w.taker_leg_chain(dir).contains(&txid),
        "no first broadcast under a hold"
    );
}

#[tokio::test]
async fn a_held_taker_keeps_an_unseen_lock_unsent_paying_btc() {
    held_unseen_lock_is_kept_unsent(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn a_held_taker_keeps_an_unseen_lock_unsent_paying_divi() {
    held_unseen_lock_is_kept_unsent(Direction::TakerPaysDivi).await;
}

/// Crash between the broadcast and the `taker_leg_sent` marker, but the chain already shows
/// the lock (mempool is enough, `MockChain::confirmations` reports `Some(0)`): the hold marks
/// it sent and lets the (idempotent) broadcast in `lock` run, instead of refusing it forever.
async fn held_lock_the_chain_shows_is_marked_sent_and_runs_on(dir: Direction) {
    let mut w = world(dir, Stop::LockedUnsent).await;
    let funding = w.rec().taker_leg_funding.clone().unwrap();
    w.taker_leg(dir).broadcast(&funding.tx).await.unwrap();
    assert!(w.taker_leg_chain(dir).contains(&funding.tx.txid));
    w.restart(true);
    w.taker.lock(&w.tid).await.unwrap();
    assert!(w.rec().taker_leg_sent);
}

#[tokio::test]
async fn a_held_taker_marks_a_seen_lock_sent_paying_btc() {
    held_lock_the_chain_shows_is_marked_sent_and_runs_on(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn a_held_taker_marks_a_seen_lock_sent_paying_divi() {
    held_lock_the_chain_shows_is_marked_sent_and_runs_on(Direction::TakerPaysDivi).await;
}

/// A lock already marked sent (funds definitely committed before the hold, or lifted and
/// relocked once) is never blocked: `lock` re-broadcasts it (idempotent) exactly as with no
/// hold at all.
async fn held_already_sent_lock_is_never_blocked(dir: Direction) {
    let mut w = world(dir, Stop::LockedSent).await;
    let txid = w.rec().taker_leg_funding.clone().unwrap().tx.txid;
    w.restart(true);
    w.taker.lock(&w.tid).await.unwrap();
    assert!(w.rec().taker_leg_sent);
    assert!(w.taker_leg_chain(dir).contains(&txid));
}

#[tokio::test]
async fn a_held_taker_never_blocks_an_already_sent_lock_paying_btc() {
    held_already_sent_lock_is_never_blocked(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn a_held_taker_never_blocks_an_already_sent_lock_paying_divi() {
    held_already_sent_lock_is_never_blocked(Direction::TakerPaysDivi).await;
}

/// End to end, under a hold the whole way: a lock already marked sent before the restart
/// still runs the swap to `Done` on both sides — refunds and claims never wait on this hold,
/// only the very first, never-yet-sent funding does.
async fn held_already_sent_swap_still_finishes(dir: Direction) {
    let mut w = world(dir, Stop::LockedSent).await;
    w.restart(true);
    for _ in 0..120 {
        w.divi.mine(1);
        w.btc.mine(1);
        let _ = w.maker.tick().await;
        let view = w.maker.view(&w.mid).unwrap();
        let _ = w.taker.step(&w.tid, view.as_ref()).await;
        let m = w.store.get_maker_swap(&w.mid).unwrap().unwrap().state;
        let t = w.rec().state;
        if m == SwapState::Done && t == TakerState::Done {
            return;
        }
    }
    panic!(
        "not done under a hold: maker {:?}, taker {:?} ({:?})",
        w.store.get_maker_swap(&w.mid).unwrap().unwrap().state,
        w.rec().state,
        w.rec().last_error
    );
}

#[tokio::test]
async fn a_held_taker_with_an_already_sent_lock_finishes_the_swap_paying_btc() {
    held_already_sent_swap_still_finishes(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn a_held_taker_with_an_already_sent_lock_finishes_the_swap_paying_divi() {
    held_already_sent_swap_still_finishes(Direction::TakerPaysDivi).await;
}
