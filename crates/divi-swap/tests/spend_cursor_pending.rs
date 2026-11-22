// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Engine-level guards for H2 review finding S10b (the correction on top of H2's spend
//! cursors). A backend that reads at most a bounded window of blocks per pass answers "no
//! spend" for a window that has not yet reached the tip. Before the correction the engine's
//! spend reads turned that into a bare "no spend", so the maker could refund its leg, and the
//! taker could refund its own leg, on a window that could still be hiding the counterparty's
//! claim or refund.
//!
//! With the correction a bounded read short of the tip is `Pending`, distinct from "read
//! through the tip, no spend". These tests drive the real [`Maker`] / [`Taker`] state machines
//! over a [`MockChain`] whose spend scan reads only [`WINDOW`] blocks per pass, and assert,
//! black-box (swap state and on-chain refund counts, never the cursor internals):
//!
//! - a no-spend-dependent decision (the maker-leg refund, the taker-leg refund) is never taken
//!   while the scan is short of the tip, so under the old behaviour the `first >= 2` assertions
//!   would fire (the refund went out on the very first partial window);
//! - the decision is still taken once the scan has resumed, window by window, through the tip,
//!   so a legitimate refund always eventually goes out (completion is never sacrificed); and
//! - a claim hidden several windows past the lock is found before any refund, across a restart
//!   and a reorg under the cursor.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::MockChain;
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, Maker, Outpoint, Profile, Store, SwapConfig,
    SwapState, Taker, TakerState,
};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 1_000_000_000_000;
const SATS: u64 = 1_000_000;
/// Blocks the bounded spend scan reads per pass. Small, so a claim or the tip sits several
/// passes past the lock and a single pass is always short of it.
///
/// Engine requirement this encodes: a resumed pass re-reads the anchor block (the saved mark)
/// so the backend re-verifies its hash in the same request — the BTC/LTC block-scan loop
/// checks the mark's hash only at `height == mark`, so the anchor must be inside the pass (the
/// cursor must not skip it). A `WINDOW`-block pass therefore nets `WINDOW - 1` *new* blocks of
/// progress. Against a tip that is not moving, any `WINDOW >= 2` catches up; against a tip that
/// grows `g` blocks per engine step, catch-up needs `WINDOW - 1 > g`, i.e. `WINDOW >= g + 2`.
const WINDOW: u64 = 2;
/// Window for the moving-tip taker test below, where the tip grows one block per refund call.
/// `WINDOW` (2) nets one new block per pass and merely ties that growth, so the scan would
/// chase the tip forever and the refund would never go out; three nets two and wins by one.
/// See [`WINDOW`] for the `WINDOW >= g + 2` requirement (here `g == 1`).
const MOVING_TIP_WINDOW: u64 = 3;
/// Target block interval of the mock BTC chain (its maker leg), seconds. `MockChain::mine`
/// advances MTP by this per block, so every empty block mined to put a spend past the first
/// scan window also spends that much of the BTC claim margin.
const BTC_BLOCK_SECS: u32 = 600;
/// Empty blocks mined past the maker lock before anything spends it, so the spender (or the
/// tip) is many windows away and the first passes are always short.
const GAP: u64 = 16;

fn maker_cfg() -> SwapConfig {
    let mut cfg = SwapConfig::profile(Profile::Testnet);
    cfg.btc_confirmations = 1;
    cfg.divi_confirmations = 1;
    cfg
}

fn offer() -> Offer {
    Offer {
        id: "o".into(),
        direction: Direction::TakerPaysDivi,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }
}

/// A maker and an honest taker on a shared store, their swap driven to `MakerLockConfirmed`.
/// The maker leg is on BTC (`btc`), the taker leg on DIVI (`divi`); the maker-leg spend scan
/// reads [`WINDOW`] blocks per pass.
struct World {
    divi: MockChain,
    btc: MockChain,
    store: Store,
    maker: Maker,
    taker: Taker,
    mid: String,
    tid: String,
    /// The maker-leg locktime, fixed when the leg was built.
    maker_locktime: u32,
}

impl World {
    /// The maker-leg (BTC) lock outpoint.
    fn maker_leg(&self) -> Outpoint {
        self.store
            .get_maker_swap(&self.mid)
            .unwrap()
            .unwrap()
            .maker_leg_funding
            .expect("a persisted maker-leg funding")
            .outpoint
    }

    fn maker_state(&self) -> SwapState {
        self.maker.view(&self.mid).unwrap().unwrap().state
    }

    /// Maker-leg refund broadcasts of the lock so far.
    fn maker_refunds(&self) -> u32 {
        self.btc.tx_counts(&self.maker_leg()).refund_attempts
    }

    /// Rebuild the maker on the same store and backends (a restart on the same database).
    fn restart_maker(&mut self) {
        let mdivi: Arc<dyn ChainBackend> = Arc::new(self.divi.backend(1, Amount(FUNDS)));
        let mbtc: Arc<dyn ChainBackend> = Arc::new(self.btc.backend(1, Amount(FUNDS)));
        self.maker =
            Maker::new(maker_cfg(), mdivi, mbtc, self.store.clone(), vec![offer()]).unwrap();
    }

    /// Move the maker-leg (BTC) chain past its locktime so the leg is refundable, with the tip
    /// `GAP` blocks past the lock so the scan needs several passes to read through it.
    fn make_maker_leg_refundable(&self) {
        // Height first, without time, so the tip is far from the lock but no deadline moved.
        self.btc.mine(GAP);
        let wait = (self.maker_locktime + 7200).saturating_sub(self.btc.mtp());
        self.btc.advance_time(wait);
        self.btc.mine(3);
        assert!(
            self.btc.mtp() > self.maker_locktime,
            "the maker leg is past its locktime"
        );
    }
}

/// Drive a swap to `MakerLockConfirmed` with the maker-leg spend scan bounded to [`WINDOW`].
async fn setup() -> World {
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let mdivi: Arc<dyn ChainBackend> = Arc::new(divi.backend(1, Amount(FUNDS)));
    let mbtc: Arc<dyn ChainBackend> = Arc::new(btc.backend(1, Amount(FUNDS)));
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(maker_cfg(), mdivi, mbtc, store.clone(), vec![offer()]).unwrap();
    let tdivi: Arc<dyn ChainBackend> = Arc::new(divi.backend(3, Amount(FUNDS)));
    let tbtc: Arc<dyn ChainBackend> = Arc::new(btc.backend(4, Amount(FUNDS)));
    let taker = Taker::new(tdivi, tbtc, store.clone());

    let q = maker.quote("o", SATS).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;

    let mut view = maker.view(&mid).unwrap().unwrap();
    for _ in 0..40 {
        divi.mine(1);
        btc.mine(1);
        maker.tick().await.unwrap();
        view = maker.view(&mid).unwrap().unwrap();
        if view.state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(
        view.state,
        SwapState::MakerLockConfirmed,
        "maker lock confirmed"
    );
    let maker_locktime = view.maker_leg.as_ref().unwrap().htlc.locktime;
    btc.set_scan_window(WINDOW);
    World {
        divi,
        btc,
        store,
        maker,
        taker,
        mid,
        tid,
        maker_locktime,
    }
}

/// A refundable maker leg with no claim: the refund never goes out on a partial window, but
/// once the scan has read through the tip the maker refunds. (Under the old behaviour the
/// refund went out on the very first refundable tick.)
#[tokio::test]
async fn a_maker_refund_waits_for_the_scan_to_reach_the_tip() {
    let w = setup().await;
    w.make_maker_leg_refundable();

    let mut first_refund = None;
    for i in 0..80 {
        w.maker.tick().await.unwrap();
        if first_refund.is_none() && w.maker_refunds() > 0 {
            first_refund = Some(i);
        }
        if w.maker_state().is_terminal() {
            break;
        }
    }
    let first = first_refund.expect("the maker eventually refunds its leg");
    assert!(
        first >= 2,
        "the refund went out on tick {first}, before the scan read through the tip: a partial \
         window authorised a no-spend decision"
    );
}

/// A claim hidden several windows past the lock is found before any refund: the maker reaches
/// `TakerClaimed`, never refunding on a partial window. (Under the old behaviour the first
/// partial window read as "no claim" and the maker refunded, losing the taker leg.)
///
/// The height gap must stay within the BTC claim margin: `MockChain::mine` advances MTP by
/// `BTC_BLOCK_SECS` per block, so mining the gap also ages the chain toward the maker-leg
/// locktime. Mining `GAP` (16) empty BTC blocks here would advance MTP by `16 * 600 = 9600`s,
/// past the margin, and the honest taker would (correctly) decline to claim and stay `Locked`.
#[tokio::test]
async fn a_maker_finds_a_claim_beyond_the_first_window_and_never_refunds() {
    let w = setup().await;
    let view = w.maker.view(&w.mid).unwrap().unwrap();
    // Push the maker-leg tip past the first scan window, then let the honest taker claim it
    // there. Mining each empty block ages the BTC MTP toward the locktime, so the gap is held
    // to what the claim margin affords (keeping blocks back for the claim loop and the reveal
    // slack below), not the full `GAP` the refund tests use (those have no claim deadline).
    let margin = ClaimDeadline::builtin(Chain::Btc).margin_secs();
    let afford =
        u64::from((w.maker_locktime - margin).saturating_sub(w.btc.mtp()) / BTC_BLOCK_SECS);
    let gap = (WINDOW + 4).min(afford.saturating_sub(3));
    assert!(
        gap > WINDOW,
        "the claim must sit beyond the first {WINDOW}-block scan window (afforded {afford} \
         blocks before the claim margin)"
    );
    w.btc.mine(gap);
    // Reveal with more than one mined block of slack: the claim loop mines a BTC block before
    // its first step, which must not by itself carry the MTP across the claim deadline.
    let reveal_at = w.maker_locktime - margin - 2 * BTC_BLOCK_SECS;
    let wait = reveal_at.saturating_sub(w.btc.mtp());
    w.btc.advance_time(wait);
    w.divi.advance_time(wait);

    let mut tstate = TakerState::Locked;
    for _ in 0..6 {
        w.divi.mine(1);
        w.btc.mine(1);
        tstate = w.taker.step(&w.tid, Some(&view)).await.unwrap();
        if tstate == TakerState::Claimed {
            break;
        }
    }
    assert_eq!(
        tstate,
        TakerState::Claimed,
        "the taker claimed the maker leg"
    );
    // Mine the claim and move the leg past its locktime (tip grows past the claim).
    w.btc.mine(1);
    let wait = (w.maker_locktime + 7200).saturating_sub(w.btc.mtp());
    w.btc.advance_time(wait);
    w.btc.mine(3);

    for _ in 0..80 {
        w.maker.tick().await.unwrap();
        assert_eq!(
            w.maker_refunds(),
            0,
            "the maker refunded its leg while a claim was hiding past the scanned window"
        );
        if w.maker_state() == SwapState::MakerClaimed {
            // A tick can discover the preimage and broadcast the DIVI claim before returning.
            w.divi.mine(1);
        }
        if w.maker_state() == SwapState::Done {
            break;
        }
    }
    assert_eq!(
        w.maker_state(),
        SwapState::Done,
        "the maker must find the late claim and confirm its own claim"
    );
    assert!(
        w.store
            .get_maker_swap(&w.mid)
            .unwrap()
            .unwrap()
            .preimage
            .is_some(),
        "the maker learned the preimage from the late claim"
    );
}

/// The maker-leg scan resumes from its persisted cursor across a restart: a fresh maker on
/// the same database does not start the scan over, and still refunds once it reaches the tip.
#[tokio::test]
async fn a_maker_refund_resumes_across_a_restart() {
    let mut w = setup().await;
    w.make_maker_leg_refundable();

    // A couple of passes short of the tip, then restart with no refund yet.
    for _ in 0..2 {
        w.maker.tick().await.unwrap();
    }
    assert_eq!(w.maker_refunds(), 0, "no refund before the restart");
    w.restart_maker();

    let mut refunded = false;
    for _ in 0..80 {
        w.maker.tick().await.unwrap();
        if w.maker_refunds() > 0 {
            refunded = true;
            break;
        }
    }
    assert!(
        refunded,
        "the restarted maker resumed the scan and refunded"
    );
}

/// A reorg under the cursor (the marked block replaced) makes the scan restart from the lock,
/// and the maker still refunds once the new chain is read through the tip: a partial window
/// across the reorg never authorises the refund.
#[tokio::test]
async fn a_maker_refund_survives_a_reorg_under_the_cursor() {
    let w = setup().await;
    w.make_maker_leg_refundable();

    // One pass so a cursor is saved below the tip.
    w.maker.tick().await.unwrap();
    assert_eq!(
        w.maker_refunds(),
        0,
        "no refund on the first partial window"
    );
    // Replace the chain under the mark and re-mine past the locktime.
    w.btc.rewind(GAP);
    let wait = (w.maker_locktime + 7200).saturating_sub(w.btc.mtp());
    w.btc.advance_time(wait);
    w.btc.mine(GAP + 3);

    let mut refunded = false;
    for _ in 0..100 {
        w.maker.tick().await.unwrap();
        if w.maker_refunds() > 0 {
            refunded = true;
            break;
        }
    }
    assert!(
        refunded,
        "the maker refunded after reading the reorganised chain through the tip"
    );
}

/// The taker-side mirror: a taker recovering its own leg refunds only once its scan for a
/// maker claim has read through the tip. On a partial window the refund is withheld; once the
/// scan completes with no claim, the refund goes out, and the taker is never declared lost on
/// a partial window. (Under the old behaviour the refund went out on the first partial
/// window.)
///
/// The tip grows one block per refund call below, so this uses [`MOVING_TIP_WINDOW`] (3), not
/// [`WINDOW`] (2): a resumed pass re-reads the anchor and nets `window - 1` new blocks, so a
/// 2-block window would net exactly one — tying the tip's one-block growth and never catching
/// up, so the refund would never go out even though it should. Three nets two and gains one
/// block per pass on the moving tip (see [`WINDOW`]).
#[tokio::test]
async fn a_taker_refund_waits_for_the_scan_to_reach_the_tip() {
    // A fresh world; the taker leg is on DIVI, so its scan is the bounded one here.
    let divi = MockChain::new(Chain::Divi, T0, 60);
    let btc = MockChain::new(Chain::Btc, T0, 600);
    let mdivi: Arc<dyn ChainBackend> = Arc::new(divi.backend(1, Amount(FUNDS)));
    let mbtc: Arc<dyn ChainBackend> = Arc::new(btc.backend(1, Amount(FUNDS)));
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(maker_cfg(), mdivi, mbtc, store.clone(), vec![offer()]).unwrap();
    let tdivi: Arc<dyn ChainBackend> = Arc::new(divi.backend(3, Amount(FUNDS)));
    let tbtc: Arc<dyn ChainBackend> = Arc::new(btc.backend(4, Amount(FUNDS)));
    let taker = Taker::new(tdivi, tbtc, store.clone());

    let q = maker.quote("o", SATS).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let _notice = taker.lock(&tid).await.unwrap();

    let rec = store.get_taker_swap(&tid).unwrap().unwrap();
    let at = rec
        .taker_leg_funding
        .expect("a persisted taker-leg funding")
        .outpoint;
    let locktime = rec
        .taker_leg_htlc
        .expect("a persisted taker-leg htlc")
        .locktime;

    // Confirm the taker leg, push the tip GAP blocks past it, then move past the locktime, so
    // the lost-scan has several windows to read before it reaches the tip.
    divi.set_scan_window(MOVING_TIP_WINDOW);
    divi.mine(1 + GAP);
    let wait = (locktime + 7200).saturating_sub(divi.mtp());
    divi.advance_time(wait);
    divi.mine(3);

    let mut first_refund = None;
    for i in 0..80 {
        let st = taker.refund(&tid).await.unwrap();
        assert_ne!(
            st,
            TakerState::Lost,
            "the taker recorded a loss without reading a maker claim through the tip"
        );
        divi.mine(1);
        if first_refund.is_none() && divi.tx_counts(&at).refund_attempts > 0 {
            first_refund = Some(i);
        }
        if st == TakerState::Done {
            break;
        }
    }
    let first = first_refund.expect("the taker eventually refunds its leg");
    assert!(
        first >= 2,
        "the taker refund went out on call {first}, before the scan read through the tip: a \
         partial window authorised a no-spend decision"
    );
}
