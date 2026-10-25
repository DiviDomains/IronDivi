// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Model-based property tests of the swap state machine: random sequences of accept, fund,
//! confirm, timeout, refund and restart (drop both engines and reopen the database, as the
//! restart matrix in `engine.rs` does), plus engine passes, crashes, second-claim probes,
//! mempool evictions of the taker's claim and a hostile maker refund, driven through the real
//! maker and taker on two mock chains. After every op each leg is
//! checked against a reference model (`Unfunded → Funded → Claimed | Refunded`, who may move
//! it and when), and two invariants hold:
//!
//! 1. No leg is ever claimed twice or both claimed and refunded: a second claim attempt is
//!    refused or is a no-op, and the engines never sign two different claims of one leg.
//! 2. After the sequence, with time past every locktime and the engines run to quiescence,
//!    every funded leg is claimed or refunded — never stuck, never both.
//!
//! An evicted claim of the maker leg has leaked the preimage, so the maker may then claim the
//! taker leg while the maker leg is refunded: the taker may end `Lost`, but only after such a
//! leak and only with the taker leg claimed and the maker leg refunded.
//!
//! `PROPTEST_CASES=2000` runs a longer search than the default.

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::{MockBackend, MockChain, TxCounts};
use divi_swap::store::{MakerRecord, TakerRecord};
use divi_swap::{
    Amount, Chain, ChainBackend, Maker, Outpoint, Profile, Store, SwapConfig, SwapState, Taker,
    TakerState,
};
use proptest::prelude::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const BTC_SATS: u64 = 1_000_000;
/// Each side's balance on the chain it locks on: enough for two swaps.
const DIVI_FUNDS: u64 = 2_000_000_000;
const BTC_FUNDS: u64 = 10_000_000;
const MAX_SWAPS: usize = 2;

/// Cases per direction; `PROPTEST_CASES` overrides it for longer runs.
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32)
}

#[derive(Clone, Copy, Debug)]
enum CrashAt {
    Maker(SwapState),
    Taker(TakerState),
}

#[derive(Clone, Copy, Debug)]
enum Op {
    /// quote → prepare → accept → accepted for a new swap (at most [`MAX_SWAPS`]).
    Accept,
    /// The taker locks swap `i` and tells the maker.
    Fund(u8),
    /// Mine `n` blocks on both chains.
    Confirm(u8),
    /// Move one chain's MTP (and the maker's clock) forward without mining.
    Timeout { taker_chain: bool, secs: u32 },
    /// The taker's refund-only path on swap `i`.
    Refund(u8),
    /// Drop both engines and reopen the database file.
    Restart,
    /// Halt one engine right after it enters a state, run one pass, then restart.
    Crash(CrashAt),
    /// One maker scheduler pass.
    Tick,
    /// One taker step on swap `i` with the maker's current view.
    Step(u8),
    /// Try to claim each already-claimed leg of swap `i` again.
    ReClaim(u8),
    /// Drop the taker's claim of swap `i`'s maker leg from the mempool if it is unmined
    /// there: the preimage has leaked, the leg is unspent again.
    Evict(u8),
    /// The maker's key refunds swap `i`'s maker leg on its own, without its engine (a
    /// hostile or out-of-band maker), first letting time pass to the locktime if needed.
    HostileRefund(u8),
}

/// The reference model of one HTLC leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Leg {
    Unfunded,
    Funded,
    Claimed,
    Refunded,
}

/// Which op moved the world, i.e. which engine was allowed to act.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum By {
    Fund,
    Maker,
    Taker,
    TakerRefund,
    /// Both engines (a crash pass or a settle round).
    Both,
    /// Nobody: chain-only ops, restarts and probes must not move any leg.
    Nobody,
    /// [`Op::Evict`]: only an unmined maker-leg claim may go back to `Funded`.
    Evict,
    /// [`Op::HostileRefund`]: time passes, then only a maker-leg refund past its locktime.
    HostileRefund,
}

impl By {
    /// `notify_lock` runs the maker, so a fund op lets the maker act too.
    fn maker(self) -> bool {
        matches!(self, By::Maker | By::Fund | By::Both)
    }

    fn taker(self) -> bool {
        matches!(self, By::Taker | By::Both)
    }
}

const TAKER_LEG: usize = 0;
const MAKER_LEG: usize = 1;

struct Swap {
    taker_id: String,
    maker_id: String,
    legs: [Leg; 2],
    /// A probe built a second, different claim of this leg ([`Op::ReClaim`]).
    probed: [bool; 2],
    /// A claim of the maker leg was evicted after revealing the preimage ([`Op::Evict`]).
    leaked: bool,
}

struct World {
    dir: Direction,
    btc: MockChain,
    divi: MockChain,
    mdivi: MockBackend,
    mbtc: MockBackend,
    tdivi: MockBackend,
    tbtc: MockBackend,
    /// A third key on each chain, for second-claim attempts.
    pdivi: MockBackend,
    pbtc: MockBackend,
    cfg: SwapConfig,
    clock: Arc<AtomicU64>,
    path: PathBuf,
    _tmp: tempfile::TempDir,
    store: Store,
    maker: Maker,
    taker: Taker,
    swaps: Vec<Swap>,
}

fn offer(dir: Direction) -> Offer {
    Offer {
        id: "o1".into(),
        direction: dir,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }
}

impl World {
    fn new(dir: Direction) -> World {
        let btc = MockChain::new(Chain::Btc, T0, 600);
        let divi = MockChain::new(Chain::Divi, T0, 60);
        let (maker_divi, maker_btc, taker_divi, taker_btc) = match dir {
            Direction::TakerPaysBtc => (DIVI_FUNDS, 0, 0, BTC_FUNDS),
            Direction::TakerPaysDivi => (0, BTC_FUNDS, DIVI_FUNDS, 0),
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("swap.db");
        let store = Store::open(&path).unwrap();
        let clock = Arc::new(AtomicU64::new(T0 as u64));
        let cfg = SwapConfig::profile(Profile::Testnet);
        let (mdivi, mbtc) = (
            divi.backend(1, Amount(maker_divi)),
            btc.backend(2, Amount(maker_btc)),
        );
        let (tdivi, tbtc) = (
            divi.backend(3, Amount(taker_divi)),
            btc.backend(4, Amount(taker_btc)),
        );
        let (pdivi, pbtc) = (divi.backend(7, Amount(0)), btc.backend(8, Amount(0)));
        let maker = build_maker(&cfg, &clock, &mdivi, &mbtc, dir, store.clone());
        let taker = Taker::new(
            Arc::new(tdivi.clone()),
            Arc::new(tbtc.clone()),
            store.clone(),
        );
        World {
            dir,
            btc,
            divi,
            mdivi,
            mbtc,
            tdivi,
            tbtc,
            pdivi,
            pbtc,
            cfg,
            clock,
            path,
            _tmp: tmp,
            store,
            maker,
            taker,
            swaps: Vec::new(),
        }
    }

    fn chain(&self, leg: usize) -> &MockChain {
        let c = if leg == TAKER_LEG {
            self.dir.taker_chain()
        } else {
            self.dir.maker_chain()
        };
        match c {
            Chain::Divi => &self.divi,
            _ => &self.btc,
        }
    }

    /// The backend of the side that claims `leg` (the maker claims the taker leg), and the
    /// probe key on that chain.
    fn claimer(&self, leg: usize) -> (&MockBackend, &MockBackend) {
        let chain = if leg == TAKER_LEG {
            self.dir.taker_chain()
        } else {
            self.dir.maker_chain()
        };
        match (leg == TAKER_LEG, chain == Chain::Divi) {
            (true, true) => (&self.mdivi, &self.pdivi),
            (true, false) => (&self.mbtc, &self.pbtc),
            (false, true) => (&self.tdivi, &self.pdivi),
            (false, false) => (&self.tbtc, &self.pbtc),
        }
    }

    fn records(&self) -> (Vec<MakerRecord>, Vec<TakerRecord>) {
        let mut m = self.store.list_maker_swaps().unwrap();
        let mut t = self.store.list_taker_swaps().unwrap();
        m.sort_by(|a, b| a.id.cmp(&b.id));
        t.sort_by(|a, b| a.id.cmp(&b.id));
        (m, t)
    }

    fn maker_rec(&self, s: &Swap) -> MakerRecord {
        self.store.get_maker_swap(&s.maker_id).unwrap().unwrap()
    }

    fn taker_rec(&self, s: &Swap) -> TakerRecord {
        self.store.get_taker_swap(&s.taker_id).unwrap().unwrap()
    }

    /// Drop both engines and reopen the database: the persisted state must be unchanged.
    fn restart(&mut self) {
        let before = self.records();
        let store = Store::open(&self.path).unwrap();
        self.maker = build_maker(
            &self.cfg,
            &self.clock,
            &self.mdivi,
            &self.mbtc,
            self.dir,
            store.clone(),
        );
        self.taker = Taker::new(
            Arc::new(self.tdivi.clone()),
            Arc::new(self.tbtc.clone()),
            store.clone(),
        );
        self.store = store;
        assert!(
            self.records() == before,
            "a restart changed the stored swaps"
        );
    }

    fn mine(&self, n: u64) {
        self.btc.mine(n);
        self.divi.mine(n);
    }

    async fn tick(&self) {
        let _ = self.maker.tick().await;
    }

    async fn step(&self, i: usize) {
        let s = &self.swaps[i];
        let view = self.maker.view(&s.maker_id).unwrap();
        let _ = self.taker.step(&s.taker_id, view.as_ref()).await;
    }

    async fn step_all(&self) {
        for i in 0..self.swaps.len() {
            self.step(i).await;
        }
    }

    fn pick(&self, i: u8) -> Option<usize> {
        (!self.swaps.is_empty()).then(|| i as usize % self.swaps.len())
    }

    async fn apply(&mut self, op: Op) {
        let by = match op {
            Op::Accept => {
                self.accept().await;
                By::Nobody
            }
            Op::Fund(i) => {
                if let Some(i) = self.pick(i) {
                    let s = &self.swaps[i];
                    if let Ok(notice) = self.taker.lock(&s.taker_id).await {
                        let _ = self.maker.notify_lock(&s.maker_id, notice).await;
                    }
                }
                By::Fund
            }
            Op::Confirm(n) => {
                self.mine(n as u64);
                By::Nobody
            }
            Op::Timeout { taker_chain, secs } => {
                let leg = if taker_chain { TAKER_LEG } else { MAKER_LEG };
                self.chain(leg).advance_time(secs);
                self.clock.fetch_add(secs as u64, Ordering::SeqCst);
                By::Nobody
            }
            Op::Refund(i) => {
                if let Some(i) = self.pick(i) {
                    let _ = self.taker.refund(&self.swaps[i].taker_id).await;
                }
                By::TakerRefund
            }
            Op::Restart => {
                self.restart();
                By::Nobody
            }
            Op::Crash(at) => {
                match at {
                    CrashAt::Maker(s) => self.maker.halt_after(Some(s)),
                    CrashAt::Taker(s) => self.taker.halt_after(Some(s)),
                }
                self.tick().await;
                self.step_all().await;
                self.restart();
                By::Both
            }
            Op::Tick => {
                self.tick().await;
                By::Maker
            }
            Op::Step(i) => {
                if let Some(i) = self.pick(i) {
                    self.step(i).await;
                }
                By::Taker
            }
            Op::ReClaim(i) => {
                if let Some(i) = self.pick(i) {
                    self.reclaim(i).await;
                }
                By::Nobody
            }
            Op::Evict(i) => {
                if let Some(i) = self.pick(i) {
                    self.evict(i).await;
                }
                By::Evict
            }
            Op::HostileRefund(i) => {
                if let Some(i) = self.pick(i) {
                    self.hostile_refund(i).await;
                }
                By::HostileRefund
            }
        };
        self.check(by).await;
    }

    async fn accept(&mut self) {
        if self.swaps.len() >= MAX_SWAPS {
            return;
        }
        let Ok(quote) = self.maker.quote("o1", BTC_SATS).await else {
            return;
        };
        let Ok((taker_id, req)) = self.taker.prepare(&quote).await else {
            return;
        };
        let Ok(view) = self.maker.accept(req).await else {
            return;
        };
        let _ = self.taker.accepted(&taker_id, &view).await;
        self.swaps.push(Swap {
            taker_id,
            maker_id: view.id,
            legs: [Leg::Unfunded; 2],
            probed: [false; 2],
            leaked: false,
        });
    }

    /// Second claims of every claimed leg of swap `i`: the engine's own signed claim again
    /// (must be a no-op) and a different claim with the now public preimage (must be refused).
    async fn reclaim(&mut self, i: usize) {
        let (m, t) = (
            self.maker_rec(&self.swaps[i]),
            self.taker_rec(&self.swaps[i]),
        );
        for leg in [TAKER_LEG, MAKER_LEG] {
            if self.swaps[i].legs[leg] != Leg::Claimed {
                continue;
            }
            let (own, probe) = self.claimer(leg);
            let (own, probe) = (own.clone(), probe.clone());
            let (htlc, at, amount, preimage, signed) = if leg == TAKER_LEG {
                (
                    m.taker_leg_htlc,
                    m.taker_leg_outpoint.unwrap(),
                    m.taker_leg_locked.unwrap(),
                    m.preimage.unwrap(),
                    m.taker_leg_claim.clone(),
                )
            } else {
                (
                    t.maker_leg_htlc.unwrap(),
                    t.maker_leg_outpoint.unwrap(),
                    t.maker_leg_amount.unwrap(),
                    t.preimage,
                    t.maker_leg_claim.clone(),
                )
            };
            if let Some(tx) = signed {
                let _ = own.broadcast(&tx).await;
            }
            let other = probe
                .build_claim(&htlc, &at, amount, &preimage)
                .await
                .unwrap();
            let res = probe.broadcast(&other).await;
            self.swaps[i].probed[leg] = true;
            assert!(
                res.is_err(),
                "invariant 1: a second, different claim of swap {i} leg {leg} was accepted"
            );
        }
    }

    async fn evict(&mut self, i: usize) {
        let Some(claim) = self.taker_rec(&self.swaps[i]).maker_leg_claim else {
            return;
        };
        let (taker, _) = self.claimer(MAKER_LEG);
        if taker.confirmations(&claim.txid).await.unwrap() == Some(0) {
            self.chain(MAKER_LEG).forget(&claim.txid);
            self.swaps[i].leaked = true;
        }
    }

    async fn hostile_refund(&self, i: usize) {
        let m = self.maker_rec(&self.swaps[i]);
        let (Some(htlc), Some(f)) = (m.maker_leg_htlc, m.maker_leg_funding) else {
            return;
        };
        let wait = htlc.locktime.saturating_sub(self.chain(MAKER_LEG).mtp());
        self.chain(MAKER_LEG).advance_time(wait);
        self.clock.fetch_add(wait as u64, Ordering::SeqCst);
        let maker = match self.dir.maker_chain() {
            Chain::Divi => &self.mdivi,
            _ => &self.mbtc,
        };
        if let Ok(tx) = maker.build_refund(&htlc, &f.outpoint, f.amount).await {
            let _ = maker.broadcast(&tx).await;
        }
    }

    fn outpoint(&self, s: &Swap, leg: usize) -> Option<Outpoint> {
        if leg == TAKER_LEG {
            self.taker_rec(s).taker_leg_funding.map(|f| f.outpoint)
        } else {
            self.maker_rec(s).maker_leg_funding.map(|f| f.outpoint)
        }
    }

    fn counts(&self, s: &Swap, leg: usize) -> Option<TxCounts> {
        self.outpoint(s, leg)
            .map(|at| self.chain(leg).tx_counts(&at))
    }

    /// Observe every leg on chain, assert invariant 1 and that each change is one the model
    /// allows for the op that ran, then check the engines' states against the legs.
    async fn check(&mut self, by: By) {
        for i in 0..self.swaps.len() {
            let mut now = [Leg::Unfunded; 2];
            for leg in [TAKER_LEG, MAKER_LEG] {
                let Some(c) = self.counts(&self.swaps[i], leg) else {
                    continue;
                };
                let probed = self.swaps[i].probed[leg] as u32;
                assert!(
                    c.claims <= 1 && c.claims + c.refunds <= 1,
                    "invariant 1: swap {i} leg {leg} spent more than once: {c:?}"
                );
                assert!(
                    c.claim_attempts <= 1 + probed,
                    "invariant 1: the engines signed two different claims of swap {i} leg {leg}: {c:?}"
                );
                now[leg] = match c {
                    TxCounts { fundings: 0, .. } => Leg::Unfunded,
                    TxCounts { claims: 1, .. } => Leg::Claimed,
                    TxCounts { refunds: 1, .. } => Leg::Refunded,
                    _ => Leg::Funded,
                };
            }
            for leg in [TAKER_LEG, MAKER_LEG] {
                let old = self.swaps[i].legs[leg];
                // A leg funded and spent within one op takes both model steps.
                if old == Leg::Unfunded && now[leg] != Leg::Unfunded {
                    let mut funded = now;
                    funded[leg] = Leg::Funded;
                    self.allowed(i, leg, old, funded, by).await;
                    if now[leg] != Leg::Funded {
                        self.allowed(i, leg, Leg::Funded, now, by).await;
                    }
                } else if old != now[leg] {
                    self.allowed(i, leg, old, now, by).await;
                }
            }
            self.swaps[i].legs = now;
            self.states_match(i);
        }
    }

    /// The reference model's transitions of one leg.
    async fn allowed(&self, i: usize, leg: usize, old: Leg, now: [Leg; 2], by: By) {
        let s = &self.swaps[i];
        let new = now[leg];
        let what = format!("swap {i} leg {leg}: {old:?} -> {new:?} by {by:?}");
        let mtp_past_locktime = || {
            let locktime = if leg == TAKER_LEG {
                self.maker_rec(s).taker_leg_htlc.locktime
            } else {
                self.maker_rec(s).maker_leg_htlc.unwrap().locktime
            };
            self.chain(leg).mtp() >= locktime
        };
        let ok = match (old, new, leg) {
            (Leg::Unfunded, Leg::Funded, TAKER_LEG) => by == By::Fund,
            (Leg::Unfunded, Leg::Funded, _) => {
                // The maker locks only after the taker lock is confirmed deep enough.
                let need = self.cfg.confirmations(self.dir.taker_chain());
                let f = self.taker_rec(s).taker_leg_funding.unwrap();
                let (backend, _) = self.claimer(TAKER_LEG);
                let confs = backend.confirmations(&f.tx.txid).await.unwrap();
                by.maker() && now[TAKER_LEG] != Leg::Unfunded && confs.unwrap_or(0) >= need
            }
            // The taker claims the maker leg; never through its refund-only path.
            (Leg::Funded, Leg::Claimed, MAKER_LEG) => by.taker(),
            // The maker claims the taker leg, and only with the preimage the taker revealed:
            // in a claim of the maker leg on chain, or in one evicted from the mempool.
            (Leg::Funded, Leg::Claimed, _) => {
                by.maker() && (now[MAKER_LEG] == Leg::Claimed || s.leaked)
            }
            (Leg::Claimed, Leg::Funded, MAKER_LEG) => by == By::Evict,
            (Leg::Funded, Leg::Refunded, TAKER_LEG) => {
                (by.taker() || by == By::TakerRefund) && mtp_past_locktime()
            }
            (Leg::Funded, Leg::Refunded, _) => {
                (by.maker() || by == By::HostileRefund) && mtp_past_locktime()
            }
            _ => false,
        };
        assert!(ok, "model: {what} is not allowed");
    }

    /// What each engine's state says about the legs.
    fn states_match(&self, i: usize) {
        let s = &self.swaps[i];
        let (m, t) = (self.maker_rec(s).state, self.taker_rec(s).state);
        let [tl, ml] = s.legs;
        match t {
            TakerState::Prepared | TakerState::Accepted => {
                assert_eq!(
                    tl,
                    Leg::Unfunded,
                    "swap {i}: taker {t:?} but taker leg {tl:?}"
                )
            }
            TakerState::Done => assert!(
                ml == Leg::Claimed || tl == Leg::Refunded,
                "swap {i}: taker Done with taker leg {tl:?}, maker leg {ml:?}"
            ),
            TakerState::Lost => assert!(
                s.leaked && tl == Leg::Claimed && ml == Leg::Refunded,
                "swap {i}: taker Lost with taker leg {tl:?}, maker leg {ml:?}, leaked {}",
                s.leaked
            ),
            _ => {}
        }
        match m {
            SwapState::Aborted => {
                assert_eq!(
                    ml,
                    Leg::Unfunded,
                    "swap {i}: maker Aborted but maker leg {ml:?}"
                )
            }
            SwapState::Done => assert!(
                tl == Leg::Claimed || ml == Leg::Refunded,
                "swap {i}: maker Done with taker leg {tl:?}, maker leg {ml:?}"
            ),
            _ => {}
        }
    }

    async fn round(&mut self) {
        self.tick().await;
        self.check(By::Maker).await;
        self.step_all().await;
        self.check(By::Taker).await;
        self.mine(1);
        self.check(By::Nobody).await;
    }

    /// Let the engines finish honestly, then move both chains past every locktime and run
    /// to quiescence. Invariant 2: every funded leg is claimed or refunded.
    async fn settle(&mut self) {
        for _ in 0..12 {
            self.round().await;
        }
        self.btc.advance_time(22_000);
        self.divi.advance_time(22_000);
        self.clock.fetch_add(22_000, Ordering::SeqCst);
        for _ in 0..40 {
            self.round().await;
        }
        for (i, s) in self.swaps.iter().enumerate() {
            for leg in [TAKER_LEG, MAKER_LEG] {
                let Some(c) = self.counts(s, leg) else {
                    continue;
                };
                if c.fundings == 0 {
                    continue;
                }
                assert!(
                    c.claims + c.refunds == 1,
                    "invariant 2: swap {i} leg {leg} is funded but stuck: {c:?}, maker {:?}, taker {:?}",
                    self.maker_rec(s).state,
                    self.taker_rec(s).state
                );
            }
            if s.legs[TAKER_LEG] != Leg::Unfunded {
                // Lost is checked against the legs by `states_match`.
                let t = self.taker_rec(s).state;
                assert!(
                    matches!(t, TakerState::Done | TakerState::Lost),
                    "swap {i}: taker stuck in {t:?}"
                );
            }
            if s.legs[MAKER_LEG] != Leg::Unfunded {
                let m = self.maker_rec(s).state;
                assert!(m.is_terminal(), "swap {i}: maker stuck in {m:?}");
            }
        }
    }
}

fn build_maker(
    cfg: &SwapConfig,
    clock: &Arc<AtomicU64>,
    mdivi: &MockBackend,
    mbtc: &MockBackend,
    dir: Direction,
    store: Store,
) -> Maker {
    let clock = clock.clone();
    Maker::new(
        cfg.clone(),
        Arc::new(mdivi.clone()),
        Arc::new(mbtc.clone()),
        store,
        vec![offer(dir)],
    )
    .unwrap()
    .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)))
}

fn crash_at() -> impl Strategy<Value = CrashAt> {
    prop_oneof![
        prop::sample::select(vec![
            SwapState::TakerLockSeen,
            SwapState::TakerLockConfirmed,
            SwapState::MakerLocked,
            SwapState::MakerLockConfirmed,
            SwapState::MakerRefundable,
            SwapState::TakerClaimed,
            SwapState::MakerClaimed,
            SwapState::MakerRefunded,
        ])
        .prop_map(CrashAt::Maker),
        prop::sample::select(vec![
            TakerState::MakerLockConfirmed,
            TakerState::Claimed,
            TakerState::Refunded,
            TakerState::Lost,
        ])
        .prop_map(CrashAt::Taker),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => Just(Op::Accept),
        3 => (0u8..2).prop_map(Op::Fund),
        4 => (1u8..4).prop_map(Op::Confirm),
        2 => (any::<bool>(), prop::sample::select(vec![1_800u32, 10_800, 22_000]))
            .prop_map(|(taker_chain, secs)| Op::Timeout { taker_chain, secs }),
        2 => (0u8..2).prop_map(Op::Refund),
        2 => Just(Op::Restart),
        2 => crash_at().prop_map(Op::Crash),
        4 => Just(Op::Tick),
        4 => (0u8..2).prop_map(Op::Step),
        1 => (0u8..2).prop_map(Op::ReClaim),
        4 => (0u8..2).prop_map(Op::Evict),
        2 => (0u8..2).prop_map(Op::HostileRefund),
    ]
}

/// Fund one swap and step the taker until its maker-leg claim is broadcast, evicting the
/// claim after every step: random ops then start from a leaked preimage, which the plain
/// sequences reach only rarely. A claim evicted on the last round is resent by the next step
/// unless the maker refunds first, so these runs end both `Done` and `Lost`.
fn leaked_prefix() -> Vec<Op> {
    let mut ops = vec![Op::Accept, Op::Fund(0)];
    for _ in 0..4 {
        ops.extend([
            Op::Confirm(2),
            Op::Tick,
            Op::Step(0),
            Op::Tick,
            Op::Evict(0),
        ]);
    }
    ops
}

fn run(dir: Direction, ops: &[Op]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut w = World::new(dir);
        for op in ops {
            w.apply(*op).await;
        }
        w.settle().await;
    });
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn model_fwd(ops in proptest::collection::vec(op(), 1..40)) {
        run(Direction::TakerPaysBtc, &ops);
    }

    #[test]
    fn model_rev(ops in proptest::collection::vec(op(), 1..40)) {
        run(Direction::TakerPaysDivi, &ops);
    }

    #[test]
    fn leaked_fwd(ops in proptest::collection::vec(op(), 0..20)) {
        run(Direction::TakerPaysBtc, &[leaked_prefix(), ops].concat());
    }

    #[test]
    fn leaked_rev(ops in proptest::collection::vec(op(), 0..20)) {
        run(Direction::TakerPaysDivi, &[leaked_prefix(), ops].concat());
    }
}
