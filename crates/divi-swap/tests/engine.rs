// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Maker + taker engines against two mock chains: the acceptance scenarios of the swap POC.

use async_trait::async_trait;
use divi_swap::api::{AcceptRequest, Direction, LockNotice, Offer, Quote};
use divi_swap::htlc::ScriptVersion;
use divi_swap::mock::{MockBackend, MockChain, TxCounts};
use divi_swap::store::{MakerRecord, TakerRecord};
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, LockedOutput, Maker, Outpoint, Profile,
    Result, SignedTx, SpendInfo, Store, SwapConfig, SwapState, Taker, TakerState, Txid,
};
use proptest::prelude::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const T0: u32 = 1_800_000_000;
const BTC_SATS: u64 = 1_000_000;
const MAKER_DIVI_FUNDS: u64 = 2_000_000_000;
const TAKER_BTC_FUNDS: u64 = 10_000_000;
const MAKER_BTC_FUNDS: u64 = 10_000_000;
const TAKER_DIVI_FUNDS: u64 = 2_000_000_000;

const FWD: Direction = Direction::TakerPaysBtc;
const REV: Direction = Direction::TakerPaysDivi;

thread_local! {
    /// The counter chain (and its block interval) the harness builds on this test's thread:
    /// BTC unless a test runs under [`on_counter`]. Fields named `btc`/`mbtc`/`tbtc` below
    /// are that counter chain.
    static COUNTER: std::cell::Cell<(Chain, u32)> = const { std::cell::Cell::new((Chain::Btc, 600)) };
}

/// Run the rest of this test thread's harness against `chain` (block interval `block_secs`).
fn on_counter(chain: Chain, block_secs: u32) {
    COUNTER.with(|c| c.set((chain, block_secs)));
}

fn counter() -> (Chain, u32) {
    COUNTER.with(|c| c.get())
}

fn offer(dir: Direction) -> Offer {
    Offer {
        id: "o1".into(),
        direction: dir,
        counter_chain: counter().0,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }
}

struct H {
    dir: Direction,
    btc: MockChain,
    divi: MockChain,
    mdivi: MockBackend,
    mbtc: MockBackend,
    tdivi: MockBackend,
    tbtc: MockBackend,
    cfg: SwapConfig,
    clock: Arc<AtomicU64>,
    path: PathBuf,
    _dir: tempfile::TempDir,
    store: Store,
    maker: Maker,
    taker: Taker,
    maker_id: String,
    taker_id: String,
    restarts: u32,
    /// Restart at every checkpoint instead of once at an armed crash state.
    restart_every: bool,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Scn {
    /// Taker claims; both sides complete.
    Happy,
    /// Taker goes silent after locking; both sides time out and refund.
    Refund,
}

#[derive(Clone, Copy, Debug)]
enum Crash {
    Maker(SwapState),
    Taker(TakerState),
}

fn build_maker(h: &H, store: Store) -> Maker {
    let clock = h.clock.clone();
    Maker::new(
        h.cfg.clone(),
        Arc::new(h.mdivi.clone()),
        Arc::new(h.mbtc.clone()),
        store,
        vec![offer(h.dir)],
    )
    .unwrap()
    .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)))
}

impl H {
    fn new() -> H {
        H::with(FWD)
    }

    fn with(dir: Direction) -> H {
        let (counter_chain, block_secs) = counter();
        let btc = MockChain::new(counter_chain, T0, block_secs);
        let divi = MockChain::new(Chain::Divi, T0, 60);
        // Each side funds on the chain where it locks: the taker on the taker-leg chain, the
        // maker on the maker-leg chain.
        let (maker_divi, maker_btc, taker_divi, taker_btc) = match dir {
            Direction::TakerPaysBtc => (MAKER_DIVI_FUNDS, 0, 0, TAKER_BTC_FUNDS),
            Direction::TakerPaysDivi => (0, MAKER_BTC_FUNDS, TAKER_DIVI_FUNDS, 0),
        };
        let mdivi = divi.backend(1, Amount(maker_divi));
        let mbtc = btc.backend(2, Amount(maker_btc));
        let tdivi = divi.backend(3, Amount(taker_divi));
        let tbtc = btc.backend(4, Amount(taker_btc));
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("swap.db");
        let store = Store::open(&path).unwrap();
        let cfg = SwapConfig::profile(Profile::Testnet);
        let clock = Arc::new(AtomicU64::new(T0 as u64));
        let mut h = H {
            dir,
            btc,
            divi,
            mdivi,
            mbtc,
            tdivi,
            tbtc,
            cfg,
            clock,
            path,
            _dir: tmp,
            store: store.clone(),
            maker: Maker::new(
                SwapConfig::profile(Profile::Testnet),
                Arc::new(divi_swap_placeholder()),
                Arc::new(divi_swap_placeholder()),
                store.clone(),
                vec![],
            )
            .unwrap(),
            taker: Taker::new(
                Arc::new(divi_swap_placeholder()),
                Arc::new(divi_swap_placeholder()),
                store.clone(),
            ),
            maker_id: String::new(),
            taker_id: String::new(),
            restarts: 0,
            restart_every: false,
        };
        h.maker = build_maker(&h, store.clone());
        h.taker = Taker::new(
            Arc::new(h.tdivi.clone()),
            Arc::new(h.tbtc.clone()),
            store.clone(),
        );
        h
    }

    /// Drop both engines and reopen the database file, as after a process restart.
    fn restart(&mut self) {
        let store = Store::open(&self.path).unwrap();
        self.maker = build_maker(self, store.clone());
        self.taker = Taker::new(
            Arc::new(self.tdivi.clone()),
            Arc::new(self.tbtc.clone()),
            store.clone(),
        );
        self.store = store;
        self.restarts += 1;
    }

    fn maker_state(&self) -> SwapState {
        self.store
            .get_maker_swap(&self.maker_id)
            .unwrap()
            .unwrap()
            .state
    }

    fn taker_state(&self) -> TakerState {
        self.store
            .get_taker_swap(&self.taker_id)
            .unwrap()
            .unwrap()
            .state
    }

    fn arm(&self, crash: Option<Crash>) {
        match crash {
            Some(Crash::Maker(s)) => self.maker.halt_after(Some(s)),
            Some(Crash::Taker(s)) => self.taker.halt_after(Some(s)),
            None => {}
        }
    }

    /// Restart once if the armed crash state has been reached.
    fn maybe_crash(&mut self, crash: Option<Crash>) {
        if self.restart_every && !(self.maker_id.is_empty() && self.taker_id.is_empty()) {
            self.restart();
            return;
        }
        if self.restarts > 0 || self.maker_id.is_empty() && self.taker_id.is_empty() {
            return;
        }
        let hit = match crash {
            Some(Crash::Maker(s)) => !self.maker_id.is_empty() && self.maker_state() == s,
            Some(Crash::Taker(s)) => !self.taker_id.is_empty() && self.taker_state() == s,
            None => false,
        };
        if hit {
            self.restart();
        }
    }

    async fn quote(&self) -> Quote {
        self.maker.quote("o1", BTC_SATS).await.unwrap()
    }

    /// quote → prepare → accept → accepted. Returns the request for the caller to reuse.
    async fn accept(&mut self, crash: Option<Crash>) {
        self.arm(crash);
        let quote = self.quote().await;
        let (tid, req): (String, AcceptRequest) = self.taker.prepare(&quote).await.unwrap();
        self.taker_id = tid;
        self.maybe_crash(crash);
        let view = self.maker.accept(req).await.unwrap();
        self.maker_id = view.id.clone();
        self.maybe_crash(crash);
        self.taker.accepted(&self.taker_id, &view).await.unwrap();
        self.maybe_crash(crash);
    }

    /// Taker funds the BTC HTLC and tells the maker.
    async fn lock_and_notify(&mut self, crash: Option<Crash>) {
        let notice: LockNotice = match self.taker.lock(&self.taker_id).await {
            Ok(n) => n,
            Err(_) => {
                self.maybe_crash(crash);
                assert_eq!(self.restarts, 1, "lock failed without a crash");
                self.taker.lock(&self.taker_id).await.unwrap()
            }
        };
        self.maker
            .notify_lock(&self.maker_id, notice)
            .await
            .unwrap();
        self.maybe_crash(crash);
    }

    async fn round(&mut self, scn: Scn, crash: Option<Crash>, timed_out: &mut bool, offline: bool) {
        self.btc.set_offline(offline);
        self.divi.set_offline(offline);
        let _ = self.maker.tick().await;
        self.maybe_crash(crash);
        if scn == Scn::Refund && !*timed_out && self.maker_state() == SwapState::MakerLockConfirmed
        {
            self.expire_both();
            *timed_out = true;
        }
        if scn == Scn::Happy || *timed_out {
            let view = self.maker.view(&self.maker_id).unwrap();
            let _ = self.taker.step(&self.taker_id, view.as_ref()).await;
            self.maybe_crash(crash);
        }
        self.btc.set_offline(false);
        self.divi.set_offline(false);
        self.btc.mine(1);
        self.divi.mine(1);
    }

    fn finished(&self) -> bool {
        self.maker_state().is_terminal() && self.taker_state() == TakerState::Done
    }

    /// Run a whole swap, optionally crashing once, with `offline_rounds` of chain outage.
    async fn run(&mut self, scn: Scn, crash: Option<Crash>, offline_rounds: &[usize]) {
        self.accept(crash).await;
        self.lock_and_notify(crash).await;
        let mut timed_out = false;
        for i in 0..80 {
            self.round(scn, crash, &mut timed_out, offline_rounds.contains(&i))
                .await;
            if self.finished() {
                return;
            }
        }
        panic!(
            "did not finish: maker {:?} taker {:?}",
            self.maker_state(),
            self.taker_state()
        );
    }

    /// The chain of the taker leg / maker leg.
    fn tl_chain(&self) -> &MockChain {
        match self.dir.taker_chain() {
            Chain::Divi => &self.divi,
            _ => &self.btc, // the counter chain (BTC here)
        }
    }
    fn ml_chain(&self) -> &MockChain {
        match self.dir.maker_chain() {
            Chain::Divi => &self.divi,
            _ => &self.btc, // the counter chain (BTC here)
        }
    }

    /// Maker's / taker's backend on the taker-leg chain and on the maker-leg chain.
    fn m_tl(&self) -> &MockBackend {
        match self.dir.taker_chain() {
            Chain::Divi => &self.mdivi,
            _ => &self.mbtc, // the counter chain (BTC here)
        }
    }
    fn m_ml(&self) -> &MockBackend {
        match self.dir.maker_chain() {
            Chain::Divi => &self.mdivi,
            _ => &self.mbtc, // the counter chain (BTC here)
        }
    }
    fn t_tl(&self) -> &MockBackend {
        match self.dir.taker_chain() {
            Chain::Divi => &self.tdivi,
            _ => &self.tbtc, // the counter chain (BTC here)
        }
    }
    fn t_ml(&self) -> &MockBackend {
        match self.dir.maker_chain() {
            Chain::Divi => &self.tdivi,
            _ => &self.tbtc, // the counter chain (BTC here)
        }
    }

    /// Move both clocks past their HTLC locktimes (taker 6 h, maker 3 h on the testnet profile).
    fn expire_both(&self) {
        self.tl_chain().advance_time(22_000);
        self.ml_chain().advance_time(12_000);
    }

    /// What the maker received (on the taker-leg chain) and the taker received (on the
    /// maker-leg chain).
    fn maker_got(&self) -> u64 {
        self.tl_chain().balance(&self.m_tl().pubkey()).0
    }
    fn taker_got(&self) -> u64 {
        self.ml_chain().balance(&self.t_ml().pubkey()).0
    }
    fn mine_all(&self, n: u64) {
        self.btc.mine(n);
        self.divi.mine(n);
    }
}

/// A backend that only exists to fill struct slots before the real ones are built.
fn divi_swap_placeholder() -> MockBackend {
    MockChain::new(Chain::Divi, T0, 60).backend(9, Amount(0))
}

fn assert_atomic(h: &H, scn: Scn) {
    match scn {
        Scn::Happy => {
            assert!(h.taker_got() > 0, "taker got nothing on the maker leg");
            assert!(h.maker_got() > 0, "maker got nothing on the taker leg");
            assert_eq!(h.maker_state(), SwapState::Done);
            // Each side received the other's leg, less one claim fee.
            assert_eq!(h.taker_got(), leg_amount(h.dir.maker_chain()) - 1_000);
            assert_eq!(h.maker_got(), leg_amount(h.dir.taker_chain()) - 1_000);
        }
        Scn::Refund => {
            assert_eq!(h.taker_got(), 0, "taker got coins in a refund swap");
            assert_eq!(h.maker_got(), 0, "maker got coins in a refund swap");
            // Both refunded: each side is down only fees.
            let mf = h.ml_chain().balance(&h.m_ml().pubkey()).0;
            let tf = h.tl_chain().balance(&h.t_tl().pubkey()).0;
            let (want_m, want_t) = match h.dir {
                Direction::TakerPaysBtc => (MAKER_DIVI_FUNDS, TAKER_BTC_FUNDS),
                Direction::TakerPaysDivi => (MAKER_BTC_FUNDS, TAKER_DIVI_FUNDS),
            };
            assert!(mf >= want_m - 10_000);
            assert!(tf >= want_t - 10_000);
        }
    }
}

/// Value of the swap on `c`: BTC sats or DIVI sats at the offer price.
fn leg_amount(c: Chain) -> u64 {
    match c {
        Chain::Divi => 500_000_000,
        _ => BTC_SATS, // the counter chain (BTC here)
    }
}

/// Neither maker backend has selected coins.
fn assert_no_funding(h: &H, when: &str) {
    assert_eq!(h.mdivi.funding_calls(), 0, "DIVI coin selection {when}");
    assert_eq!(h.mbtc.funding_calls(), 0, "BTC coin selection {when}");
}

macro_rules! both {
    ($fwd:ident, $rev:ident, $body:ident) => {
        #[tokio::test]
        async fn $fwd() {
            $body(FWD).await
        }
        #[tokio::test]
        async fn $rev() {
            $body(REV).await
        }
    };
}

async fn happy_path_body(dir: Direction) {
    let mut h = H::with(dir);
    h.run(Scn::Happy, None, &[]).await;
    assert_atomic(&h, Scn::Happy);
    let v = h.maker.view(&h.maker_id).unwrap().unwrap();
    assert!(v.preimage.is_some());
    assert_eq!(v.quote.direction, dir);
    // Exactly one maker coin selection, on the maker-leg chain only.
    assert_eq!(h.m_ml().funding_calls(), 1);
    assert_eq!(h.m_tl().funding_calls(), 0);
}
both!(happy_path, rev_happy_path, happy_path_body);

async fn case_a_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::Accepted);
    h.clock.fetch_add(2_000, Ordering::SeqCst);
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_no_funding(&h, "after abort");
    let funds = match dir {
        Direction::TakerPaysBtc => MAKER_DIVI_FUNDS,
        Direction::TakerPaysDivi => MAKER_BTC_FUNDS,
    };
    assert_eq!(h.ml_chain().balance(&h.m_ml().pubkey()).0, funds);
}
both!(
    case_a_taker_never_locks,
    rev_case_a_taker_never_locks,
    case_a_body
);

async fn case_b_body(dir: Direction) {
    let amount = leg_amount(dir.taker_chain());

    // Wrong amount.
    let mut h = H::with(dir);
    h.accept(None).await;
    let view = h.maker.view(&h.maker_id).unwrap().unwrap();
    let f = h
        .t_tl()
        .build_funding(&view.taker_leg.htlc, Amount(amount - 1))
        .await
        .unwrap();
    h.t_tl().broadcast(&f.tx).await.unwrap();
    h.maker
        .notify_lock(
            &h.maker_id,
            LockNotice {
                outpoint: f.outpoint,
            },
        )
        .await
        .unwrap();
    for _ in 0..8 {
        h.tl_chain().mine(1);
        h.maker.tick().await.unwrap();
    }
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_no_funding(&h, "after wrong-amount lock");

    // Wrong script (refund key differs from the one in the accepted HTLC).
    let mut h = H::with(dir);
    h.accept(None).await;
    let view = h.maker.view(&h.maker_id).unwrap().unwrap();
    let mut wrong = view.taker_leg.htlc;
    wrong.refund_pubkey = [0x02; 33];
    let f = h
        .t_tl()
        .build_funding(&wrong, Amount(amount))
        .await
        .unwrap();
    h.t_tl().broadcast(&f.tx).await.unwrap();
    h.maker
        .notify_lock(
            &h.maker_id,
            LockNotice {
                outpoint: f.outpoint,
            },
        )
        .await
        .unwrap();
    // Unconfirmed is not conclusive (a load-balanced Esplora can 404 `/tx` for a mempool tx
    // whose `/status` it already knows), so the maker waits for a confirmation to abort.
    h.maker.tick().await.unwrap();
    assert_ne!(h.maker_state(), SwapState::Aborted);
    for _ in 0..8 {
        h.tl_chain().mine(1);
        h.maker.tick().await.unwrap();
    }
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_no_funding(&h, "after wrong-script lock");
}
both!(
    case_b_taker_lock_invalid,
    rev_case_b_taker_lock_invalid,
    case_b_body
);

async fn case_c_body(dir: Direction) {
    let mut h = H::with(dir);
    h.run(Scn::Refund, None, &[]).await;
    assert_atomic(&h, Scn::Refund);
    assert_eq!(h.maker_state(), SwapState::Done);
    assert_eq!(h.taker_state(), TakerState::Done);
}
both!(
    case_c_taker_never_claims,
    rev_case_c_taker_never_claims,
    case_c_body
);

async fn case_d_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    h.lock_and_notify(None).await;
    // Drive the maker alone until its lock is confirmed. Generous enough for the slowest
    // chain/profile combo currently configured (ZEC testnet's 9 confirmations on top of
    // whichever leg it's on, plus the taker-leg wait before the maker even locks).
    for _ in 0..30 {
        h.maker.tick().await.unwrap();
        h.mine_all(1);
        if h.maker_state() == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(h.maker_state(), SwapState::MakerLockConfirmed);
    let rec = h.store.get_maker_swap(&h.maker_id).unwrap().unwrap();
    let locktime = rec.maker_leg_htlc.unwrap().locktime;
    // Move to just inside the taker's claim window (locktime − safety margin).
    let ml = h.ml_chain().clone();
    let now = ml.mtp();
    let target = locktime - divi_swap::taker::TAKER_SAFETY_MARGIN_SECS - 30;
    ml.advance_time(target - now);
    let view = h.maker.view(&h.maker_id).unwrap();
    h.taker.step(&h.taker_id, view.as_ref()).await.unwrap();
    assert_eq!(h.taker_state(), TakerState::Claimed);
    // The maker only wakes up after its own refund time has passed.
    ml.advance_time(locktime - ml.mtp() + 10);
    for _ in 0..12 {
        let _ = h.maker.tick().await;
        let view = h.maker.view(&h.maker_id).unwrap();
        let _ = h.taker.step(&h.taker_id, view.as_ref()).await;
        h.mine_all(1);
        if h.finished() {
            break;
        }
    }
    assert!(h.finished());
    assert_atomic(&h, Scn::Happy);
}
both!(case_d_late_claim, rev_case_d_late_claim, case_d_body);

async fn crash_maker_body(dir: Direction) {
    use SwapState::*;
    let cases = [
        (Accepted, Scn::Happy),
        (TakerLockSeen, Scn::Happy),
        (TakerLockConfirmed, Scn::Happy),
        (MakerLocked, Scn::Happy),
        (MakerLockConfirmed, Scn::Happy),
        (TakerClaimed, Scn::Happy),
        (MakerClaimed, Scn::Happy),
        (MakerRefundable, Scn::Refund),
        (MakerRefunded, Scn::Refund),
    ];
    for (state, scn) in cases {
        let mut h = H::with(dir);
        h.run(scn, Some(Crash::Maker(state)), &[]).await;
        assert_eq!(h.restarts, 1, "crash at {state:?} never triggered");
        assert_atomic(&h, scn);
    }
}
both!(
    crash_at_every_maker_state,
    rev_crash_at_every_maker_state,
    crash_maker_body
);

async fn crash_taker_body(dir: Direction) {
    use TakerState::*;
    let cases = [
        (Prepared, Scn::Happy),
        (Accepted, Scn::Happy),
        (Locked, Scn::Happy),
        (MakerLockConfirmed, Scn::Happy),
        (Claimed, Scn::Happy),
        (Refunded, Scn::Refund),
    ];
    for (state, scn) in cases {
        let mut h = H::with(dir);
        h.run(scn, Some(Crash::Taker(state)), &[]).await;
        assert_eq!(h.restarts, 1, "crash at {state:?} never triggered");
        assert_atomic(&h, scn);
    }
}
both!(
    crash_at_every_taker_state,
    rev_crash_at_every_taker_state,
    crash_taker_body
);

/// Everything a finished swap left behind: both terminal states, every key's balance on
/// both chains, the funding / claim / refund txs each chain accepted, and how often each
/// side selected coins for its lock.
#[derive(Debug, PartialEq)]
struct Outcome {
    maker: SwapState,
    taker: TakerState,
    balances: [u64; 4],
    taker_leg_txs: TxCounts,
    maker_leg_txs: TxCounts,
    coin_selections: (u64, u64),
}

impl H {
    fn outcome(&self) -> Outcome {
        Outcome {
            maker: self.maker_state(),
            taker: self.taker_state(),
            balances: [
                self.divi.balance(&self.mdivi.pubkey()).0,
                self.btc.balance(&self.mbtc.pubkey()).0,
                self.divi.balance(&self.tdivi.pubkey()).0,
                self.btc.balance(&self.tbtc.pubkey()).0,
            ],
            taker_leg_txs: self.tl_chain().tx_counts(),
            maker_leg_txs: self.ml_chain().tx_counts(),
            coin_selections: (self.m_ml().funding_calls(), self.t_tl().funding_calls()),
        }
    }

    /// Restart once more after the swap finished and keep both engines running: a
    /// finished swap must not broadcast anything again.
    async fn restart_and_settle(&mut self) {
        self.restart();
        for _ in 0..3 {
            let _ = self.maker.tick().await;
            let view = self.maker.view(&self.maker_id).unwrap();
            let _ = self.taker.step(&self.taker_id, view.as_ref()).await;
            self.mine_all(1);
        }
    }
}

/// Restart points: every state each side persists, terminal ones included.
const MAKER_RESTART_POINTS: [SwapState; 10] = [
    SwapState::Accepted,
    SwapState::TakerLockSeen,
    SwapState::TakerLockConfirmed,
    SwapState::MakerLocked,
    SwapState::MakerLockConfirmed,
    SwapState::TakerClaimed,
    SwapState::MakerClaimed,
    SwapState::MakerRefundable,
    SwapState::MakerRefunded,
    SwapState::Done,
];
const TAKER_RESTART_POINTS: [TakerState; 7] = [
    TakerState::Prepared,
    TakerState::Accepted,
    TakerState::Locked,
    TakerState::MakerLockConfirmed,
    TakerState::Claimed,
    TakerState::Refunded,
    TakerState::Done,
];

/// Restart safety, the whole matrix: for the happy and the refund scenario, an in-process
/// restart (both engines dropped, the same DB file reopened, the same mock chains) right
/// after each state either side persists, plus one run that restarts at every checkpoint.
/// Each run must end exactly like the run with no restart: same terminal states, same
/// balances to the sat, one funding per leg, exactly one claim (happy) or one refund
/// (refund) per leg and nothing else, one coin selection per side. A second restart after
/// the swap finished must change nothing.
async fn restart_matrix_body(dir: Direction) {
    use SwapState as M;
    use TakerState as T;
    for scn in [Scn::Happy, Scn::Refund] {
        let mut base = H::with(dir);
        base.run(scn, None, &[]).await;
        assert_atomic(&base, scn);
        base.restart_and_settle().await;
        let want = base.outcome();
        let happy = u64::from(scn == Scn::Happy);
        let leg = TxCounts {
            funds: 1,
            claims: happy,
            refunds: 1 - happy,
        };
        assert_eq!(
            (want.taker_leg_txs, want.maker_leg_txs),
            (leg, leg),
            "{scn:?}"
        );
        assert_eq!(want.coin_selections, (1, 1), "{scn:?}");
        assert_eq!((want.maker, want.taker), (M::Done, T::Done), "{scn:?}");

        let crashes = MAKER_RESTART_POINTS
            .iter()
            .map(|s| Crash::Maker(*s))
            .chain(TAKER_RESTART_POINTS.iter().map(|s| Crash::Taker(*s)));
        let mut hit = Vec::new();
        for crash in crashes {
            let mut h = H::with(dir);
            h.run(scn, Some(crash), &[]).await;
            if h.restarts == 1 {
                hit.push(format!("{crash:?}"));
            }
            assert_atomic(&h, scn);
            h.restart_and_settle().await;
            assert_eq!(
                h.outcome(),
                want,
                "{dir:?} {scn:?}: restart after {crash:?}"
            );
        }

        let mut h = H::with(dir);
        h.restart_every = true;
        h.run(scn, None, &[]).await;
        assert!(h.restarts >= 10, "only {} restarts", h.restarts);
        h.restart_and_settle().await;
        assert_eq!(
            h.outcome(),
            want,
            "{dir:?} {scn:?}: restart at every checkpoint"
        );

        // Every state the scenario passes through was a restart point.
        let path: Vec<Crash> = match scn {
            Scn::Happy => [M::TakerClaimed, M::MakerClaimed]
                .iter()
                .map(|s| Crash::Maker(*s))
                .chain(
                    [T::MakerLockConfirmed, T::Claimed]
                        .iter()
                        .map(|s| Crash::Taker(*s)),
                )
                .collect(),
            Scn::Refund => [M::MakerRefundable, M::MakerRefunded]
                .iter()
                .map(|s| Crash::Maker(*s))
                .chain([T::Refunded].iter().map(|s| Crash::Taker(*s)))
                .collect(),
        };
        let common = [
            Crash::Maker(M::Accepted),
            Crash::Maker(M::TakerLockSeen),
            Crash::Maker(M::TakerLockConfirmed),
            Crash::Maker(M::MakerLocked),
            Crash::Maker(M::MakerLockConfirmed),
            Crash::Maker(M::Done),
            Crash::Taker(T::Prepared),
            Crash::Taker(T::Accepted),
            Crash::Taker(T::Locked),
            Crash::Taker(T::Done),
        ];
        for c in common.iter().chain(path.iter()) {
            assert!(
                hit.contains(&format!("{c:?}")),
                "{dir:?} {scn:?}: restart after {c:?} never triggered (hit: {hit:?})"
            );
        }
        eprintln!(
            "{dir:?} {scn:?}: {} restart points triggered, every-checkpoint run restarted {} times",
            hit.len(),
            h.restarts
        );
    }
}
both!(
    restart_matrix_same_outcome,
    rev_restart_matrix_same_outcome,
    restart_matrix_body
);

const MAKER_STATES: [SwapState; 9] = [
    SwapState::Accepted,
    SwapState::TakerLockSeen,
    SwapState::TakerLockConfirmed,
    SwapState::MakerLocked,
    SwapState::MakerLockConfirmed,
    SwapState::TakerClaimed,
    SwapState::MakerClaimed,
    SwapState::MakerRefundable,
    SwapState::MakerRefunded,
];
const TAKER_STATES: [TakerState; 6] = [
    TakerState::Prepared,
    TakerState::Accepted,
    TakerState::Locked,
    TakerState::MakerLockConfirmed,
    TakerState::Claimed,
    TakerState::Refunded,
];

fn prop_body(
    dir: Direction,
    refund: bool,
    maker_side: bool,
    mi: usize,
    ti: usize,
    outages: &[usize],
) {
    let scn = if refund { Scn::Refund } else { Scn::Happy };
    let crash = if maker_side {
        Crash::Maker(MAKER_STATES[mi])
    } else {
        Crash::Taker(TAKER_STATES[ti])
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut h = H::with(dir);
        h.run(scn, Some(crash), outages).await;
        // Whatever the crash, the swap is atomic: both legs complete or both refund.
        // (A crash state the scenario never visits simply never triggers.)
        assert_atomic(&h, scn);
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_random_crash_points(
        refund in any::<bool>(),
        maker_side in any::<bool>(),
        mi in 0usize..MAKER_STATES.len(),
        ti in 0usize..TAKER_STATES.len(),
        outages in proptest::collection::vec(0usize..30, 0..6),
    ) {
        prop_body(FWD, refund, maker_side, mi, ti, &outages);
    }

    #[test]
    fn rev_prop_random_crash_points(
        refund in any::<bool>(),
        maker_side in any::<bool>(),
        mi in 0usize..MAKER_STATES.len(),
        ti in 0usize..TAKER_STATES.len(),
        outages in proptest::collection::vec(0usize..30, 0..6),
    ) {
        prop_body(REV, refund, maker_side, mi, ti, &outages);
    }
}

async fn no_coin_selection_body(dir: Direction) {
    let mut h = H::with(dir);
    h.maker.halt_after(Some(SwapState::TakerLockConfirmed));
    h.accept(None).await;
    assert_no_funding(&h, "after accept");
    h.lock_and_notify(None).await;
    assert_no_funding(&h, "TakerLockSeen (unconfirmed)");
    assert_eq!(h.maker_state(), SwapState::TakerLockSeen);
    h.tl_chain().mine(1);
    h.maker.tick().await.unwrap();
    // Not yet at the required confirmations on the taker-leg chain (DIVI needs 3).
    assert_no_funding(&h, "below required confirmations");
    while h.maker_state() != SwapState::TakerLockConfirmed {
        h.tl_chain().mine(1);
        h.maker.tick().await.unwrap();
        assert_no_funding(&h, "while confirming the taker lock");
    }
    assert_no_funding(&h, "at TakerLockConfirmed");
    h.maker.halt_after(None);
    h.maker.tick().await.unwrap();
    assert_eq!(h.m_ml().funding_calls(), 1, "on the edge to MakerLocked");
    assert_eq!(h.m_tl().funding_calls(), 0, "never on the taker-leg chain");
    assert_eq!(h.maker_state(), SwapState::MakerLocked);
}
both!(
    no_coin_selection_before_taker_lock_confirmed,
    rev_no_coin_selection_before_taker_lock_confirmed,
    no_coin_selection_body
);

async fn timeout_invariant_body(dir: Direction) {
    // A config that breaks the gap cannot build an engine.
    let mut bad = SwapConfig::profile(Profile::Testnet);
    bad.maker_timeout_secs = bad.taker_timeout_secs - 3_599;
    let chain = MockChain::new(Chain::Divi, T0, 60);
    let r = Maker::new(
        bad,
        Arc::new(chain.backend(1, Amount(1))),
        Arc::new(chain.backend(2, Amount(1))),
        Store::in_memory().unwrap(),
        vec![],
    );
    assert!(r.is_err());

    // The taker-leg window shrinking below what the maker needs aborts before any coin is
    // locked on either chain.
    let mut h = H::with(dir);
    h.accept(None).await;
    h.lock_and_notify(None).await;
    assert_eq!(h.maker_state(), SwapState::TakerLockSeen);
    h.tl_chain().advance_time(10_000); // 21_600 − 10_000 < maker_timeout + claim_margin
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_no_funding(&h, "after window collapse");
}
both!(
    timeout_invariant_enforced,
    rev_timeout_invariant_enforced,
    timeout_invariant_body
);

#[tokio::test]
async fn quote_expires() {
    for dir in [FWD, REV] {
        let h = H::with(dir);
        let q = h.quote().await;
        assert_eq!(q.direction, dir);
        let (_, req) = h.taker.prepare(&q).await.unwrap();
        h.clock
            .fetch_add(h.cfg.quote_expiry_secs as u64 + 1, Ordering::SeqCst);
        assert!(h.maker.accept(req).await.is_err());

        // A fresh quote still works, and a quote is single use.
        let q = h.quote().await;
        let (_, req) = h.taker.prepare(&q).await.unwrap();
        h.maker.accept(req.clone()).await.unwrap();
        assert!(h.maker.accept(req).await.is_err());
    }
}

/// Delegates to a mock backend but asserts every broadcast tx is already in the store.
struct Spy {
    inner: MockBackend,
    store: Store,
    checked: Arc<AtomicU64>,
}

impl Spy {
    fn persisted(&self, txid: &Txid) -> bool {
        let maker = self.store.list_maker_swaps().unwrap().into_iter().any(|m| {
            m.maker_leg_funding
                .as_ref()
                .is_some_and(|f| f.tx.txid == *txid)
                || m.maker_leg_refund.as_ref().is_some_and(|t| t.txid == *txid)
                || m.taker_leg_claim.as_ref().is_some_and(|t| t.txid == *txid)
        });
        let taker = self.store.list_taker_swaps().unwrap().into_iter().any(|t| {
            t.taker_leg_funding
                .as_ref()
                .is_some_and(|f| f.tx.txid == *txid)
                || t.maker_leg_claim.as_ref().is_some_and(|c| c.txid == *txid)
                || t.taker_leg_refund.as_ref().is_some_and(|r| r.txid == *txid)
        });
        maker || taker
    }
}

#[async_trait]
impl ChainBackend for Spy {
    fn chain(&self) -> Chain {
        self.inner.chain()
    }
    fn pubkey(&self) -> [u8; 33] {
        self.inner.pubkey()
    }
    async fn tip_height(&self) -> Result<u64> {
        self.inner.tip_height().await
    }
    async fn tip_hash(&self) -> Result<String> {
        self.inner.tip_hash().await
    }
    async fn median_time_past(&self) -> Result<u32> {
        self.inner.median_time_past().await
    }
    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        self.inner.build_funding(htlc, amount).await
    }
    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        self.inner.build_claim(htlc, at, amount, preimage).await
    }
    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.inner.build_refund(htlc, at, amount).await
    }
    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        assert!(
            self.persisted(&tx.txid),
            "broadcast of {} before it was persisted",
            tx.txid
        );
        self.checked.fetch_add(1, Ordering::SeqCst);
        self.inner.broadcast(tx).await
    }
    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        self.inner.confirmations(txid).await
    }
    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        self.inner.htlc_output(htlc, at).await
    }
    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        self.inner.find_spend(outpoint, from_height).await
    }
}

#[tokio::test]
async fn broadcast_after_persist() {
    for dir in [FWD, REV] {
        for scn in [Scn::Happy, Scn::Refund] {
            let h = H::with(dir);
            let checked = Arc::new(AtomicU64::new(0));
            let spy = |b: &MockBackend| -> Arc<dyn ChainBackend> {
                Arc::new(Spy {
                    inner: b.clone(),
                    store: h.store.clone(),
                    checked: checked.clone(),
                })
            };
            let clock = h.clock.clone();
            let maker = Maker::new(
                h.cfg.clone(),
                spy(&h.mdivi),
                spy(&h.mbtc),
                h.store.clone(),
                vec![offer(dir)],
            )
            .unwrap()
            .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)));
            let taker = Taker::new(spy(&h.tdivi), spy(&h.tbtc), h.store.clone());

            let q = maker.quote("o1", BTC_SATS).await.unwrap();
            let (tid, req) = taker.prepare(&q).await.unwrap();
            let view = maker.accept(req).await.unwrap();
            taker.accepted(&tid, &view).await.unwrap();
            let notice = taker.lock(&tid).await.unwrap();
            maker.notify_lock(&view.id, notice).await.unwrap();
            let mut timed_out = false;
            for _ in 0..60 {
                let _ = maker.tick().await;
                let st = h.store.get_maker_swap(&view.id).unwrap().unwrap().state;
                if scn == Scn::Refund && !timed_out && st == SwapState::MakerLockConfirmed {
                    h.expire_both();
                    timed_out = true;
                }
                if scn == Scn::Happy || timed_out {
                    let v = maker.view(&view.id).unwrap();
                    let _ = taker.step(&tid, v.as_ref()).await;
                }
                h.mine_all(1);
                let done = h.store.get_taker_swap(&tid).unwrap().unwrap().state == TakerState::Done;
                if done && st.is_terminal() {
                    break;
                }
            }
            // happy: fund, fund, claim, claim; refund: fund, fund, refund, refund (at least).
            assert!(checked.load(Ordering::SeqCst) >= 4, "{dir:?} {scn:?}");
        }
    }
}

/// Drive `h` (already past accept+lock) through `scn`, arming `chain.reject_next_broadcast()`
/// the first round `armed(h)` is true (checked against the state as of the *previous*
/// round, i.e. before this round's tick/step runs) — so the very next broadcast that round
/// attempts gets rejected once, forcing the engine to drop its persisted bytes and re-sign.
/// Asserts the swap still reaches the expected terminal balances, and that the reject point
/// was actually reached (a test bug that never arms would otherwise pass trivially).
async fn resign_after_reject(
    h: &mut H,
    scn: Scn,
    chain: &MockChain,
    mut armed: impl FnMut(&H) -> bool,
) {
    h.accept(None).await;
    h.lock_and_notify(None).await;
    let mut timed_out = false;
    let mut injected = false;
    for i in 0..80 {
        if !injected && armed(h) {
            chain.reject_next_broadcast();
            injected = true;
        }
        h.round(scn, None, &mut timed_out, false).await;
        if h.finished() {
            assert!(injected, "reject point never reached in {i} rounds");
            assert_atomic(h, scn);
            return;
        }
    }
    panic!(
        "did not finish: maker {:?} taker {:?} injected={injected}",
        h.maker_state(),
        h.taker_state()
    );
}

/// The maker's refund of its own leg (`on_maker_refundable`) drops the persisted refund and
/// re-signs after a rejection, instead of resending dead bytes forever (regression: a maker
/// persisted a claim signed by a buggy sighash and rebroadcast it forever — fixed for every
/// claim/refund path, this covers the maker-refund one with the mock's reject switch).
async fn resign_after_maker_refund_reject_body(dir: Direction) {
    let mut h = H::with(dir);
    let ml_chain = h.ml_chain().clone();
    resign_after_reject(&mut h, Scn::Refund, &ml_chain, |h| {
        h.maker_state() == SwapState::MakerRefundable
    })
    .await;
}

/// The maker's claim of the taker's leg (`on_taker_claimed`) does the same. Armed one state
/// earlier than the target (`MakerLockConfirmed`, not `TakerClaimed`): `on_taker_claimed`
/// unconditionally chains into `MakerClaimed` on a successful broadcast (no confirmation
/// gate), and the maker's `step()` keeps draining `Flow::Moved` transitions within one
/// `tick()` call, so `TakerClaimed` is never observable as a paused, between-rounds state —
/// arming while still `MakerLockConfirmed` catches the broadcast on its first attempt
/// instead, inside whichever round's `tick()` drives the whole chain through.
async fn resign_after_maker_claim_reject_body(dir: Direction) {
    let mut h = H::with(dir);
    let tl_chain = h.tl_chain().clone();
    resign_after_reject(&mut h, Scn::Happy, &tl_chain, |h| {
        h.maker_state() == SwapState::MakerLockConfirmed
    })
    .await;
}

/// The taker's refund of its own leg (`on_refunded`) does the same.
async fn resign_after_taker_refund_reject_body(dir: Direction) {
    let mut h = H::with(dir);
    let tl_chain = h.tl_chain().clone();
    resign_after_reject(&mut h, Scn::Refund, &tl_chain, |h| {
        h.taker_state() == TakerState::Refunded
    })
    .await;
}

/// The taker's claim of the maker's leg (`on_claimed`) does the same — this path had no
/// lazy-rebuild at all before this change (a cleared `maker_leg_claim` would hard-error
/// instead of re-signing), so this is the strongest regression test of the four.
async fn resign_after_taker_claim_reject_body(dir: Direction) {
    let mut h = H::with(dir);
    let ml_chain = h.ml_chain().clone();
    resign_after_reject(&mut h, Scn::Happy, &ml_chain, |h| {
        h.taker_state() == TakerState::Claimed
    })
    .await;
}

both!(
    resign_maker_refund,
    rev_resign_maker_refund,
    resign_after_maker_refund_reject_body
);
both!(
    resign_maker_claim,
    rev_resign_maker_claim,
    resign_after_maker_claim_reject_body
);
both!(
    resign_taker_refund,
    rev_resign_taker_refund,
    resign_after_taker_refund_reject_body
);
both!(
    resign_taker_claim,
    rev_resign_taker_claim,
    resign_after_taker_claim_reject_body
);

/// Drive both engines (no claim-stepping gate) until the taker reaches `target`, frozen
/// there via `halt_after` so nothing past it (in particular, `on_maker_lock_confirmed`'s
/// claim branch) has run yet. Un-arms the hook before returning.
async fn drive_taker_to(h: &mut H, target: TakerState) {
    h.taker.halt_after(Some(target));
    for _ in 0..40 {
        let _ = h.maker.tick().await;
        let view = h.maker.view(&h.maker_id).unwrap();
        let _ = h.taker.step(&h.taker_id, view.as_ref()).await;
        h.mine_all(1);
        if h.taker_state() == target {
            break;
        }
    }
    assert_eq!(
        h.taker_state(),
        target,
        "test setup bug: never reached {target:?}"
    );
    h.taker.halt_after(None);
}

/// `Taker::refund` called while `MakerLockConfirmed` and still well within the safe-to-claim
/// window must leave the state alone and build no claim — the live bug (`Taker::step`, which
/// `divi-swap refund` used to call, claims whenever still safe, regardless of the operator's
/// intent to refund instead).
async fn refund_never_claims_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    h.lock_and_notify(None).await;
    drive_taker_to(&mut h, TakerState::MakerLockConfirmed).await;

    let state = h.taker.refund(&h.taker_id).await.unwrap();
    assert_eq!(state, TakerState::MakerLockConfirmed);
    let rec = h.store.get_taker_swap(&h.taker_id).unwrap().unwrap();
    assert!(
        rec.maker_leg_claim.is_none(),
        "refund must not build a claim"
    );
}

/// `Taker::refund` repeated after the taker-leg timeout drives the same `MakerLockConfirmed`
/// swap to `Done` via a refund, never a claim.
async fn refund_after_timeout_reaches_done_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    h.lock_and_notify(None).await;
    drive_taker_to(&mut h, TakerState::MakerLockConfirmed).await;

    h.tl_chain().advance_time(22_000); // past the taker's own (longer) timeout
    for _ in 0..40 {
        let state = h.taker.refund(&h.taker_id).await.unwrap();
        h.mine_all(1);
        if state == TakerState::Done {
            let rec = h.store.get_taker_swap(&h.taker_id).unwrap().unwrap();
            assert!(rec.maker_leg_claim.is_none(), "must never have claimed");
            return;
        }
    }
    panic!("refund did not reach Done: {:?}", h.taker_state());
}

/// `Taker::refund` on an already-`Claimed` swap does nothing (leaves the state exactly as
/// it is) rather than erroring or reverting.
async fn refund_on_claimed_does_nothing_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    h.lock_and_notify(None).await;
    drive_taker_to(&mut h, TakerState::Claimed).await;

    let state = h.taker.refund(&h.taker_id).await.unwrap();
    assert_eq!(
        state,
        TakerState::Claimed,
        "refund on Claimed must do nothing"
    );
}

both!(
    refund_never_claims,
    rev_refund_never_claims,
    refund_never_claims_body
);
both!(
    refund_after_timeout_reaches_done,
    rev_refund_after_timeout_reaches_done,
    refund_after_timeout_reaches_done_body
);
both!(
    refund_on_claimed_does_nothing,
    rev_refund_on_claimed_does_nothing,
    refund_on_claimed_does_nothing_body
);

/// Safety review (orchestrator): the maker must never lock its own leg if there isn't
/// enough of the taker-leg's own timeout left for the maker to later claim it safely —
/// `maker.rs::taker_window_too_short` (`remaining = taker HTLC locktime - taker-chain mtp`
/// vs `needed = maker_timeout_secs + claim_margin_secs`) is the gate, checked at every
/// point the maker could still back out (`on_accepted`'s `lock_window_gone`,
/// `on_taker_lock_seen`, and — the critical one — right before `build_funding` in
/// `on_taker_lock_confirmed`, the "staking edge"). This exact path had zero test coverage
/// before this review, despite being the primary protection for "the maker can never be
/// left unable to claim after the taker claims." Testnet profile: taker_timeout 21,600s,
/// maker_timeout 10,800s, claim_margin 1,800s, so `needed` = 12,600s out of the taker
/// leg's 21,600s budget — eating into it past ~9,000s (while plenty, i.e. ~12,600s, is
/// still nominally left before the taker leg's own locktime) must trip the gate.
async fn maker_aborts_when_taker_window_too_short_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    h.lock_and_notify(None).await;
    h.tl_chain().advance_time(9_500);
    for _ in 0..40 {
        let _ = h.maker.tick().await;
        h.mine_all(1);
        if h.maker_state() == SwapState::Aborted {
            break;
        }
    }
    assert_eq!(
        h.maker_state(),
        SwapState::Aborted,
        "must abort, not lock, on a too-short window"
    );
    assert_eq!(
        h.m_ml().funding_calls(),
        0,
        "must never have selected coins for its own leg"
    );
}

/// The same gate must not false-positive: comfortably within the window, the maker locks
/// normally.
async fn maker_locks_when_taker_window_is_fine_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    h.lock_and_notify(None).await;
    h.tl_chain().advance_time(100);
    for _ in 0..40 {
        let _ = h.maker.tick().await;
        h.mine_all(1);
        if matches!(
            h.maker_state(),
            SwapState::MakerLocked | SwapState::MakerLockConfirmed
        ) {
            break;
        }
    }
    assert!(
        matches!(
            h.maker_state(),
            SwapState::MakerLocked | SwapState::MakerLockConfirmed
        ),
        "expected to lock, got {:?}",
        h.maker_state()
    );
    assert!(
        h.m_ml().funding_calls() >= 1,
        "must have selected coins for its own leg"
    );
}

both!(
    maker_aborts_too_short_window,
    rev_maker_aborts_too_short_window,
    maker_aborts_when_taker_window_too_short_body
);
both!(
    maker_locks_window_fine,
    rev_maker_locks_window_fine,
    maker_locks_when_taker_window_is_fine_body
);

const MAKER_HAPPY: &str = include_str!("fixtures/maker-forward-done-happy.json");
const MAKER_CASEC: &str = include_str!("fixtures/maker-forward-done-casec.json");
const TAKER_HAPPY: &str = include_str!("fixtures/taker-forward-done-happy.json");

/// Real records written by the pre-direction daemon (deployed swaps.db, local taker.db) still
/// deserialize, map onto the role-based fields, default to `taker_pays_btc`, and survive
/// being driven by the new engines.
#[tokio::test]
async fn forward_records_still_load() {
    let happy: MakerRecord = serde_json::from_str(MAKER_HAPPY).unwrap();
    let casec: MakerRecord = serde_json::from_str(MAKER_CASEC).unwrap();
    let taker: TakerRecord = serde_json::from_str(TAKER_HAPPY).unwrap();

    // The old JSON used btc_*/divi_* names; compare against the raw values.
    let raw: serde_json::Value = serde_json::from_str(MAKER_HAPPY).unwrap();
    assert!(
        raw.get("btc_htlc").is_some(),
        "fixture is not in the old shape"
    );
    assert!(raw["quote"].get("direction").is_none());
    for r in [&happy, &casec] {
        assert_eq!(r.quote.direction, Direction::TakerPaysBtc);
        assert_eq!(r.state, SwapState::Done);
        assert!(r.maker_leg_htlc.is_some());
        assert!(r.taker_leg_outpoint.is_some() && r.maker_leg_funding.is_some());
    }
    assert_eq!(
        serde_json::to_value(happy.taker_leg_htlc).unwrap(),
        raw["btc_htlc"]
    );
    assert_eq!(
        serde_json::to_value(happy.maker_leg_htlc).unwrap(),
        raw["divi_htlc"]
    );
    assert_eq!(
        hex::encode(happy.taker_maker_leg_pubkey),
        raw["taker_divi_pubkey"].as_str().unwrap()
    );
    // Happy path: taker claimed the maker leg (DIVI) → maker claimed the taker leg (BTC).
    assert!(happy.taker_leg_claim.is_some() && happy.maker_leg_refund.is_none());
    assert!(happy.preimage.is_some());
    // Case C: maker refunded its DIVI, never saw a preimage.
    assert!(casec.maker_leg_refund.is_some() && casec.taker_leg_claim.is_none());
    assert!(casec.preimage.is_none());

    assert_eq!(taker.quote.direction, Direction::TakerPaysBtc);
    assert_eq!(taker.state, TakerState::Done);
    assert!(taker.taker_leg_htlc.is_some() && taker.taker_leg_funding.is_some());
    assert!(taker.maker_leg_htlc.is_some() && taker.maker_leg_outpoint.is_some());
    assert!(taker.maker_leg_amount.is_some() && taker.maker_leg_claim.is_some());
    assert!(taker.taker_leg_refund.is_none());
    assert_eq!(taker.quote.btc_amount, Amount(10_000));
    assert_eq!(taker.quote.divi_amount, Amount(30_000_000_000));

    // Round-trip through the store, then drive both engines: terminal swaps stay as they are.
    let h = H::new();
    h.store.put_maker_swap(&happy).unwrap();
    h.store.put_maker_swap(&casec).unwrap();
    h.store.put_taker_swap(&taker).unwrap();
    for id in [&happy.id, &casec.id] {
        let got = h.store.get_maker_swap(id).unwrap().unwrap();
        assert_eq!(got.state, SwapState::Done);
        assert_eq!(h.maker.step(id).await.unwrap(), SwapState::Done);
        let v = h.maker.view(id).unwrap().unwrap();
        assert_eq!(v.quote.direction, Direction::TakerPaysBtc);
        assert_eq!(v.taker_leg.htlc, got.taker_leg_htlc);
        assert_eq!(v.maker_leg.unwrap().htlc, got.maker_leg_htlc.unwrap());
    }
    assert_eq!(
        h.taker.step(&taker.id, None).await.unwrap(),
        TakerState::Done
    );
    h.maker.tick().await.unwrap();
    assert_eq!(h.store.list_maker_swaps().unwrap().len(), 2);

    // Re-serialising writes the new names and reads back identically.
    let again: MakerRecord = serde_json::from_str(&serde_json::to_string(&happy).unwrap()).unwrap();
    assert_eq!(again.taker_leg_htlc, happy.taker_leg_htlc);
    assert_eq!(again.maker_leg_funding, happy.maker_leg_funding);
    let again: TakerRecord = serde_json::from_str(&serde_json::to_string(&taker).unwrap()).unwrap();
    assert_eq!(again.maker_leg_claim, taker.maker_leg_claim);
}

/// The engine suite above, re-run with another counter chain: every body is driven through a
/// harness whose counter chain is `$chain` (block interval `$secs`), in direction `$dir`. Only
/// chain parameters differ from the BTC runs: block interval and the profile's confirmation
/// count for that chain.
macro_rules! on_counter {
    ($name:ident, $chain:expr, $secs:expr, $dir:expr, $body:ident) => {
        #[tokio::test]
        async fn $name() {
            on_counter($chain, $secs);
            $body($dir).await
        }
    };
}

/// `ltc-divi-testnet`: the taker locks DIVI, the maker locks LTC.
macro_rules! ltc_rev {
    ($name:ident, $body:ident) => {
        on_counter!($name, Chain::Ltc, 150, REV, $body);
    };
}
/// `divi-ltc-testnet`: the taker locks LTC, the maker locks DIVI.
macro_rules! ltc_fwd {
    ($name:ident, $body:ident) => {
        on_counter!($name, Chain::Ltc, 150, FWD, $body);
    };
}
/// `divi-zec-testnet` / `zec-divi-testnet` (transparent ZEC, 75 s blocks).
macro_rules! zec_fwd {
    ($name:ident, $body:ident) => {
        on_counter!($name, Chain::Zec, 75, FWD, $body);
    };
}
macro_rules! zec_rev {
    ($name:ident, $body:ident) => {
        on_counter!($name, Chain::Zec, 75, REV, $body);
    };
}

ltc_rev!(ltc_rev_happy_path, happy_path_body);
ltc_rev!(ltc_rev_case_a_taker_never_locks, case_a_body);
ltc_rev!(ltc_rev_case_b_taker_lock_invalid, case_b_body);
ltc_rev!(ltc_rev_case_c_taker_never_claims, case_c_body);
ltc_rev!(ltc_rev_case_d_late_claim, case_d_body);
ltc_rev!(ltc_rev_crash_at_every_maker_state, crash_maker_body);
ltc_rev!(ltc_rev_crash_at_every_taker_state, crash_taker_body);
ltc_rev!(
    ltc_rev_no_coin_selection_before_taker_lock_confirmed,
    no_coin_selection_body
);
ltc_rev!(ltc_rev_timeout_invariant_enforced, timeout_invariant_body);
ltc_rev!(ltc_rev_quote_carries_ltc, quote_carries_counter_body);

ltc_fwd!(ltc_fwd_happy_path, happy_path_body);
ltc_fwd!(ltc_fwd_case_a_taker_never_locks, case_a_body);
ltc_fwd!(ltc_fwd_case_b_taker_lock_invalid, case_b_body);
ltc_fwd!(ltc_fwd_case_c_taker_never_claims, case_c_body);
ltc_fwd!(ltc_fwd_case_d_late_claim, case_d_body);
ltc_fwd!(ltc_fwd_crash_at_every_maker_state, crash_maker_body);
ltc_fwd!(ltc_fwd_crash_at_every_taker_state, crash_taker_body);
ltc_fwd!(
    ltc_fwd_no_coin_selection_before_taker_lock_confirmed,
    no_coin_selection_body
);
ltc_fwd!(ltc_fwd_timeout_invariant_enforced, timeout_invariant_body);
ltc_fwd!(ltc_fwd_quote_carries_ltc, quote_carries_counter_body);

zec_fwd!(zec_fwd_happy_path, happy_path_body);
zec_fwd!(zec_fwd_case_a_taker_never_locks, case_a_body);
zec_fwd!(zec_fwd_case_b_taker_lock_invalid, case_b_body);
zec_fwd!(zec_fwd_case_c_taker_never_claims, case_c_body);
zec_fwd!(zec_fwd_case_d_late_claim, case_d_body);
zec_fwd!(zec_fwd_crash_at_every_maker_state, crash_maker_body);
zec_fwd!(zec_fwd_crash_at_every_taker_state, crash_taker_body);
zec_fwd!(
    zec_fwd_no_coin_selection_before_taker_lock_confirmed,
    no_coin_selection_body
);
zec_fwd!(zec_fwd_timeout_invariant_enforced, timeout_invariant_body);
zec_fwd!(zec_fwd_quote_carries_zec, quote_carries_counter_body);

zec_rev!(zec_rev_happy_path, happy_path_body);
zec_rev!(zec_rev_case_a_taker_never_locks, case_a_body);
zec_rev!(zec_rev_case_b_taker_lock_invalid, case_b_body);
zec_rev!(zec_rev_case_c_taker_never_claims, case_c_body);
zec_rev!(zec_rev_case_d_late_claim, case_d_body);
zec_rev!(zec_rev_crash_at_every_maker_state, crash_maker_body);
zec_rev!(zec_rev_crash_at_every_taker_state, crash_taker_body);
zec_rev!(
    zec_rev_no_coin_selection_before_taker_lock_confirmed,
    no_coin_selection_body
);
zec_rev!(zec_rev_timeout_invariant_enforced, timeout_invariant_body);
zec_rev!(zec_rev_quote_carries_zec, quote_carries_counter_body);
ltc_fwd!(
    ltc_fwd_maker_aborts_too_short_window,
    maker_aborts_when_taker_window_too_short_body
);
ltc_rev!(
    ltc_rev_maker_aborts_too_short_window,
    maker_aborts_when_taker_window_too_short_body
);
zec_fwd!(
    zec_fwd_maker_aborts_too_short_window,
    maker_aborts_when_taker_window_too_short_body
);
zec_rev!(
    zec_rev_maker_aborts_too_short_window,
    maker_aborts_when_taker_window_too_short_body
);
ltc_fwd!(
    ltc_fwd_maker_locks_window_fine,
    maker_locks_when_taker_window_is_fine_body
);
ltc_rev!(
    ltc_rev_maker_locks_window_fine,
    maker_locks_when_taker_window_is_fine_body
);
zec_fwd!(
    zec_fwd_maker_locks_window_fine,
    maker_locks_when_taker_window_is_fine_body
);
zec_rev!(
    zec_rev_maker_locks_window_fine,
    maker_locks_when_taker_window_is_fine_body
);

/// What the harness actually built: a quote on the configured counter chain with that chain's
/// confirmation count and the maker's key there, the counter leg on the side the direction
/// says, and the maker's coins selected on its own leg (the guard that the `ltc_*`/`zec_*`
/// tests are not BTC in disguise).
async fn quote_carries_counter_body(dir: Direction) {
    let mut h = H::with(dir);
    let (chain, _) = counter();
    let q = h.quote().await;
    assert_eq!(q.counter_chain, chain);
    let (counter_leg, divi_leg) = match dir {
        Direction::TakerPaysBtc => (q.taker_chain(), q.maker_chain()),
        Direction::TakerPaysDivi => (q.maker_chain(), q.taker_chain()),
    };
    assert_eq!((counter_leg, divi_leg), (chain, Chain::Divi));
    assert_eq!(q.btc_confirmations, h.cfg.confirmations(chain));
    assert_eq!(q.maker_btc_pubkey, h.mbtc.pubkey());
    assert_eq!(h.mbtc.chain(), chain);
    h.run(Scn::Happy, None, &[]).await;
    let rec = h.store.get_maker_swap(&h.maker_id).unwrap().unwrap();
    assert_eq!(rec.quote.counter_chain, chain);
    let (on_counter_chain, on_divi) = match dir {
        Direction::TakerPaysBtc => (0, 1),
        Direction::TakerPaysDivi => (1, 0),
    };
    assert_eq!(
        h.mbtc.funding_calls(),
        on_counter_chain,
        "maker funding on {chain}"
    );
    assert_eq!(h.mdivi.funding_calls(), on_divi, "maker funding on divi");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn ltc_rev_prop_random_crash_points(
        refund in any::<bool>(),
        maker_side in any::<bool>(),
        mi in 0usize..MAKER_STATES.len(),
        ti in 0usize..TAKER_STATES.len(),
        outages in proptest::collection::vec(0usize..30, 0..6),
    ) {
        on_counter(Chain::Ltc, 150);
        prop_body(REV, refund, maker_side, mi, ti, &outages);
    }

    #[test]
    fn ltc_fwd_prop_random_crash_points(
        refund in any::<bool>(),
        maker_side in any::<bool>(),
        mi in 0usize..MAKER_STATES.len(),
        ti in 0usize..TAKER_STATES.len(),
        outages in proptest::collection::vec(0usize..30, 0..6),
    ) {
        on_counter(Chain::Ltc, 150);
        prop_body(FWD, refund, maker_side, mi, ti, &outages);
    }

    #[test]
    fn zec_fwd_prop_random_crash_points(
        refund in any::<bool>(),
        maker_side in any::<bool>(),
        mi in 0usize..MAKER_STATES.len(),
        ti in 0usize..TAKER_STATES.len(),
        outages in proptest::collection::vec(0usize..30, 0..6),
    ) {
        on_counter(Chain::Zec, 75);
        prop_body(FWD, refund, maker_side, mi, ti, &outages);
    }

    #[test]
    fn zec_rev_prop_random_crash_points(
        refund in any::<bool>(),
        maker_side in any::<bool>(),
        mi in 0usize..MAKER_STATES.len(),
        ti in 0usize..TAKER_STATES.len(),
        outages in proptest::collection::vec(0usize..30, 0..6),
    ) {
        on_counter(Chain::Zec, 75);
        prop_body(REV, refund, maker_side, mi, ti, &outages);
    }
}

// ---- F3: new swaps lock with the size-checked V1 script; records written before it stay V0 ----

/// A swap accepted now is V1 on both legs, on both sides' records.
async fn new_swap_is_v1_body(dir: Direction) {
    let mut h = H::with(dir);
    h.run(Scn::Happy, None, &[]).await;
    assert_atomic(&h, Scn::Happy);
    let m = h.store.get_maker_swap(&h.maker_id).unwrap().unwrap();
    assert_eq!(m.taker_leg_htlc.script_version, ScriptVersion::V1);
    assert_eq!(m.maker_leg_htlc.unwrap().script_version, ScriptVersion::V1);
    let t = h.store.get_taker_swap(&h.taker_id).unwrap().unwrap();
    assert_eq!(t.taker_leg_htlc.unwrap().script_version, ScriptVersion::V1);
    assert_eq!(t.maker_leg_htlc.unwrap().script_version, ScriptVersion::V1);
    // The V1 script is on the wire the taker reads.
    let v = h.maker.view(&h.maker_id).unwrap().unwrap();
    assert_eq!(v.taker_leg.htlc.script_version, ScriptVersion::V1);
    assert_eq!(v.maker_leg.unwrap().htlc.script_version, ScriptVersion::V1);
}
both!(new_swap_is_v1, rev_new_swap_is_v1, new_swap_is_v1_body);

/// A taker that locks the V0 script (an old client building its own leg) for a new swap is
/// refused with no write, and the maker never funds its leg.
async fn maker_refuses_v0_taker_leg_body(dir: Direction) {
    let mut h = H::with(dir);
    h.accept(None).await;
    let before = h.store.get_maker_swap(&h.maker_id).unwrap().unwrap();
    assert_eq!(before.taker_leg_htlc.script_version, ScriptVersion::V1);
    let v0 = HtlcParams {
        script_version: ScriptVersion::V0,
        ..before.taker_leg_htlc
    };
    let f = h
        .t_tl()
        .build_funding(&v0, before.quote.taker_leg_amount())
        .await
        .unwrap();
    h.t_tl().broadcast(&f.tx).await.unwrap();
    h.mine_all(1);
    let err = h
        .maker
        .notify_lock(
            &h.maker_id,
            LockNotice {
                outpoint: f.outpoint,
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("V0"), "{err}");
    let after = h.store.get_maker_swap(&h.maker_id).unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&after).unwrap(),
        serde_json::to_value(&before).unwrap(),
        "refusal must not write"
    );
    for _ in 0..5 {
        h.maker.tick().await.unwrap();
        h.mine_all(1);
    }
    assert_eq!(h.m_ml().funding_calls(), 0);
}
both!(
    maker_refuses_v0_taker_leg,
    rev_maker_refuses_v0_taker_leg,
    maker_refuses_v0_taker_leg_body
);

/// Today's JSON (no `script_version`) is V0, and its script is rebuilt byte for byte from the
/// raw fixture fields, independently of `redeem_script`.
#[test]
fn old_records_are_v0_and_rebuild_byte_for_byte() {
    let raw: serde_json::Value = serde_json::from_str(MAKER_HAPPY).unwrap();
    let rec: MakerRecord = serde_json::from_str(MAKER_HAPPY).unwrap();
    for (key, got) in [
        ("btc_htlc", rec.taker_leg_htlc),
        ("divi_htlc", rec.maker_leg_htlc.unwrap()),
    ] {
        let j = &raw[key];
        assert!(
            j.get("script_version").is_none(),
            "{key}: fixture is not pre-F3"
        );
        assert_eq!(got.script_version, ScriptVersion::V0);
        // OP_IF OP_SHA256 <h> OP_EQUALVERIFY <claim> OP_ELSE <lt> CLTV OP_DROP <refund> OP_ENDIF CHECKSIG
        let lt = divi_swap::htlc::script_num(got.locktime as i64);
        let want = format!(
            "63a820{}8821{}67{:02x}{}b17521{}68ac",
            j["hash"].as_str().unwrap(),
            j["claim_pubkey"].as_str().unwrap(),
            lt.len(),
            hex::encode(&lt),
            j["refund_pubkey"].as_str().unwrap()
        );
        assert_eq!(hex::encode(got.redeem_script()), want, "{key}");
        assert_eq!(got.redeem_script(), got.redeem_script_v(ScriptVersion::V0));
        // And it re-serializes to exactly today's JSON.
        assert_eq!(&serde_json::to_value(got).unwrap(), j, "{key}");
    }
}

ltc_rev!(ltc_rev_new_swap_is_v1, new_swap_is_v1_body);
ltc_fwd!(ltc_fwd_new_swap_is_v1, new_swap_is_v1_body);
zec_fwd!(zec_fwd_new_swap_is_v1, new_swap_is_v1_body);
zec_rev!(zec_rev_new_swap_is_v1, new_swap_is_v1_body);
ltc_rev!(
    ltc_rev_maker_refuses_v0_taker_leg,
    maker_refuses_v0_taker_leg_body
);
zec_fwd!(
    zec_fwd_maker_refuses_v0_taker_leg,
    maker_refuses_v0_taker_leg_body
);

// ---- F2: the maker re-sends a lock a reorg dropped, and stops early when it is too late ----

/// Drive the maker alone to `MakerLockConfirmed`; returns the maker lock's txid.
async fn to_maker_lock_confirmed(h: &mut H) -> Txid {
    h.accept(None).await;
    h.lock_and_notify(None).await;
    for _ in 0..30 {
        h.maker.tick().await.unwrap();
        h.mine_all(1);
        if h.maker_state() == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(h.maker_state(), SwapState::MakerLockConfirmed);
    h.maker_rec().maker_leg_funding.unwrap().tx.txid
}

impl H {
    fn maker_rec(&self) -> MakerRecord {
        self.store.get_maker_swap(&self.maker_id).unwrap().unwrap()
    }

    fn maker_leg_needed(&self) -> u32 {
        self.cfg.confirmations(self.dir.maker_chain())
    }

    async fn lock_confs(&self, lock: &Txid) -> Option<u32> {
        self.m_ml().confirmations(lock).await.unwrap()
    }

    /// Mine and tick the maker until the lock is `maker_leg_needed` deep again.
    async fn redeepen(&self, lock: &Txid) {
        for _ in 0..30 {
            self.ml_chain().mine(1);
            self.maker.tick().await.unwrap();
            if self
                .lock_confs(lock)
                .await
                .is_some_and(|c| c >= self.maker_leg_needed())
            {
                return;
            }
        }
        panic!("lock never got {} confirmations", self.maker_leg_needed());
    }
}

/// Lock confirmed → reorged back to the mempool: same bytes, no new coin selection, same
/// state; once mined deep again nothing else happens.
async fn reorged_lock_unconfirmed_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let before = h.maker_rec();
    let calls = h.m_ml().funding_calls();
    h.ml_chain().unconfirm(&lock);
    assert_eq!(h.lock_confs(&lock).await, Some(0));
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::MakerLockConfirmed);
    h.redeepen(&lock).await;
    let after = h.maker_rec();
    assert_eq!(
        after.maker_leg_funding, before.maker_leg_funding,
        "never re-signed"
    );
    assert_eq!(h.m_ml().funding_calls(), calls);
    assert_eq!(after.state, SwapState::MakerLockConfirmed);
    assert!(after.last_error.is_none() && !after.maker_lock_dropped);
}
both!(
    reorged_lock_unconfirmed,
    rev_reorged_lock_unconfirmed,
    reorged_lock_unconfirmed_body
);

/// Lock confirmed → dropped from chain and mempool (`confirmations` is `None`): one tick
/// re-sends the same signed bytes, mining confirms them. Fails on the base: nothing re-sends.
async fn reorged_lock_is_resent_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let funding = h.maker_rec().maker_leg_funding.unwrap();
    h.ml_chain().forget(&lock);
    assert_eq!(h.lock_confs(&lock).await, None);
    h.maker.tick().await.unwrap();
    assert_eq!(h.lock_confs(&lock).await, Some(0), "lock was not re-sent");
    assert_eq!(h.maker_state(), SwapState::MakerLockConfirmed);
    h.redeepen(&lock).await;
    assert_eq!(h.maker_rec().maker_leg_funding.unwrap(), funding);
}
both!(
    reorged_lock_is_resent,
    rev_reorged_lock_is_resent,
    reorged_lock_is_resent_body
);

/// The re-send is refused for good (inputs spent): one error, state unchanged, no retry loop.
async fn dropped_lock_rejected_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    h.ml_chain().forget(&lock);
    h.ml_chain().reject_next_broadcast();
    h.maker.tick().await.unwrap();
    let first = h.maker_rec();
    assert!(first.maker_lock_dropped);
    let msg = first.last_error.clone().unwrap();
    assert!(msg.contains("dropped by a reorg"), "{msg}");
    assert_eq!(first.state, SwapState::MakerLockConfirmed);
    for _ in 0..3 {
        h.maker.tick().await.unwrap();
        assert_eq!(
            h.maker_rec(),
            first,
            "the error is recorded once, not per tick"
        );
    }
    assert_eq!(h.lock_confs(&lock).await, None, "no further re-broadcast");
    assert_eq!(
        h.maker.view(&h.maker_id).unwrap().unwrap().last_error,
        Some(msg)
    );
}
both!(
    dropped_lock_rejected,
    rev_dropped_lock_rejected,
    dropped_lock_rejected_body
);

/// The taker's claim is already in the mempool when the lock is orphaned: the maker sees the
/// preimage first and does not re-send the lock.
async fn claim_in_mempool_wins_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    for _ in 0..40 {
        let view = h.maker.view(&h.maker_id).unwrap();
        h.taker.step(&h.taker_id, view.as_ref()).await.unwrap();
        if h.taker_state() == TakerState::Claimed {
            break;
        }
        h.mine_all(1);
    }
    assert_eq!(h.taker_state(), TakerState::Claimed);
    h.ml_chain().unconfirm(&lock);
    h.maker.tick().await.unwrap();
    let rec = h.maker_rec();
    assert!(rec.preimage.is_some());
    assert_ne!(rec.state, SwapState::MakerLockConfirmed);
    assert!(!rec.maker_lock_dropped);
}
both!(
    claim_in_mempool_wins,
    rev_claim_in_mempool_wins,
    claim_in_mempool_wins_body
);

/// Reorg near the locktime: a late lock cannot be claimed, so the maker stops waiting and
/// refunds as soon as the locktime allows.
async fn late_reorg_refunds_early_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let locktime = h.maker_rec().maker_leg_htlc.unwrap().locktime;
    h.ml_chain().unconfirm(&lock);
    let ml = h.ml_chain().clone();
    ml.advance_time(locktime - h.cfg.claim_margin_secs / 2 - ml.mtp());
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::MakerRefundable);
    ml.advance_time(h.cfg.claim_margin_secs);
    for _ in 0..30 {
        h.maker.tick().await.unwrap();
        ml.mine(1);
        if h.maker_state().is_terminal() {
            break;
        }
    }
    assert_eq!(h.maker_state(), SwapState::Done);
    assert!(h.maker_rec().maker_leg_refund.is_some());
}
both!(
    late_reorg_refunds_early,
    rev_late_reorg_refunds_early,
    late_reorg_refunds_early_body
);

/// A lock that is confirmed is never abandoned early, however close the locktime is.
async fn confirmed_lock_not_refunded_early_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    assert!(h.lock_confs(&lock).await.unwrap() >= h.maker_leg_needed());
    let locktime = h.maker_rec().maker_leg_htlc.unwrap().locktime;
    let ml = h.ml_chain().clone();
    ml.advance_time(locktime - 10 - ml.mtp());
    h.maker.tick().await.unwrap();
    let rec = h.maker_rec();
    assert_eq!(rec.state, SwapState::MakerLockConfirmed);
    assert!(rec.maker_leg_refund.is_none());
}
both!(
    confirmed_lock_not_refunded_early,
    rev_confirmed_lock_not_refunded_early,
    confirmed_lock_not_refunded_early_body
);

/// The lock is gone and never returns: at the locktime the maker is `MakerRefundable` and
/// reports a stable error, not a growing one.
async fn lost_lock_past_locktime_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let locktime = h.maker_rec().maker_leg_htlc.unwrap().locktime;
    h.ml_chain().forget(&lock);
    h.ml_chain().reject_next_broadcast();
    h.maker.tick().await.unwrap(); // lock dropped, flagged
    let ml = h.ml_chain().clone();
    ml.advance_time(locktime - ml.mtp());
    assert!(h.maker.tick().await.is_ok()); // tick records errors, never returns them
    let first = h.maker_rec();
    assert_eq!(first.state, SwapState::MakerRefundable);
    assert!(first.last_error.is_some());
    for _ in 0..3 {
        h.maker.tick().await.unwrap();
        let again = h.maker_rec();
        assert_eq!(again.state, SwapState::MakerRefundable);
        assert_eq!(again.last_error, first.last_error);
    }
}
both!(
    lost_lock_past_locktime,
    rev_lost_lock_past_locktime,
    lost_lock_past_locktime_body
);

/// Crash (restart) between the re-send and the next tick loses nothing.
async fn restart_after_resend_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    h.ml_chain().forget(&lock);
    h.maker.tick().await.unwrap();
    h.restart();
    h.redeepen(&lock).await;
    assert_eq!(h.maker_state(), SwapState::MakerLockConfirmed);
}
both!(
    restart_after_resend,
    rev_restart_after_resend,
    restart_after_resend_body
);

/// A record written before this change (no `maker_lock_dropped` key) loads unchanged and a
/// step leaves it alone.
async fn old_record_resumes_body(dir: Direction) {
    let mut h = H::with(dir);
    let _ = to_maker_lock_confirmed(&mut h).await;
    let rec = h.maker_rec();
    let mut json = serde_json::to_value(&rec).unwrap();
    assert!(json
        .as_object_mut()
        .unwrap()
        .remove("maker_lock_dropped")
        .is_none());
    let old: MakerRecord = serde_json::from_value(json).unwrap();
    assert_eq!(old, rec);
    h.store.put_maker_swap(&old).unwrap();
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_rec(), rec);
}
both!(
    old_record_resumes,
    rev_old_record_resumes,
    old_record_resumes_body
);

ltc_rev!(ltc_rev_reorged_lock_is_resent, reorged_lock_is_resent_body);
ltc_fwd!(ltc_fwd_reorged_lock_is_resent, reorged_lock_is_resent_body);
zec_fwd!(zec_fwd_reorged_lock_is_resent, reorged_lock_is_resent_body);
zec_rev!(zec_rev_reorged_lock_is_resent, reorged_lock_is_resent_body);
ltc_fwd!(
    ltc_fwd_late_reorg_refunds_early,
    late_reorg_refunds_early_body
);
zec_rev!(
    zec_rev_late_reorg_refunds_early,
    late_reorg_refunds_early_body
);

// ---- reorg follow-ups q3 / q4 (maker-rebroadcast-design.md §5) ----

/// q3: the re-send was refused (inputs spent) and the lock is flagged dropped. Once the node
/// sees the lock again (relayed by another node), the flag and error clear, so a second drop
/// is re-sent instead of staying stuck behind the stale flag. Fails on the base: the flag
/// only cleared at full depth, so a lock back in the mempool kept the stale error and a
/// later drop was never re-sent.
async fn dropped_flag_clears_when_lock_returns_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let funding = h.maker_rec().maker_leg_funding.unwrap();
    h.ml_chain().forget(&lock);
    h.ml_chain().reject_next_broadcast();
    h.maker.tick().await.unwrap();
    assert!(h.maker_rec().maker_lock_dropped);
    // Another node relays the lock: back in the mempool, below `maker_leg_confs`.
    h.m_ml().broadcast(&funding.tx).await.unwrap();
    assert_eq!(h.lock_confs(&lock).await, Some(0));
    h.maker.tick().await.unwrap();
    let rec = h.maker_rec();
    assert!(!rec.maker_lock_dropped, "stale dropped flag");
    assert!(rec.last_error.is_none(), "stale error");
    // Dropped again: re-sent this time.
    h.ml_chain().forget(&lock);
    h.maker.tick().await.unwrap();
    assert_eq!(h.lock_confs(&lock).await, Some(0), "lock was not re-sent");
    assert_eq!(h.maker_state(), SwapState::MakerLockConfirmed);
}
both!(
    dropped_flag_clears_when_lock_returns,
    rev_dropped_flag_clears_when_lock_returns,
    dropped_flag_clears_when_lock_returns_body
);

/// q4: a backend that cannot look the lock up (no txindex: `confirmations` and `htlc_output`
/// say `None`) but whose node still has it: the re-broadcast answers already-known, so the
/// watcher records nothing, flags nothing and changes no state. Pinned, not fixed.
async fn blind_node_is_not_a_dropped_lock_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let before = h.maker_rec();
    h.ml_chain().blind(&lock);
    assert_eq!(h.lock_confs(&lock).await, None);
    for _ in 0..3 {
        h.maker.tick().await.unwrap();
    }
    assert_eq!(h.maker_rec(), before);
    assert!(!h.maker_rec().maker_lock_dropped);
}
both!(
    blind_node_is_not_a_dropped_lock,
    rev_blind_node_is_not_a_dropped_lock,
    blind_node_is_not_a_dropped_lock_body
);

/// q3 tail: the lock is gone for good (inputs spent) and the locktime passes. The swap goes
/// to `MakerRefundable` and stays there, reporting an error each pass; it is never made
/// terminal, because "gone for good" cannot be told from "this node cannot see it" (q4).
async fn gone_lock_past_locktime_stays_refundable_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let locktime = h.maker_rec().maker_leg_htlc.unwrap().locktime;
    h.ml_chain().forget(&lock);
    h.ml_chain().reject_next_broadcast();
    h.maker.tick().await.unwrap();
    assert!(h.maker_rec().maker_lock_dropped);
    let ml = h.ml_chain().clone();
    ml.advance_time(locktime + 1 - ml.mtp());
    for _ in 0..4 {
        let _ = h.maker.tick().await;
        ml.mine(1);
        assert_eq!(h.maker_state(), SwapState::MakerRefundable);
    }
    assert!(!h.maker_state().is_terminal());
    assert!(
        h.maker_rec().maker_leg_refund.is_none(),
        "dead refund bytes kept"
    );
    assert_eq!(h.lock_confs(&lock).await, None);
}
both!(
    gone_lock_past_locktime_stays_refundable,
    rev_gone_lock_past_locktime_stays_refundable,
    gone_lock_past_locktime_stays_refundable_body
);

/// q4 follow-up: once the refund of a lock is refused and the node does not know the lock,
/// the engine asks the backend to release the lock's wallet booking (the phantom change coin
/// and the tombstoned inputs). Not before: a dropped lock inside its locktime is only re-sent.
async fn gone_lock_is_released_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let locktime = h.maker_rec().maker_leg_htlc.unwrap().locktime;
    h.ml_chain().forget(&lock);
    h.ml_chain().reject_next_broadcast();
    h.maker.tick().await.unwrap();
    assert!(h.maker_rec().maker_lock_dropped);
    assert!(
        h.m_ml().released_locks().is_empty(),
        "released while merely dropped"
    );
    let ml = h.ml_chain().clone();
    ml.advance_time(locktime + 1 - ml.mtp());
    for _ in 0..3 {
        let _ = h.maker.tick().await;
        ml.mine(1);
    }
    assert_eq!(h.maker_state(), SwapState::MakerRefundable);
    let released = h.m_ml().released_locks();
    assert!(!released.is_empty(), "phantom lock never released");
    assert!(released.iter().all(|t| *t == lock));
}
both!(
    gone_lock_is_released,
    rev_gone_lock_is_released,
    gone_lock_is_released_body
);

/// The counterpart: a lock the node merely cannot look up (no txindex) is still in the chain,
/// so the refund goes through and nothing is released.
async fn unseen_lock_is_not_released_body(dir: Direction) {
    let mut h = H::with(dir);
    let lock = to_maker_lock_confirmed(&mut h).await;
    let locktime = h.maker_rec().maker_leg_htlc.unwrap().locktime;
    h.ml_chain().blind(&lock);
    let ml = h.ml_chain().clone();
    ml.advance_time(locktime + 1 - ml.mtp());
    for _ in 0..4 {
        let _ = h.maker.tick().await;
        ml.mine(1);
    }
    assert!(
        h.m_ml().released_locks().is_empty(),
        "released a lock that is in the chain"
    );
}
both!(
    unseen_lock_is_not_released,
    rev_unseen_lock_is_not_released,
    unseen_lock_is_not_released_body
);
