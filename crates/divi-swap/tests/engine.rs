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
use divi_swap::mock::{MockBackend, MockChain};
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

fn offer(dir: Direction) -> Offer {
    Offer {
        id: "o1".into(),
        direction: dir,
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

    fn rev() -> H {
        H::with(REV)
    }

    fn with(dir: Direction) -> H {
        let btc = MockChain::new(Chain::Btc, T0, 600);
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
            Chain::Btc => &self.btc,
            Chain::Divi => &self.divi,
        }
    }
    fn ml_chain(&self) -> &MockChain {
        match self.dir.maker_chain() {
            Chain::Btc => &self.btc,
            Chain::Divi => &self.divi,
        }
    }

    /// Maker's / taker's backend on the taker-leg chain and on the maker-leg chain.
    fn m_tl(&self) -> &MockBackend {
        match self.dir.taker_chain() {
            Chain::Btc => &self.mbtc,
            Chain::Divi => &self.mdivi,
        }
    }
    fn m_ml(&self) -> &MockBackend {
        match self.dir.maker_chain() {
            Chain::Btc => &self.mbtc,
            Chain::Divi => &self.mdivi,
        }
    }
    fn t_tl(&self) -> &MockBackend {
        match self.dir.taker_chain() {
            Chain::Btc => &self.tbtc,
            Chain::Divi => &self.tdivi,
        }
    }
    fn t_ml(&self) -> &MockBackend {
        match self.dir.maker_chain() {
            Chain::Btc => &self.tbtc,
            Chain::Divi => &self.tdivi,
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
        Chain::Btc => BTC_SATS,
        Chain::Divi => 500_000_000,
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
    // Drive the maker alone until its lock is confirmed.
    for _ in 0..12 {
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
