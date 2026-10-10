// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Maker + taker engines against two mock chains: the acceptance scenarios of the swap POC.

use async_trait::async_trait;
use divi_swap::api::{AcceptRequest, LockNotice, Offer, Quote};
use divi_swap::mock::{MockBackend, MockChain};
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

fn offer() -> Offer {
    Offer {
        id: "o1".into(),
        direction: divi_swap::api::Direction::TakerPaysBtc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 10_000,
        max_btc_sats: 5_000_000,
    }
}

struct H {
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
        vec![offer()],
    )
    .unwrap()
    .with_clock(Arc::new(move || clock.load(Ordering::SeqCst)))
}

impl H {
    fn new() -> H {
        let btc = MockChain::new(Chain::Btc, T0, 600);
        let divi = MockChain::new(Chain::Divi, T0, 60);
        let mdivi = divi.backend(1, Amount(MAKER_DIVI_FUNDS));
        let mbtc = btc.backend(2, Amount(0));
        let tdivi = divi.backend(3, Amount(0));
        let tbtc = btc.backend(4, Amount(TAKER_BTC_FUNDS));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swap.db");
        let store = Store::open(&path).unwrap();
        let cfg = SwapConfig::profile(Profile::Testnet);
        let clock = Arc::new(AtomicU64::new(T0 as u64));
        let mut h = H {
            btc,
            divi,
            mdivi,
            mbtc,
            tdivi,
            tbtc,
            cfg,
            clock,
            path,
            _dir: dir,
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
            self.btc.advance_time(22_000);
            self.divi.advance_time(12_000);
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

    fn maker_btc(&self) -> u64 {
        self.btc.balance(&self.mbtc.pubkey()).0
    }
    fn taker_divi(&self) -> u64 {
        self.divi.balance(&self.tdivi.pubkey()).0
    }
}

/// A backend that only exists to fill struct slots before the real ones are built.
fn divi_swap_placeholder() -> MockBackend {
    MockChain::new(Chain::Divi, T0, 60).backend(9, Amount(0))
}

fn assert_atomic(h: &H, scn: Scn) {
    match scn {
        Scn::Happy => {
            assert!(h.taker_divi() > 0, "taker got no DIVI");
            assert!(h.maker_btc() > 0, "maker got no BTC");
            assert_eq!(h.maker_state(), SwapState::Done);
        }
        Scn::Refund => {
            assert_eq!(h.taker_divi(), 0, "taker got DIVI in a refund swap");
            assert_eq!(h.maker_btc(), 0, "maker got BTC in a refund swap");
            // Both refunded: each side is down only fees.
            assert!(h.divi.balance(&h.mdivi.pubkey()).0 >= MAKER_DIVI_FUNDS - 10_000);
            assert!(h.btc.balance(&h.tbtc.pubkey()).0 >= TAKER_BTC_FUNDS - 10_000);
        }
    }
}

#[tokio::test]
async fn happy_path() {
    let mut h = H::new();
    h.run(Scn::Happy, None, &[]).await;
    assert_atomic(&h, Scn::Happy);
    assert_eq!(h.taker_divi(), 500_000_000 - 1_000);
    assert_eq!(h.maker_btc(), BTC_SATS - 1_000);
    let v = h.maker.view(&h.maker_id).unwrap().unwrap();
    assert!(v.preimage.is_some());
    assert_eq!(h.mdivi.funding_calls(), 1);
}

#[tokio::test]
async fn case_a_taker_never_locks() {
    let mut h = H::new();
    h.accept(None).await;
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::Accepted);
    h.clock.fetch_add(2_000, Ordering::SeqCst);
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_eq!(h.mdivi.funding_calls(), 0);
    assert_eq!(h.divi.balance(&h.mdivi.pubkey()).0, MAKER_DIVI_FUNDS);
}

#[tokio::test]
async fn case_b_taker_lock_invalid() {
    // Wrong amount.
    let mut h = H::new();
    h.accept(None).await;
    let view = h.maker.view(&h.maker_id).unwrap().unwrap();
    let f = h
        .tbtc
        .build_funding(&view.taker_leg.htlc, Amount(BTC_SATS - 1))
        .await
        .unwrap();
    h.tbtc.broadcast(&f.tx).await.unwrap();
    h.maker
        .notify_lock(
            &h.maker_id,
            LockNotice {
                outpoint: f.outpoint,
            },
        )
        .await
        .unwrap();
    for _ in 0..4 {
        h.btc.mine(1);
        h.maker.tick().await.unwrap();
    }
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_eq!(h.mdivi.funding_calls(), 0);

    // Wrong script (refund key differs from the one in the accepted HTLC).
    let mut h = H::new();
    h.accept(None).await;
    let view = h.maker.view(&h.maker_id).unwrap().unwrap();
    let mut wrong = view.taker_leg.htlc;
    wrong.refund_pubkey = [0x02; 33];
    let f = h
        .tbtc
        .build_funding(&wrong, Amount(BTC_SATS))
        .await
        .unwrap();
    h.tbtc.broadcast(&f.tx).await.unwrap();
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
    for _ in 0..4 {
        h.btc.mine(1);
        h.maker.tick().await.unwrap();
    }
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_eq!(h.mdivi.funding_calls(), 0);
}

#[tokio::test]
async fn case_c_taker_never_claims() {
    let mut h = H::new();
    h.run(Scn::Refund, None, &[]).await;
    assert_atomic(&h, Scn::Refund);
    assert_eq!(h.maker_state(), SwapState::Done);
    assert_eq!(h.taker_state(), TakerState::Done);
}

#[tokio::test]
async fn case_d_late_claim() {
    let mut h = H::new();
    h.accept(None).await;
    h.lock_and_notify(None).await;
    // Drive the maker alone until its DIVI lock is confirmed.
    for _ in 0..10 {
        h.maker.tick().await.unwrap();
        h.btc.mine(1);
        h.divi.mine(1);
        if h.maker_state() == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(h.maker_state(), SwapState::MakerLockConfirmed);
    let rec = h.store.get_maker_swap(&h.maker_id).unwrap().unwrap();
    let locktime = rec.divi_htlc.unwrap().locktime;
    // Move to just inside the taker's claim window (locktime − safety margin).
    let now = h.divi.mtp();
    let target = locktime - divi_swap::taker::TAKER_SAFETY_MARGIN_SECS - 30;
    h.divi.advance_time(target - now);
    let view = h.maker.view(&h.maker_id).unwrap();
    h.taker.step(&h.taker_id, view.as_ref()).await.unwrap();
    assert_eq!(h.taker_state(), TakerState::Claimed);
    // The maker only wakes up after its own refund time has passed.
    h.divi.advance_time(locktime - h.divi.mtp() + 10);
    for _ in 0..12 {
        let _ = h.maker.tick().await;
        let view = h.maker.view(&h.maker_id).unwrap();
        let _ = h.taker.step(&h.taker_id, view.as_ref()).await;
        h.btc.mine(1);
        h.divi.mine(1);
        if h.finished() {
            break;
        }
    }
    assert!(h.finished());
    assert_atomic(&h, Scn::Happy);
}

#[tokio::test]
async fn crash_at_every_maker_state() {
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
        let mut h = H::new();
        h.run(scn, Some(Crash::Maker(state)), &[]).await;
        assert_eq!(h.restarts, 1, "crash at {state:?} never triggered");
        assert_atomic(&h, scn);
    }
}

#[tokio::test]
async fn crash_at_every_taker_state() {
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
        let mut h = H::new();
        h.run(scn, Some(Crash::Taker(state)), &[]).await;
        assert_eq!(h.restarts, 1, "crash at {state:?} never triggered");
        assert_atomic(&h, scn);
    }
}

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
        let scn = if refund { Scn::Refund } else { Scn::Happy };
        let crash = if maker_side {
            Crash::Maker(MAKER_STATES[mi])
        } else {
            Crash::Taker(TAKER_STATES[ti])
        };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let mut h = H::new();
            h.run(scn, Some(crash), &outages).await;
            // Whatever the crash, the swap is atomic: both legs complete or both refund.
            // (A crash state the scenario never visits simply never triggers.)
            assert_atomic(&h, scn);
        });
    }
}

#[tokio::test]
async fn no_coin_selection_before_taker_lock_confirmed() {
    let mut h = H::new();
    h.maker.halt_after(Some(SwapState::TakerLockConfirmed));
    h.accept(None).await;
    assert_eq!(h.mdivi.funding_calls(), 0, "after accept");
    h.lock_and_notify(None).await;
    assert_eq!(h.mdivi.funding_calls(), 0, "TakerLockSeen (unconfirmed)");
    assert_eq!(h.maker_state(), SwapState::TakerLockSeen);
    h.btc.mine(1);
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::TakerLockConfirmed);
    assert_eq!(h.mdivi.funding_calls(), 0, "at TakerLockConfirmed");
    h.maker.halt_after(None);
    h.maker.tick().await.unwrap();
    assert_eq!(h.mdivi.funding_calls(), 1, "on the edge to MakerLocked");
    assert_eq!(h.maker_state(), SwapState::MakerLocked);
}

#[tokio::test]
async fn timeout_invariant_enforced() {
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

    // The BTC window shrinking below what the maker needs aborts before any DIVI is locked.
    let mut h = H::new();
    h.accept(None).await;
    h.lock_and_notify(None).await;
    assert_eq!(h.maker_state(), SwapState::TakerLockSeen);
    h.btc.advance_time(10_000); // 21_600 − 10_000 < maker_timeout + claim_margin
    h.maker.tick().await.unwrap();
    assert_eq!(h.maker_state(), SwapState::Aborted);
    assert_eq!(h.mdivi.funding_calls(), 0);
}

#[tokio::test]
async fn quote_expires() {
    let h = H::new();
    let q = h.quote().await;
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

/// Delegates to a mock backend but asserts every broadcast tx is already in the store.
struct Spy {
    inner: MockBackend,
    store: Store,
    checked: Arc<AtomicU64>,
}

impl Spy {
    fn persisted(&self, txid: &Txid) -> bool {
        let maker = self.store.list_maker_swaps().unwrap().into_iter().any(|m| {
            m.divi_funding.as_ref().is_some_and(|f| f.tx.txid == *txid)
                || m.divi_refund.as_ref().is_some_and(|t| t.txid == *txid)
                || m.btc_claim.as_ref().is_some_and(|t| t.txid == *txid)
        });
        let taker = self.store.list_taker_swaps().unwrap().into_iter().any(|t| {
            t.btc_funding.as_ref().is_some_and(|f| f.tx.txid == *txid)
                || t.divi_claim.as_ref().is_some_and(|c| c.txid == *txid)
                || t.btc_refund.as_ref().is_some_and(|r| r.txid == *txid)
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
    for scn in [Scn::Happy, Scn::Refund] {
        let h = H::new();
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
            vec![offer()],
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
                h.btc.advance_time(22_000);
                h.divi.advance_time(12_000);
                timed_out = true;
            }
            if scn == Scn::Happy || timed_out {
                let v = maker.view(&view.id).unwrap();
                let _ = taker.step(&tid, v.as_ref()).await;
            }
            h.btc.mine(1);
            h.divi.mine(1);
            let done = h.store.get_taker_swap(&tid).unwrap().unwrap().state == TakerState::Done;
            if done && st.is_terminal() {
                break;
            }
        }
        // happy: fund, fund, claim, claim; refund: fund, fund, refund, refund (at least).
        assert!(checked.load(Ordering::SeqCst) >= 4, "{scn:?}");
    }
}
