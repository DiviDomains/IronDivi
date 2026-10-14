// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The DIVI<->XMR adaptor swap, maker and taker engines in one process over the mock chains
//! (real DIVI transactions and script checks; Monero outputs opened only by `s·G = S`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use divi_swap::api::{Direction, Offer};
use divi_swap::{Chain, Profile, Store, SwapConfig};
use divi_swap_xmr::mock::{
    MockDiviChain, MockDiviWallet, MockMoneroChain, MockMoneroWallet, MOCK_DIVI_FEE, MOCK_XMR_FEE,
};
use divi_swap_xmr::{
    XmrConfig, XmrMaker, XmrMakerState, XmrTaker, XmrTakerState, PICONERO_PER_COUNTER_SAT,
};

const T0: u32 = 1_800_000_000;
const XMR_UNITS: u64 = 1_000_000; // 0.01 XMR in 1e-8 units
const MAKER_DIVI: u64 = 100_000_000_000;
const TAKER_XMR: u64 = 1_000_000_000_000; // 1 XMR

fn offer() -> Offer {
    Offer {
        id: "divi-xmr-stagenet".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Xmr,
        divi_sats_per_btc: 5_000 * 100_000_000, // 5,000 DIVI per XMR
        min_btc_sats: 100_000,
        max_btc_sats: 100_000_000,
    }
}

fn cfg() -> XmrConfig {
    XmrConfig {
        xmr_confirmations: 3,
        divi_fee_sats: 10_000,
        ..XmrConfig::testnet()
    }
}

struct W {
    divi: MockDiviChain,
    xmr: MockMoneroChain,
    maker_divi: MockDiviWallet,
    taker_divi: MockDiviWallet,
    maker_xmr: MockMoneroWallet,
    taker_xmr: MockMoneroWallet,
    store: Store,
    clock: Arc<AtomicU64>,
    maker: XmrMaker,
    taker: XmrTaker,
}

impl W {
    fn new() -> W {
        let divi = MockDiviChain::new(T0, 60);
        let xmr = MockMoneroChain::new();
        let maker_divi = divi.wallet(1);
        let taker_divi = divi.wallet(2);
        maker_divi.fund(MAKER_DIVI);
        let maker_xmr = xmr.wallet("maker", 0);
        let taker_xmr = xmr.wallet("taker", TAKER_XMR);
        let store = Store::in_memory().unwrap();
        let clock = Arc::new(AtomicU64::new(T0 as u64));
        let (maker, taker) = Self::engines(
            &maker_divi,
            &taker_divi,
            &maker_xmr,
            &taker_xmr,
            &store,
            &clock,
        );
        W {
            divi,
            xmr,
            maker_divi,
            taker_divi,
            maker_xmr,
            taker_xmr,
            store,
            clock,
            maker,
            taker,
        }
    }

    fn engines(
        md: &MockDiviWallet,
        td: &MockDiviWallet,
        mx: &MockMoneroWallet,
        tx: &MockMoneroWallet,
        store: &Store,
        clock: &Arc<AtomicU64>,
    ) -> (XmrMaker, XmrTaker) {
        let c = clock.clone();
        let maker = XmrMaker::new(
            cfg(),
            Arc::new(md.clone()),
            Arc::new(mx.clone()),
            store.clone(),
            vec![offer()],
        )
        .unwrap()
        .with_clock(Arc::new(move || c.load(Ordering::SeqCst)));
        let taker = XmrTaker::new(
            cfg(),
            Arc::new(td.clone()),
            Arc::new(tx.clone()),
            store.clone(),
        )
        .unwrap();
        (maker, taker)
    }

    /// Drop both engines and rebuild them over the same database, as after a crash.
    fn restart(&mut self) {
        let (m, t) = Self::engines(
            &self.maker_divi,
            &self.taker_divi,
            &self.maker_xmr,
            &self.taker_xmr,
            &self.store,
            &self.clock,
        );
        self.maker = m;
        self.taker = t;
    }

    fn mine(&self, n: u64) {
        self.divi.mine(n);
        self.xmr.mine(n);
    }

    /// Quote → setup → verify → sigs (Tx_lock goes out). Returns (maker id, taker id).
    async fn open(&self) -> (String, String) {
        let q = self
            .maker
            .quote("divi-xmr-stagenet", XMR_UNITS)
            .await
            .unwrap();
        let (tid, req) = self.taker.prepare(&q).await.unwrap();
        let reply = self.maker.setup(req).await.unwrap();
        let mid = reply.swap_id.clone();
        let sigs = self.taker.accepted(&tid, reply).await.unwrap();
        let v = self.maker.sigs(&mid, sigs).await.unwrap();
        assert_eq!(v.state, XmrMakerState::Locked);
        (mid, tid)
    }

    /// One round: maker tick, taker step on the maker's view, report any XMR lock, mine.
    async fn round(&self, mid: &str, tid: &str, taker_active: bool, maker_active: bool) {
        if maker_active {
            let _ = self.maker.tick().await;
        }
        if taker_active {
            let v = self.maker.view(mid).unwrap();
            let _ = self.taker.step(tid, v.as_ref()).await;
            if let Some(n) = self.taker.lock_notice(tid).unwrap() {
                if maker_active {
                    let _ = self.maker.xmr_locked(mid, n).await;
                }
            }
        }
        self.mine(1);
    }

    fn maker_state(&self, mid: &str) -> XmrMakerState {
        self.maker.view(mid).unwrap().unwrap().state
    }

    fn taker_rec(&self, tid: &str) -> divi_swap_xmr::taker::XmrTakerRecord {
        self.taker.record(tid).unwrap().unwrap()
    }

    fn quoted_divi(&self) -> u64 {
        offer().divi_for(XMR_UNITS).0
    }
}

#[tokio::test]
async fn happy_path_maker_gets_xmr_taker_gets_divi() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    for _ in 0..30 {
        w.round(&mid, &tid, true, true).await;
        if w.maker_state(&mid) == XmrMakerState::Done
            && w.taker_rec(&tid).state == XmrTakerState::Done
        {
            break;
        }
    }
    assert_eq!(w.maker_state(&mid), XmrMakerState::Done);
    let t = w.taker_rec(&tid);
    assert_eq!(t.state, XmrTakerState::Done);
    assert_eq!(t.outcome.as_deref(), Some("redeemed"));
    // The taker received exactly the quoted DIVI (Tx_lock = quote + redeem fee).
    assert_eq!(w.taker_divi.balance(), w.quoted_divi());
    // The maker swept the XMR: the quote less one Monero fee; the taker paid quote + fee.
    let xmr = XMR_UNITS * PICONERO_PER_COUNTER_SAT;
    assert_eq!(w.maker_xmr.balance(), xmr - MOCK_XMR_FEE);
    assert_eq!(w.taker_xmr.balance(), TAKER_XMR - xmr - MOCK_XMR_FEE);
    // The maker's DIVI went down by exactly the lock (quote + fee) plus the funding fee.
    assert_eq!(
        w.maker_divi.balance(),
        MAKER_DIVI - w.quoted_divi() - cfg().divi_fee_sats - MOCK_DIVI_FEE
    );
}

#[tokio::test]
async fn taker_walks_away_after_locking_xmr_both_refund() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    // The taker locks XMR (and reports it), then goes silent; the maker offers redeem.
    for _ in 0..30 {
        w.round(&mid, &tid, true, true).await;
        if w.taker_rec(&tid).state == XmrTakerState::XmrLocked {
            break;
        }
    }
    assert_eq!(w.taker_rec(&tid).state, XmrTakerState::XmrLocked);
    for _ in 0..10 {
        w.round(&mid, &tid, false, true).await;
    }
    assert_eq!(w.maker_state(&mid), XmrMakerState::RedeemOffered);
    assert!(w.taker_rec(&tid).xmr_txid.is_some(), "XMR is locked");
    // Past t_cancel the maker cancels and refunds (revealing s_m)...
    w.divi.advance_time(cfg().cancel_after_secs);
    for _ in 0..10 {
        w.round(&mid, &tid, false, true).await;
    }
    assert_eq!(w.maker_state(&mid), XmrMakerState::Done);
    // ...and the taker, back online, recovers s_m from Tx_refund and sweeps her XMR back.
    for _ in 0..10 {
        w.round(&mid, &tid, true, true).await;
    }
    let t = w.taker_rec(&tid);
    assert_eq!(
        (t.state, t.outcome.as_deref()),
        (XmrTakerState::Done, Some("refunded"))
    );
    assert!(t.s_m.is_some());
    assert_eq!(w.taker_xmr.balance(), TAKER_XMR - 2 * MOCK_XMR_FEE);
    assert_eq!(w.taker_divi.balance(), 0);
    assert_eq!(w.maker_xmr.balance(), 0);
    let fees = 2 * cfg().divi_fee_sats + MOCK_DIVI_FEE;
    assert_eq!(w.maker_divi.balance(), MAKER_DIVI - fees);
}

#[tokio::test]
async fn taker_never_locks_xmr_maker_refunds() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    for _ in 0..3 {
        w.round(&mid, &tid, false, true).await;
    }
    w.divi.advance_time(cfg().cancel_after_secs);
    for _ in 0..10 {
        w.round(&mid, &tid, false, true).await;
    }
    assert_eq!(w.maker_state(&mid), XmrMakerState::Done);
    assert_eq!(
        w.maker_divi.balance(),
        MAKER_DIVI - 2 * cfg().divi_fee_sats - MOCK_DIVI_FEE
    );
    for _ in 0..5 {
        w.round(&mid, &tid, true, true).await;
    }
    let t = w.taker_rec(&tid);
    assert_eq!(
        (t.state, t.outcome.as_deref()),
        (XmrTakerState::Done, Some("cancelled")),
        "{:?}",
        t.last_error
    );
    assert_eq!(w.taker_xmr.balance(), TAKER_XMR, "never locked anything");
}

#[tokio::test]
async fn maker_stalls_after_xmr_lock_taker_punishes() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    // The maker broadcasts Tx_lock, sees the XMR lock reported, then goes silent.
    for _ in 0..8 {
        w.round(&mid, &tid, true, true).await;
        if w.taker_rec(&tid).state == XmrTakerState::XmrLocked {
            break;
        }
    }
    assert_eq!(w.taker_rec(&tid).state, XmrTakerState::XmrLocked);
    w.divi.advance_time(cfg().cancel_after_secs);
    for _ in 0..3 {
        w.round(&mid, &tid, true, false).await;
    }
    assert_eq!(
        w.taker_rec(&tid).state,
        XmrTakerState::Cancelled,
        "{:?}",
        w.taker_rec(&tid).last_error
    );
    w.divi.advance_time(cfg().punish_after_secs);
    for _ in 0..5 {
        w.round(&mid, &tid, true, false).await;
    }
    let t = w.taker_rec(&tid);
    assert_eq!(
        (t.state, t.outcome.as_deref()),
        (XmrTakerState::Done, Some("punished")),
        "{:?}",
        t.last_error
    );
    // The taker took the cancelled DIVI (lock less two fees); her XMR stays locked.
    assert_eq!(
        w.taker_divi.balance(),
        w.quoted_divi() - cfg().divi_fee_sats
    );
    // The maker, waking up, sees the punish and stops.
    w.round(&mid, &tid, false, true).await;
    assert_eq!(w.maker_state(&mid), XmrMakerState::Punished);
}

#[tokio::test]
async fn crash_and_restart_at_every_round() {
    let mut w = W::new();
    let (mid, tid) = w.open().await;
    for _ in 0..40 {
        w.restart();
        w.round(&mid, &tid, true, true).await;
        if w.maker_state(&mid) == XmrMakerState::Done
            && w.taker_rec(&tid).state == XmrTakerState::Done
        {
            break;
        }
    }
    assert_eq!(w.maker_state(&mid), XmrMakerState::Done);
    assert_eq!(w.taker_rec(&tid).outcome.as_deref(), Some("redeemed"));
    assert_eq!(w.taker_divi.balance(), w.quoted_divi());
    let r = w.maker.record(&mid).unwrap().unwrap();
    let spend_pub = divi_swap_xmr::crypto::shared_spend_key(
        &divi_swap_xmr::crypto::ed_pub(&r.s_m),
        &r.taker_share,
    );
    assert_eq!(
        w.xmr.locks_to(&spend_pub),
        1,
        "exactly one XMR lock despite restarts"
    );
}

/// The XMR lock report returns at once: verifying it (a long `find_lock` scan on a real
/// monerod) is left to the next tick, so the taker's request cannot time out on it.
#[tokio::test]
async fn xmr_lock_report_does_not_step_inline() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    let mut notice = None;
    for _ in 0..40 {
        let _ = w.maker.tick().await;
        let v = w.maker.view(&mid).unwrap();
        let _ = w.taker.step(&tid, v.as_ref()).await;
        notice = w.taker.lock_notice(&tid).unwrap();
        if notice.is_some() {
            break;
        }
        w.mine(1);
    }
    let notice = notice.expect("taker never locked XMR");
    w.mine(10); // well past xmr_confirmations: an inline step would offer the redeem now
    let v = w.maker.xmr_locked(&mid, notice).await.unwrap();
    assert_eq!(v.state, XmrMakerState::XmrReported);
    w.maker.tick().await.unwrap();
    assert_eq!(w.maker_state(&mid), XmrMakerState::RedeemOffered);
}

#[tokio::test]
async fn no_redeem_signature_before_the_xmr_lock_confirms() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    for _ in 0..30 {
        w.round(&mid, &tid, true, true).await;
        let v = w.maker.view(&mid).unwrap().unwrap();
        let rec = w.taker_rec(&tid);
        if v.redeem.is_some() {
            // By the time it is offered, the XMR lock is there with enough confirmations.
            let spend = divi_swap_xmr::crypto::shared_spend_key(
                &rec.setup.as_ref().unwrap().maker_xmr_share,
                &divi_swap_xmr::crypto::ed_pub(&rec.s_t),
            );
            let view = rec.setup.as_ref().unwrap().xmr_view_secret;
            let lock = divi_swap_xmr::MoneroChain::find_lock(&w.maker_xmr, &spend, &view)
                .await
                .unwrap()
                .unwrap();
            assert!(lock.confirmations >= cfg().xmr_confirmations);
            return;
        }
        assert!(rec.state != XmrTakerState::Redeemed);
    }
    panic!("redeem never offered");
}

#[tokio::test]
async fn adversarial_inputs_are_refused() {
    let w = W::new();
    let q = w.maker.quote("divi-xmr-stagenet", XMR_UNITS).await.unwrap();

    // A DLEQ proof for different points.
    let (_, mut req) = w.taker.prepare(&q).await.unwrap();
    let (_, other) = w.taker.prepare(&q).await.unwrap();
    req.taker_xmr_share = other.taker_xmr_share;
    assert!(w
        .maker
        .setup(req)
        .await
        .unwrap_err()
        .to_string()
        .contains("DLEQ"));

    // A hashlock quote cannot open an xmr swap, nor an xmr quote a hashlock one.
    let mut btc_quote = q.clone();
    btc_quote.counter_chain = Chain::Btc;
    assert!(w.taker.prepare(&btc_quote).await.is_err());

    // A setup whose Tx_cancel pays the maker instead of the 2-of-2 is refused by the taker.
    let (tid, req) = w.taker.prepare(&q).await.unwrap();
    let mut reply = w.maker.setup(req).await.unwrap();
    reply.tx_cancel.vout[0].script_pubkey = w.maker_divi.script();
    let err = w.taker.accepted(&tid, reply).await.unwrap_err().to_string();
    assert!(err.contains("Tx_cancel"), "{err}");

    // A forged Tx_cancel signature is refused by the taker.
    let q2 = w.maker.quote("divi-xmr-stagenet", XMR_UNITS).await.unwrap();
    let (tid, req) = w.taker.prepare(&q2).await.unwrap();
    let mut reply = w.maker.setup(req).await.unwrap();
    let mid = reply.swap_id.clone();
    reply.maker_cancel_sig[10] ^= 1;
    assert!(w.taker.accepted(&tid, reply).await.is_err());

    // Bad taker signatures are refused by the maker, and nothing is broadcast.
    let q3 = w.maker.quote("divi-xmr-stagenet", XMR_UNITS).await.unwrap();
    let (tid, req) = w.taker.prepare(&q3).await.unwrap();
    let reply = w.maker.setup(req).await.unwrap();
    let mid3 = reply.swap_id.clone();
    let lock_txid = reply.lock_outpoint.txid.clone();
    let mut sigs = w.taker.accepted(&tid, reply).await.unwrap();
    sigs.taker_cancel_sig[10] ^= 1;
    assert!(w.maker.sigs(&mid3, sigs).await.is_err());
    assert_eq!(w.maker_state(&mid3), XmrMakerState::Accepted);
    let lock = divi_primitives::hash::Hash256::from_hex(&lock_txid).unwrap();
    assert!(w.divi.tx(&lock).is_none(), "Tx_lock never broadcast");

    // An accepted swap whose signatures never come is forgotten (nothing locked).
    w.clock
        .fetch_add(cfg().sigs_wait_secs + 1, Ordering::SeqCst);
    w.maker.tick().await.unwrap();
    assert_eq!(w.maker_state(&mid), XmrMakerState::Aborted);
    assert_eq!(w.maker_divi.balance(), MAKER_DIVI);
}

#[test]
fn offer_and_config_rules() {
    let divi = MockDiviChain::new(T0, 60);
    let xmr = MockMoneroChain::new();
    let mut o = offer();
    o.direction = Direction::TakerPaysDivi;
    assert!(XmrMaker::new(
        cfg(),
        Arc::new(divi.wallet(1)),
        Arc::new(xmr.wallet("m", 0)),
        Store::in_memory().unwrap(),
        vec![o]
    )
    .is_err());
    let mut bad = cfg();
    bad.redeem_margin_secs = bad.cancel_after_secs;
    assert!(bad.validate().is_err());
    XmrConfig::testnet().validate().unwrap();
    // The hashlock maker refuses xmr offers outright.
    let hl = divi_swap::Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(
            divi_swap::mock::MockChain::new(Chain::Divi, T0, 60).backend(1, divi_swap::Amount(1)),
        ),
        Arc::new(
            divi_swap::mock::MockChain::new(Chain::Btc, T0, 600).backend(2, divi_swap::Amount(1)),
        ),
        Store::in_memory().unwrap(),
        vec![offer()],
    );
    assert!(hl.is_err());
}

/// The taker locks no XMR until she holds a valid maker signature on `Tx_punish` (her
/// remedy if the maker stalls after she locks): a forged one is refused, a missing one waits.
#[tokio::test]
async fn no_xmr_lock_without_a_valid_punish_signature() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    w.mine(5); // Tx_lock deeply confirmed
    let mut view = w.maker.view(&mid).unwrap().unwrap();
    let good = view
        .maker_punish_sig
        .clone()
        .expect("published once locked");
    // Missing: idle.
    view.maker_punish_sig = None;
    assert_eq!(
        w.taker.step(&tid, Some(&view)).await.unwrap(),
        XmrTakerState::Accepted
    );
    // Forged: refused.
    let mut bytes = hex::decode(&good).unwrap();
    bytes[10] ^= 1;
    view.maker_punish_sig = Some(hex::encode(bytes));
    let err = w
        .taker
        .step(&tid, Some(&view))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Tx_punish"), "{err}");
    assert_eq!(w.taker_xmr.balance(), TAKER_XMR, "no XMR moved");
    // Genuine: she locks.
    view.maker_punish_sig = Some(good);
    w.taker.step(&tid, Some(&view)).await.unwrap();
    assert!(w.taker_rec(&tid).xmr_txid.is_some());
}
