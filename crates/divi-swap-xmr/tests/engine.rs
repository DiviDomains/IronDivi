// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The DIVI<->XMR adaptor swap, maker and taker engines in one process over the mock chains
//! (real DIVI transactions and script checks; Monero outputs opened only by `s·G = S`).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxOut};
use divi_swap::api::{Direction, Offer};
use divi_swap::{Chain, Profile, Result, Store, SwapConfig};
use divi_swap_xmr::api::{JRoundReply, SigsRequest};
use divi_swap_xmr::chain::{DiviChain, MoneroChain, XmrOutput};
use divi_swap_xmr::jsig::{self, Primes};
use divi_swap_xmr::mock::{
    MockDiviChain, MockDiviWallet, MockMoneroChain, MockMoneroWallet, MOCK_DIVI_FEE, MOCK_XMR_FEE,
};
use divi_swap_xmr::taker::JNext;
use divi_swap_xmr::{
    XmrConfig, XmrMaker, XmrMakerState, XmrTaker, XmrTakerState, PICONERO_PER_COUNTER_SAT,
};
use swap_chain_xmr::lock_scripts;
use tokio::sync::Notify;

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

/// Paillier primes for the 2P-ECDSA sessions (one set per side), generated once per machine
/// and cached in the temp dir: each set takes up to a minute and a half.
fn primes() -> &'static (Primes, Primes) {
    static P: OnceLock<(Primes, Primes)> = OnceLock::new();
    P.get_or_init(|| {
        let path = std::env::temp_dir().join("divi-swap-xmr-test-primes.json");
        if let Some(p) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            return p;
        }
        let p = std::thread::scope(|s| {
            let a = s.spawn(jsig::generate_primes);
            let b = s.spawn(jsig::generate_primes);
            (a.join().unwrap(), b.join().unwrap())
        });
        let tmp = path.with_extension(format!("{}", std::process::id()));
        if std::fs::write(&tmp, serde_json::to_vec(&p).unwrap()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
        p
    })
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
        .with_clock(Arc::new(move || c.load(Ordering::SeqCst)))
        .with_primes(Arc::new(|| primes().1.clone()));
        let taker = XmrTaker::new(
            cfg(),
            Arc::new(td.clone()),
            Arc::new(tx.clone()),
            store.clone(),
        )
        .unwrap()
        .with_primes(Arc::new(|| primes().0.clone()));
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

    /// Quote → setup → the `J` exchanges (each maker reply passed through `tamper` on its way
    /// to the taker) → the taker's signatures. Returns (maker id, taker id, sigs), or the
    /// first error with the maker id it happened on.
    async fn key(
        &self,
        tamper: &mut dyn FnMut(&mut JRoundReply),
    ) -> std::result::Result<(String, String, SigsRequest), (String, String)> {
        let q = self
            .maker
            .quote("divi-xmr-stagenet", XMR_UNITS)
            .await
            .unwrap();
        let (tid, req) = self.taker.prepare(&q).await.unwrap();
        let mut reply = self.maker.setup(req).await.unwrap();
        let mid = reply.swap_id.clone();
        for _ in 0..64 {
            tamper(&mut reply);
            match self.taker.j_step(&tid, reply).await {
                Ok(JNext::Sigs(sigs)) => return Ok((mid, tid, sigs)),
                Ok(JNext::Send(r)) => {
                    reply = self
                        .maker
                        .j_round(&mid, r)
                        .await
                        .map_err(|e| (mid.clone(), e.to_string()))?
                }
                Err(e) => return Err((mid, e.to_string())),
            }
        }
        panic!("2P-ECDSA did not finish in 64 exchanges");
    }

    /// Keying, then sigs (Tx_lock goes out). Returns (maker id, taker id).
    async fn open(&self) -> (String, String) {
        let (mid, tid, sigs) = self.key(&mut |_| {}).await.unwrap();
        let v = self.maker.sigs(&mid, sigs).await.unwrap();
        assert_eq!(v.state, XmrMakerState::Locked);
        assert_eq!(self.taker_rec(&tid).state, XmrTakerState::Accepted);
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
    // The operator's view carries both deadlines (runbook: check t_punish first).
    let v = w.maker.view(&mid).unwrap().unwrap();
    let (tc, tp) = (v.t_cancel.unwrap(), v.t_punish.unwrap());
    assert!(tc > 0);
    assert_eq!(tp - tc, cfg().punish_after_secs);
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

    // A setup whose Tx_cancel pays the maker instead of the cancel script: the taker refuses
    // it before signing anything under J.
    let pay_maker = w.maker_divi.script();
    let (_, err) = w
        .key(&mut |r| {
            if let Some(s) = r.setup.as_mut() {
                s.tx_cancel.vout[0].script_pubkey = pay_maker.clone();
            }
        })
        .await
        .expect_err("refused");
    assert!(err.contains("Tx_cancel"), "{err}");

    // A setup claiming a J other than the one computed together (a key the maker alone holds,
    // say) is refused: the taker signs nothing.
    let (mid, err) = w
        .key(&mut |r| {
            if let Some(s) = r.setup.as_mut() {
                s.joint_pubkey = s.maker_divi_pubkey;
            }
        })
        .await
        .expect_err("refused");
    assert!(err.contains("J is not"), "{err}");

    // A corrupted 2P-ECDSA message fails the session (and nothing is signed).
    let mut hit = false;
    let (_, err) = w
        .key(&mut |r| {
            if !hit && !r.msgs.is_empty() {
                hit = true;
                for m in &mut r.msgs {
                    m.body = serde_json::json!({ "garbage": true });
                }
            }
        })
        .await
        .expect_err("refused");
    assert!(!err.is_empty());

    // Bad taker signatures are refused by the maker, and nothing is broadcast.
    let (mid3, _, sigs) = w.key(&mut |_| {}).await.unwrap();
    let lock_txid = w.maker.record(&mid3).unwrap().unwrap().tx_lock.txid();
    let mut bad = sigs.clone();
    let i = bad.cancel_sig.len() / 2;
    bad.cancel_sig[i] ^= 1;
    assert!(w.maker.sigs(&mid3, bad).await.is_err());
    let mut bad = sigs.clone();
    bad.refund_encsigs.pop();
    assert!(w.maker.sigs(&mid3, bad).await.is_err());
    let mut bad = sigs.clone();
    let (a, b) = (
        bad.refund_encsigs[0].encsig.clone(),
        bad.refund_encsigs[1].encsig.clone(),
    );
    bad.refund_encsigs[0].encsig = b;
    bad.refund_encsigs[1].encsig = a;
    assert!(w.maker.sigs(&mid3, bad).await.is_err());
    assert_eq!(w.maker_state(&mid3), XmrMakerState::Accepted);
    assert!(w.divi.tx(&lock_txid).is_none(), "Tx_lock never broadcast");

    // An accepted swap whose signatures never come is forgotten (nothing locked).
    w.clock
        .fetch_add(cfg().sigs_wait_secs + 1, Ordering::SeqCst);
    w.maker.tick().await.unwrap();
    assert_eq!(w.maker_state(&mid), XmrMakerState::Aborted);
    assert_eq!(w.maker_state(&mid3), XmrMakerState::Aborted);
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

/// C1: `Tx_lock`'s cancel branch takes only `σ_J`, and `σ_J` exists once, so the lock has
/// exactly one cancel transaction. Its txid still depends on how `σ_J` is encoded (anyone may
/// re-encode it: flip `s`, re-push it); whichever of the 120 encodings is mined, the maker
/// can refund with the taker's adaptor signature for it, and that refund hands her `s_m`.
#[tokio::test]
async fn a_re_encoded_tx_cancel_still_refunds_and_reveals_s_m() {
    let w = W::new();
    let (mid, tid) = w.open().await;
    for _ in 0..30 {
        w.round(&mid, &tid, true, true).await;
        if w.taker_rec(&tid).state == XmrTakerState::XmrLocked {
            break;
        }
    }
    assert_eq!(w.taker_rec(&tid).state, XmrTakerState::XmrLocked);
    let r = w.maker.record(&mid).unwrap().unwrap();
    let canonical = r.cancel_signed.clone().unwrap();
    let variants = lock_scripts::cancel_variants(&r.tx_cancel, &r.cancel_sig, &r.redeem_script);
    assert_eq!(variants.len(), lock_scripts::CANCEL_VARIANTS);
    // A third party (a staker, say) mines an encoding neither side would broadcast.
    w.divi.advance_time(cfg().cancel_after_secs);
    let mut mined = None;
    for v in variants
        .iter()
        .rev()
        .filter(|v| v.txid() != canonical.txid())
    {
        if w.maker_divi.broadcast(v).await.is_ok() {
            mined = Some(v.txid());
            break;
        }
    }
    let mined = mined.expect("some other encoding of Tx_cancel is valid");
    w.mine(1);
    for _ in 0..12 {
        w.round(&mid, &tid, true, true).await;
    }
    assert_eq!(w.maker_state(&mid), XmrMakerState::Done);
    let t = w.taker_rec(&tid);
    assert_eq!(
        (t.state, t.outcome.as_deref()),
        (XmrTakerState::Done, Some("refunded")),
        "{:?}",
        t.last_error
    );
    assert_eq!(
        t.cancel_actual.as_ref().map(|c| c.txid()),
        Some(mined),
        "the refund spent the re-encoded Tx_cancel"
    );
    assert_eq!(w.taker_xmr.balance(), TAKER_XMR - 2 * MOCK_XMR_FEE);
}

/// A Monero wallet whose next `find_lock` parks until released: a monerod scan that hangs.
struct StallingScan {
    inner: MockMoneroWallet,
    armed: AtomicBool,
    parked: Notify,
    release: Notify,
}

#[async_trait]
impl MoneroChain for StallingScan {
    async fn lock(&self, spend_pub: &[u8; 32], view: &[u8; 32], amount: u64) -> Result<String> {
        self.inner.lock(spend_pub, view, amount).await
    }

    async fn find_lock(&self, spend: &[u8; 32], view: &[u8; 32]) -> Result<Option<XmrOutput>> {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.parked.notify_one();
            self.release.notified().await;
        }
        self.inner.find_lock(spend, view).await
    }

    async fn sweep(&self, lock: &XmrOutput, spend: &[u8; 32], view: &[u8; 32]) -> Result<String> {
        self.inner.sweep(lock, spend, view).await
    }

    async fn confirmations(&self, txid: &str) -> Result<Option<u32>> {
        self.inner.confirmations(txid).await
    }
}

/// Swaps step independently: while one swap's step is stuck in a Monero scan, another
/// swap's step runs to completion (under the old engine-wide gate it waited).
#[tokio::test]
async fn a_stuck_scan_does_not_hold_up_other_swaps() {
    let w = W::new();
    let (ma, ta) = w.open().await;
    w.mine(1);
    let (mb, tb) = w.open().await;
    let mut notices = (None, None);
    for _ in 0..40 {
        let _ = w.maker.tick().await;
        for (mid, tid, n) in [(&ma, &ta, &mut notices.0), (&mb, &tb, &mut notices.1)] {
            let v = w.maker.view(mid).unwrap();
            let _ = w.taker.step(tid, v.as_ref()).await;
            *n = w.taker.lock_notice(tid).unwrap();
        }
        if notices.0.is_some() && notices.1.is_some() {
            break;
        }
        w.mine(1);
    }
    w.mine(10);
    w.maker.xmr_locked(&ma, notices.0.unwrap()).await.unwrap();
    w.maker.xmr_locked(&mb, notices.1.unwrap()).await.unwrap();

    // A second maker engine over the same database, whose Monero scans can be stalled.
    let scan = Arc::new(StallingScan {
        inner: w.maker_xmr.clone(),
        armed: AtomicBool::new(true),
        parked: Notify::new(),
        release: Notify::new(),
    });
    let c = w.clock.clone();
    let maker = XmrMaker::new(
        cfg(),
        Arc::new(w.maker_divi.clone()),
        scan.clone(),
        w.store.clone(),
        vec![offer()],
    )
    .unwrap()
    .with_clock(Arc::new(move || c.load(Ordering::SeqCst)));

    let other = async {
        scan.parked.notified().await; // swap A is now inside its scan
        let b = tokio::time::timeout(Duration::from_secs(5), maker.step(&mb))
            .await
            .expect("swap B waited on swap A's scan");
        scan.release.notify_one();
        b
    };
    let (a, b) = tokio::join!(maker.step(&ma), other);
    assert_eq!(a.unwrap(), XmrMakerState::RedeemOffered);
    assert_eq!(b.unwrap(), XmrMakerState::RedeemOffered);
}

/// A DIVI node that has not seen one transaction (a lost broadcast) and counts scans for
/// the spender of one outpoint.
struct Forgetful {
    inner: MockDiviWallet,
    unseen: Hash256,
    watched: OutPoint,
    scans: AtomicU64,
}

#[async_trait]
impl DiviChain for Forgetful {
    fn payout_script(&self) -> Script {
        self.inner.payout_script()
    }

    async fn tip_height(&self) -> Result<u64> {
        self.inner.tip_height().await
    }

    async fn median_time_past(&self) -> Result<u32> {
        self.inner.median_time_past().await
    }

    async fn build_funding(&self, script_pubkey: &Script, amount: u64) -> Result<Transaction> {
        self.inner.build_funding(script_pubkey, amount).await
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.inner.broadcast(tx).await
    }

    async fn confirmations(&self, txid: &Hash256) -> Result<Option<u32>> {
        if *txid == self.unseen {
            return Ok(None);
        }
        self.inner.confirmations(txid).await
    }

    async fn output(&self, at: &OutPoint) -> Result<Option<(TxOut, u32)>> {
        if at.txid == self.unseen {
            return Ok(None);
        }
        self.inner.output(at).await
    }

    async fn find_spend(&self, at: &OutPoint) -> Result<Option<Transaction>> {
        if *at == self.watched {
            self.scans.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.find_spend(at).await
    }
}

/// A `Tx_lock` the node does not know is simply broadcast again: the maker does not first
/// scan the chain for who spent its funding coin (on a remote node, a scan from an old
/// coin's height took longer than the whole swap).
#[tokio::test]
async fn an_unseen_tx_lock_is_rebroadcast_without_a_scan() {
    let w = W::new();
    let (mid, _tid) = w.open().await;
    let r = w.maker.record(&mid).unwrap().unwrap();
    let divi = Arc::new(Forgetful {
        inner: w.maker_divi.clone(),
        unseen: r.tx_lock.txid(),
        watched: r.tx_lock.vin[0].prevout,
        scans: AtomicU64::new(0),
    });
    let c = w.clock.clone();
    let maker = XmrMaker::new(
        cfg(),
        divi.clone(),
        Arc::new(w.maker_xmr.clone()),
        w.store.clone(),
        vec![offer()],
    )
    .unwrap()
    .with_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    assert_eq!(maker.step(&mid).await.unwrap(), XmrMakerState::Locked);
    assert_eq!(divi.scans.load(Ordering::SeqCst), 0);
    assert!(maker.record(&mid).unwrap().unwrap().lock_actual.is_none());
}

/// A taker whose HTTP reply was lost retries the same `J` request: the maker answers it
/// again, byte for byte, instead of feeding a one-shot session twice (which would abort the
/// swap, and after `σ_J` would leave the taker without the maker's last message). A taker
/// speaking another `J` scheme is refused at setup.
#[tokio::test]
async fn a_retried_j_round_gets_the_same_reply() {
    let w = W::new();
    let q = w.maker.quote("divi-xmr-stagenet", XMR_UNITS).await.unwrap();
    let (_, mut old) = w.taker.prepare(&q).await.unwrap();
    old.j_scheme = String::new();
    assert!(w
        .maker
        .setup(old)
        .await
        .unwrap_err()
        .to_string()
        .contains("scheme"));

    let q = w.maker.quote("divi-xmr-stagenet", XMR_UNITS).await.unwrap();
    let (tid, req) = w.taker.prepare(&q).await.unwrap();
    let mut reply = w.maker.setup(req).await.unwrap();
    let mid = reply.swap_id.clone();
    let mut retried = 0;
    let sigs = loop {
        match w.taker.j_step(&tid, reply).await.unwrap() {
            JNext::Sigs(sigs) => break sigs,
            JNext::Send(r) => {
                let first = w.maker.j_round(&mid, r.clone()).await.unwrap();
                let again = w.maker.j_round(&mid, r).await.unwrap();
                assert_eq!(
                    serde_json::to_string(&first).unwrap(),
                    serde_json::to_string(&again).unwrap()
                );
                retried += 1;
                reply = again;
            }
        }
    };
    assert!(retried >= 3);
    let v = w.maker.sigs(&mid, sigs).await.unwrap();
    assert_eq!(v.state, XmrMakerState::Locked);
}
