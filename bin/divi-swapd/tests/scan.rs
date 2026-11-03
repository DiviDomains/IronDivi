// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Background wallet scan: health reporting, request gating, cursor resume.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use divi_swap::Store;
use divi_swapd::{follow_once, router, run_scan, AppState, ScanStatus, WalletScan};
use parking_lot::Mutex;
use serde_json::Value;

/// Scanner with a saved cursor, a fixed tip, and an optional number of initial failures.
struct Fake {
    cursor: Mutex<Option<u64>>,
    tip: Mutex<u64>,
    calls: Mutex<Vec<(u64, u64)>>,
    failures: Mutex<u32>,
}

impl Fake {
    fn new(cursor: Option<u64>, tip: u64) -> Self {
        Fake {
            cursor: Mutex::new(cursor),
            tip: Mutex::new(tip),
            calls: Mutex::new(vec![]),
            failures: Mutex::new(0),
        }
    }
}

impl WalletScan for Fake {
    fn scanned_height(&self) -> Option<u64> {
        *self.cursor.lock()
    }
    async fn tip(&self) -> Result<u64, String> {
        Ok(*self.tip.lock())
    }
    async fn scan_range(&self, from: u64, to: u64) -> Result<u64, String> {
        {
            let mut f = self.failures.lock();
            if *f > 0 {
                *f -= 1;
                return Err("rpc down".into());
            }
        }
        self.calls.lock().push((from, to));
        *self.cursor.lock() = Some(to + 1);
        Ok(to + 1)
    }
}

async fn serve_scanning(w: &World, scan: ScanStatus) -> (String, tokio::task::JoinHandle<()>) {
    let state = AppState {
        maker: w.maker(Store::in_memory().unwrap()),
        divi: Arc::new(w.maker_divi.clone()),
        btc: Arc::new(w.maker_btc.clone()),
        scan,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state, "/swap");
    let h = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/swap"), h)
}

async fn get_json(url: &str) -> (u16, Value) {
    let r = reqwest::get(url).await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

#[tokio::test]
async fn healthz_reports_scan_and_quote_is_503_until_done() {
    let w = World::new();
    let scan = ScanStatus::scanning();
    let (base, h) = serve_scanning(&w, scan.clone()).await;

    let (code, body) = get_json(&format!("{base}/healthz")).await;
    assert_eq!(code, 200);
    assert_eq!(body["ok"], false);
    assert_eq!(body["divi_scan"]["state"], "scanning");

    let quote = format!("{base}/offers/{OFFER_ID}/quote?btc_sats={BTC_SATS}");
    let (code, body) = get_json(&quote).await;
    assert_eq!(code, 503);
    assert_eq!(body["error"], "wallet scan in progress");

    // Progress is visible while the scan runs; finishing flips ok and lifts the gate.
    let fake = Fake::new(None, 1_000);
    run_scan(&fake, 0, &scan, 400, Duration::from_millis(1)).await;
    let (_, body) = get_json(&format!("{base}/healthz")).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["divi_scan"]["state"], "done");
    assert_eq!(body["divi_scan"]["next_height"], 1_001);
    assert_eq!(body["divi_scan"]["target_height"], 1_000);
    let (code, _) = get_json(&quote).await;
    assert_eq!(code, 200);
    h.abort();
}

#[tokio::test]
async fn failed_scan_is_reported_not_swallowed() {
    let w = World::new();
    let scan = ScanStatus::scanning();
    let (base, h) = serve_scanning(&w, scan.clone()).await;
    let fake = Arc::new(Fake::new(None, 10));
    *fake.failures.lock() = 1;
    let task = {
        let (fake, scan) = (fake.clone(), scan.clone());
        tokio::spawn(
            async move { run_scan(&*fake, 0, &scan, 100, Duration::from_secs(3600)).await },
        )
    };
    // Wait for the failure to surface.
    for _ in 0..200 {
        if scan.info().error.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (code, body) = get_json(&format!("{base}/healthz")).await;
    assert_eq!(code, 200);
    assert_eq!(body["ok"], false);
    assert_eq!(body["divi_scan"]["state"], "failed");
    assert_eq!(body["divi_scan"]["error"], "rpc down");
    task.abort();
    h.abort();
}

#[tokio::test]
async fn scan_resumes_from_saved_cursor() {
    // Config start ahead of the cursor wins.
    let fake = Fake::new(Some(100), 130);
    let scan = ScanStatus::scanning();
    run_scan(&fake, 120, &scan, 500, Duration::from_millis(1)).await;
    assert_eq!(*fake.calls.lock(), vec![(120, 130)]);
    assert!(scan.is_done());

    // Cursor ahead of config start: scans only the new blocks, in chunks.
    let fake = Fake::new(Some(339_900), 340_000);
    let scan = ScanStatus::scanning();
    run_scan(&fake, 339_800, &scan, 60, Duration::from_millis(1)).await;
    assert_eq!(
        *fake.calls.lock(),
        vec![(339_900, 339_959), (339_960, 340_000)]
    );
    assert_eq!(fake.scanned_height(), Some(340_001));
}

#[tokio::test]
async fn follow_keeps_the_cursor_behind_the_tip_and_stays_done() {
    let fake = Fake::new(None, 1_000);
    let scan = ScanStatus::scanning();
    run_scan(&fake, 0, &scan, 500, Duration::from_millis(1)).await;
    assert_eq!(fake.scanned_height(), Some(1_001));

    // Fewer new blocks than the lag: nothing to scan yet.
    *fake.tip.lock() = 1_004;
    follow_once(&fake, &scan, 500, 6).await.unwrap();
    assert_eq!(fake.scanned_height(), Some(1_001));

    // The tip moves on: the cursor follows to tip - lag, and the scan never stops being done.
    *fake.tip.lock() = 1_020;
    fake.calls.lock().clear();
    follow_once(&fake, &scan, 10, 6).await.unwrap();
    assert_eq!(*fake.calls.lock(), vec![(1_001, 1_010), (1_011, 1_014)]);
    assert_eq!(fake.scanned_height(), Some(1_015));
    assert!(scan.is_done());
    assert_eq!(scan.info().next_height, 1_015);

    // A failure leaves the status done and the cursor where it was.
    *fake.tip.lock() = 1_030;
    *fake.failures.lock() = 1;
    assert!(follow_once(&fake, &scan, 10, 6).await.is_err());
    assert!(scan.is_done());
    assert_eq!(fake.scanned_height(), Some(1_015));
}

#[tokio::test]
async fn claims_and_refunds_complete_during_wallet_scan_while_divi_funding_waits() {
    use divi_swap::SwapState;
    use divi_swapd::{router_with_auth, spawn_gated_scheduler, HashlockAuth, ProxyTrust};

    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("m.db")).unwrap();
    let maker = w.maker(store.clone());
    let taker = w.taker(&dir.path().join("t.db"));

    // 1. `claim_mid`: both legs locked and confirmed, then taker claims DIVI (revealing preimage)
    //    before the daemon restarts into scan catch-up.
    let q1 = maker.quote(OFFER_ID, BTC_SATS).await.unwrap();
    let (tid1, req1) = taker.prepare(&q1).await.unwrap();
    let v1 = maker.accept(req1).await.unwrap();
    taker.accepted(&tid1, &v1).await.unwrap();
    let n1 = taker.lock(&tid1).await.unwrap();
    let claim_mid = maker.notify_lock(&v1.id, n1).await.unwrap().id;
    for _ in 0..15 {
        w.divi.mine(1);
        w.btc.mine(1);
        maker.tick().await.unwrap();
        if maker.view(&claim_mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(
        maker.view(&claim_mid).unwrap().unwrap().state,
        SwapState::MakerLockConfirmed
    );
    let view1 = maker.view(&claim_mid).unwrap();
    taker.step(&tid1, view1.as_ref()).await.unwrap();
    w.divi.mine(1);

    // 2. `refund_mid`: both legs locked and confirmed; we will advance DIVI past the maker-leg
    //    locktime once the third swap is staged so `refund_mid` refunds during scan catch-up.
    let q2 = maker.quote(OFFER_ID, BTC_SATS).await.unwrap();
    let (tid2, req2) = taker.prepare(&q2).await.unwrap();
    let v2 = maker.accept(req2).await.unwrap();
    taker.accepted(&tid2, &v2).await.unwrap();
    let n2 = taker.lock(&tid2).await.unwrap();
    let refund_mid = maker.notify_lock(&v2.id, n2).await.unwrap().id;
    for _ in 0..15 {
        w.divi.mine(1);
        w.btc.mine(1);
        if maker.step(&refund_mid).await.unwrap() == SwapState::MakerLockConfirmed {
            break;
        }
    }
    assert_eq!(
        maker.view(&refund_mid).unwrap().unwrap().state,
        SwapState::MakerLockConfirmed
    );

    // 3. `fund_mid`: accepted before scan, taker locks BTC and confirms it, but maker has not
    //    been notified or selected a DIVI coin yet.
    let q3 = maker.quote(OFFER_ID, BTC_SATS).await.unwrap();
    let (tid3, req3) = taker.prepare(&q3).await.unwrap();
    let v3 = maker.accept(req3).await.unwrap();
    taker.accepted(&tid3, &v3).await.unwrap();
    let n3 = taker.lock(&tid3).await.unwrap();
    w.btc.mine(6);
    let fund_mid = v3.id.clone();

    // Advance DIVI past `refund_mid`'s maker-leg locktime so its refund is final now.
    let refund_locktime = store
        .get_maker_swap(&refund_mid)
        .unwrap()
        .unwrap()
        .maker_leg_htlc
        .unwrap()
        .locktime;
    let delta = refund_locktime.saturating_sub(w.divi.mtp()) + 60;
    w.divi.advance_time(delta);

    let divi_fundings_before = w.maker_divi.funding_calls();

    // Start the HTTP server and gated scheduler while the DIVI wallet scan is still in progress.
    let scan = ScanStatus::scanning();
    let sched = spawn_gated_scheduler(maker.clone(), Duration::from_millis(15), scan.clone());
    let state = AppState {
        maker: maker.clone(),
        divi: Arc::new(w.maker_divi.clone()),
        btc: Arc::new(w.maker_btc.clone()),
        scan: scan.clone(),
    };
    let auth = HashlockAuth::new(store.clone()).allow_tokenless(true);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router_with_auth(state, None, "/swap", ProxyTrust::off(), auth);
    let srv = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}/swap");

    // Notify `/lock` for `fund_mid` during the scan: must verify the BTC lock without selecting DIVI coins.
    let resp = reqwest::Client::new()
        .post(format!("{base}/swaps/{fund_mid}/lock"))
        .json(&n3)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    for _ in 0..80 {
        w.divi.mine(1);
        w.btc.mine(1);
        let s1 = maker.view(&claim_mid).unwrap().unwrap().state;
        let s2 = maker.view(&refund_mid).unwrap().unwrap().state;
        if s1 == SwapState::Done && s2 == SwapState::Done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert!(!scan.is_done(), "scan is still running");
    assert_eq!(
        maker.view(&claim_mid).unwrap().unwrap().state,
        SwapState::Done,
        "maker claim must finish while DIVI wallet scan is running"
    );
    assert_eq!(
        maker.view(&refund_mid).unwrap().unwrap().state,
        SwapState::Done,
        "maker refund must finish while DIVI wallet scan is running"
    );
    assert_eq!(
        maker.view(&fund_mid).unwrap().unwrap().state,
        SwapState::TakerLockConfirmed,
        "DIVI maker-leg funding must wait in TakerLockConfirmed until scan finishes"
    );
    assert_eq!(
        w.maker_divi.funding_calls(),
        divi_fundings_before,
        "zero DIVI coin selections while scan is running"
    );

    // Finish the scan: `fund_mid` now selects a DIVI coin and locks.
    let fake = Fake::new(None, 100);
    run_scan(&fake, 0, &scan, 500, Duration::from_millis(1)).await;
    assert!(scan.is_done());
    for _ in 0..80 {
        w.divi.mine(1);
        w.btc.mine(1);
        if maker.view(&fund_mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert_eq!(
        maker.view(&fund_mid).unwrap().unwrap().state,
        SwapState::MakerLockConfirmed
    );
    assert_eq!(w.maker_divi.funding_calls(), divi_fundings_before + 1);

    sched.abort();
    srv.abort();
}
