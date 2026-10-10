// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
use divi_swapd::{router, run_scan, AppState, ScanStatus, WalletScan};
use parking_lot::Mutex;
use serde_json::Value;

/// Scanner with a saved cursor, a fixed tip, and an optional number of initial failures.
struct Fake {
    cursor: Mutex<Option<u64>>,
    tip: u64,
    calls: Mutex<Vec<(u64, u64)>>,
    failures: Mutex<u32>,
}

impl Fake {
    fn new(cursor: Option<u64>, tip: u64) -> Self {
        Fake {
            cursor: Mutex::new(cursor),
            tip,
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
        Ok(self.tip)
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
