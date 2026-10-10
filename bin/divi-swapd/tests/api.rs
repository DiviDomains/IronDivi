// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! HTTP API behaviour over simulated chains.

mod common;

use std::time::Duration;

use common::*;
use divi_swap::api::SwapView;
use divi_swap::{Store, SwapState};
use divi_swap_cli::{flow, MakerClient, Sessions};
use serde_json::Value;

async fn get_json(url: &str) -> (u16, Value) {
    let r = reqwest::get(url).await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

#[tokio::test]
async fn healthz_ok() {
    let w = World::new();
    w.divi.mine(5);
    let d = serve(&w, w.maker(Store::in_memory().unwrap()), None).await;
    let (code, body) = get_json(&format!("{}/healthz", d.base)).await;
    assert_eq!(code, 200);
    assert_eq!(body["ok"], true);
    assert_eq!(body["divi"]["tip"], 5);
    assert_eq!(body["btc"]["tip"], 0);
    assert!(body["version"].is_string());

    w.btc.set_offline(true);
    let (code, body) = get_json(&format!("{}/healthz", d.base)).await;
    assert_eq!(code, 200);
    assert_eq!(body["ok"], false);
    assert!(body["btc"]["error"].is_string());
    d.stop();
}

#[tokio::test]
async fn offers_list() {
    let w = World::new();
    let d = serve(&w, w.maker(Store::in_memory().unwrap()), None).await;
    let (code, body) = get_json(&format!("{}/offers", d.base)).await;
    assert_eq!(code, 200);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["id"], OFFER_ID);
    // Routes exist only under the configured prefix.
    let bare = d.base.replace("/swap", "");
    assert_eq!(
        reqwest::get(format!("{bare}/offers"))
            .await
            .unwrap()
            .status(),
        404
    );
    d.stop();
}

#[tokio::test]
async fn quote_expires_after_60s() {
    let w = World::new();
    let d = serve(&w, w.maker(Store::in_memory().unwrap()), None).await;
    let before = now_secs();
    let (code, q) = get_json(&format!(
        "{}/offers/{OFFER_ID}/quote?btc_sats={BTC_SATS}",
        d.base
    ))
    .await;
    assert_eq!(code, 200);
    let ttl = q["expires_at"].as_u64().unwrap() - before;
    assert!((59..=62).contains(&ttl), "quote ttl {ttl}s");
    assert_eq!(q["btc_amount"], BTC_SATS);

    let (code, _) = get_json(&format!("{}/offers/nope/quote?btc_sats=5000", d.base)).await;
    assert!((400..500).contains(&code), "unknown offer -> {code}");
    let (code, _) = get_json(&format!("{}/offers/{OFFER_ID}/quote?btc_sats=1", d.base)).await;
    assert!((400..500).contains(&code), "below min -> {code}");
    d.stop();
}

#[tokio::test]
async fn post_swaps_accepts_quote() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let d = serve(&w, w.maker(Store::in_memory().unwrap()), None).await;
    let taker = w.taker(&dir.path().join("t.db"));
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&dir.path().join("t.db"));

    let local = flow::begin(&taker, &client, &sessions, OFFER_ID, BTC_SATS)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;
    let (code, v) = get_json(&format!("{}/swaps/{id}", d.base)).await;
    assert_eq!(code, 200);
    assert_eq!(v["state"], "Accepted");
    assert_eq!(v["maker_leg"], Value::Null, "maker has locked nothing yet");
    assert_eq!(w.maker_divi.funding_calls(), 0);

    let (_, all) = get_json(&format!("{}/swaps", d.base)).await;
    assert_eq!(all.as_array().unwrap().len(), 1);
    let (code, _) = get_json(&format!("{}/swaps/does-not-exist", d.base)).await;
    assert_eq!(code, 404);

    // Replaying a quote id that was never issued is refused.
    let bad = reqwest::Client::new()
        .post(format!("{}/swaps", d.base))
        .json(&serde_json::json!({
            "quote_id": "nope", "hash": "00".repeat(32),
            "taker_btc_pubkey": "02".to_string() + &"11".repeat(32),
            "taker_divi_pubkey": "02".to_string() + &"22".repeat(32),
        }))
        .send()
        .await
        .unwrap();
    assert!(bad.status().is_client_error());
    d.stop();
}

#[tokio::test]
async fn get_swap_never_leaks_keys() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let d = serve(&w, w.maker(Store::in_memory().unwrap()), None).await;
    let taker = w.taker(&dir.path().join("t.db"));
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&dir.path().join("t.db"));
    let local = flow::begin(&taker, &client, &sessions, OFFER_ID, BTC_SATS)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;

    let raw = reqwest::get(format!("{}/swaps/{id}", d.base))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let v: SwapView = serde_json::from_str(&raw).unwrap();
    assert!(
        v.preimage.is_none(),
        "preimage must not exist before reveal"
    );
    let json: Value = serde_json::from_str(&raw).unwrap();
    let mut fields = vec![];
    collect_keys(&json, &mut fields);
    for f in &fields {
        let l = f.to_lowercase();
        assert!(
            !["priv", "secret", "wif", "seed", "xprv", "mnemonic"]
                .iter()
                .any(|bad| l.contains(bad)),
            "suspicious field {f} in swap view"
        );
    }
    // The list endpoint exposes the same view type, nothing more.
    let list = reqwest::get(format!("{}/swaps", d.base))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    serde_json::from_str::<Vec<SwapView>>(&list).unwrap();
    d.stop();
}

fn collect_keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                out.push(k.clone());
                collect_keys(v, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| collect_keys(v, out)),
        _ => {}
    }
}

#[tokio::test]
async fn lock_notice_advances() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let d = serve(&w, w.maker(Store::in_memory().unwrap()), None).await;
    let taker = w.taker(&dir.path().join("t.db"));
    let client = MakerClient::new(&d.base);
    let sessions = Sessions::beside(&dir.path().join("t.db"));
    let local = flow::begin(&taker, &client, &sessions, OFFER_ID, BTC_SATS)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;

    flow::lock(&taker, &client, &sessions, &local)
        .await
        .unwrap();
    let v = client.swap(&id).await.unwrap();
    assert!(
        matches!(
            v.state,
            SwapState::TakerLockSeen | SwapState::TakerLockConfirmed
        ),
        "after lock notice: {:?}",
        v.state
    );
    assert!(v.taker_leg.outpoint.is_some());
    assert_eq!(
        w.maker_divi.funding_calls(),
        0,
        "no coins before confirmation"
    );

    // Unknown swap id on the lock route is a clean client error.
    let r = reqwest::Client::new()
        .post(format!("{}/swaps/nope/lock", d.base))
        .json(&serde_json::json!({ "outpoint": v.taker_leg.outpoint }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error() || r.status().as_u16() == 404);
    d.stop();
}

#[tokio::test]
async fn scheduler_resumes_on_restart() {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("maker.db");
    let tdb = dir.path().join("t.db");
    let taker = w.taker(&tdb);
    let sessions = Sessions::beside(&tdb);

    // First life: no scheduler, so the swap is parked right after the lock notice.
    let d1 = serve(&w, w.maker(Store::open(&db).unwrap()), None).await;
    let client = MakerClient::new(&d1.base);
    let local = flow::begin(&taker, &client, &sessions, OFFER_ID, BTC_SATS)
        .await
        .unwrap();
    flow::lock(&taker, &client, &sessions, &local)
        .await
        .unwrap();
    let id = sessions.get(&local).unwrap().maker_swap_id;
    d1.stop();
    w.btc.mine(2);

    // Second life over the same database: the startup tick picks the swap up.
    let d2 = serve(
        &w,
        w.maker(Store::open(&db).unwrap()),
        Some(Duration::from_millis(20)),
    )
    .await;
    let client = MakerClient::new(&d2.base);
    let mut state = SwapState::Accepted;
    for _ in 0..200 {
        w.divi.mine(1);
        state = client.swap(&id).await.unwrap().state;
        if matches!(
            state,
            SwapState::MakerLocked | SwapState::MakerLockConfirmed
        ) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        matches!(
            state,
            SwapState::MakerLocked | SwapState::MakerLockConfirmed
        ),
        "restarted daemon did not resume: {state:?}"
    );
    assert!(w.maker_divi.funding_calls() >= 1);
    d2.stop();
}
