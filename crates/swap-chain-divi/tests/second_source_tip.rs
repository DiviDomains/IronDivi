// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `[divi].fallback_rpc_url` also covers the chain tip and the wallet scan reads: with a second
//! endpoint, a tip or a scanned transaction the two disagree on is `Transient`. No network: two
//! wiremock "nodes". Each lie test also runs the same lie against a single-source backend and
//! shows it is trusted (the behavior before this lane, and still the behavior with no fallback).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use divi_crypto::keys::SecretKey;
use divi_swap::{ChainBackend, SwapError, Txid};
use divi_wallet::address::Network;
use parking_lot::Mutex;
use serde_json::{json, Value};
use swap_chain_divi::{DiviBackend, FeePolicy, RetryPolicy, TIP_TOLERANCE_BLOCKS};
use wiremock::{matchers::method, Mock, MockServer, Request, Respond, ResponseTemplate};

const TIP: u64 = 100;

#[derive(Default)]
struct Chain {
    tip: u64,
    /// Overrides the hash of the tip block (a lying endpoint names another tip).
    tip_hash: Option<String>,
    txs: HashMap<String, Value>,
    blocks: HashMap<u64, Vec<String>>,
}

#[derive(Clone)]
struct Node(Arc<Mutex<Chain>>);

fn block_hash(h: u64) -> String {
    format!("{:064x}", h + 1)
}

impl Respond for Node {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let p = &body["params"];
        let c = self.0.lock();
        let ok = |v: Value| {
            ResponseTemplate::new(200).set_body_json(json!({"result": v, "error": null, "id": 1}))
        };
        let err = |code: i64, m: &str| {
            ResponseTemplate::new(500).set_body_json(
                json!({"result": null, "error": {"code": code, "message": m}, "id": 1}),
            )
        };
        match body["method"].as_str().unwrap_or("") {
            "getblockcount" => ok(json!(c.tip)),
            "getbestblockhash" => ok(json!(c
                .tip_hash
                .clone()
                .unwrap_or_else(|| block_hash(c.tip)))),
            "getblockhash" => {
                let h = p[0].as_u64().unwrap();
                if h > c.tip {
                    err(-8, "Block height out of range")
                } else {
                    ok(json!(block_hash(h)))
                }
            }
            "getblock" => {
                let h = u64::from_str_radix(p[0].as_str().unwrap(), 16).unwrap() - 1;
                ok(json!({"tx": c.blocks.get(&h).cloned().unwrap_or_default()}))
            }
            "getrawtransaction" => match c.txs.get(p[0].as_str().unwrap()) {
                Some(t) => ok(t.clone()),
                None => err(-5, "No such mempool or blockchain transaction"),
            },
            _ => err(-32601, "Method not found"),
        }
    }
}

async fn node() -> (MockServer, Arc<Mutex<Chain>>) {
    let server = MockServer::start().await;
    let chain = Arc::new(Mutex::new(Chain {
        tip: TIP,
        ..Chain::default()
    }));
    Mock::given(method("POST"))
        .respond_with(Node(chain.clone()))
        .mount(&server)
        .await;
    (server, chain)
}

fn key() -> SecretKey {
    SecretKey::from_hex(&"11".repeat(32)).unwrap()
}

fn single(url: &str) -> DiviBackend {
    DiviBackend::with_retry(
        url,
        key(),
        Network::Testnet,
        FeePolicy::default(),
        None,
        RetryPolicy {
            attempts: 1,
            base_delay: Duration::from_millis(1),
        },
    )
    .unwrap()
}

fn dual(primary: &str, fallback: &str) -> DiviBackend {
    single(primary).with_fallback_rpc(fallback)
}

/// A URL nothing listens on (a closed local port).
fn dead_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", l.local_addr().unwrap())
}

fn is_transient<T: std::fmt::Debug>(r: &Result<T, SwapError>) -> bool {
    matches!(r, Err(SwapError::Transient(m)) if m.contains("disagree"))
}

fn txid(n: u8) -> Txid {
    Txid([n; 32])
}

/// A transaction paying `sat` to the backend's own address, placed in block `height`.
fn pay_to_us(chain: &Arc<Mutex<Chain>>, b: &DiviBackend, n: u8, sat: u64, height: u64) {
    let spk =
        divi_primitives::script::Script::new_p2pkh(key().public_key().pubkey_hash().as_bytes())
            .to_hex();
    let _ = b;
    let id = txid(n).to_rpc_hex();
    let mut c = chain.lock();
    c.txs.insert(
        id.clone(),
        json!({
            "txid": id,
            "vin": [],
            "vout": [{"n": 0, "valueSat": sat, "value": sat as f64 / 1e8, "scriptPubKey": {"hex": spk}}],
        }),
    );
    c.blocks.entry(height).or_default().push(id);
}

// ---- tip height ----

#[tokio::test]
async fn tip_agree_gives_the_same_answer() {
    let (a, _ca) = node().await;
    let (b, _cb) = node().await;
    assert_eq!(dual(&a.uri(), &b.uri()).tip_height().await.unwrap(), TIP);
}

#[tokio::test]
async fn tip_inflated_beyond_tolerance_is_transient_and_trusted_single_source() {
    let (a, ca) = node().await;
    let (b, _cb) = node().await;
    ca.lock().tip = TIP + TIP_TOLERANCE_BLOCKS + 1;
    // Fail-before: with no fallback the inflated tip is the answer.
    assert_eq!(
        single(&a.uri()).tip_height().await.unwrap(),
        TIP + TIP_TOLERANCE_BLOCKS + 1
    );
    assert!(is_transient(&dual(&a.uri(), &b.uri()).tip_height().await));
}

#[tokio::test]
async fn tip_deflated_beyond_tolerance_is_transient() {
    let (a, _ca) = node().await;
    let (b, cb) = node().await;
    cb.lock().tip = TIP - TIP_TOLERANCE_BLOCKS - 1;
    assert_eq!(
        single(&b.uri()).tip_height().await.unwrap(),
        TIP - TIP_TOLERANCE_BLOCKS - 1
    );
    assert!(is_transient(&dual(&a.uri(), &b.uri()).tip_height().await));
}

#[tokio::test]
async fn tip_within_tolerance_is_accepted_and_the_lower_is_used() {
    let (a, ca) = node().await;
    let (b, _cb) = node().await;
    ca.lock().tip = TIP + TIP_TOLERANCE_BLOCKS;
    // The lower height wins whichever endpoint is ahead: a lag can lower the answer, never
    // raise it.
    assert_eq!(dual(&a.uri(), &b.uri()).tip_height().await.unwrap(), TIP);
    assert_eq!(dual(&b.uri(), &a.uri()).tip_height().await.unwrap(), TIP);
}

#[tokio::test]
async fn tip_with_one_endpoint_down_is_transient() {
    let (a, _ca) = node().await;
    let dead = dead_url();
    assert!(is_transient(&dual(&a.uri(), &dead).tip_height().await));
    assert!(is_transient(&dual(&dead, &a.uri()).tip_height().await));
}

// ---- tip hash ----

#[tokio::test]
async fn tip_hash_agree_and_disagree() {
    let (a, ca) = node().await;
    let (b, _cb) = node().await;
    assert_eq!(
        dual(&a.uri(), &b.uri()).tip_hash().await.unwrap(),
        block_hash(TIP)
    );
    ca.lock().tip_hash = Some(block_hash(999));
    // Fail-before: single source trusts the lie.
    assert_eq!(single(&a.uri()).tip_hash().await.unwrap(), block_hash(999));
    assert!(is_transient(&dual(&a.uri(), &b.uri()).tip_hash().await));
}

#[tokio::test]
async fn tip_hash_with_one_endpoint_down_is_transient() {
    let (a, _ca) = node().await;
    let dead = dead_url();
    assert!(is_transient(&dual(&a.uri(), &dead).tip_hash().await));
}

// ---- wallet scan ----

#[tokio::test]
async fn scan_agree_adds_the_coin() {
    let (a, ca) = node().await;
    let (b, cb) = node().await;
    let d = dual(&a.uri(), &b.uri());
    for c in [&ca, &cb] {
        pay_to_us(c, &d, 1, 7_000, 50);
    }
    assert_eq!(d.scan_range(50, 50).await.unwrap(), 51);
    assert_eq!(d.balance(), 7_000);
}

#[tokio::test]
async fn scan_invented_coin_is_transient_and_trusted_single_source() {
    let (a, ca) = node().await;
    let (b, _cb) = node().await;
    let d = dual(&a.uri(), &b.uri());
    pay_to_us(&ca, &d, 1, 9_000_000, 50);
    // Fail-before: a single-source wallet takes the primary's invented coin.
    let s = single(&a.uri());
    s.scan_range(50, 50).await.unwrap();
    assert_eq!(s.balance(), 9_000_000);
    // Both endpoints: the block lists differ.
    assert!(is_transient(&d.scan_range(50, 50).await));
    assert_eq!(d.balance(), 0);
    assert_eq!(
        d.scanned_height(),
        None,
        "no cursor moves on a disagreement"
    );
}

#[tokio::test]
async fn scan_inflated_amount_is_transient() {
    let (a, ca) = node().await;
    let (b, cb) = node().await;
    let d = dual(&a.uri(), &b.uri());
    pay_to_us(&ca, &d, 1, 9_000_000, 50);
    pay_to_us(&cb, &d, 1, 7_000, 50);
    let s = single(&a.uri());
    s.scan_range(50, 50).await.unwrap();
    assert_eq!(s.balance(), 9_000_000);
    assert!(is_transient(&d.scan_range(50, 50).await));
    assert_eq!(d.balance(), 0);
}

#[tokio::test]
async fn scan_hidden_coin_is_transient() {
    let (a, ca) = node().await;
    let (b, cb) = node().await;
    let d = dual(&a.uri(), &b.uri());
    // The fallback knows a coin the primary hides.
    pay_to_us(&cb, &d, 1, 7_000, 50);
    ca.lock().blocks.insert(50, vec![]);
    let s = single(&a.uri());
    s.scan_range(50, 50).await.unwrap();
    assert_eq!(
        s.balance(),
        0,
        "single source: the hidden coin stays hidden"
    );
    assert!(is_transient(&d.scan_range(50, 50).await));
}

#[tokio::test]
async fn scan_hidden_spend_is_transient() {
    let (a, ca) = node().await;
    let (b, cb) = node().await;
    let d = dual(&a.uri(), &b.uri());
    for c in [&ca, &cb] {
        pay_to_us(c, &d, 1, 7_000, 50);
    }
    // Block 51 spends the coin; the primary strips the input from the transaction.
    let spender = txid(2).to_rpc_hex();
    for (c, honest) in [(&ca, false), (&cb, true)] {
        let vin = if honest {
            json!([{"txid": txid(1).to_rpc_hex(), "vout": 0}])
        } else {
            json!([])
        };
        let mut c = c.lock();
        c.txs.insert(
            spender.clone(),
            json!({"txid": spender, "vin": vin, "vout": []}),
        );
        c.blocks.insert(51, vec![spender.clone()]);
    }
    let s = single(&a.uri());
    s.scan_range(50, 51).await.unwrap();
    assert_eq!(s.balance(), 7_000, "single source: the spend is hidden");
    assert!(is_transient(&d.scan_range(50, 51).await));
}

#[tokio::test]
async fn scan_with_one_endpoint_down_is_transient() {
    let (a, ca) = node().await;
    let d_probe = single(&a.uri());
    pay_to_us(&ca, &d_probe, 1, 7_000, 50);
    let dead = dead_url();
    assert!(is_transient(
        &dual(&a.uri(), &dead).scan_range(50, 50).await
    ));
}

#[tokio::test]
async fn add_funding_tx_lied_about_is_transient() {
    let (a, ca) = node().await;
    let (b, cb) = node().await;
    let d = dual(&a.uri(), &b.uri());
    pay_to_us(&ca, &d, 1, 9_000_000, 50);
    pay_to_us(&cb, &d, 1, 7_000, 50);
    let s = single(&a.uri());
    assert_eq!(s.add_funding_tx(&txid(1)).await.unwrap(), 1);
    assert_eq!(s.balance(), 9_000_000);
    assert!(is_transient(&d.add_funding_tx(&txid(1)).await));
    assert_eq!(d.balance(), 0);
}

#[tokio::test]
async fn scan_blocks_uses_the_agreed_tip() {
    let (a, ca) = node().await;
    let (b, _cb) = node().await;
    ca.lock().tip = TIP + TIP_TOLERANCE_BLOCKS + 1;
    assert!(is_transient(
        &dual(&a.uri(), &b.uri()).scan_blocks(99).await
    ));
}
