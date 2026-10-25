// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Offline tests: scripts are checked with the real interpreter, the RPC proxy is mocked.

use super::*;
use divi_primitives::serialize::deserialize;
use divi_swap::htlc::new_preimage;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use wiremock::{matchers::method, Mock, MockServer, Request, Respond, ResponseTemplate};

const LOCKTIME: u32 = 1_900_000_000;

#[test]
fn default_rpc_follows_the_network() {
    assert_eq!(default_rpc(Network::Mainnet), MAINNET_RPC);
    assert_eq!(default_rpc(Network::Testnet), TESTNET_RPC);
    assert_ne!(MAINNET_RPC, TESTNET_RPC);
    assert!(!MAINNET_RPC.contains("testnet"));
}

type NodeError = (u16, i64, String);

/// Replies to JSON-RPC calls by method name; unknown methods get a -32601 error.
#[derive(Clone, Default)]
struct Node {
    results: Arc<Mutex<HashMap<String, Value>>>,
    errors: Arc<Mutex<HashMap<String, NodeError>>>,
    plain: Arc<Mutex<HashMap<String, u16>>>,
    /// method -> (remaining failures, error); counted down on each call, then falls
    /// through to `results`/`errors` once exhausted — for "a lagging backend answers
    /// wrong a few times, then catches up" races.
    flaky: Arc<Mutex<HashMap<String, (u32, NodeError)>>>,
}

impl Node {
    fn result(&self, m: &str, v: Value) -> &Self {
        self.results.lock().insert(m.into(), v);
        self
    }
    fn plain(&self, m: &str, http: u16) -> &Self {
        self.plain.lock().insert(m.into(), http);
        self
    }
    fn error(&self, m: &str, http: u16, code: i64, msg: &str) -> &Self {
        self.errors
            .lock()
            .insert(m.into(), (http, code, msg.into()));
        self
    }
    fn flaky_error(&self, m: &str, times: u32, http: u16, code: i64, msg: &str) -> &Self {
        self.flaky
            .lock()
            .insert(m.into(), (times, (http, code, msg.into())));
        self
    }
}

impl Respond for Node {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let m = body["method"].as_str().unwrap_or("").to_string();
        if let Some((remaining, (http, code, msg))) = self.flaky.lock().get_mut(&m) {
            if *remaining > 0 {
                *remaining -= 1;
                return ResponseTemplate::new(*http).set_body_json(
                    json!({"result": null, "error": {"code": code, "message": msg}, "id": 1}),
                );
            }
        }
        if let Some(http) = self.plain.lock().get(&m) {
            return ResponseTemplate::new(*http).set_body_string("upstream unavailable");
        }
        if let Some((http, code, msg)) = self.errors.lock().get(&m) {
            return ResponseTemplate::new(*http).set_body_json(
                json!({"result": null, "error": {"code": code, "message": msg}, "id": 1}),
            );
        }
        match self.results.lock().get(&m) {
            Some(v) => ResponseTemplate::new(200).set_body_json(json!({"result": v, "error": null, "id": 1})),
            None => ResponseTemplate::new(500).set_body_json(
                json!({"result": null, "error": {"code": -32601, "message": "Method not found"}, "id": 1}),
            ),
        }
    }
}

async fn mock() -> (MockServer, Node) {
    let server = MockServer::start().await;
    let node = Node::default();
    Mock::given(method("POST"))
        .respond_with(node.clone())
        .mount(&server)
        .await;
    (server, node)
}

fn backend(url: &str, key: SecretKey) -> DiviBackend {
    DiviBackend::with_retry(
        url,
        key,
        Network::Testnet,
        FeePolicy::default(),
        None,
        RetryPolicy {
            attempts: 2,
            base_delay: Duration::from_millis(1),
        },
    )
    .unwrap()
}

fn htlc_for(b: &DiviBackend, hash: [u8; 32]) -> HtlcParams {
    HtlcParams {
        hash,
        claim_pubkey: b.pubkey(),
        refund_pubkey: b.pubkey(),
        locktime: LOCKTIME,
        script_version: Default::default(),
    }
}

fn txid_n(n: u8) -> Txid {
    Txid([n; 32])
}

fn coin(n: u8, value: u64) -> Utxo {
    Utxo {
        outpoint: Outpoint {
            txid: txid_n(n),
            vout: 0,
        },
        value,
    }
}

/// Verbose `getrawtransaction` JSON for a tx with the given outputs (spk hex, sat).
fn tx_json(txid: &Txid, vin: &[(&Txid, u32)], vout: &[(&str, u64)], confs: u32) -> Value {
    json!({
        "txid": txid.to_rpc_hex(),
        "confirmations": confs,
        "vin": vin.iter().map(|(t, n)| json!({"txid": t.to_rpc_hex(), "vout": n, "scriptSig": {"hex": "aabb"}})).collect::<Vec<_>>(),
        "vout": vout.iter().enumerate().map(|(i, (spk, sat))| json!({
            "n": i, "valueSat": sat, "value": *sat as f64 / 1e8, "scriptPubKey": {"hex": spk}
        })).collect::<Vec<_>>(),
    })
}

fn parse(tx: &SignedTx) -> Transaction {
    deserialize(&tx.raw).unwrap()
}

fn offline() -> DiviBackend {
    backend("http://127.0.0.1:1/", SecretKey::new_random())
}

const AMOUNT: Amount = Amount(100 * 100_000_000);

#[tokio::test]
async fn claim_verifies_with_interpreter() {
    let b = offline();
    let (pre, hash) = new_preimage();
    let h = htlc_for(&b, hash);
    let at = Outpoint {
        txid: txid_n(7),
        vout: 1,
    };
    let tx = b.build_claim(&h, &at, AMOUNT, &pre).await.unwrap();
    let t = parse(&tx);
    assert_eq!(t.lock_time, 0);
    assert_eq!(t.vin[0].sequence, SEQUENCE_FINAL);
    assert_eq!(t.vin[0].prevout.vout, 1);
    verify_input(
        &t,
        0,
        &htlc_script_pubkey(&h),
        DiviAmount::from_sat(AMOUNT.0 as i64),
    )
    .unwrap();
    assert_eq!(tx.txid, from_hash(&t.txid()));
    // The preimage must be recoverable from the claim's scriptSig.
    let spend = SpendInfo {
        txid: tx.txid,
        input_index: 0,
        height: None,
        script_sig: t.vin[0].script_sig.as_bytes().to_vec(),
        witness: vec![],
    };
    assert_eq!(spend.extract_preimage(&hash), Some(pre));
}

#[tokio::test]
async fn a_claim_pays_the_relay_minimum_times_the_claim_factor() {
    let b = DiviBackend::new(
        "http://127.0.0.1:1/",
        SecretKey::new_random(),
        Network::Testnet,
        FeePolicy {
            sat_per_kb: 1,
            min_fee: 1,
        },
        None,
    )
    .unwrap();
    let (pre, hash) = new_preimage();
    let h = htlc_for(&b, hash);
    let at = Outpoint {
        txid: txid_n(7),
        vout: 1,
    };
    let t = parse(&b.build_claim(&h, &at, AMOUNT, &pre).await.unwrap());
    let fee = AMOUNT.0 - t.vout[0].value.as_sat() as u64;
    let relay = RELAY_FEE_PER_KB * t.size() as u64 / 1000;
    assert!(
        fee >= CLAIM_FEE_FACTOR * relay,
        "claim fee {fee} < {CLAIM_FEE_FACTOR} x relay minimum {relay}"
    );
    // The default policy is above the floor on its own.
    let d = offline();
    let h = htlc_for(&d, hash);
    let t = parse(&d.build_claim(&h, &at, AMOUNT, &pre).await.unwrap());
    let fee = AMOUNT.0 - t.vout[0].value.as_sat() as u64;
    assert!(fee >= CLAIM_FEE_FACTOR * RELAY_FEE_PER_KB * t.size() as u64 / 1000);
}

#[tokio::test]
async fn refund_verifies_with_interpreter() {
    let b = offline();
    let (_, hash) = new_preimage();
    let h = htlc_for(&b, hash);
    let at = Outpoint {
        txid: txid_n(8),
        vout: 0,
    };
    let tx = b.build_refund(&h, &at, AMOUNT).await.unwrap();
    let t = parse(&tx);
    assert_eq!(t.lock_time, LOCKTIME);
    assert_eq!(t.vin[0].sequence, REFUND_SEQUENCE);
    verify_input(
        &t,
        0,
        &htlc_script_pubkey(&h),
        DiviAmount::from_sat(AMOUNT.0 as i64),
    )
    .unwrap();
    // Refund pays us back, less the fee.
    assert_eq!(t.vout.len(), 1);
    assert_eq!(t.vout[0].script_pubkey, b.spk);
    assert!((t.vout[0].value.as_sat() as u64) < AMOUNT.0);
}

#[tokio::test]
async fn refund_rejected_before_locktime() {
    let b = offline();
    let (_, hash) = new_preimage();
    let h = htlc_for(&b, hash);
    let at = Outpoint {
        txid: txid_n(9),
        vout: 0,
    };
    // 1. The interpreter (CLTV) rejects a refund whose nLockTime is below the script's.
    let tx = b.build_refund(&h, &at, AMOUNT).await.unwrap();
    let mut early = parse(&tx);
    early.lock_time = LOCKTIME - 1;
    let amt = DiviAmount::from_sat(AMOUNT.0 as i64);
    assert!(verify_input(&early, 0, &htlc_script_pubkey(&h), amt).is_err());

    // 2. The node's "non-final" answer maps to Premature, not Rejected.
    let (server, node) = mock().await;
    node.error("sendrawtransaction", 500, -26, "64: non-final");
    let b = backend(&server.uri(), SecretKey::new_random());
    let err = b.broadcast(&tx).await.unwrap_err();
    assert!(matches!(err, SwapError::Premature(_)), "{err:?}");
}

#[tokio::test]
async fn wrong_preimage_rejected() {
    let b = offline();
    let (_, hash) = new_preimage();
    let (other, _) = new_preimage();
    let h = htlc_for(&b, hash);
    let at = Outpoint {
        txid: txid_n(3),
        vout: 0,
    };
    let err = b.build_claim(&h, &at, AMOUNT, &other).await.unwrap_err();
    assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");
    // The interpreter itself refuses a claim signed with a preimage that does not match.
    let (pre, _) = new_preimage();
    let err = b.build_spend(&h, &at, AMOUNT, Some(&pre)).unwrap_err();
    assert!(matches!(err, SwapError::Rejected(_)), "{err:?}");
}

#[tokio::test]
async fn find_spend_scans_blocks() {
    let target = txid_n(0x11);
    let spender = txid_n(0x22);
    let other = txid_n(0x33);
    let server = MockServer::start().await;
    struct Chain {
        spender: Txid,
        other: Txid,
        target: Txid,
    }
    impl Respond for Chain {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let r = match body["method"].as_str().unwrap() {
                "getblockcount" => json!(102),
                "getblockhash" => json!("00".repeat(32)),
                "getblock" => json!({"tx": [self.other.to_rpc_hex(), self.spender.to_rpc_hex()]}),
                "getrawmempool" => json!([]),
                "getrawtransaction" => {
                    let id = body["params"][0].as_str().unwrap();
                    if id == self.spender.to_rpc_hex() {
                        tx_json(&self.spender, &[(&self.target, 1)], &[("51", 5)], 3)
                    } else {
                        tx_json(&self.other, &[(&self.target, 0)], &[("51", 5)], 3)
                    }
                }
                m => panic!("unexpected {m}"),
            };
            ResponseTemplate::new(200).set_body_json(json!({"result": r, "error": null, "id": 1}))
        }
    }
    Mock::given(method("POST"))
        .respond_with(Chain {
            spender,
            other,
            target,
        })
        .mount(&server)
        .await;
    let b2 = backend(&server.uri(), SecretKey::new_random());
    let found = b2
        .find_spend(
            &Outpoint {
                txid: target,
                vout: 1,
            },
            100,
        )
        .await
        .unwrap()
        .expect("spend found");
    assert_eq!(found.txid, spender);
    assert_eq!(found.input_index, 0);
    assert_eq!(found.height, Some(100));
    assert_eq!(found.script_sig, vec![0xaa, 0xbb]);
    // An outpoint nobody spends yields None.
    let none = b2
        .find_spend(
            &Outpoint {
                txid: target,
                vout: 5,
            },
            101,
        )
        .await
        .unwrap();
    assert!(none.is_none());
}

#[tokio::test]
async fn funding_selects_coins_and_change() {
    let b = offline();
    let (_, hash) = new_preimage();
    let h = htlc_for(&b, hash);
    {
        let mut w = b.wallet.lock();
        w.record_broadcast(
            &[],
            &[coin(1, 30 * 100_000_000), coin(2, 500 * 100_000_000)],
        )
        .unwrap();
    }
    // Smallest single coin that covers it wins: the 500 coin (the 30 is too small).
    let f = b.build_funding(&h, AMOUNT).await.unwrap();
    let t = parse(&f.tx);
    assert_eq!(t.vin.len(), 1);
    assert_eq!(t.vin[0].prevout.txid, to_hash(&txid_n(2)));
    assert_eq!(t.vout.len(), 2, "HTLC output plus change");
    assert_eq!(t.vout[0].script_pubkey, htlc_script_pubkey(&h));
    assert_eq!(t.vout[0].value.as_sat() as u64, AMOUNT.0);
    assert_eq!(t.vout[1].script_pubkey, b.spk);
    let fee = 500 * 100_000_000 - AMOUNT.0 - t.vout[1].value.as_sat() as u64;
    assert!(
        fee >= FeePolicy::default().min_fee && fee < 10_000_000,
        "fee {fee}"
    );
    assert_eq!(
        f.outpoint,
        Outpoint {
            txid: f.tx.txid,
            vout: 0
        }
    );
    verify_input(&t, 0, &b.spk, DiviAmount::from_sat(500 * 100_000_000)).unwrap();
    // Reserved coins are not reused; the 30-coin cannot fund another 100.
    assert_eq!(b.wallet.lock().reserved_count(), 1);
    let err = b.build_funding(&h, AMOUNT).await.unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
    // Two small coins combine when no single one is enough.
    {
        let mut w = b.wallet.lock();
        w.record_broadcast(&[], &[coin(3, 80 * 100_000_000)])
            .unwrap();
    }
    let f2 = b.build_funding(&h, AMOUNT).await.unwrap();
    assert_eq!(parse(&f2.tx).vin.len(), 2);
}

#[tokio::test]
async fn rpc_errors_classified() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    let (_, hash) = new_preimage();
    let tx = b
        .build_refund(
            &htlc_for(&b, hash),
            &Outpoint {
                txid: txid_n(5),
                vout: 0,
            },
            AMOUNT,
        )
        .await
        .unwrap();

    node.error("sendrawtransaction", 500, -26, "64: non-final");
    assert!(matches!(
        b.broadcast(&tx).await,
        Err(SwapError::Premature(_))
    ));
    node.error(
        "sendrawtransaction",
        500,
        -26,
        "Locktime requirement not satisfied",
    );
    assert!(matches!(
        b.broadcast(&tx).await,
        Err(SwapError::Premature(_))
    ));

    node.error(
        "sendrawtransaction",
        500,
        -27,
        "transaction already in block chain",
    );
    assert_eq!(b.broadcast(&tx).await.unwrap(), tx.txid);
    node.error("sendrawtransaction", 500, -26, "257: txn-already-known");
    assert_eq!(b.broadcast(&tx).await.unwrap(), tx.txid);

    // Rejected: the node refuses and the chain does not have the tx.
    node.error("sendrawtransaction", 500, -26, "16: bad-txns-inputs-spent");
    node.error(
        "getrawtransaction",
        500,
        -5,
        "No such mempool or blockchain transaction",
    );
    assert!(matches!(
        b.broadcast(&tx).await,
        Err(SwapError::Rejected(_))
    ));

    // Transient: 503 and 429 are retried, then surface as Transient.
    node.errors.lock().clear();
    node.plain("sendrawtransaction", 503);
    assert!(matches!(
        b.broadcast(&tx).await,
        Err(SwapError::Transient(_))
    ));
    node.plain("sendrawtransaction", 429);
    assert!(matches!(
        b.broadcast(&tx).await,
        Err(SwapError::Transient(_))
    ));
    // Network failure (nothing listening) is transient too.
    let dead = offline();
    assert!(matches!(
        dead.tip_height().await,
        Err(SwapError::Transient(_))
    ));

    // Success path records the change/proceeds as ours and spends the input.
    node.plain.lock().clear();
    node.result("sendrawtransaction", json!(tx.txid.to_rpc_hex()));
    assert_eq!(b.broadcast(&tx).await.unwrap(), tx.txid);
    assert_eq!(b.balance(), parse(&tx).vout[0].value.as_sat() as u64);

    assert_eq!(
        classify_broadcast_error("mandatory-script-verify-flag-failed"),
        BroadcastClass::Rejected
    );
    assert_eq!(
        classify_broadcast_error("Transaction outputs already in utxo set"),
        BroadcastClass::AlreadyKnown
    );
}

/// Bitcoin-Core-style (and DIVI's) node-warmup code -28 ("Loading block index...",
/// "Verifying blocks...") is transient, not a permanent rejection: it is retried by
/// `RpcClient::call`'s own backoff loop and, if the node is still warming up after every
/// attempt, surfaces as `Transient` — never `Other`.
#[tokio::test]
async fn node_warmup_is_transient() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.error("getblockcount", 500, -28, "Loading block index...");
    assert!(matches!(b.tip_height().await, Err(SwapError::Transient(_))));
}

/// A proxy fronting more than one node can report a block height as the tip via one
/// backend and then 404-equivalent ("Block not found", code -5) a `getblock`/
/// `getblockhash` lookup on a backend that has not indexed it yet — the direct DIVI
/// analog of the esplora "Block not found" bug fixed in btc/ltc (`d371a22`).
#[tokio::test]
async fn lagging_proxy_block_not_found_is_transient() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.result("getblockcount", json!(100));
    node.result("getblockhash", json!("deadbeef"));
    node.error("getblock", 500, -5, "Block not found");
    assert!(matches!(
        b.median_time_past().await,
        Err(SwapError::Transient(_))
    ));
}

/// -5 is reused for "No such mempool or blockchain transaction" too (a real, permanent
/// absence for `getrawtransaction`) — confirm that wording does NOT get swept into the
/// "Block not found" transient case above.
#[tokio::test]
async fn tx_not_found_by_message_stays_distinct_from_block_not_found() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.error(
        "getrawtransaction",
        500,
        -5,
        "No such mempool or blockchain transaction",
    );
    assert_eq!(b.get_tx_opt(&txid_n(9)).await.unwrap(), None);
}

/// A proxy returning a null/non-numeric block count is a glitch, not "the chain has no
/// height".
#[tokio::test]
async fn tip_height_non_numeric_is_transient() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.result("getblockcount", json!(null));
    assert!(matches!(b.tip_height().await, Err(SwapError::Transient(_))));
}

/// A real block always has a `time`; its absence from a block we were just given the
/// hash of means the backend serving it has not finished indexing.
#[tokio::test]
async fn median_time_past_missing_time_is_transient() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.result("getblockcount", json!(100));
    node.result("getblockhash", json!("deadbeef"));
    node.result("getblock", json!({"tx": []}));
    assert!(matches!(
        b.median_time_past().await,
        Err(SwapError::Transient(_))
    ));
}

/// A `sendrawtransaction` rejection does not necessarily mean the tx is truly absent: a
/// proxy fronting more than one node can reject against one backend while another
/// already has the tx. `broadcast` must double-check rather than trust a single `-5` and
/// conclude `Rejected` — the same lagging-backend race as the block-lookup bugs above,
/// one step further down the call chain.
#[tokio::test]
async fn broadcast_rejection_confirmed_present_after_a_lagging_lookup() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    let (_, hash) = new_preimage();
    let tx = b
        .build_refund(
            &htlc_for(&b, hash),
            &Outpoint {
                txid: txid_n(5),
                vout: 0,
            },
            AMOUNT,
        )
        .await
        .unwrap();

    node.error("sendrawtransaction", 500, -26, "16: bad-txns-inputs-spent");
    // The first getrawtransaction lookup races a lagging backend and still answers -5;
    // the second one (after broadcast's retry delay) has caught up.
    node.flaky_error(
        "getrawtransaction",
        1,
        500,
        -5,
        "No such mempool or blockchain transaction",
    );
    node.result("getrawtransaction", tx_json(&tx.txid, &[], &[], 0));
    assert_eq!(b.broadcast(&tx).await.unwrap(), tx.txid);
}

#[test]
fn txid_byte_order_round_trips() {
    let h = Hash256::from_hex(&"ab".repeat(32)).unwrap();
    assert_eq!(to_hash(&from_hash(&h)), h);
    let t = Txid::from_rpc_hex(&format!("{}{}", "01", "00".repeat(31))).unwrap();
    assert_eq!(from_hash(&to_hash(&t)), t);
}

#[tokio::test]
async fn scan_cursor_persists_with_wallet() {
    let (server, node) = mock().await;
    node.result("getblockhash", json!("00".repeat(32)))
        .result("getblock", json!({"tx": []}));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    let key = SecretKey::new_random();
    let open = || {
        DiviBackend::new(
            &server.uri(),
            key.clone(),
            Network::Testnet,
            FeePolicy::default(),
            Some(path.clone()),
        )
        .unwrap()
    };
    let b = open();
    assert_eq!(b.scanned_height(), None);
    assert_eq!(b.scan_range(100, 101).await.unwrap(), 102);
    assert_eq!(b.scanned_height(), Some(102));
    // A fresh process sees the saved cursor.
    assert_eq!(open().scanned_height(), Some(102));
}

/// Fixture: a 64-hex block hash in explorer (display) order, as DIVI `getbestblockhash` answers.
const DIVI_GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

#[tokio::test]
async fn tip_hash_reads_getbestblockhash_in_display_order() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.result("getbestblockhash", json!(DIVI_GENESIS_HASH.to_uppercase()));
    assert_eq!(b.tip_hash().await.unwrap(), DIVI_GENESIS_HASH);
}

#[tokio::test]
async fn tip_hash_non_string_or_malformed_is_transient() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.result("getbestblockhash", json!(null));
    assert!(matches!(b.tip_hash().await, Err(SwapError::Transient(_))));
    node.result("getbestblockhash", json!("deadbeef"));
    assert!(matches!(b.tip_hash().await, Err(SwapError::Transient(_))));
}

#[tokio::test]
async fn tip_hash_failing_endpoint_errors() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.plain("getbestblockhash", 503);
    assert!(b.tip_hash().await.is_err());
}

/// Read-only smoke against the live DIVI APIs: prints `SMOKE <chain> <net> <height_before>
/// <tip_hash> <height_after>` for comparison with an independent explorer. Broadcasts nothing.
#[tokio::test]
#[ignore = "hits live DIVI APIs (read-only GETs)"]
async fn tip_hash_live_smoke() {
    for net in ["testnet", "mainnet"] {
        let b = {
            let (rpc, network) = if net == "mainnet" {
                (MAINNET_RPC, Network::Mainnet)
            } else {
                (TESTNET_RPC, Network::Testnet)
            };
            DiviBackend::new(
                rpc,
                SecretKey::new_random(),
                network,
                FeePolicy::default(),
                None,
            )
            .unwrap()
        };
        let before = b.tip_height().await.unwrap();
        let hash = b.tip_hash().await.unwrap();
        let after = b.tip_height().await.unwrap();
        assert_eq!(hash.len(), 64, "{hash}");
        println!("SMOKE DIVI {net} {before} {hash} {after}");
    }
}

// ---- release_dead_lock: a lock gone for good leaves no phantom change coin ----

const COIN_SAT: u64 = 500 * 100_000_000;

fn txout_json(b: &DiviBackend, sat: u64) -> Value {
    json!({
        "bestblock": "00", "confirmations": 3, "value": sat as f64 / 1e8, "valueSat": sat,
        "scriptPubKey": {"hex": hex::encode(b.spk.as_bytes())},
    })
}

/// A backend that has funded and broadcast a lock from one 500-DIVI coin.
async fn broadcast_lock(b: &DiviBackend, node: &Node) -> Funding {
    let (_, hash) = new_preimage();
    let h = htlc_for(b, hash);
    b.wallet
        .lock()
        .record_broadcast(&[], &[coin(1, COIN_SAT)])
        .unwrap();
    let f = b.build_funding(&h, AMOUNT).await.unwrap();
    node.result("sendrawtransaction", json!(f.tx.txid.to_rpc_hex()));
    b.broadcast(&f.tx).await.unwrap();
    f
}

#[tokio::test]
async fn dead_lock_gives_back_inputs_and_drops_phantom_change() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    let f = broadcast_lock(&b, &node).await;
    let change = parse(&f.tx).vout[1].value.as_sat() as u64;
    // The wallet now counts the lock's change and has tombstoned the input.
    assert_eq!(b.balance(), change);
    assert_eq!(
        b.wallet.lock().available(),
        vec![Utxo {
            outpoint: Outpoint {
                txid: f.tx.txid,
                vout: 1
            },
            value: change,
        }]
    );
    // The input is unspent in the chain: the lock never made it.
    node.result("gettxout", txout_json(&b, COIN_SAT));
    assert!(b.release_dead_lock(&f.tx).await.unwrap());
    assert_eq!(
        b.balance(),
        COIN_SAT,
        "phantom change gone, input spendable"
    );
    assert_eq!(b.wallet.lock().available(), vec![coin(1, COIN_SAT)]);
    // Idempotent.
    assert!(!b.release_dead_lock(&f.tx).await.unwrap());
    assert_eq!(b.balance(), COIN_SAT);
    // The released input is selectable again.
    let (_, hash) = new_preimage();
    let again = b.build_funding(&htlc_for(&b, hash), AMOUNT).await.unwrap();
    assert_eq!(parse(&again.tx).vin[0].prevout.txid, to_hash(&txid_n(1)));
}

#[tokio::test]
async fn dead_lock_is_not_released_without_proof() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    let f = broadcast_lock(&b, &node).await;
    let change = parse(&f.tx).vout[1].value.as_sat() as u64;
    // Input spent (the lock, or a rival, is in the chain): `gettxout` says null.
    node.result("gettxout", Value::Null);
    assert!(!b.release_dead_lock(&f.tx).await.unwrap());
    // Input not ours: not released.
    node.result(
        "gettxout",
        json!({"value": 1.0, "valueSat": 100_000_000, "scriptPubKey": {"hex": "aa"}}),
    );
    assert!(!b.release_dead_lock(&f.tx).await.unwrap());
    // The node refuses `gettxout`: fails closed with an error.
    node.results.lock().remove("gettxout");
    node.error("gettxout", 500, -32601, "Method not found");
    assert!(b.release_dead_lock(&f.tx).await.is_err());
    // Transport failure: Transient, nothing released.
    node.errors.lock().clear();
    node.plain("gettxout", 503);
    assert!(matches!(
        b.release_dead_lock(&f.tx).await,
        Err(SwapError::Transient(_))
    ));
    assert_eq!(b.balance(), change, "change still booked");
    assert_eq!(b.wallet.lock().reserved_count(), 0);
}

#[tokio::test]
async fn released_state_survives_a_restart() {
    let (server, node) = mock().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.json");
    let key = SecretKey::new_random();
    let mk = |k: SecretKey| {
        DiviBackend::with_retry(
            &server.uri(),
            k,
            Network::Testnet,
            FeePolicy::default(),
            Some(path.clone()),
            RetryPolicy {
                attempts: 2,
                base_delay: Duration::from_millis(1),
            },
        )
        .unwrap()
    };
    let b = mk(key.clone());
    let f = broadcast_lock(&b, &node).await;
    node.result("gettxout", txout_json(&b, COIN_SAT));
    assert!(b.release_dead_lock(&f.tx).await.unwrap());
    drop(b);
    let b2 = mk(key);
    assert_eq!(b2.balance(), COIN_SAT);
    assert!(
        !b2.release_dead_lock(&f.tx).await.unwrap(),
        "nothing left to release"
    );
}

// ---- lock-input reservations: the shared `input_reservation` table ----

/// A backend on `url` holding coins `coins` and sharing `res` with other processes.
fn reserving(url: &str, key: SecretKey, res: &InputReservations, coins: &[Utxo]) -> DiviBackend {
    let b = backend(url, key).with_input_reservations(res.clone());
    b.wallet.lock().record_broadcast(&[], coins).unwrap();
    b
}

/// `sendrawtransaction` calls the node received.
async fn sends(server: &MockServer) -> usize {
    let reqs = server.received_requests().await.unwrap();
    reqs.iter()
        .filter(|r| {
            serde_json::from_slice::<Value>(&r.body).unwrap()["method"] == "sendrawtransaction"
        })
        .count()
}

/// Every reservation on DIVI, as (input, reserving tx).
fn divi_rows(res: &InputReservations) -> Vec<(Outpoint, Txid)> {
    res.list_all()
        .unwrap()
        .into_iter()
        .filter(|r| r.chain == Chain::Divi)
        .map(|r| (r.input, r.reserved_by))
        .collect()
}

fn new_htlc(b: &DiviBackend) -> HtlcParams {
    htlc_for(b, new_preimage().1)
}

#[tokio::test]
async fn funding_skips_coins_another_process_reserved() {
    let res = InputReservations::in_memory().unwrap();
    let b = reserving(
        "http://127.0.0.1:1/",
        SecretKey::new_random(),
        &res,
        &[coin(1, COIN_SAT), coin(2, 2 * COIN_SAT)],
    );
    // Another taker's lock holds coin 1, the one selection would otherwise pick.
    res.reserve(Chain::Divi, &txid_n(0x77), &[coin(1, 0).outpoint])
        .unwrap();
    assert_eq!(
        b.spendable().await.unwrap(),
        Some(Amount(2 * COIN_SAT)),
        "a reserved coin is not spendable"
    );
    let f = b.build_funding(&new_htlc(&b), AMOUNT).await.unwrap();
    let t = parse(&f.tx);
    assert_eq!(t.vin.len(), 1);
    assert_eq!(t.vin[0].prevout.txid, to_hash(&txid_n(2)));
    // With coin 2 taken by this build too, nothing is left.
    let err = b.build_funding(&new_htlc(&b), AMOUNT).await.unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
}

#[tokio::test]
async fn a_lock_reserves_its_inputs_before_it_is_sent() {
    let (server, node) = mock().await;
    let res = InputReservations::in_memory().unwrap();
    let key = SecretKey::new_random();
    let a = reserving(&server.uri(), key.clone(), &res, &[coin(1, COIN_SAT)]);
    let f = a.build_funding(&new_htlc(&a), AMOUNT).await.unwrap();
    assert!(divi_rows(&res).is_empty(), "built, not sent: nothing reserved");
    node.result("sendrawtransaction", json!(f.tx.txid.to_rpc_hex()));
    a.broadcast(&f.tx).await.unwrap();
    assert_eq!(divi_rows(&res), vec![(coin(1, 0).outpoint, f.tx.txid)]);
    // A re-broadcast of the same bytes (a restart) keeps the one reservation.
    a.broadcast(&f.tx).await.unwrap();
    assert_eq!(divi_rows(&res).len(), 1);

    // A second process on the same wallet that never saw the lock cannot select its coin.
    let b = reserving(&server.uri(), key, &res, &[coin(1, COIN_SAT)]);
    let err = b.build_funding(&new_htlc(&b), AMOUNT).await.unwrap_err();
    assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
}

#[tokio::test]
async fn a_lock_whose_input_another_lock_holds_is_never_sent() {
    let (server, node) = mock().await;
    let res = InputReservations::in_memory().unwrap();
    let b = reserving(
        &server.uri(),
        SecretKey::new_random(),
        &res,
        &[coin(1, COIN_SAT)],
    );
    let f = b.build_funding(&new_htlc(&b), AMOUNT).await.unwrap();
    node.result("sendrawtransaction", json!(f.tx.txid.to_rpc_hex()));
    // The other taker reserved coin 1 between this build and this broadcast.
    res.reserve(Chain::Divi, &txid_n(0x77), &[coin(1, 0).outpoint])
        .unwrap();
    let err = b.broadcast(&f.tx).await.unwrap_err();
    assert!(matches!(err, SwapError::Rejected(_)), "{err:?}");
    assert_eq!(sends(&server).await, 0, "never sent");
    assert_eq!(divi_rows(&res), vec![(coin(1, 0).outpoint, txid_n(0x77))]);
    assert_eq!(
        b.wallet.lock().reserved_count(),
        0,
        "the wallet file drops its own hold on the coin"
    );
}

#[tokio::test]
async fn a_failed_reservation_write_blocks_the_broadcast() {
    let (server, node) = mock().await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("swaps.db");
    InputReservations::open(&db).unwrap();
    let res = InputReservations::open_read_only(&db).unwrap();
    let b = reserving(
        &server.uri(),
        SecretKey::new_random(),
        &res,
        &[coin(1, COIN_SAT)],
    );
    let f = b.build_funding(&new_htlc(&b), AMOUNT).await.unwrap();
    node.result("sendrawtransaction", json!(f.tx.txid.to_rpc_hex()));
    assert!(b.broadcast(&f.tx).await.is_err());
    assert_eq!(sends(&server).await, 0, "never sent");
}

#[tokio::test]
async fn claims_and_refunds_reserve_nothing() {
    let (server, node) = mock().await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("swaps.db");
    InputReservations::open(&db).unwrap();
    // Read-only: a reservation attempt would fail the broadcast.
    let res = InputReservations::open_read_only(&db).unwrap();
    let b = reserving(&server.uri(), SecretKey::new_random(), &res, &[]);
    let (pre, hash) = new_preimage();
    let h = htlc_for(&b, hash);
    let claim = b
        .build_claim(&h, &Outpoint { txid: txid_n(7), vout: 0 }, AMOUNT, &pre)
        .await
        .unwrap();
    let refund = b
        .build_refund(&h, &Outpoint { txid: txid_n(8), vout: 0 }, AMOUNT)
        .await
        .unwrap();
    node.result("sendrawtransaction", json!("00"));
    b.broadcast(&claim).await.unwrap();
    b.broadcast(&refund).await.unwrap();
    assert!(divi_rows(&res).is_empty());
}

#[tokio::test]
async fn a_confirmed_lock_releases_its_reservation() {
    let (server, node) = mock().await;
    let res = InputReservations::in_memory().unwrap();
    let b = reserving(
        &server.uri(),
        SecretKey::new_random(),
        &res,
        &[coin(1, COIN_SAT)],
    );
    let f = b.build_funding(&new_htlc(&b), AMOUNT).await.unwrap();
    node.result("sendrawtransaction", json!(f.tx.txid.to_rpc_hex()));
    b.broadcast(&f.tx).await.unwrap();
    node.result("getrawtransaction", json!({"txid": f.tx.txid.to_rpc_hex(), "confirmations": 0}));
    assert_eq!(b.confirmations(&f.tx.txid).await.unwrap(), Some(0));
    assert_eq!(divi_rows(&res).len(), 1, "in the mempool: kept");
    node.result("getrawtransaction", json!({"txid": f.tx.txid.to_rpc_hex(), "confirmations": 1}));
    assert_eq!(b.confirmations(&f.tx.txid).await.unwrap(), Some(1));
    assert!(divi_rows(&res).is_empty(), "confirmed: released");
    // The wallet keeps the input tombstoned: it is spent on chain.
    assert!(!b
        .wallet
        .lock()
        .available()
        .iter()
        .any(|u| u.outpoint == coin(1, 0).outpoint));
}

#[tokio::test]
async fn a_dead_lock_releases_its_reservation_with_its_wallet_booking() {
    let (server, node) = mock().await;
    let res = InputReservations::in_memory().unwrap();
    let b = backend(&server.uri(), SecretKey::new_random()).with_input_reservations(res.clone());
    let f = broadcast_lock(&b, &node).await;
    assert_eq!(divi_rows(&res).len(), 1);
    // No proof (the input is spent): both stay held.
    node.result("gettxout", Value::Null);
    assert!(!b.release_dead_lock(&f.tx).await.unwrap());
    assert_eq!(divi_rows(&res).len(), 1);
    node.result("gettxout", txout_json(&b, COIN_SAT));
    assert!(b.release_dead_lock(&f.tx).await.unwrap());
    assert!(divi_rows(&res).is_empty());
    assert_eq!(b.spendable().await.unwrap(), Some(Amount(COIN_SAT)));
}

const TIP: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

#[tokio::test]
async fn the_tip_header_comes_from_the_best_block() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.result("getbestblockhash", json!(TIP));
    node.result(
        "getblock",
        json!({"hash": TIP, "height": 1234, "time": 1_800_000_000u32}),
    );
    assert_eq!(
        b.tip_header().await.unwrap(),
        divi_swap::backend::TipHeader {
            height: 1234,
            hash: TIP.into(),
            time: 1_800_000_000,
        }
    );
    // A block that is not the one asked for (the tip moved, a lagging node) is transient.
    node.result(
        "getblock",
        json!({"hash": "00".repeat(32), "height": 1234, "time": 1_800_000_000u32}),
    );
    assert!(matches!(
        b.tip_header().await,
        Err(SwapError::Transient(_))
    ));
    node.result("getblock", json!({"hash": TIP, "height": 1234}));
    assert!(matches!(
        b.tip_header().await,
        Err(SwapError::Transient(_))
    ));
}

#[tokio::test]
async fn a_block_is_in_the_best_chain_when_its_height_still_names_it() {
    let (server, node) = mock().await;
    let b = backend(&server.uri(), SecretKey::new_random());
    node.result("getblockhash", json!(TIP));
    assert!(b.in_best_chain(1234, TIP).await.unwrap());
    assert!(b
        .in_best_chain(1234, &TIP.to_ascii_uppercase())
        .await
        .unwrap());
    assert!(!b.in_best_chain(1234, &"00".repeat(32)).await.unwrap());
    assert_eq!(b.target_block_secs(), Some(60));
}

#[tokio::test]
async fn with_a_fallback_the_tip_header_and_best_chain_must_agree() {
    let (primary, p) = mock().await;
    let (fallback, f) = mock().await;
    let b = backend(&primary.uri(), SecretKey::new_random()).with_fallback_rpc(&fallback.uri());
    for n in [&p, &f] {
        n.result("getbestblockhash", json!(TIP));
        n.result("getblock", json!({"hash": TIP, "height": 9, "time": 1_800_000_000u32}));
        n.result("getblockhash", json!(TIP));
    }
    assert_eq!(b.tip_header().await.unwrap().height, 9);
    assert!(b.in_best_chain(9, TIP).await.unwrap());
    f.result("getblockhash", json!("00".repeat(32)));
    assert!(matches!(
        b.in_best_chain(9, TIP).await,
        Err(SwapError::Transient(_))
    ));
    f.result("getbestblockhash", json!("00".repeat(32)));
    f.result(
        "getblock",
        json!({"hash": "00".repeat(32), "height": 9, "time": 1_800_000_000u32}),
    );
    assert!(matches!(
        b.tip_header().await,
        Err(SwapError::Transient(_))
    ));
}
