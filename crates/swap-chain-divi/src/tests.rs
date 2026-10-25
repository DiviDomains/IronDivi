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

// --- G2: two DIVI sources -------------------------------------------------------------

/// A cryptoid stand-in: `tx.raw.dws` answers `tx` (or "unknown"), `block.raw.dws` gives
/// block `h` the time `h * 60`, and `api.dws?q=getblockcount` says `tip`.
#[derive(Clone)]
struct Cryptoid {
    tx: Arc<Mutex<Option<Value>>>,
    status: Arc<Mutex<u16>>,
    tip: u64,
}

impl Respond for Cryptoid {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let status = *self.status.lock();
        if status != 200 {
            return ResponseTemplate::new(status).set_body_string("busy");
        }
        let q: HashMap<String, String> = req.url.query_pairs().into_owned().collect();
        match req.url.path() {
            "/explorer/tx.raw.dws" => match &*self.tx.lock() {
                Some(tx) => ResponseTemplate::new(200).set_body_json(tx),
                None => ResponseTemplate::new(200).set_body_string("\"unknown\""),
            },
            "/explorer/block.raw.dws" => {
                let h: u64 = q["height"].parse().unwrap();
                ResponseTemplate::new(200).set_body_json(json!({"height": h, "time": h * 60}))
            }
            "/divi/api.dws" if q["q"] == "getblockcount" => {
                ResponseTemplate::new(200).set_body_string(self.tip.to_string())
            }
            _ => ResponseTemplate::new(404).set_body_string("not found"),
        }
    }
}

async fn cryptoid(tx: Option<Value>) -> (MockServer, Cryptoid) {
    let server = MockServer::start().await;
    let c = Cryptoid {
        tx: Arc::new(Mutex::new(tx)),
        status: Arc::new(Mutex::new(200)),
        tip: 100,
    };
    Mock::given(method("GET"))
        .respond_with(c.clone())
        .mount(&server)
        .await;
    (server, c)
}

/// The maker's lock as both sources print it: `sat` to the HTLC, in block `block`.
fn lock_json(h: &HtlcParams, sat: u64, confs: u32, block: Option<&str>) -> Value {
    let mut tx = tx_json(
        &txid_n(7),
        &[],
        &[(&htlc_script_pubkey(h).to_hex(), sat)],
        confs,
    );
    if let Some(b) = block {
        tx["blockhash"] = json!(b);
    }
    tx
}

const LOCK_AT: Outpoint = Outpoint {
    txid: Txid([7; 32]),
    vout: 0,
};

async fn two_source(
    rpc_tx: Value,
    cid_tx: Option<Value>,
) -> (
    TwoSource<DiviBackend>,
    HtlcParams,
    MockServer,
    MockServer,
    Cryptoid,
) {
    let (rpc, node) = mock().await;
    let b = backend(&rpc.uri(), SecretKey::new_random());
    let h = htlc_for(&b, [5; 32]);
    let rpc_tx = if rpc_tx.is_null() {
        lock_json(&h, 5_000, 12, Some("aa"))
    } else {
        rpc_tx
    };
    node.result("getrawtransaction", rpc_tx);
    let (cs, c) = cryptoid(cid_tx).await;
    let t = b.with_second_source(Arc::new(CryptoidObserver::new(&cs.uri(), "divi")));
    (t, h, rpc, cs, c)
}

#[tokio::test]
async fn two_sources_that_agree_give_the_lower_count() {
    let (rpc, node) = mock().await;
    let b = backend(&rpc.uri(), SecretKey::new_random());
    let h = htlc_for(&b, [5; 32]);
    node.result("getrawtransaction", lock_json(&h, 5_000, 12, Some("aa")));
    let (cs, _c) = cryptoid(Some(lock_json(&h, 5_000, 10, Some("aa")))).await;
    let t = b.with_second_source(Arc::new(CryptoidObserver::new(&cs.uri(), "divi")));
    let lo = t.htlc_output(&h, &LOCK_AT).await.unwrap().unwrap();
    assert_eq!((lo.amount, lo.confirmations), (Amount(5_000), 10));
    assert_eq!(t.confirmations(&LOCK_AT.txid).await.unwrap(), Some(10));
}

#[tokio::test]
async fn a_lock_cryptoid_does_not_know_is_no_lock() {
    let (t, h, _r, _c, _) = two_source(Value::Null, None).await;
    assert_eq!(t.htlc_output(&h, &LOCK_AT).await.unwrap(), None);
    assert_eq!(t.confirmations(&LOCK_AT.txid).await.unwrap(), None);
}

#[tokio::test]
async fn a_lock_paying_another_script_on_cryptoid_is_no_lock() {
    let (rpc, node) = mock().await;
    let b = backend(&rpc.uri(), SecretKey::new_random());
    let h = htlc_for(&b, [5; 32]);
    node.result("getrawtransaction", lock_json(&h, 5_000, 12, Some("aa")));
    let other = htlc_for(&b, [6; 32]);
    let (cs, _c) = cryptoid(Some(lock_json(&other, 5_000, 12, Some("aa")))).await;
    let t = b.with_second_source(Arc::new(CryptoidObserver::new(&cs.uri(), "divi")));
    assert_eq!(t.htlc_output(&h, &LOCK_AT).await.unwrap(), None);
}

#[tokio::test]
async fn sources_reporting_different_amounts_are_refused() {
    let (rpc, node) = mock().await;
    let b = backend(&rpc.uri(), SecretKey::new_random());
    let h = htlc_for(&b, [5; 32]);
    node.result("getrawtransaction", lock_json(&h, 9_000, 12, Some("aa")));
    let (cs, _c) = cryptoid(Some(lock_json(&h, 5_000, 12, Some("aa")))).await;
    let t = b.with_second_source(Arc::new(CryptoidObserver::new(&cs.uri(), "divi")));
    let e = t.htlc_output(&h, &LOCK_AT).await.unwrap_err();
    assert!(
        matches!(e, SwapError::Other(m) if m.contains("rpc says") && m.contains("cryptoid says"))
    );
}

#[tokio::test]
async fn sources_reporting_different_blocks_wait() {
    let (rpc, node) = mock().await;
    let b = backend(&rpc.uri(), SecretKey::new_random());
    let h = htlc_for(&b, [5; 32]);
    node.result("getrawtransaction", lock_json(&h, 5_000, 12, Some("aa")));
    let (cs, _c) = cryptoid(Some(lock_json(&h, 5_000, 12, Some("bb")))).await;
    let t = b.with_second_source(Arc::new(CryptoidObserver::new(&cs.uri(), "divi")));
    let e = t.htlc_output(&h, &LOCK_AT).await.unwrap_err();
    assert!(matches!(e, SwapError::Transient(_)), "{e:?}");
}

#[tokio::test]
async fn cryptoid_down_is_transient() {
    let (t, h, _r, _cs, c) = two_source(Value::Null, None).await;
    *c.status.lock() = 503;
    let e = t.htlc_output(&h, &LOCK_AT).await.unwrap_err();
    assert!(matches!(e, SwapError::Transient(_)), "{e:?}");
    *c.status.lock() = 429;
    let e = t.confirmations(&LOCK_AT.txid).await.unwrap_err();
    assert!(matches!(e, SwapError::Transient(_)), "{e:?}");
}

#[tokio::test]
async fn cryptoid_mtp_is_the_median_of_the_last_11_and_is_cached() {
    let (cs, _c) = cryptoid(None).await;
    let o = CryptoidObserver::new(&cs.uri(), "divi");
    // Tip 100: blocks 90..=100, times h * 60, median block 95.
    assert_eq!(o.median_time_past().await.unwrap(), 95 * 60);
    let calls = cs.received_requests().await.unwrap().len();
    assert_eq!(calls, 12);
    // Cached: no second Query API call, which would also have to wait out the 10 s gap.
    assert_eq!(o.median_time_past().await.unwrap(), 95 * 60);
    assert_eq!(cs.received_requests().await.unwrap().len(), calls);
}

#[tokio::test]
async fn two_source_mtp_is_the_later_one() {
    let (rpc, node) = mock().await;
    let b = backend(&rpc.uri(), SecretKey::new_random());
    node.result("getblockcount", json!(5))
        .result("getblockhash", json!("h"))
        .result("getblock", json!({"time": 1_000_000}));
    let (cs, _c) = cryptoid(None).await;
    let t = b.with_second_source(Arc::new(CryptoidObserver::new(&cs.uri(), "divi")));
    assert_eq!(t.median_time_past().await.unwrap(), 1_000_000);
}

/// Live: the mainnet proxy and cryptoid agree on a real mainnet tx and on the clock.
/// Run with `--ignored live_mainnet_sources_agree`.
#[tokio::test]
#[ignore = "network: services.divi.domains and chainz.cryptoid.info"]
async fn live_mainnet_sources_agree() {
    let b = DiviBackend::new(
        MAINNET_RPC,
        SecretKey::new_random(),
        Network::Mainnet,
        FeePolicy::default(),
        None,
    )
    .unwrap();
    let t = b.with_second_source(Arc::new(CryptoidObserver::mainnet()));
    // First tx of block 3,000,000.
    let txid =
        Txid::from_rpc_hex("85ffd9b4719ae59a1285c4b9bf60b0c20d0ac174932e556513fce69156cb4e99")
            .unwrap();
    let confs = t.confirmations(&txid).await.unwrap().unwrap();
    assert!(confs > 1_000_000, "{confs}");
    assert_eq!(t.confirmations(&txid_n(9)).await.unwrap(), None);
    let mtp = t.median_time_past().await.unwrap() as u64;
    let now = divi_swap::rt::unix_now();
    assert!(now.abs_diff(mtp) < 3 * 3600, "mtp {mtp} now {now}");
}
