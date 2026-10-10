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
}

impl Respond for Node {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let m = body["method"].as_str().unwrap_or("").to_string();
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
