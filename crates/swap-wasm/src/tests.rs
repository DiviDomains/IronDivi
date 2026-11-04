// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use divi_swap::api::{Direction, Quote};
use divi_swap::mock::MockChain;
use divi_swap::store::{StoreBackend, Table};
use divi_swap::{Amount, Chain, ChainBackend, HtlcParams, Store, SwapError, Taker};
use parking_lot::Mutex;

use super::*;

const SEED: [u8; 64] = [7u8; 64];
const OTHER: [u8; 64] = [9u8; 64];

#[derive(Default)]
struct MemSink {
    stored: Mutex<Vec<Entry>>,
    fail: AtomicBool,
}

#[async_trait]
impl Sink for MemSink {
    async fn persist(&self, entries: &[Entry]) -> std::result::Result<(), String> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("disk full (test)".into());
        }
        self.stored.lock().extend_from_slice(entries);
        Ok(())
    }
}

fn put(s: &EncryptedStore, id: &str, json: &str) {
    s.put(Table::TakerSwaps, id, json, None).unwrap();
}

#[test]
fn entries_are_sealed_and_reopen() {
    let s = EncryptedStore::open(&SEED, &[]).unwrap();
    put(&s, "a", r#"{"secret":"deadbeef"}"#);
    put(&s, "b", "{}");
    let entries = s.take_pending();
    assert_eq!(entries.len(), 2);
    for e in &entries {
        assert!(e.key.starts_with(s.prefix()));
        assert!(!e.ct.contains("deadbeef"));
    }
    let again = EncryptedStore::open(&SEED, &entries).unwrap();
    assert_eq!(
        again.get(Table::TakerSwaps, "a").unwrap().as_deref(),
        Some(r#"{"secret":"deadbeef"}"#)
    );
    assert_eq!(
        again.list(Table::TakerSwaps).unwrap(),
        vec!["{}", r#"{"secret":"deadbeef"}"#]
    );
    assert!(again.take_pending().is_empty());
}

#[test]
fn prefix_is_per_seed_and_hides_it() {
    let p = store_prefix(&SEED);
    assert_ne!(p, store_prefix(&OTHER));
    assert!(p.starts_with("swap:") && p.ends_with(':'));
    assert!(!p.contains(&hex::encode(&SEED[..8])));
}

#[test]
fn another_seeds_entries_are_ignored() {
    let s = EncryptedStore::open(&SEED, &[]).unwrap();
    put(&s, "a", "{}");
    let entries = s.take_pending();
    let other = EncryptedStore::open(&OTHER, &entries).unwrap();
    assert!(other.list(Table::TakerSwaps).unwrap().is_empty());
}

#[test]
fn tampered_or_moved_entries_fail_to_open() {
    let s = EncryptedStore::open(&SEED, &[]).unwrap();
    put(&s, "a", "{}");
    let good = s.take_pending().remove(0);

    let mut flipped = good.clone();
    let last = flipped.ct.pop().unwrap();
    flipped.ct.push(if last == '0' { '1' } else { '0' });
    assert!(matches!(
        EncryptedStore::open(&SEED, &[flipped]),
        Err(SwapError::Storage(_))
    ));

    let mut moved = good.clone();
    moved.key = moved.key.replace(":a", ":b");
    assert!(EncryptedStore::open(&SEED, &[moved]).is_err());

    let mut reseq = good.clone();
    reseq.seq += 1;
    assert!(EncryptedStore::open(&SEED, &[reseq]).is_err());

    let mut short = good;
    short.ct.truncate(10);
    assert!(EncryptedStore::open(&SEED, &[short]).is_err());
}

#[test]
fn upsert_keeps_list_position() {
    let s = EncryptedStore::open(&SEED, &[]).unwrap();
    put(&s, "a", "1");
    put(&s, "b", "2");
    put(&s, "a", "3");
    assert_eq!(s.list(Table::TakerSwaps).unwrap(), vec!["2", "3"]);
    // One pending entry per key, the newest.
    let pending = s.take_pending();
    assert_eq!(pending.len(), 2);
    let reopened = EncryptedStore::open(&SEED, &pending).unwrap();
    assert_eq!(reopened.list(Table::TakerSwaps).unwrap(), vec!["2", "3"]);
}

#[test]
fn requeue_never_resurrects_an_older_write() {
    let s = EncryptedStore::open(&SEED, &[]).unwrap();
    put(&s, "a", "old");
    put(&s, "b", "only");
    let first = s.take_pending();
    put(&s, "a", "new");
    s.requeue(first);
    let pending = s.take_pending();
    assert_eq!(pending.len(), 2);
    let reopened = EncryptedStore::open(&SEED, &pending).unwrap();
    assert_eq!(
        reopened.get(Table::TakerSwaps, "a").unwrap().as_deref(),
        Some("new")
    );
    assert_eq!(
        reopened.get(Table::TakerSwaps, "b").unwrap().as_deref(),
        Some("only")
    );
}

fn htlc(claim: [u8; 33], refund: [u8; 33]) -> HtlcParams {
    HtlcParams {
        hash: [1; 32],
        claim_pubkey: claim,
        refund_pubkey: refund,
        locktime: 1_800_000_000,
        script_version: divi_swap::ScriptVersion::V1,
    }
}

#[tokio::test]
async fn no_broadcast_until_the_secret_is_stored() {
    let chain = MockChain::new(Chain::Btc, 1_700_000_000, 600);
    let mine = chain.backend(2, Amount::from_sat(1_000_000));
    let theirs = chain.backend(3, Amount::from_sat(0));
    let start = chain.balance(&mine.pubkey());

    let store = Arc::new(EncryptedStore::open(&SEED, &[]).unwrap());
    let sink = Arc::new(MemSink::default());
    let persister = Arc::new(Persister::new(store.clone(), None, sink.clone()));
    let durable = Durable::new(Arc::new(mine.clone()), persister);

    let funding = durable
        .build_funding(
            &htlc(theirs.pubkey(), mine.pubkey()),
            Amount::from_sat(100_000),
        )
        .await
        .unwrap();
    put(&store, "swap", r#"{"preimage":"secret"}"#);

    sink.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        durable.broadcast(&funding.tx).await,
        Err(SwapError::Storage(_))
    ));
    assert_eq!(chain.balance(&mine.pubkey()), start, "coins moved unsaved");
    assert!(sink.stored.lock().is_empty());

    sink.fail.store(false, Ordering::SeqCst);
    durable.broadcast(&funding.tx).await.unwrap();
    assert!(chain.balance(&mine.pubkey()) < start);
    let stored = sink.stored.lock().clone();
    assert_eq!(stored.len(), 1);
    let reopened = EncryptedStore::open(&SEED, &stored).unwrap();
    assert!(reopened.get(Table::TakerSwaps, "swap").unwrap().is_some());
}

fn quote() -> Quote {
    Quote {
        id: "q1".into(),
        offer_id: "divi-btc-testnet".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        btc_amount: Amount::from_sat(10_000),
        divi_amount: Amount::from_sat(1_000_000_000),
        expires_at: u64::MAX,
        maker_btc_pubkey: [2; 33],
        maker_divi_pubkey: [3; 33],
        taker_timeout_secs: 7200,
        maker_timeout_secs: 3600,
        btc_confirmations: 1,
        divi_confirmations: 1,
    }
}

#[tokio::test]
async fn summary_never_carries_the_preimage() {
    let divi = MockChain::new(Chain::Divi, 1_700_000_000, 60);
    let btc = MockChain::new(Chain::Btc, 1_700_000_000, 600);
    let store = Store::in_memory().unwrap();
    let taker = Taker::with_counters(
        Arc::new(divi.backend(4, Amount::from_sat(0))),
        vec![Arc::new(btc.backend(5, Amount::from_sat(1_000_000)))],
        store.clone(),
    );
    let (id, _) = taker.prepare(&quote()).await.unwrap();
    let rec = store.get_taker_swap(&id).unwrap().unwrap();
    let json = serde_json::to_string(&SwapSummary::from(&rec)).unwrap();
    assert!(!json.contains("preimage"));
    assert!(!json.contains(&hex::encode(rec.preimage)));
    assert!(json.contains(r#""state":"prepared""#));
}

#[test]
fn seed_buffer_is_zeroized_after_engine_derives_keys_and_drops() {
    use zeroize::{Zeroize, Zeroizing};

    let mut stack_seed = SEED;
    let raw_buf = stack_seed.to_vec();
    let ptr = raw_buf.as_ptr();
    let cfg = Config {
        maker_url: "https://divi.cx/swap".into(),
        divi_rpc: "http://127.0.0.1:51475".into(),
        btc_endpoints: vec!["https://blockstream.info/testnet/api".into()],
        ltc_endpoints: vec!["https://litecoinspace.org/testnet/api".into()],
        index: 0,
    };
    let (addrs, prefix) = {
        let seed = Zeroizing::new(raw_buf);
        assert_eq!(seed.as_ptr(), ptr);
        let store = Arc::new(EncryptedStore::open(&seed, &[]).unwrap());
        let prefix = store.prefix().to_string();
        let sink: Arc<dyn Sink> = Arc::new(MemSink::default());
        let engine = Engine::new(&seed, &cfg, store, sink).unwrap();
        let addrs = engine.addresses().clone();
        drop(engine);
        (addrs, prefix)
    };
    stack_seed.zeroize();
    assert_eq!(stack_seed, [0u8; 64]);
    assert!(addrs.divi.starts_with(['x', 'y']), "{}", addrs.divi);
    assert!(addrs.btc.starts_with("tb1q"));
    assert!(addrs.ltc.starts_with("tltc1q"));
    assert!(prefix.starts_with("swap:"));
}

#[tokio::test]
async fn tick_refunds_locked_swap_when_maker_aborted_without_taker_outpoint() {
    use divi_swap::api::{LegView, SwapView};
    use divi_swap::{SwapState, TakerState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let now = divi_swap::rt::unix_now() as u32;
    let divi = MockChain::new(Chain::Divi, now - 10_000, 60);
    let btc = MockChain::new(Chain::Btc, now - 10_000, 600);
    let divi_b = Arc::new(divi.backend(11, Amount::from_sat(0)));
    let btc_b = Arc::new(btc.backend(12, Amount::from_sat(1_000_000)));

    let mut q = quote();
    q.taker_timeout_secs = 3_600;
    q.maker_timeout_secs = 1_800;
    q.maker_btc_pubkey = [2; 33];
    q.maker_divi_pubkey = [3; 33];

    let store_enc = Arc::new(EncryptedStore::open(&SEED, &[]).unwrap());
    let sink: Arc<dyn Sink> = Arc::new(MemSink::default());
    let persister = Arc::new(Persister::new(store_enc.clone(), None, sink));
    let swaps = Store::with_backend(store_enc);
    let taker = Taker::with_counters(divi_b, vec![btc_b.clone()], swaps.clone());

    let (id, _) = taker.prepare(&q).await.unwrap();
    let rec = swaps.get_taker_swap(&id).unwrap().unwrap();
    let mtp = btc_b.median_time_past().await.unwrap();
    let locktime = mtp + q.taker_timeout_secs;
    let taker_htlc = HtlcParams {
        hash: rec.hash,
        claim_pubkey: q.maker_btc_pubkey,
        refund_pubkey: btc_b.pubkey(),
        locktime,
        script_version: divi_swap::ScriptVersion::V1,
    };
    let accepted_view = SwapView {
        id: "m1".into(),
        state: SwapState::Accepted,
        quote: q.clone(),
        taker_leg: LegView {
            htlc: taker_htlc,
            amount: q.btc_amount,
            outpoint: None,
            spend_txid: None,
        },
        maker_leg: None,
        preimage: None,
        last_error: None,
        maker_mtp_at_lock: None,
    };
    taker.accepted(&id, &accepted_view).await.unwrap();
    taker.lock(&id).await.unwrap();
    btc.mine(1);

    // Advance chain MTP past taker_locktime AND past the current wall clock? Wait:
    // `Engine::tick` checks `rt::unix_now() < h.locktime`, and here `locktime = (now - 10_000) + 3_600 = now - 6_400`,
    // so `rt::unix_now() >= locktime` AND mining 10 blocks advances MockChain MTP past `locktime`!
    btc.mine(10);

    let aborted_body = serde_json::to_string(&SwapView {
        state: SwapState::Aborted,
        ..accepted_view
    })
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = aborted_body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let resp = if req.starts_with("GET /swaps/m1 ") {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 409 Conflict\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"error\":\"aborted\"}".to_string()
                };
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });

    let dummy_divi = Arc::new(
        swap_chain_divi::DiviBackend::new(
            "http://127.0.0.1:9",
            divi_crypto::SecretKey::new_random(),
            divi_wallet::Network::Testnet,
            swap_chain_divi::FeePolicy::default(),
            None,
        )
        .unwrap(),
    );
    let engine = Engine::from_parts(
        taker,
        MakerClient::new(&format!("http://{addr}")).unwrap(),
        swaps,
        persister,
        dummy_divi,
        Addresses {
            divi: "yTest".into(),
            btc: "tb1qtest".into(),
            ltc: "tltc1qtest".into(),
        },
    );

    let after_first = engine.tick().await.unwrap();
    assert_eq!(after_first[0].state, TakerState::Refunded);
    assert!(after_first[0].refund_txid.is_some());

    btc.mine(2);
    let after_confirm = engine.tick().await.unwrap();
    assert_eq!(after_confirm[0].state, TakerState::Done);
    assert!(after_confirm[0].refund_txid.is_some());
}

#[tokio::test]
async fn begin_persists_swap_token_encrypted_and_sends_it_after_reopen() {
    use divi_swap::api::{AcceptReply, AcceptRequest, LegView, SwapView};
    use divi_swap::{SwapState, TakerState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let now = divi_swap::rt::unix_now() as u32;
    let divi = MockChain::new(Chain::Divi, now, 60);
    let btc = MockChain::new(Chain::Btc, now, 600);
    let divi_b = Arc::new(divi.backend(21, Amount::from_sat(0)));
    let btc_b = Arc::new(btc.backend(22, Amount::from_sat(1_000_000)));
    let btc_pub = btc_b.pubkey();

    let mut q = quote();
    q.taker_timeout_secs = 7_200;
    q.maker_timeout_secs = 3_600;
    let q_for_srv = q.clone();
    let secret_token = "tok_secret_64hex_deadbeefcafebabe0123456789abcdef";
    let saw_support = Arc::new(AtomicBool::new(false));
    let saw_lock_tok = Arc::new(AtomicBool::new(false));
    let saw_get_tok = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (s_sup, s_lock, s_get) = (
        saw_support.clone(),
        saw_lock_tok.clone(),
        saw_get_tok.clone(),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let q = q_for_srv.clone();
            let (s_sup, s_lock, s_get) = (s_sup.clone(), s_lock.clone(), s_get.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let lower = req.to_ascii_lowercase();
                let (status, body) = if req.starts_with("GET /offers/divi-btc-testnet/quote") {
                    ("200 OK", serde_json::to_string(&q).unwrap())
                } else if req.starts_with("POST /swaps ") {
                    if lower.contains("x-swap-token-support: 1") {
                        s_sup.store(true, Ordering::SeqCst);
                    }
                    let json_body = req.split("\r\n\r\n").nth(1).unwrap_or("{}");
                    let ar: AcceptRequest = serde_json::from_str(json_body).unwrap();
                    let reply = AcceptReply {
                        view: SwapView {
                            id: "m-tok".into(),
                            state: SwapState::Accepted,
                            quote: q.clone(),
                            taker_leg: LegView {
                                htlc: HtlcParams {
                                    hash: ar.hash,
                                    claim_pubkey: q.maker_btc_pubkey,
                                    refund_pubkey: btc_pub,
                                    locktime: now + q.taker_timeout_secs,
                                    script_version: divi_swap::ScriptVersion::V1,
                                },
                                amount: q.btc_amount,
                                outpoint: None,
                                spend_txid: None,
                            },
                            maker_leg: None,
                            preimage: None,
                            last_error: None,
                            maker_mtp_at_lock: None,
                        },
                        swap_token: Some(secret_token.into()),
                    };
                    ("201 Created", serde_json::to_string(&reply).unwrap())
                } else if req.starts_with("POST /swaps/m-tok/lock ") {
                    if lower.contains(&format!("x-swap-token: {secret_token}")) {
                        s_lock.store(true, Ordering::SeqCst);
                        let view = SwapView {
                            id: "m-tok".into(),
                            state: SwapState::TakerLockSeen,
                            quote: q.clone(),
                            taker_leg: LegView {
                                htlc: HtlcParams {
                                    hash: [1; 32],
                                    claim_pubkey: q.maker_btc_pubkey,
                                    refund_pubkey: btc_pub,
                                    locktime: now + q.taker_timeout_secs,
                                    script_version: divi_swap::ScriptVersion::V1,
                                },
                                amount: q.btc_amount,
                                outpoint: None,
                                spend_txid: None,
                            },
                            maker_leg: None,
                            preimage: None,
                            last_error: None,
                            maker_mtp_at_lock: None,
                        };
                        ("200 OK", serde_json::to_string(&view).unwrap())
                    } else {
                        ("404 Not Found", "{\"error\":\"missing token\"}".into())
                    }
                } else if req.starts_with("GET /swaps/m-tok ") {
                    if lower.contains(&format!("x-swap-token: {secret_token}")) {
                        s_get.store(true, Ordering::SeqCst);
                    }
                    ("404 Not Found", "{\"error\":\"done checking\"}".into())
                } else {
                    ("404 Not Found", "{}".into())
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });

    let sink = Arc::new(MemSink::default());
    let make_engine = |entries: &[Entry], sink: Arc<MemSink>| {
        let store_enc = Arc::new(EncryptedStore::open(&SEED, entries).unwrap());
        let sink_dyn: Arc<dyn Sink> = sink;
        let persister = Arc::new(Persister::new(store_enc.clone(), None, sink_dyn));
        let swaps = Store::with_backend(store_enc);
        let taker = Taker::with_counters(divi_b.clone(), vec![btc_b.clone()], swaps.clone());
        let dummy_divi = Arc::new(
            swap_chain_divi::DiviBackend::new(
                "http://127.0.0.1:9",
                divi_crypto::SecretKey::new_random(),
                divi_wallet::Network::Testnet,
                swap_chain_divi::FeePolicy::default(),
                None,
            )
            .unwrap(),
        );
        Engine::from_parts(
            taker,
            MakerClient::new(&format!("http://{addr}")).unwrap(),
            swaps,
            persister,
            dummy_divi,
            Addresses {
                divi: "yTest".into(),
                btc: "tb1qtest".into(),
                ltc: "tltc1qtest".into(),
            },
        )
    };

    let engine1 = make_engine(&[], sink.clone());
    let begun = engine1.begin("divi-btc-testnet", 10_000).await.unwrap();
    assert_eq!(begun.state, TakerState::Accepted);
    assert!(saw_support.load(Ordering::SeqCst));

    // Snapshot entries as persisted to chrome.storage.local (dedup newest per key).
    let mut snapshot_map = std::collections::BTreeMap::new();
    for e in sink.stored.lock().iter() {
        assert!(!e.ct.contains(secret_token), "token leaked in ciphertext");
        assert!(!e.key.contains(secret_token), "token leaked in key");
        snapshot_map.insert(e.key.clone(), e.clone());
    }
    let snapshot: Vec<Entry> = snapshot_map.into_values().collect();

    // Reopen in a fresh Engine (simulating browser close + reopen) and verify lock + tick send token.
    let engine2 = make_engine(&snapshot, Arc::new(MemSink::default()));
    let locked = engine2.lock(&begun.id).await.unwrap();
    assert_eq!(locked.state, TakerState::Locked);
    assert!(saw_lock_tok.load(Ordering::SeqCst));

    engine2.tick().await.unwrap();
    assert!(saw_get_tok.load(Ordering::SeqCst));
}
