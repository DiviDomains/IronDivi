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
        profile: divi_swap::Profile::Testnet,
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
    )
    .unwrap();

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
    // `begin` refuses a quote expiring implausibly far ahead (`MAX_QUOTE_TTL_SECS`).
    q.expires_at = now as u64 + 60;
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
                let (status, body) = if req.starts_with("GET /offers HTTP/") {
                    (
                        "200 OK",
                        serde_json::to_string(&[selected_offer()]).unwrap(),
                    )
                } else if req.starts_with("GET /offers/divi-btc-testnet/quote") {
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
        .unwrap()
    };

    let engine1 = make_engine(&[], sink.clone());
    let shown = engine1.offers().await.unwrap();
    let begun = engine1
        .begin_selected(&pick(&shown[0], "10000"))
        .await
        .unwrap();
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
    // Selections do not survive the restart, so no new swap starts from the old listing ...
    let err = engine2
        .begin_selected(&pick(&shown[0], "10000"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("selection missing"), "{err}");
    // ... but the swap already begun resumes from the sealed store.
    let locked = engine2.lock(&begun.id).await.unwrap();
    assert_eq!(locked.state, TakerState::Locked);
    assert!(saw_lock_tok.load(Ordering::SeqCst));

    engine2.tick().await.unwrap();
    assert!(saw_get_tok.load(Ordering::SeqCst));
}

/// The offer the maker lists: 10_000 sats of BTC buys 1e9 DIVI sats.
fn selected_offer() -> divi_swap::api::Offer {
    divi_swap::api::Offer {
        id: "divi-btc-testnet".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: 10_000_000_000_000,
        min_btc_sats: 1_000,
        max_btc_sats: 1_000_000,
    }
}

/// [`quote`] on terms the testnet floor accepts, live for a minute.
fn testnet_quote() -> Quote {
    Quote {
        expires_at: divi_swap::rt::unix_now() + 60,
        taker_timeout_secs: 6 * 3600,
        maker_timeout_secs: 3 * 3600,
        divi_confirmations: 3,
        ..quote()
    }
}

type Quoting = (Engine, Arc<std::sync::atomic::AtomicUsize>, Arc<MemSink>);

/// An engine (no profile floor) whose maker lists [`selected_offer`], answers every quote
/// request with `q` and counts (then refuses) `POST /swaps`. Returns the engine, that
/// counter and the host sink.
async fn engine_quoting(q: Quote) -> Quoting {
    engine_quoting_on(None, q).await
}

/// [`engine_quoting`] with the taker under `floor`, as [`Engine::new`] builds it.
async fn engine_quoting_on(floor: Option<divi_swap::Profile>, q: Quote) -> Quoting {
    engine_listing(floor, Arc::new(Mutex::new(vec![selected_offer()])), q).await
}

/// [`engine_quoting_on`] with a maker whose `GET /offers` answers whatever `listing` holds
/// at the time of each request.
async fn engine_listing(
    floor: Option<divi_swap::Profile>,
    listing: Arc<Mutex<Vec<divi_swap::api::Offer>>>,
    q: Quote,
) -> Quoting {
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let accepts = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = serde_json::to_string(&q).unwrap();
    let seen = accepts.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let (status, body) = if req.starts_with("GET /offers HTTP/") {
                ("200 OK", serde_json::to_string(&*listing.lock()).unwrap())
            } else if req.starts_with("GET /offers/") {
                ("200 OK", body.clone())
            } else {
                if req.starts_with("POST /swaps ") {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
                ("418 I'm a teapot", "{}".to_string())
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });

    let divi = MockChain::new(Chain::Divi, 1_700_000_000, 60);
    let btc = MockChain::new(Chain::Btc, 1_700_000_000, 600);
    let store_enc = Arc::new(EncryptedStore::open(&SEED, &[]).unwrap());
    let sink = Arc::new(MemSink::default());
    let sink_dyn: Arc<dyn Sink> = sink.clone();
    let persister = Arc::new(Persister::new(store_enc.clone(), None, sink_dyn));
    let swaps = Store::with_backend(store_enc);
    let taker = Taker::with_counters(
        Arc::new(divi.backend(31, Amount::from_sat(0))),
        vec![Arc::new(btc.backend(32, Amount::from_sat(1_000_000)))],
        swaps.clone(),
    );
    let taker = match floor {
        Some(p) => taker.with_profile_floor(p),
        None => taker,
    };
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
    )
    .unwrap();
    (engine, accepts, sink)
}

/// Nothing reached `POST /swaps`, recorded a swap or persisted.
fn untouched(e: &Quoting, why: &str) {
    let (engine, accepts, sink) = e;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "{why}: reached POST /swaps"
    );
    assert!(engine.swaps().unwrap().is_empty(), "{why}: swap recorded");
    assert!(sink.stored.lock().is_empty(), "{why}: persisted");
}

fn selected() -> divi_swap::QuoteIntent {
    divi_swap::QuoteIntent::for_offer(&selected_offer(), 10_000).unwrap()
}

/// What the UI sends for `btc_sats` on `shown`: its token and its displayed decimal terms,
/// through the same JSON the binding parses.
fn pick(shown: &crate::engine::OfferView, btc_sats: &str) -> SelectionSpec {
    let token = shown.selection.clone().expect("a selectable offer");
    pick_with(shown, &token, btc_sats)
}

fn pick_with(shown: &crate::engine::OfferView, token: &str, btc_sats: &str) -> SelectionSpec {
    SelectionSpec::parse(&spec_json(shown, token, btc_sats).to_string()).unwrap()
}

fn spec_json(shown: &crate::engine::OfferView, token: &str, btc_sats: &str) -> serde_json::Value {
    serde_json::json!({
        "selection": token,
        "offer_id": shown.offer.id,
        "direction": shown.offer.direction,
        "counter_chain": shown.offer.counter_chain,
        "divi_sats_per_btc": shown.exact.divi_sats_per_btc,
        "min_btc_sats": shown.exact.min_btc_sats,
        "max_btc_sats": shown.exact.max_btc_sats,
        "btc_sats": btc_sats,
    })
}

#[tokio::test]
async fn begin_refuses_a_quote_off_the_intent_before_persisting_or_accepting() {
    use divi_swap::QuoteIntent;

    let honest = testnet_quote();
    let mut other_amount = honest.clone();
    other_amount.btc_amount = Amount::from_sat(20_000);
    let mut ltc = honest.clone();
    ltc.counter_chain = Chain::Ltc;
    let mut flipped = honest.clone();
    flipped.direction = Direction::TakerPaysDivi;
    let mut cheap = honest.clone();
    cheap.divi_amount = Amount::from_sat(999_999_999);
    let mut stale = honest.clone();
    stale.expires_at = divi_swap::rt::unix_now() + 5;
    let mut forever = honest.clone();
    forever.expires_at = u64::MAX;
    let mut zero_conf = honest.clone();
    zero_conf.btc_confirmations = 0;
    // Twice the offered 1e13 DIVI sats per BTC.
    let buying_dear = selected().stricter_price(20_000_000_000_000).unwrap();
    let on_ltc = QuoteIntent {
        counter_chain: Chain::Ltc,
        ..selected()
    };

    for (q, intent, want) in [
        (other_amount, selected(), "not the 10000 asked for"),
        (ltc, selected(), "on ltc, not btc"),
        (flipped, selected(), "direction"),
        (cheap, selected(), "below the 1000000000 agreed"),
        (honest.clone(), buying_dear, "below the 2000000000 agreed"),
        (stale, selected(), "margin required to commit"),
        (forever, selected(), "check the clocks"),
        (zero_conf, selected(), "btc_confirmations 0"),
        (honest.clone(), on_ltc, "no key for ltc"),
    ] {
        let e = engine_quoting(q).await;
        let err = e.0.begin_with_intent(&intent).await.unwrap_err();
        assert!(err.to_string().contains(want), "{want}: {err}");
        untouched(&e, want);
    }

    // The same honest quote under its intent goes on to accept.
    let (engine, accepts, _) = engine_quoting(honest).await;
    let e = engine.begin_with_intent(&selected()).await.unwrap_err();
    assert!(e.to_string().contains("418"), "{e}");
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(engine.swaps().unwrap().len(), 1);
}

#[tokio::test]
async fn the_default_begin_is_bound_to_the_offer_shown() {
    use divi_swap::Profile;

    // Shown, then repriced by the maker before the quote: refused.
    let mut repriced = testnet_quote();
    repriced.divi_amount = Amount::from_sat(900_000_000);
    let e = engine_quoting_on(Some(Profile::Testnet), repriced).await;
    let shown = e.0.offers().await.unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].exact.divi_sats_per_btc, "10000000000000");
    assert!(!shown[0].ambiguous);
    let err =
        e.0.begin_selected(&pick(&shown[0], "10000"))
            .await
            .unwrap_err();
    assert!(
        err.to_string().contains("below the 1000000000 agreed"),
        "{err}"
    );
    untouched(&e, "repriced");
    // Outside the shown range: refused before a quote.
    let err =
        e.0.begin_selected(&pick(&shown[0], "999"))
            .await
            .unwrap_err();
    assert!(err.to_string().contains("outside offer"), "{err}");
    untouched(&e, "range");

    // Shown and quoted as shown: on to accept.
    let (engine, accepts, _) = engine_quoting_on(Some(Profile::Testnet), testnet_quote()).await;
    let shown = engine.offers().await.unwrap();
    let err = engine
        .begin_selected(&pick(&shown[0], "10000"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("418"), "{err}");
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

/// Another view (or a refresh) lists the same id at new terms. The selection the user made
/// keeps the terms it was shown: the maker's quote at the new price is refused, and mixing
/// the old token with the new terms is refused too.
#[tokio::test]
async fn a_refresh_never_changes_the_terms_a_selection_pins() {
    use divi_swap::Profile;

    let listing = Arc::new(Mutex::new(vec![selected_offer()]));
    // The maker now quotes half the DIVI: what the refreshed listing advertises.
    let mut halved = testnet_quote();
    halved.divi_amount = Amount::from_sat(500_000_000);
    let e = engine_listing(Some(Profile::Testnet), listing.clone(), halved).await;

    let first = e.0.offers().await.unwrap();
    listing.lock()[0].divi_sats_per_btc = 5_000_000_000_000;
    let second = e.0.offers().await.unwrap();
    assert_eq!(second[0].exact.divi_sats_per_btc, "5000000000000");
    assert_ne!(first[0].selection, second[0].selection);

    let err =
        e.0.begin_selected(&pick(&first[0], "10000"))
            .await
            .unwrap_err();
    assert!(
        err.to_string().contains("below the 1000000000 agreed"),
        "{err}"
    );
    untouched(&e, "refreshed terms behind the user's selection");

    let old_token = first[0].selection.clone().unwrap();
    let err =
        e.0.begin_selected(&pick_with(&second[0], &old_token, "10000"))
            .await
            .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match the terms shown: price"),
        "{err}"
    );
    untouched(&e, "old token, new terms");

    // Selecting the refreshed offer the user now sees goes on to accept.
    let err =
        e.0.begin_selected(&pick(&second[0], "10000"))
            .await
            .unwrap_err();
    assert!(err.to_string().contains("418"), "{err}");
    assert_eq!(e.1.load(Ordering::SeqCst), 1);
}

/// The quote endpoint is keyed by id alone, so an id the maker lists twice (on any chain)
/// is refused, never resolved to one of the listings.
#[tokio::test]
async fn a_duplicate_offer_id_is_refused_not_guessed() {
    use divi_swap::Profile;

    let listing = Arc::new(Mutex::new(vec![selected_offer()]));
    let e = engine_listing(Some(Profile::Testnet), listing.clone(), testnet_quote()).await;
    let first = e.0.offers().await.unwrap();

    // A duplicate on a chain this taker has no key on is still a duplicate.
    let mut on_ltc = selected_offer();
    on_ltc.counter_chain = Chain::Ltc;
    listing.lock().push(on_ltc);
    let second = e.0.offers().await.unwrap();
    assert_eq!(second.len(), 1);
    assert!(second[0].ambiguous && second[0].selection.is_none());
    let err =
        e.0.begin_selected(&pick(&first[0], "10000"))
            .await
            .unwrap_err();
    assert!(err.to_string().contains("ambiguous"), "{err}");
    untouched(&e, "duplicate on another chain");

    // Two listings of one id on one chain at different prices: neither is selectable.
    let mut dear = selected_offer();
    dear.divi_sats_per_btc = 1;
    *listing.lock() = vec![selected_offer(), dear];
    let third = e.0.offers().await.unwrap();
    assert_eq!(third.len(), 2);
    assert!(third.iter().all(|v| v.ambiguous && v.selection.is_none()));
    let err =
        e.0.begin_selected(&pick(&first[0], "10000"))
            .await
            .unwrap_err();
    assert!(err.to_string().contains("ambiguous"), "{err}");
    untouched(&e, "duplicate on one chain");

    // Once the maker lists the id once again, a fresh look makes it selectable.
    *listing.lock() = vec![selected_offer()];
    let fourth = e.0.offers().await.unwrap();
    assert_ne!(fourth[0].selection, first[0].selection);
    let err =
        e.0.begin_selected(&pick(&fourth[0], "10000"))
            .await
            .unwrap_err();
    assert!(err.to_string().contains("418"), "{err}");
    assert_eq!(e.1.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_missing_stale_or_inexact_selection_is_refused() {
    use crate::selection::SELECTION_TTL_SECS;
    use divi_swap::Profile;

    let e = engine_quoting_on(Some(Profile::Testnet), testnet_quote()).await;
    // Never listed in this engine (a restarted worker, a re-unlocked wallet).
    let other = engine_quoting_on(Some(Profile::Testnet), testnet_quote()).await;
    let elsewhere = other.0.offers().await.unwrap();
    let err =
        e.0.begin_selected(&pick(&elsewhere[0], "10000"))
            .await
            .unwrap_err();
    assert!(err.to_string().contains("selection missing"), "{err}");
    untouched(&e, "missing");

    let shown = e.0.offers().await.unwrap();
    let token = shown[0].selection.clone().unwrap();
    // Displayed amounts must be canonical decimals and match exactly.
    for (key, value, want) in [
        ("btc_sats", "010000", "not a decimal amount"),
        ("btc_sats", "10000.0", "not a decimal amount"),
        ("divi_sats_per_btc", "1e13", "not a decimal amount"),
        ("min_btc_sats", "1001", "minimum differs"),
        ("max_btc_sats", "999999", "maximum differs"),
        ("direction", "taker_pays_divi", "direction differs"),
        ("offer_id", "other", "offer id differs"),
    ] {
        let mut j = spec_json(&shown[0], &token, "10000");
        j[key] = serde_json::json!(value);
        let err = match SelectionSpec::parse(&j.to_string()) {
            Ok(spec) => e.0.begin_selected(&spec).await.unwrap_err(),
            Err(err) => err,
        };
        assert!(err.to_string().contains(want), "{key}={value}: {err}");
        untouched(&e, want);
    }
    // A number where a decimal string is required, or an unknown key.
    let mut j = spec_json(&shown[0], &token, "10000");
    j["btc_sats"] = serde_json::json!(10_000);
    assert!(SelectionSpec::parse(&j.to_string()).is_err());
    let mut j = spec_json(&shown[0], &token, "10000");
    j["offerId"] = serde_json::json!("divi-btc-testnet");
    assert!(SelectionSpec::parse(&j.to_string()).is_err());

    e.0.age_selections(SELECTION_TTL_SECS + 1);
    let err =
        e.0.begin_selected(&pick(&shown[0], "10000"))
            .await
            .unwrap_err();
    assert!(err.to_string().contains("stale"), "{err}");
    untouched(&e, "stale");
    let refreshed = e.0.offers().await.unwrap();
    assert_ne!(refreshed[0].selection, shown[0].selection);
    assert!(e.0.begin_selected(&pick(&shown[0], "10000")).await.is_err());
    untouched(&e, "refresh must not revive an expired selection");
}

#[tokio::test]
async fn the_profile_floor_holds_the_htlc_timing_before_prepare() {
    use divi_swap::Profile;

    let mut deep = testnet_quote();
    deep.btc_confirmations = 13; // 10800 + 1800 + 13 × 600 + 1800 > 21600
    let mut long = testnet_quote();
    long.taker_timeout_secs = 12 * 3600 + 1;
    for (floor, q, want) in [
        (Profile::Testnet, quote(), "floor"), // 2 h / 1 h: under the testnet floor
        (Profile::Testnet, deep, "maker would refuse to lock"),
        (Profile::Testnet, long, "ceiling"),
        (Profile::Mainnet, testnet_quote(), "floor"),
    ] {
        let mut q = q;
        q.expires_at = divi_swap::rt::unix_now() + 60;
        let e = engine_quoting_on(Some(floor), q).await;
        let err = e.0.begin_with_intent(&selected()).await.unwrap_err();
        assert!(err.to_string().contains(want), "{floor} {want}: {err}");
        untouched(&e, want);
    }
    let mut twelve = testnet_quote();
    twelve.btc_confirmations = 12;
    let (engine, accepts, _) = engine_quoting_on(Some(Profile::Testnet), twelve).await;
    let err = engine.begin_with_intent(&selected()).await.unwrap_err();
    assert!(err.to_string().contains("418"), "{err}");
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

#[test]
fn the_configured_profile_is_the_engines_floor() {
    let base = r#""maker_url":"https://divi.cx/swap","divi_rpc":"http://127.0.0.1:51475",
        "btc_endpoints":["https://blockstream.info/testnet/api"],
        "ltc_endpoints":["https://litecoinspace.org/testnet/api"]"#;
    for (extra, want) in [
        ("", divi_swap::Profile::Testnet),
        (r#","profile":"testnet""#, divi_swap::Profile::Testnet),
        (r#","profile":"mainnet""#, divi_swap::Profile::Mainnet),
    ] {
        let cfg: Config = serde_json::from_str(&format!("{{{base}{extra}}}")).unwrap();
        let store = Arc::new(EncryptedStore::open(&SEED, &[]).unwrap());
        let sink: Arc<dyn Sink> = Arc::new(MemSink::default());
        let engine = Engine::new(&SEED, &cfg, store, sink).unwrap();
        assert_eq!(engine.profile_floor(), Some(want), "{extra}");
    }
    assert!(serde_json::from_str::<Config>(&format!("{{{base},\"profile\":\"none\"}}")).is_err());
}

#[test]
fn intent_json_takes_exact_amounts_only() {
    use crate::engine::{exact_u64, IntentSpec, MAX_SAFE_JS_INTEGER};
    use divi_swap::QuoteIntent;
    use serde_json::json;

    let spec = |btc: serde_json::Value, limit: serde_json::Value| {
        json!({
            "offer_id": "divi-btc-testnet",
            "btc_sats": btc,
            "counter_chain": "btc",
            "direction": "taker_pays_btc",
            "limit_divi_sats_per_btc": limit,
        })
    };
    // A price past 2^53 survives as a string.
    let big = "18446744073709551615";
    let i = IntentSpec::parse(&spec(json!(1), json!(big)).to_string()).unwrap();
    assert_eq!(
        i,
        QuoteIntent::with_limit(
            "divi-btc-testnet",
            1,
            Chain::Btc,
            Direction::TakerPaysBtc,
            u64::MAX
        )
        .unwrap()
    );
    assert_eq!(
        IntentSpec::parse(&spec(json!("10000"), json!(10_000_000_000_000u64)).to_string()).unwrap(),
        selected()
    );
    for bad in [
        json!(MAX_SAFE_JS_INTEGER + 1),
        json!(1.5),
        json!(-1),
        json!("1e3"),
        json!("-1"),
        json!(" 1"),
        json!(""),
        json!("18446744073709551616"),
        json!(null),
    ] {
        assert!(exact_u64("x", &bad).is_err(), "{bad}");
        assert!(
            IntentSpec::parse(&spec(json!(10_000), bad.clone()).to_string()).is_err(),
            "{bad}"
        );
    }
    assert_eq!(
        exact_u64("x", &json!(MAX_SAFE_JS_INTEGER)).unwrap(),
        MAX_SAFE_JS_INTEGER
    );

    // Every term is required, and nothing else is accepted.
    let mut missing = spec(json!(10_000), json!("1"));
    missing
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "direction");
    assert!(IntentSpec::parse(&missing.to_string()).is_err());
    let mut extra = spec(json!(10_000), json!("1"));
    extra["limit"] = json!(1);
    assert!(IntentSpec::parse(&extra.to_string()).is_err());
    let mut opts = spec(json!(10_000), json!("10000000000000"));
    opts["min_remaining_secs"] = json!("30");
    opts["max_taker_timeout_secs"] = json!(30_000);
    let i = IntentSpec::parse(&opts.to_string()).unwrap();
    assert_eq!(
        (i.min_remaining_secs, i.max_taker_timeout_secs),
        (30, Some(30_000))
    );
}
