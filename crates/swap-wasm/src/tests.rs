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
