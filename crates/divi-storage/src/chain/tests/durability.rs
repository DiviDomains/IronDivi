// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! C3: UTXO cache/flush ownership and crash ordering.
//!
//! The durable UTXO set never lives only in the in-memory cache. Every mutating
//! path writes through to RocksDB in one atomic `WriteBatch` together with the
//! tip, undo data and the address/spent indexes (`atomic_connect_block` /
//! `atomic_disconnect_block`), and the direct writers (`add_utxo`,
//! `remove_utxo`, `flush_utxo_batch`) write to the database before they touch
//! the cache. The `UtxoCache` dirty set and `flush_utxo_cache` therefore only
//! re-write values the database already holds: a failed flush that is retried,
//! and a crash between a connect and the next flush, cannot move the on-disk
//! UTXO digest or tip away from a clean replay.
//!
//! (C3 correction: the cache is now a coherent write-through cache: writers
//! update it in the same serialized step as their database write and a
//! cache-miss read is cached only if no write can have made it stale, so
//! `ChainDatabase` never has dirty entries; see `utxo_cache`.)
//!
//! These tests prove that invariant by comparing the UTXO digest
//! (`get_utxo_stats().hash_serialized`, which hashes the best block and every
//! coin, read from a RocksDB snapshot that bypasses the cache), the active tip,
//! and the address index against a clean replay, across:
//!   1. connected blocks leaving nothing dirty, and concurrent readers,
//!   2. a crash right after a block's atomic write but before the next flush,
//!   3. a clean replay with the cache disabled (ownership).

use super::*;
use crate::fault;
use crate::search_index::SearchIndex;
use std::path::Path;

const CACHE_ENTRIES: u64 = 1_000_000;

fn open_cached(path: &Path) -> Chain {
    let db =
        Arc::new(ChainDatabase::open_with_utxo_cache(path.join("chain"), CACHE_ENTRIES).unwrap());
    Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap()
}

fn open_plain(path: &Path) -> Chain {
    let db = Arc::new(ChainDatabase::open(path.join("chain")).unwrap());
    Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap()
}

fn open_cached_search(path: &Path) -> Chain {
    let db =
        Arc::new(ChainDatabase::open_with_utxo_cache(path.join("chain"), CACHE_ENTRIES).unwrap());
    let mut chain = Chain::new(
        db.clone(),
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    chain.enable_search_index(Arc::new(SearchIndex::new(db, true, true)));
    chain
}

fn open_plain_search(path: &Path) -> Chain {
    let db = Arc::new(ChainDatabase::open(path.join("chain")).unwrap());
    let mut chain = Chain::new(
        db.clone(),
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    chain.enable_search_index(Arc::new(SearchIndex::new(db, true, true)));
    chain
}

/// Append coinbase-only blocks with the given pubkey-hash keys, returning the
/// hash of the last block accepted.
fn extend(chain: &Chain, keys: &[u8]) -> Hash256 {
    let (mut parent, mut time) = get_genesis_info(chain);
    let mut last = parent;
    for &key in keys {
        let block = create_child_block_with_pubkey(parent, time, [key; 20]);
        time = block.header.time;
        last = chain.accept_block(block).unwrap().hash;
        parent = last;
    }
    last
}

fn assert_same_utxo_and_tip(a: &crate::database::UtxoStats, b: &crate::database::UtxoStats) {
    assert_eq!(a.hash_serialized, b.hash_serialized, "UTXO digest differs");
    assert_eq!(a.best_block, b.best_block, "tip hash differs");
    assert_eq!(a.height, b.height, "tip height differs");
    assert_eq!(a.txouts, b.txouts, "UTXO count differs");
    assert_eq!(a.total_amount, b.total_amount, "total amount differs");
}

/// Write-through ownership: connecting blocks leaves nothing dirty in the
/// cache (every coin is written to the database together with the tip), the
/// flush has nothing to write, and the durable digest already equals a clean
/// replay with no cache. A flush the fault layer would stop is never reached.
#[test]
fn connected_blocks_leave_nothing_dirty_and_match_clean_replay() {
    let dir = tempdir().unwrap();
    let chain = open_cached(dir.path());
    create_chain(&chain, 20);

    assert_eq!(
        chain.db.utxo_dirty_count(),
        0,
        "write-through must not leave dirty entries"
    );
    let before = chain.db.get_utxo_stats().unwrap();

    // Nothing to write, so the flush cannot fail at its write
    fault::arm("utxo flush", 0);
    let flushed = chain.db.flush_utxo_cache();
    fault::disarm();
    assert_eq!(flushed.unwrap(), 0);
    assert_same_utxo_and_tip(&before, &chain.db.get_utxo_stats().unwrap());

    let clean_dir = tempdir().unwrap();
    let clean = open_plain(clean_dir.path());
    create_chain(&clean, 20);
    assert_same_utxo_and_tip(&before, &clean.db.get_utxo_stats().unwrap());
}

/// Readers on other threads fill the cache from the database while blocks
/// connect and the cache is flushed after each one. Afterwards every cached
/// coin equals the database, the start-up check accepts the restarted chain,
/// and its UTXO digest and tip equal a clean replay with no cache.
#[test]
fn concurrent_readers_during_connect_then_restart_match_clean_replay() {
    let dir = tempdir().unwrap();
    {
        let chain = Arc::new(open_cached(dir.path()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..2)
            .map(|_| {
                let (chain, stop) = (chain.clone(), stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        let raw = chain.db.inner_db();
                        let cf = raw.cf_handle("utxo").unwrap();
                        let ops: Vec<_> = raw
                            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
                            .map(|i| crate::utxo::outpoint_from_key(&i.unwrap().0).unwrap())
                            .collect();
                        for op in ops {
                            let _ = chain.db.get_utxo(&op).unwrap();
                            let _ = chain.db.has_utxo(&op).unwrap();
                        }
                    }
                })
            })
            .collect();
        let (mut parent, mut time) = get_genesis_info(&chain);
        for i in 0..25u8 {
            let block = create_child_block_with_pubkey(parent, time, [i; 20]);
            time = block.header.time;
            parent = chain.accept_block(block).unwrap().hash;
            chain.db.flush_utxo_cache().unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for r in readers {
            r.join().unwrap();
        }
        let raw = chain.db.inner_db();
        let cf = raw.cf_handle("utxo").unwrap();
        for item in raw.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let (k, v) = item.unwrap();
            let op = crate::utxo::outpoint_from_key(&k).unwrap();
            let cached = chain.db.get_utxo(&op).unwrap().expect("cached coin");
            assert_eq!(cached.to_bytes(), v.to_vec(), "cache differs from database");
        }
    }
    let reopened = open_cached(dir.path());
    reopened
        .verify_recent_blocks(100)
        .expect("the UTXO set must match the tip after restart");
    let clean_dir = tempdir().unwrap();
    let clean = open_plain(clean_dir.path());
    let (mut parent, mut time) = get_genesis_info(&clean);
    for i in 0..25u8 {
        let block = create_child_block_with_pubkey(parent, time, [i; 20]);
        time = block.header.time;
        parent = clean.accept_block(block).unwrap().hash;
    }
    let _ = parent;
    assert_same_utxo_and_tip(
        &reopened.db.get_utxo_stats().unwrap(),
        &clean.db.get_utxo_stats().unwrap(),
    );
}

/// A crash right after a block's atomic write (UTXOs + tip + undo + indexes in
/// one batch) but before the next cache flush leaves a database whose UTXO
/// digest, tip and address index equal a clean replay of the same blocks.
#[test]
fn crash_after_connect_reopens_equal_to_clean_replay() {
    let dir = tempdir().unwrap();
    let crashed_hash;
    {
        let chain = open_cached_search(dir.path());
        extend(&chain, &[0x0a, 0x0b, 0x0c]);

        // The next block connects atomically, then the process dies before the
        // in-memory tip update and before any flush.
        let tip = chain.tip().unwrap();
        let block = create_child_block_with_pubkey(tip.hash, tip.time, [0x0d; 20]);
        crashed_hash = compute_block_hash(&block.header);
        fault::arm("block connected", 0);
        assert!(chain.accept_block(block).is_err());
        fault::disarm();
        drop(chain);
    }

    // Reopen as a restart would. The atomically written block is the tip and
    // the start-up check accepts the UTXO set.
    let reopened = open_cached_search(dir.path());
    reopened
        .verify_recent_blocks(100)
        .expect("the UTXO set must match the tip after the crash");
    assert_eq!(reopened.tip().unwrap().hash, crashed_hash);
    assert_eq!(reopened.height(), 4);
    let crash_stats = reopened.db.get_utxo_stats().unwrap();

    // Clean replay of the same four blocks with the cache disabled.
    let clean_dir = tempdir().unwrap();
    let clean = open_plain_search(clean_dir.path());
    extend(&clean, &[0x0a, 0x0b, 0x0c, 0x0d]);
    let clean_stats = clean.db.get_utxo_stats().unwrap();

    assert_same_utxo_and_tip(&crash_stats, &clean_stats);

    // The address index moved with the chain the same way in both.
    let reopened_search = reopened.search_index().unwrap();
    let clean_search = clean.search_index().unwrap();
    for key in [0x0a, 0x0b, 0x0c, 0x0d] {
        assert_eq!(
            reopened_search.read_unspent(1, &[key; 20]).unwrap().len(),
            clean_search.read_unspent(1, &[key; 20]).unwrap().len(),
            "address index for key {key:#x} differs after the crash"
        );
    }
}

/// Ownership: whether the UTXO cache is enabled (and flushed) or absent, the
/// durable UTXO digest and tip of the same block sequence are identical. The
/// cache never owns durable state.
#[test]
fn cache_flush_does_not_change_durable_state_versus_no_cache() {
    let cached_dir = tempdir().unwrap();
    let cached = open_cached(cached_dir.path());
    create_chain(&cached, 30);
    cached.db.flush_utxo_cache().unwrap();
    let cached_stats = cached.db.get_utxo_stats().unwrap();

    let plain_dir = tempdir().unwrap();
    let plain = open_plain(plain_dir.path());
    create_chain(&plain, 30);
    let plain_stats = plain.db.get_utxo_stats().unwrap();

    assert_same_utxo_and_tip(&cached_stats, &plain_stats);

    // And the cached digest is already right before the flush: the connect path
    // wrote every coin through to the database, so the flush is redundant for
    // durability.
    let cached_dir2 = tempdir().unwrap();
    let cached2 = open_cached(cached_dir2.path());
    create_chain(&cached2, 30);
    let before_flush = cached2.db.get_utxo_stats().unwrap();
    assert_same_utxo_and_tip(&before_flush, &plain_stats);
}
