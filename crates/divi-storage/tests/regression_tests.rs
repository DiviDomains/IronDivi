// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Regression tests for divi-storage
//!
//! Bug 5 (commit 1f78c1f): Write-through UTXO cache to prevent data loss on restart.
//! Bug 6 (commit 9cc17db): Chain reorganization disabled in sync layer.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_storage::utxo::Utxo;
use divi_storage::UtxoCache;
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use std::sync::Arc;
use tempfile::tempdir;

// ============================================================
// Bug 5 (commit 1f78c1f): Write-through UTXO cache
//
// Root cause: UTXOs inserted via ChainDatabase were held in memory only until
// an explicit flush.  A crash before flushing caused data loss.
//
// Fix: ChainDatabase::add_utxo() now always writes to RocksDB before returning,
// making every insert immediately durable.
// ============================================================

/// Bug 5 (commit 1f78c1f): A UTXO written via ChainDatabase::add_utxo() must
/// be present in the DB immediately — no explicit flush required.
/// We verify durability by closing and reopening the DB.
#[test]
fn test_regression_chain_db_add_utxo_is_durable() {
    let dir = tempdir().expect("tempdir creation must succeed");

    let outpoint = OutPoint::new(Hash256::from_bytes([0xAB; 32]), 0);
    let utxo = Utxo::new(
        Amount::from_sat(100_000_000),
        Script::new_p2pkh(&[0u8; 20]),
        100,
        false,
        false,
    );

    // Write via the fixed path
    {
        let db = ChainDatabase::open(dir.path()).expect("open DB");
        db.add_utxo(&outpoint, &utxo)
            .expect("add_utxo must succeed");
        // DB is dropped here — simulates clean shutdown without explicit flush
    }

    // Reopen: simulates restart
    let db2 = ChainDatabase::open(dir.path()).expect("reopen DB");
    let stored = db2
        .get_utxo(&outpoint)
        .expect("DB read must not error")
        .expect("UTXO must be present after add_utxo — write-through guarantees durability");

    assert_eq!(
        stored.value, utxo.value,
        "UTXO value must match after DB reopen"
    );
}

/// Bug 5 (commit 1f78c1f): Removing a UTXO via ChainDatabase::remove_utxo()
/// must also be immediately durable (write-through delete).
#[test]
fn test_regression_chain_db_remove_utxo_is_durable() {
    let dir = tempdir().unwrap();

    let outpoint = OutPoint::new(Hash256::from_bytes([0xCC; 32]), 1);
    let utxo = Utxo::new(
        Amount::from_sat(50_000_000),
        Script::new_p2pkh(&[1u8; 20]),
        200,
        false,
        false,
    );

    // Add then remove in the same session
    {
        let db = ChainDatabase::open(dir.path()).unwrap();
        db.add_utxo(&outpoint, &utxo).unwrap();
        db.remove_utxo(&outpoint).unwrap();
    }

    // Reopen: UTXO must be absent
    let db2 = ChainDatabase::open(dir.path()).unwrap();
    let result = db2.get_utxo(&outpoint).expect("DB read must not error");
    assert!(
        result.is_none(),
        "UTXO must be absent from DB after remove_utxo() + restart. \
         Before commit 1f78c1f, the delete was write-back only and could be lost."
    );
}

/// Bug 5 (commit 1f78c1f): Multiple UTXOs written in sequence must all be
/// durable — write-through applies to every call, not just the first.
#[test]
fn test_regression_multiple_utxos_all_durable() {
    let dir = tempdir().unwrap();

    let outpoints: Vec<OutPoint> = (0u8..5)
        .map(|i| OutPoint::new(Hash256::from_bytes([i; 32]), i as u32))
        .collect();

    {
        let db = ChainDatabase::open(dir.path()).unwrap();
        for (i, op) in outpoints.iter().enumerate() {
            let utxo = Utxo::new(
                Amount::from_sat((i as i64 + 1) * 10_000_000),
                Script::new_p2pkh(&[i as u8; 20]),
                i as u32 * 10,
                false,
                false,
            );
            db.add_utxo(op, &utxo).unwrap();
        }
    }

    let db2 = ChainDatabase::open(dir.path()).unwrap();
    for (i, op) in outpoints.iter().enumerate() {
        let stored = db2
            .get_utxo(op)
            .expect("read must not error")
            .unwrap_or_else(|| panic!("UTXO {} must be present after restart", i));
        assert_eq!(
            stored.value.as_sat(),
            (i as i64 + 1) * 10_000_000,
            "UTXO {} value mismatch after restart",
            i
        );
    }
}

/// Bug 5 (commit 1f78c1f): Standalone UtxoCache: dirty entries are durable
/// after flush() is called with the underlying DB.
#[test]
fn test_regression_utxo_cache_flush_persists_to_db() {
    let dir = tempdir().unwrap();
    let db = ChainDatabase::open(dir.path()).unwrap();

    let cache = UtxoCache::new(1_000);
    let outpoint = OutPoint::new(Hash256::from_bytes([0xDD; 32]), 7);
    let utxo = Utxo::new(
        Amount::from_sat(777_000_000),
        Script::new_p2pkh(&[7u8; 20]),
        77,
        false,
        false,
    );

    cache.insert(outpoint.clone(), utxo.clone());
    assert_eq!(cache.dirty_count(), 1, "Must be dirty before flush");

    let flushed = cache.flush(db.inner_db()).expect("flush must succeed");
    assert_eq!(flushed, 1, "One entry should have been flushed");
    assert_eq!(cache.dirty_count(), 0, "No dirty entries after flush");

    // Verify the UTXO is now in the DB (via ChainDatabase, bypassing the standalone cache)
    let stored = db
        .get_utxo(&outpoint)
        .expect("read must not error")
        .expect("UTXO must be present in DB after cache flush");

    assert_eq!(
        stored.value, utxo.value,
        "Value must match after cache flush"
    );
}

// ============================================================
// Bug 6 (commit 9cc17db): Chain reorganization disabled
//
// Root cause: The block sync layer accepted blocks on a competing fork but
// never triggered a reorg when that fork accumulated more chain work.
// Nodes got stuck on shorter forks indefinitely.
//
// Fix: Chain::accept_block() now detects when an incoming block extends a
// chain with more cumulative work than the active tip and calls do_reorg().
// ============================================================

fn build_block(prev_hash: Hash256, prev_time: u32, tag: u8) -> Block {
    let mut block = Block::default();
    block.header.version = 1;
    block.header.prev_block = prev_hash;
    block.header.time = prev_time + 60;
    block.header.bits = 0x207fffff; // Regtest minimum difficulty

    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(vec![tag]))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250_00000000),
            Script::new_p2pkh(&[tag; 20]),
        )],
        lock_time: 0,
    };
    block.transactions.push(coinbase);
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    block
}

fn create_test_chain() -> (Chain, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    (chain, dir)
}

/// Bug 6 (commit 9cc17db): When a competing chain becomes longer (more chain
/// work), the node MUST reorganize to it.
#[test]
fn test_regression_reorg_switches_to_longer_chain() {
    let (chain, _dir) = create_test_chain();

    let genesis = chain.tip().expect("genesis must exist");
    let genesis_hash = genesis.hash;
    let genesis_time = genesis.time;

    // Chain A: genesis → A1 → A2 (height 2)
    let block_a1 = build_block(genesis_hash, genesis_time, 0x0A);
    let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;
    let block_a2 = build_block(hash_a1, block_a1.header.time, 0x0B);
    let hash_a2 = chain.accept_block(block_a2.clone()).unwrap().hash;

    assert_eq!(chain.height(), 2);
    assert_eq!(chain.tip().unwrap().hash, hash_a2);

    // Chain B: genesis → B1 → B2 → B3 (height 3, more work)
    let block_b1 = build_block(genesis_hash, genesis_time + 1, 0x1A);
    let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;
    let block_b2 = build_block(hash_b1, block_b1.header.time, 0x1B);
    let hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;
    let block_b3 = build_block(hash_b2, block_b2.header.time, 0x1C);
    let hash_b3 = chain.accept_block(block_b3).unwrap().hash;

    assert_eq!(
        chain.height(),
        3,
        "After reorg, chain height must be 3 (chain B wins with more work). \
         Before commit 9cc17db, reorg was disabled and height stayed at 2."
    );
    assert_eq!(
        chain.tip().unwrap().hash,
        hash_b3,
        "Tip must switch to hash_b3 after reorg. \
         Before commit 9cc17db, the tip was stuck on the shorter chain."
    );

    // Suppress unused variable warning
    let _ = (hash_a1, hash_a2);
}

/// Bug 6 (commit 9cc17db): After a reorg, UTXOs from the abandoned chain must
/// be removed, and UTXOs from the new chain must be present.
#[test]
fn test_regression_reorg_updates_utxo_set() {
    use divi_crypto::hash::hash_serialized;

    let (chain, _dir) = create_test_chain();

    let genesis = chain.tip().expect("genesis must exist");
    let genesis_hash = genesis.hash;
    let genesis_time = genesis.time;

    // Chain A (will be abandoned)
    let block_a1 = build_block(genesis_hash, genesis_time, 0x0A);
    let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;

    // Check A1's coinbase UTXO exists
    let a1_block = chain.get_block(&hash_a1).unwrap().unwrap();
    let a1_txid = hash_serialized(&a1_block.transactions[0]);
    let a1_outpoint = OutPoint::new(a1_txid, 0);
    assert!(chain.has_utxo(&a1_outpoint).unwrap(), "A1 UTXO must exist");

    // Chain B: longer, will replace A
    let block_b1 = build_block(genesis_hash, genesis_time + 1, 0x1A);
    let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;
    let block_b2 = build_block(hash_b1, block_b1.header.time, 0x1B);
    let _hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;

    // After reorg: A1's UTXO must be gone, B1's UTXO must exist
    assert!(
        !chain.has_utxo(&a1_outpoint).unwrap_or(true),
        "A1 UTXO must be removed after reorg to chain B"
    );

    let b1_block = chain.get_block(&hash_b1).unwrap().unwrap();
    let b1_txid = hash_serialized(&b1_block.transactions[0]);
    let b1_outpoint = OutPoint::new(b1_txid, 0);
    assert!(
        chain.has_utxo(&b1_outpoint).unwrap(),
        "B1 UTXO must exist after reorg"
    );
}

/// Bug 6 (commit 9cc17db): A side chain that is shorter than the current tip
/// must NOT trigger a reorg (only longer chains reorg).
#[test]
fn test_regression_no_reorg_for_shorter_chain() {
    let (chain, _dir) = create_test_chain();

    let genesis = chain.tip().expect("genesis must exist");
    let genesis_hash = genesis.hash;
    let genesis_time = genesis.time;

    // Build a 3-block main chain
    let b1 = build_block(genesis_hash, genesis_time, 0x01);
    let h1 = chain.accept_block(b1.clone()).unwrap().hash;
    let b2 = build_block(h1, b1.header.time, 0x02);
    let h2 = chain.accept_block(b2.clone()).unwrap().hash;
    let b3 = build_block(h2, b2.header.time, 0x03);
    let h3 = chain.accept_block(b3).unwrap().hash;

    assert_eq!(chain.height(), 3);
    assert_eq!(chain.tip().unwrap().hash, h3);

    // Add a 2-block competing chain (shorter — must NOT reorg)
    let c1 = build_block(genesis_hash, genesis_time + 1, 0x11);
    let hc1 = chain.accept_block(c1.clone()).unwrap().hash;
    let c2 = build_block(hc1, c1.header.time, 0x12);
    let _hc2 = chain.accept_block(c2).unwrap().hash;

    // Main chain must still win (height 3)
    assert_eq!(
        chain.height(),
        3,
        "A shorter competing chain (height 2) must NOT trigger a reorg"
    );
    assert_eq!(
        chain.tip().unwrap().hash,
        h3,
        "Tip must remain on the longer main chain after receiving a shorter fork"
    );
}
