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

//! Chain Consensus Integration Tests
//!
//! Tests for the chain state machine, UTXO consistency, and reorganization logic.
//! These tests verify cross-crate functionality between divi-storage, divi-consensus,
//! and related components.
//!
//! Added 2026-01-19 for comprehensive test coverage.

use divi_consensus::{lottery, treasury};
use divi_crypto::{compute_merkle_root, hash::hash_serialized};
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use std::sync::Arc;
use tempfile::tempdir;

/// Helper to create a test chain (with genesis already initialized)
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

/// Helper to create a child block
fn create_child_block(parent_hash: Hash256, parent_time: u32, pubkey_hash: [u8; 20]) -> Block {
    let mut block = Block::default();
    block.header.version = 1;
    block.header.prev_block = parent_hash;
    block.header.time = parent_time + 60;
    block.header.bits = 0x207fffff;

    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x05]))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250_00000000), // Standard block reward
            Script::new_p2pkh(&pubkey_hash),
        )],
        lock_time: 0,
    };
    block.transactions.push(coinbase);
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    block
}

/// Helper to build a chain of blocks on top of the existing genesis
fn build_chain(chain: &Chain, num_blocks: usize) -> Vec<Hash256> {
    let mut hashes = Vec::new();

    // Get the existing genesis from the chain (already initialized by Chain::new)
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;
    hashes.push(genesis_hash);

    let mut prev_hash = genesis_hash;
    let mut prev_time = genesis_time;

    for i in 0..num_blocks {
        let block = create_child_block(prev_hash, prev_time, [(i as u8 + 1); 20]);
        let hash = chain.accept_block(block).unwrap().hash;
        hashes.push(hash);
        prev_hash = hash;
        prev_time += 60;
    }

    hashes
}

// ============================================================
// Treasury Block Integration Tests
// ============================================================

#[test]
fn test_treasury_block_parameters_regtest() {
    // Verify treasury parameters for regtest
    assert_eq!(treasury::regtest::TREASURY_START_BLOCK, 102);
    assert_eq!(treasury::regtest::TREASURY_CYCLE, 50);

    // First treasury block should be at height 150 (first h >= 102 where h % 50 == 0)
    assert!(!treasury::is_treasury_block(100, 102, 50));
    assert!(!treasury::is_treasury_block(102, 102, 50));
    assert!(treasury::is_treasury_block(150, 102, 50));
    assert!(treasury::is_treasury_block(200, 102, 50));
}

#[test]
#[ignore] // Requires PoS block construction: blocks above PoW→PoS transition need coinstake
fn test_chain_with_treasury_heights() {
    let (chain, _dir) = create_test_chain();

    // Build chain past treasury block (150)
    let hashes = build_chain(&chain, 155);

    // Verify chain height
    assert_eq!(chain.height(), 155);

    // Verify blocks exist at treasury heights
    assert!(chain.has_block(&hashes[150]).unwrap());
    assert!(chain.has_block(&hashes[151]).unwrap());
}

// ============================================================
// Lottery Block Integration Tests
// ============================================================

#[test]
fn test_lottery_block_parameters_regtest() {
    assert_eq!(lottery::regtest::LOTTERY_START_BLOCK, 101);
    assert_eq!(lottery::regtest::LOTTERY_CYCLE, 10);

    // Lottery blocks at 110, 120, 130, etc.
    assert!(!lottery::is_lottery_block(100, 101, 10));
    assert!(!lottery::is_lottery_block(101, 101, 10)); // 101 % 10 = 1
    assert!(lottery::is_lottery_block(110, 101, 10));
    assert!(lottery::is_lottery_block(120, 101, 10));
}

#[test]
#[ignore] // Requires PoS block construction: blocks above PoW→PoS transition need coinstake
fn test_chain_through_lottery_heights() {
    let (chain, _dir) = create_test_chain();

    // Build chain past multiple lottery blocks
    let hashes = build_chain(&chain, 130);

    assert_eq!(chain.height(), 130);

    // Lottery blocks should exist
    for lottery_height in [110, 120, 130] {
        assert!(
            chain.has_block(&hashes[lottery_height]).unwrap(),
            "Lottery block at height {} should exist",
            lottery_height
        );
    }
}

// ============================================================
// Chain Reorganization Tests
// ============================================================

#[test]
fn test_reorg_replaces_shorter_chain() {
    let (chain, _dir) = create_test_chain();

    // Get existing genesis from chain
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;

    // Build chain A: genesis -> A1 -> A2
    let block_a1 = create_child_block(genesis_hash, genesis_time, [0x0a; 20]);
    let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;

    let block_a2 = create_child_block(hash_a1, block_a1.header.time, [0x0b; 20]);
    let hash_a2 = chain.accept_block(block_a2.clone()).unwrap().hash;

    assert_eq!(chain.height(), 2);
    assert_eq!(chain.tip().unwrap().hash, hash_a2);

    // Build competing chain B: genesis -> B1 -> B2 -> B3 (longer)
    let block_b1 = create_child_block(genesis_hash, genesis_time + 1, [0x1a; 20]);
    let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;

    let block_b2 = create_child_block(hash_b1, block_b1.header.time, [0x1b; 20]);
    let hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;

    let block_b3 = create_child_block(hash_b2, block_b2.header.time, [0x1c; 20]);
    let hash_b3 = chain.accept_block(block_b3).unwrap().hash;

    // Should have reorged to B chain
    assert_eq!(chain.height(), 3);
    assert_eq!(chain.tip().unwrap().hash, hash_b3);
}

#[test]
fn test_reorg_maintains_utxo_consistency() {
    let (chain, _dir) = create_test_chain();

    // Get existing genesis from chain
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;

    // Chain A
    let block_a1 = create_child_block(genesis_hash, genesis_time, [0x0a; 20]);
    let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;

    // Get UTXO from A1
    let a1_block = chain.get_block(&hash_a1).unwrap().unwrap();
    let a1_coinbase_txid = hash_serialized(&a1_block.transactions[0]);
    let a1_outpoint = OutPoint::new(a1_coinbase_txid, 0);

    assert!(
        chain.has_utxo(&a1_outpoint).unwrap(),
        "A1 UTXO should exist"
    );

    // Build longer competing chain B
    let block_b1 = create_child_block(genesis_hash, genesis_time + 1, [0x1a; 20]);
    let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;

    let block_b2 = create_child_block(hash_b1, block_b1.header.time, [0x1b; 20]);
    let _hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;

    // After reorg, A1's UTXO should be gone
    assert!(
        !chain.has_utxo(&a1_outpoint).unwrap_or(true),
        "A1 UTXO should be removed after reorg"
    );

    // B1's UTXO should exist
    let b1_block = chain.get_block(&hash_b1).unwrap().unwrap();
    let b1_coinbase_txid = hash_serialized(&b1_block.transactions[0]);
    let b1_outpoint = OutPoint::new(b1_coinbase_txid, 0);

    assert!(
        chain.has_utxo(&b1_outpoint).unwrap(),
        "B1 UTXO should exist after reorg"
    );
}

// ============================================================
// UTXO Set Tests
// ============================================================

#[test]
fn test_coinbase_utxo_created_and_tracked() {
    let (chain, _dir) = create_test_chain();

    // Get the existing genesis from Chain::new
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;

    // Add a block on top of genesis to have a UTXO we control
    let block1 = create_child_block(genesis_hash, genesis_time, [0x01; 20]);
    let hash1 = chain.accept_block(block1).unwrap().hash;

    let block1_data = chain.get_block(&hash1).unwrap().unwrap();
    let coinbase_txid = hash_serialized(&block1_data.transactions[0]);
    let outpoint = OutPoint::new(coinbase_txid, 0);

    let utxo = chain.get_utxo(&outpoint).unwrap().unwrap();

    assert!(utxo.is_coinbase);
    assert_eq!(utxo.height, 1);
    assert_eq!(utxo.value.as_sat(), 1250_00000000); // Block reward
}

#[test]
fn test_multiple_blocks_create_utxos() {
    let (chain, _dir) = create_test_chain();

    let hashes = build_chain(&chain, 10);

    // Skip genesis (height 0) since it's handled specially - test blocks 1-10
    for (height, hash) in hashes.iter().enumerate().skip(1) {
        let block = chain.get_block(hash).unwrap().unwrap();
        let coinbase_txid = hash_serialized(&block.transactions[0]);
        let outpoint = OutPoint::new(coinbase_txid, 0);

        assert!(
            chain.has_utxo(&outpoint).unwrap(),
            "UTXO from block at height {} should exist",
            height
        );
    }
}

// ============================================================
// Block Index Tests
// ============================================================

#[test]
fn test_block_index_by_height() {
    let (chain, _dir) = create_test_chain();

    let hashes = build_chain(&chain, 20);

    for (height, expected_hash) in hashes.iter().enumerate() {
        let index = chain
            .get_block_index_by_height(height as u32)
            .unwrap()
            .unwrap();
        assert_eq!(index.hash, *expected_hash);
        assert_eq!(index.height, height as u32);
    }
}

#[test]
fn test_chain_work_monotonically_increases() {
    let (chain, _dir) = create_test_chain();

    let hashes = build_chain(&chain, 10);

    let mut prev_work = [0u8; 32];

    for hash in &hashes {
        let index = chain.get_block_index(hash).unwrap().unwrap();
        // Compare chain work as big-endian 256-bit integers
        assert!(
            index.chain_work >= prev_work,
            "Chain work should not decrease"
        );
        prev_work = index.chain_work;
    }
}

// ============================================================
// Block Locator Tests
// ============================================================

#[test]
fn test_block_locator_contains_tip_and_genesis() {
    let (chain, _dir) = create_test_chain();

    let hashes = build_chain(&chain, 50);

    let locator = chain.get_locator().unwrap();

    assert!(!locator.is_empty());
    assert_eq!(locator[0], hashes[50]); // Tip
    assert_eq!(*locator.last().unwrap(), hashes[0]); // Genesis
}

#[test]
fn test_block_locator_exponential_backoff() {
    let (chain, _dir) = create_test_chain();

    // Build a longer chain to test exponential backoff
    let hashes = build_chain(&chain, 100);

    let locator = chain.get_locator().unwrap();

    // Should have fewer entries than blocks due to exponential backoff
    assert!(
        locator.len() < 50,
        "Locator should use exponential backoff, got {} entries",
        locator.len()
    );

    // Should still contain tip and genesis
    assert_eq!(locator[0], hashes[100]);
    assert_eq!(*locator.last().unwrap(), hashes[0]);
}

// ============================================================
// Error Handling Tests
// ============================================================

#[test]
fn test_reject_block_with_invalid_merkle_root() {
    let (chain, _dir) = create_test_chain();

    // Get existing genesis
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;

    // Create block with invalid merkle root
    let mut bad_block = create_child_block(genesis_hash, genesis_time, [0x01; 20]);
    bad_block.header.merkle_root = Hash256::from_bytes([0xff; 32]);

    let result = chain.accept_block(bad_block);
    assert!(result.is_err());
}

#[test]
fn test_reject_orphan_block() {
    let (chain, _dir) = create_test_chain();

    // Try to accept block with unknown parent (Chain already has genesis)
    let orphan = create_child_block(Hash256::from_bytes([0xaa; 32]), 1000000100, [0x01; 20]);
    let result = chain.accept_block(orphan);

    assert!(result.is_err());
}

#[test]
fn test_reject_block_with_future_timestamp() {
    let (chain, _dir) = create_test_chain();

    // Get existing genesis
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;

    // Create block with timestamp 3 hours in future
    let mut future_block = create_child_block(genesis_hash, genesis_time, [0x01; 20]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    future_block.header.time = now + 3 * 60 * 60;
    future_block.header.merkle_root = compute_merkle_root(&future_block.transactions);

    let result = chain.accept_block(future_block);
    assert!(result.is_err());
}

// ============================================================
// Concurrency Tests
// ============================================================

#[test]
fn test_concurrent_block_acceptance() {
    use std::thread;

    let dir = tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );

    // Get existing genesis (already created by Chain::new)
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;

    // Spawn multiple threads adding different blocks
    let mut handles = vec![];

    for i in 0..4 {
        let chain_clone = Arc::clone(&chain);
        let handle = thread::spawn(move || {
            let block = create_child_block(genesis_hash, genesis_time, [(i + 10) as u8; 20]);
            chain_clone.accept_block(block)
        });
        handles.push(handle);
    }

    // Collect results
    let mut success_count = 0;
    for handle in handles {
        if handle.join().unwrap().is_ok() {
            success_count += 1;
        }
    }

    // At least one should succeed
    assert!(success_count >= 1);

    // Chain should be consistent
    assert_eq!(chain.height(), 1);
}

#[test]
fn test_concurrent_reads_and_writes() {
    use std::thread;
    use std::time::Duration;

    let dir = tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );

    // Get existing genesis (already created by Chain::new)
    let genesis_index = chain.tip().expect("Chain should have genesis block");
    let genesis_hash = genesis_index.hash;
    let genesis_time = genesis_index.time;

    // Start reader threads
    let mut handles = vec![];
    for _ in 0..4 {
        let chain_clone = Arc::clone(&chain);
        let handle = thread::spawn(move || {
            for _ in 0..20 {
                let _ = chain_clone.height();
                let _ = chain_clone.tip();
                let _ = chain_clone.has_block(&genesis_hash);
                thread::sleep(Duration::from_millis(1));
            }
        });
        handles.push(handle);
    }

    // Writer thread
    {
        let chain_clone = Arc::clone(&chain);
        let handle = thread::spawn(move || {
            let mut prev_hash = genesis_hash;
            let mut prev_time = genesis_time;
            for i in 0..10 {
                let block = create_child_block(prev_hash, prev_time, [(i + 20) as u8; 20]);
                let hash = chain_clone.accept_block(block).unwrap().hash;
                prev_hash = hash;
                prev_time += 60;
            }
        });
        handles.push(handle);
    }

    // All should complete without panic
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(chain.height(), 10);
}
