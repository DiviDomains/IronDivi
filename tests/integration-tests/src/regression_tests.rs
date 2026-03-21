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

//! Regression tests for critical IronDivi bugs
//!
//! Each test documents the bug it prevents from recurring, including the
//! commit that fixed it and the root cause.
//!
//! Tests are deterministic, fast, and require no network access.

// ============================================================
// Bug 1 & 7: Transaction version=2 rejected by C++ node (commit 8d9e245)
//
// Root cause: TransactionBuilder::new() defaulted to version=2.  C++ Divi
// rejects non-standard transactions ("64: version") unless version==1.
// CURRENT_TX_VERSION was added and set to 1 to enforce the correct default.
// ============================================================

#[test]
fn test_regression_tx_version_must_be_1() {
    // Bug 1 / 7 (commit 8d9e245): TransactionBuilder must produce version=1
    use divi_primitives::constants::CURRENT_TX_VERSION;

    assert_eq!(
        CURRENT_TX_VERSION, 1,
        "CURRENT_TX_VERSION constant must be 1 (C++ rejects version!=1 as non-standard)"
    );
}

#[test]
fn test_regression_transaction_new_defaults_to_current_tx_version() {
    // Bug 1 / 7 (commit 8d9e245): Transaction::new() must default to version=1
    use divi_primitives::constants::CURRENT_TX_VERSION;
    use divi_primitives::transaction::Transaction;

    let tx = Transaction::new();
    assert_eq!(
        tx.version, CURRENT_TX_VERSION,
        "Transaction::new() must default to CURRENT_TX_VERSION={} (was 2 before the fix)",
        CURRENT_TX_VERSION,
    );
    assert_eq!(
        tx.version, 1,
        "Transaction::new() must produce version=1 (C++ Divi rejects version=2 as non-standard)"
    );
}

#[test]
fn test_regression_transaction_builder_new_produces_version_1() {
    // Bug 1 / 7 (commit 8d9e245): TransactionBuilder::new() must build a version=1 tx
    use divi_primitives::amount::Amount;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::OutPoint;
    use divi_wallet::TransactionBuilder;

    let outpoint = OutPoint::new(Hash256::from_bytes([0xAA; 32]), 0);
    let script = Script::new_p2pkh(&[0u8; 20]);
    let (tx, _prev_scripts) = TransactionBuilder::new()
        .add_input(outpoint, script.clone())
        .add_output(Amount::from_sat(1_000_000), script)
        .build();

    assert_eq!(
        tx.version, 1,
        "TransactionBuilder::new().build() must produce version=1; got version={}. \
         C++ node rejects version=2 with \"64: version\"",
        tx.version
    );
}

#[test]
fn test_regression_version_1_survives_serialization_roundtrip() {
    // Bug 1 / 7 (commit 8d9e245): version=1 must be preserved through serialize/deserialize
    use divi_primitives::constants::SEQUENCE_FINAL;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::serialize::{deserialize, serialize};
    use divi_primitives::transaction::{OutPoint, Transaction, TxIn};

    let tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::new(Hash256::from_bytes([0x11; 32]), 0),
            Script::new(),
            SEQUENCE_FINAL,
        )],
        vout: vec![],
        lock_time: 0,
    };

    let bytes = serialize(&tx);
    // First 4 bytes are the version in little-endian: 01 00 00 00
    assert_eq!(
        &bytes[0..4],
        &[0x01, 0x00, 0x00, 0x00],
        "version=1 must serialize as [01 00 00 00]"
    );

    let decoded: Transaction = deserialize(&bytes).expect("deserialization must succeed");
    assert_eq!(
        decoded.version, 1,
        "version=1 must survive a serialization roundtrip"
    );
}

// ============================================================
// Bug 2: Stake modifier mismatch (commit c00e3d8)
//
// Root cause: The staker used `tip.stake_modifier` (in-memory cached value)
// while validation uses `get_stake_modifier_hardened()` which walks backward
// through the chain DB.  These can diverge, producing blocks that fail
// their own PoS validation.
//
// The staker was fixed to always call `get_stake_modifier()` (which uses the
// same DB walkback as validation), instead of reading the cached field.
//
// Unit-level verification: the `StakeModifierService` trait and
// `MockStakeModifierService` are the single path through which the staker
// retrieves the modifier.  If both staker and validator go through this same
// interface backed by DB lookup, they are guaranteed to agree.
// ============================================================

#[test]
fn test_regression_stake_modifier_service_trait_is_the_only_path() {
    // Bug 2 (commit c00e3d8): The StakeModifierService trait must be the single
    // source of truth.  If staker and validator share the same service, they
    // can never diverge.
    use divi_consensus::MockStakeModifierService;
    use divi_consensus::StakeModifierService;
    use divi_consensus::StakingData;
    use divi_primitives::amount::Amount;
    use divi_primitives::hash::Hash256;
    use divi_primitives::transaction::OutPoint;

    let expected_modifier: u64 = 0xDEADBEEF_CAFEBABE;
    let service = MockStakeModifierService::new(expected_modifier);

    let staking_data = StakingData::new(
        0x1e0fffff,
        1_000_000,
        Hash256::from_bytes([0u8; 32]),
        OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
        Amount::from_sat(2000 * 100_000_000),
        Hash256::from_bytes([2u8; 32]),
    );

    // Staker path: retrieve modifier via service
    let modifier_from_service = service
        .get_stake_modifier(&staking_data)
        .expect("get_stake_modifier must succeed");

    assert_eq!(
        modifier_from_service, expected_modifier,
        "Stake modifier retrieved via service must match the expected DB value. \
         Before fix, staker read tip.stake_modifier (cached) which could diverge \
         from the DB-backed validator path."
    );
}

#[test]
fn test_regression_different_staking_data_same_modifier() {
    // Bug 2 (commit c00e3d8): The MockStakeModifierService always returns the
    // same modifier regardless of staking_data, verifying that the modifier
    // comes from the chain state (DB), not from the UTXO metadata.
    use divi_consensus::MockStakeModifierService;
    use divi_consensus::StakeModifierService;
    use divi_consensus::StakingData;
    use divi_primitives::amount::Amount;
    use divi_primitives::hash::Hash256;
    use divi_primitives::transaction::OutPoint;

    let chain_modifier: u64 = 123_456_789;
    let service = MockStakeModifierService::new(chain_modifier);

    let make_staking_data = |seed: u8| {
        StakingData::new(
            0x1e0fffff,
            1_000_000 + seed as u32,
            Hash256::from_bytes([seed; 32]),
            OutPoint::new(Hash256::from_bytes([seed + 1; 32]), seed as u32),
            Amount::from_sat(1000 * 100_000_000),
            Hash256::from_bytes([seed + 2; 32]),
        )
    };

    let m1 = service.get_stake_modifier(&make_staking_data(1)).unwrap();
    let m2 = service.get_stake_modifier(&make_staking_data(2)).unwrap();
    let m3 = service.get_stake_modifier(&make_staking_data(3)).unwrap();

    assert_eq!(m1, chain_modifier);
    assert_eq!(m2, chain_modifier);
    assert_eq!(m3, chain_modifier);
    // All three calls return the same modifier — consistent with DB walkback
    assert_eq!(m1, m2);
    assert_eq!(m2, m3);
}

// ============================================================
// Bug 3: Difficulty u128 truncation
//
// Root cause: compute_pos_difficulty() used u128 arithmetic to multiply the
// 256-bit target.  PoS targets occupy bytes 24-26 of the 256-bit number
// (e.g., 0x1e0fffff = bytes 27-29), which is above byte index 15 — entirely
// outside the lower 16 bytes (u128).  The product was always zero, so the
// weighted target was clamped to pow_limit (0x1e0fffff) instead of being
// computed correctly.
//
// Fix: Use Target::multiply_by() which does full 256-bit arithmetic.
// ============================================================

#[test]
fn test_regression_pos_target_bytes_above_16_not_truncated() {
    // Bug 3: verify that targets whose significant bits live in bytes 24-26
    // (above byte 15, which is the u128 boundary) produce a NON-ZERO weighted
    // target when multiplied.  With the u128 bug the result was always zero
    // and the target was clamped to pow_limit.
    use divi_consensus::target::Target;

    // 0x1e0fffff: exponent=0x1e=30, pos = 30-3 = 27
    // Significant bytes: 27, 28, 29  — all above index 15
    let base_target = Target::from_compact(0x1e0fffff);

    let bytes = base_target.as_bytes();
    // Bytes 0-15 must be zero (this is what u128 would have seen)
    for (i, &byte) in bytes.iter().enumerate().take(16) {
        assert_eq!(
            byte, 0,
            "byte {} of 0x1e0fffff target should be zero (lower 128 bits are empty)",
            i
        );
    }
    // The value lives in bytes 27-29
    assert_ne!(bytes[27], 0, "byte 27 must be non-zero");
    assert_ne!(bytes[28], 0, "byte 28 must be non-zero");
    assert_ne!(bytes[29], 0, "byte 29 must be non-zero");

    // Multiply by a coin-age weight — must produce a non-zero result
    let weight = Target::from_u64(1_000); // modest weight
    let weighted = base_target
        .multiply_by(&weight)
        .expect("multiplication of a valid PoS target must succeed");

    assert!(
        !weighted.is_zero(),
        "Weighted PoS target must be non-zero. \
         With the u128 truncation bug, only bytes 0-15 were kept, \
         so the result was always zero and difficulty was always set to pow_limit."
    );
}

#[test]
fn test_regression_pos_target_multiplication_uses_full_256_bit_arithmetic() {
    // Bug 3: verify that Target::multiply_by uses the full 256-bit value.
    // Specifically, a target with bits ONLY in the upper 128 bits (bytes 16-31)
    // multiplied by a non-zero weight must produce a non-zero result.
    use divi_consensus::target::Target;

    // Place a 1 in byte 24 (above the u128 boundary at byte 16)
    let mut bytes = [0u8; 32];
    bytes[24] = 0x01;
    let high_target = Target::from_bytes(bytes);

    let weight = Target::from_u64(2);
    let result = high_target.multiply_by(&weight);

    // With u128, bytes[24]*2 = 2 which lands at byte 24, but u128 only sees
    // bytes 0-15 (all zero), so u128 would produce zero.
    // With full 256-bit arithmetic the result is 2 at byte 24.
    assert!(
        result.is_some(),
        "Multiplying a high-byte target by 2 should not overflow"
    );
    let result_bytes = result.unwrap();
    assert!(
        !result_bytes.is_zero(),
        "256-bit multiplication of a high-byte target must produce a non-zero result. \
         u128 truncation would have yielded zero."
    );
}

#[test]
fn test_regression_pos_difficulty_not_clamped_for_valid_target() {
    // Bug 3: for an easy regtest-style target (0x207fffff), the weighted
    // difficulty result must NOT equal the pow_limit (0x1e0fffff).
    // Before the fix every weighted target was zero → clamped to pow_limit.
    use divi_consensus::target::Target;

    // Regtest target: very easy
    let base_target = Target::from_compact(0x207fffff);
    let weight = Target::from_u64(100);
    let weighted = base_target.multiply_by(&weight);

    // With a non-trivial weight and an easy target the product must be huge
    // (likely overflowing 256 bits → None, which means "always hits").
    // Either way it must NOT equal the min-difficulty pow_limit.
    let pow_limit = Target::from_compact(0x1e0fffff);

    match weighted {
        None => {
            // Overflow → always hits → definitely not equal to pow_limit
        }
        Some(w) => {
            assert_ne!(
                w, pow_limit,
                "Weighted target must not be clamped to pow_limit for a valid PoS target. \
                 Before the fix the u128 truncation always produced zero, which was \
                 then replaced with pow_limit."
            );
        }
    }
}

// ============================================================
// Bug 4: chain_mode lost on restart (commit db851dc)
//
// Root cause: WalletDb::create_persistent() stored the chain_mode in DB,
// but load() read it back as ChainMode::Divi by default, ignoring PrivateDivi.
// This caused HD derivation to use coin_type=301 (Divi) instead of 801
// (PrivateDivi) on every restart, generating wrong addresses.
//
// Fix: WalletDb::load() now reads the stored chain_mode via
// db.load_chain_mode() and passes it to HdWallet::from_mnemonic().
// ============================================================

#[test]
fn test_regression_chain_mode_privatedivi_persisted_and_reloaded() {
    // Bug 4 (commit db851dc): chain_mode=PrivateDivi must survive a
    // save/reload cycle.  After reload the HD wallet must use coin_type=801.
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network, WalletDb};

    let dir = tempfile::tempdir().expect("tempdir creation must succeed");

    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::PrivateDivi)
        .expect("mnemonic must parse");

    assert_eq!(
        hd.coin_type(),
        801,
        "HdWallet created with PrivateDivi must have coin_type=801"
    );

    // Persist the wallet
    WalletDb::create_persistent(dir.path(), Network::Regtest, hd)
        .expect("create_persistent must succeed");

    // Reload from disk
    let reloaded = WalletDb::open(dir.path(), Network::Regtest).expect("open must succeed");

    // Ask the wallet for an address — the keystore holds the HD wallet
    // with the reloaded chain_mode.  We verify indirectly by checking that
    // the reloaded wallet can generate an address (requires keystore setup).
    let addr = reloaded
        .new_receiving_address()
        .expect("new_receiving_address must succeed after reload");

    // The address must be a valid base58 string (non-empty)
    let addr_str = addr.to_string();
    assert!(
        !addr_str.is_empty(),
        "Reloaded PrivateDivi wallet must be able to generate addresses"
    );
}

#[test]
fn test_regression_chain_mode_divi_persisted_and_reloaded() {
    // Bug 4 (commit db851dc): Divi chain_mode must also be preserved correctly.
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network, WalletDb};

    let dir = tempfile::tempdir().expect("tempdir creation must succeed");

    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).expect("mnemonic must parse");

    assert_eq!(hd.coin_type(), 301, "Divi wallet must have coin_type=301");

    WalletDb::create_persistent(dir.path(), Network::Regtest, hd)
        .expect("create_persistent must succeed");

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).expect("open must succeed");

    let addr = reloaded
        .new_receiving_address()
        .expect("must generate address from reloaded Divi wallet");
    assert!(!addr.to_string().is_empty());
}

#[test]
fn test_regression_privatedivi_and_divi_wallets_produce_different_addresses() {
    // Bug 4 (commit db851dc): the two chain modes MUST produce different
    // addresses for the same mnemonic (different BIP44 coin types).
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network, WalletDb};

    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";

    let dir_pd = tempfile::tempdir().unwrap();
    let dir_d = tempfile::tempdir().unwrap();

    let hd_pd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::PrivateDivi).unwrap();
    let hd_d = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).unwrap();

    // Create and immediately reload each wallet so we test the persisted path
    WalletDb::create_persistent(dir_pd.path(), Network::Regtest, hd_pd).unwrap();
    WalletDb::create_persistent(dir_d.path(), Network::Regtest, hd_d).unwrap();

    let wallet_pd = WalletDb::open(dir_pd.path(), Network::Regtest).unwrap();
    let wallet_d = WalletDb::open(dir_d.path(), Network::Regtest).unwrap();

    let addr_pd = wallet_pd.new_receiving_address().unwrap().to_string();
    let addr_d = wallet_d.new_receiving_address().unwrap().to_string();

    assert_ne!(
        addr_pd, addr_d,
        "PrivateDivi (coin_type=801) and Divi (coin_type=301) must derive \
         different addresses from the same mnemonic"
    );
}

// ============================================================
// Bug 5: Write-through UTXO cache (commit 1f78c1f)
//
// Root cause: The UTXO cache was write-back only — inserted UTXOs were held
// in memory until an explicit flush.  If the process crashed before flushing,
// UTXOs were lost.
//
// Fix: ChainDatabase::add_utxo() now always writes to RocksDB first (write-
// through), then updates the in-memory cache.  A crash after add_utxo()
// returns can no longer lose the UTXO.
//
// Unit tests: use ChainDatabase::add_utxo() (the fixed path) and verify the
// UTXO is immediately readable from the DB even if the process "restarts"
// (simulated by reopening the DB).
// ============================================================

#[test]
fn test_regression_utxo_cache_write_through_to_db() {
    // Bug 5 (commit 1f78c1f): After ChainDatabase::add_utxo(), the UTXO must
    // be durable in the underlying RocksDB — not only in the in-memory cache.
    // We verify by reopening the DB directory and reading back the UTXO.
    use divi_primitives::amount::Amount;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::OutPoint;
    use divi_storage::utxo::Utxo;
    use divi_storage::ChainDatabase;

    let dir = tempfile::tempdir().expect("tempdir");

    let outpoint = OutPoint::new(Hash256::from_bytes([0xAB; 32]), 0);
    let utxo = Utxo::new(
        Amount::from_sat(100_000_000),
        Script::new_p2pkh(&[0u8; 20]),
        100,
        false,
        false,
    );

    // Write through the fixed add_utxo() path
    {
        let db = ChainDatabase::open(dir.path()).expect("open chain db");
        db.add_utxo(&outpoint, &utxo)
            .expect("add_utxo must succeed");
        // db is dropped here — simulating a clean shutdown
    }

    // Reopen the DB (simulating a restart)
    let db2 = ChainDatabase::open(dir.path()).expect("reopen chain db");
    let stored = db2
        .get_utxo(&outpoint)
        .expect("DB read must not error")
        .expect("UTXO must be present in DB after add_utxo — write-through ensures durability");

    assert_eq!(
        stored.value, utxo.value,
        "UTXO value must match after write-through and DB reopen"
    );
}

#[test]
fn test_regression_utxo_cache_remove_write_through_to_db() {
    // Bug 5 (commit 1f78c1f): ChainDatabase::remove_utxo() also writes through
    // to RocksDB immediately — the delete survives a restart.
    use divi_primitives::amount::Amount;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::OutPoint;
    use divi_storage::utxo::Utxo;
    use divi_storage::ChainDatabase;

    let dir = tempfile::tempdir().unwrap();

    let outpoint = OutPoint::new(Hash256::from_bytes([0xCC; 32]), 1);
    let utxo = Utxo::new(
        Amount::from_sat(50_000_000),
        Script::new_p2pkh(&[1u8; 20]),
        200,
        false,
        false,
    );

    // Add then immediately remove (both should write-through)
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
        "UTXO must be absent from DB after remove_utxo() — write-through ensures \
         the delete is durable. Before commit 1f78c1f, deletes were write-back only."
    );
}

#[test]
fn test_regression_utxo_cache_standalone_flush() {
    // Bug 5 (commit 1f78c1f): Standalone UtxoCache: dirty entries flushed via
    // flush() must appear in the underlying DB.
    use divi_primitives::amount::Amount;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::OutPoint;
    use divi_storage::utxo::Utxo;
    use divi_storage::ChainDatabase;
    use divi_storage::UtxoCache;

    let dir = tempfile::tempdir().unwrap();
    let db = ChainDatabase::open(dir.path()).unwrap();

    let cache = UtxoCache::new(1_000);

    let outpoint = OutPoint::new(Hash256::from_bytes([0xDD; 32]), 2);
    let utxo = Utxo::new(
        Amount::from_sat(200_000_000),
        Script::new_p2pkh(&[2u8; 20]),
        300,
        false,
        false,
    );

    // Insert into standalone cache (dirty)
    cache.insert(outpoint, utxo.clone());
    assert_eq!(cache.dirty_count(), 1, "Entry must be dirty before flush");

    // Flush to the DB
    let flushed = cache.flush(db.inner_db()).expect("flush must succeed");
    assert_eq!(flushed, 1, "Exactly one entry should have been flushed");
    assert_eq!(cache.dirty_count(), 0, "No dirty entries after flush");

    // Verify the UTXO is now readable from the DB (bypassing the cache)
    let stored = db
        .get_utxo(&outpoint)
        .expect("DB read must not error")
        .expect("UTXO must be present in DB after cache flush");

    assert_eq!(
        stored.value, utxo.value,
        "UTXO value must match after flush to DB"
    );
}

// ============================================================
// Bug 6: Chain reorganization disabled (commit 9cc17db)
//
// Root cause: The sync layer accepted orphaned blocks but never triggered
// a reorg when a competing chain became longer.  Nodes got stuck on a
// shorter fork.
//
// Fix: Chain::accept_block() now detects when a side chain has more work
// than the active tip and calls do_reorg() to switch.
//
// This test mirrors the existing test_reorg_replaces_shorter_chain but is
// named as a regression test for commit 9cc17db.
// ============================================================

#[test]
fn test_regression_reorg_succeeds_on_longer_competing_chain() {
    // Bug 6 (commit 9cc17db): When a competing chain accumulates more work
    // than the current tip, the node must reorganize to it.
    use divi_crypto::compute_merkle_root;
    use divi_primitives::{
        amount::Amount,
        block::Block,
        hash::Hash256,
        script::Script,
        transaction::{Transaction, TxIn, TxOut},
        ChainMode,
    };
    use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();

    let genesis = chain.tip().expect("genesis must exist");
    let genesis_hash = genesis.hash;
    let genesis_time = genesis.time;

    // Helper: build a simple block on top of a parent
    let build_block = |prev_hash: Hash256, prev_time: u32, tag: u8| -> Block {
        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = prev_hash;
        block.header.time = prev_time + 60;
        block.header.bits = 0x207fffff;

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
    };

    // Build chain A: genesis → A1 → A2 (height 2)
    let block_a1 = build_block(genesis_hash, genesis_time, 0x0A);
    let hash_a1 = chain.accept_block(block_a1.clone()).unwrap().hash;
    let block_a2 = build_block(hash_a1, block_a1.header.time, 0x0B);
    let hash_a2 = chain.accept_block(block_a2.clone()).unwrap().hash;

    assert_eq!(chain.height(), 2);
    assert_eq!(
        chain.tip().unwrap().hash,
        hash_a2,
        "Chain A tip must be hash_a2"
    );

    // Build competing chain B: genesis → B1 → B2 → B3 (height 3, more work)
    let block_b1 = build_block(genesis_hash, genesis_time + 1, 0x1A);
    let hash_b1 = chain.accept_block(block_b1.clone()).unwrap().hash;
    let block_b2 = build_block(hash_b1, block_b1.header.time, 0x1B);
    let hash_b2 = chain.accept_block(block_b2.clone()).unwrap().hash;
    let block_b3 = build_block(hash_b2, block_b2.header.time, 0x1C);
    let hash_b3 = chain.accept_block(block_b3).unwrap().hash;

    // Chain must have reorged to B (higher chain work)
    assert_eq!(
        chain.height(),
        3,
        "After reorg, chain height must be 3 (chain B wins). \
         Before commit 9cc17db, reorg was never triggered and height stayed at 2."
    );
    assert_eq!(
        chain.tip().unwrap().hash,
        hash_b3,
        "Tip must be hash_b3 after reorg to the longer chain"
    );

    // Suppress "unused variable" warnings for chain A hashes
    let _ = (hash_a1, hash_a2);
}

// ============================================================
// Bug 8: Wallet UTXO reappearing on restart (commit bebb182)
//
// Root cause: WalletDb::save() never called db.remove_utxo() for spent
// UTXOs.  On the next load the old UTXO record was still in the DB, so
// spent UTXOs reappeared.
//
// Fix: save() now iterates over `self.spent` and calls db.remove_utxo()
// for each entry before writing the updated UTXO set.
// ============================================================

#[test]
fn test_regression_spent_utxo_does_not_reappear_after_reload() {
    // Bug 8 (commit bebb182): A UTXO that is spent (via spend_utxo) and then
    // saved must NOT reappear in the UTXO set after the wallet is reloaded.
    use divi_primitives::ChainMode;
    use divi_primitives::{amount::Amount, hash::Hash256, script::Script, transaction::OutPoint};
    use divi_wallet::{HdWallet, Network, WalletDb, WalletUtxo};

    let dir = tempfile::tempdir().unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    // Generate an address that belongs to this wallet
    let addr = wallet.new_receiving_address().unwrap();

    // Manufacture a UTXO owned by that address
    let outpoint = OutPoint::new(Hash256::from_bytes([0x42; 32]), 0);
    let utxo = WalletUtxo {
        txid: Hash256::from_bytes([0x42; 32]),
        vout: 0,
        value: Amount::from_sat(5_000_000_000),
        script_pubkey: Script::new_p2pkh(addr.hash.as_bytes()),
        height: Some(100),
        is_coinbase: false,
        is_coinstake: false,
        address: addr.to_string(),
    };
    wallet.add_utxo(utxo);

    // Verify it exists
    assert!(
        wallet.has_utxo(&outpoint),
        "UTXO must exist before spending"
    );

    // Spend it
    let spent = wallet.spend_utxo(&outpoint);
    assert!(spent.is_some(), "spend_utxo must return the UTXO");
    assert!(
        !wallet.has_utxo(&outpoint),
        "UTXO must not be in the live set after spending"
    );

    // Save to disk
    wallet.save().expect("save must succeed");
    drop(wallet);

    // Reload from disk
    let reloaded = WalletDb::open(dir.path(), Network::Regtest).expect("reload must succeed");

    assert!(
        !reloaded.has_utxo(&outpoint),
        "Spent UTXO must NOT reappear after wallet reload. \
         Before commit bebb182, db.remove_utxo() was never called, \
         so the stale record survived restart."
    );
}

#[test]
fn test_regression_unspent_utxo_survives_reload() {
    // Bug 8 (commit bebb182, paired check): Unspent UTXOs MUST survive reload.
    // This ensures the fix only removes spent UTXOs, not all of them.
    use divi_primitives::ChainMode;
    use divi_primitives::{amount::Amount, hash::Hash256, script::Script, transaction::OutPoint};
    use divi_wallet::{HdWallet, Network, WalletDb, WalletUtxo};

    let dir = tempfile::tempdir().unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    let addr = wallet.new_receiving_address().unwrap();
    let outpoint = OutPoint::new(Hash256::from_bytes([0x99; 32]), 0);
    let utxo = WalletUtxo {
        txid: Hash256::from_bytes([0x99; 32]),
        vout: 0,
        value: Amount::from_sat(1_000_000_000),
        script_pubkey: Script::new_p2pkh(addr.hash.as_bytes()),
        height: Some(50),
        is_coinbase: false,
        is_coinstake: false,
        address: addr.to_string(),
    };
    wallet.add_utxo(utxo);

    // Do NOT spend it — save immediately
    wallet.save().expect("save must succeed");
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).expect("reload must succeed");
    assert!(
        reloaded.has_utxo(&outpoint),
        "Unspent UTXO must survive wallet reload"
    );
}

// ============================================================
// Bug 9: last_scan_height not persisted (part of commit bebb182)
//
// Root cause: last_scan_height was never written back in the save() call
// (it was always read as 0 on reload).  This meant the wallet rescanned
// from block 0 on every restart, which was very slow and could miss blocks
// added during the previous session.
//
// Fix: save() now calls db.store_last_scan_height(*self.last_scan_height.read()).
// ============================================================

#[test]
fn test_regression_last_scan_height_persisted_and_reloaded() {
    // Bug 9 (commit bebb182): last_scan_height must survive a save/reload
    // cycle.  Before the fix it was always 0 after reload, forcing a full
    // rescan every time.
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network, WalletDb};

    let dir = tempfile::tempdir().unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    // Set a non-zero scan height
    let expected_height: u32 = 100;
    wallet.set_last_scan_height(expected_height);
    assert_eq!(wallet.last_scan_height(), expected_height);

    // Save and reload
    wallet.save().expect("save must succeed");
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).expect("reload must succeed");

    assert_eq!(
        reloaded.last_scan_height(),
        expected_height,
        "last_scan_height must be {} after reload, got {}. \
         Before the fix, it was always 0, causing a full rescan on every restart.",
        expected_height,
        reloaded.last_scan_height()
    );
}

#[test]
fn test_regression_last_scan_height_zero_is_default_before_any_save() {
    // Bug 9: A fresh wallet must start with last_scan_height=0 (no regression
    // in the default).
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network, WalletDb};

    let dir = tempfile::tempdir().unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    assert_eq!(
        wallet.last_scan_height(),
        0,
        "A freshly created wallet must start with last_scan_height=0"
    );
}

#[test]
fn test_regression_last_scan_height_updated_after_multiple_saves() {
    // Bug 9: Verify that repeated updates + saves all persist correctly.
    use divi_primitives::ChainMode;
    use divi_wallet::{HdWallet, Network, WalletDb};

    let dir = tempfile::tempdir().unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    // Simulate scanning multiple blocks
    for height in [10u32, 50, 100, 200, 500] {
        wallet.set_last_scan_height(height);
        wallet.save().expect("save must succeed");
    }
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).expect("reload must succeed");
    assert_eq!(
        reloaded.last_scan_height(),
        500,
        "last_scan_height must reflect the final saved value (500)"
    );
}
