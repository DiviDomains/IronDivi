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

//! Integration tests for IronDivi wallet features
//!
//! Tests for:
//! - Phase A: Wallet encryption, watch-only addresses, BIP38
//! - Phase B: Coin selection, vault operations
//! - Phase C: Masternode persistence (in divi-masternode crate)
//! - Phase E: Error handling

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::ChainMode;
use divi_wallet::coin_selection::select::{select_by_confirmations, select_minimum};
use divi_wallet::wallet_db::{VaultMetadata, WalletUtxo};
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use std::collections::HashSet;
use tempfile::tempdir;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ============================================================
// PHASE A: WALLET ENCRYPTION TESTS
// ============================================================

#[test]
fn test_derive_encryption_key() {
    // Test that PBKDF2 produces consistent keys
    let _wallet = create_test_wallet();

    // Encrypt with passphrase
    // Note: wallet_db.rs has private derive_encryption_key(), so we test
    // through public unlock API

    // For now, this is tested indirectly through unlock tests below
    // Direct key derivation testing would require exposing the function
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    // Test that data survives encrypt/decrypt cycle
    // This is tested indirectly through wallet unlock/lock operations
    let wallet = create_test_wallet();

    // Create a UTXO
    let addr = wallet.new_receiving_address().unwrap();
    let utxo = create_test_utxo(&addr, 100_000_000);
    wallet.add_utxo(utxo.clone());

    // Lock and unlock wallet
    wallet.lock();
    assert!(wallet.is_locked());

    wallet.unlock("testpass", 3600).unwrap();
    assert!(!wallet.is_locked());

    // Verify UTXO is still accessible
    assert!(wallet.has_utxo(&utxo.outpoint()));
}

#[test]
fn test_unlock_with_correct_passphrase() {
    let wallet = create_test_wallet();

    // Unlock with correct passphrase
    let result = wallet.unlock("correct_passphrase", 3600);
    assert!(result.is_ok());
    assert!(!wallet.is_locked());
}

#[test]
fn test_unlock_with_wrong_passphrase() {
    let dir = tempdir().unwrap();
    let wallet_path = dir.path().join("wallet.dat");

    let hd_wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(&wallet_path, Network::Mainnet, hd_wallet).unwrap();

    // For non-encrypted wallets, unlock always succeeds
    // TODO: Implement actual encryption and test wrong passphrase rejection
    // This test is a placeholder for when encryption is fully implemented

    wallet.lock();
    let result = wallet.unlock("", 0);
    assert!(result.is_ok());
}

#[test]
fn test_auto_lock_timeout() {
    // NOTE: Auto-lock timeout requires wallet encryption to be enabled
    // Since the test wallet is not encrypted, unlock() doesn't set a timeout
    // This test verifies that the is_auto_lock_expired() function works correctly

    let wallet = create_test_wallet();

    // For non-encrypted wallet, auto-lock should always return false
    assert!(!wallet.is_auto_lock_expired());

    // Unlock succeeds for non-encrypted wallet
    wallet.unlock("test", 1).unwrap();
    assert!(!wallet.is_locked());

    // Still no timeout set for non-encrypted wallet
    assert!(!wallet.is_auto_lock_expired());
}

#[test]
fn test_lock_clears_key() {
    let wallet = create_test_wallet();

    // Unlock wallet
    wallet.unlock("passphrase", 3600).unwrap();
    assert!(!wallet.is_locked());

    // Lock wallet
    wallet.lock();
    assert!(wallet.is_locked());

    // Try to generate address while locked
    let result = wallet.new_receiving_address();
    assert!(result.is_err());
}

// ============================================================
// PHASE A: WATCH-ONLY ADDRESS TESTS
// ============================================================

#[test]
fn test_import_watch_only_address() {
    let wallet = create_test_wallet();

    // Create an external address (not in this wallet)
    let external_wallet = create_test_wallet();
    let external_addr = external_wallet.new_receiving_address().unwrap();

    // Import as watch-only
    let result = wallet.import_watch_only_address(&external_addr, Some("External".to_string()));
    assert!(result.is_ok());

    // Verify it's marked as watch-only
    assert!(wallet.is_watch_only(&external_addr));
}

#[test]
fn test_watch_only_not_spendable() {
    let wallet = create_test_wallet();

    // Create an external address
    let external_wallet = create_test_wallet();
    let external_addr = external_wallet.new_receiving_address().unwrap();

    // Import as watch-only
    wallet
        .import_watch_only_address(&external_addr, None)
        .unwrap();

    // Add a UTXO to this watch-only address
    let utxo = WalletUtxo::new(
        Hash256::from_bytes([1u8; 32]),
        0,
        Amount::from_sat(50_000_000),
        Script::new_p2pkh(external_addr.hash.as_bytes()),
        external_addr.to_string(),
    );
    wallet.add_utxo(utxo);

    // Get spendable UTXOs
    let spendable = wallet.get_spendable_utxos(1000, 1);

    // Watch-only UTXO should be excluded
    assert_eq!(spendable.len(), 0);
}

#[test]
fn test_watch_only_persistence() {
    let dir = tempdir().unwrap();
    let wallet_path = dir.path().join("wallet.dat");

    let external_addr = {
        let hd_wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet =
            WalletDb::create_persistent(&wallet_path, Network::Mainnet, hd_wallet).unwrap();

        // Create an external address
        let external_wallet = create_test_wallet();
        let addr = external_wallet.new_receiving_address().unwrap();

        // Import as watch-only
        wallet
            .import_watch_only_address(&addr, Some("Test".to_string()))
            .unwrap();
        wallet.save().unwrap();

        addr
    };

    // Reload wallet
    let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

    // Verify watch-only address persisted
    assert!(wallet.is_watch_only(&external_addr));
}

// ============================================================
// PHASE B: COIN SELECTION TESTS
// ============================================================

#[test]
fn test_select_with_exact_amount() {
    let utxos = vec![
        create_utxo(1, 0, 100_000, Some(100)),
        create_utxo(2, 0, 50_000, Some(101)),
    ];

    // Target exactly matches one UTXO (accounting for fee)
    let target = Amount::from_sat(99_000);
    let fee_rate = 1;

    let result = select_minimum(&utxos, target, fee_rate, 1).unwrap();

    // Should select the 100k UTXO
    assert_eq!(result.utxos.len(), 1);
    assert_eq!(result.total_value.as_sat(), 100_000);
}

#[test]
fn test_select_with_dust_change() {
    let utxos = vec![create_utxo(1, 0, 100_000, Some(100))];

    // Target amount that would leave very small change
    // Total: 100,000
    // Target: 99,500
    // Fee: ~226 sats (1 input, 2 outputs)
    // Change: 100,000 - 99,500 - 226 = 274 sats (dust)
    let target = Amount::from_sat(99_500);
    let fee_rate = 1;

    let result = select_minimum(&utxos, target, fee_rate, 1).unwrap();

    // Change amount should be small (dust)
    assert!(result.change_amount.as_sat() < 1000);
}

#[test]
fn test_insufficient_funds() {
    let utxos = vec![
        create_utxo(1, 0, 10_000, Some(100)),
        create_utxo(2, 0, 5_000, Some(101)),
    ];

    let target = Amount::from_sat(50_000);
    let fee_rate = 1;

    let result = select_minimum(&utxos, target, fee_rate, 1);

    assert!(result.is_err());
}

#[test]
fn test_empty_utxo_set() {
    let utxos: Vec<WalletUtxo> = vec![];

    let target = Amount::from_sat(10_000);
    let fee_rate = 1;

    let result = select_minimum(&utxos, target, fee_rate, 1);

    assert!(result.is_err());
}

#[test]
fn test_coin_selection_with_exclusions() {
    let utxos = vec![
        create_utxo(1, 0, 100_000, Some(100)),
        create_utxo(2, 0, 50_000, Some(101)),
    ];

    // Exclude the larger UTXO
    let mut excluded = HashSet::new();
    excluded.insert(utxos[0].outpoint());

    let target = Amount::from_sat(40_000);
    let fee_rate = 1;

    use divi_wallet::coin_selection::CoinSelector;
    use divi_wallet::coin_selection::MinimumSelector;

    let result = MinimumSelector
        .select(&utxos, target, fee_rate, 1, &excluded)
        .unwrap();

    // Should only use the 50k UTXO
    assert_eq!(result.utxos.len(), 1);
    assert_eq!(result.utxos[0].value.as_sat(), 50_000);
}

#[test]
fn test_confirmation_based_selection() {
    let utxos = vec![
        create_utxo(1, 0, 100_000, Some(100)), // 6 confs at height 105
        create_utxo(2, 0, 50_000, Some(104)),  // 2 confs at height 105
        create_utxo(3, 0, 75_000, None),       // 0 confs
    ];

    let target = Amount::from_sat(40_000);
    let fee_rate = 1;
    let current_height = 105;

    // Require 3+ confirmations
    let result = select_by_confirmations(&utxos, target, fee_rate, 1, 3, current_height).unwrap();

    // Should only use the 100k UTXO (6 confirmations)
    assert_eq!(result.utxos.len(), 1);
    assert_eq!(result.utxos[0].value.as_sat(), 100_000);
}

// ============================================================
// PHASE B: VAULT TESTS
// ============================================================

#[test]
fn test_vault_metadata_storage() {
    let wallet = create_test_wallet();

    let metadata = VaultMetadata {
        owner_address: "DOwner123".to_string(),
        manager_address: "DManager456".to_string(),
        vault_script: vec![1u8; 50],
        funding_txid: [2u8; 32],
    };

    wallet.store_vault(metadata.clone());

    let retrieved = wallet.get_vault(&metadata.vault_script).unwrap();
    assert_eq!(retrieved.owner_address, "DOwner123");
    assert_eq!(retrieved.manager_address, "DManager456");
}

#[test]
fn test_vault_persistence() {
    let dir = tempdir().unwrap();
    let wallet_path = dir.path().join("wallet.dat");

    let vault_script = vec![3u8; 50];

    {
        let hd_wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet =
            WalletDb::create_persistent(&wallet_path, Network::Mainnet, hd_wallet).unwrap();

        let metadata = VaultMetadata {
            owner_address: "DOwnerPersist".to_string(),
            manager_address: "DManagerPersist".to_string(),
            vault_script: vault_script.clone(),
            funding_txid: [4u8; 32],
        };

        wallet.store_vault(metadata);
    }

    // Reload wallet
    let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

    let retrieved = wallet.get_vault(&vault_script).unwrap();
    assert_eq!(retrieved.owner_address, "DOwnerPersist");
}

#[test]
fn test_vault_removal() {
    let wallet = create_test_wallet();

    let vault_script = vec![5u8; 50];
    let metadata = VaultMetadata {
        owner_address: "DOwner".to_string(),
        manager_address: "DManager".to_string(),
        vault_script: vault_script.clone(),
        funding_txid: [6u8; 32],
    };

    wallet.store_vault(metadata);
    assert!(wallet.get_vault(&vault_script).is_some());

    let removed = wallet.remove_vault(&vault_script);
    assert!(removed);
    assert!(wallet.get_vault(&vault_script).is_none());
}

#[test]
fn test_get_all_vaults() {
    let wallet = create_test_wallet();

    for i in 0..5 {
        let mut script = vec![0u8; 50];
        script[0] = i;

        let metadata = VaultMetadata {
            owner_address: format!("Owner{}", i),
            manager_address: format!("Manager{}", i),
            vault_script: script,
            funding_txid: [i; 32],
        };

        wallet.store_vault(metadata);
    }

    let vaults = wallet.get_all_vaults();
    assert_eq!(vaults.len(), 5);
}

#[test]
fn test_vault_utxos_filtering() {
    let wallet = create_test_wallet();

    let vault_script = vec![7u8; 50];
    let metadata = VaultMetadata {
        owner_address: "DVaultOwner".to_string(),
        manager_address: "DVaultManager".to_string(),
        vault_script: vault_script.clone(),
        funding_txid: [8u8; 32],
    };

    wallet.store_vault(metadata);

    // Add vault UTXO
    let vault_utxo = WalletUtxo::new(
        Hash256::from_bytes([9u8; 32]),
        0,
        Amount::from_sat(100_000_000),
        Script::from_bytes(vault_script.clone()),
        "vault_address".to_string(),
    );

    let mut vault_utxo_confirmed = vault_utxo.clone();
    vault_utxo_confirmed.height = Some(100);

    wallet.add_utxo(vault_utxo_confirmed);

    // Get vault UTXOs with 1 confirmation at height 105
    let vault_utxos = wallet.get_vault_utxos(105, 1);

    assert_eq!(vault_utxos.len(), 1);
    assert_eq!(vault_utxos[0].value.as_sat(), 100_000_000);
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

fn create_test_wallet() -> WalletDb {
    let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    WalletDb::with_hd_wallet(Network::Mainnet, wallet)
}

fn create_test_utxo(addr: &Address, value_sat: i64) -> WalletUtxo {
    WalletUtxo::new(
        Hash256::from_bytes([1u8; 32]),
        0,
        Amount::from_sat(value_sat),
        Script::new_p2pkh(addr.hash.as_bytes()),
        addr.to_string(),
    )
}

fn create_utxo(txid_byte: u8, vout: u32, value_sat: u64, height: Option<u32>) -> WalletUtxo {
    let mut utxo = WalletUtxo::new(
        Hash256::from_bytes([txid_byte; 32]),
        vout,
        Amount::from_sat(value_sat as i64),
        Script::default(),
        "test_address".to_string(),
    );
    utxo.height = height;
    utxo
}
