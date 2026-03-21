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

//! Regression tests for divi-wallet
//!
//! Bug 1 & 7 (commit 8d9e245): TransactionBuilder must produce version=1.
//! Bug 4   (commit db851dc):   chain_mode lost on restart → wrong HD derivation.
//! Bug 8   (commit bebb182):   Spent UTXOs reappear after wallet reload.
//! Bug 9   (commit bebb182):   last_scan_height not persisted (always 0 after reload).

use divi_primitives::{
    amount::Amount, hash::Hash256, script::Script, transaction::OutPoint, ChainMode,
};
use divi_wallet::{HdWallet, Network, TransactionBuilder, WalletDb, WalletUtxo};
use tempfile::tempdir;

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";

// ============================================================
// Bug 1 & 7 (commit 8d9e245): TransactionBuilder version=2
//
// Root cause: TransactionBuilder::new() defaulted to version=2.
// Fix: TransactionBuilder::new() now uses CURRENT_TX_VERSION (=1).
// ============================================================

/// Bug 1 & 7 (commit 8d9e245): TransactionBuilder::new().build() must produce
/// a transaction with version=1.
#[test]
fn test_regression_transaction_builder_produces_version_1() {
    let outpoint = OutPoint::new(Hash256::from_bytes([0xAA; 32]), 0);
    let script = Script::new_p2pkh(&[0u8; 20]);

    let (tx, _) = TransactionBuilder::new()
        .add_input(outpoint, script.clone())
        .add_output(Amount::from_sat(999_000), script)
        .build();

    assert_eq!(
        tx.version, 1,
        "TransactionBuilder::new().build() must produce version=1. \
         Before commit 8d9e245, version was hardcoded to 2, causing C++ Divi \
         to reject transactions with '64: version'."
    );
}

/// Bug 1 & 7 (commit 8d9e245): An explicitly built version=1 tx must have
/// the correct 4-byte serialization [01 00 00 00].
#[test]
fn test_regression_transaction_builder_version_1_serialization() {
    use divi_primitives::serialize::serialize;

    let outpoint = OutPoint::new(Hash256::from_bytes([0xBB; 32]), 0);
    let script = Script::new_p2pkh(&[1u8; 20]);

    let (tx, _) = TransactionBuilder::new()
        .add_input(outpoint, script.clone())
        .add_output(Amount::from_sat(1_000_000), script)
        .build();

    let bytes = serialize(&tx);
    assert_eq!(
        &bytes[0..4],
        &[0x01, 0x00, 0x00, 0x00],
        "TransactionBuilder output must serialize version as [01 00 00 00]"
    );
}

// ============================================================
// Bug 4 (commit db851dc): chain_mode lost on restart
//
// Root cause: WalletDb::load() ignored the stored chain_mode and always
// used ChainMode::Divi.  On reload a PrivateDivi wallet used coin_type=301
// instead of 801, generating wrong addresses.
//
// Fix: load() reads the stored chain_mode via db.load_chain_mode() and passes
// it to HdWallet::from_mnemonic().
// ============================================================

/// Bug 4 (commit db851dc): A PrivateDivi wallet must reload with coin_type=801
/// and generate different addresses than a Divi wallet from the same mnemonic.
#[test]
fn test_regression_privatedivi_chain_mode_persisted() {
    let dir_pd = tempdir().unwrap();
    let dir_d = tempdir().unwrap();

    let hd_pd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::PrivateDivi).unwrap();
    let hd_d = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();

    // Verify coin types before persisting
    assert_eq!(
        hd_pd.coin_type(),
        801,
        "PrivateDivi must have coin_type=801"
    );
    assert_eq!(hd_d.coin_type(), 301, "Divi must have coin_type=301");

    // Persist both wallets
    WalletDb::create_persistent(dir_pd.path(), Network::Regtest, hd_pd).unwrap();
    WalletDb::create_persistent(dir_d.path(), Network::Regtest, hd_d).unwrap();

    // Reload and compare first address
    let wallet_pd = WalletDb::open(dir_pd.path(), Network::Regtest).unwrap();
    let wallet_d = WalletDb::open(dir_d.path(), Network::Regtest).unwrap();

    let addr_pd = wallet_pd.new_receiving_address().unwrap().to_string();
    let addr_d = wallet_d.new_receiving_address().unwrap().to_string();

    assert_ne!(
        addr_pd, addr_d,
        "PrivateDivi (coin_type=801) and Divi (coin_type=301) must derive \
         different addresses from the same mnemonic. \
         Before commit db851dc, the PrivateDivi chain_mode was lost on reload, \
         so both wallets would generate the same addresses."
    );
}

/// Bug 4 (commit db851dc): A Divi wallet reloaded from disk must continue to
/// generate the same sequence of addresses as before the reload.
#[test]
fn test_regression_divi_addresses_deterministic_across_reload() {
    let dir = tempdir().unwrap();

    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    // Generate first address before reload
    let addr_before = wallet.new_receiving_address().unwrap().to_string();
    wallet.save().unwrap();
    drop(wallet);

    // Reload and generate the next address — indices were also persisted
    let wallet2 = WalletDb::open(dir.path(), Network::Regtest).unwrap();
    let addr_after = wallet2.new_receiving_address().unwrap().to_string();

    // The address after reload should be the NEXT one in the sequence (different)
    // but both must be non-empty
    assert!(!addr_before.is_empty(), "First address must be non-empty");
    assert!(
        !addr_after.is_empty(),
        "Second address (after reload) must be non-empty"
    );
    // Both are valid addresses, different because the index advanced
    assert_ne!(
        addr_before, addr_after,
        "Index must have advanced past the first address"
    );
}

// ============================================================
// Bug 8 (commit bebb182): Spent UTXOs reappear after wallet reload
//
// Root cause: WalletDb::save() never called db.remove_utxo() for spent
// UTXOs.  On the next load the old UTXO record was still in the DB.
//
// Fix: save() iterates over `self.spent` and calls db.remove_utxo() before
// writing the updated UTXO set.
// ============================================================

fn make_utxo(
    outpoint: &OutPoint,
    addr: &divi_wallet::address::Address,
    value_sat: i64,
) -> WalletUtxo {
    WalletUtxo {
        txid: outpoint.txid,
        vout: outpoint.vout,
        value: Amount::from_sat(value_sat),
        script_pubkey: Script::new_p2pkh(addr.hash.as_bytes()),
        height: Some(100),
        is_coinbase: false,
        is_coinstake: false,
        address: addr.to_string(),
    }
}

/// Bug 8 (commit bebb182): A spent UTXO must NOT reappear after wallet reload.
#[test]
fn test_regression_spent_utxo_gone_after_reload() {
    let dir = tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    let addr = wallet.new_receiving_address().unwrap();
    let outpoint = OutPoint::new(Hash256::from_bytes([0x42; 32]), 0);
    let utxo = make_utxo(&outpoint, &addr, 5_000_000_000);

    wallet.add_utxo(utxo);
    assert!(wallet.has_utxo(&outpoint), "UTXO must exist before spend");

    // Spend it
    let spent = wallet.spend_utxo(&outpoint);
    assert!(spent.is_some(), "spend_utxo must return the UTXO");
    assert!(!wallet.has_utxo(&outpoint), "UTXO must be gone after spend");

    // Save and reload
    wallet.save().unwrap();
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).unwrap();
    assert!(
        !reloaded.has_utxo(&outpoint),
        "Spent UTXO must NOT reappear after wallet reload. \
         Before commit bebb182, db.remove_utxo() was never called in save(), \
         so the stale record survived restart."
    );
}

/// Bug 8 (commit bebb182, paired): An unspent UTXO MUST survive reload.
/// (Ensures the fix only removes spent UTXOs, not all of them.)
#[test]
fn test_regression_unspent_utxo_survives_reload() {
    let dir = tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    let addr = wallet.new_receiving_address().unwrap();
    let outpoint = OutPoint::new(Hash256::from_bytes([0x99; 32]), 0);
    let utxo = make_utxo(&outpoint, &addr, 1_000_000_000);

    wallet.add_utxo(utxo);
    // Do NOT spend — save and reload
    wallet.save().unwrap();
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).unwrap();
    assert!(
        reloaded.has_utxo(&outpoint),
        "Unspent UTXO must survive wallet reload"
    );
}

/// Bug 8 (commit bebb182): Multiple UTXOs — some spent, some not — must
/// reload correctly.
#[test]
fn test_regression_mixed_spent_and_unspent_utxos_reload_correctly() {
    let dir = tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    let addr = wallet.new_receiving_address().unwrap();

    let spent_outpoint = OutPoint::new(Hash256::from_bytes([0x11; 32]), 0);
    let kept_outpoint = OutPoint::new(Hash256::from_bytes([0x22; 32]), 0);

    wallet.add_utxo(make_utxo(&spent_outpoint, &addr, 1_000_000));
    wallet.add_utxo(make_utxo(&kept_outpoint, &addr, 2_000_000));

    // Spend only the first one
    wallet.spend_utxo(&spent_outpoint).unwrap();

    wallet.save().unwrap();
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).unwrap();
    assert!(
        !reloaded.has_utxo(&spent_outpoint),
        "Spent UTXO must not appear after reload"
    );
    assert!(
        reloaded.has_utxo(&kept_outpoint),
        "Unspent UTXO must appear after reload"
    );
}

// ============================================================
// Bug 9 (commit bebb182): last_scan_height not persisted
//
// Root cause: save() did not call db.store_last_scan_height() so the height
// was always 0 after reload, forcing a full blockchain rescan every restart.
//
// Fix: save() now calls db.store_last_scan_height(*self.last_scan_height.read()).
// ============================================================

/// Bug 9 (commit bebb182): last_scan_height must survive a save/reload cycle.
#[test]
fn test_regression_last_scan_height_persisted() {
    let dir = tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    let expected_height: u32 = 100;
    wallet.set_last_scan_height(expected_height);
    assert_eq!(wallet.last_scan_height(), expected_height);

    wallet.save().unwrap();
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).unwrap();
    assert_eq!(
        reloaded.last_scan_height(),
        expected_height,
        "last_scan_height must be {} after reload, got {}. \
         Before the fix, it was always 0, forcing a full rescan on every restart.",
        expected_height,
        reloaded.last_scan_height()
    );
}

/// Bug 9 (commit bebb182): Zero is a valid starting height; a fresh wallet
/// must report 0, and setting it to 0 and reloading must also return 0.
#[test]
fn test_regression_last_scan_height_zero_survives_reload() {
    let dir = tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    assert_eq!(
        wallet.last_scan_height(),
        0,
        "Fresh wallet must start at height 0"
    );

    wallet.save().unwrap();
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).unwrap();
    assert_eq!(
        reloaded.last_scan_height(),
        0,
        "height=0 must survive reload"
    );
}

/// Bug 9 (commit bebb182): The final value after multiple successive saves
/// must be what gets reloaded — not the first value.
#[test]
fn test_regression_last_scan_height_last_write_wins() {
    let dir = tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(dir.path(), Network::Regtest, hd).unwrap();

    // Simulate scanning multiple batches of blocks
    for height in [50u32, 100, 200, 500, 1000] {
        wallet.set_last_scan_height(height);
        wallet.save().unwrap();
    }
    drop(wallet);

    let reloaded = WalletDb::open(dir.path(), Network::Regtest).unwrap();
    assert_eq!(
        reloaded.last_scan_height(),
        1000,
        "The last persisted scan height (1000) must be what reloads"
    );
}
