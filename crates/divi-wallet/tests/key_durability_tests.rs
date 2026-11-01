// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! A key handed out by the wallet must be on disk (encrypted, on an encrypted
//! wallet) before the call returns. None of these tests lets a block-driven
//! `save_incremental` run between creating a key and locking or reopening.

use divi_crypto::keys::SecretKey;
use divi_crypto::{sign_message, verify_message};
use divi_primitives::ChainMode;
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use std::path::Path;
use tempfile::tempdir;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn new_wallet(path: &Path) -> WalletDb {
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    WalletDb::create_persistent(path, Network::Testnet, hd).unwrap()
}

/// A saved, encrypted, locked wallet: the state `encryptwallet` leaves behind
fn new_encrypted_wallet(path: &Path) -> WalletDb {
    let wallet = new_wallet(path);
    wallet.save().unwrap();
    wallet.encrypt_wallet("pw").unwrap();
    wallet
}

/// The wallet owns `addr` with a usable private key
fn assert_owned_and_signs(wallet: &WalletDb, addr: &Address) {
    assert!(wallet.is_mine(addr), "{} not ismine", addr);
    assert!(!wallet.is_watch_only(addr), "{} is watch-only", addr);
    let entry = wallet.get_key_by_address(addr).unwrap();
    let secret = entry
        .secret
        .as_ref()
        .unwrap_or_else(|| panic!("private key for {} is gone", addr));
    assert_eq!(secret.public_key().to_bytes(), entry.public.to_bytes());
    let sig = sign_message(secret, b"test");
    assert!(verify_message(&entry.public, &sig, b"test"));
}

#[test]
fn new_address_survives_immediate_lock() {
    let dir = tempdir().unwrap();
    let wallet = new_encrypted_wallet(&dir.path().join("wallet"));
    wallet.unlock("pw", 60).unwrap();
    let addr = wallet.new_receiving_address().unwrap();
    wallet.lock();

    assert!(wallet.is_mine(&addr));
    assert!(!wallet.is_watch_only(&addr));
    wallet.unlock("pw", 60).unwrap();
    assert_owned_and_signs(&wallet, &addr);
}

#[test]
fn new_address_survives_lock_and_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_encrypted_wallet(&path);
    wallet.unlock("pw", 60).unwrap();
    let addr = wallet.new_receiving_address().unwrap();
    wallet.lock();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(wallet.is_mine(&addr));
    assert!(!wallet.is_watch_only(&addr));
    wallet.unlock("pw", 60).unwrap();
    assert_owned_and_signs(&wallet, &addr);
    // The receiving index was persisted with the key: no address is handed out twice
    let next = wallet.new_receiving_address().unwrap();
    assert_ne!(next, addr);
}

#[test]
fn new_address_survives_restart_without_lock() {
    // A crash while unlocked: nothing but the creation-time write can have stored it
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_encrypted_wallet(&path);
    wallet.unlock("pw", 60).unwrap();
    let addr = wallet.new_receiving_address().unwrap();
    let change = wallet.new_change_address().unwrap();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    wallet.unlock("pw", 60).unwrap();
    assert_owned_and_signs(&wallet, &addr);
    assert_owned_and_signs(&wallet, &change);
}

#[test]
fn change_address_survives_lock_and_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_encrypted_wallet(&path);
    wallet.unlock("pw", 60).unwrap();
    let change = wallet.new_change_address().unwrap();
    wallet.lock();
    assert!(wallet.is_mine(&change));
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(wallet.is_mine(&change));
    assert!(wallet.is_change_address(&change));
    wallet.unlock("pw", 60).unwrap();
    assert_owned_and_signs(&wallet, &change);
}

#[test]
fn auto_relock_keeps_new_key() {
    let dir = tempdir().unwrap();
    let wallet = new_encrypted_wallet(&dir.path().join("wallet"));
    wallet.unlock("pw", 1).unwrap();
    let addr = wallet.new_receiving_address().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1300));
    assert!(wallet.is_locked());
    wallet.unlock("pw", 60).unwrap();
    assert_owned_and_signs(&wallet, &addr);
}

#[test]
fn imported_key_survives_lock_and_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_encrypted_wallet(&path);
    wallet.unlock("pw", 60).unwrap();
    let imported = SecretKey::new_random();
    let expected = imported.as_bytes().to_vec();
    let addr = wallet.import_key(imported, None);
    wallet.lock();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    wallet.unlock("pw", 60).unwrap();
    assert_owned_and_signs(&wallet, &addr);
    assert_eq!(
        wallet
            .get_key_by_address(&addr)
            .unwrap()
            .secret
            .unwrap()
            .as_bytes(),
        &expected[..]
    );
}

#[test]
fn keypool_refill_survives_lock_and_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_encrypted_wallet(&path);
    wallet.unlock("pw", 60).unwrap();
    // walletpassphrase already topped the pool up to the default size, 1000
    // keys per chain; 1005 per chain adds 5 receiving and 5 change keys
    assert_eq!(wallet.refill_keypool(Some(1005)).unwrap(), 10);
    let pool: Vec<Address> = wallet.get_addresses();
    assert_eq!(pool.len(), 2010);
    wallet.lock();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert_eq!(wallet.keypool_size(), 2010);
    wallet.unlock("pw", 60).unwrap();
    for addr in &pool {
        assert_owned_and_signs(&wallet, addr);
    }
}

#[test]
fn unencrypted_new_keys_survive_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    wallet.save().unwrap();
    let addr = wallet.new_receiving_address().unwrap();
    let change = wallet.new_change_address().unwrap();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert_owned_and_signs(&wallet, &addr);
    assert_owned_and_signs(&wallet, &change);
}

#[test]
fn watch_only_import_survives_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    wallet.save().unwrap();
    let foreign = Address::p2pkh(&SecretKey::new_random().public_key(), Network::Testnet);
    wallet.import_watch_only_address(&foreign, None).unwrap();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(wallet.is_mine(&foreign));
    assert!(wallet.is_watch_only(&foreign));
}
