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

//! A locked wallet hands out keys from its keypool, as Divi Core does: keys
//! derived while the seed was in memory, their secrets stored encrypted. The
//! pool keys are the next HD indexes, so none may be skipped or handed out
//! twice, also across a restart.

use divi_crypto::{sign_message, verify_message};
use divi_primitives::ChainMode;
use divi_wallet::{Address, HdWallet, KeyEntry, Network, WalletDb};
use std::path::Path;
use tempfile::tempdir;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A saved, encrypted, locked wallet: the state `encryptwallet` leaves behind
fn new_encrypted_wallet(path: &Path) -> WalletDb {
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(path, Network::Testnet, hd).unwrap();
    wallet.save().unwrap();
    wallet.encrypt_wallet("pw").unwrap();
    wallet
}

/// Address of the HD key at `index` of the receiving or change chain (a
/// testnet wallet derives with Divi Core's testnet coin type, 1)
fn hd_address(change: bool, index: u32) -> Address {
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi)
        .unwrap()
        .with_coin_type(1);
    let key = if change {
        hd.derive_change(0, index).unwrap()
    } else {
        hd.derive_receiving(0, index).unwrap()
    };
    KeyEntry::new(key.secret_key().unwrap()).address(Network::Testnet)
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
    let sig = sign_message(secret, b"test");
    assert!(verify_message(&entry.public, &sig, b"test"));
}

#[test]
fn locked_wallet_hands_out_next_hd_keys_from_pool() {
    let dir = tempdir().unwrap();
    let wallet = new_encrypted_wallet(&dir.path().join("wallet"));
    assert!(wallet.is_locked());

    let a = wallet
        .new_receiving_address()
        .expect("getnewaddress while locked");
    let b = wallet
        .new_receiving_address()
        .expect("second key while locked");
    let c = wallet
        .new_change_address()
        .expect("change key while locked");
    assert_eq!(a, hd_address(false, 0));
    assert_eq!(b, hd_address(false, 1));
    assert_eq!(c, hd_address(true, 0));
    for addr in [&a, &b, &c] {
        assert!(wallet.is_mine(addr) && !wallet.is_watch_only(addr));
    }

    wallet.unlock("pw", 60).unwrap();
    for addr in [&a, &b, &c] {
        assert_owned_and_signs(&wallet, addr);
    }
    // Unlocked, the next key follows on without a gap
    assert_eq!(
        wallet.new_receiving_address().unwrap(),
        hd_address(false, 2)
    );
}

#[test]
fn pool_key_handed_out_while_locked_survives_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_encrypted_wallet(&path);
    let a = wallet
        .new_receiving_address()
        .expect("getnewaddress while locked");
    // No save(), no block: the call itself must have stored the index advance
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(wallet.is_locked());
    assert!(wallet.is_mine(&a) && !wallet.is_watch_only(&a));
    // Not handed out twice after the restart, and no index skipped
    let b = wallet.new_receiving_address().unwrap();
    assert_eq!(b, hd_address(false, 1));
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    wallet.unlock("pw", 60).unwrap();
    assert_owned_and_signs(&wallet, &a);
    assert_owned_and_signs(&wallet, &b);
    assert_eq!(
        wallet.new_receiving_address().unwrap(),
        hd_address(false, 2)
    );
}

#[test]
fn locked_pool_runs_out_and_unlock_tops_it_up() {
    let dir = tempdir().unwrap();
    let wallet = new_encrypted_wallet(&dir.path().join("wallet"));
    let full = wallet.keypool_size();
    assert_eq!(full, 2000, "encryptwallet fills the default keypool");

    let mut handed = 0;
    let err = loop {
        match wallet.new_receiving_address() {
            Ok(_) => handed += 1,
            Err(e) => break e,
        }
        assert!(
            handed <= full,
            "locked wallet derived keys without its seed"
        );
    };
    assert_eq!(err.to_string(), "keypool ran out");
    assert!(handed > 0);
    assert_eq!(wallet.keypool_size(), full - handed);

    // walletpassphrase tops the pool up again
    wallet.unlock("pw", 60).unwrap();
    assert_eq!(wallet.keypool_size(), full);
    wallet.lock();
    assert_eq!(
        wallet.new_receiving_address().unwrap(),
        hd_address(false, handed)
    );
}

#[test]
fn keypool_size_and_refill_are_real() {
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::with_hd_wallet(Network::Testnet, hd);
    // 10 keys of each chain, as Divi Core's keypoolrefill 10
    assert_eq!(wallet.refill_keypool(Some(10)).unwrap(), 20);
    // Nothing is missing: a second refill adds nothing
    assert_eq!(wallet.refill_keypool(Some(10)).unwrap(), 0);
    assert_eq!(wallet.keypool_size(), 20);

    // Change keys handed out past the pool must not make receiving keys look
    // issued: 10 receiving keys are left
    wallet.keystore().set_indices(0, 15);
    assert_eq!(wallet.keypool_size(), 10);
}
