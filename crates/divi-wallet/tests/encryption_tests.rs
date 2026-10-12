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

//! Real wallet encryption: encryptwallet, lock/unlock, passphrase change, persistence.

use divi_crypto::keys::SecretKey;
use divi_primitives::ChainMode;
use divi_wallet::{HdWallet, Network, WalletDb, WalletError};
use std::path::Path;
use tempfile::tempdir;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn new_wallet(path: &Path) -> WalletDb {
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    WalletDb::create_persistent(path, Network::Testnet, hd).unwrap()
}

/// True if any file under `dir` contains `needle`
fn dir_contains(dir: &Path, needle: &[u8]) -> bool {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if dir_contains(&path, needle) {
                return true;
            }
        } else if let Ok(data) = std::fs::read(&path) {
            if data.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn encrypt_removes_plaintext_and_locks() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let addr = wallet.new_receiving_address().unwrap();
    let imported = SecretKey::new_random();
    let imported_bytes = imported.as_bytes().to_vec();
    let imported_addr = wallet.import_key(imported, None);
    let derived_secret = wallet
        .get_key_by_address(&addr)
        .unwrap()
        .secret
        .unwrap()
        .as_bytes()
        .to_vec();
    wallet.save().unwrap();
    assert!(
        dir_contains(&path, MNEMONIC.as_bytes()),
        "sanity: plaintext before"
    );

    assert_eq!(wallet.encryption_status(), "unencrypted");
    wallet.encrypt_wallet("correct horse").unwrap();

    assert!(wallet.is_encrypted());
    assert!(wallet.is_locked());
    assert_eq!(wallet.encryption_status(), "locked");
    assert!(wallet.mnemonic().is_none());
    // Public side still works while locked, the private side is gone
    assert!(wallet.is_mine(&addr));
    assert!(wallet.get_key_by_address(&addr).unwrap().secret.is_none());
    assert!(matches!(
        wallet.new_receiving_address(),
        Err(WalletError::WalletLocked)
    ));

    drop(wallet);
    assert!(
        !dir_contains(&path, MNEMONIC.as_bytes()),
        "mnemonic on disk"
    );
    assert!(
        !dir_contains(&path, &imported_bytes),
        "imported key on disk"
    );
    assert!(!dir_contains(&path, &derived_secret), "derived key on disk");

    // Reopen from disk: encrypted, locked, public data intact
    let reopened = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(reopened.is_encrypted());
    assert!(reopened.is_locked());
    assert!(reopened.is_mine(&addr));
    assert!(reopened.is_mine(&imported_addr));
    assert!(reopened.mnemonic().is_none());
}

#[test]
fn unlock_restores_secrets_and_wrong_passphrase_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let addr = wallet.new_receiving_address().unwrap();
    let imported = SecretKey::new_random();
    let imported_bytes = imported.as_bytes().to_vec();
    let imported_addr = wallet.import_key(imported, None);
    wallet.save().unwrap();
    let expected = wallet
        .get_key_by_address(&addr)
        .unwrap()
        .secret
        .unwrap()
        .as_bytes()
        .to_vec();
    wallet.encrypt_wallet("pw one").unwrap();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(matches!(
        wallet.unlock("not the passphrase", 60),
        Err(WalletError::WrongPassphrase)
    ));
    assert!(wallet.is_locked());
    assert!(matches!(
        wallet.unlock("", 60),
        Err(WalletError::InvalidPassphrase)
    ));

    wallet.unlock("pw one", 60).unwrap();
    assert!(!wallet.is_locked());
    assert_eq!(wallet.encryption_status(), "unlocked");
    assert!(wallet.unlocked_until() > 0);
    assert_eq!(wallet.mnemonic().as_deref(), Some(MNEMONIC));
    assert_eq!(
        wallet
            .get_key_by_address(&addr)
            .unwrap()
            .secret
            .unwrap()
            .as_bytes(),
        &expected[..]
    );
    assert_eq!(
        wallet
            .get_key_by_address(&imported_addr)
            .unwrap()
            .secret
            .unwrap()
            .as_bytes(),
        &imported_bytes[..]
    );
    // HD derivation continues where it left off
    let next = wallet.new_receiving_address().unwrap();
    assert_ne!(next.to_string(), addr.to_string());

    wallet.lock();
    assert!(wallet.is_locked());
    assert!(wallet.mnemonic().is_none());
    assert!(wallet.get_key_by_address(&addr).unwrap().secret.is_none());
}

#[test]
fn keys_created_while_unlocked_are_stored_encrypted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    wallet.save().unwrap();
    wallet.encrypt_wallet("pw").unwrap();
    wallet.unlock("pw", 60).unwrap();

    let addr = wallet.new_receiving_address().unwrap();
    let secret = wallet
        .get_key_by_address(&addr)
        .unwrap()
        .secret
        .unwrap()
        .as_bytes()
        .to_vec();
    wallet.save_incremental().unwrap();
    wallet.save().unwrap();
    drop(wallet);

    assert!(
        !dir_contains(&path, &secret),
        "new key written in plaintext"
    );
    assert!(!dir_contains(&path, MNEMONIC.as_bytes()));

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    wallet.unlock("pw", 60).unwrap();
    assert_eq!(
        wallet
            .get_key_by_address(&addr)
            .unwrap()
            .secret
            .unwrap()
            .as_bytes(),
        &secret[..]
    );
}

#[test]
fn change_passphrase_replaces_old() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    wallet.save().unwrap();
    wallet.encrypt_wallet("old pass").unwrap();

    // Works while locked, and a wrong old passphrase changes nothing
    assert!(matches!(
        wallet.change_passphrase("bad", "new pass"),
        Err(WalletError::WrongPassphrase)
    ));
    wallet.change_passphrase("old pass", "new pass").unwrap();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert!(matches!(
        wallet.unlock("old pass", 60),
        Err(WalletError::WrongPassphrase)
    ));
    wallet.unlock("new pass", 60).unwrap();
    assert_eq!(wallet.mnemonic().as_deref(), Some(MNEMONIC));
}

#[test]
fn encrypt_twice_and_edge_cases() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    assert!(matches!(
        wallet.change_passphrase("a", "b"),
        Err(WalletError::WalletNotEncrypted)
    ));
    assert!(matches!(
        wallet.encrypt_wallet(""),
        Err(WalletError::InvalidPassphrase)
    ));
    assert!(!wallet.is_encrypted());
    wallet.encrypt_wallet("pw").unwrap();
    assert!(matches!(
        wallet.encrypt_wallet("pw2"),
        Err(WalletError::AlreadyEncrypted)
    ));
    // In-memory wallets cannot be encrypted: there is nowhere to keep the sealed key
    let mem = WalletDb::new(Network::Testnet);
    assert!(mem.encrypt_wallet("pw").is_err());
    assert!(!mem.is_encrypted());
}

#[test]
fn unlock_timeout_relocks_and_wipes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let addr = wallet.new_receiving_address().unwrap();
    wallet.save().unwrap();
    wallet.encrypt_wallet("pw").unwrap();
    wallet.unlock("pw", 1).unwrap();
    assert!(!wallet.is_locked());
    std::thread::sleep(std::time::Duration::from_millis(1300));
    assert!(wallet.is_locked());
    assert!(wallet.get_key_by_address(&addr).unwrap().secret.is_none());
}
