// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Saves, key writes and encryption against each other: a change made while a
//! save runs is not lost to it, a failed save keeps what it owed, and no batch
//! built while the wallet was plain lands after it was encrypted. Each wallet
//! is a throwaway made from the test mnemonic in a temporary directory.

use super::*;
use crate::fault;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;
use tempfile::tempdir;

fn new_wallet(path: &std::path::Path) -> Arc<WalletDb> {
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(path, Network::Mainnet, hd).unwrap();
    wallet.save().unwrap();
    Arc::new(wallet)
}

fn reopen(wallet: Arc<WalletDb>, path: &std::path::Path) -> WalletDb {
    drop(Arc::try_unwrap(wallet).ok().expect("wallet still shared"));
    WalletDb::open(path, Network::Mainnet).unwrap()
}

/// Encrypt on another thread while `pause` holds a write of `wallet`: the
/// encryption must wait for that write rather than finish before it
fn encrypt_while_held(wallet: &Arc<WalletDb>, pause: fault::Pause) -> std::thread::JoinHandle<()> {
    let (done_tx, done_rx) = mpsc::channel();
    let encrypter = {
        let wallet = Arc::clone(wallet);
        std::thread::spawn(move || done_tx.send(wallet.encrypt_wallet("pw")).unwrap())
    };
    // Long enough for an unserialized encryption (Argon2id is optimised in
    // test builds) to finish
    let early = done_rx.recv_timeout(Duration::from_secs(2));
    assert!(
        matches!(early, Err(RecvTimeoutError::Timeout)),
        "the encryption finished while a batch built from the plain wallet was unwritten"
    );
    pause.resume();
    std::thread::spawn(move || {
        done_rx.recv().unwrap().unwrap();
        encrypter.join().unwrap();
    })
}

/// A change made while a save is between reading the wallet and writing it
/// stays dirty, so the next save writes it (S21)
fn change_during_save_is_kept(point: &'static str, save: fn(&WalletDb) -> Result<(), WalletError>) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    wallet.mark_address_used("before the save");

    let pause = fault::pause_at(&*wallet, point);
    let saver = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || save(&wallet))
    };
    pause.reached();
    wallet.mark_address_used("during the save");
    pause.resume();
    saver.join().unwrap().unwrap();

    wallet.save_incremental().unwrap();
    let wallet = reopen(wallet, &path);
    assert!(wallet.is_address_used("before the save"));
    assert!(
        wallet.is_address_used("during the save"),
        "a change made during a save was marked clean without being written"
    );
}

#[test]
fn change_during_incremental_save_is_kept() {
    change_during_save_is_kept("wallet incremental batch built", WalletDb::save_incremental);
}

#[test]
fn change_during_full_save_is_kept() {
    change_during_save_is_kept("wallet save batch built", WalletDb::save);
}

/// A save that fails leaves what it was to write dirty for the next one
#[test]
fn failed_incremental_save_keeps_changes_dirty() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    wallet.mark_address_used("owed");

    fault::arm("wallet incremental batch built", 0);
    assert!(wallet.save_incremental().is_err());
    fault::disarm();
    assert!(wallet.dirty.read().addresses.contains("owed"));

    wallet.save_incremental().unwrap();
    assert!(!wallet.dirty.read().any_dirty());
    let wallet = reopen(wallet, &path);
    assert!(wallet.is_address_used("owed"));
}

/// A save holding the plain phrase in its batch is written before the
/// encryption, never after it, so the phrase is gone from disk (S20)
#[test]
fn encryption_waits_for_a_plain_save() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    // The index moved: the next incremental save writes the metadata,
    // the plain phrase among it
    wallet.new_receiving_address().unwrap();

    let pause = fault::pause_at(&*wallet, "wallet incremental batch built");
    let saver = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || wallet.save_incremental())
    };
    pause.reached();
    encrypt_while_held(&wallet, pause).join().unwrap();
    saver.join().unwrap().unwrap();
    assert!(wallet.is_encrypted() && wallet.is_locked());
    // A later save of the encrypted wallet writes nothing plain either
    wallet.mark_address_used("after");
    wallet.save_incremental().unwrap();
    wallet.save().unwrap();

    let wallet = reopen(wallet, &path);
    assert_eq!(wallet.db().unwrap().load_mnemonic().unwrap(), None);
    drop(wallet);
    assert_eq!(
        files_containing(&path, TEST_MNEMONIC.as_bytes()),
        Vec::<std::path::PathBuf>::new()
    );
    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    wallet.unlock("pw", 0).unwrap();
    assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
}

/// A key imported while the wallet is encrypted is neither stripped unsealed
/// nor written plain over the encrypted wallet (S20)
#[test]
fn encryption_waits_for_an_imported_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let secret = [0x5au8; 32];

    let pause = fault::pause_at(&*wallet, "wallet keys batch built");
    let importer = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || {
            let key = divi_crypto::keys::SecretKey::from_bytes(&secret).unwrap();
            wallet.import_key(key, None).unwrap()
        })
    };
    pause.reached();
    encrypt_while_held(&wallet, pause).join().unwrap();
    let address = importer.join().unwrap();
    assert!(wallet.is_encrypted() && wallet.is_locked());

    let wallet = reopen(wallet, &path);
    assert!(wallet
        .db()
        .unwrap()
        .load_keys()
        .unwrap()
        .iter()
        .all(|(_, entry)| entry.secret.is_none()));
    drop(wallet);
    assert_eq!(
        files_containing(&path, &secret),
        Vec::<std::path::PathBuf>::new()
    );
    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    wallet.unlock("pw", 0).unwrap();
    let entry = wallet.get_key_by_address(&address).unwrap();
    assert_eq!(
        entry.secret.as_ref().map(|s| s.as_bytes().to_vec()),
        Some(secret.to_vec())
    );
}

/// Once the encrypted batch is on disk the wallet is encrypted in memory too,
/// even when the flush after it fails: a later save must not write the plain
/// phrase or the encrypted flag 0 back
#[test]
fn encryption_written_but_not_flushed_stays_encrypted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);

    fault::arm("wallet encryption written", 0);
    assert!(matches!(
        wallet.encrypt_wallet("pw"),
        Err(WalletError::EncryptionCleanup(_))
    ));
    fault::disarm();
    assert!(wallet.is_encrypted() && wallet.is_locked());
    wallet.save().unwrap();

    let wallet = reopen(wallet, &path);
    assert!(wallet.is_encrypted());
    assert_eq!(wallet.db().unwrap().load_mnemonic().unwrap(), None);
    wallet.unlock("pw", 0).unwrap();
    assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
}

#[test]
fn failed_incremental_save_merges_addresses_marked_during_write() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    wallet.mark_address_used("before");
    let pause = fault::pause_at(&*wallet, "wallet incremental batch built");
    let saver = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || {
            fault::arm("wallet incremental batch built", 0);
            let result = wallet.save_incremental();
            fault::disarm();
            result
        })
    };
    pause.reached();
    wallet.mark_address_used("during");
    pause.resume();
    assert!(saver.join().unwrap().is_err());
    wallet.save_incremental().unwrap();
    let wallet = reopen(wallet, &path);
    assert!(wallet.is_address_used("before"));
    assert!(wallet.is_address_used("during"));
}
