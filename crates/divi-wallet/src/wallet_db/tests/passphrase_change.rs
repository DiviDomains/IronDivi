// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Passphrase changes and the move of older wallets to the current format
//! (S22): which passphrase a restart opens the wallet with after each result,
//! that no key is sealed in a format the wallet no longer has, that the
//! replaced sealed copies leave the wallet's live files but not older copies
//! of the wallet, and that a move made at unlock waits for a save. Every
//! wallet is a throwaway in a temporary directory, made from the test mnemonic
//! or the checked-in older-format fixture.

use super::*;
use crate::fault;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;
use tempfile::tempdir;

const OLD: &str = "old passphrase";
const NEW: &str = "new passphrase";

fn encrypted_wallet(path: &std::path::Path) -> WalletDb {
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(path, Network::Mainnet, hd).unwrap();
    wallet.new_receiving_address().unwrap();
    wallet.encrypt_wallet(OLD).unwrap();
    wallet
}

fn reopen(wallet: WalletDb, path: &std::path::Path, network: Network) -> WalletDb {
    drop(wallet);
    WalletDb::open(path, network).unwrap()
}

fn sealed_master(wallet: &WalletDb) -> Vec<u8> {
    wallet
        .db()
        .unwrap()
        .load_encryption_metadata()
        .unwrap()
        .unwrap()
        .1
}

fn is_legacy(wallet: &WalletDb) -> bool {
    wallet.db().unwrap().load_kdf_params().unwrap().is_none()
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The older-format fixture, unlocked with its records left in that format
/// (the move's write fails before it reaches the disk)
fn unlocked_legacy_wallet() -> (tempfile::TempDir, std::path::PathBuf, WalletDb) {
    let (dir, path) = legacy_wallet();
    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    fault::arm("sealed master unwritten", 0);
    wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
    fault::disarm();
    assert!(is_legacy(&wallet), "the move was written");
    assert!(!wallet.is_locked());
    (dir, path, wallet)
}

/// After the restart, `passphrase` opens the wallet, the other does not, and
/// every fixture key and `fresh` has its secret
fn assert_legacy_fixture_opens_with(
    wallet: WalletDb,
    path: &std::path::Path,
    passphrase: &str,
    other: &str,
    fresh: &Address,
) {
    let wallet = reopen(wallet, path, Network::Testnet);
    assert!(matches!(
        wallet.unlock(other, 0),
        Err(WalletError::WrongPassphrase)
    ));
    wallet.unlock(passphrase, 0).unwrap();
    assert!(!is_legacy(&wallet));
    assert_fixture_keys_whole(&wallet);
    let entry = wallet.get_key_by_address(fresh).expect("fresh key kept");
    assert!(
        entry.secret.is_some(),
        "a key made after the move lost its secret"
    );
}

/// A change takes the master key sealed under the old passphrase out of the
/// wallet's files; a copy made before still opens with the old passphrase
#[test]
fn change_retires_the_old_sealed_key_but_not_older_copies() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let backup = dir.path().join("older copy");
    let wallet = encrypted_wallet(&path);
    let old_sealed = sealed_master(&wallet);
    drop(wallet);
    assert!(!files_containing(&path, &old_sealed).is_empty());
    copy_dir(&path, &backup);

    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    wallet.change_passphrase(OLD, NEW).unwrap();
    drop(wallet);
    assert_eq!(
        files_containing(&path, &old_sealed),
        Vec::<std::path::PathBuf>::new()
    );

    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    assert!(matches!(
        wallet.unlock(OLD, 0),
        Err(WalletError::WrongPassphrase)
    ));
    wallet.unlock(NEW, 0).unwrap();
    assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
    drop(wallet);

    // Not invalidated: the copy holds the same master key under the old one
    let copy = WalletDb::open(&backup, Network::Mainnet).unwrap();
    copy.unlock(OLD, 0).unwrap();
    assert_eq!(copy.mnemonic().as_deref(), Some(TEST_MNEMONIC));
}

#[test]
fn current_format_import_and_coin_survive_interrupted_passphrase_changes() {
    for (point, active, rejected) in [
        ("sealed master unwritten", OLD, NEW),
        ("sealed master written", NEW, OLD),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let wallet = encrypted_wallet(&path);
        wallet.unlock(OLD, 0).unwrap();
        let address = wallet.import_key(imported_secret(), None).unwrap();
        let payment = paying_tx(&address, 17);
        let outpoint = OutPoint {
            txid: payment.txid(),
            vout: 0,
        };
        wallet.scan_block(Hash256::from_bytes([1; 32]), 1, 1, &[payment]);
        wallet.save().unwrap();
        fault::arm(point, 0);
        let changed = wallet.change_passphrase(OLD, NEW);
        fault::disarm();
        assert_eq!(changed.is_ok(), active == NEW);
        wallet.lock();
        let wallet = reopen(wallet, &path, Network::Mainnet);
        assert!(matches!(
            wallet.unlock(rejected, 0),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.unlock(active, 0).unwrap();
        assert_eq!(
            wallet.get_utxo(&outpoint).unwrap().address,
            address.to_string()
        );
        assert_eq!(
            wallet
                .get_key_by_address(&address)
                .unwrap()
                .secret
                .unwrap()
                .as_bytes(),
            imported_secret().as_bytes()
        );
    }
}

/// A write that never reached the disk changes nothing
#[test]
fn change_not_written_keeps_the_old_passphrase() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = encrypted_wallet(&path);

    fault::arm("sealed master unwritten", 0);
    let changed = wallet.change_passphrase(OLD, NEW);
    fault::disarm();
    assert!(
        matches!(changed, Err(WalletError::Storage(_))),
        "{changed:?}"
    );

    let wallet = reopen(wallet, &path, Network::Mainnet);
    assert!(matches!(
        wallet.unlock(NEW, 0),
        Err(WalletError::WrongPassphrase)
    ));
    wallet.unlock(OLD, 0).unwrap();
    assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
}

/// Cleanup failing after the write is reported as such: the new passphrase
/// is in effect, and an unlocked older wallet seals its next key in the new
/// format
#[test]
fn change_cleanup_failure_reports_the_new_passphrase_in_effect() {
    let (_dir, path, wallet) = unlocked_legacy_wallet();

    fault::arm("passphrase salt written", 0);
    let changed = wallet.change_passphrase(LEGACY_PASSPHRASE, NEW);
    fault::disarm();
    assert!(
        matches!(changed, Err(WalletError::PassphraseChangeCleanup(_))),
        "{changed:?}"
    );
    assert!(!is_legacy(&wallet));

    let fresh = wallet.new_receiving_address().unwrap();
    wallet.lock();
    assert_legacy_fixture_opens_with(wallet, &path, NEW, LEGACY_PASSPHRASE, &fresh);
}

/// A write that reports an error after it reached the disk is read back and
/// taken as written: keys sealed afterwards use the new format
#[test]
fn change_written_despite_an_error_is_taken_as_written() {
    let (_dir, path, wallet) = unlocked_legacy_wallet();

    fault::arm("sealed master written", 0);
    wallet.change_passphrase(LEGACY_PASSPHRASE, NEW).unwrap();
    fault::disarm();

    let fresh = wallet.new_receiving_address().unwrap();
    wallet.lock();
    assert_legacy_fixture_opens_with(wallet, &path, NEW, LEGACY_PASSPHRASE, &fresh);
}

/// The same at unlock: the move is read back, and the wallet unlocks in the
/// format now on disk
#[test]
fn unlock_move_written_despite_an_error_is_taken_as_written() {
    let (_dir, path) = legacy_wallet();
    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();

    fault::arm("sealed master written", 0);
    wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
    fault::disarm();
    assert!(!is_legacy(&wallet));

    let fresh = wallet.new_receiving_address().unwrap();
    wallet.lock();
    assert_legacy_fixture_opens_with(
        wallet,
        &path,
        LEGACY_PASSPHRASE,
        "not the passphrase",
        &fresh,
    );
}

/// The move at unlock takes the records in the older format, and the master
/// key sealed by it, out of the wallet's files; cleanup failing does not fail
/// the unlock
#[test]
fn unlock_move_retires_the_older_records() {
    let (_dir, path) = legacy_wallet();
    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    let db = wallet.db().unwrap();
    let mut old: Vec<Vec<u8>> = db
        .load_encrypted_secrets()
        .unwrap()
        .into_iter()
        .map(|(_, blob)| blob)
        .collect();
    old.push(db.load_encrypted_mnemonic().unwrap().unwrap());
    old.push(sealed_master(&wallet));
    drop(db);

    wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
    assert!(!is_legacy(&wallet));
    let wallet = reopen(wallet, &path, Network::Testnet);
    drop(wallet);
    for blob in &old {
        assert_eq!(
            files_containing(&path, blob),
            Vec::<std::path::PathBuf>::new()
        );
    }

    let (_dir, path) = legacy_wallet();
    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    fault::arm("legacy records written", 0);
    wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
    fault::disarm();
    assert!(!is_legacy(&wallet));
    let fresh = wallet.new_receiving_address().unwrap();
    wallet.lock();
    assert_legacy_fixture_opens_with(
        wallet,
        &path,
        LEGACY_PASSPHRASE,
        "not the passphrase",
        &fresh,
    );
}

/// A save of an unlocked older wallet seals every key in the older format: an
/// unlock moving the wallet meanwhile waits for it, rather than landing first
/// and having the save overwrite its records in a format it no longer reads
#[test]
fn unlock_move_waits_for_a_save() {
    let (_dir, path, wallet) = unlocked_legacy_wallet();
    let wallet = Arc::new(wallet);

    let pause = fault::pause_at(&*wallet, "wallet save batch built");
    let saver = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || wallet.save())
    };
    pause.reached();
    let (done_tx, done_rx) = mpsc::channel();
    let unlocker = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || done_tx.send(wallet.unlock(LEGACY_PASSPHRASE, 0)).unwrap())
    };
    // Long enough for an unserialized move (Argon2id is optimised in test
    // builds) to finish
    let early = done_rx.recv_timeout(Duration::from_secs(2));
    assert!(
        matches!(early, Err(RecvTimeoutError::Timeout)),
        "the move finished while a save in the older format was unwritten"
    );
    pause.resume();
    saver.join().unwrap().unwrap();
    done_rx.recv().unwrap().unwrap();
    unlocker.join().unwrap();
    assert!(!is_legacy(&wallet));

    wallet.lock();
    let wallet = reopen(
        Arc::try_unwrap(wallet).ok().expect("wallet still shared"),
        &path,
        Network::Testnet,
    );
    wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
    assert_fixture_keys_whole(&wallet);
}

// A move whose write reports an error and whose read-back fails too: the
// format on disk is unknown. Each case runs with the write landed and not.

/// Fail the move's write before (`landed` false) or after it reached the
/// disk, and the read that checks it
fn arm_unconfirmed_move(landed: bool) {
    let write = if landed {
        "sealed master written"
    } else {
        "sealed master unwritten"
    };
    fault::arm(write, 0);
    fault::arm_also("sealed master read back", 0);
}

/// `op` while the sealed master key still cannot be read back
fn while_unreadable<T>(op: impl FnOnce() -> T) -> T {
    fault::arm("sealed master read back", 0);
    let result = op();
    fault::disarm();
    result
}

fn imported_secret() -> divi_crypto::keys::SecretKey {
    divi_crypto::keys::SecretKey::from_bytes(&[0x33; 32]).unwrap()
}

#[test]
fn refused_import_does_not_upgrade_a_watch_only_entry() {
    let (_dir, _path, wallet) = unconfirmed_change(true);
    let public = crate::keystore::KeyEntry::imported(imported_secret(), true).public;
    let addr = wallet
        .keystore
        .import_watch_only(public, Some("watch".into()));
    assert!(matches!(
        while_unreadable(|| wallet.import_key(imported_secret(), Some("replacement".into()))),
        Err(WalletError::RecordFormatUnconfirmed)
    ));
    wallet.save().unwrap();
    let entry = wallet.get_key_by_address(&addr).unwrap();
    assert!(entry.is_watch_only && entry.secret.is_none());
    assert_eq!(entry.label.as_deref(), Some("watch"));
}

/// An unlocked older wallet whose passphrase change is unconfirmed, with the
/// sealed master key on disk the new one when `landed`
fn unconfirmed_change(landed: bool) -> (tempfile::TempDir, std::path::PathBuf, WalletDb) {
    let (dir, path, wallet) = unlocked_legacy_wallet();
    let before = sealed_master(&wallet);
    arm_unconfirmed_move(landed);
    let changed = wallet.change_passphrase(LEGACY_PASSPHRASE, NEW);
    fault::disarm();
    assert!(
        matches!(changed, Err(WalletError::PassphraseChangeUnconfirmed(_))),
        "{changed:?}"
    );
    assert_eq!(sealed_master(&wallet) != before, landed);
    // Not presented as locked: still unlocked, its keys in memory, and the
    // master key kept to store them once the format is known
    assert!(!wallet.is_locked());
    assert_fixture_keys_whole(&wallet);
    assert!(wallet
        .decrypted_master_key
        .read()
        .as_ref()
        .is_some_and(|m| m.unconfirmed.is_some()));
    (dir, path, wallet)
}

/// Nothing that writes keys reports success while the format is unknown: a
/// save, a fresh key and an import all fail. The import is atomic — it leaves
/// no key in memory, so a later save cannot commit an import the caller was
/// told had failed. Returns the address the import would have had.
fn assert_no_key_written(wallet: &WalletDb) -> Address {
    assert!(matches!(
        while_unreadable(|| wallet.save()),
        Err(WalletError::RecordFormatUnconfirmed)
    ));
    let addresses = wallet.get_addresses().len();
    assert!(matches!(
        while_unreadable(|| wallet.new_receiving_address()),
        Err(WalletError::RecordFormatUnconfirmed)
    ));
    assert_eq!(wallet.get_addresses().len(), addresses, "fresh key kept");
    let imported_addr =
        crate::keystore::KeyEntry::imported(imported_secret(), true).address(wallet.network());
    assert!(matches!(
        while_unreadable(|| wallet.import_key(imported_secret(), None)),
        Err(WalletError::RecordFormatUnconfirmed)
    ));
    assert!(
        wallet.get_key_by_address(&imported_addr).is_none(),
        "a failed import left no key in memory"
    );
    assert_eq!(
        wallet.get_addresses().len(),
        addresses,
        "a failed import kept nothing"
    );
    assert!(matches!(
        while_unreadable(|| wallet.save()),
        Err(WalletError::RecordFormatUnconfirmed)
    ));
    imported_addr
}

/// After a restart, the passphrase of the outcome on disk opens the wallet,
/// the other does not, every fixture key is whole, and the key imported
/// while the format was unknown left no record
fn assert_restart_without_record(
    wallet: WalletDb,
    path: &std::path::Path,
    landed: bool,
    imported: &Address,
) {
    let (open, other) = if landed {
        (NEW, LEGACY_PASSPHRASE)
    } else {
        (LEGACY_PASSPHRASE, NEW)
    };
    let wallet = reopen(wallet, path, Network::Testnet);
    assert_eq!(is_legacy(&wallet), !landed);
    assert!(wallet.get_key_by_address(imported).is_none());
    assert!(!wallet
        .db()
        .unwrap()
        .load_encrypted_secrets()
        .unwrap()
        .iter()
        .any(|(hash, _)| *hash == imported.hash));
    assert!(matches!(
        wallet.unlock(other, 0),
        Err(WalletError::WrongPassphrase)
    ));
    wallet.unlock(open, 0).unwrap();
    assert!(!is_legacy(&wallet));
    assert_fixture_keys_whole(&wallet);
}

fn change_unconfirmed_then_restart(landed: bool) {
    let (_dir, path, wallet) = unconfirmed_change(landed);
    let imported = assert_no_key_written(&wallet);
    assert_restart_without_record(wallet, &path, landed, &imported);
}

#[test]
fn change_unconfirmed_old_on_disk_writes_no_key_and_restarts() {
    change_unconfirmed_then_restart(false);
}

#[test]
fn change_unconfirmed_new_on_disk_writes_no_key_and_restarts() {
    change_unconfirmed_then_restart(true);
}

/// Once the sealed master key reads back, the next write settles the format.
/// The import attempted while the format was unknown stored nothing, so it is
/// absent; a fresh import after settling succeeds and is stored durably.
fn change_unconfirmed_then_settled(landed: bool) {
    let (_dir, path, wallet) = unconfirmed_change(landed);
    let attempted = assert_no_key_written(&wallet);
    wallet.save().unwrap();
    assert!(wallet
        .decrypted_master_key
        .read()
        .as_ref()
        .unwrap()
        .unconfirmed
        .is_none());
    assert_eq!(is_legacy(&wallet), !landed);
    assert!(
        wallet.get_key_by_address(&attempted).is_none(),
        "the import attempted while unconfirmed left nothing"
    );
    let imported = wallet.import_key(imported_secret(), None).unwrap();
    assert_eq!(imported, attempted);
    let fresh = wallet.new_receiving_address().unwrap();
    wallet.lock();
    let (open, other) = if landed {
        (NEW, LEGACY_PASSPHRASE)
    } else {
        (LEGACY_PASSPHRASE, NEW)
    };
    let wallet = reopen(wallet, &path, Network::Testnet);
    let entry = wallet.get_key_by_address(&imported).expect("import stored");
    assert!(entry.secret.is_none());
    assert_legacy_fixture_opens_with(wallet, &path, open, other, &fresh);
    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    wallet.unlock(open, 0).unwrap();
    let entry = wallet.get_key_by_address(&imported).unwrap();
    assert_eq!(
        entry.secret.as_ref().unwrap().as_bytes(),
        imported_secret().as_bytes()
    );
}

#[test]
fn change_unconfirmed_old_on_disk_settles_and_stores_keys() {
    change_unconfirmed_then_settled(false);
}

#[test]
fn change_unconfirmed_new_on_disk_settles_and_stores_keys() {
    change_unconfirmed_then_settled(true);
}

/// A lock while the format is unknown cannot store the keys: the wallet reads
/// as locked (so spends and exports stay refused) but keeps every private key
/// and the master key, with the cleanup pending, until a write settles the
/// format. That settling write then finishes the lock on its own — no second
/// lock call is needed — dropping the secrets and the master key.
#[test]
fn lock_while_unconfirmed_keeps_keys_until_stored() {
    let (_dir, path, wallet) = unconfirmed_change(true);
    let secrets_held = || {
        wallet
            .keystore
            .get_all_keys_with_hashes()
            .iter()
            .filter(|(_, e)| e.secret.is_some())
            .count()
    };
    let held = secrets_held();
    assert!(held > 0);

    while_unreadable(|| wallet.lock());
    assert!(wallet.is_locked());
    assert!(
        wallet.is_lock_cleanup_pending(),
        "the lock could not store the keys, so cleanup is deferred"
    );
    assert_eq!(
        secrets_held(),
        held,
        "the keys are kept until a write settles"
    );
    assert!(wallet.decrypted_master_key.read().is_some());

    wallet.save().unwrap();
    assert!(!is_legacy(&wallet));
    assert!(
        !wallet.is_lock_cleanup_pending(),
        "the settling save finished the deferred lock"
    );
    assert!(wallet.is_locked());
    assert_eq!(secrets_held(), 0, "the secrets are dropped once stored");
    assert!(wallet.decrypted_master_key.read().is_none());

    let wallet = reopen(wallet, &path, Network::Testnet);
    wallet.unlock(NEW, 0).unwrap();
    assert_fixture_keys_whole(&wallet);
}

/// The same at an unlock of an older wallet already unlocked: the unlock
/// fails, the wallet stays unlocked writing no key, and settles later
fn unlock_unconfirmed_while_unlocked(landed: bool, restart_first: bool) {
    let (_dir, path, wallet) = unlocked_legacy_wallet();
    arm_unconfirmed_move(landed);
    let unlocked = wallet.unlock(LEGACY_PASSPHRASE, 0);
    fault::disarm();
    assert!(
        matches!(unlocked, Err(WalletError::Storage(_))),
        "{unlocked:?}"
    );
    assert_eq!(is_legacy(&wallet), !landed);
    assert!(!wallet.is_locked());
    assert_fixture_keys_whole(&wallet);
    let imported = assert_no_key_written(&wallet);
    if restart_first {
        let wallet = reopen(wallet, &path, Network::Testnet);
        assert!(wallet.get_key_by_address(&imported).is_none());
        wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
        assert!(!is_legacy(&wallet));
        assert_fixture_keys_whole(&wallet);
        return;
    }
    wallet.save().unwrap();
    assert_eq!(is_legacy(&wallet), !landed);
    let fresh = wallet.new_receiving_address().unwrap();
    wallet.lock();
    assert_legacy_fixture_opens_with(
        wallet,
        &path,
        LEGACY_PASSPHRASE,
        "not the passphrase",
        &fresh,
    );
}

#[test]
fn unlock_unconfirmed_old_on_disk_while_unlocked() {
    unlock_unconfirmed_while_unlocked(false, false);
    unlock_unconfirmed_while_unlocked(false, true);
}

#[test]
fn unlock_unconfirmed_new_on_disk_while_unlocked() {
    unlock_unconfirmed_while_unlocked(true, false);
    unlock_unconfirmed_while_unlocked(true, true);
}

/// A locked wallet whose move is unconfirmed stays locked with no master key
#[test]
fn unlock_unconfirmed_while_locked_stays_locked() {
    for landed in [false, true] {
        let (_dir, path) = legacy_wallet();
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        arm_unconfirmed_move(landed);
        let unlocked = wallet.unlock(LEGACY_PASSPHRASE, 0);
        fault::disarm();
        assert!(unlocked.is_err());
        assert!(wallet.is_locked());
        assert!(wallet.decrypted_master_key.read().is_none());
        assert_eq!(is_legacy(&wallet), !landed);
        wallet.save().unwrap();
        let wallet = reopen(wallet, &path, Network::Testnet);
        wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
        assert!(!is_legacy(&wallet));
        assert_fixture_keys_whole(&wallet);
    }
}

/// A flush or log sync failing in the cleanup is reported, not only logged:
/// as `PassphraseChangeCleanup` for a change and `EncryptionCleanup` for an
/// encryption, with the write in effect; an unlock's move still succeeds
#[test]
fn cleanup_flush_and_log_sync_failures_are_reported() {
    for (point, skip) in [
        ("wallet cleanup flush", 0),
        ("wallet cleanup flush", 5),
        ("wallet cleanup log sync", 0),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let wallet = encrypted_wallet(&path);
        fault::arm(point, skip);
        let changed = wallet.change_passphrase(OLD, NEW);
        fault::disarm();
        assert!(
            matches!(changed, Err(WalletError::PassphraseChangeCleanup(_))),
            "{point} {skip}: {changed:?}"
        );
        let wallet = reopen(wallet, &path, Network::Mainnet);
        assert!(matches!(
            wallet.unlock(OLD, 0),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.unlock(NEW, 0).unwrap();
        assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
    }

    for point in ["wallet cleanup flush", "wallet cleanup log sync"] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(&path, Network::Mainnet, hd).unwrap();
        wallet.new_receiving_address().unwrap();
        fault::arm(point, 0);
        let encrypted = wallet.encrypt_wallet(OLD);
        fault::disarm();
        assert!(
            matches!(encrypted, Err(WalletError::EncryptionCleanup(_))),
            "{point}: {encrypted:?}"
        );
        assert!(wallet.is_encrypted());
        assert!(wallet.is_locked());
        let wallet = reopen(wallet, &path, Network::Mainnet);
        wallet.unlock(OLD, 0).unwrap();
        assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));

        let (_dir, path) = legacy_wallet();
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        fault::arm(point, 0);
        wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
        fault::disarm();
        assert!(!is_legacy(&wallet));
        assert_fixture_keys_whole(&wallet);
    }
}
