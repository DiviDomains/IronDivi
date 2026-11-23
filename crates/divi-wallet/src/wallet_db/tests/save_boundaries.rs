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

/// Reuse one transaction ID across delete, resurrection, and a second delete.
fn repeated_delete(
    point: &'static str,
    save: fn(&WalletDb) -> Result<(), WalletError>,
    overlap: bool,
) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let id = Hash256::from_bytes([7; 32]);
    let tx = WalletTx {
        txid: id,
        block_height: None,
        block_hash: None,
        confirmations: 0,
        amount: 42,
        category: "receive".into(),
        timestamp: 1,
        fee: None,
    };
    wallet.add_transaction(tx.clone());
    wallet.save_incremental().unwrap();
    wallet.clear_transactions_and_utxos();
    wallet.add_transaction(tx);
    let pause = fault::pause_at(&*wallet, point);
    let saver = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || save(&wallet))
    };
    pause.reached();
    if overlap {
        wallet.clear_transactions_and_utxos();
    }
    pause.resume();
    saver.join().unwrap().unwrap();
    if !overlap {
        wallet.clear_transactions_and_utxos();
    }
    assert!(wallet.get_transaction(&id).is_none());
    wallet.save_incremental().unwrap();
    assert!(
        reopen(wallet, &path).get_transaction(&id).is_none(),
        "deleted transaction returned after reopen"
    );
}

#[test]
fn repeated_delete_incremental() {
    repeated_delete(
        "wallet incremental batch built",
        WalletDb::save_incremental,
        true,
    );
}
#[test]
fn repeated_delete_full() {
    repeated_delete("wallet save batch built", WalletDb::save, true);
}
#[test]
fn repeated_delete_serial_control() {
    repeated_delete(
        "wallet incremental batch built",
        WalletDb::save_incremental,
        false,
    );
}

#[derive(Clone, Copy, Debug)]
enum Writer {
    Incremental,
    Full,
    Replay,
}

#[derive(Clone, Copy, Debug)]
enum FinalState {
    Deleted,
    Replaced,
    Spent,
}

fn concurrent_rows(writer: Writer, fail: bool, state: FinalState) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let raw = divi_primitives::transaction::Transaction::new();
    let id = raw.txid();
    let mut tx = WalletTx {
        txid: id,
        block_height: Some(1),
        block_hash: None,
        confirmations: 1,
        amount: 1,
        category: "receive".into(),
        timestamp: 12,
        fee: None,
    };
    let addr = wallet.new_receiving_address().unwrap();
    let mut coin = WalletUtxo::new(
        id,
        0,
        Amount::from_sat(10),
        Script::new_p2pkh(addr.hash.as_bytes()),
        addr.to_string(),
    );
    let op = coin.outpoint();
    wallet.add_transaction(tx.clone());
    wallet.add_utxo(coin.clone());
    wallet.spend_utxo_at_height(&op, Some(3)).unwrap();
    wallet.save().unwrap();
    wallet.clear_transactions_and_utxos();
    // For replacement, pause a batch containing only the old tombstones.
    // For eviction and spend, pause a batch containing the resurrected rows.
    if !matches!(state, FinalState::Replaced) {
        wallet.add_transaction(tx.clone());
        wallet.add_utxo(coin.clone());
    }
    let point = match writer {
        Writer::Incremental => "wallet incremental batch built",
        _ => "wallet save batch built",
    };
    if matches!(writer, Writer::Replay) {
        *wallet.hd_replay_generation.write() = 1;
        let db = wallet.db().unwrap();
        let mut batch = db.create_batch();
        batch.put_cf(db.cf_metadata(), b"hd_replay_pending", [1]);
        db.write_batch_sync(batch).unwrap();
    }
    let pause = fault::pause_at(&*wallet, point);
    let saver = {
        let w = wallet.clone();
        std::thread::spawn(move || {
            if fail {
                fault::arm(point, 0);
            }
            let ok = match writer {
                Writer::Incremental => w.save_incremental().is_ok(),
                Writer::Full => w.save().is_ok(),
                Writer::Replay => w.sync_to_tip(0, |_| None, |_| None).is_empty(),
            };
            fault::disarm();
            ok
        })
    };
    pause.reached();
    if !matches!(state, FinalState::Replaced) {
        wallet.spend_utxo_at_height(&op, Some(4)).unwrap();
        wallet.clear_transactions_and_utxos();
    }
    if !matches!(state, FinalState::Deleted) {
        tx.amount = 23;
        coin.value = Amount::from_sat(24);
        wallet.add_transaction(tx);
        wallet.add_utxo(coin);
        if matches!(state, FinalState::Spent) {
            wallet.spend_utxo_at_height(&op, Some(5)).unwrap();
        }
    }
    pause.resume();
    assert_eq!(saver.join().unwrap(), !fail);
    if matches!(state, FinalState::Replaced) {
        // This prune is memory-only even when the replacement was unsaved.
        let mut record = wallet.get_transaction(&id).unwrap();
        record.amount = 25;
        wallet.add_transaction(record);
        assert_eq!(
            wallet.prune_transactions(1, 10, |_| Some((raw.clone(), 0))),
            (1, 0)
        );
    }
    wallet.save_incremental().unwrap();
    let wallet = reopen(wallet, &path);
    if matches!(writer, Writer::Replay) {
        assert_eq!(
            wallet.db().unwrap().hd_replay_pending().unwrap(),
            Some(fail)
        );
        if fail {
            assert!(wallet.sync_to_tip(0, |_| None, |_| None).is_empty());
            assert_eq!(
                wallet.db().unwrap().hd_replay_pending().unwrap(),
                Some(false)
            );
        }
    }
    let db = wallet.db().unwrap();
    let spent = matches!(state, FinalState::Spent);
    assert_eq!(db.load_spent().unwrap().contains(&op), spent);
    assert_eq!(
        db.load_spent_utxo_data()
            .unwrap()
            .iter()
            .find(|(k, _, _)| *k == op)
            .map(|(_, u, h)| (u.value.as_sat(), *h)),
        spent.then_some((24, 5))
    );
    assert_eq!(
        db.load_utxos()
            .unwrap()
            .iter()
            .find(|(k, _)| *k == op)
            .map(|(_, u)| u.value.as_sat()),
        matches!(state, FinalState::Replaced).then_some(24)
    );
    assert_eq!(
        wallet.get_transaction(&id).map(|t| t.amount),
        match state {
            FinalState::Deleted => None,
            FinalState::Replaced => Some(25),
            FinalState::Spent => Some(23),
        }
    );
}

#[test]
fn same_id_save_retry_and_restart() {
    for writer in [Writer::Incremental, Writer::Full, Writer::Replay] {
        for fail in [false, true] {
            for state in [FinalState::Deleted, FinalState::Replaced, FinalState::Spent] {
                concurrent_rows(writer, fail, state);
            }
        }
    }
}

fn pruned_probe_tx() -> (divi_primitives::transaction::Transaction, WalletTx) {
    let raw = divi_primitives::transaction::Transaction::new();
    let tx = WalletTx {
        txid: raw.txid(),
        block_height: Some(1),
        block_hash: None,
        confirmations: 1,
        amount: 7,
        category: "receive".into(),
        timestamp: 12,
        fee: None,
    };
    (raw, tx)
}

#[derive(Clone, Copy)]
enum PrunedErase {
    None,
    Clear,
    Reorg,
}

fn pruned_history_survives_reopen(
    saved_first: bool,
    erase: PrunedErase,
    replay_writer: bool,
) -> bool {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let (raw, tx) = pruned_probe_tx();
    let id = tx.txid;
    wallet.add_transaction(tx);
    if saved_first {
        if replay_writer {
            *wallet.hd_replay_generation.write() = 1;
            assert!(wallet.sync_to_tip(0, |_| None, |_| None).is_empty());
            assert!(wallet.dirty.read().transactions);
        } else {
            wallet.save_incremental().unwrap();
        }
    }
    assert_eq!(
        wallet.prune_transactions(1, 10, |_| Some((raw.clone(), 0))),
        (1, 0)
    );
    match erase {
        PrunedErase::None => {}
        PrunedErase::Clear => wallet.clear_transactions_and_utxos(),
        PrunedErase::Reorg => wallet.handle_reorg(0),
    }
    assert!(wallet.get_transaction(&id).is_none());
    wallet.save_incremental().unwrap();
    reopen(wallet, &path).get_transaction(&id).is_some()
}

#[test]
fn pruned_unsaved_tx_remains_durable() {
    assert!(pruned_history_survives_reopen(
        false,
        PrunedErase::None,
        false
    ));
}

#[test]
fn pruned_unsaved_tx_cleared_does_not_return() {
    assert!(!pruned_history_survives_reopen(
        false,
        PrunedErase::Clear,
        false
    ));
}

#[test]
fn pruned_unsaved_tx_rolled_back_does_not_return() {
    assert!(!pruned_history_survives_reopen(
        false,
        PrunedErase::Reorg,
        false
    ));
}

#[test]
fn pruned_saved_tx_cleared_does_not_return() {
    assert!(!pruned_history_survives_reopen(
        true,
        PrunedErase::Clear,
        false
    ));
}

#[test]
fn pruned_saved_tx_rolled_back_does_not_return() {
    assert!(!pruned_history_survives_reopen(
        true,
        PrunedErase::Reorg,
        false
    ));
}

#[test]
fn pruned_replay_saved_tx_cleared_does_not_return() {
    assert!(!pruned_history_survives_reopen(
        true,
        PrunedErase::Clear,
        true
    ));
}

#[test]
fn pruned_replay_saved_tx_rolled_back_does_not_return() {
    assert!(!pruned_history_survives_reopen(
        true,
        PrunedErase::Reorg,
        true
    ));
}

#[test]
fn pruned_unsaved_tx_cleared_during_save_does_not_return() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let (raw, tx) = pruned_probe_tx();
    let id = tx.txid;
    wallet.add_transaction(tx);
    assert_eq!(
        wallet.prune_transactions(1, 10, |_| Some((raw.clone(), 0))),
        (1, 0)
    );
    let point = "wallet incremental batch built";
    let pause = fault::pause_at(&*wallet, point);
    let saver = {
        let wallet = Arc::clone(&wallet);
        std::thread::spawn(move || wallet.save_incremental())
    };
    pause.reached();
    wallet.clear_transactions_and_utxos();
    pause.resume();
    saver.join().unwrap().unwrap();
    wallet.save_incremental().unwrap();
    assert!(reopen(wallet, &path).get_transaction(&id).is_none());
}
