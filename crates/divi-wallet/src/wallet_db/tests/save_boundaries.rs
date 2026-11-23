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
            assert!(wallet.dirty.read().transactions.contains(&id));
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

/// What `wallet` holds in memory for `ops` and `ids` equals the rows on disk:
/// a live coin has its row and no spent marker, a spent coin a marker and no
/// row, any other coin neither; every history entry in memory has its row
/// and no other of `ids` has one
fn assert_disk_matches(wallet: &WalletDb, ops: &[OutPoint], ids: &[Hash256]) {
    let db = wallet.db().unwrap();
    let rows = db.load_utxos().unwrap();
    let marks = db.load_spent().unwrap();
    let undo = db.load_spent_utxo_data().unwrap();
    let history = db.load_transactions().unwrap();
    for op in ops {
        let live = wallet.utxos.read().get(op).map(|u| u.value.as_sat());
        let row = rows
            .iter()
            .find(|(k, _)| k == op)
            .map(|(_, u)| u.value.as_sat());
        assert_eq!(row, live, "live row of {op:?}");
        assert_eq!(
            marks.contains(op),
            wallet.spent.read().contains(op),
            "spent marker of {op:?}"
        );
        assert_eq!(
            undo.iter()
                .find(|(k, _, _)| k == op)
                .map(|(_, u, h)| (u.value.as_sat(), *h)),
            wallet
                .spent_utxo_data
                .read()
                .get(op)
                .map(|(u, h)| (u.value.as_sat(), *h)),
            "undo data of {op:?}"
        );
    }
    for id in ids {
        assert_eq!(
            history.iter().find(|t| t.txid == *id).map(|t| t.amount),
            wallet.transactions_r().get(id).map(|t| t.amount),
            "history row of {id:?}"
        );
    }
}

/// Each coin's live value and spent mark, and each history amount
type MemoryRows = (Vec<(Option<i64>, bool)>, Vec<Option<i64>>);

/// The coin and history state of `ops` and `ids`, to compare across a reopen
fn memory_rows(wallet: &WalletDb, ops: &[OutPoint], ids: &[Hash256]) -> MemoryRows {
    (
        ops.iter()
            .map(|op| {
                (
                    wallet.utxos.read().get(op).map(|u| u.value.as_sat()),
                    wallet.spent.read().contains(op),
                )
            })
            .collect(),
        ids.iter()
            .map(|id| wallet.transactions_r().get(id).map(|t| t.amount))
            .collect(),
    )
}

fn history_tx(seed: u8, height: Option<u32>, amount: i64) -> WalletTx {
    WalletTx {
        txid: Hash256::from_bytes([seed; 32]),
        block_height: height,
        block_hash: None,
        confirmations: 0,
        amount,
        category: "receive".into(),
        timestamp: 1,
        fee: None,
    }
}

fn coin_at(wallet: &WalletDb, seed: u8, height: u32, value: i64) -> WalletUtxo {
    let addr = wallet.new_receiving_address().unwrap();
    let mut coin = WalletUtxo::new(
        Hash256::from_bytes([seed; 32]),
        1,
        Amount::from_sat(value),
        Script::new_p2pkh(addr.hash.as_bytes()),
        addr.to_string(),
    );
    coin.height = Some(height);
    coin
}

/// Run one writer to completion; with `fail` its batch is refused. Replay
/// runs the deferred HD replay's full write from scan height 0.
fn run_writer(wallet: &WalletDb, writer: Writer, fail: bool) -> bool {
    let point = match writer {
        Writer::Incremental => "wallet incremental batch built",
        _ => "wallet save batch built",
    };
    if fail {
        fault::arm(point, 0);
    }
    let ok = match writer {
        Writer::Incremental => wallet.save_incremental().is_ok(),
        Writer::Full => wallet.save().is_ok(),
        Writer::Replay => {
            let last = wallet.last_scan_height();
            wallet.set_last_scan_height(0);
            *wallet.hd_replay_generation.write() = 1;
            let ok = wallet.sync_to_tip(0, |_| None, |_| None).is_empty();
            wallet.set_last_scan_height(last);
            ok
        }
    };
    fault::disarm();
    assert_eq!(ok, !fail, "{writer:?} with fail={fail}");
    ok
}

#[derive(Clone, Copy, Debug)]
enum DuringBatch {
    Replace,
    Delete,
    DeleteThenReplace,
}

/// A batch that fails (or lands) while another thread replaces and deletes
/// the history ids it carries: the next save writes what memory holds
fn history_change_during_batch(writer: Writer, fail: bool) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let replaced = history_tx(0x31, Some(3), 1);
    let deleted = history_tx(0x32, Some(5), 1);
    let readded = history_tx(0x33, Some(5), 1);
    let ids = [replaced.txid, deleted.txid, readded.txid];
    for tx in [&replaced, &deleted, &readded] {
        wallet.add_transaction(tx.clone());
    }
    wallet.save_incremental().unwrap();
    // Owed by the batch that pauses
    for tx in [&replaced, &deleted, &readded] {
        wallet.add_transaction(WalletTx {
            amount: 2,
            ..tx.clone()
        });
    }
    let point = match writer {
        Writer::Incremental => "wallet incremental batch built",
        _ => "wallet save batch built",
    };
    let pause = fault::pause_at(&*wallet, point);
    let saver = {
        let w = Arc::clone(&wallet);
        std::thread::spawn(move || {
            if fail {
                fault::arm(point, 0);
            }
            let ok = match writer {
                Writer::Incremental => w.save_incremental().is_ok(),
                _ => w.save().is_ok(),
            };
            fault::disarm();
            ok
        })
    };
    pause.reached();
    for during in [
        DuringBatch::Replace,
        DuringBatch::Delete,
        DuringBatch::DeleteThenReplace,
    ] {
        match during {
            DuringBatch::Replace => wallet.add_transaction(WalletTx {
                amount: 3,
                ..replaced.clone()
            }),
            // Both height-5 entries leave with the block
            DuringBatch::Delete => wallet.handle_reorg(4),
            DuringBatch::DeleteThenReplace => wallet.add_transaction(WalletTx {
                amount: 7,
                ..readded.clone()
            }),
        }
    }
    pause.resume();
    assert_eq!(saver.join().unwrap(), !fail);
    if fail {
        for id in &ids {
            if wallet.get_transaction(id).is_some() {
                assert!(wallet.dirty.read().transactions.contains(id));
            }
        }
    }
    wallet.save_incremental().unwrap();
    assert_disk_matches(&wallet, &[], &ids);
    let wallet = reopen(wallet, &path);
    let amounts: Vec<_> = ids
        .iter()
        .map(|id| wallet.get_transaction(id).map(|t| t.amount))
        .collect();
    assert_eq!(
        amounts,
        vec![Some(3), None, Some(7)],
        "{writer:?} fail={fail}"
    );
}

#[test]
fn failed_commit_with_same_id_replacement_and_deletion() {
    for writer in [Writer::Incremental, Writer::Full] {
        for fail in [false, true] {
            history_change_during_batch(writer, fail);
        }
    }
}

/// One coin spent, brought back, evicted and rolled back again and again,
/// with a save by `writer` after each step (every other one failing when
/// `fail`): disk follows memory, and a reopen sees the same coins
fn outpoint_matrix(writer: Writer, fail: bool) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let shared = new_wallet(&path);
    let wallet: &WalletDb = &shared;
    wallet.set_last_scan_height(20);
    let a = coin_at(wallet, 0x41, 2, 10);
    let b = coin_at(wallet, 0x42, 6, 20);
    let c = coin_at(wallet, 0x43, 9, 30);
    let ops = [a.outpoint(), b.outpoint(), c.outpoint()];
    let mut step = 0u32;
    let mut save = |wallet: &WalletDb| {
        step += 1;
        run_writer(wallet, writer, fail && step.is_multiple_of(2));
    };

    wallet.add_utxo(a.clone());
    wallet.add_utxo(b.clone());
    save(wallet);
    // Spend, resurrect with a new value, spend again
    wallet.spend_utxo_at_height(&ops[0], Some(7)).unwrap();
    save(wallet);
    wallet.add_utxo(WalletUtxo {
        value: Amount::from_sat(11),
        ..a.clone()
    });
    save(wallet);
    wallet.spend_utxo_at_height(&ops[0], Some(8)).unwrap();
    save(wallet);
    // Evict b as missing from the chain; a stays spent
    assert_eq!(wallet.reconcile_utxos(20, |_| false), 1);
    assert!(!wallet.has_utxo(&ops[1]));
    save(wallet);
    // b comes back, is spent; c is created and spent in the rolled back range
    wallet.add_utxo(b.clone());
    save(wallet);
    wallet.spend_utxo_at_height(&ops[1], Some(9)).unwrap();
    wallet.add_utxo(c.clone());
    wallet.spend_utxo_at_height(&ops[2], Some(10)).unwrap();
    save(wallet);
    // Undo heights 8 and up: a and b come back, c goes with its block
    wallet.handle_reorg(7);
    assert!(wallet.has_utxo(&ops[0]) && wallet.has_utxo(&ops[1]));
    assert!(!wallet.has_utxo(&ops[2]) && !wallet.spent.read().contains(&ops[2]));
    save(wallet);
    // A stale spent mark the chain disproves is lifted, the coin restored
    wallet.set_last_scan_height(20);
    wallet.spend_utxo_at_height(&ops[0], Some(12)).unwrap();
    save(wallet);
    assert_eq!(
        wallet.reconcile_utxos(20, |op| *op == ops[0] || *op == ops[1]),
        1
    );
    assert!(wallet.has_utxo(&ops[0]));
    save(wallet);
    // Spend once more and leave it spent
    wallet.spend_utxo_at_height(&ops[1], Some(13)).unwrap();
    save(wallet);

    wallet.save_incremental().unwrap();
    assert_disk_matches(wallet, &ops, &[]);
    let before = memory_rows(wallet, &ops, &[]);
    let wallet = reopen(shared, &path);
    assert_eq!(
        memory_rows(&wallet, &ops, &[]),
        before,
        "{writer:?} fail={fail}"
    );
    assert_disk_matches(&wallet, &ops, &[]);
}

#[test]
fn repeated_outpoint_spend_resurrection_eviction_rollback() {
    for writer in [Writer::Incremental, Writer::Full, Writer::Replay] {
        for fail in [false, true] {
            outpoint_matrix(writer, fail);
        }
    }
}

/// The same coin churn with incremental saves taken while each step's batch
/// is paused, the step then failing or landing: the next save resolves
/// every coin the paused batch carried to what memory holds after it
#[test]
fn outpoint_changes_during_failed_or_landed_batch() {
    for fail in [false, true] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let wallet = new_wallet(&path);
        wallet.set_last_scan_height(20);
        let a = coin_at(&wallet, 0x51, 2, 10);
        let b = coin_at(&wallet, 0x52, 6, 20);
        let ops = [a.outpoint(), b.outpoint()];
        wallet.add_utxo(a.clone());
        wallet.add_utxo(b.clone());
        wallet.save_incremental().unwrap();
        wallet.spend_utxo_at_height(&ops[0], Some(8)).unwrap();
        wallet.add_utxo(WalletUtxo {
            value: Amount::from_sat(21),
            ..b.clone()
        });
        let point = "wallet incremental batch built";
        let pause = fault::pause_at(&*wallet, point);
        let saver = {
            let w = Arc::clone(&wallet);
            std::thread::spawn(move || {
                if fail {
                    fault::arm(point, 0);
                }
                let ok = w.save_incremental().is_ok();
                fault::disarm();
                ok
            })
        };
        pause.reached();
        // a: resurrected and spent again; b: evicted
        wallet.add_utxo(WalletUtxo {
            value: Amount::from_sat(12),
            ..a.clone()
        });
        wallet.spend_utxo_at_height(&ops[0], Some(9)).unwrap();
        assert_eq!(wallet.reconcile_utxos(20, |_| false), 1);
        pause.resume();
        assert_eq!(saver.join().unwrap(), !fail);
        wallet.save_incremental().unwrap();
        assert_disk_matches(&wallet, &ops, &[]);
        let before = memory_rows(&wallet, &ops, &[]);
        let wallet = reopen(wallet, &path);
        assert_eq!(memory_rows(&wallet, &ops, &[]), before, "fail={fail}");
        // Undo the spend at 9 after the reopen: a is live again
        wallet.handle_reorg(8);
        wallet.save_incremental().unwrap();
        assert_disk_matches(&wallet, &ops, &[]);
        let before = memory_rows(&wallet, &ops, &[]);
        assert_eq!(before.0[0], (Some(12), false));
        drop(wallet);
        let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
        assert_eq!(memory_rows(&wallet, &ops, &[]), before, "fail={fail}");
    }
}

/// A spent marker whose spending block is unknown is lifted while a rescan
/// runs. A save in that window takes the coin's mark and writes nothing for
/// it; putting the marker back must owe it again.
#[test]
fn rescan_lifted_spend_saved_during_scan_stays_spent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let addr = wallet.new_receiving_address().unwrap();
    let coin = WalletUtxo::new(
        Hash256::from_bytes([0x61; 32]),
        0,
        Amount::from_sat(5),
        Script::new_p2pkh(addr.hash.as_bytes()),
        addr.to_string(),
    );
    let op = coin.outpoint();
    wallet.add_utxo(coin);
    wallet.spend_utxo(&op).unwrap();
    wallet.set_last_scan_height(1);
    let mut saved_inside = false;
    let (_, unreadable) = wallet.rescan(1, 1, 1, |_| {
        assert!(!wallet.spent.read().contains(&op), "the mark is lifted");
        wallet.save_incremental().unwrap();
        saved_inside = true;
        None
    });
    assert!(saved_inside);
    assert_eq!(unreadable, Some(1));
    assert!(wallet.spent.read().contains(&op));
    wallet.save_incremental().unwrap();
    assert_disk_matches(&wallet, &[op], &[]);
    let wallet = reopen(wallet, &path);
    assert!(wallet.spent.read().contains(&op));
    assert!(wallet.db().unwrap().load_spent().unwrap().contains(&op));
}

#[derive(Clone, Copy, Debug)]
enum AfterPrune {
    Keep,
    Clear,
    Reorg,
}

/// Prune before the first save of the pruned id, alone or beside other owed
/// history, then optionally clear or roll back
fn prune_before_first_save(others: bool, failed_first: bool, after: AfterPrune) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let (raw, tx) = pruned_probe_tx();
    let id = tx.txid;
    // Unconfirmed: never pruned and never in a rolled back block
    let other = history_tx(0x71, None, 5);
    let durable = history_tx(0x72, None, 6);
    wallet.add_transaction(durable.clone());
    wallet.save_incremental().unwrap();
    wallet.add_transaction(tx);
    if others {
        wallet.add_transaction(other.clone());
        wallet.add_transaction(WalletTx {
            amount: 8,
            ..durable.clone()
        });
    }
    if failed_first {
        fault::arm("wallet incremental batch built", 0);
        assert!(wallet.save_incremental().is_err());
        fault::disarm();
    }
    assert!(wallet.dirty.read().transactions.contains(&id));
    assert_eq!(
        wallet.prune_transactions(1, 10, |t| (t.txid == id).then(|| (raw.clone(), 0))),
        (if others { 3 } else { 2 }, if others { 2 } else { 1 })
    );
    match after {
        AfterPrune::Keep => {}
        AfterPrune::Clear => wallet.clear_transactions_and_utxos(),
        AfterPrune::Reorg => wallet.handle_reorg(0),
    }
    wallet.save_incremental().unwrap();
    let wallet = reopen(wallet, &path);
    let expect = |kept: bool| kept && !matches!(after, AfterPrune::Clear);
    assert_eq!(
        wallet.get_transaction(&id).is_some(),
        expect(matches!(after, AfterPrune::Keep)),
        "pruned id: others={others} failed_first={failed_first} {after:?}"
    );
    assert_eq!(
        wallet.get_transaction(&other.txid).map(|t| t.amount),
        expect(others).then_some(5)
    );
    assert_eq!(
        wallet.get_transaction(&durable.txid).map(|t| t.amount),
        expect(true).then_some(if others { 8 } else { 6 })
    );
}

#[test]
fn prune_before_first_save_matrix() {
    for others in [false, true] {
        for failed_first in [false, true] {
            for after in [AfterPrune::Keep, AfterPrune::Clear, AfterPrune::Reorg] {
                prune_before_first_save(others, failed_first, after);
            }
        }
    }
}

/// A durable row pruned while other history is owed is not written again
/// and stays on disk
#[test]
fn pruned_durable_tx_beside_owed_history_stays() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let (raw, tx) = pruned_probe_tx();
    let id = tx.txid;
    wallet.add_transaction(tx);
    wallet.save_incremental().unwrap();
    let other = history_tx(0x73, None, 9);
    wallet.add_transaction(other.clone());
    wallet.prune_transactions(1, 10, |t| (t.txid == id).then(|| (raw.clone(), 0)));
    assert!(wallet.pending_deletes.read().transactions.is_empty());
    wallet.save_incremental().unwrap();
    let wallet = reopen(wallet, &path);
    assert!(wallet.get_transaction(&id).is_some());
    assert_eq!(
        wallet.get_transaction(&other.txid).map(|t| t.amount),
        Some(9)
    );
}

/// Incremental deltas saved while an HD replay is owed, then the replay's
/// full write stopped and the process gone: the reopened wallet still owes
/// the replay, holds the deltas, and completes the replay over them
#[test]
fn reopen_after_interrupted_hd_replay() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let a = coin_at(&wallet, 0x81, 2, 10);
    let b = coin_at(&wallet, 0x82, 3, 20);
    let ops = [a.outpoint(), b.outpoint()];
    let spent_tx = history_tx(0x83, Some(2), 1);
    let ids = [spent_tx.txid];
    wallet.add_utxo(a.clone());
    wallet.add_utxo(b.clone());
    wallet.add_transaction(spent_tx.clone());
    wallet.save().unwrap();
    {
        *wallet.hd_replay_generation.write() = 1;
        let db = wallet.db().unwrap();
        let mut batch = db.create_batch();
        batch.put_cf(db.cf_metadata(), b"hd_replay_pending", [1]);
        db.write_batch_sync(batch).unwrap();
    }
    // Deltas while the replay is owed
    wallet.spend_utxo_at_height(&ops[0], Some(4)).unwrap();
    wallet.add_utxo(WalletUtxo {
        value: Amount::from_sat(21),
        ..b.clone()
    });
    wallet.add_transaction(WalletTx {
        amount: 2,
        ..spent_tx.clone()
    });
    wallet.save_incremental().unwrap();
    assert_disk_matches(&wallet, &ops, &ids);
    let before = memory_rows(&wallet, &ops, &ids);
    // The replay's write stops, as if the process died there
    fault::arm("wallet save batch built", 0);
    assert!(!wallet.sync_to_tip(0, |_| None, |_| None).is_empty());
    fault::disarm();
    let wallet = reopen(wallet, &path);
    assert_eq!(
        wallet.db().unwrap().hd_replay_pending().unwrap(),
        Some(true)
    );
    assert_eq!(memory_rows(&wallet, &ops, &ids), before);
    assert_disk_matches(&wallet, &ops, &ids);
    assert!(wallet.sync_to_tip(0, |_| None, |_| None).is_empty());
    assert_eq!(
        wallet.db().unwrap().hd_replay_pending().unwrap(),
        Some(false)
    );
    assert_disk_matches(&wallet, &ops, &ids);
    drop(wallet);
    let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
    assert_eq!(memory_rows(&wallet, &ops, &ids), before);
}

/// Legacy data with a live row under a spent marker: the open drops the coin
/// from memory and the next incremental save deletes the stale row
#[test]
fn open_owes_stale_live_row_under_spent_marker() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let wallet = new_wallet(&path);
    let a = coin_at(&wallet, 0x91, 2, 10);
    let op = a.outpoint();
    wallet.add_utxo(a.clone());
    wallet.spend_utxo(&op).unwrap();
    wallet.save().unwrap();
    {
        let db = wallet.db().unwrap();
        let mut batch = db.create_batch();
        batch.put_cf(
            db.cf_utxos(),
            crate::persistence::outpoint_key(&op),
            crate::persistence::serialize_utxo(&a),
        );
        db.write_batch_sync(batch).unwrap();
    }
    let wallet = Arc::new(reopen(wallet, &path));
    assert!(wallet.dirty.read().outpoints.contains(&op));
    wallet.save_incremental().unwrap();
    assert_disk_matches(&wallet, &[op], &[]);
}
