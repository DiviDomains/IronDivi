// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The wallet's own times are on the node's clock, which setmocktime sets, as
//! in Divi Core (GetTime, utiltime.cpp:22-35): a key's creation time
//! (CKeyMetadata(GetTime()), wallet.cpp:429-430, the same for an HD key,
//! :457-488), the time of a keypool key (CKeyPool, wallet.cpp:2254-2262) and
//! unlocked_until (nWalletUnlockTime = GetTime() + timeout,
//! rpcserver.cpp:1205, :1215); so are the name of a wallet backup made at
//! start (WalletBackupCreator.cpp:59) and the age of the newest monthly one
//! (MonthlyWalletBackupCreator.cpp:27).

use divi_crypto::keys::SecretKey;
use divi_primitives::clock::{set_mock_time, system_now};
use divi_primitives::ChainMode;
use divi_wallet::backup::{backup_at_start, time_suffix};
use divi_wallet::{HdWallet, KeyEntry, KeyStore, Network, WalletDb};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";

/// A mocked clock far from the system's
const MOCK: i64 = 1_500_000_000;

/// The clock is one for the whole test binary: one test at a time sets it
static CLOCK: Mutex<()> = Mutex::new(());

/// The clock mocked at MOCK until the guard is dropped
struct Mocked(#[allow(dead_code)] MutexGuard<'static, ()>);

impl Mocked {
    fn at_mock() -> Self {
        let guard = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!((system_now() - MOCK).abs() > 86_400);
        set_mock_time(MOCK);
        Mocked(guard)
    }
}

impl Drop for Mocked {
    fn drop(&mut self) {
        set_mock_time(0);
    }
}

fn hd() -> HdWallet {
    HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap()
}

/// GenerateNewKey: CKeyMetadata(GetTime()) (wallet.cpp:429-430)
#[test]
fn a_new_key_is_dated_on_the_node_s_clock() {
    let _clock = Mocked::at_mock();
    let entry = KeyEntry::new(SecretKey::new_random());
    assert_eq!(entry.created, MOCK as u64);
}

/// An HD key takes GenerateNewKey's metadata (wallet.cpp:429-430, :488): a
/// new address of the wallet and its keypool keys
#[test]
fn an_hd_key_is_dated_on_the_node_s_clock() {
    let _clock = Mocked::at_mock();
    let wallet = WalletDb::with_hd_wallet(Network::Regtest, hd());
    let address = wallet.new_receiving_address().unwrap();
    let entry = wallet.get_key_by_address(&address).unwrap();
    assert!(entry.hd_path.is_some());
    assert_eq!(entry.created, MOCK as u64);
}

/// An imported key and a watched key are added on the node's clock
#[test]
fn an_imported_or_watched_key_is_dated_on_the_node_s_clock() {
    let _clock = Mocked::at_mock();
    let store = KeyStore::new(Network::Regtest);
    let imported = store.import_key(SecretKey::new_random(), None);
    assert_eq!(store.get_key(&imported.hash).unwrap().created, MOCK as u64);
    let watched = store.import_watch_only(SecretKey::new_random().public_key(), None);
    let entry = store.get_key(&watched.hash).unwrap();
    assert!(entry.is_watch_only);
    assert_eq!(entry.created, MOCK as u64);
}

/// The keypool's oldest time (CKeyPool's nTime = GetTime(),
/// wallet.cpp:2254-2262), from a new key store, a new HD key store and the
/// first fill of the pool
#[test]
fn the_keypool_s_oldest_time_is_on_the_node_s_clock() {
    let _clock = Mocked::at_mock();
    assert_eq!(
        KeyStore::new(Network::Regtest).keypool_oldest(),
        MOCK as u64
    );
    let store = KeyStore::with_hd_wallet(Network::Regtest, hd());
    assert_eq!(store.keypool_oldest(), MOCK as u64);

    store.set_keypool_oldest(0);
    assert!(!store.top_up_keypool(Some(2)).unwrap().is_empty());
    assert_eq!(store.keypool_oldest(), MOCK as u64);
}

/// unlocked_until = GetTime() + timeout (rpcserver.cpp:1205, :1215)
#[test]
fn unlocked_until_is_on_the_node_s_clock() {
    let _clock = Mocked::at_mock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.dat");
    let wallet = WalletDb::create_persistent(&path, Network::Regtest, hd()).unwrap();
    wallet.encrypt_wallet("a throwaway passphrase").unwrap();

    wallet.unlock("a throwaway passphrase", 60).unwrap();
    assert_eq!(wallet.unlocked_until(), MOCK + 60);

    // walletpassphrase's timeout, set after the unlock
    wallet.set_unlock_timeout(120, false);
    assert_eq!(wallet.unlocked_until(), MOCK + 120);
}

/// The names of the entries of `dir`, sorted
fn names(dir: &std::path::Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// A backup made at start is named by GetTime (WalletBackupCreator.cpp:59),
/// and a monthly one is due when the newest is a month old by GetTime
/// (MonthlyWalletBackupCreator.cpp:27)
#[test]
fn start_up_backups_are_named_and_aged_on_the_node_s_clock() {
    let _clock = Mocked::at_mock();
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("wallet.dat");
    std::fs::create_dir_all(&wallet).unwrap();
    std::fs::write(wallet.join("data"), b"wallet").unwrap();

    backup_at_start(&wallet, dir.path(), 20).unwrap();
    let name = format!(
        "wallet.dat{}",
        time_suffix(SystemTime::UNIX_EPOCH + Duration::from_secs(MOCK as u64))
    );
    assert_eq!(names(&dir.path().join("backups")), vec![name.clone()]);
    assert_eq!(names(&dir.path().join("monthlyBackups")), vec![name]);

    // The newest monthly backup was just written; on a clock 31 days on it is
    // a month old, so another is made
    let later = system_now() + 31 * 86_400;
    set_mock_time(later);
    backup_at_start(&wallet, dir.path(), 20).unwrap();
    let monthly = names(&dir.path().join("monthlyBackups"));
    assert_eq!(monthly.len(), 2, "{monthly:?}");
    assert!(monthly.contains(&format!(
        "wallet.dat{}",
        time_suffix(SystemTime::UNIX_EPOCH + Duration::from_secs(later as u64))
    )));
}
