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

//! Wallet writes that fail for a while, as on a full disk, and then work
//! again. Divi Core logs the write it could not make and goes on; its next
//! writes reach the file once the disk takes them (wallet.cpp:1271-1274).
//! The tests lower the file size limit of the whole process, so each holds
//! LIMIT while it runs and no other test shares this binary.

use divi_primitives::ChainMode;
use divi_wallet::{HdWallet, Network, WalletDb};
use tempfile::tempdir;

/// Held by each test while it changes the file size limit
static LIMIT: std::sync::Mutex<()> = std::sync::Mutex::new(());

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Set the soft file size limit; a write past it fails with EFBIG, since
/// SIGXFSZ is ignored
fn file_size_limit(bytes: libc::rlim_t) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit), 0);
        limit.rlim_cur = bytes.min(limit.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }
}

#[test]
fn the_wallet_writes_again_once_the_disk_takes_writes() {
    let _limit = LIMIT.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(&path, Network::Regtest, hd).unwrap();
    wallet.save().unwrap();

    file_size_limit(1);
    let failed = wallet.save();
    file_size_limit(libc::RLIM_INFINITY);
    assert!(failed.is_err(), "the save under the limit");

    wallet.save().expect("a save once writes work again");
    let address = wallet
        .new_receiving_address()
        .expect("a new key once writes work again");
    drop(wallet);
    let again = WalletDb::open(&path, Network::Regtest).unwrap();
    assert!(
        again.is_mine(&address),
        "the key made after the failure is on disk"
    );
}

/// A key pool top-up or a new key whose keys cannot be written leaves the key
/// pool and the next keys as they were: Divi Core's derivation throws before
/// the key joins the pool or one is taken from it (wallet.cpp:2129-2137,
/// :2339-2347), and the change key it then hands out is the one it would
/// have handed out before
#[test]
fn a_key_request_that_cannot_be_written_leaves_the_key_pool_as_it_was() {
    let _limit = LIMIT.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet =
        WalletDb::create_persistent(&dir.path().join("wallet"), Network::Regtest, hd).unwrap();
    wallet.top_up_keypool().unwrap();
    let first = wallet.new_change_address().unwrap();
    let size = wallet.keypool_size();

    file_size_limit(1);
    let refill = wallet.top_up_keypool();
    let after_refill = wallet.keypool_size();
    let change = wallet.new_change_address();
    let after_change = wallet.keypool_size();
    file_size_limit(libc::RLIM_INFINITY);

    assert!(refill.is_err(), "the top-up under the limit");
    assert_eq!(after_refill, size, "the key pool after the failed top-up");
    assert!(change.is_err(), "the new change key under the limit");
    assert_eq!(after_change, size, "the key pool after the failed new key");
    let path = |a: &divi_wallet::Address| wallet.get_key_by_address(a).unwrap().hd_path.unwrap();
    let next = wallet.new_change_address().unwrap();
    assert!(path(&first).ends_with("/1/0"), "{}", path(&first));
    assert!(
        path(&next).ends_with("/1/1"),
        "the next change key: {}",
        path(&next)
    );
}
