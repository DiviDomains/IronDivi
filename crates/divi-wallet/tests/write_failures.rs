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

//! Wallet writes that fail for a while, as on a full disk, and then work
//! again. Divi Core logs the write it could not make and goes on; its next
//! writes reach the file once the disk takes them (wallet.cpp:1271-1274).
//! This file holds a single test: it lowers the file size limit of the whole
//! process, which no other test may share.

use divi_primitives::ChainMode;
use divi_wallet::{HdWallet, Network, WalletDb};
use tempfile::tempdir;

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
