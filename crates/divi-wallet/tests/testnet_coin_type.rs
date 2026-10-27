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

//! The BIP44 coin type a wallet derives with, against Divi Core 3.0.0's
//! divid (chainparams.cpp nExtCoinType: 301 on mainnet, 1 on testnet and
//! regtest). A new or restored IronDivi wallet uses divid's coin type for its
//! network, so the same phrase gives the same addresses in both. A testnet
//! wallet made before the coin type was stored has none recorded and keeps
//! deriving with 301, so its addresses stay where they were and differ from
//! divid's (docs/divid-differences.md W5).

use divi_primitives::ChainMode;
use divi_wallet::{Address, HdWallet, Network, WalletDatabase, WalletDb};
use std::path::Path;
use tempfile::tempdir;

/// The public BIP39 test vector
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// divid 3.0.0 -testnet (and -regtest) -mnemonic=<MNEMONIC>: getnewaddress
/// twice, with validateaddress's hdkeypath (key 0 is its default key)
const DIVID_TESTNET: [(&str, &str); 2] = [
    ("yGHV5cwYHozU2reKzXVjEbGk4asE1ECG9t", "m/44'/1'/0'/0/1"),
    ("y3veXjipa15zmhkfKAwKUDh7h6csqHtRBj", "m/44'/1'/0'/0/2"),
];

/// divid 3.0.0 (mainnet) -mnemonic=<MNEMONIC>, as above
const DIVID_MAINNET: [(&str, &str); 2] = [
    ("DJ4qwYGSW9oK5PardNcTXpZvD8KQU5B95J", "m/44'/301'/0'/0/1"),
    ("DCunwbUqP4Fa6LDdtRpYJVF2XqGfMLeo1e", "m/44'/301'/0'/0/2"),
];

/// An IronDivi testnet wallet of MNEMONIC with no stored coin type: the same
/// keys as divid's mainnet ones, with testnet addresses
const OLDER_TESTNET: [(&str, &str); 2] = [
    ("y9ubGNkqtpJpDdnJJ6vCPVEfp7QDtjmUdW", "m/44'/301'/0'/0/1"),
    ("y4kYGRyEmim5EaR5ZA8HA9un8pMUrx5BEJ", "m/44'/301'/0'/0/2"),
];

/// A wallet restored from MNEMONIC on `network`
fn restore(path: &Path, network: Network) -> WalletDb {
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(path, network, hd).unwrap();
    wallet.save().unwrap();
    wallet
}

/// The next `n` receiving addresses with their HD paths
fn receiving(wallet: &WalletDb, n: usize) -> Vec<(String, String)> {
    (0..n)
        .map(|_| {
            let addr = wallet.new_receiving_address().unwrap();
            let path = wallet.get_key_by_address(&addr).unwrap().hd_path.unwrap();
            (addr.to_string(), path)
        })
        .collect()
}

fn owned(rows: &[(&str, &str)]) -> Vec<(String, String)> {
    rows.iter()
        .map(|(a, p)| (a.to_string(), p.to_string()))
        .collect()
}

/// A phrase restored on testnet or regtest gives divid's addresses and paths
/// (coin type 1), and keeps that coin type when the wallet is opened again
#[test]
fn testnet_restore_derives_divids_addresses() {
    for network in [Network::Testnet, Network::Regtest] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        {
            let wallet = restore(&path, network);
            assert_eq!(
                wallet.hd_account_path().as_deref(),
                Some("m/44'/1'/0'"),
                "{network:?}"
            );
            // Key 0 is divid's default key; getnewaddress starts at key 1
            assert_eq!(
                receiving(&wallet, 3)[1..],
                owned(&DIVID_TESTNET),
                "{network:?}"
            );
        }
        let wallet = WalletDb::open(&path, network).unwrap();
        assert_eq!(wallet.hd_account_path().as_deref(), Some("m/44'/1'/0'"));
        assert_eq!(receiving(&wallet, 1)[0].1, "m/44'/1'/0'/0/3");
    }
}

/// A phrase restored on mainnet gives divid's addresses and paths (coin type
/// 301)
#[test]
fn mainnet_restore_derives_divids_addresses() {
    let dir = tempdir().unwrap();
    let wallet = restore(&dir.path().join("wallet"), Network::Mainnet);
    assert_eq!(wallet.hd_account_path().as_deref(), Some("m/44'/301'/0'"));
    assert_eq!(receiving(&wallet, 3)[1..], owned(&DIVID_MAINNET));
}

/// A testnet wallet stored without a coin type (made before it was stored)
/// keeps deriving with 301: its addresses are not divid's testnet ones
#[test]
fn older_testnet_wallet_keeps_coin_type_301() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    drop(restore(&path, Network::Testnet));
    {
        let db = WalletDatabase::open(&path).unwrap();
        assert_eq!(db.load_hd_coin_type().unwrap(), Some(1));
        let mut batch = db.create_batch();
        batch.delete_cf(db.cf_metadata(), b"hd_coin_type");
        db.write_batch(batch).unwrap();
    }
    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert_eq!(wallet.hd_account_path().as_deref(), Some("m/44'/301'/0'"));
    let got = receiving(&wallet, 3);
    assert_eq!(got[1..], owned(&OLDER_TESTNET));
    for (((older, _), (divid, _)), (main, _)) in
        got[1..].iter().zip(DIVID_TESTNET).zip(DIVID_MAINNET)
    {
        assert_ne!(older, divid);
        let older = Address::from_base58(older).unwrap();
        assert_eq!(older.hash, Address::from_base58(main).unwrap().hash);
    }
}
