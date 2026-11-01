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

//! An account's current address (the last of its addresses) is the one
//! labelled last while the wallet runs, and the greatest address after a
//! restart, as Divi Core reads its address book back in key order.

use divi_primitives::ChainMode;
use divi_wallet::{HdWallet, Network, WalletDb};
use tempfile::tempdir;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn current_address_after_restart_is_the_greatest() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(&path, Network::Testnet, hd).unwrap();
    let mut labelled = Vec::new();
    for _ in 0..4 {
        let address = wallet.new_receiving_address().unwrap();
        wallet.set_label(&address, "acct").unwrap();
        labelled.push(address.to_string());
    }
    // Label the smallest address last, so the last labelled is not the greatest
    let mut sorted = labelled.clone();
    sorted.sort();
    let smallest = sorted.first().unwrap().clone();
    let greatest = sorted.last().unwrap().clone();
    wallet
        .set_label(&smallest.parse().unwrap(), "acct")
        .unwrap();
    assert_eq!(
        wallet.get_addresses_by_account("acct").last(),
        Some(&smallest)
    );
    wallet.save().unwrap();
    drop(wallet);

    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    let addresses = wallet.get_addresses_by_account("acct");
    assert_eq!(addresses.len(), 4);
    assert_eq!(addresses.last(), Some(&greatest));
}
