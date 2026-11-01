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

//! New addresses asked for by many callers at once. Divi Core makes each key
//! under cs_wallet (wallet.cpp:2122-2195), so every caller gets its own key,
//! the HD indexes are used in order with none skipped, and the index stored on
//! disk is the last one handed out.

use divi_primitives::ChainMode;
use divi_wallet::{HdWallet, KeyEntry, Network, WalletDb};
use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const THREADS: usize = 16;
const PER_THREAD: usize = 8;

/// Address of the HD key at `index` of the receiving or change chain (a
/// testnet wallet derives with Divi Core's testnet coin type, 1)
fn hd_address(change: bool, index: u32) -> String {
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi)
        .unwrap()
        .with_coin_type(1);
    let key = if change {
        hd.derive_change(0, index).unwrap()
    } else {
        hd.derive_receiving(0, index).unwrap()
    };
    KeyEntry::new(key.secret_key().unwrap())
        .address(Network::Testnet)
        .to_string()
}

/// Half the threads ask for receiving addresses, half for change addresses,
/// all released together; returns what each chain handed out
fn race(wallet: &Arc<WalletDb>) -> (Vec<String>, Vec<String>) {
    let barrier = Arc::new(Barrier::new(THREADS));
    let threads: Vec<_> = (0..THREADS)
        .map(|t| {
            let wallet = Arc::clone(wallet);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let change = t % 2 == 1;
                barrier.wait();
                let addresses: Vec<String> = (0..PER_THREAD)
                    .map(|_| {
                        if change {
                            wallet.new_change_address().unwrap().to_string()
                        } else {
                            wallet.new_receiving_address().unwrap().to_string()
                        }
                    })
                    .collect();
                (change, addresses)
            })
        })
        .collect();
    let (mut receiving, mut change) = (Vec::new(), Vec::new());
    for t in threads {
        let (is_change, addresses) = t.join().unwrap();
        if is_change {
            change.extend(addresses);
        } else {
            receiving.extend(addresses);
        }
    }
    (receiving, change)
}

/// Every caller gets its own key, the keys are the chain's next indexes, and
/// after a restart each chain goes on after the last key handed out
#[test]
fn concurrent_new_addresses_are_distinct_and_stored_in_order() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet");
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = Arc::new(WalletDb::create_persistent(&path, Network::Testnet, hd).unwrap());
    wallet.save().unwrap();
    // The keypool is filled once here, so the race is over the indexes alone
    wallet.top_up_keypool().unwrap();

    let per_chain = (THREADS / 2 * PER_THREAD) as u32;
    let mut handed = (0u32, 0u32);
    for round in 0..3 {
        let (receiving, change) = race(&wallet);
        for (name, got, start) in [
            ("receiving", &receiving, handed.0),
            ("change", &change, handed.1),
        ] {
            let distinct: HashSet<&String> = got.iter().collect();
            assert_eq!(
                distinct.len(),
                got.len(),
                "round {round}: a {name} address was handed out twice"
            );
            let want: HashSet<String> = (start..start + per_chain)
                .map(|i| hd_address(name == "change", i))
                .collect();
            assert_eq!(
                distinct,
                want.iter().collect(),
                "round {round}: the {name} addresses are not the chain's next {per_chain} indexes"
            );
        }
        handed = (handed.0 + per_chain, handed.1 + per_chain);
    }

    drop(wallet);
    let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
    assert_eq!(
        wallet.new_receiving_address().unwrap().to_string(),
        hd_address(false, handed.0),
        "after a restart the receiving chain does not go on after its last key"
    );
    assert_eq!(
        wallet.new_change_address().unwrap().to_string(),
        hd_address(true, handed.1),
        "after a restart the change chain does not go on after its last key"
    );
}
