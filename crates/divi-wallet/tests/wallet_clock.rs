// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A wallet transaction's time is at most when the wallet received it, and
//! Divi Core takes that on the network-adjusted clock (nTimeReceived =
//! GetAdjustedTime(), SpentOutputTracker.cpp:47; nTimeSmart,
//! wallet.cpp:1052-1086): the node's clock, which setmocktime sets, plus the
//! network time offset, not the system clock.

use divi_primitives::clock::{set_mock_time, set_time_offset, system_now};
use divi_primitives::{
    amount::Amount,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_wallet::{HdWallet, Network, WalletDb};

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";

#[test]
fn a_block_s_time_is_capped_by_the_adjusted_clock() {
    let wallet = WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap(),
    );
    let ours = wallet.new_receiving_address().unwrap();
    let paying = |tag: u8| Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: Hash256::from_bytes([tag; 32]),
                vout: 0,
            },
            script_sig: Script::default(),
            sequence: 0xffffffff,
        }],
        vout: vec![TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: Script::new_p2pkh(ours.hash.as_bytes()),
        }],
        lock_time: 0,
    };
    let now = system_now();

    // The node's clock two hours on: a block an hour ahead of the system
    // clock is not ahead of the node's, and keeps its time
    set_mock_time(now + 7200);
    let ahead = paying(7);
    wallet.scan_transaction(
        &ahead,
        Some(Hash256::from_bytes([8; 32])),
        Some(10),
        Some((now + 3600) as u32),
    );
    assert_eq!(
        wallet.get_transaction(&ahead.txid()).unwrap().timestamp,
        (now + 3600) as u64
    );

    // The peers' offset counts too: the node's clock at the system time plus
    // a 40-minute offset caps a block an hour ahead at 40 minutes
    set_mock_time(now);
    set_time_offset(2400);
    let later = paying(9);
    wallet.scan_transaction(
        &later,
        Some(Hash256::from_bytes([10; 32])),
        Some(11),
        Some((now + 3600) as u32),
    );
    assert_eq!(
        wallet.get_transaction(&later.txid()).unwrap().timestamp,
        (now + 2400) as u64
    );

    // Unconfirmed: the time it came in, on the same clock
    let unconfirmed = paying(11);
    wallet.scan_transaction(&unconfirmed, None, None, None);
    assert_eq!(
        wallet
            .get_transaction(&unconfirmed.txid())
            .unwrap()
            .timestamp,
        (now + 2400) as u64
    );
    set_mock_time(0);
    set_time_offset(0);
}
