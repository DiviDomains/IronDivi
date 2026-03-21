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

//! Regression tests for divi-primitives
//!
//! Bug 1 & 7 (commit 8d9e245): Transaction version=2 rejected by C++ node.
//! Root cause: TransactionBuilder::new() defaulted to version=2.
//! Fix: CURRENT_TX_VERSION=1 enforces the correct default everywhere.

use divi_primitives::constants::CURRENT_TX_VERSION;
use divi_primitives::constants::SEQUENCE_FINAL;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};

/// Bug 1 & 7 (commit 8d9e245): CURRENT_TX_VERSION must equal 1.
/// C++ Divi rejects any transaction with version != 1 as "64: version".
#[test]
fn test_regression_current_tx_version_is_1() {
    assert_eq!(
        CURRENT_TX_VERSION, 1,
        "CURRENT_TX_VERSION must be 1 — C++ Divi rejects non-standard versions"
    );
}

/// Bug 1 & 7 (commit 8d9e245): Transaction::new() must use CURRENT_TX_VERSION.
/// Before the fix, TransactionBuilder set version=2 on every new transaction.
#[test]
fn test_regression_transaction_new_defaults_to_version_1() {
    let tx = Transaction::new();
    assert_eq!(
        tx.version, 1,
        "Transaction::new() must produce version=1 (CURRENT_TX_VERSION). \
         Before commit 8d9e245, new transactions defaulted to version=2, \
         which C++ Divi rejected with '64: version'."
    );
}

/// Bug 1 & 7 (commit 8d9e245): version=1 must be preserved through
/// serialization and deserialization (binary layout: [01 00 00 00] LE).
#[test]
fn test_regression_version_1_serializes_as_01_00_00_00() {
    let tx = Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::new(Hash256::from_bytes([0xAA; 32]), 0),
            Script::new(),
            SEQUENCE_FINAL,
        )],
        vout: vec![TxOut::new(
            divi_primitives::amount::Amount::from_sat(1_000_000),
            Script::new_p2pkh(&[0u8; 20]),
        )],
        lock_time: 0,
    };

    let bytes = serialize(&tx);

    // version is the first 4 bytes in little-endian
    assert_eq!(
        &bytes[0..4],
        &[0x01, 0x00, 0x00, 0x00],
        "version=1 must serialize as [01 00 00 00]; version=2 would be [02 00 00 00]"
    );

    // Must also round-trip
    let decoded: Transaction = deserialize(&bytes).expect("deserialization must succeed");
    assert_eq!(
        decoded.version, 1,
        "version=1 must survive serialize→deserialize roundtrip"
    );
}

/// Bug 1 & 7 (commit 8d9e245): version=2 must serialize as [02 00 00 00].
/// This documents what the pre-fix code was doing — it must NOT be the default.
#[test]
fn test_regression_version_2_is_not_the_default() {
    // Constructing with version=2 explicitly is fine — but it must never be
    // the default from Transaction::new().
    let tx_v2 = Transaction {
        version: 2,
        vin: vec![],
        vout: vec![],
        lock_time: 0,
    };
    let bytes = serialize(&tx_v2);
    assert_eq!(
        &bytes[0..4],
        &[0x02, 0x00, 0x00, 0x00],
        "version=2 must serialize as [02 00 00 00] (confirming serialization is correct)"
    );

    // The default constructor must NOT produce version=2
    let tx_default = Transaction::new();
    assert_ne!(
        tx_default.version, 2,
        "Transaction::new() must NOT default to version=2 — this is the bug that was fixed"
    );
}
