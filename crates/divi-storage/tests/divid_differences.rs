// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Chain-state values where irondivid knowingly differs from Divi Core
//! 3.0.0's divid. Each test pins one row of docs/divid-differences.md.

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use divi_storage::database::BatchedUtxoWriter;
use divi_storage::{ChainDatabase, Utxo};

/// gettxoutsetinfo's counts and total match divid, but bytes_serialized and
/// hash_serialized are taken over IronDivi's own UTXO records, not Core's
/// per-transaction CCoins serialization (txdb.cpp:105-140): bytes_serialized
/// is the sum of the stored records' lengths
#[test]
fn utxo_stats_are_over_irondivis_own_records() {
    let dir = tempfile::tempdir().unwrap();
    let db = ChainDatabase::open(dir.path()).unwrap();
    let coins = [
        (
            OutPoint::new(Hash256::from_bytes([1; 32]), 0),
            Utxo::new(
                Amount::from_sat(5),
                Script::new_p2pkh(&[7; 20]),
                3,
                false,
                false,
            ),
        ),
        (
            OutPoint::new(Hash256::from_bytes([1; 32]), 1),
            Utxo::new(
                Amount::from_sat(9),
                Script::new_p2pkh(&[8; 20]),
                3,
                false,
                false,
            ),
        ),
        (
            OutPoint::new(Hash256::from_bytes([2; 32]), 0),
            Utxo::new(Amount::from_sat(11), Script::new(), 4, true, false),
        ),
    ];
    let mut batch = BatchedUtxoWriter::new();
    for (outpoint, utxo) in &coins {
        batch.add(*outpoint, utxo.clone());
    }
    db.flush_utxo_batch(&batch).unwrap();
    let stats = db.get_utxo_stats().unwrap();
    assert_eq!(stats.transactions, 2);
    assert_eq!(stats.txouts, 3);
    assert_eq!(stats.total_amount, 25);
    let own: u64 = coins.iter().map(|(_, u)| u.to_bytes().len() as u64).sum();
    assert_eq!(stats.bytes_serialized, own);
}
