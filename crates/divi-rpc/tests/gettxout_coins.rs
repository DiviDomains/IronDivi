// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `gettxout` reads a coin as Divi Core's does (rpcblockchain.cpp:375-399):
//! `version` is the creating transaction's (`coins.nVersion`), and an output
//! to an OP_META script is no coin (CCoins::ClearUnspendable, coins.cpp:54-61).

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use divi_primitives::ChainMode;
use divi_rpc::{BlockchainRpc, Params};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType, Utxo};
use serde_json::{json, Value};
use std::sync::Arc;

#[test]
fn gettxout_reports_the_stored_version_and_no_op_meta_output() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            Arc::clone(&db),
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let txid = Hash256::from_bytes([9; 32]);
    let coin =
        |value: i64, script: Script| Utxo::new(Amount::from_sat(value), script, 0, false, false);
    db.add_utxo(
        &OutPoint::new(txid, 0),
        &coin(5 * 100_000_000, Script::new_p2pkh(&[3; 20])).with_version(2),
    )
    .unwrap();
    db.add_utxo(
        &OutPoint::new(txid, 1),
        &coin(100_000_000, Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4])).with_version(2),
    )
    .unwrap();
    db.add_utxo(
        &OutPoint::new(Hash256::from_bytes([8; 32]), 0),
        &coin(7, Script::new_p2pkh(&[4; 20])),
    )
    .unwrap();

    let rpc = BlockchainRpc::new(chain);
    let gettxout = |txid: Hash256, vout: u32| -> Value {
        rpc.get_tx_out(&Params::Array(vec![json!(txid.to_string()), json!(vout)]))
            .unwrap()
    };
    assert_eq!(gettxout(txid, 0)["version"], 2);
    assert_eq!(gettxout(txid, 1), Value::Null);
    assert_eq!(gettxout(Hash256::from_bytes([8; 32]), 0)["version"], 1);
}
