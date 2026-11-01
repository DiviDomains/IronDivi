// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `gettxoutsetinfo` as Divi Core 3.0.0's divid answers it for the same chain.
//!
//! `data/gettxoutsetinfo-regtest.json` holds a regtest chain made by divid
//! 3.0.0 (proof-of-work blocks, then proof-of-stake blocks with their
//! coinstakes; outputs spent and unspent, change, a vault output and an
//! OP_META output) and divid's `gettxoutsetinfo` at its tip.

use divi_primitives::block::Block;
use divi_primitives::serialize::deserialize;
use divi_primitives::ChainMode;
use divi_rpc::{BlockchainRpc, Params};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::Value;
use std::sync::Arc;

#[test]
fn gettxoutsetinfo_equals_divids_for_the_same_chain() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/gettxoutsetinfo-regtest.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    for (i, hex) in fixture["blocks"].as_array().unwrap().iter().enumerate() {
        let block: Block = deserialize(&hex::decode(hex.as_str().unwrap()).unwrap()).unwrap();
        chain
            .accept_block(block)
            .unwrap_or_else(|e| panic!("block {}: {e}", i + 1));
    }

    let divid = &fixture["gettxoutsetinfo"];
    let ours = BlockchainRpc::new(chain)
        .get_txout_set_info(&Params::Array(vec![]))
        .unwrap();
    for key in [
        "height",
        "bestblock",
        "transactions",
        "txouts",
        "bytes_serialized",
        "hash_serialized",
    ] {
        assert_eq!(ours[key], divid[key], "{key}");
    }
    assert_eq!(
        ours["total_amount"].as_f64(),
        divid["total_amount"].as_f64(),
        "total_amount"
    );
}
