// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `gettxout`, `getinfo` moneysupply and `getblock` moneysupply as Divi Core
//! 3.0.0's divid answers them for the same chain.
//!
//! `data/gettxout-supply-regtest.json` holds a regtest chain made by divid
//! 3.0.0 with `-acceptnonstandard` (a version-2 transaction, an OP_META output
//! carrying 1 DIVI, a vault output, spends, proof-of-stake blocks) and divid's
//! replies at its tip: `gettxout` for twelve outputs (spent ones and the
//! OP_META one give null), `getinfo` moneysupply and every block's moneysupply.

use divi_primitives::block::Block;
use divi_primitives::serialize::deserialize;
use divi_primitives::ChainMode;
use divi_rpc::{BlockchainRpc, Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

#[test]
fn gettxout_and_moneysupply_equal_divids_for_the_same_chain() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/gettxout-supply-regtest.json")).unwrap();
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
    let rpc = BlockchainRpc::new(Arc::clone(&chain));

    for entry in fixture["gettxout"].as_array().unwrap() {
        let what = format!("gettxout {} {}", entry["txid"], entry["vout"]);
        let ours = rpc
            .get_tx_out(&Params::Array(vec![
                entry["txid"].clone(),
                entry["vout"].clone(),
            ]))
            .unwrap();
        let divid = &entry["reply"];
        if divid.is_null() {
            assert_eq!(ours, Value::Null, "{what}");
            continue;
        }
        // irondivid adds "coinstake"; every member divid writes is the same
        for (key, value) in divid.as_object().unwrap() {
            assert_eq!(&ours[key], value, "{what}: {key}");
        }
    }

    let server = RpcServer::new(Arc::clone(&chain));
    let info = server.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: "getinfo".to_string(),
        params: Params::Array(vec![]),
    });
    assert_eq!(
        info.result.expect("getinfo")["moneysupply"].as_f64(),
        fixture["getinfo_moneysupply"].as_f64(),
        "getinfo moneysupply"
    );

    for (height, supply) in fixture["getblock_moneysupply"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let hash = chain
            .get_block_index_by_height(height as u32)
            .unwrap()
            .unwrap()
            .hash;
        let block = rpc
            .get_block(&Params::Array(vec![json!(hash.to_string())]))
            .unwrap();
        assert_eq!(
            block["moneysupply"].as_f64(),
            supply.as_f64(),
            "getblock {height}"
        );
    }
}
