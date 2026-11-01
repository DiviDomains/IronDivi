// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `getrawtransaction` finds a transaction that is still in the node's mempool.

use divi_node::Mempool;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use std::sync::Arc;

fn call(server: &RpcServer, method: &str, params: Vec<serde_json::Value>) -> Response {
    server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    })
}

#[test]
fn getrawtransaction_returns_a_mempool_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let server = RpcServer::new(chain);

    let mut tx = Transaction::new();
    tx.vin.push(TxIn::new(
        OutPoint::new(Hash256::from_bytes([7u8; 32]), 1),
        Script::from_bytes(vec![0x51]),
        0xffff_ffff,
    ));
    tx.vout.push(TxOut::new(
        Amount::from_sat(5_000_000),
        Script::new_p2pkh(&[9u8; 20]),
    ));
    let txid = tx.txid().to_string();
    let raw: String = serialize(&tx).iter().map(|b| format!("{b:02x}")).collect();

    let mempool = Arc::new(Mempool::new(Default::default()));
    mempool.add(tx, Amount::from_sat(1_000_000)).unwrap();
    server.set_mempool(mempool);

    // Non-verbose: the raw hex
    let r = call(&server, "getrawtransaction", vec![serde_json::json!(txid)]);
    assert!(r.error.is_none(), "non-verbose: {:?}", r.error);
    assert_eq!(r.result, Some(serde_json::json!(raw)));

    // Verbose: decoded, without block fields
    let r = call(
        &server,
        "getrawtransaction",
        vec![serde_json::json!(txid), serde_json::json!(1)],
    );
    assert!(r.error.is_none(), "verbose: {:?}", r.error);
    let v = r.result.unwrap();
    assert_eq!(v["txid"], serde_json::json!(txid));
    assert_eq!(v["hex"], serde_json::json!(raw));
    assert_eq!(v["vout"][0]["valueSat"], serde_json::json!(5_000_000));
    assert!(v.get("blockhash").is_none(), "mempool tx has no blockhash");
    assert!(v.get("confirmations").is_none());
    // Addresses use the node's network (regtest/testnet prefix), not mainnet's 'D'
    let addr = v["vout"][0]["scriptPubKey"]["addresses"][0]
        .as_str()
        .unwrap();
    assert!(!addr.starts_with('D'), "regtest node shows {addr}");

    // Unknown txid: still -5
    let r = call(
        &server,
        "getrawtransaction",
        vec![serde_json::json!(Hash256::from_bytes([3u8; 32]).to_string())],
    );
    assert_eq!(r.error.map(|e| e.code), Some(-5));
}
