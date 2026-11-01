// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `getblock <hash> 2` returns decoded transactions; 0/1/true/false keep their meaning.

use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::transaction::{Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::json;
use std::sync::Arc;

fn call(server: &RpcServer, method: &str, params: Vec<serde_json::Value>) -> Response {
    server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    })
}

/// One regtest PoW block on top of genesis paying to a P2PKH script.
fn mine_one(chain: &Chain) -> (Block, String) {
    let tip = chain.tip().unwrap();
    let mut block = Block::default();
    block.header.version = 4;
    block.header.prev_block = tip.hash;
    block.header.time = tip.time + 60;
    block.header.bits = 0x207fffff;
    block.transactions.push(Transaction {
        version: 1,
        vin: vec![TxIn::coinbase(Script::from_bytes(
            [
                divi_storage::bip34_height_script(tip.height + 1),
                vec![0x04, 1, 0, 0, 0],
            ]
            .concat(),
        ))],
        vout: vec![TxOut::new(
            Amount::from_sat(1250_00000000),
            Script::new_p2pkh(&[4u8; 20]),
        )],
        lock_time: 0,
    });
    block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
    // Proof of work for the block's bits
    let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    let hash = divi_crypto::compute_block_hash(&block.header).to_string();
    chain.accept_block(block.clone()).unwrap();
    (block, hash)
}

#[test]
fn getblock_verbosity_levels() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let (block, hash) = mine_one(&chain);
    let txid = block.transactions[0].txid().to_string();
    let server = RpcServer::new(chain);

    let get = |v: Option<serde_json::Value>| {
        let mut p = vec![json!(hash)];
        p.extend(v);
        let r = call(&server, "getblock", p);
        assert!(r.error.is_none(), "getblock: {:?}", r.error);
        r.result.unwrap()
    };

    // 0 / false: raw hex
    for v in [json!(0), json!(false)] {
        assert!(get(Some(v.clone())).is_string(), "verbosity {v}");
    }
    // default / 1 / true: txids
    for v in [None, Some(json!(1)), Some(json!(true))] {
        let r = get(v.clone());
        assert_eq!(r["tx"], json!([txid]), "verbosity {v:?}");
    }
    // 2: decoded transactions, same shape as getrawtransaction <txid> 1
    let r = get(Some(json!(2)));
    let tx = &r["tx"][0];
    assert!(tx.is_object(), "verbosity 2 gave {}", r["tx"]);
    assert_eq!(tx["txid"], json!(txid));
    assert_eq!(tx["blockhash"], json!(hash));
    assert_eq!(tx["height"], json!(1));
    assert!(tx["hex"].is_string());
    assert!(tx["vin"][0]["coinbase"].is_string());
    assert_eq!(tx["vout"][0]["valueSat"], json!(1250_00000000i64));
    assert!(tx["vout"][0]["scriptPubKey"]["addresses"][0].is_string());
    assert_eq!(r["height"], json!(1));
    assert_eq!(r["nTx"], json!(1));
}
