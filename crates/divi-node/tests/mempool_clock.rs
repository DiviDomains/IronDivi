// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `getrawmempool true`: a transaction's `time` is when it entered the pool on
//! the node's clock, which setmocktime sets (Divi Core's entry time,
//! GetTime() at MempoolConsensus.cpp:386, shown at rpcblockchain.cpp:125),
//! and stays what it was when the clock moves on.

use divi_node::Mempool;
use divi_primitives::amount::Amount;
use divi_primitives::clock::set_mock_time;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use std::sync::Arc;

#[test]
fn a_pool_transaction_s_time_is_on_the_node_s_clock() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let server = RpcServer::new(Arc::new(Chain::new(db, params).unwrap()));

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

    let entered = 1_700_000_000;
    set_mock_time(entered);
    let mempool = Arc::new(Mempool::new(Default::default()));
    mempool.add(tx, Amount::from_sat(1_000_000)).unwrap();
    server.set_mempool(mempool);
    set_mock_time(entered + 600);

    let r = server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: "getrawmempool".to_string(),
        params: Params::Array(vec![serde_json::json!(true)]),
    });
    set_mock_time(0);
    let v = r.result.expect("getrawmempool true");
    assert_eq!(v[&txid]["time"], serde_json::json!(entered));
}
