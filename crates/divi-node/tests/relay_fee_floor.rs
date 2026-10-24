// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The fee RPCs never go below the relay floor the mempool enforces, and
//! getinfo / getnetworkinfo report that floor as relayfee (Divi Core
//! rpcnet.cpp and rpcmisc.cpp, getMinimumRelayFeeRate). BasicSwap prices its
//! transactions with estimatesmartfee and refuses a rate under relayfee.

use divi_node::config::MempoolConfig;
use divi_node::Mempool;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Value {
    let r = server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    });
    assert!(r.error.is_none(), "{method}: {:?}", r.error);
    r.result.unwrap()
}

/// The fee figures an empty mempool with `min_relay_fee` sat/byte gives
fn fees(min_relay_fee: i64) -> [Value; 6] {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let server = RpcServer::new(Arc::new(Chain::new(db, params).unwrap()));
    server.set_mempool(Arc::new(Mempool::new(MempoolConfig {
        min_relay_fee,
        ..Default::default()
    })));
    [
        call(&server, "estimatefee", vec![json!(2)]),
        call(&server, "estimatesmartfee", vec![json!(2)])["feerate"].clone(),
        call(&server, "getmempoolinfo", vec![])["mempoolminfee"].clone(),
        call(&server, "getnetworkinfo", vec![])["relayfee"].clone(),
        call(&server, "getinfo", vec![])["relayfee"].clone(),
        json!(min_relay_fee as f64 * 1000.0 / 100_000_000.0),
    ]
}

#[test]
fn fee_rpcs_follow_the_relay_floor() {
    // Divi Core's default, 10000 sat/kB
    let [estimate, smart, mempool_min, network, info, _] = fees(10);
    for v in [&estimate, &smart, &mempool_min, &network, &info] {
        assert_eq!(*v, json!(0.0001));
    }

    // -minrelaytxfee=0.0002
    let [estimate, smart, mempool_min, network, info, floor] = fees(20);
    assert_eq!(floor, json!(0.0002));
    for v in [&estimate, &smart, &mempool_min, &network, &info] {
        assert_eq!(*v, floor);
    }
}
