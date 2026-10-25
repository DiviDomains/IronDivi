// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Calls Divi Core 3.0.0 does not have (its command table, rpcserver.cpp:329-460)
//! are unknown here too: "Method not found" with any arguments, and `help`
//! names them an unknown command (rpcserver.cpp:283-285).

use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams};
use serde_json::json;
use std::sync::Arc;

fn server() -> (RpcServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
    let wallet = Arc::new(divi_wallet::WalletDb::with_hd_wallet(
        divi_wallet::Network::Mainnet,
        divi_wallet::HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
    ));
    (RpcServer::with_wallet(chain, wallet), dir)
}

fn call(server: &RpcServer, method: &str, params: Vec<serde_json::Value>) -> Response {
    server.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    })
}

/// submitblock, getblocktemplate and reservebalance, in every form a miner or
/// staker would send, are not methods, as in divid
#[test]
fn submitblock_getblocktemplate_and_reservebalance_are_not_methods() {
    let (s, _dir) = server();
    for (method, params) in [
        ("submitblock", vec![json!("00")]),
        ("submitblock", vec![]),
        ("getblocktemplate", vec![]),
        ("getblocktemplate", vec![json!({"mode": "template"})]),
        ("reservebalance", vec![]),
        ("reservebalance", vec![json!(true), json!(100)]),
        ("reservebalance", vec![json!(false)]),
        ("reservebalance", vec![json!(false), json!(100)]),
    ] {
        let r = call(&s, method, params.clone());
        let e = r
            .error
            .unwrap_or_else(|| panic!("{method} {params:?} answered"));
        assert_eq!(
            (e.code, e.message.as_str()),
            (-32601, "Method not found"),
            "{method} {params:?}"
        );
    }
    for method in ["submitblock", "getblocktemplate", "reservebalance"] {
        assert_eq!(
            call(&s, "help", vec![json!(method)]).result,
            Some(json!(format!("help: unknown command: {method}"))),
            "help {method}"
        );
    }
}
