// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Blockchain and raw-transaction calls refuse an argument count Divi Core
//! refuses (its `if (fHelp || params.size() ...)` checks, rpcblockchain.cpp,
//! rpcmisc.cpp, rpcrawtransaction.cpp): -1 with the call's help text.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

#[test]
fn wrong_argument_counts_answer_with_the_help_text() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let server = RpcServer::new(chain);
    let tip = server
        .handle_request(request("getbestblockhash", vec![]))
        .result
        .unwrap();
    let h = || tip.clone();
    let cases: Vec<(&str, Vec<Value>)> = vec![
        ("getblockchaininfo", vec![json!(1)]),
        ("getblockcount", vec![json!(1)]),
        ("getbestblockhash", vec![json!(1)]),
        ("getdifficulty", vec![json!(1)]),
        ("getchaintips", vec![json!(1)]),
        ("gettxoutsetinfo", vec![json!(1)]),
        ("getinfo", vec![json!(1)]),
        ("getblockhash", vec![]),
        ("getblockhash", vec![json!(0), json!(1)]),
        ("getblock", vec![]),
        ("getblock", vec![h(), json!(true), json!(1)]),
        ("getblockheader", vec![h(), json!(true), json!(1)]),
        ("gettxout", vec![h()]),
        ("gettxout", vec![h(), json!(0), json!(true), json!(1)]),
        ("verifychain", vec![json!(3), json!(10), json!(1)]),
        ("getrawtransaction", vec![]),
        ("getrawtransaction", vec![h(), json!(1), json!(1)]),
        ("createrawtransaction", vec![json!([])]),
        ("createrawtransaction", vec![json!([]), json!({}), json!(0)]),
        ("decoderawtransaction", vec![json!("00"), json!(1)]),
        ("decodescript", vec![]),
        ("decodescript", vec![json!(""), json!(1)]),
        ("signrawtransaction", vec![]),
        (
            "signrawtransaction",
            vec![json!("00"), json!([]), json!([]), json!("ALL"), json!(1)],
        ),
        ("sendrawtransaction", vec![]),
        (
            "sendrawtransaction",
            vec![json!("00"), json!(false), json!(1)],
        ),
    ];
    for (method, args) in cases {
        let n = args.len();
        let reply = server.handle_request(request(method, args));
        let error = reply
            .error
            .unwrap_or_else(|| panic!("{method} with {n} arguments was answered"));
        assert_eq!(error.code, -1, "{method} with {n} arguments");
        assert!(
            error.message.starts_with(method),
            "{method} with {n} arguments: {}",
            error.message
        );
    }
    // the counts divid takes are still answered
    for (method, args) in [
        ("getblockcount", vec![]),
        ("getblockhash", vec![json!(0)]),
        ("getblock", vec![h(), json!(false)]),
        ("verifychain", vec![]),
    ] {
        let reply = server.handle_request(request(method, args));
        assert!(reply.error.is_none(), "{method}: {:?}", reply.error);
    }
}

fn request(method: &str, params: Vec<Value>) -> Request {
    Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    }
}
