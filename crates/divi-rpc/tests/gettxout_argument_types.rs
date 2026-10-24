// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! gettxout takes its arguments as Divi Core reads them (rpcblockchain.cpp:366-371:
//! `get_str`, `get_int`, `get_bool`): another type is refused with json_spirit's
//! "value is type X, expected Y".

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

#[test]
fn gettxout_refuses_arguments_of_another_type() {
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
    let call = |args: Vec<Value>| {
        server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: "gettxout".to_string(),
            params: Params::Array(args),
        })
    };
    let txid = json!("11".repeat(32));
    let refused = |args: Vec<Value>| {
        let error = call(args).error.expect("refused");
        (error.code, error.message)
    };
    let message = |s: &str| (-1, s.to_string());
    assert_eq!(
        refused(vec![txid.clone(), json!("0")]),
        message("value is type str, expected int")
    );
    assert_eq!(
        refused(vec![txid.clone(), json!(0.5)]),
        message("value is type real, expected int")
    );
    assert_eq!(
        refused(vec![txid.clone(), json!(0), json!(1)]),
        message("value is type int, expected bool")
    );
    assert_eq!(
        refused(vec![json!(5), json!(0)]),
        message("value is type int, expected str")
    );
    // the types divid takes: no such coin
    for args in [
        vec![txid.clone(), json!(0)],
        vec![txid, json!(0), json!(false)],
    ] {
        assert_eq!(call(args).result, Some(Value::Null));
    }
}
