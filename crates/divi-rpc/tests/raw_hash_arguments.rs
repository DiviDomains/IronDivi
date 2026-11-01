// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Transaction ids in createrawtransaction and getrawtransaction are read as
//! Divi Core's ParseHashV reads them (JsonParseHelpers.cpp:5-15): any hex text
//! of even length is a number (uint256::SetHex, "11" is 00..0011), a value that
//! is not a string counts as "", and an input that is not an object is refused
//! by get_obj (rpcrawtransaction.cpp:413).

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Result<Value, (i32, String)> {
    let reply = server.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    });
    match reply.error {
        Some(e) => Err((e.code, e.message)),
        None => Ok(reply.result.unwrap_or(Value::Null)),
    }
}

#[test]
fn transaction_ids_are_parsed_as_divid_parses_them() {
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

    // a short hex txid is the number it spells: one input, txid 00..0011
    let raw = call(
        &server,
        "createrawtransaction",
        vec![json!([{"txid": "11", "vout": 0}]), json!({})],
    )
    .unwrap();
    assert_eq!(
        raw,
        json!(format!(
            "0100000001{}{}00ffffffff0000000000",
            "11",
            "00".repeat(35)
        ))
    );
    assert_eq!(
        call(
            &server,
            "createrawtransaction",
            vec![json!(["x"]), json!({})]
        ),
        Err((-1, "value is type str, expected obj".to_string()))
    );
    assert_eq!(
        call(
            &server,
            "createrawtransaction",
            vec![json!([{"txid": 5, "vout": 0}]), json!({})]
        ),
        Err((-8, "txid must be hexadecimal string (not '')".to_string()))
    );

    assert_eq!(
        call(&server, "getrawtransaction", vec![json!("11"), json!(1)]),
        Err((-5, "No information available about transaction".to_string()))
    );
    assert_eq!(
        call(&server, "getrawtransaction", vec![json!(5)]),
        Err((
            -8,
            "parameter 1 must be hexadecimal string (not '')".to_string()
        ))
    );
    assert_eq!(
        call(&server, "getrawtransaction", vec![json!("abc")]),
        Err((
            -8,
            "parameter 1 must be hexadecimal string (not 'abc')".to_string()
        ))
    );
}
