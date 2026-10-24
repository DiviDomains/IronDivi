// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `help`, `help <call>` and the usage errors as Divi Core 3.0.0's divid
//! answers them (rpcserver.cpp:235-305, each call's `fHelp` throw).
//!
//! `data/divid-help.json` holds divid's replies: `help`, `help <call>` for every
//! call of its table (rpcserver.cpp:324-467) and `help nosuchcall`, with an
//! unencrypted wallet, with an encrypted one and without a wallet (for those
//! two only the texts that differ). Sample addresses and hashes in divid's
//! examples are written "diviaddress" and "hash", as irondivid writes them.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

fn data() -> Value {
    serde_json::from_str(include_str!("data/divid-help.json")).unwrap()
}

fn server(wallet: bool) -> (RpcServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    if !wallet {
        return (RpcServer::new(chain), dir);
    }
    // on disk, so it can be encrypted
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    (RpcServer::with_wallet(chain, wallet), dir)
}

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

/// The servers of the three states, by the name the data uses
fn states() -> Vec<(&'static str, RpcServer, tempfile::TempDir)> {
    let (plain, d1) = server(true);
    let (crypted, d2) = server(true);
    // a passphrase made now, for a wallet that lives as long as the test
    let passphrase = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    call(&crypted, "encryptwallet", vec![json!(passphrase)]).unwrap();
    let (none, d3) = server(false);
    vec![
        ("unencrypted", plain, d1),
        ("encrypted", crypted, d2),
        ("nowallet", none, d3),
    ]
}

/// divid's text of `help <call>` in a state: the state's own where it differs
fn expected(data: &Value, state: &str, method: &str) -> String {
    data[state]["help_of"][method]
        .as_str()
        .or(data["unencrypted"]["help_of"][method].as_str())
        .unwrap()
        .to_string()
}

#[test]
fn help_of_every_call_is_divids() {
    let data = data();
    for (state, server, _dir) in states() {
        let mut differ = Vec::new();
        for method in data["unencrypted"]["help_of"].as_object().unwrap().keys() {
            let got = call(&server, "help", vec![json!(method)]).unwrap();
            if got.as_str() != Some(expected(&data, state, method).as_str()) {
                differ.push(method.clone());
            }
        }
        assert!(differ.is_empty(), "{state}: help differs for {differ:?}");
        assert_eq!(
            call(&server, "help", vec![json!("nosuchcall")]).unwrap(),
            data[state]["unknown"],
            "{state}"
        );
    }
}

#[test]
fn help_lists_divids_calls_as_divid_does() {
    let data = data();
    for (state, server, _dir) in states() {
        let list = call(&server, "help", vec![]).unwrap();
        let list = list.as_str().unwrap();
        // irondivid's own calls follow, under "<category> (irondivid)" sections
        let core_part = match list.find(" (irondivid) ==") {
            Some(at) => list[..list[..at].rfind("== ").unwrap()].trim_end_matches('\n'),
            None => list,
        };
        assert_eq!(core_part, data[state]["help"].as_str().unwrap(), "{state}");
    }
}
