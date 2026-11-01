// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Account call replies as Divi Core 3.0.0's divid gives them, with wrong
//! arguments: the argument count, the "*" account and argument types
//! (scripts/accounts-replies compares them on live nodes).

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

fn server() -> (RpcServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    (RpcServer::with_wallet(chain, wallet), dir)
}

fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Response {
    server.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    })
}

fn ok(server: &RpcServer, method: &str, params: Vec<Value>) -> Value {
    let reply = call(server, method, params);
    assert!(
        reply.error.is_none(),
        "{method}: {:?}",
        reply.error.map(|e| e.message)
    );
    reply.result.expect("result")
}

fn err(server: &RpcServer, method: &str, params: Vec<Value>) -> (i32, String) {
    let e = call(server, method, params).error.expect("an error");
    (e.code, e.message)
}

/// divid's `help getaccount`, which also answers a wrong argument count
/// (rpcwallet.cpp:624-636); its example's sample address written "diviaddress",
/// as irondivid's help texts write it
const GETACCOUNT_HELP: &str = "getaccount \"diviaddress\"\n\nReturns the account associated with the given address.\n\nArguments:\n1. \"diviaddress\"  (string, required) The divi address for account lookup.\n\nResult:\n\"accountname\"        (string) the account address\n\nExamples:\n> divi-cli getaccount \"diviaddress\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getaccount\", \"params\": [\"diviaddress\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n";

/// The account names the wallet has
fn accounts(server: &RpcServer) -> Vec<String> {
    let mut names: Vec<String> = ok(server, "listaccounts", vec![json!(0)])
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    names.sort();
    names
}

#[test]
fn wrong_argument_count_answers_cores_help_text() {
    let (server, _dir) = server();
    let own = ok(&server, "getnewaddress", vec![json!("")]);
    assert_eq!(
        err(&server, "getaccount", vec![]),
        (-1, GETACCOUNT_HELP.to_string())
    );
    let calls: Vec<(&str, Vec<Value>, &str)> = vec![
        (
            "getaccount",
            vec![own.clone(), json!(1)],
            "getaccount \"diviaddress\"\n",
        ),
        (
            "getaccountaddress",
            vec![],
            "getaccountaddress \"account\"\n",
        ),
        (
            "getaccountaddress",
            vec![json!("a"), json!("b")],
            "getaccountaddress \"account\"\n",
        ),
        (
            "getaddressesbyaccount",
            vec![],
            "getaddressesbyaccount \"account\"\n",
        ),
        (
            "getaddressesbyaccount",
            vec![json!("a"), json!("b")],
            "getaddressesbyaccount \"account\"\n",
        ),
        (
            "setaccount",
            vec![],
            "setaccount \"diviaddress\" \"account\"\n",
        ),
        (
            "setaccount",
            vec![own.clone(), json!("a"), json!("b")],
            "setaccount \"diviaddress\" \"account\"\n",
        ),
        (
            "getreceivedbyaccount",
            vec![],
            "getreceivedbyaccount \"account\" ( minconf )\n",
        ),
        (
            "listaccounts",
            vec![json!(1), json!(2), json!(3)],
            "listaccounts ( minconf includeWatchonly)\n",
        ),
        (
            "listreceivedbyaccount",
            vec![json!(1), json!(true), json!(true), json!(4)],
            "listreceivedbyaccount ( minconf includeempty includeWatchonly)\n",
        ),
        (
            "getnewaddress",
            vec![json!("a"), json!("b")],
            "getnewaddress ( \"account\" )\n",
        ),
    ];
    for (method, params, first_line) in calls {
        let (code, message) = err(&server, method, params.clone());
        assert_eq!(code, -1, "{method} {params:?}");
        assert!(
            message.starts_with(first_line),
            "{method} {params:?}: {message}"
        );
        assert!(
            message.contains("\nArguments:\n") || method == "listaccounts",
            "{method}: {message}"
        );
        assert_eq!(
            message,
            ok(&server, "help", vec![json!(method)]),
            "{method}"
        );
    }
    // Nothing was made or moved: no account "a", own stays in ""
    assert_eq!(accounts(&server), vec![String::new()]);
    assert_eq!(ok(&server, "getaccount", vec![own]), json!(""));
}

#[test]
fn star_names_no_account() {
    let (server, _dir) = server();
    let own = ok(&server, "getnewaddress", vec![json!("")]);
    let invalid = (-11, "Invalid account name".to_string());
    assert_eq!(err(&server, "getnewaddress", vec![json!("*")]), invalid);
    assert_eq!(err(&server, "getaccountaddress", vec![json!("*")]), invalid);
    assert_eq!(
        err(&server, "getaddressesbyaccount", vec![json!("*")]),
        invalid
    );
    assert_eq!(
        err(&server, "getreceivedbyaccount", vec![json!("*")]),
        invalid
    );
    assert_eq!(
        err(&server, "getreceivedbyaccount", vec![json!("*"), json!(0)]),
        invalid
    );
    assert_eq!(
        err(&server, "setaccount", vec![own.clone(), json!("*")]),
        invalid
    );
    assert_eq!(
        err(&server, "sendfrom", vec![json!("*"), own.clone(), json!(1)]),
        invalid
    );
    // The arguments Core reads first answer first
    assert_eq!(
        err(&server, "setaccount", vec![json!("xyz"), json!("*")]),
        (-5, "Invalid DIVI address".to_string())
    );
    assert_eq!(
        err(
            &server,
            "getreceivedbyaccount",
            vec![json!("*"), json!("1")]
        ),
        (-1, "value is type str, expected int".to_string())
    );
    assert_eq!(accounts(&server), vec![String::new()]);
    assert_eq!(ok(&server, "getaccount", vec![own]), json!(""));
}

#[test]
fn listreceived_arguments_are_read_as_core_reads_them() {
    let (server, _dir) = server();
    for method in ["listreceivedbyaccount", "listreceivedbyaddress"] {
        assert_eq!(
            err(&server, method, vec![json!("x")]),
            (-1, "value is type str, expected int".to_string()),
            "{method}"
        );
        assert_eq!(
            err(&server, method, vec![json!(0), json!(1)]),
            (-1, "value is type int, expected bool".to_string()),
            "{method}"
        );
        ok(&server, method, vec![json!(0), json!(true), json!(false)]);
    }
}
