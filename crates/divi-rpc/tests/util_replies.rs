// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Utility call replies as Divi Core 3.0.0's divid gives them: validateaddress,
//! signmessage, verifymessage, getmininginfo, getdifficulty and help, with good
//! and with wrong arguments (scripts/util-replies compares them on live nodes).

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

fn keys(v: &Value) -> Vec<&str> {
    let mut k: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    k.sort();
    k
}

/// A regtest address nobody holds a key for
const FOREIGN: &str = "y7VQ7R3SDRxzNuUsUuFzuq2FT1uVtW8iBz";

/// divid's `help getdifficulty`, which also answers a wrong argument count
/// (rpcblockchain.cpp:66-75)
const GETDIFFICULTY_HELP: &str = "getdifficulty\n\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n\nResult:\nn.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n\nExamples:\n> divi-cli getdifficulty \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getdifficulty\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n";

/// An address the wallet does not know: isvalid, address, scriptPubKey and
/// ismine only (rpcmisc.cpp:343-354); iswatchonly and isscript come with an
/// address of the wallet
#[test]
fn validateaddress_of_a_foreign_address_has_four_fields() {
    let (server, _dir) = server();
    let foreign = ok(&server, "validateaddress", vec![json!(FOREIGN)]);
    assert_eq!(
        keys(&foreign),
        ["address", "ismine", "isvalid", "scriptPubKey"]
    );
    let own = ok(&server, "getnewaddress", vec![]);
    let own = ok(&server, "validateaddress", vec![own]);
    assert_eq!(own["iswatchonly"], false);
    assert_eq!(own["isscript"], false);
    assert_eq!(own["ismine"], true);
}

/// A P2SH address has a P2SH scriptPubKey (GetScriptForDestination,
/// rpcmisc.cpp:347-348)
#[test]
fn validateaddress_of_a_script_address() {
    let (server, _dir) = server();
    let own = ok(&server, "getnewaddress", vec![]);
    let key = ok(&server, "validateaddress", vec![own])["pubkey"].clone();
    let multisig = ok(&server, "createmultisig", vec![json!(1), json!([key])]);
    let info = ok(
        &server,
        "validateaddress",
        vec![multisig["address"].clone()],
    );
    assert_eq!(
        info["scriptPubKey"],
        format!(
            "a914{}87",
            multisig["redeemScript"].as_str().map(script_hash).unwrap()
        )
    );
}

fn script_hash(redeem_script: &str) -> String {
    let bytes = hex::decode(redeem_script).unwrap();
    hex::encode(divi_crypto::hash160(&bytes))
}

/// validateaddress takes exactly one string (rpcmisc.cpp:320-321, :337)
#[test]
fn validateaddress_arguments() {
    let (server, _dir) = server();
    for params in [vec![], vec![json!(FOREIGN), json!(1)]] {
        let (code, text) = err(&server, "validateaddress", params);
        assert_eq!(code, -1);
        assert!(
            text.starts_with("validateaddress \"diviaddress\"\n\nReturn information"),
            "{text}"
        );
        assert!(text.ends_with("http://127.0.0.1:51473/\n"), "{text}");
    }
    assert_eq!(
        err(&server, "validateaddress", vec![json!(1)]),
        (-1, "value is type int, expected str".to_string())
    );
}

/// signmessage takes 2 to 4 strings, verifymessage 3 (rpcwallet.cpp:1366,
/// rpcmisc.cpp:487); a wrong count answers the whole help text
#[test]
fn sign_and_verify_message_arguments() {
    let (server, _dir) = server();
    let address = ok(&server, "getnewaddress", vec![]);
    let (code, text) = err(&server, "signmessage", vec![address.clone()]);
    assert_eq!(code, -1);
    assert!(text.starts_with("signmessage \"diviaddress\" \"message\" \"input_format\" \"output_format\"\n\nSign a message"), "{text}");
    assert_eq!(
        err(&server, "signmessage", vec![json!(1), json!("hello")]),
        (-1, "value is type int, expected str".to_string())
    );
    let (code, text) = err(
        &server,
        "verifymessage",
        vec![address.clone(), json!("sig")],
    );
    assert_eq!(code, -1);
    assert!(
        text.starts_with(
            "verifymessage \"diviaddress\" \"signature\" \"message\"\n\nVerify a signed message\n"
        ),
        "{text}"
    );
    assert_eq!(
        err(
            &server,
            "verifymessage",
            vec![address, json!(1), json!("hello")]
        ),
        (-1, "value is type int, expected str".to_string())
    );
}

/// getmininginfo: divid's six members (rpcmining.cpp:236-243), no argument
#[test]
fn getmininginfo_members_and_arguments() {
    let (server, _dir) = server();
    let info = ok(&server, "getmininginfo", vec![]);
    assert_eq!(
        keys(&info),
        [
            "blocks",
            "chain",
            "difficulty",
            "errors",
            "pooledtx",
            "testnet"
        ]
    );
    let (code, text) = err(&server, "getmininginfo", vec![json!(1)]);
    assert_eq!(code, -1);
    assert!(text.starts_with("getmininginfo\n\nReturns a json object containing mining-related information.\nResult:\n"), "{text}");
}

/// A wrong argument count answers divid's whole help text, Examples included
#[test]
fn wrong_argument_count_answers_cores_help_text() {
    let (server, _dir) = server();
    assert_eq!(
        err(&server, "getdifficulty", vec![json!(1)]),
        (-1, GETDIFFICULTY_HELP.to_string())
    );
    assert_eq!(
        ok(&server, "help", vec![json!("getdifficulty")]),
        GETDIFFICULTY_HELP
    );
    let (code, text) = err(&server, "getinfo", vec![json!(1)]);
    assert_eq!(code, -1);
    assert!(
        text.starts_with("getinfo\nReturns an object containing various state info.\n\nResult:\n"),
        "{text}"
    );
    let (code, text) = err(&server, "verifychain", vec![json!(1), json!(2), json!(3)]);
    assert_eq!(code, -1);
    assert!(text.ends_with("\"method\": \"verifychain\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n"), "{text}");
}

/// help: one string at most (rpcserver.cpp:291-302); "" lists the calls
#[test]
fn help_arguments() {
    let (server, _dir) = server();
    let (code, text) = err(&server, "help", vec![json!("help"), json!(1)]);
    assert_eq!(code, -1);
    assert!(
        text.starts_with("help ( \"command\" )\n\nList all commands"),
        "{text}"
    );
    assert_eq!(
        err(&server, "help", vec![json!(1)]),
        (-1, "value is type int, expected str".to_string())
    );
    assert_eq!(
        ok(&server, "help", vec![json!("")]),
        ok(&server, "help", vec![])
    );
}

/// help lists divid's calls as divid does (rpcserver.cpp:235-289): category
/// sections in name order, each call by the first line of its help; then
/// irondivid's own calls under "(irondivid)" sections
#[test]
fn help_list_is_cores() {
    let (server, _dir) = server();
    let list = ok(&server, "help", vec![]);
    let list = list.as_str().unwrap();
    assert!(
        list.starts_with(
            "== Addressindex ==\ngetaddressbalance <address>|<addresses> (only_vaults)\n"
        ),
        "{list}"
    );
    for part in [
        "\n\n== Control ==\ngetinfo\nhelp ( \"command\" )\nstop\n\n== Divi ==\n",
        "\n== Util ==\ncreatemultisig nrequired [\"key\",...]\nvalidateaddress \"diviaddress\"\nverifymessage \"diviaddress\" \"signature\" \"message\"\n\n== Wallet ==\n",
        "\ngetbalance ( \"account\" minconf includeWatchonly )\n\ngetnewaddress ( \"account\" )\n",
        "\nsignmessage \"diviaddress\" \"message\" \"input_format\" \"output_format\"\n\n== ",
    ] {
        assert!(list.contains(part), "{part:?} not in {list}");
    }
    // An unencrypted wallet: encryptwallet, not the passphrase calls
    assert!(list.contains("\nencryptwallet \"passphrase\"\n"));
    assert!(!list.contains("\nwalletlock\n"));
    // Calls Core hides
    assert!(!list.contains("\nsetmocktime"));
    assert!(!list.contains("\ninvalidateblock"));
    // irondivid's own calls come after divid's
    let own = list.find(" (irondivid) ==\n").expect("own calls");
    assert!(list[own..].contains("\nestimatesmartfee\n"));
    assert!(!list[..own].contains("estimatesmartfee"));
}
