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

/// One argument more than divid takes answers -1 with divid's help text
#[test]
fn one_argument_too_many_answers_divids_help_text() {
    let data = data();
    let (server, _dir) = server(true);
    // (call, most arguments divid takes), from each call's fHelp check
    let most: &[(&str, usize)] = &[
        ("getinfo", 0),
        ("getnetworkinfo", 0),
        ("addnode", 2),
        ("getaddednodeinfo", 2),
        ("getconnectioncount", 0),
        ("getnettotals", 0),
        ("getpeerinfo", 0),
        ("ping", 0),
        ("getblockchaininfo", 0),
        ("getbestblockhash", 0),
        ("getblockcount", 0),
        ("getlotteryblockwinners", 1),
        ("getblock", 2),
        ("getblockhash", 1),
        ("getblockheader", 2),
        ("getchaintips", 0),
        ("getdifficulty", 0),
        ("getmempoolinfo", 0),
        ("getrawmempool", 1),
        ("gettxout", 3),
        ("gettxoutsetinfo", 0),
        ("verifychain", 2),
        ("reverseblocktransactions", 1),
        ("invalidateblock", 1),
        ("reconsiderblock", 1),
        ("getinvalid", 1),
        ("getmininginfo", 0),
        ("prioritisetransaction", 3),
        ("setgenerate", 1),
        ("generateblock", 1),
        ("createrawtransaction", 2),
        ("decoderawtransaction", 1),
        ("decodescript", 1),
        ("getrawtransaction", 2),
        ("sendrawtransaction", 2),
        ("signrawtransaction", 4),
        ("createmultisig", 2),
        ("validateaddress", 1),
        ("verifymessage", 3),
        ("setmocktime", 1),
        ("listmasternodes", 1),
        ("getmasternodecount", 0),
        ("setupmasternode", 6),
        ("signmnbroadcast", 1),
        ("verifymasternodesetup", 4),
        ("broadcaststartmasternode", 2),
        ("startmasternode", 2),
        ("getmasternodestatus", 0),
        ("getmasternodewinners", 3),
        ("importmnbroadcast", 1),
        ("listmnbroadcasts", 0),
        ("mnsync", 1),
        ("spork", 2),
        ("ban", 1),
        ("clearbanned", 1),
        ("listbanned", 1),
        ("allocatefunds", 3),
        ("getaddressbalance", 2),
        ("getaddressdeltas", 2),
        ("getaddresstxids", 2),
        ("getaddressutxos", 2),
        ("getspentinfo", 1),
        ("addmultisigaddress", 3),
        ("backupwallet", 1),
        ("dumpprivkey", 1),
        ("dumphdinfo", 0),
        ("bip38paperwallet", 1),
        ("bip38decrypt", 2),
        ("encryptwallet", 1),
        ("getaccountaddress", 1),
        ("getaccount", 1),
        ("getaddressesbyaccount", 1),
        ("getbalance", 3),
        ("getnewaddress", 1),
        ("getrawchangeaddress", 1),
        ("getreceivedbyaccount", 2),
        ("getreceivedbyaddress", 2),
        ("getstakingstatus", 0),
        ("gettransaction", 2),
        ("getunconfirmedbalance", 0),
        ("getwalletinfo", 0),
        ("loadwallet", 1),
        ("importprivkey", 3),
        ("importaddress", 3),
        ("keypoolrefill", 1),
        ("listaccounts", 2),
        ("listlockunspent", 0),
        ("listreceivedbyaccount", 3),
        ("listreceivedbyaddress", 3),
        ("listtransactions", 4),
        ("listunspent", 3),
        ("lockunspent", 2),
        ("sendfrom", 5),
        ("sendmany", 4),
        ("sendtoaddress", 5),
        ("fundvault", 2),
        ("reclaimvaultfunds", 5),
        ("debitvaultbyname", 4),
        ("addvault", 2),
        ("getcoinavailability", 1),
        ("setaccount", 2),
        ("signmessage", 4),
    ];
    let mut differ = Vec::new();
    for (method, max) in most {
        // arguments that could not do anything if a call took them
        let filler = match *method {
            "backupwallet" => "/nonexistent/divid-help/x",
            "encryptwallet" => "",
            _ => "x",
        };
        let want = expected(&data, "unencrypted", method);
        match call(&server, method, vec![json!(filler); max + 1]) {
            Err((-1, message)) if message == want => {}
            _ => differ.push(*method),
        }
    }
    assert!(differ.is_empty(), "not divid's usage error: {differ:?}");
}
