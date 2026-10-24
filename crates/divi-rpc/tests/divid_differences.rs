// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Replies where irondivid knowingly differs from Divi Core 3.0.0's divid.
//! Each test pins one row of docs/divid-differences.md, so a change that
//! drops or alters the difference has to change the document too.

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

fn result(server: &RpcServer, method: &str, params: Vec<Value>) -> Value {
    let reply = call(server, method, params);
    assert!(
        reply.error.is_none(),
        "{method}: {:?}",
        reply.error.map(|e| e.message)
    );
    reply.result.expect("result")
}

fn keys(v: &Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

/// Core 3.0.0 has no estimatefee / estimatesmartfee (not in rpcserver.cpp's
/// table); irondivid answers both, at or above the relay floor, for BasicSwap
#[test]
fn fee_estimates_exist() {
    let (server, _dir) = server();
    let fee = result(&server, "estimatefee", vec![json!(2)]);
    assert!(fee.as_f64().unwrap() >= 0.0001, "{fee}");
    let smart = result(&server, "estimatesmartfee", vec![json!(2)]);
    assert!(smart["feerate"].as_f64().unwrap() >= 0.0001, "{smart}");
}

/// getblockchaininfo carries fields divid lacks (Core sends chain, blocks,
/// headers, bestblockhash, difficulty, chainwork: rpcblockchain.cpp:445-452)
#[test]
fn getblockchaininfo_has_fields_divid_lacks() {
    let (server, _dir) = server();
    let info = result(&server, "getblockchaininfo", vec![]);
    for core in [
        "chain",
        "blocks",
        "headers",
        "bestblockhash",
        "difficulty",
        "chainwork",
    ] {
        assert!(info.get(core).is_some(), "{core} missing: {info}");
    }
    for extra in [
        "mediantime",
        "pruned",
        "pruneheight",
        "winnersstripheight",
        "warnings",
    ] {
        assert!(info.get(extra).is_some(), "{extra} gone: {info}");
    }
}

/// getwalletinfo carries fields divid lacks (rpcwallet.cpp:2873-2930)
#[test]
fn getwalletinfo_has_fields_divid_lacks() {
    let (server, _dir) = server();
    let info = result(&server, "getwalletinfo", vec![]);
    for extra in ["walletname", "keypoololdest", "paytxfee", "hdmasterkeyid"] {
        assert!(info.get(extra).is_some(), "{extra} gone: {info}");
    }
}

/// getinfo reports divid's version; getnetworkinfo reports irondivid's own
/// version, and both report divid's protocol version, 70915 (version.h:21)
#[test]
fn versions_name_irondivid() {
    let (server, _dir) = server();
    let info = result(&server, "getinfo", vec![]);
    assert_eq!(info["version"], "3.0.0.0");
    let net = result(&server, "getnetworkinfo", vec![]);
    assert_eq!(
        net["version"],
        format!("{}.0", env!("CARGO_PKG_VERSION")),
        "{net}"
    );
    assert_eq!(net["protocolversion"], 70915);
    assert_eq!(info["protocolversion"], 70915);
}

/// Members of a result come in name order, not in divid's insertion order
#[test]
fn result_members_are_in_name_order() {
    let (server, _dir) = server();
    for method in ["getinfo", "getblockchaininfo", "getwalletinfo"] {
        let info = result(&server, method, vec![]);
        let names = keys(&info);
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "{method}");
    }
}

/// loadwallet exists in divid (rpcserver.cpp:439) and is refused here: the
/// wallet is chosen at start
#[test]
fn loadwallet_is_refused() {
    let (server, _dir) = server();
    let reply = call(&server, "loadwallet", vec![json!("other.dat")]);
    let error = reply.error.expect("refused");
    assert!(error.message.contains("--wallet"), "{}", error.message);
}

/// getblock also takes 0, 1 and 2 for verbose, as Bitcoin Core's verbosity;
/// divid takes only true or false (rpcblockchain.cpp:216)
#[test]
fn getblock_takes_a_verbosity_number() {
    let (server, _dir) = server();
    let tip = call(&server, "getbestblockhash", vec![]).result.unwrap();
    for v in [0, 1, 2] {
        let reply = call(&server, "getblock", vec![tip.clone(), json!(v)]);
        assert!(reply.error.is_none(), "verbosity {v}: {:?}", reply.error);
    }
}

/// getmempoolinfo: divid gives size and bytes (rpcblockchain.cpp:569-574);
/// irondivid adds usage, maxmempool and mempoolminfee
#[test]
fn getmempoolinfo_has_fields_divid_lacks() {
    let (server, _dir) = server();
    let info = result(&server, "getmempoolinfo", vec![]);
    assert_eq!(
        keys(&info),
        ["bytes", "maxmempool", "mempoolminfee", "size", "usage"]
    );
}

/// generateblock answers on regtest only, as setgenerate; divid has no
/// network check for it (rpcmining.cpp:121-210)
#[test]
fn generateblock_is_regtest_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Testnet, ChainMode::Divi),
        )
        .unwrap(),
    );
    // with a wallet, as divid reaches generateblock only with one
    // (rpcserver.cpp:369, :1043-1047)
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Testnet,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain, wallet);
    let error = call(&server, "generateblock", vec![])
        .error
        .expect("refused");
    assert_eq!(error.code, -32601);
    assert_eq!(
        error.message,
        "Method disabled: invalid networks setting (regtest only)"
    );
}
