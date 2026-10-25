// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! signmessage, walletpassphrase and walletpassphrasechange as Divi Core 3.0.0
//! answers them: the order of their checks, the unlock state they leave, and
//! getwalletinfo's unlocked_until.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcError, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

struct Node {
    server: RpcServer,
    _dir: tempfile::TempDir,
}

/// A regtest node whose wallet is encrypted with "pass" (and so locked)
fn encrypted_node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    let node = Node {
        server: RpcServer::with_wallet(chain, wallet),
        _dir: dir,
    };
    node.ok("encryptwallet", vec![json!("pass")]);
    node
}

impl Node {
    fn call(&self, method: &str, params: Vec<Value>) -> Response {
        self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        })
    }

    fn err(&self, method: &str, params: Vec<Value>) -> (i32, String) {
        let reply = self.call(method, params.clone());
        let e: RpcError = reply
            .error
            .unwrap_or_else(|| panic!("{method} {params:?} answered {:?}", reply.result));
        (e.code, e.message)
    }

    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        let reply = self.call(method, params.clone());
        assert!(
            reply.error.is_none(),
            "{method} {params:?}: {:?}",
            reply.error
        );
        reply.result.expect("result")
    }

    fn status(&self) -> Value {
        self.ok("getwalletinfo", vec![])["encryption_status"].clone()
    }
}

fn unlock_needed() -> (i32, String) {
    (
        -13,
        "Error: Please enter the wallet passphrase with walletpassphrase first.".to_string(),
    )
}

/// signmessage checks that the wallet is unlocked before it reads an argument
/// (rpcwallet.cpp:1385-1388): a message of the wrong type is -13 while locked
/// or unlocked for staking only, and -1 once unlocked
#[test]
fn signmessage_checks_the_unlock_before_the_arguments() {
    let node = encrypted_node();
    let address = node.ok("getnewaddress", vec![]);
    assert_eq!(
        node.err("signmessage", vec![address.clone(), json!(5)]),
        unlock_needed()
    );
    node.ok(
        "walletpassphrase",
        vec![json!("pass"), json!(600), json!(true)],
    );
    assert_eq!(
        node.err("signmessage", vec![address.clone(), json!(5)]),
        unlock_needed()
    );
    node.ok("walletlock", vec![]);
    node.ok("walletpassphrase", vec![json!("pass"), json!(600)]);
    assert_eq!(
        node.err("signmessage", vec![address, json!(5)]),
        (-1, "value is type int, expected str".to_string())
    );
}

fn unlocked_until(node: &Node) -> i64 {
    node.ok("getwalletinfo", vec![])["unlocked_until"]
        .as_i64()
        .unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// walletpassphrase reads its timeout with get_int64 after it has unlocked
/// the wallet (rpcwallet.cpp:2615-2623). A timeout that is no integer is -1
/// with the wallet unlocked and unlocked_until as it was; one of 0 or less
/// unlocks with no timer, unlocked_until now plus it (rpcserver.cpp:1195-1220)
#[test]
fn walletpassphrase_reads_its_timeout_after_the_unlock() {
    let node = encrypted_node();
    assert_eq!(
        node.err("walletpassphrase", vec![json!("pass"), json!(1.5)]),
        (-1, "value is type real, expected int".to_string())
    );
    assert_eq!(node.status(), json!("unlocked"));
    assert_eq!(unlocked_until(&node), 0);
    node.ok("walletlock", vec![]);

    assert_eq!(
        node.err("walletpassphrase", vec![json!("pass"), json!(null)]),
        (-1, "value is type null, expected int".to_string())
    );
    assert_eq!(node.status(), json!("unlocked"));
    node.ok("walletlock", vec![]);

    node.ok("walletpassphrase", vec![json!("pass"), json!(-5)]);
    assert_eq!(node.status(), json!("unlocked"));
    assert!((unlocked_until(&node) - (now() - 5)).abs() <= 2);
    node.ok("walletlock", vec![]);
    assert_eq!(unlocked_until(&node), 0);

    node.ok("walletpassphrase", vec![json!("pass"), json!(0)]);
    assert!((unlocked_until(&node) - now()).abs() <= 2);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(node.status(), json!("unlocked"), "no timer for 0");
    node.ok("walletlock", vec![]);

    node.ok("walletpassphrase", vec![json!("pass"), json!(2)]);
    assert!((unlocked_until(&node) - (now() + 2)).abs() <= 2);
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(node.status(), json!("locked"));
    assert_eq!(unlocked_until(&node), 0);
}
