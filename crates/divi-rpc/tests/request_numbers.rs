// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Numbers in a request body read as Divi Core's json_spirit reads them
//! (json_spirit_reader_template.h:498-501), seen through walletpassphrase's
//! timeout on an encrypted wallet: found by scripts/wallet-encryption.

use divi_primitives::ChainMode;
use divi_rpc::RpcServer;
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const PASS: &str = "correct horse battery staple";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn server(dir: &std::path::Path) -> RpcServer {
    let db = Arc::new(ChainDatabase::open(dir.join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &dir.join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    wallet.encrypt_wallet(PASS).unwrap();
    RpcServer::with_wallet(chain, wallet)
}

fn reply(server: &RpcServer, body: &str) -> Value {
    let (_, reply) = server.handle_http_body(body);
    serde_json::from_str(&reply).unwrap()
}

/// walletpassphrase with `timeout` written as given; the reply and then
/// getwalletinfo's encryption_status and unlocked_until
fn unlock(server: &RpcServer, timeout: &str) -> (Value, String, i64) {
    let body = format!(r#"{{"method":"walletpassphrase","params":["{PASS}",{timeout}],"id":1}}"#);
    let answer = reply(server, &body);
    let info = &reply(server, r#"{"method":"getwalletinfo","params":[],"id":2}"#)["result"];
    let status = info["encryption_status"].as_str().unwrap().to_string();
    let until = info["unlocked_until"].as_i64().unwrap();
    reply(server, r#"{"method":"walletlock","params":[],"id":3}"#);
    (answer, status, until)
}

/// An integer that fits neither int64 nor uint64 makes the request a parse
/// error in divid, so the wallet stays locked; read as a real, it unlocked the
/// wallet and only then failed on the timeout's type, leaving it unlocked with
/// no timer
#[test]
fn a_timeout_beyond_uint64_is_a_parse_error_and_unlocks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path());
    for timeout in ["18446744073709551616", "-9223372036854775809"] {
        let (answer, status, until) = unlock(&server, timeout);
        assert_eq!(answer["error"]["code"], -32700, "{timeout}: {answer}");
        assert_eq!(answer["error"]["message"], "Parse error");
        assert_eq!(answer["id"], Value::Null);
        assert_eq!(status, "locked", "{timeout}");
        assert_eq!(until, 0, "{timeout}");
    }
}

/// json_spirit reads "+60" and "060" as the integer 60 and "-0" as 0: the
/// wallet unlocks for 60 seconds, or with no timer
#[test]
fn a_timeout_with_a_plus_sign_or_leading_zero_is_an_integer() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path());
    for timeout in ["+60", "060"] {
        let before = now();
        let (answer, status, until) = unlock(&server, timeout);
        assert_eq!(answer["error"], Value::Null, "{timeout}: {answer}");
        assert_eq!(status, "unlocked", "{timeout}");
        assert!(
            until >= before + 60 && until <= now() + 60,
            "{timeout}: {until}"
        );
    }
    let before = now();
    let (answer, status, until) = unlock(&server, "-0");
    assert_eq!(answer["error"], Value::Null, "-0: {answer}");
    assert_eq!(status, "unlocked");
    assert!(until >= before && until <= now(), "-0: {until}");
}

/// "1." and ".5" are reals to json_spirit: the wallet unlocks, then the
/// timeout is refused as no integer (rpcwallet.cpp:2614-2623)
#[test]
fn a_timeout_with_a_bare_dot_is_a_real() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path());
    for timeout in ["60.", ".5"] {
        let (answer, status, _) = unlock(&server, timeout);
        assert_eq!(answer["error"]["code"], -1, "{timeout}: {answer}");
        assert_eq!(
            answer["error"]["message"],
            "value is type real, expected int"
        );
        assert_eq!(status, "unlocked", "{timeout}");
    }
}
