// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! signmessage / verifymessage answer with Divi Core's error codes
//! (src/rpcwallet.cpp signmessage, src/rpcmisc.cpp verifymessage).

use divi_primitives::hash::Hash160;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use serde_json::json;
use std::sync::Arc;

fn call(server: &RpcServer, method: &str, params: &[&str]) -> Response {
    server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params.iter().map(|p| json!(p)).collect()),
    })
}

fn code(r: &Response) -> Option<i32> {
    r.error.as_ref().map(|e| e.code)
}

#[test]
fn message_signing_error_codes_match_divid() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain, wallet);

    let mine = call(&server, "getnewaddress", &[]).result.unwrap();
    let mine = mine.as_str().unwrap();
    let p2sh = Address::p2sh(Hash160::from_bytes([1u8; 20]), Network::Regtest).to_base58();
    let foreign =
        Address::from_pubkey_hash(Hash160::from_bytes([2u8; 20]), Network::Regtest).to_base58();

    // signmessage
    let r = call(&server, "signmessage", &["notanaddress", "hi"]);
    assert_eq!(code(&r), Some(-3), "invalid address: {:?}", r.error);
    let r = call(&server, "signmessage", &[&p2sh, "hi"]);
    assert_eq!(code(&r), Some(-3), "P2SH address: {:?}", r.error);
    assert_eq!(r.error.unwrap().message, "Address does not refer to key");
    let r = call(&server, "signmessage", &[&foreign, "hi"]);
    assert_eq!(code(&r), Some(-4), "no private key: {:?}", r.error);
    let sig = call(&server, "signmessage", &[mine, "hi"]).result.unwrap();
    let sig = sig.as_str().unwrap();

    // verifymessage
    let r = call(&server, "verifymessage", &["notanaddress", sig, "hi"]);
    assert_eq!(code(&r), Some(-3), "invalid address: {:?}", r.error);
    let r = call(&server, "verifymessage", &[&p2sh, sig, "hi"]);
    assert_eq!(code(&r), Some(-3), "P2SH address: {:?}", r.error);
    assert_eq!(r.error.unwrap().message, "Address does not refer to key");
    let r = call(&server, "verifymessage", &[mine, "A", "hi"]);
    assert_eq!(code(&r), Some(-5), "dangling base64: {:?}", r.error);
    for junk in ["AAAA", "!!notbase64"] {
        let r = call(&server, "verifymessage", &[mine, junk, "hi"]);
        assert_eq!(r.result, Some(json!(false)), "{junk}: {:?}", r.error);
    }
    let r = call(&server, "verifymessage", &[mine, sig, "hi"]);
    assert_eq!(r.result, Some(json!(true)));
    let r = call(&server, "verifymessage", &[mine, sig, "other"]);
    assert_eq!(r.result, Some(json!(false)));
}
