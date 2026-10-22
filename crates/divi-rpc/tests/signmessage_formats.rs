// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! signmessage "address" "message" ( "input_format" "output_format" ) as Divi
//! Core's rpcwallet.cpp: input "hex" or "b64" decodes the message before it is
//! signed (anything else signs it as text), output "hex" returns the signature
//! in hex instead of base64. verifymessage takes exactly three arguments.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

fn call(server: &RpcServer, method: &str, params: &[&str]) -> Response {
    server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params.iter().map(|p| json!(p)).collect()),
    })
}

fn ok(r: Response) -> Value {
    assert!(r.error.is_none(), "{:?}", r.error);
    r.result.unwrap()
}

#[test]
fn signmessage_input_and_output_formats() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain, wallet);
    let addr = ok(call(&server, "getnewaddress", &[]));
    let addr = addr.as_str().unwrap();
    let sign = |args: &[&str]| {
        let mut all = vec![addr];
        all.extend_from_slice(args);
        ok(call(&server, "signmessage", &all))
    };

    // Signatures are deterministic, so equal messages give equal signatures
    let plain = sign(&["hi there"]);
    assert_eq!(sign(&["6869207468657265", "hex"]), plain, "hex input");
    assert_eq!(sign(&["aGkgdGhlcmU=", "b64"]), plain, "b64 input");
    // Core's ParseHex skips spaces between bytes and stops at the first non-hex pair
    assert_eq!(sign(&["68 69 20 74 68 65 72 65zz", "hex"]), plain);
    // Any other input format signs the text as given
    assert_eq!(sign(&["hi there", "text"]), plain);
    assert_ne!(sign(&["6869207468657265", "HEX"]), plain);

    // Output "hex": the same 65-byte signature, hex-encoded
    let hex_sig = sign(&["hi there", "", "hex"]);
    let raw = STANDARD.decode(plain.as_str().unwrap()).unwrap();
    assert_eq!(hex_sig, json!(hex::encode(&raw)));
    assert_eq!(sign(&["6869207468657265", "hex", "hex"]), hex_sig);
    // Any other output format is base64
    assert_eq!(sign(&["hi there", "", "b64"]), plain);

    // The base64 signature of decoded input verifies against the decoded text
    let r = ok(call(
        &server,
        "verifymessage",
        &[addr, plain.as_str().unwrap(), "hi there"],
    ));
    assert_eq!(r, json!(true));

    // Argument counts as Divi Core: signmessage 2..4, verifymessage exactly 3
    let r = call(&server, "signmessage", &[addr, "hi", "", "hex", "extra"]);
    assert_eq!(r.error.map(|e| e.code), Some(-1));
    let r = call(
        &server,
        "verifymessage",
        &[addr, plain.as_str().unwrap(), "hi there", "hex"],
    );
    assert_eq!(r.error.map(|e| e.code), Some(-1));
}
