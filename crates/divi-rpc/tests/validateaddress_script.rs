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

//! validateaddress of a script address the wallet knows describes the script
//! as Divi Core's DescribeAddressVisitor does (rpcmisc.cpp:249-270): its type,
//! hex, the addresses it pays and, for a multisig, the signatures it needs;
//! with only the address watched the wallet has no script, and says so.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

fn node(dir: &tempfile::TempDir) -> RpcServer {
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    RpcServer::with_wallet(chain, wallet)
}

fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Value {
    let r = server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    });
    assert!(r.error.is_none(), "{method}: {:?}", r.error);
    r.result.unwrap()
}

/// A new key of `server`: its address and public key
fn key(server: &RpcServer) -> (String, String) {
    let addr = call(server, "getnewaddress", vec![]);
    let info = call(server, "validateaddress", vec![addr.clone()]);
    (
        addr.as_str().unwrap().to_string(),
        info["pubkey"].as_str().unwrap().to_string(),
    )
}

#[test]
fn validateaddress_of_a_multisig_address_describes_its_script() {
    let (d1, d2, d3) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let (a, b, watcher) = (node(&d1), node(&d2), node(&d3));
    let (addr_a, pk_a) = key(&a);
    let (addr_b, pk_b) = key(&b);
    let (addr_c, pk_c) = key(&b);
    let keys = json!([pk_a, pk_b, pk_c]);

    // a holds one key of the three: the address is watch-only there
    let ms = call(&a, "addmultisigaddress", vec![json!(2), keys.clone()]);
    let redeem = call(&a, "createmultisig", vec![json!(2), keys])["redeemScript"].clone();
    let info = call(&a, "validateaddress", vec![ms.clone()]);
    assert_eq!(info["isscript"], true);
    assert_eq!(info["iswatchonly"], true);
    assert_eq!(info["script"], "multisig");
    assert_eq!(info["hex"], redeem);
    assert_eq!(info["addresses"], json!([addr_a, addr_b, addr_c]));
    assert_eq!(info["sigsrequired"], 2);

    // Only the address watched: no script in the wallet
    call(
        &watcher,
        "importaddress",
        vec![ms.clone(), json!(""), json!(false)],
    );
    let info = call(&watcher, "validateaddress", vec![ms.clone()]);
    assert_eq!(info["iswatchonly"], true);
    assert_eq!(info["script"], "nonstandard");
    assert_eq!(info["hex"], "");
    assert_eq!(info["addresses"], json!([]));
    assert!(info.get("sigsrequired").is_none());

    // A wallet that does not know the address: none of these
    let fresh = tempfile::tempdir().unwrap();
    let info = call(&node(&fresh), "validateaddress", vec![ms]);
    for field in ["script", "hex", "addresses", "sigsrequired", "iswatchonly"] {
        assert!(
            info.get(field).is_none(),
            "{field} on an address not in the wallet"
        );
    }
}
