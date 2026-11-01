// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! createmultisig and addmultisigaddress check their arguments as Divi Core's
//! _createmultisig_redeemScript does (rpcmisc.cpp:388-445), with its texts, and
//! addmultisigaddress labels the address with the account
//! (rpcwallet.cpp:1763-1774).

use divi_primitives::hash::Hash160;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

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

#[test]
fn multisig_arguments_are_checked_as_divid_checks_them() {
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
    let server = RpcServer::with_wallet(chain, wallet);
    let address = call(&server, "getnewaddress", vec![]).unwrap();
    let key = call(&server, "validateaddress", vec![address.clone()]).unwrap()["pubkey"].clone();
    let keyless =
        Address::from_pubkey_hash(Hash160::from_bytes([7; 20]), Network::Regtest).to_base58();
    let script = Address::p2sh(Hash160::from_bytes([8; 20]), Network::Regtest).to_base58();
    let no_point = format!("02{}", "00".repeat(32));
    let refused = |m: &str| Err((-1, m.to_string()));

    for method in ["createmultisig", "addmultisigaddress"] {
        let run = |args: Vec<Value>| call(&server, method, args);
        assert_eq!(
            run(vec![json!(0), json!([key])]),
            refused("a multisignature address must require at least one key to redeem")
        );
        assert_eq!(
            run(vec![json!(3), json!([key, key])]),
            refused("not enough keys supplied (got 2 keys, but need at least 3 to redeem)")
        );
        assert_eq!(
            run(vec![json!(1), json!(vec![key.clone(); 17])]),
            refused("Number of addresses involved in the multisignature address creation > 16\nReduce the number")
        );
        assert_eq!(
            run(vec![json!(1), json!(["xyz"])]),
            refused(" Invalid public key: xyz")
        );
        assert_eq!(
            run(vec![json!(1), json!([no_point])]),
            refused(&format!(" Invalid public key: {no_point}"))
        );
        assert_eq!(
            run(vec![json!(1), json!([keyless])]),
            refused(&format!("no full public key for address {keyless}"))
        );
        assert_eq!(
            run(vec![json!(1), json!([script])]),
            refused(&format!("{script} does not refer to a key"))
        );
        assert_eq!(
            run(vec![json!("1"), json!([key])]),
            refused("value is type str, expected int")
        );
        assert_eq!(
            run(vec![json!(1), key.clone()]),
            refused("value is type str, expected array")
        );
        // an address of the wallet and a hex key make the same script
        assert!(run(vec![json!(1), json!([address, key])]).is_ok());
    }
    assert!(call(
        &server,
        "createmultisig",
        vec![json!(1), json!([key]), json!("x")]
    )
    .is_err());

    let made = call(
        &server,
        "addmultisigaddress",
        vec![json!(1), json!([key]), json!("msig")],
    )
    .unwrap();
    assert_eq!(
        call(&server, "getaddressesbyaccount", vec![json!("msig")]).unwrap(),
        json!([made])
    );
    assert_eq!(
        call(
            &server,
            "addmultisigaddress",
            vec![json!(1), json!([key]), json!("*")]
        ),
        Err((-11, "Invalid account name".to_string()))
    );
}
