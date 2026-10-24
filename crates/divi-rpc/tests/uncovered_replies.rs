// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Replies of the divid calls no other replies script makes, as Divi Core
//! 3.0.0's divid gives them: listlockunspent, getrawchangeaddress, loadwallet,
//! validateaddress of a change key, signtransactionwithaddresskey and
//! getinvalid
//! (scripts/uncovered-replies compares them on live nodes).

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

fn server() -> (RpcServer, Arc<WalletDb>, tempfile::TempDir) {
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
    (RpcServer::with_wallet(chain, wallet.clone()), wallet, dir)
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

/// divid answers a wrong argument count with -1 and the call's help text
fn usage(server: &RpcServer, method: &str, params: Vec<Value>) {
    let (code, message) = err(server, method, params.clone());
    assert_eq!(code, -1, "{method} {params:?}");
    assert!(
        message.starts_with(method),
        "{method} {params:?}: {message}"
    );
}

/// The locked coins in divid's std::set<COutPoint> order: the txid as a
/// 256-bit number, which is its hex as written, then the output
/// (rpcwallet.cpp:2816-2848, uint256.cpp:139-148)
#[test]
fn listlockunspent_lists_in_divid_s_order_and_takes_no_argument() {
    let (server, wallet, _dir) = server();
    let txid = |first: u8, last: u8| {
        let mut b = [0x55u8; 32];
        b[31] = first; // the first byte of the hex as written
        b[0] = last;
        Hash256::from_bytes(b)
    };
    let coins = [
        OutPoint::new(txid(0x90, 0x01), 1),
        OutPoint::new(txid(0x10, 0xff), 0),
        OutPoint::new(txid(0x90, 0x01), 0),
        OutPoint::new(txid(0x40, 0x00), 7),
    ];
    for c in coins {
        wallet.set_coin_locked(c, true);
    }
    let listed: Vec<(String, u64)> = ok(&server, "listlockunspent", vec![])
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            (
                o["txid"].as_str().unwrap().to_string(),
                o["vout"].as_u64().unwrap(),
            )
        })
        .collect();
    let mut want: Vec<(String, u64)> = coins
        .iter()
        .map(|c| (c.txid.to_string(), u64::from(c.vout)))
        .collect();
    want.sort();
    assert_eq!(listed, want);
    assert!(listed[0].0.starts_with("10"), "{listed:?}");
    usage(&server, "listlockunspent", vec![json!("x")]);
}

/// getrawchangeaddress takes at most one argument (rpcwallet.cpp:560); a
/// change key has no address-book entry, so validateaddress gives it no
/// account (rpcmisc.cpp:363), while a receiving address has ""
#[test]
fn change_address_arguments_and_account() {
    let (server, _wallet, _dir) = server();
    let change = ok(&server, "getrawchangeaddress", vec![json!(1)]);
    usage(&server, "getrawchangeaddress", vec![json!(1), json!(2)]);
    let info = ok(&server, "validateaddress", vec![change]);
    assert_eq!(info["ismine"], json!(true));
    assert!(info.get("account").is_none(), "{info}");

    let receiving = ok(&server, "getnewaddress", vec![]);
    let info = ok(&server, "validateaddress", vec![receiving]);
    assert_eq!(info["account"], json!(""));
}

/// loadwallet takes one string argument before anything else
/// (rpcwallet.cpp:526-534)
#[test]
fn loadwallet_counts_and_types_its_argument() {
    let (server, _wallet, _dir) = server();
    usage(&server, "loadwallet", vec![]);
    usage(&server, "loadwallet", vec![json!("a.dat"), json!("b.dat")]);
    assert_eq!(
        err(&server, "loadwallet", vec![json!(5)]),
        (-1, "value is type int, expected str".to_string())
    );
}

/// A transaction of two inputs and one output, the first input's coin the
/// wallet's
fn two_inputs() -> String {
    let tx = Transaction {
        version: 1,
        vin: (0u8..2)
            .map(|n| {
                TxIn::new(
                    OutPoint::new(Hash256::from_bytes([n + 1; 32]), 0),
                    Script::new(),
                    0xffffffff,
                )
            })
            .collect(),
        vout: vec![TxOut::new(
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(&[0xaa; 20]),
        )],
        lock_time: 0,
    };
    hex::encode(divi_primitives::serialize(&tx))
}

/// signtransactionwithaddresskey signs with SIGHASH_SINGLE; for an input
/// without an output of its index Core's SignatureHash is the value 1
/// (SignatureCheckers.cpp), and the signature is over that
#[test]
fn signtransactionwithaddresskey_signs_core_s_hash() {
    let (server, wallet, _dir) = server();
    let address = ok(&server, "getnewaddress", vec![]);
    let key = wallet
        .get_key_by_address(&divi_wallet::Address::from_base58(address.as_str().unwrap()).unwrap())
        .unwrap();
    let raw = two_inputs();
    for index in [0usize, 1] {
        let asm = ok(
            &server,
            "signtransactionwithaddresskey",
            vec![json!(raw), address.clone(), json!(index)],
        );
        let mut sig = hex::decode(asm.as_str().unwrap()).unwrap();
        assert_eq!(sig.pop(), Some(3), "SIGHASH_SINGLE");
        let tx: Transaction = divi_primitives::deserialize(&hex::decode(&raw).unwrap()).unwrap();
        let mut code = vec![key.pubkey_bytes().len() as u8];
        code.extend_from_slice(&key.pubkey_bytes());
        code.push(0xac);
        let hash = divi_script::checker::signature_hash(&Script::from_bytes(code), &tx, index, 3);
        if index == 1 {
            let mut one = [0u8; 32];
            one[0] = 1;
            assert_eq!(hash, one);
        }
        assert!(
            divi_script::checker::verify_ecdsa_lax(&key.pubkey_bytes(), &sig, &hash),
            "input {index}: not a signature over Core's hash"
        );
    }
    // A fourth argument is not read (no count check, rpcrawtransaction.cpp:566-572)
    ok(
        &server,
        "signtransactionwithaddresskey",
        vec![json!(raw), address.clone(), json!(0), json!(1)],
    );
}

/// ParseHexV: -8 naming the text, "" for a value that is not a string
/// (JsonParseHelpers.cpp:20-26)
#[test]
fn signtransactionwithaddresskey_hex_errors_name_the_text() {
    let (server, _wallet, _dir) = server();
    let address = ok(&server, "getnewaddress", vec![]);
    for (hex, shown) in [
        (json!("zz"), "zz"),
        (json!(5), ""),
        (json!(""), ""),
        (json!("abc"), "abc"),
    ] {
        assert_eq!(
            err(
                &server,
                "signtransactionwithaddresskey",
                vec![hex, address.clone(), json!(0)]
            ),
            (
                -8,
                format!("Transaction hex data must be hexadecimal string (not '{shown}')")
            )
        );
    }
}

/// getinvalid: Core's fixed empty summary, at most one string argument
/// (rpcblockchain.cpp:687-725)
#[test]
fn getinvalid_checks_its_argument() {
    let (server, _wallet, _dir) = server();
    let empty = json!([{
        "addresses_with_invalid": {},
        "total_unspent": "0.00",
        "total_minted": "0.00",
        "total_valid_used": "0.00",
    }]);
    assert_eq!(ok(&server, "getinvalid", vec![]), empty);
    assert_eq!(ok(&server, "getinvalid", vec![json!("all")]), empty);
    assert_eq!(
        err(&server, "getinvalid", vec![json!(5)]),
        (-1, "value is type int, expected str".to_string())
    );
    usage(&server, "getinvalid", vec![json!("all"), json!("x")]);
}
