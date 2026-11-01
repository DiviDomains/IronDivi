// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! signrawtransaction's 4th argument, sighashtype, as Divi Core's
//! rpcrawtransaction.cpp: ALL, NONE, SINGLE, each optionally |ANYONECANPAY,
//! -8 "Invalid sighash param" for anything else, and with SINGLE an input
//! without a matching output is left unsigned.

use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{encode_wif, HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Response {
    server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    })
}

fn ok(r: Response) -> Value {
    assert!(r.error.is_none(), "{:?}", r.error);
    r.result.unwrap()
}

fn server() -> (RpcServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    (RpcServer::with_wallet(chain, wallet), dir)
}

fn wif(k: &SecretKey) -> String {
    let mut b = [0u8; 32];
    b.copy_from_slice(k.as_bytes());
    encode_wif(&b, true, Network::Regtest)
}

/// Two P2PKH inputs paying `key`, one output: input 1 has no output at its index
fn two_in_one_out(key: &SecretKey) -> (Transaction, Script, Value) {
    let spk = Script::new_p2pkh(divi_crypto::hash160(&key.public_key().to_bytes()).as_bytes());
    let outs = [
        OutPoint::new(Hash256::from_bytes([0x41; 32]), 0),
        OutPoint::new(Hash256::from_bytes([0x42; 32]), 1),
    ];
    let mut tx = Transaction::new();
    for o in outs {
        tx.vin.push(TxIn::new(o, Script::new(), 0xffff_ffff));
    }
    tx.vout.push(TxOut::new(
        Amount::from_sat(1_000_000),
        Script::new_p2pkh(&[6u8; 20]),
    ));
    let prevtxs = json!([
        {"txid": outs[0].txid.to_string(), "vout": 0, "scriptPubKey": hex::encode(spk.as_bytes())},
        {"txid": outs[1].txid.to_string(), "vout": 1, "scriptPubKey": hex::encode(spk.as_bytes())},
    ]);
    (tx, spk, prevtxs)
}

/// The sighash byte at the end of the signature push of a P2PKH scriptSig
fn hash_type_byte(script_sig: &Script) -> u8 {
    let b = script_sig.as_bytes();
    let len = b[0] as usize;
    b[len]
}

#[test]
fn signrawtransaction_uses_the_requested_sighash_type() {
    let (server, _dir) = server();
    let key = SecretKey::new_random();
    let (tx, spk, prevtxs) = two_in_one_out(&key);
    let unsigned = hex::encode(serialize(&tx));

    for (name, byte) in [
        ("ALL", 0x01u8),
        ("NONE", 0x02),
        ("SINGLE", 0x03),
        ("ALL|ANYONECANPAY", 0x81),
        ("NONE|ANYONECANPAY", 0x82),
        ("SINGLE|ANYONECANPAY", 0x83),
    ] {
        let r = ok(call(
            &server,
            "signrawtransaction",
            vec![
                json!(unsigned),
                prevtxs.clone(),
                json!([wif(&key)]),
                json!(name),
            ],
        ));
        let t: Transaction =
            deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(hash_type_byte(&t.vin[0].script_sig), byte, "{name}");
        divi_script::verify_input(&t, 0, &spk, Amount::ZERO)
            .unwrap_or_else(|e| panic!("{name}: input 0 does not verify: {e:?}"));
        if name.starts_with("SINGLE") {
            // Divi Core signs SIGHASH_SINGLE only where there is a matching output
            assert!(t.vin[1].script_sig.is_empty(), "{name}: input 1 signed");
            assert_eq!(r["complete"], json!(false), "{name}");
        } else {
            assert_eq!(hash_type_byte(&t.vin[1].script_sig), byte, "{name}");
            divi_script::verify_input(&t, 1, &spk, Amount::ZERO).unwrap();
            assert_eq!(r["complete"], json!(true), "{name}");
        }
    }

    // A signature made with NONE stays valid when the outputs change; ALL does not
    let sign = |name: &str| -> Transaction {
        let r = ok(call(
            &server,
            "signrawtransaction",
            vec![
                json!(unsigned),
                prevtxs.clone(),
                json!([wif(&key)]),
                json!(name),
            ],
        ));
        deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap()
    };
    let mut none = sign("NONE");
    none.vout[0].value = Amount::from_sat(5);
    divi_script::verify_input(&none, 0, &spk, Amount::ZERO).expect("NONE ignores outputs");
    let mut all = sign("ALL");
    all.vout[0].value = Amount::from_sat(5);
    assert!(divi_script::verify_input(&all, 0, &spk, Amount::ZERO).is_err());

    // null is the default (ALL)
    let r = ok(call(
        &server,
        "signrawtransaction",
        vec![
            json!(unsigned),
            prevtxs.clone(),
            json!([wif(&key)]),
            Value::Null,
        ],
    ));
    let t: Transaction = deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(hash_type_byte(&t.vin[0].script_sig), 0x01);
}

#[test]
fn signrawtransaction_rejects_an_unknown_sighash_type() {
    let (server, _dir) = server();
    let key = SecretKey::new_random();
    let (tx, _, prevtxs) = two_in_one_out(&key);
    let unsigned = hex::encode(serialize(&tx));
    for bad in ["all", "ANYONECANPAY", "ALL|NONE", "", "SIGHASH_ALL"] {
        let r = call(
            &server,
            "signrawtransaction",
            vec![
                json!(unsigned),
                prevtxs.clone(),
                json!([wif(&key)]),
                json!(bad),
            ],
        );
        let e = r.error.unwrap_or_else(|| panic!("{bad:?} accepted"));
        assert_eq!(
            (e.code, e.message.as_str()),
            (-8, "Invalid sighash param"),
            "{bad:?}"
        );
    }
}

#[test]
fn signrawtransaction_wallet_keys_use_the_sighash_type_too() {
    let (server, _dir) = server();
    let own = ok(call(&server, "getnewaddress", vec![]));
    let spk_hex = ok(call(&server, "validateaddress", vec![own]))["scriptPubKey"]
        .as_str()
        .unwrap()
        .to_string();
    let spk = Script::from_bytes(hex::decode(&spk_hex).unwrap());
    let out = OutPoint::new(Hash256::from_bytes([0x43; 32]), 0);
    let mut tx = Transaction::new();
    tx.vin.push(TxIn::new(out, Script::new(), 0xffff_ffff));
    tx.vout.push(TxOut::new(
        Amount::from_sat(1_000),
        Script::new_p2pkh(&[6u8; 20]),
    ));
    let prevtxs = json!([{"txid": out.txid.to_string(), "vout": 0, "scriptPubKey": spk_hex}]);
    let r = ok(call(
        &server,
        "signrawtransaction",
        vec![
            json!(hex::encode(serialize(&tx))),
            prevtxs,
            Value::Null,
            json!("SINGLE|ANYONECANPAY"),
        ],
    ));
    let t: Transaction = deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(hash_type_byte(&t.vin[0].script_sig), 0x83);
    divi_script::verify_input(&t, 0, &spk, Amount::ZERO).expect("wallet key, SINGLE|ACP");
}
