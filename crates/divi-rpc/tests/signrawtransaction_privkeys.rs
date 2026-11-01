// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! signrawtransaction with privkeys signs only with those keys, as Divi Core does.

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

#[test]
fn signrawtransaction_signs_with_given_privkeys_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain, wallet);

    // Two keys the wallet does not hold
    let (k1, k2) = (SecretKey::new_random(), SecretKey::new_random());
    let wif = |k: &SecretKey| {
        let mut b = [0u8; 32];
        b.copy_from_slice(k.as_bytes());
        encode_wif(&b, true, Network::Regtest)
    };
    let (pk1, pk2) = (k1.public_key().to_bytes(), k2.public_key().to_bytes());
    let p2pkh = Script::new_p2pkh(divi_crypto::hash160(&pk1).as_bytes());
    let ms = ok(call(
        &server,
        "createmultisig",
        vec![json!(2), json!([hex::encode(&pk1), hex::encode(&pk2)])],
    ));
    let redeem = ms["redeemScript"].as_str().unwrap().to_string();
    let p2sh = Script::new_p2sh(divi_crypto::hash160(&hex::decode(&redeem).unwrap()).as_bytes());

    // Input 0: P2PKH to k1. Input 1: 2-of-2 P2SH of k1, k2. Input 2: the wallet's own key.
    let own = ok(call(&server, "getnewaddress", vec![]));
    let own_spk = ok(call(&server, "validateaddress", vec![own]))["scriptPubKey"]
        .as_str()
        .unwrap()
        .to_string();
    let outs = [
        OutPoint::new(Hash256::from_bytes([0x31; 32]), 0),
        OutPoint::new(Hash256::from_bytes([0x32; 32]), 1),
        OutPoint::new(Hash256::from_bytes([0x33; 32]), 2),
    ];
    let mut tx = Transaction::new();
    for o in outs {
        tx.vin.push(TxIn::new(o, Script::new(), 0xffff_ffff));
    }
    tx.vout.push(TxOut::new(
        Amount::from_sat(1_000_000),
        Script::new_p2pkh(&[6u8; 20]),
    ));
    let unsigned = hex::encode(serialize(&tx));
    let prevtxs = json!([
        {"txid": outs[0].txid.to_string(), "vout": 0, "scriptPubKey": hex::encode(p2pkh.as_bytes())},
        {"txid": outs[1].txid.to_string(), "vout": 1, "scriptPubKey": hex::encode(p2sh.as_bytes()),
         "redeemScript": redeem},
        {"txid": outs[2].txid.to_string(), "vout": 2, "scriptPubKey": own_spk},
    ]);
    let sign = |hex_tx: &str, keys: Value| {
        let r = ok(call(
            &server,
            "signrawtransaction",
            vec![json!(hex_tx), prevtxs.clone(), keys],
        ));
        let signed: Transaction =
            deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap();
        (r["hex"].as_str().unwrap().to_string(), signed)
    };

    // k1 alone: the P2PKH input verifies, the multisig is half done, the wallet's
    // own input is NOT signed (given keys replace the wallet)
    let (half, t) = sign(&unsigned, json!([wif(&k1)]));
    divi_script::verify_input(&t, 0, &p2pkh, Amount::ZERO).expect("P2PKH signed with k1");
    assert!(divi_script::verify_input(&t, 1, &p2sh, Amount::ZERO).is_err());
    assert!(
        t.vin[2].script_sig.is_empty(),
        "wallet key used despite privkeys"
    );

    // k2 adds the second multisig signature
    let (_, t) = sign(&half, json!([wif(&k2)]));
    divi_script::verify_input(&t, 0, &p2pkh, Amount::ZERO).expect("P2PKH kept");
    divi_script::verify_input(&t, 1, &p2sh, Amount::ZERO).expect("2-of-2 complete");

    // A bad key is -5
    let r = call(
        &server,
        "signrawtransaction",
        vec![json!(unsigned), prevtxs.clone(), json!(["notakey"])],
    );
    assert_eq!(r.error.map(|e| e.code), Some(-5));
}
