// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Addresses and keys the RPC prints use the node's network, not mainnet's.

use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{encode_wif, Address, Network};
use serde_json::{json, Value};
use std::sync::Arc;

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

#[test]
fn rpc_addresses_use_the_node_network() {
    // A regtest node without a wallet
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let server = RpcServer::new(Arc::new(Chain::new(db, params).unwrap()));
    let net = Network::Regtest;

    // decoderawtransaction (same decoder as getrawtransaction 1 and getblock 2)
    let mut tx = Transaction::new();
    tx.vin.push(TxIn::new(
        OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
        Script::new(),
        0xffff_ffff,
    ));
    tx.vout.push(TxOut::new(
        Amount::from_sat(1),
        Script::new_p2pkh(&[9u8; 20]),
    ));
    tx.vout.push(TxOut::new(
        Amount::from_sat(1),
        Script::new_p2sh(&[8u8; 20]),
    ));
    let decoded = call(
        &server,
        "decoderawtransaction",
        vec![json!(hex::encode(serialize(&tx)))],
    );
    assert_eq!(
        decoded["vout"][0]["scriptPubKey"]["addresses"][0],
        json!(Address::from_pubkey_hash(Hash160::from_bytes([9u8; 20]), net).to_base58())
    );
    assert_eq!(
        decoded["vout"][1]["scriptPubKey"]["addresses"][0],
        json!(Address::p2sh(Hash160::from_bytes([8u8; 20]), net).to_base58())
    );

    // createmultisig
    let pubkey = hex::encode(SecretKey::new_random().public_key().to_bytes());
    let ms = call(&server, "createmultisig", vec![json!(1), json!([pubkey])]);
    let redeem = hex::decode(ms["redeemScript"].as_str().unwrap()).unwrap();
    assert_eq!(
        ms["address"],
        json!(Address::p2sh(divi_crypto::hash160(&redeem), net).to_base58())
    );

    // bip38decrypt returns the key as WIF for the node's network
    let key = [7u8; 32];
    let encrypted = divi_crypto::bip38_encrypt(&key, "pw", true).unwrap();
    let r = call(&server, "bip38decrypt", vec![json!(encrypted), json!("pw")]);
    assert_eq!(r, json!(encode_wif(&key, true, net)));
}
