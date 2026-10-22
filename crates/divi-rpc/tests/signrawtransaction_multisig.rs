// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! signrawtransaction co-signs a P2SH multisig input across two wallets, matches
//! prevtxs to inputs by outpoint, and signs P2PK inputs.

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
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

fn pubkey(server: &RpcServer) -> String {
    let addr = call(server, "getnewaddress", vec![]);
    let info = call(server, "validateaddress", vec![addr]);
    info["pubkey"].as_str().unwrap().to_string()
}

fn sign(server: &RpcServer, hex: &str, prevtxs: &Value) -> (String, bool) {
    let r = call(
        server,
        "signrawtransaction",
        vec![json!(hex), prevtxs.clone()],
    );
    (
        r["hex"].as_str().unwrap().to_string(),
        r["complete"].as_bool().unwrap(),
    )
}

#[test]
fn two_wallets_cosign_a_p2sh_multisig_input() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (node(&da), node(&db));
    let (pk_a, pk_b) = (pubkey(&a), pubkey(&b));
    let keys = json!([pk_a, pk_b]);

    // A stores the redeem script; B only learns it from prevtxs
    let ms_a = call(&a, "addmultisigaddress", vec![json!(2), keys.clone()]);
    let ms_b = call(&b, "createmultisig", vec![json!(2), keys]);
    assert_eq!(ms_a["address"], ms_b["address"]);
    let redeem = ms_b["redeemScript"].as_str().unwrap().to_string();
    let redeem_bytes = hex::decode(&redeem).unwrap();
    let p2sh = Script::new_p2sh(divi_crypto::hash160(&redeem_bytes).as_bytes());

    // Input 0: the multisig output. Input 1: a P2PK output to A's key.
    let pk_a_bytes = hex::decode(&pk_a).unwrap();
    let mut p2pk = vec![pk_a_bytes.len() as u8];
    p2pk.extend_from_slice(&pk_a_bytes);
    p2pk.push(0xac);
    let p2pk = Script::from_bytes(p2pk);
    let ms_out = OutPoint::new(Hash256::from_bytes([0x11; 32]), 1);
    let pk_out = OutPoint::new(Hash256::from_bytes([0x22; 32]), 0);
    let mut tx = Transaction::new();
    tx.vin.push(TxIn::new(ms_out, Script::new(), 0xffff_ffff));
    tx.vin.push(TxIn::new(pk_out, Script::new(), 0xffff_ffff));
    tx.vout.push(TxOut::new(
        Amount::from_sat(9_000_000),
        Script::new_p2pkh(&[5u8; 20]),
    ));
    let unsigned = hex::encode(serialize(&tx));

    // prevtxs deliberately in the opposite order of the inputs
    let prevtxs = json!([
        {"txid": pk_out.txid.to_string(), "vout": 0, "scriptPubKey": hex::encode(p2pk.as_bytes())},
        {"txid": ms_out.txid.to_string(), "vout": 1, "scriptPubKey": hex::encode(p2sh.as_bytes()),
         "redeemScript": redeem},
    ]);

    let (half, complete) = sign(&a, &unsigned, &prevtxs);
    assert!(
        !complete,
        "one of two multisig signatures must not be complete"
    );
    assert_ne!(half, unsigned, "A added nothing");

    let (full, complete) = sign(&b, &half, &prevtxs);
    assert!(
        complete,
        "A's and B's signatures together must complete the tx"
    );

    // The other order gives an equally valid transaction
    let (half_b, complete) = sign(&b, &unsigned, &prevtxs);
    assert!(!complete);
    let (full2, complete) = sign(&a, &half_b, &prevtxs);
    assert!(complete);

    for hex_tx in [&full, &full2] {
        let signed: Transaction = deserialize(&hex::decode(hex_tx).unwrap()).unwrap();
        divi_script::verify_input(&signed, 0, &p2sh, Amount::ZERO).expect("multisig input");
        divi_script::verify_input(&signed, 1, &p2pk, Amount::ZERO).expect("P2PK input");
    }

    // Re-signing a complete transaction keeps it complete
    let (again, complete) = sign(&b, &full, &prevtxs);
    assert!(complete);
    assert_eq!(again, full);
}
