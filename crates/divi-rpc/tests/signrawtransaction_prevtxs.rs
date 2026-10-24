// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! signrawtransaction reads its prevtxs as Divi Core does
//! (rpcrawtransaction.cpp:712-754): RPCTypeCheck of txid, vout and scriptPubKey
//! ("Missing <name>", "Expected type <type> for <name>, got <type>"),
//! ParseHashO/ParseHexO texts, "vout must be positive", a scriptPubKey that is
//! not the one of a coin the node holds refused with both scripts, and a P2SH
//! output's redeemScript required, and used, only with given keys.

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType, Utxo};
use divi_wallet::{HdWallet, Network, WalletDb};
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
fn prevtxs_are_read_as_divid_reads_them() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            Arc::clone(&db),
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain, wallet);

    // A coin the chain holds, to a pay-to-key-hash script
    let held = OutPoint::new(Hash256::from_bytes([0x31; 32]), 0);
    let p2pkh = Script::new_p2pkh(&[0x41; 20]);
    db.add_utxo(
        &held,
        &Utxo::new(Amount::from_sat(100_000), p2pkh.clone(), 1, false, false),
    )
    .unwrap();
    let txid = held.txid.to_string();
    let raw = call(
        &server,
        "createrawtransaction",
        vec![json!([{"txid": txid, "vout": 0}]), json!({})],
    )
    .unwrap();
    let address = call(&server, "getnewaddress", vec![]).unwrap();
    let key = call(&server, "dumpprivkey", vec![address]).unwrap();
    let p2sh_hex = hex::encode(Script::new_p2sh(&[0x42; 20]).as_bytes());
    let p2pkh_hex = hex::encode(p2pkh.as_bytes());
    let sign = |prevtx: Value, keys: Value| {
        call(
            &server,
            "signrawtransaction",
            vec![raw.clone(), json!([prevtx]), keys],
        )
    };
    let text = |code: i32, s: &str| Err((code, s.to_string()));

    assert_eq!(
        sign(json!({"txid": txid, "vout": 0}), Value::Null),
        text(-3, "Missing scriptPubKey")
    );
    assert_eq!(
        sign(
            json!({"txid": txid, "vout": "0", "scriptPubKey": p2pkh_hex}),
            Value::Null
        ),
        text(-3, "Expected type int for vout, got str")
    );
    assert_eq!(
        sign(
            json!({"txid": "xyz", "vout": 0, "scriptPubKey": p2pkh_hex}),
            Value::Null
        ),
        text(-8, "txid must be hexadecimal string (not 'xyz')")
    );
    assert_eq!(
        sign(
            json!({"txid": txid, "vout": -1, "scriptPubKey": p2pkh_hex}),
            Value::Null
        ),
        text(-22, "vout must be positive")
    );
    assert_eq!(
        sign(
            json!({"txid": txid, "vout": 0, "scriptPubKey": "xyz"}),
            Value::Null
        ),
        text(-8, "scriptPubKey must be hexadecimal string (not 'xyz')")
    );
    assert_eq!(
        sign(json!({"txid": txid, "vout": 0, "scriptPubKey": p2sh_hex}), Value::Null),
        text(
            -22,
            &format!(
                "Previous output scriptPubKey mismatch:\nOP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG\nvs:\nOP_HASH160 {} OP_EQUAL",
                "41".repeat(20),
                "42".repeat(20)
            )
        )
    );

    // A P2SH output nobody holds: the redeemScript is needed with given keys only
    let other = Hash256::from_bytes([0x32; 32]).to_string();
    let p2sh_prevtx = json!({"txid": other, "vout": 0, "scriptPubKey": p2sh_hex});
    assert_eq!(
        sign(p2sh_prevtx.clone(), json!([key])),
        text(-3, "Missing redeemScript")
    );
    let unsigned = sign(p2sh_prevtx, Value::Null).unwrap();
    assert_eq!(unsigned["complete"], json!(false), "{unsigned}");
}
