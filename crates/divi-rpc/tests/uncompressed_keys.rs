// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A WIF without the compression flag is an uncompressed key, as in Divi Core:
//! its address is hash160 of the 65-byte public key and it signs with that
//! public key. Used to be treated as compressed everywhere, so such a key could
//! not spend its own outputs, sign or verify messages for its address, and
//! importprivkey / dumpprivkey changed which address it controls.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{encode_wif, Address, HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::path::Path;
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

fn chain(dir: &Path) -> Arc<Chain> {
    let db = Arc::new(ChainDatabase::open(dir).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    Arc::new(Chain::new(db, params).unwrap())
}

fn memory_server(dir: &Path) -> RpcServer {
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    RpcServer::with_wallet(chain(dir), wallet)
}

struct Key {
    wif: String,
    uncompressed_pubkey: Vec<u8>,
    address: String,
    compressed_address: String,
    script_pubkey: Script,
}

fn uncompressed_key() -> (SecretKey, Key) {
    let secret = SecretKey::new_random();
    let mut b = [0u8; 32];
    b.copy_from_slice(secret.as_bytes());
    let pubkey = secret.public_key().serialize_uncompressed().to_vec();
    let hash = divi_crypto::hash160(&pubkey);
    let key = Key {
        wif: encode_wif(&b, false, Network::Regtest),
        address: Address::from_pubkey_hash(hash, Network::Regtest).to_base58(),
        compressed_address: Address::p2pkh(&secret.public_key(), Network::Regtest).to_base58(),
        script_pubkey: Script::new_p2pkh(hash.as_bytes()),
        uncompressed_pubkey: pubkey,
    };
    (secret, key)
}

fn spend_of(spk: &Script) -> (String, Value) {
    let out = OutPoint::new(Hash256::from_bytes([0x51; 32]), 0);
    let mut tx = Transaction::new();
    tx.vin.push(TxIn::new(out, Script::new(), 0xffff_ffff));
    tx.vout.push(TxOut::new(
        Amount::from_sat(1_000),
        Script::new_p2pkh(&[6u8; 20]),
    ));
    let prevtxs = json!([{"txid": out.txid.to_string(), "vout": 0,
                          "scriptPubKey": hex::encode(spk.as_bytes())}]);
    (hex::encode(serialize(&tx)), prevtxs)
}

/// The public key pushed by a P2PKH scriptSig
fn pushed_pubkey(script_sig: &Script) -> Vec<u8> {
    let b = script_sig.as_bytes();
    let sig_len = b[0] as usize;
    let pk_len = b[1 + sig_len] as usize;
    b[2 + sig_len..2 + sig_len + pk_len].to_vec()
}

#[test]
fn signrawtransaction_signs_with_an_uncompressed_wif() {
    let dir = tempfile::tempdir().unwrap();
    let server = memory_server(dir.path());
    let (_, key) = uncompressed_key();
    let (unsigned, prevtxs) = spend_of(&key.script_pubkey);

    let r = ok(call(
        &server,
        "signrawtransaction",
        vec![json!(unsigned), prevtxs, json!([key.wif])],
    ));
    let t: Transaction = deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap();
    assert!(
        !t.vin[0].script_sig.is_empty(),
        "uncompressed key did not sign"
    );
    assert_eq!(pushed_pubkey(&t.vin[0].script_sig), key.uncompressed_pubkey);
    divi_script::verify_input(&t, 0, &key.script_pubkey, Amount::ZERO)
        .expect("spend of an uncompressed-key output verifies");
    assert_eq!(r["complete"], json!(true));
}

#[test]
fn imported_uncompressed_key_controls_its_own_address() {
    let dir = tempfile::tempdir().unwrap();
    let server = memory_server(dir.path());
    let (_, key) = uncompressed_key();

    ok(call(
        &server,
        "importprivkey",
        vec![json!(key.wif), json!("old")],
    ));

    let v = ok(call(&server, "validateaddress", vec![json!(key.address)]));
    assert_eq!(v["ismine"], json!(true), "{v}");
    assert_eq!(v["iscompressed"], json!(false), "{v}");
    assert_eq!(v["pubkey"], json!(hex::encode(&key.uncompressed_pubkey)));
    // Divi Core: the compressed form of the key is a different address, not ours
    let c = ok(call(
        &server,
        "validateaddress",
        vec![json!(key.compressed_address)],
    ));
    assert_eq!(c["ismine"], json!(false), "{c}");

    // dumpprivkey gives back the same, uncompressed, WIF
    assert_eq!(
        ok(call(&server, "dumpprivkey", vec![json!(key.address)])),
        json!(key.wif)
    );

    // BIP38 keeps the key's form: decrypting gives the uncompressed key, whose
    // address the wallet already holds (bip38decrypt adds the key as Divi Core
    // does, rpcdump.cpp:331-337, so it refuses it here)
    let enc = ok(call(
        &server,
        "bip38encrypt",
        vec![json!(key.address), json!("test only pass")],
    ));
    let r = call(&server, "bip38decrypt", vec![enc, json!("test only pass")]);
    let e = r.error.expect("key already held");
    assert_eq!(
        (e.code, e.message.as_str()),
        (-4, "Key already held by wallet")
    );

    // The wallet signs spends of the address with its uncompressed public key
    let (unsigned, prevtxs) = spend_of(&key.script_pubkey);
    let r = ok(call(
        &server,
        "signrawtransaction",
        vec![json!(unsigned), prevtxs],
    ));
    let t: Transaction = deserialize(&hex::decode(r["hex"].as_str().unwrap()).unwrap()).unwrap();
    divi_script::verify_input(&t, 0, &key.script_pubkey, Amount::ZERO)
        .expect("wallet signs for its uncompressed key");

    // signmessage marks the signature uncompressed (header 27..30) and it verifies
    let sig = ok(call(
        &server,
        "signmessage",
        vec![json!(key.address), json!("hello")],
    ));
    let raw = STANDARD.decode(sig.as_str().unwrap()).unwrap();
    assert!((27..=30).contains(&raw[0]), "header {}", raw[0]);
    assert_eq!(
        ok(call(
            &server,
            "verifymessage",
            vec![json!(key.address), sig, json!("hello")]
        )),
        json!(true)
    );
}

#[test]
fn verifymessage_accepts_a_signature_by_an_uncompressed_key() {
    // As Divi Core makes them for an uncompressed key: header 27 + recid
    let dir = tempfile::tempdir().unwrap();
    let server = memory_server(dir.path());
    let (secret, key) = uncompressed_key();
    let hash = divi_rpc::wallet::message_magic_hash(b"core message");
    let rsig = divi_crypto::sign_hash_recoverable(&secret, &hash).unwrap();
    let b64 = |b: &[u8]| STANDARD.encode(b);

    let uncompressed = b64(&rsig.to_compact_with_recovery_uncompressed());
    let compressed = b64(&rsig.to_compact_with_recovery());
    let verify = |addr: &str, sig: &str| {
        ok(call(
            &server,
            "verifymessage",
            vec![json!(addr), json!(sig), json!("core message")],
        ))
    };
    assert_eq!(verify(&key.address, &uncompressed), json!(true));
    assert_eq!(verify(&key.compressed_address, &compressed), json!(true));
    // The header says which form of the key signed
    assert_eq!(verify(&key.address, &compressed), json!(false));
    assert_eq!(verify(&key.compressed_address, &uncompressed), json!(false));
}

#[test]
fn imported_uncompressed_key_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = dir.path().join("wallet");
    let (_, key) = uncompressed_key();
    {
        let wallet = WalletDb::create_persistent(
            &wallet_dir,
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap();
        let server = RpcServer::with_wallet(chain(&dir.path().join("c1")), Arc::new(wallet));
        ok(call(&server, "importprivkey", vec![json!(key.wif)]));
        // Encrypting rewrites every key with its secret held apart
        ok(call(
            &server,
            "encryptwallet",
            vec![json!("test only pass")],
        ));
    }
    let wallet = WalletDb::open(&wallet_dir, Network::Regtest).unwrap();
    let server = RpcServer::with_wallet(chain(&dir.path().join("c2")), Arc::new(wallet));
    ok(call(
        &server,
        "walletpassphrase",
        vec![json!("test only pass"), json!(60)],
    ));
    let v = ok(call(&server, "validateaddress", vec![json!(key.address)]));
    assert_eq!(v["ismine"], json!(true), "{v}");
    assert_eq!(v["iscompressed"], json!(false), "{v}");
    assert_eq!(
        ok(call(&server, "dumpprivkey", vec![json!(key.address)])),
        json!(key.wif)
    );
}

#[test]
fn createmultisig_keeps_an_uncompressed_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let server = memory_server(dir.path());
    let (_, key) = uncompressed_key();
    let hexkey = hex::encode(&key.uncompressed_pubkey);
    let r = ok(call(
        &server,
        "createmultisig",
        vec![json!(1), json!([hexkey])],
    ));
    // Divi Core: OP_1 <65-byte key> OP_1 OP_CHECKMULTISIG
    assert_eq!(r["redeemScript"], json!(format!("5141{hexkey}51ae")));

    // The same through a wallet address of an imported uncompressed key
    ok(call(&server, "importprivkey", vec![json!(key.wif)]));
    let r2 = ok(call(
        &server,
        "createmultisig",
        vec![json!(1), json!([key.address])],
    ));
    assert_eq!(r2["redeemScript"], r["redeemScript"]);
    let r3 = ok(call(
        &server,
        "addmultisigaddress",
        vec![json!(1), json!([key.address])],
    ));
    // Divi Core answers the address alone
    assert_eq!(r3, r["address"]);
}
