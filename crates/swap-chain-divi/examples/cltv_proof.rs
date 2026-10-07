// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Wave 0.3 go/no-go: live HTLC claim + CLTV refund on Divi testnet, built and signed with
//! IronDivi crates and verified by IronDivi's interpreter before every broadcast.
//!
//! ```sh
//! export SWAP_KEY_REF="op://global_secret_store/IronDivi Swap POC - maker-divi/password"
//! cargo run -p swap-chain-divi --example cltv_proof -- fund <funding_txid> <state.json>
//! cargo run -p swap-chain-divi --example cltv_proof -- claim  <state.json>
//! cargo run -p swap-chain-divi --example cltv_proof -- refund <state.json>   # after locktime
//! ```
//! `<funding_txid>` is a tx paying the key's testnet P2PKH address (no address index on the
//! proxy, so the txid is passed in). The state file holds only public data plus the
//! proof's throwaway preimage; keep it outside the git tree.

use divi_crypto::keys::SecretKey;
use divi_crypto::signature::sign_hash;
use divi_primitives::amount::Amount;
use divi_primitives::constants::SEQUENCE_FINAL;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::{verify_input, SigHashType};
use divi_swap::htlc::{
    claim_script_sig, new_preimage, refund_script_sig, HtlcParams, REFUND_SEQUENCE,
};
use divi_swap::secrets::SecretRef;
use divi_wallet::address::{Address, Network};
use divi_wallet::signer::sighash;
use serde_json::{json, Value};

const RPC: &str = "https://services.divi.domains/api/testnet/rpc/";
const FEE: i64 = 1_000_000; // 0.01 tDIVI, generous
const HTLC_VALUE: i64 = 100 * 100_000_000; // 100 tDIVI each
const REFUND_DELAY_SECS: u32 = 600;

async fn rpc(method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params});
    let resp: Value = reqwest::Client::new()
        .post(RPC)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    if !resp["error"].is_null() {
        return Err(format!("{method}: {}", resp["error"]));
    }
    Ok(resp["result"].clone())
}

fn key() -> SecretKey {
    let r = std::env::var("SWAP_KEY_REF").expect("SWAP_KEY_REF=op://…");
    let hex = SecretRef::parse(&r)
        .unwrap()
        .resolve()
        .expect("resolve key");
    SecretKey::from_hex(&hex).expect("key hex")
}

fn p2sh_of(redeem: &[u8]) -> Script {
    Script::new_p2sh(divi_crypto::hash::hash160(redeem).as_bytes())
}

fn sign(tx: &Transaction, idx: usize, script_code: &Script, sk: &SecretKey) -> Vec<u8> {
    let h = sighash(tx, idx, script_code, SigHashType::All, false).unwrap();
    let mut sig = sign_hash(sk, h.as_bytes()).unwrap().to_der();
    sig.push(SigHashType::All as u8);
    sig
}

async fn mtp() -> u32 {
    let tip = rpc("getblockcount", json!([])).await.unwrap();
    let hash = rpc("getblockhash", json!([tip])).await.unwrap();
    let hdr = rpc("getblock", json!([hash])).await.unwrap();
    hdr["mediantime"]
        .as_u64()
        .or_else(|| hdr["time"].as_u64())
        .unwrap() as u32
}

async fn broadcast(tx: &Transaction) -> Result<String, String> {
    rpc("sendrawtransaction", json!([hex::encode(serialize(tx))]))
        .await
        .map(|v| v.as_str().unwrap_or_default().to_string())
}

fn htlc_from(state: &Value, which: &str) -> HtlcParams {
    serde_json::from_value(state[which]["params"].clone()).unwrap()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let sk = key();
    let pk = sk.public_key();
    let my_spk = Script::new_p2pkh(pk.pubkey_hash().as_bytes());
    let my_addr = Address::p2pkh(&pk, Network::Testnet);
    eprintln!("key address {my_addr}  mtp {}", mtp().await);
    match cmd {
        "fund" => {
            let fund_txid = &args[2];
            let path = &args[3];
            let prev = rpc("getrawtransaction", json!([fund_txid, 1]))
                .await
                .unwrap();
            let (vout, value) = prev["vout"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(my_spk.to_hex().as_str()))
                .map(|o| {
                    let sat = (o["value"].as_f64().unwrap() * 1e8).round() as i64;
                    (o["n"].as_u64().unwrap() as u32, sat)
                })
                .expect("funding tx does not pay the key");
            let (pre_a, hash_a) = new_preimage();
            let (_, hash_b) = new_preimage();
            let mypk: [u8; 33] = pk.serialize_compressed();
            let a = HtlcParams {
                hash: hash_a,
                claim_pubkey: mypk,
                refund_pubkey: mypk,
                locktime: mtp().await + 86_400,
            };
            let b = HtlcParams {
                hash: hash_b,
                claim_pubkey: mypk,
                refund_pubkey: mypk,
                locktime: (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32)
                    + REFUND_DELAY_SECS,
            };
            let (ra, rb) = (a.redeem_script(), b.redeem_script());
            for (n, r) in [("A", &ra), ("B", &rb)] {
                let dec = rpc("decodescript", json!([hex::encode(r)])).await;
                let ours = Address::p2sh(divi_crypto::hash::hash160(r), Network::Testnet);
                eprintln!(
                    "HTLC {n}: ours {ours}  node {:?}",
                    dec.map(|d| d["p2sh"].clone())
                );
            }
            let mut tx = Transaction::new();
            tx.vin.push(TxIn::new(
                OutPoint::new(Hash256::from_hex(fund_txid).unwrap(), vout),
                Script::new(),
                SEQUENCE_FINAL,
            ));
            tx.vout
                .push(TxOut::new(Amount::from_sat(HTLC_VALUE), p2sh_of(&ra)));
            tx.vout
                .push(TxOut::new(Amount::from_sat(HTLC_VALUE), p2sh_of(&rb)));
            let change = value - 2 * HTLC_VALUE - FEE;
            assert!(change > 0, "funding too small");
            tx.vout
                .push(TxOut::new(Amount::from_sat(change), my_spk.clone()));
            let sig = sign(&tx, 0, &my_spk, &sk);
            let mut ss = Vec::new();
            divi_swap::htlc::push_data(&mut ss, &sig);
            divi_swap::htlc::push_data(&mut ss, &mypk);
            tx.vin[0].script_sig = Script::from_bytes(ss);
            verify_input(&tx, 0, &my_spk, Amount::from_sat(value)).expect("local verify fund");
            let txid = broadcast(&tx).await.expect("broadcast fund");
            println!("fund txid {txid}");
            let state = json!({
                "fund_txid": txid,
                "A": {"params": a, "vout": 0, "preimage": hex::encode(pre_a)},
                "B": {"params": b, "vout": 1},
            });
            std::fs::write(path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
        }
        "claim" | "refund" | "refund-early" => {
            let path = &args[2];
            let state: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let which = if cmd == "claim" { "A" } else { "B" };
            let p = htlc_from(&state, which);
            let redeem = p.redeem_script();
            let spk = p2sh_of(&redeem);
            let outpoint = OutPoint::new(
                Hash256::from_hex(state["fund_txid"].as_str().unwrap()).unwrap(),
                state[which]["vout"].as_u64().unwrap() as u32,
            );
            let mut tx = Transaction::new();
            let refund = cmd != "claim";
            tx.vin.push(TxIn::new(
                outpoint,
                Script::new(),
                if refund {
                    REFUND_SEQUENCE
                } else {
                    SEQUENCE_FINAL
                },
            ));
            tx.vout.push(TxOut::new(
                Amount::from_sat(HTLC_VALUE - FEE),
                my_spk.clone(),
            ));
            if refund {
                tx.lock_time = p.locktime;
            }
            let sig = sign(&tx, 0, &Script::from_bytes(redeem.clone()), &sk);
            tx.vin[0].script_sig = Script::from_bytes(if refund {
                refund_script_sig(&sig, &redeem)
            } else {
                let pre: [u8; 32] = hex::decode(state["A"]["preimage"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                claim_script_sig(&sig, &pre, &redeem)
            });
            verify_input(&tx, 0, &spk, Amount::from_sat(HTLC_VALUE))
                .unwrap_or_else(|e| panic!("local verify {cmd}: {e:?}"));
            let raw = hex::encode(serialize(&tx));
            let _: Transaction = deserialize(&hex::decode(&raw).unwrap()).unwrap();
            eprintln!(
                "{cmd}: locktime {} txid {}",
                tx.lock_time,
                tx.txid().to_hex()
            );
            match broadcast(&tx).await {
                Ok(txid) => println!("{cmd} txid {txid}"),
                Err(e) => {
                    println!("{cmd} rejected: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: cltv_proof fund <txid> <state> | claim <state> | refund <state>");
            std::process::exit(2);
        }
    }
}
