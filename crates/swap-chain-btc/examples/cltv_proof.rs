// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Wave 0.4: live P2WSH HTLC claim + CLTV refund on BTC signet with rust-bitcoin and the
//! mempool.space Esplora API, each spend checked by libbitcoinconsensus before broadcast.
//!
//! ```sh
//! export SWAP_KEY_REF="op://global_secret_store/IronDivi Swap POC - taker-btc/password"
//! cargo run -p swap-chain-btc --example cltv_proof -- address
//! cargo run -p swap-chain-btc --example cltv_proof -- fund <state.json>   # uses key's UTXOs
//! cargo run -p swap-chain-btc --example cltv_proof -- claim <state.json>
//! cargo run -p swap-chain-btc --example cltv_proof -- refund <state.json> # after locktime
//! ```

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize;
use bitcoin::ecdsa::Signature;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use divi_swap::htlc::{new_preimage, HtlcParams, REFUND_SEQUENCE};
use divi_swap::secrets::SecretRef;
use serde_json::{json, Value};
use std::str::FromStr;

const API: &str = "https://mempool.space/signet/api";
const FEE: u64 = 1_000; // sats; ~5 sat/vB for these sizes
const HTLC_VALUE: u64 = 20_000;
/// Signet MTP lags wall clock ~1 h; 2 h ahead of MTP keeps the refund honest (plan 0.4).
const REFUND_AHEAD_OF_MTP: u32 = 2 * 3600;

async fn get(path: &str) -> String {
    reqwest::get(format!("{API}{path}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

async fn mtp() -> u32 {
    let tip = get("/blocks/tip/hash").await;
    let b: Value = serde_json::from_str(&get(&format!("/block/{tip}")).await).unwrap();
    b["mediantime"].as_u64().unwrap() as u32
}

async fn broadcast(tx: &Transaction) -> Result<String, String> {
    let resp = reqwest::Client::new()
        .post(format!("{API}/tx"))
        .body(hex::encode(serialize(tx)))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let ok = resp.status().is_success();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if ok {
        Ok(text)
    } else {
        Err(text)
    }
}

fn htlc_spk(p: &HtlcParams) -> ScriptBuf {
    ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(p.redeem_script()).wscript_hash())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let secp = Secp256k1::new();
    let r = std::env::var("SWAP_KEY_REF").expect("SWAP_KEY_REF=op://…");
    let sk_hex = SecretRef::parse(&r)
        .unwrap()
        .resolve()
        .expect("resolve key");
    let sk = SecretKey::from_str(&sk_hex).expect("key hex");
    let pk = CompressedPublicKey(sk.public_key(&secp));
    let addr = Address::p2wpkh(&pk, Network::Signet);
    let my_spk = addr.script_pubkey();
    eprintln!("key address {addr}  mtp {}", mtp().await);
    let sign = |tx: &Transaction, idx: usize, code: &ScriptBuf, amt: u64, wsh: bool| {
        let mut cache = SighashCache::new(tx);
        let h = if wsh {
            cache
                .p2wsh_signature_hash(idx, code, Amount::from_sat(amt), EcdsaSighashType::All)
                .unwrap()
        } else {
            cache
                .p2wpkh_signature_hash(idx, code, Amount::from_sat(amt), EcdsaSighashType::All)
                .unwrap()
        };
        let sig = secp.sign_ecdsa(&Message::from_digest(h.to_byte_array()), &sk);
        Signature::sighash_all(sig).to_vec()
    };
    use bitcoin::hashes::Hash;
    match cmd {
        "address" => println!("{addr}"),
        "fund" => {
            let path = &args[2];
            let utxos: Value =
                serde_json::from_str(&get(&format!("/address/{addr}/utxo")).await).unwrap();
            let u = utxos
                .as_array()
                .unwrap()
                .iter()
                .max_by_key(|u| u["value"].as_u64())
                .expect("no UTXOs on key address");
            let value = u["value"].as_u64().unwrap();
            let mypk = pk.to_bytes();
            let (pre_a, hash_a) = new_preimage();
            let (_, hash_b) = new_preimage();
            let m = mtp().await;
            let a = HtlcParams {
                hash: hash_a,
                claim_pubkey: mypk,
                refund_pubkey: mypk,
                locktime: m + 86_400,
            };
            let b = HtlcParams {
                hash: hash_b,
                claim_pubkey: mypk,
                refund_pubkey: mypk,
                locktime: m + REFUND_AHEAD_OF_MTP,
            };
            let change = value - 2 * HTLC_VALUE - FEE;
            let mut tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(
                        Txid::from_str(u["txid"].as_str().unwrap()).unwrap(),
                        u["vout"].as_u64().unwrap() as u32,
                    ),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(HTLC_VALUE),
                        script_pubkey: htlc_spk(&a),
                    },
                    TxOut {
                        value: Amount::from_sat(HTLC_VALUE),
                        script_pubkey: htlc_spk(&b),
                    },
                    TxOut {
                        value: Amount::from_sat(change),
                        script_pubkey: my_spk.clone(),
                    },
                ],
            };
            let sig = sign(&tx, 0, &my_spk, value, false);
            tx.input[0].witness = Witness::from_slice(&[sig, mypk.to_vec()]);
            bitcoin::consensus::verify_script(&my_spk, 0, Amount::from_sat(value), &serialize(&tx))
                .expect("consensus verify fund");
            let txid = broadcast(&tx).await.expect("broadcast fund");
            println!("fund txid {txid}");
            for (n, p) in [("A", &a), ("B", &b)] {
                let s = ScriptBuf::from_bytes(p.redeem_script());
                eprintln!("HTLC {n}: {}", Address::p2wsh(&s, Network::Signet));
            }
            let state = json!({
                "fund_txid": txid,
                "A": {"params": a, "vout": 0, "preimage": hex::encode(pre_a)},
                "B": {"params": b, "vout": 1},
            });
            std::fs::write(path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
        }
        "claim" | "refund" => {
            let state: Value =
                serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
            let which = if cmd == "claim" { "A" } else { "B" };
            let p: HtlcParams = serde_json::from_value(state[which]["params"].clone()).unwrap();
            let ws = ScriptBuf::from_bytes(p.redeem_script());
            let refund = cmd == "refund";
            let mut tx = Transaction {
                version: Version::TWO,
                lock_time: if refund {
                    LockTime::from_time(p.locktime).unwrap()
                } else {
                    LockTime::ZERO
                },
                input: vec![TxIn {
                    previous_output: OutPoint::new(
                        Txid::from_str(state["fund_txid"].as_str().unwrap()).unwrap(),
                        state[which]["vout"].as_u64().unwrap() as u32,
                    ),
                    script_sig: ScriptBuf::new(),
                    sequence: if refund {
                        Sequence(REFUND_SEQUENCE)
                    } else {
                        Sequence::MAX
                    },
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(HTLC_VALUE - FEE),
                    script_pubkey: my_spk.clone(),
                }],
            };
            let sig = sign(&tx, 0, &ws, HTLC_VALUE, true);
            tx.input[0].witness = if refund {
                Witness::from_slice(&[sig, vec![], ws.to_bytes()])
            } else {
                let pre = hex::decode(state["A"]["preimage"].as_str().unwrap()).unwrap();
                Witness::from_slice(&[sig, pre, vec![1], ws.to_bytes()])
            };
            bitcoin::consensus::verify_script(
                &htlc_spk(&p),
                0,
                Amount::from_sat(HTLC_VALUE),
                &serialize(&tx),
            )
            .unwrap_or_else(|e| panic!("consensus verify {cmd}: {e:?}"));
            eprintln!(
                "{cmd}: locktime {} txid {}",
                tx.lock_time,
                tx.compute_txid()
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
            eprintln!("usage: cltv_proof address | fund <state> | claim <state> | refund <state>");
            std::process::exit(2);
        }
    }
}
