// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live redeem with the **business roles swapped** (`xmr-design.md`'s `## Protocol`
//! `### Roles`, updated 2026-10-12): `examples/xmr_live.rs` already proved the "sell
//! XMR" direction (business-taker locks XMR, business-maker locks DIVI first). A
//! market also needs "buy XMR" -- business-taker locks DIVI **first** (crypto-Maker
//! role: encrypts `Tx_redeem`, ends up sweeping the Monero), business-maker locks XMR
//! (crypto-Taker role: completes `Tx_redeem` with `s_t`, ends up with the DIVI). The
//! protocol itself is identical either way -- this binary calls the exact same
//! `swap_templates`/`multisig` functions `xmr_live.rs` does, just with the business
//! party in each crypto-role slot swapped, to demonstrate on real chains that nothing
//! in `swap-chain-xmr` hardcodes which business party plays which role. See
//! `role_swap_e2e.rs` for the offline version of this same claim.
//!
//! Funding: `Tx_lock` (business-taker's leg, since she locks DIVI first) spends the
//! live punish-path run's own reclaimed DIVI (`examples/xmr_live_punish.rs`'s
//! `Tx_punish` output 0, paid to that round's Taker) -- no new tDIVI needed. The
//! Monero lock (business-maker's leg) is funded the same way every round's has been:
//! a manual `monero-wallet-rpc transfer` from `mining-wallet`, its resulting txid
//! recorded into this binary's state file.
//!
//! Resumable, same discipline as the other three live examples: persists to
//! `/mnt/storage1/bshuler-xmr/xmr_live_role_swap_state.json`
//! (`XMR_LIVE_ROLE_SWAP_STATE_PATH` to override). Never mainnet -- checked at startup,
//! same as every other live example in this crate.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use ciphersuite::group::ff::PrimeField;
use ciphersuite::{Ciphersuite, Ed25519};
use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::constants::CURRENT_TX_VERSION;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::SigHashType;
use divi_swap::htlc::push_data;
use divi_wallet::address::{Address, Network as DiviNetwork};
use divi_wallet::signer::sighash;
use dkg::Participant;
use monero_wallet::address::Network as XmrNetwork;
use monero_wallet::interface::FeeRate;
use monero_wallet::{OutputWithDecoys, ViewPair};
use rand::{thread_rng, RngCore};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use swap_adaptor::adaptor::{AdaptorSigner, Scalar as SecpScalar};
use swap_adaptor::dleq::{random_clamped_secret, ScalarQ};
use swap_chain_divi::{RetryPolicy, RpcClient, TESTNET_RPC};
use zeroize::Zeroizing;

use swap_chain_xmr::live_rpc::{
    check_divi_confirmed, check_xmr_confirmed, check_xmr_spendable, monerod_get_info,
    scan_for_lock_output, LiveDecoys, MONEROD_RPC_DEFAULT,
};
use swap_chain_xmr::monero_key_share::{additive_two_of_two_keys, dleq_secret_to_ed25519_scalar};
use swap_chain_xmr::multisig::{redeem_script, script_pubkey};
use swap_chain_xmr::swap_templates::divi_secret_to_adaptor_scalar;

// Crypto-protocol participant slots for the Monero additive key share -- business-taker
// sits in the crypto-Maker slot this round (she locks DIVI first), business-maker in the
// crypto-Taker slot (she locks XMR). Swapped from xmr_live.rs's assignment on purpose.
const CRYPTO_MAKER: Participant = match Participant::new(1) {
    Some(p) => p,
    None => unreachable!(),
};
const CRYPTO_TAKER: Participant = match Participant::new(2) {
    Some(p) => p,
    None => unreachable!(),
};

// The live punish run's own reclaimed DIVI (examples/xmr_live_punish.rs's Tx_punish
// output 0, paid to that round's Taker) funds this round's Tx_lock -- no new tDIVI
// needed. See docs/plans/swap-poc/status/xmr.md for that round's full txid history.
const FUNDING_TXID: &str = "d0cc708e7f133e30cdd40c4e859fcbd8c220ad393c0ebdda574b8b1b8a4606d9";
const FUNDING_VOUT: u32 = 0;
const FUNDING_AMOUNT_SAT: i64 = 96_900_000;
const PUNISH_STATE_PATH: &str = "/mnt/storage1/bshuler-xmr/xmr_live_punish_state.json";

fn state_path() -> PathBuf {
    std::env::var("XMR_LIVE_ROLE_SWAP_STATE_PATH")
        .unwrap_or_else(|_| "/mnt/storage1/bshuler-xmr/xmr_live_role_swap_state.json".to_string())
        .into()
}

/// Persisted across runs, same shape as `xmr_live.rs`'s `LiveState` -- just named for
/// the business role each key actually plays this round.
#[derive(Serialize, Deserialize)]
struct RoleSwapState {
    /// Business-taker's DIVI-side multisig key -- she locks DIVI first, so she plays
    /// the crypto-Maker role (calls `maker_encrypts_tx_redeem`).
    business_taker_divi_key: [u8; 32],
    /// Business-maker's DIVI-side multisig key -- she locks XMR, so she plays the
    /// crypto-Taker role (calls `taker_completes_tx_redeem`).
    business_maker_divi_key: [u8; 32],
    s_t_bytes: [u8; 32],
    s_m_bytes: [u8; 32],
    xmr_view_key_bytes: [u8; 32],
    divi_lock_txid: Option<String>,
    divi_redeem_txid: Option<String>,
    xmr_lock_txid: Option<String>,
    xmr_sweep_txid: Option<String>,
}

impl RoleSwapState {
    fn fresh() -> Self {
        let mut rng = thread_rng();
        RoleSwapState {
            business_taker_divi_key: key_bytes(&SecretKey::new_random()),
            business_maker_divi_key: key_bytes(&SecretKey::new_random()),
            s_t_bytes: random_clamped_secret(&mut rng).to_bytes(),
            s_m_bytes: random_clamped_secret(&mut rng).to_bytes(),
            xmr_view_key_bytes: <[u8; 32]>::from(monero_wallet::ed25519::Scalar::random(&mut rng)),
            divi_lock_txid: None,
            divi_redeem_txid: None,
            xmr_lock_txid: None,
            xmr_sweep_txid: None,
        }
    }

    fn load_or_fresh() -> std::io::Result<Self> {
        match fs::read(state_path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).expect("state file is valid JSON")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::fresh()),
            Err(e) => Err(e),
        }
    }

    fn save(&self) -> std::io::Result<()> {
        let path = state_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(self).expect("serializable"))
    }

    fn business_taker_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.business_taker_divi_key).expect("persisted key is valid")
    }

    fn business_maker_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.business_maker_divi_key).expect("persisted key is valid")
    }

    fn s_t(&self) -> ScalarQ {
        ScalarQ::from_canonical_bytes(self.s_t_bytes).expect("persisted DLEQ secret is canonical")
    }

    fn s_m(&self) -> ScalarQ {
        ScalarQ::from_canonical_bytes(self.s_m_bytes).expect("persisted DLEQ secret is canonical")
    }

    fn xmr_view_key(&self) -> Zeroizing<monero_wallet::ed25519::Scalar> {
        Zeroizing::new(
            monero_wallet::ed25519::Scalar::read(&mut &self.xmr_view_key_bytes[..])
                .expect("persisted view key is canonical"),
        )
    }
}

fn key_bytes(sk: &SecretKey) -> [u8; 32] {
    sk.as_bytes().try_into().expect("secret key is 32 bytes")
}

fn ed25519_point_for(secret: &ScalarQ) -> <Ed25519 as Ciphersuite>::G {
    Ed25519::generator() * dleq_secret_to_ed25519_scalar(secret)
}

fn secp256k1_scalar_for(secret: &ScalarQ) -> SecpScalar {
    let mut bytes = secret.to_bytes();
    bytes.reverse();
    SecpScalar::from_bytes(bytes)
        .expect("a DLEQ secret clamped below 2^252 is always a valid secp256k1 scalar")
}

fn sign_p2pkh(
    tx: &Transaction,
    input_index: usize,
    scriptpubkey: &Script,
    key: &SecretKey,
) -> Vec<u8> {
    let hash = sighash(tx, input_index, scriptpubkey, SigHashType::All, false)
        .expect("sighash computation");
    let signature = divi_crypto::signature::sign_hash(key, hash.as_bytes()).expect("signing");
    let mut sig_bytes = signature.to_der();
    sig_bytes.push(SigHashType::All as u8);
    sig_bytes
}

fn p2pkh_script_sig(sig: &[u8], pubkey: &[u8; 33]) -> Script {
    let mut s = Vec::new();
    push_data(&mut s, sig);
    push_data(&mut s, pubkey);
    Script::from_bytes(s)
}

#[tokio::main]
async fn main() {
    // Never mainnet -- checked against what the daemon actually reports, same as
    // every other live example in this crate.
    let monerod_rpc =
        std::env::var("MONEROD_RPC").unwrap_or_else(|_| MONEROD_RPC_DEFAULT.to_string());
    let info = monerod_get_info(&monerod_rpc)
        .await
        .expect("MONEROD_RPC must be reachable before doing anything else");
    assert!(
        info["result"]["nettype"] == "stagenet" && info["result"]["mainnet"] == false,
        "refusing to run xmr_live_role_swap against a non-stagenet daemon ({monerod_rpc}): \
         get_info reported nettype={:?}",
        info["result"]["nettype"]
    );
    assert!(
        TESTNET_RPC.contains("testnet"),
        "DIVI RPC endpoint must be the testnet proxy, not mainnet"
    );

    let mut state = RoleSwapState::load_or_fresh().expect("state file readable/writable");
    state
        .save()
        .expect("persist state before doing anything else");

    println!("=== xmr_live_role_swap: buy-XMR direction, roles swapped from xmr_live.rs ===");
    println!("state file: {}", state_path().display());
    println!(
        "business-taker locks DIVI first (crypto-Maker role, ends up with the XMR); \
         business-maker locks XMR (crypto-Taker role, ends up with the DIVI)."
    );

    let business_taker_key = state.business_taker_key();
    let business_maker_key = state.business_maker_key();
    let pubkey_taker_biz = business_taker_key.public_key().serialize_compressed();
    let pubkey_maker_biz = business_maker_key.public_key().serialize_compressed();
    // redeem_script's argument order is (pubkey_a, pubkey_b) -- crypto-Maker's key goes
    // first, matching every other live example's convention (its first arg is whoever
    // locks DIVI). Here that's business-taker's key.
    let redeem = redeem_script(&pubkey_taker_biz, &pubkey_maker_biz);
    let divi_spk = script_pubkey(&redeem);

    let divi_rpc = RpcClient::new(TESTNET_RPC, RetryPolicy::default());

    // --- Step 1: fund Tx_lock by spending the live punish run's reclaimed P2PKH
    // output (business-taker's leg -- she's the one locking DIVI first this round). ---
    if state.divi_lock_txid.is_none() {
        let punish_state: serde_json::Value = serde_json::from_slice(
            &fs::read(PUNISH_STATE_PATH).expect("punish run's state file readable"),
        )
        .expect("punish state is valid JSON");
        let old_taker_key_bytes: Vec<u8> = punish_state["taker_divi_key"]
            .as_array()
            .expect("taker_divi_key present")
            .iter()
            .map(|v| v.as_u64().expect("byte") as u8)
            .collect();
        let old_taker_key =
            SecretKey::from_bytes(&old_taker_key_bytes).expect("punish run's taker key is valid");
        let old_pubkey_hash =
            divi_crypto::hash::hash160(&old_taker_key.public_key().serialize_compressed());
        let old_p2pkh_spk = Script::new_p2pkh(old_pubkey_hash.as_bytes());

        const FEE: i64 = 500_000;
        let mut tx = Transaction {
            version: CURRENT_TX_VERSION,
            vin: vec![TxIn::new(
                OutPoint::new(
                    Hash256::from_hex(FUNDING_TXID).expect("valid funding txid"),
                    FUNDING_VOUT,
                ),
                Script::new(),
                divi_primitives::constants::SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_sat(FUNDING_AMOUNT_SAT - FEE),
                divi_spk.clone(),
            )],
            lock_time: 0,
        };
        let sig = sign_p2pkh(&tx, 0, &old_p2pkh_spk, &old_taker_key);
        tx.vin[0].script_sig =
            p2pkh_script_sig(&sig, &old_taker_key.public_key().serialize_compressed());

        let raw = hex::encode(divi_primitives::serialize::serialize(&tx));
        let txid = divi_rpc
            .call_ok("sendrawtransaction", serde_json::json!([raw]))
            .await
            .expect("Tx_lock broadcast");
        let txid = txid.as_str().expect("txid string").to_string();
        println!(
            "Tx_lock broadcast (funds business-taker's leg from the punish run's reclaimed \
             DIVI): {txid}"
        );
        state.divi_lock_txid = Some(txid);
        state.save().expect("persist Tx_lock txid");
    }

    let divi_lock_address =
        Address::p2sh(divi_crypto::hash::hash160(&redeem), DiviNetwork::Testnet).to_base58();
    println!();
    println!(
        "DIVI P2SH testnet address (informational -- already funded above): {divi_lock_address}"
    );

    let s_t = state.s_t();
    let s_m = state.s_m();
    let s_t_pub = ed25519_point_for(&s_t);
    let s_m_pub = ed25519_point_for(&s_m);
    let verification_shares = HashMap::from([(CRYPTO_MAKER, s_m_pub), (CRYPTO_TAKER, s_t_pub)]);
    let keys_crypto_maker = additive_two_of_two_keys(
        CRYPTO_MAKER,
        dleq_secret_to_ed25519_scalar(&s_m),
        verification_shares,
    )
    .expect("valid additive key construction");
    let group_key = keys_crypto_maker.group_key();
    let spend_point = monero_wallet::ed25519::Point::from(group_key.0);
    let view_key = state.xmr_view_key();
    let xmr_lock_address = ViewPair::new(spend_point, view_key)
        .expect("torsion-free spend key")
        .legacy_address(XmrNetwork::Stagenet);

    println!(
        "Monero stagenet address to fund (business-maker's leg, she's locking XMR to sell it):"
    );
    println!("  {xmr_lock_address}");
    println!();

    // --- Check funding status on both chains. ---
    let divi_lock_txid = state.divi_lock_txid.clone().unwrap();
    let divi_funded = check_divi_confirmed(&divi_rpc, &divi_lock_txid).await;

    let xmr_funded = match &state.xmr_lock_txid {
        Some(txid) => check_xmr_confirmed(&monerod_rpc, txid).await,
        None => {
            println!(
                "Monero: no lock txid recorded yet. Once the address above is funded (e.g. by \
                 transferring from the mining wallet), set xmr_lock_txid in {} and re-run.",
                state_path().display()
            );
            false
        }
    };

    println!();
    println!(
        "status: DIVI Tx_lock confirmed = {divi_funded}, Monero lock confirmed = {xmr_funded}"
    );

    if !(divi_funded && xmr_funded) {
        println!("Not yet ready for Tx_redeem -- re-run once both legs are confirmed.");
        return;
    }

    let s_t_secp = secp256k1_scalar_for(&s_t);
    let x_point = AdaptorSigner::new().verification_key_for(&s_t_secp);

    let recovered_s_t_secp = if let Some(existing_redeem_txid) = state.divi_redeem_txid.clone() {
        println!(
            "Tx_redeem already broadcast in an earlier run ({existing_redeem_txid}); reusing \
             the already-known s_t for the sweep rather than re-deriving it."
        );
        s_t_secp
    } else {
        println!("Both legs confirmed -- building Tx_redeem.");
        let lock_outpoint = Hash256::from_hex(&divi_lock_txid)
            .map(|txid| OutPoint::new(txid, 0))
            .expect("valid recorded txid");
        const FEE: i64 = 500_000;
        // business-maker is paid here (crypto-Taker's payout) -- the mirror of
        // xmr_live.rs, where the crypto-Taker payout goes to business-taker.
        let business_maker_payout = TxOut::new(
            Amount::from_sat(FUNDING_AMOUNT_SAT - 500_000 - FEE),
            Script::new_p2pkh(divi_crypto::hash::hash160(&pubkey_maker_biz).as_bytes()),
        );
        let (tx_redeem_unsigned, crypto_maker_encrypted) =
            swap_chain_xmr::swap_templates::maker_encrypts_tx_redeem(
                lock_outpoint,
                &redeem,
                &business_taker_key,
                &x_point,
                business_maker_payout,
                divi_swap::htlc::REFUND_SEQUENCE,
            )
            .expect("business-taker (crypto-Maker) builds her encrypted Tx_redeem half");

        let crypto_maker_verification_point = AdaptorSigner::new()
            .verification_key_for(&divi_secret_to_adaptor_scalar(&business_taker_key));
        let tx_redeem = swap_chain_xmr::swap_templates::taker_completes_tx_redeem(
            tx_redeem_unsigned,
            &redeem,
            &crypto_maker_verification_point,
            crypto_maker_encrypted.clone(),
            &business_maker_key,
            &s_t_secp,
        )
        .expect("business-maker (crypto-Taker) completes Tx_redeem with her own s_t");

        swap_chain_xmr::swap_templates::verify_spend(
            &tx_redeem,
            &divi_spk,
            Amount::from_sat(FUNDING_AMOUNT_SAT - FEE),
        )
        .expect("Tx_redeem satisfies the 2-of-2 script before broadcasting it for real");

        let completed_sig =
            AdaptorSigner::new().decrypt_signature(&s_t_secp, crypto_maker_encrypted.clone());
        let recovered = swap_chain_xmr::swap_templates::recover_secret_from_chain(
            &x_point,
            &completed_sig,
            &crypto_maker_encrypted,
        )
        .expect("business-taker (crypto-Maker) must recover s_t from the completed Tx_redeem");
        assert_eq!(
            recovered, s_t_secp,
            "recovered s_t must match business-maker's actual secret"
        );
        println!(
            "business-taker recovered s_t from the completed signature \
             (matches business-maker's own s_t)."
        );

        let raw = hex::encode(divi_primitives::serialize::serialize(&tx_redeem));
        match divi_rpc
            .call_ok("sendrawtransaction", serde_json::json!([raw]))
            .await
        {
            Ok(txid) => {
                println!("Tx_redeem broadcast: {txid}");
                state.divi_redeem_txid = txid.as_str().map(|s| s.to_string());
                state.save().expect("persist the redeem txid");
            }
            Err(e) => println!("Tx_redeem broadcast failed: {e} (fine if already broadcast)"),
        }
        recovered
    };

    // --- The sweep: business-taker now holds the full Monero private spend key (her
    // own s_m plus business-maker's s_t, recovered or already known) -- she bought the
    // XMR with the DIVI she locked. ---
    if state.xmr_sweep_txid.is_some() {
        println!(
            "Monero sweep already broadcast ({:?}).",
            state.xmr_sweep_txid
        );
        return;
    }
    let xmr_lock_txid = state
        .xmr_lock_txid
        .clone()
        .expect("checked xmr_funded above");
    if !check_xmr_spendable(&monerod_rpc, &xmr_lock_txid).await {
        println!(
            "Waiting for the Monero lock ({xmr_lock_txid}) to reach {} confirmations \
             (Monero's real spendable-age minimum) -- re-run shortly.",
            swap_chain_xmr::live_rpc::SPENDABLE_AGE
        );
        return;
    }
    println!("Scanning for the Monero lock output...");
    let recovered_s_t_ed25519 = {
        let mut bytes = recovered_s_t_secp.to_bytes();
        bytes.reverse();
        <Ed25519 as Ciphersuite>::F::from_repr(bytes)
            .expect("recovered s_t must be a canonical Ed25519 scalar")
    };
    let full_spend_key = dleq_secret_to_ed25519_scalar(&s_m) + recovered_s_t_ed25519;
    assert_eq!(
        Ed25519::generator() * full_spend_key,
        group_key,
        "the combined spend key must reconstruct the Monero group key both sides agreed on"
    );

    let output = scan_for_lock_output(
        &monerod_rpc,
        &xmr_lock_txid,
        ViewPair::new(spend_point, state.xmr_view_key()).expect("torsion-free spend key"),
    )
    .await
    .expect("monerod reachable")
    .expect("the confirmed lock transaction must contain a scannable output for our key");
    println!(
        "Found the lock output: {} atomic units, output index {}.",
        output.commitment().amount,
        output.index_on_blockchain()
    );

    let info = monerod_get_info(&monerod_rpc)
        .await
        .expect("get_info reachable");
    let latest_height = info["result"]["height"].as_u64().expect("height present") as usize;
    let fee_body: serde_json::Value = reqwest::Client::new()
        .post(format!("{monerod_rpc}/json_rpc"))
        .json(&serde_json::json!({"jsonrpc":"2.0","id":"0","method":"get_fee_estimate"}))
        .send()
        .await
        .expect("get_fee_estimate reachable")
        .json()
        .await
        .expect("get_fee_estimate returns JSON");
    let fee_rate = FeeRate::new(
        fee_body["result"]["fee"].as_u64().expect("fee present"),
        fee_body["result"]["quantization_mask"]
            .as_u64()
            .expect("quantization_mask present"),
    )
    .expect("daemon-reported fee rate is valid");

    let live_decoys = LiveDecoys {
        monerod_rpc: monerod_rpc.clone(),
        latest_height,
    };
    let mut decoys = None;
    for _ in 0..8 {
        if let Ok(d) =
            OutputWithDecoys::new(&mut OsRng, &live_decoys, 16, latest_height, output.clone()).await
        {
            decoys = Some(d);
            break;
        }
    }
    let decoys = decoys.expect("decoy selection should succeed within a handful of attempts");

    // A fresh throwaway destination -- business-taker's own post-swap XMR wallet.
    let destination_view_pair = ViewPair::new(
        monero_wallet::ed25519::Point::from(
            &curve25519_dalek::Scalar::random(&mut thread_rng())
                * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE,
        ),
        Zeroizing::new(monero_wallet::ed25519::Scalar::random(&mut thread_rng())),
    )
    .expect("torsion-free spend key");
    let destination = destination_view_pair.legacy_address(XmrNetwork::Stagenet);
    println!("Sweep destination (business-taker's, freshly generated): {destination}");

    let mut outgoing_view_key = [0u8; 32];
    thread_rng().fill_bytes(&mut outgoing_view_key);
    let tx = swap_chain_xmr::monero_sweep::sweep(
        &mut OsRng,
        &output,
        decoys,
        destination,
        outgoing_view_key,
        fee_rate,
        &full_spend_key,
    )
    .expect("sweep must build and sign against the real lock output and live decoys");

    let tx_hex = hex::encode(monero_wallet::transaction::Transaction::serialize(&tx));
    let resp = reqwest::Client::new()
        .post(format!("{monerod_rpc}/send_raw_transaction"))
        .json(&serde_json::json!({"tx_as_hex": tx_hex, "do_not_relay": false}))
        .send()
        .await
        .expect("send_raw_transaction reachable");
    let body: serde_json::Value = resp
        .json()
        .await
        .expect("send_raw_transaction returns JSON");
    if body["status"] == "OK" && !body["not_relayed"].as_bool().unwrap_or(true) {
        let sweep_txid = hex::encode(tx.hash());
        println!("Monero sweep broadcast: {sweep_txid}");
        state.xmr_sweep_txid = Some(sweep_txid);
        state.save().expect("persist the sweep txid");
    } else {
        println!("Monero sweep broadcast rejected: {body}");
    }
}
