// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live abort/refund path: DIVI testnet + Monero stagenet, fresh throwaway keys,
//! deliberately **short** DIVI timelocks (`t_cancel`/`t_refund` a few blocks out, not
//! the design's real-world hours/days) so maturation takes minutes, matching the
//! orchestrator's ask to prove the mechanism live without an impractical wait.
//!
//! The scenario: Taker locks XMR, Maker locks DIVI, **nobody redeems** -- then
//! `Tx_cancel` and `Tx_refund` land on DIVI (Maker reclaims his DIVI, revealing `s_m`),
//! and Taker sweeps her own locked XMR back using her `s_t` combined with the
//! recovered `s_m` (`xmr-design.md`'s `## Protocol`, the "Maker locks DIVI, Taker
//! locks XMR, Maker then stalls/aborts" + "Taker reclaims her own XMR" failure case).
//!
//! Funding: Maker's `Tx_lock` is funded by spending the still-real, still-confirmed
//! P2PKH output `examples/xmr_live.rs`'s own `Tx_redeem` paid out (Taker's reclaimed
//! DIVI from the *forward* swap) -- no new tDIVI needed from a human. The Monero lock
//! still needs a manual `transfer` from `mining-wallet` (digest-auth RPC, simplest to
//! do directly rather than implementing an HTTP Digest client here) -- see the
//! printed address and `docs/plans/swap-poc/status/xmr.md`.
//!
//! Resumable, same discipline as `xmr_live.rs`: persists to
//! `/mnt/storage1/bshuler-xmr/xmr_live_refund_state.json`
//! (`XMR_LIVE_REFUND_STATE_PATH` to override), does the next ready step, and exits --
//! re-run as many times as needed (`cargo run -p swap-chain-xmr --example
//! xmr_live_refund --features live`).

use std::fs;
use std::path::PathBuf;

use ciphersuite::group::ff::PrimeField;
use ciphersuite::{Ciphersuite, Ed25519};
use divi_crypto::keys::SecretKey;
use divi_primitives::amount::Amount;
use divi_primitives::constants::{CURRENT_TX_VERSION, SEQUENCE_FINAL};
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::SigHashType;
use divi_swap::htlc::{push_data, REFUND_SEQUENCE};
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
use swap_chain_xmr::multisig::{
    build_presigned_spend, funding_output, redeem_script, script_pubkey,
};
use swap_chain_xmr::swap_templates::{
    divi_secret_to_adaptor_scalar, maker_completes_tx_refund, recover_secret_from_chain,
    taker_encrypts_tx_refund, verify_spend,
};

const MAKER: Participant = match Participant::new(1) {
    Some(p) => p,
    None => unreachable!(),
};
const TAKER: Participant = match Participant::new(2) {
    Some(p) => p,
    None => unreachable!(),
};

// The forward run's own reclaimed DIVI (examples/xmr_live.rs's Tx_redeem output 0,
// Taker's leg -- confirmed live, docs/plans/swap-poc/status/xmr.md has the full
// history) funds this round's Tx_lock, so no new tDIVI is needed from a human.
const FUNDING_TXID: &str = "3b9f3b383cb50e576df9d3e8403c2b2edd7e9ee1e67ef8335089eb406f6c3e4f";
const FUNDING_VOUT: u32 = 0;
const FUNDING_AMOUNT_SAT: i64 = 99_500_000;
// The forward run's taker_divi_key, which controls the output above -- read directly
// from its state file rather than duplicated, so there's exactly one copy of this key
// on disk.
const FORWARD_STATE_PATH: &str = "/mnt/storage1/bshuler-xmr/xmr_live_state.json";

fn state_path() -> PathBuf {
    std::env::var("XMR_LIVE_REFUND_STATE_PATH")
        .unwrap_or_else(|_| "/mnt/storage1/bshuler-xmr/xmr_live_refund_state.json".to_string())
        .into()
}

#[derive(Serialize, Deserialize)]
struct RefundState {
    maker_divi_key: [u8; 32],
    taker_divi_key: [u8; 32],
    s_t_bytes: [u8; 32],
    s_m_bytes: [u8; 32],
    xmr_view_key_bytes: [u8; 32],
    /// Picked once, at Tx_lock funding time, from the DIVI height then -- must stay
    /// fixed afterward since Tx_cancel/Tx_refund are built against them.
    t_cancel: Option<u32>,
    t_refund: Option<u32>,
    divi_lock_txid: Option<String>,
    xmr_lock_txid: Option<String>,
    tx_cancel_txid: Option<String>,
    tx_refund_txid: Option<String>,
    xmr_refund_sweep_txid: Option<String>,
}

impl RefundState {
    fn fresh() -> Self {
        let mut rng = thread_rng();
        RefundState {
            maker_divi_key: key_bytes(&SecretKey::new_random()),
            taker_divi_key: key_bytes(&SecretKey::new_random()),
            s_t_bytes: random_clamped_secret(&mut rng).to_bytes(),
            s_m_bytes: random_clamped_secret(&mut rng).to_bytes(),
            xmr_view_key_bytes: <[u8; 32]>::from(monero_wallet::ed25519::Scalar::random(&mut rng)),
            t_cancel: None,
            t_refund: None,
            divi_lock_txid: None,
            xmr_lock_txid: None,
            tx_cancel_txid: None,
            tx_refund_txid: None,
            xmr_refund_sweep_txid: None,
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

    fn maker_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.maker_divi_key).expect("persisted key is valid")
    }

    fn taker_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.taker_divi_key).expect("persisted key is valid")
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

/// Signs a plain P2PKH input (legacy sighash, scriptCode = the output's own
/// scriptPubKey) -- the forward run's reclaimed `Tx_redeem` output is an ordinary
/// P2PKH, not a 2-of-2, so `crate::multisig`'s multisig-shaped signing doesn't apply.
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

async fn divi_height(divi_rpc: &RpcClient) -> u32 {
    divi_rpc
        .call_ok("getblockcount", serde_json::json!([]))
        .await
        .expect("getblockcount reachable")
        .as_u64()
        .expect("height present") as u32
}

#[tokio::main]
async fn main() {
    let monerod_rpc =
        std::env::var("MONEROD_RPC").unwrap_or_else(|_| MONEROD_RPC_DEFAULT.to_string());
    let info = monerod_get_info(&monerod_rpc)
        .await
        .expect("MONEROD_RPC must be reachable before doing anything else");
    assert!(
        info["result"]["nettype"] == "stagenet" && info["result"]["mainnet"] == false,
        "refusing to run against a non-stagenet daemon ({monerod_rpc})"
    );
    assert!(
        TESTNET_RPC.contains("testnet"),
        "DIVI RPC must be the testnet proxy"
    );

    let mut state = RefundState::load_or_fresh().expect("state file readable/writable");
    state
        .save()
        .expect("persist state before doing anything else");

    println!("=== xmr_live_refund: abort/refund path, DIVI testnet <-> Monero stagenet ===");
    println!("state file: {}", state_path().display());

    let maker_key = state.maker_key();
    let taker_key = state.taker_key();
    let pubkey_maker = maker_key.public_key().serialize_compressed();
    let pubkey_taker = taker_key.public_key().serialize_compressed();
    let redeem = redeem_script(&pubkey_maker, &pubkey_taker);
    let divi_spk = script_pubkey(&redeem);
    let divi_lock_address =
        Address::p2sh(divi_crypto::hash::hash160(&redeem), DiviNetwork::Testnet).to_base58();

    let s_t = state.s_t();
    let s_m = state.s_m();
    let s_t_pub = ed25519_point_for(&s_t);
    let s_m_pub = ed25519_point_for(&s_m);
    let verification_shares = std::collections::HashMap::from([(MAKER, s_m_pub), (TAKER, s_t_pub)]);
    let keys_taker = additive_two_of_two_keys(
        TAKER,
        dleq_secret_to_ed25519_scalar(&s_t),
        verification_shares,
    )
    .expect("valid additive key construction");
    let group_key = keys_taker.group_key();
    let spend_point = monero_wallet::ed25519::Point::from(group_key.0);
    let view_key = state.xmr_view_key();
    let xmr_lock_address = monero_wallet::ViewPair::new(spend_point, view_key)
        .expect("torsion-free spend key")
        .legacy_address(XmrNetwork::Stagenet);

    let divi_rpc = RpcClient::new(TESTNET_RPC, RetryPolicy::default());

    // --- Step 1: fund Tx_lock by spending the forward run's reclaimed P2PKH output. ---
    if state.divi_lock_txid.is_none() {
        let forward_state: serde_json::Value = serde_json::from_slice(
            &fs::read(FORWARD_STATE_PATH).expect("forward run's state file readable"),
        )
        .expect("forward state is valid JSON");
        let old_taker_key_bytes: Vec<u8> = forward_state["taker_divi_key"]
            .as_array()
            .expect("taker_divi_key present")
            .iter()
            .map(|v| v.as_u64().expect("byte") as u8)
            .collect();
        let old_taker_key =
            SecretKey::from_bytes(&old_taker_key_bytes).expect("forward run's taker key is valid");
        let old_taker_pubkey_hash =
            divi_crypto::hash::hash160(&old_taker_key.public_key().serialize_compressed());
        let old_p2pkh_spk = Script::new_p2pkh(old_taker_pubkey_hash.as_bytes());

        // A couple of DIVI blocks out from right now -- "a few blocks, ~1 min each"
        // per the orchestrator, confirmed live this block time is ~53s/block.
        let height = divi_height(&divi_rpc).await;
        let t_cancel = height + 3;
        let t_refund = height + 5;
        state.t_cancel = Some(t_cancel);
        state.t_refund = Some(t_refund);
        println!("DIVI height {height}; t_cancel={t_cancel}, t_refund={t_refund}.");

        const FEE: i64 = 300_000;
        let mut tx = Transaction {
            version: CURRENT_TX_VERSION,
            vin: vec![TxIn::new(
                OutPoint::new(
                    Hash256::from_hex(FUNDING_TXID).expect("valid funding txid"),
                    FUNDING_VOUT,
                ),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![funding_output(
                &redeem,
                Amount::from_sat(FUNDING_AMOUNT_SAT - FEE),
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
            "Tx_lock broadcast (funds Maker's leg from the forward run's reclaimed DIVI): {txid}"
        );
        state.divi_lock_txid = Some(txid);
        state.save().expect("persist Tx_lock txid");
    }

    println!();
    println!(
        "DIVI P2SH testnet address (informational -- already funded above): {divi_lock_address}"
    );
    println!(
        "Monero stagenet address to fund (Taker's leg, {} atomic units needed):",
        50_000_000_000u64
    );
    println!("  {xmr_lock_address}");
    println!();

    // --- Step 2: wait for Tx_lock to confirm. ---
    let divi_lock_txid = state.divi_lock_txid.clone().unwrap();
    if !check_divi_confirmed(&divi_rpc, &divi_lock_txid).await {
        println!("Waiting for Tx_lock ({divi_lock_txid}) to confirm -- re-run shortly.");
        return;
    }

    // --- Step 3: Taker locks XMR (manual transfer from mining-wallet; this just
    // checks). ---
    let Some(xmr_lock_txid) = state.xmr_lock_txid.clone() else {
        println!(
            "Monero: no lock txid recorded yet. Transfer from mining-wallet to the address \
             above, then set xmr_lock_txid in {} and re-run.",
            state_path().display()
        );
        return;
    };
    if !check_xmr_confirmed(&monerod_rpc, &xmr_lock_txid).await {
        println!("Waiting for the Monero lock ({xmr_lock_txid}) to confirm -- re-run shortly.");
        return;
    }

    let t_cancel = state.t_cancel.expect("set when Tx_lock was funded");
    let t_refund = state.t_refund.expect("set when Tx_lock was funded");

    // --- Step 4: once t_cancel matures, build + broadcast Tx_cancel (plain, both
    // sign, nobody redeemed). ---
    if state.tx_cancel_txid.is_none() {
        let height = divi_height(&divi_rpc).await;
        if height < t_cancel {
            println!(
                "Waiting for DIVI height {height} to reach t_cancel={t_cancel} -- re-run shortly."
            );
            return;
        }
        let lock_outpoint =
            OutPoint::new(Hash256::from_hex(&divi_lock_txid).expect("valid txid"), 0);
        let tx_cancel = build_presigned_spend(
            lock_outpoint,
            Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000),
            &redeem,
            &maker_key,
            &taker_key,
            funding_output(
                &redeem,
                Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000 - 500_000),
            ),
            t_cancel,
            REFUND_SEQUENCE,
        )
        .expect("build Tx_cancel");
        verify_spend(
            &tx_cancel,
            &divi_spk,
            Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000),
        )
        .expect("Tx_cancel satisfies the 2-of-2 script");

        let raw = hex::encode(divi_primitives::serialize::serialize(&tx_cancel));
        let txid = divi_rpc
            .call_ok("sendrawtransaction", serde_json::json!([raw]))
            .await
            .expect("Tx_cancel broadcast");
        let txid = txid.as_str().expect("txid string").to_string();
        println!("Tx_cancel broadcast: {txid}");
        state.tx_cancel_txid = Some(txid);
        state.save().expect("persist Tx_cancel txid");
        return;
    }

    // --- Step 5: wait for Tx_cancel to confirm. ---
    let tx_cancel_txid = state.tx_cancel_txid.clone().unwrap();
    if !check_divi_confirmed(&divi_rpc, &tx_cancel_txid).await {
        println!("Waiting for Tx_cancel ({tx_cancel_txid}) to confirm -- re-run shortly.");
        return;
    }

    // --- Step 6: once t_refund matures, build Tx_refund (Taker encrypts under Y,
    // Maker completes with s_m and broadcasts) and recover s_m in-memory. ---
    let s_m_secp = secp256k1_scalar_for(&s_m);
    let recovered_s_m_secp = if let Some(existing) = state.tx_refund_txid.clone() {
        println!(
            "Tx_refund already broadcast ({existing}); reusing the already-known s_m for the \
             sweep rather than re-deriving it."
        );
        s_m_secp
    } else {
        let height = divi_height(&divi_rpc).await;
        if height < t_refund {
            println!(
                "Waiting for DIVI height {height} to reach t_refund={t_refund} -- re-run shortly."
            );
            return;
        }
        let y_point = AdaptorSigner::new().verification_key_for(&s_m_secp);
        let cancel_outpoint =
            OutPoint::new(Hash256::from_hex(&tx_cancel_txid).expect("valid txid"), 0);
        let maker_payout = TxOut::new(
            Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000 - 500_000 - 500_000),
            Script::new_p2pkh(divi_crypto::hash::hash160(&pubkey_maker).as_bytes()),
        );
        let (tx_refund_unsigned, taker_encrypted) = taker_encrypts_tx_refund(
            cancel_outpoint,
            &redeem,
            &taker_key,
            &y_point,
            maker_payout,
            t_refund,
            REFUND_SEQUENCE,
        )
        .expect("build Taker's encrypted Tx_refund half");

        let taker_verification_point =
            AdaptorSigner::new().verification_key_for(&divi_secret_to_adaptor_scalar(&taker_key));
        let tx_refund = maker_completes_tx_refund(
            tx_refund_unsigned,
            &redeem,
            &taker_verification_point,
            taker_encrypted.clone(),
            &maker_key,
            &s_m_secp,
        )
        .expect("Maker completes Tx_refund with his own s_m");
        verify_spend(
            &tx_refund,
            &divi_spk,
            Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000 - 500_000),
        )
        .expect("Tx_refund satisfies the 2-of-2 script");

        let completed_taker_sig =
            AdaptorSigner::new().decrypt_signature(&s_m_secp, taker_encrypted.clone());
        let recovered = recover_secret_from_chain(&y_point, &completed_taker_sig, &taker_encrypted)
            .expect("Taker must recover s_m from the completed Tx_refund");
        assert_eq!(
            recovered, s_m_secp,
            "recovered s_m must match Maker's actual secret"
        );
        println!("Taker recovered s_m from the completed signature (matches Maker's own s_m).");

        let raw = hex::encode(divi_primitives::serialize::serialize(&tx_refund));
        let txid = divi_rpc
            .call_ok("sendrawtransaction", serde_json::json!([raw]))
            .await
            .expect("Tx_refund broadcast");
        let txid = txid.as_str().expect("txid string").to_string();
        println!("Tx_refund broadcast: {txid}");
        state.tx_refund_txid = Some(txid);
        state.save().expect("persist Tx_refund txid");
        recovered
    };

    // --- Step 7: Taker sweeps her own Monero back, combining her s_t with the
    // recovered s_m. ---
    if state.xmr_refund_sweep_txid.is_some() {
        println!(
            "Monero refund-sweep already broadcast ({:?}).",
            state.xmr_refund_sweep_txid
        );
        return;
    }
    // Monero's real CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE: an ordinary output needs
    // SPENDABLE_AGE confirmations before it can be used as an input, not just one --
    // found live (first attempt here was rejected with "invalid_input": true against
    // a 1-confirmation lock output).
    if !check_xmr_spendable(&monerod_rpc, &xmr_lock_txid).await {
        println!(
            "Waiting for the Monero lock ({xmr_lock_txid}) to reach {} confirmations \
             (Monero's real spendable-age minimum, not just \"confirmed\") -- re-run shortly.",
            swap_chain_xmr::live_rpc::SPENDABLE_AGE
        );
        return;
    }
    println!("Scanning for the Monero lock output...");
    let recovered_s_m_ed25519 = {
        let mut bytes = recovered_s_m_secp.to_bytes();
        bytes.reverse();
        <Ed25519 as Ciphersuite>::F::from_repr(bytes)
            .expect("recovered s_m must be a canonical Ed25519 scalar")
    };
    let full_spend_key = dleq_secret_to_ed25519_scalar(&s_t) + recovered_s_m_ed25519;
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

    // Taker's own fresh destination -- reclaiming her XMR to a wallet of her own.
    let destination_view_pair = ViewPair::new(
        monero_wallet::ed25519::Point::from(
            &curve25519_dalek::Scalar::random(&mut thread_rng())
                * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE,
        ),
        Zeroizing::new(monero_wallet::ed25519::Scalar::random(&mut thread_rng())),
    )
    .expect("torsion-free spend key");
    let destination = destination_view_pair.legacy_address(XmrNetwork::Stagenet);
    println!("Refund-sweep destination (Taker's own, freshly generated): {destination}");

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
        println!("Monero refund-sweep broadcast: {sweep_txid}");
        state.xmr_refund_sweep_txid = Some(sweep_txid);
        state.save().expect("persist the refund-sweep txid");
    } else {
        println!("Monero refund-sweep broadcast rejected: {body}");
    }
}
