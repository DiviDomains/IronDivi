// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live punish path: DIVI testnet + Monero stagenet, fresh throwaway keys, short DIVI
//! timelocks -- the third and last of this design's three on-chain outcomes
//! (`xmr-design.md`'s `## Protocol` failure case: "Maker locks DIVI, Taker locks XMR,
//! Maker then stalls" -- the mirror image of `xmr_live_refund.rs`'s "Maker reclaims
//! his DIVI" outcome, but here Maker goes silent instead and Taker seizes everything).
//!
//! The scenario: Taker locks XMR, Maker locks DIVI, `Tx_cancel` lands (same as the
//! refund run), but **Maker never completes `Tx_refund`** -- deliberately not built or
//! broadcast here, simulating a maker who has gone silent. Once `t_punish` matures,
//! Taker broadcasts the plain, pre-signed `Tx_punish` (signed by both parties back at
//! `Tx_cancel` time -- see the design doc: "signed by Maker at setup, handed to
//! Taker"), taking Maker's entire locked DIVI as compensation.
//!
//! **Taker's locked XMR is NOT recovered in this path -- that's the point.** Nothing
//! ever reveals `s_m` to her (Maker never completes `Tx_refund`), so she cannot
//! reconstruct the full Monero spend key and her XMR stays locked in the 2-of-2
//! forever. This is the documented, deliberate deterrent cost that falls on Maker for
//! stalling, not a bug -- so unlike the forward and refund runs, there is no final
//! Monero sweep step here. A small XMR amount is used specifically because it is
//! genuinely, permanently unrecoverable by design.
//!
//! Funding: `Tx_lock` is funded by spending the *refund* run's own reclaimed DIVI
//! (`xmr_live_refund.rs`'s `Tx_refund` output 0, Maker's leg) -- no new tDIVI needed.
//!
//! Resumable, same discipline as the other two live examples: persists to
//! `/mnt/storage1/bshuler-xmr/xmr_live_punish_state.json`
//! (`XMR_LIVE_PUNISH_STATE_PATH` to override).

use std::fs;
use std::path::PathBuf;

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
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use swap_adaptor::dleq::{random_clamped_secret, ScalarQ};
use swap_chain_divi::{RetryPolicy, RpcClient, TESTNET_RPC};

use swap_chain_xmr::live_rpc::{
    check_divi_confirmed, check_xmr_confirmed, monerod_get_info, MONEROD_RPC_DEFAULT,
};
use swap_chain_xmr::monero_key_share::{additive_two_of_two_keys, dleq_secret_to_ed25519_scalar};
use swap_chain_xmr::multisig::{
    build_presigned_spend, funding_output, redeem_script, script_pubkey,
};
use swap_chain_xmr::swap_templates::verify_spend;

const MAKER: Participant = match Participant::new(1) {
    Some(p) => p,
    None => unreachable!(),
};
const TAKER: Participant = match Participant::new(2) {
    Some(p) => p,
    None => unreachable!(),
};

// The refund run's own reclaimed DIVI (examples/xmr_live_refund.rs's Tx_refund output
// 0, Maker's leg) funds this round's Tx_lock -- no new tDIVI needed from a human.
const FUNDING_TXID: &str = "b55438cd0416b7fbd57bdb5bf83dd50816f61d3ac8c337bd217707c167045390";
const FUNDING_VOUT: u32 = 0;
const FUNDING_AMOUNT_SAT: i64 = 98_200_000;
const REFUND_STATE_PATH: &str = "/mnt/storage1/bshuler-xmr/xmr_live_refund_state.json";

// Small and deliberately unrecoverable -- see the module docs.
const XMR_LOCK_ATOMIC_UNITS: u64 = 10_000_000_000; // 0.01 XMR

fn state_path() -> PathBuf {
    std::env::var("XMR_LIVE_PUNISH_STATE_PATH")
        .unwrap_or_else(|_| "/mnt/storage1/bshuler-xmr/xmr_live_punish_state.json".to_string())
        .into()
}

#[derive(Serialize, Deserialize)]
struct PunishState {
    maker_divi_key: [u8; 32],
    taker_divi_key: [u8; 32],
    s_t_bytes: [u8; 32],
    s_m_bytes: [u8; 32],
    xmr_view_key_bytes: [u8; 32],
    t_cancel: Option<u32>,
    t_punish: Option<u32>,
    divi_lock_txid: Option<String>,
    xmr_lock_txid: Option<String>,
    tx_cancel_txid: Option<String>,
    /// Built and "handed to Taker" (held in state) as soon as Tx_cancel confirms --
    /// not broadcast until t_punish matures.
    tx_punish_hex: Option<String>,
    tx_punish_txid: Option<String>,
}

impl PunishState {
    fn fresh() -> Self {
        let mut rng = thread_rng();
        PunishState {
            maker_divi_key: key_bytes(&SecretKey::new_random()),
            taker_divi_key: key_bytes(&SecretKey::new_random()),
            s_t_bytes: random_clamped_secret(&mut rng).to_bytes(),
            s_m_bytes: random_clamped_secret(&mut rng).to_bytes(),
            xmr_view_key_bytes: <[u8; 32]>::from(monero_wallet::ed25519::Scalar::random(&mut rng)),
            t_cancel: None,
            t_punish: None,
            divi_lock_txid: None,
            xmr_lock_txid: None,
            tx_cancel_txid: None,
            tx_punish_hex: None,
            tx_punish_txid: None,
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
}

fn key_bytes(sk: &SecretKey) -> [u8; 32] {
    sk.as_bytes().try_into().expect("secret key is 32 bytes")
}

fn ed25519_point_for(secret: &ScalarQ) -> <Ed25519 as Ciphersuite>::G {
    Ed25519::generator() * dleq_secret_to_ed25519_scalar(secret)
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

    let mut state = PunishState::load_or_fresh().expect("state file readable/writable");
    state
        .save()
        .expect("persist state before doing anything else");

    println!("=== xmr_live_punish: punish path, DIVI testnet <-> Monero stagenet ===");
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
    let view_key = zeroize::Zeroizing::new(
        monero_wallet::ed25519::Scalar::read(&mut &state.xmr_view_key_bytes[..])
            .expect("persisted view key is canonical"),
    );
    let xmr_lock_address = monero_wallet::ViewPair::new(spend_point, view_key)
        .expect("torsion-free spend key")
        .legacy_address(XmrNetwork::Stagenet);

    let divi_rpc = RpcClient::new(TESTNET_RPC, RetryPolicy::default());

    // --- Step 1: fund Tx_lock by spending the refund run's reclaimed P2PKH output. ---
    if state.divi_lock_txid.is_none() {
        let refund_state: serde_json::Value = serde_json::from_slice(
            &fs::read(REFUND_STATE_PATH).expect("refund run's state file readable"),
        )
        .expect("refund state is valid JSON");
        let old_maker_key_bytes: Vec<u8> = refund_state["maker_divi_key"]
            .as_array()
            .expect("maker_divi_key present")
            .iter()
            .map(|v| v.as_u64().expect("byte") as u8)
            .collect();
        let old_maker_key =
            SecretKey::from_bytes(&old_maker_key_bytes).expect("refund run's maker key is valid");
        let old_maker_pubkey_hash =
            divi_crypto::hash::hash160(&old_maker_key.public_key().serialize_compressed());
        let old_p2pkh_spk = Script::new_p2pkh(old_maker_pubkey_hash.as_bytes());

        let height = divi_height(&divi_rpc).await;
        let t_cancel = height + 3;
        let t_punish = height + 7; // past a notional t_refund = t_cancel + 2, with margin
        state.t_cancel = Some(t_cancel);
        state.t_punish = Some(t_punish);
        println!("DIVI height {height}; t_cancel={t_cancel}, t_punish={t_punish}.");

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
        let sig = sign_p2pkh(&tx, 0, &old_p2pkh_spk, &old_maker_key);
        tx.vin[0].script_sig =
            p2pkh_script_sig(&sig, &old_maker_key.public_key().serialize_compressed());

        let raw = hex::encode(divi_primitives::serialize::serialize(&tx));
        let txid = divi_rpc
            .call_ok("sendrawtransaction", serde_json::json!([raw]))
            .await
            .expect("Tx_lock broadcast");
        let txid = txid.as_str().expect("txid string").to_string();
        println!(
            "Tx_lock broadcast (funds Maker's leg from the refund run's reclaimed DIVI): {txid}"
        );
        state.divi_lock_txid = Some(txid);
        state.save().expect("persist Tx_lock txid");
    }

    println!();
    println!(
        "DIVI P2SH testnet address (informational -- already funded above): {divi_lock_address}"
    );
    println!(
        "Monero stagenet address to fund (Taker's leg, {XMR_LOCK_ATOMIC_UNITS} atomic units needed \
         -- NOTE: this XMR will be permanently unrecoverable once the punish path completes, by design):"
    );
    println!("  {xmr_lock_address}");
    println!();

    // --- Step 2: wait for Tx_lock to confirm. ---
    let divi_lock_txid = state.divi_lock_txid.clone().unwrap();
    if !check_divi_confirmed(&divi_rpc, &divi_lock_txid).await {
        println!("Waiting for Tx_lock ({divi_lock_txid}) to confirm -- re-run shortly.");
        return;
    }

    // --- Step 3: Taker locks XMR (manual transfer from mining-wallet; this just checks). ---
    let Some(xmr_lock_txid) = state.xmr_lock_txid.clone() else {
        println!(
            "Monero: no lock txid recorded yet. Transfer from mining-wallet to the address above, \
             then set xmr_lock_txid in {} and re-run.",
            state_path().display()
        );
        return;
    };
    if !check_xmr_confirmed(&monerod_rpc, &xmr_lock_txid).await {
        println!("Waiting for the Monero lock ({xmr_lock_txid}) to confirm -- re-run shortly.");
        return;
    }

    let t_cancel = state.t_cancel.expect("set when Tx_lock was funded");
    let t_punish = state.t_punish.expect("set when Tx_lock was funded");

    // --- Step 4: once t_cancel matures, build + broadcast Tx_cancel. ---
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

    // --- Step 5: wait for Tx_cancel to confirm, then build (not yet broadcast) the
    // plain, pre-signed Tx_punish -- "signed by Maker at setup, handed to Taker" per
    // the design doc; built here (as soon as Tx_cancel's real txid is known) rather
    // than literally at setup, since this simulation needs the real outpoint. Maker
    // deliberately never builds/broadcasts Tx_refund -- that's the "stalls" scenario. ---
    let tx_cancel_txid = state.tx_cancel_txid.clone().unwrap();
    if !check_divi_confirmed(&divi_rpc, &tx_cancel_txid).await {
        println!("Waiting for Tx_cancel ({tx_cancel_txid}) to confirm -- re-run shortly.");
        return;
    }
    if state.tx_punish_hex.is_none() {
        let cancel_outpoint =
            OutPoint::new(Hash256::from_hex(&tx_cancel_txid).expect("valid txid"), 0);
        let taker_payout = TxOut::new(
            Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000 - 500_000 - 500_000),
            Script::new_p2pkh(divi_crypto::hash::hash160(&pubkey_taker).as_bytes()),
        );
        let tx_punish = build_presigned_spend(
            cancel_outpoint,
            Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000 - 500_000),
            &redeem,
            &maker_key,
            &taker_key,
            taker_payout,
            t_punish,
            REFUND_SEQUENCE,
        )
        .expect("build Tx_punish");
        verify_spend(
            &tx_punish,
            &divi_spk,
            Amount::from_sat(FUNDING_AMOUNT_SAT - 300_000 - 500_000),
        )
        .expect("Tx_punish satisfies the 2-of-2 script");
        state.tx_punish_hex = Some(hex::encode(divi_primitives::serialize::serialize(
            &tx_punish,
        )));
        state
            .save()
            .expect("persist Tx_punish (built, not yet broadcast)");
        println!(
            "Tx_punish built and signed by both parties (held by Taker; Maker has gone silent -- \
             no Tx_refund will ever be built in this run)."
        );
    }

    // --- Step 6: once t_punish matures, Taker broadcasts Tx_punish. ---
    if state.tx_punish_txid.is_some() {
        println!("Tx_punish already broadcast ({:?}).", state.tx_punish_txid);
        println!(
            "Taker's XMR lock ({xmr_lock_txid}) is permanently unrecoverable -- by design, see \
             the module docs. The punish path is complete."
        );
        return;
    }
    let height = divi_height(&divi_rpc).await;
    if height < t_punish {
        println!(
            "Waiting for DIVI height {height} to reach t_punish={t_punish} -- re-run shortly."
        );
        return;
    }
    let raw = state
        .tx_punish_hex
        .clone()
        .expect("built in the step above");
    let txid = divi_rpc
        .call_ok("sendrawtransaction", serde_json::json!([raw]))
        .await
        .expect("Tx_punish broadcast");
    let txid = txid.as_str().expect("txid string").to_string();
    println!("Tx_punish broadcast (Taker seizes Maker's entire locked DIVI): {txid}");
    state.tx_punish_txid = Some(txid);
    state.save().expect("persist Tx_punish txid");
}
