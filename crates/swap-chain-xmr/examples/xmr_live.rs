// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live happy-path run: DIVI **testnet** + Monero **stagenet** only. Never mainnet —
//! enforced below, not just promised in a comment: every daemon URL this binary talks
//! to is checked at startup and the run aborts if any of them don't look like a test
//! network.
//!
//! Resumable by design: real confirmations take real wall-clock time (DIVI testnet
//! needs a human to fund it; stagenet XMR needs mining or a faucet to clear), so this
//! persists its state to a JSON file outside the repo
//! (`/mnt/storage1/bshuler-xmr/xmr_live_state.json` by default, override with
//! `XMR_LIVE_STATE_PATH`) and picks up where it left off on every run. Safe to re-run
//! as often as you like — `cargo run -p swap-chain-xmr --example xmr_live`.
//!
//! Needs, at run time (none of it checked into the repo or hardcoded):
//! - A local `monerod --stagenet` with its RPC reachable at `MONEROD_RPC`
//!   (default `http://127.0.0.1:38081`, localhost by construction).
//! - DIVI testnet coin sent to the P2SH address this prints once generated —
//!   that funding step needs a human; see `docs/plans/swap-poc/status/xmr.md`'s
//!   `- needs:` for the live address once this has been run once.
//!
//! Phases implemented so far: key/address generation (real, persisted) and
//! funding-status checks against both chains (real RPC). Building and broadcasting
//! `Tx_redeem` (reusing `crate::swap_templates`) is wired in but only runs once both
//! legs report confirmed — which needs real coin on both chains, so it cannot be
//! exercised yet this round. The final sweep of the Monero output (combining the
//! recovered secret with Maker's own share into a real spend via
//! `monero_wallet::send`) is the next increment after that — scanning for the deposit
//! and decoy selection need real on-chain state from both locks to build against.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use ciphersuite::{Ciphersuite, Ed25519};
use divi_crypto::keys::SecretKey;
use divi_primitives::hash::Hash256;
use divi_wallet::address::{Address, Network as DiviNetwork};
use dkg::Participant;
use monero_wallet::address::Network as XmrNetwork;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use swap_adaptor::adaptor::{AdaptorSigner, Scalar as SecpScalar};
use swap_adaptor::dleq::{random_clamped_secret, ScalarQ};
use swap_chain_divi::{RetryPolicy, RpcClient, TESTNET_RPC};
use zeroize::Zeroizing;

use swap_chain_xmr::monero_key_share::{additive_two_of_two_keys, dleq_secret_to_ed25519_scalar};
use swap_chain_xmr::multisig::{redeem_script, script_pubkey};
use swap_chain_xmr::swap_templates::divi_secret_to_adaptor_scalar;

const MAKER: Participant = match Participant::new(1) {
    Some(p) => p,
    None => unreachable!(),
};
const TAKER: Participant = match Participant::new(2) {
    Some(p) => p,
    None => unreachable!(),
};

const MONEROD_RPC_DEFAULT: &str = "http://127.0.0.1:38081";

fn state_path() -> PathBuf {
    std::env::var("XMR_LIVE_STATE_PATH")
        .unwrap_or_else(|_| "/mnt/storage1/bshuler-xmr/xmr_live_state.json".to_string())
        .into()
}

/// Persisted across runs -- real keys for a real (if worthless) test run, so this file
/// lives outside the repo by construction (see `state_path`), never committed.
#[derive(Serialize, Deserialize)]
struct LiveState {
    maker_divi_key: [u8; 32],
    taker_divi_key: [u8; 32],
    /// `swap_adaptor::dleq::ScalarQ`'s canonical bytes (curve25519-dalek-ng encoding).
    s_t_bytes: [u8; 32],
    s_m_bytes: [u8; 32],
    divi_lock_txid: Option<String>,
    divi_redeem_txid: Option<String>,
}

impl LiveState {
    fn fresh() -> Self {
        let mut rng = thread_rng();
        LiveState {
            maker_divi_key: key_bytes(&SecretKey::new_random()),
            taker_divi_key: key_bytes(&SecretKey::new_random()),
            s_t_bytes: random_clamped_secret(&mut rng).to_bytes(),
            s_m_bytes: random_clamped_secret(&mut rng).to_bytes(),
            divi_lock_txid: None,
            divi_redeem_txid: None,
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

/// Bridges a DLEQ secret into the ed25519 point it commits to, the same canonical-bytes
/// re-encode `monero_key_share::dleq_secret_to_ed25519_scalar` already does -- used here
/// just to get both parties' *public* contributions for `additive_two_of_two_keys`'s
/// `verification_shares` map.
fn ed25519_point_for(secret: &ScalarQ) -> <Ed25519 as Ciphersuite>::G {
    Ed25519::generator() * dleq_secret_to_ed25519_scalar(secret)
}

/// The same DLEQ secret, re-encoded as a secp256k1 scalar -- `swap_adaptor::dleq`'s test
/// module does this identical big-endian/little-endian reversal to get `x·G` on the
/// secp256k1 side; `s_t`/`s_m` need this form to drive `AdaptorSigner`.
fn secp256k1_scalar_for(secret: &ScalarQ) -> SecpScalar {
    let mut bytes = secret.to_bytes();
    bytes.reverse();
    SecpScalar::from_bytes(bytes)
        .expect("a DLEQ secret clamped below 2^252 is always a valid secp256k1 scalar")
}

#[tokio::main]
async fn main() {
    // Never mainnet: both endpoints are hardcoded to their test-network form, and
    // checked here rather than just promised in a doc comment.
    let monerod_rpc =
        std::env::var("MONEROD_RPC").unwrap_or_else(|_| MONEROD_RPC_DEFAULT.to_string());
    assert!(
        monerod_rpc.starts_with("http://127.0.0.1:")
            || monerod_rpc.starts_with("http://localhost:"),
        "MONEROD_RPC must be localhost -- refusing to run xmr_live against a remote \
         or mainnet-shaped daemon: {monerod_rpc}"
    );
    assert!(
        TESTNET_RPC.contains("testnet"),
        "DIVI RPC endpoint must be the testnet proxy, not mainnet"
    );

    let state = LiveState::load_or_fresh().expect("state file readable/writable");
    state
        .save()
        .expect("persist state before doing anything else");

    println!("=== xmr_live: DIVI testnet <-> Monero stagenet, never mainnet ===");
    println!("state file: {}", state_path().display());

    // --- Addresses, derived fresh from the persisted keys every run (cheap, so no
    // need to persist them separately -- they're fully determined by the keys). ---
    let maker_key = state.maker_key();
    let taker_key = state.taker_key();
    let pubkey_maker = maker_key.public_key().serialize_compressed();
    let pubkey_taker = taker_key.public_key().serialize_compressed();
    let redeem = redeem_script(&pubkey_maker, &pubkey_taker);
    let divi_spk = script_pubkey(&redeem);
    let divi_script_hash = divi_crypto::hash::hash160(&redeem);
    let divi_lock_address = Address::p2sh(divi_script_hash, DiviNetwork::Testnet).to_base58();

    let s_t = state.s_t();
    let s_m = state.s_m();
    let s_t_pub = ed25519_point_for(&s_t);
    let s_m_pub = ed25519_point_for(&s_m);
    let verification_shares = HashMap::from([(MAKER, s_m_pub), (TAKER, s_t_pub)]);
    let keys_maker = additive_two_of_two_keys(
        MAKER,
        dleq_secret_to_ed25519_scalar(&s_m),
        verification_shares,
    )
    .expect("valid additive key construction");
    let group_key = keys_maker.group_key();
    // monero-wallet's ed25519::Point wraps curve25519-dalek's EdwardsPoint directly --
    // same bridge monero_dkg's and happy_path_e2e's tests already use.
    let spend_point = monero_wallet::ed25519::Point::from(group_key.0);
    // Simplification noted in xmr-design.md and monero_key_share's tests: a real
    // 2-of-2 shares the view key in the clear; generated fresh here for this run.
    let view_key = Zeroizing::new(monero_wallet::ed25519::Scalar::random(&mut thread_rng()));
    let xmr_lock_address = monero_wallet::ViewPair::new(spend_point, view_key)
        .expect("torsion-free spend key")
        .legacy_address(XmrNetwork::Stagenet);

    println!();
    println!("DIVI P2SH testnet address to fund (Tx_lock, Maker's leg):");
    println!("  {divi_lock_address}");
    println!("Monero stagenet address to fund (the 2-of-2 lock, Taker's leg):");
    println!("  {xmr_lock_address}");
    println!();

    // --- Check funding status on both chains. ---
    let divi_rpc = RpcClient::new(TESTNET_RPC, RetryPolicy::default());
    let divi_funded = match &state.divi_lock_txid {
        Some(txid) => check_divi_confirmed(&divi_rpc, txid).await,
        None => {
            println!("DIVI: no Tx_lock txid recorded yet. Once the address above is funded,");
            println!(
                "      set divi_lock_txid in {} and re-run.",
                state_path().display()
            );
            false
        }
    };

    let xmr_funded = check_xmr_node_synced(&monerod_rpc).await;

    println!();
    println!(
        "status: DIVI Tx_lock confirmed = {divi_funded}, Monero node synced = {xmr_funded} \
         (deposit scanning for the 2-of-2 address is the next increment)"
    );

    if !(divi_funded && xmr_funded) {
        println!("Not yet ready for Tx_redeem -- re-run once both legs are confirmed.");
        return;
    }

    if state.divi_redeem_txid.is_some() {
        println!(
            "Tx_redeem already broadcast ({:?}); the Monero sweep is the next increment, \
             not yet implemented here.",
            state.divi_redeem_txid
        );
        return;
    }

    // --- Both legs confirmed: build and broadcast Tx_redeem. ---
    println!("Both legs confirmed -- building Tx_redeem.");
    let lock_outpoint = Hash256::from_hex(state.divi_lock_txid.as_deref().unwrap())
        .map(|txid| divi_primitives::transaction::OutPoint::new(txid, 0))
        .expect("valid recorded txid");

    let x_point = AdaptorSigner::new().verification_key_for(&secp256k1_scalar_for(&s_t));
    let taker_payout = divi_primitives::transaction::TxOut::new(
        divi_primitives::amount::Amount::from_divi(1)
            - divi_primitives::amount::Amount::from_sat(1_000),
        divi_primitives::script::Script::new_p2pkh(
            divi_crypto::hash::hash160(&pubkey_taker).as_bytes(),
        ),
    );
    let (tx_redeem_unsigned, maker_encrypted) =
        swap_chain_xmr::swap_templates::maker_encrypts_tx_redeem(
            lock_outpoint,
            &redeem,
            &maker_key,
            &x_point,
            taker_payout,
            divi_swap::htlc::REFUND_SEQUENCE,
        )
        .expect("build Maker's encrypted Tx_redeem half");

    let maker_verification_point =
        AdaptorSigner::new().verification_key_for(&divi_secret_to_adaptor_scalar(&maker_key));
    let tx_redeem = swap_chain_xmr::swap_templates::taker_completes_tx_redeem(
        tx_redeem_unsigned,
        &redeem,
        &maker_verification_point,
        maker_encrypted,
        &taker_key,
        &secp256k1_scalar_for(&s_t),
    )
    .expect("Taker completes Tx_redeem with her own s_t");

    swap_chain_xmr::swap_templates::verify_spend(
        &tx_redeem,
        &divi_spk,
        divi_primitives::amount::Amount::from_divi(1),
    )
    .expect("Tx_redeem satisfies the 2-of-2 script before broadcasting it for real");

    let raw = hex::encode(divi_primitives::serialize::serialize(&tx_redeem));
    match divi_rpc
        .call_ok("sendrawtransaction", serde_json::json!([raw]))
        .await
    {
        Ok(txid) => {
            println!("Tx_redeem broadcast: {txid}");
            let mut state = state;
            state.divi_redeem_txid = txid.as_str().map(|s| s.to_string());
            state.save().expect("persist the redeem txid");
        }
        Err(e) => println!("Tx_redeem broadcast failed: {e} (fine if already broadcast)"),
    }
}

async fn check_divi_confirmed(rpc: &RpcClient, txid: &str) -> bool {
    match rpc
        .call_ok("getrawtransaction", serde_json::json!([txid, 1]))
        .await
    {
        Ok(v) => v.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0) >= 1,
        Err(_) => false,
    }
}

/// Whether the local stagenet node has finished its initial sync -- a prerequisite for
/// trusting any balance/deposit check against it. Scanning the 2-of-2 address for an
/// actual incoming deposit (needed to drive real funding status, not just "the node is
/// usable") is the next increment, alongside the sweep -- both need
/// `monero_wallet::scan::Scanner` wired to this run's view key, which only matters once
/// there's really something to scan for.
async fn check_xmr_node_synced(monerod_rpc: &str) -> bool {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{monerod_rpc}/json_rpc"))
        .json(&serde_json::json!({"jsonrpc":"2.0","id":"0","method":"get_info"}))
        .send()
        .await;
    match resp {
        Ok(r) => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let synced = body["result"]["synchronized"].as_bool().unwrap_or(false);
            if !synced {
                println!(
                    "Monero: local stagenet node still syncing (height {}/{}) -- can't check \
                     for a real deposit yet.",
                    body["result"]["height"], body["result"]["target_height"]
                );
            }
            synced
        }
        Err(e) => {
            println!("Monero: local daemon unreachable ({e}) -- is monerod running?");
            false
        }
    }
}
