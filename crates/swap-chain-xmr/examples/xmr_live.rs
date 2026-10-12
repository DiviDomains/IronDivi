// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live happy-path run: DIVI **testnet** + Monero **stagenet** only, through a public
//! restricted node. Never mainnet — enforced below, not just promised in a doc
//! comment: every daemon URL this binary talks to is checked at startup and the run
//! aborts if any of them don't look like a test network.
//!
//! Resumable by design: real confirmations take real wall-clock time, so this
//! persists its state to a JSON file outside the repo
//! (`/mnt/storage1/bshuler-xmr/xmr_live_state.json` by default, override with
//! `XMR_LIVE_STATE_PATH`) and picks up where it left off on every run. Safe to re-run
//! as often as you like — `cargo run -p swap-chain-xmr --example xmr_live --features live`.
//!
//! The full happy path has run live, for real, on both chains: DIVI `Tx_lock` and
//! `Tx_redeem`, and the Monero lock + final sweep — see
//! `docs/plans/swap-poc/status/xmr.md` for every txid. The live-RPC machinery this
//! binary depends on (`crate::live_rpc`) is shared with `examples/xmr_live_refund.rs`,
//! the abort-path counterpart.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use ciphersuite::group::ff::PrimeField;
use ciphersuite::{Ciphersuite, Ed25519};
use divi_crypto::keys::SecretKey;
use divi_primitives::hash::Hash256;
use divi_wallet::address::{Address, Network as DiviNetwork};
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

const MAKER: Participant = match Participant::new(1) {
    Some(p) => p,
    None => unreachable!(),
};
const TAKER: Participant = match Participant::new(2) {
    Some(p) => p,
    None => unreachable!(),
};

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
    /// The Monero lock address's view key. Must be generated once and persisted, not
    /// regenerated per run: the printed address encodes it, so a fresh view key on
    /// every run would print a *different* address each time (same spend key, but an
    /// unrelated stealth-address target on-chain) and strand anything sent to an
    /// earlier run's address.
    xmr_view_key_bytes: [u8; 32],
    divi_lock_txid: Option<String>,
    divi_redeem_txid: Option<String>,
    /// The Monero transaction that funded the 2-of-2 lock address (Taker's leg) --
    /// set externally once that funding happens, same pattern as `divi_lock_txid`.
    xmr_lock_txid: Option<String>,
    /// The final sweep's broadcast txid, set once it's actually sent.
    xmr_sweep_txid: Option<String>,
}

impl LiveState {
    fn fresh() -> Self {
        let mut rng = thread_rng();
        LiveState {
            maker_divi_key: key_bytes(&SecretKey::new_random()),
            taker_divi_key: key_bytes(&SecretKey::new_random()),
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
    // Never mainnet. The Monero daemon is a public, restricted node rather than a
    // trusted localhost one, so this can't just check the hostname -- it asks the
    // daemon what network it actually claims to be on, the one check that still works
    // regardless of which node (local, remote, trusted, restricted) is configured.
    let monerod_rpc =
        std::env::var("MONEROD_RPC").unwrap_or_else(|_| MONEROD_RPC_DEFAULT.to_string());
    let info = monerod_get_info(&monerod_rpc)
        .await
        .expect("MONEROD_RPC must be reachable before doing anything else");
    assert!(
        info["result"]["nettype"] == "stagenet" && info["result"]["mainnet"] == false,
        "refusing to run xmr_live against a non-stagenet daemon ({monerod_rpc}): \
         get_info reported nettype={:?}",
        info["result"]["nettype"]
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
    // 2-of-2 shares the view key in the clear; persisted (not regenerated) per run --
    // see LiveState::xmr_view_key_bytes's docs for why that matters here.
    let view_key = state.xmr_view_key();
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

    let xmr_funded = match &state.xmr_lock_txid {
        Some(txid) => check_xmr_confirmed(&monerod_rpc, txid).await,
        None => {
            println!(
                "Monero: no lock txid recorded yet. Once the address above is funded \
                 (e.g. by transferring from the mining wallet once its unlocked balance \
                 covers the swap amount), set xmr_lock_txid in {} and re-run.",
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

    let mut state = state;
    let s_t_secp = secp256k1_scalar_for(&s_t);
    let x_point = AdaptorSigner::new().verification_key_for(&s_t_secp);

    // Recovering s_t needs the *exact* encrypted signature Tx_redeem was actually
    // completed from -- ecdsa_fun's synthetic nonces mean a freshly-recomputed
    // encrypted signature on a later run would NOT be the one actually used on an
    // already-broadcast Tx_redeem. So building, completing, broadcasting, and
    // recovering all happen in this one run/one encrypted-signature instance; a
    // Tx_redeem broadcast by an earlier run is detected and its already-known s_t
    // (this process persists both parties' secrets regardless) is reused for the
    // sweep instead of re-deriving it.
    let recovered_s_t_secp = if let Some(existing_redeem_txid) = state.divi_redeem_txid.clone() {
        println!(
            "Tx_redeem already broadcast in an earlier run ({existing_redeem_txid}); reusing \
             the already-known s_t for the sweep rather than re-deriving it (recovery-from-chain \
             was already demonstrated when it was first broadcast)."
        );
        s_t_secp
    } else {
        println!("Both legs confirmed -- building Tx_redeem.");
        let lock_outpoint = Hash256::from_hex(state.divi_lock_txid.as_deref().unwrap())
            .map(|txid| divi_primitives::transaction::OutPoint::new(txid, 0))
            .expect("valid recorded txid");
        // 500_000 sat, not 1_000 -- matches swap-chain-divi's real `FeePolicy` ballpark
        // (`min_fee: 100_000`, `sat_per_kb: 1_000_000`; this ~400-450 byte 2-of-2 P2SH
        // spend's size-based fee alone is already close to that). A too-low fee is
        // exactly what got this rejected live ("insufficient priority") the first time.
        let taker_payout = divi_primitives::transaction::TxOut::new(
            divi_primitives::amount::Amount::from_divi(1)
                - divi_primitives::amount::Amount::from_sat(500_000),
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
            maker_encrypted.clone(),
            &taker_key,
            &s_t_secp,
        )
        .expect("Taker completes Tx_redeem with her own s_t");

        swap_chain_xmr::swap_templates::verify_spend(
            &tx_redeem,
            &divi_spk,
            divi_primitives::amount::Amount::from_divi(1),
        )
        .expect("Tx_redeem satisfies the 2-of-2 script before broadcasting it for real");

        // Real recovery-from-the-completed-signature, same mechanism happy_path_e2e.rs
        // proves offline -- here against a transaction that's actually about to be (or
        // just was) broadcast for real.
        let completed_maker_sig =
            AdaptorSigner::new().decrypt_signature(&s_t_secp, maker_encrypted.clone());
        let recovered = swap_chain_xmr::swap_templates::recover_secret_from_chain(
            &x_point,
            &completed_maker_sig,
            &maker_encrypted,
        )
        .expect("Maker must recover s_t from the completed Tx_redeem");
        assert_eq!(
            recovered, s_t_secp,
            "recovered s_t must match Taker's actual secret"
        );
        println!("Maker recovered s_t from the completed signature (matches Taker's own s_t).");

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

    // --- The sweep: Maker now holds the full Monero private spend key (his own s_m
    // plus Taker's s_t, recovered or already known) -- an ordinary single-key send,
    // not a cooperative multisig round. See monero_sweep's module docs. ---
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
    // Monero's real CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE: an ordinary output needs
    // SPENDABLE_AGE confirmations before it can be used as an input, not just one --
    // found live against xmr_live_refund.rs's faster-moving run (rejected with
    // "invalid_input": true against a 1-confirmation lock output); this run happened
    // to have enough real elapsed time already, but checking properly either way.
    if !check_xmr_spendable(&monerod_rpc, &xmr_lock_txid).await {
        println!(
            "Waiting for the Monero lock ({xmr_lock_txid}) to reach {} confirmations \
             (Monero's real spendable-age minimum, not just \"confirmed\") -- re-run shortly.",
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

    // A fresh throwaway destination -- Maker's own post-swap XMR wallet; nothing needs
    // to have sent anything to it beforehand, it's just where the swept funds land.
    let destination_view_pair = ViewPair::new(
        monero_wallet::ed25519::Point::from(
            &curve25519_dalek::Scalar::random(&mut thread_rng())
                * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE,
        ),
        Zeroizing::new(monero_wallet::ed25519::Scalar::random(&mut thread_rng())),
    )
    .expect("torsion-free spend key");
    let destination = destination_view_pair.legacy_address(XmrNetwork::Stagenet);
    println!("Sweep destination (Maker's, freshly generated): {destination}");

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
