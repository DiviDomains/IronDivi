// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Final live-acceptance run, post go-live authorization: the same forward happy path
//! `examples/xmr_live.rs` already proved, run once more end to end -- and the first
//! time `divi_chain::LiveDiviChain::build_funding`/`broadcast` fund `Tx_lock` for real
//! instead of a human manually sending tDIVI. Never mainnet, enforced the same way
//! every live example here does (checked at startup, not just promised).
//!
//! Funding: spends the role-swap round's own reclaimed DIVI
//! (`examples/xmr_live_role_swap.rs`'s `Tx_redeem` output 0, paid to that round's
//! business-maker key) via `LiveDiviChain`, not a hand-built raw transaction -- this
//! round doubles as `divi_chain.rs`'s first live exercise outside its own tests.
//!
//! Resumable: `/mnt/storage1/bshuler-xmr/xmr_live_final_state.json`
//! (`XMR_LIVE_FINAL_STATE_PATH` to override).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use ciphersuite::group::ff::PrimeField;
use ciphersuite::{Ciphersuite, Ed25519};
use divi_crypto::keys::SecretKey;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::OutPoint;
use divi_wallet::address::{Address, Network as DiviNetwork};
use dkg::Participant;
use monero_wallet::address::Network as XmrNetwork;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use swap_adaptor::adaptor::{AdaptorSigner, Scalar as SecpScalar};
use swap_adaptor::dleq::{random_clamped_secret, ScalarQ};
use swap_chain_divi::{FeePolicy, TESTNET_RPC};

use swap_chain_xmr::divi_chain::LiveDiviChain;
use swap_chain_xmr::live_rpc::{
    check_divi_confirmed, check_xmr_confirmed, check_xmr_spendable, monerod_get_info,
    MONEROD_RPC_DEFAULT,
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

// The role-swap round's own reclaimed DIVI (examples/xmr_live_role_swap.rs's
// Tx_redeem output 0, paid to that round's business-maker key) funds this round's
// Tx_lock -- no new tDIVI needed. See docs/plans/swap-poc/status/xmr.md.
const FUNDING_TXID: &str = "0de8a0c6d5c117bf1aefa0bfd6d3c4790e7c9a52c5ee27c569858818e934307c";
const FUNDING_AMOUNT_SAT: u64 = 95_900_000;
const ROLE_SWAP_STATE_PATH: &str = "/mnt/storage1/bshuler-xmr/xmr_live_role_swap_state.json";

fn state_path() -> PathBuf {
    std::env::var("XMR_LIVE_FINAL_STATE_PATH")
        .unwrap_or_else(|_| "/mnt/storage1/bshuler-xmr/xmr_live_final_state.json".to_string())
        .into()
}

#[derive(Serialize, Deserialize)]
struct LiveState {
    maker_divi_key: [u8; 32],
    taker_divi_key: [u8; 32],
    s_t_bytes: [u8; 32],
    s_m_bytes: [u8; 32],
    xmr_view_key_bytes: [u8; 32],
    divi_lock_txid: Option<String>,
    divi_redeem_txid: Option<String>,
    xmr_lock_txid: Option<String>,
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

    fn xmr_view_key(&self) -> zeroize::Zeroizing<monero_wallet::ed25519::Scalar> {
        zeroize::Zeroizing::new(
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

#[tokio::main]
async fn main() {
    let monerod_rpc =
        std::env::var("MONEROD_RPC").unwrap_or_else(|_| MONEROD_RPC_DEFAULT.to_string());
    let info = monerod_get_info(&monerod_rpc)
        .await
        .expect("MONEROD_RPC must be reachable before doing anything else");
    assert!(
        info["result"]["nettype"] == "stagenet" && info["result"]["mainnet"] == false,
        "refusing to run against a non-stagenet daemon ({monerod_rpc}): nettype={:?}",
        info["result"]["nettype"]
    );
    assert!(
        TESTNET_RPC.contains("testnet"),
        "DIVI RPC endpoint must be the testnet proxy, not mainnet"
    );

    let mut state = LiveState::load_or_fresh().expect("state file readable/writable");
    state
        .save()
        .expect("persist state before doing anything else");

    println!("=== xmr_live_final: go-live acceptance run, DIVI testnet <-> Monero stagenet ===");
    println!("state file: {}", state_path().display());

    let maker_key = state.maker_key();
    let taker_key = state.taker_key();
    let pubkey_maker = maker_key.public_key().serialize_compressed();
    let pubkey_taker = taker_key.public_key().serialize_compressed();
    let redeem = redeem_script(&pubkey_maker, &pubkey_taker);
    let divi_spk = script_pubkey(&redeem);
    let divi_script_hash = divi_crypto::hash::hash160(&redeem);
    let divi_lock_address = Address::p2sh(divi_script_hash, DiviNetwork::Testnet).to_base58();

    // --- Step 0: fund Tx_lock via LiveDiviChain, spending the role-swap round's
    // reclaimed DIVI -- the funding key is the role-swap round's own business-maker
    // key, loaded from that round's state file (same recycling pattern every round
    // has used, just funded through the new library module instead of a hand-built
    // raw transaction). ---
    if state.divi_lock_txid.is_none() {
        let role_swap_state: serde_json::Value = serde_json::from_slice(
            &fs::read(ROLE_SWAP_STATE_PATH).expect("role-swap state file readable"),
        )
        .expect("role-swap state is valid JSON");
        let funding_key_bytes: Vec<u8> = role_swap_state["business_maker_divi_key"]
            .as_array()
            .expect("business_maker_divi_key present")
            .iter()
            .map(|v| v.as_u64().expect("byte") as u8)
            .collect();
        let funding_key =
            SecretKey::from_bytes(&funding_key_bytes).expect("role-swap business-maker key valid");

        let funding_wallet_path: PathBuf =
            "/mnt/storage1/bshuler-xmr/xmr_live_final_funding_wallet.json".into();
        let funding_chain = LiveDiviChain::new(
            TESTNET_RPC,
            funding_key,
            FeePolicy::default(),
            Some(funding_wallet_path),
        )
        .expect("LiveDiviChain construction");
        let learned = funding_chain
            .learn_utxo(FUNDING_TXID)
            .await
            .expect("learn the known recycled UTXO");
        println!("LiveDiviChain learned {learned} coin(s) from the recycled funding tx.");

        let fund_amount = FUNDING_AMOUNT_SAT - 500_000; // leave room for this tx's own fee
        let funding_tx = funding_chain
            .build_funding(&divi_spk, fund_amount)
            .await
            .expect("LiveDiviChain::build_funding");
        funding_chain
            .broadcast(&funding_tx)
            .await
            .expect("LiveDiviChain::broadcast");
        let txid = funding_tx.txid().to_hex();
        println!("Tx_lock broadcast via LiveDiviChain (funds Maker's leg): {txid}");
        state.divi_lock_txid = Some(txid);
        state.save().expect("persist Tx_lock txid");
    }

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
    let spend_point = monero_wallet::ed25519::Point::from(group_key.0);
    let view_key = state.xmr_view_key();
    let xmr_lock_address = monero_wallet::ViewPair::new(spend_point, view_key)
        .expect("torsion-free spend key")
        .legacy_address(XmrNetwork::Stagenet);

    println!();
    println!(
        "DIVI P2SH testnet address (informational -- already funded above): {divi_lock_address}"
    );
    println!("Monero stagenet address to fund (the 2-of-2 lock, Taker's leg):");
    println!("  {xmr_lock_address}");
    println!();

    let divi_rpc =
        swap_chain_divi::RpcClient::new(TESTNET_RPC, swap_chain_divi::RetryPolicy::default());
    let divi_lock_txid = state.divi_lock_txid.clone().unwrap();
    let divi_funded = check_divi_confirmed(&divi_rpc, &divi_lock_txid).await;

    let xmr_funded = match &state.xmr_lock_txid {
        Some(txid) => check_xmr_confirmed(&monerod_rpc, txid).await,
        None => {
            println!(
                "Monero: no lock txid recorded yet. Once the address above is funded, set \
                 xmr_lock_txid in {} and re-run.",
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
             the already-known s_t for the sweep."
        );
        s_t_secp
    } else {
        println!("Both legs confirmed -- building Tx_redeem.");
        let lock_outpoint = Hash256::from_hex(&divi_lock_txid)
            .map(|txid| OutPoint::new(txid, 0))
            .expect("valid recorded txid");
        let taker_payout = divi_primitives::transaction::TxOut::new(
            divi_primitives::amount::Amount::from_sat(
                (FUNDING_AMOUNT_SAT - 500_000 - 500_000) as i64,
            ),
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
            divi_primitives::amount::Amount::from_sat((FUNDING_AMOUNT_SAT - 500_000) as i64),
        )
        .expect("Tx_redeem satisfies the 2-of-2 script before broadcasting it for real");

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
        let computed_txid = tx_redeem.txid().to_hex();
        match divi_rpc
            .call_ok("sendrawtransaction", serde_json::json!([raw]))
            .await
        {
            Ok(txid) => {
                println!("Tx_redeem broadcast: {txid}");
                state.divi_redeem_txid = txid.as_str().map(|s| s.to_string());
                state.save().expect("persist the redeem txid");
            }
            Err(e) => {
                // A node error here does not by itself mean the broadcast failed -- the
                // same tx can have reached the mempool before an error response arrived
                // (e.g. an `rpc -25` with no message, seen live on 2026-10-13). Verify
                // against the chain itself rather than assuming either outcome, the same
                // way `divi_chain::LiveDiviChain::broadcast`'s reject-then-recheck does.
                println!("Tx_redeem broadcast call failed: {e} -- checking the chain directly.");
                match divi_rpc
                    .call_ok("getrawtransaction", serde_json::json!([computed_txid, 1]))
                    .await
                {
                    Ok(_) => {
                        println!(
                            "Confirmed via getrawtransaction: Tx_redeem {computed_txid} is \
                             really on the node despite the error."
                        );
                        state.divi_redeem_txid = Some(computed_txid);
                        state.save().expect("persist the redeem txid");
                    }
                    Err(lookup_err) => {
                        panic!(
                            "Tx_redeem broadcast failed ({e}) and getrawtransaction cannot find \
                             {computed_txid} either ({lookup_err}) -- it genuinely did not \
                             reach the chain. Re-run once the cause is fixed; do not proceed to \
                             the Monero sweep without a confirmed Tx_redeem."
                        );
                    }
                }
            }
        }
        recovered
    };

    if state.xmr_sweep_txid.is_some() {
        println!(
            "Monero sweep already broadcast ({:?}).",
            state.xmr_sweep_txid
        );
        println!("=== GO-LIVE ACCEPTANCE RUN COMPLETE ===");
        return;
    }
    let xmr_lock_txid = state
        .xmr_lock_txid
        .clone()
        .expect("checked xmr_funded above");
    if !check_xmr_spendable(&monerod_rpc, &xmr_lock_txid).await {
        println!(
            "Waiting for the Monero lock ({xmr_lock_txid}) to reach {} confirmations -- re-run shortly.",
            swap_chain_xmr::live_rpc::SPENDABLE_AGE
        );
        return;
    }

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

    let destination_view_pair = monero_wallet::ViewPair::new(
        monero_wallet::ed25519::Point::from(
            &curve25519_dalek::Scalar::random(&mut thread_rng())
                * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE,
        ),
        zeroize::Zeroizing::new(monero_wallet::ed25519::Scalar::random(&mut thread_rng())),
    )
    .expect("torsion-free spend key");
    let destination = destination_view_pair.legacy_address(XmrNetwork::Stagenet);
    println!("Sweep destination (Maker's, freshly generated): {destination}");

    let lock = swap_chain_xmr::monero_chain::XmrLockOutput {
        txid: xmr_lock_txid,
        amount_piconero: 0,
        confirmations: 0,
    };
    match swap_chain_xmr::monero_chain::sweep(
        &monerod_rpc,
        &lock,
        full_spend_key.to_repr(),
        state.xmr_view_key_bytes,
        destination,
    )
    .await
    {
        Ok(sweep_txid) => {
            println!("Monero sweep broadcast: {sweep_txid}");
            state.xmr_sweep_txid = Some(sweep_txid);
            state.save().expect("persist the sweep txid");
            println!("=== GO-LIVE ACCEPTANCE RUN COMPLETE ===");
        }
        Err(e) => println!("Monero sweep broadcast rejected: {e}"),
    }
}
