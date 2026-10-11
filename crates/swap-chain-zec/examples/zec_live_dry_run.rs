// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live-readiness dry run: resolves the real `testnet.zec.rocks` lightwalletd endpoint,
//! reads the live consensus branch id, then builds, signs and consensus-verifies a claim
//! and a refund HTLC spend through [`ZecBackend`] — the exact production v6/ZIP-229 code
//! path, nothing mocked. Never broadcasts.
//!
//! No funded key is required: without `SWAP_ZEC_TEST_KEY_HEX` a throwaway key is
//! generated. With it (the same env var `live_fund_claim_refund` reads), the address is
//! real, so once it holds coins this dry run also builds (but does not broadcast) a real
//! funding tx — proving everything short of broadcast. At that point a funded run is one
//! command: `cargo test -p swap-chain-zec --features live -- --ignored live_fund_claim_refund`.
//!
//! ```sh
//! cargo run -p swap-chain-zec --example zec_live_dry_run
//! SWAP_ZEC_TEST_KEY_HEX=<hex> cargo run -p swap-chain-zec --example zec_live_dry_run
//! ```

use divi_swap::htlc::new_preimage;
use divi_swap::{Amount, ChainBackend, HtlcParams, Outpoint, SwapError, Txid};
use secp256k1::SecretKey;
use swap_chain_zec::{FeePolicy, ZecBackend};

const HTLC_ZATOSHI: u64 = 20_000; // matches live_fund_claim_refund
const REFUND_AHEAD_OF_MTP: u32 = 2 * 3600;

fn key() -> SecretKey {
    match std::env::var("SWAP_ZEC_TEST_KEY_HEX") {
        Ok(hex_key) => {
            let bytes = hex::decode(hex_key.trim()).expect("SWAP_ZEC_TEST_KEY_HEX is hex");
            SecretKey::from_slice(&bytes).expect("SWAP_ZEC_TEST_KEY_HEX is a valid key")
        }
        Err(_) => {
            eprintln!("SWAP_ZEC_TEST_KEY_HEX not set: using a fresh throwaway key");
            let random: [u8; 32] = rand::random();
            SecretKey::from_slice(&random).expect("random key")
        }
    }
}

#[tokio::main]
async fn main() {
    let backend = ZecBackend::testnet(key(), FeePolicy::default()).expect("construct ZecBackend");
    println!("address: {}", backend.address().encode());

    let tip = backend
        .tip_height()
        .await
        .expect("tip_height (primary endpoint reachable)");
    let mtp = backend.median_time_past().await.expect("median_time_past");
    println!("endpoints resolved: tip {tip}, median_time_past {mtp}");

    let (preimage, hash) = new_preimage();
    let htlc = HtlcParams {
        hash,
        claim_pubkey: backend.pubkey(),
        refund_pubkey: backend.pubkey(),
        locktime: mtp + REFUND_AHEAD_OF_MTP,
    };
    let amount = Amount::from_sat(HTLC_ZATOSHI);
    // Claim/refund building signs a spend of this outpoint; it does not need the output to
    // exist on-chain (that only matters once the signed tx is broadcast), so a synthetic
    // one exercises the real v6 signing + consensus-verification path with no funds needed.
    let at = Outpoint {
        txid: Txid([0x42; 32]),
        vout: 0,
    };

    let claim = backend
        .build_claim(&htlc, &at, amount, &preimage)
        .await
        .expect("build + consensus-verify claim (live consensus branch id, v6 digest tree)");
    println!("claim built and consensus-verified: txid {}", claim.txid);

    let refund = backend
        .build_refund(&htlc, &at, amount)
        .await
        .expect("build + consensus-verify refund (live consensus branch id, v6 digest tree)");
    println!("refund built and consensus-verified: txid {}", refund.txid);

    match backend.build_funding(&htlc, amount).await {
        Ok(f) => println!(
            "bonus: address already holds coins — funding tx built and consensus-verified: \
             txid {} (NOT broadcast)",
            f.tx.txid
        ),
        Err(SwapError::InsufficientFunds(_)) => {
            println!(
                "address has no UTXOs yet (expected for an unfunded dry run); fund it to also \
                 prove build_funding here"
            );
        }
        Err(e) => panic!("unexpected error building funding tx: {e}"),
    }

    println!(
        "dry run OK: endpoints resolved, claim + refund signed and consensus-verified against \
         the live v6/NU7 consensus branch id, nothing broadcast"
    );
}
