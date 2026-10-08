// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live test against the Divi testnet proxy. Spends real tDIVI of the key named by
//! `SWAP_KEY_REF` (an `op://…` reference; the key never touches disk).
//!
//! ```sh
//! export SWAP_KEY_REF="op://global_secret_store/IronDivi Swap POC - maker-divi/password"
//! export SWAP_SEED_TXID=03f9983c25cfb97b964031741a737848d18c9a319eb2224ea3bf6cb60721bb1f
//! export SWAP_EXCLUDE_TXID=6ff5e4289f59b69a9463994c6619aa5c569cd68d7396cbdba92e0351271cfe26
//! cargo test -p swap-chain-divi --features live --test live -- --ignored --nocapture
//! ```
//! Takes ~15-20 minutes: HTLC B's 10-minute locktime must pass the median time past.

#![cfg(feature = "live")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use divi_crypto::keys::SecretKey;
use divi_swap::htlc::{new_preimage, HtlcParams};
use divi_swap::secrets::SecretRef;
use divi_swap::{Amount, ChainBackend, Outpoint, SwapError, Txid};
use divi_wallet::address::Network;
use swap_chain_divi::{DiviBackend, FeePolicy, TESTNET_RPC};

const HTLC_VALUE: Amount = Amount(100 * 100_000_000);

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

async fn wait_confirmed(b: &DiviBackend, txid: &Txid, what: &str) {
    for _ in 0..120 {
        if b.confirmations(txid).await.unwrap().unwrap_or(0) >= 1 {
            println!("{what} {txid} confirmed");
            return;
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
    panic!("{what} {txid} not confirmed within 30 minutes");
}

#[tokio::test]
#[ignore = "spends tDIVI on the live testnet; run with --features live -- --ignored"]
async fn live_fund_claim_refund() {
    let key_ref = std::env::var("SWAP_KEY_REF").expect("SWAP_KEY_REF=op://…");
    let key = SecretKey::from_hex(&SecretRef::parse(&key_ref).unwrap().resolve().unwrap()).unwrap();
    let b = DiviBackend::new(
        TESTNET_RPC,
        key,
        Network::Testnet,
        FeePolicy::default(),
        None,
    )
    .unwrap();
    println!("address {}", b.address());

    if let Ok(t) = std::env::var("SWAP_EXCLUDE_TXID") {
        b.exclude_txid(t.parse().unwrap()).unwrap();
    }
    let seed: Txid = std::env::var("SWAP_SEED_TXID")
        .expect("SWAP_SEED_TXID")
        .parse()
        .unwrap();
    b.add_funding_tx(&seed).await.unwrap();
    println!("balance {} sat", b.balance());
    assert!(b.balance() > 2 * HTLC_VALUE.0, "wallet too poor to run");

    let start_height = b.tip_height().await.unwrap();
    let (pre_a, hash_a) = new_preimage();
    let (_, hash_b) = new_preimage();
    let pk = b.pubkey();
    let a = HtlcParams {
        hash: hash_a,
        claim_pubkey: pk,
        refund_pubkey: pk,
        locktime: now() + 86_400,
    };
    let bp = HtlcParams {
        hash: hash_b,
        claim_pubkey: pk,
        refund_pubkey: pk,
        locktime: now() + 600,
    };

    // Fund both.
    let fa = b.build_funding(&a, HTLC_VALUE).await.unwrap();
    let txid_a = b.broadcast(&fa.tx).await.unwrap();
    let fb = b.build_funding(&bp, HTLC_VALUE).await.unwrap();
    let txid_b = b.broadcast(&fb.tx).await.unwrap();
    println!("live_fund_txid {txid_a}");
    println!("fund B txid {txid_b}");
    wait_confirmed(&b, &txid_a, "fund A").await;
    wait_confirmed(&b, &txid_b, "fund B").await;

    for (h, f) in [(&a, &fa), (&bp, &fb)] {
        let out = b
            .htlc_output(h, &f.outpoint)
            .await
            .unwrap()
            .expect("htlc output");
        assert_eq!(out.amount, HTLC_VALUE);
        assert!(out.confirmations >= 1);
    }

    // Claim A with the preimage.
    let claim = b
        .build_claim(&a, &fa.outpoint, HTLC_VALUE, &pre_a)
        .await
        .unwrap();
    let claim_txid = b.broadcast(&claim).await.unwrap();
    println!("live_claim_txid {claim_txid}");
    wait_confirmed(&b, &claim_txid, "claim").await;

    // The counterparty's view: find the spend and recover the preimage.
    let spend = b
        .find_spend(&fa.outpoint, start_height)
        .await
        .unwrap()
        .expect("claim visible to find_spend");
    assert_eq!(spend.txid, claim_txid);
    assert_eq!(spend.extract_preimage(&hash_a), Some(pre_a));

    // Refund B once the median time past has passed its locktime.
    let refund = b.build_refund(&bp, &fb.outpoint, HTLC_VALUE).await.unwrap();
    let refund_txid = loop {
        match b.broadcast(&refund).await {
            Ok(t) => break t,
            Err(SwapError::Premature(m)) => {
                println!(
                    "refund premature (mtp {} < {}): {m}",
                    b.median_time_past().await.unwrap(),
                    bp.locktime
                );
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            Err(e) => panic!("refund broadcast: {e}"),
        }
    };
    println!("live_refund_txid {refund_txid}");
    wait_confirmed(&b, &refund_txid, "refund").await;

    let Outpoint { txid, .. } = fb.outpoint;
    assert_eq!(txid, txid_b);
}
