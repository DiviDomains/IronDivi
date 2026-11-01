// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Plain P2WPKH send on Bitcoin testnet3 or signet (no HTLC) — moves funds directly between
//! swap wallets (`docs/plans/swap-poc/funding.md`), e.g. from the one a faucet paid to a
//! test taker. Building, signing and consensus-verification are [`BtcBackend::build_send`]
//! (`crates/swap-chain-btc/src/send.rs`), covered by unit tests there and by
//! `tests.rs::backend_send_selects_coins_and_change` against a mocked Esplora server — this
//! file is a thin CLI over that.
//!
//! The key is read from `SWAP_BTC_KEY_HEX` only — never a CLI argument (so it never shows
//! up in `ps`, shell history, or a crash log that prints argv) and never printed.
//!
//! ```sh
//! SWAP_BTC_KEY_HEX=<hex> cargo run -p swap-chain-btc --example btc_send -- --network testnet --to <tb1…> --sats <n> [--dry-run]
//! ```

use bitcoin::secp256k1::SecretKey;
use divi_swap::ChainBackend;
use swap_chain_btc::{BtcBackend, FeePolicy};

struct Args {
    network: String,
    to: String,
    sats: u64,
    dry_run: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: SWAP_BTC_KEY_HEX=<hex> btc_send [--network testnet|signet] --to <tb1…> --sats <n> [--dry-run]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut network = "testnet".to_string();
    let mut to = None;
    let mut sats = None;
    let mut dry_run = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--network" => network = it.next().unwrap_or_else(|| usage()),
            "--to" => to = it.next(),
            "--sats" => sats = it.next().and_then(|s| s.parse().ok()),
            "--dry-run" => dry_run = true,
            other => {
                eprintln!("unknown argument {other:?}");
                usage();
            }
        }
    }
    let (Some(to), Some(sats)) = (to, sats) else {
        usage();
    };
    Args {
        network,
        to,
        sats,
        dry_run,
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let Ok(hex_key) = std::env::var("SWAP_BTC_KEY_HEX") else {
        eprintln!("SWAP_BTC_KEY_HEX must be set (never pass the key as an argument)");
        std::process::exit(2);
    };
    let key = SecretKey::from_slice(&hex::decode(hex_key.trim()).expect("hex"))
        .expect("valid secp256k1 key");
    drop(hex_key); // the raw hex is never logged or printed, only the derived key used below

    let backend = BtcBackend::for_network(&args.network, key, FeePolicy::default())
        .expect("construct backend");
    eprintln!("from address: {}", backend.address());
    eprintln!("to address:   {}", args.to);
    eprintln!("amount:       {} sats", args.sats);

    let signed = backend
        .build_send(&args.to, args.sats)
        .await
        .expect("build + sign + consensus-verify send");
    println!("txid: {}", signed.txid);
    println!("raw:  {}", hex::encode(&signed.raw));

    if args.dry_run {
        println!("--dry-run: not broadcasting");
        return;
    }

    let sent = backend.broadcast(&signed).await.expect("broadcast");
    println!("broadcast: {sent}");
}
