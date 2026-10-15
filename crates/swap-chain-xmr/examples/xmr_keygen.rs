// Copyright (C) 2026 IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Generate a Monero wallet's spend and view keys as a 1Password item template on **stdout**,
//! for piping straight into `op item create --vault global_secret_store -`. The keys never
//! touch disk, argv or the terminal; stderr gets only the address.
//!
//! ```sh
//! cargo run -q -p swap-chain-xmr --example xmr_keygen -- stagenet "IronDivi Swap POC - maker-xmr-wallet" \
//!   | op item create --vault global_secret_store - >/dev/null
//! ```
//! The maker's `[xmr].sweep_address` is the printed address. The wallet is restorable with
//! `monero-wallet-cli --generate-from-keys` (address, spend key, view key: 32-byte
//! little-endian hex, Monero's own encoding).

use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use monero_wallet::address::Network;
use rand_core::OsRng;

fn main() {
    let mut args = std::env::args().skip(1);
    let usage = "usage: xmr_keygen <stagenet|mainnet> <1Password item title>";
    let network = match args.next().expect(usage).as_str() {
        "stagenet" => Network::Stagenet,
        "mainnet" => Network::Mainnet,
        other => panic!("unknown network {other}; {usage}"),
    };
    let title = args.next().expect(usage);
    let spend = <Ed25519 as Ciphersuite>::F::random(&mut OsRng);
    let view = <Ed25519 as Ciphersuite>::F::random(&mut OsRng);
    let spend_pub: [u8; 32] = (Ed25519::generator() * spend).to_bytes();
    let view_secret: [u8; 32] = view.to_repr();
    let address = swap_chain_xmr::monero_chain::lock_address(spend_pub, view_secret, network)
        .expect("a fresh key pair is valid")
        .to_string();
    let net = format!("{network:?}").to_lowercase();
    let template = serde_json::json!({
        "title": title,
        "category": "PASSWORD",
        "fields": [
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD",
             "label": "password", "value": hex::encode(spend.to_repr())},
            {"id": "view_key", "type": "CONCEALED", "label": "view_key",
             "value": hex::encode(view_secret)},
            {"id": "address", "type": "STRING", "label": "address", "value": address},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
             "value": format!("Monero {net} wallet (atomic swap maker sweep target). password = private spend key, view_key = private view key; 32-byte little-endian hex. docs/plans/swap-poc/xmr-mainnet-plan.md A4")}
        ]
    });
    println!("{template}");
    eprintln!("{title}: {net} address={address}");
}
