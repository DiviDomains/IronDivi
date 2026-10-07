// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Generate one swap engine key as a 1Password item template on **stdout**, for piping
//! straight into `op item create --vault global_secret_store -`. The secret never touches
//! disk, argv or the terminal; stderr gets only the public key and DIVI testnet address.
//!
//! ```sh
//! cargo run -q -p swap-chain-divi --example keygen -- "IronDivi Swap POC - maker-divi" \
//!   | op item create --vault global_secret_store - >/dev/null
//! ```
//! Resolve later with `op read "op://global_secret_store/<title>/password"` (32-byte hex).

use divi_crypto::keys::SecretKey;
use divi_wallet::address::{Address, Network};

fn main() {
    let title = std::env::args()
        .nth(1)
        .expect("usage: keygen <1Password item title>");
    let sk = SecretKey::new_random();
    let pk = sk.public_key();
    let pubkey = pk.to_hex();
    let addr = Address::p2pkh(&pk, Network::Testnet).to_base58();
    let template = serde_json::json!({
        "title": title,
        "category": "PASSWORD",
        "fields": [
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD",
             "label": "password", "value": sk.to_hex()},
            {"id": "pubkey", "type": "STRING", "label": "pubkey", "value": pubkey},
            {"id": "divi_testnet_address", "type": "STRING",
             "label": "divi_testnet_address", "value": addr},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
             "value": "Atomic swap POC engine key (testnet only). 32-byte secp256k1 secret, hex. docs/plans/atomic-swap-poc.md"}
        ]
    });
    println!("{template}");
    eprintln!("{title}: pubkey={pubkey} divi_testnet={addr}");
}
