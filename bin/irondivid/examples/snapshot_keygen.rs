// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Generate the snapshot root-signing key as a 1Password item template on **stdout**, for
//! piping straight into `op item create --vault global_secret_store -`. The secret is never
//! written to disk, argv or the terminal; stderr gets only the public key and the testnet and
//! mainnet P2PKH addresses. The same secret serves both networks (only the address prefix differs).
//!
//! Resolve later with `secret get --name <n> --op-ref "op://global_secret_store/<title>/password"`
//! (32-byte hex, the form `irondivid --sign-snapshot` reads on stdin).

use divi_crypto::keys::SecretKey;
use divi_wallet::address::{Address, Network};

fn main() {
    let title = std::env::args()
        .nth(1)
        .expect("usage: snapshot_keygen <1Password item title>");
    let sk = SecretKey::new_random();
    let pk = sk.public_key();
    let pubkey = pk.to_hex();
    let testnet = Address::p2pkh(&pk, Network::Testnet).to_base58();
    let mainnet = Address::p2pkh(&pk, Network::Mainnet).to_base58();
    let template = serde_json::json!({
        "title": title,
        "category": "PASSWORD",
        "fields": [
            {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD",
             "label": "password", "value": sk.to_hex()},
            {"id": "pubkey", "type": "STRING", "label": "pubkey", "value": pubkey},
            {"id": "divi_testnet_address", "type": "STRING",
             "label": "divi_testnet_address", "value": testnet},
            {"id": "divi_mainnet_address", "type": "STRING",
             "label": "divi_mainnet_address", "value": mainnet},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
             "value": "IronDivi snapshot root-signing key. 32-byte secp256k1 secret, hex, in the password field. Signs ROOT.sig via irondivid --sign-snapshot; importers pin the address."}
        ]
    });
    println!("{template}");
    eprintln!("{title}: pubkey={pubkey} testnet={testnet} mainnet={mainnet}");
}
