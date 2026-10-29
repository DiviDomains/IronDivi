// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

use super::*;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};

/// The public BIP39/BIP84 test phrase. It holds no funds.
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> [u8; 64] {
    let m: bip39::Mnemonic = PHRASE.parse().unwrap();
    m.to_seed("")
}

fn divi_address(k: &SwapKeys, net: divi_wallet::Network) -> String {
    divi_wallet::Address::p2pkh(&k.divi.public_key(), net).to_string()
}

fn btc_address(key: &bitcoin::secp256k1::SecretKey, net: Network) -> String {
    let pk = CompressedPublicKey(key.public_key(&Secp256k1::new()));
    Address::p2wpkh(&pk, net).to_string()
}

#[test]
fn seed_matches_the_extension() {
    // What the extension's `Mnemonic.toSeed` prints for PHRASE (and the BIP39 vector).
    assert_eq!(
        hex::encode(seed()),
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
         9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    );
}

#[test]
fn divi_addresses_match_the_extension() {
    // From the extension's own `deriveAddresses(seed, net, 0, 3)` on 2026-10-25.
    let cases = [
        (
            Net::Mainnet,
            divi_wallet::Network::Mainnet,
            0,
            "DHnrKW52thFXkbftiAFNnmCjP176vkWnRK",
        ),
        (
            Net::Mainnet,
            divi_wallet::Network::Mainnet,
            1,
            "DJ4qwYGSW9oK5PardNcTXpZvD8KQU5B95J",
        ),
        (
            Net::Mainnet,
            divi_wallet::Network::Mainnet,
            2,
            "DCunwbUqP4Fa6LDdtRpYJVF2XqGfMLeo1e",
        ),
        (
            Net::Testnet,
            divi_wallet::Network::Testnet,
            0,
            "y2HTGbENn5pf1SmUVy3RsjPRWmEnKDCfSU",
        ),
        (
            Net::Testnet,
            divi_wallet::Network::Testnet,
            1,
            "yGHV5cwYHozU2reKzXVjEbGk4asE1ECG9t",
        ),
        (
            Net::Testnet,
            divi_wallet::Network::Testnet,
            2,
            "y3veXjipa15zmhkfKAwKUDh7h6csqHtRBj",
        ),
    ];
    for (net, addr_net, index, want) in cases {
        let k = SwapKeys::from_seed(&seed(), net, index).unwrap();
        assert_eq!(divi_address(&k, addr_net), want, "{net:?} {index}");
    }
}

#[test]
fn btc_mainnet_matches_the_bip84_vectors() {
    // BIP84 test vectors, m/84'/0'/0'/0/0 and /1.
    let k0 = SwapKeys::from_seed(&seed(), Net::Mainnet, 0).unwrap();
    let k1 = SwapKeys::from_seed(&seed(), Net::Mainnet, 1).unwrap();
    assert_eq!(
        btc_address(&k0.btc, Network::Bitcoin),
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    );
    assert_eq!(
        btc_address(&k1.btc, Network::Bitcoin),
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
    );
}

#[test]
fn every_chain_and_index_gets_its_own_key_on_mainnet() {
    let a = SwapKeys::from_seed(&seed(), Net::Mainnet, 0).unwrap();
    let b = SwapKeys::from_seed(&seed(), Net::Mainnet, 1).unwrap();
    assert_ne!(a.btc, a.ltc);
    assert_ne!(a.divi.as_bytes(), &a.btc.secret_bytes()[..]);
    assert_ne!(a.divi.as_bytes(), &a.ltc.secret_bytes()[..]);
    assert_ne!(a.btc, b.btc);
    assert_ne!(a.divi.as_bytes(), b.divi.as_bytes());
}

#[test]
fn testnet_btc_and_ltc_share_coin_type_1() {
    // Deliberate: standard BIP84 wallets do the same (see the crate docs).
    let k = SwapKeys::from_seed(&seed(), Net::Testnet, 0).unwrap();
    assert_eq!(k.btc, k.ltc);
    assert_ne!(k.divi.as_bytes(), &k.btc.secret_bytes()[..]);
    let main = SwapKeys::from_seed(&seed(), Net::Mainnet, 0).unwrap();
    assert_ne!(k.btc, main.btc);
}

#[test]
fn the_divi_backend_funds_from_the_extensions_address() {
    let k = SwapKeys::from_seed(&seed(), Net::Testnet, 0).unwrap();
    let backend = swap_chain_divi::DiviBackend::new(
        "http://127.0.0.1:1/",
        k.divi.clone(),
        divi_wallet::Network::Testnet,
        swap_chain_divi::FeePolicy::default(),
        None,
    )
    .unwrap();
    assert_eq!(backend.address(), "y2HTGbENn5pf1SmUVy3RsjPRWmEnKDCfSU");
}

#[test]
fn the_ltc_backend_uses_the_ltc_key() {
    let k = SwapKeys::from_seed(&seed(), Net::Mainnet, 0).unwrap();
    let backend = swap_chain_ltc::LtcBackend::new(
        vec!["http://127.0.0.1:1".into()],
        k.ltc,
        swap_chain_ltc::FeePolicy::default(),
        swap_chain_ltc::RetryPolicy::default(),
    )
    .unwrap();
    let pk = CompressedPublicKey(k.ltc.public_key(&Secp256k1::new()));
    let want =
        swap_chain_ltc::encode_segwit_v0(swap_chain_ltc::TLTC_HRP, pk.wpubkey_hash().as_ref())
            .unwrap();
    assert_eq!(backend.address(), want);
}

#[test]
fn bad_seed_lengths_are_refused() {
    for len in [0, 15, 65] {
        assert!(matches!(
            SwapKeys::from_seed(&vec![7; len], Net::Mainnet, 0),
            Err(KeyError::SeedLength(n)) if n == len
        ));
    }
}

#[test]
fn derivation_is_deterministic() {
    let a = SwapKeys::from_seed(&seed(), Net::Testnet, 5).unwrap();
    let b = SwapKeys::from_seed(&seed(), Net::Testnet, 5).unwrap();
    assert_eq!(a.divi.as_bytes(), b.divi.as_bytes());
    assert_eq!(a.btc, b.btc);
}
