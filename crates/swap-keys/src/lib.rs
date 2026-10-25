// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Swap keys for DIVI, BTC and LTC from the IronDivi extension's one recovery phrase.
//!
//! The extension turns the phrase into the 64-byte BIP39 seed (it already does, for its
//! DIVI addresses) and hands the seed to the taker in memory. Deriving here, rather than
//! in the extension, keeps every swap key in one place the tests below pin down; taking
//! the seed, rather than the phrase, keeps the extension's wordlist languages out of it.
//!
//! | chain | path                        | address | backend                     |
//! |-------|-----------------------------|---------|-----------------------------|
//! | DIVI  | `m/44'/{301,1}'/0'/0/i`     | P2PKH   | `swap_chain_divi::DiviBackend` |
//! | BTC   | `m/84'/{0,1}'/0'/0/i`       | P2WPKH  | `swap_chain_btc::BtcBackend`   |
//! | LTC   | `m/84'/{2,1}'/0'/0/i`       | P2WPKH  | `swap_chain_ltc::LtcBackend`   |
//!
//! (mainnet coin type first, testnet second.) The DIVI path is the one the extension uses,
//! so the DIVI swap address is an address the extension already shows. BTC and LTC use
//! plain BIP84, so if the extension is lost, the phrase imported into any standard wallet
//! (Electrum, Sparrow, Electrum-LTC) holds the same keys and can still sign a refund.
//!
//! On testnet BTC (signet) and LTC both use coin type 1 under purpose 84, so they get the
//! **same key**. That is what every BIP84 wallet does and is deliberate here; on mainnet
//! the coin types differ and so do the keys.

use divi_wallet::ExtendedPrivateKey;
use zeroize::Zeroizing;

/// Which coin types to derive under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    /// DIVI mainnet, BTC mainnet, LTC mainnet.
    Mainnet,
    /// DIVI testnet, BTC signet, LTC testnet.
    Testnet,
}

impl Net {
    fn coin_types(self) -> (u32, u32, u32) {
        match self {
            Net::Mainnet => (divi_wallet::DIVI_COIN_TYPE, 0, 2),
            Net::Testnet => (1, 1, 1),
        }
    }
}

/// Key derivation failed.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("seed must be 16 to 64 bytes, got {0}")]
    SeedLength(usize),
    #[error("key derivation: {0}")]
    Derive(String),
}

/// One swap's keys, all from the same seed and address index.
pub struct SwapKeys {
    pub divi: divi_crypto::keys::SecretKey,
    pub btc: bitcoin::secp256k1::SecretKey,
    pub ltc: bitcoin::secp256k1::SecretKey,
}

impl Drop for SwapKeys {
    fn drop(&mut self) {
        // `divi` wipes itself. The secp256k1 keys are `Copy`, so this is best effort: it
        // clears these copies, not ones already handed to a backend.
        self.btc.non_secure_erase();
        self.ltc.non_secure_erase();
    }
}

impl SwapKeys {
    /// Derive the keys at address `index` from a BIP39 `seed`.
    pub fn from_seed(seed: &[u8], net: Net, index: u32) -> Result<Self, KeyError> {
        // BIP32 allows 128 to 512 bit seeds; BIP39 seeds are always 512.
        if !(16..=64).contains(&seed.len()) {
            return Err(KeyError::SeedLength(seed.len()));
        }
        let master = ExtendedPrivateKey::from_seed(seed).map_err(derive_err)?;
        let (divi_coin, btc_coin, ltc_coin) = net.coin_types();

        let divi = path_key(&master, 44, divi_coin, index)?;
        let btc = path_key(&master, 84, btc_coin, index)?;
        let ltc = path_key(&master, 84, ltc_coin, index)?;
        Ok(Self {
            divi: divi_crypto::keys::SecretKey::from_bytes(&divi[..]).map_err(derive_err)?,
            btc: bitcoin::secp256k1::SecretKey::from_slice(&btc[..]).map_err(derive_err)?,
            ltc: bitcoin::secp256k1::SecretKey::from_slice(&ltc[..]).map_err(derive_err)?,
        })
    }
}

/// Private key bytes at `m/purpose'/coin'/0'/0/index`.
fn path_key(
    master: &ExtendedPrivateKey,
    purpose: u32,
    coin: u32,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let key = master
        .derive_hardened(purpose)
        .and_then(|k| k.derive_hardened(coin))
        .and_then(|k| k.derive_hardened(0))
        .and_then(|k| k.derive_normal(0))
        .and_then(|k| k.derive_normal(index))
        .map_err(derive_err)?;
    Ok(Zeroizing::new(key.private_key_bytes()))
}

fn derive_err(e: impl std::fmt::Display) -> KeyError {
    KeyError::Derive(e.to_string())
}

#[cfg(test)]
mod tests;
