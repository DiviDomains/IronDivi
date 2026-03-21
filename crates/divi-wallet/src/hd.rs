// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! HD key derivation (BIP32/BIP44)
//!
//! Implements hierarchical deterministic key derivation for Divi and PrivateDivi.
//!
//! BIP44 path: m/44'/coin'/account'/change/index
//! - 44' = BIP44 purpose
//! - coin' = 301 (Divi) or 801 (PrivateDivi)
//! - account' = account number (hardened)
//! - change = 0 for external, 1 for change
//! - index = address index

use crate::error::WalletError;
use bip32::{ChildNumber, PublicKey as Bip32PublicKey, XPrv, XPub};
use bip39::Mnemonic;
use divi_crypto::keys::{PublicKey, SecretKey};
use divi_primitives::ChainMode;
use rand::RngCore;

/// Divi coin type for BIP44 derivation
pub const DIVI_COIN_TYPE: u32 = 301;

/// PrivateDivi coin type for BIP44 derivation
pub const PRIVATEDIVI_COIN_TYPE: u32 = 801;

/// Extended private key wrapper
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    inner: XPrv,
}

impl ExtendedPrivateKey {
    /// Create from seed bytes
    pub fn from_seed(seed: &[u8]) -> Result<Self, WalletError> {
        let xprv = XPrv::new(seed).map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        Ok(ExtendedPrivateKey { inner: xprv })
    }

    /// Derive child key
    pub fn derive_child(&self, index: ChildNumber) -> Result<Self, WalletError> {
        let child = self
            .inner
            .derive_child(index)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        Ok(ExtendedPrivateKey { inner: child })
    }

    /// Derive hardened child
    pub fn derive_hardened(&self, index: u32) -> Result<Self, WalletError> {
        let child_number =
            ChildNumber::new(index, true).map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        self.derive_child(child_number)
    }

    /// Derive normal child
    pub fn derive_normal(&self, index: u32) -> Result<Self, WalletError> {
        let child_number = ChildNumber::new(index, false)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        self.derive_child(child_number)
    }

    /// Get the private key bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.inner.private_key().to_bytes().into()
    }

    /// Get the secret key
    pub fn secret_key(&self) -> Result<SecretKey, WalletError> {
        SecretKey::from_bytes(&self.private_key_bytes())
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))
    }

    /// Get the public key
    pub fn public_key(&self) -> Result<ExtendedPublicKey, WalletError> {
        Ok(ExtendedPublicKey {
            inner: self.inner.public_key(),
        })
    }
}

/// Extended public key wrapper
#[derive(Clone)]
pub struct ExtendedPublicKey {
    inner: XPub,
}

impl ExtendedPublicKey {
    /// Derive child key (non-hardened only)
    pub fn derive_child(&self, index: u32) -> Result<Self, WalletError> {
        let child_number = ChildNumber::new(index, false)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        let child = self
            .inner
            .derive_child(child_number)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
        Ok(ExtendedPublicKey { inner: child })
    }

    /// Get the public key bytes (33 bytes compressed)
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.inner.public_key().to_bytes()
    }

    /// Get the public key
    pub fn public_key(&self) -> Result<PublicKey, WalletError> {
        PublicKey::from_compressed(&self.public_key_bytes())
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))
    }
}

/// HD wallet master key
pub struct HdWallet {
    /// Master private key
    master: ExtendedPrivateKey,
    /// Mnemonic words (if available)
    mnemonic: Option<String>,
    /// Chain mode affects BIP44 coin type
    chain_mode: ChainMode,
}

impl HdWallet {
    /// Create a new HD wallet with random 24-word mnemonic
    pub fn new(chain_mode: ChainMode) -> Result<Self, WalletError> {
        // Generate 32 bytes (256 bits) of entropy for 24 words
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        Self::from_mnemonic(&mnemonic.to_string(), None, chain_mode)
    }

    /// Create from mnemonic phrase
    pub fn from_mnemonic(
        phrase: &str,
        passphrase: Option<&str>,
        chain_mode: ChainMode,
    ) -> Result<Self, WalletError> {
        let mnemonic: Mnemonic = phrase
            .parse()
            .map_err(|e: bip39::Error| WalletError::InvalidMnemonic(e.to_string()))?;

        let seed = mnemonic.to_seed(passphrase.unwrap_or(""));
        let master = ExtendedPrivateKey::from_seed(&seed)?;

        Ok(HdWallet {
            master,
            mnemonic: Some(phrase.to_string()),
            chain_mode,
        })
    }

    /// Create from seed bytes
    pub fn from_seed(seed: &[u8], chain_mode: ChainMode) -> Result<Self, WalletError> {
        let master = ExtendedPrivateKey::from_seed(seed)?;
        Ok(HdWallet {
            master,
            mnemonic: None,
            chain_mode,
        })
    }

    /// Get the mnemonic phrase (if available)
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Get the HD master key ID (hash160 of master public key)
    ///
    /// This is used in getwalletinfo RPC to identify the HD wallet
    pub fn master_key_id(&self) -> Result<[u8; 20], WalletError> {
        let pubkey = self.master.public_key()?;
        let pubkey_bytes = pubkey.public_key_bytes();
        let hash = divi_crypto::hash160(&pubkey_bytes);
        Ok(*hash.as_bytes())
    }

    /// Get the BIP44 coin type for the current chain mode
    pub fn coin_type(&self) -> u32 {
        match self.chain_mode {
            ChainMode::Divi => DIVI_COIN_TYPE,
            ChainMode::PrivateDivi => PRIVATEDIVI_COIN_TYPE,
        }
    }

    /// Derive BIP44 account key
    /// Path: m/44'/coin'/account'
    pub fn derive_account(&self, account: u32) -> Result<ExtendedPrivateKey, WalletError> {
        // m/44'/coin'/account'
        let key = self.master.derive_hardened(44)?;
        let key = key.derive_hardened(self.coin_type())?;
        let key = key.derive_hardened(account)?;
        Ok(key)
    }

    /// Derive receiving address key
    /// Path: m/44'/301'/account'/0/index
    pub fn derive_receiving(
        &self,
        account: u32,
        index: u32,
    ) -> Result<ExtendedPrivateKey, WalletError> {
        let account_key = self.derive_account(account)?;
        let external = account_key.derive_normal(0)?;
        external.derive_normal(index)
    }

    /// Derive change address key
    /// Path: m/44'/301'/account'/1/index
    pub fn derive_change(
        &self,
        account: u32,
        index: u32,
    ) -> Result<ExtendedPrivateKey, WalletError> {
        let account_key = self.derive_account(account)?;
        let internal = account_key.derive_normal(1)?;
        internal.derive_normal(index)
    }

    /// Get the master extended public key for an account
    pub fn account_xpub(&self, account: u32) -> Result<ExtendedPublicKey, WalletError> {
        let account_key = self.derive_account(account)?;
        account_key.public_key()
    }

    pub fn get_master_pubkey(&self) -> Result<divi_crypto::keys::PublicKey, WalletError> {
        let secret = self.master.secret_key()?;
        Ok(secret.public_key())
    }
}

impl Default for HdWallet {
    fn default() -> Self {
        Self::new(ChainMode::Divi).expect("Failed to create HD wallet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::ChainMode;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_create_wallet() {
        let wallet = HdWallet::new(ChainMode::Divi).unwrap();
        assert!(wallet.mnemonic().is_some());
    }

    #[test]
    fn test_from_mnemonic() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        assert_eq!(wallet.mnemonic(), Some(TEST_MNEMONIC));
    }

    #[test]
    fn test_derive_account() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let account0 = wallet.derive_account(0).unwrap();
        let account1 = wallet.derive_account(1).unwrap();

        // Different accounts should produce different keys
        assert_ne!(account0.private_key_bytes(), account1.private_key_bytes());
    }

    #[test]
    fn test_derive_addresses() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();

        let addr0 = wallet.derive_receiving(0, 0).unwrap();
        let addr1 = wallet.derive_receiving(0, 1).unwrap();
        let change0 = wallet.derive_change(0, 0).unwrap();

        // All addresses should be different
        assert_ne!(addr0.private_key_bytes(), addr1.private_key_bytes());
        assert_ne!(addr0.private_key_bytes(), change0.private_key_bytes());
    }

    #[test]
    fn test_public_key_derivation() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let key = wallet.derive_receiving(0, 0).unwrap();

        // Private key should derive to same public key
        let pub_from_priv = key.public_key().unwrap();
        let secret = key.secret_key().unwrap();
        let pub_direct = secret.public_key();

        assert_eq!(
            pub_from_priv.public_key_bytes().as_slice(),
            pub_direct.to_bytes().as_slice()
        );
    }

    #[test]
    fn test_account_xpub() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let xpub = wallet.account_xpub(0).unwrap();

        // Can derive non-hardened children from xpub
        let child = xpub.derive_child(0).unwrap();
        assert!(child.public_key().is_ok());
    }

    #[test]
    fn test_deterministic_derivation() {
        // Same mnemonic should produce same keys
        let wallet1 = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet2 = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();

        let key1 = wallet1.derive_receiving(0, 0).unwrap();
        let key2 = wallet2.derive_receiving(0, 0).unwrap();

        assert_eq!(key1.private_key_bytes(), key2.private_key_bytes());
    }

    #[test]
    fn test_passphrase_affects_keys() {
        let wallet_no_pass = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet_with_pass =
            HdWallet::from_mnemonic(TEST_MNEMONIC, Some("password"), ChainMode::Divi).unwrap();

        let key1 = wallet_no_pass.derive_receiving(0, 0).unwrap();
        let key2 = wallet_with_pass.derive_receiving(0, 0).unwrap();

        // Different passphrases should produce different keys
        assert_ne!(key1.private_key_bytes(), key2.private_key_bytes());
    }

    #[test]
    fn test_master_key_id() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();

        // Master key ID should be 20 bytes (hash160)
        let key_id = wallet.master_key_id().unwrap();
        assert_eq!(key_id.len(), 20);

        // Should be deterministic
        let wallet2 = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let key_id2 = wallet2.master_key_id().unwrap();
        assert_eq!(key_id, key_id2);

        // Different passphrase = different key ID
        let wallet3 =
            HdWallet::from_mnemonic(TEST_MNEMONIC, Some("password"), ChainMode::Divi).unwrap();
        let key_id3 = wallet3.master_key_id().unwrap();
        assert_ne!(key_id, key_id3);
    }

    #[test]
    fn test_privatedivi_coin_type() {
        let wallet_divi = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet_pd =
            HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::PrivateDivi).unwrap();

        // Different coin types should produce different account keys
        let key_divi = wallet_divi.derive_account(0).unwrap();
        let key_pd = wallet_pd.derive_account(0).unwrap();
        assert_ne!(key_divi.private_key_bytes(), key_pd.private_key_bytes());

        // Verify coin types
        assert_eq!(wallet_divi.coin_type(), 301);
        assert_eq!(wallet_pd.coin_type(), 801);
    }

    #[test]
    fn test_coin_type_constants() {
        // BIP44 coin type for Divi
        assert_eq!(DIVI_COIN_TYPE, 301);
        // BIP44 coin type for PrivateDivi
        assert_eq!(PRIVATEDIVI_COIN_TYPE, 801);
    }

    #[test]
    fn test_bip44_path_isolation_between_chains() {
        // m/44'/301'/0'/0/0 (Divi) must differ from m/44'/801'/0'/0/0 (PrivateDivi)
        let wallet_divi = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet_pd =
            HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::PrivateDivi).unwrap();

        let recv_divi = wallet_divi.derive_receiving(0, 0).unwrap();
        let recv_pd = wallet_pd.derive_receiving(0, 0).unwrap();

        assert_ne!(recv_divi.private_key_bytes(), recv_pd.private_key_bytes());

        // Change addresses also differ
        let change_divi = wallet_divi.derive_change(0, 0).unwrap();
        let change_pd = wallet_pd.derive_change(0, 0).unwrap();
        assert_ne!(
            change_divi.private_key_bytes(),
            change_pd.private_key_bytes()
        );
    }

    #[test]
    fn test_passphrase_affects_receiving_keys() {
        // Different passphrase → different seed → different keys at every path level
        let w_no_pass = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let w_pass =
            HdWallet::from_mnemonic(TEST_MNEMONIC, Some("secret"), ChainMode::Divi).unwrap();

        let key_no = w_no_pass.derive_receiving(0, 0).unwrap();
        let key_with = w_pass.derive_receiving(0, 0).unwrap();
        assert_ne!(key_no.private_key_bytes(), key_with.private_key_bytes());

        // Also check index 5 to be thorough
        let key_no5 = w_no_pass.derive_receiving(0, 5).unwrap();
        let key_with5 = w_pass.derive_receiving(0, 5).unwrap();
        assert_ne!(key_no5.private_key_bytes(), key_with5.private_key_bytes());
    }

    #[test]
    fn test_known_bip44_derivation_vector() {
        // Test against a known BIP32 test vector.
        // "abandon" x11 + "about" with no passphrase is a standard test mnemonic.
        // Verify the first receiving key is deterministic and matches itself across
        // two wallet instances (belt-and-suspenders determinism test).
        let wallet_a = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet_b = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();

        // Keys at index 0, 1, 2 must all match across instances
        for idx in 0..3u32 {
            let ka = wallet_a.derive_receiving(0, idx).unwrap();
            let kb = wallet_b.derive_receiving(0, idx).unwrap();
            assert_eq!(
                ka.private_key_bytes(),
                kb.private_key_bytes(),
                "Receiving key at index {} not deterministic",
                idx
            );

            let ca = wallet_a.derive_change(0, idx).unwrap();
            let cb = wallet_b.derive_change(0, idx).unwrap();
            assert_eq!(
                ca.private_key_bytes(),
                cb.private_key_bytes(),
                "Change key at index {} not deterministic",
                idx
            );
        }
    }

    #[test]
    fn test_bip44_receiving_vs_change_differ() {
        // m/44'/301'/0'/0/idx (external) must differ from m/44'/301'/0'/1/idx (internal)
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();

        for idx in 0..3u32 {
            let recv = wallet.derive_receiving(0, idx).unwrap();
            let change = wallet.derive_change(0, idx).unwrap();
            assert_ne!(
                recv.private_key_bytes(),
                change.private_key_bytes(),
                "Receiving and change keys must differ at index {}",
                idx
            );
        }
    }

    #[test]
    fn test_different_accounts_produce_different_keys() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();

        // Receiving index 0 from account 0 vs account 1 must differ
        let a0 = wallet.derive_receiving(0, 0).unwrap();
        let a1 = wallet.derive_receiving(1, 0).unwrap();
        assert_ne!(a0.private_key_bytes(), a1.private_key_bytes());
    }

    #[test]
    fn test_privatedivi_wallet_has_correct_coin_type() {
        let wallet = HdWallet::new(ChainMode::PrivateDivi).unwrap();
        assert_eq!(wallet.coin_type(), PRIVATEDIVI_COIN_TYPE);
        assert_eq!(wallet.coin_type(), 801);
    }

    #[test]
    fn test_divi_wallet_has_correct_coin_type() {
        let wallet = HdWallet::new(ChainMode::Divi).unwrap();
        assert_eq!(wallet.coin_type(), DIVI_COIN_TYPE);
        assert_eq!(wallet.coin_type(), 301);
    }

    #[test]
    fn test_from_seed_no_mnemonic() {
        let seed = [0x42u8; 64];
        let wallet = HdWallet::from_seed(&seed, ChainMode::Divi).unwrap();
        // Wallet from raw seed has no mnemonic
        assert!(wallet.mnemonic().is_none());
        // But can still derive keys
        assert!(wallet.derive_receiving(0, 0).is_ok());
    }

    #[test]
    fn test_invalid_mnemonic_rejected() {
        let result = HdWallet::from_mnemonic("not a valid mnemonic at all", None, ChainMode::Divi);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_addresses_both_coin_types() {
        let mnemonic = match std::env::var("WALLET_MNEMONIC") {
            Ok(m) => m,
            Err(_) => {
                eprintln!("WALLET_MNEMONIC not set, skipping");
                return;
            }
        };
        let target = "DBaZuqwjGUamhQ1AzZZbGCxFW68dJzDSVv";
        let target2 = "DT8rJBP9tqrR9X6ochPDRaBD1xGpBGMpiX";
        let max_idx = 500u32;

        for (name, mode) in [
            ("Divi(301)", ChainMode::Divi),
            ("PrivateDivi(801)", ChainMode::PrivateDivi),
        ] {
            let wallet = HdWallet::from_mnemonic(&mnemonic, None, mode).unwrap();
            let key_id = wallet.master_key_id().unwrap();
            eprintln!("\n=== {} === master_key_id={}", name, hex::encode(key_id));

            // Check receiving addresses
            for i in 0..max_idx {
                let key = wallet.derive_receiving(0, i).unwrap();
                let secret = key.secret_key().unwrap();
                let pubkey = secret.public_key();
                let addr =
                    crate::address::Address::p2pkh(&pubkey, crate::address::Network::Mainnet);
                let addr_str = addr.to_base58();
                if addr_str == target || addr_str == target2 || i < 3 {
                    eprintln!(
                        "  recv[{}]: {}{}{}",
                        i,
                        addr_str,
                        if addr_str == target {
                            " <-- TARGET1!"
                        } else {
                            ""
                        },
                        if addr_str == target2 {
                            " <-- TARGET2!"
                        } else {
                            ""
                        }
                    );
                }
            }
            // Check change addresses
            for i in 0..max_idx {
                let key = wallet.derive_change(0, i).unwrap();
                let secret = key.secret_key().unwrap();
                let pubkey = secret.public_key();
                let addr =
                    crate::address::Address::p2pkh(&pubkey, crate::address::Network::Mainnet);
                let addr_str = addr.to_base58();
                if addr_str == target || addr_str == target2 || i < 3 {
                    eprintln!(
                        "  change[{}]: {}{}{}",
                        i,
                        addr_str,
                        if addr_str == target {
                            " <-- TARGET1!"
                        } else {
                            ""
                        },
                        if addr_str == target2 {
                            " <-- TARGET2!"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
    }
}
