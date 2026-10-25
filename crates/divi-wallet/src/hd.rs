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
use zeroize::Zeroizing;

/// Divi coin type for BIP44 derivation
pub const DIVI_COIN_TYPE: u32 = 301;

/// PrivateDivi coin type for BIP44 derivation
pub const PRIVATEDIVI_COIN_TYPE: u32 = 801;

/// Coin type Divi Core derives with on testnet and regtest
pub const TEST_COIN_TYPE: u32 = 1;

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
    mnemonic: Option<Zeroizing<String>>,
    /// BIP39 passphrase the seed was made with (Divi Core's -mnemonicpassphrase)
    passphrase: Option<Zeroizing<String>>,
    /// Chain mode affects BIP44 coin type
    chain_mode: ChainMode,
    /// BIP44 coin type of the derivation path
    coin_type: u32,
    /// The seed of a wallet made from a seed rather than words (Divi Core's
    /// -hdseed); a mnemonic wallet's seed comes from its words
    seed: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl HdWallet {
    /// Create a new HD wallet with random 24-word mnemonic
    pub fn new(chain_mode: ChainMode) -> Result<Self, WalletError> {
        Self::generate(None, chain_mode)
    }

    /// Create a new HD wallet with a random 24-word mnemonic and the BIP39
    /// `passphrase`, as Divi Core makes new words for -mnemonicpassphrase
    /// without -mnemonic (hdchain.cpp:56-67)
    pub fn generate(passphrase: Option<&str>, chain_mode: ChainMode) -> Result<Self, WalletError> {
        // Generate 32 bytes (256 bits) of entropy for 24 words
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut entropy[..]);

        let mnemonic = Mnemonic::from_entropy(&entropy[..])
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        let phrase = Zeroizing::new(mnemonic.to_string());
        Self::from_mnemonic(&phrase, passphrase, chain_mode)
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

        let seed = Zeroizing::new(mnemonic.to_seed(passphrase.unwrap_or("")));
        let master = ExtendedPrivateKey::from_seed(&seed[..])?;

        Ok(HdWallet {
            master,
            mnemonic: Some(Zeroizing::new(phrase.to_string())),
            passphrase: passphrase
                .filter(|p| !p.is_empty())
                .map(|p| Zeroizing::new(p.to_string())),
            chain_mode,
            coin_type: legacy_coin_type(chain_mode),
            seed: None,
        })
    }

    /// Create from seed bytes
    pub fn from_seed(seed: &[u8], chain_mode: ChainMode) -> Result<Self, WalletError> {
        let master = ExtendedPrivateKey::from_seed(seed)?;
        Ok(HdWallet {
            master,
            mnemonic: None,
            passphrase: None,
            chain_mode,
            coin_type: legacy_coin_type(chain_mode),
            seed: Some(zeroize::Zeroizing::new(seed.to_vec())),
        })
    }

    /// Derive with another BIP44 coin type (see `core_coin_type`)
    pub fn with_coin_type(mut self, coin_type: u32) -> Self {
        self.coin_type = coin_type;
        self
    }

    /// Get the mnemonic phrase (if available)
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_ref().map(|m| m.as_str())
    }

    /// The seed of a wallet made from a seed (no words)
    pub fn seed(&self) -> Option<&[u8]> {
        self.seed.as_ref().map(|s| s.as_slice())
    }

    /// Divi Core's HD chain id: the double SHA-256 of the seed, the BIP39
    /// seed of the words for a mnemonic wallet (hdchain.cpp:116-119)
    pub fn seed_hash(&self) -> Option<[u8; 32]> {
        if let Some(seed) = self.seed() {
            return Some(divi_crypto::double_sha256(seed));
        }
        let mnemonic: Mnemonic = self.mnemonic.as_deref()?.parse().ok()?;
        let seed =
            zeroize::Zeroizing::new(mnemonic.to_seed(self.mnemonic_passphrase().unwrap_or("")));
        Some(divi_crypto::double_sha256(seed.as_slice()))
    }

    /// Path of the account the wallet's keys derive from, m/44'/coin'/0'
    /// (Divi Core hdchain.cpp:121-145; keys are .../change/index)
    pub fn account_path(&self) -> String {
        format!("m/44'/{}'/0'", self.coin_type)
    }

    /// The BIP39 passphrase of the seed, if one was given
    pub fn mnemonic_passphrase(&self) -> Option<&str> {
        self.passphrase.as_ref().map(|p| p.as_str())
    }

    /// The chain mode the wallet was made for
    pub fn chain_mode(&self) -> ChainMode {
        self.chain_mode
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

    /// The BIP44 coin type of the derivation path
    pub fn coin_type(&self) -> u32 {
        self.coin_type
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

/// Coin type of wallets made before the coin type was stored: the chain mode's
fn legacy_coin_type(chain_mode: ChainMode) -> u32 {
    match chain_mode {
        ChainMode::Divi => DIVI_COIN_TYPE,
        ChainMode::PrivateDivi => PRIVATEDIVI_COIN_TYPE,
    }
}

/// BIP44 coin type Divi Core derives with: 301 on mainnet and 1 on testnet and
/// regtest (chainparams.cpp nExtCoinType). PrivateDivi keeps its own.
pub fn core_coin_type(chain_mode: ChainMode, mainnet: bool) -> u32 {
    match chain_mode {
        ChainMode::Divi if !mainnet => TEST_COIN_TYPE,
        mode => legacy_coin_type(mode),
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

    /// BIP32 test vector 1 (seed 000102...0f), chain m/0'/1/2'/2/1000000000.
    /// Pins derivation to the spec so a bip32 crate upgrade cannot change keys.
    #[test]
    fn test_bip32_official_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut key = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let chain: [(Option<(u32, bool)>, &str, &str); 6] = [
            (
                None,
                "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            ),
            (
                Some((0, true)),
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
            ),
            (
                Some((1, false)),
                "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
            ),
            (
                Some((2, true)),
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
            ),
            (
                Some((2, false)),
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
            ),
            (
                Some((1_000_000_000, false)),
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
            ),
        ];
        for (step, want_priv, want_pub) in chain {
            if let Some((index, hardened)) = step {
                key = if hardened {
                    key.derive_hardened(index).unwrap()
                } else {
                    key.derive_normal(index).unwrap()
                };
            }
            assert_eq!(hex::encode(key.private_key_bytes()), want_priv);
            assert_eq!(
                hex::encode(key.public_key().unwrap().public_key_bytes()),
                want_pub
            );
        }
    }

    /// Fixed IronDivi BIP44 vectors for the public "abandon ... about" test
    /// mnemonic, captured from the bip32 0.5 implementation. Existing seeds
    /// must keep producing these exact keys and addresses.
    #[test]
    fn test_bip44_wallet_vectors_unchanged() {
        // (mode, [(label, account, change, index, priv, pub, addr)], xpub recv0)
        let cases = [
            (
                ChainMode::Divi,
                [
                    (
                        "recv0",
                        0,
                        false,
                        0,
                        "5098ec92f7bf700cfd07820c57099ebd389ccaac4acc3b3cbfffc4fe1b4372cd",
                        "0339c817aa28e7f241cd2bbd8132f7ef99b8e34ccdd8ce2dfa1ba6d1b240b7b13b",
                        "DHnrKW52thFXkbftiAFNnmCjP176vkWnRK",
                    ),
                    (
                        "recv1",
                        0,
                        false,
                        1,
                        "0cf2ef35e19fc03a1354f22ccf03df9a80c84a32f6bf59c85c970fdc439635ce",
                        "03ea6a3be5755588bbcf9a51a1d9615a5daf15a4de2b765dd9082b07c4bdb58709",
                        "DJ4qwYGSW9oK5PardNcTXpZvD8KQU5B95J",
                    ),
                    (
                        "change0",
                        0,
                        true,
                        0,
                        "0c2c59b4ff6f5b8c29cd81785dc9793171396c6458639721e05fc4cf270081d4",
                        "026b03522a13b3682395a0e348df38cebb5447fc2dba8d5636946873fdd30965e1",
                        "DJGuMSV47x27kgS5bCB9DoDf6f3RpbNLeZ",
                    ),
                    (
                        "acct1recv0",
                        1,
                        false,
                        0,
                        "12f26dce097e13ed67297679cdc650bdb851bd02d0095627318aa4c2789558d6",
                        "0350bc0055ead7235276c598498600de508b13c591861ffe5d25ed0281208fa481",
                        "DF5J5ibvr1cmET3VtRM11cQfpGRAunPi1i",
                    ),
                ],
            ),
            (
                ChainMode::PrivateDivi,
                [
                    (
                        "recv0",
                        0,
                        false,
                        0,
                        "e1c4743dd7347a0815aa2b22842feae2571a04f8a4e134c79e0e9c6a307f830d",
                        "022ce0b67078c625b3c9120160ce0875d16870ec8074c0d99aafc27fd050da8b9a",
                        "DTGLN7tK8eTCWz5u7KFgpjT1Nq6uN3pwph",
                    ),
                    (
                        "recv1",
                        0,
                        false,
                        1,
                        "aa88feaa3b71f468681cdf3687a517ee34cf836e946bba9b36660a128a2fbad3",
                        "03d8d51ba80f6bd0a8c9c266a6bca735714f04f086e4662100cae38ca1dffea0df",
                        "DHqM3Zs5VitRTxcmpy4nEX2WWeR2akKPNU",
                    ),
                    (
                        "change0",
                        0,
                        true,
                        0,
                        "272e8340bce0903f34675990a9717213eeefc80b94286992d8802e8564d9b042",
                        "0316093f7bbb2f1f8fa9db99849d023398b84f740cf01c426508c5f4923adcd745",
                        "DK4GbMoL2khebryi4SyMXS3Zt8oTKRPWVS",
                    ),
                    (
                        "acct1recv0",
                        1,
                        false,
                        0,
                        "3f7f0ed7ecea93d359e9e5ff2662b882d7ac795c0ec69f5fa9cba66a153abea7",
                        "03c23c2dac0cce28de6d2363070d4840fb8d823cd2fe82b8a3617cfd7abcc03d27",
                        "DP6um8GjjFhAMEpUizb6WoM1nVJp2E2teY",
                    ),
                ],
            ),
        ];
        for (mode, keys) in cases {
            let w = HdWallet::from_mnemonic(TEST_MNEMONIC, None, mode).unwrap();
            // BIP32 fingerprint of this mnemonic's master key is 73c5da0a.
            assert_eq!(
                hex::encode(w.master_key_id().unwrap()),
                "73c5da0a03d2d0803b731f04242bb40ced2f8bbc"
            );
            for (label, account, change, index, want_priv, want_pub, want_addr) in keys {
                let k = if change {
                    w.derive_change(account, index).unwrap()
                } else {
                    w.derive_receiving(account, index).unwrap()
                };
                assert_eq!(
                    hex::encode(k.private_key_bytes()),
                    want_priv,
                    "{mode:?} {label}"
                );
                assert_eq!(
                    hex::encode(k.public_key().unwrap().public_key_bytes()),
                    want_pub,
                    "{mode:?} {label}"
                );
                let pk = k.secret_key().unwrap().public_key();
                let addr = crate::address::Address::p2pkh(&pk, crate::address::Network::Mainnet);
                assert_eq!(addr.to_base58(), want_addr, "{mode:?} {label}");
            }
            // Public-only derivation from the account xpub must agree.
            let xpub = w
                .account_xpub(0)
                .unwrap()
                .derive_child(0)
                .unwrap()
                .derive_child(0)
                .unwrap();
            assert_eq!(
                hex::encode(xpub.public_key_bytes()),
                keys[0].5,
                "{mode:?} xpub"
            );
        }
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
