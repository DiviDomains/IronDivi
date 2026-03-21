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

//! divi-wallet - HD wallet and key management
//!
//! This crate provides wallet functionality for Divi including:
//! - BIP32/BIP44 HD key derivation
//! - Address generation and encoding
//! - Key storage and management
//!
//! # Example
//!
//! ```
//! use divi_wallet::{HdWallet, KeyStore, Network};
//! use divi_primitives::ChainMode;
//!
//! // Create a new HD wallet
//! let wallet = HdWallet::new(ChainMode::Divi).unwrap();
//! assert!(wallet.mnemonic().is_some());
//!
//! // Create keystore with HD wallet
//! let store = KeyStore::with_hd_wallet(Network::Mainnet, wallet);
//!
//! // Generate receiving addresses
//! let addr1 = store.new_receiving_address().unwrap();
//! let addr2 = store.new_receiving_address().unwrap();
//!
//! // Addresses should be different
//! assert_ne!(addr1.to_string(), addr2.to_string());
//! ```

pub mod address;
pub mod coin_selection;
pub mod coinstake;
pub mod error;
pub mod hd;
pub mod keystore;
pub mod persistence;
pub mod signer;
pub mod wallet_db;

pub use address::{decode_wif, encode_wif, Address, AddressType, Network, WifKey};
pub use coin_selection::{CoinSelector, SelectionResult};
pub use coinstake::CoinstakeBuilder;
pub use error::WalletError;
pub use hd::{ExtendedPrivateKey, ExtendedPublicKey, HdWallet, DIVI_COIN_TYPE};
pub use keystore::{KeyEntry, KeyStore};
pub use persistence::WalletDatabase;
pub use signer::{sighash, sign_input, TransactionBuilder, TransactionSigner};
pub use wallet_db::{WalletDb, WalletTx, WalletUtxo};
