// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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

/// A point where a test can stop the operation, as if the process died there
/// (see `fault`); nothing outside test builds
#[cfg(not(target_arch = "wasm32"))]
macro_rules! stop_point {
    ($point:expr) => {
        #[cfg(test)]
        crate::fault::check($point)?;
    };
}

pub mod address;
#[cfg(not(target_arch = "wasm32"))]
mod at_rest;
#[cfg(not(target_arch = "wasm32"))]
pub mod backup;
#[cfg(not(target_arch = "wasm32"))]
pub mod coin_selection;
#[cfg(not(target_arch = "wasm32"))]
pub mod coinstake;
pub mod error;
#[cfg(test)]
mod fault;
pub mod hd;
pub mod keystore;
#[cfg(not(target_arch = "wasm32"))]
pub mod manager;
#[cfg(not(target_arch = "wasm32"))]
pub mod persistence;
pub mod pq_sweep;
#[cfg(not(target_arch = "wasm32"))]
pub mod send;
pub mod signer;
#[cfg(not(target_arch = "wasm32"))]
pub mod wallet_db;

pub use address::{decode_wif, encode_wif, Address, AddressType, Network, WifKey};
#[cfg(not(target_arch = "wasm32"))]
pub use coin_selection::{CoinSelector, SelectionResult};
#[cfg(not(target_arch = "wasm32"))]
pub use coinstake::{
    classify_utxo_staking_posture, summarize_utxos_staking_posture, CoinstakeBuilder,
};
pub use divi_script::{
    classify_staking_script_posture, summarize_staking_posture, StakingQuantumPosture,
};
pub use error::WalletError;
pub use hd::{
    core_coin_type, derive_hardened_bip44_key, hardened_bip44_indices, ExtendedPrivateKey,
    ExtendedPublicKey, HardenedBip44Source, HdWallet, WalletKeyHygiene, BIP44_PURPOSE_HARDENED,
    BRANCH_EXTERNAL_HARDENED, BRANCH_INTERNAL_HARDENED, BRANCH_VAULT_MANAGER_HARDENED,
    BRANCH_VAULT_OWNER_HARDENED, DIVI_COIN_TYPE, HARDENED_INDEX_BIT,
};
pub use keystore::{HdPublicIds, KeyEntry, KeyStore, PoolState};
#[cfg(not(target_arch = "wasm32"))]
pub use manager::WalletManager;
#[cfg(not(target_arch = "wasm32"))]
pub use persistence::WalletDatabase;
pub use pq_sweep::{
    plan_voluntary_pq_sweep, PqSweepBatchTx, PqSweepDestination, PqSweepError, PqSweepPlan,
    PqSweepPlanConfig, QuantumExposureReason, SubThresholdVaultPolicy, TrackableWalletUtxo,
    DEFAULT_MAX_SWEEP_INPUTS_PER_TX, DEFAULT_MAX_SWEEP_TX_WEIGHT, DEFAULT_SWEEP_FEE_PER_KB_SAT,
    MIN_NON_DUST_OUTPUT_SAT, MIN_VAULT_SWEEP_OUTPUT_SAT,
};
pub use signer::{sighash, sign_input, TransactionBuilder, TransactionSigner};
#[cfg(not(target_arch = "wasm32"))]
pub use wallet_db::{
    DetachedTx, Ownership, TxListener, WalletDb, WalletTx, WalletUtxo, BACKUP_MARKER,
};
