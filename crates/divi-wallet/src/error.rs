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

//! Wallet error types

use thiserror::Error;

/// Wallet errors
#[derive(Debug, Error)]
pub enum WalletError {
    /// Key derivation error
    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    /// Invalid mnemonic
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Key not found
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Address not found
    #[error("address not found: {0}")]
    AddressNotFound(String),

    /// Invalid key
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Insufficient funds
    #[error("insufficient funds: need {need}, have {have}")]
    InsufficientFunds { need: i64, have: i64 },

    /// Transaction building error
    #[error("transaction error: {0}")]
    TransactionError(String),

    /// Wallet locked
    #[error("wallet is locked")]
    WalletLocked,

    /// Wrong passphrase
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// Wallet already encrypted
    #[error("wallet already encrypted")]
    AlreadyEncrypted,

    /// Wallet not encrypted
    #[error("wallet not encrypted")]
    NotEncrypted,

    /// Wallet not encrypted (alias)
    #[error("wallet not encrypted")]
    WalletNotEncrypted,

    /// Invalid passphrase
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Storage error
    #[error("storage error: {0}")]
    Storage(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
