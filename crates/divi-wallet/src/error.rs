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

    /// A key record of the wallet could not be read: Divi Core's DB_CORRUPT
    /// (walletdb.cpp:495-503), refused at start (init.cpp:1153-1156)
    #[error("Error loading wallet.dat: Wallet corrupted")]
    Corrupt,

    /// No pre-generated key left to hand out while the wallet is locked
    #[error("keypool ran out")]
    KeypoolRanOut,

    /// Wrong passphrase
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// Wallet already encrypted
    #[error("wallet already encrypted")]
    AlreadyEncrypted,

    #[error("wallet encrypted and locked, but plaintext cleanup failed: {0}")]
    EncryptionCleanup(#[source] Box<WalletError>),

    /// The new passphrase is in effect on disk; taking the master key sealed
    /// under the old one out of the wallet files failed
    #[error("wallet passphrase changed, but cleanup of the old sealed key failed: {0}")]
    PassphraseChangeCleanup(#[source] Box<WalletError>),

    /// The passphrase change's write reported an error and whether it reached
    /// the disk cannot be told: the wallet opens with the old or the new one
    #[error("wallet passphrase change not confirmed on disk: {0}")]
    PassphraseChangeUnconfirmed(#[source] Box<WalletError>),

    /// A move of the wallet to the current record format reported an error
    /// and could not be read back, so the format its keys must be sealed in
    /// is not known: no key is written (and nothing that writes keys reports
    /// success) until the database can be read again
    #[error("wallet record format not confirmed on disk; keys are not written until the wallet database can be read")]
    RecordFormatUnconfirmed,

    /// Wallet not encrypted
    #[error("wallet not encrypted")]
    NotEncrypted,

    /// Wallet not encrypted (alias)
    #[error("wallet not encrypted")]
    WalletNotEncrypted,

    /// Invalid passphrase
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Wallet already loaded in manager
    #[error("wallet already loaded: {0}")]
    WalletAlreadyLoaded(String),

    /// Wallet file not found on disk
    #[error("wallet not found: {0}")]
    WalletNotFound(String),

    /// Wallet is not currently loaded in manager
    #[error("wallet not loaded: {0}")]
    WalletNotLoaded(String),

    /// Wallet file already exists on disk
    #[error("wallet already exists: {0}")]
    WalletAlreadyExists(String),

    /// No default wallet is currently loaded
    #[error("no default wallet loaded")]
    NoDefaultWallet,

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
