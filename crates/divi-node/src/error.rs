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

//! Node error types

use thiserror::Error;

/// Node errors
#[derive(Debug, Error)]
pub enum NodeError {
    /// Storage error
    #[error("storage error: {0}")]
    Storage(#[from] divi_storage::StorageError),

    /// Network error
    #[error("network error: {0}")]
    Network(#[from] divi_network::NetworkError),

    /// RPC error
    #[error("RPC error: {0}")]
    Rpc(#[from] divi_rpc::Error),

    /// Wallet error
    #[error("wallet error: {0}")]
    Wallet(#[from] divi_wallet::WalletError),

    /// Consensus error
    #[error("consensus error: {0}")]
    Consensus(#[from] divi_consensus::ConsensusError),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Initialization error
    #[error("initialization error: {0}")]
    Init(String),

    /// Shutdown error
    #[error("shutdown error: {0}")]
    Shutdown(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Already running
    #[error("node is already running")]
    AlreadyRunning,

    /// Not running
    #[error("node is not running")]
    NotRunning,

    /// Block validation error
    #[error("block validation failed: {0}")]
    BlockValidation(String),

    /// Transaction validation error
    #[error("transaction validation failed: {0}")]
    TransactionValidation(String),
}
