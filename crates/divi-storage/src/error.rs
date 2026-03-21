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

//! Storage error types

use thiserror::Error;

/// Errors that can occur during storage operations
#[derive(Debug, Error)]
pub enum StorageError {
    /// RocksDB error
    #[error("database error: {0}")]
    Database(#[from] rocksdb::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// Key not found
    #[error("key not found: {0}")]
    NotFound(String),

    /// Block not found
    #[error("block not found: {0}")]
    BlockNotFound(String),

    /// Invalid block
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// Orphan block (parent not found)
    #[error("orphan block: parent {0} not found")]
    OrphanBlock(String),

    /// UTXO not found
    #[error("UTXO not found: {0}")]
    UtxoNotFound(String),

    /// Double spend detected
    #[error("double spend detected: {0}")]
    DoubleSpend(String),

    /// Chain state error
    #[error("chain state error: {0}")]
    ChainState(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid parameter
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

impl From<divi_primitives::error::Error> for StorageError {
    fn from(e: divi_primitives::error::Error) -> Self {
        StorageError::Serialization(e.to_string())
    }
}
