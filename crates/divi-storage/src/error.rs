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

    /// Snapshot export or import refused or failed
    #[error("snapshot: {0}")]
    Snapshot(String),

    /// Key not found
    #[error("key not found: {0}")]
    NotFound(String),

    /// Block not found
    #[error("block not found: {0}")]
    BlockNotFound(String),

    /// Invalid block
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// A consensus failure that Divi Core scores other than 100 against the
    /// peer that relayed the block (see [`StorageError::misbehaviour_score`])
    #[error("invalid block: {reason}")]
    InvalidBlockScored { score: u32, reason: String },

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

    /// A database irondivid did not make (such as Divi Core's LevelDB chainstate)
    #[error("{0}")]
    NotIronDivi(String),

    /// A chain database made for another network
    #[error("{0}")]
    WrongNetwork(String),
}

impl From<divi_primitives::error::Error> for StorageError {
    fn from(e: divi_primitives::error::Error) -> Self {
        StorageError::Serialization(e.to_string())
    }
}

impl StorageError {
    /// A block refused with this error: the misbehaviour score Divi Core
    /// gives the peer that relayed it (the score CheckBlock, AcceptBlock and
    /// ConnectBlock record). Plain consensus failures are 100; failures that
    /// Core records with score 0 or without a state (proof of
    /// stake, block signature, payments, timestamps) score what Core gives
    /// them; an orphan and local storage errors score 0.
    pub fn misbehaviour_score(&self) -> u32 {
        match self {
            StorageError::InvalidBlock(_)
            | StorageError::UtxoNotFound(_)
            | StorageError::DoubleSpend(_) => 100,
            StorageError::InvalidBlockScored { score, .. } => *score,
            _ => 0,
        }
    }

    /// A consensus failure Divi Core scores `score`
    pub fn invalid_block_scored(score: u32, reason: String) -> Self {
        StorageError::InvalidBlockScored { score, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misbehaviour_scores_follow_divi_core() {
        assert_eq!(
            StorageError::InvalidBlock("merkle".into()).misbehaviour_score(),
            100
        );
        assert_eq!(
            StorageError::UtxoNotFound("x".into()).misbehaviour_score(),
            100
        );
        assert_eq!(
            StorageError::invalid_block_scored(10, "non-final".into()).misbehaviour_score(),
            10
        );
        assert_eq!(
            StorageError::invalid_block_scored(0, "future".into()).misbehaviour_score(),
            0
        );
        assert_eq!(
            StorageError::OrphanBlock("p".into()).misbehaviour_score(),
            0
        );
        assert_eq!(
            StorageError::ChainState("db".into()).misbehaviour_score(),
            0
        );
        // Same text either way
        assert_eq!(
            StorageError::invalid_block_scored(0, "x".into()).to_string(),
            StorageError::InvalidBlock("x".into()).to_string()
        );
    }
}
