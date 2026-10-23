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

    /// The mempool refused a transaction, with Divi Core's reject code and
    /// reason (e.g. 64 "dust", 66 "insufficient fee") and the misbehaviour
    /// score Core's AcceptToMemoryPool records for it (`dos`)
    #[error("{code}: {reason}")]
    TxRejected { code: u8, reason: String, dos: u32 },

    /// A transaction spends a coin that is neither in the chain nor the mempool
    #[error("missing inputs")]
    MissingInputs,

    /// Transaction cannot be mined in the next block (Divi Core reject code 64)
    #[error("64: non-final")]
    NonFinal,
}

impl NodeError {
    /// A transaction a peer relayed was refused with this error: the
    /// misbehaviour score Divi Core gives that peer (the score its
    /// AcceptToMemoryPool records for ProcessMessage's `Misbehaving`).
    /// Most REJECT_INVALID refusals are 100 there (a CheckTransaction failure,
    /// coinbase or coinstake as a loose transaction, bad input values, value
    /// in below value out, a mandatory script failure), but an immature
    /// coinbase or coinstake spend is 0. Policy refusals (standardness, fee,
    /// non-final, non-mandatory script), conflicts, spent and missing inputs
    /// (an orphan) are 0.
    pub fn misbehaviour_score(&self) -> u32 {
        match self {
            NodeError::TxRejected { dos, .. } => *dos,
            _ => 0,
        }
    }

    /// A refusal with Core's reject code and reason; REJECT_INVALID scores 100,
    /// everything else 0
    pub fn rejected(code: u8, reason: impl Into<String>) -> Self {
        let dos = if code == reject::INVALID { 100 } else { 0 };
        NodeError::rejected_scored(code, reason, dos)
    }

    /// A refusal with an explicit misbehaviour score
    pub fn rejected_scored(code: u8, reason: impl Into<String>, dos: u32) -> Self {
        NodeError::TxRejected {
            code,
            reason: reason.into(),
            dos,
        }
    }
}

/// Divi Core reject codes (defaultValues.h)
pub mod reject {
    pub const INVALID: u8 = 0x10;
    pub const DUPLICATE: u8 = 0x12;
    pub const NONSTANDARD: u8 = 0x40;
    pub const INSUFFICIENT_FEE: u8 = 0x42;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_scores_follow_divi_core() {
        let rejected = |code, reason: &str| NodeError::rejected(code, reason);
        assert_eq!(
            rejected(reject::INVALID, "coinstake").misbehaviour_score(),
            100
        );
        assert_eq!(
            rejected(reject::INVALID, "mandatory-script-verify-flag-failed (x)")
                .misbehaviour_score(),
            100
        );
        assert_eq!(
            rejected(reject::NONSTANDARD, "dust").misbehaviour_score(),
            0
        );
        assert_eq!(
            rejected(reject::INSUFFICIENT_FEE, "insufficient fee").misbehaviour_score(),
            0
        );
        assert_eq!(NodeError::MissingInputs.misbehaviour_score(), 0);
        assert_eq!(NodeError::NonFinal.misbehaviour_score(), 0);
    }
}
