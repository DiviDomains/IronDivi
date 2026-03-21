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

//! Consensus error types

use thiserror::Error;

/// Errors that can occur during consensus operations
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// Stake modifier not found
    #[error("stake modifier not found for block")]
    StakeModifierNotFound,

    /// Proof-of-stake hash does not meet target
    #[error("proof-of-stake hash does not meet target")]
    ProofOfStakeTargetNotMet,

    /// Minimum coin age not met for staking
    #[error("minimum coin age not met: required {required}s, got {actual}s")]
    MinimumCoinAgeNotMet { required: u32, actual: u32 },

    /// Hashproof timestamp violation (timestamp before coinstake time)
    #[error(
        "hashproof timestamp {hashproof_time} is before coinstake start time {coinstake_time}"
    )]
    TimestampViolation {
        hashproof_time: u32,
        coinstake_time: u32,
    },

    /// Block not found in chain
    #[error("block not found in chain: {0}")]
    BlockNotFound(String),

    /// Invalid coinstake transaction
    #[error("invalid coinstake transaction: {0}")]
    InvalidCoinstake(String),

    /// Invalid block header
    #[error("invalid block header: {0}")]
    InvalidHeader(String),

    /// Block time is too old
    #[error("block time too old")]
    BlockTimeTooOld,

    /// Block time is too far in the future
    #[error("block time too far in the future")]
    BlockTimeTooNew,

    /// Invalid proof-of-work
    #[error("invalid proof-of-work")]
    InvalidProofOfWork,

    /// Invalid proof-of-stake
    #[error("invalid proof-of-stake: {0}")]
    InvalidProofOfStake(String),

    /// Target overflow during multiplication
    #[error("target overflow during weighted calculation")]
    TargetOverflow,
}
