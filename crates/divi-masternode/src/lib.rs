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

//! # Divi Masternode System
//!
//! This crate implements the Divi masternode system, including:
//! - Masternode registration and management
//! - Masternode tier system (COPPER, SILVER, GOLD, PLATINUM, DIAMOND)
//! - Masternode payment validation
//! - Masternode P2P synchronization protocol
//! - Masternode RPC commands
//!
//! ## Architecture
//!
//! The masternode system is built around several key components:
//!
//! - **Tier System**: Defines the 5 masternode tiers with their collateral requirements
//! - **Data Structures**: Core structs like `Masternode`, `MasternodeBroadcast`, `MasternodePing`
//! - **Manager**: Central registry for all masternodes with RocksDB persistence
//! - **Payment System**: Deterministic scoring algorithm for payment distribution
//! - **Sync Protocol**: P2P protocol for synchronizing masternode lists across nodes
//!
//! ## Consensus-Critical Warning
//!
//! The masternode system is **consensus-critical**. Any deviation from the C++ Divi
//! implementation will cause chain splits. Key consensus rules include:
//!
//! - Exact collateral amounts per tier
//! - 15 confirmation requirement for collateral
//! - Scoring algorithm hash rounds
//! - Payment percentage (60% post-fork)
//! - Message serialization format
//! - Signature verification
//!
//! All implementations must be validated against C++ Divi testnet data.

mod constants;
mod manager;
mod masternode;
mod payments;
mod relay;
mod rpc;
mod signature;
mod sync;
mod tier;

pub use constants::{
    MASTERNODE_PAYMENT_FORK_HEIGHT, MASTERNODE_PAYMENT_PERCENTAGE_POST_FORK,
    MASTERNODE_PAYMENT_PERCENTAGE_PRE_FORK,
};
pub use manager::{MasternodeError, MasternodeManager, Utxo, UtxoProvider};
pub use masternode::{
    Masternode, MasternodeBroadcast, MasternodePaymentWinner, MasternodePing, MasternodeStatus,
    ServiceAddr,
};
pub use payments::{
    calculate_block_subsidy, calculate_masternode_payment, calculate_score, find_payment_winner,
    get_expected_payment_winner, validate_block_payment, PaymentValidationError,
    PaymentVoteTracker,
};
pub use relay::{MessageValidator, RelayManager, ValidationError};
pub use rpc::{
    MasternodeCountResponse, MasternodeInfo, MasternodeListResponse, MasternodeRpc,
    MasternodeWinnerInfo,
};
pub use signature::{
    parse_pubkey, sign_broadcast, sign_ping, sign_winner, verify_broadcast_signature,
    verify_ping_signature, verify_winner_signature, SignatureError,
};
pub use sync::{
    MasternodeMessage, MasternodePaymentBlock, RequestMasternodeList, SyncAction, SyncStage,
    SyncStatus, SyncStatusCount, MESSAGE_DSEG, MESSAGE_MNB, MESSAGE_MNP, MESSAGE_MNW, MESSAGE_MNWB,
    MESSAGE_SSC,
};
pub use tier::{MasternodeTier, MASTERNODE_TIERS, TIER_INVALID};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_loads() {
        // Basic smoke test to ensure the module compiles
        assert_eq!(TIER_INVALID, MasternodeTier::Invalid);
    }
}
