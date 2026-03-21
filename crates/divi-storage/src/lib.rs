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

//! divi-storage - Chain storage and state management
//!
//! This crate provides persistent storage for the blockchain data including:
//! - Block storage
//! - Block index management
//! - UTXO set
//! - Chain state machine
//! - Address index (for lite wallet services)
//! - Chain export (for validation and cross-reference)

pub mod address_index;
pub mod block_index;
pub mod chain;
pub mod database;
pub mod difficulty;
pub mod error;
pub mod export;
pub mod fork_activation;
pub mod lottery;
pub mod masternode;
pub mod pos_validation;
pub mod rewards;
pub mod spent_index;
pub mod spork;
pub mod stake_modifier;
pub mod txindex;
pub mod undo;
pub mod utxo;
pub mod utxo_cache;

pub use address_index::{AddressHistoryEntry, AddressIndex, AddressUtxo, TxIndexEntry};
pub use block_index::{BlockIndex, BlockStatus};
pub use chain::{AcceptBlockResult, Chain, ChainParams, NetworkType};
pub use database::{ChainDatabase, UtxoStats};
pub use difficulty::{get_next_work_required, DifficultyParams};
pub use error::StorageError;
pub use export::{BlockExport, ExportManifest, TransactionExport};
pub use fork_activation::{ActivationState, Fork};
#[allow(deprecated)]
pub use lottery::calculate_winner_payout;
pub use lottery::{
    calculate_lottery_score, calculate_total_lottery_payout, compute_ranked_scores,
    get_minimum_lottery_ticket, is_coinstake_valid_for_lottery, select_lottery_winners,
    LotteryCoinstake, RankAwareScore, DEFAULT_LOTTERY_TICKET_MINIMUM, LOTTERY_VETO_CYCLES,
    LOTTERY_WINNER_COUNT,
};
pub use masternode::{
    get_hash_rounds_for_tier, tier_from_string, tier_to_string, MasternodeCollateral,
    MasternodeTier,
};
pub use pos_validation::{
    check_pos_time_requirements, compute_and_verify_proof_of_stake,
    validate_coinstake_inputs_same_script, validate_coinstake_transaction, StakingData, HASH_DRIFT,
};
#[allow(deprecated)]
pub use rewards::get_conservative_block_reward;
pub use rewards::{
    block_subsidy, get_block_rewards, get_charity_reward, get_lottery_reward, get_treasury_reward,
    is_lottery_block, is_treasury_block, BlockRewards, RewardParams,
};
pub use spent_index::{SpentIndex, SpentIndexKey, SpentIndexValue};
pub use spork::{
    spork_ids, BlockPaymentSpork, BlockSubsidySpork, LotteryTicketMinSpork, SporkManager,
    TxFeeSpork,
};
pub use stake_modifier::{
    compute_next_stake_modifier, get_stake_entropy_bit, get_stake_modifier_selection_interval,
    get_stake_modifier_selection_interval_section, MODIFIER_INTERVAL, MODIFIER_INTERVAL_RATIO,
};
pub use txindex::{TxIndex, TxLocation};
pub use utxo::Utxo;
pub use utxo_cache::{CacheStats, UtxoCache, DEFAULT_UTXO_CACHE_SIZE};
