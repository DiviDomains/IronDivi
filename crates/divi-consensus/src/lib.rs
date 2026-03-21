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

//! Divi Consensus
//!
//! This crate implements the consensus rules for Divi, including
//! proof-of-stake validation, block validation, and difficulty adjustment.
//!
//! # Proof-of-Stake
//!
//! Divi uses a proof-of-stake consensus mechanism where block producers
//! must prove ownership of coins (UTXOs) to create new blocks.
//!
//! The proof-of-stake hash is computed as:
//! ```text
//! hashProof = Hash(stakeModifier || coinstakeStartTime || prevout || timestamp)
//! ```
//!
//! The target is weighted by the coin's value and age:
//! ```text
//! weightedTarget = target * (value * timeWeight) / COIN / 400
//! ```
//!
//! A valid proof satisfies: `hashProof < weightedTarget`
//!
//! # Example
//!
//! ```
//! use divi_consensus::{ProofOfStakeGenerator, StakingData, MockStakeModifierService};
//! use divi_primitives::{Hash256, OutPoint, Amount};
//!
//! // Create staking data (using test vector from Divi block 10k)
//! let staking_data = StakingData::new(
//!     470026099, // nBits (difficulty target)
//!     1538645320, // block time of first confirmation
//!     Hash256::from_hex("967b03e3c1daf39633ed73ffb29abfcab9ae5b384dc5b95dabee0890bf8b4546").unwrap(),
//!     OutPoint::new(
//!         Hash256::from_hex("4266403b499375917920311b1af704805d3fa2d6d6f4e3217026618028423607").unwrap(),
//!         1,
//!     ),
//!     Amount::from_sat(62542750000000), // UTXO value
//!     Hash256::from_hex("acf49c06030a7a76059a25b174dc7adcdc5f4ad36c91b564c585743af4829f7a").unwrap(),
//! );
//!
//! // Create a stake modifier service (normally from chain data)
//! let service = MockStakeModifierService::new(13260253192);
//!
//! // Create the PoS generator
//! let generator = ProofOfStakeGenerator::new(service, 0);
//!
//! // Verify a proof-of-stake
//! let result = generator.compute_and_verify(&staking_data, 1538663336);
//! assert!(result.is_ok());
//! ```

pub mod block_subsidy;
pub mod error;
pub mod lottery;
pub mod pos_calculator;
pub mod pos_generator;
pub mod stake_modifier;
pub mod staking_data;
pub mod target;
pub mod treasury;

pub use block_subsidy::{
    calculate_weighted_treasury_payment, get_block_subsidy, BlockRewards, SUBSIDY_HALVING_INTERVAL,
};
pub use error::ConsensusError;
pub use lottery::{
    calculate_lottery_payments, calculate_lottery_score, get_last_lottery_height,
    is_coinstake_valid_for_lottery, is_lottery_block, update_lottery_winners,
    LOTTERY_TICKET_MINIMUM, LOTTERY_WINNER_COUNT,
};
pub use pos_calculator::{
    compute_stake_hash, create_hashproof, stake_target_hit, HashproofResult,
    ProofOfStakeCalculator, MAXIMUM_COIN_AGE_WEIGHT_FOR_STAKING, N_HASH_DRIFT,
};
pub use pos_generator::ProofOfStakeGenerator;
pub use stake_modifier::{
    get_stake_modifier_selection_interval, get_stake_modifier_selection_interval_section,
    MockStakeModifierService, SimpleStakeModifierService, StakeModifierService, MODIFIER_INTERVAL,
    MODIFIER_INTERVAL_RATIO,
};
pub use staking_data::StakingData;
pub use target::{bits_to_difficulty, difficulty_to_bits, get_block_proof, Target};
pub use treasury::{
    calculate_treasury_payments, get_charity_script, get_last_treasury_height,
    get_treasury_payment_cycle, get_treasury_script, is_treasury_block,
    is_treasury_block_with_lottery,
};
