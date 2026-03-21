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

//! Proof-of-Stake Validation
//!
//! This module implements the core PoS validation logic from C++ Divi, including:
//! - Kernel hash computation
//! - Stake target verification
//! - Coin age weighting
//! - Coinstake transaction validation
//!
//! Reference: Divi/divi/src/ProofOfStakeCalculator.cpp
//!           Divi/divi/src/ProofOfStakeGenerator.cpp
//!           Divi/divi/src/BlockProofVerifier.cpp

use divi_primitives::{Amount, Block, Hash256, OutPoint, Transaction};
use sha2::{Digest, Sha256};
use std::io::Write;

/// Maximum coin age weight for staking (7 days - 1 hour, in seconds)
/// Reference: ProofOfStakeCalculator.cpp:8
const MAXIMUM_COIN_AGE_WEIGHT_FOR_STAKING: u64 = 60 * 60 * 24 * 7 - 60 * 60;

/// Minimum coin age required for staking (60 seconds)
/// Reference: ProofOfStakeGenerator.cpp and Settings
const MINIMUM_COIN_AGE_FOR_STAKING: u64 = 60;

/// Hash drift allowance for proof-of-stake (45 seconds)
/// Reference: I_ProofOfStakeGenerator.h:30
pub const HASH_DRIFT: u32 = 45;

/// Maximum number of inputs that can be combined in a coinstake transaction
/// Reference: BlockProofVerifier.cpp:54
const MAX_COMBINABLE_INPUTS: usize = 30;

/// Staking data required for proof-of-stake validation
/// Reference: StakingData.h
#[derive(Debug, Clone)]
pub struct StakingData {
    /// Block difficulty bits
    pub n_bits: u32,
    /// Block time of the first confirmation block (when UTXO was created)
    pub block_time_of_first_confirmation: u32,
    /// Block hash of the first confirmation block
    pub block_hash_of_first_confirmation: Hash256,
    /// The UTXO being staked (kernel input)
    pub utxo_being_staked: OutPoint,
    /// Value of the UTXO being staked
    pub utxo_value: Amount,
    /// Block hash of the chain tip
    pub block_hash_of_chain_tip: Hash256,
}

/// Compute the stake hash for proof-of-stake
///
/// Reference: ProofOfStakeCalculator.cpp:10-16
/// Formula: Hash(stakeModifier || coinstakeStartTime || prevout.n || prevout.hash || hashproofTimestamp)
fn compute_stake_hash(
    stake_modifier: u64,
    hashproof_timestamp: u32,
    prevout: &OutPoint,
    coinstake_start_time: u32,
) -> Hash256 {
    tracing::debug!("compute_stake_hash inputs:");
    tracing::debug!("  stake_modifier: 0x{:016x}", stake_modifier);
    tracing::debug!("  coinstake_start_time: {}", coinstake_start_time);
    tracing::debug!("  prevout.vout: {}", prevout.vout);
    tracing::debug!("  prevout.txid (display): {}", prevout.txid);
    tracing::debug!(
        "  prevout.txid (raw bytes): {:02x?}",
        &prevout.txid.as_bytes()[..8]
    );
    tracing::debug!("  hashproof_timestamp: {}", hashproof_timestamp);

    // Build the data buffer to hash - exactly 52 bytes
    // Order: stakeModifier(8) + coinstakeStartTime(4) + prevout.n(4) + prevout.hash(32) + hashproofTimestamp(4)
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&stake_modifier.to_le_bytes()); // 8 bytes
    data.extend_from_slice(&coinstake_start_time.to_le_bytes()); // 4 bytes
    data.extend_from_slice(&prevout.vout.to_le_bytes()); // 4 bytes
    data.extend_from_slice(prevout.txid.as_bytes()); // 32 bytes
    data.extend_from_slice(&hashproof_timestamp.to_le_bytes()); // 4 bytes

    // Log the complete buffer being hashed
    tracing::debug!("  stake_hash_input (52 bytes): {:02x?}", &data);

    let mut hasher = Sha256::new();
    hasher.write_all(&data).unwrap();
    let first_hash = hasher.finalize();

    // Double SHA256 (standard Bitcoin hash)
    let mut second_hasher = Sha256::new();
    second_hasher.write_all(&first_hash).unwrap();
    let result = second_hasher.finalize();

    // Store directly - Hash256 uses same byte order as Bitcoin uint256
    let computed = Hash256::from_slice(&result);
    tracing::debug!("  computed_stake_hash: {}", computed);

    computed
}

/// Check if the stake hash meets the target adjusted by coin age weight
///
/// Reference: ProofOfStakeCalculator.cpp:19-33
fn stake_target_hit(
    hash_proof_of_stake: &Hash256,
    value_in: Amount,
    coin_age_target: &Hash256,
    time_weight: i64,
) -> bool {
    // Compute coin age weight: (value * time_weight) / COIN / 400
    // Reference: ProofOfStakeCalculator.cpp:21
    let value_satoshis = value_in.as_sat() as u128;
    let time_weight_u128 = time_weight as u128;

    // COIN = 100_000_000 satoshis (1 DIVI)
    const COIN: u128 = 100_000_000;
    const DIVISOR: u128 = COIN * 400;

    let coin_age_weight_raw = (value_satoshis * time_weight_u128) / DIVISOR;

    tracing::debug!("stake_target_hit debug:");
    tracing::debug!("  value_satoshis: {}", value_satoshis);
    tracing::debug!("  time_weight: {}", time_weight);
    tracing::debug!("  coin_age_weight_raw: {}", coin_age_weight_raw);

    // Convert coin_age_weight to Hash256 (uint256)
    let coin_age_weight = if coin_age_weight_raw <= u128::MAX {
        Hash256::from_u128_le(coin_age_weight_raw)
    } else {
        // Overflow - target always hit (regtest edge case)
        // Reference: ProofOfStakeCalculator.cpp:24-28
        return true;
    };

    tracing::debug!("  coin_age_target (full): {}", coin_age_target);
    tracing::debug!(
        "  coin_age_weight: {:02x?}",
        &coin_age_weight.as_bytes()[..8]
    );

    // Multiply target by coin age weight
    // Reference: ProofOfStakeCalculator.cpp:23-29
    let target = match coin_age_target.multiply_by(&coin_age_weight) {
        Some(t) => t,
        None => {
            // Overflow means target is huge, always hit
            tracing::debug!("  target: OVERFLOW (always hit)");
            return true;
        }
    };

    tracing::debug!("  final_target (display): {}", target);
    tracing::debug!("  final_target (raw bytes): {:02x?}", target.as_bytes());
    tracing::debug!("  hash_to_compare (display): {}", hash_proof_of_stake);
    tracing::debug!(
        "  hash_to_compare (raw bytes): {:02x?}",
        hash_proof_of_stake.as_bytes()
    );

    // Check if proof-of-stake hash meets target
    // Reference: ProofOfStakeCalculator.cpp:32
    // Hash256 comparison now properly treats values as 256-bit little-endian integers
    // (comparing from byte[31] down to byte[0])
    let result = hash_proof_of_stake < &target;
    tracing::debug!(
        "  comparison: hash < target = {} (hash[31]=0x{:02x}, target[31]=0x{:02x})",
        result,
        hash_proof_of_stake.as_bytes()[31],
        target.as_bytes()[31]
    );
    result
}

/// Compute proof-of-stake and check if it meets the target
///
/// Reference: ProofOfStakeCalculator.cpp:47-55
pub fn compute_and_verify_proof_of_stake(
    stake_modifier: u64,
    staking_data: &StakingData,
    hashproof_timestamp: u32,
) -> Result<(Hash256, bool), String> {
    // Compute the stake hash
    let computed_hash = compute_stake_hash(
        stake_modifier,
        hashproof_timestamp,
        &staking_data.utxo_being_staked,
        staking_data.block_time_of_first_confirmation,
    );

    // Compute coin age weight (capped at 7 days - 1 hour)
    // Reference: ProofOfStakeCalculator.cpp:53
    let time_diff =
        hashproof_timestamp.saturating_sub(staking_data.block_time_of_first_confirmation);
    let coin_age_weight =
        std::cmp::min(time_diff as u64, MAXIMUM_COIN_AGE_WEIGHT_FOR_STAKING) as i64;

    // Parse compact bits to get target
    let coin_age_target = Hash256::from_compact(staking_data.n_bits);

    // Check if hash meets target
    let meets_target = stake_target_hit(
        &computed_hash,
        staking_data.utxo_value,
        &coin_age_target,
        coin_age_weight,
    );

    Ok((computed_hash, meets_target))
}

/// Check if proof-of-stake time requirements are met
///
/// Reference: ProofOfStakeGenerator.cpp:75-90
pub fn check_pos_time_requirements(
    coinstake_start_time: u32,
    hashproof_timestamp: u32,
) -> Result<(), String> {
    // Transaction timestamp violation
    // Reference: ProofOfStakeGenerator.cpp:79-82
    if hashproof_timestamp < coinstake_start_time {
        return Err(format!(
            "nTime violation: hashproof_timestamp ({}) < coinstake_start_time ({})",
            hashproof_timestamp, coinstake_start_time
        ));
    }

    // Minimum age requirement
    // Reference: ProofOfStakeGenerator.cpp:84-88
    if coinstake_start_time + MINIMUM_COIN_AGE_FOR_STAKING as u32 > hashproof_timestamp {
        return Err(format!(
            "min age violation: coinstake_start_time ({}) + min_age ({}) > hashproof_timestamp ({})",
            coinstake_start_time, MINIMUM_COIN_AGE_FOR_STAKING, hashproof_timestamp
        ));
    }

    Ok(())
}

/// Validate a coinstake transaction structure
///
/// Reference: BlockProofVerifier.cpp:47-108
pub fn validate_coinstake_transaction(tx: &Transaction) -> Result<(), String> {
    // Must be a coinstake transaction
    if !tx.is_coinstake() {
        return Err("Transaction is not a coinstake".to_string());
    }

    // Check input count
    // Reference: BlockProofVerifier.cpp:59-61
    if tx.vin.is_empty() {
        return Err("Coinstake has no inputs".to_string());
    }

    if tx.vin.len() > MAX_COMBINABLE_INPUTS {
        return Err(format!(
            "Coinstake has too many inputs: {} > {}",
            tx.vin.len(),
            MAX_COMBINABLE_INPUTS
        ));
    }

    // Output 0 must be empty (marker output)
    if !tx.vout.is_empty() {
        if tx.vout[0].value != Amount::ZERO {
            return Err("Coinstake output 0 must be empty".to_string());
        }
    } else {
        return Err("Coinstake must have at least one output".to_string());
    }

    Ok(())
}

/// Validate that all coinstake inputs pay to the same script
///
/// Reference: BlockProofVerifier.cpp:74-82
/// This requires UTXO lookup and is called during block validation with chain context
pub fn validate_coinstake_inputs_same_script(
    tx: &Transaction,
    get_prev_tx_output: &dyn Fn(&OutPoint) -> Option<divi_primitives::TxOut>,
) -> Result<(), String> {
    if tx.vin.is_empty() {
        return Err("Coinstake has no inputs".to_string());
    }

    // Get kernel script (from first input)
    let kernel_input = &tx.vin[0].prevout;
    let kernel_output = get_prev_tx_output(kernel_input)
        .ok_or_else(|| format!("Failed to get kernel UTXO: {:?}", kernel_input))?;
    let kernel_script = &kernel_output.script_pubkey;

    // Verify all other inputs pay to the same script
    for (i, input) in tx.vin.iter().enumerate().skip(1) {
        let prev_output = get_prev_tx_output(&input.prevout)
            .ok_or_else(|| format!("Failed to get UTXO for input {}: {:?}", i, input.prevout))?;

        if &prev_output.script_pubkey != kernel_script {
            return Err(format!(
                "Stake input {} pays to different script than kernel",
                i
            ));
        }
    }

    Ok(())
}

/// Validate vault-specific coinstake rules
///
/// For vault coinstakes (where the kernel input pays to a vault script):
/// 1. Staking outputs must pay to the same vault script
/// 2. Total vault output value >= total vault input value (no value lost from vault)
///
/// Reference: Divi/divi/src/VaultManager.cpp CheckCoinstakeForVaults()
pub fn validate_coinstake_vault_rules(
    tx: &Transaction,
    get_prev_tx_output: &dyn Fn(&OutPoint) -> Option<divi_primitives::TxOut>,
) -> Result<(), String> {
    if tx.vin.is_empty() {
        return Err("Coinstake has no inputs".to_string());
    }

    // Get kernel input's script
    let kernel_output = get_prev_tx_output(&tx.vin[0].prevout)
        .ok_or_else(|| "Cannot find kernel UTXO".to_string())?;

    // Check if kernel is a vault script - if not, no vault rules apply
    // Vault scripts are exactly 50 bytes: OP_IF(0x63) <20> <owner> OP_ELSE(0x67) OP_REQUIRE_COINSTAKE(0xb9) <20> <manager> OP_ENDIF(0x68) ...
    let script_bytes = kernel_output.script_pubkey.as_bytes();
    if script_bytes.len() != 50
        || script_bytes[0] != 0x63
        || script_bytes[22] != 0x67
        || script_bytes[23] != 0xb9
    {
        return Ok(());
    }

    // Sum total vault input value
    let mut total_input_value = Amount::ZERO;
    for input in &tx.vin {
        if let Some(prev_out) = get_prev_tx_output(&input.prevout) {
            if prev_out.script_pubkey.as_bytes() == script_bytes {
                total_input_value = total_input_value + prev_out.value;
            }
        }
    }

    // Check vault outputs (vout[0] is empty coinstake marker)
    if tx.vout.len() < 2 {
        return Err("Vault coinstake must have at least 2 outputs".to_string());
    }

    // vout[1] must pay to the same vault script
    let stake_output = &tx.vout[1];
    if stake_output.script_pubkey.as_bytes() != script_bytes {
        return Err("Vault coinstake output[1] must pay to the same vault script".to_string());
    }

    let mut total_vault_output_value = stake_output.value;

    // If vout[2] also pays to vault script (split), count it
    if tx.vout.len() > 2 && tx.vout[2].script_pubkey.as_bytes() == script_bytes {
        total_vault_output_value = total_vault_output_value + tx.vout[2].value;
    }

    // Vault output value must be >= vault input value
    if total_vault_output_value < total_input_value {
        return Err(format!(
            "Vault output value ({}) < vault input value ({})",
            total_vault_output_value, total_input_value
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_hash_computation() {
        // Test basic stake hash computation
        let stake_modifier = 0x7374616b656d6f64u64; // "stakemod"
        let hashproof_timestamp = 1000000;
        let prevout = OutPoint {
            txid: Hash256::from_slice(&[1u8; 32]),
            vout: 0,
        };
        let coinstake_start_time = 999940; // 60 seconds before hashproof

        let hash = compute_stake_hash(
            stake_modifier,
            hashproof_timestamp,
            &prevout,
            coinstake_start_time,
        );

        // Hash should be deterministic
        assert!(!hash.is_zero());

        // Computing again should give same result
        let hash2 = compute_stake_hash(
            stake_modifier,
            hashproof_timestamp,
            &prevout,
            coinstake_start_time,
        );
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_pos_time_requirements_valid() {
        let coinstake_start = 1000000;
        let hashproof = coinstake_start + 60; // Exactly minimum age

        assert!(check_pos_time_requirements(coinstake_start, hashproof).is_ok());

        let hashproof2 = coinstake_start + 3600; // 1 hour later
        assert!(check_pos_time_requirements(coinstake_start, hashproof2).is_ok());
    }

    #[test]
    fn test_pos_time_requirements_too_young() {
        let coinstake_start = 1000000;
        let hashproof = coinstake_start + 59; // 1 second too young

        assert!(check_pos_time_requirements(coinstake_start, hashproof).is_err());
    }

    #[test]
    fn test_pos_time_requirements_backwards() {
        let coinstake_start = 1000000;
        let hashproof = 999999; // Before coinstake start

        let result = check_pos_time_requirements(coinstake_start, hashproof);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nTime violation"));
    }

    #[test]
    fn test_coin_age_weight_capped() {
        // Test that coin age weight is capped at 7 days - 1 hour
        let staking_data = StakingData {
            n_bits: 0x1e0ffff0, // Easy difficulty
            block_time_of_first_confirmation: 1000000,
            block_hash_of_first_confirmation: Hash256::from_slice(&[0u8; 32]),
            utxo_being_staked: OutPoint {
                txid: Hash256::from_slice(&[1u8; 32]),
                vout: 0,
            },
            utxo_value: Amount::from_divi(1000),
            block_hash_of_chain_tip: Hash256::from_slice(&[2u8; 32]),
        };

        let stake_modifier = 0x7374616b656d6f64u64;

        // 30 days later (way over the cap)
        let hashproof = staking_data.block_time_of_first_confirmation + (30 * 24 * 60 * 60);

        // Should not panic, weight should be capped
        let result = compute_and_verify_proof_of_stake(stake_modifier, &staking_data, hashproof);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_coinstake_empty_inputs() {
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
        };

        let result = validate_coinstake_transaction(&tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_coinstake_too_many_inputs() {
        use divi_primitives::{Script, TxIn, TxOut};

        // Create transaction with too many inputs
        let mut inputs = Vec::new();
        for i in 0..MAX_COMBINABLE_INPUTS + 1 {
            inputs.push(TxIn {
                prevout: OutPoint {
                    txid: Hash256::from_slice(&[i as u8; 32]),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFF,
            });
        }

        // Create valid coinstake outputs (empty marker + at least one output)
        let outputs = vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: Script::new(),
            },
            TxOut {
                value: Amount::from_divi(100),
                script_pubkey: Script::new(),
            },
        ];

        let tx = Transaction {
            version: 1,
            vin: inputs,
            vout: outputs,
            lock_time: 0,
        };

        let result = validate_coinstake_transaction(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many inputs"));
    }

    #[test]
    fn test_mainnet_block_10k_pos_validation() {
        // Test vectors from mainnet block 10,000
        // These should match the test in divi-consensus/src/pos_calculator.rs
        let staking_data = StakingData {
            n_bits: 470026099, // difficulty bits
            block_time_of_first_confirmation: 1538645320,
            block_hash_of_first_confirmation: Hash256::from_hex(
                "967b03e3c1daf39633ed73ffb29abfcab9ae5b384dc5b95dabee0890bf8b4546",
            )
            .unwrap(),
            utxo_being_staked: OutPoint {
                txid: Hash256::from_hex(
                    "4266403b499375917920311b1af704805d3fa2d6d6f4e3217026618028423607",
                )
                .unwrap(),
                vout: 1,
            },
            utxo_value: Amount::from_sat(62542750000000), // ~625k DIVI
            block_hash_of_chain_tip: Hash256::from_hex(
                "acf49c06030a7a76059a25b174dc7adcdc5f4ad36c91b564c585743af4829f7a",
            )
            .unwrap(),
        };

        let stake_modifier = 13260253192u64;
        let hashproof_timestamp = 1538663336u32;

        let (hash_proof, meets_target) =
            compute_and_verify_proof_of_stake(stake_modifier, &staking_data, hashproof_timestamp)
                .expect("PoS computation should succeed");

        // The hash should meet the target for this valid mainnet block
        assert!(
            meets_target,
            "Block 10k PoS validation should pass. Hash: {}",
            hash_proof
        );
    }

    #[test]
    fn test_mainnet_block_1m_pos_validation() {
        // Test vectors from mainnet block 1,000,000
        let staking_data = StakingData {
            n_bits: 453338064, // difficulty bits
            block_time_of_first_confirmation: 1598487374,
            block_hash_of_first_confirmation: Hash256::from_hex(
                "e5fd3874ca56174d611c8925785a0dda728a4160b59ab777644e7a17500576d4",
            )
            .unwrap(),
            utxo_being_staked: OutPoint {
                txid: Hash256::from_hex(
                    "d17d0226b20b1853b6ad50e73f132a1bd1ce1b5fa08db17c0cbbc93b82619da1",
                )
                .unwrap(),
                vout: 1,
            },
            utxo_value: Amount::from_sat(1445296875000), // ~14k DIVI
            block_hash_of_chain_tip: Hash256::from_hex(
                "25f7f482cbf34cd7da9d5db0e3b633c8c0abe54e0de1ef96e97ba15e8713e984",
            )
            .unwrap(),
        };

        let stake_modifier = 3657064020262u64;
        let hashproof_timestamp = 1598693544u32;

        let (hash_proof, meets_target) =
            compute_and_verify_proof_of_stake(stake_modifier, &staking_data, hashproof_timestamp)
                .expect("PoS computation should succeed");

        // The hash should meet the target for this valid mainnet block
        assert!(
            meets_target,
            "Block 1M PoS validation should pass. Hash: {}",
            hash_proof
        );
    }
}
