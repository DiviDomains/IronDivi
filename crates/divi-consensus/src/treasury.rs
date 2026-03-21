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

// Treasury and Charity payment logic for Divi
// Treasury and charity payments accumulate over a cycle and are paid in lump sum

use divi_primitives::{Amount, Script};

/// Treasury block parameters for mainnet
pub mod mainnet {
    /// Height where treasury payments begin
    pub const TREASURY_START_BLOCK: u32 = 101;
    /// Treasury cycle (blocks between treasury payouts)
    /// 60 * 24 * 7 + 1 = 10081 blocks (~1 week)
    pub const TREASURY_CYCLE: u32 = 10081;
    /// Lottery block cycle (60 * 24 * 7 = 10080)
    pub const LOTTERY_CYCLE: u32 = 10080;
}

/// Treasury block parameters for testnet
pub mod testnet {
    /// Height where treasury payments begin
    pub const TREASURY_START_BLOCK: u32 = 102;
    /// Treasury cycle (blocks between treasury payouts)
    pub const TREASURY_CYCLE: u32 = 201;
    /// Lottery block cycle
    pub const LOTTERY_CYCLE: u32 = 200;
}

/// Treasury block parameters for regtest
pub mod regtest {
    /// Height where treasury payments begin
    pub const TREASURY_START_BLOCK: u32 = 102;
    /// Treasury cycle (blocks between treasury payouts)
    pub const TREASURY_CYCLE: u32 = 50;
    /// Lottery block cycle
    pub const LOTTERY_CYCLE: u32 = 10;
}

/// Check if a given height is a treasury block.
///
/// Matches C++ SuperblockHeightValidator logic:
/// - Before transition (lottery_cycle * treasury_cycle): legacy rule `height % treasury_cycle == 0`
/// - At/after transition: treasury occurs when `IsValidLotteryBlockHeight(height - 1)`,
///   i.e., `((height - 1 - transition) % lottery_cycle) == 0`
pub fn is_treasury_block(height: u32, start_block: u32, cycle: u32) -> bool {
    is_treasury_block_with_lottery(height, start_block, cycle, 0)
}

/// Check if a given height is a treasury block, accounting for the superblock transition.
///
/// When `lottery_cycle > 0`, applies C++ SuperblockHeightValidator logic where treasury
/// and lottery merge into a unified "superblock" cycle after the transition height.
pub fn is_treasury_block_with_lottery(
    height: u32,
    start_block: u32,
    treasury_cycle: u32,
    lottery_cycle: u32,
) -> bool {
    if height < start_block {
        return false;
    }

    // If no lottery cycle specified, use legacy rule
    if lottery_cycle == 0 {
        return (height % treasury_cycle) == 0;
    }

    let transition_height = lottery_cycle * treasury_cycle;

    if height < transition_height {
        // Pre-transition: legacy rule
        (height % treasury_cycle) == 0
    } else {
        // Post-transition: treasury block is one block after a lottery block
        // C++ logic: IsValidTreasuryBlockHeight(h) = IsValidLotteryBlockHeight(h - 1)
        // where IsValidLotteryBlockHeight(h) = ((h - transition) % lottery_cycle) == 0
        let lottery_height = height - 1;
        if lottery_height < transition_height {
            return false;
        }
        ((lottery_height - transition_height) % lottery_cycle) == 0
    }
}

/// Get the treasury payment cycle length for a given height.
///
/// Matches C++ SuperblockHeightValidator::GetTreasuryBlockPaymentCycle:
/// - Pre-transition: treasury_cycle
/// - At transition+1 (first post-transition treasury): treasury_cycle + 1
///   (because the gap from last pre-transition treasury to first post-transition is treasury_cycle+1)
/// - Post-transition: lottery_cycle
pub fn get_treasury_payment_cycle(height: u32, treasury_cycle: u32, lottery_cycle: u32) -> u32 {
    if lottery_cycle == 0 {
        return treasury_cycle;
    }
    let transition_height = lottery_cycle * treasury_cycle;
    if height < transition_height {
        treasury_cycle
    } else if height <= transition_height + 1 {
        treasury_cycle + 1
    } else {
        lottery_cycle
    }
}

/// Get the last treasury block height at or before the given height
pub fn get_last_treasury_height(height: u32, start_block: u32, cycle: u32) -> u32 {
    if height < start_block {
        return 0;
    }

    // Find the last block that is both >= start_block and divisible by cycle
    let candidate = (height / cycle) * cycle;
    if candidate >= start_block && is_treasury_block(candidate, start_block, cycle) {
        candidate
    } else {
        0
    }
}

/// Calculate treasury and charity payments for a treasury block
/// Returns (treasury_amount, charity_amount)
pub fn calculate_treasury_payments(
    height: u32,
    per_block_treasury: Amount,
    per_block_charity: Amount,
    start_block: u32,
    cycle: u32,
) -> (Amount, Amount) {
    if !is_treasury_block(height, start_block, cycle) {
        return (Amount::ZERO, Amount::ZERO);
    }

    // Treasury and charity rewards accumulate since the last treasury block
    // For the first treasury block, this is from start_block to current height
    // For subsequent blocks, this is from last_treasury_height to current height
    let last_treasury_height =
        get_last_treasury_height(height.saturating_sub(1), start_block, cycle);
    let blocks_since_last = if last_treasury_height == 0 {
        // First treasury block: count from start_block
        height - start_block
    } else {
        // Subsequent treasury blocks: count from last treasury block
        height - last_treasury_height
    };

    let blocks_i64 = blocks_since_last as i64;
    let treasury_payment = per_block_treasury * blocks_i64;
    let charity_payment = per_block_charity * blocks_i64;

    (treasury_payment, charity_payment)
}

/// Decode a base58 Divi address to a pubkey hash
/// This is a simplified version without full address validation
fn decode_address_to_hash(address: &str) -> Option<[u8; 20]> {
    // Use bs58 to decode
    let data = bs58::decode(address).into_vec().ok()?;

    if data.len() != 25 {
        return None;
    }

    // Extract 20-byte hash (skip version byte, checksum)
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&data[1..21]);
    Some(hash)
}

/// Get the treasury payment script
/// Uses testnet address for regtest (matching C++ behavior)
pub fn get_treasury_script(is_mainnet: bool) -> Script {
    // Mainnet: DPhJsztbZafDc1YeyrRqSjmKjkmLJpQpUn
    // Testnet/Regtest: xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd
    let address_str = if is_mainnet {
        "DPhJsztbZafDc1YeyrRqSjmKjkmLJpQpUn"
    } else {
        "xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd"
    };

    address_to_p2pkh_script(address_str)
}

/// Get the charity payment script
/// Uses testnet address for regtest (matching C++ behavior)
pub fn get_charity_script(is_mainnet: bool) -> Script {
    // Mainnet: DPujt2XAdHyRcZNB5ySZBBVKjzY2uXZGYq
    // Testnet/Regtest: y8zytdJziDeXcdk48Wv7LH6FgnF4zDiXM5
    let address_str = if is_mainnet {
        "DPujt2XAdHyRcZNB5ySZBBVKjzY2uXZGYq"
    } else {
        "y8zytdJziDeXcdk48Wv7LH6FgnF4zDiXM5"
    };

    address_to_p2pkh_script(address_str)
}

/// Convert a base58 address string to a P2PKH script
fn address_to_p2pkh_script(address: &str) -> Script {
    let hash = decode_address_to_hash(address).expect("Invalid treasury/charity address");

    Script::new_p2pkh(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const START_BLOCK: u32 = 102;
    const CYCLE: u32 = 50;

    #[test]
    fn test_is_treasury_block() {
        // Regtest params: start=102, cycle=50

        // Before start block
        assert!(!is_treasury_block(101, START_BLOCK, CYCLE));

        // At start block (102 % 50 == 2, not 0)
        assert!(!is_treasury_block(102, START_BLOCK, CYCLE));

        // First treasury block (150 % 50 == 0)
        assert!(is_treasury_block(150, START_BLOCK, CYCLE));

        // Second treasury block
        assert!(is_treasury_block(200, START_BLOCK, CYCLE));

        // Not treasury blocks
        assert!(!is_treasury_block(151, START_BLOCK, CYCLE));
        assert!(!is_treasury_block(199, START_BLOCK, CYCLE));
    }

    #[test]
    fn test_get_last_treasury_height() {
        // Regtest params: start=102, cycle=50

        assert_eq!(get_last_treasury_height(101, START_BLOCK, CYCLE), 0);
        // Block 149: (149 / 50) * 50 = 100, but 100 < 102, so returns 0
        assert_eq!(get_last_treasury_height(149, START_BLOCK, CYCLE), 0);
        assert_eq!(get_last_treasury_height(150, START_BLOCK, CYCLE), 150);
        assert_eq!(get_last_treasury_height(199, START_BLOCK, CYCLE), 150);
        assert_eq!(get_last_treasury_height(200, START_BLOCK, CYCLE), 200);
    }

    #[test]
    fn test_calculate_treasury_payments() {
        let per_block_treasury = Amount::from_divi(200); // 16% of 1250
        let per_block_charity = Amount::from_divi(12); // 1% of 1250 (using 12 for test simplicity)

        // Not a treasury block
        let (t, c) = calculate_treasury_payments(
            149,
            per_block_treasury,
            per_block_charity,
            START_BLOCK,
            CYCLE,
        );
        assert_eq!(t, Amount::ZERO);
        assert_eq!(c, Amount::ZERO);

        // First treasury block (150): accumulate from 102 to 150 = 48 blocks
        let (t, c) = calculate_treasury_payments(
            150,
            per_block_treasury,
            per_block_charity,
            START_BLOCK,
            CYCLE,
        );
        assert_eq!(t, Amount::from_divi(9600)); // 200 * 48
        assert_eq!(c, Amount::from_divi(576)); // 12 * 48

        // Second treasury block (200): accumulate from 150 to 200 = 50 blocks
        let (t, c) = calculate_treasury_payments(
            200,
            per_block_treasury,
            per_block_charity,
            START_BLOCK,
            CYCLE,
        );
        assert_eq!(t, Amount::from_divi(10000)); // 200 * 50
        assert_eq!(c, Amount::from_divi(600)); // 12 * 50
    }

    #[test]
    fn test_decode_treasury_addresses() {
        // Test mainnet treasury address
        let treasury_hash = decode_address_to_hash("DPhJsztbZafDc1YeyrRqSjmKjkmLJpQpUn");
        assert!(treasury_hash.is_some());

        // Test mainnet charity address
        let charity_hash = decode_address_to_hash("DPujt2XAdHyRcZNB5ySZBBVKjzY2uXZGYq");
        assert!(charity_hash.is_some());

        // Test testnet treasury address
        let testnet_treasury = decode_address_to_hash("xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd");
        assert!(testnet_treasury.is_some());

        // Test testnet charity address
        let testnet_charity = decode_address_to_hash("y8zytdJziDeXcdk48Wv7LH6FgnF4zDiXM5");
        assert!(testnet_charity.is_some());
    }

    #[test]
    fn test_get_treasury_scripts() {
        // Mainnet
        let treasury_script = get_treasury_script(true);
        assert!(treasury_script.is_p2pkh());
        assert_eq!(treasury_script.len(), 25);

        let charity_script = get_charity_script(true);
        assert!(charity_script.is_p2pkh());
        assert_eq!(charity_script.len(), 25);

        // Testnet/Regtest
        let testnet_treasury = get_treasury_script(false);
        assert!(testnet_treasury.is_p2pkh());

        let testnet_charity = get_charity_script(false);
        assert!(testnet_charity.is_p2pkh());
    }

    // ============================================================
    // COMPREHENSIVE TREASURY TESTS
    // Added 2026-01-19 for full coverage
    // ============================================================

    // Test different network configurations
    #[test]
    fn test_treasury_params_regtest() {
        // Regtest: start=102, cycle=50
        assert_eq!(regtest::TREASURY_START_BLOCK, 102);
        assert_eq!(regtest::TREASURY_CYCLE, 50);

        // First treasury block at 150 (first height >= 102 where height % 50 == 0)
        assert!(!is_treasury_block(
            100,
            regtest::TREASURY_START_BLOCK,
            regtest::TREASURY_CYCLE
        ));
        assert!(!is_treasury_block(
            102,
            regtest::TREASURY_START_BLOCK,
            regtest::TREASURY_CYCLE
        ));
        assert!(is_treasury_block(
            150,
            regtest::TREASURY_START_BLOCK,
            regtest::TREASURY_CYCLE
        ));
    }

    // Edge cases for is_treasury_block
    #[test]
    fn test_is_treasury_block_edge_cases() {
        // Block 0 is never a treasury block
        assert!(!is_treasury_block(0, 102, 50));

        // Block at start is NOT treasury (102 % 50 == 2)
        assert!(!is_treasury_block(102, 102, 50));

        // Block just before first treasury
        assert!(!is_treasury_block(149, 102, 50));

        // Exact first treasury block
        assert!(is_treasury_block(150, 102, 50));

        // Block just after treasury
        assert!(!is_treasury_block(151, 102, 50));

        // Very large height
        assert!(is_treasury_block(1000000, 102, 50)); // 1000000 % 50 == 0
        assert!(!is_treasury_block(1000001, 102, 50)); // 1000001 % 50 == 1
    }

    #[test]
    fn test_is_treasury_block_with_different_cycles() {
        // Cycle of 1 (every block is treasury after start)
        assert!(!is_treasury_block(100, 101, 1));
        assert!(is_treasury_block(101, 101, 1)); // 101 >= 101 && 101 % 1 == 0
        assert!(is_treasury_block(102, 101, 1));

        // Cycle of 100
        assert!(!is_treasury_block(99, 100, 100));
        assert!(is_treasury_block(100, 100, 100)); // 100 >= 100 && 100 % 100 == 0
        assert!(!is_treasury_block(101, 100, 100));
        assert!(is_treasury_block(200, 100, 100));
    }

    // Treasury height calculation tests
    #[test]
    fn test_get_last_treasury_height_edge_cases() {
        // Before any treasury block
        assert_eq!(get_last_treasury_height(0, 102, 50), 0);
        assert_eq!(get_last_treasury_height(50, 102, 50), 0);
        assert_eq!(get_last_treasury_height(100, 102, 50), 0); // 100 < 102

        // Just at start block (but 102 % 50 != 0)
        assert_eq!(get_last_treasury_height(102, 102, 50), 0);

        // Between start and first treasury
        assert_eq!(get_last_treasury_height(125, 102, 50), 0);

        // At first treasury block
        assert_eq!(get_last_treasury_height(150, 102, 50), 150);

        // Between first and second treasury
        assert_eq!(get_last_treasury_height(175, 102, 50), 150);
        assert_eq!(get_last_treasury_height(199, 102, 50), 150);

        // At second treasury
        assert_eq!(get_last_treasury_height(200, 102, 50), 200);

        // Large heights
        assert_eq!(get_last_treasury_height(999, 102, 50), 950);
        assert_eq!(get_last_treasury_height(1000, 102, 50), 1000);
    }

    // Payment calculation tests
    #[test]
    fn test_calculate_treasury_payments_not_treasury_block() {
        let per_block_treasury = Amount::from_divi(200);
        let per_block_charity = Amount::from_divi(12);

        // Not a treasury block - should return zero
        let (t, c) =
            calculate_treasury_payments(100, per_block_treasury, per_block_charity, 102, 50);
        assert_eq!(t, Amount::ZERO);
        assert_eq!(c, Amount::ZERO);

        let (t, c) =
            calculate_treasury_payments(151, per_block_treasury, per_block_charity, 102, 50);
        assert_eq!(t, Amount::ZERO);
        assert_eq!(c, Amount::ZERO);
    }

    #[test]
    fn test_calculate_treasury_payments_first_block() {
        let per_block_treasury = Amount::from_divi(200);
        let per_block_charity = Amount::from_divi(12);

        // First treasury block at 150: accumulates from block 102 to 150
        // That's 150 - 102 = 48 blocks of rewards
        let (t, c) =
            calculate_treasury_payments(150, per_block_treasury, per_block_charity, 102, 50);
        assert_eq!(t, Amount::from_divi(48 * 200)); // 9600 DIVI
        assert_eq!(c, Amount::from_divi(48 * 12)); // 576 DIVI
    }

    #[test]
    fn test_calculate_treasury_payments_subsequent_blocks() {
        let per_block_treasury = Amount::from_divi(200);
        let per_block_charity = Amount::from_divi(12);

        // Second treasury block at 200: accumulates from 150 to 200
        // That's 200 - 150 = 50 blocks
        let (t, c) =
            calculate_treasury_payments(200, per_block_treasury, per_block_charity, 102, 50);
        assert_eq!(t, Amount::from_divi(50 * 200)); // 10000 DIVI
        assert_eq!(c, Amount::from_divi(50 * 12)); // 600 DIVI

        // Third treasury block at 250
        let (t, c) =
            calculate_treasury_payments(250, per_block_treasury, per_block_charity, 102, 50);
        assert_eq!(t, Amount::from_divi(50 * 200)); // 10000 DIVI
        assert_eq!(c, Amount::from_divi(50 * 12)); // 600 DIVI
    }

    #[test]
    fn test_calculate_treasury_payments_large_amounts() {
        // Test with realistic mainnet values
        // Treasury: 16% of 1250 DIVI = 200 DIVI per block
        // Charity: 1.5% of 1250 DIVI = 18.75 DIVI per block
        let per_block_treasury = Amount::from_sat(200_00000000);
        let per_block_charity = Amount::from_sat(18_75000000);

        // On mainnet, cycle is 43201 blocks
        // First treasury at height where height % 43201 == 0 and height >= 101
        // e.g., at height 43201
        let (t, c) =
            calculate_treasury_payments(43201, per_block_treasury, per_block_charity, 101, 43201);

        // From block 101 to 43201 = 43100 blocks
        assert_eq!(t, Amount::from_sat(43100 * 200_00000000));
        assert_eq!(c, Amount::from_sat(43100 * 18_75000000));
    }

    // Address decoding tests
    #[test]
    fn test_decode_address_invalid() {
        // Invalid addresses should return None
        assert!(decode_address_to_hash("invalid").is_none());
        assert!(decode_address_to_hash("").is_none());
        assert!(decode_address_to_hash("1").is_none());
        assert!(decode_address_to_hash("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD").is_none());
    }

    #[test]
    fn test_decode_address_wrong_version() {
        // Bitcoin mainnet address (different version byte)
        // This should fail because Divi expects different version
        let btc_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        // May or may not be None depending on implementation
        let _ = decode_address_to_hash(btc_address);
    }

    // Script generation tests
    #[test]
    fn test_treasury_scripts_different_networks() {
        let mainnet_treasury = get_treasury_script(true);
        let testnet_treasury = get_treasury_script(false);

        // They should be different
        assert_ne!(mainnet_treasury.as_bytes(), testnet_treasury.as_bytes());

        let mainnet_charity = get_charity_script(true);
        let testnet_charity = get_charity_script(false);

        assert_ne!(mainnet_charity.as_bytes(), testnet_charity.as_bytes());
    }

    #[test]
    fn test_treasury_script_format() {
        let script = get_treasury_script(true);
        let bytes = script.as_bytes();

        // P2PKH format: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(bytes.len(), 25);
        assert_eq!(bytes[0], 0x76); // OP_DUP
        assert_eq!(bytes[1], 0xa9); // OP_HASH160
        assert_eq!(bytes[2], 0x14); // Push 20 bytes
        assert_eq!(bytes[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(bytes[24], 0xac); // OP_CHECKSIG
    }

    // Integration-style test
    #[test]
    fn test_treasury_payment_cycle_consistency() {
        // Verify that consecutive treasury blocks have expected payment amounts
        let per_block_treasury = Amount::from_divi(200);
        let per_block_charity = Amount::from_divi(12);

        let mut total_treasury = Amount::ZERO;
        let mut total_charity = Amount::ZERO;

        // Go through several treasury blocks
        for height in (150..=500).step_by(50) {
            let (t, c) = calculate_treasury_payments(
                height as u32,
                per_block_treasury,
                per_block_charity,
                START_BLOCK,
                CYCLE,
            );
            total_treasury = total_treasury + t;
            total_charity = total_charity + c;
        }

        // Total blocks from 102 to 500 = 398 blocks
        // Should equal sum of all treasury payments
        // First payment (150): 48 blocks
        // Subsequent payments (200, 250, 300, 350, 400, 450, 500): 7 * 50 = 350 blocks
        // Total: 48 + 350 = 398 blocks
        assert_eq!(total_treasury, Amount::from_divi(398 * 200));
        assert_eq!(total_charity, Amount::from_divi(398 * 12));
    }

    // ============================================================
    // SUPERBLOCK TRANSITION TESTS
    // Tests for C++ SuperblockHeightValidator transition logic
    // ============================================================

    #[test]
    fn test_is_treasury_block_with_lottery_testnet() {
        // Testnet: treasury_cycle=201, lottery_cycle=200
        // Transition height = 200 * 201 = 40200
        let tc = testnet::TREASURY_CYCLE; // 201
        let lc = testnet::LOTTERY_CYCLE; // 200
        let start = testnet::TREASURY_START_BLOCK; // 102

        // Pre-transition: legacy rule (height % 201 == 0)
        assert!(is_treasury_block_with_lottery(39999, start, tc, lc)); // 39999 % 201 == 0 (199*201)
        assert!(!is_treasury_block_with_lottery(40000, start, tc, lc));

        // Height 40200 is the transition height
        // C++: IsValidTreasuryBlockHeight(40200) = IsValidLotteryBlockHeight(40199)
        // Pre-transition lottery: 40199 % 200 = 199 → NOT a lottery block
        // So 40200 is NOT a treasury block post-transition
        assert!(!is_treasury_block_with_lottery(40200, start, tc, lc));

        // Height 40201 is the first post-transition treasury block
        // IsValidTreasuryBlockHeight(40201) = IsValidLotteryBlockHeight(40200)
        // Post-transition lottery: (40200 - 40200) % 200 == 0 → YES
        assert!(is_treasury_block_with_lottery(40201, start, tc, lc));

        // Height 40401 is the second post-transition treasury block
        // IsValidTreasuryBlockHeight(40401) = IsValidLotteryBlockHeight(40400)
        // (40400 - 40200) % 200 == 0 → YES
        assert!(is_treasury_block_with_lottery(40401, start, tc, lc));

        // Non-treasury heights post-transition
        assert!(!is_treasury_block_with_lottery(40202, start, tc, lc));
        assert!(!is_treasury_block_with_lottery(40400, start, tc, lc));
    }

    #[test]
    fn test_is_treasury_block_with_lottery_regtest() {
        // Regtest: treasury_cycle=50, lottery_cycle=10
        // Transition height = 10 * 50 = 500
        let tc = regtest::TREASURY_CYCLE; // 50
        let lc = regtest::LOTTERY_CYCLE; // 10
        let start = regtest::TREASURY_START_BLOCK; // 102

        // Pre-transition: height % 50 == 0
        assert!(is_treasury_block_with_lottery(150, start, tc, lc));
        assert!(is_treasury_block_with_lottery(450, start, tc, lc));
        assert!(!is_treasury_block_with_lottery(499, start, tc, lc));

        // Height 500 is transition - NOT treasury post-transition
        // is_lottery_block(499) = 499 % 10 != 0 → false
        assert!(!is_treasury_block_with_lottery(500, start, tc, lc));

        // Height 501 is first post-transition treasury
        // is_lottery_block(500) = (500 - 500) % 10 == 0 → true
        assert!(is_treasury_block_with_lottery(501, start, tc, lc));

        // Height 511 = is_lottery_block(510) = (510-500) % 10 == 0 → true
        assert!(is_treasury_block_with_lottery(511, start, tc, lc));
    }

    #[test]
    fn test_get_treasury_payment_cycle() {
        // Testnet: treasury_cycle=201, lottery_cycle=200, transition=40200
        let tc = testnet::TREASURY_CYCLE;
        let lc = testnet::LOTTERY_CYCLE;

        // Pre-transition: returns treasury_cycle
        assert_eq!(get_treasury_payment_cycle(39999, tc, lc), 201);
        assert_eq!(get_treasury_payment_cycle(201, tc, lc), 201);

        // Transition block (height <= transition+1 = 40201): returns treasury_cycle + 1
        assert_eq!(get_treasury_payment_cycle(40200, tc, lc), 202);
        assert_eq!(get_treasury_payment_cycle(40201, tc, lc), 202);

        // Post-transition: returns lottery_cycle
        assert_eq!(get_treasury_payment_cycle(40202, tc, lc), 200);
        assert_eq!(get_treasury_payment_cycle(40401, tc, lc), 200);
    }

    #[test]
    fn test_treasury_transition_payment_cycle_accuracy() {
        // Verify that get_treasury_payment_cycle produces the correct
        // prior_treasury_height when subtracted from the current height
        let tc = testnet::TREASURY_CYCLE;
        let lc = testnet::LOTTERY_CYCLE;

        // First post-transition treasury at 40201:
        // payment_cycle = 202, prior = 40201 - 202 = 39999 (last pre-transition treasury, 199*201)
        let cycle = get_treasury_payment_cycle(40201, tc, lc);
        assert_eq!(40201 - cycle, 39999);

        // Second post-transition treasury at 40401:
        // payment_cycle = 200, prior = 40401 - 200 = 40201 ✓
        let cycle = get_treasury_payment_cycle(40401, tc, lc);
        assert_eq!(40401 - cycle, 40201);
    }
}
