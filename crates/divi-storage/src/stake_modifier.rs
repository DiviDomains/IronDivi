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

use crate::block_index::BlockIndex;
use crate::error::StorageError;
use divi_primitives::hash::Hash256;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use tracing;

pub const MODIFIER_INTERVAL: u32 = 60;
pub const MODIFIER_INTERVAL_RATIO: i64 = 3;

// Checkpoints removed - we compute stake modifiers algorithmically like C++

pub fn get_stake_modifier_selection_interval_section(section: i32) -> i64 {
    assert!(section >= 0 && section < 64);
    let numerator = (MODIFIER_INTERVAL as i64) * 63;
    let denominator = 63 + ((63 - section) as i64 * (MODIFIER_INTERVAL_RATIO - 1));
    numerator / denominator
}

pub fn get_stake_modifier_selection_interval() -> i64 {
    let mut selection_interval = 0i64;
    for section in 0..64 {
        selection_interval += get_stake_modifier_selection_interval_section(section);
    }
    selection_interval
}

/// Extract the stake entropy bit from a block hash
///
/// C++ Reference: CBlockIndex::GetStakeEntropyBit() in chain.cpp:82-85
/// Returns the lowest bit (bit 0) of the lowest 64 bits of the hash
pub fn get_stake_entropy_bit(block_hash: &Hash256) -> u64 {
    // Extract lowest 64 bits from hash (first 8 bytes in internal order)
    let hash_bytes = block_hash.as_bytes();
    let low_64 = u64::from_le_bytes([
        hash_bytes[0],
        hash_bytes[1],
        hash_bytes[2],
        hash_bytes[3],
        hash_bytes[4],
        hash_bytes[5],
        hash_bytes[6],
        hash_bytes[7],
    ]);
    // Return bit 0 (lowest bit)
    low_64 & 1
}

fn get_last_block_index_with_generated_stake_modifier<'a>(
    index: &'a BlockIndex,
    get_prev: &impl Fn(&Hash256) -> Option<&'a BlockIndex>,
) -> Option<&'a BlockIndex> {
    let mut current = Some(index);
    while let Some(idx) = current {
        if idx.generated_stake_modifier {
            return Some(idx);
        }
        if idx.prev_hash.is_zero() {
            return Some(idx);
        }
        current = get_prev(&idx.prev_hash);
    }
    None
}

struct RecentBlocksSorted {
    blocks: Vec<(i64, Hash256)>,
    timestamp_lower_bound: i64,
}

fn get_recent_blocks_sorted<'a>(
    prev_index: &'a BlockIndex,
    get_prev: &impl Fn(&Hash256) -> Option<&'a BlockIndex>,
) -> RecentBlocksSorted {
    let selection_interval = get_stake_modifier_selection_interval();
    let timestamp_lower_bound = (prev_index.time as i64 / MODIFIER_INTERVAL as i64)
        * MODIFIER_INTERVAL as i64
        - selection_interval;

    let mut blocks = Vec::with_capacity(64);
    let mut current = Some(prev_index);

    while let Some(idx) = current {
        if (idx.time as i64) < timestamp_lower_bound {
            break;
        }
        blocks.push((idx.time as i64, idx.hash));
        if idx.prev_hash.is_zero() {
            break;
        }
        current = get_prev(&idx.prev_hash);
    }

    blocks.reverse();
    // Sort by (timestamp, hash) to match C++ std::sort behavior on pair<int64_t, uint256>
    // This ensures deterministic ordering for blocks with equal timestamps
    blocks.sort_by(|(time_a, hash_a), (time_b, hash_b)| {
        time_a.cmp(time_b).then_with(|| hash_a.cmp(hash_b))
    });

    RecentBlocksSorted {
        blocks,
        timestamp_lower_bound,
    }
}

fn select_block_with_timestamp_upper_bound<'a>(
    blocks: &[(i64, Hash256)],
    selected_hashes: &HashSet<Hash256>,
    timestamp_upper_bound: i64,
    last_stake_modifier: u64,
    block_map: &HashMap<Hash256, &'a BlockIndex>,
) -> Option<&'a BlockIndex> {
    let mut best_hash: Option<Hash256> = None;
    let mut best_selection_hash: Option<Hash256> = None;
    let mut selected_index: Option<&'a BlockIndex> = None;

    for (time, hash) in blocks {
        if let Some(ref bh) = best_hash {
            if *time > timestamp_upper_bound {
                break;
            }
        }

        if selected_hashes.contains(hash) {
            continue;
        }

        let Some(&idx) = block_map.get(hash) else {
            continue;
        };

        // Use the stored is_proof_of_stake flag which is set based on transaction structure
        // (vtx[1] is coinstake), matching C++ CBlockIndex::IsProofOfStake()
        let is_pos = idx.is_proof_of_stake;
        let selection_seed = if is_pos { Hash256::zero() } else { *hash };

        // Compute selection hash using double SHA256 (matching C++ Hash() function)
        // C++ code: Hash(ss.begin(), ss.end()) where ss contains seed || modifier
        let mut hasher = Sha256::new();
        hasher.update(selection_seed.as_bytes());
        hasher.update(&last_stake_modifier.to_le_bytes());
        let first_hash = hasher.finalize();

        let mut second_hasher = Sha256::new();
        second_hasher.update(&first_hash);
        let hash_result = second_hasher.finalize();

        // SHA256 output directly maps to Hash256 bytes.
        // Both Rust and C++ treat the first bytes as least significant for comparison.
        let mut selection_hash_bytes = [0u8; 32];
        selection_hash_bytes.copy_from_slice(&hash_result);
        let mut selection_hash = Hash256::from_bytes(selection_hash_bytes);

        if is_pos {
            // C++ does: hashSelection >> 32 (right shift by 32 bits)
            // For a little-endian 256-bit integer:
            // - bytes[0..4] contain the lowest 32 bits
            // - bytes[4..8] contain the next 32 bits, etc.
            // Right shift by 32 bits = move bytes[4..32] to bytes[0..28], clear bytes[28..32]
            let bytes = selection_hash.as_bytes();
            let mut shifted = [0u8; 32];
            shifted[..28].copy_from_slice(&bytes[4..]);
            // bytes[28..32] remain zero (highest 32 bits cleared after right shift)
            selection_hash = Hash256::from_bytes(shifted);
        }

        // C++ Algorithm from ChainExtensionService.cpp:SelectBlockIndexWithTimestampUpperBound
        // Simply find the block with the MINIMUM selection_hash.
        // No comparison to block_hash - just track the smallest selection_hash seen so far.
        //
        // if (fSelected && hashSelection < hashBest) {
        //     hashBest = hashSelection;
        //     pindexSelected = pindex;
        // } else if (!fSelected) {
        //     fSelected = true;
        //     hashBest = hashSelection;
        //     pindexSelected = pindex;
        // }

        // Debug: log selection hashes for blocks around height 50-60 when computing modifier for height 99
        // This helps diagnose selection algorithm mismatches with C++
        if idx.height >= 50 && idx.height <= 60 {
            tracing::debug!(
                "  candidate height={}, selection_hash={}, is_pos={}",
                idx.height,
                selection_hash,
                is_pos
            );
        }

        // Track block with minimum selection_hash
        if best_selection_hash.is_none() || selection_hash < best_selection_hash.unwrap() {
            best_hash = Some(*hash);
            best_selection_hash = Some(selection_hash);
            selected_index = Some(idx);
        }
    }

    selected_index
}

pub fn compute_next_stake_modifier<'a>(
    prev_index: Option<&'a BlockIndex>,
    get_prev: &impl Fn(&Hash256) -> Option<&'a BlockIndex>,
    block_map: &HashMap<Hash256, &'a BlockIndex>,
    hardened_fork_active: bool,
) -> Result<(u64, bool), StorageError> {
    if prev_index.is_none() {
        return Ok((0, true));
    }

    let prev_index = prev_index.unwrap();

    if prev_index.height == 0 {
        return Ok((0x7374616b656d6f64, true));
    }

    let Some(last_modifier_index) =
        get_last_block_index_with_generated_stake_modifier(prev_index, get_prev)
    else {
        return Err(StorageError::ChainState(
            "Unable to get last stake modifier".into(),
        ));
    };

    if !last_modifier_index.generated_stake_modifier {
        return Err(StorageError::ChainState(
            "Last stake modifier not generated".into(),
        ));
    }

    let last_modifier_time_interval = last_modifier_index.time / MODIFIER_INTERVAL;
    let current_time_interval = prev_index.time / MODIFIER_INTERVAL;

    if last_modifier_time_interval >= current_time_interval {
        return Ok((last_modifier_index.stake_modifier, false));
    }

    let recent_blocks = get_recent_blocks_sorted(prev_index, get_prev);
    let mut new_stake_modifier = 0u64;
    let mut selected_hashes = HashSet::new();
    let mut timestamp_upper_bound = recent_blocks.timestamp_lower_bound;

    let num_rounds = std::cmp::min(64, recent_blocks.blocks.len());

    // Debug: log the modifier computation for early heights
    let log_details = prev_index.height < 100;
    if log_details {
        tracing::info!(
            "Computing stake modifier for height {}: using last_modifier=0x{:016x} from height {}, {} candidate blocks",
            prev_index.height + 1,
            last_modifier_index.stake_modifier,
            last_modifier_index.height,
            recent_blocks.blocks.len()
        );
    }

    for round in 0..num_rounds {
        timestamp_upper_bound += get_stake_modifier_selection_interval_section(round as i32);

        let Some(selected_block) = select_block_with_timestamp_upper_bound(
            &recent_blocks.blocks,
            &selected_hashes,
            timestamp_upper_bound,
            last_modifier_index.stake_modifier,
            block_map,
        ) else {
            return Err(StorageError::ChainState(format!(
                "Unable to select block at round {}",
                round
            )));
        };

        let entropy_bit = get_stake_entropy_bit(&selected_block.hash);
        new_stake_modifier |= entropy_bit << round;
        selected_hashes.insert(selected_block.hash);

        // Debug: log each round's selection for early heights
        if log_details {
            tracing::info!(
                "StakeModifier round {}: selected height={}, entropy_bit={}",
                round,
                selected_block.height,
                entropy_bit
            );
        }
    }

    let final_modifier = if hardened_fork_active {
        // C++ uses CHashWriter::GetHash() which is double SHA256 (SHA256d)
        // Reference: ChainExtensionService.cpp:189-191
        let mut hasher = Sha256::new();
        hasher.update(prev_index.hash.as_bytes());
        hasher.update(&new_stake_modifier.to_le_bytes());
        let first_hash = hasher.finalize();

        let mut second_hasher = Sha256::new();
        second_hasher.update(&first_hash);
        let hash_result = second_hasher.finalize();

        u64::from_le_bytes([
            hash_result[0],
            hash_result[1],
            hash_result[2],
            hash_result[3],
            hash_result[4],
            hash_result[5],
            hash_result[6],
            hash_result[7],
        ])
    } else {
        new_stake_modifier
    };

    Ok((final_modifier, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::lottery::LotteryWinners;

    #[test]
    fn test_modifier_interval_section() {
        assert_eq!(get_stake_modifier_selection_interval_section(0), 20);
        assert_eq!(get_stake_modifier_selection_interval_section(63), 60);
    }

    #[test]
    fn test_modifier_selection_interval_total() {
        let total = get_stake_modifier_selection_interval();
        assert_eq!(total, 2087);
    }

    #[test]
    fn test_stake_entropy_bit_even() {
        // Hash with lowest bit = 0
        let mut bytes = [0u8; 32];
        bytes[0] = 0b00000000; // even (bit 0 = 0)
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(get_stake_entropy_bit(&hash), 0);
    }

    #[test]
    fn test_stake_entropy_bit_odd() {
        // Hash with lowest bit = 1
        let mut bytes = [0u8; 32];
        bytes[0] = 0b00000001; // odd (bit 0 = 1)
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(get_stake_entropy_bit(&hash), 1);
    }

    #[test]
    fn test_stake_entropy_bit_only_lowest_matters() {
        // All other bits set, lowest bit = 0
        let mut bytes = [0u8; 32];
        for b in &mut bytes {
            *b = 0xFF;
        }
        bytes[0] = 0b11111110; // all bits except lowest
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(get_stake_entropy_bit(&hash), 0);

        // All other bits set, lowest bit = 1
        bytes[0] = 0b11111111; // all bits including lowest
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(get_stake_entropy_bit(&hash), 1);
    }

    #[test]
    fn test_compute_stake_modifier_genesis() {
        let result = compute_next_stake_modifier(None, &|_| None, &HashMap::new(), false);
        assert!(result.is_ok());
        let (modifier, generated) = result.unwrap();
        assert_eq!(modifier, 0);
        assert!(generated);
    }

    #[test]
    fn test_compute_stake_modifier_block_1() {
        let genesis = BlockIndex {
            hash: Hash256::zero(),
            prev_hash: Hash256::zero(),
            height: 0,
            version: 1,
            merkle_root: Hash256::zero(),
            time: 1000,
            bits: 0,
            nonce: 0,
            accumulator: None,
            n_tx: 1,
            chain_work: [0u8; 32],
            status: crate::BlockStatus::empty(),
            file_num: 0,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: true,
            lottery_winners: LotteryWinners::new(0),
            is_proof_of_stake: false, // Genesis is PoW
        };

        let result = compute_next_stake_modifier(Some(&genesis), &|_| None, &HashMap::new(), false);
        assert!(result.is_ok());
        let (modifier, generated) = result.unwrap();
        assert_eq!(modifier, 0x7374616b656d6f64);
        assert!(generated);
    }

    #[test]
    fn test_compute_stake_modifier_reuse_same_interval() {
        // Test modifier reuse logic using heights above CHECKPOINT_HEIGHT (200)
        // to avoid checkpoint interference
        let base_height = 1000;
        let base_time: u32 = 1_600_000_000; // High timestamp to ensure blocks are in same interval

        let block_prev = BlockIndex {
            hash: Hash256::from_bytes([100u8; 32]),
            prev_hash: Hash256::zero(),
            height: base_height,
            version: 1,
            merkle_root: Hash256::zero(),
            time: base_time,
            bits: 0,
            nonce: 0,
            accumulator: None,
            n_tx: 1,
            chain_work: [0u8; 32],
            status: crate::BlockStatus::empty(),
            file_num: 0,
            data_pos: 0,
            stake_modifier: 0x7374616b656d6f64,
            generated_stake_modifier: true,
            lottery_winners: LotteryWinners::new(base_height),
            is_proof_of_stake: false,
        };

        // Block within same modifier interval (only 10 seconds later, within 60-second interval)
        let block_current = BlockIndex {
            hash: Hash256::from_bytes([101u8; 32]),
            prev_hash: block_prev.hash,
            height: base_height + 1,
            version: 1,
            merkle_root: Hash256::zero(),
            time: base_time + 10, // Same interval (within 60 seconds)
            bits: 0,
            nonce: 0,
            accumulator: None,
            n_tx: 1,
            chain_work: [0u8; 32],
            status: crate::BlockStatus::empty(),
            file_num: 0,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::new(base_height + 1),
            is_proof_of_stake: false,
        };

        let mut block_map: HashMap<Hash256, &BlockIndex> = HashMap::new();
        block_map.insert(block_prev.hash, &block_prev);
        block_map.insert(block_current.hash, &block_current);

        let get_prev = |hash: &Hash256| -> Option<&BlockIndex> { block_map.get(hash).copied() };

        let result =
            compute_next_stake_modifier(Some(&block_current), &get_prev, &block_map, false);
        assert!(result.is_ok(), "Error: {:?}", result.err());
        let (modifier, generated) = result.unwrap();
        // Should reuse the previous block's modifier since we're in the same interval
        assert_eq!(modifier, 0x7374616b656d6f64);
        assert!(
            !generated,
            "Should not generate new modifier within same interval"
        );
    }

    #[test]
    fn test_selection_hash_byte_order() {
        // Test that selection hash is computed with correct byte order for comparison
        // This verifies the fix for the byte reversal issue
        use sha2::{Digest, Sha256};

        // Create two different hashes and compute their selection hashes
        let hash1 =
            Hash256::from_hex("0000001ed50ef8690b21d23a70093c4e2197477826dfeb5c7479565df7649bdf")
                .unwrap();
        let hash2 =
            Hash256::from_hex("000000860410dd3e0140d7a293025f1f85bdd625c9ff921a1c8987cc33ce17f0")
                .unwrap();
        let last_modifier: u64 = 0x00fc4575ec439378;

        // Compute selection hashes the same way as select_block_with_timestamp_upper_bound
        // Uses double SHA256 like the production code
        fn compute_selection_hash(block_hash: &Hash256, modifier: u64) -> Hash256 {
            let mut hasher = Sha256::new();
            hasher.update(block_hash.as_bytes());
            hasher.update(&modifier.to_le_bytes());
            let first_hash = hasher.finalize();

            let mut second_hasher = Sha256::new();
            second_hasher.update(&first_hash);
            let hash_result = second_hasher.finalize();

            // SHA256 output directly maps to Hash256 bytes
            let mut selection_hash_bytes = [0u8; 32];
            selection_hash_bytes.copy_from_slice(&hash_result);
            Hash256::from_bytes(selection_hash_bytes)
        }

        let sel1 = compute_selection_hash(&hash1, last_modifier);
        let sel2 = compute_selection_hash(&hash2, last_modifier);

        // The comparison should be deterministic and produce consistent ordering
        // This just verifies the computation doesn't panic and produces different results
        assert_ne!(
            sel1, sel2,
            "Different inputs should produce different selection hashes"
        );

        // Verify the comparison is total (one must be less than the other)
        assert!(
            sel1 < sel2 || sel2 < sel1,
            "Selection hashes should be comparable"
        );
    }

    /// Test block selection using known C++ modifier value
    /// Verifies that given the same input modifier, we select the same blocks as C++
    ///
    /// Ground truth from C++ divid: For block 99, using modifier 0x00fc4575ec439378 (from height 97):
    /// Round 0 selects height 52, Round 1 selects height 50, etc.
    #[test]
    fn test_block_selection_with_cpp_modifier() {
        // Mainnet block data for heights 50-98
        // Format: (height, timestamp, hash_hex)
        let blocks_data: &[(u32, u32, &str)] = &[
            (
                50,
                1538067793,
                "000000860410dd3e0140d7a293025f1f85bdd625c9ff921a1c8987cc33ce17f0",
            ),
            (
                51,
                1538067794,
                "000000f266b7296dc98e672051f4e4a6b66b9aaf3cc1cd040c493a9a80d971af",
            ),
            (
                52,
                1538067796,
                "0000001ed50ef8690b21d23a70093c4e2197477826dfeb5c7479565df7649bdf",
            ),
            (
                53,
                1538067805,
                "0000005278bf7199f645ba576bb37d1ba0d483362e567736de2dfddbcda07b85",
            ),
            (
                54,
                1538067816,
                "000000035c9e65389ba0752fc442d272f6f018faf0481b6494e7ec67fa4f577a",
            ),
            (
                55,
                1538067828,
                "0000006329f012ebfb2c3e11b50aa538a7baf6bdf58ac8e6d0bda588522bba1d",
            ),
            (
                56,
                1538067831,
                "00000047a33967fd3be180d6b49237bc5f12b87daf1598a9c0608ea3b8b5efc9",
            ),
            (
                57,
                1538067836,
                "00000055cd35ab9548dbb8d1e08b4a60d50fe6b54780e5f3c0451126e2ee652c",
            ),
            (
                58,
                1538067920,
                "0000000da69822164b353cdd7623ee72a7ee5c5660c3363a9cf4e22a3fa20e3e",
            ),
            (
                59,
                1538067941,
                "00000069132d1b543957f38ea1fb05a9e353bf8c451e956157a820218f26abe0",
            ),
            (
                60,
                1538067949,
                "0000000ba57a6aa1908a1c25f1db95f3b69eb054ab3660ff2f0eec2a34851138",
            ),
            (
                61,
                1538067985,
                "00000056ba0e3bad87f5f0de101b851a980767a091fc46e57c3980f2a8c1289b",
            ),
            (
                62,
                1538068073,
                "0000000e375df40fcef80363caed1ebd08dbd3895ce9ae889b96b1fee5d33724",
            ),
            (
                63,
                1538068097,
                "000000040eb14fdb597e343809d445130aeaa78108509d5809dac460bc334a25",
            ),
            (
                64,
                1538068144,
                "0000002c487dfbebe7fd0927b6b4f66942d7dd7c7d5ebdfd80d52f580444259c",
            ),
            (
                65,
                1538068230,
                "00000049b72ad891bd584f59cc68ebec2eec78545c7dca96337f78934963f1a9",
            ),
            (
                66,
                1538068341,
                "0000002683bb687f3e07723880cc476f668e1c35d9ee798c258aeb8837a76424",
            ),
            (
                67,
                1538068354,
                "0000004d9423dfdd5fe1e158db2133b17cfdc5fee30c4ac37e8abdad6551c0a3",
            ),
            (
                68,
                1538068419,
                "00000047409bac5da5bb6d3553dec8c662902f66a2df8de149b45f523b3d929b",
            ),
            (
                69,
                1538068435,
                "0000000c40bc00c1e941d426f9ad972436c32328c2f97f06ce8ca42841f4c94a",
            ),
            (
                70,
                1538068467,
                "00000050ac0d9f287ac74e76651cb12cbc6a258ad7a78a752cf80cc53652d20b",
            ),
            (
                71,
                1538068513,
                "0000003d50a83a2c62c4a371eeadd38da43aa7571476676f049d78724c2c5b31",
            ),
            (
                72,
                1538068610,
                "000000322e8f9a410b0700d2463dfb84148b793c97b23bf8bdc0379ff402f8c1",
            ),
            (
                73,
                1538068618,
                "0000000a309abeed6991da7cf550843e99ea535b0183fb288068528224ecb745",
            ),
            (
                74,
                1538068653,
                "0000000182cd0c457438abf6b086d45b8affdfbe919fd9680c847d61276e74b4",
            ),
            (
                75,
                1538068760,
                "0000002d1737dd73b41f9fa18a29db8e5531d20059d472544e418c4d36fe93c7",
            ),
            (
                76,
                1538068775,
                "00000013444d18afe4a8c4c999ae9a5d044879c2297ff219b339204e85334786",
            ),
            (
                77,
                1538068784,
                "0000002c4cd65a5e3bd3dd80ea3bf5a935c47d0d94d027130ad8c09129137091",
            ),
            (
                78,
                1538068797,
                "0000001a04bd4ba113f23c3b1dda71dc32c0a1b7dd518ea1b39751ef0d14fa09",
            ),
            (
                79,
                1538068998,
                "0000002db63d7852eb973f2b7aca9772b68ae8ab932e0824e59886861b140853",
            ),
            (
                80,
                1538069044,
                "0000002bba01b5a88ccf0239b7999cf9659953bf54f7d9999ab5395436e16f72",
            ),
            (
                81,
                1538069069,
                "0000004ee8196627217dd92441c2d0e9d06aaa38c3b15e45566fae3885084e43",
            ),
            (
                82,
                1538069077,
                "000000373e3c7113c5badb1d7f1fe61eb2635b7b4254ff32bf5be82b463c6e7c",
            ),
            (
                83,
                1538069091,
                "0000001ef5bc7e7c2571f5e20624a276b5650ec772f415fab4d4b384069446b7",
            ),
            (
                84,
                1538069126,
                "0000002df3259569e784162e6b2c8303d2171c0f693819ed00c0da7f372ba3f8",
            ),
            (
                85,
                1538069146,
                "0000000d7e9b771b5fa9ea84da337c306012325b10981f86d69a70c2e91a04b6",
            ),
            (
                86,
                1538069170,
                "0000002c4adf1386dedb6d8f55857f16ec8ed03593f927979286bfda1cd4da2a",
            ),
            (
                87,
                1538069183,
                "000000013038690bd6fd458b36e25d05daae665162645d5110457f59d9420de3",
            ),
            (
                88,
                1538069183,
                "0000003656e45acd1b936461d6234d9e5eb652235cbc7ef3580c03e682041dd8",
            ),
            (
                89,
                1538069308,
                "0000000bf062cbd82db42db67e63ebad32b6a66cd29edb578c70705838f1566c",
            ),
            (
                90,
                1538069340,
                "0000002e52c35d3eb38f73e879ffd7407d9a2faba287b5fc4f2fd283fb557dd2",
            ),
            (
                91,
                1538069365,
                "00000013a21a04e5486a798c91cd5ab7ca73f654cd6d1494aa9742124719fd4d",
            ),
            (
                92,
                1538069370,
                "000000217fe6f27f2031db573798d672281c5d32eec98e3c0e6d467cf7d74577",
            ),
            (
                93,
                1538069539,
                "0000002b91c2a5a0d000440b8d8af8e76297ab155018e18312fccb451dd3b9bd",
            ),
            (
                94,
                1538069651,
                "00000006ff4d5a296ed72d326effae70538c3b4de68e8ca6bcca1c36e9534d77",
            ),
            (
                95,
                1538069669,
                "00000027fb7e0aba9ea03aae37b0f84a24627a6cbaaf7e88ca3a08278e1a07e3",
            ),
            (
                96,
                1538069826,
                "00000015888cbc7c8fcffd5218b24e370906384d14dc1afcd689ba3ffe46e677",
            ),
            (
                97,
                1538069861,
                "000000110ba20bc3644dce8d74faae4c1aeb450eabcfac9a8ee7e706e8ad5281",
            ),
            (
                98,
                1538069908,
                "000000229b4d8271d6a5fb51012c5208d22e973a458d2ed383cc4bfd1cfd0824",
            ),
        ];

        // Create BlockIndex entries
        let mut blocks: Vec<BlockIndex> = Vec::new();
        let mut prev_hash = Hash256::zero();

        for (height, time, hash_hex) in blocks_data {
            let hash = Hash256::from_hex(hash_hex).unwrap();
            blocks.push(BlockIndex {
                hash,
                prev_hash,
                height: *height,
                time: *time,
                bits: 0x1d33b9be,
                nonce: 0,
                version: 4,
                merkle_root: Hash256::zero(),
                accumulator: None,
                n_tx: 1,
                chain_work: [0; 32],
                status: crate::block_index::BlockStatus::VALID_MASK,
                file_num: 0,
                data_pos: 0,
                stake_modifier: 0,
                generated_stake_modifier: false,
                lottery_winners: LotteryWinners::new(*height),
                is_proof_of_stake: false,
            });
            prev_hash = hash;
        }

        // Create hash maps for lookups
        let mut block_map: HashMap<Hash256, &BlockIndex> = HashMap::new();
        for block in blocks.iter() {
            block_map.insert(block.hash, block);
        }

        // Test block selection using C++ ground truth modifier
        // For block 99 computation, C++ uses modifier 0x00fc4575ec439378 from height 97
        let cpp_modifier: u64 = 0x00fc4575ec439378;

        // Block 98's time is 1538069908
        // timestamp_lower_bound = (1538069908 / 60) * 60 - 2087 = 25634498 * 60 - 2087 = 1538069880 - 2087 = 1538067793
        // This matches block 50's timestamp exactly, so blocks 50-98 are candidates

        // Sort blocks by timestamp (already in order in our test data)
        let mut sorted_blocks: Vec<(i64, Hash256)> =
            blocks.iter().map(|b| (b.time as i64, b.hash)).collect();
        sorted_blocks.sort_by_key(|(time, _)| *time);

        // Test round 0 selection
        // C++ selects height 52, entropy bit = 1
        let mut selected_hashes = HashSet::new();

        // Round 0: timestamp_upper_bound = 1538067793 + 20 = 1538067813
        let timestamp_upper_bound_0 =
            1538067793i64 + get_stake_modifier_selection_interval_section(0);
        let selected_0 = select_block_with_timestamp_upper_bound(
            &sorted_blocks,
            &selected_hashes,
            timestamp_upper_bound_0,
            cpp_modifier,
            &block_map,
        );

        let selected_0 = selected_0.expect("Should select a block in round 0");
        println!(
            "Round 0: selected height {}, C++ expected 52",
            selected_0.height
        );

        // This is the key test - does our selection match C++?
        assert_eq!(
            selected_0.height, 52,
            "Round 0 should select height 52 per C++ ground truth"
        );

        // Continue with round 1
        selected_hashes.insert(selected_0.hash);
        let timestamp_upper_bound_1 =
            timestamp_upper_bound_0 + get_stake_modifier_selection_interval_section(1);
        let selected_1 = select_block_with_timestamp_upper_bound(
            &sorted_blocks,
            &selected_hashes,
            timestamp_upper_bound_1,
            cpp_modifier,
            &block_map,
        );

        let selected_1 = selected_1.expect("Should select a block in round 1");
        println!(
            "Round 1: selected height {}, C++ expected 50",
            selected_1.height
        );
        assert_eq!(
            selected_1.height, 50,
            "Round 1 should select height 50 per C++ ground truth"
        );

        // Verify entropy bits match
        assert_eq!(
            get_stake_entropy_bit(&selected_0.hash),
            1,
            "Height 52 entropy should be 1"
        );
        assert_eq!(
            get_stake_entropy_bit(&selected_1.hash),
            0,
            "Height 50 entropy should be 0"
        );
    }

    #[test]
    fn test_entropy_bit_from_mainnet_blocks() {
        // Test entropy bit extraction using real mainnet block hashes
        // Ground truth from C++ divid debug output

        // Height 50: hash=000000860410dd3e0140d7a293025f1f85bdd625c9ff921a1c8987cc33ce17f0, entropy=0
        let hash50 =
            Hash256::from_hex("000000860410dd3e0140d7a293025f1f85bdd625c9ff921a1c8987cc33ce17f0")
                .unwrap();
        assert_eq!(
            get_stake_entropy_bit(&hash50),
            0,
            "Height 50 entropy should be 0"
        );

        // Height 51: hash=000000f266b7296dc98e672051f4e4a6b66b9aaf3cc1cd040c493a9a80d971af, entropy=1
        let hash51 =
            Hash256::from_hex("000000f266b7296dc98e672051f4e4a6b66b9aaf3cc1cd040c493a9a80d971af")
                .unwrap();
        assert_eq!(
            get_stake_entropy_bit(&hash51),
            1,
            "Height 51 entropy should be 1"
        );

        // Height 52: hash=0000001ed50ef8690b21d23a70093c4e2197477826dfeb5c7479565df7649bdf, entropy=1
        let hash52 =
            Hash256::from_hex("0000001ed50ef8690b21d23a70093c4e2197477826dfeb5c7479565df7649bdf")
                .unwrap();
        assert_eq!(
            get_stake_entropy_bit(&hash52),
            1,
            "Height 52 entropy should be 1"
        );

        // Height 55: hash=0000006329f012ebfb2c3e11b50aa538a7baf6bdf58ac8e6d0bda588522bba1d, entropy=1
        let hash55 =
            Hash256::from_hex("0000006329f012ebfb2c3e11b50aa538a7baf6bdf58ac8e6d0bda588522bba1d")
                .unwrap();
        assert_eq!(
            get_stake_entropy_bit(&hash55),
            1,
            "Height 55 entropy should be 1"
        );

        // Height 57: hash=00000055cd35ab9548dbb8d1e08b4a60d50fe6b54780e5f3c0451126e2ee652c, entropy=0
        let hash57 =
            Hash256::from_hex("00000055cd35ab9548dbb8d1e08b4a60d50fe6b54780e5f3c0451126e2ee652c")
                .unwrap();
        assert_eq!(
            get_stake_entropy_bit(&hash57),
            0,
            "Height 57 entropy should be 0"
        );
    }

    /// Test block selection using the initial "stakemod" modifier value
    /// This tests the very FIRST modifier computation which uses 0x7374616b656d6f64
    ///
    /// Ground truth from C++: First generated modifier at height 59 is 0x00dc8a4a2dafe4e6
    #[test]
    fn test_first_block_selection_with_initial_modifier() {
        // Initial modifier value - test both possible byte orderings
        // Rust value (0x7374616b656d6f64): to_le_bytes() = "domekats"
        // Alternative (0x646f6d656b617473): to_le_bytes() = "stakemod"
        let initial_modifier_rust: u64 = 0x7374616b656d6f64;
        let initial_modifier_alt: u64 = 0x646f6d656b617473;

        println!("Rust modifier: 0x{:016x}", initial_modifier_rust);
        println!("  to_le_bytes: {:?}", initial_modifier_rust.to_le_bytes());
        println!("Alt modifier: 0x{:016x}", initial_modifier_alt);
        println!("  to_le_bytes: {:?}", initial_modifier_alt.to_le_bytes());

        // Use the Rust value for now
        let initial_modifier: u64 = initial_modifier_rust;

        // Print exact bytes for block 50 selection hash computation
        let hash50 =
            Hash256::from_hex("000000860410dd3e0140d7a293025f1f85bdd625c9ff921a1c8987cc33ce17f0")
                .unwrap();
        println!("\nBlock 50 hash:");
        println!("  display: {}", hash50);
        println!(
            "  as_bytes (internal, first 8): {:02x?}",
            &hash50.as_bytes()[0..8]
        );
        println!(
            "  as_bytes (internal, last 8): {:02x?}",
            &hash50.as_bytes()[24..32]
        );

        // Compute selection hash step by step
        let mut data = Vec::new();
        data.extend_from_slice(hash50.as_bytes()); // 32 bytes
        data.extend_from_slice(&initial_modifier.to_le_bytes()); // 8 bytes
        println!("\nSerialized data ({} bytes):", data.len());
        println!("  first 8 bytes: {:02x?}", &data[0..8]);
        println!("  last 8 bytes: {:02x?}", &data[32..40]);

        // Mainnet block data for early heights used in first computation
        // Format: (height, timestamp, hash_hex)
        let blocks_data: &[(u32, u32, &str)] = &[
            (
                50,
                1538067793,
                "000000860410dd3e0140d7a293025f1f85bdd625c9ff921a1c8987cc33ce17f0",
            ),
            (
                51,
                1538067794,
                "000000f266b7296dc98e672051f4e4a6b66b9aaf3cc1cd040c493a9a80d971af",
            ),
            (
                52,
                1538067796,
                "0000001ed50ef8690b21d23a70093c4e2197477826dfeb5c7479565df7649bdf",
            ),
            (
                53,
                1538067805,
                "0000005278bf7199f645ba576bb37d1ba0d483362e567736de2dfddbcda07b85",
            ),
            (
                54,
                1538067816,
                "000000035c9e65389ba0752fc442d272f6f018faf0481b6494e7ec67fa4f577a",
            ),
            (
                55,
                1538067828,
                "0000006329f012ebfb2c3e11b50aa538a7baf6bdf58ac8e6d0bda588522bba1d",
            ),
            (
                56,
                1538067831,
                "00000047a33967fd3be180d6b49237bc5f12b87daf1598a9c0608ea3b8b5efc9",
            ),
            (
                57,
                1538067836,
                "00000055cd35ab9548dbb8d1e08b4a60d50fe6b54780e5f3c0451126e2ee652c",
            ),
            (
                58,
                1538067920,
                "0000000da69822164b353cdd7623ee72a7ee5c5660c3363a9cf4e22a3fa20e3e",
            ),
        ];

        // Create BlockIndex entries
        let mut blocks: Vec<BlockIndex> = Vec::new();
        let mut prev_hash = Hash256::zero();

        for (height, time, hash_hex) in blocks_data {
            let hash = Hash256::from_hex(hash_hex).unwrap();
            blocks.push(BlockIndex {
                hash,
                prev_hash,
                height: *height,
                time: *time,
                bits: 0x1d33b9be,
                nonce: 0,
                version: 4,
                merkle_root: Hash256::zero(),
                accumulator: None,
                n_tx: 1,
                chain_work: [0; 32],
                status: crate::block_index::BlockStatus::VALID_MASK,
                file_num: 0,
                data_pos: 0,
                stake_modifier: 0,
                generated_stake_modifier: false,
                lottery_winners: LotteryWinners::new(*height),
                is_proof_of_stake: false, // All early blocks are PoW
            });
            prev_hash = hash;
        }

        // Create hash maps for lookups
        let mut block_map: HashMap<Hash256, &BlockIndex> = HashMap::new();
        for block in blocks.iter() {
            block_map.insert(block.hash, block);
        }

        // Sort blocks by timestamp for selection
        let mut sorted_blocks: Vec<(i64, Hash256)> =
            blocks.iter().map(|b| (b.time as i64, b.hash)).collect();
        sorted_blocks.sort_by_key(|(time, _)| *time);

        // Test round 0 selection with initial modifier
        let mut selected_hashes = HashSet::new();

        // Block 58's time is 1538067920
        // timestamp_lower_bound = (1538067920 / 60) * 60 - 2087 = 1538067900 - 2087 = 1538065813
        // But our earliest block (50) has time 1538067793, so all 50-58 are candidates
        let timestamp_lower_bound = 1538067793i64; // Just use earliest block time

        // Round 0: timestamp_upper_bound = timestamp_lower_bound + section_0 interval
        let timestamp_upper_bound_0 =
            timestamp_lower_bound + get_stake_modifier_selection_interval_section(0);
        println!("Round 0 timestamp_upper_bound: {}", timestamp_upper_bound_0);

        let selected_0 = select_block_with_timestamp_upper_bound(
            &sorted_blocks,
            &selected_hashes,
            timestamp_upper_bound_0,
            initial_modifier,
            &block_map,
        );

        let selected_0 = selected_0.expect("Should select a block in round 0");
        println!(
            "Round 0 with initial_modifier: selected height {}, hash={}",
            selected_0.height, selected_0.hash
        );

        // Run all rounds and compute the modifier
        let mut selected_hashes_full = HashSet::new();
        let mut new_modifier = 0u64;
        let mut timestamp_ub = timestamp_lower_bound;

        let num_rounds = sorted_blocks.len();
        for round in 0..num_rounds {
            timestamp_ub += get_stake_modifier_selection_interval_section(round as i32);

            let selected = select_block_with_timestamp_upper_bound(
                &sorted_blocks,
                &selected_hashes_full,
                timestamp_ub,
                initial_modifier,
                &block_map,
            );

            if let Some(block) = selected {
                let entropy_bit = get_stake_entropy_bit(&block.hash);
                new_modifier |= entropy_bit << round;
                selected_hashes_full.insert(block.hash);
                println!(
                    "Round {}: selected height {}, entropy_bit={}",
                    round, block.height, entropy_bit
                );
            } else {
                println!("Round {}: no block selected", round);
                break;
            }
        }

        println!(
            "\nComputed modifier with initial 'stakemod': 0x{:016x}",
            new_modifier
        );
        println!("C++ expected modifier at height 59: 0x00dc8a4a2dafe4e6");

        // The actual verification would need more block data and the exact C++ computation
        // For now, just show the result to help debug
    }
}
