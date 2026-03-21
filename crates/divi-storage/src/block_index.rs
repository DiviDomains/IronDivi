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

//! Block index types
//!
//! The block index contains metadata about each block in the chain,
//! enabling efficient chain traversal and validation.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use divi_consensus::get_block_proof;
use divi_primitives::block::BlockHeader;
use divi_primitives::hash::Hash256;
use divi_primitives::lottery::LotteryWinners;
use std::io::Read;

/// Block status flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStatus(u32);

impl BlockStatus {
    /// Block has valid header
    pub const VALID_HEADER: BlockStatus = BlockStatus(1);
    /// Block has valid transactions
    pub const VALID_TRANSACTIONS: BlockStatus = BlockStatus(2);
    /// Block has valid chain connection
    pub const VALID_CHAIN: BlockStatus = BlockStatus(4);
    /// Block has valid scripts
    pub const VALID_SCRIPTS: BlockStatus = BlockStatus(8);
    /// Block is fully validated
    pub const VALID_MASK: BlockStatus = BlockStatus(15);
    /// Block data is stored on disk
    pub const HAVE_DATA: BlockStatus = BlockStatus(16);
    /// Block failed validation
    pub const FAILED: BlockStatus = BlockStatus(32);
    /// Block is on the main chain
    pub const ON_MAIN_CHAIN: BlockStatus = BlockStatus(64);

    /// Create empty status
    pub fn empty() -> Self {
        BlockStatus(0)
    }

    /// Check if status contains flag
    pub fn contains(&self, flag: BlockStatus) -> bool {
        (self.0 & flag.0) == flag.0
    }

    /// Add a flag
    pub fn insert(&mut self, flag: BlockStatus) {
        self.0 |= flag.0;
    }

    /// Remove a flag
    pub fn remove(&mut self, flag: BlockStatus) {
        self.0 &= !flag.0;
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Create from raw value
    pub fn from_bits(bits: u32) -> Self {
        BlockStatus(bits)
    }
}

/// Index entry for a block
#[derive(Debug, Clone)]
pub struct BlockIndex {
    /// Block hash
    pub hash: Hash256,
    /// Hash of previous block
    pub prev_hash: Hash256,
    /// Block height
    pub height: u32,
    /// Block version
    pub version: i32,
    /// Merkle root
    pub merkle_root: Hash256,
    /// Block timestamp
    pub time: u32,
    /// Difficulty target (nBits)
    pub bits: u32,
    /// Nonce
    pub nonce: u32,
    /// Accumulator (for PoS v4 blocks)
    pub accumulator: Option<Hash256>,
    /// Number of transactions in block
    pub n_tx: u32,
    /// Total chain work up to this block
    pub chain_work: [u8; 32],
    /// Block status
    pub status: BlockStatus,
    /// File number where block data is stored
    pub file_num: i32,
    /// Offset within the file
    pub data_pos: u32,
    /// Stake modifier (for PoS)
    pub stake_modifier: u64,
    /// Whether this block generated a new stake modifier
    pub generated_stake_modifier: bool,
    /// Lottery winners tracked up to this block (top 11 coinstakes)
    pub lottery_winners: LotteryWinners,
    /// Whether this block is a proof-of-stake block
    /// Set based on transaction structure (vtx[1] is coinstake)
    pub is_proof_of_stake: bool,
}

impl BlockIndex {
    /// Create a new block index from a header
    pub fn from_header(header: &BlockHeader, height: u32, prev_index: Option<&BlockIndex>) -> Self {
        // Compute chain work from difficulty
        // Work for a block is proportional to its difficulty
        let mut chain_work = [0u8; 32];
        if let Some(prev) = prev_index {
            chain_work = prev.chain_work;
        }

        // Calculate work for this block using C++ GetBlockProof formula:
        //   work = (~target / (target + 1)) + 1
        // This produces exact parity with C++ Divi chainwork values.
        let work = get_block_proof(header.bits);

        // Add work to chain_work (little-endian 256-bit addition)
        Self::add_256_to_chain_work(&mut chain_work, &work);

        BlockIndex {
            hash: Hash256::zero(), // Will be set after hashing
            prev_hash: header.prev_block,
            height,
            version: header.version,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
            accumulator: if header.version > 3 {
                Some(header.accumulator_checkpoint)
            } else {
                None
            },
            n_tx: 0,
            chain_work,
            status: BlockStatus::empty(),
            file_num: -1,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::new(height),
            is_proof_of_stake: false, // Will be set by caller based on block content
        }
    }

    /// Set the proof-of-stake flag
    pub fn set_proof_of_stake(&mut self, is_pos: bool) {
        self.is_proof_of_stake = is_pos;
    }

    /// Add a u64 work value to chain_work (256-bit little-endian addition)
    #[allow(dead_code)]
    fn add_u64_to_chain_work(chain_work: &mut [u8; 32], work: u64) {
        let mut carry: u16 = 0;
        for i in 0..32 {
            let byte_work = if i < 8 {
                ((work >> (i * 8)) & 0xff) as u16
            } else {
                0
            };
            let sum = (chain_work[i] as u16) + byte_work + carry;
            chain_work[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }

    /// Add a 256-bit work value to chain_work (little-endian addition)
    fn add_256_to_chain_work(chain_work: &mut [u8; 32], work: &[u8; 32]) {
        let mut carry: u16 = 0;
        for i in 0..32 {
            let sum = (chain_work[i] as u16) + (work[i] as u16) + carry;
            chain_work[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }

    /// Check if this block is fully validated
    pub fn is_valid(&self) -> bool {
        self.status.contains(BlockStatus::VALID_SCRIPTS)
    }

    /// Check if block data is available
    pub fn has_data(&self) -> bool {
        self.status.contains(BlockStatus::HAVE_DATA)
    }

    /// Check if this block failed validation
    pub fn failed(&self) -> bool {
        self.status.contains(BlockStatus::FAILED)
    }

    /// Check if this block is on the main chain
    pub fn is_on_main_chain(&self) -> bool {
        self.status.contains(BlockStatus::ON_MAIN_CHAIN)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(self.hash.as_bytes());
        buf.extend_from_slice(self.prev_hash.as_bytes());
        buf.write_u32::<LittleEndian>(self.height).unwrap();
        buf.write_i32::<LittleEndian>(self.version).unwrap();
        buf.extend_from_slice(self.merkle_root.as_bytes());
        buf.write_u32::<LittleEndian>(self.time).unwrap();
        buf.write_u32::<LittleEndian>(self.bits).unwrap();
        buf.write_u32::<LittleEndian>(self.nonce).unwrap();

        // Accumulator (optional)
        if let Some(acc) = &self.accumulator {
            buf.push(1);
            buf.extend_from_slice(acc.as_bytes());
        } else {
            buf.push(0);
        }

        buf.write_u32::<LittleEndian>(self.n_tx).unwrap();
        buf.extend_from_slice(&self.chain_work);
        buf.write_u32::<LittleEndian>(self.status.bits()).unwrap();
        buf.write_i32::<LittleEndian>(self.file_num).unwrap();
        buf.write_u32::<LittleEndian>(self.data_pos).unwrap();
        buf.write_u64::<LittleEndian>(self.stake_modifier).unwrap();
        buf.push(if self.generated_stake_modifier { 1 } else { 0 });

        // Serialize lottery winners
        use divi_primitives::Encodable;
        self.lottery_winners.encode(&mut buf).unwrap();

        // Serialize is_proof_of_stake flag (added for stake modifier computation)
        buf.push(if self.is_proof_of_stake { 1 } else { 0 });

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::StorageError> {
        let mut cursor = std::io::Cursor::new(data);

        let mut hash_bytes = [0u8; 32];
        cursor.read_exact(&mut hash_bytes)?;
        let hash = Hash256::from_bytes(hash_bytes);

        let mut prev_bytes = [0u8; 32];
        cursor.read_exact(&mut prev_bytes)?;
        let prev_hash = Hash256::from_bytes(prev_bytes);

        let height = cursor.read_u32::<LittleEndian>()?;
        let version = cursor.read_i32::<LittleEndian>()?;

        let mut merkle_bytes = [0u8; 32];
        cursor.read_exact(&mut merkle_bytes)?;
        let merkle_root = Hash256::from_bytes(merkle_bytes);

        let time = cursor.read_u32::<LittleEndian>()?;
        let bits = cursor.read_u32::<LittleEndian>()?;
        let nonce = cursor.read_u32::<LittleEndian>()?;

        let has_accumulator = cursor.read_u8()? != 0;
        let accumulator = if has_accumulator {
            let mut acc_bytes = [0u8; 32];
            cursor.read_exact(&mut acc_bytes)?;
            Some(Hash256::from_bytes(acc_bytes))
        } else {
            None
        };

        let n_tx = cursor.read_u32::<LittleEndian>()?;

        let mut chain_work = [0u8; 32];
        cursor.read_exact(&mut chain_work)?;

        let status = BlockStatus::from_bits(cursor.read_u32::<LittleEndian>()?);
        let file_num = cursor.read_i32::<LittleEndian>()?;
        let data_pos = cursor.read_u32::<LittleEndian>()?;
        let stake_modifier = cursor.read_u64::<LittleEndian>()?;
        let generated_stake_modifier = cursor.read_u8()? != 0;

        // Try to deserialize lottery winners (for backwards compatibility with old indexes)
        use divi_primitives::Decodable;
        let lottery_winners =
            LotteryWinners::decode(&mut cursor).unwrap_or_else(|_| LotteryWinners::new(height));

        // Try to deserialize is_proof_of_stake flag (for backwards compatibility)
        let is_proof_of_stake = cursor.read_u8().map(|v| v != 0).unwrap_or(false);

        Ok(BlockIndex {
            hash,
            prev_hash,
            height,
            version,
            merkle_root,
            time,
            bits,
            nonce,
            accumulator,
            n_tx,
            chain_work,
            status,
            file_num,
            data_pos,
            stake_modifier,
            generated_stake_modifier,
            lottery_winners,
            is_proof_of_stake,
        })
    }
}

/// Key for block index storage by hash
pub fn block_index_key(hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 32);
    key.push(b'b'); // Prefix for block index
    key.extend_from_slice(hash.as_bytes());
    key
}

/// Key for block index by height
pub fn height_key(height: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 4);
    key.push(b'h'); // Prefix for height lookup
    key.write_u32::<LittleEndian>(height).unwrap();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_status_flags() {
        let mut status = BlockStatus::empty();
        assert!(!status.contains(BlockStatus::VALID_HEADER));

        status.insert(BlockStatus::VALID_HEADER);
        assert!(status.contains(BlockStatus::VALID_HEADER));

        status.insert(BlockStatus::HAVE_DATA);
        assert!(status.contains(BlockStatus::VALID_HEADER));
        assert!(status.contains(BlockStatus::HAVE_DATA));

        status.remove(BlockStatus::VALID_HEADER);
        assert!(!status.contains(BlockStatus::VALID_HEADER));
        assert!(status.contains(BlockStatus::HAVE_DATA));
    }

    #[test]
    fn test_block_index_roundtrip() {
        let index = BlockIndex {
            hash: Hash256::from_bytes([1u8; 32]),
            prev_hash: Hash256::from_bytes([2u8; 32]),
            height: 100000,
            version: 4,
            merkle_root: Hash256::from_bytes([3u8; 32]),
            time: 1638000000,
            bits: 0x1d00ffff,
            nonce: 12345,
            accumulator: Some(Hash256::from_bytes([4u8; 32])),
            n_tx: 50,
            chain_work: [5u8; 32],
            status: BlockStatus::from_bits(0x17), // VALID_MASK | HAVE_DATA
            file_num: 0,
            data_pos: 1000,
            stake_modifier: 0xdeadbeef,
            generated_stake_modifier: true,
            lottery_winners: LotteryWinners::new(100000),
            is_proof_of_stake: true,
        };

        let bytes = index.to_bytes();
        let decoded = BlockIndex::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.hash, index.hash);
        assert_eq!(decoded.prev_hash, index.prev_hash);
        assert_eq!(decoded.height, index.height);
        assert_eq!(decoded.version, index.version);
        assert_eq!(decoded.time, index.time);
        assert_eq!(decoded.bits, index.bits);
        assert_eq!(decoded.nonce, index.nonce);
        assert_eq!(decoded.accumulator, index.accumulator);
        assert_eq!(decoded.n_tx, index.n_tx);
        assert_eq!(decoded.chain_work, index.chain_work);
        assert_eq!(decoded.status.bits(), index.status.bits());
        assert_eq!(decoded.stake_modifier, index.stake_modifier);
        assert!(decoded.generated_stake_modifier);
        assert!(decoded.is_proof_of_stake);
    }

    #[test]
    fn test_block_index_without_accumulator() {
        let index = BlockIndex {
            hash: Hash256::zero(),
            prev_hash: Hash256::zero(),
            height: 0,
            version: 3,
            merkle_root: Hash256::zero(),
            time: 0,
            bits: 0,
            nonce: 0,
            accumulator: None,
            n_tx: 0,
            chain_work: [0u8; 32],
            status: BlockStatus::empty(),
            file_num: -1,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::new(0),
            is_proof_of_stake: false,
        };

        let bytes = index.to_bytes();
        let decoded = BlockIndex::from_bytes(&bytes).unwrap();

        assert!(decoded.accumulator.is_none());
        assert!(!decoded.is_proof_of_stake);
    }

    // ================================================================
    // Key functions
    // ================================================================

    #[test]
    fn test_block_index_key_format() {
        let hash = Hash256::from_bytes([0xab; 32]);
        let key = block_index_key(&hash);

        assert_eq!(key[0], b'b');
        assert_eq!(&key[1..], hash.as_bytes());
        assert_eq!(key.len(), 33);
    }

    #[test]
    fn test_block_index_key_uniqueness() {
        let hash1 = Hash256::from_bytes([0x01; 32]);
        let hash2 = Hash256::from_bytes([0x02; 32]);
        assert_ne!(block_index_key(&hash1), block_index_key(&hash2));
    }

    #[test]
    fn test_height_key_format() {
        let key0 = height_key(0);
        assert_eq!(key0[0], b'h');
        assert_eq!(&key0[1..], &[0u8, 0, 0, 0]);
        assert_eq!(key0.len(), 5);

        let key1 = height_key(1);
        assert_eq!(&key1[1..], &[1u8, 0, 0, 0]);

        let key256 = height_key(256);
        assert_eq!(&key256[1..], &[0u8, 1, 0, 0]);

        let key_max = height_key(u32::MAX);
        assert_eq!(&key_max[1..], &[0xffu8, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_height_key_uniqueness() {
        assert_ne!(height_key(0), height_key(1));
        assert_ne!(height_key(100), height_key(101));
        assert_eq!(height_key(500), height_key(500));
    }

    // ================================================================
    // BlockStatus flag combinations
    // ================================================================

    #[test]
    fn test_block_status_all_flags() {
        let mut status = BlockStatus::empty();

        // Add all flags
        status.insert(BlockStatus::VALID_HEADER);
        status.insert(BlockStatus::VALID_TRANSACTIONS);
        status.insert(BlockStatus::VALID_CHAIN);
        status.insert(BlockStatus::VALID_SCRIPTS);
        status.insert(BlockStatus::HAVE_DATA);
        status.insert(BlockStatus::FAILED);
        status.insert(BlockStatus::ON_MAIN_CHAIN);

        assert!(status.contains(BlockStatus::VALID_HEADER));
        assert!(status.contains(BlockStatus::VALID_TRANSACTIONS));
        assert!(status.contains(BlockStatus::VALID_CHAIN));
        assert!(status.contains(BlockStatus::VALID_SCRIPTS));
        assert!(status.contains(BlockStatus::HAVE_DATA));
        assert!(status.contains(BlockStatus::FAILED));
        assert!(status.contains(BlockStatus::ON_MAIN_CHAIN));
    }

    #[test]
    fn test_block_status_bits_roundtrip() {
        let status = BlockStatus::from_bits(0x1F); // First 5 flags
        assert_eq!(status.bits(), 0x1F);
        assert!(status.contains(BlockStatus::VALID_HEADER)); // bit 1
        assert!(status.contains(BlockStatus::VALID_TRANSACTIONS)); // bit 2
        assert!(status.contains(BlockStatus::VALID_CHAIN)); // bit 4
        assert!(status.contains(BlockStatus::VALID_SCRIPTS)); // bit 8
        assert!(status.contains(BlockStatus::HAVE_DATA)); // bit 16
    }

    #[test]
    fn test_block_status_remove_nonexistent() {
        // Removing a flag not set should be a no-op
        let mut status = BlockStatus::empty();
        status.remove(BlockStatus::VALID_HEADER);
        assert_eq!(status.bits(), 0);
    }

    // ================================================================
    // BlockIndex helper methods
    // ================================================================

    #[test]
    fn test_block_index_is_valid() {
        let mut index = BlockIndex {
            hash: Hash256::zero(),
            prev_hash: Hash256::zero(),
            height: 0,
            version: 4,
            merkle_root: Hash256::zero(),
            time: 0,
            bits: 0,
            nonce: 0,
            accumulator: None,
            n_tx: 0,
            chain_work: [0u8; 32],
            status: BlockStatus::empty(),
            file_num: -1,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::new(0),
            is_proof_of_stake: false,
        };

        assert!(!index.is_valid());
        assert!(!index.has_data());
        assert!(!index.failed());
        assert!(!index.is_on_main_chain());

        index.status.insert(BlockStatus::VALID_SCRIPTS);
        assert!(index.is_valid());

        index.status.insert(BlockStatus::HAVE_DATA);
        assert!(index.has_data());

        index.status.insert(BlockStatus::FAILED);
        assert!(index.failed());

        index.status.insert(BlockStatus::ON_MAIN_CHAIN);
        assert!(index.is_on_main_chain());
    }

    #[test]
    fn test_block_index_set_proof_of_stake() {
        let mut index = BlockIndex {
            hash: Hash256::zero(),
            prev_hash: Hash256::zero(),
            height: 100,
            version: 4,
            merkle_root: Hash256::zero(),
            time: 1_700_000_000,
            bits: 0x1e0fffff,
            nonce: 0,
            accumulator: None,
            n_tx: 2,
            chain_work: [0u8; 32],
            status: BlockStatus::empty(),
            file_num: 0,
            data_pos: 0,
            stake_modifier: 0,
            generated_stake_modifier: false,
            lottery_winners: LotteryWinners::new(100),
            is_proof_of_stake: false,
        };

        assert!(!index.is_proof_of_stake);
        index.set_proof_of_stake(true);
        assert!(index.is_proof_of_stake);
        index.set_proof_of_stake(false);
        assert!(!index.is_proof_of_stake);
    }

    // ================================================================
    // BlockIndex::from_header
    // ================================================================

    #[test]
    fn test_block_index_from_header_genesis() {
        use divi_primitives::block::BlockHeader;

        let header = BlockHeader {
            version: 3,
            prev_block: Hash256::zero(),
            merkle_root: Hash256::from_bytes([0x11; 32]),
            time: 1_609_459_200,
            bits: 0x1e0fffff,
            nonce: 12345,
            accumulator_checkpoint: Hash256::zero(),
        };

        let idx = BlockIndex::from_header(&header, 0, None);

        assert_eq!(idx.height, 0);
        assert_eq!(idx.version, 3);
        assert_eq!(idx.prev_hash, Hash256::zero());
        assert_eq!(idx.merkle_root, header.merkle_root);
        assert_eq!(idx.time, header.time);
        assert_eq!(idx.bits, header.bits);
        assert_eq!(idx.nonce, header.nonce);
        assert_eq!(idx.n_tx, 0);
        assert!(!idx.is_proof_of_stake);
        // Genesis has no accumulator (version <= 3)
        assert!(idx.accumulator.is_none());
    }

    #[test]
    fn test_block_index_from_header_v4_has_accumulator() {
        use divi_primitives::block::BlockHeader;

        let header = BlockHeader {
            version: 4, // v4+ has accumulator
            prev_block: Hash256::from_bytes([0x01; 32]),
            merkle_root: Hash256::from_bytes([0x02; 32]),
            time: 1_700_000_000,
            bits: 0x1e0fffff,
            nonce: 99,
            accumulator_checkpoint: Hash256::from_bytes([0x33; 32]),
        };

        let idx = BlockIndex::from_header(&header, 1000, None);

        assert!(idx.accumulator.is_some());
        assert_eq!(idx.accumulator.unwrap(), header.accumulator_checkpoint);
    }

    #[test]
    fn test_block_index_from_header_chain_work_accumulates() {
        use divi_primitives::block::BlockHeader;

        let header = BlockHeader {
            version: 3,
            prev_block: Hash256::zero(),
            merkle_root: Hash256::zero(),
            time: 1_000_000,
            bits: 0x1e0fffff,
            nonce: 0,
            accumulator_checkpoint: Hash256::zero(),
        };

        let idx0 = BlockIndex::from_header(&header, 0, None);
        // Chain work should be non-zero even from genesis
        let has_work = idx0.chain_work.iter().any(|&b| b != 0);
        assert!(
            has_work,
            "chain_work should be non-zero after genesis block"
        );

        let idx1 = BlockIndex::from_header(&header, 1, Some(&idx0));
        // Both idx0 and idx1 should have non-zero chain_work
        let work0_nonzero = idx0.chain_work.iter().any(|&b| b != 0);
        let work1_nonzero = idx1.chain_work.iter().any(|&b| b != 0);
        assert!(work0_nonzero, "Genesis chain_work should be non-zero");
        assert!(work1_nonzero, "Height-1 chain_work should be non-zero");

        // Compare as 256-bit little-endian: height-1 should have strictly more work
        // (compare from MSB down)
        let mut idx1_greater = false;
        for i in (0..32).rev() {
            if idx1.chain_work[i] > idx0.chain_work[i] {
                idx1_greater = true;
                break;
            } else if idx1.chain_work[i] < idx0.chain_work[i] {
                break;
            }
        }
        assert!(
            idx1_greater,
            "Chain work must increase: work0={:02x?}, work1={:02x?}",
            &idx0.chain_work[..8],
            &idx1.chain_work[..8]
        );
    }

    #[test]
    fn test_get_block_proof_pos_target() {
        use divi_consensus::get_block_proof;
        // For PoS target bits = 0x1e0fffff (easiest target),
        // verify get_block_proof returns a non-zero work value.
        let work = get_block_proof(0x1e0fffff);
        let has_work = work.iter().any(|&b| b != 0);
        assert!(
            has_work,
            "get_block_proof(0x1e0fffff) should produce non-zero work"
        );
    }

    #[test]
    fn test_get_block_proof_higher_difficulty() {
        use divi_consensus::get_block_proof;
        // Higher difficulty (lower target) should produce more work
        let work_easy = get_block_proof(0x1e0fffff);
        let work_hard = get_block_proof(0x1d00ffff); // 256x harder

        // Compare as 256-bit LE: work_hard should be > work_easy
        let mut hard_greater = false;
        for i in (0..32).rev() {
            if work_hard[i] > work_easy[i] {
                hard_greater = true;
                break;
            } else if work_hard[i] < work_easy[i] {
                break;
            }
        }
        assert!(hard_greater, "Higher difficulty should produce more work");
    }

    #[test]
    fn test_get_block_proof_zero_bits() {
        use divi_consensus::get_block_proof;
        let work = get_block_proof(0);
        assert_eq!(work, [0u8; 32], "Zero bits should produce zero work");
    }
}
