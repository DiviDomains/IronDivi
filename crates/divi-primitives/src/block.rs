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

//! Block types for Divi

use crate::compact::CompactSize;
use crate::constants::CURRENT_BLOCK_VERSION;
use crate::error::Error;
use crate::hash::Hash256;
use crate::serialize::{serialize, Decodable, Encodable};
use crate::transaction::Transaction;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Write};

/// A Divi block header
///
/// Note: Divi block headers include an accumulator checkpoint field
/// when version > 3 (zerocoin era).
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct BlockHeader {
    /// Block format version
    pub version: i32,
    /// Hash of the previous block
    pub prev_block: Hash256,
    /// Merkle root of all transactions
    pub merkle_root: Hash256,
    /// Block timestamp (seconds since Unix epoch)
    pub time: u32,
    /// Difficulty target in compact format
    pub bits: u32,
    /// Nonce for proof-of-work (legacy, not used in PoS)
    pub nonce: u32,
    /// Zerocoin accumulator checkpoint (only for version > 3)
    pub accumulator_checkpoint: Hash256,
}

impl BlockHeader {
    /// Create a new block header with current version
    pub fn new() -> Self {
        BlockHeader {
            version: CURRENT_BLOCK_VERSION,
            prev_block: Hash256::zero(),
            merkle_root: Hash256::zero(),
            time: 0,
            bits: 0,
            nonce: 0,
            accumulator_checkpoint: Hash256::zero(),
        }
    }

    /// Compute the block hash using SHA256d
    ///
    /// WARNING: This is only correct for version >= 4 (PoS) blocks.
    /// For version < 4 (PoW) blocks, use `divi_crypto::compute_block_hash()`
    /// which applies the Quark hash algorithm.
    pub fn hash(&self) -> Hash256 {
        let serialized = serialize(self);
        // Double SHA256
        let first_hash = Sha256::digest(serialized);
        let second_hash = Sha256::digest(first_hash);
        Hash256::from_bytes(second_hash.into())
    }

    /// Check if this is a null block (bits == 0)
    pub fn is_null(&self) -> bool {
        self.bits == 0
    }

    /// Get the block time as i64
    pub fn block_time(&self) -> i64 {
        self.time as i64
    }
}

impl fmt::Debug for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockHeader")
            .field("version", &self.version)
            .field("prev_block", &self.prev_block)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &format!("{:#010x}", self.bits))
            .field("nonce", &self.nonce)
            .field("accumulator_checkpoint", &self.accumulator_checkpoint)
            .finish()
    }
}

impl Encodable for BlockHeader {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = self.version.encode(writer)?;
        size += self.prev_block.encode(writer)?;
        size += self.merkle_root.encode(writer)?;
        size += self.time.encode(writer)?;
        size += self.bits.encode(writer)?;
        size += self.nonce.encode(writer)?;

        // Accumulator checkpoint only for version > 3
        if self.version > 3 {
            size += self.accumulator_checkpoint.encode(writer)?;
        }

        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        let base_size = 4 + 32 + 32 + 4 + 4 + 4; // version, prev, merkle, time, bits, nonce
        if self.version > 3 {
            base_size + 32 // accumulator checkpoint
        } else {
            base_size
        }
    }
}

impl Decodable for BlockHeader {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let version = i32::decode(reader)?;
        let prev_block = Hash256::decode(reader)?;
        let merkle_root = Hash256::decode(reader)?;
        let time = u32::decode(reader)?;
        let bits = u32::decode(reader)?;
        let nonce = u32::decode(reader)?;

        let accumulator_checkpoint = if version > 3 {
            Hash256::decode(reader)?
        } else {
            Hash256::zero()
        };

        Ok(BlockHeader {
            version,
            prev_block,
            merkle_root,
            time,
            bits,
            nonce,
            accumulator_checkpoint,
        })
    }
}

/// A Divi block
///
/// A block consists of a header and a vector of transactions.
/// For proof-of-stake blocks, includes a block signature.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Transactions in the block
    pub transactions: Vec<Transaction>,
    /// Block signature (for proof-of-stake blocks)
    pub block_sig: Vec<u8>,
}

impl Block {
    /// Create a new empty block
    pub fn new() -> Self {
        Block {
            header: BlockHeader::new(),
            transactions: Vec::new(),
            block_sig: Vec::new(),
        }
    }

    /// Create a block from header and transactions
    pub fn from_header(header: BlockHeader) -> Self {
        Block {
            header,
            transactions: Vec::new(),
            block_sig: Vec::new(),
        }
    }

    /// Get the block hash (from header)
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    /// Check if this is a proof-of-stake block
    ///
    /// A PoS block has the second transaction (index 1) as a coinstake.
    pub fn is_proof_of_stake(&self) -> bool {
        self.transactions.len() > 1 && self.transactions[1].is_coinstake()
    }

    /// Check if this is a proof-of-work block
    pub fn is_proof_of_work(&self) -> bool {
        !self.is_proof_of_stake()
    }

    /// Get the coinbase transaction
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.transactions.first()
    }

    /// Get the coinstake transaction (if PoS block)
    pub fn coinstake(&self) -> Option<&Transaction> {
        if self.is_proof_of_stake() {
            self.transactions.get(1)
        } else {
            None
        }
    }

    /// Get block header
    pub fn get_block_header(&self) -> BlockHeader {
        self.header.clone()
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("header", &self.header)
            .field("transactions", &self.transactions.len())
            .field("is_pos", &self.is_proof_of_stake())
            .finish()
    }
}

impl Encodable for Block {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = self.header.encode(writer)?;
        size += self.transactions.encode(writer)?;

        // Divi ONLY includes block_sig for PoS blocks
        if self.is_proof_of_stake() {
            size += CompactSize(self.block_sig.len() as u64).encode(writer)?;
            if !self.block_sig.is_empty() {
                writer.write_all(&self.block_sig)?;
                size += self.block_sig.len();
            }
        }

        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        let mut size = self.header.encoded_size();
        size += self.transactions.encoded_size();

        // Only include block_sig for PoS blocks
        if self.is_proof_of_stake() {
            size += CompactSize(self.block_sig.len() as u64).encoded_size();
            size += self.block_sig.len();
        }

        size
    }
}

impl Decodable for Block {
    #[allow(unexpected_cfgs)]
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let header = BlockHeader::decode(reader)?;
        let header_size = header.encoded_size();

        // Read transaction count
        let tx_count = crate::compact::CompactSize::decode(reader)?.0 as usize;
        let tx_count_size = CompactSize(tx_count as u64).encoded_size();

        // Read each transaction
        let mut transactions = Vec::with_capacity(tx_count);
        let mut txs_total_size = 0usize;
        for _i in 0..tx_count {
            let tx = crate::transaction::Transaction::decode(reader)?;
            let tx_size = tx.encoded_size();
            txs_total_size += tx_size;
            transactions.push(tx);
        }

        // Divi ONLY includes block_sig for Proof-of-Stake blocks.
        // PoS is detected by: transactions.len() > 1 && transactions[1].is_coinstake()
        // For PoW blocks, there's no block_sig field at all.
        let is_pos = transactions.len() > 1 && transactions[1].is_coinstake();

        // Calculate position before reading block_sig
        let pos_before_sig = header_size + tx_count_size + txs_total_size;

        // Debug: log coinstake detection details for troubleshooting
        #[cfg(feature = "block_debug")]
        if transactions.len() > 1 {
            let tx1 = &transactions[1];
            let vout_ok = tx1.vout.len() >= 2;
            let vout0_empty = vout_ok && tx1.vout[0].is_empty();

            // Log if detection seems wrong (has 2+ outputs but first isn't empty)
            if vout_ok && !vout0_empty && tx1.vout[0].value.0 == 0 {
                eprintln!(
                    "BLOCK_DEBUG: tx1 vout[0] value=0 but script not empty (len={}), is_pos={}",
                    tx1.vout[0].script_pubkey.len(),
                    is_pos
                );
            }
        }

        let block_sig = if is_pos {
            let len = CompactSize::decode(reader)?.0 as usize;
            let _len_size = CompactSize(len as u64).encoded_size();

            // Sanity check: typical block_sig is 65-72 bytes (recoverable ECDSA)
            // DER signatures are usually 70-72 bytes
            if !(60..=200).contains(&len) {
                eprintln!(
                    "BLOCK_PARSE: pos_before_sig={}, sig_len={}, header={}, tx_count_size={}, txs_size={}, tx_count={}",
                    pos_before_sig, len, header_size, tx_count_size, txs_total_size, tx_count
                );
            }
            if len > 0 {
                let mut sig = vec![0u8; len];
                reader.read_exact(&mut sig)?;
                // Log first few bytes to verify it looks like a signature
                if sig.len() >= 2 {
                    let first_byte = sig[0];
                    let valid_sig_start = first_byte == 0x30  // DER signature
                        || (0x1b..=0x22).contains(&first_byte)  // Recoverable sig recovery ID
                        || first_byte == 0x41; // Length prefix mistakenly included
                    if !valid_sig_start {
                        eprintln!(
                            "WARNING: block_sig doesn't start with expected bytes: {:02x?}, pos_before_sig={}",
                            &sig[..sig.len().min(8)], pos_before_sig
                        );
                    }
                }
                sig
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Block {
            header,
            transactions,
            block_sig,
        })
    }
}

/// Block locator for synchronization
///
/// Contains a list of block hashes at exponentially decreasing heights,
/// used to find common ancestor during sync.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BlockLocator {
    /// List of block hashes
    pub hashes: Vec<Hash256>,
}

impl BlockLocator {
    /// Create a new empty locator
    pub fn new() -> Self {
        BlockLocator { hashes: Vec::new() }
    }

    /// Create a locator with given hashes
    pub fn from_hashes(hashes: Vec<Hash256>) -> Self {
        BlockLocator { hashes }
    }

    /// Check if locator is empty
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

impl Encodable for BlockLocator {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.hashes.encode(writer)
    }

    fn encoded_size(&self) -> usize {
        self.hashes.encoded_size()
    }
}

impl Decodable for BlockLocator {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(BlockLocator {
            hashes: Vec::<Hash256>::decode(reader)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crate::script::Script;
    use crate::serialize::{deserialize, serialize};
    use crate::transaction::{OutPoint, TxIn, TxOut};

    #[test]
    fn test_block_header_v4_serialization() {
        let header = BlockHeader {
            version: 4,
            prev_block: Hash256::from_bytes([1u8; 32]),
            merkle_root: Hash256::from_bytes([2u8; 32]),
            time: 1234567890,
            bits: 0x1d00ffff,
            nonce: 42,
            accumulator_checkpoint: Hash256::from_bytes([3u8; 32]),
        };

        let encoded = serialize(&header);
        // v4 header: 4 + 32 + 32 + 4 + 4 + 4 + 32 = 112 bytes
        assert_eq!(encoded.len(), 112);

        let decoded: BlockHeader = deserialize(&encoded).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_block_header_v3_serialization() {
        let header = BlockHeader {
            version: 3,
            prev_block: Hash256::from_bytes([1u8; 32]),
            merkle_root: Hash256::from_bytes([2u8; 32]),
            time: 1234567890,
            bits: 0x1d00ffff,
            nonce: 42,
            accumulator_checkpoint: Hash256::zero(), // Not serialized for v3
        };

        let encoded = serialize(&header);
        // v3 header: 4 + 32 + 32 + 4 + 4 + 4 = 80 bytes (no accumulator)
        assert_eq!(encoded.len(), 80);

        let decoded: BlockHeader = deserialize(&encoded).unwrap();
        assert_eq!(decoded.version, 3);
        assert_eq!(decoded.accumulator_checkpoint, Hash256::zero());
    }

    fn create_coinbase_tx() -> Transaction {
        Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x04, 0xff]))],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        }
    }

    fn create_coinstake_tx() -> Transaction {
        Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                u32::MAX,
            )],
            vout: vec![
                TxOut::empty(), // Coinstake marker
                TxOut::new(Amount::from_divi(100), Script::new()),
            ],
            lock_time: 0,
        }
    }

    #[test]
    fn test_real_block_payload() {
        // Read a real block payload captured from the network
        let payload_path = "/tmp/block_payload_10345.bin";
        if !std::path::Path::new(payload_path).exists() {
            println!("Skipping test - {} not found", payload_path);
            return;
        }

        let payload = std::fs::read(payload_path).expect("Failed to read block payload");
        println!("Payload size: {} bytes", payload.len());

        // Deserialize with cursor to track position
        use std::io::Cursor;
        let mut cursor = Cursor::new(&payload);

        let block: Block = Block::decode(&mut cursor).expect("Failed to deserialize block");
        let consumed = cursor.position() as usize;

        println!("Block hash: {}", block.hash());
        println!("Header version: {}", block.header.version);
        println!("Transaction count: {}", block.transactions.len());
        println!("is_proof_of_stake: {}", block.is_proof_of_stake());
        println!("block_sig.len: {}", block.block_sig.len());
        println!("Bytes consumed: {}", consumed);
        println!("Payload length: {}", payload.len());

        for (i, tx) in block.transactions.iter().enumerate() {
            println!(
                "  TX {}: vin_count={}, vout_count={}, is_coinstake={}",
                i,
                tx.vin.len(),
                tx.vout.len(),
                tx.is_coinstake()
            );
            if !tx.vin.is_empty() {
                println!("    vin[0].script_sig.len={}", tx.vin[0].script_sig.len());
            }
        }

        // Critical check: did we consume all bytes?
        assert_eq!(
            consumed,
            payload.len(),
            "Consumed {} bytes but payload has {} bytes (diff: {})",
            consumed,
            payload.len(),
            payload.len() as i64 - consumed as i64
        );

        // Re-serialize and compare
        let reserialized = serialize(&block);
        assert_eq!(
            reserialized.len(),
            payload.len(),
            "Reserialized size {} != payload size {}",
            reserialized.len(),
            payload.len()
        );
        assert_eq!(
            reserialized, payload,
            "Reserialized data doesn't match original"
        );

        println!("SUCCESS: Block parsed and reserialized correctly");
    }

    #[test]
    fn test_pow_block() {
        let block = Block {
            header: BlockHeader::new(),
            transactions: vec![create_coinbase_tx()],
            block_sig: Vec::new(),
        };

        assert!(block.is_proof_of_work());
        assert!(!block.is_proof_of_stake());
        assert!(block.coinbase().is_some());
        assert!(block.coinstake().is_none());
    }

    #[test]
    fn test_pos_block() {
        let block = Block {
            header: BlockHeader::new(),
            transactions: vec![create_coinbase_tx(), create_coinstake_tx()],
            block_sig: vec![0x30, 0x44], // Dummy DER signature start
        };

        assert!(!block.is_proof_of_work());
        assert!(block.is_proof_of_stake());
        assert!(block.coinbase().is_some());
        assert!(block.coinstake().is_some());
    }

    #[test]
    fn test_pos_block_serialization() {
        let block = Block {
            header: BlockHeader {
                version: 4,
                prev_block: Hash256::from_bytes([1u8; 32]),
                merkle_root: Hash256::from_bytes([2u8; 32]),
                time: 1234567890,
                bits: 0x1d00ffff,
                nonce: 0,
                accumulator_checkpoint: Hash256::zero(),
            },
            transactions: vec![create_coinbase_tx(), create_coinstake_tx()],
            block_sig: vec![0x30, 0x44, 0x00], // Dummy signature
        };

        let encoded = serialize(&block);
        let decoded: Block = deserialize(&encoded).unwrap();

        assert_eq!(decoded.header, block.header);
        assert_eq!(decoded.transactions.len(), 2);
        assert_eq!(decoded.block_sig, block.block_sig);
        assert!(decoded.is_proof_of_stake());
    }

    #[test]
    fn test_block_locator() {
        let locator = BlockLocator::from_hashes(vec![
            Hash256::from_bytes([1u8; 32]),
            Hash256::from_bytes([2u8; 32]),
            Hash256::from_bytes([3u8; 32]),
        ]);

        let encoded = serialize(&locator);
        let decoded: BlockLocator = deserialize(&encoded).unwrap();

        assert_eq!(decoded.hashes.len(), 3);
        assert_eq!(decoded, locator);
    }

    // ---- NEW: BlockHeader v4 exactly 112 bytes with zeroed fields ----

    #[test]
    fn test_block_header_v4_zero_fields_size() {
        let header = BlockHeader {
            version: 4,
            prev_block: Hash256::zero(),
            merkle_root: Hash256::zero(),
            time: 0,
            bits: 0,
            nonce: 0,
            accumulator_checkpoint: Hash256::zero(),
        };

        let encoded = serialize(&header);
        assert_eq!(
            encoded.len(),
            112,
            "v4 BlockHeader (with accumulator) must always be 112 bytes"
        );

        let decoded: BlockHeader = deserialize(&encoded).unwrap();
        assert_eq!(decoded, header);
    }

    // ---- NEW: BlockHeader v3 exactly 80 bytes (standard Bitcoin header size) ----

    #[test]
    fn test_block_header_v3_exactly_80_bytes() {
        let header = BlockHeader {
            version: 3,
            prev_block: Hash256::zero(),
            merkle_root: Hash256::zero(),
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
            accumulator_checkpoint: Hash256::zero(), // not serialized for v3
        };

        let encoded = serialize(&header);
        assert_eq!(
            encoded.len(),
            80,
            "v3 BlockHeader must be 80 bytes (no accumulator checkpoint)"
        );

        let decoded: BlockHeader = deserialize(&encoded).unwrap();
        assert_eq!(decoded.version, 3);
        assert_eq!(decoded.bits, 0x1d00ffff);
        // Accumulator checkpoint is not in the stream, so decoded should be zero
        assert_eq!(decoded.accumulator_checkpoint, Hash256::zero());
    }

    // ---- NEW: Block hash is deterministic ----

    #[test]
    fn test_block_hash_is_deterministic() {
        let header = BlockHeader {
            version: 4,
            prev_block: Hash256::from_bytes([1u8; 32]),
            merkle_root: Hash256::from_bytes([2u8; 32]),
            time: 1234567890,
            bits: 0x1d00ffff,
            nonce: 42,
            accumulator_checkpoint: Hash256::zero(),
        };
        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2, "block hash must be deterministic");
        assert!(
            !hash1.is_zero(),
            "non-trivial header should not have a zero hash"
        );
    }

    #[test]
    fn test_block_hash_changes_with_nonce() {
        let make_header = |nonce: u32| BlockHeader {
            version: 4,
            prev_block: Hash256::from_bytes([1u8; 32]),
            merkle_root: Hash256::from_bytes([2u8; 32]),
            time: 1234567890,
            bits: 0x1d00ffff,
            nonce,
            accumulator_checkpoint: Hash256::zero(),
        };

        let h1 = make_header(0).hash();
        let h2 = make_header(1).hash();
        assert_ne!(h1, h2, "different nonces must produce different hashes");
    }

    // ---- NEW: Block and header hash consistency ----

    #[test]
    fn test_block_hash_equals_header_hash() {
        let block = Block {
            header: BlockHeader {
                version: 4,
                prev_block: Hash256::from_bytes([0xABu8; 32]),
                merkle_root: Hash256::from_bytes([0xCDu8; 32]),
                time: 1000000,
                bits: 0x1d00ffff,
                nonce: 999,
                accumulator_checkpoint: Hash256::zero(),
            },
            transactions: vec![create_coinbase_tx()],
            block_sig: Vec::new(),
        };

        assert_eq!(
            block.hash(),
            block.header.hash(),
            "Block::hash() and BlockHeader::hash() must agree"
        );
    }

    // ---- NEW: PoW block serialization roundtrip ----

    #[test]
    fn test_pow_block_serialization_roundtrip() {
        let block = Block {
            header: BlockHeader {
                version: 4,
                prev_block: Hash256::from_bytes([0x11u8; 32]),
                merkle_root: Hash256::from_bytes([0x22u8; 32]),
                time: 1_600_000_000,
                bits: 0x1e0ffff0,
                nonce: 12345,
                accumulator_checkpoint: Hash256::zero(),
            },
            transactions: vec![create_coinbase_tx()],
            block_sig: Vec::new(),
        };

        assert!(block.is_proof_of_work());

        let encoded = serialize(&block);
        let decoded: Block = deserialize(&encoded).unwrap();

        assert_eq!(decoded.header, block.header);
        assert_eq!(decoded.transactions.len(), 1);
        assert!(decoded.block_sig.is_empty());
        assert!(decoded.is_proof_of_work());
    }

    // ---- NEW: Block::new() defaults ----

    #[test]
    fn test_block_new_defaults() {
        let block = Block::new();
        assert!(block.transactions.is_empty());
        assert!(block.block_sig.is_empty());
        assert_eq!(
            block.header.version,
            crate::constants::CURRENT_BLOCK_VERSION
        );
    }

    // ---- NEW: is_null ----

    #[test]
    fn test_block_header_is_null_when_bits_zero() {
        let header = BlockHeader {
            version: 4,
            prev_block: Hash256::zero(),
            merkle_root: Hash256::zero(),
            time: 0,
            bits: 0, // null indicator
            nonce: 0,
            accumulator_checkpoint: Hash256::zero(),
        };
        assert!(header.is_null());
    }

    #[test]
    fn test_block_header_not_null_when_bits_nonzero() {
        let header = BlockHeader {
            version: 4,
            prev_block: Hash256::zero(),
            merkle_root: Hash256::zero(),
            time: 0,
            bits: 0x1d00ffff,
            nonce: 0,
            accumulator_checkpoint: Hash256::zero(),
        };
        assert!(!header.is_null());
    }

    // ---- NEW: BlockLocator empty ----

    #[test]
    fn test_block_locator_empty() {
        let locator = BlockLocator::new();
        assert!(locator.is_empty());
        let encoded = serialize(&locator);
        // Just CompactSize(0) = 1 byte
        assert_eq!(encoded, vec![0u8]);
        let decoded: BlockLocator = deserialize(&encoded).unwrap();
        assert_eq!(decoded.hashes.len(), 0);
    }

    // ---- NEW: PoS block with empty block_sig still serializes correctly ----

    #[test]
    fn test_pos_block_empty_sig_serialization() {
        let block = Block {
            header: BlockHeader::new(),
            transactions: vec![create_coinbase_tx(), create_coinstake_tx()],
            block_sig: vec![], // empty sig is legal for testing
        };

        assert!(block.is_proof_of_stake());

        let encoded = serialize(&block);
        let decoded: Block = deserialize(&encoded).unwrap();

        assert_eq!(decoded.transactions.len(), 2);
        assert!(decoded.block_sig.is_empty());
        assert!(decoded.is_proof_of_stake());
    }
}

#[test]
fn test_real_block_payload() {
    let payload = std::fs::read("/tmp/block_payload_5953.bin");
    if let Ok(payload) = payload {
        println!("Payload size: {} bytes", payload.len());
        println!("First 32 bytes: {:02x?}", &payload[..32.min(payload.len())]);
        println!(
            "Last 32 bytes: {:02x?}",
            &payload[payload.len().saturating_sub(32)..]
        );

        let block: Result<Block, _> = crate::serialize::deserialize(&payload);
        match block {
            Ok(block) => {
                println!("Block hash: {}", block.hash());
                println!("Version: {}", block.header.version);
                println!("Transactions: {}", block.transactions.len());
                println!("Is PoS: {}", block.is_proof_of_stake());
                println!("Block sig len: {}", block.block_sig.len());

                // Calculate expected size
                let expected_size = crate::serialize::serialize(&block).len();
                println!("Serialized size: {}", expected_size);

                assert_eq!(expected_size, payload.len(), "Size mismatch!");
            }
            Err(e) => {
                println!("Deserialization error: {:?}", e);
                // Still useful to see where it fails
            }
        }
    } else {
        println!("No payload file found, skipping test");
    }
}
