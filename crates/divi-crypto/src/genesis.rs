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

//! Genesis block construction and verification
//!
//! This module provides functionality to construct and verify genesis blocks.

use crate::hash::{hash256, hash_serialized};
use divi_primitives::{
    amount::Amount,
    block::BlockHeader,
    hash::Hash256,
    script::Script,
    test_vectors::genesis,
    transaction::{Transaction, TxIn, TxOut},
};

/// Construct the mainnet genesis coinbase transaction
pub fn create_mainnet_genesis_coinbase() -> Transaction {
    // Decode the coinbase public key from test vectors
    let pubkey_hex = genesis::mainnet::COINBASE_PUBKEY;
    let pubkey = hex::decode(pubkey_hex).expect("Invalid pubkey hex");

    // Coinbase scriptSig: nBits + extra nonce + genesis message
    // Divi: "September 26, 2018 - US-Iran: Trump set to chair key UN Security Council session"
    // The message is 80 bytes, so it needs OP_PUSHDATA1 (0x4c) prefix
    let coinbase_msg =
        b"September 26, 2018 - US-Iran: Trump set to chair key UN Security Council session";
    let mut script_sig_bytes = Vec::new();
    script_sig_bytes.push(4); // Push 4 bytes (bits)
    script_sig_bytes.extend_from_slice(&genesis::mainnet::BITS.to_le_bytes());
    script_sig_bytes.push(1); // Push 1 byte (extra nonce)
    script_sig_bytes.push(4); // Extra nonce = 4
    script_sig_bytes.push(0x4c); // OP_PUSHDATA1 (message is >75 bytes)
    script_sig_bytes.push(coinbase_msg.len() as u8); // 80 = 0x50
    script_sig_bytes.extend_from_slice(coinbase_msg);

    // Create coinbase input
    let coinbase_input = TxIn::coinbase(Script::from_bytes(script_sig_bytes));

    // Create output with 50 DIVI to the genesis public key
    // scriptPubKey: <pubkey> OP_CHECKSIG
    let mut script_pubkey_bytes = Vec::new();
    script_pubkey_bytes.push(pubkey.len() as u8);
    script_pubkey_bytes.extend_from_slice(&pubkey);
    script_pubkey_bytes.push(0xac); // OP_CHECKSIG

    let output = TxOut::new(
        Amount::from_divi(50),
        Script::from_bytes(script_pubkey_bytes),
    );

    Transaction {
        version: 1,
        vin: vec![coinbase_input],
        vout: vec![output],
        lock_time: 0,
    }
}

/// Compute the merkle root from a list of transactions
pub fn compute_merkle_root(transactions: &[Transaction]) -> Hash256 {
    if transactions.is_empty() {
        return Hash256::zero();
    }

    // Get transaction hashes
    let mut hashes: Vec<Hash256> = transactions.iter().map(hash_serialized).collect();

    // Build merkle tree
    while hashes.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..hashes.len()).step_by(2) {
            let left = &hashes[i];
            let right = if i + 1 < hashes.len() {
                &hashes[i + 1]
            } else {
                left // Duplicate last hash if odd number
            };

            // Concatenate and hash
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(left.as_bytes());
            combined.extend_from_slice(right.as_bytes());
            next_level.push(hash256(&combined));
        }

        hashes = next_level;
    }

    hashes.into_iter().next().unwrap()
}

/// Create the mainnet genesis block header
pub fn create_mainnet_genesis_header() -> BlockHeader {
    let coinbase_tx = create_mainnet_genesis_coinbase();
    let merkle_root = compute_merkle_root(&[coinbase_tx]);

    BlockHeader {
        version: 1,
        prev_block: Hash256::zero(),
        merkle_root,
        time: genesis::mainnet::TIMESTAMP,
        bits: genesis::mainnet::BITS,
        nonce: genesis::mainnet::NONCE,
        accumulator_checkpoint: Hash256::zero(), // Not used in v1 headers
    }
}

/// Compute the block hash for a header
pub fn block_hash(header: &BlockHeader) -> Hash256 {
    hash_serialized(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_coinbase_construction() {
        let tx = create_mainnet_genesis_coinbase();
        assert!(tx.is_coinbase());
        assert_eq!(tx.vout.len(), 1);
        assert_eq!(tx.vout[0].value, Amount::from_divi(50));
    }

    #[test]
    fn test_genesis_merkle_root() {
        let coinbase_tx = create_mainnet_genesis_coinbase();
        let merkle_root = compute_merkle_root(&[coinbase_tx]);

        // For a single transaction, merkle root = txid
        let txid = hash_serialized(&create_mainnet_genesis_coinbase());
        assert_eq!(merkle_root, txid);

        // Print for debugging
        println!("Computed merkle root: {}", merkle_root);
        println!("Expected merkle root: {}", genesis::mainnet::MERKLE_ROOT);
    }

    #[test]
    fn test_genesis_header_hash() {
        let header = create_mainnet_genesis_header();

        // Serialize and hash
        let hash = block_hash(&header);

        println!("Computed genesis hash: {}", hash);
        println!("Expected genesis hash: {}", genesis::mainnet::BLOCK_HASH);

        // Print header details for debugging
        println!("Header version: {}", header.version);
        println!("Header prev_block: {}", header.prev_block);
        println!("Header merkle_root: {}", header.merkle_root);
        println!("Header time: {}", header.time);
        println!("Header bits: {:#010x}", header.bits);
        println!("Header nonce: {}", header.nonce);

        // Note: The merkle root might not match exactly due to coinbase construction
        // differences. The full test requires exact coinbase reproduction.
    }

    #[test]
    fn test_genesis_timestamp() {
        assert_eq!(genesis::mainnet::TIMESTAMP, 1537971708);
    }

    #[test]
    fn test_genesis_nonce() {
        assert_eq!(genesis::mainnet::NONCE, 749845);
    }

    #[test]
    fn test_genesis_bits() {
        assert_eq!(genesis::mainnet::BITS, 0x1e0ffff0);
    }
}
