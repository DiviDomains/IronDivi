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

//! Chain export functionality for validation and cross-reference
//!
//! Exports blockchain data to JSON format for validation against C++ Divi.

use crate::chain::Chain;
use crate::error::StorageError;
use divi_crypto::compute_block_hash;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// Exported block in JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockExport {
    /// Block height
    pub height: u32,
    /// Block hash (display format - reversed)
    pub hash: String,
    /// Block version
    pub version: i32,
    /// Previous block hash
    pub prev_hash: String,
    /// Merkle root
    pub merkle_root: String,
    /// Timestamp (seconds since Unix epoch)
    pub timestamp: u32,
    /// Difficulty target (compact format)
    pub bits: u32,
    /// Nonce
    pub nonce: u32,
    /// Accumulator checkpoint (zerocoin era, version > 3)
    pub accumulator_checkpoint: String,
    /// Block signature (hex encoded)
    pub block_sig: String,
    /// Transactions
    pub transactions: Vec<TransactionExport>,
}

/// Exported transaction in JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExport {
    /// Transaction ID
    pub txid: String,
    /// Version
    pub version: i32,
    /// Lock time
    pub lock_time: u32,
    /// Number of inputs
    pub vin_count: usize,
    /// Number of outputs
    pub vout_count: usize,
    /// Serialized transaction (hex encoded)
    pub hex: String,
}

/// Export manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    /// Chain name
    pub chain: String,
    /// Export timestamp
    pub exported_at: String,
    /// Total blocks exported
    pub block_count: u32,
    /// Start height
    pub start_height: u32,
    /// End height
    pub end_height: u32,
    /// Genesis hash
    pub genesis_hash: String,
    /// Tip hash at export time
    pub tip_hash: String,
    /// Export complete flag
    pub export_complete: bool,
    /// Blocks directory (relative path)
    pub blocks_dir: String,
}

impl BlockExport {
    /// Convert a Block to BlockExport format
    pub fn from_block(block: &Block, height: u32) -> Self {
        let hash = compute_block_hash(&block.header);
        let header = &block.header;

        let transactions: Vec<TransactionExport> = block
            .transactions
            .iter()
            .map(TransactionExport::from_transaction)
            .collect();

        BlockExport {
            height,
            hash: hash.to_string(),
            version: header.version,
            prev_hash: header.prev_block.to_string(),
            merkle_root: header.merkle_root.to_string(),
            timestamp: header.time,
            bits: header.bits,
            nonce: header.nonce,
            accumulator_checkpoint: header.accumulator_checkpoint.to_string(),
            block_sig: hex::encode(&block.block_sig),
            transactions,
        }
    }
}

impl TransactionExport {
    /// Convert a Transaction to TransactionExport format
    pub fn from_transaction(tx: &Transaction) -> Self {
        use divi_primitives::serialize::serialize;

        let txid = tx.txid();
        let hex_data = serialize(tx);

        TransactionExport {
            txid: txid.to_string(),
            version: tx.version,
            lock_time: tx.lock_time,
            vin_count: tx.vin.len(),
            vout_count: tx.vout.len(),
            hex: hex::encode(hex_data),
        }
    }
}

impl Chain {
    /// Export a single block at specified height
    pub fn export_block(&self, height: u32) -> Result<BlockExport, StorageError> {
        let block_index = self
            .get_block_index_by_height(height)?
            .ok_or_else(|| StorageError::BlockNotFound(format!("height {}", height)))?;

        let block = self
            .get_block(&block_index.hash)?
            .ok_or_else(|| StorageError::BlockNotFound(format!("hash {}", block_index.hash)))?;

        Ok(BlockExport::from_block(&block, height))
    }

    /// Export entire chain to directory
    ///
    /// Creates a directory structure:
    /// ```text
    /// output_dir/
    ///   manifest.json
    ///   blocks/
    ///     00000000.json
    ///     00000001.json
    ///     ...
    /// ```
    pub fn export_chain(
        &self,
        start_height: u32,
        end_height: u32,
        output_dir: &Path,
    ) -> Result<(), StorageError> {
        // Validate range
        if start_height > end_height {
            return Err(StorageError::InvalidParameter(
                "start_height must be <= end_height".to_string(),
            ));
        }

        // Create output directory structure
        fs::create_dir_all(output_dir).map_err(StorageError::Io)?;

        let blocks_dir = output_dir.join("blocks");
        fs::create_dir_all(&blocks_dir).map_err(StorageError::Io)?;

        info!(
            "Starting chain export: heights {} to {} ({} blocks)",
            start_height,
            end_height,
            end_height - start_height + 1
        );

        // Export each block
        let mut exported_count = 0;
        for height in start_height..=end_height {
            // Progress logging every 10,000 blocks
            if height > start_height && (height - start_height).is_multiple_of(10000) {
                info!(
                    "Export progress: {}/{} blocks ({:.1}%)",
                    height - start_height,
                    end_height - start_height + 1,
                    ((height - start_height) as f64 / (end_height - start_height + 1) as f64)
                        * 100.0
                );
            }

            // Export block
            match self.export_block(height) {
                Ok(block_export) => {
                    let filename = format!("{:08}.json", height);
                    let filepath = blocks_dir.join(filename);

                    let json = serde_json::to_string_pretty(&block_export).map_err(|e| {
                        StorageError::Serialization(format!("JSON serialization failed: {}", e))
                    })?;

                    fs::write(&filepath, json).map_err(StorageError::Io)?;

                    exported_count += 1;
                }
                Err(e) => {
                    warn!("Failed to export block at height {}: {}", height, e);
                }
            }
        }

        let tip = self
            .tip()
            .ok_or_else(|| StorageError::ChainState("No chain tip available".to_string()))?;
        let tip_hash = tip.hash;

        let genesis_hash = if let Some(genesis) = self.get_block_index_by_height(0)? {
            genesis.hash
        } else {
            Hash256::zero()
        };

        let manifest = ExportManifest {
            chain: "mainnet".to_string(),
            exported_at: chrono::Utc::now().to_rfc3339(),
            block_count: exported_count,
            start_height,
            end_height,
            genesis_hash: genesis_hash.to_string(),
            tip_hash: tip_hash.to_string(),
            export_complete: exported_count == (end_height - start_height + 1),
            blocks_dir: "./blocks".to_string(),
        };

        let manifest_path = output_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| {
            StorageError::Serialization(format!("Manifest JSON serialization failed: {}", e))
        })?;

        fs::write(&manifest_path, manifest_json).map_err(StorageError::Io)?;

        info!(
            "✅ Chain export complete: {} blocks exported to {:?}",
            exported_count, output_dir
        );

        if exported_count != (end_height - start_height + 1) {
            warn!(
                "⚠️  Export incomplete: {} of {} blocks exported",
                exported_count,
                end_height - start_height + 1
            );
        }

        Ok(())
    }

    /// Quick export for testing (first N blocks)
    pub fn export_chain_quick(
        &self,
        block_count: u32,
        output_dir: &Path,
    ) -> Result<(), StorageError> {
        self.export_chain(0, block_count - 1, output_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_export_serialization() {
        // Create a minimal block export
        let export = BlockExport {
            height: 12345,
            hash: "abc123".to_string(),
            version: 1,
            prev_hash: "def456".to_string(),
            merkle_root: "789ghi".to_string(),
            timestamp: 1234567890,
            bits: 486604799,
            nonce: 987654321,
            accumulator_checkpoint: "000000".to_string(),
            block_sig: "aabbcc".to_string(),
            transactions: vec![],
        };

        // Should serialize to JSON without errors
        let json = serde_json::to_string_pretty(&export).expect("Failed to serialize");
        assert!(json.contains("\"height\": 12345"));
        assert!(json.contains("\"hash\": \"abc123\""));

        // Should deserialize back
        let deserialized: BlockExport = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.height, 12345);
        assert_eq!(deserialized.hash, "abc123");
    }

    #[test]
    fn test_manifest_serialization() {
        let manifest = ExportManifest {
            chain: "mainnet".to_string(),
            exported_at: "2026-01-20T12:00:00Z".to_string(),
            block_count: 100,
            start_height: 0,
            end_height: 99,
            genesis_hash: "genesis".to_string(),
            tip_hash: "tip".to_string(),
            export_complete: true,
            blocks_dir: "./blocks".to_string(),
        };

        let json = serde_json::to_string_pretty(&manifest).expect("Failed to serialize");
        assert!(json.contains("\"chain\": \"mainnet\""));
        assert!(json.contains("\"block_count\": 100"));

        let deserialized: ExportManifest =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.block_count, 100);
        assert!(deserialized.export_complete);
    }
}
