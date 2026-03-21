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

//! Block undo data (CBlockUndo equivalent)
//!
//! Stores the previous UTXO state for every input spent in a block,
//! enabling deterministic and efficient block disconnection.

use crate::utxo::Utxo;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use divi_primitives::transaction::OutPoint;

/// Undo data for a single spent input
#[derive(Debug, Clone)]
pub struct TxUndo {
    /// The outpoint that was spent
    pub outpoint: OutPoint,
    /// The UTXO that was consumed (previous state to restore on disconnect)
    pub prev_utxo: Utxo,
}

/// Undo data for an entire block
///
/// Contains the previous UTXO state for every input spent in the block.
/// Written atomically during connect_block, read during disconnect_block.
#[derive(Debug, Clone)]
pub struct BlockUndo {
    pub entries: Vec<TxUndo>,
}

impl Default for BlockUndo {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockUndo {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, outpoint: OutPoint, prev_utxo: Utxo) {
        self.entries.push(TxUndo {
            outpoint,
            prev_utxo,
        });
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Entry count
        buf.write_u32::<LittleEndian>(self.entries.len() as u32)
            .unwrap();

        for entry in &self.entries {
            // Outpoint: txid (32 bytes) + vout (4 bytes)
            buf.extend_from_slice(entry.outpoint.txid.as_bytes());
            buf.write_u32::<LittleEndian>(entry.outpoint.vout).unwrap();

            // UTXO data (length-prefixed)
            let utxo_bytes = entry.prev_utxo.to_bytes();
            buf.write_u32::<LittleEndian>(utxo_bytes.len() as u32)
                .unwrap();
            buf.extend_from_slice(&utxo_bytes);
        }

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::StorageError> {
        let mut cursor = std::io::Cursor::new(data);

        let count = cursor.read_u32::<LittleEndian>()? as usize;
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            // Read outpoint
            let mut txid_bytes = [0u8; 32];
            std::io::Read::read_exact(&mut cursor, &mut txid_bytes)?;
            let txid = divi_primitives::hash::Hash256::from_bytes(txid_bytes);
            let vout = cursor.read_u32::<LittleEndian>()?;
            let outpoint = OutPoint::new(txid, vout);

            // Read UTXO
            let utxo_len = cursor.read_u32::<LittleEndian>()? as usize;
            let pos = cursor.position() as usize;
            if pos + utxo_len > data.len() {
                return Err(crate::error::StorageError::Deserialization(
                    "undo data: UTXO data exceeds buffer".into(),
                ));
            }
            let prev_utxo = Utxo::from_bytes(&data[pos..pos + utxo_len])?;
            cursor.set_position((pos + utxo_len) as u64);

            entries.push(TxUndo {
                outpoint,
                prev_utxo,
            });
        }

        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::amount::Amount;
    use divi_primitives::script::Script;

    #[test]
    fn test_block_undo_roundtrip() {
        let mut undo = BlockUndo::new();

        let txid = divi_primitives::hash::Hash256::from_bytes([0xab; 32]);
        undo.push(
            OutPoint::new(txid, 1),
            Utxo::new(
                Amount::from_sat(5000_00000000),
                Script::new_p2pkh(&[0x11; 20]),
                1000,
                false,
                true,
            ),
        );
        undo.push(
            OutPoint::new(txid, 0),
            Utxo::new(
                Amount::from_sat(100_00000000),
                Script::new_p2pkh(&[0x22; 20]),
                500,
                true,
                false,
            ),
        );

        let bytes = undo.to_bytes();
        let decoded = BlockUndo::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].outpoint.vout, 1);
        assert_eq!(decoded.entries[0].prev_utxo.value.as_sat(), 5000_00000000);
        assert!(decoded.entries[0].prev_utxo.is_coinstake);
        assert_eq!(decoded.entries[1].outpoint.vout, 0);
        assert!(decoded.entries[1].prev_utxo.is_coinbase);
    }

    #[test]
    fn test_block_undo_empty() {
        let undo = BlockUndo::new();
        let bytes = undo.to_bytes();
        let decoded = BlockUndo::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.entries.len(), 0);
    }
}
