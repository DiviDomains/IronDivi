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

//! UTXO (Unspent Transaction Output) types
//!
//! The UTXO set represents all spendable transaction outputs in the chain.
//! This is the core data structure for validating transactions.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;

/// An unspent transaction output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// Value in satoshis
    pub value: Amount,
    /// Output script (defines spending conditions)
    pub script_pubkey: Script,
    /// Height of the block that contains this UTXO
    pub height: u32,
    /// Whether this is from a coinbase transaction
    pub is_coinbase: bool,
    /// Whether this is from a coinstake transaction
    pub is_coinstake: bool,
}

impl Utxo {
    /// Create a new UTXO
    pub fn new(
        value: Amount,
        script_pubkey: Script,
        height: u32,
        is_coinbase: bool,
        is_coinstake: bool,
    ) -> Self {
        Utxo {
            value,
            script_pubkey,
            height,
            is_coinbase,
            is_coinstake,
        }
    }

    /// Check if this UTXO is mature enough to be spent
    ///
    /// Coinbase outputs require 100 confirmations.
    /// Coinstake outputs require 100 confirmations.
    pub fn is_mature(&self, current_height: u32) -> bool {
        const COINBASE_MATURITY: u32 = 100;

        if self.is_coinbase || self.is_coinstake {
            current_height >= self.height + COINBASE_MATURITY
        } else {
            true
        }
    }

    /// Check if this UTXO is mature enough to be spent with a specific maturity requirement.
    ///
    /// Use this for network-aware maturity checks (mainnet=20, testnet/regtest=1).
    pub fn is_mature_with(&self, current_height: u32, maturity: u32) -> bool {
        if self.is_coinbase || self.is_coinstake {
            current_height >= self.height + maturity
        } else {
            true
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Value (8 bytes)
        buf.write_i64::<LittleEndian>(self.value.as_sat()).unwrap();

        // Script (with length prefix)
        let script_bytes = self.script_pubkey.as_bytes();
        buf.write_u32::<LittleEndian>(script_bytes.len() as u32)
            .unwrap();
        buf.extend_from_slice(script_bytes);

        // Height (4 bytes)
        buf.write_u32::<LittleEndian>(self.height).unwrap();

        // Flags (1 byte)
        let mut flags = 0u8;
        if self.is_coinbase {
            flags |= 1;
        }
        if self.is_coinstake {
            flags |= 2;
        }
        buf.push(flags);

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::StorageError> {
        let mut cursor = std::io::Cursor::new(data);

        let value = Amount::from_sat(cursor.read_i64::<LittleEndian>()?);

        let script_len = cursor.read_u32::<LittleEndian>()? as usize;
        let pos = cursor.position() as usize;
        if pos + script_len > data.len() {
            return Err(crate::error::StorageError::Deserialization(
                "script too long".into(),
            ));
        }
        let script_pubkey = Script::from_bytes(data[pos..pos + script_len].to_vec());
        cursor.set_position((pos + script_len) as u64);

        let height = cursor.read_u32::<LittleEndian>()?;

        let flags = cursor.read_u8()?;
        let is_coinbase = (flags & 1) != 0;
        let is_coinstake = (flags & 2) != 0;

        Ok(Utxo {
            value,
            script_pubkey,
            height,
            is_coinbase,
            is_coinstake,
        })
    }
}

/// Key for UTXO storage
///
/// Format: "u" + txid (32 bytes) + vout (4 bytes)
pub fn utxo_key(outpoint: &OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 32 + 4);
    key.push(b'u'); // Prefix for UTXO
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.write_u32::<LittleEndian>(outpoint.vout).unwrap();
    key
}

pub fn outpoint_from_key(key: &[u8]) -> Result<OutPoint, String> {
    if key.len() != 37 || key[0] != b'u' {
        return Err("Invalid UTXO key format".to_string());
    }

    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&key[1..33]);
    let txid = divi_primitives::Hash256::from_bytes(txid_bytes);

    let mut vout_bytes = [0u8; 4];
    vout_bytes.copy_from_slice(&key[33..37]);
    let vout = u32::from_le_bytes(vout_bytes);

    Ok(OutPoint::new(txid, vout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_roundtrip() {
        let utxo = Utxo::new(
            Amount::from_sat(1000000),
            Script::new_p2pkh(&[0u8; 20]),
            100000,
            false,
            false,
        );

        let bytes = utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.value, utxo.value);
        assert_eq!(
            decoded.script_pubkey.as_bytes(),
            utxo.script_pubkey.as_bytes()
        );
        assert_eq!(decoded.height, utxo.height);
        assert_eq!(decoded.is_coinbase, utxo.is_coinbase);
        assert_eq!(decoded.is_coinstake, utxo.is_coinstake);
    }

    #[test]
    fn test_utxo_coinbase_roundtrip() {
        let utxo = Utxo::new(
            Amount::from_sat(5000000000),
            Script::new_p2pkh(&[1u8; 20]),
            1,
            true,
            false,
        );

        let bytes = utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();

        assert!(decoded.is_coinbase);
        assert!(!decoded.is_coinstake);
    }

    #[test]
    fn test_utxo_maturity() {
        let coinbase_utxo = Utxo::new(
            Amount::from_sat(5000000000),
            Script::new(),
            100,
            true,
            false,
        );

        // Not mature at height 150 (only 50 confirmations)
        assert!(!coinbase_utxo.is_mature(150));

        // Mature at height 200 (100 confirmations)
        assert!(coinbase_utxo.is_mature(200));

        // Regular UTXO is always mature
        let regular_utxo = Utxo::new(Amount::from_sat(1000000), Script::new(), 100, false, false);
        assert!(regular_utxo.is_mature(100));
    }

    #[test]
    fn test_utxo_key() {
        let outpoint = OutPoint::new(divi_primitives::hash::Hash256::from_bytes([0xab; 32]), 5);

        let key = utxo_key(&outpoint);

        assert_eq!(key[0], b'u');
        assert_eq!(&key[1..33], &[0xab; 32]);
        // vout in little-endian
        assert_eq!(&key[33..37], &[5, 0, 0, 0]);
    }

    // ============================================================
    // COMPREHENSIVE UTXO TESTS
    // Added 2026-01-19 for full coverage
    // ============================================================

    #[test]
    fn test_utxo_coinstake_roundtrip() {
        let utxo = Utxo::new(
            Amount::from_sat(10000_00000000), // 10000 DIVI
            Script::new_p2pkh(&[0xaa; 20]),
            5000,
            false,
            true, // coinstake
        );

        let bytes = utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();

        assert!(!decoded.is_coinbase);
        assert!(decoded.is_coinstake);
        assert_eq!(decoded.height, 5000);
        assert_eq!(decoded.value.as_sat(), 10000_00000000);
    }

    #[test]
    fn test_utxo_both_flags() {
        // Edge case: both coinbase and coinstake flags set
        // (shouldn't happen in practice but test serialization)
        let utxo = Utxo::new(
            Amount::from_sat(1000),
            Script::new_p2pkh(&[0xff; 20]),
            1,
            true,
            true,
        );

        let bytes = utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();

        assert!(decoded.is_coinbase);
        assert!(decoded.is_coinstake);
    }

    #[test]
    fn test_utxo_maturity_coinstake() {
        // Coinstake also requires 100 confirmations
        let coinstake_utxo = Utxo::new(
            Amount::from_sat(15000_00000000),
            Script::new(),
            1000,
            false,
            true,
        );

        // Not mature at 1050 (only 50 confirmations)
        assert!(!coinstake_utxo.is_mature(1050));

        // Not mature at 1099 (99 confirmations)
        assert!(!coinstake_utxo.is_mature(1099));

        // Mature at exactly 100 confirmations
        assert!(coinstake_utxo.is_mature(1100));

        // Mature with more confirmations
        assert!(coinstake_utxo.is_mature(2000));
    }

    #[test]
    fn test_utxo_maturity_edge_cases() {
        // Coinbase at height 0
        let genesis_coinbase = Utxo::new(
            Amount::from_sat(5000_00000000),
            Script::new(),
            0,
            true,
            false,
        );

        assert!(!genesis_coinbase.is_mature(0));
        assert!(!genesis_coinbase.is_mature(99));
        assert!(genesis_coinbase.is_mature(100));

        // Very high height
        let high_coinbase = Utxo::new(
            Amount::from_sat(1000_00000000),
            Script::new(),
            1_000_000,
            true,
            false,
        );

        assert!(!high_coinbase.is_mature(1_000_000));
        assert!(!high_coinbase.is_mature(1_000_099));
        assert!(high_coinbase.is_mature(1_000_100));
    }

    #[test]
    fn test_utxo_value_edge_cases() {
        // Zero value (dust)
        let dust_utxo = Utxo::new(
            Amount::from_sat(0),
            Script::new_p2pkh(&[0x00; 20]),
            100,
            false,
            false,
        );

        let bytes = dust_utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.value.as_sat(), 0);

        // Maximum value
        let max_utxo = Utxo::new(
            Amount::from_sat(i64::MAX),
            Script::new_p2pkh(&[0xff; 20]),
            u32::MAX,
            false,
            false,
        );

        let bytes = max_utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.value.as_sat(), i64::MAX);
        assert_eq!(decoded.height, u32::MAX);
    }

    #[test]
    fn test_utxo_various_script_sizes() {
        // Empty script
        let empty_script_utxo = Utxo::new(Amount::from_sat(1000), Script::new(), 1, false, false);
        let bytes = empty_script_utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.script_pubkey.len(), 0);

        // P2PKH script (25 bytes)
        let p2pkh_utxo = Utxo::new(
            Amount::from_sat(1000),
            Script::new_p2pkh(&[0xab; 20]),
            1,
            false,
            false,
        );
        let bytes = p2pkh_utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.script_pubkey.len(), 25);

        // Larger script (e.g., multisig)
        let large_script = Script::from_bytes(vec![0x51; 100]); // 100 bytes
        let large_script_utxo = Utxo::new(Amount::from_sat(1000), large_script, 1, false, false);
        let bytes = large_script_utxo.to_bytes();
        let decoded = Utxo::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.script_pubkey.len(), 100);
    }

    #[test]
    fn test_utxo_key_uniqueness() {
        let txid1 = divi_primitives::hash::Hash256::from_bytes([0x11; 32]);
        let txid2 = divi_primitives::hash::Hash256::from_bytes([0x22; 32]);

        // Same txid, different vout
        let key1 = utxo_key(&OutPoint::new(txid1, 0));
        let key2 = utxo_key(&OutPoint::new(txid1, 1));
        assert_ne!(key1, key2);

        // Different txid, same vout
        let key3 = utxo_key(&OutPoint::new(txid1, 0));
        let key4 = utxo_key(&OutPoint::new(txid2, 0));
        assert_ne!(key3, key4);

        // Same outpoint = same key
        let key5 = utxo_key(&OutPoint::new(txid1, 5));
        let key6 = utxo_key(&OutPoint::new(txid1, 5));
        assert_eq!(key5, key6);
    }

    #[test]
    fn test_utxo_key_vout_encoding() {
        let txid = divi_primitives::hash::Hash256::from_bytes([0xcc; 32]);

        // vout = 0
        let key0 = utxo_key(&OutPoint::new(txid, 0));
        assert_eq!(&key0[33..37], &[0, 0, 0, 0]);

        // vout = 255
        let key255 = utxo_key(&OutPoint::new(txid, 255));
        assert_eq!(&key255[33..37], &[255, 0, 0, 0]);

        // vout = 256
        let key256 = utxo_key(&OutPoint::new(txid, 256));
        assert_eq!(&key256[33..37], &[0, 1, 0, 0]);

        // vout = max u32
        let key_max = utxo_key(&OutPoint::new(txid, u32::MAX));
        assert_eq!(&key_max[33..37], &[255, 255, 255, 255]);
    }

    #[test]
    fn test_utxo_deserialization_error_short_data() {
        // Too short - missing fields
        let short_data = vec![0u8; 5];
        let result = Utxo::from_bytes(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_utxo_deserialization_error_bad_script_length() {
        // Create data with script length larger than remaining data
        let mut bad_data = Vec::new();
        bad_data.write_i64::<LittleEndian>(1000).unwrap(); // value
        bad_data.write_u32::<LittleEndian>(1000).unwrap(); // script_len = 1000 (too big)
        bad_data.extend_from_slice(&[0u8; 10]); // only 10 bytes of script

        let result = Utxo::from_bytes(&bad_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_utxo_equality() {
        let utxo1 = Utxo::new(
            Amount::from_sat(1000),
            Script::new_p2pkh(&[0xab; 20]),
            100,
            true,
            false,
        );

        let utxo2 = Utxo::new(
            Amount::from_sat(1000),
            Script::new_p2pkh(&[0xab; 20]),
            100,
            true,
            false,
        );

        let utxo3 = Utxo::new(
            Amount::from_sat(2000), // different value
            Script::new_p2pkh(&[0xab; 20]),
            100,
            true,
            false,
        );

        assert_eq!(utxo1, utxo2);
        assert_ne!(utxo1, utxo3);
    }
}
