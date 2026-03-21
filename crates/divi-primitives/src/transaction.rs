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

//! Transaction types for Divi

use crate::amount::Amount;
use crate::constants::{CURRENT_TX_VERSION, SEQUENCE_FINAL};
use crate::error::Error;
use crate::hash::Hash256;
use crate::script::Script;
use crate::serialize::{serialize, Decodable, Encodable};
use std::fmt;
use std::io::{Read, Write};

/// An outpoint - a reference to a specific output in a previous transaction
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OutPoint {
    /// Transaction ID containing the output
    pub txid: Hash256,
    /// Index of the output in that transaction
    pub vout: u32,
}

impl OutPoint {
    /// Create a new outpoint
    pub fn new(txid: Hash256, vout: u32) -> Self {
        OutPoint { txid, vout }
    }

    /// Create a null outpoint (used for coinbase/coinstake inputs)
    pub fn null() -> Self {
        OutPoint {
            txid: Hash256::zero(),
            vout: u32::MAX,
        }
    }

    /// Check if this is a null outpoint
    pub fn is_null(&self) -> bool {
        self.txid.is_zero() && self.vout == u32::MAX
    }
}

impl fmt::Debug for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutPoint({}:{})", self.txid, self.vout)
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl Encodable for OutPoint {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = self.txid.encode(writer)?;
        size += self.vout.encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        32 + 4 // txid + vout
    }
}

impl Decodable for OutPoint {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(OutPoint {
            txid: Hash256::decode(reader)?,
            vout: u32::decode(reader)?,
        })
    }
}

/// A transaction input
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct TxIn {
    /// Reference to previous output being spent
    pub prevout: OutPoint,
    /// Script that satisfies the previous output's conditions
    pub script_sig: Script,
    /// Sequence number (used for relative time locks, RBF)
    pub sequence: u32,
}

impl TxIn {
    /// Create a new transaction input
    pub fn new(prevout: OutPoint, script_sig: Script, sequence: u32) -> Self {
        TxIn {
            prevout,
            script_sig,
            sequence,
        }
    }

    /// Create a coinbase input (no previous output)
    pub fn coinbase(script_sig: Script) -> Self {
        TxIn {
            prevout: OutPoint::null(),
            script_sig,
            sequence: SEQUENCE_FINAL,
        }
    }

    /// Check if this is a coinbase input
    pub fn is_coinbase(&self) -> bool {
        self.prevout.is_null()
    }

    /// Check if this input is final (sequence = max)
    pub fn is_final(&self) -> bool {
        self.sequence == SEQUENCE_FINAL
    }
}

impl fmt::Debug for TxIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxIn")
            .field("prevout", &self.prevout)
            .field("script_sig", &self.script_sig.to_hex())
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl Encodable for TxIn {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = self.prevout.encode(writer)?;
        size += self.script_sig.encode(writer)?;
        size += self.sequence.encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.prevout.encoded_size() + self.script_sig.encoded_size() + self.sequence.encoded_size()
    }
}

impl Decodable for TxIn {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(TxIn {
            prevout: OutPoint::decode(reader)?,
            script_sig: Script::decode(reader)?,
            sequence: u32::decode(reader)?,
        })
    }
}

/// A transaction output
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct TxOut {
    /// Value in satoshis
    pub value: Amount,
    /// Script defining spend conditions
    pub script_pubkey: Script,
}

impl TxOut {
    /// Create a new transaction output
    pub fn new(value: Amount, script_pubkey: Script) -> Self {
        TxOut {
            value,
            script_pubkey,
        }
    }

    /// Create an empty output (used as first output in coinstake)
    pub fn empty() -> Self {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: Script::new(),
        }
    }

    /// Check if this output is empty
    pub fn is_empty(&self) -> bool {
        self.value.is_zero() && self.script_pubkey.is_empty()
    }

    /// Check if this is an OP_RETURN output
    pub fn is_op_return(&self) -> bool {
        self.script_pubkey.is_op_return()
    }

    /// Check if this output is dust (below economic threshold)
    pub fn is_dust(&self, dust_threshold: Amount) -> bool {
        self.value < dust_threshold && !self.is_op_return()
    }
}

impl fmt::Debug for TxOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxOut")
            .field("value", &self.value)
            .field("script_pubkey", &self.script_pubkey.to_hex())
            .finish()
    }
}

impl Encodable for TxOut {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = self.value.encode(writer)?;
        size += self.script_pubkey.encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.value.encoded_size() + self.script_pubkey.encoded_size()
    }
}

impl Decodable for TxOut {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(TxOut {
            value: Amount::decode(reader)?,
            script_pubkey: Script::decode(reader)?,
        })
    }
}

/// A Divi transaction
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Transaction {
    /// Transaction format version
    pub version: i32,
    /// List of inputs
    pub vin: Vec<TxIn>,
    /// List of outputs
    pub vout: Vec<TxOut>,
    /// Lock time (block height or timestamp)
    pub lock_time: u32,
}

impl Transaction {
    /// Create a new empty transaction
    pub fn new() -> Self {
        Transaction {
            version: CURRENT_TX_VERSION,
            vin: Vec::new(),
            vout: Vec::new(),
            lock_time: 0,
        }
    }

    /// Compute the transaction ID (double SHA256 of serialized tx)
    pub fn txid(&self) -> Hash256 {
        use sha2::{Digest, Sha256};
        let data = serialize(self);
        let first = Sha256::digest(&data);
        let second = Sha256::digest(first);
        let mut result = [0u8; 32];
        result.copy_from_slice(&second);
        Hash256::from_bytes(result)
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].is_coinbase()
    }

    /// Check if this is a coinstake transaction
    ///
    /// A coinstake transaction:
    /// - Has at least 2 inputs (the staked UTXO + potentially more)
    /// - First output is empty (marker)
    /// - Is not a coinbase
    pub fn is_coinstake(&self) -> bool {
        !self.vin.is_empty()
            && !self.vin[0].prevout.is_null()
            && self.vout.len() >= 2
            && self.vout[0].is_empty()
    }

    /// Get total output value
    pub fn output_value(&self) -> Amount {
        self.vout
            .iter()
            .map(|out| out.value)
            .fold(Amount::ZERO, |acc, v| acc + v)
    }

    /// Check if transaction is final at given height/time
    pub fn is_final(&self, block_height: u32, block_time: u32) -> bool {
        if self.lock_time == 0 {
            return true;
        }

        let lock_threshold = if self.lock_time < 500_000_000 {
            // Lock time is block height
            block_height
        } else {
            // Lock time is unix timestamp
            block_time
        };

        if self.lock_time < lock_threshold {
            return true;
        }

        // Check if all inputs are final
        self.vin.iter().all(|input| input.is_final())
    }

    /// Get the size of the transaction in bytes
    pub fn size(&self) -> usize {
        self.encoded_size()
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("version", &self.version)
            .field("vin", &self.vin)
            .field("vout", &self.vout)
            .field("lock_time", &self.lock_time)
            .finish()
    }
}

impl Encodable for Transaction {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = self.version.encode(writer)?;
        size += self.vin.encode(writer)?;
        size += self.vout.encode(writer)?;
        size += self.lock_time.encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.version.encoded_size()
            + self.vin.encoded_size()
            + self.vout.encoded_size()
            + self.lock_time.encoded_size()
    }
}

impl Decodable for Transaction {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(Transaction {
            version: i32::decode(reader)?,
            vin: Vec::<TxIn>::decode(reader)?,
            vout: Vec::<TxOut>::decode(reader)?,
            lock_time: u32::decode(reader)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize, serialize};

    #[test]
    fn test_outpoint_null() {
        let null = OutPoint::null();
        assert!(null.is_null());

        let normal = OutPoint::new(Hash256::zero(), 0);
        assert!(!normal.is_null()); // vout is 0, not MAX
    }

    #[test]
    fn test_outpoint_serialization() {
        let outpoint = OutPoint::new(Hash256::from_bytes([1u8; 32]), 42);
        let encoded = serialize(&outpoint);
        assert_eq!(encoded.len(), 36); // 32 + 4

        let decoded: OutPoint = deserialize(&encoded).unwrap();
        assert_eq!(decoded, outpoint);
    }

    #[test]
    fn test_txin_serialization() {
        let txin = TxIn::new(
            OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
            Script::from_bytes(vec![0x00, 0x14]),
            SEQUENCE_FINAL,
        );

        let encoded = serialize(&txin);
        let decoded: TxIn = deserialize(&encoded).unwrap();
        assert_eq!(decoded, txin);
    }

    #[test]
    fn test_txout_serialization() {
        let txout = TxOut::new(Amount::from_divi(100), Script::new_p2pkh(&[0u8; 20]));

        let encoded = serialize(&txout);
        let decoded: TxOut = deserialize(&encoded).unwrap();
        assert_eq!(decoded, txout);
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(50),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        };

        let encoded = serialize(&tx);
        let decoded: Transaction = deserialize(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn test_coinbase_detection() {
        let coinbase_tx = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![
                0x04, 0xff, 0xff, 0x00, 0x1d,
            ]))],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        };

        assert!(coinbase_tx.is_coinbase());
        assert!(!coinbase_tx.is_coinstake());
    }

    #[test]
    fn test_coinstake_detection() {
        let coinstake_tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::new(),
                SEQUENCE_FINAL,
            )],
            vout: vec![
                TxOut::empty(), // Marker
                TxOut::new(Amount::from_divi(100), Script::new()),
            ],
            lock_time: 0,
        };

        assert!(!coinstake_tx.is_coinbase());
        assert!(coinstake_tx.is_coinstake());
    }

    #[test]
    fn test_output_value() {
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![
                TxOut::new(Amount::from_divi(50), Script::new()),
                TxOut::new(Amount::from_divi(30), Script::new()),
                TxOut::new(Amount::from_divi(20), Script::new()),
            ],
            lock_time: 0,
        };

        assert_eq!(tx.output_value().as_divi(), 100);
    }

    // ---- NEW: Transaction::new() must default to version=1 ----

    #[test]
    fn test_transaction_new_defaults_version_1() {
        use crate::constants::CURRENT_TX_VERSION;
        let tx = Transaction::new();
        assert_eq!(
            tx.version, 1,
            "Transaction::new() must produce version=1 (CURRENT_TX_VERSION={CURRENT_TX_VERSION})"
        );
        assert_eq!(tx.vin.len(), 0);
        assert_eq!(tx.vout.len(), 0);
        assert_eq!(tx.lock_time, 0);
    }

    // ---- NEW: empty transaction serialization roundtrip ----

    /// An empty transaction (version=1, no inputs, no outputs, locktime=0) must
    /// serialize and deserialize correctly.  The binary layout is:
    ///   version  : 4 bytes  [01 00 00 00]
    ///   vin count: 1 byte   [00]
    ///   vout count: 1 byte  [00]
    ///   locktime : 4 bytes  [00 00 00 00]
    ///   total    : 10 bytes
    #[test]
    fn test_empty_transaction_serialization() {
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
        };

        let encoded = serialize(&tx);
        // 4 (version) + 1 (vin count=0) + 1 (vout count=0) + 4 (locktime) = 10
        assert_eq!(
            encoded.len(),
            10,
            "empty tx should be 10 bytes, got {}",
            encoded.len()
        );

        // Verify exact binary layout
        assert_eq!(
            &encoded[0..4],
            &[0x01, 0x00, 0x00, 0x00],
            "version bytes mismatch"
        );
        assert_eq!(encoded[4], 0x00, "vin count should be 0");
        assert_eq!(encoded[5], 0x00, "vout count should be 0");
        assert_eq!(
            &encoded[6..10],
            &[0x00, 0x00, 0x00, 0x00],
            "locktime bytes mismatch"
        );

        let decoded: Transaction = deserialize(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }

    // ---- NEW: version=1 preserved through serialization roundtrip ----

    #[test]
    fn test_transaction_version_1_preserved_in_roundtrip() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([0xABu8; 32]), 7),
                Script::from_bytes(vec![0x51]), // OP_1
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(1),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        };

        let encoded = serialize(&tx);
        // First 4 bytes should be 0x01000000 (version=1 LE)
        assert_eq!(
            &encoded[0..4],
            &[0x01, 0x00, 0x00, 0x00],
            "version=1 must serialize as [01 00 00 00]"
        );

        let decoded: Transaction = deserialize(&encoded).unwrap();
        assert_eq!(decoded.version, 1, "version must survive roundtrip");
    }

    // ---- NEW: txid computation is deterministic ----

    #[test]
    fn test_transaction_txid_is_deterministic() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x04, 0xff]))],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        };

        let txid1 = tx.txid();
        let txid2 = tx.txid();
        assert_eq!(txid1, txid2, "txid() must be deterministic");
        assert!(
            !txid1.is_zero(),
            "txid must not be all-zero for a non-trivial tx"
        );
    }

    #[test]
    fn test_transaction_different_txids_for_different_txs() {
        let tx1 = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x01]))],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        };
        let tx2 = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(vec![0x02]))],
            vout: vec![TxOut::new(Amount::from_divi(50), Script::new())],
            lock_time: 0,
        };
        assert_ne!(
            tx1.txid(),
            tx2.txid(),
            "different txs must have different txids"
        );
    }

    // ---- NEW: size() matches encoded_size() ----

    #[test]
    fn test_transaction_size_matches_serialized_len() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::new(Hash256::from_bytes([1u8; 32]), 0),
                Script::from_bytes(vec![0x76, 0xa9, 0x14]),
                SEQUENCE_FINAL,
            )],
            vout: vec![TxOut::new(
                Amount::from_divi(1),
                Script::new_p2pkh(&[0u8; 20]),
            )],
            lock_time: 0,
        };

        assert_eq!(
            tx.size(),
            serialize(&tx).len(),
            "Transaction::size() must match actual serialized length"
        );
    }

    // ---- NEW: OutPoint 36-byte layout ----

    #[test]
    fn test_outpoint_serialization_exact_layout() {
        // Null outpoint: txid=[0;32], vout=0xFFFFFFFF
        let null = OutPoint::null();
        let encoded = serialize(&null);
        assert_eq!(encoded.len(), 36, "outpoint must be exactly 36 bytes");
        // First 32 bytes: txid (all zeros)
        assert_eq!(&encoded[0..32], &[0u8; 32], "null txid should be all zeros");
        // Last 4 bytes: vout = u32::MAX in LE
        assert_eq!(
            &encoded[32..36],
            &[0xFF, 0xFF, 0xFF, 0xFF],
            "null vout should be MAX"
        );
    }

    #[test]
    fn test_outpoint_with_known_vout() {
        let txid = Hash256::from_bytes([0xBBu8; 32]);
        let outpoint = OutPoint::new(txid, 3);
        let encoded = serialize(&outpoint);
        assert_eq!(encoded.len(), 36);
        assert_eq!(
            &encoded[32..36],
            &[0x03, 0x00, 0x00, 0x00],
            "vout=3 should be [03 00 00 00]"
        );
    }

    // ---- NEW: TxOut empty ----

    #[test]
    fn test_txout_empty_is_empty() {
        let empty = TxOut::empty();
        assert!(empty.is_empty());
        assert!(empty.value.is_zero());
        assert!(empty.script_pubkey.is_empty());
    }

    #[test]
    fn test_txout_empty_serialization() {
        let empty = TxOut::empty();
        let encoded = serialize(&empty);
        // 8 bytes (value=0) + 1 byte (script length=0) = 9 bytes
        assert_eq!(
            encoded.len(),
            9,
            "empty TxOut should be 9 bytes, got {}",
            encoded.len()
        );
        let decoded: TxOut = deserialize(&encoded).unwrap();
        assert_eq!(decoded, empty);
    }

    // ---- NEW: is_final() ----

    #[test]
    fn test_transaction_is_final_locktime_zero() {
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
        };
        assert!(
            tx.is_final(100, 1_600_000_000),
            "locktime=0 should always be final"
        );
    }

    #[test]
    fn test_transaction_is_final_locktime_height_passed() {
        let tx = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            lock_time: 100, // block height lock
        };
        // current block height 101 > lock_time 100 → final
        assert!(tx.is_final(101, 0));
    }

    #[test]
    fn test_transaction_not_final_when_inputs_non_final() {
        // lock_time in the future, inputs with non-final sequence
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(
                OutPoint::null(),
                Script::new(),
                0, // non-final sequence
            )],
            vout: vec![],
            lock_time: 500, // future block height
        };
        // current height=100, lock_time=500: lock_time >= current → not final from locktime
        // all inputs non-final → not final
        assert!(!tx.is_final(100, 0));
    }
}
