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

//! Lottery-related types and functions
//!
//! Divi implements a proof-of-stake lottery system where:
//! - Every nth block is a "lottery block" (n=10 in regtest)
//! - During non-lottery blocks, valid coinstakes (>10k DIVI) are tracked
//! - Each coinstake is scored using SHA256(coinstake_hash || last_lottery_hash)
//! - Top 11 coinstakes by score become lottery winners
//! - At lottery blocks, winners are paid from the lottery pool
//! - Winner #1 gets 50% of the pool, winners #2-11 get 5% each

use crate::error::Error;
use crate::hash::Hash256;
use crate::script::Script;
use crate::serialize::{Decodable, Encodable};
use std::io::{Read, Write};

/// A lottery coinstake entry: (transaction_hash, payment_script)
///
/// This represents one potential lottery winner. The transaction hash is used
/// for scoring, and the payment script is where the lottery payout goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LotteryCoinstake {
    /// Hash of the coinstake transaction
    pub tx_hash: Hash256,
    /// Script pubkey to pay if this coinstake wins
    pub script_pubkey: Script,
}

impl LotteryCoinstake {
    pub fn new(tx_hash: Hash256, script_pubkey: Script) -> Self {
        Self {
            tx_hash,
            script_pubkey,
        }
    }
}

impl Encodable for LotteryCoinstake {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = 0;
        size += self.tx_hash.encode(writer)?;
        size += self.script_pubkey.encode(writer)?;
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.tx_hash.encoded_size() + self.script_pubkey.encoded_size()
    }
}

impl Decodable for LotteryCoinstake {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let tx_hash = Hash256::decode(reader)?;
        let script_pubkey = Script::decode(reader)?;
        Ok(Self {
            tx_hash,
            script_pubkey,
        })
    }
}

/// Collection of lottery coinstakes (top 11 candidates)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LotteryWinners {
    /// The block height where this winner data is valid
    pub height: u32,
    /// List of up to 11 lottery coinstakes, sorted by score (best first)
    pub coinstakes: Vec<LotteryCoinstake>,
}

impl LotteryWinners {
    pub fn new(height: u32) -> Self {
        Self {
            height,
            coinstakes: Vec::new(),
        }
    }

    pub fn with_coinstakes(height: u32, coinstakes: Vec<LotteryCoinstake>) -> Self {
        Self { height, coinstakes }
    }

    /// Check if this contains valid winner data
    pub fn is_valid(&self) -> bool {
        self.coinstakes.len() <= 11
    }

    /// Get number of winners
    pub fn len(&self) -> usize {
        self.coinstakes.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.coinstakes.is_empty()
    }
}

impl Encodable for LotteryWinners {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        use crate::CompactSize;
        use byteorder::{LittleEndian, WriteBytesExt};

        writer.write_u32::<LittleEndian>(self.height)?;
        let mut size = 4;

        let count_size = CompactSize(self.coinstakes.len() as u64);
        size += count_size.encode(writer)?;

        for coinstake in &self.coinstakes {
            size += coinstake.encode(writer)?;
        }
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        use crate::CompactSize;
        let mut size = 4; // height
        size += CompactSize(self.coinstakes.len() as u64).encoded_size();
        for coinstake in &self.coinstakes {
            size += coinstake.encoded_size();
        }
        size
    }
}

impl Decodable for LotteryWinners {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        use crate::CompactSize;
        use byteorder::{LittleEndian, ReadBytesExt};

        let height = reader.read_u32::<LittleEndian>()?;
        let count = CompactSize::decode(reader)?.0 as usize;

        if count > 11 {
            return Err(Error::Deserialization(
                "Too many lottery coinstakes (max 11)".to_string(),
            ));
        }

        let mut coinstakes = Vec::with_capacity(count);
        for _ in 0..count {
            coinstakes.push(LotteryCoinstake::decode(reader)?);
        }

        Ok(Self { height, coinstakes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lottery_coinstake_encode_decode() {
        let tx_hash = Hash256::from_bytes([1u8; 32]);
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 OP_PUSH(20)
        let coinstake = LotteryCoinstake::new(tx_hash, script.clone());

        let mut encoded = Vec::new();
        coinstake.encode(&mut encoded).unwrap();

        let decoded = LotteryCoinstake::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.tx_hash, tx_hash);
        assert_eq!(decoded.script_pubkey, script);
    }

    #[test]
    fn test_lottery_winners_encode_decode() {
        let mut winners = LotteryWinners::new(2130);
        winners.coinstakes.push(LotteryCoinstake::new(
            Hash256::from_bytes([1u8; 32]),
            Script::from_bytes(vec![0x76]),
        ));
        winners.coinstakes.push(LotteryCoinstake::new(
            Hash256::from_bytes([2u8; 32]),
            Script::from_bytes(vec![0xa9]),
        ));

        let mut encoded = Vec::new();
        winners.encode(&mut encoded).unwrap();

        let decoded = LotteryWinners::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.height, 2130);
        assert_eq!(decoded.coinstakes.len(), 2);
        assert_eq!(
            decoded.coinstakes[0].tx_hash,
            Hash256::from_bytes([1u8; 32])
        );
    }

    #[test]
    fn test_lottery_winners_max_11() {
        let mut encoded = vec![];
        use byteorder::{LittleEndian, WriteBytesExt};
        encoded.write_u32::<LittleEndian>(100).unwrap();
        crate::CompactSize(12).encode(&mut encoded).unwrap(); // 12 coinstakes (too many!)

        let result = LotteryWinners::decode(&mut &encoded[..]);
        assert!(result.is_err());
    }
}
