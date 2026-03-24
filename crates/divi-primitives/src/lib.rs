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

//! Core primitive types for Divi blockchain
//!
//! This crate provides byte-compatible implementations of Divi's core types,
//! matching the C++ serialization format exactly.

pub mod amount;
pub mod block;
pub mod compact;
pub mod error;
pub mod hash;
pub mod lottery;
pub mod script;
pub mod serialize;
pub mod test_vectors;
pub mod transaction;

pub use amount::Amount;
pub use block::{Block, BlockHeader};
pub use compact::CompactSize;
pub use error::Error;
pub use hash::{Hash160, Hash256};
pub use lottery::{LotteryCoinstake, LotteryWinners};
pub use script::Script;
pub use serialize::{deserialize, serialize, Decodable, Encodable};
pub use transaction::{OutPoint, Transaction, TxIn, TxOut};

/// Chain mode - selects between Divi and PrivateDivi chains
///
/// PrivateDivi is a hard fork of Divi with identical consensus rules
/// but different magic bytes, ports, DNS seeds, and BIP44 coin type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ChainMode {
    /// Original Divi chain
    #[default]
    Divi,
    /// PrivateDivi chain (hard fork with separate genesis)
    PrivateDivi,
}

impl std::fmt::Display for ChainMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainMode::Divi => write!(f, "divi"),
            ChainMode::PrivateDivi => write!(f, "privatedivi"),
        }
    }
}

/// Network magic bytes for different networks
pub mod network {
    /// Mainnet magic bytes
    pub const MAINNET_MAGIC: [u8; 4] = [0x90, 0x0d, 0xf0, 0x0d];
    /// Testnet magic bytes
    pub const TESTNET_MAGIC: [u8; 4] = [0x45, 0x76, 0x65, 0x21];
    /// Regtest magic bytes
    pub const REGTEST_MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];
}

/// Protocol constants
pub mod constants {
    use super::Amount;

    /// One DIVI in satoshis (10^8)
    pub const COIN: i64 = 100_000_000;

    /// Maximum money supply — matches C++ nMaxMoneyOut for mainnet (2,534,320,700 DIVI)
    pub const MAX_MONEY: Amount = Amount(2_534_320_700 * COIN);

    /// Coinbase maturity for mainnet (must wait this many blocks to spend coinbase).
    /// Testnet and regtest use 1.
    pub const COINBASE_MATURITY: u32 = 20;

    /// Coinstake maturity (must wait this many blocks to spend coinstake)
    pub const COINSTAKE_MATURITY: u32 = 20;

    /// Maximum block size
    pub const MAX_BLOCK_SIZE: usize = 2_000_000;

    /// Maximum transaction size
    pub const MAX_TX_SIZE: usize = 1_000_000;

    /// Sequence number for final transactions
    pub const SEQUENCE_FINAL: u32 = 0xffffffff;

    /// Current block version
    pub const CURRENT_BLOCK_VERSION: i32 = 4;

    /// Current transaction version
    pub const CURRENT_TX_VERSION: i32 = 1;
}
