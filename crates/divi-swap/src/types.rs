// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Chain-neutral value types used by the contract.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

use crate::error::SwapError;

/// The chains this POC swaps between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    /// DIVI (testnet in the POC).
    Divi,
    /// Bitcoin (signet in the POC).
    Btc,
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Chain::Divi => "divi",
            Chain::Btc => "btc",
        })
    }
}

/// A transaction id in **internal byte order** (the order hashed, as in `OutPoint`
/// serialization). `Display`/`FromStr` use the reversed hex that RPC and explorers show.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Txid(pub [u8; 32]);

impl Txid {
    /// Parse from RPC/explorer (reversed) hex.
    pub fn from_rpc_hex(s: &str) -> Result<Self, SwapError> {
        let mut bytes: [u8; 32] = hex::decode(s)
            .map_err(|e| SwapError::InvalidParams(format!("txid hex: {e}")))?
            .try_into()
            .map_err(|_| SwapError::InvalidParams("txid must be 32 bytes".into()))?;
        bytes.reverse();
        Ok(Txid(bytes))
    }

    /// RPC/explorer (reversed) hex.
    pub fn to_rpc_hex(&self) -> String {
        let mut b = self.0;
        b.reverse();
        hex::encode(b)
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rpc_hex())
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({})", self.to_rpc_hex())
    }
}

impl FromStr for Txid {
    type Err = SwapError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Txid::from_rpc_hex(s)
    }
}

impl Serialize for Txid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rpc_hex())
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Txid::from_rpc_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A transaction output reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Outpoint {
    /// Funding transaction.
    pub txid: Txid,
    /// Output index.
    pub vout: u32,
}

impl fmt::Display for Outpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// An amount in the chain's smallest unit (satoshis; DIVI also uses 1e8 per coin).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    /// Smallest units per whole coin, for both chains.
    pub const COIN: u64 = 100_000_000;

    /// From satoshis.
    pub const fn from_sat(sat: u64) -> Self {
        Amount(sat)
    }

    /// Satoshis.
    pub const fn to_sat(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:08}", self.0 / Self::COIN, self.0 % Self::COIN)
    }
}

/// A fully signed transaction, not yet necessarily broadcast.
///
/// Backends **build** transactions and the engine **persists** them before calling
/// [`crate::ChainBackend::broadcast`] (write-ahead, plan §3.2). Rebroadcasting the same
/// `SignedTx` after a crash must be harmless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTx {
    /// Id of `raw`.
    pub txid: Txid,
    /// Network serialization, ready for `sendrawtransaction` / Esplora `POST /tx`.
    #[serde(with = "hex_bytes")]
    pub raw: Vec<u8>,
}

/// A built HTLC funding transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Funding {
    /// The signed funding transaction.
    pub tx: SignedTx,
    /// The HTLC output inside `tx`.
    pub outpoint: Outpoint,
    /// Value locked in the HTLC output.
    pub amount: Amount,
}

/// What a backend sees at an HTLC outpoint (used to verify the counterparty's lock).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedOutput {
    /// Value of the output.
    pub amount: Amount,
    /// Confirmations of the funding transaction (0 = in mempool).
    pub confirmations: u32,
}

/// A transaction input that spent an HTLC outpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendInfo {
    /// The spending transaction.
    pub txid: Txid,
    /// Index of the input that spends the HTLC.
    pub input_index: u32,
    /// Block height of the spend, `None` while in mempool.
    pub height: Option<u64>,
    /// The input's scriptSig (DIVI P2SH spends carry the preimage here).
    #[serde(with = "hex_bytes")]
    pub script_sig: Vec<u8>,
    /// The input's witness stack (BTC P2WSH spends carry the preimage here).
    #[serde(with = "hex_vec")]
    pub witness: Vec<Vec<u8>>,
}

impl SpendInfo {
    /// Find the 32-byte preimage of `hash` among the witness items and scriptSig pushes.
    ///
    /// A refund spend carries no preimage and returns `None`.
    ///
    /// ```
    /// use divi_swap::{SpendInfo, Txid};
    /// use sha2::{Digest, Sha256};
    /// let preimage = [7u8; 32];
    /// let hash: [u8; 32] = Sha256::digest(preimage).into();
    /// let mut script_sig = vec![0x20];
    /// script_sig.extend_from_slice(&preimage);
    /// script_sig.push(0x51); // OP_1 (claim branch)
    /// let spend = SpendInfo { txid: Txid([0; 32]), input_index: 0, height: None,
    ///                         script_sig, witness: vec![] };
    /// assert_eq!(spend.extract_preimage(&hash), Some(preimage));
    /// ```
    pub fn extract_preimage(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
        let pushes = script_pushes(&self.script_sig);
        self.witness
            .iter()
            .map(Vec::as_slice)
            .chain(pushes.iter().map(Vec::as_slice))
            .filter_map(|item| <[u8; 32]>::try_from(item).ok())
            .find(|candidate| Sha256::digest(candidate).as_slice() == hash)
    }
}

/// Data pushes of a script, ignoring non-push opcodes. Stops at a malformed push.
pub fn script_pushes(script: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0x01..=0x4b => op as usize,
            0x4c if i < script.len() => {
                i += 1;
                script[i - 1] as usize
            }
            0x4d if i + 1 < script.len() => {
                i += 2;
                u16::from_le_bytes([script[i - 2], script[i - 1]]) as usize
            }
            0x4e if i + 3 < script.len() => {
                i += 4;
                u32::from_le_bytes([script[i - 4], script[i - 3], script[i - 2], script[i - 1]])
                    as usize
            }
            0x4c..=0x4e => break,
            _ => continue,
        };
        if i + len > script.len() {
            break;
        }
        out.push(script[i..i + len].to_vec());
        i += len;
    }
    out
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(hex::encode).collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|h| hex::decode(h).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_hex_round_trip_is_reversed() {
        let t = Txid::from_rpc_hex(&format!("{}01", "00".repeat(31))).unwrap();
        assert_eq!(t.0[0], 1);
        assert_eq!(t.to_rpc_hex(), format!("{}01", "00".repeat(31)));
    }

    #[test]
    fn refund_spend_has_no_preimage() {
        let spend = SpendInfo {
            txid: Txid([0; 32]),
            input_index: 0,
            height: Some(1),
            script_sig: vec![0x00],
            witness: vec![vec![1; 71], vec![]],
        };
        assert_eq!(spend.extract_preimage(&[0; 32]), None);
    }

    #[test]
    fn pushdata1_parsed() {
        let mut s = vec![0x4c, 3, 1, 2, 3, 0x51];
        s.extend([0x02, 9, 9]);
        assert_eq!(script_pushes(&s), vec![vec![1, 2, 3], vec![9, 9]]);
    }

    #[test]
    fn amount_display() {
        assert_eq!(Amount(150_000_000).to_string(), "1.50000000");
    }
}
