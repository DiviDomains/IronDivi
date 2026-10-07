// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The HTLC redeem script, identical on both chains (P2SH on DIVI, P2WSH on BTC).
//!
//! ```text
//! OP_IF   OP_SHA256 <h32> OP_EQUALVERIFY <claim_pubkey>
//! OP_ELSE <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pubkey>
//! OP_ENDIF OP_CHECKSIG
//! ```
//!
//! Spending stacks (bottom first):
//! - claim:  `<sig> <preimage32> OP_1`  (+ `<redeem_script>` for P2SH / witness script)
//! - refund: `<sig> OP_0`               (+ `<redeem_script>`), with the spending tx's
//!   `nLockTime >= locktime` and the input's `nSequence != 0xffffffff`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, SwapError};

/// `OP_IF`
pub const OP_IF: u8 = 0x63;
/// `OP_ELSE`
pub const OP_ELSE: u8 = 0x67;
/// `OP_ENDIF`
pub const OP_ENDIF: u8 = 0x68;
/// `OP_SHA256`
pub const OP_SHA256: u8 = 0xa8;
/// `OP_EQUALVERIFY`
pub const OP_EQUALVERIFY: u8 = 0x88;
/// `OP_CHECKLOCKTIMEVERIFY`
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
/// `OP_DROP`
pub const OP_DROP: u8 = 0x75;
/// `OP_CHECKSIG`
pub const OP_CHECKSIG: u8 = 0xac;
/// `OP_0` / `OP_FALSE`
pub const OP_0: u8 = 0x00;
/// `OP_1` / `OP_TRUE`
pub const OP_1: u8 = 0x51;

/// Locktimes below this are block heights; the HTLC only accepts unix timestamps.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Sequence to use on a refund input: not final, so `OP_CHECKLOCKTIMEVERIFY` is enforced,
/// and no BIP68 relative lock.
pub const REFUND_SEQUENCE: u32 = 0xffff_fffe;

/// Parameters of one HTLC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HtlcParams {
    /// SHA256 of the 32-byte swap preimage.
    #[serde(with = "hex32")]
    pub hash: [u8; 32],
    /// Compressed secp256k1 pubkey allowed to claim with the preimage.
    #[serde(with = "hex33")]
    pub claim_pubkey: [u8; 33],
    /// Compressed secp256k1 pubkey allowed to refund after `locktime`.
    #[serde(with = "hex33")]
    pub refund_pubkey: [u8; 33],
    /// Unix timestamp, compared against median time past (must be `>= LOCKTIME_THRESHOLD`).
    pub locktime: u32,
}

impl HtlcParams {
    /// Check the parameters are well formed.
    pub fn validate(&self) -> Result<()> {
        if self.locktime < LOCKTIME_THRESHOLD {
            return Err(SwapError::InvalidParams(format!(
                "locktime {} is a block height; HTLCs use unix timestamps",
                self.locktime
            )));
        }
        for (name, pk) in [
            ("claim", &self.claim_pubkey),
            ("refund", &self.refund_pubkey),
        ] {
            if pk[0] != 0x02 && pk[0] != 0x03 {
                return Err(SwapError::InvalidParams(format!(
                    "{name} pubkey is not compressed"
                )));
            }
        }
        Ok(())
    }

    /// The redeem / witness script.
    ///
    /// ```
    /// use divi_swap::HtlcParams;
    /// let p = HtlcParams {
    ///     hash: [0xaa; 32],
    ///     claim_pubkey: [0x02; 33],
    ///     refund_pubkey: [0x03; 33],
    ///     locktime: 1_800_000_000, // 0x6b49d200
    /// };
    /// let s = hex::encode(p.redeem_script());
    /// assert_eq!(
    ///     s,
    ///     format!(
    ///         "63a820{}8821{}6704{}b17521{}68ac",
    ///         "aa".repeat(32),
    ///         "02".repeat(33),
    ///         "00d2496b",
    ///         "03".repeat(33)
    ///     )
    /// );
    /// assert_eq!(p.redeem_script().len(), 114);
    /// ```
    pub fn redeem_script(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(114);
        s.extend([OP_IF, OP_SHA256]);
        push_data(&mut s, &self.hash);
        s.push(OP_EQUALVERIFY);
        push_data(&mut s, &self.claim_pubkey);
        s.push(OP_ELSE);
        push_data(&mut s, &script_num(self.locktime as i64));
        s.extend([OP_CHECKLOCKTIMEVERIFY, OP_DROP]);
        push_data(&mut s, &self.refund_pubkey);
        s.extend([OP_ENDIF, OP_CHECKSIG]);
        s
    }

    /// SHA256 of the redeem script (the P2WSH program).
    pub fn script_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.redeem_script()).into()
    }
}

/// Generate a fresh random 32-byte preimage and its SHA256 hash.
pub fn new_preimage() -> ([u8; 32], [u8; 32]) {
    let preimage: [u8; 32] = rand::random();
    let hash = Sha256::digest(preimage).into();
    (preimage, hash)
}

/// P2SH scriptSig for the claim branch: `<sig> <preimage> OP_1 <redeem_script>`.
/// `sig` is DER + sighash-type byte.
pub fn claim_script_sig(sig: &[u8], preimage: &[u8; 32], redeem_script: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    push_data(&mut s, sig);
    push_data(&mut s, preimage);
    s.push(OP_1);
    push_data(&mut s, redeem_script);
    s
}

/// P2SH scriptSig for the refund branch: `<sig> OP_0 <redeem_script>`.
pub fn refund_script_sig(sig: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    push_data(&mut s, sig);
    s.push(OP_0);
    push_data(&mut s, redeem_script);
    s
}

/// Minimal CScriptNum encoding (little endian, sign bit in the top byte).
pub fn script_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if out.last().is_some_and(|b| b & 0x80 != 0) {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *out.last_mut().expect("non-empty") |= 0x80;
    }
    out
}

/// Append a minimal data push.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => script.push(OP_0),
        n @ 1..=0x4b => script.push(n as u8),
        n @ 0x4c..=0xff => script.extend([0x4c, n as u8]),
        n @ 0x100..=0xffff => {
            script.push(0x4d);
            script.extend((n as u16).to_le_bytes());
        }
        n => {
            script.push(0x4e);
            script.extend((n as u32).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        hex::decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex33 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        hex::decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_num_vectors() {
        assert_eq!(script_num(0), Vec::<u8>::new());
        assert_eq!(script_num(1), vec![1]);
        assert_eq!(script_num(127), vec![0x7f]);
        assert_eq!(script_num(128), vec![0x80, 0x00]);
        assert_eq!(script_num(-1), vec![0x81]);
        assert_eq!(script_num(-128), vec![0x80, 0x80]);
        assert_eq!(script_num(1_800_000_000), vec![0x00, 0xd2, 0x49, 0x6b]);
        // Above 2^31 needs a fifth byte; CLTV accepts 5-byte numbers.
        assert_eq!(script_num(0x8000_0000), vec![0, 0, 0, 0x80, 0]);
    }

    #[test]
    fn validate_rejects_heights_and_uncompressed() {
        let mut p = HtlcParams {
            hash: [0; 32],
            claim_pubkey: [2; 33],
            refund_pubkey: [3; 33],
            locktime: 1_800_000_000,
        };
        assert!(p.validate().is_ok());
        p.locktime = 340_000;
        assert!(p.validate().is_err());
        p.locktime = 1_800_000_000;
        p.claim_pubkey[0] = 4;
        assert!(p.validate().is_err());
    }

    #[test]
    fn preimage_hash_matches() {
        let (pre, h) = new_preimage();
        assert_eq!(<[u8; 32]>::from(Sha256::digest(pre)), h);
    }

    #[test]
    fn serde_round_trip() {
        let p = HtlcParams {
            hash: [9; 32],
            claim_pubkey: [2; 33],
            refund_pubkey: [3; 33],
            locktime: 1_800_000_000,
        };
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<HtlcParams>(&j).unwrap(), p);
    }
}
