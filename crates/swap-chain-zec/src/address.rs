// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Zcash testnet transparent addresses: Base58Check with a 2-byte version prefix (one byte
//! more than Bitcoin's), `tm…` for P2PKH and `t2…` for P2SH. Prefixes from zcashd
//! `src/chainparams.cpp` `CChainParams::Base58Prefixes` for `CBaseChainParams::TESTNET`.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use divi_swap::SwapError;

/// `pubkeyhash` Base58Check version bytes, testnet (`tm…`).
pub const PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1d, 0x25];
/// `scripthash` Base58Check version bytes, testnet (`t2…`).
pub const SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xba];

/// `OP_DUP`
const OP_DUP: u8 = 0x76;
/// `OP_HASH160`
const OP_HASH160: u8 = 0xa9;
/// `OP_EQUALVERIFY`
const OP_EQUALVERIFY: u8 = 0x88;
/// `OP_CHECKSIG`
const OP_CHECKSIG: u8 = 0xac;
/// `OP_EQUAL`
const OP_EQUAL: u8 = 0x87;

/// RIPEMD160(SHA256(data)), as used for both address kinds.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

fn base58check(prefix: [u8; 2], payload: &[u8; 20]) -> String {
    let mut v = Vec::with_capacity(2 + 20 + 4);
    v.extend(prefix);
    v.extend(payload);
    let checksum = Sha256::digest(Sha256::digest(&v));
    v.extend(&checksum[..4]);
    bs58::encode(v).into_string()
}

/// A decoded transparent address: which kind, and its 20-byte hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentAddress {
    /// `tm…`: hash160 of a compressed pubkey.
    PubKeyHash([u8; 20]),
    /// `t2…`: hash160 of a redeem script.
    ScriptHash([u8; 20]),
}

impl TransparentAddress {
    /// Encode the P2PKH (`tm…`) address of a compressed pubkey.
    pub fn p2pkh(pubkey: &[u8; 33]) -> Self {
        TransparentAddress::PubKeyHash(hash160(pubkey))
    }

    /// Encode the P2SH (`t2…`) address of a redeem script.
    pub fn p2sh(redeem_script: &[u8]) -> Self {
        TransparentAddress::ScriptHash(hash160(redeem_script))
    }

    /// Base58Check string, e.g. `tm9z…` or `t2Ug…`.
    pub fn encode(&self) -> String {
        match self {
            TransparentAddress::PubKeyHash(h) => base58check(PUBKEY_ADDRESS_PREFIX, h),
            TransparentAddress::ScriptHash(h) => base58check(SCRIPT_ADDRESS_PREFIX, h),
        }
    }

    /// Parse a `tm…` or `t2…` Base58Check string.
    pub fn decode(s: &str) -> Result<Self, SwapError> {
        let data = bs58::decode(s)
            .into_vec()
            .map_err(|e| SwapError::InvalidParams(format!("bad base58 address {s:?}: {e}")))?;
        if data.len() != 2 + 20 + 4 {
            return Err(SwapError::InvalidParams(format!(
                "address {s:?} has wrong length {}",
                data.len()
            )));
        }
        let (body, checksum) = data.split_at(2 + 20);
        let want = Sha256::digest(Sha256::digest(body));
        if &want[..4] != checksum {
            return Err(SwapError::InvalidParams(format!(
                "address {s:?} has a bad checksum"
            )));
        }
        let prefix = [body[0], body[1]];
        let hash: [u8; 20] = body[2..].try_into().expect("exactly 20 bytes");
        if prefix == PUBKEY_ADDRESS_PREFIX {
            Ok(TransparentAddress::PubKeyHash(hash))
        } else if prefix == SCRIPT_ADDRESS_PREFIX {
            Ok(TransparentAddress::ScriptHash(hash))
        } else {
            Err(SwapError::InvalidParams(format!(
                "address {s:?} has an unrecognized prefix {prefix:02x?} (want testnet tm… or t2…)"
            )))
        }
    }

    /// The transparent `scriptPubKey` this address is paid with.
    pub fn script_pubkey(&self) -> Vec<u8> {
        match self {
            TransparentAddress::PubKeyHash(h) => {
                let mut s = Vec::with_capacity(25);
                s.extend([OP_DUP, OP_HASH160, 20]);
                s.extend(h);
                s.extend([OP_EQUALVERIFY, OP_CHECKSIG]);
                s
            }
            TransparentAddress::ScriptHash(h) => {
                let mut s = Vec::with_capacity(23);
                s.push(OP_HASH160);
                s.push(20);
                s.extend(h);
                s.push(OP_EQUAL);
                s
            }
        }
    }
}

/// The P2SH `scriptPubKey` of an HTLC redeem script.
pub fn htlc_script_pubkey(redeem_script: &[u8]) -> Vec<u8> {
    TransparentAddress::p2sh(redeem_script).script_pubkey()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_address_encoding() {
        // zcashd `validateaddress` / `decodescript` testnet vector: the all-zero compressed
        // pubkey's hash160 round-trips through a `tm…` address and back.
        let pubkey = [2u8; 33];
        let addr = TransparentAddress::p2pkh(&pubkey);
        let s = addr.encode();
        assert!(s.starts_with("tm"), "{s}");
        assert_eq!(TransparentAddress::decode(&s).unwrap(), addr);

        let script = vec![0x51; 10];
        let p2sh = TransparentAddress::p2sh(&script);
        let s2 = p2sh.encode();
        assert!(s2.starts_with("t2"), "{s2}");
        assert_eq!(TransparentAddress::decode(&s2).unwrap(), p2sh);
        assert_ne!(s, s2);

        // A corrupted checksum is rejected.
        let mut bytes = bs58::decode(&s).into_vec().unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let corrupted = bs58::encode(bytes).into_string();
        assert!(TransparentAddress::decode(&corrupted).is_err());

        // scriptPubKey shapes.
        let TransparentAddress::PubKeyHash(h) = addr else {
            unreachable!()
        };
        let spk = addr.script_pubkey();
        assert_eq!(spk[0], OP_DUP);
        assert_eq!(spk[1], OP_HASH160);
        assert_eq!(&spk[3..23], &h);
        assert_eq!(spk[23], OP_EQUALVERIFY);
        assert_eq!(spk[24], OP_CHECKSIG);

        let TransparentAddress::ScriptHash(h2) = p2sh else {
            unreachable!()
        };
        let spk2 = p2sh.script_pubkey();
        assert_eq!(spk2[0], OP_HASH160);
        assert_eq!(&spk2[2..22], &h2);
        assert_eq!(spk2[22], OP_EQUAL);
    }

    /// Cross-check against `docs/plans/swap-poc/funding.md`: the taker-btc / maker-btc
    /// swap keys (same pubkey, reused across chains per that decision) must derive the
    /// exact `tm…` addresses the orchestrator funded on Zcash testnet. If this ever fails,
    /// stop and report it — it means our P2PKH derivation disagrees with
    /// `tools/swap-poc/derive-addrs.py`'s and funded TAZ would be unspendable by us.
    #[test]
    fn funding_table_addresses_match() {
        let taker_btc_pubkey: [u8; 33] =
            hex::decode("03a7f9cfee27410046ac906b13c2500672b2930584da9693ce69f9f0a81a5f22f5")
                .unwrap()
                .try_into()
                .unwrap();
        let maker_btc_pubkey: [u8; 33] =
            hex::decode("02d05bd358a1efd8e5aa9c82c10d0e2c0ce67c1e5a984f02684724df28a343a7dd")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            TransparentAddress::p2pkh(&taker_btc_pubkey).encode(),
            "tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk"
        );
        assert_eq!(
            TransparentAddress::p2pkh(&maker_btc_pubkey).encode(),
            "tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn"
        );
    }
}
