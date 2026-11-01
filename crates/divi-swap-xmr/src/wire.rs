// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Serde forms for the protocol's values (`#[serde(with = "...")]`), all hex strings:
//! secp256k1 points (33-byte compressed), ed25519 points (32-byte compressed, rejected unless
//! torsion-free) and scalars, encrypted signatures (`ecdsa_fun`'s 162-byte encoding), DIVI
//! transactions (network serialization) and secret keys (for the persisted records only —
//! never on the wire).

use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

fn hex_str<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    hex::decode(String::deserialize(d)?).map_err(D::Error::custom)
}

/// `Vec<u8>` as hex.
pub mod bytes {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex_str(d)
    }
}

/// `[u8; 32]` as hex.
pub mod b32 {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        hex_str(d)?
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// `[u8; 33]` as hex.
pub mod b33 {
    use super::*;
    pub fn serialize<S: Serializer>(v: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        hex_str(d)?
            .try_into()
            .map_err(|_| D::Error::custom("expected 33 bytes"))
    }
}

/// A secp256k1 point (`swap_adaptor` / `secp256kfun`), compressed.
pub mod secp_point {
    use super::*;
    use swap_adaptor::adaptor::Point;
    pub fn serialize<S: Serializer>(p: &Point, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(p.to_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Point, D::Error> {
        let b: [u8; 33] = hex_str(d)?
            .try_into()
            .map_err(|_| D::Error::custom("expected a 33-byte point"))?;
        Point::from_bytes(b).ok_or_else(|| D::Error::custom("not a secp256k1 point"))
    }
}

/// An ed25519 point (`curve25519-dalek-ng`), compressed; must be in the prime-order subgroup.
pub mod ed_point {
    use super::*;
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use swap_adaptor::dleq::PointQ;
    pub fn serialize<S: Serializer>(p: &PointQ, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(p.compress().to_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PointQ, D::Error> {
        let b: [u8; 32] = hex_str(d)?
            .try_into()
            .map_err(|_| D::Error::custom("expected a 32-byte point"))?;
        CompressedEdwardsY(b)
            .decompress()
            .filter(|p| p.is_torsion_free())
            .ok_or_else(|| D::Error::custom("not a prime-order ed25519 point"))
    }
}

/// An ed25519 scalar (persisted secrets only).
pub mod ed_scalar {
    use super::*;
    use swap_adaptor::dleq::ScalarQ;
    pub fn serialize<S: Serializer>(v: &ScalarQ, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.to_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ScalarQ, D::Error> {
        let b: [u8; 32] = hex_str(d)?
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))?;
        ScalarQ::from_canonical_bytes(b).ok_or_else(|| D::Error::custom("not a canonical scalar"))
    }
}

/// A DIVI secret key (persisted secrets only).
pub mod divi_secret {
    use super::*;
    use divi_crypto::keys::SecretKey;
    pub fn serialize<S: Serializer>(k: &SecretKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&k.to_hex())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretKey, D::Error> {
        SecretKey::from_hex(&String::deserialize(d)?).map_err(D::Error::custom)
    }
}

/// An `ecdsa_fun` adaptor-encrypted signature.
pub mod enc_sig {
    use super::*;
    use std::str::FromStr;
    use swap_adaptor::adaptor::EncryptedSignature;
    pub fn serialize<S: Serializer>(v: &EncryptedSignature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<EncryptedSignature, D::Error> {
        EncryptedSignature::from_str(&String::deserialize(d)?)
            .map_err(|_| D::Error::custom("not an encrypted signature"))
    }
}

/// A DIVI transaction, network-serialized.
pub mod divi_tx {
    use super::*;
    use divi_primitives::transaction::Transaction;
    pub fn serialize<S: Serializer>(tx: &Transaction, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(divi_primitives::serialize::serialize(tx)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Transaction, D::Error> {
        divi_primitives::serialize::deserialize(&hex_str(d)?)
            .map_err(|e| D::Error::custom(format!("transaction: {e}")))
    }
}

/// `Option` of a DIVI transaction.
pub mod opt_divi_tx {
    use super::*;
    use divi_primitives::transaction::Transaction;
    use serde::Serialize;
    pub fn serialize<S: Serializer>(tx: &Option<Transaction>, s: S) -> Result<S::Ok, S::Error> {
        tx.as_ref()
            .map(|t| hex::encode(divi_primitives::serialize::serialize(t)))
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Transaction>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|h| {
                let b = hex::decode(h).map_err(D::Error::custom)?;
                divi_primitives::serialize::deserialize(&b)
                    .map_err(|e| D::Error::custom(format!("transaction: {e}")))
            })
            .transpose()
    }
}
