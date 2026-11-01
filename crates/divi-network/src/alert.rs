// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! `alert` messages as Divi Core judges them (alert.cpp `ProcessAlert`)
//!
//! IronDivi neither shows nor relays alerts; it only needs Core's verdict,
//! because Core costs a peer 10 points for every alert it cannot accept.

use crate::constants::{Magic, MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};
use crate::wire::Reader;
use divi_crypto::double_sha256;

/// Divi Core `vAlertPubKey` (chainparams.cpp); regtest uses the testnet key
const MAINNET_ALERT_KEY: &str =
    "0231c07d17c2d69facd84908434dc402b5a9b9e25e5062d1e65163acc7afd0e3ef";
const TESTNET_ALERT_KEY: &str = "046e70d194b1b6b63b9c5431ea83c7b17d0db8930408b1e7937e41759a799e8fcd22d99ffc0c880094bb07a852a9020f810068417e65d19def8ffbdfa90727b637";

/// Points Divi Core adds for an alert it cannot process (main.cpp)
pub const BAD_ALERT_SCORE: u32 = 10;

/// The alert key of a Divi network, by its magic (None for other chains)
pub fn alert_key(magic: &Magic) -> Option<Vec<u8>> {
    let key = if magic == &MAINNET_MAGIC {
        MAINNET_ALERT_KEY
    } else if magic == &TESTNET_MAGIC || magic == &REGTEST_MAGIC {
        TESTNET_ALERT_KEY
    } else {
        return None;
    };
    hex::decode(key).ok()
}

/// The two parts of a `CAlert`: the signed message and its signature
pub struct Alert {
    pub msg: Vec<u8>,
    pub sig: Vec<u8>,
}

impl Alert {
    /// Parse an `alert` payload; an error is a malformed message
    pub fn parse(payload: &[u8]) -> Result<Self, crate::error::NetworkError> {
        let mut r = Reader::new(payload);
        let msg = r.var_bytes()?.to_vec();
        let sig = r.var_bytes()?.to_vec();
        Ok(Alert { msg, sig })
    }

    /// Divi Core `CAlert::GetHash`: double SHA-256 of the signed message
    pub fn hash(&self) -> [u8; 32] {
        double_sha256(&self.msg)
    }

    /// Divi Core `CAlert::ProcessAlert` without the cancellation of stored
    /// alerts (IronDivi stores none): the signature by `key`, the alert in
    /// effect at `adjusted_time`, and the reserved maximum id used only for
    /// the fixed "key compromised" alert
    pub fn is_acceptable(&self, key: &[u8], adjusted_time: i64) -> bool {
        let hash = double_sha256(&self.msg);
        if !divi_script::checker::verify_ecdsa_lax(key, &self.sig, &hash) {
            return false;
        }
        let Ok(u) = UnsignedAlert::parse(&self.msg) else {
            return false;
        };
        if adjusted_time >= u.expiration {
            return false;
        }
        let max = i32::MAX;
        if u.id == max
            && !(u.expiration == i64::from(max)
                && u.cancel == max - 1
                && u.min_ver == 0
                && u.max_ver == max
                && u.set_sub_ver_empty
                && u.priority == max
                && u.status_bar == "URGENT: Alert key compromised, upgrade required")
        {
            return false;
        }
        true
    }
}

/// The fields of `CUnsignedAlert` the checks use
struct UnsignedAlert {
    expiration: i64,
    id: i32,
    cancel: i32,
    min_ver: i32,
    max_ver: i32,
    set_sub_ver_empty: bool,
    priority: i32,
    status_bar: String,
}

impl UnsignedAlert {
    fn parse(data: &[u8]) -> Result<Self, crate::error::NetworkError> {
        let mut r = Reader::new(data);
        let _version = r.i32()?;
        let _relay_until = r.i64()?;
        let expiration = r.i64()?;
        let id = r.i32()?;
        let cancel = r.i32()?;
        for _ in 0..r.size()? {
            r.i32()?; // setCancel
        }
        let min_ver = r.i32()?;
        let max_ver = r.i32()?;
        let sub_vers = r.size()?;
        for _ in 0..sub_vers {
            r.var_bytes()?;
        }
        let priority = r.i32()?;
        let _comment = r.limited_string(65536)?;
        let status_bar = r.limited_string(256)?;
        let _reserved = r.limited_string(256)?;
        Ok(UnsignedAlert {
            expiration,
            id,
            cancel,
            min_ver,
            max_ver,
            set_sub_ver_empty: sub_vers == 0,
            priority,
            status_bar,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_crypto::KeyPair;

    fn unsigned(expiration: i64, id: i32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1i32.to_le_bytes());
        v.extend_from_slice(&0i64.to_le_bytes());
        v.extend_from_slice(&expiration.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.push(0); // setCancel
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&i32::MAX.to_le_bytes());
        v.push(0); // setSubVer
        v.extend_from_slice(&1i32.to_le_bytes());
        v.push(0); // comment
        v.push(4);
        v.extend_from_slice(b"test");
        v.push(0); // reserved
        v
    }

    fn signed(kp: &KeyPair, msg: Vec<u8>) -> Alert {
        let hash = double_sha256(&msg);
        let sig = divi_crypto::sign_hash(kp.secret_key(), &hash)
            .unwrap()
            .to_der();
        Alert { msg, sig }
    }

    #[test]
    fn signature_expiry_and_reserved_id() {
        let kp = KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let now = 1_000_000;
        assert!(signed(&kp, unsigned(now + 1, 7)).is_acceptable(&key, now));
        // Expired
        assert!(!signed(&kp, unsigned(now, 7)).is_acceptable(&key, now));
        // Another key
        let other = KeyPair::new_random();
        assert!(!signed(&other, unsigned(now + 1, 7)).is_acceptable(&key, now));
        // The reserved id needs the fixed content
        assert!(!signed(&kp, unsigned(now + 1, i32::MAX)).is_acceptable(&key, now));
    }

    #[test]
    fn keys_by_network() {
        assert_eq!(alert_key(&MAINNET_MAGIC).unwrap().len(), 33);
        assert_eq!(alert_key(&REGTEST_MAGIC).unwrap().len(), 65);
        assert!(alert_key(&crate::constants::PRIVATEDIVI_MAINNET_MAGIC).is_none());
    }
}
