// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Encryption of wallet secrets at rest.
//!
//! The passphrase key is derived with Argon2id, at a cost stored in the wallet
//! (`kdf_params`). It seals a random 256-bit master key, and the master key
//! encrypts the mnemonic and each private key. Both layers use
//! XChaCha20-Poly1305 with the record's database key as associated data, so a
//! changed byte or a blob moved to another record fails to open.
//!
//! Wallets written before `kdf_params` existed use PBKDF2-HMAC-SHA512 and
//! AES-256-CBC with no authentication ([`legacy`]). They are opened as they are
//! and moved to the new format on the next unlock.

use crate::error::WalletError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Associated data for the sealed master key, followed by the KDF record and salt
pub(crate) const MASTER_KEY_AAD: &[u8] = b"encrypted_master_key";

/// Argon2id cost of a wallet's passphrase key, stored with the wallet
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB
    pub m_kib: u32,
    /// Passes over the memory
    pub t: u32,
    /// Lanes
    pub p: u32,
}

impl KdfParams {
    /// The cost new wallets and changed passphrases get: 64 MiB, 3 passes
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };

    /// The cheapest cost Argon2 allows; only for tests
    #[cfg(test)]
    pub const TEST_ONLY_FAST: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    /// Format version byte at the start of the stored record
    const VERSION: u8 = 2;

    /// The stored record: version, then m, t and p as little-endian u32
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13);
        out.push(Self::VERSION);
        out.extend_from_slice(&self.m_kib.to_le_bytes());
        out.extend_from_slice(&self.t.to_le_bytes());
        out.extend_from_slice(&self.p.to_le_bytes());
        out
    }

    /// Parse a stored record. An unknown version or a cost Argon2 rejects, or one
    /// above 4 GiB, is refused rather than guessed at.
    pub(crate) fn decode(data: &[u8]) -> Result<KdfParams, WalletError> {
        let bad = || WalletError::Storage("unsupported wallet key derivation record".into());
        if data.len() != 13 || data[0] != Self::VERSION {
            return Err(bad());
        }
        let word = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let params = KdfParams {
            m_kib: word(1),
            t: word(5),
            p: word(9),
        };
        if params.m_kib > 4 * 1024 * 1024 || params.argon2().is_err() {
            return Err(bad());
        }
        Ok(params)
    }

    fn argon2(&self) -> Result<argon2::Argon2<'static>, argon2::Error> {
        let params = argon2::Params::new(self.m_kib, self.t, self.p, Some(32))?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }

    /// The 32-byte key `passphrase` and `salt` give at this cost
    pub(crate) fn derive(
        &self,
        passphrase: &str,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, WalletError> {
        let mut key = Zeroizing::new([0u8; 32]);
        self.argon2()
            .and_then(|a| a.hash_password_into(passphrase.as_bytes(), salt, &mut key[..]))
            .map_err(|e| WalletError::Storage(format!("key derivation failed: {}", e)))?;
        Ok(key)
    }
}

/// The decrypted master key, and the format the wallet's records are in
pub(crate) struct MasterKey {
    pub key: Zeroizing<Vec<u8>>,
    /// True once the wallet stores `kdf_params` and its records are AEAD
    pub aead: bool,
}

impl MasterKey {
    /// Encrypt a record stored under `record_key`
    pub fn seal_record(&self, record_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        if self.aead {
            seal(&self.key, record_key, plaintext)
        } else {
            legacy::encrypt_blob(&self.key, plaintext)
        }
    }

    /// Decrypt the record stored under `record_key`. The master key is already
    /// known to be right, so a failure means the record is corrupt or was changed.
    pub fn open_record(
        &self,
        record_key: &[u8],
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        let plain = if self.aead {
            open(&self.key, record_key, blob)
        } else {
            legacy::decrypt_blob(blob, &self.key)
        };
        plain.map(Zeroizing::new).ok_or_else(|| {
            WalletError::Storage(format!(
                "encrypted wallet record {} is corrupt or has been changed",
                describe_record(record_key)
            ))
        })
    }
}

/// A record key for an error message: printable text, or hex
fn describe_record(key: &[u8]) -> String {
    match std::str::from_utf8(key) {
        Ok(text) if text.bytes().all(|b| b.is_ascii_graphic()) => text.to_string(),
        _ => hex::encode(key),
    }
}

/// Associated data binding the sealed master key to its KDF record and salt
pub(crate) fn master_key_aad(params: &KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut aad = MASTER_KEY_AAD.to_vec();
    aad.extend_from_slice(&params.encode());
    aad.extend_from_slice(salt);
    aad
}

/// Seal `master_key` under the key `passphrase` gives at `params`
pub(crate) fn seal_master_key(
    master_key: &[u8],
    passphrase: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Vec<u8>, WalletError> {
    let key = params.derive(passphrase, salt)?;
    Ok(seal(&key[..], &master_key_aad(params, salt), master_key))
}

/// Open a sealed master key; a wrong passphrase gives `WrongPassphrase`
pub(crate) fn open_master_key(
    sealed: &[u8],
    passphrase: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<Vec<u8>>, WalletError> {
    let key = params.derive(passphrase, salt)?;
    let plain = open(&key[..], &master_key_aad(params, salt), sealed)
        .map(Zeroizing::new)
        .ok_or(WalletError::WrongPassphrase)?;
    if plain.len() != 32 {
        return Err(WalletError::WrongPassphrase);
    }
    Ok(plain)
}

/// XChaCha20-Poly1305 with a random nonce: `[nonce (24)] [ciphertext and tag]`
fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes");
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    out
}

/// Inverse of `seal`; None if the key, the data or the associated data differ
fn open(key: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return None;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let (nonce, body) = sealed.split_at(24);
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
        .ok()
}

/// The format of wallets written before `kdf_params`: PBKDF2-HMAC-SHA512 at
/// 25,000 iterations and AES-256-CBC. Only read, and written only to records
/// of a wallet that could not be moved to the new format.
pub(crate) mod legacy {
    use crate::error::WalletError;
    use zeroize::Zeroizing;

    /// PBKDF2 iterations (matches C++ Divi's default)
    const PBKDF2_ITERATIONS: u32 = 25000;

    /// Derive the passphrase key with PBKDF2-HMAC-SHA512
    pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Zeroizing<Vec<u8>> {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;

        let mut key = Zeroizing::new(vec![0u8; 32]);
        pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
        key
    }

    /// Seal a master key: AES-256-CBC of `master || sha256(master)[..4]`.
    /// The checksum makes a wrong passphrase detectable with certainty (padding
    /// alone accepts a wrong key about 1 time in 256). New wallets never use
    /// this; it is kept to build old-format wallets in tests.
    #[cfg(test)]
    pub fn seal_master_key(master_key: &[u8], key: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut plain = Zeroizing::new(master_key.to_vec());
        plain.extend_from_slice(&Sha256::digest(master_key)[..4]);
        encrypt_blob(key, &plain)
    }

    /// Open a sealed master key; any wrong key yields `WrongPassphrase`
    pub fn open_master_key(sealed: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        use sha2::{Digest, Sha256};
        let plain = Zeroizing::new(decrypt_blob(sealed, key).ok_or(WalletError::WrongPassphrase)?);
        if plain.len() != 36 || Sha256::digest(&plain[..32])[..4] != plain[32..] {
            return Err(WalletError::WrongPassphrase);
        }
        Ok(Zeroizing::new(plain[..32].to_vec()))
    }

    /// AES-256-CBC (PKCS7) with a fresh random IV; output is `[IV (16)] [ciphertext]`
    pub fn encrypt_blob(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        use aes::Aes256;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use rand::RngCore;

        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        let cipher = cbc::Encryptor::<Aes256>::new_from_slices(key, &iv)
            .expect("AES-256 key is 32 bytes and IV is 16 bytes");
        let mut out = iv.to_vec();
        out.extend_from_slice(
            &cipher.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plaintext),
        );
        out
    }

    /// Inverse of `encrypt_blob`; None on a bad length, key or padding
    pub fn decrypt_blob(encrypted: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        use aes::Aes256;
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};

        if encrypted.len() < 16 {
            return None;
        }
        let (iv, ciphertext) = encrypted.split_at(16);
        let cipher = cbc::Decryptor::<Aes256>::new_from_slices(key, iv).ok()?;
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        let decrypted = cipher
            .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
            .ok()?;
        Some(decrypted.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams::TEST_ONLY_FAST;

    #[test]
    fn node07_kdf_record_round_trips_and_rejects_nonsense() {
        assert_eq!(
            KdfParams::decode(&KdfParams::DEFAULT.encode()).unwrap(),
            KdfParams::DEFAULT
        );
        let mut wrong_version = KdfParams::DEFAULT.encode();
        wrong_version[0] = 1;
        assert!(KdfParams::decode(&wrong_version).is_err());
        let zero_passes = KdfParams {
            t: 0,
            ..KdfParams::DEFAULT
        };
        assert!(KdfParams::decode(&zero_passes.encode()).is_err());
        let huge = KdfParams {
            m_kib: u32::MAX,
            ..KdfParams::DEFAULT
        };
        assert!(KdfParams::decode(&huge.encode()).is_err());
        assert!(KdfParams::decode(&[2u8; 12]).is_err());
    }

    #[test]
    fn node07_argon2id_matches_the_reference_vector() {
        // RFC 9106 has no vector without secret and AD; this one is from the
        // argon2 reference implementation (argon2 -id -t 2 -m 16 -p 1 -l 32)
        let params = KdfParams {
            m_kib: 1 << 16,
            t: 2,
            p: 1,
        };
        let key = params.derive("password", b"somesalt").unwrap();
        assert_eq!(
            hex::encode(&key[..]),
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
        );
    }

    #[test]
    fn node07_wrong_passphrase_is_refused() {
        let salt = [5u8; 16];
        let sealed = seal_master_key(&[9u8; 32], "right", &salt, &FAST).unwrap();
        assert_eq!(
            &open_master_key(&sealed, "right", &salt, &FAST).unwrap()[..],
            &[9u8; 32]
        );
        assert!(matches!(
            open_master_key(&sealed, "wrong", &salt, &FAST),
            Err(WalletError::WrongPassphrase)
        ));
        // A lowered cost or another salt does not open it either
        let cheaper = KdfParams { t: 2, ..FAST };
        assert!(open_master_key(&sealed, "right", &salt, &cheaper).is_err());
        assert!(open_master_key(&sealed, "right", &[6u8; 16], &FAST).is_err());
    }

    #[test]
    fn node08_changed_or_moved_records_fail_to_open() {
        let master = MasterKey {
            key: Zeroizing::new(vec![3u8; 32]),
            aead: true,
        };
        let blob = master.seal_record(b"record-a", b"secret bytes");
        assert_eq!(
            &master.open_record(b"record-a", &blob).unwrap()[..],
            b"secret bytes"
        );
        for i in 0..blob.len() {
            let mut flipped = blob.clone();
            flipped[i] ^= 0x01;
            assert!(
                master.open_record(b"record-a", &flipped).is_err(),
                "byte {i}"
            );
        }
        assert!(master.open_record(b"record-b", &blob).is_err());
        assert!(master.open_record(b"record-a", &blob[..30]).is_err());
    }

    #[test]
    fn legacy_records_still_open() {
        let key = legacy::derive_key_from_passphrase("pass", &[1u8; 16]);
        let sealed = legacy::seal_master_key(&[4u8; 32], &key);
        let master = legacy::open_master_key(&sealed, &key).unwrap();
        let master = MasterKey {
            key: master,
            aead: false,
        };
        let blob = master.seal_record(b"ignored", b"abc");
        assert_eq!(&master.open_record(b"other", &blob).unwrap()[..], b"abc");
    }
}
