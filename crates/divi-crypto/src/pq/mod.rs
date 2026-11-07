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

//! Post-Quantum Cryptographic Primitives, Domain-Separated Prehashing, and
//! Deterministic BIP39 PQ HD Key Derivation (`DIP-PQ-1`, Track 7C Phase 1 `P1.3`).
//!
//! This module is **consensus-inert** in Phase 1 (`P1.3`): it provides the fixed
//! NIST parameter sets (`ML-DSA-44`, `FN-DSA-512`, `SLH-DSA-128s`, and
//! `LMS-SHA256-M32-H10`), strict canonical byte-encoding validators (zero
//! floating-point instructions), `SHA-512` domain-separated signing prehashes,
//! `HMAC-SHA512` / `SHAKE256` deterministic BIP39 post-quantum HD key derivation,
//! and the pure-integer `LMS-SHA256-M32-H10` (`LMOTS-SHA256-N32-W4`) stateful
//! Spork signature reference implementation, with zero active consensus call sites
//! until `DIP-PQ-2..4` fork activation.

use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Root HMAC-SHA512 domain key separating the post-quantum HD tree from classical BIP32 (`DIP-PQ-1` §5.1).
pub const PQ_HD_MASTER_KEY_DOMAIN: &[u8] = b"Divi PQ seed v1";

/// `SHAKE256` prefix used to expand a PQ HD leaf node into an algorithm keygen stream (`DIP-PQ-1` §5.4).
pub const PQ_KEYGEN_STREAM_DOMAIN: &[u8] = b"Divi-PQ-Keygen-v1";

/// `SHA-256` prefix used for 256-bit post-quantum script/address key commitments (`DIP-PQ-1` §5.5).
pub const PQ_PUBKEY_COMMITMENT_DOMAIN: &[u8] = b"Divi-PQ-PubKey-v1";

/// Hardened child index bit (`2^31 = 0x8000_0000`, `DIP-PQ-1` §5.2).
pub const HARDENED_INDEX_BIT: u32 = 0x8000_0000;

/// Canonical BIP44 purpose index (`44'`, `DIP-PQ-1` §5.3).
pub const PQ_BIP44_PURPOSE: u32 = 44;

/// LMS tree height $H = 10$ ($2^{10} = 1,024$ leaves) for `LMS_SHA256_M32_H10` (`DIP-PQ-1` §2.1 #4).
pub const LMS_TREE_HEIGHT: usize = 10;

/// Number of one-time signature leaves ($2^{10} = 1,024$) in an `LMS_SHA256_M32_H10` tree.
pub const LMS_NUM_LEAVES: u32 = 1 << LMS_TREE_HEIGHT;

/// RFC 8554 / SP 800-208 typecode for `LMS_SHA256_M32_H10` (`0x00000006`).
pub const LMS_TYPE_SHA256_M32_H10: u32 = 0x0000_0006;

/// RFC 8554 / SP 800-208 typecode for `LMOTS_SHA256_N32_W4` (`0x00000003`).
pub const LMOTS_TYPE_SHA256_N32_W4: u32 = 0x0000_0003;

/// Number of Winternitz $w=4$ hash chains ($p = 67$) in `LMOTS_SHA256_N32_W4`.
pub const LMOTS_W4_CHAINS: usize = 67;

/// Errors returned by post-quantum key derivation, canonical encoding validation, or verification.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PqError {
    #[error("unknown post-quantum scheme identifier: 0x{0:02x}")]
    UnknownSchemeId(u8),

    #[error("invalid BIP39 seed length for PQ HD derivation: expected 64 bytes, got {0}")]
    InvalidBip39SeedLength(usize),

    #[error("non-hardened PQ HD child derivation is forbidden (index 0x{0:08x} < 0x80000000)")]
    NonHardenedPqDerivationForbidden(u32),

    #[error("invalid public key length for {scheme:?}: expected {expected} bytes, got {actual}")]
    InvalidPublicKeyLength {
        scheme: PqSchemeId,
        expected: usize,
        actual: usize,
    },

    #[error("invalid signature length for {scheme:?}: expected {expected} bytes, got {actual}")]
    InvalidSignatureLength {
        scheme: PqSchemeId,
        expected: usize,
        actual: usize,
    },

    #[error("scheme {scheme:?} is forbidden in domain {domain:?}")]
    SchemeForbiddenInDomain {
        scheme: PqSchemeId,
        domain: PqDomainTag,
    },

    #[error("non-canonical public key encoding for {scheme:?}: {reason}")]
    NonCanonicalPublicKey {
        scheme: PqSchemeId,
        reason: &'static str,
    },

    #[error("non-canonical signature encoding for {scheme:?}: {reason}")]
    NonCanonicalSignature {
        scheme: PqSchemeId,
        reason: &'static str,
    },

    #[error("LMS one-time signature key exhausted at leaf index {0}")]
    LmsKeyExhausted(u32),

    #[error("post-quantum signature verification failed")]
    VerificationFailed,
}

/// Fixed NIST post-quantum signature parameter set identifier (`DIP-PQ-1` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PqSchemeId {
    /// NIST FIPS 204 `ML-DSA-44` (`|pk| = 1,312 B`, `|sig| = 2,420 B`).
    MlDsa44 = 0x01,
    /// NIST FIPS 206 `FN-DSA-512` / Falcon-512 padded (`|pk| = 897 B`, `|sig| = 666 B`).
    FnDsa512 = 0x02,
    /// NIST FIPS 205 `SLH-DSA-SHAKE-128s` (`|pk| = 32 B`, `|sig| = 7,856 B`).
    SlhDsa128s = 0x03,
    /// NIST SP 800-208 / RFC 8554 `LMS-SHA256-M32-H10` + `LMOTS-SHA256-N32-W4` (`|pk| = 60 B`, `|sig| = 2,512 B`).
    LmsSha256M32H10 = 0x04,
}

impl PqSchemeId {
    /// Parse a 1-byte `scheme_id` tag (`0x01`–`0x04`).
    pub const fn from_u8(byte: u8) -> Result<Self, PqError> {
        match byte {
            0x01 => Ok(Self::MlDsa44),
            0x02 => Ok(Self::FnDsa512),
            0x03 => Ok(Self::SlhDsa128s),
            0x04 => Ok(Self::LmsSha256M32H10),
            other => Err(PqError::UnknownSchemeId(other)),
        }
    }

    /// Return the canonical 1-byte wire identifier (`0x01`–`0x04`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Return the exact public-key byte length (`|pk|`) required by `DIP-PQ-1` §2.
    pub const fn pubkey_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::FnDsa512 => 897,
            Self::SlhDsa128s => 32,
            Self::LmsSha256M32H10 => 60,
        }
    }

    /// Return the exact signature byte length (`|sig|`) required by `DIP-PQ-1` §2.
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::FnDsa512 => 666,
            Self::SlhDsa128s => 7856,
            Self::LmsSha256M32H10 => 2512,
        }
    }

    /// Return the algorithm keygen seed byte length consumed from `KeygenStream` (`DIP-PQ-1` §2, §5.4).
    pub const fn keygen_seed_len(self) -> usize {
        match self {
            Self::MlDsa44 => 32,
            Self::FnDsa512 => 64,
            Self::SlhDsa128s => 48,
            Self::LmsSha256M32H10 => 48,
        }
    }

    /// Check whether this scheme is permitted in the given protocol domain (`DIP-PQ-1` §3.1 #2).
    pub const fn is_allowed_in_domain(self, domain: PqDomainTag) -> bool {
        match self {
            Self::MlDsa44 | Self::FnDsa512 => true,
            Self::SlhDsa128s => match domain {
                PqDomainTag::TxSigV1 | PqDomainTag::SporkV1 => true,
                PqDomainTag::BlockSigV1 => false,
            },
            Self::LmsSha256M32H10 => matches!(domain, PqDomainTag::SporkV1),
        }
    }

    /// Enforce exact public-key byte length, rejecting any short or trailing byte (`DIP-PQ-1` §3.1 #1).
    pub const fn validate_pubkey_len(self, pubkey_bytes: &[u8]) -> Result<(), PqError> {
        let expected = self.pubkey_len();
        let actual = pubkey_bytes.len();
        if actual != expected {
            return Err(PqError::InvalidPublicKeyLength {
                scheme: self,
                expected,
                actual,
            });
        }
        Ok(())
    }

    /// Enforce exact signature byte length, rejecting any short or trailing byte (`DIP-PQ-1` §3.1 #1).
    pub const fn validate_signature_len(self, sig_bytes: &[u8]) -> Result<(), PqError> {
        let expected = self.signature_len();
        let actual = sig_bytes.len();
        if actual != expected {
            return Err(PqError::InvalidSignatureLength {
                scheme: self,
                expected,
                actual,
            });
        }
        Ok(())
    }

    /// Validate both exact public-key length and scheme-specific canonical encoding (`DIP-PQ-1` §3).
    pub fn validate_pubkey_encoding(self, pubkey_bytes: &[u8]) -> Result<(), PqError> {
        self.validate_pubkey_len(pubkey_bytes)?;
        match self {
            Self::MlDsa44 | Self::SlhDsa128s => Ok(()),
            Self::FnDsa512 => validate_fndsa512_pubkey(pubkey_bytes),
            Self::LmsSha256M32H10 => validate_lms_pubkey(pubkey_bytes),
        }
    }

    /// Validate both exact signature length and scheme-specific canonical encoding (`DIP-PQ-1` §3).
    pub fn validate_signature_encoding(self, sig_bytes: &[u8]) -> Result<(), PqError> {
        self.validate_signature_len(sig_bytes)?;
        match self {
            Self::MlDsa44 => validate_mldsa44_signature(sig_bytes),
            Self::FnDsa512 => validate_fndsa512_signature(sig_bytes),
            Self::SlhDsa128s => Ok(()),
            Self::LmsSha256M32H10 => validate_lms_signature(sig_bytes),
        }
    }
}

/// Canonical domain-separation tags for post-quantum signatures (`DIP-PQ-1` §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqDomainTag {
    /// Transaction input witness signature domain (`"Divi-PQ-TxSig-v1"`, 16 bytes).
    TxSigV1,
    /// Proof-of-Stake block header signature domain (`"Divi-PQ-BlockSig-v1"`, 19 bytes).
    BlockSigV1,
    /// Network Spork governance signature domain (`"Divi-PQ-Spork-v1"`, 16 bytes).
    SporkV1,
}

impl PqDomainTag {
    /// Return the exact ASCII byte slice of the domain tag (without NUL terminator).
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::TxSigV1 => b"Divi-PQ-TxSig-v1",
            Self::BlockSigV1 => b"Divi-PQ-BlockSig-v1",
            Self::SporkV1 => b"Divi-PQ-Spork-v1",
        }
    }

    /// Return the canonical string representation of the domain tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TxSigV1 => "Divi-PQ-TxSig-v1",
            Self::BlockSigV1 => "Divi-PQ-BlockSig-v1",
            Self::SporkV1 => "Divi-PQ-Spork-v1",
        }
    }
}

/// Compute the 32-byte scheme-bound public-key digest `SHA-256(scheme_id || pubkey_bytes)`
/// used inside `prehash_msg` (`DIP-PQ-1` §4.2).
pub fn pq_key_hash_256(scheme_id: PqSchemeId, pubkey_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([scheme_id.as_u8()]);
    hasher.update(pubkey_bytes);
    hasher.finalize().into()
}

/// Compute the 32-byte domain-prefixed post-quantum address/script key commitment
/// `SHA-256("Divi-PQ-PubKey-v1" || u8(scheme_id) || pubkey_bytes)` (`DIP-PQ-1` §5.5).
pub fn pq_address_key_hash_256(scheme_id: PqSchemeId, pubkey_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PQ_PUBKEY_COMMITMENT_DOMAIN);
    hasher.update([scheme_id.as_u8()]);
    hasher.update(pubkey_bytes);
    hasher.finalize().into()
}

/// Serialize the exact domain-separated signing preimage defined in `DIP-PQ-1` §4.2:
/// `u8(|domain_tag|) || domain_tag || network_magic (4 B) || scheme_id (1 B) || pk_hash256 (32 B) || ctx_payload`.
pub fn serialize_pq_signing_preimage(
    domain_tag: PqDomainTag,
    network_magic: [u8; 4],
    scheme_id: PqSchemeId,
    pk_hash256: &[u8; 32],
    ctx_payload: &[u8],
) -> Vec<u8> {
    let tag_bytes = domain_tag.as_bytes();
    let mut preimage = Vec::with_capacity(1 + tag_bytes.len() + 4 + 1 + 32 + ctx_payload.len());
    preimage.push(tag_bytes.len() as u8);
    preimage.extend_from_slice(tag_bytes);
    preimage.extend_from_slice(&network_magic);
    preimage.push(scheme_id.as_u8());
    preimage.extend_from_slice(pk_hash256);
    preimage.extend_from_slice(ctx_payload);
    preimage
}

/// Compute the 64-byte (`SHA-512`) domain-separated signing prehash `prehash_msg` from a
/// precomputed 32-byte `pk_hash256` and context payload (`DIP-PQ-1` §4.2, §6 Vector 4).
pub fn compute_pq_signing_prehash_with_pk_hash(
    domain_tag: PqDomainTag,
    network_magic: [u8; 4],
    scheme_id: PqSchemeId,
    pk_hash256: &[u8; 32],
    ctx_payload: &[u8],
) -> [u8; 64] {
    let tag_bytes = domain_tag.as_bytes();
    let mut hasher = Sha512::new();
    hasher.update([tag_bytes.len() as u8]);
    hasher.update(tag_bytes);
    hasher.update(network_magic);
    hasher.update([scheme_id.as_u8()]);
    hasher.update(pk_hash256);
    hasher.update(ctx_payload);
    hasher.finalize().into()
}

/// Compute the 64-byte (`SHA-512`) domain-separated signing prehash `prehash_msg` binding
/// `domain_tag`, `network_magic`, `scheme_id`, `pubkey_bytes` (via `pq_key_hash_256`), and
/// `ctx_payload` (`DIP-PQ-1` §4.2).
pub fn compute_pq_signing_prehash(
    domain_tag: PqDomainTag,
    network_magic: [u8; 4],
    scheme_id: PqSchemeId,
    pubkey_bytes: &[u8],
    ctx_payload: &[u8],
) -> [u8; 64] {
    let pk_hash256 = pq_key_hash_256(scheme_id, pubkey_bytes);
    compute_pq_signing_prehash_with_pk_hash(
        domain_tag,
        network_magic,
        scheme_id,
        &pk_hash256,
        ctx_payload,
    )
}

// ============================================================================
// Pure-Integer Canonical Encoding Validators (`DIP-PQ-1` §3.2 - §3.5)
// ============================================================================

/// Validate `ML-DSA-44` (`0x01`) signature canonical encoding (`DIP-PQ-1` §3.2):
/// - Unpack 18-bit `z` coefficients ($4 \times 256$) and require $\|z\|_\infty < \gamma_1 - \beta = 130,994$.
/// - Validate `HintBitUnpack` on `sig[2336..2420]` ($\omega = 80, k = 4$).
fn validate_mldsa44_signature(sig: &[u8]) -> Result<(), PqError> {
    const GAMMA1: i32 = 131_072; // 2^17
    const BETA: i32 = 78;
    const Z_BOUND: i32 = GAMMA1 - BETA; // 130,994
    const OMEGA: usize = 80;
    const K: usize = 4;

    // z_packed occupies bytes 32..2336 (2,304 bytes = 1,024 * 18 bits = 256 * 9-byte chunks of 4 coeffs)
    let z_packed = &sig[32..2336];
    for chunk in z_packed.as_chunks::<9>().0 {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk[1]);
        let b2 = u32::from(chunk[2]);
        let b3 = u32::from(chunk[3]);
        let b4 = u32::from(chunk[4]);
        let b5 = u32::from(chunk[5]);
        let b6 = u32::from(chunk[6]);
        let b7 = u32::from(chunk[7]);
        let b8 = u32::from(chunk[8]);

        let u0 = (b0 | (b1 << 8) | (b2 << 16)) & 0x3_ffff;
        let u1 = ((b2 >> 2) | (b3 << 6) | (b4 << 14)) & 0x3_ffff;
        let u2 = ((b4 >> 4) | (b5 << 4) | (b6 << 12)) & 0x3_ffff;
        let u3 = ((b6 >> 6) | (b7 << 2) | (b8 << 10)) & 0x3_ffff;

        for u in [u0, u1, u2, u3] {
            let z = GAMMA1 - (u as i32);
            if z <= -Z_BOUND || z >= Z_BOUND {
                return Err(PqError::NonCanonicalSignature {
                    scheme: PqSchemeId::MlDsa44,
                    reason: "ML-DSA-44 z coefficient norm >= gamma1 - beta",
                });
            }
        }
    }

    // Hint vector h_packed occupies bytes 2336..2420 (84 bytes = 80 index bytes + 4 offset bytes)
    let h_bytes = &sig[2336..2420];
    let mut prev_offset = 0usize;
    for i in 0..K {
        let cur_offset = usize::from(h_bytes[OMEGA + i]);
        if cur_offset < prev_offset || cur_offset > OMEGA {
            return Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::MlDsa44,
                reason: "ML-DSA-44 hint offsets non-monotonic or exceed omega=80",
            });
        }
        for j in (prev_offset + 1)..cur_offset {
            if h_bytes[j - 1] >= h_bytes[j] {
                return Err(PqError::NonCanonicalSignature {
                    scheme: PqSchemeId::MlDsa44,
                    reason: "ML-DSA-44 hint indices not strictly ascending",
                });
            }
        }
        prev_offset = cur_offset;
    }

    for &pad_byte in &h_bytes[prev_offset..OMEGA] {
        if pad_byte != 0 {
            return Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::MlDsa44,
                reason: "ML-DSA-44 non-zero byte in unused hint padding tail",
            });
        }
    }

    Ok(())
}

/// Validate `FN-DSA-512` (`0x02`) public key canonical encoding (`DIP-PQ-1` §3.3 #1):
/// - Byte `0` MUST be `0x09`.
/// - Bytes `1..897` unpack into 512 14-bit unsigned integers $h_i < 12289$.
fn validate_fndsa512_pubkey(pk: &[u8]) -> Result<(), PqError> {
    const Q: u32 = 12289;
    if pk[0] != 0x09 {
        return Err(PqError::NonCanonicalPublicKey {
            scheme: PqSchemeId::FnDsa512,
            reason: "FN-DSA-512 public key header byte must equal 0x09",
        });
    }
    // 896 bytes = 128 groups of 7 bytes (each 7 bytes = 56 bits = 4 * 14-bit coefficients)
    let body = &pk[1..897];
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    for &byte in body {
        acc = (acc << 8) | u32::from(byte);
        acc_bits += 8;
        while acc_bits >= 14 {
            acc_bits -= 14;
            let coeff = (acc >> acc_bits) & 0x3fff;
            if coeff >= Q {
                return Err(PqError::NonCanonicalPublicKey {
                    scheme: PqSchemeId::FnDsa512,
                    reason: "FN-DSA-512 public key coefficient >= q (12289)",
                });
            }
        }
    }
    Ok(())
}

/// Validate `FN-DSA-512` (`0x02`) signature canonical encoding (`DIP-PQ-1` §3.3 #2):
/// - Byte `0` MUST be `0x39` (fixed padded compressed format with $\log_2 n = 9$).
/// - Decompress 512 Golomb-Rice coefficients from `sig[41..666]`, rejecting `-0` and $|s_{2,i}| > 2047$,
///   and require all remaining padding bits up to bit 5,000 to be `0`.
fn validate_fndsa512_signature(sig: &[u8]) -> Result<(), PqError> {
    if sig[0] != 0x39 {
        return Err(PqError::NonCanonicalSignature {
            scheme: PqSchemeId::FnDsa512,
            reason: "FN-DSA-512 signature header byte must equal 0x39",
        });
    }
    let payload = &sig[41..666]; // 625 bytes = 5,000 bits
    let total_bits = payload.len() * 8;
    let mut bit_pos = 0usize;

    let read_bit = |pos: usize| -> Result<u8, PqError> {
        if pos >= total_bits {
            return Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::FnDsa512,
                reason: "FN-DSA-512 compressed s2 bitstream truncated before 512 coefficients",
            });
        }
        let byte = payload[pos >> 3];
        let shift = 7 - (pos & 7);
        Ok((byte >> shift) & 1)
    };

    for _ in 0..512 {
        let sign_bit = read_bit(bit_pos)?;
        bit_pos += 1;

        let mut u_low: u32 = 0;
        for _ in 0..7 {
            u_low = (u_low << 1) | u32::from(read_bit(bit_pos)?);
            bit_pos += 1;
        }

        let mut u_high: u32 = 0;
        loop {
            let b = read_bit(bit_pos)?;
            bit_pos += 1;
            if b == 1 {
                break;
            }
            u_high += 1;
            if u_high > 16 {
                return Err(PqError::NonCanonicalSignature {
                    scheme: PqSchemeId::FnDsa512,
                    reason: "FN-DSA-512 coefficient magnitude exceeds 2047",
                });
            }
        }

        let mag = u_low + (u_high << 7);
        if mag == 0 && sign_bit == 1 {
            return Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::FnDsa512,
                reason: "FN-DSA-512 non-canonical -0 coefficient encoding",
            });
        }
        if mag > 2047 {
            return Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::FnDsa512,
                reason: "FN-DSA-512 coefficient magnitude exceeds 2047",
            });
        }
    }

    while bit_pos < total_bits {
        if read_bit(bit_pos)? != 0 {
            return Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::FnDsa512,
                reason: "FN-DSA-512 non-zero bit in trailing signature padding",
            });
        }
        bit_pos += 1;
    }

    Ok(())
}

/// Validate `LMS-SHA256-M32-H10` (`0x04`) 60-byte public key header & reserved zero tail (`DIP-PQ-1` §3.5 #1).
fn validate_lms_pubkey(pk: &[u8]) -> Result<(), PqError> {
    let lms_type = u32::from_be_bytes([pk[0], pk[1], pk[2], pk[3]]);
    let lmots_type = u32::from_be_bytes([pk[4], pk[5], pk[6], pk[7]]);
    let reserved = u32::from_be_bytes([pk[56], pk[57], pk[58], pk[59]]);
    if lms_type != LMS_TYPE_SHA256_M32_H10 {
        return Err(PqError::NonCanonicalPublicKey {
            scheme: PqSchemeId::LmsSha256M32H10,
            reason: "LMS public key typecode must equal LMS_SHA256_M32_H10 (0x00000006)",
        });
    }
    if lmots_type != LMOTS_TYPE_SHA256_N32_W4 {
        return Err(PqError::NonCanonicalPublicKey {
            scheme: PqSchemeId::LmsSha256M32H10,
            reason: "LMS public key OTS typecode must equal LMOTS_SHA256_N32_W4 (0x00000003)",
        });
    }
    if reserved != 0 {
        return Err(PqError::NonCanonicalPublicKey {
            scheme: PqSchemeId::LmsSha256M32H10,
            reason: "LMS public key reserved bytes [56..60] must equal 0x00000000",
        });
    }
    Ok(())
}

/// Validate `LMS-SHA256-M32-H10` (`0x04`) 2,512-byte signature header, leaf bound, and reserved zero tail (`DIP-PQ-1` §3.5 #2).
fn validate_lms_signature(sig: &[u8]) -> Result<(), PqError> {
    let q = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
    let lmots_type = u32::from_be_bytes([sig[4], sig[5], sig[6], sig[7]]);
    let lms_type = u32::from_be_bytes([sig[2184], sig[2185], sig[2186], sig[2187]]);
    let reserved = u32::from_be_bytes([sig[2508], sig[2509], sig[2510], sig[2511]]);
    if q >= LMS_NUM_LEAVES {
        return Err(PqError::NonCanonicalSignature {
            scheme: PqSchemeId::LmsSha256M32H10,
            reason: "LMS signature leaf index q >= 1024",
        });
    }
    if lmots_type != LMOTS_TYPE_SHA256_N32_W4 {
        return Err(PqError::NonCanonicalSignature {
            scheme: PqSchemeId::LmsSha256M32H10,
            reason: "LMS signature OTS typecode must equal LMOTS_SHA256_N32_W4 (0x00000003)",
        });
    }
    if lms_type != LMS_TYPE_SHA256_M32_H10 {
        return Err(PqError::NonCanonicalSignature {
            scheme: PqSchemeId::LmsSha256M32H10,
            reason: "LMS signature tree typecode must equal LMS_SHA256_M32_H10 (0x00000006)",
        });
    }
    if reserved != 0 {
        return Err(PqError::NonCanonicalSignature {
            scheme: PqSchemeId::LmsSha256M32H10,
            reason: "LMS signature reserved bytes [2508..2512] must equal 0x00000000",
        });
    }
    Ok(())
}

// ============================================================================
// Pure-Rust HMAC-SHA512 & FIPS 202 SHAKE256 (`DIP-PQ-1` §5.1 - §5.4)
// ============================================================================

/// Compute `HMAC-SHA512(key, data)` (RFC 2104) with zeroization of intermediate key pads.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK_LEN: usize = 128;
    let mut k_block = Zeroizing::new([0u8; BLOCK_LEN]);
    if key.len() > BLOCK_LEN {
        let hashed = Sha512::digest(key);
        k_block[..64].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new([0x36u8; BLOCK_LEN]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK_LEN]);
    for i in 0..BLOCK_LEN {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner_hasher = Sha512::new();
    inner_hasher.update(&ipad[..]);
    inner_hasher.update(data);
    let inner_digest = Zeroizing::new(<[u8; 64]>::from(inner_hasher.finalize()));

    let mut outer_hasher = Sha512::new();
    outer_hasher.update(&opad[..]);
    outer_hasher.update(&inner_digest[..]);
    outer_hasher.finalize().into()
}

/// Keccak-f[1600] round constants (FIPS 202 §3.2.5).
const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Keccak-f[1600] rotation offsets $\rho$ (FIPS 202 Table 2).
const KECCAK_RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Keccak-f[1600] lane permutation $\pi$ indices.
const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &KECCAK_RC {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in (0..25).step_by(5) {
                state[x + y] ^= d;
            }
        }

        // Rho & Pi
        let mut current = state[1];
        for i in 0..24 {
            let pi_idx = KECCAK_PI[i];
            let tmp = state[pi_idx];
            state[pi_idx] = current.rotate_left(KECCAK_RHO[i]);
            current = tmp;
        }

        // Chi
        for y in (0..25).step_by(5) {
            let row = [
                state[y],
                state[y + 1],
                state[y + 2],
                state[y + 3],
                state[y + 4],
            ];
            for x in 0..5 {
                state[y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        // Iota
        state[0] ^= rc;
    }
}

/// FIPS 202 `SHAKE256` extendable-output function (XOF) with rate $r = 136$ bytes ($1088$ bits)
/// and zeroization on drop (`DIP-PQ-1` §5.4).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Shake256Xof {
    state: [u64; 25],
    buf: [u8; 136],
    pos: usize,
    squeezing: bool,
}

impl Default for Shake256Xof {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256Xof {
    const RATE: usize = 136;

    /// Create a new `SHAKE256` absorber.
    pub const fn new() -> Self {
        Self {
            state: [0u64; 25],
            buf: [0u8; 136],
            pos: 0,
            squeezing: false,
        }
    }

    /// Absorb input bytes into the `SHAKE256` sponge.
    pub fn update(&mut self, mut input: &[u8]) {
        assert!(
            !self.squeezing,
            "cannot update SHAKE256 after squeezing has begun"
        );
        while !input.is_empty() {
            let take = (Self::RATE - self.pos).min(input.len());
            self.buf[self.pos..self.pos + take].copy_from_slice(&input[..take]);
            self.pos += take;
            input = &input[take..];
            if self.pos == Self::RATE {
                self.xor_buf_and_permute();
                self.pos = 0;
            }
        }
    }

    /// Squeeze an arbitrary number of output bytes from the `SHAKE256` sponge.
    pub fn squeeze(&mut self, mut out: &mut [u8]) {
        if !self.squeezing {
            // SHAKE256 domain separation suffix 0x1f + pad10*1 final bit 0x80
            self.buf[self.pos] ^= 0x1f;
            self.buf[Self::RATE - 1] ^= 0x80;
            self.xor_buf_and_permute();
            self.extract_rate_to_buf();
            self.pos = 0;
            self.squeezing = true;
        }

        while !out.is_empty() {
            if self.pos == Self::RATE {
                keccak_f1600(&mut self.state);
                self.extract_rate_to_buf();
                self.pos = 0;
            }
            let take = (Self::RATE - self.pos).min(out.len());
            out[..take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            out = &mut out[take..];
        }
    }

    fn xor_buf_and_permute(&mut self) {
        for (i, chunk) in self.buf.as_chunks::<8>().0.iter().enumerate() {
            let lane = u64::from_le_bytes(*chunk);
            self.state[i] ^= lane;
        }
        self.buf.zeroize();
        keccak_f1600(&mut self.state);
    }

    fn extract_rate_to_buf(&mut self) {
        for (i, chunk) in self.buf.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            *chunk = self.state[i].to_le_bytes();
        }
    }
}

/// Expand `SHAKE256(input)` into a fixed-size byte array `[u8; N]`.
pub fn shake256<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut xof = Shake256Xof::new();
    xof.update(input);
    let mut out = [0u8; N];
    xof.squeeze(&mut out);
    out
}

// ============================================================================
// Deterministic BIP39 Post-Quantum HD Key Derivation (`DIP-PQ-1` §5)
// ============================================================================

/// Post-Quantum HD master or intermediate node $(k, c) \in \{0,1\}^{256} \times \{0,1\}^{256}$
/// (`DIP-PQ-1` §5.1–§5.2).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PqMasterKey {
    k: [u8; 32],
    c: [u8; 32],
}

impl std::fmt::Debug for PqMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqMasterKey")
            .field("k", &"<redacted>")
            .field("c", &"<redacted>")
            .finish()
    }
}

impl PqMasterKey {
    /// Construct a `PqMasterKey` from raw $(k, c)$ 32-byte halves.
    pub const fn from_parts(k: [u8; 32], c: [u8; 32]) -> Self {
        Self { k, c }
    }

    /// Return the 32-byte secret key material half $k$ (`I[0..32]`).
    pub const fn key_bytes(&self) -> &[u8; 32] {
        &self.k
    }

    /// Return the 32-byte chain code half $c$ (`I[32..64]`).
    pub const fn chain_code_bytes(&self) -> &[u8; 32] {
        &self.c
    }

    /// Derive a hardened child node using `CKDpriv_PQ` (`DIP-PQ-1` §5.2).
    ///
    /// Returns `Err(PqError::NonHardenedPqDerivationForbidden)` if `child_index < 0x8000_0000`.
    pub fn derive_child_raw(&self, child_index: u32) -> Result<Self, PqError> {
        if (child_index & HARDENED_INDEX_BIT) == 0 {
            return Err(PqError::NonHardenedPqDerivationForbidden(child_index));
        }
        let mut data = Zeroizing::new([0u8; 37]);
        data[0] = 0x00;
        data[1..33].copy_from_slice(&self.k);
        data[33..37].copy_from_slice(&child_index.to_be_bytes());

        let i_out = Zeroizing::new(hmac_sha512(&self.c, &data[..]));
        let mut k_child = [0u8; 32];
        let mut c_child = [0u8; 32];
        k_child.copy_from_slice(&i_out[0..32]);
        c_child.copy_from_slice(&i_out[32..64]);
        Ok(Self {
            k: k_child,
            c: c_child,
        })
    }

    /// Derive a hardened child node at `index | 0x8000_0000`.
    ///
    /// Rejects `index >= 0x8000_0000` if callers use `derive_child_hardened` with an out-of-range
    /// unmasked index; accepts unmasked indices in `0..0x8000_0000`.
    pub fn derive_child_hardened(&self, unhardened_index: u32) -> Result<Self, PqError> {
        self.derive_child_raw(unhardened_index | HARDENED_INDEX_BIT)
    }
}

/// Derived post-quantum leaf node at `m / 44' / coin_type' / account' / scheme' / index'`
/// together with its `SHAKE256` algorithm keygen seed stream (`DIP-PQ-1` §5.3–§5.4).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PqLeafKey {
    #[zeroize(skip)]
    scheme_id: PqSchemeId,
    k_leaf: [u8; 32],
    c_leaf: [u8; 32],
    keygen_stream_64: [u8; 64],
}

impl std::fmt::Debug for PqLeafKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqLeafKey")
            .field("scheme_id", &self.scheme_id)
            .field("k_leaf", &"<redacted>")
            .field("c_leaf", &"<redacted>")
            .finish()
    }
}

impl PqLeafKey {
    /// Return the post-quantum scheme identifier for this leaf.
    pub const fn scheme_id(&self) -> PqSchemeId {
        self.scheme_id
    }

    /// Return the 32-byte leaf secret key material $k_{\text{leaf}}$.
    pub const fn k_leaf(&self) -> &[u8; 32] {
        &self.k_leaf
    }

    /// Return the 32-byte leaf chain code $c_{\text{leaf}}$.
    pub const fn c_leaf(&self) -> &[u8; 32] {
        &self.c_leaf
    }

    /// Return the first 64 bytes of `KeygenStream = SHAKE256("Divi-PQ-Keygen-v1" || scheme_id || k_leaf || c_leaf)`.
    pub const fn keygen_stream_64(&self) -> &[u8; 64] {
        &self.keygen_stream_64
    }

    /// Return the exact algorithm keygen seed slice required by `self.scheme_id` (`DIP-PQ-1` §5.4):
    /// - `ML-DSA-44` (`0x01`): `32` bytes ($\xi$)
    /// - `FN-DSA-512` (`0x02`): `64` bytes (`SHAKE256` PRNG seed)
    /// - `SLH-DSA-128s` (`0x03`): `48` bytes (`SK.seed || SK.prf || PK.seed`)
    /// - `LMS-SHA256-M32-H10` (`0x04`): `48` bytes (`I[16 B] || SEED[32 B]`)
    pub fn algorithm_seed(&self) -> &[u8] {
        &self.keygen_stream_64[..self.scheme_id.keygen_seed_len()]
    }

    /// Open a fresh `Shake256Xof` positioned at byte 0 of `KeygenStream` for algorithms needing
    /// arbitrary-length deterministic randomness (`DIP-PQ-1` §5.4).
    pub fn keygen_xof(&self) -> Shake256Xof {
        let mut xof = Shake256Xof::new();
        xof.update(PQ_KEYGEN_STREAM_DOMAIN);
        xof.update(&[self.scheme_id.as_u8()]);
        xof.update(&self.k_leaf);
        xof.update(&self.c_leaf);
        xof
    }
}

/// Derive the root post-quantum master node $(k_{\text{master}}, c_{\text{master}})$ from a
/// 64-byte (`512`-bit) BIP39 seed via `HMAC-SHA512("Divi PQ seed v1", bip39_seed)` (`DIP-PQ-1` §5.1).
pub fn derive_pq_master(bip39_seed: &[u8]) -> Result<PqMasterKey, PqError> {
    if bip39_seed.len() != 64 {
        return Err(PqError::InvalidBip39SeedLength(bip39_seed.len()));
    }
    let i_master = Zeroizing::new(hmac_sha512(PQ_HD_MASTER_KEY_DOMAIN, bip39_seed));
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&i_master[0..32]);
    c.copy_from_slice(&i_master[32..64]);
    Ok(PqMasterKey::from_parts(k, c))
}

/// Derive the post-quantum leaf key and `SHAKE256` keygen stream at the canonical 5-level
/// hardened path `m / 44' / coin_type' / account' / scheme' / index'` (`DIP-PQ-1` §5.3–§5.4).
pub fn derive_pq_leaf(
    bip39_seed: &[u8],
    coin_type: u32,
    account: u32,
    scheme_id: PqSchemeId,
    index: u32,
) -> Result<PqLeafKey, PqError> {
    let master = derive_pq_master(bip39_seed)?;
    derive_pq_leaf_from_master(&master, coin_type, account, scheme_id, index)
}

/// Derive the post-quantum leaf key from an already derived `PqMasterKey` at
/// `m / 44' / coin_type' / account' / scheme' / index'`.
pub fn derive_pq_leaf_from_master(
    master: &PqMasterKey,
    coin_type: u32,
    account: u32,
    scheme_id: PqSchemeId,
    index: u32,
) -> Result<PqLeafKey, PqError> {
    let path = [
        PQ_BIP44_PURPOSE | HARDENED_INDEX_BIT,
        coin_type | HARDENED_INDEX_BIT,
        account | HARDENED_INDEX_BIT,
        u32::from(scheme_id.as_u8()) | HARDENED_INDEX_BIT,
        index | HARDENED_INDEX_BIT,
    ];
    let mut node = master.clone();
    for raw_idx in path {
        node = node.derive_child_raw(raw_idx)?;
    }

    let mut xof = Shake256Xof::new();
    xof.update(PQ_KEYGEN_STREAM_DOMAIN);
    xof.update(&[scheme_id.as_u8()]);
    xof.update(&node.k);
    xof.update(&node.c);
    let mut keygen_stream_64 = [0u8; 64];
    xof.squeeze(&mut keygen_stream_64);

    Ok(PqLeafKey {
        scheme_id,
        k_leaf: node.k,
        c_leaf: node.c,
        keygen_stream_64,
    })
}

// ============================================================================
// Pure-SHA256 `LMS-SHA256-M32-H10` / `LMOTS-SHA256-N32-W4` (`0x04`, `DIP-PQ-1` §2.1 #4, §3.5)
// ============================================================================

const D_PBLC: [u8; 2] = [0x80, 0x80];
const D_MESG: [u8; 2] = [0x81, 0x81];
const D_LEAF: [u8; 2] = [0x82, 0x82];
const D_INTR: [u8; 2] = [0x83, 0x83];

/// Extract the $i$-th 4-bit big-endian nybble ($w = 4$) from `bytes` (RFC 8554 §3.1.3 `coef`).
#[inline]
const fn lmots_w4_coef(bytes: &[u8], i: usize) -> u8 {
    let byte = bytes[i >> 1];
    if (i & 1) == 0 {
        (byte >> 4) & 0x0f
    } else {
        byte & 0x0f
    }
}

/// Compute the 34-byte extended message `Q || u16be(Cksm(Q) << 4)` for `LMOTS_SHA256_N32_W4`
/// (RFC 8554 §4.4).
fn lmots_w4_hash_and_checksum(
    tree_id: &[u8; 16],
    q: u32,
    randomizer_c: &[u8; 32],
    message: &[u8],
) -> [u8; 34] {
    let mut hasher = Sha256::new();
    hasher.update(tree_id);
    hasher.update(q.to_be_bytes());
    hasher.update(D_MESG);
    hasher.update(randomizer_c);
    hasher.update(message);
    let q_hash: [u8; 32] = hasher.finalize().into();

    let mut sum: u16 = 0;
    for i in 0..64 {
        sum += 15 - u16::from(lmots_w4_coef(&q_hash, i));
    }
    let cksm_shifted = sum << 4;

    let mut q_ext = [0u8; 34];
    q_ext[0..32].copy_from_slice(&q_hash);
    q_ext[32..34].copy_from_slice(&cksm_shifted.to_be_bytes());
    q_ext
}

/// Deterministically derive the $i$-th LMOTS secret chain seed $x_q[i]$ from `(I, SEED, q, i)`
/// per NIST SP 800-208 / RFC 8554 Appendix A.
fn lmots_derive_secret_chain_seed(
    tree_id: &[u8; 16],
    master_seed: &[u8; 32],
    q: u32,
    i: u16,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tree_id);
    hasher.update(q.to_be_bytes());
    hasher.update(i.to_be_bytes());
    hasher.update([0xff]);
    hasher.update(master_seed);
    hasher.finalize().into()
}

/// Advance an LMOTS $w = 4$ hash chain from step `j_start` to `j_end` (exclusive).
fn lmots_advance_chain(
    tree_id: &[u8; 16],
    q: u32,
    i: u16,
    start_val: [u8; 32],
    j_start: u8,
    j_end: u8,
) -> [u8; 32] {
    let mut tmp = start_val;
    for j in j_start..j_end {
        let mut hasher = Sha256::new();
        hasher.update(tree_id);
        hasher.update(q.to_be_bytes());
        hasher.update(i.to_be_bytes());
        hasher.update([j]);
        hasher.update(tmp);
        tmp = hasher.finalize().into();
    }
    tmp
}

/// Compute the 32-byte LMOTS public key $K_q$ for leaf $q \in [0, 1023]$ from `(I, SEED)`.
fn lmots_compute_pubkey(tree_id: &[u8; 16], master_seed: &[u8; 32], q: u32) -> [u8; 32] {
    let mut pub_hasher = Sha256::new();
    pub_hasher.update(tree_id);
    pub_hasher.update(q.to_be_bytes());
    pub_hasher.update(D_PBLC);
    for i in 0..(LMOTS_W4_CHAINS as u16) {
        let x_i = Zeroizing::new(lmots_derive_secret_chain_seed(tree_id, master_seed, q, i));
        let z_i = lmots_advance_chain(tree_id, q, i, *x_i, 0, 15);
        pub_hasher.update(z_i);
    }
    pub_hasher.finalize().into()
}

/// Canonical 60-byte `LMS-SHA256-M32-H10` public key (`DIP-PQ-1` §2.1 #4, §3.5).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LmsPublicKey {
    bytes: [u8; 60],
}

impl std::fmt::Debug for LmsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LmsPublicKey({})", hex::encode(self.bytes))
    }
}

impl LmsPublicKey {
    /// Parse and canonically validate a 60-byte `LMS-SHA256-M32-H10` public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> {
        PqSchemeId::LmsSha256M32H10.validate_pubkey_encoding(bytes)?;
        let mut arr = [0u8; 60];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Return the canonical 60-byte encoding:
    /// `u32be(0x00000006) || u32be(0x00000003) || I[16] || T[1][32] || u32be(0)`.
    pub const fn as_bytes(&self) -> &[u8; 60] {
        &self.bytes
    }

    /// Return the 16-byte LMS tree identifier `I`.
    pub fn tree_id(&self) -> [u8; 16] {
        let mut id = [0u8; 16];
        id.copy_from_slice(&self.bytes[8..24]);
        id
    }

    /// Return the 32-byte Merkle root `T[1]`.
    pub fn root(&self) -> [u8; 32] {
        let mut root = [0u8; 32];
        root.copy_from_slice(&self.bytes[24..56]);
        root
    }
}

/// Stateful `LMS-SHA256-M32-H10` + `LMOTS-SHA256-N32-W4` private key for Spork governance
/// signing (`DIP-PQ-1` §2.1 #4, §3.5, §5.4).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LmsPrivateKey {
    tree_id: [u8; 16],
    master_seed: [u8; 32],
    next_leaf_q: u32,
    /// 1-indexed complete binary Merkle tree (`nodes[1..2048]`), cached on keygen.
    nodes: Vec<[u8; 32]>,
    #[zeroize(skip)]
    public_key: [u8; 60],
}

impl std::fmt::Debug for LmsPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LmsPrivateKey")
            .field("tree_id", &hex::encode(self.tree_id))
            .field("next_leaf_q", &self.next_leaf_q)
            .field("master_seed", &"<redacted>")
            .finish()
    }
}

impl LmsPrivateKey {
    /// Deterministically generate an `LMS-SHA256-M32-H10` keypair from a 16-byte tree identifier
    /// `I` and 32-byte `SEED` (`DIP-PQ-1` §5.4).
    pub fn from_seed(tree_id: [u8; 16], master_seed: [u8; 32]) -> Self {
        let num_leaves = LMS_NUM_LEAVES as usize; // 1024
        let mut nodes = vec![[0u8; 32]; 2 * num_leaves]; // 2048 entries (1..2047 used)

        for q in 0..LMS_NUM_LEAVES {
            let k_q = lmots_compute_pubkey(&tree_id, &master_seed, q);
            let r = LMS_NUM_LEAVES + q;
            let mut leaf_hasher = Sha256::new();
            leaf_hasher.update(tree_id);
            leaf_hasher.update(r.to_be_bytes());
            leaf_hasher.update(D_LEAF);
            leaf_hasher.update(k_q);
            nodes[r as usize] = leaf_hasher.finalize().into();
        }

        for r in (1..LMS_NUM_LEAVES).rev() {
            let idx = r as usize;
            let mut intr_hasher = Sha256::new();
            intr_hasher.update(tree_id);
            intr_hasher.update(r.to_be_bytes());
            intr_hasher.update(D_INTR);
            intr_hasher.update(nodes[2 * idx]);
            intr_hasher.update(nodes[2 * idx + 1]);
            nodes[idx] = intr_hasher.finalize().into();
        }

        let mut public_key = [0u8; 60];
        public_key[0..4].copy_from_slice(&LMS_TYPE_SHA256_M32_H10.to_be_bytes());
        public_key[4..8].copy_from_slice(&LMOTS_TYPE_SHA256_N32_W4.to_be_bytes());
        public_key[8..24].copy_from_slice(&tree_id);
        public_key[24..56].copy_from_slice(&nodes[1]);
        // bytes 56..60 remain 0x00000000 per DIP-PQ-1 §2.1 #4

        Self {
            tree_id,
            master_seed,
            next_leaf_q: 0,
            nodes,
            public_key,
        }
    }

    /// Deterministically derive an `LMS-SHA256-M32-H10` keypair from a `PqLeafKey` (`DIP-PQ-1` §5.4).
    pub fn from_pq_leaf(leaf: &PqLeafKey) -> Result<Self, PqError> {
        if leaf.scheme_id() != PqSchemeId::LmsSha256M32H10 {
            return Err(PqError::SchemeForbiddenInDomain {
                scheme: leaf.scheme_id(),
                domain: PqDomainTag::SporkV1,
            });
        }
        let stream = leaf.keygen_stream_64();
        let mut tree_id = [0u8; 16];
        let mut master_seed = [0u8; 32];
        tree_id.copy_from_slice(&stream[0..16]);
        master_seed.copy_from_slice(&stream[16..48]);
        Ok(Self::from_seed(tree_id, master_seed))
    }

    /// Return the 60-byte `LmsPublicKey`.
    pub const fn public_key(&self) -> LmsPublicKey {
        LmsPublicKey {
            bytes: self.public_key,
        }
    }

    /// Return the canonical 60-byte public key slice.
    pub const fn public_key_bytes(&self) -> &[u8; 60] {
        &self.public_key
    }

    /// Return the next unused one-time signature leaf index $q \in [0, 1024]$.
    pub const fn next_leaf_index(&self) -> u32 {
        self.next_leaf_q
    }

    /// Return the number of remaining one-time signatures ($1024 - q$).
    pub const fn remaining_signatures(&self) -> u32 {
        LMS_NUM_LEAVES.saturating_sub(self.next_leaf_q)
    }

    /// Sign a 64-byte `prehash_msg` using the next available one-time leaf $q$, advancing the
    /// internal leaf counter by 1 (`DIP-PQ-1` §2.1 #4, §3.5).
    pub fn sign_prehash(&mut self, prehash_msg: &[u8; 64]) -> Result<[u8; 2512], PqError> {
        let q = self.next_leaf_q;
        if q >= LMS_NUM_LEAVES {
            return Err(PqError::LmsKeyExhausted(q));
        }
        self.next_leaf_q = q + 1;

        // Deterministic per-leaf, per-message 32-byte randomizer C (SP 800-208 / RFC 8554 Appendix A)
        let mut c_hasher = Sha256::new();
        c_hasher.update(self.tree_id);
        c_hasher.update(q.to_be_bytes());
        c_hasher.update([0xff, 0xfe, 0xff]);
        c_hasher.update(self.master_seed);
        c_hasher.update(prehash_msg);
        let randomizer_c: [u8; 32] = c_hasher.finalize().into();

        let q_ext = lmots_w4_hash_and_checksum(&self.tree_id, q, &randomizer_c, prehash_msg);

        let mut sig = [0u8; 2512];
        sig[0..4].copy_from_slice(&q.to_be_bytes());
        sig[4..8].copy_from_slice(&LMOTS_TYPE_SHA256_N32_W4.to_be_bytes());
        sig[8..40].copy_from_slice(&randomizer_c);

        for i in 0..LMOTS_W4_CHAINS {
            let a_i = lmots_w4_coef(&q_ext, i);
            let x_i = Zeroizing::new(lmots_derive_secret_chain_seed(
                &self.tree_id,
                &self.master_seed,
                q,
                i as u16,
            ));
            let y_i = lmots_advance_chain(&self.tree_id, q, i as u16, *x_i, 0, a_i);
            let offset = 40 + i * 32;
            sig[offset..offset + 32].copy_from_slice(&y_i);
        }

        sig[2184..2188].copy_from_slice(&LMS_TYPE_SHA256_M32_H10.to_be_bytes());

        let mut node_num = (LMS_NUM_LEAVES + q) as usize;
        for level in 0..LMS_TREE_HEIGHT {
            let sibling = self.nodes[node_num ^ 1];
            let offset = 2188 + level * 32;
            sig[offset..offset + 32].copy_from_slice(&sibling);
            node_num >>= 1;
        }
        // bytes 2508..2512 remain 0x00000000 per DIP-PQ-1 §2.1 #4

        Ok(sig)
    }

    /// Sign a Spork governance payload in the `"Divi-PQ-Spork-v1"` domain (`DIP-PQ-1` §3.1 #2, §4).
    pub fn sign_spork(
        &mut self,
        network_magic: [u8; 4],
        spork_payload: &[u8],
    ) -> Result<[u8; 2512], PqError> {
        let prehash = compute_pq_signing_prehash(
            PqDomainTag::SporkV1,
            network_magic,
            PqSchemeId::LmsSha256M32H10,
            &self.public_key,
            spork_payload,
        );
        self.sign_prehash(&prehash)
    }
}

/// Verify an `LMS-SHA256-M32-H10` (`0x04`) 2,512-byte signature against a 60-byte public key and
/// 64-byte `prehash_msg` in pure integer arithmetic (`DIP-PQ-1` §3.5).
pub fn verify_lms_prehash(
    pubkey_bytes: &[u8],
    prehash_msg: &[u8; 64],
    sig_bytes: &[u8],
) -> Result<(), PqError> {
    PqSchemeId::LmsSha256M32H10.validate_pubkey_encoding(pubkey_bytes)?;
    PqSchemeId::LmsSha256M32H10.validate_signature_encoding(sig_bytes)?;

    let mut tree_id = [0u8; 16];
    tree_id.copy_from_slice(&pubkey_bytes[8..24]);
    let expected_root = &pubkey_bytes[24..56];

    let q = u32::from_be_bytes([sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3]]);
    let mut randomizer_c = [0u8; 32];
    randomizer_c.copy_from_slice(&sig_bytes[8..40]);

    let q_ext = lmots_w4_hash_and_checksum(&tree_id, q, &randomizer_c, prehash_msg);

    let mut kc_hasher = Sha256::new();
    kc_hasher.update(tree_id);
    kc_hasher.update(q.to_be_bytes());
    kc_hasher.update(D_PBLC);

    for i in 0..LMOTS_W4_CHAINS {
        let a_i = lmots_w4_coef(&q_ext, i);
        let offset = 40 + i * 32;
        let mut y_i = [0u8; 32];
        y_i.copy_from_slice(&sig_bytes[offset..offset + 32]);
        let z_i = lmots_advance_chain(&tree_id, q, i as u16, y_i, a_i, 15);
        kc_hasher.update(z_i);
    }
    let kc: [u8; 32] = kc_hasher.finalize().into();

    let mut node_num = LMS_NUM_LEAVES + q;
    let mut tmp_hasher = Sha256::new();
    tmp_hasher.update(tree_id);
    tmp_hasher.update(node_num.to_be_bytes());
    tmp_hasher.update(D_LEAF);
    tmp_hasher.update(kc);
    let mut tmp: [u8; 32] = tmp_hasher.finalize().into();

    for level in 0..LMS_TREE_HEIGHT {
        let offset = 2188 + level * 32;
        let sibling = &sig_bytes[offset..offset + 32];
        let parent_num = node_num >> 1;
        let mut intr_hasher = Sha256::new();
        intr_hasher.update(tree_id);
        intr_hasher.update(parent_num.to_be_bytes());
        intr_hasher.update(D_INTR);
        if (node_num & 1) == 1 {
            intr_hasher.update(sibling);
            intr_hasher.update(tmp);
        } else {
            intr_hasher.update(tmp);
            intr_hasher.update(sibling);
        }
        tmp = intr_hasher.finalize().into();
        node_num = parent_num;
    }

    // Constant-time root comparison
    let mut diff = 0u8;
    for (a, b) in tmp.iter().zip(expected_root.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(PqError::VerificationFailed);
    }
    Ok(())
}

/// Verify an `LMS-SHA256-M32-H10` (`0x04`) signature with full domain-tag role enforcement
/// (`"Divi-PQ-Spork-v1"` only) and `SHA-512` prehash binding (`DIP-PQ-1` §3.1 #2, §3.5, §4.2).
pub fn verify_lms_with_domain(
    domain_tag: PqDomainTag,
    network_magic: [u8; 4],
    pubkey_bytes: &[u8],
    ctx_payload: &[u8],
    sig_bytes: &[u8],
) -> Result<(), PqError> {
    if !PqSchemeId::LmsSha256M32H10.is_allowed_in_domain(domain_tag) {
        return Err(PqError::SchemeForbiddenInDomain {
            scheme: PqSchemeId::LmsSha256M32H10,
            domain: domain_tag,
        });
    }
    let prehash = compute_pq_signing_prehash(
        domain_tag,
        network_magic,
        PqSchemeId::LmsSha256M32H10,
        pubkey_bytes,
        ctx_payload,
    );
    verify_lms_prehash(pubkey_bytes, &prehash, sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIP39_SEED_HEX: &str = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";
    const DIVI_MAINNET_MAGIC: [u8; 4] = [0xdf, 0xf0, 0xc8, 0xf3];

    #[test]
    fn test_scheme_id_lengths_and_strict_bounds() {
        let cases = [
            (PqSchemeId::MlDsa44, 0x01u8, 1312usize, 2420usize, 32usize),
            (PqSchemeId::FnDsa512, 0x02u8, 897usize, 666usize, 64usize),
            (PqSchemeId::SlhDsa128s, 0x03u8, 32usize, 7856usize, 48usize),
            (
                PqSchemeId::LmsSha256M32H10,
                0x04u8,
                60usize,
                2512usize,
                48usize,
            ),
        ];

        for (scheme, id_byte, pk_len, sig_len, seed_len) in cases {
            assert_eq!(PqSchemeId::from_u8(id_byte).unwrap(), scheme);
            assert_eq!(scheme.as_u8(), id_byte);
            assert_eq!(scheme.pubkey_len(), pk_len);
            assert_eq!(scheme.signature_len(), sig_len);
            assert_eq!(scheme.keygen_seed_len(), seed_len);

            let exact_pk = vec![0u8; pk_len];
            let short_pk = vec![0u8; pk_len - 1];
            let trailing_pk = vec![0u8; pk_len + 1];
            assert!(scheme.validate_pubkey_len(&exact_pk).is_ok());
            assert!(matches!(
                scheme.validate_pubkey_len(&short_pk),
                Err(PqError::InvalidPublicKeyLength { .. })
            ));
            assert!(matches!(
                scheme.validate_pubkey_len(&trailing_pk),
                Err(PqError::InvalidPublicKeyLength { .. })
            ));

            let exact_sig = vec![0u8; sig_len];
            let short_sig = vec![0u8; sig_len - 1];
            let trailing_sig = vec![0u8; sig_len + 1];
            assert!(scheme.validate_signature_len(&exact_sig).is_ok());
            assert!(matches!(
                scheme.validate_signature_len(&short_sig),
                Err(PqError::InvalidSignatureLength { .. })
            ));
            assert!(matches!(
                scheme.validate_signature_len(&trailing_sig),
                Err(PqError::InvalidSignatureLength { .. })
            ));
        }

        assert!(matches!(
            PqSchemeId::from_u8(0x00),
            Err(PqError::UnknownSchemeId(0x00))
        ));
        assert!(matches!(
            PqSchemeId::from_u8(0x05),
            Err(PqError::UnknownSchemeId(0x05))
        ));
    }

    #[test]
    fn test_domain_role_restrictions() {
        // LMS (0x04) is strictly Spork-only
        assert!(!PqSchemeId::LmsSha256M32H10.is_allowed_in_domain(PqDomainTag::TxSigV1));
        assert!(!PqSchemeId::LmsSha256M32H10.is_allowed_in_domain(PqDomainTag::BlockSigV1));
        assert!(PqSchemeId::LmsSha256M32H10.is_allowed_in_domain(PqDomainTag::SporkV1));

        // SLH-DSA-128s (0x03) is allowed in TxSigV1 and SporkV1, forbidden in BlockSigV1
        assert!(PqSchemeId::SlhDsa128s.is_allowed_in_domain(PqDomainTag::TxSigV1));
        assert!(!PqSchemeId::SlhDsa128s.is_allowed_in_domain(PqDomainTag::BlockSigV1));
        assert!(PqSchemeId::SlhDsa128s.is_allowed_in_domain(PqDomainTag::SporkV1));

        // ML-DSA-44 (0x01) and FN-DSA-512 (0x02) are allowed in all three domains
        for scheme in [PqSchemeId::MlDsa44, PqSchemeId::FnDsa512] {
            for domain in [
                PqDomainTag::TxSigV1,
                PqDomainTag::BlockSigV1,
                PqDomainTag::SporkV1,
            ] {
                assert!(scheme.is_allowed_in_domain(domain));
            }
        }
    }

    #[test]
    fn test_dip_pq_1_vector_1_master_derivation() {
        let seed = hex::decode(BIP39_SEED_HEX).unwrap();
        let master = derive_pq_master(&seed).unwrap();
        assert_eq!(
            hex::encode(master.key_bytes()),
            "47cd0fc16effbec1c630f59b2f3aae6924a13d6058d7fab33395829e21fe7a37"
        );
        assert_eq!(
            hex::encode(master.chain_code_bytes()),
            "80b033237fd0594e16a0b3afaa608abbdf86f03cff7bf4c2ca248fbf95f9a77a"
        );

        // Non-hardened derivation must be rejected
        assert_eq!(
            master.derive_child_raw(44),
            Err(PqError::NonHardenedPqDerivationForbidden(44))
        );
    }

    #[test]
    fn test_dip_pq_1_vector_2_mainnet_leaf_keys_and_shake256_streams() {
        let seed = hex::decode(BIP39_SEED_HEX).unwrap();

        // 1. ML-DSA-44 (0x01) at m/44'/301'/0'/1'/0'
        let mldsa = derive_pq_leaf(&seed, 301, 0, PqSchemeId::MlDsa44, 0).unwrap();
        assert_eq!(
            hex::encode(mldsa.k_leaf()),
            "eb2660d9798dde6a7dfd99da787fdcc470b3a19270fa04a708986c282904b8a8"
        );
        assert_eq!(
            hex::encode(mldsa.c_leaf()),
            "abce2677b924f115d859de017055629b07357fcd1d6772e4dc7dd6bddf3e1e9e"
        );
        assert_eq!(
            hex::encode(mldsa.algorithm_seed()),
            "5453ad6e329dfd732cffdd3f9adaa808682f8c6597100bb7912b03116c26f38a"
        );
        assert_eq!(
            hex::encode(mldsa.keygen_stream_64()),
            "5453ad6e329dfd732cffdd3f9adaa808682f8c6597100bb7912b03116c26f38a20a2a8f18860a1ae440eae38b21af9a36ae65680f430fe5b4684a4e68a9ef9a1"
        );

        // 2. FN-DSA-512 (0x02) at m/44'/301'/0'/2'/0'
        let fndsa = derive_pq_leaf(&seed, 301, 0, PqSchemeId::FnDsa512, 0).unwrap();
        assert_eq!(
            hex::encode(fndsa.k_leaf()),
            "59d356d84afc5b11ec409c8485c8c4cc63f85e7035a25d36fcf19cbec285f8f2"
        );
        assert_eq!(
            hex::encode(fndsa.c_leaf()),
            "951f0c084b45664df19555b13fbbc391f0af07fb27d403db2a2b65de85d3dd97"
        );
        assert_eq!(
            hex::encode(fndsa.algorithm_seed()),
            "61644f3db169e2dd7a7750f58c032b525fdf6d8afbc0a3243ac01606ace6d5ae2d2865aba8d5f1cf73d359389b5a28a92e279794c3bcad50405d743b7a83ee67"
        );

        // 3. SLH-DSA-128s (0x03) at m/44'/301'/0'/3'/0'
        let slhdsa = derive_pq_leaf(&seed, 301, 0, PqSchemeId::SlhDsa128s, 0).unwrap();
        assert_eq!(
            hex::encode(slhdsa.k_leaf()),
            "6ef5a0ac7cf91103ade416d58fa8c26887bd0c489757aeb3cff9e40acd8af5af"
        );
        assert_eq!(
            hex::encode(slhdsa.c_leaf()),
            "18c4307336d7e9cad796e51355c38692fca7a4cc7bd8d230fd2b032f28ed34b3"
        );
        assert_eq!(
            hex::encode(slhdsa.algorithm_seed()),
            "1c9107b4294ea04d121061281585ea22b78f0dddc6c4dc588448f2eee2287c70f11b6af4d424344c4522942c3123320a"
        );

        // 4. LMS-SHA256-M32-H10 (0x04) at m/44'/301'/0'/4'/0'
        let lms = derive_pq_leaf(&seed, 301, 0, PqSchemeId::LmsSha256M32H10, 0).unwrap();
        assert_eq!(
            hex::encode(lms.k_leaf()),
            "40454acf8491c7e178e9417993e1b48fc1b9cbe703569c9515cf783d4e57721c"
        );
        assert_eq!(
            hex::encode(lms.c_leaf()),
            "0c175a7c66ac8f3d6bd514f4eef0daa0f70b59aab0ce8ee599c8f67b7923b3c9"
        );
        assert_eq!(
            hex::encode(&lms.algorithm_seed()[0..16]),
            "bf2fd2b1a59e04f9b9da4243bb4b78d6"
        );
        assert_eq!(
            hex::encode(&lms.algorithm_seed()[16..48]),
            "4d4fc0255e0916ff0fc4e1ebcf26d65b45cc4c47717afc7cecb68799b5c3d981"
        );
    }

    #[test]
    fn test_dip_pq_1_vector_3_cross_network_coin_type_isolation() {
        let seed = hex::decode(BIP39_SEED_HEX).unwrap();

        // 1. Testnet / Regtest (coin_type = 1')
        let testnet_leaf = derive_pq_leaf(&seed, 1, 0, PqSchemeId::MlDsa44, 0).unwrap();
        assert_eq!(
            hex::encode(testnet_leaf.k_leaf()),
            "279ea392e7ca0264cfcc9e78568e9cfaaa8e402ae0b42151bbd1a659105ea819"
        );
        assert_eq!(
            hex::encode(testnet_leaf.c_leaf()),
            "92a323683917ed6642ed3398404b179e69e239d28287b81617d17406db588b71"
        );
        assert_eq!(
            hex::encode(testnet_leaf.algorithm_seed()),
            "866b3335fad05491e55b4c8b95dc87a249d01beb8d6d6bd190eb6e2836d1def2"
        );

        // 2. PrivateDivi Mainnet (coin_type = 801')
        let privatedivi_leaf = derive_pq_leaf(&seed, 801, 0, PqSchemeId::MlDsa44, 0).unwrap();
        assert_eq!(
            hex::encode(privatedivi_leaf.k_leaf()),
            "1d61da22286da2de751a8e2bc126a3bc79606a194e68ac23507814d95888760d"
        );
        assert_eq!(
            hex::encode(privatedivi_leaf.c_leaf()),
            "69966d43af748806b5dfe98a925dbf06562d9a8dec2f44be446493ce4994eb7a"
        );
        assert_eq!(
            hex::encode(privatedivi_leaf.algorithm_seed()),
            "a1eba3460aeb33c7c46ebf4957cab8761fd8e5f305141d1e8617657655ad9206"
        );
    }

    #[test]
    fn test_dip_pq_1_vector_4_domain_separated_prehash_construction() {
        let pk_hash256 = [0xaau8; 32];

        // 1. Transaction Witness Domain ("Divi-PQ-TxSig-v1", ML-DSA-44)
        let tx_payload = [0xbbu8; 32];
        let tx_preimage = serialize_pq_signing_preimage(
            PqDomainTag::TxSigV1,
            DIVI_MAINNET_MAGIC,
            PqSchemeId::MlDsa44,
            &pk_hash256,
            &tx_payload,
        );
        assert_eq!(
            hex::encode(&tx_preimage),
            "10446976692d50512d54785369672d7631dff0c8f301aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        let tx_prehash = compute_pq_signing_prehash_with_pk_hash(
            PqDomainTag::TxSigV1,
            DIVI_MAINNET_MAGIC,
            PqSchemeId::MlDsa44,
            &pk_hash256,
            &tx_payload,
        );
        assert_eq!(
            hex::encode(tx_prehash),
            "35a53a5300c86e71a0ca916cbbb5000fa2f06dca1b6bd6938a0945c92d00c9dcef28976fbd763b535da1683a0ca12e0cf65592666751bb2eb4bf97bf1201132f"
        );

        // 2. Proof-of-Stake Block Header Domain ("Divi-PQ-BlockSig-v1", FN-DSA-512)
        let mut block_payload = [0u8; 64];
        block_payload[0..32].copy_from_slice(&[0xccu8; 32]);
        block_payload[32..64].copy_from_slice(&[0xddu8; 32]);
        let block_preimage = serialize_pq_signing_preimage(
            PqDomainTag::BlockSigV1,
            DIVI_MAINNET_MAGIC,
            PqSchemeId::FnDsa512,
            &pk_hash256,
            &block_payload,
        );
        assert_eq!(
            hex::encode(&block_preimage),
            "13446976692d50512d426c6f636b5369672d7631dff0c8f302aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        let block_prehash = compute_pq_signing_prehash_with_pk_hash(
            PqDomainTag::BlockSigV1,
            DIVI_MAINNET_MAGIC,
            PqSchemeId::FnDsa512,
            &pk_hash256,
            &block_payload,
        );
        assert_eq!(
            hex::encode(block_prehash),
            "c87bc21802e2ceaba45c471cf9d4911b808223789d053b77e096378e6d2b85483af8e1b04a9022e10f336ab571205852de60ac31f965af19c52312380ec8ab9c"
        );

        // 3. Network Spork Governance Domain ("Divi-PQ-Spork-v1", LMS-SHA256-M32-H10)
        let mut spork_payload = Vec::with_capacity(20);
        spork_payload.extend_from_slice(&10012i32.to_le_bytes());
        spork_payload.extend_from_slice(&4070908800i64.to_le_bytes());
        spork_payload.extend_from_slice(&1700000000i64.to_le_bytes());
        let spork_preimage = serialize_pq_signing_preimage(
            PqDomainTag::SporkV1,
            DIVI_MAINNET_MAGIC,
            PqSchemeId::LmsSha256M32H10,
            &pk_hash256,
            &spork_payload,
        );
        assert_eq!(
            hex::encode(&spork_preimage),
            "10446976692d50512d53706f726b2d7631dff0c8f304aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c2700008023a5f20000000000f1536500000000"
        );
        let spork_prehash = compute_pq_signing_prehash_with_pk_hash(
            PqDomainTag::SporkV1,
            DIVI_MAINNET_MAGIC,
            PqSchemeId::LmsSha256M32H10,
            &pk_hash256,
            &spork_payload,
        );
        assert_eq!(
            hex::encode(spork_prehash),
            "fc80064a5487fc3a9f9152ff6002fca7b6f14f159f4b67be058b3df72e78982018b4bd345b0b77bc89e42db3a9817c6f75cd28b6caf877f963fc2bc7d0bd2783"
        );
    }

    #[test]
    fn test_pq_key_hash_256_and_address_commitment_isolation() {
        let dummy_pk = [0x42u8; 60];
        let bind_hash = pq_key_hash_256(PqSchemeId::LmsSha256M32H10, &dummy_pk);
        let addr_hash = pq_address_key_hash_256(PqSchemeId::LmsSha256M32H10, &dummy_pk);
        assert_ne!(bind_hash, addr_hash);

        // Changing scheme_id changes both hashes even for identical raw bytes
        let bind_hash_other = pq_key_hash_256(PqSchemeId::SlhDsa128s, &dummy_pk);
        assert_ne!(bind_hash, bind_hash_other);
    }

    #[test]
    fn test_lms_sha256_m32_h10_keygen_sign_verify_and_tamper_rejection() {
        let seed = hex::decode(BIP39_SEED_HEX).unwrap();
        let leaf = derive_pq_leaf(&seed, 301, 0, PqSchemeId::LmsSha256M32H10, 0).unwrap();
        let mut lms_sk = LmsPrivateKey::from_pq_leaf(&leaf).unwrap();
        let lms_pk = lms_sk.public_key();
        let pk_bytes = *lms_pk.as_bytes();

        assert_eq!(pk_bytes.len(), 60);
        assert_eq!(lms_sk.next_leaf_index(), 0);
        assert_eq!(lms_sk.remaining_signatures(), 1024);

        let mut spork_payload = Vec::with_capacity(20);
        spork_payload.extend_from_slice(&10012i32.to_le_bytes());
        spork_payload.extend_from_slice(&4070908800i64.to_le_bytes());
        spork_payload.extend_from_slice(&1700000000i64.to_le_bytes());

        // Sign leaf 0 and leaf 1
        let sig0 = lms_sk
            .sign_spork(DIVI_MAINNET_MAGIC, &spork_payload)
            .unwrap();
        assert_eq!(sig0.len(), 2512);
        assert_eq!(lms_sk.next_leaf_index(), 1);
        assert_eq!(u32::from_be_bytes([sig0[0], sig0[1], sig0[2], sig0[3]]), 0);

        let sig1 = lms_sk
            .sign_spork(DIVI_MAINNET_MAGIC, &spork_payload)
            .unwrap();
        assert_eq!(lms_sk.next_leaf_index(), 2);
        assert_eq!(u32::from_be_bytes([sig1[0], sig1[1], sig1[2], sig1[3]]), 1);
        assert_ne!(sig0, sig1);

        // Both valid Spork signatures verify cleanly
        assert!(verify_lms_with_domain(
            PqDomainTag::SporkV1,
            DIVI_MAINNET_MAGIC,
            &pk_bytes,
            &spork_payload,
            &sig0,
        )
        .is_ok());
        assert!(verify_lms_with_domain(
            PqDomainTag::SporkV1,
            DIVI_MAINNET_MAGIC,
            &pk_bytes,
            &spork_payload,
            &sig1,
        )
        .is_ok());

        // Role restriction: LMS signature presented in TxSigV1 or BlockSigV1 must be rejected
        assert_eq!(
            verify_lms_with_domain(
                PqDomainTag::TxSigV1,
                DIVI_MAINNET_MAGIC,
                &pk_bytes,
                &spork_payload,
                &sig0,
            ),
            Err(PqError::SchemeForbiddenInDomain {
                scheme: PqSchemeId::LmsSha256M32H10,
                domain: PqDomainTag::TxSigV1,
            })
        );
        assert_eq!(
            verify_lms_with_domain(
                PqDomainTag::BlockSigV1,
                DIVI_MAINNET_MAGIC,
                &pk_bytes,
                &spork_payload,
                &sig0,
            ),
            Err(PqError::SchemeForbiddenInDomain {
                scheme: PqSchemeId::LmsSha256M32H10,
                domain: PqDomainTag::BlockSigV1,
            })
        );

        // Wrong network magic must fail verification
        assert_eq!(
            verify_lms_with_domain(
                PqDomainTag::SporkV1,
                [0xf4, 0xc4, 0xd7, 0xaa], // Testnet magic
                &pk_bytes,
                &spork_payload,
                &sig0,
            ),
            Err(PqError::VerificationFailed)
        );

        // Tampered payload byte must fail verification
        let mut tampered_payload = spork_payload.clone();
        tampered_payload[0] ^= 0x01;
        assert_eq!(
            verify_lms_with_domain(
                PqDomainTag::SporkV1,
                DIVI_MAINNET_MAGIC,
                &pk_bytes,
                &tampered_payload,
                &sig0,
            ),
            Err(PqError::VerificationFailed)
        );

        // Tampered LMOTS chain byte or Merkle path byte must fail verification
        let mut tampered_sig = sig0;
        tampered_sig[100] ^= 0x80;
        assert_eq!(
            verify_lms_with_domain(
                PqDomainTag::SporkV1,
                DIVI_MAINNET_MAGIC,
                &pk_bytes,
                &spork_payload,
                &tampered_sig,
            ),
            Err(PqError::VerificationFailed)
        );

        // Non-zero reserved byte in pk[56..60] or sig[2508..2512] must fail canonical check
        let mut bad_pk = pk_bytes;
        bad_pk[59] = 1;
        assert!(matches!(
            verify_lms_with_domain(
                PqDomainTag::SporkV1,
                DIVI_MAINNET_MAGIC,
                &bad_pk,
                &spork_payload,
                &sig0,
            ),
            Err(PqError::NonCanonicalPublicKey { .. })
        ));

        let mut bad_reserved_sig = sig0;
        bad_reserved_sig[2511] = 1;
        assert!(matches!(
            verify_lms_with_domain(
                PqDomainTag::SporkV1,
                DIVI_MAINNET_MAGIC,
                &pk_bytes,
                &spork_payload,
                &bad_reserved_sig,
            ),
            Err(PqError::NonCanonicalSignature { .. })
        ));

        // Trailing 0x00 byte on signature or public key must fail immediately
        let mut trailing_sig = sig0.to_vec();
        trailing_sig.push(0x00);
        assert!(matches!(
            verify_lms_with_domain(
                PqDomainTag::SporkV1,
                DIVI_MAINNET_MAGIC,
                &pk_bytes,
                &spork_payload,
                &trailing_sig,
            ),
            Err(PqError::InvalidSignatureLength {
                scheme: PqSchemeId::LmsSha256M32H10,
                expected: 2512,
                actual: 2513,
            })
        ));
    }

    #[test]
    fn test_mldsa44_and_fndsa512_canonical_encoding_rejections() {
        // ML-DSA-44: all-zero signature has u_0 = 0 -> z_0 = gamma1 = 131072 >= 130994 -> rejected!
        let bad_mldsa_sig = vec![0u8; 2420];
        assert!(matches!(
            PqSchemeId::MlDsa44.validate_signature_encoding(&bad_mldsa_sig),
            Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::MlDsa44,
                ..
            })
        ));

        // FN-DSA-512: wrong pk header byte and out-of-range 14-bit coefficient (>= 12289)
        let mut bad_fndsa_pk = vec![0u8; 897];
        assert!(matches!(
            PqSchemeId::FnDsa512.validate_pubkey_encoding(&bad_fndsa_pk),
            Err(PqError::NonCanonicalPublicKey {
                scheme: PqSchemeId::FnDsa512,
                ..
            })
        ));
        bad_fndsa_pk[0] = 0x09;
        assert!(PqSchemeId::FnDsa512
            .validate_pubkey_encoding(&bad_fndsa_pk)
            .is_ok());
        // Set first 14-bit coeff to 16383 (>= 12289)
        bad_fndsa_pk[1] = 0xff;
        bad_fndsa_pk[2] = 0xfc;
        assert!(matches!(
            PqSchemeId::FnDsa512.validate_pubkey_encoding(&bad_fndsa_pk),
            Err(PqError::NonCanonicalPublicKey {
                scheme: PqSchemeId::FnDsa512,
                ..
            })
        ));

        // FN-DSA-512: reject -0 encoding in Golomb-Rice stream (sign=1, u_low=0, terminating 1 -> 0x80 | 0x00, next bit 1 -> 0x80, 0x80)
        let mut bad_fndsa_sig = vec![0u8; 666];
        bad_fndsa_sig[0] = 0x39;
        bad_fndsa_sig[41] = 0x80; // sign_bit = 1, u_low = 0
        bad_fndsa_sig[42] = 0x80; // terminating 1 bit -> u_high = 0 -> mag = 0 with sign = 1 (-0)
        assert!(matches!(
            PqSchemeId::FnDsa512.validate_signature_encoding(&bad_fndsa_sig),
            Err(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::FnDsa512,
                ..
            })
        ));
    }
}
