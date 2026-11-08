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

//! `DIP-PQ-4`: Post-Quantum Proof-of-Stake Block Signing (`vchBlockSig` Envelope,
//! Coinstake Vault Binding & Cutoff Policy).
//!
//! In classical Divi Proof-of-Stake blocks (`divi/src/BlockSigning.cpp` and
//! `crates/divi-storage/src/chain.rs`), `vchBlockSig` (`Block::block_sig`) holds a
//! `65`-byte compact recoverable `secp256k1` signature (`RecoverCompact`) from which
//! validators recover the 33-byte public key and compare `Hash160(pubkey)` against the
//! coinstake output (`coinstake.vout[1].scriptPubKey`).
//!
//! Because post-quantum lattice signature schemes (`FN-DSA-512` and `ML-DSA-44`) do not
//! support public-key recovery from `(message, signature)` alone, `DIP-PQ-4` defines:
//! - A non-malleable `PqBlockSigEnvelope` wire layout inside `vchBlockSig` with zero
//!   internal length prefixes (`0x50 || 0x01 || scheme_id || pubkey_bytes || sig_bytes`,
//!   `1,566` bytes for `FN-DSA-512` and `3,735` bytes for `ML-DSA-44`),
//! - Domain-separated PoS block payload hashing (`"DIVI-POS-BLOCK-V1"`) and 64-byte
//!   `SHA-512` signing prehash construction under `PqDomainTag::BlockSigV1`
//!   (`"Divi-PQ-BlockSig-v1"`),
//! - Strict coinstake script binding to `PQ_STAKING_VAULT` (`74` bytes, requiring the
//!   hot `vault_hash_256` key and explicitly forbidding the cold `owner_hash_256` key)
//!   and `P2PQPKH` (`34` bytes, `addr_key_hash_256`), and
//! - Phased cutoff enforcement via [`PosBlockAuthPolicy`].

use divi_crypto::pq::{
    compute_pq_signing_prehash, pq_address_key_hash_256, pq_key_hash_256, PqDomainTag, PqError,
    PqSchemeId,
};
use divi_primitives::Script;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Leading magic byte (`'P'` = `0x50`) identifying a `DIP-PQ-4` post-quantum `vchBlockSig` envelope.
///
/// Disjoint from classical `65`-byte compact `secp256k1` recovery headers (`0x1b..=0x22`)
/// and ASN.1 DER `P2PK` block signatures (`0x30`).
pub const PQ_BLOCK_SIG_MAGIC: u8 = 0x50;

/// Envelope format version `1` (`0x01`) for `DIP-PQ-4` post-quantum `vchBlockSig`.
pub const PQ_BLOCK_SIG_VERSION_V1: u8 = 0x01;

/// Fixed 3-byte header length (`magic || version || scheme_id`) of a [`PqBlockSigEnvelope`].
pub const PQ_BLOCK_SIG_HEADER_LEN: usize = 3;

/// Exact total `vchBlockSig` byte length for an `FN-DSA-512` (`0x02`) PoS block signature envelope
/// (`3 B` header + `897 B` public key + `666 B` padded signature = `1,566` bytes).
pub const FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN: usize = PQ_BLOCK_SIG_HEADER_LEN + 897 + 666;

/// Exact total `vchBlockSig` byte length for an `ML-DSA-44` (`0x01`) PoS block signature envelope
/// (`3 B` header + `1,312 B` public key + `2,420 B` signature = `3,735` bytes).
pub const ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN: usize = PQ_BLOCK_SIG_HEADER_LEN + 1312 + 2420;

/// Exact byte length of a classical `secp256k1` compact recoverable `vchBlockSig` (`65` bytes).
pub const CLASSICAL_COMPACT_BLOCK_SIG_LEN: usize = 65;

/// ASCII domain prefix (`17` bytes) used to construct the 32-byte PoS block payload digest (`DIP-PQ-4` §4.1).
pub const POS_BLOCK_PAYLOAD_DOMAIN: &[u8] = b"DIVI-POS-BLOCK-V1";

/// Exact byte length of the `DIP-PQ-4` §4.1 PoS block payload preimage (`17 + 32 + 32 + 4 = 85` bytes).
pub const POS_BLOCK_PAYLOAD_PREIMAGE_LEN: usize = 17 + 32 + 32 + 4;

/// Exact byte length of a canonical `DIP-PQ-3` `P2PQPKH` `scriptPubKey` (`OP_1 0x20 <32B>`).
const P2PQPKH_SCRIPT_LEN: usize = 34;

/// Exact byte length of a canonical `DIP-PQ-3` `PQ_STAKING_VAULT` `scriptPubKey` (`74` bytes).
const PQ_STAKING_VAULT_SCRIPT_LEN: usize = 74;

/// Exact byte length of a classical `Hash160` `STAKING_VAULT` `scriptPubKey` (`50` bytes).
const CLASSICAL_STAKING_VAULT_SCRIPT_LEN: usize = 50;

/// Exact byte length of a classical `P2PKH` `scriptPubKey` (`25` bytes).
const CLASSICAL_P2PKH_SCRIPT_LEN: usize = 25;

/// Errors returned during `DIP-PQ-4` `vchBlockSig` envelope parsing, staker key binding,
/// or cutoff policy enforcement.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PqBlockSigError {
    #[error("Proof-of-Stake block has an empty vchBlockSig")]
    EmptyBlockSignature,

    #[error(
        "invalid PQ block signature envelope magic: expected 0x{expected:02x}, got 0x{actual:02x}"
    )]
    InvalidEnvelopeMagic { expected: u8, actual: u8 },

    #[error("unsupported PQ block signature envelope version: 0x{0:02x} (expected 0x01)")]
    UnsupportedEnvelopeVersion(u8),

    #[error("invalid PQ block signature envelope byte length for {scheme:?}: expected {expected} bytes, got {actual}")]
    InvalidEnvelopeLength {
        scheme: Option<PqSchemeId>,
        expected: usize,
        actual: usize,
    },

    #[error("invalid classical secp256k1 block signature format (len={len}, first_byte=0x{first_byte:02x})")]
    InvalidClassicalSignatureFormat { len: usize, first_byte: u8 },

    #[error("post-quantum vchBlockSig is forbidden under PosBlockAuthPolicy::ClassicalOnly")]
    PostQuantumBlockSigForbiddenBeforeActivation,

    #[error("256-bit post-quantum coinstake output requires a post-quantum vchBlockSig envelope")]
    MissingPostQuantumBlockSigForPqOutput,

    #[error("classical secp256k1 vchBlockSig is forbidden at block_time {block_time} >= cutoff_block_time {cutoff_block_time}")]
    MissingPostQuantumBlockSigAfterCutoff {
        block_time: u32,
        cutoff_block_time: u32,
    },

    #[error("coinstake output script is not a valid 256-bit PQ staking script (expected 74B PQ_STAKING_VAULT or 34B P2PQPKH)")]
    UnsupportedCoinstakeScriptForPqBlockSig,

    #[error("coinstake output script is not a valid classical staking script (expected 50B STAKING_VAULT, 25B P2PKH, or P2PK)")]
    UnsupportedCoinstakeScriptForClassicalBlockSig,

    #[error("PQ_STAKING_VAULT cold owner key is strictly forbidden from signing PoS blocks; must sign with hot vault manager key")]
    ColdOwnerKeyForbiddenForBlockSigning {
        owner_hash_256: [u8; 32],
        vault_hash_256: [u8; 32],
    },

    #[error("PQ block signature staker key hash mismatch against coinstake output")]
    StakerKeyHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("post-quantum cryptographic validation error: {0}")]
    Crypto(#[from] PqError),
}

/// Parsed wire format classification of a Proof-of-Stake `vchBlockSig` (`DIP-PQ-4` §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSigFormat {
    /// Classical `secp256k1` block signature (`65`-byte compact recovery or `64..=73`-byte ASN.1 DER).
    ClassicalSecp256k1,
    /// `DIP-PQ-4` version 1 post-quantum block signature envelope (`1,566 B` `FN-DSA-512` or `3,735 B` `ML-DSA-44`).
    PostQuantumV1(PqBlockSigEnvelope),
}

/// Extracted 256-bit key commitment from a `DIP-PQ-3` post-quantum coinstake output (`coinstake.vout[1].scriptPubKey`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoinstakeStakerBinding {
    /// `74`-byte `PQ_STAKING_VAULT` output (`DIP-PQ-3` §3.2), binding the hot `vault_hash_256` manager key
    /// while keeping the cold `owner_hash_256` key unrevealed.
    PqStakingVault {
        owner_hash_256: [u8; 32],
        vault_hash_256: [u8; 32],
    },
    /// `34`-byte `P2PQPKH` single-key post-quantum output (`DIP-PQ-3` §3.1).
    P2PqPkh { addr_key_hash_256: [u8; 32] },
}

impl CoinstakeStakerBinding {
    /// Return the 32-byte `pq_address_key_hash_256` expected to authenticate `vchBlockSig`.
    pub const fn expected_staker_hash_256(&self) -> [u8; 32] {
        match self {
            Self::PqStakingVault { vault_hash_256, .. } => *vault_hash_256,
            Self::P2PqPkh { addr_key_hash_256 } => *addr_key_hash_256,
        }
    }
}

/// Canonical `DIP-PQ-4` post-quantum Proof-of-Stake block signature envelope (`vchBlockSig`).
///
/// Wire layout (`zero` internal `CompactSize` length prefixes):
/// `0x50 ('P') || 0x01 (v1) || u8(scheme_id) || pubkey_bytes[|pk|] || signature_bytes[|sig|]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqBlockSigEnvelope {
    /// Post-quantum signature scheme (`PqSchemeId::FnDsa512` `0x02` or `PqSchemeId::MlDsa44` `0x01`).
    pub scheme_id: PqSchemeId,
    /// Canonical public key bytes (`897 B` for `FN-DSA-512`, `1,312 B` for `ML-DSA-44`).
    pub pubkey_bytes: Vec<u8>,
    /// Canonical signature bytes (`666 B` for `FN-DSA-512`, `2,420 B` for `ML-DSA-44`).
    pub signature_bytes: Vec<u8>,
}

impl PqBlockSigEnvelope {
    /// Expected total serialized envelope byte length (`3 + |pk| + |sig|`) for a permitted `BlockSigV1` scheme.
    pub const fn expected_envelope_len(scheme_id: PqSchemeId) -> Result<usize, PqError> {
        if !scheme_id.is_allowed_in_domain(PqDomainTag::BlockSigV1) {
            return Err(PqError::SchemeForbiddenInDomain {
                scheme: scheme_id,
                domain: PqDomainTag::BlockSigV1,
            });
        }
        Ok(PQ_BLOCK_SIG_HEADER_LEN + scheme_id.pubkey_len() + scheme_id.signature_len())
    }

    /// Construct and canonically validate a [`PqBlockSigEnvelope`] (`DIP-PQ-4` §2.1–§2.4).
    pub fn new(
        scheme_id: PqSchemeId,
        pubkey_bytes: Vec<u8>,
        signature_bytes: Vec<u8>,
    ) -> Result<Self, PqBlockSigError> {
        if !scheme_id.is_allowed_in_domain(PqDomainTag::BlockSigV1) {
            return Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
                scheme: scheme_id,
                domain: PqDomainTag::BlockSigV1,
            }));
        }
        scheme_id.validate_pubkey_encoding(&pubkey_bytes)?;
        scheme_id.validate_signature_encoding(&signature_bytes)?;
        Ok(Self {
            scheme_id,
            pubkey_bytes,
            signature_bytes,
        })
    }

    /// Serialize the canonical fixed-length `vchBlockSig` byte vector (`1,566 B` for `FN-DSA-512`,
    /// `3,735 B` for `ML-DSA-44`).
    pub fn encode(&self) -> Vec<u8> {
        let total_len =
            PQ_BLOCK_SIG_HEADER_LEN + self.pubkey_bytes.len() + self.signature_bytes.len();
        let mut out = Vec::with_capacity(total_len);
        out.push(PQ_BLOCK_SIG_MAGIC);
        out.push(PQ_BLOCK_SIG_VERSION_V1);
        out.push(self.scheme_id.as_u8());
        out.extend_from_slice(&self.pubkey_bytes);
        out.extend_from_slice(&self.signature_bytes);
        out
    }

    /// Decode and canonically validate a `PqBlockSigEnvelope` from raw `vchBlockSig` bytes (`DIP-PQ-4` §2).
    pub fn decode(bytes: &[u8]) -> Result<Self, PqBlockSigError> {
        if bytes.is_empty() {
            return Err(PqBlockSigError::EmptyBlockSignature);
        }
        if bytes[0] != PQ_BLOCK_SIG_MAGIC {
            return Err(PqBlockSigError::InvalidEnvelopeMagic {
                expected: PQ_BLOCK_SIG_MAGIC,
                actual: bytes[0],
            });
        }
        if bytes.len() < PQ_BLOCK_SIG_HEADER_LEN {
            return Err(PqBlockSigError::InvalidEnvelopeLength {
                scheme: None,
                expected: PQ_BLOCK_SIG_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[1];
        if version != PQ_BLOCK_SIG_VERSION_V1 {
            return Err(PqBlockSigError::UnsupportedEnvelopeVersion(version));
        }

        let scheme_id = PqSchemeId::from_u8(bytes[2])?;
        let expected_len = Self::expected_envelope_len(scheme_id)?;
        if bytes.len() != expected_len {
            return Err(PqBlockSigError::InvalidEnvelopeLength {
                scheme: Some(scheme_id),
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        let pk_end = PQ_BLOCK_SIG_HEADER_LEN + scheme_id.pubkey_len();
        let pubkey_bytes = bytes[PQ_BLOCK_SIG_HEADER_LEN..pk_end].to_vec();
        let signature_bytes = bytes[pk_end..expected_len].to_vec();

        Self::new(scheme_id, pubkey_bytes, signature_bytes)
    }

    /// Compute the 32-byte `DIP-PQ-1` §5.5 address/script key commitment:
    /// `SHA-256("Divi-PQ-PubKey-v1" || u8(scheme_id) || pubkey_bytes)`.
    pub fn staker_key_hash_256(&self) -> [u8; 32] {
        pq_address_key_hash_256(self.scheme_id, &self.pubkey_bytes)
    }

    /// Compute the 32-byte `DIP-PQ-1` §4.2 prehash public-key commitment:
    /// `SHA-256(u8(scheme_id) || pubkey_bytes)`.
    pub fn signing_key_hash_256(&self) -> [u8; 32] {
        pq_key_hash_256(self.scheme_id, &self.pubkey_bytes)
    }

    /// Verify canonical encoding AND bind `self.staker_key_hash_256()` against `coinstake.vout[1].scriptPubKey`
    /// (`DIP-PQ-4` §3.2).
    ///
    /// Strictly forbids a `PQ_STAKING_VAULT`'s cold `owner_hash_256` from signing `vchBlockSig`.
    pub fn verify_structural_and_staker_binding(
        &self,
        coinstake_script_pubkey: &Script,
    ) -> Result<CoinstakeStakerBinding, PqBlockSigError> {
        if !self.scheme_id.is_allowed_in_domain(PqDomainTag::BlockSigV1) {
            return Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
                scheme: self.scheme_id,
                domain: PqDomainTag::BlockSigV1,
            }));
        }
        self.scheme_id
            .validate_pubkey_encoding(&self.pubkey_bytes)?;
        self.scheme_id
            .validate_signature_encoding(&self.signature_bytes)?;

        let actual_hash = self.staker_key_hash_256();
        let binding = parse_pq_coinstake_script(coinstake_script_pubkey)
            .ok_or(PqBlockSigError::UnsupportedCoinstakeScriptForPqBlockSig)?;

        match binding {
            CoinstakeStakerBinding::PqStakingVault {
                owner_hash_256,
                vault_hash_256,
            } => {
                // Check cold owner_hash_256 FIRST so that neither the cold owner key nor a
                // degenerate vault with owner_hash_256 == vault_hash_256 can ever sign blocks.
                if actual_hash == owner_hash_256 {
                    return Err(PqBlockSigError::ColdOwnerKeyForbiddenForBlockSigning {
                        owner_hash_256,
                        vault_hash_256,
                    });
                }
                if actual_hash != vault_hash_256 {
                    return Err(PqBlockSigError::StakerKeyHashMismatch {
                        expected: vault_hash_256,
                        actual: actual_hash,
                    });
                }
                Ok(binding)
            }
            CoinstakeStakerBinding::P2PqPkh { addr_key_hash_256 } => {
                if actual_hash != addr_key_hash_256 {
                    return Err(PqBlockSigError::StakerKeyHashMismatch {
                        expected: addr_key_hash_256,
                        actual: actual_hash,
                    });
                }
                Ok(binding)
            }
        }
    }
}

/// Phased activation and cutoff policy for Proof-of-Stake `vchBlockSig` authentication (`DIP-PQ-4` §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosBlockAuthPolicy {
    /// Pre-`DIP-PQ-4` activation: only classical `secp256k1` `vchBlockSig` on classical coinstake outputs is allowed.
    ClassicalOnly,
    /// Transition mode allowing classical `secp256k1` on classical outputs and requiring `PostQuantumV1` on PQ outputs.
    DualAllowed { network_magic: [u8; 4] },
    /// Enforces `PostQuantumV1` `vchBlockSig` for all `DIP-PQ-3` PQ coinstake outputs (`PQ_STAKING_VAULT` & `P2PQPKH`).
    PqRequiredForPqOutputs { network_magic: [u8; 4] },
    /// Full post-quantum PoS cutoff: blocks with `block_time >= cutoff_block_time` MUST use PQ coinstake outputs and `PostQuantumV1` `vchBlockSig`.
    PqRequiredAllAfter {
        network_magic: [u8; 4],
        cutoff_block_time: u32,
    },
}

/// Result of verifying a PoS block's `vchBlockSig` format, cutoff policy, coinstake key binding,
/// and domain-separated signing prehash (`DIP-PQ-4` §3–§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedBlockSigBinding {
    /// Classical `secp256k1` block signature on a classical coinstake output (`P2PKH`, `STAKING_VAULT`, or `P2PK`).
    ClassicalSecp256k1,
    /// Post-quantum `DIP-PQ-4` `v1` envelope verified against a 256-bit `PQ_STAKING_VAULT` or `P2PQPKH` coinstake output.
    PostQuantumV1 {
        scheme_id: PqSchemeId,
        staker_key_hash_256: [u8; 32],
        coinstake_binding: CoinstakeStakerBinding,
        payload_hash_256: [u8; 32],
        signing_prehash_512: [u8; 64],
    },
}

/// Parse a `DIP-PQ-3` post-quantum coinstake `scriptPubKey` (`74`-byte `PQ_STAKING_VAULT` or `34`-byte `P2PQPKH`).
pub fn parse_pq_coinstake_script(script: &Script) -> Option<CoinstakeStakerBinding> {
    let bytes = script.as_bytes();
    if bytes.len() == P2PQPKH_SCRIPT_LEN && bytes[0] == 0x51 && bytes[1] == 0x20 {
        let mut addr_key_hash_256 = [0u8; 32];
        addr_key_hash_256.copy_from_slice(&bytes[2..34]);
        return Some(CoinstakeStakerBinding::P2PqPkh { addr_key_hash_256 });
    }
    if bytes.len() == PQ_STAKING_VAULT_SCRIPT_LEN
        && bytes[0] == 0x63 // OP_IF
        && bytes[1] == 0x20 // PUSH32
        && bytes[34] == 0x67 // OP_ELSE
        && bytes[35] == 0xb9 // OP_REQUIRE_COINSTAKE
        && bytes[36] == 0x20 // PUSH32
        && bytes[69] == 0x68 // OP_ENDIF
        && bytes[70] == 0x78 // OP_OVER
        && bytes[71] == 0xa8 // OP_SHA256
        && bytes[72] == 0x88 // OP_EQUALVERIFY
        && bytes[73] == 0xac
    // OP_CHECKSIG
    {
        let mut owner_hash_256 = [0u8; 32];
        owner_hash_256.copy_from_slice(&bytes[2..34]);
        let mut vault_hash_256 = [0u8; 32];
        vault_hash_256.copy_from_slice(&bytes[37..69]);
        return Some(CoinstakeStakerBinding::PqStakingVault {
            owner_hash_256,
            vault_hash_256,
        });
    }
    None
}

/// Check whether `script` is a canonical classical PoS staking output (`50 B` `STAKING_VAULT`,
/// `25 B` `P2PKH`, or `35`/`67 B` `P2PK`).
pub fn is_classical_coinstake_script(script: &Script) -> bool {
    let bytes = script.as_bytes();
    match bytes.len() {
        // Classical P2PKH: OP_DUP (0x76) OP_HASH160 (0xa9) PUSH20 (0x14) <20B> OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
        CLASSICAL_P2PKH_SCRIPT_LEN => {
            bytes[0] == 0x76
                && bytes[1] == 0xa9
                && bytes[2] == 0x14
                && bytes[23] == 0x88
                && bytes[24] == 0xac
        }
        // Classical STAKING_VAULT: OP_IF (0x63) 0x14 <20B> OP_ELSE (0x67) OP_REQUIRE_COINSTAKE (0xb9) 0x14 <20B> OP_ENDIF (0x68) OP_OVER (0x78) OP_HASH160 (0xa9) OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
        CLASSICAL_STAKING_VAULT_SCRIPT_LEN => {
            bytes[0] == 0x63
                && bytes[1] == 0x14
                && bytes[22] == 0x67
                && bytes[23] == 0xb9
                && bytes[24] == 0x14
                && bytes[45] == 0x68
                && bytes[46] == 0x78
                && bytes[47] == 0xa9
                && bytes[48] == 0x88
                && bytes[49] == 0xac
        }
        // Classical compressed P2PK: PUSH33 (0x21) <0x02/0x03 + 32B> OP_CHECKSIG (0xac)
        35 => bytes[0] == 0x21 && (bytes[1] == 0x02 || bytes[1] == 0x03) && bytes[34] == 0xac,
        // Classical uncompressed P2PK: PUSH65 (0x41) <0x04 + 64B> OP_CHECKSIG (0xac)
        67 => bytes[0] == 0x41 && bytes[1] == 0x04 && bytes[66] == 0xac,
        _ => false,
    }
}

/// Classify a raw `vchBlockSig` slice into [`BlockSigFormat::ClassicalSecp256k1`] or
/// [`BlockSigFormat::PostQuantumV1`] (`DIP-PQ-4` §2.2).
pub fn classify_block_sig_format(vch_block_sig: &[u8]) -> Result<BlockSigFormat, PqBlockSigError> {
    if vch_block_sig.is_empty() {
        return Err(PqBlockSigError::EmptyBlockSignature);
    }
    if vch_block_sig[0] == PQ_BLOCK_SIG_MAGIC {
        let env = PqBlockSigEnvelope::decode(vch_block_sig)?;
        return Ok(BlockSigFormat::PostQuantumV1(env));
    }

    let first = vch_block_sig[0];
    let len = vch_block_sig.len();
    let is_compact_secp = len == CLASSICAL_COMPACT_BLOCK_SIG_LEN && (0x1b..=0x22).contains(&first);
    let is_der_secp = first == 0x30 && (64..=73).contains(&len);

    if is_compact_secp || is_der_secp {
        Ok(BlockSigFormat::ClassicalSecp256k1)
    } else if len == FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN || len == ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN {
        Err(PqBlockSigError::InvalidEnvelopeMagic {
            expected: PQ_BLOCK_SIG_MAGIC,
            actual: first,
        })
    } else {
        Err(PqBlockSigError::InvalidClassicalSignatureFormat {
            len,
            first_byte: first,
        })
    }
}

/// Serialize the exact 85-byte PoS block payload preimage (`DIP-PQ-4` §4.1):
/// `"DIVI-POS-BLOCK-V1" (17 B) || block_hash (32 B) || coinstake_txid (32 B) || u32_le(coinstake_vout) (4 B)`.
pub fn serialize_pos_block_payload_preimage(
    block_hash: &[u8; 32],
    coinstake_txid: &[u8; 32],
    coinstake_vout: u32,
) -> [u8; POS_BLOCK_PAYLOAD_PREIMAGE_LEN] {
    let mut preimage = [0u8; POS_BLOCK_PAYLOAD_PREIMAGE_LEN];
    preimage[0..17].copy_from_slice(POS_BLOCK_PAYLOAD_DOMAIN);
    preimage[17..49].copy_from_slice(block_hash);
    preimage[49..81].copy_from_slice(coinstake_txid);
    preimage[81..85].copy_from_slice(&coinstake_vout.to_le_bytes());
    preimage
}

/// Compute the 32-byte `SHA-256` PoS block payload digest binding the block header hash and
/// the coinstake staking outpoint (`DIP-PQ-4` §4.1).
pub fn compute_pos_block_payload_hash(
    block_hash: &[u8; 32],
    coinstake_txid: &[u8; 32],
    coinstake_vout: u32,
) -> [u8; 32] {
    let preimage = serialize_pos_block_payload_preimage(block_hash, coinstake_txid, coinstake_vout);
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Compute the 64-byte (`SHA-512`) domain-separated signing prehash under `PqDomainTag::BlockSigV1`
/// (`"Divi-PQ-BlockSig-v1"`, `DIP-PQ-4` §4.2).
///
/// Rejects schemes forbidden in `BlockSigV1` (`SLH-DSA-128s` `0x03` and `LMS-SHA256-M32-H10` `0x04`)
/// and validates canonical public-key encoding before computing the prehash.
pub fn compute_pos_block_signing_prehash(
    network_magic: [u8; 4],
    scheme_id: PqSchemeId,
    pubkey_bytes: &[u8],
    block_hash: &[u8; 32],
    coinstake_txid: &[u8; 32],
    coinstake_vout: u32,
) -> Result<[u8; 64], PqBlockSigError> {
    if !scheme_id.is_allowed_in_domain(PqDomainTag::BlockSigV1) {
        return Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
            scheme: scheme_id,
            domain: PqDomainTag::BlockSigV1,
        }));
    }
    scheme_id.validate_pubkey_encoding(pubkey_bytes)?;

    let payload_hash_256 =
        compute_pos_block_payload_hash(block_hash, coinstake_txid, coinstake_vout);
    Ok(compute_pq_signing_prehash(
        PqDomainTag::BlockSigV1,
        network_magic,
        scheme_id,
        pubkey_bytes,
        &payload_hash_256,
    ))
}

/// Verify a Proof-of-Stake block's `vchBlockSig` envelope, cutoff policy, coinstake key binding,
/// and domain-separated `BlockSigV1` signing prehash (`DIP-PQ-4` §2–§5).
pub fn verify_block_sig_envelope_binding(
    vch_block_sig: &[u8],
    coinstake_script_pubkey: &Script,
    block_hash: &[u8; 32],
    coinstake_txid: &[u8; 32],
    coinstake_vout: u32,
    block_time: u32,
    policy: &PosBlockAuthPolicy,
) -> Result<VerifiedBlockSigBinding, PqBlockSigError> {
    let format = classify_block_sig_format(vch_block_sig)?;
    let is_pq_output = parse_pq_coinstake_script(coinstake_script_pubkey).is_some();

    match policy {
        PosBlockAuthPolicy::ClassicalOnly => match format {
            BlockSigFormat::PostQuantumV1(_) => {
                Err(PqBlockSigError::PostQuantumBlockSigForbiddenBeforeActivation)
            }
            BlockSigFormat::ClassicalSecp256k1 => {
                if is_pq_output || !is_classical_coinstake_script(coinstake_script_pubkey) {
                    return Err(PqBlockSigError::UnsupportedCoinstakeScriptForClassicalBlockSig);
                }
                Ok(VerifiedBlockSigBinding::ClassicalSecp256k1)
            }
        },
        PosBlockAuthPolicy::DualAllowed { network_magic }
        | PosBlockAuthPolicy::PqRequiredForPqOutputs { network_magic } => {
            verify_dual_or_pq_output_policy(
                format,
                coinstake_script_pubkey,
                block_hash,
                coinstake_txid,
                coinstake_vout,
                *network_magic,
            )
        }
        PosBlockAuthPolicy::PqRequiredAllAfter {
            network_magic,
            cutoff_block_time,
        } => {
            if block_time >= *cutoff_block_time
                && matches!(format, BlockSigFormat::ClassicalSecp256k1)
            {
                return Err(PqBlockSigError::MissingPostQuantumBlockSigAfterCutoff {
                    block_time,
                    cutoff_block_time: *cutoff_block_time,
                });
            }
            verify_dual_or_pq_output_policy(
                format,
                coinstake_script_pubkey,
                block_hash,
                coinstake_txid,
                coinstake_vout,
                *network_magic,
            )
        }
    }
}

fn verify_dual_or_pq_output_policy(
    format: BlockSigFormat,
    coinstake_script_pubkey: &Script,
    block_hash: &[u8; 32],
    coinstake_txid: &[u8; 32],
    coinstake_vout: u32,
    network_magic: [u8; 4],
) -> Result<VerifiedBlockSigBinding, PqBlockSigError> {
    let is_pq_output = parse_pq_coinstake_script(coinstake_script_pubkey).is_some();
    match format {
        BlockSigFormat::ClassicalSecp256k1 => {
            if is_pq_output {
                return Err(PqBlockSigError::MissingPostQuantumBlockSigForPqOutput);
            }
            if !is_classical_coinstake_script(coinstake_script_pubkey) {
                return Err(PqBlockSigError::UnsupportedCoinstakeScriptForClassicalBlockSig);
            }
            Ok(VerifiedBlockSigBinding::ClassicalSecp256k1)
        }
        BlockSigFormat::PostQuantumV1(env) => {
            let coinstake_binding =
                env.verify_structural_and_staker_binding(coinstake_script_pubkey)?;
            let staker_key_hash_256 = env.staker_key_hash_256();
            let payload_hash_256 =
                compute_pos_block_payload_hash(block_hash, coinstake_txid, coinstake_vout);
            let signing_prehash_512 = compute_pos_block_signing_prehash(
                network_magic,
                env.scheme_id,
                &env.pubkey_bytes,
                block_hash,
                coinstake_txid,
                coinstake_vout,
            )?;
            Ok(VerifiedBlockSigBinding::PostQuantumV1 {
                scheme_id: env.scheme_id,
                staker_key_hash_256,
                coinstake_binding,
                payload_hash_256,
                signing_prehash_512,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIVI_MAINNET_MAGIC: [u8; 4] = [0xdf, 0xf0, 0xc8, 0xf3];
    const DIVI_TESTNET_MAGIC: [u8; 4] = [0xf4, 0xc4, 0xd7, 0xaa];

    /// Build a canonical 897-byte `FN-DSA-512` public key (`pk[0] == 0x09`, all 14-bit coeffs `< 12289`).
    fn sample_fndsa512_pubkey(tag: u8) -> Vec<u8> {
        let mut pk = Vec::with_capacity(897);
        pk.push(0x09);
        let mut acc: u32 = 0;
        let mut acc_bits: u32 = 0;
        for i in 0..512u32 {
            let coeff = (i + u32::from(tag)) % 1024;
            acc = (acc << 14) | coeff;
            acc_bits += 14;
            while acc_bits >= 8 {
                acc_bits -= 8;
                pk.push(((acc >> acc_bits) & 0xff) as u8);
            }
        }
        assert_eq!(pk.len(), 897);
        assert!(PqSchemeId::FnDsa512.validate_pubkey_encoding(&pk).is_ok());
        pk
    }

    /// Build a canonical 666-byte `FN-DSA-512` padded signature (`sig[0] == 0x39`, 512 zero coeffs + zero padding).
    fn sample_fndsa512_signature(nonce_byte: u8) -> Vec<u8> {
        let mut sig = vec![0u8; 666];
        sig[0] = 0x39;
        for b in &mut sig[1..41] {
            *b = nonce_byte;
        }
        // Encode 512 zero coefficients in Golomb-Rice: each coeff is 9 bits (0_0000000_1)
        // 512 * 9 bits = 4,608 bits = 576 bytes (sig[41..617]); every 9th bit (positions 8, 17, 26, ...) is 1.
        let payload = &mut sig[41..666];
        for coeff_idx in 0..512usize {
            let bit_pos = coeff_idx * 9 + 8;
            let byte_idx = bit_pos >> 3;
            let bit_shift = 7 - (bit_pos & 7);
            payload[byte_idx] |= 1u8 << bit_shift;
        }
        assert!(PqSchemeId::FnDsa512
            .validate_signature_encoding(&sig)
            .is_ok());
        sig
    }

    /// Build a canonical 1,312-byte `ML-DSA-44` public key.
    fn sample_mldsa44_pubkey(tag: u8) -> Vec<u8> {
        let mut pk = vec![0u8; 1312];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(tag);
        }
        assert!(PqSchemeId::MlDsa44.validate_pubkey_encoding(&pk).is_ok());
        pk
    }

    /// Build a canonical 2,420-byte `ML-DSA-44` signature (`z = 0` unpacked coefficients + zero hints).
    fn sample_mldsa44_signature(c_tilde_byte: u8) -> Vec<u8> {
        let mut sig = vec![0u8; 2420];
        for b in &mut sig[0..32] {
            *b = c_tilde_byte;
        }
        // Each 9-byte chunk packs four 18-bit unsigned integers u0..u3 = gamma1 = 131072 (0x20000),
        // which unpacks to z = gamma1 - u = 0 (< 130994).
        let zero_z_chunk: [u8; 9] = [0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x20, 0x00, 0x80];
        for chunk in sig[32..2336].as_chunks_mut::<9>().0 {
            chunk.copy_from_slice(&zero_z_chunk);
        }
        // bytes 2336..2420 remain 0x00 (valid 0-hint HintBitUnpack vector)
        assert!(PqSchemeId::MlDsa44
            .validate_signature_encoding(&sig)
            .is_ok());
        sig
    }

    fn build_pq_staking_vault_script(
        owner_hash_256: &[u8; 32],
        vault_hash_256: &[u8; 32],
    ) -> Script {
        let mut bytes = Vec::with_capacity(PQ_STAKING_VAULT_SCRIPT_LEN);
        bytes.push(0x63); // OP_IF
        bytes.push(0x20); // PUSH32
        bytes.extend_from_slice(owner_hash_256);
        bytes.push(0x67); // OP_ELSE
        bytes.push(0xb9); // OP_REQUIRE_COINSTAKE
        bytes.push(0x20); // PUSH32
        bytes.extend_from_slice(vault_hash_256);
        bytes.push(0x68); // OP_ENDIF
        bytes.push(0x78); // OP_OVER
        bytes.push(0xa8); // OP_SHA256
        bytes.push(0x88); // OP_EQUALVERIFY
        bytes.push(0xac); // OP_CHECKSIG
        Script::from_bytes(bytes)
    }

    fn build_p2pqpkh_script(addr_key_hash_256: &[u8; 32]) -> Script {
        let mut bytes = Vec::with_capacity(P2PQPKH_SCRIPT_LEN);
        bytes.push(0x51); // OP_1
        bytes.push(0x20); // PUSH32
        bytes.extend_from_slice(addr_key_hash_256);
        Script::from_bytes(bytes)
    }

    fn build_classical_vault_script(owner_hash160: &[u8; 20], vault_hash160: &[u8; 20]) -> Script {
        let mut bytes = Vec::with_capacity(CLASSICAL_STAKING_VAULT_SCRIPT_LEN);
        bytes.push(0x63);
        bytes.push(0x14);
        bytes.extend_from_slice(owner_hash160);
        bytes.push(0x67);
        bytes.push(0xb9);
        bytes.push(0x14);
        bytes.extend_from_slice(vault_hash160);
        bytes.push(0x68);
        bytes.push(0x78);
        bytes.push(0xa9);
        bytes.push(0x88);
        bytes.push(0xac);
        Script::from_bytes(bytes)
    }

    fn build_classical_p2pkh_script(hash160: &[u8; 20]) -> Script {
        let mut bytes = Vec::with_capacity(CLASSICAL_P2PKH_SCRIPT_LEN);
        bytes.push(0x76);
        bytes.push(0xa9);
        bytes.push(0x14);
        bytes.extend_from_slice(hash160);
        bytes.push(0x88);
        bytes.push(0xac);
        Script::from_bytes(bytes)
    }

    #[test]
    fn test_fndsa512_envelope_encode_decode_roundtrip_and_exact_1566_len() {
        let pk = sample_fndsa512_pubkey(0x01);
        let sig = sample_fndsa512_signature(0xaa);
        let env = PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, pk.clone(), sig.clone()).unwrap();
        let encoded = env.encode();

        assert_eq!(encoded.len(), FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN);
        assert_eq!(encoded.len(), 1566);
        assert_eq!(&encoded[0..3], &[0x50, 0x01, 0x02]);

        let decoded = PqBlockSigEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);
        assert_eq!(
            decoded.staker_key_hash_256(),
            pq_address_key_hash_256(PqSchemeId::FnDsa512, &pk)
        );
        assert_eq!(
            decoded.signing_key_hash_256(),
            pq_key_hash_256(PqSchemeId::FnDsa512, &pk)
        );
    }

    #[test]
    fn test_mldsa44_envelope_encode_decode_roundtrip_and_exact_3735_len() {
        let pk = sample_mldsa44_pubkey(0x02);
        let sig = sample_mldsa44_signature(0xbb);
        let env = PqBlockSigEnvelope::new(PqSchemeId::MlDsa44, pk.clone(), sig.clone()).unwrap();
        let encoded = env.encode();

        assert_eq!(encoded.len(), ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN);
        assert_eq!(encoded.len(), 3735);
        assert_eq!(&encoded[0..3], &[0x50, 0x01, 0x01]);

        let decoded = PqBlockSigEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);
        assert_eq!(
            decoded.staker_key_hash_256(),
            pq_address_key_hash_256(PqSchemeId::MlDsa44, &pk)
        );
    }

    #[test]
    fn test_forbidden_schemes_slhdsa_and_lms_rejected_in_block_sig_envelope() {
        // SLH-DSA-128s (0x03) is forbidden in BlockSigV1
        let slh_pk = vec![0x11u8; 32];
        let slh_sig = vec![0x22u8; 7856];
        assert_eq!(
            PqBlockSigEnvelope::new(PqSchemeId::SlhDsa128s, slh_pk.clone(), slh_sig.clone()),
            Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
                scheme: PqSchemeId::SlhDsa128s,
                domain: PqDomainTag::BlockSigV1,
            }))
        );

        let mut raw_slh = Vec::with_capacity(3 + 32 + 7856);
        raw_slh.extend_from_slice(&[0x50, 0x01, 0x03]);
        raw_slh.extend_from_slice(&slh_pk);
        raw_slh.extend_from_slice(&slh_sig);
        assert_eq!(
            PqBlockSigEnvelope::decode(&raw_slh),
            Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
                scheme: PqSchemeId::SlhDsa128s,
                domain: PqDomainTag::BlockSigV1,
            }))
        );

        // LMS-SHA256-M32-H10 (0x04) is Spork-only and forbidden in BlockSigV1
        let mut raw_lms = vec![0u8; 3 + 60 + 2512];
        raw_lms[0..3].copy_from_slice(&[0x50, 0x01, 0x04]);
        assert_eq!(
            PqBlockSigEnvelope::decode(&raw_lms),
            Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
                scheme: PqSchemeId::LmsSha256M32H10,
                domain: PqDomainTag::BlockSigV1,
            }))
        );
    }

    #[test]
    fn test_unknown_scheme_id_and_unsupported_version_rejected() {
        let mut encoded = PqBlockSigEnvelope::new(
            PqSchemeId::FnDsa512,
            sample_fndsa512_pubkey(1),
            sample_fndsa512_signature(1),
        )
        .unwrap()
        .encode();

        // Unknown scheme_id 0x05
        encoded[2] = 0x05;
        assert_eq!(
            PqBlockSigEnvelope::decode(&encoded),
            Err(PqBlockSigError::Crypto(PqError::UnknownSchemeId(0x05)))
        );

        // Unsupported version 0x02
        encoded[2] = 0x02;
        encoded[1] = 0x02;
        assert_eq!(
            PqBlockSigEnvelope::decode(&encoded),
            Err(PqBlockSigError::UnsupportedEnvelopeVersion(0x02))
        );

        // Wrong magic 0x51
        encoded[1] = 0x01;
        encoded[0] = 0x51;
        assert_eq!(
            PqBlockSigEnvelope::decode(&encoded),
            Err(PqBlockSigError::InvalidEnvelopeMagic {
                expected: 0x50,
                actual: 0x51,
            })
        );
    }

    #[test]
    fn test_envelope_trailing_byte_and_truncation_rejected() {
        let encoded = PqBlockSigEnvelope::new(
            PqSchemeId::FnDsa512,
            sample_fndsa512_pubkey(1),
            sample_fndsa512_signature(1),
        )
        .unwrap()
        .encode();

        // Truncated by 1 byte (1,565 bytes)
        assert_eq!(
            PqBlockSigEnvelope::decode(&encoded[..encoded.len() - 1]),
            Err(PqBlockSigError::InvalidEnvelopeLength {
                scheme: Some(PqSchemeId::FnDsa512),
                expected: 1566,
                actual: 1565,
            })
        );

        // Trailing 0x00 byte (1,567 bytes)
        let mut with_trailing = encoded.clone();
        with_trailing.push(0x00);
        assert_eq!(
            PqBlockSigEnvelope::decode(&with_trailing),
            Err(PqBlockSigError::InvalidEnvelopeLength {
                scheme: Some(PqSchemeId::FnDsa512),
                expected: 1566,
                actual: 1567,
            })
        );

        // Truncated header (< 3 bytes)
        assert_eq!(
            PqBlockSigEnvelope::decode(&[0x50, 0x01]),
            Err(PqBlockSigError::InvalidEnvelopeLength {
                scheme: None,
                expected: 3,
                actual: 2,
            })
        );
        assert_eq!(
            PqBlockSigEnvelope::decode(&[]),
            Err(PqBlockSigError::EmptyBlockSignature)
        );
    }

    #[test]
    fn test_non_canonical_fndsa512_pubkey_and_signature_rejected_in_envelope() {
        let pk = sample_fndsa512_pubkey(3);
        let sig = sample_fndsa512_signature(3);
        let base_encoded = PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, pk, sig)
            .unwrap()
            .encode();

        // 1. Corrupt FN-DSA-512 public key header byte (must be 0x09)
        let mut bad_pk_header = base_encoded.clone();
        bad_pk_header[3] = 0x08;
        assert!(matches!(
            PqBlockSigEnvelope::decode(&bad_pk_header),
            Err(PqBlockSigError::Crypto(PqError::NonCanonicalPublicKey {
                scheme: PqSchemeId::FnDsa512,
                ..
            }))
        ));

        // 2. Corrupt FN-DSA-512 signature header byte (must be 0x39)
        let mut bad_sig_header = base_encoded.clone();
        bad_sig_header[3 + 897] = 0x38;
        assert!(matches!(
            PqBlockSigEnvelope::decode(&bad_sig_header),
            Err(PqBlockSigError::Crypto(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::FnDsa512,
                ..
            }))
        ));

        // 3. Corrupt FN-DSA-512 trailing padding bit (last byte of 1,566-byte envelope must be 0x00)
        let mut bad_sig_padding = base_encoded;
        *bad_sig_padding.last_mut().unwrap() = 0x01;
        assert!(matches!(
            PqBlockSigEnvelope::decode(&bad_sig_padding),
            Err(PqBlockSigError::Crypto(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::FnDsa512,
                ..
            }))
        ));
    }

    #[test]
    fn test_non_canonical_mldsa44_z_norm_and_hint_vector_rejected_in_envelope() {
        let pk = sample_mldsa44_pubkey(4);
        let sig = sample_mldsa44_signature(4);
        let base_encoded = PqBlockSigEnvelope::new(PqSchemeId::MlDsa44, pk, sig)
            .unwrap()
            .encode();

        // 1. Zero out first z chunk -> u0 = 0 -> z0 = gamma1 = 131072 >= 130994 -> rejected
        let mut bad_z = base_encoded.clone();
        let z_start = 3 + 1312 + 32;
        bad_z[z_start..z_start + 9].fill(0);
        assert!(matches!(
            PqBlockSigEnvelope::decode(&bad_z),
            Err(PqBlockSigError::Crypto(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::MlDsa44,
                ..
            }))
        ));

        // 2. Set non-zero byte in unused hint padding tail (with hint offsets = 0)
        let mut bad_hint_pad = base_encoded.clone();
        let hint_start = 3 + 1312 + 2336;
        bad_hint_pad[hint_start] = 0x01;
        assert!(matches!(
            PqBlockSigEnvelope::decode(&bad_hint_pad),
            Err(PqBlockSigError::Crypto(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::MlDsa44,
                ..
            }))
        ));

        // 3. Set hint offset > omega (80)
        let mut bad_hint_offset = base_encoded;
        bad_hint_offset[hint_start + 80] = 81;
        assert!(matches!(
            PqBlockSigEnvelope::decode(&bad_hint_offset),
            Err(PqBlockSigError::Crypto(PqError::NonCanonicalSignature {
                scheme: PqSchemeId::MlDsa44,
                ..
            }))
        ));
    }

    #[test]
    fn test_pq_staking_vault_hot_vault_key_accepted_and_cold_owner_key_forbidden() {
        let owner_pk = sample_mldsa44_pubkey(0x10);
        let owner_sig = sample_mldsa44_signature(0x10);
        let owner_hash_256 = pq_address_key_hash_256(PqSchemeId::MlDsa44, &owner_pk);

        let vault_pk = sample_fndsa512_pubkey(0x20);
        let vault_sig = sample_fndsa512_signature(0x20);
        let vault_hash_256 = pq_address_key_hash_256(PqSchemeId::FnDsa512, &vault_pk);

        let vault_script = build_pq_staking_vault_script(&owner_hash_256, &vault_hash_256);

        // 1. Hot vault key (FN-DSA-512) signing vchBlockSig is ACCEPTED
        let hot_env = PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, vault_pk, vault_sig).unwrap();
        let binding = hot_env
            .verify_structural_and_staker_binding(&vault_script)
            .unwrap();
        assert_eq!(
            binding,
            CoinstakeStakerBinding::PqStakingVault {
                owner_hash_256,
                vault_hash_256,
            }
        );
        assert_eq!(binding.expected_staker_hash_256(), vault_hash_256);

        // 2. Cold owner key (ML-DSA-44) attempting to sign vchBlockSig is STRICTLY FORBIDDEN
        let cold_env = PqBlockSigEnvelope::new(PqSchemeId::MlDsa44, owner_pk, owner_sig).unwrap();
        assert_eq!(
            cold_env.verify_structural_and_staker_binding(&vault_script),
            Err(PqBlockSigError::ColdOwnerKeyForbiddenForBlockSigning {
                owner_hash_256,
                vault_hash_256,
            })
        );

        // 3. Degenerate vault where owner_hash_256 == vault_hash_256 is ALSO rejected as ColdOwnerKeyForbiddenForBlockSigning
        let degenerate_script = build_pq_staking_vault_script(&vault_hash_256, &vault_hash_256);
        assert_eq!(
            hot_env.verify_structural_and_staker_binding(&degenerate_script),
            Err(PqBlockSigError::ColdOwnerKeyForbiddenForBlockSigning {
                owner_hash_256: vault_hash_256,
                vault_hash_256,
            })
        );

        // 4. Unrelated third key is rejected with StakerKeyHashMismatch
        let other_pk = sample_fndsa512_pubkey(0x99);
        let other_sig = sample_fndsa512_signature(0x99);
        let other_hash_256 = pq_address_key_hash_256(PqSchemeId::FnDsa512, &other_pk);
        let other_env = PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, other_pk, other_sig).unwrap();
        assert_eq!(
            other_env.verify_structural_and_staker_binding(&vault_script),
            Err(PqBlockSigError::StakerKeyHashMismatch {
                expected: vault_hash_256,
                actual: other_hash_256,
            })
        );
    }

    #[test]
    fn test_p2pqpkh_staker_key_binding_acceptance_and_mismatch_rejection() {
        let staker_pk = sample_fndsa512_pubkey(0x33);
        let staker_sig = sample_fndsa512_signature(0x33);
        let addr_key_hash_256 = pq_address_key_hash_256(PqSchemeId::FnDsa512, &staker_pk);
        let p2pqpkh_script = build_p2pqpkh_script(&addr_key_hash_256);

        let env = PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, staker_pk, staker_sig).unwrap();
        let binding = env
            .verify_structural_and_staker_binding(&p2pqpkh_script)
            .unwrap();
        assert_eq!(
            binding,
            CoinstakeStakerBinding::P2PqPkh { addr_key_hash_256 }
        );
        assert_eq!(binding.expected_staker_hash_256(), addr_key_hash_256);

        // Wrong key hash in P2PQPKH output -> StakerKeyHashMismatch
        let wrong_script = build_p2pqpkh_script(&[0xeeu8; 32]);
        assert_eq!(
            env.verify_structural_and_staker_binding(&wrong_script),
            Err(PqBlockSigError::StakerKeyHashMismatch {
                expected: [0xeeu8; 32],
                actual: addr_key_hash_256,
            })
        );
    }

    #[test]
    fn test_dip_pq_4_vector_1_pos_block_payload_hash_and_signing_prehash() {
        let block_hash = [0x11u8; 32];
        let coinstake_txid = [0x22u8; 32];
        let coinstake_vout = 1u32;

        let preimage =
            serialize_pos_block_payload_preimage(&block_hash, &coinstake_txid, coinstake_vout);
        assert_eq!(preimage.len(), 85);
        assert_eq!(
            hex::encode(preimage),
            "444956492d504f532d424c4f434b2d56311111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222201000000"
        );

        let payload_hash =
            compute_pos_block_payload_hash(&block_hash, &coinstake_txid, coinstake_vout);
        // Changing block_hash, coinstake_txid, or coinstake_vout changes payload_hash
        assert_ne!(
            payload_hash,
            compute_pos_block_payload_hash(&[0x12u8; 32], &coinstake_txid, coinstake_vout)
        );
        assert_ne!(
            payload_hash,
            compute_pos_block_payload_hash(&block_hash, &[0x23u8; 32], coinstake_vout)
        );
        assert_ne!(
            payload_hash,
            compute_pos_block_payload_hash(&block_hash, &coinstake_txid, 2)
        );

        let pk = sample_fndsa512_pubkey(0x05);
        let prehash_mainnet = compute_pos_block_signing_prehash(
            DIVI_MAINNET_MAGIC,
            PqSchemeId::FnDsa512,
            &pk,
            &block_hash,
            &coinstake_txid,
            coinstake_vout,
        )
        .unwrap();
        let prehash_testnet = compute_pos_block_signing_prehash(
            DIVI_TESTNET_MAGIC,
            PqSchemeId::FnDsa512,
            &pk,
            &block_hash,
            &coinstake_txid,
            coinstake_vout,
        )
        .unwrap();
        assert_ne!(prehash_mainnet, prehash_testnet);
    }

    #[test]
    fn test_classify_block_sig_format_disjointness() {
        // 1. Classical 65-byte compact secp256k1 signature (header 0x1b..=0x22)
        let mut compact_sig = vec![0xaa; 65];
        compact_sig[0] = 0x1f;
        assert_eq!(
            classify_block_sig_format(&compact_sig).unwrap(),
            BlockSigFormat::ClassicalSecp256k1
        );

        // 2. Classical 71-byte ASN.1 DER secp256k1 signature (header 0x30)
        let mut der_sig = vec![0xbb; 71];
        der_sig[0] = 0x30;
        assert_eq!(
            classify_block_sig_format(&der_sig).unwrap(),
            BlockSigFormat::ClassicalSecp256k1
        );

        // 3. Post-Quantum FN-DSA-512 (1,566 bytes)
        let fn_env = PqBlockSigEnvelope::new(
            PqSchemeId::FnDsa512,
            sample_fndsa512_pubkey(7),
            sample_fndsa512_signature(7),
        )
        .unwrap();
        let fn_bytes = fn_env.encode();
        assert_eq!(
            classify_block_sig_format(&fn_bytes).unwrap(),
            BlockSigFormat::PostQuantumV1(fn_env)
        );

        // 4. Invalid classical length/header rejected
        assert_eq!(
            classify_block_sig_format(&[0x1f; 64]),
            Err(PqBlockSigError::InvalidClassicalSignatureFormat {
                len: 64,
                first_byte: 0x1f,
            })
        );
    }

    #[test]
    fn test_pos_block_auth_policy_transitions_and_cutoff_enforcement() {
        let block_hash = [0x44u8; 32];
        let coinstake_txid = [0x55u8; 32];
        let coinstake_vout = 1u32;

        // Classical vault + 65B compact sig
        let classical_vault = build_classical_vault_script(&[0x11u8; 20], &[0x22u8; 20]);
        let classical_p2pkh = build_classical_p2pkh_script(&[0x33u8; 20]);
        let mut classical_sig = vec![0x99u8; 65];
        classical_sig[0] = 0x1c;

        // PQ vault + 1,566B FN-DSA-512 envelope
        let owner_hash_256 = [0x77u8; 32];
        let vault_pk = sample_fndsa512_pubkey(0x42);
        let vault_sig = sample_fndsa512_signature(0x42);
        let vault_hash_256 = pq_address_key_hash_256(PqSchemeId::FnDsa512, &vault_pk);
        let pq_vault = build_pq_staking_vault_script(&owner_hash_256, &vault_hash_256);
        let pq_env = PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, vault_pk, vault_sig).unwrap();
        let pq_sig_bytes = pq_env.encode();

        // Stage 1: ClassicalOnly
        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &classical_vault,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_700_000_000,
                &PosBlockAuthPolicy::ClassicalOnly,
            )
            .unwrap(),
            VerifiedBlockSigBinding::ClassicalSecp256k1
        );
        assert_eq!(
            verify_block_sig_envelope_binding(
                &pq_sig_bytes,
                &pq_vault,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_700_000_000,
                &PosBlockAuthPolicy::ClassicalOnly,
            ),
            Err(PqBlockSigError::PostQuantumBlockSigForbiddenBeforeActivation)
        );

        // Stage 2/3: PqRequiredForPqOutputs
        let pq_policy = PosBlockAuthPolicy::PqRequiredForPqOutputs {
            network_magic: DIVI_MAINNET_MAGIC,
        };
        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &classical_p2pkh,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_750_000_000,
                &pq_policy,
            )
            .unwrap(),
            VerifiedBlockSigBinding::ClassicalSecp256k1
        );
        // Classical sig on PQ vault must fail with MissingPostQuantumBlockSigForPqOutput
        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &pq_vault,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_750_000_000,
                &pq_policy,
            ),
            Err(PqBlockSigError::MissingPostQuantumBlockSigForPqOutput)
        );
        // PQ sig on classical vault must fail with UnsupportedCoinstakeScriptForPqBlockSig
        assert_eq!(
            verify_block_sig_envelope_binding(
                &pq_sig_bytes,
                &classical_vault,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_750_000_000,
                &pq_policy,
            ),
            Err(PqBlockSigError::UnsupportedCoinstakeScriptForPqBlockSig)
        );
        // PQ sig on PQ vault succeeds and returns full binding + prehash
        let verified = verify_block_sig_envelope_binding(
            &pq_sig_bytes,
            &pq_vault,
            &block_hash,
            &coinstake_txid,
            coinstake_vout,
            1_750_000_000,
            &pq_policy,
        )
        .unwrap();
        assert!(matches!(
            verified,
            VerifiedBlockSigBinding::PostQuantumV1 {
                scheme_id: PqSchemeId::FnDsa512,
                staker_key_hash_256,
                ..
            } if staker_key_hash_256 == vault_hash_256
        ));

        // Stage 4: PqRequiredAllAfter { cutoff_block_time = 1_900_000_000 }
        let cutoff_policy = PosBlockAuthPolicy::PqRequiredAllAfter {
            network_magic: DIVI_MAINNET_MAGIC,
            cutoff_block_time: 1_900_000_000,
        };
        // Pre-cutoff (1_899_999_999): classical still allowed on classical output
        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &classical_vault,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_899_999_999,
                &cutoff_policy,
            )
            .unwrap(),
            VerifiedBlockSigBinding::ClassicalSecp256k1
        );
        // At cutoff (1_900_000_000): classical rejected with MissingPostQuantumBlockSigAfterCutoff
        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &classical_vault,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_900_000_000,
                &cutoff_policy,
            ),
            Err(PqBlockSigError::MissingPostQuantumBlockSigAfterCutoff {
                block_time: 1_900_000_000,
                cutoff_block_time: 1_900_000_000,
            })
        );
        // Post-cutoff PQ vault + PQ sig accepted
        assert!(matches!(
            verify_block_sig_envelope_binding(
                &pq_sig_bytes,
                &pq_vault,
                &block_hash,
                &coinstake_txid,
                coinstake_vout,
                1_900_000_001,
                &cutoff_policy,
            )
            .unwrap(),
            VerifiedBlockSigBinding::PostQuantumV1 { .. }
        ));
    }

    #[test]
    fn test_mldsa44_pq_staking_vault_hot_vault_key_acceptance() {
        let owner_hash_256 = [0x91u8; 32];
        let vault_pk = sample_mldsa44_pubkey(0x51);
        let vault_sig = sample_mldsa44_signature(0x51);
        let vault_hash_256 = pq_address_key_hash_256(PqSchemeId::MlDsa44, &vault_pk);
        let vault_script = build_pq_staking_vault_script(&owner_hash_256, &vault_hash_256);

        let env = PqBlockSigEnvelope::new(PqSchemeId::MlDsa44, vault_pk, vault_sig).unwrap();
        let binding = env
            .verify_structural_and_staker_binding(&vault_script)
            .unwrap();
        assert_eq!(
            binding,
            CoinstakeStakerBinding::PqStakingVault {
                owner_hash_256,
                vault_hash_256,
            }
        );
    }

    #[test]
    fn test_mldsa44_p2pqpkh_staker_key_binding_acceptance() {
        let staker_pk = sample_mldsa44_pubkey(0x61);
        let staker_sig = sample_mldsa44_signature(0x61);
        let addr_key_hash_256 = pq_address_key_hash_256(PqSchemeId::MlDsa44, &staker_pk);
        let p2pqpkh_script = build_p2pqpkh_script(&addr_key_hash_256);

        let env = PqBlockSigEnvelope::new(PqSchemeId::MlDsa44, staker_pk, staker_sig).unwrap();
        let binding = env
            .verify_structural_and_staker_binding(&p2pqpkh_script)
            .unwrap();
        assert_eq!(
            binding,
            CoinstakeStakerBinding::P2PqPkh { addr_key_hash_256 }
        );
    }

    #[test]
    fn test_heterogeneous_vault_slhdsa_owner_and_fndsa_vault_hot_key_binding() {
        // Cold owner uses SLH-DSA-128s (32B pubkey, never exposed in BlockSigV1), hot staker uses FN-DSA-512
        let slh_owner_pk = [0xa5u8; 32];
        let owner_hash_256 = pq_address_key_hash_256(PqSchemeId::SlhDsa128s, &slh_owner_pk);

        let fndsa_vault_pk = sample_fndsa512_pubkey(0x72);
        let fndsa_vault_sig = sample_fndsa512_signature(0x72);
        let vault_hash_256 = pq_address_key_hash_256(PqSchemeId::FnDsa512, &fndsa_vault_pk);

        let script = build_pq_staking_vault_script(&owner_hash_256, &vault_hash_256);
        let env =
            PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, fndsa_vault_pk, fndsa_vault_sig).unwrap();
        assert_eq!(
            env.verify_structural_and_staker_binding(&script).unwrap(),
            CoinstakeStakerBinding::PqStakingVault {
                owner_hash_256,
                vault_hash_256,
            }
        );
    }

    #[test]
    fn test_heterogeneous_vault_slhdsa_owner_and_mldsa_vault_hot_key_binding() {
        let slh_owner_pk = [0xb6u8; 32];
        let owner_hash_256 = pq_address_key_hash_256(PqSchemeId::SlhDsa128s, &slh_owner_pk);

        let mldsa_vault_pk = sample_mldsa44_pubkey(0x73);
        let mldsa_vault_sig = sample_mldsa44_signature(0x73);
        let vault_hash_256 = pq_address_key_hash_256(PqSchemeId::MlDsa44, &mldsa_vault_pk);

        let script = build_pq_staking_vault_script(&owner_hash_256, &vault_hash_256);
        let env =
            PqBlockSigEnvelope::new(PqSchemeId::MlDsa44, mldsa_vault_pk, mldsa_vault_sig).unwrap();
        assert_eq!(
            env.verify_structural_and_staker_binding(&script).unwrap(),
            CoinstakeStakerBinding::PqStakingVault {
                owner_hash_256,
                vault_hash_256,
            }
        );
    }

    #[test]
    fn test_compute_pos_block_signing_prehash_rejects_forbidden_schemes() {
        let block_hash = [0x11u8; 32];
        let coinstake_txid = [0x22u8; 32];

        assert_eq!(
            compute_pos_block_signing_prehash(
                DIVI_MAINNET_MAGIC,
                PqSchemeId::SlhDsa128s,
                &[0u8; 32],
                &block_hash,
                &coinstake_txid,
                1,
            ),
            Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
                scheme: PqSchemeId::SlhDsa128s,
                domain: PqDomainTag::BlockSigV1,
            }))
        );
        assert_eq!(
            compute_pos_block_signing_prehash(
                DIVI_MAINNET_MAGIC,
                PqSchemeId::LmsSha256M32H10,
                &[0u8; 60],
                &block_hash,
                &coinstake_txid,
                1,
            ),
            Err(PqBlockSigError::Crypto(PqError::SchemeForbiddenInDomain {
                scheme: PqSchemeId::LmsSha256M32H10,
                domain: PqDomainTag::BlockSigV1,
            }))
        );
    }

    #[test]
    fn test_compute_pos_block_signing_prehash_rejects_non_canonical_pubkey() {
        let mut bad_pk = sample_fndsa512_pubkey(0x11);
        bad_pk[0] = 0x00; // invalid FN-DSA-512 header byte
        assert!(matches!(
            compute_pos_block_signing_prehash(
                DIVI_MAINNET_MAGIC,
                PqSchemeId::FnDsa512,
                &bad_pk,
                &[0x11u8; 32],
                &[0x22u8; 32],
                1,
            ),
            Err(PqBlockSigError::Crypto(PqError::NonCanonicalPublicKey {
                scheme: PqSchemeId::FnDsa512,
                ..
            }))
        ));
    }

    #[test]
    fn test_classical_compressed_and_uncompressed_p2pk_coinstake_recognition() {
        // 35-byte compressed P2PK: 0x21 || (0x02 + 32B) || 0xac
        let mut compressed = vec![0u8; 35];
        compressed[0] = 0x21;
        compressed[1] = 0x02;
        compressed[34] = 0xac;
        assert!(is_classical_coinstake_script(&Script::from_bytes(
            compressed
        )));

        // 67-byte uncompressed P2PK: 0x41 || (0x04 + 64B) || 0xac
        let mut uncompressed = vec![0u8; 67];
        uncompressed[0] = 0x41;
        uncompressed[1] = 0x04;
        uncompressed[66] = 0xac;
        assert!(is_classical_coinstake_script(&Script::from_bytes(
            uncompressed
        )));
    }

    #[test]
    fn test_non_standard_coinstake_script_rejected_under_all_policies() {
        let non_standard = Script::from_bytes(vec![0x6a, 0x04, 1, 2, 3, 4]); // OP_RETURN
        let mut classical_sig = vec![0x99u8; 65];
        classical_sig[0] = 0x1b;

        let pq_env = PqBlockSigEnvelope::new(
            PqSchemeId::FnDsa512,
            sample_fndsa512_pubkey(9),
            sample_fndsa512_signature(9),
        )
        .unwrap();
        let pq_sig = pq_env.encode();

        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &non_standard,
                &[0x11u8; 32],
                &[0x22u8; 32],
                1,
                1_700_000_000,
                &PosBlockAuthPolicy::ClassicalOnly,
            ),
            Err(PqBlockSigError::UnsupportedCoinstakeScriptForClassicalBlockSig)
        );
        assert_eq!(
            verify_block_sig_envelope_binding(
                &pq_sig,
                &non_standard,
                &[0x11u8; 32],
                &[0x22u8; 32],
                1,
                1_700_000_000,
                &PosBlockAuthPolicy::DualAllowed {
                    network_magic: DIVI_MAINNET_MAGIC,
                },
            ),
            Err(PqBlockSigError::UnsupportedCoinstakeScriptForPqBlockSig)
        );
    }

    #[test]
    fn test_dual_allowed_policy_accepts_both_classical_and_pq_outputs() {
        let policy = PosBlockAuthPolicy::DualAllowed {
            network_magic: DIVI_MAINNET_MAGIC,
        };
        let classical_p2pkh = build_classical_p2pkh_script(&[0x44u8; 20]);
        let mut classical_sig = vec![0x88u8; 65];
        classical_sig[0] = 0x1d;

        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &classical_p2pkh,
                &[0x11u8; 32],
                &[0x22u8; 32],
                1,
                1_800_000_000,
                &policy,
            )
            .unwrap(),
            VerifiedBlockSigBinding::ClassicalSecp256k1
        );

        let pk = sample_fndsa512_pubkey(0x88);
        let sig = sample_fndsa512_signature(0x88);
        let p2pqpkh = build_p2pqpkh_script(&pq_address_key_hash_256(PqSchemeId::FnDsa512, &pk));
        let pq_sig = PqBlockSigEnvelope::new(PqSchemeId::FnDsa512, pk, sig)
            .unwrap()
            .encode();

        assert!(matches!(
            verify_block_sig_envelope_binding(
                &pq_sig,
                &p2pqpkh,
                &[0x11u8; 32],
                &[0x22u8; 32],
                1,
                1_800_000_000,
                &policy,
            )
            .unwrap(),
            VerifiedBlockSigBinding::PostQuantumV1 {
                scheme_id: PqSchemeId::FnDsa512,
                ..
            }
        ));
    }

    #[test]
    fn test_pq_required_all_after_rejects_classical_even_on_pq_output_at_cutoff() {
        let cutoff_policy = PosBlockAuthPolicy::PqRequiredAllAfter {
            network_magic: DIVI_MAINNET_MAGIC,
            cutoff_block_time: 1_900_000_000,
        };
        let mut classical_sig = vec![0x88u8; 65];
        classical_sig[0] = 0x1e;
        let p2pqpkh = build_p2pqpkh_script(&[0x55u8; 32]);

        assert_eq!(
            verify_block_sig_envelope_binding(
                &classical_sig,
                &p2pqpkh,
                &[0x11u8; 32],
                &[0x22u8; 32],
                1,
                1_900_000_000,
                &cutoff_policy,
            ),
            Err(PqBlockSigError::MissingPostQuantumBlockSigAfterCutoff {
                block_time: 1_900_000_000,
                cutoff_block_time: 1_900_000_000,
            })
        );
    }

    #[test]
    fn test_envelope_magic_mismatch_at_exact_pq_lengths_1566_and_3735() {
        let mut fn_bytes = vec![0u8; FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN];
        fn_bytes[0] = 0x4f;
        assert_eq!(
            classify_block_sig_format(&fn_bytes),
            Err(PqBlockSigError::InvalidEnvelopeMagic {
                expected: PQ_BLOCK_SIG_MAGIC,
                actual: 0x4f,
            })
        );

        let mut ml_bytes = vec![0u8; ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN];
        ml_bytes[0] = 0x51;
        assert_eq!(
            classify_block_sig_format(&ml_bytes),
            Err(PqBlockSigError::InvalidEnvelopeMagic {
                expected: PQ_BLOCK_SIG_MAGIC,
                actual: 0x51,
            })
        );
    }

    #[test]
    fn test_mldsa44_envelope_truncation_and_trailing_byte_rejection() {
        let encoded = PqBlockSigEnvelope::new(
            PqSchemeId::MlDsa44,
            sample_mldsa44_pubkey(0x12),
            sample_mldsa44_signature(0x12),
        )
        .unwrap()
        .encode();

        assert_eq!(
            PqBlockSigEnvelope::decode(&encoded[..encoded.len() - 1]),
            Err(PqBlockSigError::InvalidEnvelopeLength {
                scheme: Some(PqSchemeId::MlDsa44),
                expected: 3735,
                actual: 3734,
            })
        );

        let mut trailing = encoded;
        trailing.push(0x00);
        assert_eq!(
            PqBlockSigEnvelope::decode(&trailing),
            Err(PqBlockSigError::InvalidEnvelopeLength {
                scheme: Some(PqSchemeId::MlDsa44),
                expected: 3735,
                actual: 3736,
            })
        );
    }
}
