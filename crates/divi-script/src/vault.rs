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

//! Staking vault script support & `DIP-PQ-3` post-quantum output templates,
//! BIP-350 `Bech32m` 256-bit addresses, and segregated post-quantum witness framing.
//!
//! This module provides functionality to create and parse:
//! - Classical 2-key `STAKING_VAULT` scripts (`50` bytes, `Hash160` commitments),
//! - `DIP-PQ-3` 256-bit `P2PQPKH` (`34` bytes, `OP_1 PUSH32 <addr_key_hash_256>`),
//! - `DIP-PQ-3` 256-bit `PQ_STAKING_VAULT` (`74` bytes, two-tier `SHA-256` commitments),
//! - Pure-Rust BIP-350 `Bech32m` (`0x2bc830a3`) address encoding/decoding across
//!   `"divi"`, `"tdivi"`, `"rdivi"`, `"pdivi"`, and `"tpdivi"`, and
//! - Segregated post-quantum witness stack framing (`PqWitnessStack` / `PqInputWitness`),
//!   `wtxid` (`SHA256d(txid || witness_merkle_root)`), and witness weight accounting.
//!
//! # Classical Vault Script Structure (`50` bytes)
//!
//! ```text
//! OP_IF
//!     <20-byte ownerPubKeyHash>
//! OP_ELSE
//!     OP_REQUIRE_COINSTAKE <20-byte vaultPubKeyHash>
//! OP_ENDIF
//! OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
//! ```
//!
//! # Post-Quantum Vault Script Structure (`DIP-PQ-3`, `74` bytes)
//!
//! ```text
//! OP_IF (0x63)
//!     PUSH32 (0x20) <32-byte ownerKeyHash256>
//! OP_ELSE (0x67)
//!     OP_REQUIRE_COINSTAKE (0xb9) PUSH32 (0x20) <32-byte vaultKeyHash256>
//! OP_ENDIF (0x68)
//! OP_OVER (0x78) OP_SHA256 (0xa8) OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
//! ```

use crate::opcodes::Opcode;
use divi_primitives::script::Script;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Exact byte length of a canonical `DIP-PQ-3` `P2PQPKH` `scriptPubKey` (`OP_1 0x20 <32B>`).
pub const P2PQPKH_SCRIPT_LEN: usize = 34;

/// Exact byte length of a canonical `DIP-PQ-3` `PQ_STAKING_VAULT` `scriptPubKey` (`74` bytes).
pub const PQ_STAKING_VAULT_SCRIPT_LEN: usize = 74;

/// Witness version `1` (`OP_1`) identifying a 32-byte `P2PQPKH` address/script program (`DIP-PQ-3` §3.1).
pub const PQ_WITNESS_VERSION_P2PQPKH: u8 = 1;

/// Witness version `2` (`OP_2`) identifying a 64-byte `PQ_STAKING_VAULT` address program (`DIP-PQ-3` §3.2).
pub const PQ_WITNESS_VERSION_VAULT: u8 = 2;

/// BIP-350 `Bech32m` polymod constant (`0x2bc830a3`, `DIP-PQ-3` §4.1).
pub const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Legacy BIP-173 `Bech32` polymod constant (`1`), explicitly rejected by `DIP-PQ-3` decoders.
const BECH32_LEGACY_CONST: u32 = 1;

/// Maximum byte size of a single segregated post-quantum witness stack item (`8,192 B`, `DIP-PQ-3` §2.2).
///
/// Accommodates `SLH-DSA-128s` (`7,856 B` signature + `1 B` `scheme_id` + `1 B` `sighash_type` = `7,858 B`),
/// `ML-DSA-44` (`2,420 B` signature / `1,312 B` pubkey), and `FN-DSA-512` (`897 B` pubkey / `666 B` signature).
pub const MAX_PQ_WITNESS_ITEM_SIZE: usize = 8_192;

/// Maximum total serialized witness bytes permitted for a single transaction input (`16,384 B`, `DIP-PQ-3` §2.2).
pub const MAX_PQ_TX_WITNESS_BYTES: usize = 16_384;

/// Maximum number of stack items permitted in a single post-quantum input witness (`8`, `DIP-PQ-3` §2.2).
pub const MAX_PQ_WITNESS_STACK_ITEMS: usize = 8;

/// Base-byte weight multiplier (`base_bytes * 4 + witness_bytes`, `DIP-PQ-3` §2.5).
pub const PQ_WITNESS_SCALE_FACTOR: usize = 4;

/// Maximum total block weight (`8,000,000` weight units inside Divi's `2 MB` block cap, `DIP-PQ-3` §2.5).
pub const MAX_PQ_BLOCK_WEIGHT: usize = 8_000_000;

/// Maximum raw serialized block size (`2,000,000` bytes = `MAX_BLOCK_SIZE_CURRENT`, `DIP-PQ-3` §2.5).
pub const MAX_PQ_BLOCK_RAW_BYTES: usize = 2_000_000;

/// Maximum string length of a `DIP-PQ-3` `Bech32m` address (`128` chars to accommodate `64`-byte `v2` vault programs).
const MAX_PQ_BECH32M_STRING_LEN: usize = 128;

/// Bech32/Bech32m 32-character alphabet (`BIP-173` / `BIP-350`).
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Reverse lookup table mapping ASCII `0x00..=0x7f` to 5-bit Bech32 character values (`-1` if invalid).
const BECH32_CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

/// Staking vault script data (classical `Hash160` 20-byte commitments)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingVaultScript {
    /// Hash of the owner's public key (full spending control)
    pub owner_pubkey_hash: [u8; 20],
    /// Hash of the vault's public key (staking only - requires coinstake)
    pub vault_pubkey_hash: [u8; 20],
    /// Optional: Hash of the reward destination key (for DIP-001 extended vaults)
    pub reward_destination_hash: Option<[u8; 20]>,
}

impl StakingVaultScript {
    /// Create a new 2-key staking vault script
    pub fn new(owner_pubkey_hash: [u8; 20], vault_pubkey_hash: [u8; 20]) -> Self {
        StakingVaultScript {
            owner_pubkey_hash,
            vault_pubkey_hash,
            reward_destination_hash: None,
        }
    }

    /// Create a new 3-key staking vault script (DIP-001)
    pub fn new_extended(
        owner_pubkey_hash: [u8; 20],
        vault_pubkey_hash: [u8; 20],
        reward_destination_hash: [u8; 20],
    ) -> Self {
        StakingVaultScript {
            owner_pubkey_hash,
            vault_pubkey_hash,
            reward_destination_hash: Some(reward_destination_hash),
        }
    }

    /// Build the script bytes for a 2-key vault
    pub fn to_script(&self) -> Script {
        let mut bytes = Vec::new();

        // OP_IF <ownerPubKeyHash>
        bytes.push(Opcode::OP_IF as u8);
        bytes.push(0x14); // Push 20 bytes
        bytes.extend_from_slice(&self.owner_pubkey_hash);

        // OP_ELSE OP_REQUIRE_COINSTAKE <vaultPubKeyHash>
        bytes.push(Opcode::OP_ELSE as u8);
        bytes.push(Opcode::OP_REQUIRE_COINSTAKE as u8);
        bytes.push(0x14); // Push 20 bytes
        bytes.extend_from_slice(&self.vault_pubkey_hash);

        // OP_ENDIF
        bytes.push(Opcode::OP_ENDIF as u8);

        // OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
        bytes.push(Opcode::OP_OVER as u8);
        bytes.push(Opcode::OP_HASH160 as u8);
        bytes.push(Opcode::OP_EQUALVERIFY as u8);
        bytes.push(Opcode::OP_CHECKSIG as u8);

        Script::from_bytes(bytes)
    }

    /// Parse a vault script from bytes
    ///
    /// Returns None if the script is not a valid staking vault script.
    pub fn from_script(script: &Script) -> Option<Self> {
        let bytes = script.as_bytes();

        // Minimum length check
        // OP_IF(1) + push(1) + hash(20) + OP_ELSE(1) + OP_REQUIRE_COINSTAKE(1)
        // + push(1) + hash(20) + OP_ENDIF(1) + OP_OVER(1) + OP_HASH160(1)
        // + OP_EQUALVERIFY(1) + OP_CHECKSIG(1) = 50 bytes
        if bytes.len() < 50 {
            return None;
        }

        let mut pos = 0;

        // Check OP_IF
        if bytes.get(pos)? != &(Opcode::OP_IF as u8) {
            return None;
        }
        pos += 1;

        // Check push 20 bytes (owner hash)
        if bytes.get(pos)? != &0x14 {
            return None;
        }
        pos += 1;

        // Read owner pubkey hash
        if pos + 20 > bytes.len() {
            return None;
        }
        let mut owner_hash = [0u8; 20];
        owner_hash.copy_from_slice(&bytes[pos..pos + 20]);
        pos += 20;

        // Check OP_ELSE
        if bytes.get(pos)? != &(Opcode::OP_ELSE as u8) {
            return None;
        }
        pos += 1;

        // Check OP_REQUIRE_COINSTAKE
        if bytes.get(pos)? != &(Opcode::OP_REQUIRE_COINSTAKE as u8) {
            return None;
        }
        pos += 1;

        // Check push 20 bytes (vault hash)
        if bytes.get(pos)? != &0x14 {
            return None;
        }
        pos += 1;

        // Read vault pubkey hash
        if pos + 20 > bytes.len() {
            return None;
        }
        let mut vault_hash = [0u8; 20];
        vault_hash.copy_from_slice(&bytes[pos..pos + 20]);
        pos += 20;

        // Check OP_ENDIF
        if bytes.get(pos)? != &(Opcode::OP_ENDIF as u8) {
            return None;
        }
        pos += 1;

        // Check OP_OVER
        if bytes.get(pos)? != &(Opcode::OP_OVER as u8) {
            return None;
        }
        pos += 1;

        // Check OP_HASH160
        if bytes.get(pos)? != &(Opcode::OP_HASH160 as u8) {
            return None;
        }
        pos += 1;

        // Check OP_EQUALVERIFY
        if bytes.get(pos)? != &(Opcode::OP_EQUALVERIFY as u8) {
            return None;
        }
        pos += 1;

        // Check OP_CHECKSIG
        if bytes.get(pos)? != &(Opcode::OP_CHECKSIG as u8) {
            return None;
        }
        pos += 1;

        // Should have consumed all bytes
        if pos != bytes.len() {
            return None;
        }

        Some(StakingVaultScript::new(owner_hash, vault_hash))
    }
}

/// Check if a script is a classical 20-byte `Hash160` staking vault script (`50` bytes)
pub fn is_staking_vault_script(script: &Script) -> bool {
    StakingVaultScript::from_script(script).is_some()
}

/// Extract the 20-byte `Hash160` pubkey hashes from a classical staking vault script
pub fn get_vault_pubkey_hashes(script: &Script) -> Option<([u8; 20], [u8; 20])> {
    StakingVaultScript::from_script(script).map(|v| (v.owner_pubkey_hash, v.vault_pubkey_hash))
}

// ============================================================================
// DIP-PQ-3: 256-Bit P2PQPKH & PQ_STAKING_VAULT Script Templates
// ============================================================================

/// Build a canonical `34`-byte `P2PQPKH` (`Pay-to-Post-Quantum-Public-Key-Hash`) output script
/// (`DIP-PQ-3` §3.1):
///
/// `OP_1 (0x51) || PUSH32 (0x20) || addr_key_hash_256[32]`
pub fn create_p2pqpkh_script(addr_key_hash_256: &[u8; 32]) -> Script {
    let mut bytes = Vec::with_capacity(P2PQPKH_SCRIPT_LEN);
    bytes.push(Opcode::OP_1 as u8);
    bytes.push(0x20); // Direct 32-byte push
    bytes.extend_from_slice(addr_key_hash_256);
    Script::from_bytes(bytes)
}

/// Check whether `script` is a canonical `34`-byte `DIP-PQ-3` `P2PQPKH` output script,
/// returning the 32-byte `addr_key_hash_256` commitment if valid.
pub fn is_p2pqpkh_script(script: &Script) -> Option<[u8; 32]> {
    let bytes = script.as_bytes();
    if bytes.len() != P2PQPKH_SCRIPT_LEN {
        return None;
    }
    if bytes[0] != (Opcode::OP_1 as u8) || bytes[1] != 0x20 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[2..34]);
    Some(hash)
}

/// Post-Quantum 2-key Staking Vault script (`DIP-PQ-3` §3.2, `74` bytes).
///
/// Upgrades Divi's two-tier `STAKING_VAULT` (`ownerKeyHash` / `vaultKeyHash` + `OP_REQUIRE_COINSTAKE`)
/// from 160-bit `Hash160` (`2^80` Grover preimage) to full 256-bit `SHA-256` commitments
/// (`pq_address_key_hash_256`, `2^128` Grover preimage):
///
/// ```text
/// [0]      0x63  OP_IF
/// [1]      0x20  PUSH32
/// [2..34]        <owner_pubkey_hash_256: 32 B>
/// [34]     0x67  OP_ELSE
/// [35]     0xb9  OP_REQUIRE_COINSTAKE
/// [36]     0x20  PUSH32
/// [37..69]       <vault_pubkey_hash_256: 32 B>
/// [69]     0x68  OP_ENDIF
/// [70]     0x78  OP_OVER
/// [71]     0xa8  OP_SHA256
/// [72]     0x88  OP_EQUALVERIFY
/// [73]     0xac  OP_CHECKSIG
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PqStakingVaultScript {
    /// 32-byte `DIP-PQ-1` `pq_address_key_hash_256` of the cold owner key (`OP_IF` spend branch).
    pub owner_pubkey_hash_256: [u8; 32],
    /// 32-byte `DIP-PQ-1` `pq_address_key_hash_256` of the hot coinstake manager key (`OP_ELSE` branch).
    pub vault_pubkey_hash_256: [u8; 32],
}

impl PqStakingVaultScript {
    /// Construct a new 256-bit post-quantum staking vault script descriptor.
    pub const fn new(owner_pubkey_hash_256: [u8; 32], vault_pubkey_hash_256: [u8; 32]) -> Self {
        Self {
            owner_pubkey_hash_256,
            vault_pubkey_hash_256,
        }
    }

    /// Serialize the canonical `74`-byte `PQ_STAKING_VAULT` `scriptPubKey`.
    pub fn to_script(&self) -> Script {
        let mut bytes = Vec::with_capacity(PQ_STAKING_VAULT_SCRIPT_LEN);

        // OP_IF (0x63) PUSH32 (0x20) <owner_pubkey_hash_256: 32B>
        bytes.push(Opcode::OP_IF as u8);
        bytes.push(0x20);
        bytes.extend_from_slice(&self.owner_pubkey_hash_256);

        // OP_ELSE (0x67) OP_REQUIRE_COINSTAKE (0xb9) PUSH32 (0x20) <vault_pubkey_hash_256: 32B>
        bytes.push(Opcode::OP_ELSE as u8);
        bytes.push(Opcode::OP_REQUIRE_COINSTAKE as u8);
        bytes.push(0x20);
        bytes.extend_from_slice(&self.vault_pubkey_hash_256);

        // OP_ENDIF (0x68)
        bytes.push(Opcode::OP_ENDIF as u8);

        // OP_OVER (0x78) OP_SHA256 (0xa8) OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
        bytes.push(Opcode::OP_OVER as u8);
        bytes.push(Opcode::OP_SHA256 as u8);
        bytes.push(Opcode::OP_EQUALVERIFY as u8);
        bytes.push(Opcode::OP_CHECKSIG as u8);

        Script::from_bytes(bytes)
    }

    /// Parse a canonical `74`-byte `PQ_STAKING_VAULT` script, returning `None` on any length
    /// or opcode mismatch.
    pub fn from_script(script: &Script) -> Option<Self> {
        let bytes = script.as_bytes();
        if bytes.len() != PQ_STAKING_VAULT_SCRIPT_LEN {
            return None;
        }
        if bytes[0] != (Opcode::OP_IF as u8)
            || bytes[1] != 0x20
            || bytes[34] != (Opcode::OP_ELSE as u8)
            || bytes[35] != (Opcode::OP_REQUIRE_COINSTAKE as u8)
            || bytes[36] != 0x20
            || bytes[69] != (Opcode::OP_ENDIF as u8)
            || bytes[70] != (Opcode::OP_OVER as u8)
            || bytes[71] != (Opcode::OP_SHA256 as u8)
            || bytes[72] != (Opcode::OP_EQUALVERIFY as u8)
            || bytes[73] != (Opcode::OP_CHECKSIG as u8)
        {
            return None;
        }

        let mut owner_hash = [0u8; 32];
        owner_hash.copy_from_slice(&bytes[2..34]);
        let mut vault_hash = [0u8; 32];
        vault_hash.copy_from_slice(&bytes[37..69]);

        Some(Self::new(owner_hash, vault_hash))
    }
}

/// Create a canonical `74`-byte `PQ_STAKING_VAULT` `scriptPubKey` from 32-byte `owner_hash_256`
/// and `vault_hash_256` commitments (`DIP-PQ-3` §3.2).
pub fn create_pq_staking_vault_script(
    owner_hash_256: &[u8; 32],
    vault_hash_256: &[u8; 32],
) -> Script {
    PqStakingVaultScript::new(*owner_hash_256, *vault_hash_256).to_script()
}

/// Check whether `script` is a canonical `74`-byte `PQ_STAKING_VAULT` output script, returning
/// `Some((owner_hash_256, vault_hash_256))` if valid.
pub fn is_pq_staking_vault_script(script: &Script) -> Option<([u8; 32], [u8; 32])> {
    PqStakingVaultScript::from_script(script)
        .map(|v| (v.owner_pubkey_hash_256, v.vault_pubkey_hash_256))
}

/// Alias for [`is_pq_staking_vault_script`] mirroring [`get_vault_pubkey_hashes`].
pub fn get_pq_vault_pubkey_hashes(script: &Script) -> Option<([u8; 32], [u8; 32])> {
    is_pq_staking_vault_script(script)
}

// ============================================================================
// DIP-PQ-3: Pure-Rust BIP-350 Bech32m 256-Bit PQ Address Encoding
// ============================================================================

/// Canonical Human-Readable Part (`hrp`) prefixes for `DIP-PQ-3` `Bech32m` addresses (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqAddressHrp {
    /// Divi Mainnet (`"divi"`, `divi1...`)
    DiviMainnet,
    /// Divi Testnet (`"tdivi"`, `tdivi1...`)
    DiviTestnet,
    /// Divi Regtest (`"rdivi"`, `rdivi1...`)
    DiviRegtest,
    /// PrivateDivi Mainnet (`"pdivi"`, `pdivi1...`)
    PrivateDiviMainnet,
    /// PrivateDivi Testnet (`"tpdivi"`, `tpdivi1...`)
    PrivateDiviTestnet,
}

impl PqAddressHrp {
    /// Return the canonical lowercase ASCII HRP string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiviMainnet => "divi",
            Self::DiviTestnet => "tdivi",
            Self::DiviRegtest => "rdivi",
            Self::PrivateDiviMainnet => "pdivi",
            Self::PrivateDiviTestnet => "tpdivi",
        }
    }

    /// Parse a lowercase HRP string (`"divi"`, `"tdivi"`, `"rdivi"`, `"pdivi"`, `"tpdivi"`).
    pub fn parse_hrp(hrp: &str) -> Result<Self, PqAddressError> {
        match hrp {
            "divi" => Ok(Self::DiviMainnet),
            "tdivi" => Ok(Self::DiviTestnet),
            "rdivi" => Ok(Self::DiviRegtest),
            "pdivi" => Ok(Self::PrivateDiviMainnet),
            "tpdivi" => Ok(Self::PrivateDiviTestnet),
            other => Err(PqAddressError::UnknownHrp(other.to_string())),
        }
    }
}

/// Errors returned when encoding or decoding a `DIP-PQ-3` `Bech32m` post-quantum address.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PqAddressError {
    #[error("empty or oversized Bech32m address string (len = {0})")]
    InvalidStringLength(usize),

    #[error("mixed-case Bech32m address is forbidden by BIP-173/BIP-350")]
    MixedCase,

    #[error("missing or misplaced '1' separator in Bech32m address")]
    MissingSeparator,

    #[error("unknown Divi/PrivateDivi Bech32m HRP: {0}")]
    UnknownHrp(String),

    #[error("invalid Bech32m character '{0}' at index {1}")]
    InvalidCharacter(char, usize),

    #[error("Bech32m checksum mismatch (expected BIP-350 constant 0x2bc830a3)")]
    ChecksumMismatch,

    #[error(
        "legacy BIP-173 Bech32 checksum is forbidden for v1+ PQ addresses; use BIP-350 Bech32m"
    )]
    LegacyBech32Forbidden,

    #[error(
        "unsupported PQ witness version {0} (DIP-PQ-3 permits v1 = P2PQPKH, v2 = PQ_STAKING_VAULT)"
    )]
    UnsupportedWitnessVersion(u8),

    #[error("invalid witness program length {actual} for witness version {version} (expected {expected})")]
    InvalidProgramLength {
        version: u8,
        expected: usize,
        actual: usize,
    },

    #[error("non-canonical 5-bit to 8-bit Bech32m padding")]
    InvalidPadding,
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, &g) in GEN.iter().enumerate() {
            if ((top >> i) & 1) != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 0x1f);
    }
    out
}

fn create_bech32m_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&values) ^ BECH32M_CONST;
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((polymod >> (5 * (5 - i))) & 0x1f) as u8;
    }
    out
}

fn verify_bech32m_checksum(hrp: &str, data_with_checksum: &[u8]) -> Result<(), PqAddressError> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data_with_checksum);
    let residue = bech32_polymod(&values);
    if residue == BECH32M_CONST {
        Ok(())
    } else if residue == BECH32_LEGACY_CONST {
        Err(PqAddressError::LegacyBech32Forbidden)
    } else {
        Err(PqAddressError::ChecksumMismatch)
    }
}

fn convert_bits(
    data: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, PqAddressError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to_bits) - 1;
    let max_acc: u32 = (1 << (from_bits + to_bits - 1)) - 1;
    let mut ret =
        Vec::with_capacity((data.len() * (from_bits as usize)).div_ceil(to_bits as usize));

    for &value in data {
        let v = u32::from(value);
        if (v >> from_bits) != 0 {
            return Err(PqAddressError::InvalidPadding);
        }
        acc = ((acc << from_bits) | v) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(PqAddressError::InvalidPadding);
    }

    Ok(ret)
}

fn validate_witness_program_len(version: u8, len: usize) -> Result<(), PqAddressError> {
    let expected = match version {
        PQ_WITNESS_VERSION_P2PQPKH => 32,
        PQ_WITNESS_VERSION_VAULT => 64,
        other => return Err(PqAddressError::UnsupportedWitnessVersion(other)),
    };
    if len != expected {
        return Err(PqAddressError::InvalidProgramLength {
            version,
            expected,
            actual: len,
        });
    }
    Ok(())
}

/// Encode a `DIP-PQ-3` post-quantum witness address using BIP-350 `Bech32m` (`0x2bc830a3`).
///
/// - `witness_version == 1` (`P2PQPKH`): requires `program.len() == 32` (`addr_key_hash_256`).
/// - `witness_version == 2` (`PQ_STAKING_VAULT`): requires `program.len() == 64` (`owner_hash_256 || vault_hash_256`).
pub fn encode_pq_bech32m_address(
    hrp: PqAddressHrp,
    witness_version: u8,
    program: &[u8],
) -> Result<String, PqAddressError> {
    validate_witness_program_len(witness_version, program.len())?;

    let hrp_str = hrp.as_str();
    let mut five_bit_data = Vec::with_capacity(1 + (program.len() * 8).div_ceil(5));
    five_bit_data.push(witness_version);
    five_bit_data.extend(convert_bits(program, 8, 5, true)?);

    let checksum = create_bech32m_checksum(hrp_str, &five_bit_data);

    let mut out = String::with_capacity(hrp_str.len() + 1 + five_bit_data.len() + 6);
    out.push_str(hrp_str);
    out.push('1');
    for &u in five_bit_data.iter().chain(checksum.iter()) {
        out.push(BECH32_CHARSET[usize::from(u)] as char);
    }
    Ok(out)
}

/// Decode and verify a `DIP-PQ-3` BIP-350 `Bech32m` post-quantum address into
/// `(hrp, witness_version, program_bytes)`.
pub fn decode_pq_bech32m_address(
    addr: &str,
) -> Result<(PqAddressHrp, u8, Vec<u8>), PqAddressError> {
    let len = addr.len();
    if !(8..=MAX_PQ_BECH32M_STRING_LEN).contains(&len) {
        return Err(PqAddressError::InvalidStringLength(len));
    }

    let mut has_lower = false;
    let mut has_upper = false;
    for b in addr.bytes() {
        if !(33..=126).contains(&b) {
            return Err(PqAddressError::InvalidCharacter(b as char, 0));
        }
        if b.is_ascii_lowercase() {
            has_lower = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    if has_lower && has_upper {
        return Err(PqAddressError::MixedCase);
    }

    let lower = addr.to_ascii_lowercase();
    let sep_pos = lower.rfind('1').ok_or(PqAddressError::MissingSeparator)?;
    if sep_pos == 0 || sep_pos + 7 > lower.len() {
        return Err(PqAddressError::MissingSeparator);
    }

    let hrp_str = &lower[..sep_pos];
    let hrp = PqAddressHrp::parse_hrp(hrp_str)?;

    let data_part = &lower[sep_pos + 1..];
    let mut data_u5 = Vec::with_capacity(data_part.len());
    for (idx, ch) in data_part.chars().enumerate() {
        let code = ch as usize;
        if code >= 128 {
            return Err(PqAddressError::InvalidCharacter(ch, sep_pos + 1 + idx));
        }
        let val = BECH32_CHARSET_REV[code];
        if val < 0 {
            return Err(PqAddressError::InvalidCharacter(ch, sep_pos + 1 + idx));
        }
        data_u5.push(val as u8);
    }

    verify_bech32m_checksum(hrp_str, &data_u5)?;

    let payload_u5 = &data_u5[..data_u5.len() - 6];
    let witness_version = payload_u5[0];
    let program = convert_bits(&payload_u5[1..], 5, 8, false)?;
    validate_witness_program_len(witness_version, program.len())?;

    Ok((hrp, witness_version, program))
}

/// Encode a `32`-byte `P2PQPKH` address (`witness_version = 1`) for the given network `hrp`.
pub fn encode_p2pqpkh_address(
    hrp: PqAddressHrp,
    addr_key_hash_256: &[u8; 32],
) -> Result<String, PqAddressError> {
    encode_pq_bech32m_address(hrp, PQ_WITNESS_VERSION_P2PQPKH, addr_key_hash_256)
}

/// Encode a `64`-byte `PQ_STAKING_VAULT` address (`witness_version = 2`,
/// `owner_hash_256 || vault_hash_256`) for the given network `hrp`.
pub fn encode_pq_vault_address(
    hrp: PqAddressHrp,
    owner_hash_256: &[u8; 32],
    vault_hash_256: &[u8; 32],
) -> Result<String, PqAddressError> {
    let mut program = [0u8; 64];
    program[..32].copy_from_slice(owner_hash_256);
    program[32..64].copy_from_slice(vault_hash_256);
    encode_pq_bech32m_address(hrp, PQ_WITNESS_VERSION_VAULT, &program)
}

/// Convert a `DIP-PQ-3` `Bech32m` address directly into its `(hrp, scriptPubKey)` pair
/// (`34`-byte `P2PQPKH` for `v1`, `74`-byte `PQ_STAKING_VAULT` for `v2`).
pub fn pq_address_to_script_pubkey(addr: &str) -> Result<(PqAddressHrp, Script), PqAddressError> {
    let (hrp, version, program) = decode_pq_bech32m_address(addr)?;
    match version {
        PQ_WITNESS_VERSION_P2PQPKH => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&program);
            Ok((hrp, create_p2pqpkh_script(&hash)))
        }
        PQ_WITNESS_VERSION_VAULT => {
            let mut owner = [0u8; 32];
            let mut vault = [0u8; 32];
            owner.copy_from_slice(&program[..32]);
            vault.copy_from_slice(&program[32..64]);
            Ok((hrp, create_pq_staking_vault_script(&owner, &vault)))
        }
        other => Err(PqAddressError::UnsupportedWitnessVersion(other)),
    }
}

/// Convert a `P2PQPKH` (`34 B`) or `PQ_STAKING_VAULT` (`74 B`) `scriptPubKey` into its
/// canonical `Bech32m` address for `hrp`.
pub fn script_pubkey_to_pq_address(hrp: PqAddressHrp, script: &Script) -> Option<String> {
    if let Some(addr_hash) = is_p2pqpkh_script(script) {
        return encode_p2pqpkh_address(hrp, &addr_hash).ok();
    }
    if let Some((owner_hash, vault_hash)) = is_pq_staking_vault_script(script) {
        return encode_pq_vault_address(hrp, &owner_hash, &vault_hash).ok();
    }
    None
}

// ============================================================================
// DIP-PQ-3: Segregated Post-Quantum Witness Framing & Weight Accounting (P3.1)
// ============================================================================

/// Errors returned when validating or deserializing segregated post-quantum witness stacks.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PqWitnessError {
    #[error("PQ witness stack item count {actual} exceeds MAX_PQ_WITNESS_STACK_ITEMS ({max})")]
    TooManyStackItems { actual: usize, max: usize },

    #[error("PQ witness item #{index} size {actual} B exceeds MAX_PQ_WITNESS_ITEM_SIZE ({max} B)")]
    ItemTooLarge {
        index: usize,
        actual: usize,
        max: usize,
    },

    #[error(
        "PQ input witness serialized size {actual} B exceeds MAX_PQ_TX_WITNESS_BYTES ({max} B)"
    )]
    InputWitnessTooLarge { actual: usize, max: usize },

    #[error("unexpected end of buffer while deserializing PQ witness stack")]
    UnexpectedEof,

    #[error("non-canonical CompactSize encoding in PQ witness stack")]
    NonCanonicalCompactSize,

    #[error("trailing bytes ({0} B) after canonical PQ witness stack")]
    TrailingBytes(usize),

    #[error(
        "block weight {weight} WU (base {base_bytes} B, witness {witness_bytes} B) exceeds limit"
    )]
    BlockWeightExceeded {
        base_bytes: usize,
        witness_bytes: usize,
        weight: usize,
    },
}

fn compact_size_len(n: usize) -> usize {
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

fn write_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

fn read_compact_size(bytes: &[u8], pos: &mut usize) -> Result<usize, PqWitnessError> {
    let first = *bytes.get(*pos).ok_or(PqWitnessError::UnexpectedEof)?;
    *pos += 1;
    match first {
        0x00..=0xfc => Ok(usize::from(first)),
        0xfd => {
            if *pos + 2 > bytes.len() {
                return Err(PqWitnessError::UnexpectedEof);
            }
            let val = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
            *pos += 2;
            if val < 0xfd {
                return Err(PqWitnessError::NonCanonicalCompactSize);
            }
            Ok(val)
        }
        0xfe => {
            if *pos + 4 > bytes.len() {
                return Err(PqWitnessError::UnexpectedEof);
            }
            let val = u32::from_le_bytes([
                bytes[*pos],
                bytes[*pos + 1],
                bytes[*pos + 2],
                bytes[*pos + 3],
            ]) as usize;
            *pos += 4;
            if val <= 0xffff {
                return Err(PqWitnessError::NonCanonicalCompactSize);
            }
            Ok(val)
        }
        0xff => {
            if *pos + 8 > bytes.len() {
                return Err(PqWitnessError::UnexpectedEof);
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[*pos..*pos + 8]);
            *pos += 8;
            let val_u64 = u64::from_le_bytes(raw);
            if val_u64 <= 0xffff_ffff {
                return Err(PqWitnessError::NonCanonicalCompactSize);
            }
            usize::try_from(val_u64).map_err(|_| PqWitnessError::NonCanonicalCompactSize)
        }
    }
}

fn double_sha256_bytes(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// Segregated post-quantum witness stack for a single transaction input (`DIP-PQ-3` §2.1).
///
/// Legacy `scriptSig` imposes `MAX_SCRIPT_ELEMENT_SIZE = 520` bytes per push, which cannot hold
/// `ML-DSA-44` (`1,312 B` pubkey + `2,420 B` signature), `FN-DSA-512` (`897 B` pubkey + `666 B`
/// signature), or `SLH-DSA-128s` (`7,856 B` signature). `PqInputWitness` carries these items
/// outside `scriptSig` (keeping `scriptSig` empty for `P2PQPKH` and `PQ_STAKING_VAULT` spends)
/// under `MAX_PQ_WITNESS_ITEM_SIZE = 8,192 B` and `MAX_PQ_TX_WITNESS_BYTES = 16,384 B`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PqInputWitness {
    /// Ordered stack elements (bottom-to-top) supplied by the spending input.
    pub items: Vec<Vec<u8>>,
}

/// Canonical type alias matching `DIP-PQ-3` specification terminology (`PqWitnessStack`).
pub type PqWitnessStack = PqInputWitness;

impl PqInputWitness {
    /// Construct an empty witness stack (used by classical `secp256k1` inputs and coinbase).
    pub const fn empty() -> Self {
        Self { items: Vec::new() }
    }

    /// Construct a witness stack from a vector of raw byte items.
    pub fn from_items(items: Vec<Vec<u8>>) -> Self {
        Self { items }
    }

    /// Construct a canonical 2-item `P2PQPKH` witness stack:
    /// `[scheme_id || sig || sighash_type, scheme_id || pubkey]`.
    pub fn for_p2pqpkh(scheme_id: u8, pubkey: &[u8], signature: &[u8], sighash_type: u8) -> Self {
        let mut sig_item = Vec::with_capacity(1 + signature.len() + 1);
        sig_item.push(scheme_id);
        sig_item.extend_from_slice(signature);
        sig_item.push(sighash_type);

        let mut pk_item = Vec::with_capacity(1 + pubkey.len());
        pk_item.push(scheme_id);
        pk_item.extend_from_slice(pubkey);

        Self {
            items: vec![sig_item, pk_item],
        }
    }

    /// Construct a canonical 3-item `PQ_STAKING_VAULT` witness stack:
    /// `[scheme_id || sig || sighash_type, scheme_id || pubkey, branch_selector]`,
    /// where `branch_selector` is `[0x01]` for cold owner spend (`OP_IF`) or `[]` (`OP_0`) for
    /// hot coinstake manager spend (`OP_ELSE OP_REQUIRE_COINSTAKE`).
    pub fn for_pq_vault(
        is_owner_spend: bool,
        scheme_id: u8,
        pubkey: &[u8],
        signature: &[u8],
        sighash_type: u8,
    ) -> Self {
        let mut stack = Self::for_p2pqpkh(scheme_id, pubkey, signature, sighash_type);
        if is_owner_spend {
            stack.items.push(vec![0x01]);
        } else {
            stack.items.push(Vec::new());
        }
        stack
    }

    /// Returns `true` when this input carries zero witness items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Total raw payload bytes across all items (excluding CompactSize length prefixes).
    pub fn total_item_bytes(&self) -> usize {
        self.items.iter().map(Vec::len).sum()
    }

    /// Exact canonical wire byte length (`CompactSize(item_count) + sum(CompactSize(|item|) + |item|)`).
    pub fn serialized_size(&self) -> usize {
        let mut total = compact_size_len(self.items.len());
        for item in &self.items {
            total += compact_size_len(item.len()) + item.len();
        }
        total
    }

    /// Serialize this input witness stack using canonical `CompactSize` framing.
    pub fn serialize_canonical(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());
        write_compact_size(&mut buf, self.items.len());
        for item in &self.items {
            write_compact_size(&mut buf, item.len());
            buf.extend_from_slice(item);
        }
        buf
    }

    /// Deserialize a canonical `PqInputWitness` and validate `DIP-PQ-3` stack/item/byte bounds.
    pub fn deserialize_canonical(bytes: &[u8]) -> Result<Self, PqWitnessError> {
        if bytes.len() > MAX_PQ_TX_WITNESS_BYTES {
            return Err(PqWitnessError::InputWitnessTooLarge {
                actual: bytes.len(),
                max: MAX_PQ_TX_WITNESS_BYTES,
            });
        }
        let mut pos = 0;
        let count = read_compact_size(bytes, &mut pos)?;
        if count > MAX_PQ_WITNESS_STACK_ITEMS {
            return Err(PqWitnessError::TooManyStackItems {
                actual: count,
                max: MAX_PQ_WITNESS_STACK_ITEMS,
            });
        }
        let mut items = Vec::with_capacity(count);
        for index in 0..count {
            let item_len = read_compact_size(bytes, &mut pos)?;
            if item_len > MAX_PQ_WITNESS_ITEM_SIZE {
                return Err(PqWitnessError::ItemTooLarge {
                    index,
                    actual: item_len,
                    max: MAX_PQ_WITNESS_ITEM_SIZE,
                });
            }
            if pos + item_len > bytes.len() {
                return Err(PqWitnessError::UnexpectedEof);
            }
            items.push(bytes[pos..pos + item_len].to_vec());
            pos += item_len;
        }
        if pos != bytes.len() {
            return Err(PqWitnessError::TrailingBytes(bytes.len() - pos));
        }
        let witness = Self { items };
        validate_pq_witness_limits(&witness)?;
        Ok(witness)
    }

    /// Compute the 32-byte `SHA256d` leaf hash of this input witness stack (`DIP-PQ-3` §2.3).
    pub fn leaf_hash(&self) -> [u8; 32] {
        double_sha256_bytes(&self.serialize_canonical())
    }
}

/// Validate that a single `PqInputWitness` satisfies `MAX_PQ_WITNESS_STACK_ITEMS` (`8`),
/// `MAX_PQ_WITNESS_ITEM_SIZE` (`8,192 B`), and `MAX_PQ_TX_WITNESS_BYTES` (`16,384 B`).
pub fn validate_pq_witness_limits(witness: &PqInputWitness) -> Result<(), PqWitnessError> {
    if witness.items.len() > MAX_PQ_WITNESS_STACK_ITEMS {
        return Err(PqWitnessError::TooManyStackItems {
            actual: witness.items.len(),
            max: MAX_PQ_WITNESS_STACK_ITEMS,
        });
    }
    for (index, item) in witness.items.iter().enumerate() {
        if item.len() > MAX_PQ_WITNESS_ITEM_SIZE {
            return Err(PqWitnessError::ItemTooLarge {
                index,
                actual: item.len(),
                max: MAX_PQ_WITNESS_ITEM_SIZE,
            });
        }
    }
    let total_bytes = witness.serialized_size();
    if total_bytes > MAX_PQ_TX_WITNESS_BYTES {
        return Err(PqWitnessError::InputWitnessTooLarge {
            actual: total_bytes,
            max: MAX_PQ_TX_WITNESS_BYTES,
        });
    }
    Ok(())
}

/// Compute the 32-byte Bitcoin-style binary Merkle root over per-input `PqInputWitness::leaf_hash()`
/// digests (`DIP-PQ-3` §2.3). Returns `[0u8; 32]` when all input witnesses are empty.
pub fn compute_witness_merkle_root(witnesses: &[PqInputWitness]) -> [u8; 32] {
    if witnesses.is_empty() || witnesses.iter().all(PqInputWitness::is_empty) {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = witnesses.iter().map(PqInputWitness::leaf_hash).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().expect("non-empty layer");
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for [left, right] in layer.as_chunks::<2>().0 {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(left);
            combined[32..64].copy_from_slice(right);
            next.push(double_sha256_bytes(&combined));
        }
        layer = next;
    }
    layer[0]
}

/// Compute the `DIP-PQ-3` witness transaction identifier (`wtxid`, §2.4):
///
/// - If `witnesses` is empty or every `PqInputWitness` is empty, `wtxid == *txid` (preserving
///   full backward compatibility for classical transactions).
/// - Otherwise, `wtxid = SHA256d(txid[32] || witness_merkle_root[32])`.
pub fn compute_wtxid(txid: &[u8; 32], witnesses: &[PqInputWitness]) -> [u8; 32] {
    if witnesses.is_empty() || witnesses.iter().all(PqInputWitness::is_empty) {
        return *txid;
    }
    let witness_root = compute_witness_merkle_root(witnesses);
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(txid);
    preimage[32..64].copy_from_slice(&witness_root);
    double_sha256_bytes(&preimage)
}

/// Compute `DIP-PQ-3` transaction/block weight (`base_bytes * 4 + witness_bytes`, §2.5).
pub const fn compute_pq_tx_weight(base_bytes: usize, witness_bytes: usize) -> usize {
    base_bytes
        .saturating_mul(PQ_WITNESS_SCALE_FACTOR)
        .saturating_add(witness_bytes)
}

/// Enforce `DIP-PQ-3` block weight (`<= 8,000,000` WU) and raw block byte cap (`<= 2,000,000` B).
pub fn validate_pq_block_weight(
    base_bytes: usize,
    witness_bytes: usize,
) -> Result<usize, PqWitnessError> {
    let weight = compute_pq_tx_weight(base_bytes, witness_bytes);
    let raw_bytes = base_bytes.saturating_add(witness_bytes);
    if weight > MAX_PQ_BLOCK_WEIGHT || raw_bytes > MAX_PQ_BLOCK_RAW_BYTES {
        return Err(PqWitnessError::BlockWeightExceeded {
            base_bytes,
            witness_bytes,
            weight,
        });
    }
    Ok(weight)
}

/// Per-transaction segregated witness container (`DIP-PQ-3` §2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PqTxWitness {
    /// One witness stack per transaction input (`inputs.len() == tx.vin.len()`).
    pub inputs: Vec<PqInputWitness>,
}

impl PqTxWitness {
    /// Returns `true` if there are no non-empty input witness stacks.
    pub fn is_empty(&self) -> bool {
        self.inputs.iter().all(PqInputWitness::is_empty)
    }

    /// Total serialized witness byte count across all transaction inputs.
    pub fn total_serialized_bytes(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            self.inputs
                .iter()
                .map(PqInputWitness::serialized_size)
                .sum()
        }
    }

    /// Validate all per-input witness stacks against `DIP-PQ-3` consensus limits.
    pub fn validate_limits(&self) -> Result<(), PqWitnessError> {
        for input in &self.inputs {
            validate_pq_witness_limits(input)?;
        }
        Ok(())
    }

    /// Compute the 32-byte witness Merkle root across all inputs.
    pub fn witness_merkle_root(&self) -> [u8; 32] {
        compute_witness_merkle_root(&self.inputs)
    }

    /// Compute `wtxid` (`SHA256d(txid || witness_merkle_root)`) for this transaction.
    pub fn wtxid(&self, txid: &[u8; 32]) -> [u8; 32] {
        compute_wtxid(txid, &self.inputs)
    }
}

// ============================================================================
// Post-Quantum Staking Posture Classification (DIP-PQ-0 & DIP-PQ-3)
// ============================================================================

/// Post-quantum staking key-exposure classification (`DIP-PQ-0` §3.1–3.2 & `DIP-PQ-3` §3.3).
///
/// Every classical Proof-of-Stake block carries a compact recoverable `secp256k1` signature
/// (`vchBlockSig`), revealing the full 33-byte signing `CPubKey` on the first minted block:
/// - When staking via a classical 2-key `STAKING_VAULT` (`50 B`), a 256-bit `PQ_STAKING_VAULT`
///   (`74 B`), or a 256-bit `P2PQPKH` (`34 B`) output, the cold owner key / PQ public key remains
///   insulated behind a cryptographic hash (`Hash160` or 256-bit `SHA-256` `pq_address_key_hash_256`).
/// - When staking directly with classical `P2PKH` (or `P2PK`), `vchBlockSig` exposes the spending
///   `secp256k1` `CPubKey` on-chain to offline Shor discrete-logarithm recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StakingQuantumPosture {
    /// Vault-insulated or 256-bit PQ hash-insulated output (`STAKING_VAULT`, `PQ_STAKING_VAULT`,
    /// or `P2PQPKH`). For 256-bit `DIP-PQ-3` outputs, `owner_hash160` and `manager_hash160` carry
    /// the leading 20-byte fingerprint of the 32-byte `SHA-256` commitments.
    VaultInsulated {
        /// Cold owner `Hash160` (or leading 20-byte prefix of `owner_hash_256` / `addr_key_hash_256`)
        owner_hash160: [u8; 20],
        /// Hot manager `Hash160` (or leading 20-byte prefix of `vault_hash_256` / `addr_key_hash_256`)
        manager_hash160: [u8; 20],
    },
    /// Direct classical `P2PKH` (or other non-vault) staking output where `vchBlockSig` exposes the
    /// spending `secp256k1` `CPubKey` directly on-chain.
    DirectPubKeyExposed,
}

impl StakingQuantumPosture {
    /// Classify a `Script` into its post-quantum staking posture (`DIP-PQ-0` & `DIP-PQ-3`).
    pub fn from_script(script: &Script) -> Self {
        if let Some(vault) = StakingVaultScript::from_script(script) {
            StakingQuantumPosture::VaultInsulated {
                owner_hash160: vault.owner_pubkey_hash,
                manager_hash160: vault.vault_pubkey_hash,
            }
        } else if let Some((owner_hash_256, vault_hash_256)) = is_pq_staking_vault_script(script) {
            let mut owner_hash160 = [0u8; 20];
            let mut manager_hash160 = [0u8; 20];
            owner_hash160.copy_from_slice(&owner_hash_256[..20]);
            manager_hash160.copy_from_slice(&vault_hash_256[..20]);
            StakingQuantumPosture::VaultInsulated {
                owner_hash160,
                manager_hash160,
            }
        } else if let Some(addr_hash_256) = is_p2pqpkh_script(script) {
            let mut hash160 = [0u8; 20];
            hash160.copy_from_slice(&addr_hash_256[..20]);
            StakingQuantumPosture::VaultInsulated {
                owner_hash160: hash160,
                manager_hash160: hash160,
            }
        } else {
            StakingQuantumPosture::DirectPubKeyExposed
        }
    }

    /// Classify raw script bytes into their post-quantum staking posture.
    pub fn from_script_bytes(script_bytes: &[u8]) -> Self {
        let script = Script::from_bytes(script_bytes.to_vec());
        Self::from_script(&script)
    }

    /// Returns `true` if the staking output insulates the owner key via `STAKING_VAULT`,
    /// `PQ_STAKING_VAULT`, or `P2PQPKH`.
    pub fn is_vault_insulated(&self) -> bool {
        matches!(self, StakingQuantumPosture::VaultInsulated { .. })
    }

    /// Returns `true` if staking with this output directly exposes the spending `CPubKey`.
    pub fn is_direct_pubkey_exposed(&self) -> bool {
        matches!(self, StakingQuantumPosture::DirectPubKeyExposed)
    }

    /// Telemetry advisory label for `getstakingstatus` / `getdiaginfo` (`DIP-PQ-0` §3.2).
    pub fn advisory_label(&self) -> &'static str {
        match self {
            StakingQuantumPosture::VaultInsulated { .. } => "vault_only",
            StakingQuantumPosture::DirectPubKeyExposed => "mixed_or_direct_p2pkh",
        }
    }
}

/// Classify a staking UTXO `scriptPubKey` for post-quantum insulation (`DIP-PQ-0` & `DIP-PQ-3`).
pub fn classify_staking_script_posture(script: &Script) -> StakingQuantumPosture {
    StakingQuantumPosture::from_script(script)
}

/// Alias for [`classify_staking_script_posture`] (`DIP-PQ-3` §3.3).
pub fn classify_staking_quantum_posture(script: &Script) -> StakingQuantumPosture {
    StakingQuantumPosture::from_script(script)
}

/// Summarize aggregate `vault_insulation` telemetry across a collection of staking scripts.
///
/// Returns `"vault_only"` when all inspected scripts are vault/PQ-insulated outputs (and at least
/// one script is present), or `"mixed_or_direct_p2pkh"` if any exposed script is present.
pub fn summarize_staking_posture<'a, I>(scripts: I) -> &'static str
where
    I: IntoIterator<Item = &'a Script>,
{
    let mut saw_any = false;
    for script in scripts {
        saw_any = true;
        if !classify_staking_script_posture(script).is_vault_insulated() {
            return "mixed_or_direct_p2pkh";
        }
    }
    if saw_any {
        "vault_only"
    } else {
        "mixed_or_direct_p2pkh"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_crypto::pq::{pq_address_key_hash_256, PqSchemeId};

    #[test]
    fn test_vault_script_roundtrip() {
        let owner_hash = [1u8; 20];
        let vault_hash = [2u8; 20];

        let vault = StakingVaultScript::new(owner_hash, vault_hash);
        let script = vault.to_script();

        let parsed = StakingVaultScript::from_script(&script).expect("Should parse");
        assert_eq!(parsed.owner_pubkey_hash, owner_hash);
        assert_eq!(parsed.vault_pubkey_hash, vault_hash);
    }

    #[test]
    fn test_is_staking_vault_script() {
        let owner_hash = [1u8; 20];
        let vault_hash = [2u8; 20];

        let vault = StakingVaultScript::new(owner_hash, vault_hash);
        let script = vault.to_script();

        assert!(is_staking_vault_script(&script));

        // P2PKH should not be detected as vault
        let p2pkh = Script::new_p2pkh(&owner_hash);
        assert!(!is_staking_vault_script(&p2pkh));
    }

    #[test]
    fn test_vault_script_structure() {
        let owner_hash = [1u8; 20];
        let vault_hash = [2u8; 20];

        let vault = StakingVaultScript::new(owner_hash, vault_hash);
        let script = vault.to_script();
        let bytes = script.as_bytes();

        // Check structure
        assert_eq!(bytes[0], Opcode::OP_IF as u8);
        assert_eq!(bytes[1], 0x14); // Push 20
        assert_eq!(&bytes[2..22], &owner_hash);
        assert_eq!(bytes[22], Opcode::OP_ELSE as u8);
        assert_eq!(bytes[23], Opcode::OP_REQUIRE_COINSTAKE as u8);
        assert_eq!(bytes[24], 0x14); // Push 20
        assert_eq!(&bytes[25..45], &vault_hash);
        assert_eq!(bytes[45], Opcode::OP_ENDIF as u8);
        assert_eq!(bytes[46], Opcode::OP_OVER as u8);
        assert_eq!(bytes[47], Opcode::OP_HASH160 as u8);
        assert_eq!(bytes[48], Opcode::OP_EQUALVERIFY as u8);
        assert_eq!(bytes[49], Opcode::OP_CHECKSIG as u8);
        assert_eq!(bytes.len(), 50);
    }

    #[test]
    fn test_get_vault_pubkey_hashes() {
        let owner_hash = [0xaa; 20];
        let vault_hash = [0xbb; 20];

        let vault = StakingVaultScript::new(owner_hash, vault_hash);
        let script = vault.to_script();

        let (parsed_owner, parsed_vault) = get_vault_pubkey_hashes(&script).unwrap();
        assert_eq!(parsed_owner, owner_hash);
        assert_eq!(parsed_vault, vault_hash);
    }

    #[test]
    fn test_dip_pq_0_vector_3_vault_script_and_posture() {
        let owner_bytes = hex::decode("101112131415161718191a1b1c1d1e1f20212223").unwrap();
        let vault_bytes = hex::decode("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3").unwrap();
        let mut owner_hash = [0u8; 20];
        let mut vault_hash = [0u8; 20];
        owner_hash.copy_from_slice(&owner_bytes);
        vault_hash.copy_from_slice(&vault_bytes);

        let vault = StakingVaultScript::new(owner_hash, vault_hash);
        let script = vault.to_script();
        assert_eq!(
            hex::encode(script.as_bytes()),
            "6314101112131415161718191a1b1c1d1e1f2021222367b914a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b36878a988ac"
        );

        let posture = classify_staking_script_posture(&script);
        assert_eq!(
            posture,
            StakingQuantumPosture::VaultInsulated {
                owner_hash160: owner_hash,
                manager_hash160: vault_hash,
            }
        );
        assert!(posture.is_vault_insulated());
        assert!(!posture.is_direct_pubkey_exposed());
        assert_eq!(posture.advisory_label(), "vault_only");
    }

    #[test]
    fn test_staking_quantum_posture_p2pkh_vs_vault() {
        let owner_hash = [0x11; 20];
        let manager_hash = [0x22; 20];

        let vault_script = StakingVaultScript::new(owner_hash, manager_hash).to_script();
        let p2pkh_script = Script::new_p2pkh(&owner_hash);

        let vault_posture = StakingQuantumPosture::from_script(&vault_script);
        assert_eq!(
            vault_posture,
            StakingQuantumPosture::VaultInsulated {
                owner_hash160: owner_hash,
                manager_hash160: manager_hash,
            }
        );
        assert_eq!(
            StakingQuantumPosture::from_script_bytes(vault_script.as_bytes()),
            vault_posture
        );

        let p2pkh_posture = classify_staking_script_posture(&p2pkh_script);
        assert_eq!(p2pkh_posture, StakingQuantumPosture::DirectPubKeyExposed);
        assert!(p2pkh_posture.is_direct_pubkey_exposed());
        assert!(!p2pkh_posture.is_vault_insulated());
        assert_eq!(p2pkh_posture.advisory_label(), "mixed_or_direct_p2pkh");

        assert_eq!(summarize_staking_posture([&vault_script]), "vault_only");
        assert_eq!(
            summarize_staking_posture([&vault_script, &p2pkh_script]),
            "mixed_or_direct_p2pkh"
        );
        assert_eq!(
            summarize_staking_posture([&p2pkh_script]),
            "mixed_or_direct_p2pkh"
        );
    }

    // ========================================================================
    // DIP-PQ-3 Unit Tests (25 tests covering P2PQPKH, PQ_STAKING_VAULT,
    // Bech32m, Segregated PQ Witness Framing, wtxid, and Weight Accounting)
    // ========================================================================

    #[test]
    fn test_p2pqpkh_script_creation_and_extraction() {
        let pk_bytes = [0x42u8; 1312];
        let addr_hash = pq_address_key_hash_256(PqSchemeId::MlDsa44, &pk_bytes);
        let script = create_p2pqpkh_script(&addr_hash);

        assert_eq!(script.as_bytes().len(), P2PQPKH_SCRIPT_LEN);
        assert_eq!(script.as_bytes()[0], Opcode::OP_1 as u8);
        assert_eq!(script.as_bytes()[1], 0x20);
        assert_eq!(&script.as_bytes()[2..34], &addr_hash);
        assert_eq!(is_p2pqpkh_script(&script), Some(addr_hash));
        assert!(!is_staking_vault_script(&script));
        assert!(is_pq_staking_vault_script(&script).is_none());
    }

    #[test]
    fn test_p2pqpkh_rejects_malleated_lengths_and_opcodes() {
        let addr_hash = [0x55u8; 32];
        let valid = create_p2pqpkh_script(&addr_hash);

        // Wrong length (33 bytes or 35 bytes)
        let short = Script::from_bytes(valid.as_bytes()[..33].to_vec());
        assert!(is_p2pqpkh_script(&short).is_none());

        let mut trailing = valid.as_bytes().to_vec();
        trailing.push(0x00);
        assert!(is_p2pqpkh_script(&Script::from_bytes(trailing)).is_none());

        // Wrong witness version opcode (OP_0 or OP_2 instead of OP_1)
        let mut wrong_ver = valid.as_bytes().to_vec();
        wrong_ver[0] = Opcode::OP_0 as u8;
        assert!(is_p2pqpkh_script(&Script::from_bytes(wrong_ver)).is_none());

        // Non-minimal PUSHDATA1 0x20 instead of direct 0x20 push
        let mut non_minimal = vec![Opcode::OP_1 as u8, Opcode::OP_PUSHDATA1 as u8, 0x20];
        non_minimal.extend_from_slice(&addr_hash);
        assert!(is_p2pqpkh_script(&Script::from_bytes(non_minimal)).is_none());
    }

    #[test]
    fn test_pq_staking_vault_script_roundtrip_and_byte_layout() {
        let owner_hash = [0x11u8; 32];
        let vault_hash = [0x22u8; 32];

        let script = create_pq_staking_vault_script(&owner_hash, &vault_hash);
        let bytes = script.as_bytes();

        assert_eq!(bytes.len(), PQ_STAKING_VAULT_SCRIPT_LEN);
        assert_eq!(bytes[0], Opcode::OP_IF as u8);
        assert_eq!(bytes[1], 0x20);
        assert_eq!(&bytes[2..34], &owner_hash);
        assert_eq!(bytes[34], Opcode::OP_ELSE as u8);
        assert_eq!(bytes[35], Opcode::OP_REQUIRE_COINSTAKE as u8);
        assert_eq!(bytes[36], 0x20);
        assert_eq!(&bytes[37..69], &vault_hash);
        assert_eq!(bytes[69], Opcode::OP_ENDIF as u8);
        assert_eq!(bytes[70], Opcode::OP_OVER as u8);
        assert_eq!(bytes[71], Opcode::OP_SHA256 as u8);
        assert_eq!(bytes[72], Opcode::OP_EQUALVERIFY as u8);
        assert_eq!(bytes[73], Opcode::OP_CHECKSIG as u8);

        assert_eq!(
            is_pq_staking_vault_script(&script),
            Some((owner_hash, vault_hash))
        );
        assert_eq!(
            get_pq_vault_pubkey_hashes(&script),
            Some((owner_hash, vault_hash))
        );
        assert!(!is_staking_vault_script(&script));
        assert!(is_p2pqpkh_script(&script).is_none());
    }

    #[test]
    fn test_pq_staking_vault_rejects_opcode_and_length_mutations() {
        let owner_hash = [0xa1u8; 32];
        let vault_hash = [0xb2u8; 32];
        let base = create_pq_staking_vault_script(&owner_hash, &vault_hash)
            .as_bytes()
            .to_vec();

        // Any single-opcode mutation at control positions must be rejected
        for &pos in &[0usize, 1, 34, 35, 36, 69, 70, 71, 72, 73] {
            let mut mutated = base.clone();
            mutated[pos] ^= 0x01;
            assert!(
                is_pq_staking_vault_script(&Script::from_bytes(mutated)).is_none(),
                "expected rejection when mutating byte at position {pos}"
            );
        }

        // Trailing byte must be rejected
        let mut trailing = base.clone();
        trailing.push(Opcode::OP_NOP as u8);
        assert!(is_pq_staking_vault_script(&Script::from_bytes(trailing)).is_none());

        // Truncated byte must be rejected
        let truncated = base[..73].to_vec();
        assert!(is_pq_staking_vault_script(&Script::from_bytes(truncated)).is_none());
    }

    #[test]
    fn test_bech32m_constant_and_p2pqpkh_roundtrip_all_five_hrps() {
        assert_eq!(BECH32M_CONST, 0x2bc8_30a3);

        let program = [0x3cu8; 32];
        let hrps = [
            (PqAddressHrp::DiviMainnet, "divi1"),
            (PqAddressHrp::DiviTestnet, "tdivi1"),
            (PqAddressHrp::DiviRegtest, "rdivi1"),
            (PqAddressHrp::PrivateDiviMainnet, "pdivi1"),
            (PqAddressHrp::PrivateDiviTestnet, "tpdivi1"),
        ];

        for (hrp, expected_prefix) in hrps {
            let addr = encode_p2pqpkh_address(hrp, &program).expect("encode v1 address");
            assert!(
                addr.starts_with(expected_prefix),
                "address {addr} did not start with {expected_prefix}"
            );
            let (decoded_hrp, version, decoded_prog) =
                decode_pq_bech32m_address(&addr).expect("decode v1 address");
            assert_eq!(decoded_hrp, hrp);
            assert_eq!(version, PQ_WITNESS_VERSION_P2PQPKH);
            assert_eq!(decoded_prog, program);

            // All-uppercase form is also valid per BIP-173/BIP-350
            let upper = addr.to_ascii_uppercase();
            let (u_hrp, u_ver, u_prog) =
                decode_pq_bech32m_address(&upper).expect("decode uppercase v1 address");
            assert_eq!(u_hrp, hrp);
            assert_eq!(u_ver, PQ_WITNESS_VERSION_P2PQPKH);
            assert_eq!(u_prog, program);
        }
    }

    #[test]
    fn test_bech32m_pq_vault_v2_roundtrip_all_five_hrps() {
        let owner_hash = [0x10u8; 32];
        let vault_hash = [0x20u8; 32];

        for hrp in [
            PqAddressHrp::DiviMainnet,
            PqAddressHrp::DiviTestnet,
            PqAddressHrp::DiviRegtest,
            PqAddressHrp::PrivateDiviMainnet,
            PqAddressHrp::PrivateDiviTestnet,
        ] {
            let addr = encode_pq_vault_address(hrp, &owner_hash, &vault_hash)
                .expect("encode v2 vault address");
            let (decoded_hrp, version, decoded_prog) =
                decode_pq_bech32m_address(&addr).expect("decode v2 vault address");
            assert_eq!(decoded_hrp, hrp);
            assert_eq!(version, PQ_WITNESS_VERSION_VAULT);
            assert_eq!(decoded_prog.len(), 64);
            assert_eq!(&decoded_prog[..32], &owner_hash);
            assert_eq!(&decoded_prog[32..64], &vault_hash);
        }
    }

    #[test]
    fn test_bech32m_script_pubkey_conversion_roundtrip() {
        let addr_hash = [0x77u8; 32];
        let p2pqpkh_script = create_p2pqpkh_script(&addr_hash);
        let addr_v1 = script_pubkey_to_pq_address(PqAddressHrp::DiviMainnet, &p2pqpkh_script)
            .expect("v1 script to address");
        let (hrp_v1, roundtrip_v1) =
            pq_address_to_script_pubkey(&addr_v1).expect("v1 address to script");
        assert_eq!(hrp_v1, PqAddressHrp::DiviMainnet);
        assert_eq!(roundtrip_v1, p2pqpkh_script);

        let owner_hash = [0x88u8; 32];
        let vault_hash = [0x99u8; 32];
        let pq_vault_script = create_pq_staking_vault_script(&owner_hash, &vault_hash);
        let addr_v2 =
            script_pubkey_to_pq_address(PqAddressHrp::PrivateDiviMainnet, &pq_vault_script)
                .expect("v2 script to address");
        let (hrp_v2, roundtrip_v2) =
            pq_address_to_script_pubkey(&addr_v2).expect("v2 address to script");
        assert_eq!(hrp_v2, PqAddressHrp::PrivateDiviMainnet);
        assert_eq!(roundtrip_v2, pq_vault_script);
    }

    #[test]
    fn test_bech32m_detects_single_character_corruption() {
        let program = [0xab; 32];
        let addr = encode_p2pqpkh_address(PqAddressHrp::DiviMainnet, &program).unwrap();
        let bytes = addr.as_bytes();

        // Corrupt every character after the '1' separator one by one and verify checksum failure
        let sep_idx = addr.find('1').unwrap();
        for i in (sep_idx + 1)..bytes.len() {
            let mut corrupted = bytes.to_vec();
            corrupted[i] = if corrupted[i] == b'q' { b'p' } else { b'q' };
            let corrupted_str = String::from_utf8(corrupted).unwrap();
            assert_eq!(
                decode_pq_bech32m_address(&corrupted_str),
                Err(PqAddressError::ChecksumMismatch),
                "expected ChecksumMismatch at character index {i}"
            );
        }
    }

    #[test]
    fn test_bech32m_rejects_mixed_case_and_unknown_hrp() {
        let program = [0xcd; 32];
        let addr = encode_p2pqpkh_address(PqAddressHrp::DiviMainnet, &program).unwrap();

        // Flip only the first character to uppercase -> MixedCase
        let mut mixed = addr.clone();
        mixed.replace_range(0..1, "D");
        assert_eq!(
            decode_pq_bech32m_address(&mixed),
            Err(PqAddressError::MixedCase)
        );

        // Unknown HRP ("bc1...")
        assert!(matches!(
            decode_pq_bech32m_address(
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
            ),
            Err(PqAddressError::UnknownHrp(_))
        ));
    }

    #[test]
    fn test_bech32m_rejects_legacy_bech32_checksum() {
        // Construct a payload with legacy BIP-173 checksum constant (1 instead of 0x2bc830a3)
        let hrp_str = "divi";
        let program = [0x11u8; 32];
        let mut five_bit_data = vec![PQ_WITNESS_VERSION_P2PQPKH];
        five_bit_data.extend(convert_bits(&program, 8, 5, true).unwrap());

        let mut values = hrp_expand(hrp_str);
        values.extend_from_slice(&five_bit_data);
        values.extend_from_slice(&[0u8; 6]);
        let polymod = bech32_polymod(&values) ^ BECH32_LEGACY_CONST;

        let mut legacy_addr = String::from("divi1");
        for &u in &five_bit_data {
            legacy_addr.push(BECH32_CHARSET[usize::from(u)] as char);
        }
        for i in 0..6 {
            let u = ((polymod >> (5 * (5 - i))) & 0x1f) as usize;
            legacy_addr.push(BECH32_CHARSET[u] as char);
        }

        assert_eq!(
            decode_pq_bech32m_address(&legacy_addr),
            Err(PqAddressError::LegacyBech32Forbidden)
        );
    }

    #[test]
    fn test_bech32m_rejects_invalid_witness_version_and_program_length() {
        // Witness version 0 and 3 are rejected for DIP-PQ-3 encoding
        assert_eq!(
            encode_pq_bech32m_address(PqAddressHrp::DiviMainnet, 0, &[0u8; 32]),
            Err(PqAddressError::UnsupportedWitnessVersion(0))
        );
        assert_eq!(
            encode_pq_bech32m_address(PqAddressHrp::DiviMainnet, 3, &[0u8; 32]),
            Err(PqAddressError::UnsupportedWitnessVersion(3))
        );

        // Witness version 1 requires 32 bytes (reject 20 or 64)
        assert_eq!(
            encode_pq_bech32m_address(PqAddressHrp::DiviMainnet, 1, &[0u8; 20]),
            Err(PqAddressError::InvalidProgramLength {
                version: 1,
                expected: 32,
                actual: 20,
            })
        );

        // Witness version 2 requires 64 bytes (reject 32)
        assert_eq!(
            encode_pq_bech32m_address(PqAddressHrp::DiviMainnet, 2, &[0u8; 32]),
            Err(PqAddressError::InvalidProgramLength {
                version: 2,
                expected: 64,
                actual: 32,
            })
        );
    }

    #[test]
    fn test_canonical_dip_pq_3_address_test_vectors() {
        // Verify BIP-350 official reference vector ("a1lqfn3a") against our pure-Rust polymod
        let bip350_chk = create_bech32m_checksum("a", &[]);
        let mut bip350_ref = String::from("a1");
        for &u in &bip350_chk {
            bip350_ref.push(BECH32_CHARSET[usize::from(u)] as char);
        }
        assert_eq!(bip350_ref, "a1lqfn3a");

        // Canonical DIP-PQ-3 Vector 1: P2PQPKH (witness v1) with addr_key_hash_256 = [0x11; 32]
        let hash_v1 = [0x11u8; 32];
        let divi_v1 = encode_p2pqpkh_address(PqAddressHrp::DiviMainnet, &hash_v1).unwrap();
        let tdivi_v1 = encode_p2pqpkh_address(PqAddressHrp::DiviTestnet, &hash_v1).unwrap();
        let rdivi_v1 = encode_p2pqpkh_address(PqAddressHrp::DiviRegtest, &hash_v1).unwrap();
        let pdivi_v1 = encode_p2pqpkh_address(PqAddressHrp::PrivateDiviMainnet, &hash_v1).unwrap();
        let tpdivi_v1 = encode_p2pqpkh_address(PqAddressHrp::PrivateDiviTestnet, &hash_v1).unwrap();

        let owner_v2 = [0x22u8; 32];
        let vault_v2 = [0x33u8; 32];
        let divi_v2 =
            encode_pq_vault_address(PqAddressHrp::DiviMainnet, &owner_v2, &vault_v2).unwrap();

        assert_eq!(
            divi_v1,
            "divi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsvgff7j"
        );
        assert_eq!(
            tdivi_v1,
            "tdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsnfa2ee"
        );
        assert_eq!(
            rdivi_v1,
            "rdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsj9gcf6"
        );
        assert_eq!(
            pdivi_v1,
            "pdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs2puk7m"
        );
        assert_eq!(
            tpdivi_v1,
            "tpdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsf68lva"
        );
        assert_eq!(
            divi_v2,
            "divi1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3rxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvc5tmafc"
        );
    }

    #[test]
    fn test_pq_witness_stack_canonical_serialization_roundtrip_mldsa44() {
        // ML-DSA-44: pubkey = 1,312 B, signature = 2,420 B
        let pubkey = vec![0x11u8; 1312];
        let signature = vec![0x22u8; 2420];
        let witness = PqInputWitness::for_p2pqpkh(
            PqSchemeId::MlDsa44.as_u8(),
            &pubkey,
            &signature,
            0x01, // SIGHASH_ALL
        );

        assert_eq!(witness.items.len(), 2);
        assert_eq!(witness.items[0].len(), 1 + 2420 + 1);
        assert_eq!(witness.items[1].len(), 1 + 1312);
        assert!(validate_pq_witness_limits(&witness).is_ok());

        let bytes = witness.serialize_canonical();
        // 1 (count=2) + 3 (len=2422) + 2422 + 3 (len=1313) + 1313 = 3,742 B
        assert_eq!(bytes.len(), 3742);

        let decoded =
            PqInputWitness::deserialize_canonical(&bytes).expect("deserialize ML-DSA-44 witness");
        assert_eq!(decoded, witness);
    }

    #[test]
    fn test_pq_witness_stack_canonical_serialization_roundtrip_slhdsa128s_vault() {
        // SLH-DSA-128s cold owner vault spend: pubkey = 32 B, signature = 7,856 B
        let pubkey = vec![0x33u8; 32];
        let signature = vec![0x44u8; 7856];
        let witness = PqInputWitness::for_pq_vault(
            true,
            PqSchemeId::SlhDsa128s.as_u8(),
            &pubkey,
            &signature,
            0x01,
        );

        assert_eq!(witness.items.len(), 3);
        assert_eq!(witness.items[0].len(), 7858); // <= MAX_PQ_WITNESS_ITEM_SIZE (8,192 B)
        assert_eq!(witness.items[1].len(), 33);
        assert_eq!(witness.items[2], vec![0x01]);
        assert!(validate_pq_witness_limits(&witness).is_ok());

        let encoded = witness.serialize_canonical();
        let decoded =
            PqInputWitness::deserialize_canonical(&encoded).expect("deserialize SLH-DSA witness");
        assert_eq!(decoded, witness);
    }

    #[test]
    fn test_pq_witness_limits_reject_oversized_item_and_stack() {
        // Item exceeding MAX_PQ_WITNESS_ITEM_SIZE (8,192 B)
        let oversized_item =
            PqInputWitness::from_items(vec![vec![0u8; MAX_PQ_WITNESS_ITEM_SIZE + 1]]);
        assert_eq!(
            validate_pq_witness_limits(&oversized_item),
            Err(PqWitnessError::ItemTooLarge {
                index: 0,
                actual: MAX_PQ_WITNESS_ITEM_SIZE + 1,
                max: MAX_PQ_WITNESS_ITEM_SIZE,
            })
        );

        // Stack with > MAX_PQ_WITNESS_STACK_ITEMS (8) items
        let too_many_items =
            PqInputWitness::from_items(vec![vec![0x01]; MAX_PQ_WITNESS_STACK_ITEMS + 1]);
        assert_eq!(
            validate_pq_witness_limits(&too_many_items),
            Err(PqWitnessError::TooManyStackItems {
                actual: MAX_PQ_WITNESS_STACK_ITEMS + 1,
                max: MAX_PQ_WITNESS_STACK_ITEMS,
            })
        );

        // Total serialized bytes exceeding MAX_PQ_TX_WITNESS_BYTES (16,384 B) using three 6,000 B items
        let total_overflow =
            PqInputWitness::from_items(vec![vec![0xaa; 6000], vec![0xbb; 6000], vec![0xcc; 6000]]);
        assert!(matches!(
            validate_pq_witness_limits(&total_overflow),
            Err(PqWitnessError::InputWitnessTooLarge { .. })
        ));
    }

    #[test]
    fn test_pq_witness_deserialization_rejects_non_canonical_compact_size_and_trailing_bytes() {
        // 0xfd 0x01 0x00 is non-canonical CompactSize for 1
        let non_canonical = [0xfd, 0x01, 0x00, 0x01, 0xff];
        assert_eq!(
            PqInputWitness::deserialize_canonical(&non_canonical),
            Err(PqWitnessError::NonCanonicalCompactSize)
        );

        // Valid empty stack (0x00) followed by a trailing byte
        let trailing = [0x00, 0x99];
        assert_eq!(
            PqInputWitness::deserialize_canonical(&trailing),
            Err(PqWitnessError::TrailingBytes(1))
        );
    }

    #[test]
    fn test_compute_wtxid_classical_identity_and_pq_commitment() {
        let txid = [0x5au8; 32];

        // Classical tx (no witnesses or all empty witnesses) -> wtxid == txid
        assert_eq!(compute_wtxid(&txid, &[]), txid);
        assert_eq!(
            compute_wtxid(&txid, &[PqInputWitness::empty(), PqInputWitness::empty()]),
            txid
        );

        // PQ tx -> wtxid = SHA256d(txid || witness_merkle_root) != txid
        let w0 = PqInputWitness::for_p2pqpkh(0x02, &[0x11; 897], &[0x22; 666], 0x01);
        let w1 = PqInputWitness::for_pq_vault(false, 0x02, &[0x33; 897], &[0x44; 666], 0x01);
        let wtxid = compute_wtxid(&txid, &[w0.clone(), w1.clone()]);
        assert_ne!(wtxid, txid);

        // Mutating a single witness byte changes wtxid while leaving txid untouched
        let mut w1_mut = w1;
        w1_mut.items[0][10] ^= 0x01;
        let wtxid_mut = compute_wtxid(&txid, &[w0, w1_mut]);
        assert_ne!(wtxid_mut, wtxid);
    }

    #[test]
    fn test_pq_tx_weight_and_block_weight_accounting() {
        // 2-in/2-out FN-DSA-512 transaction: ~220 B base, ~3,140 B witness
        let weight = compute_pq_tx_weight(220, 3_140);
        assert_eq!(weight, 220 * 4 + 3_140);
        assert_eq!(validate_pq_block_weight(220, 3_140), Ok(4_020));

        // Exact block weight ceiling: 1,500,000 B base * 4 + 0 B witness = 6,000,000 WU (valid)
        assert_eq!(validate_pq_block_weight(1_500_000, 500_000), Ok(6_500_000));

        // Exceeding 8,000,000 WU is rejected even if raw bytes <= 2,000,000 B
        assert!(matches!(
            validate_pq_block_weight(1_950_000, 400_000),
            Err(PqWitnessError::BlockWeightExceeded { .. })
        ));

        // Exceeding 2,000,000 raw bytes is rejected even if weight <= 8,000,000 WU
        assert!(matches!(
            validate_pq_block_weight(100_000, 1_950_000),
            Err(PqWitnessError::BlockWeightExceeded { .. })
        ));
    }

    #[test]
    fn test_classify_staking_quantum_posture_covers_classical_vault_pq_vault_and_p2pqpkh() {
        let classical_vault = StakingVaultScript::new([0x11; 20], [0x22; 20]).to_script();
        let pq_vault = create_pq_staking_vault_script(&[0x33; 32], &[0x44; 32]);
        let p2pqpkh = create_p2pqpkh_script(&[0x55; 32]);
        let legacy_p2pkh = Script::new_p2pkh(&[0x66; 20]);

        assert!(classify_staking_quantum_posture(&classical_vault).is_vault_insulated());
        assert!(classify_staking_quantum_posture(&pq_vault).is_vault_insulated());
        assert!(classify_staking_quantum_posture(&p2pqpkh).is_vault_insulated());
        assert!(classify_staking_quantum_posture(&legacy_p2pkh).is_direct_pubkey_exposed());

        assert_eq!(
            summarize_staking_posture([&classical_vault, &pq_vault, &p2pqpkh]),
            "vault_only"
        );
        assert_eq!(
            summarize_staking_posture([&pq_vault, &legacy_p2pkh]),
            "mixed_or_direct_p2pkh"
        );
    }

    #[test]
    fn test_pq_tx_witness_merkle_root_and_empty_detection() {
        let mut tx_wit = PqTxWitness {
            inputs: vec![PqInputWitness::empty(), PqInputWitness::empty()],
        };
        assert!(tx_wit.is_empty());
        assert_eq!(tx_wit.total_serialized_bytes(), 0);
        assert_eq!(tx_wit.witness_merkle_root(), [0u8; 32]);

        tx_wit.inputs[1] = PqInputWitness::for_p2pqpkh(0x02, &[0xaa; 897], &[0xbb; 666], 0x01);
        assert!(!tx_wit.is_empty());
        assert!(tx_wit.total_serialized_bytes() > 1560);
        assert_ne!(tx_wit.witness_merkle_root(), [0u8; 32]);
        assert!(tx_wit.validate_limits().is_ok());
    }

    #[test]
    fn test_witness_merkle_root_odd_leaf_duplication() {
        let w0 = PqInputWitness::from_items(vec![vec![0x01]]);
        let w1 = PqInputWitness::from_items(vec![vec![0x02]]);
        let w2 = PqInputWitness::from_items(vec![vec![0x03]]);

        // 3 inputs -> third leaf is duplicated in layer 0 ([w0, w1, w2, w2])
        let root_3 = compute_witness_merkle_root(&[w0.clone(), w1.clone(), w2.clone()]);
        let root_4_dup = compute_witness_merkle_root(&[w0, w1, w2.clone(), w2]);
        assert_eq!(root_3, root_4_dup);
    }

    #[test]
    fn test_bech32m_rejects_non_zero_padding_bits() {
        // Take a valid v1 address and flip the lowest bit of the last 5-bit data word (which has 4 padding bits)
        let hrp_str = "divi";
        let program = [0x00u8; 32];
        let mut five_bit_data = vec![PQ_WITNESS_VERSION_P2PQPKH];
        five_bit_data.extend(convert_bits(&program, 8, 5, true).unwrap());
        // Last 5-bit word has 1 data bit (top bit) and 4 padding bits (low 4 bits = 0). Set low bit = 1:
        *five_bit_data.last_mut().unwrap() |= 0x01;
        let checksum = create_bech32m_checksum(hrp_str, &five_bit_data);

        let mut bad_pad_addr = String::from("divi1");
        for &u in five_bit_data.iter().chain(checksum.iter()) {
            bad_pad_addr.push(BECH32_CHARSET[usize::from(u)] as char);
        }

        assert_eq!(
            decode_pq_bech32m_address(&bad_pad_addr),
            Err(PqAddressError::InvalidPadding)
        );
    }

    #[test]
    fn test_bech32m_rejects_missing_separator_and_invalid_lengths() {
        assert_eq!(
            decode_pq_bech32m_address(""),
            Err(PqAddressError::InvalidStringLength(0))
        );
        assert_eq!(
            decode_pq_bech32m_address("divi_no_separator_here_at_all"),
            Err(PqAddressError::MissingSeparator)
        );
        let too_long = "d".repeat(MAX_PQ_BECH32M_STRING_LEN + 1);
        assert_eq!(
            decode_pq_bech32m_address(&too_long),
            Err(PqAddressError::InvalidStringLength(
                MAX_PQ_BECH32M_STRING_LEN + 1
            ))
        );
    }

    #[test]
    fn test_script_pubkey_to_pq_address_returns_none_for_classical_scripts() {
        let p2pkh = Script::new_p2pkh(&[0x11; 20]);
        let classical_vault = StakingVaultScript::new([0x11; 20], [0x22; 20]).to_script();
        assert!(script_pubkey_to_pq_address(PqAddressHrp::DiviMainnet, &p2pkh).is_none());
        assert!(script_pubkey_to_pq_address(PqAddressHrp::DiviMainnet, &classical_vault).is_none());
    }

    #[test]
    fn test_dip_pq_1_derived_keys_to_dip_pq_3_scripts_and_addresses() {
        // Derive PQ address key commitments for ML-DSA-44 (hot manager) and SLH-DSA-128s (cold owner)
        let owner_pk_slh = [0x9au8; 32];
        let vault_pk_fndsa = [0xbc; 897];

        let owner_hash_256 = pq_address_key_hash_256(PqSchemeId::SlhDsa128s, &owner_pk_slh);
        let vault_hash_256 = pq_address_key_hash_256(PqSchemeId::FnDsa512, &vault_pk_fndsa);

        let vault_script = create_pq_staking_vault_script(&owner_hash_256, &vault_hash_256);
        assert_eq!(vault_script.as_bytes().len(), PQ_STAKING_VAULT_SCRIPT_LEN);

        let vault_addr =
            encode_pq_vault_address(PqAddressHrp::DiviMainnet, &owner_hash_256, &vault_hash_256)
                .unwrap();
        let (hrp, recovered_script) = pq_address_to_script_pubkey(&vault_addr).unwrap();
        assert_eq!(hrp, PqAddressHrp::DiviMainnet);
        assert_eq!(recovered_script, vault_script);
    }
}
