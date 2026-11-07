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

//! Staking vault script support
//!
//! This module provides functionality to create and parse staking vault scripts,
//! which are Divi's mechanism for delegating staking while maintaining owner control.
//!
//! # Vault Script Structure
//!
//! A 2-key staking vault script has this structure:
//! ```text
//! OP_IF
//!     <ownerPubKeyHash>
//! OP_ELSE
//!     OP_REQUIRE_COINSTAKE <vaultPubKeyHash>
//! OP_ENDIF
//! OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
//! ```
//!
//! This allows:
//! - Owner key: Spend anytime (bypass coinstake requirement)
//! - Vault key: Can only spend via coinstake transaction (staking)
//!
//! # Extended Vault (DIP-001)
//!
//! A 3-key vault adds a reward destination:
//! ```text
//! OP_IF
//!     <ownerPubKeyHash>
//! OP_ELSE
//!     OP_IF
//!         <rewardDestinationHash> OP_REWARD_DESTINATION
//!     OP_ELSE
//!         OP_REQUIRE_COINSTAKE <vaultPubKeyHash>
//!     OP_ENDIF
//! OP_ENDIF
//! OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
//! ```

use crate::opcodes::Opcode;
use divi_primitives::script::Script;

/// Staking vault script data
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

/// Check if a script is a staking vault script
pub fn is_staking_vault_script(script: &Script) -> bool {
    StakingVaultScript::from_script(script).is_some()
}

/// Extract the pubkey hashes from a staking vault script
pub fn get_vault_pubkey_hashes(script: &Script) -> Option<([u8; 20], [u8; 20])> {
    StakingVaultScript::from_script(script).map(|v| (v.owner_pubkey_hash, v.vault_pubkey_hash))
}

/// Post-quantum staking key-exposure classification (`DIP-PQ-0` §3.1–3.2).
///
/// Every Proof-of-Stake block carries a compact recoverable `secp256k1` signature (`vchBlockSig`),
/// revealing the full 33-byte signing `CPubKey` on the first minted block:
/// - When staking via a 2-key `STAKING_VAULT`, only the hot coinstake-restricted manager key
///   (`manager_hash160`) signs `vchBlockSig`; the owner key (`owner_hash160`) stays hidden
///   behind `Hash160` (`RIPEMD160(SHA256(ownerPubKey))`) and consensus rules prevent coinstake
///   transactions from redirecting vault principal or rewards away from the vault script.
/// - When staking directly with `P2PKH` (or `P2PK`), `vchBlockSig` exposes the spending
///   `CPubKey` on-chain to offline Shor discrete-logarithm recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StakingQuantumPosture {
    /// Two-key `STAKING_VAULT` output with `Hash160`-insulated cold owner key and
    /// `OP_REQUIRE_COINSTAKE`-restricted hot manager key.
    VaultInsulated {
        /// Cold owner `Hash160` (`OP_IF` spending branch; unrevealed during staking)
        owner_hash160: [u8; 20],
        /// Hot manager `Hash160` (`OP_ELSE OP_REQUIRE_COINSTAKE` coinstake branch)
        manager_hash160: [u8; 20],
    },
    /// Direct `P2PKH` (or other non-vault) staking output where `vchBlockSig` exposes the
    /// spending `secp256k1` `CPubKey` directly on-chain.
    DirectPubKeyExposed,
}

impl StakingQuantumPosture {
    /// Classify a `Script` into its post-quantum staking posture.
    pub fn from_script(script: &Script) -> Self {
        if let Some(vault) = StakingVaultScript::from_script(script) {
            StakingQuantumPosture::VaultInsulated {
                owner_hash160: vault.owner_pubkey_hash,
                manager_hash160: vault.vault_pubkey_hash,
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

    /// Returns `true` if the staking output insulates the owner key via `STAKING_VAULT`.
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

/// Classify a staking UTXO `scriptPubKey` for post-quantum insulation (`DIP-PQ-0` §3.1–3.2).
pub fn classify_staking_script_posture(script: &Script) -> StakingQuantumPosture {
    StakingQuantumPosture::from_script(script)
}

/// Summarize aggregate `vault_insulation` telemetry across a collection of staking scripts.
///
/// Returns `"vault_only"` when all inspected scripts are `STAKING_VAULT` outputs (and at least
/// one script is present), or `"mixed_or_direct_p2pkh"` if any non-vault script is present.
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
}
