// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
}
