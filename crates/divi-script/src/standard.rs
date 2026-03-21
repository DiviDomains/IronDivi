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

//! Script type detection and address extraction
//!
//! This module implements script type detection matching C++ Divi's
//! `ExtractScriptPubKeyFormat()` function from `standard.cpp`.
//!
//! # Supported Script Types
//!
//! - **P2PKH**: Pay-to-Public-Key-Hash - `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`
//! - **P2SH**: Pay-to-Script-Hash - `OP_HASH160 <20 bytes> OP_EQUAL`
//! - **P2PK**: Pay-to-Public-Key - `<33 or 65 bytes pubkey> OP_CHECKSIG`
//! - **Multisig**: `<m> <pubkeys...> <n> OP_CHECKMULTISIG`
//! - **Vault**: Staking vault scripts with owner and vault keys
//! - **HTLC**: Hash Time Locked Contracts
//! - **NullData**: `OP_META <push-only data...>` (prunable data outputs)

use crate::opcodes::Opcode;
use crate::vault::{is_staking_vault_script, StakingVaultScript};
use divi_primitives::script::Script;

/// Script type classification matching C++ `txnouttype` enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptType {
    /// TX_NONSTANDARD - Not a recognized standard script type
    NonStandard,
    /// TX_PUBKEY - `<pubkey> OP_CHECKSIG`
    PubKey,
    /// TX_PUBKEYHASH - `OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`
    PubKeyHash,
    /// TX_SCRIPTHASH - `OP_HASH160 <scripthash> OP_EQUAL`
    ScriptHash,
    /// TX_VAULT - Staking vault script
    Vault,
    /// TX_HTLC - Hash Time Locked Contract
    Htlc,
    /// TX_MULTISIG - `<m> <pubkeys...> <n> OP_CHECKMULTISIG`
    Multisig,
    /// TX_NULL_DATA - `OP_META <data...>` (provably unspendable)
    NullData,
}

/// Address destination extracted from a script
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Destination {
    /// Pay-to-public-key-hash address (20 byte hash160)
    PubKeyHash([u8; 20]),
    /// Pay-to-script-hash address (20 byte hash160)
    ScriptHash([u8; 20]),
}

/// Get the string name for a script type, matching C++ `GetTxnOutputType()`
pub fn get_script_type_name(script_type: ScriptType) -> &'static str {
    match script_type {
        ScriptType::NonStandard => "nonstandard",
        ScriptType::PubKey => "pubkey",
        ScriptType::PubKeyHash => "pubkeyhash",
        ScriptType::ScriptHash => "scripthash",
        ScriptType::Vault => "vault",
        ScriptType::Htlc => "htlc",
        ScriptType::Multisig => "multisig",
        ScriptType::NullData => "nulldata",
    }
}

/// Extract the script type and associated data from a script.
///
/// Returns a tuple of (ScriptType, extracted_data) where extracted_data contains:
/// - P2PKH: [pubkey_hash (20 bytes)]
/// - P2SH: [script_hash (20 bytes)]
/// - P2PK: [pubkey (33 or 65 bytes)]
/// - Multisig: [m, pubkey1, pubkey2, ..., n]
/// - Vault: [owner_hash (20 bytes), vault_hash (20 bytes)]
/// - HTLC: [hash_type, hash_value, receiver_hash, timeout_value, sender_hash]
/// - NullData: [] (no data extracted)
/// - NonStandard: [] (no data extracted)
///
/// This matches C++ `ExtractScriptPubKeyFormat()` behavior.
pub fn extract_script_type(script: &[u8]) -> (ScriptType, Vec<Vec<u8>>) {
    // Shortcut for P2SH (most constrained format)
    // Exactly: OP_HASH160 0x14 <20 bytes> OP_EQUAL
    if is_p2sh(script) {
        let hash = script[2..22].to_vec();
        return (ScriptType::ScriptHash, vec![hash]);
    }

    // P2PKH detection
    // OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if is_p2pkh(script) {
        let hash = script[3..23].to_vec();
        return (ScriptType::PubKeyHash, vec![hash]);
    }

    // NullData detection (OP_META followed by push-only data)
    if is_null_data(script) {
        return (ScriptType::NullData, vec![]);
    }

    // P2PK detection
    // <33 or 65 byte pubkey> OP_CHECKSIG
    if is_p2pk(script) {
        let pubkey_len = script[0] as usize;
        let pubkey = script[1..1 + pubkey_len].to_vec();
        return (ScriptType::PubKey, vec![pubkey]);
    }

    // Multisig detection
    // <m> <pubkeys...> <n> OP_CHECKMULTISIG
    if let Some((m, n)) = is_multisig(script) {
        let mut solutions = Vec::new();
        solutions.push(vec![m]);

        // Extract pubkeys
        let mut pos = 1; // Skip m opcode
        for _ in 0..n {
            if pos >= script.len() {
                return (ScriptType::NonStandard, vec![]);
            }
            let push_len = script[pos] as usize;
            if push_len < 33 || push_len > 65 || pos + 1 + push_len > script.len() {
                return (ScriptType::NonStandard, vec![]);
            }
            solutions.push(script[pos + 1..pos + 1 + push_len].to_vec());
            pos += 1 + push_len;
        }
        solutions.push(vec![n]);

        return (ScriptType::Multisig, solutions);
    }

    // Vault detection
    let script_obj = Script::from_bytes(script.to_vec());
    if is_staking_vault_script(&script_obj) {
        if let Some(vault) = StakingVaultScript::from_script(&script_obj) {
            return (
                ScriptType::Vault,
                vec![
                    vault.owner_pubkey_hash.to_vec(),
                    vault.vault_pubkey_hash.to_vec(),
                ],
            );
        }
    }

    // HTLC detection
    if let Some(htlc_data) = extract_htlc_data(script) {
        return (ScriptType::Htlc, htlc_data);
    }

    (ScriptType::NonStandard, vec![])
}

/// Check if script is P2PKH (Pay-to-Public-Key-Hash)
///
/// Matches C++ `IsPayToPublicKeyHash()`:
/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`
pub fn is_p2pkh(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == Opcode::OP_DUP as u8       // 0x76
        && script[1] == Opcode::OP_HASH160 as u8   // 0xa9
        && script[2] == 0x14                        // Push 20 bytes
        && script[23] == Opcode::OP_EQUALVERIFY as u8 // 0x88
        && script[24] == Opcode::OP_CHECKSIG as u8 // 0xac
}

/// Check if script is P2SH (Pay-to-Script-Hash)
///
/// Matches C++ `IsPayToScriptHash()`:
/// `OP_HASH160 <20 bytes> OP_EQUAL`
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == Opcode::OP_HASH160 as u8  // 0xa9
        && script[1] == 0x14                       // Push 20 bytes
        && script[22] == Opcode::OP_EQUAL as u8 // 0x87
}

/// Check if script is P2PK (Pay-to-Public-Key)
///
/// `<33 or 65 byte pubkey> OP_CHECKSIG`
pub fn is_p2pk(script: &[u8]) -> bool {
    // Compressed pubkey: 34 bytes (1 push + 33 pubkey + 1 OP_CHECKSIG)
    // Uncompressed pubkey: 67 bytes (1 push + 65 pubkey + 1 OP_CHECKSIG)
    if script.len() == 35 {
        // Compressed pubkey
        script[0] == 0x21 // Push 33 bytes
            && (script[1] == 0x02 || script[1] == 0x03) // Compressed pubkey prefix
            && script[34] == Opcode::OP_CHECKSIG as u8
    } else if script.len() == 67 {
        // Uncompressed pubkey
        script[0] == 0x41 // Push 65 bytes
            && script[1] == 0x04 // Uncompressed pubkey prefix
            && script[66] == Opcode::OP_CHECKSIG as u8
    } else {
        false
    }
}

/// Check if script is a multisig script
///
/// `<m> <pubkeys...> <n> OP_CHECKMULTISIG`
///
/// Returns `Some((m, n))` if it's a valid multisig, where m is required sigs and n is total keys.
pub fn is_multisig(script: &[u8]) -> Option<(u8, u8)> {
    if script.len() < 4 {
        return None;
    }

    // Last byte must be OP_CHECKMULTISIG
    if script[script.len() - 1] != Opcode::OP_CHECKMULTISIG as u8 {
        return None;
    }

    // First byte must be OP_1 through OP_16 (m value)
    let m_opcode = script[0];
    if !(Opcode::OP_1 as u8..=Opcode::OP_16 as u8).contains(&m_opcode) {
        return None;
    }
    let m = decode_op_n(m_opcode)?;

    // Second-to-last byte must be OP_1 through OP_16 (n value)
    let n_opcode = script[script.len() - 2];
    if !(Opcode::OP_1 as u8..=Opcode::OP_16 as u8).contains(&n_opcode) {
        return None;
    }
    let n = decode_op_n(n_opcode)?;

    // Validate m <= n
    if m > n || m < 1 || n < 1 || n > 16 {
        return None;
    }

    // Verify we have exactly n pubkeys
    let mut pos = 1; // Skip m opcode
    let mut pubkey_count = 0;

    while pos < script.len() - 2 {
        // Should be followed by n pubkey pushes
        let push_len = script[pos] as usize;

        // Valid pubkey lengths are 33 (compressed) or 65 (uncompressed)
        if push_len != 33 && push_len != 65 {
            return None;
        }

        if pos + 1 + push_len > script.len() - 2 {
            return None;
        }

        pubkey_count += 1;
        pos += 1 + push_len;
    }

    if pubkey_count != n {
        return None;
    }

    // Should be exactly at n opcode position
    if pos != script.len() - 2 {
        return None;
    }

    Some((m, n))
}

/// Check if script is NullData (OP_META/OP_RETURN with push-only data)
///
/// `OP_META <push-only data...>`
pub fn is_null_data(script: &[u8]) -> bool {
    if script.is_empty() {
        return false;
    }

    // Must start with OP_META (0x6a, same as OP_RETURN)
    if script[0] != Opcode::OP_RETURN as u8 {
        return false;
    }

    // Rest must be push-only
    is_push_only(&script[1..])
}

/// Extract destination address from a script
///
/// Matches C++ `ExtractDestination()` behavior:
/// - P2PKH: Returns PubKeyHash
/// - P2SH: Returns ScriptHash
/// - P2PK: Computes hash160 of pubkey, returns PubKeyHash
/// - Other types: Returns None
pub fn extract_destination(script: &[u8]) -> Option<Destination> {
    let (script_type, solutions) = extract_script_type(script);

    match script_type {
        ScriptType::PubKeyHash => {
            if solutions.len() == 1 && solutions[0].len() == 20 {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&solutions[0]);
                Some(Destination::PubKeyHash(hash))
            } else {
                None
            }
        }
        ScriptType::ScriptHash => {
            if solutions.len() == 1 && solutions[0].len() == 20 {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&solutions[0]);
                Some(Destination::ScriptHash(hash))
            } else {
                None
            }
        }
        ScriptType::PubKey => {
            // P2PK: compute hash160 of pubkey
            if solutions.len() == 1 && (solutions[0].len() == 33 || solutions[0].len() == 65) {
                let hash = hash160(&solutions[0]);
                Some(Destination::PubKeyHash(hash))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract destinations from a script (supports multisig)
///
/// Returns `Some((script_type, destinations, required_sigs))` for scripts with extractable destinations.
/// For multisig, computes hash160 of each pubkey.
/// For vault, returns the owner and vault pubkey hashes.
pub fn extract_destinations(script: &[u8]) -> Option<(ScriptType, Vec<Destination>, usize)> {
    let (script_type, solutions) = extract_script_type(script);

    match script_type {
        ScriptType::Multisig => {
            if solutions.len() < 3 {
                return None;
            }
            let m = solutions[0].first().copied().unwrap_or(0) as usize;

            // Skip first (m) and last (n) elements
            let mut destinations = Vec::new();
            for pubkey in &solutions[1..solutions.len() - 1] {
                if pubkey.len() == 33 || pubkey.len() == 65 {
                    let hash = hash160(pubkey);
                    destinations.push(Destination::PubKeyHash(hash));
                }
            }

            if destinations.is_empty() {
                return None;
            }

            Some((script_type, destinations, m))
        }
        ScriptType::Vault => {
            // Vault has owner and vault hashes
            if solutions.len() != 2 {
                return None;
            }
            let mut destinations = Vec::new();
            for hash_bytes in &solutions {
                if hash_bytes.len() == 20 {
                    let mut hash = [0u8; 20];
                    hash.copy_from_slice(hash_bytes);
                    destinations.push(Destination::PubKeyHash(hash));
                }
            }
            // Vault requires 1 signature
            Some((script_type, destinations, 1))
        }
        ScriptType::NullData => {
            // NullData has no addresses
            None
        }
        _ => {
            // Single destination types
            extract_destination(script).map(|dest| (script_type, vec![dest], 1))
        }
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Decode OP_N opcodes (OP_0 through OP_16) to their numeric value
fn decode_op_n(opcode: u8) -> Option<u8> {
    if opcode == Opcode::OP_0 as u8 {
        Some(0)
    } else if (Opcode::OP_1 as u8..=Opcode::OP_16 as u8).contains(&opcode) {
        Some(opcode - Opcode::OP_1 as u8 + 1)
    } else {
        None
    }
}

/// Check if script bytes are push-only (only data pushes, no other opcodes)
fn is_push_only(script: &[u8]) -> bool {
    let mut pos = 0;

    while pos < script.len() {
        let opcode = script[pos];

        if opcode <= 0x4b {
            // Direct push: 0x01-0x4b bytes
            let push_len = opcode as usize;
            pos += 1 + push_len;
        } else if opcode == Opcode::OP_PUSHDATA1 as u8 {
            // OP_PUSHDATA1: next byte is length
            if pos + 1 >= script.len() {
                return false;
            }
            let push_len = script[pos + 1] as usize;
            pos += 2 + push_len;
        } else if opcode == Opcode::OP_PUSHDATA2 as u8 {
            // OP_PUSHDATA2: next 2 bytes are length (little-endian)
            if pos + 2 >= script.len() {
                return false;
            }
            let push_len = u16::from_le_bytes([script[pos + 1], script[pos + 2]]) as usize;
            pos += 3 + push_len;
        } else if opcode == Opcode::OP_PUSHDATA4 as u8 {
            // OP_PUSHDATA4: next 4 bytes are length (little-endian)
            if pos + 4 >= script.len() {
                return false;
            }
            let push_len = u32::from_le_bytes([
                script[pos + 1],
                script[pos + 2],
                script[pos + 3],
                script[pos + 4],
            ]) as usize;
            pos += 5 + push_len;
        } else if opcode == Opcode::OP_0 as u8 {
            // OP_0 pushes empty array
            pos += 1;
        } else if opcode == Opcode::OP_1NEGATE as u8 {
            // OP_1NEGATE pushes -1
            pos += 1;
        } else if (Opcode::OP_1 as u8..=Opcode::OP_16 as u8).contains(&opcode) {
            // OP_1 through OP_16 push their respective values
            pos += 1;
        } else {
            // Any other opcode means not push-only
            return false;
        }

        // Check for buffer overrun
        if pos > script.len() {
            return false;
        }
    }

    true
}

/// Compute HASH160 (SHA256 then RIPEMD160) of data
fn hash160(data: &[u8]) -> [u8; 20] {
    let hash = divi_crypto::hash160(data);
    let mut result = [0u8; 20];
    result.copy_from_slice(hash.as_ref());
    result
}

/// Extract HTLC data from script
///
/// HTLC template from C++:
/// `<hash_type> <hash_value> OP_EQUAL OP_IF <receiver_hash> OP_ELSE <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_hash> OP_ENDIF OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG`
fn extract_htlc_data(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    // HTLC scripts are complex - implement basic pattern matching
    // Minimum length check (rough estimate)
    if script.len() < 60 {
        return None;
    }

    let mut pos = 0;

    // First opcode should be a hash type (OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256)
    let hash_type = script.get(pos)?;
    if !matches!(
        *hash_type,
        0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa // RIPEMD160, SHA1, SHA256, HASH160, HASH256
    ) {
        return None;
    }
    pos += 1;

    // Next should be push of hash value
    let hash_push_len = *script.get(pos)? as usize;
    if pos + 1 + hash_push_len >= script.len() {
        return None;
    }
    let hash_value = script[pos + 1..pos + 1 + hash_push_len].to_vec();
    pos += 1 + hash_push_len;

    // OP_EQUAL
    if script.get(pos)? != &(Opcode::OP_EQUAL as u8) {
        return None;
    }
    pos += 1;

    // OP_IF
    if script.get(pos)? != &(Opcode::OP_IF as u8) {
        return None;
    }
    pos += 1;

    // Receiver pubkey hash (20 bytes)
    let receiver_push_len = *script.get(pos)? as usize;
    if receiver_push_len != 20 || pos + 1 + 20 > script.len() {
        return None;
    }
    let receiver_hash = script[pos + 1..pos + 21].to_vec();
    pos += 21;

    // OP_ELSE
    if script.get(pos)? != &(Opcode::OP_ELSE as u8) {
        return None;
    }
    pos += 1;

    // Timeout value (variable length CScriptNum)
    let timeout_push_len = *script.get(pos)? as usize;
    if timeout_push_len == 0 || pos + 1 + timeout_push_len >= script.len() {
        return None;
    }
    let timeout_value = script[pos + 1..pos + 1 + timeout_push_len].to_vec();
    pos += 1 + timeout_push_len;

    // OP_CHECKLOCKTIMEVERIFY
    if script.get(pos)? != &(Opcode::OP_CHECKLOCKTIMEVERIFY as u8) {
        return None;
    }
    pos += 1;

    // OP_DROP
    if script.get(pos)? != &(Opcode::OP_DROP as u8) {
        return None;
    }
    pos += 1;

    // Sender pubkey hash (20 bytes)
    let sender_push_len = *script.get(pos)? as usize;
    if sender_push_len != 20 || pos + 1 + 20 > script.len() {
        return None;
    }
    let sender_hash = script[pos + 1..pos + 21].to_vec();
    pos += 21;

    // OP_ENDIF
    if script.get(pos)? != &(Opcode::OP_ENDIF as u8) {
        return None;
    }
    pos += 1;

    // OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
    if script.len() - pos != 4 {
        return None;
    }
    if script[pos] != Opcode::OP_OVER as u8
        || script[pos + 1] != Opcode::OP_HASH160 as u8
        || script[pos + 2] != Opcode::OP_EQUALVERIFY as u8
        || script[pos + 3] != Opcode::OP_CHECKSIG as u8
    {
        return None;
    }

    Some(vec![
        vec![*hash_type],
        hash_value,
        receiver_hash,
        timeout_value,
        sender_hash,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create script bytes
    fn make_p2pkh(hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::with_capacity(25);
        script.push(0x76); // OP_DUP
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(hash);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        script
    }

    fn make_p2sh(hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::with_capacity(23);
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(hash);
        script.push(0x87); // OP_EQUAL
        script
    }

    fn make_p2pk_compressed(pubkey: &[u8; 33]) -> Vec<u8> {
        let mut script = Vec::with_capacity(35);
        script.push(0x21); // Push 33 bytes
        script.extend_from_slice(pubkey);
        script.push(0xac); // OP_CHECKSIG
        script
    }

    fn make_p2pk_uncompressed(pubkey: &[u8; 65]) -> Vec<u8> {
        let mut script = Vec::with_capacity(67);
        script.push(0x41); // Push 65 bytes
        script.extend_from_slice(pubkey);
        script.push(0xac); // OP_CHECKSIG
        script
    }

    fn make_nulldata(data: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(0x6a); // OP_RETURN/OP_META
        if data.len() <= 75 {
            script.push(data.len() as u8);
        } else if data.len() <= 255 {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(data.len() as u8);
        }
        script.extend_from_slice(data);
        script
    }

    fn make_multisig_2of3(pubkeys: &[[u8; 33]; 3]) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(0x52); // OP_2
        for pk in pubkeys {
            script.push(0x21); // Push 33 bytes
            script.extend_from_slice(pk);
        }
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG
        script
    }

    #[test]
    fn test_is_p2pkh() {
        let hash = [0xab; 20];
        let script = make_p2pkh(&hash);
        assert!(is_p2pkh(&script));

        // Wrong length
        assert!(!is_p2pkh(&script[..24]));

        // Wrong opcodes
        let mut bad = script.clone();
        bad[0] = 0x00;
        assert!(!is_p2pkh(&bad));
    }

    #[test]
    fn test_is_p2sh() {
        let hash = [0xcd; 20];
        let script = make_p2sh(&hash);
        assert!(is_p2sh(&script));

        // Wrong length
        assert!(!is_p2sh(&script[..22]));

        // Wrong opcodes
        let mut bad = script.clone();
        bad[22] = 0x88; // OP_EQUALVERIFY instead of OP_EQUAL
        assert!(!is_p2sh(&bad));
    }

    #[test]
    fn test_is_p2pk_compressed() {
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02; // Compressed pubkey prefix
        let script = make_p2pk_compressed(&pubkey);
        assert!(is_p2pk(&script));
    }

    #[test]
    fn test_is_p2pk_uncompressed() {
        let mut pubkey = [0u8; 65];
        pubkey[0] = 0x04; // Uncompressed pubkey prefix
        let script = make_p2pk_uncompressed(&pubkey);
        assert!(is_p2pk(&script));
    }

    #[test]
    fn test_is_null_data() {
        let data = b"Hello, Divi!";
        let script = make_nulldata(data);
        assert!(is_null_data(&script));

        // Empty data
        let empty_nulldata = vec![0x6a]; // Just OP_META
        assert!(is_null_data(&empty_nulldata));

        // Non-push-only after OP_META should fail
        let bad = vec![0x6a, 0x76]; // OP_META OP_DUP
        assert!(!is_null_data(&bad));
    }

    #[test]
    fn test_is_multisig() {
        let pk1 = [0x02; 33];
        let pk2 = [0x03; 33];
        let mut pk3 = [0x02; 33];
        pk3[1] = 0xff;

        let script = make_multisig_2of3(&[pk1, pk2, pk3]);
        let result = is_multisig(&script);
        assert_eq!(result, Some((2, 3)));
    }

    #[test]
    fn test_multisig_invalid() {
        // Not enough bytes
        assert!(is_multisig(&[0x51, 0x51, 0xae]).is_none());

        // m > n
        let mut bad = vec![0x53]; // OP_3
        bad.push(0x21);
        bad.extend_from_slice(&[0x02; 33]);
        bad.push(0x52); // OP_2
        bad.push(0xae);
        assert!(is_multisig(&bad).is_none());
    }

    #[test]
    fn test_extract_script_type_p2pkh() {
        let hash = [0x11; 20];
        let script = make_p2pkh(&hash);
        let (script_type, solutions) = extract_script_type(&script);

        assert_eq!(script_type, ScriptType::PubKeyHash);
        assert_eq!(solutions.len(), 1);
        assert_eq!(solutions[0], hash.to_vec());
    }

    #[test]
    fn test_extract_script_type_p2sh() {
        let hash = [0x22; 20];
        let script = make_p2sh(&hash);
        let (script_type, solutions) = extract_script_type(&script);

        assert_eq!(script_type, ScriptType::ScriptHash);
        assert_eq!(solutions.len(), 1);
        assert_eq!(solutions[0], hash.to_vec());
    }

    #[test]
    fn test_extract_script_type_p2pk() {
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        let script = make_p2pk_compressed(&pubkey);
        let (script_type, solutions) = extract_script_type(&script);

        assert_eq!(script_type, ScriptType::PubKey);
        assert_eq!(solutions.len(), 1);
        assert_eq!(solutions[0], pubkey.to_vec());
    }

    #[test]
    fn test_extract_script_type_nulldata() {
        let data = b"test data";
        let script = make_nulldata(data);
        let (script_type, solutions) = extract_script_type(&script);

        assert_eq!(script_type, ScriptType::NullData);
        assert!(solutions.is_empty());
    }

    #[test]
    fn test_extract_script_type_multisig() {
        let pk1 = [0x02; 33];
        let pk2 = [0x03; 33];
        let mut pk3 = [0x02; 33];
        pk3[1] = 0xaa;

        let script = make_multisig_2of3(&[pk1, pk2, pk3]);
        let (script_type, solutions) = extract_script_type(&script);

        assert_eq!(script_type, ScriptType::Multisig);
        assert_eq!(solutions.len(), 5); // m, pk1, pk2, pk3, n
        assert_eq!(solutions[0], vec![2u8]);
        assert_eq!(solutions[1], pk1.to_vec());
        assert_eq!(solutions[2], pk2.to_vec());
        assert_eq!(solutions[3], pk3.to_vec());
        assert_eq!(solutions[4], vec![3u8]);
    }

    #[test]
    fn test_extract_destination_p2pkh() {
        let hash = [0x33; 20];
        let script = make_p2pkh(&hash);
        let dest = extract_destination(&script);

        assert_eq!(dest, Some(Destination::PubKeyHash(hash)));
    }

    #[test]
    fn test_extract_destination_p2sh() {
        let hash = [0x44; 20];
        let script = make_p2sh(&hash);
        let dest = extract_destination(&script);

        assert_eq!(dest, Some(Destination::ScriptHash(hash)));
    }

    #[test]
    fn test_extract_destination_p2pk() {
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02;
        pubkey[1..].fill(0x55);

        let script = make_p2pk_compressed(&pubkey);
        let dest = extract_destination(&script);

        // Should return PubKeyHash with hash160 of pubkey
        assert!(matches!(dest, Some(Destination::PubKeyHash(_))));
    }

    #[test]
    fn test_extract_destinations_multisig() {
        let pk1 = [0x02; 33];
        let pk2 = [0x03; 33];
        let mut pk3 = [0x02; 33];
        pk3[1] = 0xbb;

        let script = make_multisig_2of3(&[pk1, pk2, pk3]);
        let result = extract_destinations(&script);

        assert!(result.is_some());
        let (script_type, destinations, required) = result.unwrap();

        assert_eq!(script_type, ScriptType::Multisig);
        assert_eq!(destinations.len(), 3);
        assert_eq!(required, 2);

        // All destinations should be PubKeyHash
        for dest in &destinations {
            assert!(matches!(dest, Destination::PubKeyHash(_)));
        }
    }

    #[test]
    fn test_get_script_type_name() {
        assert_eq!(get_script_type_name(ScriptType::NonStandard), "nonstandard");
        assert_eq!(get_script_type_name(ScriptType::PubKey), "pubkey");
        assert_eq!(get_script_type_name(ScriptType::PubKeyHash), "pubkeyhash");
        assert_eq!(get_script_type_name(ScriptType::ScriptHash), "scripthash");
        assert_eq!(get_script_type_name(ScriptType::Vault), "vault");
        assert_eq!(get_script_type_name(ScriptType::Htlc), "htlc");
        assert_eq!(get_script_type_name(ScriptType::Multisig), "multisig");
        assert_eq!(get_script_type_name(ScriptType::NullData), "nulldata");
    }

    #[test]
    fn test_is_push_only() {
        // Empty is push-only
        assert!(is_push_only(&[]));

        // Direct push
        assert!(is_push_only(&[0x04, 0x01, 0x02, 0x03, 0x04]));

        // OP_PUSHDATA1
        assert!(is_push_only(&[0x4c, 0x02, 0xab, 0xcd]));

        // OP_0
        assert!(is_push_only(&[0x00]));

        // OP_1 through OP_16
        assert!(is_push_only(&[0x51, 0x52, 0x60])); // OP_1, OP_2, OP_16

        // OP_1NEGATE
        assert!(is_push_only(&[0x4f]));

        // Non-push opcode
        assert!(!is_push_only(&[0x76])); // OP_DUP
        assert!(!is_push_only(&[0xac])); // OP_CHECKSIG
    }

    #[test]
    fn test_decode_op_n() {
        assert_eq!(decode_op_n(0x00), Some(0)); // OP_0
        assert_eq!(decode_op_n(0x51), Some(1)); // OP_1
        assert_eq!(decode_op_n(0x52), Some(2)); // OP_2
        assert_eq!(decode_op_n(0x60), Some(16)); // OP_16
        assert_eq!(decode_op_n(0x61), None); // OP_NOP - not a number opcode
        assert_eq!(decode_op_n(0x76), None); // OP_DUP - not a number opcode
    }

    #[test]
    fn test_vault_script_detection() {
        let owner_hash = [0xaa; 20];
        let vault_hash = [0xbb; 20];

        let vault = StakingVaultScript::new(owner_hash, vault_hash);
        let script = vault.to_script();

        let (script_type, solutions) = extract_script_type(script.as_bytes());

        assert_eq!(script_type, ScriptType::Vault);
        assert_eq!(solutions.len(), 2);
        assert_eq!(solutions[0], owner_hash.to_vec());
        assert_eq!(solutions[1], vault_hash.to_vec());
    }

    #[test]
    fn test_nonstandard_script() {
        // Random garbage
        let script = vec![0x76, 0xa9, 0x00, 0x88]; // Incomplete P2PKH
        let (script_type, solutions) = extract_script_type(&script);

        assert_eq!(script_type, ScriptType::NonStandard);
        assert!(solutions.is_empty());
    }
}
