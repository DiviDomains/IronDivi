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

//! Comprehensive integration tests for divi-script.
//!
//! These tests cover script type detection, vault scripts, HTLC scripts,
//! multisig variants, and interpreter/opcode execution – filling gaps
//! not covered by the inline unit tests already present in each module.

use divi_primitives::script::Script;
use divi_script::{
    error::{ScriptError, ScriptFlags},
    interpreter::{NullChecker, ScriptInterpreter, SignatureChecker},
    is_multisig, is_null_data, is_p2pk, is_p2pkh, is_p2sh,
    opcodes::Opcode,
    stack::{ScriptNum, Stack, MAX_STACK_SIZE},
    standard::{
        extract_destination, extract_destinations, extract_script_type, get_script_type_name,
    },
    vault::{get_vault_pubkey_hashes, is_staking_vault_script, StakingVaultScript},
    Destination, ScriptType,
};

// =============================================================================
// Helper builders
// =============================================================================

fn make_script(bytes: &[u8]) -> Script {
    Script::from_bytes(bytes.to_vec())
}

fn make_p2pkh(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(hash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

fn make_p2sh(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(23);
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(hash);
    s.push(0x87); // OP_EQUAL
    s
}

fn make_p2pk_compressed(pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(35);
    s.push(0x21); // push 33 bytes
    s.extend_from_slice(pubkey);
    s.push(0xac); // OP_CHECKSIG
    s
}

fn make_p2pk_uncompressed(pubkey: &[u8; 65]) -> Vec<u8> {
    let mut s = Vec::with_capacity(67);
    s.push(0x41); // push 65 bytes
    s.extend_from_slice(pubkey);
    s.push(0xac); // OP_CHECKSIG
    s
}

/// Build a generic m-of-n multisig script from compressed pubkeys (each 33 bytes).
fn make_multisig(m: u8, pubkeys: &[[u8; 33]]) -> Vec<u8> {
    let n = pubkeys.len() as u8;
    let mut s = Vec::new();
    s.push(0x50 + m); // OP_m (OP_1 = 0x51 … OP_16 = 0x60)
    for pk in pubkeys {
        s.push(0x21); // push 33 bytes
        s.extend_from_slice(pk);
    }
    s.push(0x50 + n); // OP_n
    s.push(0xae); // OP_CHECKMULTISIG
    s
}

fn make_nulldata(data: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    s.push(0x6a); // OP_RETURN / OP_META
    if data.len() <= 75 {
        s.push(data.len() as u8);
    } else {
        s.push(0x4c); // OP_PUSHDATA1
        s.push(data.len() as u8);
    }
    s.extend_from_slice(data);
    s
}

// =============================================================================
// 1. Script type detection – additional variants
// =============================================================================

mod script_type_detection {
    use super::*;

    // --- P2PKH ---

    #[test]
    fn p2pkh_correct() {
        let hash = [0x11u8; 20];
        assert!(is_p2pkh(&make_p2pkh(&hash)));
    }

    #[test]
    fn p2pkh_wrong_first_opcode() {
        let hash = [0u8; 20];
        let mut s = make_p2pkh(&hash);
        s[0] = 0x00; // break OP_DUP
        assert!(!is_p2pkh(&s));
    }

    #[test]
    fn p2pkh_wrong_hash_size_byte() {
        let hash = [0u8; 20];
        let mut s = make_p2pkh(&hash);
        s[2] = 0x13; // push 19 instead of 20
        assert!(!is_p2pkh(&s));
    }

    #[test]
    fn p2pkh_wrong_trailing_opcode() {
        let hash = [0u8; 20];
        let mut s = make_p2pkh(&hash);
        // Replace OP_CHECKSIG with OP_EQUAL
        *s.last_mut().unwrap() = 0x87;
        assert!(!is_p2pkh(&s));
    }

    #[test]
    fn p2pkh_too_short() {
        assert!(!is_p2pkh(&[0x76, 0xa9, 0x14]));
    }

    #[test]
    fn p2pkh_too_long() {
        let hash = [0u8; 20];
        let mut s = make_p2pkh(&hash);
        s.push(0x00); // extra byte
        assert!(!is_p2pkh(&s));
    }

    // --- P2SH ---

    #[test]
    fn p2sh_correct() {
        let hash = [0x22u8; 20];
        assert!(is_p2sh(&make_p2sh(&hash)));
    }

    #[test]
    fn p2sh_wrong_leading_opcode() {
        let hash = [0u8; 20];
        let mut s = make_p2sh(&hash);
        s[0] = 0x76; // OP_DUP instead of OP_HASH160
        assert!(!is_p2sh(&s));
    }

    #[test]
    fn p2sh_wrong_trailing_opcode() {
        let hash = [0u8; 20];
        let mut s = make_p2sh(&hash);
        *s.last_mut().unwrap() = 0x88; // OP_EQUALVERIFY instead of OP_EQUAL
        assert!(!is_p2sh(&s));
    }

    // --- P2PK compressed ---

    #[test]
    fn p2pk_compressed_prefix_02() {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk[1] = 0xab;
        assert!(is_p2pk(&make_p2pk_compressed(&pk)));
    }

    #[test]
    fn p2pk_compressed_prefix_03() {
        let mut pk = [0u8; 33];
        pk[0] = 0x03;
        assert!(is_p2pk(&make_p2pk_compressed(&pk)));
    }

    #[test]
    fn p2pk_compressed_wrong_prefix_rejected() {
        // Prefix 0x04 is uncompressed, not valid for a 33-byte key in P2PK
        let mut pk = [0u8; 33];
        pk[0] = 0x04;
        assert!(!is_p2pk(&make_p2pk_compressed(&pk)));
    }

    #[test]
    fn p2pk_compressed_wrong_trailing_opcode() {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        let mut s = make_p2pk_compressed(&pk);
        *s.last_mut().unwrap() = 0x88; // OP_EQUALVERIFY instead of OP_CHECKSIG
        assert!(!is_p2pk(&s));
    }

    // --- P2PK uncompressed ---

    #[test]
    fn p2pk_uncompressed_correct() {
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        assert!(is_p2pk(&make_p2pk_uncompressed(&pk)));
    }

    #[test]
    fn p2pk_uncompressed_wrong_prefix_rejected() {
        let mut pk = [0u8; 65];
        pk[0] = 0x02; // compressed prefix on uncompressed-size key
        assert!(!is_p2pk(&make_p2pk_uncompressed(&pk)));
    }

    // --- NullData ---

    #[test]
    fn nulldata_empty_payload() {
        // Just OP_RETURN with no push after
        assert!(is_null_data(&[0x6a]));
    }

    #[test]
    fn nulldata_with_data() {
        let data = b"hello";
        assert!(is_null_data(&make_nulldata(data)));
    }

    #[test]
    fn nulldata_with_pushdata1() {
        let data = vec![0xabu8; 100];
        let script = make_nulldata(&data);
        assert!(is_null_data(&script));
    }

    #[test]
    fn nulldata_non_push_after_op_return_rejected() {
        // OP_RETURN OP_DUP → not push-only
        assert!(!is_null_data(&[0x6a, 0x76]));
    }

    #[test]
    fn nulldata_wrong_leading_opcode_rejected() {
        let data = b"test";
        let mut s = make_nulldata(data);
        s[0] = 0x76; // OP_DUP instead of OP_RETURN
        assert!(!is_null_data(&s));
    }

    #[test]
    fn nulldata_empty_script_rejected() {
        assert!(!is_null_data(&[]));
    }

    // --- Multisig variants ---

    #[test]
    fn multisig_1_of_2() {
        let pk1 = compressed_pk(0x02, 1);
        let pk2 = compressed_pk(0x03, 2);
        let script = make_multisig(1, &[pk1, pk2]);
        assert_eq!(is_multisig(&script), Some((1, 2)));
    }

    #[test]
    fn multisig_2_of_2() {
        let pk1 = compressed_pk(0x02, 1);
        let pk2 = compressed_pk(0x03, 2);
        let script = make_multisig(2, &[pk1, pk2]);
        assert_eq!(is_multisig(&script), Some((2, 2)));
    }

    #[test]
    fn multisig_2_of_3() {
        let pks = [
            compressed_pk(0x02, 1),
            compressed_pk(0x03, 2),
            compressed_pk(0x02, 3),
        ];
        let script = make_multisig(2, &pks);
        assert_eq!(is_multisig(&script), Some((2, 3)));
    }

    #[test]
    fn multisig_3_of_5() {
        let pks: Vec<[u8; 33]> = (1u8..=5).map(|i| compressed_pk(0x02, i)).collect();
        let script = make_multisig(3, &pks);
        let arr: [[u8; 33]; 5] = pks.try_into().unwrap();
        let script2 = make_multisig(3, &arr);
        assert_eq!(is_multisig(&script2), Some((3, 5)));
        let _ = script; // silence unused warning
    }

    #[test]
    fn multisig_m_greater_than_n_rejected() {
        // Build a script that claims m=3, n=2
        let pk1 = compressed_pk(0x02, 1);
        let pk2 = compressed_pk(0x03, 2);
        let mut s = vec![0x53u8]; // OP_3 (m=3)
        s.push(0x21);
        s.extend_from_slice(&pk1);
        s.push(0x21);
        s.extend_from_slice(&pk2);
        s.push(0x52); // OP_2 (n=2)
        s.push(0xae); // OP_CHECKMULTISIG
        assert!(is_multisig(&s).is_none());
    }

    #[test]
    fn multisig_missing_checkmultisig_opcode_rejected() {
        let pk = compressed_pk(0x02, 1);
        let mut s = make_multisig(1, &[pk]);
        // Replace OP_CHECKMULTISIG with OP_CHECKSIG
        *s.last_mut().unwrap() = 0xac;
        assert!(is_multisig(&s).is_none());
    }

    #[test]
    fn multisig_wrong_pubkey_length_rejected() {
        // Build a script with a 32-byte "pubkey" (too short)
        let mut s = vec![0x51u8]; // OP_1
        s.push(0x20); // push 32 bytes
        s.extend_from_slice(&[0x02u8; 32]);
        s.push(0x51); // OP_1
        s.push(0xae); // OP_CHECKMULTISIG
        assert!(is_multisig(&s).is_none());
    }

    #[test]
    fn multisig_extract_script_type_1of2() {
        let pk1 = compressed_pk(0x02, 1);
        let pk2 = compressed_pk(0x03, 2);
        let script = make_multisig(1, &[pk1, pk2]);
        let (st, sols) = extract_script_type(&script);
        assert_eq!(st, ScriptType::Multisig);
        // solutions: [m=1], pk1, pk2, [n=2]
        assert_eq!(sols.len(), 4);
        assert_eq!(sols[0], vec![1u8]);
        assert_eq!(sols[1], pk1.to_vec());
        assert_eq!(sols[2], pk2.to_vec());
        assert_eq!(sols[3], vec![2u8]);
    }

    #[test]
    fn multisig_extract_destinations_2of2() {
        let pk1 = compressed_pk(0x02, 1);
        let pk2 = compressed_pk(0x03, 2);
        let script = make_multisig(2, &[pk1, pk2]);
        let result = extract_destinations(&script).unwrap();
        let (st, dests, required) = result;
        assert_eq!(st, ScriptType::Multisig);
        assert_eq!(required, 2);
        assert_eq!(dests.len(), 2);
        for d in &dests {
            assert!(matches!(d, Destination::PubKeyHash(_)));
        }
    }

    // --- NonStandard ---

    #[test]
    fn nonstandard_empty_script() {
        let (st, sols) = extract_script_type(&[]);
        assert_eq!(st, ScriptType::NonStandard);
        assert!(sols.is_empty());
    }

    #[test]
    fn nonstandard_single_byte() {
        let (st, _) = extract_script_type(&[0x76]);
        assert_eq!(st, ScriptType::NonStandard);
    }

    #[test]
    fn nonstandard_random_garbage() {
        let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let (st, _) = extract_script_type(&garbage);
        assert_eq!(st, ScriptType::NonStandard);
    }

    // --- get_script_type_name ---

    #[test]
    fn script_type_names_all_variants() {
        assert_eq!(get_script_type_name(ScriptType::NonStandard), "nonstandard");
        assert_eq!(get_script_type_name(ScriptType::PubKey), "pubkey");
        assert_eq!(get_script_type_name(ScriptType::PubKeyHash), "pubkeyhash");
        assert_eq!(get_script_type_name(ScriptType::ScriptHash), "scripthash");
        assert_eq!(get_script_type_name(ScriptType::Vault), "vault");
        assert_eq!(get_script_type_name(ScriptType::Htlc), "htlc");
        assert_eq!(get_script_type_name(ScriptType::Multisig), "multisig");
        assert_eq!(get_script_type_name(ScriptType::NullData), "nulldata");
    }

    // --- extract_destination ---

    #[test]
    fn extract_destination_nulldata_returns_none() {
        let script = make_nulldata(b"data");
        assert!(extract_destination(&script).is_none());
    }

    #[test]
    fn extract_destination_multisig_returns_none() {
        let pks = [compressed_pk(0x02, 1), compressed_pk(0x03, 2)];
        let script = make_multisig(1, &pks);
        assert!(extract_destination(&script).is_none());
    }

    #[test]
    fn extract_destination_nonstandard_returns_none() {
        assert!(extract_destination(&[0xde, 0xad]).is_none());
    }

    #[test]
    fn extract_destination_p2pk_uncompressed() {
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        pk[1] = 0xab;
        let script = make_p2pk_uncompressed(&pk);
        let dest = extract_destination(&script);
        assert!(matches!(dest, Some(Destination::PubKeyHash(_))));
    }

    // Helper: build a compressed pubkey with a given prefix and fill byte
    fn compressed_pk(prefix: u8, fill: u8) -> [u8; 33] {
        let mut pk = [fill; 33];
        pk[0] = prefix;
        pk
    }
}

// =============================================================================
// 2. Vault scripts
// =============================================================================

mod vault_scripts {
    use super::*;

    #[test]
    fn roundtrip_distinct_hashes() {
        let owner = [0xaa; 20];
        let vault = [0xbb; 20];
        let v = StakingVaultScript::new(owner, vault);
        let script = v.to_script();
        let parsed = StakingVaultScript::from_script(&script).unwrap();
        assert_eq!(parsed.owner_pubkey_hash, owner);
        assert_eq!(parsed.vault_pubkey_hash, vault);
        assert_eq!(parsed.reward_destination_hash, None);
    }

    #[test]
    fn roundtrip_all_zero_hashes() {
        let owner = [0x00; 20];
        let vault = [0x00; 20];
        let v = StakingVaultScript::new(owner, vault);
        let script = v.to_script();
        let parsed = StakingVaultScript::from_script(&script).unwrap();
        assert_eq!(parsed.owner_pubkey_hash, owner);
        assert_eq!(parsed.vault_pubkey_hash, vault);
    }

    #[test]
    fn roundtrip_all_ff_hashes() {
        let owner = [0xff; 20];
        let vault = [0xff; 20];
        let v = StakingVaultScript::new(owner, vault);
        let script = v.to_script();
        let parsed = StakingVaultScript::from_script(&script).unwrap();
        assert_eq!(parsed.owner_pubkey_hash, owner);
        assert_eq!(parsed.vault_pubkey_hash, vault);
    }

    #[test]
    fn is_vault_true_for_valid_vault() {
        let v = StakingVaultScript::new([1u8; 20], [2u8; 20]);
        assert!(is_staking_vault_script(&v.to_script()));
    }

    #[test]
    fn is_vault_false_for_p2pkh() {
        let p2pkh = Script::new_p2pkh(&[0u8; 20]);
        assert!(!is_staking_vault_script(&p2pkh));
    }

    #[test]
    fn is_vault_false_for_empty_script() {
        let empty = Script::from_bytes(vec![]);
        assert!(!is_staking_vault_script(&empty));
    }

    #[test]
    fn is_vault_false_for_truncated_script() {
        let v = StakingVaultScript::new([1u8; 20], [2u8; 20]);
        let script = v.to_script();
        // Truncate by 1 byte
        let truncated = Script::from_bytes(script.as_bytes()[..49].to_vec());
        assert!(!is_staking_vault_script(&truncated));
    }

    #[test]
    fn is_vault_false_wrong_op_if() {
        let v = StakingVaultScript::new([1u8; 20], [2u8; 20]);
        let mut bytes = v.to_script().as_bytes().to_vec();
        bytes[0] = Opcode::OP_NOTIF as u8; // corrupt first byte
        assert!(!is_staking_vault_script(&Script::from_bytes(bytes)));
    }

    #[test]
    fn is_vault_false_wrong_op_else() {
        let v = StakingVaultScript::new([1u8; 20], [2u8; 20]);
        let mut bytes = v.to_script().as_bytes().to_vec();
        bytes[22] = Opcode::OP_ENDIF as u8; // position of OP_ELSE
        assert!(!is_staking_vault_script(&Script::from_bytes(bytes)));
    }

    #[test]
    fn is_vault_false_wrong_trailing_opcodes() {
        let v = StakingVaultScript::new([1u8; 20], [2u8; 20]);
        let mut bytes = v.to_script().as_bytes().to_vec();
        // Replace last OP_CHECKSIG with OP_EQUAL
        *bytes.last_mut().unwrap() = Opcode::OP_EQUAL as u8;
        assert!(!is_staking_vault_script(&Script::from_bytes(bytes)));
    }

    #[test]
    fn get_vault_pubkey_hashes_correct() {
        let owner = [0xcc; 20];
        let vault = [0xdd; 20];
        let v = StakingVaultScript::new(owner, vault);
        let script = v.to_script();
        let (o, vk) = get_vault_pubkey_hashes(&script).unwrap();
        assert_eq!(o, owner);
        assert_eq!(vk, vault);
    }

    #[test]
    fn get_vault_pubkey_hashes_none_for_p2pkh() {
        let p2pkh = Script::new_p2pkh(&[0u8; 20]);
        assert!(get_vault_pubkey_hashes(&p2pkh).is_none());
    }

    #[test]
    fn extract_script_type_vault() {
        let owner = [0xaa; 20];
        let vault = [0xbb; 20];
        let v = StakingVaultScript::new(owner, vault);
        let (st, sols) = extract_script_type(v.to_script().as_bytes());
        assert_eq!(st, ScriptType::Vault);
        assert_eq!(sols.len(), 2);
        assert_eq!(sols[0], owner.to_vec());
        assert_eq!(sols[1], vault.to_vec());
    }

    #[test]
    fn extract_destinations_vault_returns_two_pkh() {
        let owner = [0xaa; 20];
        let vault = [0xbb; 20];
        let v = StakingVaultScript::new(owner, vault);
        let result = extract_destinations(v.to_script().as_bytes()).unwrap();
        let (st, dests, required) = result;
        assert_eq!(st, ScriptType::Vault);
        assert_eq!(required, 1);
        assert_eq!(dests.len(), 2);
        assert_eq!(dests[0], Destination::PubKeyHash(owner));
        assert_eq!(dests[1], Destination::PubKeyHash(vault));
    }

    #[test]
    fn new_extended_vault_has_reward_hash() {
        let owner = [1u8; 20];
        let vault = [2u8; 20];
        let reward = [3u8; 20];
        let v = StakingVaultScript::new_extended(owner, vault, reward);
        assert_eq!(v.owner_pubkey_hash, owner);
        assert_eq!(v.vault_pubkey_hash, vault);
        assert_eq!(v.reward_destination_hash, Some(reward));
    }

    #[test]
    fn vault_script_exact_length() {
        let v = StakingVaultScript::new([1u8; 20], [2u8; 20]);
        let script = v.to_script();
        // OP_IF(1)+push(1)+20+OP_ELSE(1)+OP_REQUIRE_COINSTAKE(1)+push(1)+20
        // +OP_ENDIF(1)+OP_OVER(1)+OP_HASH160(1)+OP_EQUALVERIFY(1)+OP_CHECKSIG(1) = 50
        assert_eq!(script.as_bytes().len(), 50);
    }
}

// =============================================================================
// 3. HTLC scripts
// =============================================================================

mod htlc_scripts {
    use super::*;

    /// Build a minimal valid HTLC script.
    ///
    /// Template (from standard.rs comments):
    /// `<hash_type> <hash_value> OP_EQUAL OP_IF <receiver_hash> OP_ELSE <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_hash> OP_ENDIF OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG`
    fn make_htlc(
        hash_type: u8,
        hash_value: &[u8],
        receiver_hash: &[u8; 20],
        timeout: &[u8],
        sender_hash: &[u8; 20],
    ) -> Vec<u8> {
        let mut s = Vec::new();
        s.push(hash_type);
        s.push(hash_value.len() as u8);
        s.extend_from_slice(hash_value);
        s.push(Opcode::OP_EQUAL as u8);
        s.push(Opcode::OP_IF as u8);
        s.push(0x14); // push 20
        s.extend_from_slice(receiver_hash);
        s.push(Opcode::OP_ELSE as u8);
        s.push(timeout.len() as u8);
        s.extend_from_slice(timeout);
        s.push(Opcode::OP_CHECKLOCKTIMEVERIFY as u8);
        s.push(Opcode::OP_DROP as u8);
        s.push(0x14); // push 20
        s.extend_from_slice(sender_hash);
        s.push(Opcode::OP_ENDIF as u8);
        s.push(Opcode::OP_OVER as u8);
        s.push(Opcode::OP_HASH160 as u8);
        s.push(Opcode::OP_EQUALVERIFY as u8);
        s.push(Opcode::OP_CHECKSIG as u8);
        s
    }

    #[test]
    fn htlc_detection_hash160() {
        let hash_value = [0xabu8; 20]; // HASH160 produces 20 bytes
        let receiver = [0x11u8; 20];
        let timeout = [0x04u8, 0x00, 0x00, 0x00]; // block 4 (LE CScriptNum)
        let sender = [0x22u8; 20];
        let script = make_htlc(0xa9, &hash_value, &receiver, &timeout, &sender);
        let (st, sols) = extract_script_type(&script);
        assert_eq!(st, ScriptType::Htlc);
        // solutions: [hash_type], hash_value, receiver_hash, timeout_value, sender_hash
        assert_eq!(sols.len(), 5);
        assert_eq!(sols[0], vec![0xa9u8]); // HASH160 opcode byte
        assert_eq!(sols[1], hash_value.to_vec());
        assert_eq!(sols[2], receiver.to_vec());
        assert_eq!(sols[3], timeout.to_vec());
        assert_eq!(sols[4], sender.to_vec());
    }

    #[test]
    fn htlc_detection_sha256() {
        let hash_value = [0xbbu8; 32]; // SHA256 produces 32 bytes
        let receiver = [0x33u8; 20];
        let timeout = ScriptNum::new(100).encode();
        let sender = [0x44u8; 20];
        let script = make_htlc(0xa8, &hash_value, &receiver, &timeout, &sender);
        let (st, sols) = extract_script_type(&script);
        assert_eq!(st, ScriptType::Htlc);
        assert_eq!(sols[0], vec![0xa8u8]); // SHA256 opcode byte
        assert_eq!(sols[1], hash_value.to_vec());
    }

    #[test]
    fn htlc_detection_ripemd160() {
        let hash_value = [0xcc; 20];
        let receiver = [0x55u8; 20];
        let timeout = ScriptNum::new(500).encode();
        let sender = [0x66u8; 20];
        let script = make_htlc(0xa6, &hash_value, &receiver, &timeout, &sender);
        let (st, _) = extract_script_type(&script);
        assert_eq!(st, ScriptType::Htlc);
    }

    #[test]
    fn htlc_extract_all_fields() {
        let hash_value = [0x01u8; 32];
        let receiver = [0x02u8; 20];
        let timeout = ScriptNum::new(1000).encode();
        let sender = [0x03u8; 20];
        let script = make_htlc(0xa8, &hash_value, &receiver, &timeout, &sender);
        let (st, sols) = extract_script_type(&script);
        assert_eq!(st, ScriptType::Htlc);
        assert_eq!(sols[1], hash_value.to_vec());
        assert_eq!(sols[2], receiver.to_vec());
        assert_eq!(sols[3], timeout);
        assert_eq!(sols[4], sender.to_vec());
    }

    #[test]
    fn htlc_not_detected_when_hash_type_wrong() {
        // Use a non-hash opcode as hash_type
        let hash_value = [0xabu8; 20];
        let receiver = [0x11u8; 20];
        let timeout = vec![0x01u8];
        let sender = [0x22u8; 20];
        // 0x76 = OP_DUP – not a valid hash-type opcode
        let script = make_htlc(0x76, &hash_value, &receiver, &timeout, &sender);
        let (st, _) = extract_script_type(&script);
        // Should fall through to NonStandard since 0x76 is not a hash opcode
        assert_ne!(st, ScriptType::Htlc);
    }

    #[test]
    fn htlc_too_short_not_detected() {
        // A script shorter than 60 bytes is rejected immediately
        let script = vec![0xa9u8; 30];
        let (st, _) = extract_script_type(&script);
        assert_ne!(st, ScriptType::Htlc);
    }
}

// =============================================================================
// 4. Interpreter – opcode execution
// =============================================================================

mod interpreter_opcodes {
    use super::*;

    fn eval_ok(bytes: &[u8]) -> bool {
        let script = make_script(bytes);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        match interp.eval(&script) {
            Ok(()) => interp.success(),
            Err(_) => false,
        }
    }

    fn eval_err(bytes: &[u8]) -> ScriptError {
        let script = make_script(bytes);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        interp.eval(&script).unwrap_err()
    }

    // --- OP_DUP ---

    #[test]
    fn op_dup_duplicates_top() {
        // Push 0x05 (OP_5), dup, equal → true
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_DUP as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_dup_on_empty_stack_fails() {
        let script = make_script(&[Opcode::OP_DUP as u8]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        assert!(interp.eval(&script).is_err());
    }

    // --- OP_HASH160 ---

    #[test]
    fn op_hash160_produces_20_bytes() {
        // Push data, hash160, size → 20
        assert!(eval_ok(&[
            0x04,
            0x01,
            0x02,
            0x03,
            0x04, // push 4 bytes
            Opcode::OP_HASH160 as u8,
            Opcode::OP_SIZE as u8,
            0x01,
            0x14, // push 20 (0x14)
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- OP_EQUALVERIFY ---

    #[test]
    fn op_equalverify_passes_when_equal() {
        // Push 5, dup, equalverify, then push true so script succeeds
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_DUP as u8,
            Opcode::OP_EQUALVERIFY as u8,
            Opcode::OP_1 as u8,
        ]));
    }

    #[test]
    fn op_equalverify_fails_when_not_equal() {
        let err = eval_err(&[
            Opcode::OP_5 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_EQUALVERIFY as u8,
        ]);
        assert_eq!(err, ScriptError::EqualVerify);
    }

    // --- OP_VERIFY ---

    #[test]
    fn op_verify_passes_with_true() {
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_VERIFY as u8,
            Opcode::OP_1 as u8,
        ]));
    }

    #[test]
    fn op_verify_fails_with_false() {
        let err = eval_err(&[Opcode::OP_0 as u8, Opcode::OP_VERIFY as u8]);
        assert_eq!(err, ScriptError::Verify);
    }

    // --- OP_NOT / OP_0NOTEQUAL ---

    #[test]
    fn op_not_zero_gives_one() {
        assert!(eval_ok(&[
            Opcode::OP_0 as u8,
            Opcode::OP_NOT as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_not_one_gives_zero() {
        assert!(!eval_ok(&[Opcode::OP_1 as u8, Opcode::OP_NOT as u8]));
    }

    #[test]
    fn op_0notequal_nonzero_gives_one() {
        assert!(eval_ok(&[Opcode::OP_5 as u8, Opcode::OP_0NOTEQUAL as u8,]));
    }

    // --- OP_NEGATE / OP_ABS ---

    #[test]
    fn op_negate() {
        // 3 negate → -3; -3 abs → 3; 3 OP_3 EQUAL → true
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_NEGATE as u8,
            Opcode::OP_ABS as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- OP_ADD / OP_SUB ---

    #[test]
    fn op_sub() {
        // 5 - 3 = 2
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_SUB as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- OP_MIN / OP_MAX ---

    #[test]
    fn op_min() {
        // min(3, 5) = 3
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_MIN as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_max() {
        // max(3, 5) = 5
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_MAX as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- OP_WITHIN ---

    #[test]
    fn op_within_in_range() {
        // within(3, 1, 5) → true (1 <= 3 < 5)
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_WITHIN as u8,
        ]));
    }

    #[test]
    fn op_within_out_of_range() {
        // within(5, 1, 5) → false (5 is not < 5)
        assert!(!eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_WITHIN as u8,
        ]));
    }

    // --- OP_BOOLAND / OP_BOOLOR ---

    #[test]
    fn op_booland_true_true() {
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_BOOLAND as u8,
        ]));
    }

    #[test]
    fn op_booland_true_false() {
        assert!(!eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_0 as u8,
            Opcode::OP_BOOLAND as u8,
        ]));
    }

    #[test]
    fn op_boolor_false_false() {
        assert!(!eval_ok(&[
            Opcode::OP_0 as u8,
            Opcode::OP_0 as u8,
            Opcode::OP_BOOLOR as u8,
        ]));
    }

    #[test]
    fn op_boolor_false_true() {
        assert!(eval_ok(&[
            Opcode::OP_0 as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_BOOLOR as u8,
        ]));
    }

    // --- OP_LESSTHAN / OP_GREATERTHAN etc. ---

    #[test]
    fn op_lessthan_true() {
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_LESSTHAN as u8,
        ]));
    }

    #[test]
    fn op_greaterthan_true() {
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_GREATERTHAN as u8,
        ]));
    }

    #[test]
    fn op_lessthanorequal_equal() {
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_LESSTHANOREQUAL as u8,
        ]));
    }

    #[test]
    fn op_greaterthanorequal_equal() {
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_GREATERTHANOREQUAL as u8,
        ]));
    }

    // --- OP_NUMEQUAL / OP_NUMNOTEQUAL ---

    #[test]
    fn op_numequal_equal() {
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_NUMEQUAL as u8,
        ]));
    }

    #[test]
    fn op_numnotequal_different() {
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_NUMNOTEQUAL as u8,
        ]));
    }

    #[test]
    fn op_numequalverify_passes() {
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_NUMEQUALVERIFY as u8,
            Opcode::OP_1 as u8,
        ]));
    }

    #[test]
    fn op_numequalverify_fails() {
        let err = eval_err(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_NUMEQUALVERIFY as u8,
        ]);
        assert_eq!(err, ScriptError::NumEqualVerify);
    }

    // --- Stack operations ---

    #[test]
    fn op_drop() {
        // Push two values, drop top, check remaining
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_DROP as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_swap() {
        // [3, 5] → swap → [5, 3]; pop 3, check 5 remains
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_SWAP as u8,
            Opcode::OP_DROP as u8, // drop 3 (was bottom, now top after swap)
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_over() {
        // [3, 5] → over → [3, 5, 3]
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_OVER as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_EQUAL as u8, // top = 3
        ]));
    }

    #[test]
    fn op_2dup() {
        // [5, 5] → 2dup → [5, 5, 5, 5]
        // Top two are equal, bottom two are equal.
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_2DUP as u8,   // → [5, 5, 5, 5]
            Opcode::OP_EQUAL as u8,  // top two 5==5 → true
            Opcode::OP_VERIFY as u8, // consume true
            Opcode::OP_EQUAL as u8,  // bottom two 5==5 → true
        ]));
    }

    #[test]
    fn op_2drop() {
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_2DROP as u8,
            Opcode::OP_1 as u8, // stack was empty, push true
        ]));
    }

    #[test]
    fn op_toaltstack_fromaltstack() {
        // Push 5, move to alt, push 3, bring back 5, check equal
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_TOALTSTACK as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_DROP as u8,
            Opcode::OP_FROMALTSTACK as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_depth() {
        // Push 3 items, check depth
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_DEPTH as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_EQUAL as u8,
            Opcode::OP_VERIFY as u8,
            Opcode::OP_1 as u8, // leave stack non-empty and true
        ]));
    }

    #[test]
    fn op_size() {
        // Push 5 bytes, check size = 5
        assert!(eval_ok(&[
            0x05,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05, // push [1,2,3,4,5]
            Opcode::OP_SIZE as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
            Opcode::OP_VERIFY as u8,
            Opcode::OP_1 as u8,
        ]));
    }

    // --- OP_IFDUP ---

    #[test]
    fn op_ifdup_on_true_duplicates() {
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_IFDUP as u8,
            Opcode::OP_EQUAL as u8, // two 1s → equal → true
        ]));
    }

    #[test]
    fn op_ifdup_on_false_does_not_duplicate() {
        // OP_0 IFDUP → stack still has one element (OP_0), eval = false
        assert!(!eval_ok(&[Opcode::OP_0 as u8, Opcode::OP_IFDUP as u8]));
    }

    // --- OP_NIP ---

    #[test]
    fn op_nip_removes_second() {
        // [3, 5] nip → [5]
        assert!(eval_ok(&[
            Opcode::OP_3 as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_NIP as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- OP_ROT ---

    #[test]
    fn op_rot_rotates_three() {
        // [1, 2, 3] rot → [2, 3, 1]
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_ROT as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_EQUAL as u8, // top should be 1 now
        ]));
    }

    // --- Conditional branches ---

    #[test]
    fn op_if_false_branch() {
        // IF with false condition takes ELSE branch
        assert!(!eval_ok(&[
            Opcode::OP_0 as u8,
            Opcode::OP_IF as u8,
            Opcode::OP_1 as u8, // true branch (not taken)
            Opcode::OP_ELSE as u8,
            Opcode::OP_0 as u8, // false branch (taken)
            Opcode::OP_ENDIF as u8,
        ]));
    }

    #[test]
    fn op_notif_true_branch_not_taken() {
        // NOTIF with true condition → else branch
        assert!(!eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_NOTIF as u8,
            Opcode::OP_1 as u8, // not taken
            Opcode::OP_ELSE as u8,
            Opcode::OP_0 as u8, // taken
            Opcode::OP_ENDIF as u8,
        ]));
    }

    #[test]
    fn op_else_without_if_fails() {
        let err = eval_err(&[Opcode::OP_ELSE as u8]);
        assert_eq!(err, ScriptError::UnbalancedConditional);
    }

    #[test]
    fn op_endif_without_if_fails() {
        let err = eval_err(&[Opcode::OP_ENDIF as u8]);
        assert_eq!(err, ScriptError::UnbalancedConditional);
    }

    // --- OP_NOP variants ---

    #[test]
    fn op_nop_is_no_op() {
        assert!(eval_ok(&[Opcode::OP_NOP as u8, Opcode::OP_1 as u8]));
    }

    #[test]
    fn op_nop1_with_upgradable_nops_discouraged() {
        let script = make_script(&[Opcode::OP_NOP1 as u8, Opcode::OP_1 as u8]);
        let flags = ScriptFlags::from_bits(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS);
        let mut interp = ScriptInterpreter::new(flags, &NullChecker);
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::DiscourageUpgradableNops);
    }

    #[test]
    fn op_nop1_without_flag_is_allowed() {
        assert!(eval_ok(&[Opcode::OP_NOP1 as u8, Opcode::OP_1 as u8]));
    }

    // --- OP_1NEGATE ---

    #[test]
    fn op_1negate_pushes_minus_one() {
        assert!(eval_ok(&[
            Opcode::OP_1NEGATE as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_ADD as u8,
            Opcode::OP_0 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- OP_CHECKSIG (always false with NullChecker) ---

    #[test]
    fn op_checksig_with_null_checker_false() {
        let sig = vec![0x30u8, 0x01, 0x01, 0x01]; // some bytes
        let pk = vec![0x02u8; 33];
        let mut script_bytes = Vec::new();
        // push sig
        script_bytes.push(sig.len() as u8);
        script_bytes.extend_from_slice(&sig);
        // push pk
        script_bytes.push(pk.len() as u8);
        script_bytes.extend_from_slice(&pk);
        script_bytes.push(Opcode::OP_CHECKSIG as u8);
        assert!(!eval_ok(&script_bytes));
    }

    // --- OP_CHECKMULTISIG (NullChecker = always false) ---

    #[test]
    fn op_checkmultisig_1of1_null_checker() {
        // Stack for OP_CHECKMULTISIG: dummy | sig | m | pk | n
        // We push OP_0 (dummy), sig bytes, OP_1 (m=1), pk bytes, OP_1 (n=1)
        let sig = vec![0x30u8, 0x01, 0x01];
        let pk = vec![0x02u8; 33];
        let mut s = Vec::new();
        s.push(Opcode::OP_0 as u8); // dummy
        s.push(sig.len() as u8);
        s.extend_from_slice(&sig);
        s.push(Opcode::OP_1 as u8); // n_sigs = 1
        s.push(pk.len() as u8);
        s.extend_from_slice(&pk);
        s.push(Opcode::OP_1 as u8); // n_keys = 1
        s.push(Opcode::OP_CHECKMULTISIG as u8);
        // NullChecker returns false for every signature
        assert!(!eval_ok(&s));
    }

    #[test]
    fn op_checkmultisig_0_required_sigs_succeeds() {
        // 0-of-1 (no signatures required): should succeed even with NullChecker
        let pk = vec![0x02u8; 33];
        let mut s = Vec::new();
        s.push(Opcode::OP_0 as u8); // dummy
                                    // no sigs (n_sigs = 0)
        s.push(Opcode::OP_0 as u8); // n_sigs = 0
        s.push(pk.len() as u8);
        s.extend_from_slice(&pk);
        s.push(Opcode::OP_1 as u8); // n_keys = 1
        s.push(Opcode::OP_CHECKMULTISIG as u8);
        assert!(eval_ok(&s));
    }

    #[test]
    fn op_checkmultisig_nulldummy_flag_enforced() {
        // With NULLDUMMY flag, the dummy must be empty
        let sig = vec![0x30u8, 0x01, 0x01];
        let pk = vec![0x02u8; 33];
        let mut s = Vec::new();
        // non-empty dummy → should fail
        s.push(0x01); // push 1 byte
        s.push(0x01); // the byte (non-empty dummy)
        s.push(sig.len() as u8);
        s.extend_from_slice(&sig);
        s.push(Opcode::OP_1 as u8);
        s.push(pk.len() as u8);
        s.extend_from_slice(&pk);
        s.push(Opcode::OP_1 as u8);
        s.push(Opcode::OP_CHECKMULTISIG as u8);

        let script = make_script(&s);
        let flags = ScriptFlags::from_bits(ScriptFlags::NULLDUMMY);
        let mut interp = ScriptInterpreter::new(flags, &NullChecker);
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::SigNullDummy);
    }

    // --- OP_CHECKLOCKTIMEVERIFY ---

    #[test]
    fn op_cltv_treated_as_nop_when_flag_not_set() {
        // Without CHECKLOCKTIMEVERIFY flag, CLTV is treated as NOP
        let locktime_bytes = ScriptNum::new(100).encode();
        let mut s = Vec::new();
        s.push(locktime_bytes.len() as u8);
        s.extend_from_slice(&locktime_bytes);
        s.push(Opcode::OP_CHECKLOCKTIMEVERIFY as u8);
        // locktime stays on stack, script result is top = 100 (truthy)
        assert!(eval_ok(&s));
    }

    struct AlwaysOkChecker;
    impl SignatureChecker for AlwaysOkChecker {
        fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool {
            true
        }
        fn check_lock_time(&self, _: i64) -> bool {
            true
        }
        fn check_sequence(&self, _: i64) -> bool {
            true
        }
    }

    #[test]
    fn op_cltv_passes_when_checker_approves() {
        let locktime_bytes = ScriptNum::new(500).encode();
        let mut s = Vec::new();
        s.push(locktime_bytes.len() as u8);
        s.extend_from_slice(&locktime_bytes);
        s.push(Opcode::OP_CHECKLOCKTIMEVERIFY as u8);
        // Script top = 500 (truthy) → success

        let script = make_script(&s);
        let flags = ScriptFlags::from_bits(ScriptFlags::CHECKLOCKTIMEVERIFY);
        let mut interp = ScriptInterpreter::new(flags, &AlwaysOkChecker);
        interp.eval(&script).unwrap();
        assert!(interp.success());
    }

    #[test]
    fn op_cltv_fails_when_checker_rejects() {
        let locktime_bytes = ScriptNum::new(500).encode();
        let mut s = Vec::new();
        s.push(locktime_bytes.len() as u8);
        s.extend_from_slice(&locktime_bytes);
        s.push(Opcode::OP_CHECKLOCKTIMEVERIFY as u8);

        let script = make_script(&s);
        let flags = ScriptFlags::from_bits(ScriptFlags::CHECKLOCKTIMEVERIFY);
        let mut interp = ScriptInterpreter::new(flags, &NullChecker);
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::UnsatisfiedLocktime);
    }

    #[test]
    fn op_cltv_negative_locktime_fails() {
        let neg = ScriptNum::new(-1).encode();
        let mut s = Vec::new();
        s.push(neg.len() as u8);
        s.extend_from_slice(&neg);
        s.push(Opcode::OP_CHECKLOCKTIMEVERIFY as u8);

        let script = make_script(&s);
        let flags = ScriptFlags::from_bits(ScriptFlags::CHECKLOCKTIMEVERIFY);
        let mut interp = ScriptInterpreter::new(flags, &NullChecker);
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::NegativeLocktime);
    }

    // --- Disabled opcodes must fail ---

    #[test]
    fn op_cat_disabled() {
        let err = eval_err(&[Opcode::OP_1 as u8, Opcode::OP_2 as u8, Opcode::OP_CAT as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_substr_disabled() {
        let err = eval_err(&[
            Opcode::OP_1 as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_SUBSTR as u8,
        ]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_left_disabled() {
        let err = eval_err(&[
            Opcode::OP_1 as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_LEFT as u8,
        ]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_right_disabled() {
        let err = eval_err(&[
            Opcode::OP_1 as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_RIGHT as u8,
        ]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_invert_disabled() {
        let err = eval_err(&[Opcode::OP_1 as u8, Opcode::OP_INVERT as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_and_disabled() {
        let err = eval_err(&[Opcode::OP_1 as u8, Opcode::OP_2 as u8, Opcode::OP_AND as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_or_disabled() {
        let err = eval_err(&[Opcode::OP_1 as u8, Opcode::OP_2 as u8, Opcode::OP_OR as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_xor_disabled() {
        let err = eval_err(&[Opcode::OP_1 as u8, Opcode::OP_2 as u8, Opcode::OP_XOR as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_mul_disabled() {
        let err = eval_err(&[Opcode::OP_2 as u8, Opcode::OP_3 as u8, Opcode::OP_MUL as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_div_disabled() {
        let err = eval_err(&[Opcode::OP_6 as u8, Opcode::OP_3 as u8, Opcode::OP_DIV as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_mod_disabled() {
        let err = eval_err(&[Opcode::OP_5 as u8, Opcode::OP_3 as u8, Opcode::OP_MOD as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_lshift_disabled() {
        let err = eval_err(&[
            Opcode::OP_2 as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_LSHIFT as u8,
        ]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_rshift_disabled() {
        let err = eval_err(&[
            Opcode::OP_4 as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_RSHIFT as u8,
        ]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_2mul_disabled() {
        let err = eval_err(&[Opcode::OP_3 as u8, Opcode::OP_2MUL as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    #[test]
    fn op_2div_disabled() {
        let err = eval_err(&[Opcode::OP_4 as u8, Opcode::OP_2DIV as u8]);
        assert_eq!(err, ScriptError::DisabledOpcode);
    }

    // --- Reserved opcodes must fail ---

    #[test]
    fn op_ver_invalid() {
        let err = eval_err(&[Opcode::OP_VER as u8]);
        assert_eq!(err, ScriptError::BadOpcode);
    }

    #[test]
    fn op_reserved_invalid() {
        let err = eval_err(&[Opcode::OP_RESERVED as u8]);
        assert_eq!(err, ScriptError::BadOpcode);
    }

    // --- Script size limit ---

    #[test]
    fn script_size_limit_exactly_at_max_passes() {
        // A script of exactly 10000 NOPs hits OpCount (201) before finishing,
        // which confirms the script size check let it through (ScriptSize = 10001+)
        let script_bytes = vec![Opcode::OP_NOP as u8; 10000];
        let script = Script::from_bytes(script_bytes);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        let err = interp.eval(&script).unwrap_err();
        // 10000 NOPs → hits OpCount (201) before completing, not ScriptSize
        assert_eq!(err, ScriptError::OpCount);
    }

    #[test]
    fn script_size_limit_over_max_fails() {
        // A script of 10001 bytes should immediately fail with ScriptSize
        let script_bytes = vec![Opcode::OP_NOP as u8; 10001];
        let script = Script::from_bytes(script_bytes);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        let err = interp.eval(&script).unwrap_err();
        assert_eq!(err, ScriptError::ScriptSize);
    }

    // --- Stack size limit ---

    #[test]
    fn stack_limit_1000_elements() {
        // Push 1000 elements via individual push ops → should work (exactly at limit
        // during pushes, not exceeding).  Use OP_1 which doesn't exceed op-count limit
        // quickly enough to matter here.
        // Use data push bytes 0x01 0x01 (push 1 byte = 0x01) repeated 999 times
        // then check depth = 999. Keep under op-count by staying with push ops.
        let mut stack = Stack::new();
        for i in 0..MAX_STACK_SIZE {
            stack
                .push(vec![i as u8])
                .expect("should not exceed limit yet");
        }
        assert_eq!(stack.len(), MAX_STACK_SIZE);
        // One more should fail
        let err = stack.push(vec![0]).unwrap_err();
        assert_eq!(err, ScriptError::StackSize);
    }

    // --- OP_1ADD / OP_1SUB ---

    #[test]
    fn op_1add() {
        assert!(eval_ok(&[
            Opcode::OP_4 as u8,
            Opcode::OP_1ADD as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_1sub() {
        assert!(eval_ok(&[
            Opcode::OP_5 as u8,
            Opcode::OP_1SUB as u8,
            Opcode::OP_4 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- Crypto ops ---

    #[test]
    fn op_sha256_produces_32_bytes() {
        assert!(eval_ok(&[
            0x04,
            0x01,
            0x02,
            0x03,
            0x04,
            Opcode::OP_SHA256 as u8,
            Opcode::OP_SIZE as u8,
            0x01,
            0x20, // push 32 (0x20)
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_hash256_produces_32_bytes() {
        assert!(eval_ok(&[
            0x04,
            0x01,
            0x02,
            0x03,
            0x04,
            Opcode::OP_HASH256 as u8,
            Opcode::OP_SIZE as u8,
            0x01,
            0x20, // push 32
            Opcode::OP_EQUAL as u8,
        ]));
    }

    #[test]
    fn op_ripemd160_produces_20_bytes() {
        assert!(eval_ok(&[
            0x04,
            0x01,
            0x02,
            0x03,
            0x04,
            Opcode::OP_RIPEMD160 as u8,
            Opcode::OP_SIZE as u8,
            0x01,
            0x14, // push 20
            Opcode::OP_EQUAL as u8,
        ]));
    }

    // --- OP_PICK and OP_ROLL ---

    #[test]
    fn op_pick() {
        // [1, 2, 3], pick(1) → copies index-1-from-top = 2
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_1 as u8, // pick index 1
            Opcode::OP_PICK as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_EQUAL as u8, // should be 2
        ]));
    }

    #[test]
    fn op_roll() {
        // [1, 2, 3], roll(2) → removes index-2 (=1) and pushes it to top → [2, 3, 1]
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_2 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_2 as u8, // roll index 2
            Opcode::OP_ROLL as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_EQUAL as u8, // top should be 1
        ]));
    }

    // --- OP_TUCK ---

    #[test]
    fn op_tuck() {
        // [a=1, b=3] tuck → [b=3, a=1, b=3]; verify top=3
        assert!(eval_ok(&[
            Opcode::OP_1 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_TUCK as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_EQUAL as u8,
        ]));
    }
}

// =============================================================================
// 5. Opcodes module – additional coverage
// =============================================================================

mod opcodes_module {
    use super::*;

    #[test]
    fn all_disabled_opcodes_report_disabled() {
        let disabled = [
            Opcode::OP_CAT,
            Opcode::OP_SUBSTR,
            Opcode::OP_LEFT,
            Opcode::OP_RIGHT,
            Opcode::OP_INVERT,
            Opcode::OP_AND,
            Opcode::OP_OR,
            Opcode::OP_XOR,
            Opcode::OP_2MUL,
            Opcode::OP_2DIV,
            Opcode::OP_MUL,
            Opcode::OP_DIV,
            Opcode::OP_MOD,
            Opcode::OP_LSHIFT,
            Opcode::OP_RSHIFT,
        ];
        for op in &disabled {
            assert!(op.is_disabled(), "{op:?} should be disabled");
        }
    }

    #[test]
    fn non_disabled_opcodes_not_reported_disabled() {
        let enabled = [
            Opcode::OP_DUP,
            Opcode::OP_HASH160,
            Opcode::OP_CHECKSIG,
            Opcode::OP_ADD,
            Opcode::OP_EQUAL,
            Opcode::OP_IF,
            Opcode::OP_RETURN,
            Opcode::OP_REQUIRE_COINSTAKE,
        ];
        for op in &enabled {
            assert!(!op.is_disabled(), "{op:?} should not be disabled");
        }
    }

    #[test]
    fn opcode_names_spot_check() {
        assert_eq!(Opcode::OP_DUP.name(), "OP_DUP");
        assert_eq!(Opcode::OP_HASH160.name(), "OP_HASH160");
        assert_eq!(Opcode::OP_CHECKSIG.name(), "OP_CHECKSIG");
        assert_eq!(Opcode::OP_CAT.name(), "OP_CAT");
        assert_eq!(Opcode::OP_REQUIRE_COINSTAKE.name(), "OP_REQUIRE_COINSTAKE");
        assert_eq!(Opcode::OP_LIMIT_TRANSFER.name(), "OP_LIMIT_TRANSFER");
        assert_eq!(
            Opcode::OP_REWARD_DESTINATION.name(),
            "OP_REWARD_DESTINATION"
        );
        assert_eq!(Opcode::OP_INVALIDOPCODE.name(), "OP_UNKNOWN");
    }

    #[test]
    fn small_push_boundary() {
        assert!(!Opcode::is_small_push(0x00)); // OP_0 is not a "small push" in this definition
        assert!(Opcode::is_small_push(0x01));
        assert!(Opcode::is_small_push(0x4b)); // max direct push
        assert!(!Opcode::is_small_push(0x4c)); // OP_PUSHDATA1
    }

    #[test]
    fn from_u8_full_roundtrip_for_known_opcodes() {
        let pairs: &[(u8, Opcode)] = &[
            (0x00, Opcode::OP_0),
            (0x4f, Opcode::OP_1NEGATE),
            (0x51, Opcode::OP_1),
            (0x60, Opcode::OP_16),
            (0x63, Opcode::OP_IF),
            (0x67, Opcode::OP_ELSE),
            (0x68, Opcode::OP_ENDIF),
            (0x76, Opcode::OP_DUP),
            (0xa9, Opcode::OP_HASH160),
            (0xac, Opcode::OP_CHECKSIG),
            (0xae, Opcode::OP_CHECKMULTISIG),
            (0xb1, Opcode::OP_CHECKLOCKTIMEVERIFY),
            (0xb9, Opcode::OP_REQUIRE_COINSTAKE),
            (0xb8, Opcode::OP_LIMIT_TRANSFER),
            (0xc1, Opcode::OP_REWARD_DESTINATION),
            (0xff, Opcode::OP_INVALIDOPCODE),
        ];
        for (byte, expected) in pairs {
            assert_eq!(Opcode::from_u8(*byte), *expected, "byte=0x{byte:02x}");
        }
    }

    #[test]
    fn display_trait_works() {
        let s = format!("{}", Opcode::OP_DUP);
        assert_eq!(s, "OP_DUP");
    }
}

// =============================================================================
// 6. Stack module – additional coverage
// =============================================================================

mod stack_module {
    use super::*;

    #[test]
    fn push_max_element_size_ok() {
        use divi_script::stack::MAX_ELEMENT_SIZE;
        let mut stack = Stack::new();
        let big = vec![0u8; MAX_ELEMENT_SIZE];
        assert!(stack.push(big).is_ok());
    }

    #[test]
    fn push_over_max_element_size_fails() {
        use divi_script::stack::MAX_ELEMENT_SIZE;
        let mut stack = Stack::new();
        let too_big = vec![0u8; MAX_ELEMENT_SIZE + 1];
        assert_eq!(stack.push(too_big), Err(ScriptError::ElementSize));
    }

    #[test]
    fn pop_empty_stack_fails() {
        let mut stack = Stack::new();
        assert!(stack.pop().is_err());
    }

    #[test]
    fn top_empty_stack_fails() {
        let stack = Stack::new();
        assert!(stack.top().is_err());
    }

    #[test]
    fn peek_out_of_range_fails() {
        let mut stack = Stack::new();
        stack.push(vec![1]).unwrap();
        assert!(stack.peek(1).is_err());
    }

    #[test]
    fn remove_out_of_range_fails() {
        let mut stack = Stack::new();
        stack.push(vec![1]).unwrap();
        assert!(stack.remove(1).is_err());
    }

    #[test]
    fn push_bool_true() {
        let mut stack = Stack::new();
        stack.push_bool(true).unwrap();
        assert_eq!(stack.top().unwrap(), &vec![1u8]);
    }

    #[test]
    fn push_bool_false() {
        let mut stack = Stack::new();
        stack.push_bool(false).unwrap();
        assert_eq!(stack.top().unwrap(), &vec![]);
    }

    #[test]
    fn push_num_and_pop_num_roundtrip() {
        let mut stack = Stack::new();
        for val in [-1000i64, -1, 0, 1, 127, 128, 1000] {
            stack.push_num(ScriptNum::new(val)).unwrap();
            let decoded = stack.pop_num(false).unwrap();
            assert_eq!(decoded.value(), val, "roundtrip for {val}");
        }
    }

    #[test]
    fn swap_on_single_element_fails() {
        let mut stack = Stack::new();
        stack.push(vec![1]).unwrap();
        assert!(stack.swap().is_err());
    }

    #[test]
    fn dup_on_empty_fails() {
        let mut stack = Stack::new();
        assert!(stack.dup().is_err());
    }

    #[test]
    fn over2_requires_four_elements() {
        let mut stack = Stack::new();
        for i in 0..3 {
            stack.push(vec![i]).unwrap();
        }
        assert!(stack.over2().is_err());
    }

    #[test]
    fn swap2_requires_four_elements() {
        let mut stack = Stack::new();
        for i in 0..3 {
            stack.push(vec![i]).unwrap();
        }
        assert!(stack.swap2().is_err());
    }

    #[test]
    fn dup3_requires_three_elements() {
        let mut stack = Stack::new();
        stack.push(vec![1]).unwrap();
        stack.push(vec![2]).unwrap();
        assert!(stack.dup3().is_err());
    }

    #[test]
    fn rot_requires_three_elements() {
        let mut stack = Stack::new();
        stack.push(vec![1]).unwrap();
        stack.push(vec![2]).unwrap();
        assert!(stack.rot().is_err());
    }

    #[test]
    fn clear_empties_stack() {
        let mut stack = Stack::new();
        for _ in 0..10 {
            stack.push(vec![0]).unwrap();
        }
        stack.clear();
        assert!(stack.is_empty());
    }

    #[test]
    fn data_and_into_data() {
        let mut stack = Stack::new();
        stack.push(vec![1, 2]).unwrap();
        stack.push(vec![3, 4]).unwrap();
        let data = stack.data().to_vec();
        assert_eq!(data, vec![vec![1u8, 2], vec![3, 4]]);
        let owned = Stack::new();
        let into = owned.into_data();
        assert!(into.is_empty());
    }

    #[test]
    fn script_num_ops() {
        let a = ScriptNum::new(5);
        let b = ScriptNum::new(3);
        assert_eq!((a.clone() + b.clone()).value(), 8);
        assert_eq!((a.clone() - b.clone()).value(), 2);
        assert_eq!((-a).value(), -5);
        let c: i64 = b.into();
        assert_eq!(c, 3);
        let d = ScriptNum::from(7i64);
        assert_eq!(d.value(), 7);
    }

    #[test]
    fn script_num_overflow_rejected() {
        // 5-byte encoding with max_size=4 should fail
        let five_bytes = vec![0x01u8; 5];
        assert_eq!(
            ScriptNum::decode(&five_bytes, 4, false),
            Err(ScriptError::ScriptNumOverflow)
        );
    }

    #[test]
    fn script_num_minimal_encoding_enforced() {
        // 0x00 0x00 encodes zero non-minimally (trailing zero without needing sign byte)
        let non_minimal = vec![0x00u8, 0x00];
        let result = ScriptNum::decode(&non_minimal, 4, true);
        assert_eq!(result, Err(ScriptError::MinimalData));
    }
}

// =============================================================================
// 7. ScriptFlags
// =============================================================================

mod script_flags {
    use super::*;

    #[test]
    fn new_flags_empty() {
        let f = ScriptFlags::new();
        assert!(!f.has(ScriptFlags::P2SH));
        assert!(!f.has(ScriptFlags::NULLDUMMY));
    }

    #[test]
    fn set_and_clear_flags() {
        let mut f = ScriptFlags::new();
        f.set(ScriptFlags::P2SH);
        assert!(f.has(ScriptFlags::P2SH));
        f.clear(ScriptFlags::P2SH);
        assert!(!f.has(ScriptFlags::P2SH));
    }

    #[test]
    fn from_bits_preserves_all_bits() {
        let bits = ScriptFlags::P2SH | ScriptFlags::NULLDUMMY | ScriptFlags::CHECKLOCKTIMEVERIFY;
        let f = ScriptFlags::from_bits(bits);
        assert!(f.has(ScriptFlags::P2SH));
        assert!(f.has(ScriptFlags::NULLDUMMY));
        assert!(f.has(ScriptFlags::CHECKLOCKTIMEVERIFY));
        assert!(!f.has(ScriptFlags::DERSIG));
    }

    #[test]
    fn standard_flags_include_expected() {
        let f = ScriptFlags::standard();
        assert!(f.has(ScriptFlags::P2SH));
        assert!(f.has(ScriptFlags::DERSIG));
        assert!(f.has(ScriptFlags::LOW_S));
        assert!(f.has(ScriptFlags::NULLDUMMY));
        assert!(f.has(ScriptFlags::CHECKLOCKTIMEVERIFY));
    }
}
