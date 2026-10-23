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

//! Relay policy for scripts, as Divi Core's mempool applies it
//!
//! [`solver`] is Core's `ExtractScriptPubKeyFormat` (script/standard.cpp:41-207):
//! template matching by opcode, so it accepts exactly the scripts Core calls
//! standard (a 40-byte "pubkey" push, a PUSHDATA1-encoded hash). The wallet's
//! [`extract_script_type`](crate::standard::extract_script_type) is stricter and
//! is not used for relay decisions.

use crate::interpreter::{get_op, sig_op_count};
use crate::standard::ScriptType;

const OP_0: u8 = 0x00;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_META: u8 = 0x6a;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_OVER: u8 = 0x78;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_RIPEMD160: u8 = 0xa6;
const OP_HASH160: u8 = 0xa9;
const OP_HASH256: u8 = 0xaa;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_REQUIRE_COINSTAKE: u8 = 0xb9;
const OP_INVALIDOPCODE: u8 = 0xff;

/// Divi Core `MAX_OP_META_RELAY` (defaultValues.h:40): largest relayed OP_META output
pub const MAX_OP_META_RELAY: usize = 603;

/// Divi Core `MAX_P2SH_SIGOPS` (defaultValues.h:59)
pub const MAX_P2SH_SIGOPS: u32 = 15;

/// Largest data push a script may contain (MAX_SCRIPT_ELEMENT_SIZE)
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// One element of a Core script template
#[derive(Clone, Copy, PartialEq)]
enum T {
    Op(u8),
    PubKey,
    PubKeyHash,
    PubKeys,
    SmallInteger,
    AnyHash,
    AnyData,
}

/// Core's templates in its `multimap` order (by `txnouttype`), so the first match wins
/// as in Core
const TEMPLATES: &[(ScriptType, &[T])] = &[
    (ScriptType::PubKey, &[T::PubKey, T::Op(OP_CHECKSIG)]),
    (
        ScriptType::PubKeyHash,
        &[
            T::Op(OP_DUP),
            T::Op(OP_HASH160),
            T::PubKeyHash,
            T::Op(OP_EQUALVERIFY),
            T::Op(OP_CHECKSIG),
        ],
    ),
    (
        ScriptType::Vault,
        &[
            T::Op(OP_IF),
            T::PubKeyHash,
            T::Op(OP_ELSE),
            T::Op(OP_REQUIRE_COINSTAKE),
            T::PubKeyHash,
            T::Op(OP_ENDIF),
            T::Op(OP_OVER),
            T::Op(OP_HASH160),
            T::Op(OP_EQUALVERIFY),
            T::Op(OP_CHECKSIG),
        ],
    ),
    (
        ScriptType::Htlc,
        &[
            T::AnyHash,
            T::AnyData,
            T::Op(OP_EQUAL),
            T::Op(OP_IF),
            T::PubKeyHash,
            T::Op(OP_ELSE),
            T::AnyData,
            T::Op(OP_CHECKLOCKTIMEVERIFY),
            T::Op(OP_DROP),
            T::PubKeyHash,
            T::Op(OP_ENDIF),
            T::Op(OP_OVER),
            T::Op(OP_HASH160),
            T::Op(OP_EQUALVERIFY),
            T::Op(OP_CHECKSIG),
        ],
    ),
    (
        ScriptType::Multisig,
        &[
            T::SmallInteger,
            T::PubKeys,
            T::SmallInteger,
            T::Op(OP_CHECKMULTISIG),
        ],
    ),
];

fn is_small_integer(opcode: u8) -> bool {
    opcode == OP_0 || (OP_1..=OP_16).contains(&opcode)
}

/// `CScript::DecodeOP_N`
fn decode_op_n(opcode: u8) -> u8 {
    if opcode == OP_0 {
        0
    } else {
        opcode - (OP_1 - 1)
    }
}

/// Core's `GetOp` as the template loop sees it: on failure the opcode reads
/// as OP_INVALIDOPCODE with no data
fn next_op<'a>(script: &'a [u8], pc: &mut usize) -> Option<(u8, &'a [u8])> {
    if *pc >= script.len() {
        return None;
    }
    get_op(script, pc)
}

/// Divi Core `ExtractScriptPubKeyFormat` (script/standard.cpp:41-207): the
/// script's type and its solutions, or `None` when Core finds no match
/// (TX_NONSTANDARD).
pub fn solver(script: &[u8]) -> Option<(ScriptType, Vec<Vec<u8>>)> {
    if script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL
    {
        return Some((ScriptType::ScriptHash, vec![script[2..22].to_vec()]));
    }
    if !script.is_empty() && script[0] == OP_META && crate::is_push_only(&script[1..]) {
        return Some((ScriptType::NullData, vec![]));
    }

    for (script_type, template) in TEMPLATES {
        let mut solutions: Vec<Vec<u8>> = Vec::new();
        let mut pc1 = 0usize;
        let mut pc2 = 0usize;
        loop {
            if pc1 == script.len() && pc2 == template.len() {
                if *script_type == ScriptType::Multisig {
                    let m = solutions.first()?[0];
                    let n = solutions.last()?[0];
                    if m < 1 || n < 1 || m > n || solutions.len() - 2 != n as usize {
                        return None;
                    }
                }
                return Some((*script_type, solutions));
            }
            let Some((mut opcode1, mut vch1)) = next_op(script, &mut pc1) else {
                break;
            };
            let Some(&first) = template.get(pc2) else {
                break;
            };
            pc2 += 1;
            let mut opcode2 = first;

            if opcode2 == T::PubKeys {
                while (33..=65).contains(&vch1.len()) {
                    solutions.push(vch1.to_vec());
                    match next_op(script, &mut pc1) {
                        Some((op, data)) => {
                            opcode1 = op;
                            vch1 = data;
                        }
                        None => {
                            opcode1 = OP_INVALIDOPCODE;
                            vch1 = &[];
                            break;
                        }
                    }
                }
                let Some(&next) = template.get(pc2) else {
                    break;
                };
                pc2 += 1;
                opcode2 = next;
            }

            match opcode2 {
                T::PubKey => {
                    if !(33..=65).contains(&vch1.len()) {
                        break;
                    }
                    solutions.push(vch1.to_vec());
                }
                T::PubKeyHash => {
                    if vch1.len() != 20 {
                        break;
                    }
                    solutions.push(vch1.to_vec());
                }
                T::SmallInteger => {
                    if !is_small_integer(opcode1) {
                        break;
                    }
                    solutions.push(vec![decode_op_n(opcode1)]);
                }
                T::AnyHash => {
                    if !(OP_RIPEMD160..=OP_HASH256).contains(&opcode1) {
                        break;
                    }
                    solutions.push(vec![opcode1]);
                }
                T::AnyData => {
                    if is_small_integer(opcode1) {
                        solutions.push(vec![decode_op_n(opcode1)]);
                    } else {
                        solutions.push(vch1.to_vec());
                    }
                }
                T::PubKeys => break,
                T::Op(op) => {
                    if opcode1 != op || !vch1.is_empty() {
                        break;
                    }
                }
            }
        }
    }
    None
}

/// Divi Core `ScriptSigArgsExpected` (script/standard.cpp:209-232); `None` for -1
pub fn script_sig_args_expected(script_type: ScriptType, solutions: &[Vec<u8>]) -> Option<usize> {
    match script_type {
        ScriptType::NonStandard | ScriptType::NullData => None,
        ScriptType::PubKey => Some(1),
        ScriptType::PubKeyHash => Some(2),
        ScriptType::Multisig => solutions
            .first()
            .and_then(|m| m.first())
            .map(|m| *m as usize + 1),
        ScriptType::ScriptHash => Some(1),
        ScriptType::Vault | ScriptType::Htlc => Some(3),
    }
}

/// Divi Core `IsStandard(scriptPubKey, whichType, maximumMetadataBytes)`
/// (script/standard.cpp:234-253): the output's type if it may be relayed
pub fn standard_output_type(script: &[u8], max_meta_bytes: usize) -> Option<ScriptType> {
    let (script_type, solutions) = solver(script)?;
    match script_type {
        ScriptType::Multisig => {
            let m = solutions.first()?[0];
            let n = solutions.last()?[0];
            // Up to x-of-3 multisig is standard
            if !(1..=3).contains(&n) || m < 1 || m > n {
                return None;
            }
        }
        ScriptType::NullData if script.len() > max_meta_bytes => return None,
        _ => {}
    }
    Some(script_type)
}

/// Core's `EvalScript` of a push-only scriptSig with no flags: the stack it
/// leaves, or `None` where Core's evaluation fails (oversized push, OP_RESERVED,
/// a script over 10,000 bytes or a stack over 1,000 items)
fn eval_push_only(script_sig: &[u8]) -> Option<Vec<Vec<u8>>> {
    if script_sig.len() > 10_000 {
        return None;
    }
    let mut stack = Vec::new();
    let mut pc = 0;
    while pc < script_sig.len() {
        let (opcode, data) = get_op(script_sig, &mut pc)?;
        if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return None;
        }
        if opcode <= OP_PUSHDATA4 {
            stack.push(data.to_vec());
        } else if opcode == OP_1NEGATE {
            stack.push(vec![0x81]);
        } else if (OP_1..=OP_16).contains(&opcode) {
            stack.push(vec![opcode - (OP_1 - 1)]);
        } else {
            return None;
        }
        if stack.len() > 1000 {
            return None;
        }
    }
    Some(stack)
}

/// One input of Divi Core `MempoolConsensus::AreInputsStandard`
/// (MempoolConsensus.cpp:137-191): the scriptSig carries exactly the arguments
/// the spent script needs; a vault spend ends in an empty or 0x01 flag; a P2SH
/// redeem script of no known type has at most 15 sigops.
pub fn is_input_standard(prev_script: &[u8], script_sig: &[u8]) -> bool {
    let Some((script_type, solutions)) = solver(prev_script) else {
        return false;
    };
    let Some(mut args_expected) = script_sig_args_expected(script_type, &solutions) else {
        return false;
    };
    let Some(stack) = eval_push_only(script_sig) else {
        return false;
    };

    if script_type == ScriptType::Vault {
        let Some(last) = stack.last() else {
            return false;
        };
        if last.len() > 1 || (last.len() == 1 && last[0] != 0x01) {
            return false;
        }
    } else if script_type == ScriptType::ScriptHash {
        let Some(subscript) = stack.last() else {
            return false;
        };
        match solver(subscript) {
            Some((inner_type, inner_solutions)) => {
                match script_sig_args_expected(inner_type, &inner_solutions) {
                    Some(n) => args_expected += n,
                    None => return false,
                }
            }
            // Any other script with at most 15 sigops; extra data left on the
            // stack is fine too
            None => return sig_op_count(subscript, true) <= MAX_P2SH_SIGOPS,
        }
    }

    stack.len() == args_expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p2pkh(hash: [u8; 20]) -> Vec<u8> {
        [
            &[OP_DUP, OP_HASH160, 0x14][..],
            &hash,
            &[OP_EQUALVERIFY, OP_CHECKSIG],
        ]
        .concat()
    }

    fn vault(owner: [u8; 20], manager: [u8; 20]) -> Vec<u8> {
        [
            &[OP_IF, 0x14][..],
            &owner,
            &[OP_ELSE, OP_REQUIRE_COINSTAKE, 0x14],
            &manager,
            &[OP_ENDIF, OP_OVER, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG],
        ]
        .concat()
    }

    fn multisig(m: u8, keys: &[Vec<u8>]) -> Vec<u8> {
        let mut s = vec![OP_1 - 1 + m];
        for k in keys {
            s.push(k.len() as u8);
            s.extend_from_slice(k);
        }
        s.push(OP_1 - 1 + keys.len() as u8);
        s.push(OP_CHECKMULTISIG);
        s
    }

    #[test]
    fn common_outputs_are_standard() {
        assert_eq!(
            standard_output_type(&p2pkh([1; 20]), MAX_OP_META_RELAY),
            Some(ScriptType::PubKeyHash)
        );
        let p2sh = [&[OP_HASH160, 0x14][..], &[2; 20], &[OP_EQUAL]].concat();
        assert_eq!(
            standard_output_type(&p2sh, MAX_OP_META_RELAY),
            Some(ScriptType::ScriptHash)
        );
        assert_eq!(
            standard_output_type(&vault([1; 20], [2; 20]), MAX_OP_META_RELAY),
            Some(ScriptType::Vault)
        );
        let pk = [&[33u8][..], &[2; 33], &[OP_CHECKSIG]].concat();
        assert_eq!(
            standard_output_type(&pk, MAX_OP_META_RELAY),
            Some(ScriptType::PubKey)
        );
    }

    /// Core matches templates by push size only: a 40-byte push before
    /// OP_CHECKSIG is a standard pubkey output, and a PUSHDATA1-encoded hash
    /// still fits the pubkey-hash template
    #[test]
    fn templates_match_by_push_size_as_in_core() {
        let odd_pk = [&[40u8][..], &[7; 40], &[OP_CHECKSIG]].concat();
        assert_eq!(solver(&odd_pk).map(|s| s.0), Some(ScriptType::PubKey));
        let long_hash = [
            &[OP_DUP, OP_HASH160, 0x4c, 0x14][..],
            &[1; 20],
            &[OP_EQUALVERIFY, OP_CHECKSIG],
        ]
        .concat();
        assert_eq!(
            solver(&long_hash).map(|s| s.0),
            Some(ScriptType::PubKeyHash)
        );
    }

    #[test]
    fn multisig_up_to_three_keys_is_standard() {
        let key = vec![2u8; 33];
        let two_of_three = multisig(2, &[key.clone(), key.clone(), key.clone()]);
        assert_eq!(
            standard_output_type(&two_of_three, MAX_OP_META_RELAY),
            Some(ScriptType::Multisig)
        );
        let one_of_four = multisig(1, &[key.clone(), key.clone(), key.clone(), key.clone()]);
        assert_eq!(
            solver(&one_of_four).map(|s| s.0),
            Some(ScriptType::Multisig)
        );
        assert_eq!(standard_output_type(&one_of_four, MAX_OP_META_RELAY), None);
        let three_of_two = multisig(3, &[key.clone(), key]);
        assert_eq!(solver(&three_of_two), None);
    }

    #[test]
    fn op_meta_size_limit() {
        let mut meta = vec![OP_META, 0x4d];
        meta.extend_from_slice(&599u16.to_le_bytes());
        meta.extend_from_slice(&[0; 599]);
        assert_eq!(meta.len(), MAX_OP_META_RELAY);
        assert_eq!(
            standard_output_type(&meta, MAX_OP_META_RELAY),
            Some(ScriptType::NullData)
        );
        meta.push(OP_0);
        assert_eq!(standard_output_type(&meta, MAX_OP_META_RELAY), None);
        assert_eq!(
            standard_output_type(&[OP_META, OP_CHECKSIG], MAX_OP_META_RELAY),
            None
        );
    }

    #[test]
    fn nonstandard_outputs() {
        assert_eq!(standard_output_type(&[], MAX_OP_META_RELAY), None);
        assert_eq!(standard_output_type(&[OP_1], MAX_OP_META_RELAY), None);
        let mut extra = p2pkh([1; 20]);
        extra.push(OP_DROP);
        assert_eq!(standard_output_type(&extra, MAX_OP_META_RELAY), None);
    }

    fn push(data: &[u8]) -> Vec<u8> {
        [&[data.len() as u8][..], data].concat()
    }

    #[test]
    fn p2pkh_spend_needs_exactly_two_pushes() {
        let prev = p2pkh([1; 20]);
        let sig = push(&[0x30; 71]);
        let key = push(&[2; 33]);
        assert!(is_input_standard(
            &prev,
            &[sig.clone(), key.clone()].concat()
        ));
        assert!(!is_input_standard(
            &prev,
            &[sig.clone(), key.clone(), vec![OP_0]].concat()
        ));
        assert!(!is_input_standard(&prev, &sig));
    }

    #[test]
    fn vault_spend_flag_must_be_empty_or_one() {
        let prev = vault([1; 20], [2; 20]);
        let sig = push(&[0x30; 71]);
        let key = push(&[2; 33]);
        let with = |flag: &[u8]| [sig.clone(), key.clone(), flag.to_vec()].concat();
        assert!(is_input_standard(&prev, &with(&[OP_1])));
        assert!(is_input_standard(&prev, &with(&[OP_0])));
        assert!(!is_input_standard(&prev, &with(&[OP_1 + 1])));
        assert!(!is_input_standard(&prev, &with(&push(&[1, 0]))));
    }

    #[test]
    fn p2sh_redeem_script_sigops_limit() {
        let mut redeem = vec![OP_CHECKSIG; 15];
        let hash = [3u8; 20];
        let prev = [&[OP_HASH160, 0x14][..], &hash, &[OP_EQUAL]].concat();
        assert!(is_input_standard(&prev, &push(&redeem)));
        redeem.push(OP_CHECKSIG);
        assert!(!is_input_standard(&prev, &push(&redeem)));
    }

    #[test]
    fn p2sh_of_a_known_type_counts_its_arguments() {
        let redeem = p2pkh([4; 20]);
        let hash = [3u8; 20];
        let prev = [&[OP_HASH160, 0x14][..], &hash, &[OP_EQUAL]].concat();
        let sig = push(&[0x30; 71]);
        let key = push(&[2; 33]);
        assert!(is_input_standard(
            &prev,
            &[sig.clone(), key.clone(), push(&redeem)].concat()
        ));
        assert!(!is_input_standard(&prev, &[sig, push(&redeem)].concat()));
    }
}
