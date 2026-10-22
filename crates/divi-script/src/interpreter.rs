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

//! Script interpreter
//!
//! A port of Divi Core's script evaluation (script/interpreter.cpp
//! `EvalScript` / `VerifyScript` and script/StackManager.cpp), kept close to
//! the C++ so that consensus behaviour matches it operation by operation:
//! what is parsed, counted and checked in unexecuted branches, the order of
//! checks, and which error each failure reports.

use crate::error::{ScriptError, ScriptFlags};
use crate::stack::{cast_to_bool, ScriptNum, Stack, MAX_OPS_PER_SCRIPT, MAX_SCRIPT_SIZE};
use divi_primitives::script::Script;

/// Largest data push a script may contain (MAX_SCRIPT_ELEMENT_SIZE)
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Combined size limit of the main and alt stacks
const MAX_STACK_SIZE: usize = 1000;
/// Most public keys an OP_CHECKMULTISIG may name
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;
/// Default CScriptNum size; CHECKLOCKTIMEVERIFY allows 5, LIMIT_TRANSFER 8
const DEFAULT_NUM_SIZE: usize = 4;

/// Raw opcode values (script/opcodes.h)
#[allow(dead_code)]
mod op {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHDATA1: u8 = 0x4c;
    pub const OP_PUSHDATA2: u8 = 0x4d;
    pub const OP_PUSHDATA4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_1: u8 = 0x51;
    pub const OP_16: u8 = 0x60;
    pub const OP_NOP: u8 = 0x61;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_META: u8 = 0x6a; // OP_RETURN
    pub const OP_TOALTSTACK: u8 = 0x6b;
    pub const OP_FROMALTSTACK: u8 = 0x6c;
    pub const OP_2DROP: u8 = 0x6d;
    pub const OP_2DUP: u8 = 0x6e;
    pub const OP_3DUP: u8 = 0x6f;
    pub const OP_2OVER: u8 = 0x70;
    pub const OP_2ROT: u8 = 0x71;
    pub const OP_2SWAP: u8 = 0x72;
    pub const OP_IFDUP: u8 = 0x73;
    pub const OP_DEPTH: u8 = 0x74;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_NIP: u8 = 0x77;
    pub const OP_OVER: u8 = 0x78;
    pub const OP_PICK: u8 = 0x79;
    pub const OP_ROLL: u8 = 0x7a;
    pub const OP_ROT: u8 = 0x7b;
    pub const OP_SWAP: u8 = 0x7c;
    pub const OP_TUCK: u8 = 0x7d;
    pub const OP_CAT: u8 = 0x7e;
    pub const OP_SUBSTR: u8 = 0x7f;
    pub const OP_LEFT: u8 = 0x80;
    pub const OP_RIGHT: u8 = 0x81;
    pub const OP_SIZE: u8 = 0x82;
    pub const OP_INVERT: u8 = 0x83;
    pub const OP_AND: u8 = 0x84;
    pub const OP_OR: u8 = 0x85;
    pub const OP_XOR: u8 = 0x86;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_1ADD: u8 = 0x8b;
    pub const OP_1SUB: u8 = 0x8c;
    pub const OP_2MUL: u8 = 0x8d;
    pub const OP_2DIV: u8 = 0x8e;
    pub const OP_NEGATE: u8 = 0x8f;
    pub const OP_ABS: u8 = 0x90;
    pub const OP_NOT: u8 = 0x91;
    pub const OP_0NOTEQUAL: u8 = 0x92;
    pub const OP_ADD: u8 = 0x93;
    pub const OP_SUB: u8 = 0x94;
    pub const OP_MUL: u8 = 0x95;
    pub const OP_DIV: u8 = 0x96;
    pub const OP_MOD: u8 = 0x97;
    pub const OP_LSHIFT: u8 = 0x98;
    pub const OP_RSHIFT: u8 = 0x99;
    pub const OP_BOOLAND: u8 = 0x9a;
    pub const OP_BOOLOR: u8 = 0x9b;
    pub const OP_NUMEQUAL: u8 = 0x9c;
    pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
    pub const OP_NUMNOTEQUAL: u8 = 0x9e;
    pub const OP_LESSTHAN: u8 = 0x9f;
    pub const OP_GREATERTHAN: u8 = 0xa0;
    pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
    pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
    pub const OP_MIN: u8 = 0xa3;
    pub const OP_MAX: u8 = 0xa4;
    pub const OP_WITHIN: u8 = 0xa5;
    pub const OP_RIPEMD160: u8 = 0xa6;
    pub const OP_SHA1: u8 = 0xa7;
    pub const OP_SHA256: u8 = 0xa8;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_HASH256: u8 = 0xaa;
    pub const OP_CODESEPARATOR: u8 = 0xab;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
    pub const OP_NOP1: u8 = 0xb0;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1; // NOP2
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2; // NOP3
    pub const OP_LIMIT_TRANSFER: u8 = 0xb8; // NOP9
    pub const OP_REQUIRE_COINSTAKE: u8 = 0xb9; // NOP10
}

/// Signature checker trait for verifying signatures during script execution
///
/// Mirrors Divi Core's `BaseSignatureChecker`: every check fails unless an
/// implementation says otherwise.
pub trait SignatureChecker {
    /// Check a signature (DER plus hash-type byte) against a public key
    fn check_sig(&self, sig: &[u8], pubkey: &[u8], script_code: &Script) -> bool;

    /// Check a lock time condition (OP_CHECKLOCKTIMEVERIFY)
    fn check_lock_time(&self, lock_time: i64) -> bool;

    /// Check a sequence condition. Not a Divi opcode: only evaluated when the
    /// non-Divi CHECKSEQUENCEVERIFY flag bit is set by a caller.
    fn check_sequence(&self, sequence: i64) -> bool;

    /// Check that the spending transaction is a coinstake
    ///
    /// Reference: Divi/divi/src/script/SignatureCheckers.h BaseSignatureChecker::CheckCoinstake
    fn check_coinstake(&self) -> bool {
        false
    }

    /// OP_LIMIT_TRANSFER: the output at this input's index must pay at least
    /// `minimum_change` to `change_script`
    ///
    /// Reference: Divi/divi/src/script/SignatureCheckers.cpp CheckTransferLimit
    fn check_transfer_limit(&self, _minimum_change: i64, _change_script: &[u8]) -> bool {
        false
    }
}

/// A null signature checker that fails all signature checks
pub struct NullChecker;

impl SignatureChecker for NullChecker {
    fn check_sig(&self, _sig: &[u8], _pubkey: &[u8], _script_code: &Script) -> bool {
        false
    }

    fn check_lock_time(&self, _lock_time: i64) -> bool {
        false
    }

    fn check_sequence(&self, _sequence: i64) -> bool {
        false
    }
}

/// Read one operation at `*pc`, as Core's `CScript::GetOp2`: returns the
/// opcode and its push data, or None on a truncated push. On failure `*pc`
/// may already have moved past the opcode and length bytes, as in Core
/// (this matters for scriptCode serialization and FindAndDelete).
pub fn get_op<'s>(script: &'s [u8], pc: &mut usize) -> Option<(u8, &'s [u8])> {
    if *pc >= script.len() {
        return None;
    }
    let opcode = script[*pc];
    *pc += 1;
    if opcode > op::OP_PUSHDATA4 {
        return Some((opcode, &[]));
    }
    let remaining = |pc: usize| script.len() - pc;
    let size = if opcode < op::OP_PUSHDATA1 {
        opcode as usize
    } else if opcode == op::OP_PUSHDATA1 {
        if remaining(*pc) < 1 {
            return None;
        }
        let n = script[*pc] as usize;
        *pc += 1;
        n
    } else if opcode == op::OP_PUSHDATA2 {
        if remaining(*pc) < 2 {
            return None;
        }
        let n = u16::from_le_bytes([script[*pc], script[*pc + 1]]) as usize;
        *pc += 2;
        n
    } else {
        if remaining(*pc) < 4 {
            return None;
        }
        let n = u32::from_le_bytes([
            script[*pc],
            script[*pc + 1],
            script[*pc + 2],
            script[*pc + 3],
        ]) as usize;
        *pc += 4;
        n
    };
    if remaining(*pc) < size {
        return None;
    }
    let data = &script[*pc..*pc + size];
    *pc += size;
    Some((opcode, data))
}

/// Core's `CScript::IsPushOnly`: every operation parses and is at most OP_16
pub fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0;
    while pc < script.len() {
        match get_op(script, &mut pc) {
            Some((opcode, _)) if opcode <= op::OP_16 => {}
            _ => return false,
        }
    }
    true
}

/// `CScript() << data`: the push of `data` with the shortest push opcode
pub(crate) fn push_data_script(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    if data.len() < op::OP_PUSHDATA1 as usize {
        out.push(data.len() as u8);
    } else if data.len() <= 0xff {
        out.push(op::OP_PUSHDATA1);
        out.push(data.len() as u8);
    } else if data.len() <= 0xffff {
        out.push(op::OP_PUSHDATA2);
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    } else {
        out.push(op::OP_PUSHDATA4);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

/// Core's `CScript::FindAndDelete`: remove every occurrence of `pattern`
/// that starts on an operation boundary
pub(crate) fn find_and_delete(script: &mut Vec<u8>, pattern: &[u8]) {
    if pattern.is_empty() {
        return;
    }
    let mut pc = 0;
    loop {
        while script.len() - pc >= pattern.len() && script[pc..pc + pattern.len()] == *pattern {
            script.drain(pc..pc + pattern.len());
        }
        if get_op(script, &mut pc).is_none() {
            break;
        }
    }
}

/// Core's `CheckMinimalPush` (MINIMALDATA)
fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
    if data.is_empty() {
        opcode == op::OP_0
    } else if data.len() == 1 && (1..=16).contains(&data[0]) {
        opcode == op::OP_1 + (data[0] - 1)
    } else if data.len() == 1 && data[0] == 0x81 {
        opcode == op::OP_1NEGATE
    } else if data.len() <= 75 {
        opcode as usize == data.len()
    } else if data.len() <= 255 {
        opcode == op::OP_PUSHDATA1
    } else if data.len() <= 65535 {
        opcode == op::OP_PUSHDATA2
    } else {
        true
    }
}

/// Opcodes that fail the script wherever they appear, executed or not
fn is_disabled(opcode: u8) -> bool {
    matches!(
        opcode,
        op::OP_CAT
            | op::OP_SUBSTR
            | op::OP_LEFT
            | op::OP_RIGHT
            | op::OP_INVERT
            | op::OP_AND
            | op::OP_OR
            | op::OP_XOR
            | op::OP_2MUL
            | op::OP_2DIV
            | op::OP_MUL
            | op::OP_DIV
            | op::OP_MOD
            | op::OP_LSHIFT
            | op::OP_RSHIFT
    )
}

/// `CScriptNum(vch, fRequireMinimal, nMaxNumSize)`. Core throws on overflow
/// or a non-minimal encoding and EvalScript reports SCRIPT_ERR_UNKNOWN_ERROR.
fn script_num(data: &[u8], require_minimal: bool, max_size: usize) -> Result<i64, ScriptError> {
    ScriptNum::decode(data, max_size, require_minimal)
        .map(|n| n.value())
        .map_err(|_| ScriptError::Unknown)
}

/// `CScriptNum::getint`: clamp to the i32 range
fn getint(n: i64) -> i64 {
    n.clamp(i32::MIN as i64, i32::MAX as i64)
}

fn num_bytes(n: i64) -> Vec<u8> {
    ScriptNum::new(n).encode()
}

fn bool_bytes(b: bool) -> Vec<u8> {
    if b {
        vec![1]
    } else {
        Vec::new()
    }
}

/// Core's `BaseSignatureChecker::CheckSignatureEncoding`
pub fn check_signature_encoding(sig: &[u8], flags: ScriptFlags) -> Result<(), ScriptError> {
    // An empty signature is a compact way to fail CHECK(MULTI)SIG
    if sig.is_empty() {
        return Ok(());
    }
    if flags.has(ScriptFlags::DERSIG | ScriptFlags::LOW_S | ScriptFlags::STRICTENC)
        && !is_valid_signature_encoding(sig)
    {
        return Err(ScriptError::SigDer);
    }
    if flags.has(ScriptFlags::LOW_S) && !is_low_der_signature(sig) {
        return Err(ScriptError::SigHighS);
    }
    if flags.has(ScriptFlags::STRICTENC) && !is_defined_hashtype_signature(sig) {
        return Err(ScriptError::SigHashType);
    }
    Ok(())
}

/// Core's `BaseSignatureChecker::CheckPubKeyEncoding`
pub fn check_pubkey_encoding(pubkey: &[u8], flags: ScriptFlags) -> Result<(), ScriptError> {
    if flags.has(ScriptFlags::STRICTENC) && !is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(ScriptError::PubkeyType);
    }
    Ok(())
}

fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    match pubkey.first() {
        _ if pubkey.len() < 33 => false,
        Some(0x04) => pubkey.len() == 65,
        Some(0x02) | Some(0x03) => pubkey.len() == 33,
        _ => false,
    }
}

/// Core's `IsValidSignatureEncoding` (strict DER plus a hash-type byte; BIP66)
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    let len = sig.len();
    if !(9..=73).contains(&len) {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != len - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= len {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != len {
        return false;
    }
    if sig[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    true
}

/// Core's `IsLowDERSignature`: S is in 1..=order/2
fn is_low_der_signature(sig: &[u8]) -> bool {
    if !is_valid_signature_encoding(sig) {
        return false;
    }
    let len_r = sig[3] as usize;
    let len_s = sig[5 + len_r] as usize;
    let s = &sig[6 + len_r..6 + len_r + len_s];
    const HALF_ORDER: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B,
        0x20, 0xA0,
    ];
    compare_big_endian(s, &[]) == std::cmp::Ordering::Greater
        && compare_big_endian(s, &HALF_ORDER) != std::cmp::Ordering::Greater
}

/// eccryptoverify `CompareBigEndian`: compare as unsigned big-endian
/// numbers, ignoring leading zero bytes
fn compare_big_endian(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let strip = |x: &[u8]| -> Vec<u8> { x.iter().copied().skip_while(|&v| v == 0).collect() };
    let (a, b) = (strip(a), strip(b));
    a.len().cmp(&b.len()).then_with(|| a.cmp(&b))
}

/// Core's `IsDefinedHashtypeSignature`
fn is_defined_hashtype_signature(sig: &[u8]) -> bool {
    match sig.last() {
        None => false,
        Some(&b) => {
            let base = b & !0x80;
            (1..=3).contains(&base)
        }
    }
}

/// Script execution context (one `EvalScript` at a time; the main stack is
/// carried from one evaluation to the next, everything else is reset)
pub struct ScriptInterpreter<'a> {
    /// Main execution stack
    stack: Stack,
    /// Alternate stack (for OP_TOALTSTACK/OP_FROMALTSTACK)
    alt_stack: Vec<Vec<u8>>,
    /// Verification flags
    flags: ScriptFlags,
    /// Signature checker
    checker: &'a dyn SignatureChecker,
    /// Value of the output being spent (OP_LIMIT_TRANSFER)
    amount: i64,
    /// Conditional execution stack (tracking IF/ELSE/ENDIF nesting)
    exec_stack: Vec<bool>,
    /// Number of opcodes counted against MAX_OPS_PER_SCRIPT
    op_count: usize,
}

impl<'a> ScriptInterpreter<'a> {
    /// Create a new interpreter (spent amount 0)
    pub fn new(flags: ScriptFlags, checker: &'a dyn SignatureChecker) -> Self {
        Self::with_amount(flags, checker, 0)
    }

    /// Create a new interpreter for an input spending `amount` satoshis
    pub fn with_amount(flags: ScriptFlags, checker: &'a dyn SignatureChecker, amount: i64) -> Self {
        ScriptInterpreter {
            stack: Stack::new(),
            alt_stack: Vec::new(),
            flags,
            checker,
            amount,
            exec_stack: Vec::new(),
            op_count: 0,
        }
    }

    fn needs_closing(&self) -> bool {
        self.exec_stack.contains(&false)
    }

    fn st(&mut self) -> &mut Vec<Vec<u8>> {
        self.stack.raw_mut()
    }

    /// Element `depth` from the top (0 = top); the caller checks the size
    fn top(&self, depth: usize) -> &Vec<u8> {
        let data = self.stack.data();
        &data[data.len() - 1 - depth]
    }

    fn need(&self, n: usize) -> Result<(), ScriptError> {
        if self.stack.len() < n {
            Err(ScriptError::InvalidStackOperation)
        } else {
            Ok(())
        }
    }

    /// Evaluate a script (Core's `EvalScript`)
    pub fn eval(&mut self, script: &Script) -> Result<(), ScriptError> {
        // Each EvalScript gets a fresh StackOperationManager: alt stack,
        // conditions and the op count do not carry over
        self.alt_stack.clear();
        self.exec_stack.clear();
        self.op_count = 0;

        let bytes = script.as_bytes();
        if bytes.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSize);
        }
        let require_minimal = self.flags.has(ScriptFlags::MINIMALDATA);
        let mut pc = 0usize;
        let mut begin_code_hash = 0usize;

        while pc < bytes.len() {
            let (opcode, data) = get_op(bytes, &mut pc).ok_or(ScriptError::BadOpcode)?;
            if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
            // OP_RESERVED does not count towards the opcode limit
            if opcode > op::OP_16 {
                self.op_count += 1;
                if self.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }
            }
            if is_disabled(opcode) {
                return Err(ScriptError::DisabledOpcode);
            }

            let executing = !self.needs_closing();
            if executing && opcode <= op::OP_PUSHDATA4 {
                if require_minimal && !check_minimal_push(data, opcode) {
                    return Err(ScriptError::MinimalData);
                }
                self.st().push(data.to_vec());
            } else if executing || (op::OP_IF..=op::OP_ENDIF).contains(&opcode) {
                match opcode {
                    op::OP_NOP => {}
                    op::OP_CODESEPARATOR => begin_code_hash = pc,
                    op::OP_CHECKSIG
                    | op::OP_CHECKSIGVERIFY
                    | op::OP_CHECKMULTISIG
                    | op::OP_CHECKMULTISIGVERIFY => {
                        self.signature_op(opcode, &bytes[begin_code_hash..])?;
                    }
                    _ => self.apply_op(opcode)?,
                }
            }

            if self.stack.len() + self.alt_stack.len() > MAX_STACK_SIZE {
                return Err(ScriptError::StackSize);
            }
        }

        if !self.exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }
        Ok(())
    }

    /// Core's `ApplyOpcode` (everything but the signature opcodes)
    fn apply_op(&mut self, opcode: u8) -> Result<(), ScriptError> {
        let flags = self.flags;
        let minimal = flags.has(ScriptFlags::MINIMALDATA);

        if flags.has(ScriptFlags::LIMIT_TRANSFER) && opcode == op::OP_LIMIT_TRANSFER {
            return self.limit_transfer();
        }
        if flags.has(ScriptFlags::REQUIRE_COINSTAKE) && opcode == op::OP_REQUIRE_COINSTAKE {
            // CoinstakeCheckOp pushes the result, fails on false, pops on true
            return if self.checker.check_coinstake() {
                Ok(())
            } else {
                Err(ScriptError::RequireCoinstake)
            };
        }
        if flags.has(ScriptFlags::CHECKLOCKTIMEVERIFY) && opcode == op::OP_CHECKLOCKTIMEVERIFY {
            self.need(1)?;
            let lock_time = script_num(self.top(0), minimal, 5)?;
            if lock_time < 0 {
                return Err(ScriptError::NegativeLocktime);
            }
            if !self.checker.check_lock_time(lock_time) {
                return Err(ScriptError::UnsatisfiedLocktime);
            }
            return Ok(());
        }
        // Not a Divi rule: only callers that set this non-Divi bit get BIP112
        if flags.has(ScriptFlags::CHECKSEQUENCEVERIFY) && opcode == op::OP_CHECKSEQUENCEVERIFY {
            self.need(1)?;
            let sequence = script_num(self.top(0), minimal, 5)?;
            if sequence < 0 {
                return Err(ScriptError::NegativeLocktime);
            }
            if sequence & (1 << 31) == 0 && !self.checker.check_sequence(sequence) {
                return Err(ScriptError::UnsatisfiedLocktime);
            }
            return Ok(());
        }

        match opcode {
            op::OP_META => Err(ScriptError::OpReturn),
            op::OP_WITHIN => {
                // (x min max -- out)
                self.need(3)?;
                let x = script_num(self.top(2), minimal, DEFAULT_NUM_SIZE)?;
                let min = script_num(self.top(1), minimal, DEFAULT_NUM_SIZE)?;
                let max = script_num(self.top(0), minimal, DEFAULT_NUM_SIZE)?;
                let st = self.st();
                st.truncate(st.len() - 3);
                st.push(bool_bytes(min <= x && x < max));
                Ok(())
            }
            op::OP_NOP1..=op::OP_REQUIRE_COINSTAKE => {
                if flags.has(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                    Err(ScriptError::DiscourageUpgradableNops)
                } else {
                    Ok(())
                }
            }
            op::OP_1NEGATE | op::OP_1..=op::OP_16 => {
                let n = opcode as i64 - (op::OP_1 as i64 - 1);
                self.st().push(num_bytes(n));
                Ok(())
            }
            op::OP_IF | op::OP_NOTIF => {
                let mut value = false;
                if !self.needs_closing() {
                    if self.stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    value = cast_to_bool(self.top(0));
                    if opcode == op::OP_NOTIF {
                        value = !value;
                    }
                    self.st().pop();
                }
                self.exec_stack.push(value);
                Ok(())
            }
            op::OP_ELSE => match self.exec_stack.last_mut() {
                Some(top) => {
                    *top = !*top;
                    Ok(())
                }
                None => Err(ScriptError::UnbalancedConditional),
            },
            op::OP_ENDIF => match self.exec_stack.pop() {
                Some(_) => Ok(()),
                None => Err(ScriptError::UnbalancedConditional),
            },
            op::OP_TOALTSTACK..=op::OP_TUCK | op::OP_SIZE => self.stack_op(opcode, minimal),
            op::OP_VERIFY => {
                self.need(1)?;
                if cast_to_bool(self.top(0)) {
                    self.st().pop();
                    Ok(())
                } else {
                    Err(ScriptError::Verify)
                }
            }
            op::OP_EQUAL | op::OP_EQUALVERIFY => {
                self.need(2)?;
                let equal = self.top(1) == self.top(0);
                let st = self.st();
                st.truncate(st.len() - 2);
                st.push(bool_bytes(equal));
                if opcode == op::OP_EQUALVERIFY {
                    if equal {
                        self.st().pop();
                    } else {
                        return Err(ScriptError::EqualVerify);
                    }
                }
                Ok(())
            }
            op::OP_1ADD
            | op::OP_1SUB
            | op::OP_NEGATE
            | op::OP_ABS
            | op::OP_NOT
            | op::OP_0NOTEQUAL => {
                self.need(1)?;
                let n = script_num(self.top(0), minimal, DEFAULT_NUM_SIZE)?;
                let out = match opcode {
                    op::OP_1ADD => n + 1,
                    op::OP_1SUB => n - 1,
                    op::OP_NEGATE => -n,
                    op::OP_ABS => n.abs(),
                    op::OP_NOT => (n == 0) as i64,
                    _ => (n != 0) as i64,
                };
                let st = self.st();
                st.pop();
                st.push(num_bytes(out));
                Ok(())
            }
            op::OP_ADD
            | op::OP_SUB
            | op::OP_BOOLAND
            | op::OP_BOOLOR
            | op::OP_NUMEQUAL
            | op::OP_NUMEQUALVERIFY
            | op::OP_NUMNOTEQUAL
            | op::OP_LESSTHAN
            | op::OP_GREATERTHAN
            | op::OP_LESSTHANOREQUAL
            | op::OP_GREATERTHANOREQUAL
            | op::OP_MIN
            | op::OP_MAX => {
                self.need(2)?;
                let a = script_num(self.top(1), minimal, DEFAULT_NUM_SIZE)?;
                let b = script_num(self.top(0), minimal, DEFAULT_NUM_SIZE)?;
                let out = match opcode {
                    op::OP_ADD => a + b,
                    op::OP_SUB => a - b,
                    op::OP_BOOLAND => (a != 0 && b != 0) as i64,
                    op::OP_BOOLOR => (a != 0 || b != 0) as i64,
                    op::OP_NUMEQUAL | op::OP_NUMEQUALVERIFY => (a == b) as i64,
                    op::OP_NUMNOTEQUAL => (a != b) as i64,
                    op::OP_LESSTHAN => (a < b) as i64,
                    op::OP_GREATERTHAN => (a > b) as i64,
                    op::OP_LESSTHANOREQUAL => (a <= b) as i64,
                    op::OP_GREATERTHANOREQUAL => (a >= b) as i64,
                    op::OP_MIN => a.min(b),
                    _ => a.max(b),
                };
                let st = self.st();
                st.truncate(st.len() - 2);
                st.push(num_bytes(out));
                if opcode == op::OP_NUMEQUALVERIFY {
                    if cast_to_bool(self.top(0)) {
                        self.st().pop();
                    } else {
                        return Err(ScriptError::NumEqualVerify);
                    }
                }
                Ok(())
            }
            op::OP_RIPEMD160 | op::OP_SHA1 | op::OP_SHA256 | op::OP_HASH160 | op::OP_HASH256 => {
                self.need(1)?;
                let data = self.st().pop().expect("checked");
                let hash = match opcode {
                    op::OP_RIPEMD160 => divi_crypto::ripemd160(&data).to_vec(),
                    op::OP_SHA1 => {
                        use sha1::Digest;
                        sha1::Sha1::digest(&data).to_vec()
                    }
                    op::OP_SHA256 => divi_crypto::sha256(&data).to_vec(),
                    op::OP_HASH160 => divi_crypto::ripemd160(&divi_crypto::sha256(&data)).to_vec(),
                    _ => divi_crypto::double_sha256(&data).to_vec(),
                };
                self.st().push(hash);
                Ok(())
            }
            _ => Err(ScriptError::BadOpcode),
        }
    }

    /// Core's `StackModificationOp`
    fn stack_op(&mut self, opcode: u8, minimal: bool) -> Result<(), ScriptError> {
        match opcode {
            op::OP_TOALTSTACK => {
                self.need(1)?;
                let v = self.st().pop().expect("checked");
                self.alt_stack.push(v);
            }
            op::OP_FROMALTSTACK => {
                let v = self
                    .alt_stack
                    .pop()
                    .ok_or(ScriptError::InvalidAltstackOperation)?;
                self.st().push(v);
            }
            op::OP_2DROP => {
                self.need(2)?;
                let st = self.st();
                st.truncate(st.len() - 2);
            }
            op::OP_2DUP => {
                self.need(2)?;
                let (a, b) = (self.top(1).clone(), self.top(0).clone());
                self.st().extend([a, b]);
            }
            op::OP_3DUP => {
                self.need(3)?;
                let (a, b, c) = (
                    self.top(2).clone(),
                    self.top(1).clone(),
                    self.top(0).clone(),
                );
                self.st().extend([a, b, c]);
            }
            op::OP_2OVER => {
                self.need(4)?;
                let (a, b) = (self.top(3).clone(), self.top(2).clone());
                self.st().extend([a, b]);
            }
            op::OP_2ROT => {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                self.need(6)?;
                let st = self.st();
                let n = st.len();
                let moved: Vec<Vec<u8>> = st.drain(n - 6..n - 4).collect();
                st.extend(moved);
            }
            op::OP_2SWAP => {
                self.need(4)?;
                let st = self.st();
                let n = st.len();
                st.swap(n - 4, n - 2);
                st.swap(n - 3, n - 1);
            }
            op::OP_IFDUP => {
                self.need(1)?;
                if cast_to_bool(self.top(0)) {
                    let v = self.top(0).clone();
                    self.st().push(v);
                }
            }
            op::OP_DEPTH => {
                let n = self.stack.len() as i64;
                self.st().push(num_bytes(n));
            }
            op::OP_DROP => {
                self.need(1)?;
                self.st().pop();
            }
            op::OP_DUP => {
                self.need(1)?;
                let v = self.top(0).clone();
                self.st().push(v);
            }
            op::OP_NIP => {
                self.need(2)?;
                let st = self.st();
                let n = st.len();
                st.remove(n - 2);
            }
            op::OP_OVER => {
                self.need(2)?;
                let v = self.top(1).clone();
                self.st().push(v);
            }
            op::OP_PICK | op::OP_ROLL => {
                self.need(2)?;
                let n = getint(script_num(self.top(0), minimal, DEFAULT_NUM_SIZE)?);
                self.st().pop();
                if n < 0 || n >= self.stack.len() as i64 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let n = n as usize;
                let v = self.top(n).clone();
                if opcode == op::OP_ROLL {
                    let st = self.st();
                    let len = st.len();
                    st.remove(len - n - 1);
                }
                self.st().push(v);
            }
            op::OP_ROT => {
                // (x1 x2 x3 -- x2 x3 x1)
                self.need(3)?;
                let st = self.st();
                let n = st.len();
                st.swap(n - 3, n - 2);
                st.swap(n - 2, n - 1);
            }
            op::OP_SWAP => {
                self.need(2)?;
                let st = self.st();
                let n = st.len();
                st.swap(n - 2, n - 1);
            }
            op::OP_TUCK => {
                self.need(2)?;
                let v = self.top(0).clone();
                let st = self.st();
                let n = st.len();
                st.insert(n - 2, v);
            }
            op::OP_SIZE => {
                self.need(1)?;
                let n = self.top(0).len() as i64;
                self.st().push(num_bytes(n));
            }
            _ => return Err(ScriptError::BadOpcode),
        }
        Ok(())
    }

    /// Core's `LimitTransferCheckOp`: leaves the stack as it is
    fn limit_transfer(&mut self) -> Result<(), ScriptError> {
        self.need(2)?;
        let limit = self.top(1);
        let hash = self.top(0);
        if limit.len() > 8 || hash.len() != 20 {
            return Err(ScriptError::LimitTransfer);
        }
        // An 8-byte limit always decodes
        let transfer_limit = script_num(limit, false, 8)?.max(0);
        let minimum_change = if self.amount < transfer_limit {
            0
        } else {
            (self.amount - transfer_limit).max(0)
        };
        let mut change_script = Vec::with_capacity(23);
        change_script.push(op::OP_HASH160);
        change_script.push(20);
        change_script.extend_from_slice(hash);
        change_script.push(op::OP_EQUAL);
        if self
            .checker
            .check_transfer_limit(minimum_change, &change_script)
        {
            Ok(())
        } else {
            Err(ScriptError::LimitTransfer)
        }
    }

    /// Core's `SignatureCheckOp`; `code` is the script from just after the
    /// last executed OP_CODESEPARATOR
    fn signature_op(&mut self, opcode: u8, code: &[u8]) -> Result<(), ScriptError> {
        let flags = self.flags;
        let minimal = flags.has(ScriptFlags::MINIMALDATA);
        let mut script_code = code.to_vec();

        if opcode == op::OP_CHECKSIG || opcode == op::OP_CHECKSIGVERIFY {
            self.need(2)?;
            let sig = self.top(1).clone();
            let pubkey = self.top(0).clone();
            // A signature cannot sign itself
            find_and_delete(&mut script_code, &push_data_script(&sig));
            check_signature_encoding(&sig, flags)?;
            check_pubkey_encoding(&pubkey, flags)?;
            let ok = self
                .checker
                .check_sig(&sig, &pubkey, &Script::from_bytes(script_code));
            let st = self.st();
            st.truncate(st.len() - 2);
            st.push(bool_bytes(ok));
            if opcode == op::OP_CHECKSIGVERIFY {
                if ok {
                    self.st().pop();
                } else {
                    return Err(ScriptError::CheckSigVerify);
                }
            }
            return Ok(());
        }

        // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
        let mut i: usize = 1;
        self.need(1)?;
        let mut keys = getint(script_num(self.top(i - 1), minimal, DEFAULT_NUM_SIZE)?);
        if !(0..=MAX_PUBKEYS_PER_MULTISIG).contains(&keys) {
            return Err(ScriptError::PubkeyCount);
        }
        self.op_count += keys as usize;
        if self.op_count > MAX_OPS_PER_SCRIPT {
            return Err(ScriptError::OpCount);
        }
        i += 1;
        let mut ikey = i;
        i += keys as usize;
        self.need(i)?;
        let mut sigs = getint(script_num(self.top(i - 1), minimal, DEFAULT_NUM_SIZE)?);
        if sigs < 0 || sigs > keys {
            return Err(ScriptError::SigCount);
        }
        i += 1;
        let mut isig = i;
        i += sigs as usize;
        self.need(i)?;

        for k in 0..sigs as usize {
            let pattern = push_data_script(self.top(isig + k - 1));
            find_and_delete(&mut script_code, &pattern);
        }
        let script_code = Script::from_bytes(script_code);

        let mut success = true;
        while success && sigs > 0 {
            let sig = self.top(isig - 1);
            let pubkey = self.top(ikey - 1);
            // Encoding errors fail the script, in this exact order
            check_signature_encoding(sig, flags)?;
            check_pubkey_encoding(pubkey, flags)?;
            if self.checker.check_sig(sig, pubkey, &script_code) {
                isig += 1;
                sigs -= 1;
            }
            ikey += 1;
            keys -= 1;
            // More signatures left than keys: too many have failed
            if sigs > keys {
                success = false;
            }
        }

        // Clean up the arguments, then the extra element the original
        // implementation consumes
        let st = self.st();
        st.truncate(st.len() - (i - 1));
        self.need(1)?;
        if flags.has(ScriptFlags::NULLDUMMY) && !self.top(0).is_empty() {
            return Err(ScriptError::SigNullDummy);
        }
        self.st().pop();
        self.st().push(bool_bytes(success));
        if opcode == op::OP_CHECKMULTISIGVERIFY {
            if success {
                self.st().pop();
            } else {
                return Err(ScriptError::CheckMultiSigVerify);
            }
        }
        Ok(())
    }

    /// Get the current stack
    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    /// Take the stack
    pub fn into_stack(self) -> Stack {
        self.stack
    }

    /// Check if evaluation succeeded (stack top is true)
    pub fn success(&self) -> bool {
        self.stack
            .data()
            .last()
            .is_some_and(|top| cast_to_bool(top))
    }
}

/// Verify a script pair (scriptSig + scriptPubKey), spent amount 0
pub fn verify_script(
    script_sig: &Script,
    script_pubkey: &Script,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    verify_script_with_amount(script_sig, script_pubkey, 0, flags, checker)
}

/// Verify a script pair for an input spending `amount` satoshis (Core's
/// `VerifyScript`)
pub fn verify_script_with_amount(
    script_sig: &Script,
    script_pubkey: &Script,
    amount: i64,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    if flags.has(ScriptFlags::SIGPUSHONLY) && !is_push_only(script_sig.as_bytes()) {
        return Err(ScriptError::SigPushOnly);
    }

    // Core evaluates the scriptSig against a dummy output of value 0
    let mut interp = ScriptInterpreter::with_amount(flags, checker, 0);
    interp.eval(script_sig)?;
    let stack_copy: Vec<Vec<u8>> = interp.stack.data().to_vec();

    interp.amount = amount;
    interp.eval(script_pubkey)?;
    if !interp.success() {
        return Err(ScriptError::EvalFalse);
    }

    // Additional validation for spend-to-script-hash transactions
    if flags.has(ScriptFlags::P2SH) && script_pubkey.is_p2sh() {
        // scriptSig must be literals-only
        if !is_push_only(script_sig.as_bytes()) {
            return Err(ScriptError::SigPushOnly);
        }
        // Not empty here: HASH160 <h> EQUAL on an empty stack already failed
        let mut stack_copy = stack_copy;
        let redeem_script = Script::from_bytes(stack_copy.pop().ok_or(ScriptError::EvalFalse)?);
        let mut p2sh = ScriptInterpreter::with_amount(flags, checker, amount);
        *p2sh.stack.raw_mut() = stack_copy;
        p2sh.eval(&redeem_script)?;
        if !p2sh.success() {
            return Err(ScriptError::EvalFalse);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::Opcode;

    fn make_script(bytes: &[u8]) -> Script {
        Script::from_bytes(bytes.to_vec())
    }

    #[test]
    fn test_op_true() {
        let script = make_script(&[Opcode::OP_1 as u8]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        interp.eval(&script).unwrap();
        assert!(interp.success());
    }

    #[test]
    fn test_op_false() {
        let script = make_script(&[Opcode::OP_0 as u8]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        interp.eval(&script).unwrap();
        assert!(!interp.success());
    }

    #[test]
    fn test_op_dup_equal() {
        // Push 5, dup, check equal
        let script = make_script(&[
            Opcode::OP_5 as u8,
            Opcode::OP_DUP as u8,
            Opcode::OP_EQUAL as u8,
        ]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        interp.eval(&script).unwrap();
        assert!(interp.success());
    }

    #[test]
    fn test_op_add() {
        // 2 + 3 = 5
        let script = make_script(&[
            Opcode::OP_2 as u8,
            Opcode::OP_3 as u8,
            Opcode::OP_ADD as u8,
            Opcode::OP_5 as u8,
            Opcode::OP_EQUAL as u8,
        ]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        interp.eval(&script).unwrap();
        assert!(interp.success());
    }

    #[test]
    fn test_op_if_else() {
        // IF 1 ELSE 0 ENDIF with true condition
        let script = make_script(&[
            Opcode::OP_1 as u8,
            Opcode::OP_IF as u8,
            Opcode::OP_1 as u8,
            Opcode::OP_ELSE as u8,
            Opcode::OP_0 as u8,
            Opcode::OP_ENDIF as u8,
        ]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        interp.eval(&script).unwrap();
        assert!(interp.success());
    }

    #[test]
    fn test_op_return_fails() {
        let script = make_script(&[Opcode::OP_RETURN as u8]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        let result = interp.eval(&script);
        assert!(matches!(result, Err(ScriptError::OpReturn)));
    }

    #[test]
    fn test_op_hash160() {
        // Push some data, hash it
        let script = make_script(&[
            0x04, // Push 4 bytes
            0x01,
            0x02,
            0x03,
            0x04,
            Opcode::OP_HASH160 as u8,
            Opcode::OP_SIZE as u8, // Size should be 20
            Opcode::OP_16 as u8,   // Compare with 16
            Opcode::OP_4 as u8,    // + 4
            Opcode::OP_ADD as u8,
            Opcode::OP_EQUAL as u8, // Should equal 20
        ]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        interp.eval(&script).unwrap();
        assert!(interp.success());
    }

    #[test]
    fn test_unbalanced_if() {
        // IF without ENDIF - but first push a value so IF can execute
        let script = make_script(&[
            Opcode::OP_1 as u8,
            Opcode::OP_IF as u8,
            // Missing OP_ENDIF
        ]);
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(), &NullChecker);
        let result = interp.eval(&script);
        assert!(matches!(result, Err(ScriptError::UnbalancedConditional)));
    }
}
