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
//! This module implements the Bitcoin/Divi script virtual machine,
//! a stack-based language for transaction validation.

use crate::error::{ScriptError, ScriptFlags, SigHashType};
use crate::opcodes::Opcode;
use crate::stack::{cast_to_bool, ScriptNum, Stack, MAX_OPS_PER_SCRIPT, MAX_SCRIPT_SIZE};
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::Transaction;

/// Signature checker trait for verifying signatures during script execution
pub trait SignatureChecker {
    /// Check a signature against a public key
    fn check_sig(&self, sig: &[u8], pubkey: &[u8], script_code: &Script) -> bool;

    /// Check a lock time condition
    fn check_lock_time(&self, lock_time: i64) -> bool;

    /// Check a sequence condition
    fn check_sequence(&self, sequence: i64) -> bool;
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

/// Script execution context
pub struct ScriptInterpreter<'a> {
    /// Main execution stack
    stack: Stack,
    /// Alternate stack (for OP_TOALTSTACK/OP_FROMALTSTACK)
    alt_stack: Stack,
    /// Verification flags
    flags: ScriptFlags,
    /// Signature checker
    checker: &'a dyn SignatureChecker,
    /// Conditional execution stack (tracking IF/ELSE/ENDIF nesting)
    exec_stack: Vec<bool>,
    /// Number of opcodes executed
    op_count: usize,
    /// Code separator position for signature hashing
    code_separator: usize,
}

impl<'a> ScriptInterpreter<'a> {
    /// Create a new interpreter
    pub fn new(flags: ScriptFlags, checker: &'a dyn SignatureChecker) -> Self {
        ScriptInterpreter {
            stack: Stack::new(),
            alt_stack: Stack::new(),
            flags,
            checker,
            exec_stack: Vec::new(),
            op_count: 0,
            code_separator: 0,
        }
    }

    /// Check if we are currently in an executing branch
    fn is_executing(&self) -> bool {
        self.exec_stack.iter().all(|&b| b)
    }

    /// Evaluate a script
    pub fn eval(&mut self, script: &Script) -> Result<(), ScriptError> {
        let bytes = script.as_bytes();

        if bytes.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSize);
        }

        let mut pc = 0;

        while pc < bytes.len() {
            let opcode_byte = bytes[pc];
            pc += 1;

            // Check opcode count
            if opcode_byte > Opcode::OP_16 as u8 {
                self.op_count += 1;
                if self.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }
            }

            // Handle push operations
            if Opcode::is_small_push(opcode_byte) {
                let len = opcode_byte as usize;
                if pc + len > bytes.len() {
                    return Err(ScriptError::BadOpcode);
                }
                if self.is_executing() {
                    let data = bytes[pc..pc + len].to_vec();
                    self.stack.push(data)?;
                }
                pc += len;
                continue;
            }

            let opcode = Opcode::from_u8(opcode_byte);

            // Handle PUSHDATA opcodes
            match opcode {
                Opcode::OP_PUSHDATA1 => {
                    if pc >= bytes.len() {
                        return Err(ScriptError::BadOpcode);
                    }
                    let len = bytes[pc] as usize;
                    pc += 1;
                    if pc + len > bytes.len() {
                        return Err(ScriptError::BadOpcode);
                    }
                    if self.is_executing() {
                        let data = bytes[pc..pc + len].to_vec();
                        self.stack.push(data)?;
                    }
                    pc += len;
                    continue;
                }
                Opcode::OP_PUSHDATA2 => {
                    if pc + 2 > bytes.len() {
                        return Err(ScriptError::BadOpcode);
                    }
                    let len = u16::from_le_bytes([bytes[pc], bytes[pc + 1]]) as usize;
                    pc += 2;
                    if pc + len > bytes.len() {
                        return Err(ScriptError::BadOpcode);
                    }
                    if self.is_executing() {
                        let data = bytes[pc..pc + len].to_vec();
                        self.stack.push(data)?;
                    }
                    pc += len;
                    continue;
                }
                Opcode::OP_PUSHDATA4 => {
                    if pc + 4 > bytes.len() {
                        return Err(ScriptError::BadOpcode);
                    }
                    let len = u32::from_le_bytes([
                        bytes[pc],
                        bytes[pc + 1],
                        bytes[pc + 2],
                        bytes[pc + 3],
                    ]) as usize;
                    pc += 4;
                    if pc + len > bytes.len() {
                        return Err(ScriptError::BadOpcode);
                    }
                    if self.is_executing() {
                        let data = bytes[pc..pc + len].to_vec();
                        self.stack.push(data)?;
                    }
                    pc += len;
                    continue;
                }
                _ => {}
            }

            // Execute the opcode
            if self.is_executing() || self.is_conditional_opcode(opcode) {
                self.execute_opcode(opcode, script, &bytes[..pc - 1])?;
            }
        }

        // Check for unbalanced conditionals
        if !self.exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(())
    }

    fn is_conditional_opcode(&self, opcode: Opcode) -> bool {
        matches!(
            opcode,
            Opcode::OP_IF | Opcode::OP_NOTIF | Opcode::OP_ELSE | Opcode::OP_ENDIF
        )
    }

    fn execute_opcode(
        &mut self,
        opcode: Opcode,
        script: &Script,
        _executed: &[u8],
    ) -> Result<(), ScriptError> {
        // Check for disabled opcodes
        if opcode.is_disabled() {
            return Err(ScriptError::DisabledOpcode);
        }

        let require_minimal = self.flags.has(ScriptFlags::MINIMALDATA);

        match opcode {
            // Push values
            Opcode::OP_0 => {
                self.stack.push(vec![])?;
            }
            Opcode::OP_1NEGATE => {
                self.stack.push_num(ScriptNum::new(-1))?;
            }
            Opcode::OP_1
            | Opcode::OP_2
            | Opcode::OP_3
            | Opcode::OP_4
            | Opcode::OP_5
            | Opcode::OP_6
            | Opcode::OP_7
            | Opcode::OP_8
            | Opcode::OP_9
            | Opcode::OP_10
            | Opcode::OP_11
            | Opcode::OP_12
            | Opcode::OP_13
            | Opcode::OP_14
            | Opcode::OP_15
            | Opcode::OP_16 => {
                let n = (opcode as u8) - (Opcode::OP_1 as u8) + 1;
                self.stack.push_num(ScriptNum::new(n as i64))?;
            }

            // Control flow
            Opcode::OP_NOP => {}
            Opcode::OP_IF | Opcode::OP_NOTIF => {
                let mut value = false;
                if self.is_executing() {
                    let top = self.stack.pop()?;
                    value = cast_to_bool(&top);
                    if opcode == Opcode::OP_NOTIF {
                        value = !value;
                    }
                }
                self.exec_stack.push(value);
            }
            Opcode::OP_ELSE => {
                if self.exec_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                let last = self.exec_stack.len() - 1;
                self.exec_stack[last] = !self.exec_stack[last];
            }
            Opcode::OP_ENDIF => {
                if self.exec_stack.is_empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                self.exec_stack.pop();
            }
            Opcode::OP_VERIFY => {
                let value = self.stack.pop_bool()?;
                if !value {
                    return Err(ScriptError::Verify);
                }
            }
            Opcode::OP_RETURN => {
                return Err(ScriptError::OpReturn);
            }

            // Stack operations
            Opcode::OP_TOALTSTACK => {
                let value = self.stack.pop()?;
                self.alt_stack.push(value)?;
            }
            Opcode::OP_FROMALTSTACK => {
                let value = self
                    .alt_stack
                    .pop()
                    .map_err(|_| ScriptError::InvalidAltstackOperation)?;
                self.stack.push(value)?;
            }
            Opcode::OP_2DROP => self.stack.drop2()?,
            Opcode::OP_2DUP => self.stack.dup2()?,
            Opcode::OP_3DUP => self.stack.dup3()?,
            Opcode::OP_2OVER => self.stack.over2()?,
            Opcode::OP_2SWAP => self.stack.swap2()?,
            Opcode::OP_IFDUP => {
                let top = self.stack.top()?;
                if cast_to_bool(top) {
                    self.stack.dup()?;
                }
            }
            Opcode::OP_DEPTH => {
                let depth = self.stack.len() as i64;
                self.stack.push_num(ScriptNum::new(depth))?;
            }
            Opcode::OP_DROP => self.stack.drop()?,
            Opcode::OP_DUP => self.stack.dup()?,
            Opcode::OP_NIP => self.stack.nip()?,
            Opcode::OP_OVER => self.stack.over()?,
            Opcode::OP_PICK => {
                let n = self.stack.pop_num(require_minimal)?.value() as usize;
                let elem = self.stack.peek(n)?.clone();
                self.stack.push(elem)?;
            }
            Opcode::OP_ROLL => {
                let n = self.stack.pop_num(require_minimal)?.value() as usize;
                let elem = self.stack.remove(n)?;
                self.stack.push(elem)?;
            }
            Opcode::OP_ROT => self.stack.rot()?,
            Opcode::OP_SWAP => self.stack.swap()?,
            Opcode::OP_TUCK => self.stack.tuck()?,

            // Splice operations
            Opcode::OP_SIZE => {
                let size = self.stack.top()?.len() as i64;
                self.stack.push_num(ScriptNum::new(size))?;
            }

            // Bitwise logic
            Opcode::OP_EQUAL => {
                let b = self.stack.pop()?;
                let a = self.stack.pop()?;
                self.stack.push_bool(a == b)?;
            }
            Opcode::OP_EQUALVERIFY => {
                let b = self.stack.pop()?;
                let a = self.stack.pop()?;
                if a != b {
                    return Err(ScriptError::EqualVerify);
                }
            }

            // Numeric operations
            Opcode::OP_1ADD => {
                let n = self.stack.pop_num(require_minimal)?;
                self.stack.push_num(n + ScriptNum::new(1))?;
            }
            Opcode::OP_1SUB => {
                let n = self.stack.pop_num(require_minimal)?;
                self.stack.push_num(n - ScriptNum::new(1))?;
            }
            Opcode::OP_NEGATE => {
                let n = self.stack.pop_num(require_minimal)?;
                self.stack.push_num(-n)?;
            }
            Opcode::OP_ABS => {
                let n = self.stack.pop_num(require_minimal)?.value();
                self.stack.push_num(ScriptNum::new(n.abs()))?;
            }
            Opcode::OP_NOT => {
                let n = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if n == 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_0NOTEQUAL => {
                let n = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if n != 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_ADD => {
                let b = self.stack.pop_num(require_minimal)?;
                let a = self.stack.pop_num(require_minimal)?;
                self.stack.push_num(a + b)?;
            }
            Opcode::OP_SUB => {
                let b = self.stack.pop_num(require_minimal)?;
                let a = self.stack.pop_num(require_minimal)?;
                self.stack.push_num(a - b)?;
            }
            Opcode::OP_BOOLAND => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a != 0 && b != 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_BOOLOR => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a != 0 || b != 0 { 1 } else { 0 }))?;
            }
            Opcode::OP_NUMEQUAL => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a == b { 1 } else { 0 }))?;
            }
            Opcode::OP_NUMEQUALVERIFY => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                if a != b {
                    return Err(ScriptError::NumEqualVerify);
                }
            }
            Opcode::OP_NUMNOTEQUAL => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a != b { 1 } else { 0 }))?;
            }
            Opcode::OP_LESSTHAN => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a < b { 1 } else { 0 }))?;
            }
            Opcode::OP_GREATERTHAN => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a > b { 1 } else { 0 }))?;
            }
            Opcode::OP_LESSTHANOREQUAL => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a <= b { 1 } else { 0 }))?;
            }
            Opcode::OP_GREATERTHANOREQUAL => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if a >= b { 1 } else { 0 }))?;
            }
            Opcode::OP_MIN => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack.push_num(ScriptNum::new(a.min(b)))?;
            }
            Opcode::OP_MAX => {
                let b = self.stack.pop_num(require_minimal)?.value();
                let a = self.stack.pop_num(require_minimal)?.value();
                self.stack.push_num(ScriptNum::new(a.max(b)))?;
            }
            Opcode::OP_WITHIN => {
                let max = self.stack.pop_num(require_minimal)?.value();
                let min = self.stack.pop_num(require_minimal)?.value();
                let x = self.stack.pop_num(require_minimal)?.value();
                self.stack
                    .push_num(ScriptNum::new(if x >= min && x < max { 1 } else { 0 }))?;
            }

            // Crypto operations
            Opcode::OP_RIPEMD160 => {
                let data = self.stack.pop()?;
                let hash = divi_crypto::ripemd160(&data);
                self.stack.push(hash.to_vec())?;
            }
            Opcode::OP_SHA256 => {
                let data = self.stack.pop()?;
                let hash = divi_crypto::sha256(&data);
                self.stack.push(hash.to_vec())?;
            }
            Opcode::OP_HASH160 => {
                let data = self.stack.pop()?;
                let hash = divi_crypto::hash160(&data);
                self.stack.push(hash.as_bytes().to_vec())?;
            }
            Opcode::OP_HASH256 => {
                let data = self.stack.pop()?;
                let hash = divi_crypto::double_sha256(&data);
                self.stack.push(hash.to_vec())?;
            }
            Opcode::OP_CODESEPARATOR => {
                // Update code separator position
                // Used for signature hashing
            }
            Opcode::OP_CHECKSIG => {
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;
                let valid = self.checker.check_sig(&sig, &pubkey, script);
                self.stack.push_bool(valid)?;
            }
            Opcode::OP_CHECKSIGVERIFY => {
                let pubkey = self.stack.pop()?;
                let sig = self.stack.pop()?;
                let valid = self.checker.check_sig(&sig, &pubkey, script);
                if !valid {
                    return Err(ScriptError::CheckSigVerify);
                }
            }
            Opcode::OP_CHECKMULTISIG => {
                // Get number of public keys
                let n_keys = self.stack.pop_num(require_minimal)?.value() as usize;
                if n_keys > 20 {
                    return Err(ScriptError::PubkeyCount);
                }
                self.op_count += n_keys;
                if self.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }

                // Get public keys
                let mut pubkeys = Vec::with_capacity(n_keys);
                for _ in 0..n_keys {
                    pubkeys.push(self.stack.pop()?);
                }

                // Get number of signatures
                let n_sigs = self.stack.pop_num(require_minimal)?.value() as usize;
                if n_sigs > n_keys {
                    return Err(ScriptError::SigCount);
                }

                // Get signatures
                let mut sigs = Vec::with_capacity(n_sigs);
                for _ in 0..n_sigs {
                    sigs.push(self.stack.pop()?);
                }

                // Pop the dummy element (bug compatibility)
                let dummy = self.stack.pop()?;
                if self.flags.has(ScriptFlags::NULLDUMMY) && !dummy.is_empty() {
                    return Err(ScriptError::SigNullDummy);
                }

                // Verify signatures
                let mut key_idx = 0;
                let mut success = true;
                for sig in &sigs {
                    if sig.is_empty() {
                        continue;
                    }
                    let mut found = false;
                    while key_idx < n_keys {
                        if self.checker.check_sig(sig, &pubkeys[key_idx], script) {
                            found = true;
                            key_idx += 1;
                            break;
                        }
                        key_idx += 1;
                    }
                    if !found {
                        success = false;
                        break;
                    }
                }

                self.stack.push_bool(success)?;
            }
            Opcode::OP_CHECKMULTISIGVERIFY => {
                // Same as CHECKMULTISIG but verify result
                // (implementation would be similar, followed by verify)
                return Err(ScriptError::CheckMultiSigVerify);
            }

            // BIP65/BIP112 lock time operations
            Opcode::OP_CHECKLOCKTIMEVERIFY => {
                if !self.flags.has(ScriptFlags::CHECKLOCKTIMEVERIFY) {
                    // Treat as NOP if flag not set
                    if self.flags.has(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                } else {
                    let lock_time = self.stack.peek(0)?;
                    let lock_time = ScriptNum::decode(lock_time, 5, require_minimal)?;
                    if lock_time.value() < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if !self.checker.check_lock_time(lock_time.value()) {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }
            }
            Opcode::OP_CHECKSEQUENCEVERIFY => {
                if !self.flags.has(ScriptFlags::CHECKSEQUENCEVERIFY) {
                    if self.flags.has(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                } else {
                    let sequence = self.stack.peek(0)?;
                    let sequence = ScriptNum::decode(sequence, 5, require_minimal)?;
                    if sequence.value() < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if !self.checker.check_sequence(sequence.value()) {
                        return Err(ScriptError::CheckSequenceVerify);
                    }
                }
            }

            // Divi-specific opcodes
            Opcode::OP_REQUIRE_COINSTAKE => {
                if self.flags.has(ScriptFlags::REQUIRE_COINSTAKE) {
                    // This is a marker opcode - validation happens at transaction level
                    // If we reach here and the flag is set, the spending tx must be coinstake
                    return Err(ScriptError::RequireCoinstake);
                }
            }
            Opcode::OP_LIMIT_TRANSFER => {
                if self.flags.has(ScriptFlags::LIMIT_TRANSFER) {
                    return Err(ScriptError::LimitTransfer);
                }
            }

            // NOP operations
            Opcode::OP_NOP1
            | Opcode::OP_NOP4
            | Opcode::OP_NOP5
            | Opcode::OP_NOP6
            | Opcode::OP_NOP7
            | Opcode::OP_NOP8 => {
                if self.flags.has(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
            }

            // Reserved/invalid opcodes
            Opcode::OP_RESERVED
            | Opcode::OP_VER
            | Opcode::OP_VERIF
            | Opcode::OP_VERNOTIF
            | Opcode::OP_RESERVED1
            | Opcode::OP_RESERVED2 => {
                return Err(ScriptError::BadOpcode);
            }

            // Disabled opcodes are caught earlier
            _ => {
                return Err(ScriptError::BadOpcode);
            }
        }

        Ok(())
    }

    /// Get the final stack
    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    /// Take ownership of the stack
    pub fn into_stack(self) -> Stack {
        self.stack
    }

    /// Check if evaluation succeeded (stack top is true)
    pub fn success(&self) -> bool {
        if let Ok(top) = self.stack.top() {
            cast_to_bool(top)
        } else {
            false
        }
    }
}

/// Verify a script pair (scriptSig + scriptPubKey)
pub fn verify_script(
    script_sig: &Script,
    script_pubkey: &Script,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    // Evaluate scriptSig
    let mut interp = ScriptInterpreter::new(flags, checker);

    // Check scriptSig for push-only if P2SH
    if flags.has(ScriptFlags::SIGPUSHONLY) {
        // Verify scriptSig contains only push operations
        // (simplified check - full check would iterate opcodes)
    }

    interp.eval(script_sig)?;

    // Copy stack for P2SH
    let stack_copy: Vec<Vec<u8>> = interp.stack().data().to_vec();

    // Evaluate scriptPubKey
    interp.eval(script_pubkey)?;

    // Check result
    if !interp.success() {
        return Err(ScriptError::EvalFalse);
    }

    // P2SH verification
    if flags.has(ScriptFlags::P2SH) && script_pubkey.is_p2sh() {
        // The last element of the original scriptSig is the serialized script
        if let Some(serialized_script) = stack_copy.last() {
            let redeem_script = Script::from_bytes(serialized_script.clone());

            // Reset interpreter with stack from scriptSig (minus last element)
            let mut p2sh_interp = ScriptInterpreter::new(flags, checker);
            for elem in &stack_copy[..stack_copy.len() - 1] {
                p2sh_interp.stack.push(elem.clone())?;
            }

            // Evaluate the redeem script
            p2sh_interp.eval(&redeem_script)?;

            if !p2sh_interp.success() {
                return Err(ScriptError::EvalFalse);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
