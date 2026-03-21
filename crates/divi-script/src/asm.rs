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

//! Script ASM disassembly
//!
//! This module provides human-readable disassembly of Divi scripts,
//! matching the output format of C++ Divi's `CScript::ToString()` function.

use crate::stack::ScriptNum;

/// A wrapper around raw script bytes for disassembly purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script(Vec<u8>);

impl Script {
    /// Create a new Script from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Script(bytes)
    }

    /// Create a Script from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex)?;
        Ok(Script(bytes))
    }

    /// Get the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the script is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to human-readable ASM format.
    ///
    /// This matches the output format of C++ Divi's `CScript::ToString()` function:
    /// - Opcodes are separated by spaces
    /// - Push data <= 4 bytes is interpreted as a signed integer
    /// - Push data > 4 bytes is printed as hex
    /// - On error, "[error]" is appended and parsing stops
    pub fn to_asm(&self) -> String {
        let mut result = String::new();
        let mut iter = ScriptIterator::new(&self.0);

        while let Some(item) = iter.next() {
            if !result.is_empty() {
                result.push(' ');
            }

            match item {
                ScriptItem::PushData(data) => {
                    result.push_str(&value_string(&data));
                }
                ScriptItem::Opcode(opcode) => {
                    result.push_str(get_op_name(opcode));
                }
                ScriptItem::Error => {
                    result.push_str("[error]");
                    break;
                }
            }
        }

        result
    }
}

impl From<Vec<u8>> for Script {
    fn from(bytes: Vec<u8>) -> Self {
        Script(bytes)
    }
}

impl From<&[u8]> for Script {
    fn from(bytes: &[u8]) -> Self {
        Script(bytes.to_vec())
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Convenience function to convert script bytes to ASM string.
pub fn to_asm(script: &[u8]) -> String {
    Script::from(script).to_asm()
}

/// Items that can appear in a script during iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptItem {
    /// Push data (0x00-0x4e opcodes)
    PushData(Vec<u8>),
    /// A regular opcode
    Opcode(u8),
    /// Parse error
    Error,
}

/// Iterator over script opcodes and push data.
///
/// This matches the behavior of C++ Divi's `GetOp2` function.
pub struct ScriptIterator<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ScriptIterator<'a> {
    /// Create a new iterator over the given script bytes.
    pub fn new(data: &'a [u8]) -> Self {
        ScriptIterator { data, pos: 0 }
    }

    /// Get the current position in the script.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Check if we've reached the end.
    pub fn is_at_end(&self) -> bool {
        self.pos >= self.data.len()
    }
}

impl<'a> Iterator for ScriptIterator<'a> {
    type Item = ScriptItem;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }

        let opcode = self.data[self.pos];
        self.pos += 1;

        // Handle push opcodes (0x00 - 0x4e)
        if opcode <= 0x4e {
            // OP_PUSHDATA4 = 0x4e
            let data_len = if opcode == 0x00 {
                // OP_0 pushes empty data
                0usize
            } else if opcode <= 0x4b {
                // Direct push: opcode is the number of bytes to push
                opcode as usize
            } else if opcode == 0x4c {
                // OP_PUSHDATA1: next byte is length
                if self.pos >= self.data.len() {
                    return Some(ScriptItem::Error);
                }
                let len = self.data[self.pos] as usize;
                self.pos += 1;
                len
            } else if opcode == 0x4d {
                // OP_PUSHDATA2: next 2 bytes (little-endian) are length
                if self.pos + 2 > self.data.len() {
                    return Some(ScriptItem::Error);
                }
                let len =
                    u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as usize;
                self.pos += 2;
                len
            } else {
                // OP_PUSHDATA4 (0x4e): next 4 bytes (little-endian) are length
                if self.pos + 4 > self.data.len() {
                    return Some(ScriptItem::Error);
                }
                let len = u32::from_le_bytes([
                    self.data[self.pos],
                    self.data[self.pos + 1],
                    self.data[self.pos + 2],
                    self.data[self.pos + 3],
                ]) as usize;
                self.pos += 4;
                len
            };

            // Read the push data
            if self.pos + data_len > self.data.len() {
                return Some(ScriptItem::Error);
            }
            let data = self.data[self.pos..self.pos + data_len].to_vec();
            self.pos += data_len;

            Some(ScriptItem::PushData(data))
        } else {
            Some(ScriptItem::Opcode(opcode))
        }
    }
}

/// Convert push data to a string representation.
///
/// Matches C++ Divi's `ValueString()` function:
/// - If data is <= 4 bytes, interpret as CScriptNum and print as decimal integer
/// - If data is > 4 bytes, print as hex
fn value_string(data: &[u8]) -> String {
    if data.len() <= 4 {
        // Decode as script number (don't require minimal encoding for display)
        match ScriptNum::decode(data, 4, false) {
            Ok(num) => {
                // C++ uses getint() which clamps to i32 range
                let value = num.value();
                let clamped = if value > i32::MAX as i64 {
                    i32::MAX
                } else if value < i32::MIN as i64 {
                    i32::MIN
                } else {
                    value as i32
                };
                clamped.to_string()
            }
            Err(_) => {
                // On decode error, fall back to hex
                hex::encode(data)
            }
        }
    } else {
        hex::encode(data)
    }
}

/// Get the display name for an opcode.
///
/// Matches C++ Divi's `GetOpName()` function exactly:
/// - OP_0 (0x00) -> "0"
/// - OP_1NEGATE (0x4f) -> "-1"
/// - OP_1 through OP_16 (0x51-0x60) -> "1" through "16"
/// - OP_META (0x6a, Divi's OP_RETURN) -> "OP_META"
/// - Other opcodes use their full names like "OP_DUP"
fn get_op_name(opcode: u8) -> &'static str {
    match opcode {
        // Special numeric representations
        0x00 => "0",  // OP_0
        0x4f => "-1", // OP_1NEGATE
        0x51 => "1",  // OP_1
        0x52 => "2",  // OP_2
        0x53 => "3",  // OP_3
        0x54 => "4",  // OP_4
        0x55 => "5",  // OP_5
        0x56 => "6",  // OP_6
        0x57 => "7",  // OP_7
        0x58 => "8",  // OP_8
        0x59 => "9",  // OP_9
        0x5a => "10", // OP_10
        0x5b => "11", // OP_11
        0x5c => "12", // OP_12
        0x5d => "13", // OP_13
        0x5e => "14", // OP_14
        0x5f => "15", // OP_15
        0x60 => "16", // OP_16

        // PUSHDATA opcodes (shouldn't be reached in normal to_asm flow,
        // but included for completeness)
        0x4c => "OP_PUSHDATA1",
        0x4d => "OP_PUSHDATA2",
        0x4e => "OP_PUSHDATA4",

        // Control
        0x50 => "OP_RESERVED",
        0x61 => "OP_NOP",
        0x62 => "OP_VER",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x65 => "OP_VERIF",
        0x66 => "OP_VERNOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        0x6a => "OP_META", // Divi uses OP_META instead of OP_RETURN

        // Stack
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x70 => "OP_2OVER",
        0x71 => "OP_2ROT",
        0x72 => "OP_2SWAP",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",

        // Splice
        0x7e => "OP_CAT",
        0x7f => "OP_SUBSTR",
        0x80 => "OP_LEFT",
        0x81 => "OP_RIGHT",
        0x82 => "OP_SIZE",

        // Bitwise
        0x83 => "OP_INVERT",
        0x84 => "OP_AND",
        0x85 => "OP_OR",
        0x86 => "OP_XOR",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x89 => "OP_RESERVED1",
        0x8a => "OP_RESERVED2",

        // Numeric
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8d => "OP_2MUL",
        0x8e => "OP_2DIV",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x98 => "OP_LSHIFT",
        0x99 => "OP_RSHIFT",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LESSTHAN",
        0xa0 => "OP_GREATERTHAN",
        0xa1 => "OP_LESSTHANOREQUAL",
        0xa2 => "OP_GREATERTHANOREQUAL",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",

        // Crypto
        0xa6 => "OP_RIPEMD160",
        0xa7 => "OP_SHA1",
        0xa8 => "OP_SHA256",
        0xa9 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xab => "OP_CODESEPARATOR",
        0xac => "OP_CHECKSIG",
        0xad => "OP_CHECKSIGVERIFY",
        0xae => "OP_CHECKMULTISIG",
        0xaf => "OP_CHECKMULTISIGVERIFY",

        // Expansion
        0xb0 => "OP_NOP1",
        0xb1 => "OP_CHECKLOCKTIMEVERIFY",
        0xb2 => "OP_NOP3", // OP_CHECKSEQUENCEVERIFY in Bitcoin, but OP_NOP3 in Divi's GetOpName
        0xb3 => "OP_NOP4",
        0xb4 => "OP_NOP5",
        0xb5 => "OP_NOP6",
        0xb6 => "OP_NOP7",
        0xb7 => "OP_NOP8",

        // Divi-specific
        0xb8 => "OP_LIMIT_TRANSFER",
        0xb9 => "OP_REQUIRE_COINSTAKE",

        // Invalid/unknown
        0xff => "OP_INVALIDOPCODE",

        _ => "OP_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_script() {
        let script = Script::new(vec![]);
        assert_eq!(script.to_asm(), "");
    }

    #[test]
    fn test_op_0() {
        // OP_0 (0x00) pushes empty data, which decodes to 0
        let script = Script::new(vec![0x00]);
        assert_eq!(script.to_asm(), "0");
    }

    #[test]
    fn test_op_1_through_16() {
        // OP_1 (0x51) through OP_16 (0x60)
        let script = Script::new(vec![0x51]);
        assert_eq!(script.to_asm(), "1");

        let script = Script::new(vec![0x60]);
        assert_eq!(script.to_asm(), "16");
    }

    #[test]
    fn test_op_1negate() {
        let script = Script::new(vec![0x4f]);
        assert_eq!(script.to_asm(), "-1");
    }

    #[test]
    fn test_op_meta() {
        // OP_RETURN/OP_META (0x6a)
        let script = Script::new(vec![0x6a]);
        assert_eq!(script.to_asm(), "OP_META");
    }

    #[test]
    fn test_p2pkh() {
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        // 76a914000000000000000000000000000000000000000088ac
        let script =
            Script::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
        assert_eq!(
            script.to_asm(),
            "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG"
        );
    }

    #[test]
    fn test_p2sh() {
        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        // a914000000000000000000000000000000000000000087
        let script = Script::from_hex("a914000000000000000000000000000000000000000087").unwrap();
        assert_eq!(
            script.to_asm(),
            "OP_HASH160 0000000000000000000000000000000000000000 OP_EQUAL"
        );
    }

    #[test]
    fn test_small_push_as_integer() {
        // Push 1 byte [0x01] = 1
        let script = Script::new(vec![0x01, 0x01]);
        assert_eq!(script.to_asm(), "1");

        // Push 1 byte [0x81] = -1
        let script = Script::new(vec![0x01, 0x81]);
        assert_eq!(script.to_asm(), "-1");

        // Push 2 bytes [0x80, 0x00] = 128
        let script = Script::new(vec![0x02, 0x80, 0x00]);
        assert_eq!(script.to_asm(), "128");

        // Push 4 bytes max
        let script = Script::new(vec![0x04, 0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(script.to_asm(), "2147483647"); // i32::MAX
    }

    #[test]
    fn test_large_push_as_hex() {
        // Push 5 bytes should be hex
        let script = Script::new(vec![0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(script.to_asm(), "0102030405");
    }

    #[test]
    fn test_pushdata1() {
        // OP_PUSHDATA1 with 5 bytes
        let script = Script::new(vec![0x4c, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(script.to_asm(), "0102030405");
    }

    #[test]
    fn test_pushdata2() {
        // OP_PUSHDATA2 with 2 bytes of data [0xab, 0xcd]
        // Little-endian: 0xcdab = 52651
        // MSB (0xcd) has bit 7 set, so it's negative
        // Value = -(0xcdab & ~0x8000) = -(0x4dab) = -19883
        let script = Script::new(vec![0x4d, 0x02, 0x00, 0xab, 0xcd]);
        assert_eq!(script.to_asm(), "-19883");
    }

    #[test]
    fn test_error_truncated_push() {
        // Direct push expecting 5 bytes but only 3 available
        let script = Script::new(vec![0x05, 0x01, 0x02, 0x03]);
        assert_eq!(script.to_asm(), "[error]");
    }

    #[test]
    fn test_error_truncated_pushdata1() {
        // OP_PUSHDATA1 with no length byte
        let script = Script::new(vec![0x4c]);
        assert_eq!(script.to_asm(), "[error]");
    }

    #[test]
    fn test_error_truncated_pushdata2() {
        // OP_PUSHDATA2 with only 1 length byte
        let script = Script::new(vec![0x4d, 0x05]);
        assert_eq!(script.to_asm(), "[error]");
    }

    #[test]
    fn test_error_truncated_pushdata4() {
        // OP_PUSHDATA4 with only 2 length bytes
        let script = Script::new(vec![0x4e, 0x05, 0x00]);
        assert_eq!(script.to_asm(), "[error]");
    }

    #[test]
    fn test_multisig() {
        // 2-of-3 multisig pattern: 2 <pubkey1> <pubkey2> <pubkey3> 3 OP_CHECKMULTISIG
        // Using short test pubkeys
        let script = Script::new(vec![
            0x52, // OP_2
            0x21, // push 33 bytes (compressed pubkey)
            0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, // push 33 bytes (compressed pubkey)
            0x03, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x21, // push 33 bytes (compressed pubkey)
            0x02, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x53, // OP_3
            0xae, // OP_CHECKMULTISIG
        ]);
        let asm = script.to_asm();
        assert!(asm.starts_with("2 "));
        assert!(asm.ends_with(" 3 OP_CHECKMULTISIG"));
    }

    #[test]
    fn test_op_return_with_data() {
        // OP_RETURN with some data
        let script = Script::new(vec![0x6a, 0x04, 0x74, 0x65, 0x73, 0x74]);
        assert_eq!(script.to_asm(), "OP_META 1953719668"); // "test" as little-endian i32
    }

    #[test]
    fn test_staking_vault() {
        // OP_REQUIRE_COINSTAKE followed by P2PKH
        let script =
            Script::from_hex("b976a914000000000000000000000000000000000000000088ac").unwrap();
        assert_eq!(
            script.to_asm(),
            "OP_REQUIRE_COINSTAKE OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG"
        );
    }

    #[test]
    fn test_to_asm_function() {
        let bytes = hex::decode("76a914000000000000000000000000000000000000000088ac").unwrap();
        assert_eq!(
            to_asm(&bytes),
            "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG"
        );
    }

    #[test]
    fn test_script_from_hex() {
        let script = Script::from_hex("76a9").unwrap();
        assert_eq!(script.to_asm(), "OP_DUP OP_HASH160");
    }

    #[test]
    fn test_script_iterator() {
        let script = Script::new(vec![0x76, 0xa9, 0x01, 0x42, 0x88]);
        let items: Vec<_> = ScriptIterator::new(script.as_bytes()).collect();
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], ScriptItem::Opcode(0x76)); // OP_DUP
        assert_eq!(items[1], ScriptItem::Opcode(0xa9)); // OP_HASH160
        assert_eq!(items[2], ScriptItem::PushData(vec![0x42])); // push 1 byte
        assert_eq!(items[3], ScriptItem::Opcode(0x88)); // OP_EQUALVERIFY
    }

    #[test]
    fn test_negative_numbers() {
        // Test various negative number encodings
        // -1 = [0x81]
        let script = Script::new(vec![0x01, 0x81]);
        assert_eq!(script.to_asm(), "-1");

        // -127 = [0xff]
        let script = Script::new(vec![0x01, 0xff]);
        assert_eq!(script.to_asm(), "-127");

        // -128 = [0x80, 0x80]
        let script = Script::new(vec![0x02, 0x80, 0x80]);
        assert_eq!(script.to_asm(), "-128");

        // -255 = [0xff, 0x80]
        let script = Script::new(vec![0x02, 0xff, 0x80]);
        assert_eq!(script.to_asm(), "-255");
    }

    #[test]
    fn test_zero_push() {
        // Empty push data should decode to 0
        // OP_0 (0x00) pushes empty vector
        let script = Script::new(vec![0x00]);
        assert_eq!(script.to_asm(), "0");
    }

    #[test]
    fn test_limit_transfer() {
        let script = Script::new(vec![0xb8]);
        assert_eq!(script.to_asm(), "OP_LIMIT_TRANSFER");
    }

    #[test]
    fn test_checklocktimeverify() {
        let script = Script::new(vec![0xb1]);
        assert_eq!(script.to_asm(), "OP_CHECKLOCKTIMEVERIFY");
    }

    #[test]
    fn test_unknown_opcode() {
        // Use an opcode in the undefined range
        let script = Script::new(vec![0xba]);
        assert_eq!(script.to_asm(), "OP_UNKNOWN");
    }
}
