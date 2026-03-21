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

//! Bitcoin/Divi Script type
//!
//! Script is simply a sequence of bytes representing stack-based operations.
//! Interpretation happens in the divi-script crate.

use crate::compact::CompactSize;
use crate::error::Error;
use crate::serialize::{Decodable, Encodable};
use std::fmt;
use std::io::{Read, Write};
use std::ops::Deref;

/// A Bitcoin/Divi script
///
/// Scripts are interpreted by a stack-based virtual machine.
/// This type is just the raw bytes; interpretation is in divi-script.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Script(Vec<u8>);

impl Script {
    /// Create an empty script
    pub fn new() -> Self {
        Script(Vec::new())
    }

    /// Create a script from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Script(bytes)
    }

    /// Create a script from hex
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
        Ok(Script(bytes))
    }

    /// Get the script as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the script as a mutable byte vector
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Get the script length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the script is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Create OP_RETURN script with data
    pub fn new_op_return(data: &[u8]) -> Self {
        let mut script = Vec::with_capacity(2 + data.len());
        script.push(0x6a); // OP_RETURN

        // Push data with appropriate opcode
        if data.len() <= 75 {
            script.push(data.len() as u8);
        } else if data.len() <= 255 {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(data.len() as u8);
        } else {
            script.push(0x4d); // OP_PUSHDATA2
            script.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        script.extend_from_slice(data);

        Script(script)
    }

    /// Check if this is an OP_RETURN script
    pub fn is_op_return(&self) -> bool {
        !self.0.is_empty() && self.0[0] == 0x6a
    }

    /// Check if this is a P2PKH script (pay to pubkey hash)
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25
            && self.0[0] == 0x76  // OP_DUP
            && self.0[1] == 0xa9  // OP_HASH160
            && self.0[2] == 0x14  // Push 20 bytes
            && self.0[23] == 0x88 // OP_EQUALVERIFY
            && self.0[24] == 0xac // OP_CHECKSIG
    }

    /// Create a P2PKH script from a pubkey hash
    pub fn new_p2pkh(pubkey_hash: &[u8; 20]) -> Self {
        let mut script = Vec::with_capacity(25);
        script.push(0x76); // OP_DUP
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(pubkey_hash);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        Script(script)
    }

    /// Check if this is a P2SH script (pay to script hash)
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23
            && self.0[0] == 0xa9  // OP_HASH160
            && self.0[1] == 0x14  // Push 20 bytes
            && self.0[22] == 0x87 // OP_EQUAL
    }

    /// Create a P2SH script from a script hash
    pub fn new_p2sh(script_hash: &[u8; 20]) -> Self {
        let mut script = Vec::with_capacity(23);
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(script_hash);
        script.push(0x87); // OP_EQUAL
        Script(script)
    }

    /// Extract the pubkey hash from a P2PKH script
    pub fn extract_p2pkh_hash(&self) -> Option<[u8; 20]> {
        if self.is_p2pkh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&self.0[3..23]);
            Some(hash)
        } else {
            None
        }
    }

    /// Extract the script hash from a P2SH script
    pub fn extract_p2sh_hash(&self) -> Option<[u8; 20]> {
        if self.is_p2sh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&self.0[2..22]);
            Some(hash)
        } else {
            None
        }
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Script({})", self.to_hex())
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Deref for Script {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Script {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Script {
    fn from(bytes: Vec<u8>) -> Self {
        Script(bytes)
    }
}

impl Encodable for Script {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = CompactSize(self.0.len() as u64).encode(writer)?;
        writer.write_all(&self.0)?;
        size += self.0.len();
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        CompactSize(self.0.len() as u64).encoded_size() + self.0.len()
    }
}

impl Decodable for Script {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let len = CompactSize::decode(reader)?.0 as usize;
        let mut bytes = vec![0u8; len];
        reader.read_exact(&mut bytes)?;
        Ok(Script(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize, serialize};

    #[test]
    fn test_empty_script() {
        let script = Script::new();
        assert!(script.is_empty());
        assert_eq!(script.len(), 0);
    }

    #[test]
    fn test_p2pkh_script() {
        let hash = [0u8; 20];
        let script = Script::new_p2pkh(&hash);

        assert!(script.is_p2pkh());
        assert!(!script.is_p2sh());
        assert_eq!(script.len(), 25);

        let extracted = script.extract_p2pkh_hash().unwrap();
        assert_eq!(extracted, hash);
    }

    #[test]
    fn test_p2sh_script() {
        let hash = [0u8; 20];
        let script = Script::new_p2sh(&hash);

        assert!(!script.is_p2pkh());
        assert!(script.is_p2sh());
        assert_eq!(script.len(), 23);

        let extracted = script.extract_p2sh_hash().unwrap();
        assert_eq!(extracted, hash);
    }

    #[test]
    fn test_op_return_script() {
        let data = b"Hello, Divi!";
        let script = Script::new_op_return(data);

        assert!(script.is_op_return());
        assert!(!script.is_p2pkh());
    }

    #[test]
    fn test_script_serialization() {
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let encoded = serialize(&script);

        // CompactSize(3) + 3 bytes = 4 bytes
        assert_eq!(encoded, vec![3, 0x76, 0xa9, 0x14]);

        let decoded: Script = deserialize(&encoded).unwrap();
        assert_eq!(decoded, script);
    }

    #[test]
    fn test_script_hex() {
        let script = Script::from_hex("76a914").unwrap();
        assert_eq!(script.as_bytes(), &[0x76, 0xa9, 0x14]);
        assert_eq!(script.to_hex(), "76a914");
    }
}
