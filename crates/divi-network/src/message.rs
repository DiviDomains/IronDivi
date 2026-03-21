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

//! Network message types
//!
//! Implements the Divi P2P protocol message format.
//!
//! # Message Format
//!
//! Each message consists of:
//! - Header (24 bytes)
//!   - Magic (4 bytes): Network identifier
//!   - Command (12 bytes): Message type (null-padded)
//!   - Size (4 bytes): Payload size (little-endian)
//!   - Checksum (4 bytes): First 4 bytes of double-SHA256 of payload
//! - Payload (variable): Message-specific data

use crate::constants::Magic;
use crate::error::NetworkError;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use divi_crypto::double_sha256;

/// Message header size in bytes
pub const HEADER_SIZE: usize = 24;

/// Command field size in bytes
pub const COMMAND_SIZE: usize = 12;

/// Message header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    /// Network magic bytes
    pub magic: Magic,
    /// Command name (e.g., "version", "block")
    pub command: [u8; COMMAND_SIZE],
    /// Payload size in bytes
    pub payload_size: u32,
    /// First 4 bytes of double-SHA256 of payload
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Create a new message header
    pub fn new(magic: Magic, command: &str, payload: &[u8]) -> Self {
        let mut cmd = [0u8; COMMAND_SIZE];
        let bytes = command.as_bytes();
        let len = bytes.len().min(COMMAND_SIZE);
        cmd[..len].copy_from_slice(&bytes[..len]);

        let hash = double_sha256(payload);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&hash[..4]);

        MessageHeader {
            magic,
            command: cmd,
            payload_size: payload.len() as u32,
            checksum,
        }
    }

    /// Get the command as a string
    pub fn command_string(&self) -> String {
        let end = self
            .command
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMMAND_SIZE);
        String::from_utf8_lossy(&self.command[..end]).to_string()
    }

    /// Validate the magic bytes
    pub fn validate_magic(&self, expected: &Magic) -> bool {
        &self.magic == expected
    }

    /// Validate the checksum against payload
    pub fn validate_checksum(&self, payload: &[u8]) -> bool {
        let hash = double_sha256(payload);
        self.checksum == &hash[..4]
    }

    /// Serialize the header
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.command);
        buf.write_u32::<LittleEndian>(self.payload_size).unwrap();
        buf.extend_from_slice(&self.checksum);
        buf
    }

    /// Deserialize a header from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        if data.len() < HEADER_SIZE {
            return Err(NetworkError::InvalidHeader(format!(
                "header too short: {} bytes",
                data.len()
            )));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        let mut command = [0u8; COMMAND_SIZE];
        command.copy_from_slice(&data[4..16]);

        let mut cursor = std::io::Cursor::new(&data[16..20]);
        let payload_size = cursor.read_u32::<LittleEndian>()?;

        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&data[20..24]);

        Ok(MessageHeader {
            magic,
            command,
            payload_size,
            checksum,
        })
    }
}

/// Inventory item type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum InvType {
    /// Transaction
    Tx = 1,
    /// Block
    Block = 2,
    /// Filtered block
    FilteredBlock = 3,
    /// Transaction lock request
    TxLockRequest = 4,
    /// Transaction lock vote
    TxLockVote = 5,
    /// Spork
    Spork = 6,
    /// Masternode winner
    MasternodeWinner = 7,
    /// Masternode scanning error
    MasternodeScanningError = 8,
    /// Budget vote
    BudgetVote = 9,
    /// Budget proposal
    BudgetProposal = 10,
    /// Budget finalized
    BudgetFinalized = 11,
    /// Budget finalized vote
    BudgetFinalizedVote = 12,
    /// Masternode quorum
    MasternodeQuorum = 13,
    /// Masternode announce
    MasternodeAnnounce = 14,
    /// Masternode ping
    MasternodePing = 15,
}

impl InvType {
    /// Convert from u32
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(InvType::Tx),
            2 => Some(InvType::Block),
            3 => Some(InvType::FilteredBlock),
            4 => Some(InvType::TxLockRequest),
            5 => Some(InvType::TxLockVote),
            6 => Some(InvType::Spork),
            7 => Some(InvType::MasternodeWinner),
            8 => Some(InvType::MasternodeScanningError),
            9 => Some(InvType::BudgetVote),
            10 => Some(InvType::BudgetProposal),
            11 => Some(InvType::BudgetFinalized),
            12 => Some(InvType::BudgetFinalizedVote),
            13 => Some(InvType::MasternodeQuorum),
            14 => Some(InvType::MasternodeAnnounce),
            15 => Some(InvType::MasternodePing),
            _ => None,
        }
    }
}

/// Inventory item
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InvItem {
    /// Item type
    pub inv_type: InvType,
    /// Item hash
    pub hash: divi_primitives::hash::Hash256,
}

impl InvItem {
    /// Create a new inventory item
    pub fn new(inv_type: InvType, hash: divi_primitives::hash::Hash256) -> Self {
        InvItem { inv_type, hash }
    }

    /// Serialize the inventory item
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        buf.write_u32::<LittleEndian>(self.inv_type as u32).unwrap();
        buf.extend_from_slice(self.hash.as_bytes());
        buf
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        if data.len() < 36 {
            return Err(NetworkError::Deserialization("inv item too short".into()));
        }

        let mut cursor = std::io::Cursor::new(&data[0..4]);
        let type_val = cursor.read_u32::<LittleEndian>()?;
        let inv_type = InvType::from_u32(type_val).ok_or_else(|| {
            NetworkError::Deserialization(format!("unknown inv type: {}", type_val))
        })?;

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&data[4..36]);
        let hash = divi_primitives::hash::Hash256::from_bytes(hash_bytes);

        Ok(InvItem { inv_type, hash })
    }
}

/// Network address with services
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddr {
    /// Services offered by this node
    pub services: u64,
    /// IPv6 address (IPv4 addresses are mapped)
    pub ip: [u8; 16],
    /// Port number
    pub port: u16,
}

impl NetAddr {
    /// Create from IPv4 address
    pub fn from_ipv4(ip: [u8; 4], port: u16, services: u64) -> Self {
        // Map IPv4 to IPv6
        let mut ip6 = [0u8; 16];
        ip6[10] = 0xff;
        ip6[11] = 0xff;
        ip6[12..16].copy_from_slice(&ip);

        NetAddr {
            services,
            ip: ip6,
            port,
        }
    }

    /// Create from IPv6 address
    pub fn from_ipv6(ip: [u8; 16], port: u16, services: u64) -> Self {
        NetAddr { services, ip, port }
    }

    /// Serialize the address (without time)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(26);
        buf.write_u64::<LittleEndian>(self.services).unwrap();
        buf.extend_from_slice(&self.ip);
        buf.write_u16::<byteorder::BigEndian>(self.port).unwrap(); // Port is big-endian!
        buf
    }

    /// Deserialize from bytes (without time)
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        if data.len() < 26 {
            return Err(NetworkError::Deserialization("net addr too short".into()));
        }

        let mut cursor = std::io::Cursor::new(&data[0..8]);
        let services = cursor.read_u64::<LittleEndian>()?;

        let mut ip = [0u8; 16];
        ip.copy_from_slice(&data[8..24]);

        let mut cursor = std::io::Cursor::new(&data[24..26]);
        let port = cursor.read_u16::<byteorder::BigEndian>()?;

        Ok(NetAddr { services, ip, port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAINNET_MAGIC;

    #[test]
    fn test_message_header_roundtrip() {
        let payload = b"test payload";
        let header = MessageHeader::new(MAINNET_MAGIC, "version", payload);

        let serialized = header.serialize();
        assert_eq!(serialized.len(), HEADER_SIZE);

        let deserialized = MessageHeader::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, header);
    }

    #[test]
    fn test_message_header_command() {
        let header = MessageHeader::new(MAINNET_MAGIC, "version", &[]);
        assert_eq!(header.command_string(), "version");

        let header = MessageHeader::new(MAINNET_MAGIC, "verylongcommand", &[]);
        assert_eq!(header.command_string(), "verylongcomm"); // Truncated
    }

    #[test]
    fn test_message_header_checksum() {
        let payload = b"test payload";
        let header = MessageHeader::new(MAINNET_MAGIC, "test", payload);

        assert!(header.validate_checksum(payload));
        assert!(!header.validate_checksum(b"wrong payload"));
    }

    #[test]
    fn test_inv_item_roundtrip() {
        let hash = divi_primitives::hash::Hash256::from_bytes([0xab; 32]);
        let item = InvItem::new(InvType::Block, hash);

        let serialized = item.serialize();
        assert_eq!(serialized.len(), 36);

        let deserialized = InvItem::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, item);
    }

    #[test]
    fn test_net_addr_ipv4() {
        let addr = NetAddr::from_ipv4([192, 168, 1, 1], 51472, 1);

        let serialized = addr.serialize();
        assert_eq!(serialized.len(), 26);

        let deserialized = NetAddr::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, addr);
    }

    // ============================================================
    // MISSING TESTS: Header format, magic validation, PrivateDivi
    // ============================================================

    #[test]
    fn test_header_is_exactly_24_bytes() {
        // The Bitcoin-derived P2P header must be exactly 24 bytes:
        // magic(4) + command(12) + length(4) + checksum(4) = 24
        let payload = b"hello world";
        let header = MessageHeader::new(MAINNET_MAGIC, "ping", payload);
        let serialized = header.serialize();
        assert_eq!(serialized.len(), HEADER_SIZE);
        assert_eq!(HEADER_SIZE, 24);
    }

    #[test]
    fn test_header_magic_occupies_first_4_bytes() {
        let payload = b"test";
        let header = MessageHeader::new(MAINNET_MAGIC, "ping", payload);
        let serialized = header.serialize();

        assert_eq!(&serialized[0..4], &MAINNET_MAGIC);
    }

    #[test]
    fn test_header_command_occupies_bytes_4_to_16() {
        let payload = b"";
        let header = MessageHeader::new(MAINNET_MAGIC, "version", payload);
        let serialized = header.serialize();

        // Command field bytes 4..16
        let cmd_bytes = &serialized[4..16];
        // "version" = 7 chars, rest null-padded
        assert_eq!(&cmd_bytes[..7], b"version");
        for &b in &cmd_bytes[7..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_header_length_occupies_bytes_16_to_20() {
        let payload = b"ABCD"; // 4 bytes
        let header = MessageHeader::new(MAINNET_MAGIC, "ping", payload);
        let serialized = header.serialize();

        // Length is little-endian at bytes 16..20
        let length = u32::from_le_bytes([
            serialized[16],
            serialized[17],
            serialized[18],
            serialized[19],
        ]);
        assert_eq!(length, 4);
    }

    #[test]
    fn test_header_checksum_occupies_bytes_20_to_24() {
        let payload = b"test payload";
        let header = MessageHeader::new(MAINNET_MAGIC, "tx", payload);
        let serialized = header.serialize();

        // Checksum is at bytes 20..24
        let checksum = &serialized[20..24];
        assert_eq!(checksum, &header.checksum);
    }

    #[test]
    fn test_wrong_magic_rejection() {
        let payload = b"test";
        let header = MessageHeader::new(MAINNET_MAGIC, "ping", payload);

        // Validate against the correct magic — should pass
        assert!(header.validate_magic(&MAINNET_MAGIC));

        // Validate against wrong magic — should fail
        let wrong_magic: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        assert!(!header.validate_magic(&wrong_magic));
    }

    #[test]
    fn test_privatedivi_testnet_magic_value() {
        use crate::constants::PRIVATEDIVI_TESTNET_MAGIC;
        // PrivateDivi testnet magic must be 0x70 0xd1 0x76 0x12
        assert_eq!(PRIVATEDIVI_TESTNET_MAGIC, [0x70, 0xd1, 0x76, 0x12]);
    }

    #[test]
    fn test_privatedivi_mainnet_magic_value() {
        use crate::constants::PRIVATEDIVI_MAINNET_MAGIC;
        // PrivateDivi mainnet magic must be 0x70 0xd1 0x76 0x11
        assert_eq!(PRIVATEDIVI_MAINNET_MAGIC, [0x70, 0xd1, 0x76, 0x11]);
    }

    #[test]
    fn test_privatedivi_testnet_magic_rejected_by_mainnet() {
        use crate::constants::PRIVATEDIVI_TESTNET_MAGIC;
        let payload = b"test";
        let header = MessageHeader::new(PRIVATEDIVI_TESTNET_MAGIC, "version", payload);

        // Should pass when checked against its own magic
        assert!(header.validate_magic(&PRIVATEDIVI_TESTNET_MAGIC));

        // Should fail when checked against mainnet magic
        assert!(!header.validate_magic(&MAINNET_MAGIC));
    }

    #[test]
    fn test_header_deserialize_too_short() {
        // Less than 24 bytes should fail
        let too_short = vec![0u8; 10];
        let result = MessageHeader::deserialize(&too_short);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_checksum_detects_payload_corruption() {
        let original_payload = b"original payload";
        let header = MessageHeader::new(MAINNET_MAGIC, "test", original_payload);

        // Correct payload validates
        assert!(header.validate_checksum(original_payload));

        // Corrupted payload fails
        let corrupted_payload = b"corrupted payload";
        assert!(!header.validate_checksum(corrupted_payload));
    }

    #[test]
    fn test_header_empty_payload_checksum() {
        // Empty payload gets its own deterministic checksum
        let header = MessageHeader::new(MAINNET_MAGIC, "verack", b"");
        assert_eq!(header.payload_size, 0);
        assert!(header.validate_checksum(b""));
        assert!(!header.validate_checksum(b"notempty"));
    }

    #[test]
    fn test_inv_type_all_known_values() {
        // Verify all InvType values are parseable
        assert!(InvType::from_u32(1).is_some()); // Tx
        assert!(InvType::from_u32(2).is_some()); // Block
        assert!(InvType::from_u32(15).is_some()); // MasternodePing
        assert!(InvType::from_u32(0).is_none()); // Unknown
        assert!(InvType::from_u32(16).is_none()); // Unknown
    }

    #[test]
    fn test_net_addr_port_is_big_endian() {
        // Bitcoin protocol encodes port in network byte order (big-endian)
        let port = 51472u16;
        let addr = NetAddr::from_ipv4([127, 0, 0, 1], port, 0);
        let serialized = addr.serialize();

        // Port is at bytes 24..26, big-endian
        let encoded_port = u16::from_be_bytes([serialized[24], serialized[25]]);
        assert_eq!(encoded_port, port);
    }

    #[test]
    fn test_net_addr_ipv6_roundtrip() {
        let ip = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let addr = NetAddr::from_ipv6(ip, 51472, 1);

        let serialized = addr.serialize();
        assert_eq!(serialized.len(), 26);

        let deserialized = NetAddr::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.ip, ip);
        assert_eq!(deserialized.port, 51472);
    }

    #[test]
    fn test_command_size_is_12() {
        assert_eq!(COMMAND_SIZE, 12);
    }
}
