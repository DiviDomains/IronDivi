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

//! Version message for P2P handshake
//!
//! The version message is exchanged when establishing a connection.
//! Both nodes send their version, then acknowledge with verack.

use crate::error::NetworkError;
use crate::message::NetAddr;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use divi_primitives::compact::CompactSize;
use divi_primitives::serialize::{Decodable, Encodable};
use std::io::Cursor;

/// Version message payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    /// Protocol version
    pub version: i32,
    /// Services provided by this node
    pub services: u64,
    /// Unix timestamp
    pub timestamp: i64,
    /// Address of receiving node
    pub addr_recv: NetAddr,
    /// Address of sending node
    pub addr_from: NetAddr,
    /// Random nonce for connection detection
    pub nonce: u64,
    /// User agent string
    pub user_agent: String,
    /// Best block height known to this node
    pub start_height: i32,
    /// Whether this node wants to receive relay messages
    pub relay: bool,
}

impl VersionMessage {
    /// Serialize the version message
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.write_i32::<LittleEndian>(self.version).unwrap();
        buf.write_u64::<LittleEndian>(self.services).unwrap();
        buf.write_i64::<LittleEndian>(self.timestamp).unwrap();
        buf.extend_from_slice(&self.addr_recv.serialize());
        buf.extend_from_slice(&self.addr_from.serialize());
        buf.write_u64::<LittleEndian>(self.nonce).unwrap();

        // User agent with CompactSize length prefix
        let user_agent_bytes = self.user_agent.as_bytes();
        let len = CompactSize::new(user_agent_bytes.len() as u64);
        let mut len_buf = Vec::new();
        len.encode(&mut len_buf).unwrap();
        buf.extend_from_slice(&len_buf);
        buf.extend_from_slice(user_agent_bytes);

        buf.write_i32::<LittleEndian>(self.start_height).unwrap();
        buf.push(if self.relay { 1 } else { 0 });

        buf
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        let mut cursor = Cursor::new(data);

        let version = cursor.read_i32::<LittleEndian>()?;
        let services = cursor.read_u64::<LittleEndian>()?;
        let timestamp = cursor.read_i64::<LittleEndian>()?;

        // Read addr_recv (26 bytes)
        let pos = cursor.position() as usize;
        let addr_recv = NetAddr::deserialize(&data[pos..pos + 26])?;
        cursor.set_position((pos + 26) as u64);

        // Read addr_from (26 bytes)
        let pos = cursor.position() as usize;
        let addr_from = NetAddr::deserialize(&data[pos..pos + 26])?;
        cursor.set_position((pos + 26) as u64);

        let nonce = cursor.read_u64::<LittleEndian>()?;

        // Read user agent
        let len = CompactSize::decode(&mut cursor)
            .map_err(|e| NetworkError::Deserialization(e.to_string()))?;
        let len = len.value() as usize;
        let pos = cursor.position() as usize;
        if pos + len > data.len() {
            return Err(NetworkError::Deserialization("user agent too long".into()));
        }
        let user_agent = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        cursor.set_position((pos + len) as u64);

        let start_height = cursor.read_i32::<LittleEndian>()?;

        // Relay is optional (added in BIP 0037)
        let relay = if cursor.position() < data.len() as u64 {
            cursor.read_u8()? != 0
        } else {
            true
        };

        // Check for unconsumed bytes (version messages may have extra data)
        let consumed = cursor.position() as usize;
        if consumed != data.len() {
            tracing::warn!(
                "version message: consumed {} bytes but payload has {} bytes ({} unconsumed)",
                consumed,
                data.len(),
                data.len() - consumed
            );
            tracing::warn!(
                "Unconsumed bytes: {:02x?}",
                &data[consumed..data.len().min(consumed + 64)]
            );
        }

        Ok(VersionMessage {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{services::NODE_NETWORK, PROTOCOL_VERSION, USER_AGENT};

    #[test]
    fn test_version_message_roundtrip() {
        let msg = VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            timestamp: 1234567890,
            addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 51472, NODE_NETWORK),
            addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, NODE_NETWORK),
            nonce: 0xdeadbeef,
            user_agent: USER_AGENT.to_string(),
            start_height: 100000,
            relay: true,
        };

        let serialized = msg.serialize();
        let deserialized = VersionMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, msg.version);
        assert_eq!(deserialized.services, msg.services);
        assert_eq!(deserialized.timestamp, msg.timestamp);
        assert_eq!(deserialized.nonce, msg.nonce);
        assert_eq!(deserialized.user_agent, msg.user_agent);
        assert_eq!(deserialized.start_height, msg.start_height);
        assert_eq!(deserialized.relay, msg.relay);
    }

    #[test]
    fn test_version_message_min_fields() {
        let msg = VersionMessage {
            version: 60002,
            services: 0,
            timestamp: 0,
            addr_recv: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            nonce: 0,
            user_agent: String::new(),
            start_height: 0,
            relay: false,
        };

        let serialized = msg.serialize();
        let deserialized = VersionMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, msg.version);
        assert_eq!(deserialized.user_agent, "");
        assert!(!deserialized.relay);
    }

    // ============================================================
    // MISSING TESTS: PrivateDivi testnet version message, field sizes
    // ============================================================

    #[test]
    fn test_version_message_privatedivi_testnet() {
        use crate::constants::{
            services::NODE_NETWORK, PRIVATEDIVI_TESTNET_MAGIC, PROTOCOL_VERSION,
        };

        // Build a version message as would be sent on PrivateDivi testnet
        let msg = VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            timestamp: 1704067200,
            addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 52474, NODE_NETWORK),
            addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, NODE_NETWORK),
            nonce: 0xdeadbeef_cafebabe,
            user_agent: "/IronDivi:0.1.0/".to_string(),
            start_height: 500_000,
            relay: true,
        };

        // Serialize and round-trip
        let serialized = msg.serialize();
        let deserialized = VersionMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, PROTOCOL_VERSION);
        assert_eq!(deserialized.services, NODE_NETWORK);
        assert_eq!(deserialized.start_height, 500_000);
        assert!(deserialized.relay);
        assert_eq!(deserialized.user_agent, "/IronDivi:0.1.0/");

        // The magic bytes for PrivateDivi testnet are 0x70 0xd1 0x76 0x12
        assert_eq!(PRIVATEDIVI_TESTNET_MAGIC, [0x70, 0xd1, 0x76, 0x12]);
    }

    #[test]
    fn test_version_message_fixed_field_sizes() {
        // A version message with no user agent is: 4+8+8+26+26+8+1+4+1 = 86 bytes
        let msg = VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            timestamp: 0,
            addr_recv: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            nonce: 0,
            user_agent: String::new(),
            start_height: 0,
            relay: false,
        };

        let serialized = msg.serialize();
        // version(4) + services(8) + timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8) + user_agent_len(1=varint) + start_height(4) + relay(1)
        // = 4+8+8+26+26+8+1+0+4+1 = 86
        assert_eq!(serialized.len(), 86);
    }

    #[test]
    fn test_version_message_services_field() {
        let msg = VersionMessage {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            timestamp: 0,
            addr_recv: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            nonce: 0,
            user_agent: String::new(),
            start_height: 0,
            relay: true,
        };

        let serialized = msg.serialize();
        let deserialized = VersionMessage::deserialize(&serialized).unwrap();

        // Services should be preserved exactly
        assert_eq!(deserialized.services, NODE_NETWORK);
        assert_eq!(deserialized.services & NODE_NETWORK, NODE_NETWORK);
    }

    #[test]
    fn test_version_message_nonce_uniqueness() {
        // Two messages with different nonces should be distinct
        let make_msg = |nonce: u64| VersionMessage {
            version: PROTOCOL_VERSION,
            services: 0,
            timestamp: 0,
            addr_recv: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            nonce,
            user_agent: String::new(),
            start_height: 0,
            relay: false,
        };

        let msg1 = make_msg(0x1111111111111111);
        let msg2 = make_msg(0x2222222222222222);

        let s1 = msg1.serialize();
        let s2 = msg2.serialize();

        let d1 = VersionMessage::deserialize(&s1).unwrap();
        let d2 = VersionMessage::deserialize(&s2).unwrap();

        assert_ne!(d1.nonce, d2.nonce);
        assert_eq!(d1.nonce, 0x1111111111111111);
        assert_eq!(d2.nonce, 0x2222222222222222);
    }
}
