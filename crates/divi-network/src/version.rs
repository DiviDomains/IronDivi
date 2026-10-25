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
use crate::wire::Reader;
use byteorder::{LittleEndian, WriteBytesExt};
use divi_primitives::compact::CompactSize;
use divi_primitives::serialize::Encodable;

/// Divi Core `LIMITED_STRING(strSubVer, 256)`
pub const MAX_SUBVERSION_LENGTH: usize = 256;

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

    /// Deserialize from bytes. As in Divi Core, only the fields up to the
    /// receiver's address are required; the sender's address and nonce, the
    /// user agent (at most 256 bytes), the start height and the relay flag
    /// are read only if the payload goes on.
    pub fn deserialize(data: &[u8]) -> Result<Self, NetworkError> {
        let mut r = Reader::new(data);
        let version = r.i32()?;
        let services = r.u64()?;
        let timestamp = r.i64()?;
        let addr_recv = NetAddr::read(&mut r)?;

        let (addr_from, nonce) = if r.is_empty() {
            (NetAddr::from_ipv4([0, 0, 0, 0], 0, 0), 1)
        } else {
            (NetAddr::read(&mut r)?, r.u64()?)
        };
        let user_agent = if r.is_empty() {
            String::new()
        } else {
            r.limited_string(MAX_SUBVERSION_LENGTH)?
        };
        let start_height = if r.is_empty() { -1 } else { r.i32()? };
        let relay = if r.is_empty() { true } else { r.u8()? != 0 };

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
            user_agent: USER_AGENT.to_string(),
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
        assert_eq!(deserialized.user_agent, USER_AGENT);

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
