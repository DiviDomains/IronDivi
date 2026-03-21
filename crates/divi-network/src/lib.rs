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

//! Divi Network Protocol
//!
//! This crate implements the P2P network protocol for Divi,
//! enabling communication with other nodes on the network.
//!
//! # Protocol Overview
//!
//! Divi uses a Bitcoin-derived protocol with these message types:
//! - **Handshake**: `version` and `verack` messages to establish connections
//! - **Inventory**: `inv`, `getdata`, `notfound` for announcing and requesting data
//! - **Blocks**: `getblocks`, `getheaders`, `headers`, `block` for sync
//! - **Transactions**: `tx` for transaction propagation
//! - **Utility**: `ping`, `pong`, `addr`, `getaddr` for network health
//!
//! # Message Format
//!
//! Each message has a 24-byte header:
//! - Magic (4 bytes): Network identifier
//! - Command (12 bytes): Message type name
//! - Size (4 bytes): Payload size
//! - Checksum (4 bytes): First 4 bytes of double-SHA256 of payload
//!
//! # Example
//!
//! ```
//! use divi_network::{NetworkMessage, VersionMessage, NetAddr, MAINNET_MAGIC, PROTOCOL_VERSION, services};
//!
//! // Create a version message
//! let version = VersionMessage {
//!     version: PROTOCOL_VERSION,
//!     services: services::NODE_NETWORK,
//!     timestamp: 1704067200, // 2024-01-01
//!     addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 51472, services::NODE_NETWORK),
//!     addr_from: NetAddr::from_ipv4([127, 0, 0, 1], 51472, services::NODE_NETWORK),
//!     nonce: 0x1234567890abcdef,
//!     user_agent: "/DiviRust:0.1.0/".to_string(),
//!     start_height: 1000000,
//!     relay: true,
//! };
//! let msg = NetworkMessage::Version(version);
//!
//! // Serialize for sending
//! let bytes = msg.to_bytes(MAINNET_MAGIC).unwrap();
//! assert!(bytes.len() > 24); // Header + payload
//! ```

pub mod constants;
pub mod error;
pub mod message;
pub mod messages;
pub mod version;

// P2P networking
pub mod codec;
pub mod connection;
pub mod masternode_handler;
pub mod peer;
pub mod peer_manager;
pub mod relay;
pub mod scoring;
pub mod spork;
pub mod sync;

pub use constants::{
    services, Magic, MAINNET_MAGIC, MAX_MESSAGE_SIZE, MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION,
    REGTEST_MAGIC, TESTNET_MAGIC, USER_AGENT,
};
pub use error::NetworkError;
pub use message::{InvItem, InvType, MessageHeader, NetAddr, COMMAND_SIZE, HEADER_SIZE};
pub use messages::{
    spork_ids, GetBlocksMessage, GetHeadersMessage, NetworkMessage, RejectMessage, SporkMessage,
};
pub use version::VersionMessage;

// P2P types
pub use codec::DiviCodec;
pub use connection::Connection;
pub use masternode_handler::MasternodeHandler;
pub use peer::{PeerDirection, PeerEvent, PeerHandle, PeerId, PeerInfo, PeerState};
pub use peer_manager::{
    mainnet_peer_manager, regtest_peer_manager, testnet_peer_manager, AddedNode, PeerManager,
    PeerManagerConfig,
};
pub use relay::{TxRelay, TxRelayEvent, TxRelayStats};
pub use scoring::{BanEntry, Misbehavior, PeerScoring, PeerStats};
pub use spork::{SporkManager, SporkSyncProgress, SporkSyncState};
pub use sync::{BlockConnectedCallback, BlockSync, ReorgCallback, SyncProgress, SyncState};
