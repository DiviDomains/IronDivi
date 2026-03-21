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

//! Network constants
//!
//! Magic bytes, protocol versions, and other network parameters.

/// Network magic bytes (4 bytes identifying the network)
pub type Magic = [u8; 4];

/// Mainnet magic bytes
pub const MAINNET_MAGIC: Magic = [0xdf, 0xa0, 0x8d, 0x8f];

/// Testnet magic bytes
pub const TESTNET_MAGIC: Magic = [0xdf, 0xa0, 0x8d, 0x78];

/// Regtest magic bytes
pub const REGTEST_MAGIC: Magic = [0xa1, 0xcf, 0x7e, 0xac];

/// Unit test magic bytes (same as regtest for convenience)
pub const UNITTEST_MAGIC: Magic = [0xa1, 0xcf, 0x7e, 0xac];

/// PrivateDivi mainnet magic bytes
pub const PRIVATEDIVI_MAINNET_MAGIC: Magic = [0x70, 0xd1, 0x76, 0x11];

/// PrivateDivi testnet magic bytes
pub const PRIVATEDIVI_TESTNET_MAGIC: Magic = [0x70, 0xd1, 0x76, 0x12];

/// PrivateDivi regtest magic bytes
pub const PRIVATEDIVI_REGTEST_MAGIC: Magic = [0x70, 0xd1, 0x76, 0x13];

/// Initial protocol version (used in handshake before negotiation)
pub const INIT_PROTO_VERSION: i32 = 209;

/// Current protocol version
pub const PROTOCOL_VERSION: i32 = 70920;

/// Minimum peer protocol version after enforcement
pub const MIN_PEER_PROTO_VERSION: i32 = 70915;

/// Version when time field was added to CAddress
pub const CADDR_TIME_VERSION: i32 = 31402;

/// Version when pong message was added (BIP 0031)
pub const BIP0031_VERSION: i32 = 60000;

/// Version when getheaders was introduced
pub const GETHEADERS_VERSION: i32 = 70077;

/// Maximum message payload size (32 MB)
pub const MAX_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;

/// Maximum number of headers in a single headers message
pub const MAX_HEADERS_RESULTS: usize = 2000;

/// Maximum number of inventory items in a single inv/getdata message
pub const MAX_INV_SIZE: usize = 50000;

/// Default port for mainnet
pub const DEFAULT_PORT_MAINNET: u16 = 51472;

/// Default port for testnet
pub const DEFAULT_PORT_TESTNET: u16 = 51474;

/// Default port for regtest
pub const DEFAULT_PORT_REGTEST: u16 = 51476;

/// Default port for PrivateDivi mainnet
pub const DEFAULT_PORT_PRIVATEDIVI_MAINNET: u16 = 52472;

/// Default port for PrivateDivi testnet
pub const DEFAULT_PORT_PRIVATEDIVI_TESTNET: u16 = 52474;

/// Default port for PrivateDivi regtest
pub const DEFAULT_PORT_PRIVATEDIVI_REGTEST: u16 = 52476;

/// Default RPC port for Divi mainnet
pub const DEFAULT_RPC_PORT_MAINNET: u16 = 51471;

/// Default RPC port for Divi testnet
pub const DEFAULT_RPC_PORT_TESTNET: u16 = 51473;

/// Default RPC port for Divi regtest
pub const DEFAULT_RPC_PORT_REGTEST: u16 = 51475;

/// Default RPC port for PrivateDivi mainnet
pub const DEFAULT_RPC_PORT_PRIVATEDIVI_MAINNET: u16 = 52471;

/// Default RPC port for PrivateDivi testnet
pub const DEFAULT_RPC_PORT_PRIVATEDIVI_TESTNET: u16 = 52473;

/// Default RPC port for PrivateDivi regtest
pub const DEFAULT_RPC_PORT_PRIVATEDIVI_REGTEST: u16 = 52475;

/// User agent string
pub const USER_AGENT: &str = "/IronDivi:0.1.0/";

/// Service flags
pub mod services {
    /// This node can be asked for full blocks
    pub const NODE_NETWORK: u64 = 1 << 0;

    /// This node supports bloom filters
    pub const NODE_BLOOM: u64 = 1 << 2;

    /// This node supports bloom but doesn't want masternode messages
    pub const NODE_BLOOM_WITHOUT_MN: u64 = 1 << 4;
}
