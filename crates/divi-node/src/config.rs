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

//! Node configuration
//!
//! Configuration for the Divi node including network, storage, and RPC settings.

use divi_primitives::ChainMode;
use divi_wallet::Network;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Network type (mainnet/testnet)
    pub network: NetworkConfig,

    /// Data directory
    pub data_dir: PathBuf,

    /// P2P network settings
    pub p2p: P2pConfig,

    /// RPC server settings
    pub rpc: RpcConfig,

    /// Staking settings
    pub staking: StakingConfig,

    /// Mempool settings
    pub mempool: MempoolConfig,

    /// Debug/development settings
    pub debug: DebugConfig,

    /// Index settings
    pub index: IndexConfig,

    /// Logging settings
    pub log: LogConfig,

    /// UTXO cache size (number of entries). Default: 10_000_000. Set to 0 to disable.
    pub utxo_cache_size: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            network: NetworkConfig::default(),
            data_dir: PathBuf::from("./data"),
            p2p: P2pConfig::default(),
            rpc: RpcConfig::default(),
            staking: StakingConfig::default(),
            mempool: MempoolConfig::default(),
            debug: DebugConfig::default(),
            index: IndexConfig::default(),
            log: LogConfig::default(),
            utxo_cache_size: 10_000_000,
        }
    }
}

impl NodeConfig {
    /// Create a new config with default mainnet settings
    ///
    /// PrivateDivi mainnet listens on P2P 52472 (PrivateDivi Core
    /// chainparams.cpp:184) and serves RPC on 52471. Core's own mainnet RPC
    /// port is 52473 (chainparamsbase.cpp:25), but irondivi's PrivateDivi
    /// testnet RPC already uses 52473, so mainnet takes 52471, the port the
    /// CLI and `DEFAULT_RPC_PORT_PRIVATEDIVI_MAINNET` already assume.
    pub fn mainnet(chain_mode: ChainMode) -> Self {
        let (p2p_port, rpc_port) = match chain_mode {
            ChainMode::Divi => (51472, 51471),
            ChainMode::PrivateDivi => (52472, 52471),
        };
        NodeConfig {
            network: NetworkConfig::mainnet(chain_mode),
            p2p: P2pConfig {
                port: p2p_port,
                ..Default::default()
            },
            rpc: RpcConfig {
                port: rpc_port,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create a new config with default testnet settings
    pub fn testnet(chain_mode: ChainMode) -> Self {
        let (p2p_port, rpc_port) = match chain_mode {
            ChainMode::Divi => (51474, 51473),
            ChainMode::PrivateDivi => (52474, 52473),
        };
        NodeConfig {
            network: NetworkConfig::testnet(chain_mode),
            p2p: P2pConfig {
                port: p2p_port,
                ..Default::default()
            },
            rpc: RpcConfig {
                port: rpc_port,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create a new config with default regtest settings
    pub fn regtest(chain_mode: ChainMode) -> Self {
        let (p2p_port, rpc_port) = match chain_mode {
            ChainMode::Divi => (51476, 51475),
            ChainMode::PrivateDivi => (52476, 52475),
        };
        NodeConfig {
            network: NetworkConfig::regtest(chain_mode),
            p2p: P2pConfig {
                port: p2p_port,
                ..Default::default()
            },
            rpc: RpcConfig {
                port: rpc_port,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Get the blocks database path
    pub fn blocks_path(&self) -> PathBuf {
        self.data_dir.join("blocks")
    }

    /// Get the chainstate database path
    pub fn chainstate_path(&self) -> PathBuf {
        self.data_dir.join("chainstate")
    }

    /// Get the wallet path
    pub fn wallet_path(&self) -> PathBuf {
        self.data_dir.join("wallet.dat")
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network type
    pub network_type: NetworkType,

    /// Chain mode (Divi or PrivateDivi)
    pub chain_mode: ChainMode,

    /// Magic bytes for network messages
    pub magic: [u8; 4],

    /// Protocol version
    pub protocol_version: u32,

    /// Minimum supported protocol version
    pub min_protocol_version: u32,

    /// DNS seeds for peer discovery
    pub dns_seeds: Vec<String>,

    /// Static peers to connect to
    pub static_peers: Vec<String>,
}

/// Network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Regtest,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::mainnet(ChainMode::Divi)
    }
}

impl NetworkConfig {
    /// Mainnet configuration
    pub fn mainnet(chain_mode: ChainMode) -> Self {
        use divi_primitives::test_vectors::{dns_seeds, static_peers};
        match chain_mode {
            ChainMode::Divi => NetworkConfig {
                network_type: NetworkType::Mainnet,
                chain_mode,
                magic: [0xdf, 0xa0, 0x8d, 0x8f],
                protocol_version: 70920,
                min_protocol_version: 70915,
                dns_seeds: dns_seeds::divi::MAINNET
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                static_peers: static_peers::divi::MAINNET
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            },
            ChainMode::PrivateDivi => NetworkConfig {
                network_type: NetworkType::Mainnet,
                chain_mode,
                // 2026-04-20 relaunch (PrivateDivi Core 21de13166, chainparams.cpp:172-175)
                magic: [0x70, 0xd2, 0x76, 0x11],
                protocol_version: 70920,
                min_protocol_version: 70915,
                dns_seeds: dns_seeds::privatedivi::MAINNET
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                static_peers: static_peers::privatedivi::MAINNET
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            },
        }
    }

    /// The network's standard P2P port: the port DNS-seed results are dialed
    /// on. Independent of `-port`, which only changes where this node listens.
    pub fn default_p2p_port(&self) -> u16 {
        match (self.network_type, self.chain_mode) {
            (NetworkType::Mainnet, ChainMode::Divi) => 51472,
            (NetworkType::Mainnet, ChainMode::PrivateDivi) => 52472,
            (NetworkType::Testnet, ChainMode::Divi) => 51474,
            (NetworkType::Testnet, ChainMode::PrivateDivi) => 52474,
            (NetworkType::Regtest, ChainMode::Divi) => 51476,
            (NetworkType::Regtest, ChainMode::PrivateDivi) => 52476,
        }
    }

    /// Testnet configuration
    pub fn testnet(chain_mode: ChainMode) -> Self {
        use divi_primitives::test_vectors::{dns_seeds, static_peers};
        match chain_mode {
            ChainMode::Divi => NetworkConfig {
                network_type: NetworkType::Testnet,
                chain_mode,
                magic: [0xdf, 0xa0, 0x8d, 0x78],
                protocol_version: 70920,
                min_protocol_version: 70915,
                dns_seeds: dns_seeds::divi::TESTNET
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                static_peers: Vec::new(),
            },
            ChainMode::PrivateDivi => NetworkConfig {
                network_type: NetworkType::Testnet,
                chain_mode,
                magic: [0x70, 0xd1, 0x76, 0x12],
                protocol_version: 70920,
                min_protocol_version: 70915,
                dns_seeds: dns_seeds::privatedivi::TESTNET
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                static_peers: static_peers::privatedivi::TESTNET
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            },
        }
    }

    /// Regtest configuration (for local testing)
    pub fn regtest(chain_mode: ChainMode) -> Self {
        let magic = match chain_mode {
            ChainMode::Divi => [0xa1, 0xcf, 0x7e, 0xac],
            ChainMode::PrivateDivi => [0x70, 0xd1, 0x76, 0x13],
        };
        NetworkConfig {
            network_type: NetworkType::Regtest,
            chain_mode,
            magic,
            protocol_version: 70920,
            min_protocol_version: 70915,
            dns_seeds: Vec::new(),
            static_peers: Vec::new(),
        }
    }

    /// Get the wallet network type
    pub fn wallet_network(&self) -> Network {
        match self.network_type {
            NetworkType::Mainnet => Network::Mainnet,
            NetworkType::Testnet | NetworkType::Regtest => Network::Testnet,
        }
    }
}

/// P2P network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Listen address
    pub listen_addr: String,

    /// Listen port
    pub port: u16,

    /// Maximum number of inbound connections
    pub max_inbound: usize,

    /// Maximum number of outbound connections
    pub max_outbound: usize,

    /// Enable peer discovery
    pub enable_discovery: bool,

    /// `-connect` peers. When non-empty the node connects ONLY to these
    /// (no built-in static peers, no DNS seeds), matching C++ `-connect`.
    #[serde(default)]
    pub connect: Vec<String>,

    /// Accept inbound connections. `None` = default: listen unless `connect`
    /// is set (C++ soft-sets `-listen=0` under `-connect`).
    #[serde(default)]
    pub listen: Option<bool>,

    /// Ban time for misbehaving peers (seconds)
    pub ban_time: u64,

    /// User agent string
    pub user_agent: String,
}

impl Default for P2pConfig {
    fn default() -> Self {
        P2pConfig {
            listen_addr: "0.0.0.0".to_string(),
            port: 51472,
            max_inbound: 125,
            max_outbound: 8,
            enable_discovery: true,
            connect: Vec::new(),
            listen: None,
            ban_time: 86400, // 24 hours
            user_agent: format!("/DiviRust:{}/", env!("CARGO_PKG_VERSION")),
        }
    }
}

/// Where a node finds peers, after `-connect` / `-listen` / discovery are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSources {
    pub static_peers: Vec<String>,
    pub dns_seeds: Vec<String>,
    pub listen: bool,
}

impl NodeConfig {
    /// Resolve the peer sources. With `connect` set, outbound goes only to
    /// those peers and inbound is off unless `listen` was given explicitly.
    pub fn peer_sources(&self) -> PeerSources {
        if !self.p2p.connect.is_empty() {
            return PeerSources {
                static_peers: self.p2p.connect.clone(),
                dns_seeds: Vec::new(),
                listen: self.p2p.listen.unwrap_or(false),
            };
        }
        PeerSources {
            static_peers: self.network.static_peers.clone(),
            dns_seeds: if self.p2p.enable_discovery {
                self.network.dns_seeds.clone()
            } else {
                Vec::new()
            },
            listen: self.p2p.listen.unwrap_or(true),
        }
    }
}

impl P2pConfig {
    /// Get the socket address to listen on
    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.listen_addr, self.port)
            .parse()
            .expect("Invalid P2P listen address")
    }
}

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Enable RPC server
    pub enabled: bool,

    /// RPC listen address
    pub listen_addr: String,

    /// RPC port
    pub port: u16,

    /// RPC username (for authentication)
    pub username: Option<String>,

    /// RPC password (for authentication)
    pub password: Option<String>,

    /// Maximum request size (bytes)
    pub max_request_size: usize,

    /// Request timeout (seconds)
    pub timeout: u64,
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            enabled: true,
            listen_addr: "127.0.0.1".to_string(),
            port: 51471,
            username: None,
            password: None,
            max_request_size: 10 * 1024 * 1024, // 10 MB
            timeout: 30,
        }
    }
}

impl RpcConfig {
    /// Get the socket address to listen on
    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.listen_addr, self.port)
            .parse()
            .expect("Invalid RPC listen address")
    }
}

/// Staking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Enable staking
    pub enabled: bool,

    /// Minimum stake amount
    pub min_stake_amount: i64,

    /// Reserve balance (don't stake this much)
    pub reserve_balance: i64,

    /// Split stake threshold
    pub split_threshold: i64,

    /// Combine stake threshold
    pub combine_threshold: i64,

    /// Allow staking on a tip older than 24h (`stakeonstaletip`). Default off.
    #[serde(default)]
    pub stake_on_stale_tip: bool,
}

impl Default for StakingConfig {
    fn default() -> Self {
        StakingConfig {
            enabled: true,       // C++ -staking defaults to 1
            min_stake_amount: 0, // No minimum - any UTXO can stake (matches C++ Divi)
            reserve_balance: 0,
            split_threshold: 10_000_000_000_000, // 100,000 DIVI
            combine_threshold: 100_000_000_000,  // 1,000 DIVI
            stake_on_stale_tip: false,
        }
    }
}

/// Mempool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum mempool size (bytes)
    pub max_size: usize,

    /// Minimum relay fee (satoshis per byte)
    pub min_relay_fee: i64,

    /// Maximum orphan transactions
    pub max_orphan_txs: usize,

    /// Expiry time for transactions (seconds)
    pub expiry_time: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            max_size: 300 * 1024 * 1024, // 300 MB
            min_relay_fee: 10, // 10 sat/byte (matches C++ Divi CFeeRate(10000) = 10000 sat/kB)
            max_orphan_txs: 100,
            expiry_time: 336 * 60 * 60, // 2 weeks
        }
    }
}

/// Debug configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugConfig {
    /// Enable debug logging
    pub debug_logging: bool,

    /// Log network messages
    pub log_network: bool,

    /// Log RPC calls
    pub log_rpc: bool,

    /// Log mempool activity
    pub log_mempool: bool,

    /// Print block on accept
    pub print_blocks: bool,
}

/// Index configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    /// Enable transaction index (-txindex)
    pub txindex: bool,

    /// Enable spent index (-spentindex)
    pub spentindex: bool,

    /// Enable address index (-addressindex)
    pub addressindex: bool,
}

impl Default for IndexConfig {
    fn default() -> Self {
        IndexConfig {
            // txindex is required for PoS validation to find kernel transactions
            txindex: true,
            spentindex: false,
            addressindex: false,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Maximum size of each log file in bytes (default: 1MB = 1048576)
    pub max_file_size: u64,

    /// Number of log files to keep (default: 5)
    pub max_files: u32,

    /// Enable debug logging
    pub debug: bool,

    /// Print to console instead of file
    pub print_to_console: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            max_file_size: 1_048_576, // 1 MB
            max_files: 5,
            debug: false,
            print_to_console: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.p2p.port, 51472);
        assert_eq!(config.rpc.port, 51471);
    }

    #[test]
    fn test_mainnet_config() {
        let config = NodeConfig::mainnet(ChainMode::Divi);
        assert_eq!(config.network.network_type, NetworkType::Mainnet);
        assert_eq!(config.network.magic, [0xdf, 0xa0, 0x8d, 0x8f]);
    }

    #[test]
    fn test_testnet_config() {
        let config = NodeConfig::testnet(ChainMode::Divi);
        assert_eq!(config.network.network_type, NetworkType::Testnet);
        assert_eq!(config.p2p.port, 51474);
        assert_eq!(config.rpc.port, 51473);
    }

    #[test]
    fn test_paths() {
        let config = NodeConfig::default();
        assert!(config.blocks_path().ends_with("blocks"));
        assert!(config.chainstate_path().ends_with("chainstate"));
        assert!(config.wallet_path().ends_with("wallet.dat"));
    }

    #[test]
    fn test_socket_addrs() {
        let config = NodeConfig::default();
        let p2p_addr = config.p2p.socket_addr();
        assert_eq!(p2p_addr.port(), 51472);

        let rpc_addr = config.rpc.socket_addr();
        assert_eq!(rpc_addr.port(), 51471);
    }

    #[test]
    fn test_wallet_network() {
        assert_eq!(
            NetworkConfig::mainnet(ChainMode::Divi).wallet_network(),
            Network::Mainnet
        );
        assert_eq!(
            NetworkConfig::testnet(ChainMode::Divi).wallet_network(),
            Network::Testnet
        );
    }

    #[test]
    fn test_privatedivi_mainnet_config() {
        let config = NodeConfig::mainnet(ChainMode::PrivateDivi);
        assert_eq!(config.network.network_type, NetworkType::Mainnet);
        assert_eq!(config.network.chain_mode, ChainMode::PrivateDivi);
        assert_eq!(config.network.magic, [0x70, 0xd2, 0x76, 0x11]);
        assert_eq!(config.p2p.port, 52472);
        assert_eq!(config.rpc.port, 52471);
    }

    /// Seeds are dialed on the network's port even when `-port` moves the
    /// listener (a second node on one host must still reach real peers).
    #[test]
    fn default_p2p_port_matches_network_and_ignores_listen_port() {
        for mode in [ChainMode::Divi, ChainMode::PrivateDivi] {
            for mut c in [
                NodeConfig::mainnet(mode),
                NodeConfig::testnet(mode),
                NodeConfig::regtest(mode),
            ] {
                assert_eq!(c.network.default_p2p_port(), c.p2p.port);
                c.p2p.port = 51492;
                assert_ne!(c.network.default_p2p_port(), 51492);
            }
        }
    }

    /// Every default port across both modes and all networks is distinct,
    /// so a Divi and a PrivateDivi node (or two PrivateDivi networks) can
    /// run side by side on one host.
    #[test]
    fn default_ports_never_collide() {
        let mut ports = Vec::new();
        for mode in [ChainMode::Divi, ChainMode::PrivateDivi] {
            for c in [
                NodeConfig::mainnet(mode),
                NodeConfig::testnet(mode),
                NodeConfig::regtest(mode),
            ] {
                ports.push(c.p2p.port);
                ports.push(c.rpc.port);
            }
        }
        let mut uniq = ports.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), ports.len(), "{ports:?}");
    }

    #[test]
    fn test_privatedivi_testnet_config() {
        let config = NodeConfig::testnet(ChainMode::PrivateDivi);
        assert_eq!(config.network.network_type, NetworkType::Testnet);
        assert_eq!(config.network.chain_mode, ChainMode::PrivateDivi);
        assert_eq!(config.p2p.port, 52474);
        assert_eq!(config.rpc.port, 52473);
    }

    #[test]
    fn test_privatedivi_regtest_config() {
        let config = NodeConfig::regtest(ChainMode::PrivateDivi);
        assert_eq!(config.network.network_type, NetworkType::Regtest);
        assert_eq!(config.network.magic, [0x70, 0xd1, 0x76, 0x13]);
        assert_eq!(config.p2p.port, 52476);
        assert_eq!(config.rpc.port, 52475);
    }

    #[test]
    fn peer_sources_default_uses_builtin_peers_seeds_and_listens() {
        let config = NodeConfig::testnet(ChainMode::PrivateDivi);
        let src = config.peer_sources();
        assert!(!src.static_peers.is_empty());
        assert!(!src.dns_seeds.is_empty());
        assert!(src.listen);
    }

    #[test]
    fn peer_sources_connect_is_exclusive() {
        // Regression: -connect used to be appended to the built-in testnet
        // peers (vps1:52581..52585) and DNS seeds stayed on.
        let mut config = NodeConfig::testnet(ChainMode::PrivateDivi);
        config.p2p.connect = vec!["127.0.0.1:52581".to_string()];
        let src = config.peer_sources();
        assert_eq!(src.static_peers, vec!["127.0.0.1:52581".to_string()]);
        assert!(src.dns_seeds.is_empty());
        assert!(!src.listen, "-connect implies -listen=0 by default");

        config.p2p.listen = Some(true);
        assert!(config.peer_sources().listen, "explicit listen=1 wins");
    }

    #[test]
    fn peer_sources_discovery_off_drops_dns_seeds_only() {
        let mut config = NodeConfig::testnet(ChainMode::PrivateDivi);
        config.p2p.enable_discovery = false;
        let src = config.peer_sources();
        assert!(src.dns_seeds.is_empty());
        assert_eq!(src.static_peers, config.network.static_peers);
    }
}
