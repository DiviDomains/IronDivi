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

//! divi-node - Full node orchestration
//!
//! This crate provides the main node implementation that ties together
//! all Divi components: storage, networking, consensus, RPC, and wallet.
//!
//! # Overview
//!
//! The Node struct is the central orchestrator that:
//! - Manages the blockchain database
//! - Handles the transaction mempool
//! - Coordinates P2P networking
//! - Serves RPC requests
//! - Optionally runs a wallet
//!
//! # Example
//!
//! ```
//! use divi_node::{Node, NodeConfig};
//! use divi_primitives::ChainMode;
//!
//! // Create node config with a temporary data directory
//! let mut config = NodeConfig::testnet(ChainMode::Divi);
//! let temp_dir = std::env::temp_dir().join(format!("divi_doctest_{}", std::process::id()));
//! config.data_dir = temp_dir.clone();
//!
//! // Create the node
//! let node = Node::new(config).unwrap();
//!
//! // Get blockchain info (node starts at genesis)
//! let info = node.get_blockchain_info();
//! assert_eq!(info.blocks, 0);
//! assert_eq!(info.chain, "test");
//!
//! // Get network info
//! let net_info = node.get_network_info();
//! assert_eq!(net_info.protocol_version, 70920);
//!
//! // Clean up
//! let _ = std::fs::remove_dir_all(&temp_dir);
//! ```

pub mod config;
pub mod error;
pub mod fee_estimator;
pub mod mempool;
pub mod node;
pub mod staker;

pub use config::{NetworkConfig, NetworkType, NodeConfig, P2pConfig, RpcConfig};
pub use error::NodeError;
pub use fee_estimator::{FeeEstimator, FeeEstimatorStats};
pub use mempool::{Mempool, MempoolEntry, MempoolStats};
pub use node::{BlockchainInfo, MempoolInfo, NetworkInfo, Node, NodeEvent, NodeStatus};
pub use staker::{StakeResult, Staker, StakerEvent, StakingConfig, StakingStatus};
