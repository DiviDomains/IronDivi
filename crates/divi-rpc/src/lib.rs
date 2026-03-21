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

//! divi-rpc - JSON-RPC server for Divi node
//!
//! This crate provides a JSON-RPC 2.0 server for interacting with the Divi node.
//! It supports standard Bitcoin/Divi RPC methods for querying blockchain state.
//!
//! # Example
//!
//! ```
//! use divi_rpc::{RpcConfig, RpcServer, Request, Params, RequestId};
//! use divi_storage::{Chain, ChainDatabase, ChainParams};
//! use std::sync::Arc;
//!
//! // Create a temporary data directory
//! let temp_dir = std::env::temp_dir().join(format!("divi_rpc_doctest_{}", std::process::id()));
//!
//! // Initialize database and chain
//! let db = Arc::new(ChainDatabase::open(&temp_dir).unwrap());
//! let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
//!
//! // Create RPC server
//! let server = RpcServer::new(chain);
//!
//! // Make an RPC request
//! let request = Request {
//!     jsonrpc: "2.0".to_string(),
//!     id: RequestId::Number(1),
//!     method: "getblockcount".to_string(),
//!     params: Params::None,
//! };
//! let response = server.handle_request(request);
//!
//! // Verify response (block count is 0 at genesis)
//! assert!(response.error.is_none());
//! assert_eq!(response.result, Some(serde_json::json!(0)));
//!
//! // Clean up
//! let _ = std::fs::remove_dir_all(&temp_dir);
//! ```

pub mod blockchain;
pub mod error;
pub mod lite_wallet;
pub mod masternode;
pub mod network;
pub mod protocol;
pub mod server;
pub mod spork;
pub mod staking;
pub mod wallet;
pub mod websocket;

pub use blockchain::BlockchainRpc;
pub use error::{Error, RpcError};
pub use lite_wallet::LiteWalletRpc;
pub use masternode::MasternodeRpc;
pub use network::NetworkRpc;
pub use protocol::{Params, Request, RequestId, Response};
pub use server::{
    create_router, start_server, start_server_with_peer_manager,
    start_server_with_peer_manager_and_setup, start_server_with_wallet_and_peer_manager,
    start_server_with_wallet_peer_and_staker, LogConfigInfo, RpcConfig, RpcServer,
};
pub use staking::{StakingInfo, StakingRpc};
pub use wallet::WalletRpc;
pub use websocket::{ws_handler, Notification, NotificationHub, WsState};
