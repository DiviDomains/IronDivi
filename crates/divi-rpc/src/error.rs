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

//! RPC error types
//!
//! Standard JSON-RPC 2.0 error codes and custom Divi error codes.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standard JSON-RPC 2.0 error codes
pub mod codes {
    // Standard JSON-RPC errors
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    // Bitcoin/Divi specific errors (from Bitcoin Core)
    pub const MISC_ERROR: i32 = -1;
    pub const TYPE_ERROR: i32 = -3;
    pub const INVALID_ADDRESS_OR_KEY: i32 = -5;
    pub const OUT_OF_MEMORY: i32 = -7;
    pub const INVALID_PARAMETER: i32 = -8;
    pub const DATABASE_ERROR: i32 = -20;
    pub const DESERIALIZATION_ERROR: i32 = -22;
    pub const VERIFY_ERROR: i32 = -25;
    pub const VERIFY_REJECTED: i32 = -26;
    pub const VERIFY_ALREADY_IN_CHAIN: i32 = -27;
    pub const IN_WARMUP: i32 = -28;

    // P2P client errors
    pub const CLIENT_NOT_CONNECTED: i32 = -9;
    pub const CLIENT_IN_INITIAL_DOWNLOAD: i32 = -10;
    pub const CLIENT_NODE_ALREADY_ADDED: i32 = -23;
    pub const CLIENT_NODE_NOT_ADDED: i32 = -24;
    pub const CLIENT_NODE_NOT_CONNECTED: i32 = -29;
    pub const CLIENT_INVALID_IP_OR_SUBNET: i32 = -30;

    // Wallet errors
    pub const WALLET_ERROR: i32 = -4;
    pub const WALLET_INSUFFICIENT_FUNDS: i32 = -6;
    pub const WALLET_INVALID_ACCOUNT_NAME: i32 = -11;
    pub const WALLET_KEYPOOL_RAN_OUT: i32 = -12;
    pub const WALLET_UNLOCK_NEEDED: i32 = -13;
    pub const WALLET_PASSPHRASE_INCORRECT: i32 = -14;
    pub const WALLET_WRONG_ENC_STATE: i32 = -15;
    pub const WALLET_ENCRYPTION_FAILED: i32 = -16;
    pub const WALLET_ALREADY_UNLOCKED: i32 = -17;
}

/// RPC error type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl RpcError {
    /// Create a new RPC error
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Create an error with additional data
    pub fn with_data(code: i32, message: impl Into<String>, data: serde_json::Value) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Standard parse error
    pub fn parse_error() -> Self {
        Self::new(codes::PARSE_ERROR, "Parse error")
    }

    /// Standard invalid request error
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(codes::INVALID_REQUEST, msg)
    }

    /// Standard method not found error
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            codes::METHOD_NOT_FOUND,
            format!("Method not found: {}", method),
        )
    }

    /// Standard invalid params error
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(codes::INVALID_PARAMS, msg)
    }

    /// Standard internal error
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::new(codes::INTERNAL_ERROR, msg)
    }

    /// Block not found error
    pub fn block_not_found(hash: &str) -> Self {
        Self::new(
            codes::INVALID_ADDRESS_OR_KEY,
            format!("Block not found: {}", hash),
        )
    }

    /// Transaction not found error
    pub fn tx_not_found(txid: &str) -> Self {
        Self::new(
            codes::INVALID_ADDRESS_OR_KEY,
            format!("Transaction not found: {}", txid),
        )
    }

    /// Database error
    pub fn database_error(msg: impl Into<String>) -> Self {
        Self::new(codes::DATABASE_ERROR, msg)
    }

    /// Warmup in progress
    pub fn in_warmup(msg: impl Into<String>) -> Self {
        Self::new(codes::IN_WARMUP, msg)
    }
}

/// Error type for RPC operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("RPC error: {0}")]
    Rpc(RpcError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] divi_storage::StorageError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

impl From<RpcError> for Error {
    fn from(e: RpcError) -> Self {
        Error::Rpc(e)
    }
}
