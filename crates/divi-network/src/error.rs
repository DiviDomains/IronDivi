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

//! Network error types

use thiserror::Error;

/// Errors that can occur during network operations
#[derive(Debug, Error)]
pub enum NetworkError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid message header
    #[error("invalid message header: {0}")]
    InvalidHeader(String),

    /// Invalid magic bytes
    #[error("invalid magic bytes")]
    InvalidMagic,

    /// Message too large
    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: u32, max: u32 },

    /// Invalid checksum
    #[error("invalid checksum")]
    InvalidChecksum,

    /// Unknown message command
    #[error("unknown command: {0}")]
    UnknownCommand(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// Handshake failed
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Protocol version mismatch
    #[error("protocol version mismatch: peer has {peer}, we require at least {required}")]
    VersionMismatch { peer: i32, required: i32 },

    /// Peer disconnected
    #[error("peer disconnected")]
    Disconnected,

    /// Timeout
    #[error("operation timed out")]
    Timeout,

    /// Peer not found
    #[error("peer not found: {0}")]
    PeerNotFound(u64),

    /// Connection refused (e.g., banned IP)
    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Invalid message content
    #[error("invalid message: {0}")]
    InvalidMessage(String),
}

impl From<divi_primitives::error::Error> for NetworkError {
    fn from(e: divi_primitives::error::Error) -> Self {
        NetworkError::Serialization(e.to_string())
    }
}
