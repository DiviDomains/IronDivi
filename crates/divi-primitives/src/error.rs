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

//! Error types for primitive operations

use thiserror::Error;

/// Errors that can occur during primitive operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid hex string
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Invalid length for fixed-size type
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// Unexpected end of data
    #[error("unexpected end of data")]
    UnexpectedEof,

    /// Non-canonical encoding
    #[error("non-canonical encoding: {0}")]
    NonCanonical(String),

    /// Value out of range
    #[error("value out of range: {0}")]
    OutOfRange(String),

    /// Invalid script
    #[error("invalid script: {0}")]
    InvalidScript(String),

    /// Invalid transaction
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Invalid block
    #[error("invalid block: {0}")]
    InvalidBlock(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::UnexpectedEof
        } else {
            Error::Deserialization(e.to_string())
        }
    }
}
