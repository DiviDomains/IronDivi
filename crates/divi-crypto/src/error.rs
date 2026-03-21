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

//! Cryptographic error types

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid message")]
    InvalidMessage,

    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("secp256k1 error: {0}")]
    Secp256k1(String),

    #[error("hex decode error: {0}")]
    HexDecode(String),

    #[error("{0}")]
    Custom(String),
}

impl From<secp256k1::Error> for CryptoError {
    fn from(e: secp256k1::Error) -> Self {
        CryptoError::Secp256k1(e.to_string())
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(e: hex::FromHexError) -> Self {
        CryptoError::HexDecode(e.to_string())
    }
}
