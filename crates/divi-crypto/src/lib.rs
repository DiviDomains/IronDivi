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

//! Cryptographic primitives for Divi
//!
//! This crate provides hash functions, ECDSA key management, and signature
//! operations compatible with Divi's C++ implementation.

pub mod bip38;
pub mod error;
pub mod genesis;
pub mod hash;
pub mod keys;
pub mod quark;
pub mod signature;

pub use bip38::{decrypt as bip38_decrypt, encrypt as bip38_encrypt};
pub use error::CryptoError;
pub use genesis::{block_hash, compute_merkle_root};
pub use hash::{compute_block_hash, double_sha256, hash160, hash256, ripemd160, sha256};
pub use keys::{KeyPair, PublicKey, SecretKey};
pub use quark::hash_quark;
pub use signature::{
    sign_hash, sign_hash_recoverable, sign_message, sign_recoverable, verify_hash, verify_message,
    RecoverableSig, Signature,
};
