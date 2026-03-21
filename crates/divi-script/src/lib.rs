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

//! Script interpreter for Divi
//!
//! This crate implements the Bitcoin/Divi script virtual machine,
//! a stack-based language used for transaction validation.
//!
//! # Overview
//!
//! Scripts in Divi (derived from Bitcoin) are small programs that define
//! the conditions under which coins can be spent. Each transaction output
//! contains a "locking script" (scriptPubKey), and spending transactions
//! must provide an "unlocking script" (scriptSig) that satisfies those conditions.
//!
//! # Standard Script Types
//!
//! - **P2PKH** (Pay-to-Public-Key-Hash): `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`
//! - **P2SH** (Pay-to-Script-Hash): `OP_HASH160 <scriptHash> OP_EQUAL`
//! - **Multisig**: `<m> <pubkey1>...<pubkeyN> <n> OP_CHECKMULTISIG`
//!
//! # Divi Extensions
//!
//! - **Staking Vault Script**: Uses `OP_REQUIRE_COINSTAKE` to restrict spending to coinstake transactions
//! - **Limit Transfer**: Uses `OP_LIMIT_TRANSFER` for spending restrictions

pub mod asm;
pub mod checker;
pub mod error;
pub mod interpreter;
pub mod opcodes;
pub mod stack;
pub mod standard;
pub mod vault;

pub use asm::{to_asm, Script as AsmScript, ScriptItem, ScriptIterator};
pub use checker::{verify_input, TransactionSignatureChecker};
pub use error::{ScriptError, ScriptFlags, SigHashType};
pub use interpreter::{verify_script, NullChecker, ScriptInterpreter, SignatureChecker};
pub use opcodes::Opcode;
pub use stack::{ScriptNum, Stack};
pub use standard::{
    extract_destination, extract_destinations, extract_script_type, get_script_type_name,
    is_multisig, is_null_data, is_p2pk, is_p2pkh, is_p2sh, Destination, ScriptType,
};
pub use vault::{is_staking_vault_script, StakingVaultScript};
