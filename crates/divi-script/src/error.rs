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

//! Script error types

use thiserror::Error;

/// Script execution errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    #[error("script evaluated to false")]
    EvalFalse,

    #[error("OP_RETURN was executed")]
    OpReturn,

    // Size limits
    #[error("script size exceeded limit")]
    ScriptSize,

    #[error("push size exceeded limit")]
    PushSize,

    #[error("opcode count exceeded limit")]
    OpCount,

    #[error("stack size exceeded limit")]
    StackSize,

    #[error("element size exceeded limit")]
    ElementSize,

    // Stack operations
    #[error("invalid stack operation")]
    InvalidStackOperation,

    #[error("invalid altstack operation")]
    InvalidAltstackOperation,

    // Signature/pubkey errors
    #[error("too many signature operations")]
    SigCount,

    #[error("too many public keys")]
    PubkeyCount,

    #[error("invalid public key format")]
    PubkeyType,

    #[error("invalid DER signature encoding")]
    SigDer,

    #[error("scriptSig contains non-push operation")]
    SigPushOnly,

    #[error("invalid signature hash type")]
    SigHashType,

    #[error("signature has high S value")]
    SigHighS,

    #[error("checkmultisig dummy argument not null")]
    SigNullDummy,

    // Verify operations
    #[error("OP_VERIFY failed")]
    Verify,

    #[error("OP_EQUALVERIFY failed")]
    EqualVerify,

    #[error("OP_CHECKSIGVERIFY failed")]
    CheckSigVerify,

    #[error("OP_CHECKMULTISIGVERIFY failed")]
    CheckMultiSigVerify,

    #[error("OP_NUMEQUALVERIFY failed")]
    NumEqualVerify,

    // Logic/format errors
    #[error("invalid opcode")]
    BadOpcode,

    #[error("disabled opcode")]
    DisabledOpcode,

    #[error("unbalanced conditional")]
    UnbalancedConditional,

    #[error("data push not minimal")]
    MinimalData,

    #[error("upgradable NOP instruction")]
    DiscourageUpgradableNops,

    // Policy errors
    #[error("OP_CHECKLOCKTIMEVERIFY failed")]
    CheckLockTimeVerify,

    #[error("OP_CHECKSEQUENCEVERIFY failed")]
    CheckSequenceVerify,

    #[error("OP_LIMIT_TRANSFER constraint violated")]
    LimitTransfer,

    #[error("OP_REQUIRE_COINSTAKE constraint violated")]
    RequireCoinstake,

    #[error("unknown error")]
    Unknown,

    #[error("negative locktime")]
    NegativeLocktime,

    #[error("unsatisfied locktime")]
    UnsatisfiedLocktime,

    #[error("script number overflow")]
    ScriptNumOverflow,

    #[error("invalid signature")]
    InvalidSignature,
}

/// Script verification flags
#[derive(Debug, Clone, Copy, Default)]
pub struct ScriptFlags {
    bits: u32,
}

impl ScriptFlags {
    pub const NONE: u32 = 0;
    pub const P2SH: u32 = 1 << 0;
    pub const STRICTENC: u32 = 1 << 1;
    pub const DERSIG: u32 = 1 << 2;
    pub const LOW_S: u32 = 1 << 3;
    pub const NULLDUMMY: u32 = 1 << 4;
    pub const SIGPUSHONLY: u32 = 1 << 5;
    pub const MINIMALDATA: u32 = 1 << 6;
    pub const DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 7;
    pub const REQUIRE_COINSTAKE: u32 = 1 << 8;
    pub const CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
    pub const LIMIT_TRANSFER: u32 = 1 << 10;
    pub const CHECKSEQUENCEVERIFY: u32 = 1 << 11;

    /// Create flags from raw bits
    pub fn from_bits(bits: u32) -> Self {
        ScriptFlags { bits }
    }

    /// Get raw bits
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Create new empty flags
    pub fn new() -> Self {
        ScriptFlags { bits: 0 }
    }

    /// Standard verification flags for mainnet
    pub fn standard() -> Self {
        ScriptFlags {
            bits: Self::P2SH
                | Self::STRICTENC
                | Self::DERSIG
                | Self::LOW_S
                | Self::NULLDUMMY
                | Self::CHECKLOCKTIMEVERIFY,
        }
    }

    /// Check if a flag is set
    pub fn has(&self, flag: u32) -> bool {
        self.bits & flag != 0
    }

    /// Set a flag
    pub fn set(&mut self, flag: u32) {
        self.bits |= flag;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: u32) {
        self.bits &= !flag;
    }
}

/// Signature hash types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHashType {
    All = 1,
    None = 2,
    Single = 3,
    AnyoneCanPay = 0x80,
}

impl SigHashType {
    /// Parse sighash type from byte
    pub fn from_u8(byte: u8) -> Option<(SigHashType, bool)> {
        let anyone_can_pay = byte & 0x80 != 0;
        let base_type = byte & 0x1f;

        let sighash = match base_type {
            1 => SigHashType::All,
            2 => SigHashType::None,
            3 => SigHashType::Single,
            _ => return None,
        };

        Some((sighash, anyone_can_pay))
    }
}
