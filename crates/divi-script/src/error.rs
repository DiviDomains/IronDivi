// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
impl ScriptError {
    /// Divi Core's text for this error (`ScriptErrorString`,
    /// script/script_error.cpp), as used in reject reasons such as
    /// "mandatory-script-verify-flag-failed (...)"
    pub fn core_message(&self) -> &'static str {
        use ScriptError::*;
        match self {
            EvalFalse => {
                "Script evaluated without error but finished with a false/empty top stack element"
            }
            // OP_RETURN is Divi's OP_META
            OpReturn => "OP_META was encountered",
            ScriptSize => "Script is too big",
            PushSize | ElementSize => "Push value size limit exceeded",
            OpCount => "Operation limit exceeded",
            StackSize => "Stack size limit exceeded",
            InvalidStackOperation => "Operation not valid with the current stack size",
            InvalidAltstackOperation => "Operation not valid with the current altstack size",
            SigCount => "Signature count negative or greater than pubkey count",
            PubkeyCount => "Pubkey count negative or limit exceeded",
            PubkeyType => "Public key is neither compressed or uncompressed",
            SigDer => "Non-canonical DER signature",
            SigPushOnly => "Only non-push operators allowed in signatures",
            SigHashType => "Signature hash type missing or not understood",
            SigHighS => "Non-canonical signature: S value is unnecessarily high",
            SigNullDummy => "Dummy CHECKMULTISIG argument must be zero",
            // Core's CoinstakeCheckOp fails with SCRIPT_ERR_VERIFY
            Verify | RequireCoinstake => "Script failed an OP_VERIFY operation",
            EqualVerify => "Script failed an OP_EQUALVERIFY operation",
            CheckSigVerify => "Script failed an OP_CHECKSIGVERIFY operation",
            CheckMultiSigVerify => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            NumEqualVerify => "Script failed an OP_NUMEQUALVERIFY operation",
            BadOpcode => "Opcode missing or not understood",
            DisabledOpcode => "Attempted to use a disabled opcode",
            UnbalancedConditional => "Invalid OP_IF construction",
            MinimalData => "Data push larger than necessary",
            DiscourageUpgradableNops => "NOPx reserved for soft-fork upgrades",
            CheckLockTimeVerify | NegativeLocktime | UnsatisfiedLocktime => {
                "Invalid transaction lock time (BIP65)"
            }
            LimitTransfer => "Invalid transfer limit",
            CheckSequenceVerify | Unknown | ScriptNumOverflow | InvalidSignature => "unknown error",
        }
    }
}

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
                | Self::REQUIRE_COINSTAKE
                | Self::CHECKLOCKTIMEVERIFY,
        }
    }

    /// Divi Core's `MANDATORY_SCRIPT_VERIFY_FLAGS`: what every block input
    /// must pass (script/standard.h). Blocks add CHECKLOCKTIMEVERIFY and
    /// LIMIT_TRANSFER once those forks are active.
    pub fn mandatory() -> Self {
        ScriptFlags {
            bits: Self::P2SH | Self::DERSIG | Self::REQUIRE_COINSTAKE,
        }
    }

    /// Divi Core's `POS_SCRIPT_VERIFY_FLAGS`: the coinstake kernel input's
    /// check in CheckProofOfStake
    pub fn pos() -> Self {
        ScriptFlags {
            bits: Self::mandatory().bits | Self::STRICTENC | Self::MINIMALDATA | Self::NULLDUMMY,
        }
    }

    /// Divi Core's `STANDARD_SCRIPT_VERIFY_FLAGS`: mempool policy. Unlike
    /// [`standard`](Self::standard) it has no LOW_S, as in Core.
    pub fn policy() -> Self {
        ScriptFlags {
            bits: Self::pos().bits
                | Self::CHECKLOCKTIMEVERIFY
                | Self::LIMIT_TRANSFER
                | Self::DISCOURAGE_UPGRADABLE_NOPS,
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
