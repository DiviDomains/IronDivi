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

//! Spork synchronization manager
//!
//! Divi requires spork synchronization before regular block sync can proceed.
//! After the version/verack handshake, the peer sends a `sporkcount` message
//! indicating how many sporks it has. We respond with `getsporks` to request
//! them all, then receive individual `spork` messages.

use crate::message::{InvItem, InvType};
use crate::messages::SporkMessage;
use crate::peer::PeerId;
use crate::peer_manager::PeerManager;
use crate::NetworkMessage;
use divi_consensus::spork_values::SporkEntry;
use divi_crypto::pq::{
    compute_pq_signing_prehash_with_pk_hash, pq_key_hash_256, verify_lms_prehash, LmsPrivateKey,
    PqDomainTag, PqError, PqSchemeId,
};
use divi_primitives::hash::Hash256;
use divi_storage::{ChainDatabase, SharedSporks, StorageError};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::broadcast;

/// Byte length of a legacy `CSporkMessage` v1 compact `secp256k1` signature (`DIP-PQ-2` §2.2).
pub const CLASSICAL_SPORK_SIG_LEN: usize = 65;

/// Byte length of a post-quantum `LMS-SHA256-M32-H10` (`LMOTS-SHA256-N32-W4`) Spork signature (`DIP-PQ-1` §2.1 #4).
pub const PQ_LMS_SPORK_SIG_LEN: usize = 2512;

/// Byte length of a post-quantum `LMS-SHA256-M32-H10` public key (`DIP-PQ-1` §2.1 #4).
pub const PQ_LMS_SPORK_PUBKEY_LEN: usize = 60;

/// Total byte length of a hybrid `CSporkMessage` v2 signature (`65 B` `secp256k1` + `2,512 B` `LMS-SHA256-M32-H10` = `2,577 B`, `DIP-PQ-2` §2.2).
pub const HYBRID_SPORK_SIG_LEN: usize = CLASSICAL_SPORK_SIG_LEN + PQ_LMS_SPORK_SIG_LEN;

/// Domain prefix for `DIP-PQ-2` Spork payload hashing (`"DIVI-SPORK-PAYLOAD-V1"`, 21 bytes, `DIP-PQ-2` §3.1).
pub const SPORK_PQ_PAYLOAD_DOMAIN: &[u8] = b"DIVI-SPORK-PAYLOAD-V1";

/// Three-stage transition and cutoff policy for Spork signature authentication (`DIP-PQ-2` §4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SporkAuthPolicy {
    /// Stage 1 (Legacy / Pre-`DIP-PQ-2`): Verify the 65-byte classical `secp256k1` compact
    /// signature. Accepts either a 65-byte `v1` signature or a 2,577-byte `v2` hybrid signature
    /// whose 65-byte classical prefix is valid and whose 2,512-byte `LMS` suffix is canonically
    /// encoded (`DIP-PQ-2` §4.1 #1).
    #[default]
    ClassicalOnly,

    /// Stage 2 (`DIP-PQ-2` `P2.1` Soft Transition): Pre-cutoff Sporks may carry either a valid
    /// 65-byte classical `v1` signature OR a valid 2,577-byte hybrid `v2` (`secp256k1` +
    /// `LMS-SHA256-M32-H10`) signature verified against `pq_spork_pubkey` and `network_magic`.
    HybridOptional {
        pq_spork_pubkey: [u8; PQ_LMS_SPORK_PUBKEY_LEN],
        network_magic: [u8; 4],
    },

    /// Stage 3 (`DIP-PQ-2` `P2.2` Consensus Cutoff): Sporks with `time_signed < cutoff_time_signed`
    /// follow `HybridOptional` rules, whereas Sporks with `time_signed >= cutoff_time_signed`
    /// strictly require a valid 2,577-byte hybrid `v2` (`secp256k1` + `LMS-SHA256-M32-H10`)
    /// signature (`DIP-PQ-2` §4.1 #3).
    HybridRequiredAfter {
        pq_spork_pubkey: [u8; PQ_LMS_SPORK_PUBKEY_LEN],
        network_magic: [u8; 4],
        cutoff_time_signed: i64,
    },
}

/// Authentication kind established by [`SporkMessage::verify_with_policy`] (`DIP-PQ-2` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SporkAuthKind {
    /// Authenticated by a 65-byte classical `secp256k1` compact signature (`CSporkMessage` v1).
    ClassicalV1,
    /// Authenticated by both a 65-byte classical `secp256k1` compact signature and a 2,512-byte
    /// `LMS-SHA256-M32-H10` post-quantum signature, verified against the policy's
    /// `pq_spork_pubkey`, using one-time leaf index `lms_leaf_q` (`CSporkMessage` v2).
    HybridV2 { lms_leaf_q: u32 },
    /// A `CSporkMessage` v2 accepted under [`SporkAuthPolicy::ClassicalOnly`]: the classical
    /// signature verified, but the `LMS` signature was only checked for canonical framing because
    /// no post-quantum key is configured. `lms_leaf_q` is unauthenticated and the message is not
    /// post-quantum authenticated.
    HybridV2LmsUnverified { lms_leaf_q: u32 },
}

/// Alias for [`SporkAuthKind`] representing the signature status of a Spork message.
pub type SporkSigStatus = SporkAuthKind;

/// Errors returned when signing or verifying a Spork message under `DIP-PQ-2`.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SporkVerifyError {
    #[error("invalid spork signature length: expected 65 (v1) or 2577 (v2), got {0}")]
    InvalidSignatureLength(usize),

    #[error("invalid classical secp256k1 spork signature")]
    InvalidClassicalSignature,

    #[error(
        "classical-only 65-byte spork signature rejected at or after cutoff (time_signed={time_signed} >= cutoff={cutoff_time_signed})"
    )]
    MissingPostQuantumSignatureAfterCutoff {
        time_signed: i64,
        cutoff_time_signed: i64,
    },

    #[error("invalid post-quantum LMS spork signature: {0}")]
    InvalidPostQuantumSignature(#[from] PqError),

    #[error(
        "LMS spork signing is unavailable: this build has no durable, exclusive LMS leaf reservation (DIP-PQ-2 §5.1)"
    )]
    LmsSigningUnavailable,
}

/// Compute the 32-byte `DIP-PQ-2` §3.1 `payload_hash_256` for an integer-valued Spork:
/// `SHA256("DIVI-SPORK-PAYLOAD-V1" || i32_le(spork_id) || i64_le(value) || i64_le(time_signed) || sig_secp256k1[65])`.
pub fn spork_pq_payload_hash_i64(
    spork_id: i32,
    value: i64,
    time_signed: i64,
    sig_secp256k1: &[u8; CLASSICAL_SPORK_SIG_LEN],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SPORK_PQ_PAYLOAD_DOMAIN);
    hasher.update(spork_id.to_le_bytes());
    hasher.update(value.to_le_bytes());
    hasher.update(time_signed.to_le_bytes());
    hasher.update(sig_secp256k1);
    hasher.finalize().into()
}

/// Compute the 32-byte `DIP-PQ-2` §3.1 `payload_hash_256` binding `spork_id`, `value`, `time_signed`,
/// and the 65-byte classical `secp256k1` signature `sig_secp256k1`.
///
/// - When `value` is a canonical base-10 `i64` integer string (`v.to_string() == value`), hashes the
///   exact 106-byte preimage `"DIVI-SPORK-PAYLOAD-V1" || i32_le(spork_id) || i64_le(v) || i64_le(time_signed) || sig_secp256k1[65]`.
/// - When `value` is a multi-value string (e.g. `"5000;100"` for `SPORK_13`–`SPORK_16`), hashes the
///   disjoint `>= 107`-byte preimage `"DIVI-SPORK-PAYLOAD-V1" || i32_le(spork_id) || u64_le(|value|) || 0xff || value || i64_le(time_signed) || sig_secp256k1[65]`.
pub fn spork_pq_payload_hash(
    spork_id: i32,
    value: &str,
    time_signed: i64,
    sig_secp256k1: &[u8; CLASSICAL_SPORK_SIG_LEN],
) -> [u8; 32] {
    if let Ok(v) = value.parse::<i64>() {
        if v.to_string() == value {
            return spork_pq_payload_hash_i64(spork_id, v, time_signed, sig_secp256k1);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(SPORK_PQ_PAYLOAD_DOMAIN);
    hasher.update(spork_id.to_le_bytes());
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update([0xff]);
    hasher.update(value.as_bytes());
    hasher.update(time_signed.to_le_bytes());
    hasher.update(sig_secp256k1);
    hasher.finalize().into()
}

/// Compute the 64-byte (`SHA-512`) domain-separated `DIP-PQ-1` / `DIP-PQ-2` signing prehash for a
/// hybrid Spork v2 message under `PqDomainTag::SporkV1` (`"Divi-PQ-Spork-v1"`) and
/// `PqSchemeId::LmsSha256M32H10` (`0x04`).
pub fn spork_pq_signing_prehash(
    spork_id: i32,
    value: &str,
    time_signed: i64,
    sig_secp256k1: &[u8; CLASSICAL_SPORK_SIG_LEN],
    network_magic: [u8; 4],
    pq_spork_pubkey: &[u8; PQ_LMS_SPORK_PUBKEY_LEN],
) -> [u8; 64] {
    let payload_hash_256 = spork_pq_payload_hash(spork_id, value, time_signed, sig_secp256k1);
    let pk_hash256 = pq_key_hash_256(PqSchemeId::LmsSha256M32H10, pq_spork_pubkey);
    compute_pq_signing_prehash_with_pk_hash(
        PqDomainTag::SporkV1,
        network_magic,
        PqSchemeId::LmsSha256M32H10,
        &pk_hash256,
        &payload_hash_256,
    )
}

/// Sign a hybrid `CSporkMessage` v2 (`65 B` `secp256k1` + `2,512 B` `LMS-SHA256-M32-H10` = `2,577 B`)
/// using the classical Spork secret key and stateful `LMS-SHA256-M32-H10` private key (`DIP-PQ-2` §2–§3).
///
/// Returns [`SporkVerifyError::LmsSigningUnavailable`] before signing anything unless the
/// test-only `lms-volatile-test-signer` feature is enabled: no durable, exclusive leaf
/// reservation exists, so a restarted or restored signer would reuse one-time leaves (§5.1).
pub fn sign_hybrid_spork_lms(
    secret_key: &divi_crypto::SecretKey,
    lms_sk: &mut LmsPrivateKey,
    network_magic: [u8; 4],
    spork_id: i32,
    value: impl Into<String>,
    time_signed: i64,
) -> Result<SporkMessage, SporkVerifyError> {
    #[cfg(feature = "lms-volatile-test-signer")]
    {
        sign_hybrid_spork_lms_volatile(
            secret_key,
            lms_sk,
            network_magic,
            spork_id,
            value,
            time_signed,
        )
    }
    #[cfg(not(feature = "lms-volatile-test-signer"))]
    {
        let _ = (
            secret_key,
            lms_sk,
            network_magic,
            spork_id,
            value,
            time_signed,
        );
        Err(SporkVerifyError::LmsSigningUnavailable)
    }
}

/// [`sign_hybrid_spork_lms`] with the in-memory leaf counter of a test-only signer.
#[cfg(any(test, feature = "lms-volatile-test-signer"))]
fn sign_hybrid_spork_lms_volatile(
    secret_key: &divi_crypto::SecretKey,
    lms_sk: &mut LmsPrivateKey,
    network_magic: [u8; 4],
    spork_id: i32,
    value: impl Into<String>,
    time_signed: i64,
) -> Result<SporkMessage, SporkVerifyError> {
    let value = value.into();
    let message = format!("{spork_id}{value}{time_signed}");
    let classical_sig = divi_masternode::cpp_wire::sign_message(secret_key, message.as_bytes())
        .map_err(|_| SporkVerifyError::InvalidClassicalSignature)?;
    let mut spork = SporkMessage {
        spork_id,
        value,
        time_signed,
        signature: classical_sig,
    };
    spork.attach_lms_signature_volatile(lms_sk, network_magic)?;
    Ok(spork)
}

/// Spork synchronization state per peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SporkSyncState {
    /// Haven't received sporkcount yet
    Pending,
    /// Received sporkcount, waiting for sporks
    Syncing { expected: u32, received: u32 },
    /// All sporks received from this peer
    Synced,
}

/// Spork sync progress event
#[derive(Debug, Clone)]
pub struct SporkSyncProgress {
    /// Number of peers with synced sporks
    pub synced_peers: usize,
    /// Total number of peers
    pub total_peers: usize,
    /// Number of unique sporks received
    pub spork_count: usize,
}

/// Spork synchronization manager
/// Divi Core `strSporkKey` (chainparams.cpp); regtest uses the testnet key
const MAINNET_SPORK_KEY: &str =
    "02c1ed5eadcf6793fa22840febfbd667fabbabc48ddd75c2d228662d65e292eb00";
const TESTNET_SPORK_KEY: &str =
    "034ffa41e5cffdd009f3b34a3e1482ec82b514bb218b7648948b5858cc5c035adb";

/// How long before an inventory item is asked for again (net.cpp `AskFor`)
const ASK_AGAIN_AFTER: Duration = Duration::from_secs(120);

/// Points Divi Core adds for a spork with a bad signature (spork.cpp)
pub const BAD_SPORK_SCORE: u32 = 100;

/// The PrivateDivi Core revision whose `strSporkKey` is pinned here
/// (`divi/src/chainparams.cpp:444`; regtest inherits it, `:458`). It predates the
/// PrivateDivi mainnet relaunch, so it pins testnet and regtest only.
pub const PRIVATEDIVI_REFERENCE_REVISION: &str = "408ad01e929543c7d11586b06fe8d26de8460539";

/// PrivateDivi Core testnet/regtest `strSporkKey` at
/// [`PRIVATEDIVI_REFERENCE_REVISION`]: the same key as Divi testnet
const PRIVATEDIVI_TESTNET_SPORK_KEY: &str =
    "034ffa41e5cffdd009f3b34a3e1482ec82b514bb218b7648948b5858cc5c035adb";

/// Who signs the sporks of a network
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SporkAuthority {
    /// Divi Core's `strSporkKey`. Stored sporks load without a second check, as
    /// Divi Core's `LoadSporksFromDB` loads them.
    Divi(Vec<u8>),
    /// PrivateDivi Core's `strSporkKey`, pinned at
    /// [`PRIVATEDIVI_REFERENCE_REVISION`]. Rows stored by earlier IronDivi
    /// releases were never checked, so each stored spork must verify again
    /// before it loads.
    PrivateDivi(Vec<u8>),
    /// No key is known. Sporks are not accepted, stored, relayed or loaded, and
    /// the peers that relay them are not scored.
    Unmapped,
}

impl SporkAuthority {
    /// The compressed `secp256k1` key that signs sporks, if any
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            SporkAuthority::Divi(key) | SporkAuthority::PrivateDivi(key) => Some(key),
            SporkAuthority::Unmapped => None,
        }
    }

    fn from_key(key: Option<Vec<u8>>) -> Self {
        key.map_or(SporkAuthority::Unmapped, SporkAuthority::Divi)
    }
}

/// The spork authority of a network, by its magic. The PrivateDivi mainnet is
/// `Unmapped`: its key after the relaunch has not been confirmed.
pub fn spork_authority(magic: &crate::constants::Magic) -> SporkAuthority {
    use crate::constants::{
        MAINNET_MAGIC, PRIVATEDIVI_REGTEST_MAGIC, PRIVATEDIVI_TESTNET_MAGIC, REGTEST_MAGIC,
        TESTNET_MAGIC,
    };
    let decode = |key: &str| hex::decode(key).ok();
    let authority = if magic == &MAINNET_MAGIC {
        decode(MAINNET_SPORK_KEY).map(SporkAuthority::Divi)
    } else if magic == &TESTNET_MAGIC || magic == &REGTEST_MAGIC {
        decode(TESTNET_SPORK_KEY).map(SporkAuthority::Divi)
    } else if magic == &PRIVATEDIVI_TESTNET_MAGIC || magic == &PRIVATEDIVI_REGTEST_MAGIC {
        decode(PRIVATEDIVI_TESTNET_SPORK_KEY).map(SporkAuthority::PrivateDivi)
    } else {
        None
    };
    authority.unwrap_or(SporkAuthority::Unmapped)
}

/// The spork key of a network, by its magic (None where no authority is mapped)
pub fn spork_key(magic: &crate::constants::Magic) -> Option<Vec<u8>> {
    spork_authority(magic).key().map(<[u8]>::to_vec)
}

/// The environment variable an operator sets to the fingerprint of a
/// [`SporkStoreHold`] to start the node anyway (see `docs/spork-authority.md`)
pub const SPORK_HOLD_ACK_ENV: &str = "IRONDIVI_SPORK_HOLD_ACK";

/// Why a stored spork was not loaded
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineReason {
    /// The network has no mapped spork authority
    NoAuthority,
    /// The spork does not verify against the network's authority
    InvalidSignature(SporkVerifyError),
    /// The row does not decode to a spork, or does not re-encode to the same
    /// bytes, so what it held cannot be checked
    Undecodable(String),
    /// The row `spork_<id>` holds a spork of another id
    IdMismatch { decoded_id: i32 },
}

impl std::fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineReason::NoAuthority => write!(f, "no spork authority is mapped"),
            QuarantineReason::InvalidSignature(err) => write!(f, "{err}"),
            QuarantineReason::Undecodable(err) => write!(f, "row does not decode: {err}"),
            QuarantineReason::IdMismatch { decoded_id } => {
                write!(f, "row holds a spork of id {decoded_id}")
            }
        }
    }
}

/// The fields of a stored row that decodes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSpork {
    pub spork_id: i32,
    pub value: String,
    pub time_signed: i64,
    pub signature_len: usize,
}

/// A stored spork that was not loaded. Its database row is left as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedSpork {
    /// The id of the row, `spork_<id>`
    pub spork_id: i32,
    /// What the row decodes to (None: it does not decode)
    pub decoded: Option<StoredSpork>,
    pub reason: QuarantineReason,
    /// The row as stored, byte for byte
    pub raw: Vec<u8>,
}

/// A stored spork row that could not be read at start: its content is unknown
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableSpork {
    pub spork_id: i32,
    pub error: String,
}

/// Raised at startup when stored sporks cannot be authenticated on a network
/// with no spork authority. Starting with defaults would change the active
/// values, and loading the rows would accept values nobody can verify. The
/// node stops instead, until an operator acknowledges [`Self::fingerprint`] or
/// rolls back (see `docs/spork-authority.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkStoreHold {
    pub quarantined: Vec<QuarantinedSpork>,
    /// SHA-256 of the held rows (id, then raw bytes, in id order), hex
    pub fingerprint: String,
}

impl SporkStoreHold {
    fn new(quarantined: Vec<QuarantinedSpork>) -> Self {
        let mut hasher = Sha256::new();
        for spork in &quarantined {
            hasher.update(spork.spork_id.to_le_bytes());
            hasher.update((spork.raw.len() as u64).to_le_bytes());
            hasher.update(&spork.raw);
        }
        let fingerprint = hex::encode(hasher.finalize());
        SporkStoreHold {
            quarantined,
            fingerprint,
        }
    }
}

impl std::fmt::Display for SporkStoreHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "spork store hold: {} stored spork(s) cannot be authenticated because this network has no mapped spork authority",
            self.quarantined.len()
        )?;
        for spork in &self.quarantined {
            match &spork.decoded {
                Some(d) => writeln!(
                    f,
                    "  spork_{} id={} value={:?} time_signed={} signature={} bytes ({})",
                    spork.spork_id,
                    d.spork_id,
                    d.value,
                    d.time_signed,
                    d.signature_len,
                    spork.reason
                )?,
                None => writeln!(
                    f,
                    "  spork_{} {} bytes ({})",
                    spork.spork_id,
                    spork.raw.len(),
                    spork.reason
                )?,
            }
        }
        writeln!(f, "  fingerprint: {}", self.fingerprint)?;
        write!(
            f,
            "  The rows were not loaded and are unchanged. To start with default spork values, set {}={}; to keep the previous behaviour, roll back the binary. See docs/spork-authority.md.",
            SPORK_HOLD_ACK_ENV, self.fingerprint
        )
    }
}

impl std::error::Error for SporkStoreHold {}

/// Why [`SporkManager::try_with_chain`] refused to start
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SporkStartError {
    /// Stored rows could not be read on a network whose stored sporks must be
    /// checked. Their content is unknown, so no acknowledgement releases this.
    Unreadable(Vec<UnreadableSpork>),
    /// Stored rows are held; [`SPORK_HOLD_ACK_ENV`] can release them
    Held(SporkStoreHold),
}

impl std::fmt::Display for SporkStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SporkStartError::Held(hold) => std::fmt::Display::fmt(hold, f),
            SporkStartError::Unreadable(rows) => {
                writeln!(
                    f,
                    "spork store unreadable: {} stored spork row(s) could not be read, so they cannot be checked",
                    rows.len()
                )?;
                for row in rows {
                    writeln!(f, "  spork_{}: {}", row.spork_id, row.error)?;
                }
                write!(
                    f,
                    "  Their content is unknown; {} does not release this. Repair or restore the chain database, or roll back the binary. See docs/spork-authority.md.",
                    SPORK_HOLD_ACK_ENV
                )
            }
        }
    }
}

impl std::error::Error for SporkStartError {}

/// The ids Divi Core loads at start: those from `SPORK_START` to `SPORK_END`
/// (spork.h) that have a name (spork.cpp:196-197, `GetSporkNameByID`). It stores
/// a spork of any id it is sent, but loads only these.
const SPORK_IDS: [i32; 11] = {
    use crate::messages::spork_ids::*;
    [
        SPORK_2_SWIFTTX_ENABLED,
        SPORK_3_SWIFTTX_BLOCK_FILTERING,
        SPORK_5_INSTANTSEND_MAX_VALUE,
        SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT,
        SPORK_9_SUPERBLOCKS_ENABLED,
        SPORK_10_MASTERNODE_PAY_UPDATED_NODES,
        SPORK_12_RECONSIDER_BLOCKS,
        SPORK_13_BLOCK_PAYMENTS,
        SPORK_14_TX_FEE,
        SPORK_15_BLOCK_VALUE,
        SPORK_16_LOTTERY_TICKET_MIN_VALUE,
    ]
};

/// Where a spork id is kept in the chain database's metadata
fn db_key(spork_id: i32) -> Vec<u8> {
    format!("spork_{spork_id}").into_bytes()
}

/// PrivateDivi Core `CSporkMessage::CheckSignature` at
/// [`PRIVATEDIVI_REFERENCE_REVISION`]: a 65-byte compact signature only, as
/// PrivateDivi has no `HybridSporkV2` fork. The manager's [`SporkAuthPolicy`]
/// does not apply.
fn verify_privatedivi(spork: &SporkMessage, key: &[u8]) -> Result<SporkAuthKind, SporkVerifyError> {
    if spork.signature.len() != CLASSICAL_SPORK_SIG_LEN {
        return Err(SporkVerifyError::InvalidSignatureLength(
            spork.signature.len(),
        ));
    }
    spork.verify_with_policy(key, &SporkAuthPolicy::ClassicalOnly)
}

/// Where a quarantined row of a spork id is copied before it is replaced
fn quarantine_db_key(spork_id: i32) -> Vec<u8> {
    format!("spork_quarantine_{spork_id}").into_bytes()
}

/// Divi Core `IsMultiValueSpork`: sporks 13 to 16 keep a list of values
fn is_multi_value(spork_id: i32) -> bool {
    use crate::messages::spork_ids::*;
    matches!(
        spork_id,
        SPORK_13_BLOCK_PAYMENTS
            | SPORK_14_TX_FEE
            | SPORK_15_BLOCK_VALUE
            | SPORK_16_LOTTERY_TICKET_MIN_VALUE
    )
}

impl SporkMessage {
    /// Return the 65-byte classical `secp256k1` compact signature prefix if `self.signature` has
    /// canonical `v1` (`65 B`) or `v2` (`2,577 B`) length (`DIP-PQ-2` §2.2).
    pub fn classical_signature(&self) -> Option<&[u8; CLASSICAL_SPORK_SIG_LEN]> {
        if self.signature.len() != CLASSICAL_SPORK_SIG_LEN
            && self.signature.len() != HYBRID_SPORK_SIG_LEN
        {
            return None;
        }
        self.signature[..CLASSICAL_SPORK_SIG_LEN].try_into().ok()
    }

    /// Return the 2,512-byte `LMS-SHA256-M32-H10` post-quantum signature suffix if `self.signature`
    /// is a hybrid `v2` (`2,577 B`) signature (`DIP-PQ-2` §2.2).
    pub fn lms_signature(&self) -> Option<&[u8; PQ_LMS_SPORK_SIG_LEN]> {
        if self.signature.len() != HYBRID_SPORK_SIG_LEN {
            return None;
        }
        self.signature[CLASSICAL_SPORK_SIG_LEN..HYBRID_SPORK_SIG_LEN]
            .try_into()
            .ok()
    }

    /// Return `true` if this Spork carries a 2,577-byte hybrid `v2` (`secp256k1 + LMS`) signature.
    pub fn is_hybrid_v2(&self) -> bool {
        self.signature.len() == HYBRID_SPORK_SIG_LEN
    }

    /// Extract the big-endian `LMS` leaf index $q \in [0, 1023]$ from a hybrid `v2` Spork signature.
    pub fn lms_leaf_index(&self) -> Option<u32> {
        let lms_sig = self.lms_signature()?;
        Some(u32::from_be_bytes([
            lms_sig[0], lms_sig[1], lms_sig[2], lms_sig[3],
        ]))
    }

    /// Attach a 2,512-byte `LMS-SHA256-M32-H10` signature to a `SporkMessage` that already carries
    /// a 65-byte classical `secp256k1` signature, upgrading `self.signature` in-place to the
    /// 2,577-byte `DIP-PQ-2` hybrid `v2` layout (`sig_secp256k1[65] || sig_lms_m32_h10[2512]`).
    ///
    /// Without the test-only `lms-volatile-test-signer` feature this returns
    /// [`SporkVerifyError::LmsSigningUnavailable`] and leaves `self` and `lms_sk` unchanged
    /// (see [`sign_hybrid_spork_lms`]).
    pub fn attach_lms_signature(
        &mut self,
        lms_sk: &mut LmsPrivateKey,
        network_magic: [u8; 4],
    ) -> Result<[u8; PQ_LMS_SPORK_SIG_LEN], SporkVerifyError> {
        #[cfg(feature = "lms-volatile-test-signer")]
        {
            self.attach_lms_signature_volatile(lms_sk, network_magic)
        }
        #[cfg(not(feature = "lms-volatile-test-signer"))]
        {
            let _ = (lms_sk, network_magic);
            Err(SporkVerifyError::LmsSigningUnavailable)
        }
    }

    #[cfg(any(test, feature = "lms-volatile-test-signer"))]
    fn attach_lms_signature_volatile(
        &mut self,
        lms_sk: &mut LmsPrivateKey,
        network_magic: [u8; 4],
    ) -> Result<[u8; PQ_LMS_SPORK_SIG_LEN], SporkVerifyError> {
        let sig_secp256k1 =
            *self
                .classical_signature()
                .ok_or(SporkVerifyError::InvalidSignatureLength(
                    self.signature.len(),
                ))?;
        let prehash = spork_pq_signing_prehash(
            self.spork_id,
            &self.value,
            self.time_signed,
            &sig_secp256k1,
            network_magic,
            lms_sk.public_key_bytes(),
        );
        let lms_sig = lms_sk.sign_prehash(&prehash)?;
        let mut combined = Vec::with_capacity(HYBRID_SPORK_SIG_LEN);
        combined.extend_from_slice(&sig_secp256k1);
        combined.extend_from_slice(&lms_sig);
        self.signature = combined;
        Ok(lms_sig)
    }

    /// Verify this Spork message against `classical_key` (`33 B` compressed `secp256k1` `strSporkKey`)
    /// and the active [`SporkAuthPolicy`] (`DIP-PQ-2` §2–§4).
    pub fn verify_with_policy(
        &self,
        classical_key: &[u8],
        policy: &SporkAuthPolicy,
    ) -> Result<SporkAuthKind, SporkVerifyError> {
        let sig_len = self.signature.len();
        if sig_len != CLASSICAL_SPORK_SIG_LEN && sig_len != HYBRID_SPORK_SIG_LEN {
            return Err(SporkVerifyError::InvalidSignatureLength(sig_len));
        }

        let sig_secp256k1: &[u8; CLASSICAL_SPORK_SIG_LEN] = self.signature
            [..CLASSICAL_SPORK_SIG_LEN]
            .try_into()
            .map_err(|_| SporkVerifyError::InvalidSignatureLength(sig_len))?;

        let message = format!("{}{}{}", self.spork_id, self.value, self.time_signed);
        // C++ CSporkMessage::CheckSignature -> CObfuScationSigner::VerifyMessage
        // (spork.cpp:522-533, obfuscation.cpp:59-74) accepts any 65-byte header
        // (RecoverCompact masks the byte) and compares CKeyIDs. The compression
        // flag is enforced inside `verify_message` via Hash160, so a spork
        // re-headed from 31+r to 39+r stays valid for both clients and an honest
        // relaying peer is no longer scored (S11). Do NOT re-add a header-range
        // pre-guard here: it would reject re-headed sporks that C++ accepts.
        let classical_ok = divi_masternode::cpp_wire::verify_message(
            classical_key,
            sig_secp256k1,
            message.as_bytes(),
        );
        if !classical_ok {
            return Err(SporkVerifyError::InvalidClassicalSignature);
        }

        if sig_len == CLASSICAL_SPORK_SIG_LEN {
            match policy {
                SporkAuthPolicy::ClassicalOnly | SporkAuthPolicy::HybridOptional { .. } => {
                    return Ok(SporkAuthKind::ClassicalV1);
                }
                SporkAuthPolicy::HybridRequiredAfter {
                    cutoff_time_signed, ..
                } => {
                    if self.time_signed >= *cutoff_time_signed {
                        return Err(SporkVerifyError::MissingPostQuantumSignatureAfterCutoff {
                            time_signed: self.time_signed,
                            cutoff_time_signed: *cutoff_time_signed,
                        });
                    }
                    return Ok(SporkAuthKind::ClassicalV1);
                }
            }
        }

        let lms_sig = &self.signature[CLASSICAL_SPORK_SIG_LEN..HYBRID_SPORK_SIG_LEN];
        match policy {
            SporkAuthPolicy::ClassicalOnly => {
                PqSchemeId::LmsSha256M32H10.validate_signature_encoding(lms_sig)?;
                let lms_leaf_q =
                    u32::from_be_bytes([lms_sig[0], lms_sig[1], lms_sig[2], lms_sig[3]]);
                Ok(SporkAuthKind::HybridV2LmsUnverified { lms_leaf_q })
            }
            SporkAuthPolicy::HybridOptional {
                pq_spork_pubkey,
                network_magic,
            }
            | SporkAuthPolicy::HybridRequiredAfter {
                pq_spork_pubkey,
                network_magic,
                ..
            } => {
                let prehash = spork_pq_signing_prehash(
                    self.spork_id,
                    &self.value,
                    self.time_signed,
                    sig_secp256k1,
                    *network_magic,
                    pq_spork_pubkey,
                );
                verify_lms_prehash(pq_spork_pubkey, &prehash, lms_sig)?;
                let lms_leaf_q =
                    u32::from_be_bytes([lms_sig[0], lms_sig[1], lms_sig[2], lms_sig[3]]);
                Ok(SporkAuthKind::HybridV2 { lms_leaf_q })
            }
        }
    }

    /// Divi Core `CSporkMessage::CheckSignature`: checks a `65 B` compact `v1` signature or a
    /// `2,577 B` hybrid `v2` signature against the compressed `secp256k1` spork key (plus
    /// canonical `LMS` framing when `2,577 B` is present).
    pub fn signature_is_valid(&self, key: &[u8]) -> bool {
        self.verify_with_policy(key, &SporkAuthPolicy::ClassicalOnly)
            .is_ok()
    }
}

pub struct SporkManager {
    /// Peer manager for sending messages
    peer_manager: Arc<PeerManager>,

    /// Who signs sporks on this network
    authority: SporkAuthority,

    /// Stored sporks that were not loaded at start; their rows are kept
    quarantined: Vec<QuarantinedSpork>,

    /// Stored rows that could not be read at start (networks whose stored
    /// sporks must be checked only)
    unreadable: Vec<UnreadableSpork>,

    /// Active `DIP-PQ-2` signature authentication and cutoff policy
    auth_policy: RwLock<SporkAuthPolicy>,

    /// Highest `LMS` leaf index $q$ across accepted Sporks whose `LMS` signature verified (`DIP-PQ-2` §5.2)
    last_lms_leaf_q: RwLock<Option<u32>>,

    /// Last verified `LMS` leaf index $q$ per `spork_id` (`DIP-PQ-2` §5.2)
    spork_lms_leaf_q: RwLock<HashMap<i32, u32>>,

    /// Observed `(lms_leaf_q -> spork_hash)` map to detect one-time leaf reuse on distinct messages
    observed_lms_leaves: RwLock<HashMap<u32, Hash256>>,

    /// Sync state per peer
    peer_states: RwLock<HashMap<PeerId, SporkSyncState>>,

    /// Received sporks (keyed by hash)
    sporks: RwLock<HashMap<Hash256, SporkMessage>>,

    /// Active sporks by ID, as Divi Core's `mapSporksActive` (a `std::map`, so
    /// in ID order): the newest one for a single-value spork, every signed
    /// entry in time order for a multi-value spork
    active_sporks: RwLock<BTreeMap<i32, Vec<SporkMessage>>>,

    /// Keeps the last spork added per id across restarts (Core's spork
    /// database); None keeps sporks in memory only
    db: Option<Arc<ChainDatabase>>,

    /// Where the entries of sporks 13 to 16 are kept for the chain, which reads
    /// them to value and pay blocks
    consensus: SharedSporks,

    /// Called when a spork 14 entry arrives (Divi Core `ExecuteSpork`,
    /// spork.cpp:256, :278-302); not at start, as it does not load sporks that way
    fee_listeners: RwLock<Vec<Arc<dyn Fn() + Send + Sync>>>,

    /// When each spork inventory item was asked for, so it is asked for once
    /// (Divi Core `AskFor` waits two minutes before asking again)
    asked: Mutex<HashMap<Hash256, Instant>>,

    /// Progress event broadcaster
    progress_tx: broadcast::Sender<SporkSyncProgress>,
}

impl SporkManager {
    /// Create a new spork manager that keeps sporks in memory only
    pub fn new(peer_manager: Arc<PeerManager>) -> Arc<Self> {
        let authority = spork_authority(&peer_manager.magic());
        Self::with_authority(peer_manager, authority, None, Default::default())
    }

    /// Create a spork manager that keeps sporks in `db` and loads the ones a
    /// previous run stored (Divi Core `LoadSporksFromDB`)
    pub fn with_db(peer_manager: Arc<PeerManager>, db: Arc<ChainDatabase>) -> Arc<Self> {
        let authority = spork_authority(&peer_manager.magic());
        Self::with_authority(peer_manager, authority, Some(db), Default::default())
    }

    /// [`SporkManager::with_db`], keeping the entries of sporks 13 to 16 in
    /// `consensus` (the chain's), loaded ones included. Unreadable rows and a
    /// [`SporkStoreHold`] are logged, not enforced;
    /// [`SporkManager::try_with_chain`] enforces them.
    pub fn with_chain(
        peer_manager: Arc<PeerManager>,
        db: Arc<ChainDatabase>,
        consensus: SharedSporks,
    ) -> Arc<Self> {
        let authority = spork_authority(&peer_manager.magic());
        Self::with_authority(peer_manager, authority, Some(db), consensus)
    }

    /// [`SporkManager::with_chain`], refusing to start while stored rows
    /// could not be read (no acknowledgement releases that) or while stored
    /// sporks are held ([`SporkManager::store_hold`]) unless `hold_ack` is the
    /// hold's fingerprint. Nothing held is loaded either way, and no row is
    /// changed.
    pub fn try_with_chain(
        peer_manager: Arc<PeerManager>,
        db: Arc<ChainDatabase>,
        consensus: SharedSporks,
        hold_ack: Option<&str>,
    ) -> Result<Arc<Self>, SporkStartError> {
        let manager = Self::with_chain(peer_manager, db, consensus);
        manager.check_start(hold_ack)?;
        Ok(manager)
    }

    /// The startup check of [`SporkManager::try_with_chain`]
    fn check_start(&self, hold_ack: Option<&str>) -> Result<(), SporkStartError> {
        if !self.unreadable.is_empty() {
            return Err(SporkStartError::Unreadable(self.unreadable.clone()));
        }
        match self.store_hold() {
            Some(hold) if hold_ack != Some(hold.fingerprint.as_str()) => {
                Err(SporkStartError::Held(hold))
            }
            Some(hold) => {
                tracing::warn!(
                    "Spork store hold {} acknowledged by the operator: starting with default spork values; the held rows stay in the database",
                    hold.fingerprint
                );
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Create a spork manager that checks sporks against `spork_key` as Divi
    /// Core does (None: no authority, so sporks are refused), optionally kept
    /// in `db`
    pub fn with_key(
        peer_manager: Arc<PeerManager>,
        spork_key: Option<Vec<u8>>,
        db: Option<Arc<ChainDatabase>>,
    ) -> Arc<Self> {
        Self::build(
            peer_manager,
            SporkAuthority::from_key(spork_key),
            SporkAuthPolicy::ClassicalOnly,
            db,
            Default::default(),
        )
    }

    /// Create a spork manager for an explicit [`SporkAuthority`]
    pub fn with_authority(
        peer_manager: Arc<PeerManager>,
        authority: SporkAuthority,
        db: Option<Arc<ChainDatabase>>,
        consensus: SharedSporks,
    ) -> Arc<Self> {
        Self::build(
            peer_manager,
            authority,
            SporkAuthPolicy::ClassicalOnly,
            db,
            consensus,
        )
    }

    /// Create a spork manager with an explicit `DIP-PQ-2` [`SporkAuthPolicy`].
    pub fn with_key_and_policy(
        peer_manager: Arc<PeerManager>,
        spork_key: Option<Vec<u8>>,
        auth_policy: SporkAuthPolicy,
        db: Option<Arc<ChainDatabase>>,
    ) -> Arc<Self> {
        Self::build(
            peer_manager,
            SporkAuthority::from_key(spork_key),
            auth_policy,
            db,
            Default::default(),
        )
    }

    /// [`SporkManager::with_key`] keeping sporks 13 to 16 in `consensus`
    pub fn with_key_and_chain(
        peer_manager: Arc<PeerManager>,
        spork_key: Option<Vec<u8>>,
        db: Option<Arc<ChainDatabase>>,
        consensus: SharedSporks,
    ) -> Arc<Self> {
        Self::build(
            peer_manager,
            SporkAuthority::from_key(spork_key),
            SporkAuthPolicy::ClassicalOnly,
            db,
            consensus,
        )
    }

    fn build(
        peer_manager: Arc<PeerManager>,
        authority: SporkAuthority,
        auth_policy: SporkAuthPolicy,
        db: Option<Arc<ChainDatabase>>,
        consensus: SharedSporks,
    ) -> Arc<Self> {
        let (progress_tx, _) = broadcast::channel(16);
        let mut manager = SporkManager {
            authority,
            quarantined: Vec::new(),
            unreadable: Vec::new(),
            auth_policy: RwLock::new(auth_policy),
            last_lms_leaf_q: RwLock::new(None),
            spork_lms_leaf_q: RwLock::new(HashMap::new()),
            observed_lms_leaves: RwLock::new(HashMap::new()),
            peer_manager,
            peer_states: RwLock::new(HashMap::new()),
            sporks: RwLock::new(HashMap::new()),
            active_sporks: RwLock::new(BTreeMap::new()),
            db,
            consensus,
            fee_listeners: RwLock::new(Vec::new()),
            asked: Mutex::new(HashMap::new()),
            progress_tx,
        };
        let rows: Vec<_> = match &manager.db {
            Some(db) => SPORK_IDS
                .iter()
                .map(|&id| (id, db.get_metadata(&db_key(id))))
                .collect(),
            None => Vec::new(),
        };
        manager.load_rows(rows);
        if !manager.unreadable.is_empty() {
            tracing::error!(
                "{}",
                SporkStartError::Unreadable(manager.unreadable.clone())
            );
        }
        if let Some(hold) = manager.store_hold() {
            tracing::error!("{}", hold);
        }
        Arc::new(manager)
    }

    /// Who signs sporks on this network
    pub fn authority(&self) -> &SporkAuthority {
        &self.authority
    }

    /// The stored sporks that were not loaded at start
    pub fn quarantined(&self) -> &[QuarantinedSpork] {
        &self.quarantined
    }

    /// The startup hold: stored sporks on a network with no spork authority.
    /// On a network with an authority, stored sporks that fail to verify are
    /// quarantined without a hold, as verified ones replace them from peers.
    pub fn store_hold(&self) -> Option<SporkStoreHold> {
        if self.authority != SporkAuthority::Unmapped || self.quarantined.is_empty() {
            return None;
        }
        Some(SporkStoreHold::new(self.quarantined.clone()))
    }

    /// Update the active `DIP-PQ-2` [`SporkAuthPolicy`].
    pub fn set_auth_policy(&self, policy: SporkAuthPolicy) {
        *self.auth_policy.write() = policy;
    }

    /// Return a clone of the active `DIP-PQ-2` [`SporkAuthPolicy`].
    pub fn auth_policy(&self) -> SporkAuthPolicy {
        self.auth_policy.read().clone()
    }

    /// Return the highest verified `LMS` leaf index $q$ observed across accepted `HybridV2` Sporks.
    pub fn last_lms_leaf_index(&self) -> Option<u32> {
        *self.last_lms_leaf_q.read()
    }

    /// Return the last verified `LMS` leaf index $q$ for a specific `spork_id`.
    pub fn spork_lms_leaf_index(&self, spork_id: i32) -> Option<u32> {
        self.spork_lms_leaf_q.read().get(&spork_id).copied()
    }

    /// The `LMS` leaf of a stored spork, if its `LMS` signature verifies under the active
    /// policy. Stored Divi rows load without a second check, so framing alone is not enough to
    /// track a leaf.
    fn verified_lms_leaf(&self, spork: &SporkMessage) -> Option<u32> {
        let SporkAuthority::Divi(key) = &self.authority else {
            return None;
        };
        if !spork.is_hybrid_v2() {
            return None;
        }
        match spork.verify_with_policy(key, &self.auth_policy.read()) {
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q }) => Some(lms_leaf_q),
            _ => None,
        }
    }

    fn record_lms_leaf(&self, spork_id: i32, hash: Hash256, lms_leaf_q: u32) {
        if let Some(prev_hash) = self.observed_lms_leaves.write().insert(lms_leaf_q, hash) {
            if prev_hash != hash {
                tracing::warn!(
                    "DIP-PQ-2 LMS one-time leaf q={} reused across distinct spork messages ({} vs {})",
                    lms_leaf_q,
                    prev_hash,
                    hash
                );
            }
        }
        {
            let mut per_spork = self.spork_lms_leaf_q.write();
            if let Some(&prev_q) = per_spork.get(&spork_id) {
                if lms_leaf_q <= prev_q {
                    tracing::warn!(
                        "DIP-PQ-2 LMS leaf index non-monotonic for spork {}: new q={} <= previous q={}",
                        spork_id,
                        lms_leaf_q,
                        prev_q
                    );
                }
            }
            per_spork.insert(spork_id, lms_leaf_q);
        }
        let mut last_q = self.last_lms_leaf_q.write();
        *last_q = Some(last_q.map_or(lms_leaf_q, |prev| prev.max(lms_leaf_q)));
    }

    /// Divi Core `LoadSporksFromDB`: one stored spork per known id, from the
    /// result of reading `spork_<id>`. On a Divi network a row loads as Divi
    /// Core loads it, and a row that cannot be read or decoded is skipped.
    /// Elsewhere [`SporkManager::stored_refusal`] decides: a refused row is
    /// quarantined instead of loaded and left as it is, and a row that cannot
    /// be read is recorded as unreadable, never as absent.
    fn load_rows(&mut self, rows: Vec<(i32, Result<Option<Vec<u8>>, StorageError>)>) {
        let checked = !matches!(self.authority, SporkAuthority::Divi(_));
        for (id, read) in rows {
            let bytes = match read {
                Ok(Some(bytes)) => bytes,
                Ok(None) => continue,
                Err(e) if checked => {
                    tracing::error!("Could not read spork {} from the database: {}", id, e);
                    self.unreadable.push(UnreadableSpork {
                        spork_id: id,
                        error: e.to_string(),
                    });
                    continue;
                }
                Err(e) => {
                    tracing::warn!("Could not read spork {} from the database: {}", id, e);
                    continue;
                }
            };
            let decoded = SporkMessage::deserialize(&bytes);
            if !checked {
                match decoded {
                    Ok(spork) => self.load_one(spork),
                    Err(e) => tracing::warn!("Stored spork {} does not decode: {}", id, e),
                }
                continue;
            }
            let spork = match decoded {
                Ok(spork) => spork,
                Err(e) => {
                    self.quarantine(
                        id,
                        None,
                        QuarantineReason::Undecodable(e.to_string()),
                        bytes,
                    );
                    continue;
                }
            };
            match self.stored_refusal(id, &bytes, &spork) {
                None => self.load_one(spork),
                Some(reason) => self.quarantine(id, Some(spork), reason, bytes),
            }
        }
    }

    fn quarantine(
        &mut self,
        id: i32,
        spork: Option<SporkMessage>,
        reason: QuarantineReason,
        raw: Vec<u8>,
    ) {
        let decoded = spork.map(|spork| StoredSpork {
            spork_id: spork.spork_id,
            signature_len: spork.signature.len(),
            value: spork.value,
            time_signed: spork.time_signed,
        });
        tracing::error!(
            "Stored spork {} ({:?}) not loaded: {}; its database row is kept",
            id,
            decoded,
            reason
        );
        self.quarantined.push(QuarantinedSpork {
            spork_id: id,
            decoded,
            reason,
            raw,
        });
    }

    fn load_one(&self, spork: SporkMessage) {
        tracing::debug!("Loaded spork {} with value {}", spork.spork_id, spork.value);
        let hash = spork.hash();
        if let Some(lms_leaf_q) = self.verified_lms_leaf(&spork) {
            self.record_lms_leaf(spork.spork_id, hash, lms_leaf_q);
        }
        self.sporks.write().insert(hash, spork.clone());
        self.add_active(spork);
    }

    /// Why a stored spork in row `spork_<id>` may not load, if it may not.
    /// Divi rows load as Divi Core loads them; PrivateDivi rows must be
    /// canonical, of their row's id, and verify again; with no authority
    /// nothing loads.
    fn stored_refusal(
        &self,
        id: i32,
        raw: &[u8],
        spork: &SporkMessage,
    ) -> Option<QuarantineReason> {
        let key = match &self.authority {
            SporkAuthority::Divi(_) => return None,
            SporkAuthority::PrivateDivi(key) => Some(key),
            SporkAuthority::Unmapped => None,
        };
        if spork.serialize() != raw {
            return Some(QuarantineReason::Undecodable(
                "trailing or non-canonical bytes".into(),
            ));
        }
        if spork.spork_id != id {
            return Some(QuarantineReason::IdMismatch {
                decoded_id: spork.spork_id,
            });
        }
        let Some(key) = key else {
            return Some(QuarantineReason::NoAuthority);
        };
        verify_privatedivi(spork, key)
            .err()
            .map(QuarantineReason::InvalidSignature)
    }

    /// Copy a quarantined row of `spork_id` to its quarantine key before a
    /// verified spork replaces it, so no operator data is lost. False when the
    /// copy could not be made, in which case the row must not be replaced.
    fn preserve_quarantined(&self, db: &ChainDatabase, spork_id: i32) -> bool {
        if self.unreadable.iter().any(|u| u.spork_id == spork_id) {
            tracing::error!(
                "Spork {} row could not be read at start; the row is not replaced",
                spork_id
            );
            return false;
        }
        let Some(held) = self.quarantined.iter().find(|q| q.spork_id == spork_id) else {
            return true;
        };
        let key = quarantine_db_key(spork_id);
        match db.get_metadata(&key) {
            Ok(Some(kept)) if kept == held.raw => true,
            Ok(Some(_)) => {
                tracing::error!(
                    "{} already holds other bytes than the quarantined spork {} row; neither is replaced",
                    String::from_utf8_lossy(&key),
                    spork_id
                );
                false
            }
            Ok(None) => match db.put_metadata(&key, &held.raw) {
                Ok(()) => {
                    tracing::warn!(
                        "Quarantined spork {} row copied to {} before a verified spork replaces it",
                        spork_id,
                        String::from_utf8_lossy(&key)
                    );
                    true
                }
                Err(e) => {
                    tracing::error!(
                        "Could not keep quarantined spork {} row: {}; the row is not replaced",
                        spork_id,
                        e
                    );
                    false
                }
            },
            Err(e) => {
                tracing::error!(
                    "Could not read quarantine key of spork {}: {}; the row is not replaced",
                    spork_id,
                    e
                );
                false
            }
        }
    }

    /// Divi Core `AddActiveSpork`: a multi-value spork joins its list unless
    /// that entry is already held; any other spork replaces the active one.
    /// True when the spork was added.
    fn add_active(&self, spork: SporkMessage) -> bool {
        let id = spork.spork_id;
        let entries: Vec<SporkEntry> = {
            let mut active = self.active_sporks.write();
            let list = active.entry(id).or_default();
            if is_multi_value(id) {
                let hash = spork.hash();
                if list.iter().any(|held| held.hash() == hash) {
                    return false;
                }
                list.push(spork);
                list.sort_by_key(|held| held.time_signed);
            } else {
                *list = vec![spork];
                return true;
            }
            list.iter()
                .map(|held| SporkEntry::new(held.value.clone(), held.time_signed))
                .collect()
        };
        // Consensus reads the entries of the multi-value sporks from here
        self.consensus.write().set(id, entries);
        true
    }

    /// Call `listener` when a spork 14 entry arrives, to take its fee settings
    pub fn on_tx_fee_spork(&self, listener: Arc<dyn Fn() + Send + Sync>) {
        self.fee_listeners.write().push(listener);
    }

    /// Subscribe to progress events
    pub fn subscribe(&self) -> broadcast::Receiver<SporkSyncProgress> {
        self.progress_tx.subscribe()
    }

    /// Check if sporks are synced from at least one peer
    pub fn is_synced(&self) -> bool {
        let states = self.peer_states.read();
        states.values().any(|s| *s == SporkSyncState::Synced)
    }

    /// Check if a specific peer has synced sporks
    pub fn is_peer_synced(&self, peer_id: PeerId) -> bool {
        let states = self.peer_states.read();
        states
            .get(&peer_id)
            .map(|s| *s == SporkSyncState::Synced)
            .unwrap_or(false)
    }

    /// Get the sync state for a peer
    pub fn peer_state(&self, peer_id: PeerId) -> SporkSyncState {
        self.peer_states
            .read()
            .get(&peer_id)
            .copied()
            .unwrap_or(SporkSyncState::Pending)
    }

    /// Handle sporkcount message from a peer. Divi Core takes a count of none
    /// or less as nothing to wait for (Node.cpp SetSporkCount) and answers
    /// every sporkcount with getsporks (spork.cpp ProcessSpork)
    pub async fn handle_sporkcount(&self, peer_id: PeerId, count: u32) {
        // The count is a signed 32-bit integer on the wire
        let count = if count > i32::MAX as u32 { 0 } else { count };
        tracing::debug!("Peer {} has {} sporks", peer_id, count);

        // Update peer state
        {
            let mut states = self.peer_states.write();
            if count == 0 {
                states.insert(peer_id, SporkSyncState::Synced);
            } else {
                states.insert(
                    peer_id,
                    SporkSyncState::Syncing {
                        expected: count,
                        received: 0,
                    },
                );
            }
        }

        tracing::debug!("Requesting sporks from peer {}", peer_id);
        if let Err(e) = self
            .peer_manager
            .send_to_peer(peer_id, NetworkMessage::GetSporks)
            .await
        {
            tracing::debug!("Could not request sporks from peer {}: {}", peer_id, e);
            self.remove_peer(peer_id);
            return;
        }
        if count == 0 {
            self.peer_manager.sporks_arrived(peer_id);
        }

        self.emit_progress();
    }

    /// Handle spork message from a peer
    pub async fn handle_spork(&self, peer_id: PeerId, spork: SporkMessage) {
        let hash = spork.hash();
        tracing::debug!(
            "Received spork {} (id={}, value={}) from peer {}",
            hash,
            spork.spork_id,
            spork.value,
            peer_id
        );

        // Divi Core ProcessSpork: a spork no newer than the active one is
        // only counted (unless it is a multi-value spork); otherwise its
        // signature must check out, or the peer gets Misbehaving(100)
        let newer = self
            .active_sporks
            .read()
            .get(&spork.spork_id)
            .and_then(|list| list.last())
            .is_none_or(|active| spork.time_signed > active.time_signed);
        if !newer && !is_multi_value(spork.spork_id) {
            self.count_received(peer_id);
            self.emit_progress();
            return;
        }
        // No authority: the spork cannot be checked, so it is not taken. An
        // honest peer relays sporks its own key accepted, so it is not scored;
        // it is counted so that its spork sync still completes.
        let Some(key) = self.authority.key() else {
            tracing::debug!(
                "Spork {} from peer {} ignored: no spork authority on this network",
                hash,
                peer_id
            );
            self.count_received(peer_id);
            self.emit_progress();
            return;
        };
        let verified = match &self.authority {
            SporkAuthority::PrivateDivi(_) => verify_privatedivi(&spork, key),
            _ => spork.verify_with_policy(key, &self.auth_policy.read().clone()),
        };
        match verified {
            Ok(SporkAuthKind::ClassicalV1 | SporkAuthKind::HybridV2LmsUnverified { .. }) => {}
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q }) => {
                self.record_lms_leaf(spork.spork_id, hash, lms_leaf_q);
            }
            Err(err) => {
                tracing::warn!(
                    "Spork {} from peer {}: invalid signature ({})",
                    hash,
                    peer_id,
                    err
                );
                self.peer_manager.report_misbehavior_score(
                    peer_id,
                    BAD_SPORK_SCORE,
                    "Invalid spork signature",
                );
                return;
            }
        }

        self.count_received(peer_id);
        self.sporks.write().insert(hash, spork.clone());

        // Divi Core writes the spork to its database when it was added
        let added = self.add_active(spork.clone());
        if added {
            if let Some(db) = &self.db {
                if self.preserve_quarantined(db, spork.spork_id) {
                    if let Err(e) = db.put_metadata(&db_key(spork.spork_id), &spork.serialize()) {
                        tracing::warn!("Could not store spork {}: {}", spork.spork_id, e);
                    }
                }
            }
        }

        if spork.spork_id == divi_consensus::spork_values::ids::TX_FEE && added {
            for listener in self.fee_listeners.read().iter() {
                listener();
            }
        }

        // Divi Core announces every spork it accepted to its other peers
        // (spork.cpp:259, `CSporkMessage::Relay`); they fetch it by getdata
        self.peer_manager.broadcast_except(
            NetworkMessage::Inv(vec![InvItem::new(InvType::Spork, hash)]),
            peer_id,
        );

        self.emit_progress();
    }

    /// Count a spork received from a peer towards its sync
    fn count_received(&self, peer_id: PeerId) {
        {
            let mut states = self.peer_states.write();
            if let Some(SporkSyncState::Syncing { expected, received }) =
                states.get(&peer_id).copied()
            {
                let new_received = received + 1;
                if new_received >= expected {
                    tracing::debug!(
                        "Spork sync complete from peer {} ({} sporks)",
                        peer_id,
                        new_received
                    );
                    states.insert(peer_id, SporkSyncState::Synced);
                    self.peer_manager.sporks_arrived(peer_id);
                } else {
                    states.insert(
                        peer_id,
                        SporkSyncState::Syncing {
                            expected,
                            received: new_received,
                        },
                    );
                }
            }
        }
    }

    /// Handle getsporks request (respond with our sporks)
    pub async fn handle_getsporks(&self, peer_id: PeerId) {
        let sporks = self.active_sporks();
        tracing::debug!("Sending {} sporks to peer {}", sporks.len(), peer_id);

        for spork in sporks {
            if let Err(e) = self
                .peer_manager
                .send_to_peer(peer_id, NetworkMessage::Spork(spork))
                .await
            {
                tracing::debug!("Could not send sporks to peer {}: {}", peer_id, e);
                break;
            }
        }
    }

    /// Handle an `inv` that announces sporks: ask for the ones this node does
    /// not hold, once (Divi Core main.cpp:559-612, `AlreadyHave` then `AskFor`)
    pub async fn handle_inv(&self, peer_id: PeerId, items: &[InvItem]) {
        // With no authority every spork would be refused, so none is asked for
        if self.authority.key().is_none() {
            return;
        }
        let wanted: Vec<InvItem> = {
            let held = self.sporks.read();
            let mut asked = self.asked.lock();
            let now = Instant::now();
            asked.retain(|_, when| now.duration_since(*when) < ASK_AGAIN_AFTER);
            items
                .iter()
                .filter(|item| item.inv_type == InvType::Spork)
                .filter(|item| !held.contains_key(&item.hash))
                .filter(|item| asked.insert(item.hash, now).is_none())
                .cloned()
                .collect()
        };
        if !wanted.is_empty() {
            let hashes: Vec<_> = wanted.iter().map(|i| i.hash).collect();
            if let Err(e) = self
                .peer_manager
                .send_to_peer(peer_id, NetworkMessage::GetData(wanted))
                .await
            {
                let mut asked = self.asked.lock();
                for hash in hashes {
                    asked.remove(&hash);
                }
                tracing::debug!(
                    "Could not request announced sporks from peer {}: {}",
                    peer_id,
                    e
                );
            }
        }
    }

    /// A spork this node holds, by its hash: what a `getdata` for it is answered
    /// with (Divi Core `ShareSporkDataWithPeer`, spork.cpp:41-50)
    pub fn spork_by_hash(&self, hash: &Hash256) -> Option<SporkMessage> {
        self.sporks.read().get(hash).cloned()
    }

    /// A peer that dialled us. Divi Core waits for no sporks from it
    /// (Node.cpp CanSendMessagesToPeer, net.cpp GetSporkSyncedOrInboundNodes).
    /// Its connection told it how many sporks this node holds, with its verack
    /// (main.cpp SetPeerVersionAndServices, `spork_count`); the peer itself
    /// sends nothing else to us until it has that many sporks, so the count
    /// must match what `getsporks` serves.
    pub async fn inbound_peer_connected(&self, peer_id: PeerId) {
        self.peer_states
            .write()
            .entry(peer_id)
            .or_insert(SporkSyncState::Synced);
        self.emit_progress();
    }

    /// Remove a peer's state when disconnected
    pub fn remove_peer(&self, peer_id: PeerId) {
        self.peer_states.write().remove(&peer_id);
        self.emit_progress();
    }

    /// The number of active sporks, every entry of a multi-value spork
    /// counted (Divi Core `GetActiveSporkCount`)
    pub fn spork_count(&self) -> usize {
        self.active_sporks.read().values().map(Vec::len).sum()
    }

    /// Every active spork, as `getsporks` serves them: by ID, and by time
    /// within a multi-value spork (Divi Core spork.cpp:261-267)
    pub fn active_sporks(&self) -> Vec<SporkMessage> {
        self.active_sporks
            .read()
            .values()
            .flat_map(|list| list.iter().cloned())
            .collect()
    }

    /// The newest active spork with this ID
    pub fn get_spork(&self, spork_id: i32) -> Option<SporkMessage> {
        self.active_sporks
            .read()
            .get(&spork_id)
            .and_then(|list| list.last())
            .cloned()
    }

    /// Get all active spork IDs
    pub fn active_spork_ids(&self) -> Vec<i32> {
        self.active_sporks.read().keys().copied().collect()
    }

    /// Emit progress event
    fn emit_progress(&self) {
        let states = self.peer_states.read();
        let synced_peers = states
            .values()
            .filter(|s| **s == SporkSyncState::Synced)
            .count();
        let total_peers = states.len();
        let spork_count = self.spork_count();

        let _ = self.progress_tx.send(SporkSyncProgress {
            synced_peers,
            total_peers,
            spork_count,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require mocking PeerManager
    // This tests the basic state machine logic

    #[test]
    fn test_spork_sync_state() {
        assert_eq!(SporkSyncState::Pending, SporkSyncState::Pending);
        assert_ne!(SporkSyncState::Pending, SporkSyncState::Synced);
    }

    fn signed(kp: &divi_crypto::KeyPair, id: i32, value: &str, time: i64) -> SporkMessage {
        let message = format!("{}{}{}", id, value, time);
        let signature =
            divi_masternode::cpp_wire::sign_message(kp.secret_key(), message.as_bytes()).unwrap();
        SporkMessage {
            spork_id: id,
            value: value.into(),
            time_signed: time,
            signature,
        }
    }

    #[test]
    fn spork_preserves_value_bytes_from_cpp_message() {
        let kp = divi_crypto::KeyPair::new_random();
        let spork = SporkMessage {
            spork_id: 10001,
            value: "001".into(),
            time_signed: 1700000000,
            signature: divi_masternode::cpp_wire::sign_message(
                kp.secret_key(),
                b"100010011700000000",
            )
            .unwrap(),
        };
        assert!(spork.signature_is_valid(&kp.public_key().to_bytes()));
    }

    #[test]
    fn spork_signature_is_checked_against_the_key() {
        let kp = divi_crypto::KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let spork = signed(&kp, 10007, "1", 1_700_000_000);
        assert!(spork.signature_is_valid(&key));

        let mut changed = spork.clone();
        changed.value = "0".into();
        assert!(!changed.signature_is_valid(&key));

        let other = divi_crypto::KeyPair::new_random();
        assert!(!spork.signature_is_valid(&other.public_key().to_bytes()));

        // Divi Core compares key ids: the recovery byte must say compressed
        let mut uncompressed = spork.clone();
        uncompressed.signature[0] -= 4;
        assert!(!uncompressed.signature_is_valid(&key));
    }

    fn quiet_peers() -> Arc<PeerManager> {
        PeerManager::new(crate::PeerManagerConfig {
            dns_seeds: vec![],
            static_peers: vec![],
            listen_addr: None,
            ..Default::default()
        })
    }

    /// A peer registered with `peers`, and the receiver of what is sent to it
    fn test_peer(
        peers: &Arc<PeerManager>,
        id: PeerId,
    ) -> tokio::sync::mpsc::Receiver<NetworkMessage> {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        peers.insert_test_peer(crate::peer::PeerHandle {
            id,
            addr: format!("127.0.0.1:{}", 2000 + id).parse().unwrap(),
            tx,
            inbound: true,
            stats: Default::default(),
        });
        rx
    }

    fn received(rx: &mut tokio::sync::mpsc::Receiver<NetworkMessage>) -> Vec<NetworkMessage> {
        let mut got = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            got.push(msg);
        }
        got
    }

    /// Divi Core answers every sporkcount with getsporks, a count of none
    /// included (spork.cpp:269-274), and takes a count of none or less as
    /// "nothing to wait for" (Node.cpp:1008-1016)
    #[tokio::test]
    async fn every_sporkcount_is_answered_with_getsporks() {
        let peers = quiet_peers();
        let sporks = SporkManager::with_key(Arc::clone(&peers), None, None);
        let mut rx = test_peer(&peers, 1);

        sporks.handle_sporkcount(1, 0).await;
        assert!(matches!(received(&mut rx)[..], [NetworkMessage::GetSporks]));
        assert!(sporks.is_peer_synced(1));

        // a count that is negative as a 32-bit integer
        sporks.handle_sporkcount(1, u32::MAX).await;
        assert!(matches!(received(&mut rx)[..], [NetworkMessage::GetSporks]));
        assert!(sporks.is_peer_synced(1));

        sporks.handle_sporkcount(1, 3).await;
        assert!(matches!(received(&mut rx)[..], [NetworkMessage::GetSporks]));
        assert_eq!(
            sporks.peer_state(1),
            SporkSyncState::Syncing {
                expected: 3,
                received: 0
            }
        );
    }

    /// Divi Core relays a spork it accepted as an inv to its peers
    /// (spork.cpp:259); a spork it refused, or one no newer than the active
    /// one, is not relayed
    #[tokio::test]
    async fn an_accepted_spork_is_announced_to_the_other_peers() {
        let kp = divi_crypto::KeyPair::new_random();
        let peers = quiet_peers();
        let sporks =
            SporkManager::with_key(Arc::clone(&peers), Some(kp.public_key().to_bytes()), None);
        let mut sender = test_peer(&peers, 1);
        let mut other = test_peer(&peers, 2);
        let mut third = test_peer(&peers, 3);

        let spork = signed(&kp, 10007, "1600000000", 2000);
        sporks.handle_spork(1, spork.clone()).await;
        let announced = |rx: &mut tokio::sync::mpsc::Receiver<NetworkMessage>| {
            received(rx)
                .into_iter()
                .filter_map(|m| match m {
                    NetworkMessage::Inv(items) => Some(items),
                    _ => None,
                })
                .flatten()
                .collect::<Vec<_>>()
        };
        let expected = vec![InvItem::new(InvType::Spork, spork.hash())];
        assert_eq!(announced(&mut other), expected);
        assert_eq!(announced(&mut third), expected);
        assert!(announced(&mut sender).is_empty());

        // older than the active one: counted, not relayed
        sporks.handle_spork(1, signed(&kp, 10007, "1", 1000)).await;
        // refused
        let mut forged = signed(&kp, 10007, "2", 3000);
        forged.signature[10] ^= 1;
        sporks.handle_spork(1, forged).await;
        assert!(announced(&mut other).is_empty());
        assert!(announced(&mut third).is_empty());
    }

    /// The entries of sporks 13 to 16 are handed to the chain as they are added,
    /// and again when a restart loads them (spork.cpp:144-168, :192-211)
    #[tokio::test]
    async fn multi_value_sporks_reach_the_chain_and_survive_a_restart() {
        use divi_storage::SharedSporks;
        let kp = divi_crypto::KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let dir = tempfile::tempdir().unwrap();
        let handed = SharedSporks::default();
        {
            let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
            let sporks = SporkManager::with_key_and_chain(
                quiet_peers(),
                Some(key.clone()),
                Some(db),
                handed.clone(),
            );
            sporks
                .handle_spork(1, signed(&kp, 10015, "5000;100", 1000))
                .await;
            sporks
                .handle_spork(1, signed(&kp, 10015, "3000;200", 2000))
                .await;
            // a single-value spork is not one of them
            sporks
                .handle_spork(1, signed(&kp, 10007, "1600000000", 2000))
                .await;
        }
        let entries = |s: &SharedSporks| s.read().entries(10015).to_vec();
        assert_eq!(
            entries(&handed),
            vec![
                SporkEntry::new("5000;100", 1000),
                SporkEntry::new("3000;200", 2000)
            ]
        );
        assert!(handed.read().entries(10007).is_empty());

        // a restart holds the last entry added to each spork, as divid's database does
        let restarted = SharedSporks::default();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let _ =
            SporkManager::with_key_and_chain(quiet_peers(), Some(key), Some(db), restarted.clone());
        assert_eq!(entries(&restarted), vec![SporkEntry::new("3000;200", 2000)]);
    }

    /// A spork 14 entry that is added tells the node to take its fees; a copy of
    /// it, another spork and a refused one do not (spork.cpp:253-257)
    #[tokio::test]
    async fn only_a_new_tx_fee_entry_runs_the_fee_listener() {
        let kp = divi_crypto::KeyPair::new_random();
        let sporks = SporkManager::with_key(quiet_peers(), Some(kp.public_key().to_bytes()), None);
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        sporks.on_tx_fee_spork(Arc::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        let count = || runs.load(std::sync::atomic::Ordering::SeqCst);

        let fee = signed(&kp, 10013, "10000;300;100000;20000;50;0", 1000);
        sporks.handle_spork(1, fee.clone()).await;
        assert_eq!(count(), 1);
        sporks.handle_spork(2, fee).await;
        assert_eq!(count(), 1, "the same entry again");
        sporks
            .handle_spork(1, signed(&kp, 10015, "5000;100", 1000))
            .await;
        assert_eq!(count(), 1, "another spork");
        let mut forged = signed(&kp, 10013, "1;1;1;1;1;0", 3000);
        forged.signature[10] ^= 1;
        sporks.handle_spork(1, forged).await;
        assert_eq!(count(), 1, "a refused entry");
        sporks
            .handle_spork(1, signed(&kp, 10013, "10000;300;100000;30000;60;0", 2000))
            .await;
        assert_eq!(count(), 2);
    }

    /// Divi Core AddActiveSpork and GetActiveSporkCount (spork.cpp:144-168,
    /// :351-356): every signed entry of a multi-value spork is kept in time
    /// order, served and counted; a single-value spork keeps the newest only
    #[tokio::test]
    async fn multi_value_spork_keeps_every_signed_entry() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let sporks = SporkManager::with_key(quiet_peers(), Some(key), None);

        let lottery = SPORK_16_LOTTERY_TICKET_MIN_VALUE;
        sporks
            .handle_spork(1, signed(&kp, lottery, "5000;100", 1000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, lottery, "6000;200", 2000))
            .await;
        // an older entry still joins the list, in time order
        sporks
            .handle_spork(1, signed(&kp, lottery, "5500;150", 1500))
            .await;
        // the same entry again is not a new one
        sporks
            .handle_spork(2, signed(&kp, lottery, "5000;100", 1000))
            .await;
        // a single-value spork keeps the newest only
        let enforcement = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        sporks
            .handle_spork(1, signed(&kp, enforcement, "1", 1000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, enforcement, "2", 2000))
            .await;
        sporks
            .handle_spork(1, signed(&kp, enforcement, "3", 1500))
            .await;

        assert_eq!(sporks.spork_count(), 4);
        let mut served: Vec<(i32, String)> = sporks
            .active_sporks()
            .into_iter()
            .map(|s| (s.spork_id, s.value))
            .collect();
        served.sort();
        assert_eq!(
            served,
            vec![
                (enforcement, "2".to_string()),
                (lottery, "5000;100".to_string()),
                (lottery, "5500;150".to_string()),
                (lottery, "6000;200".to_string()),
            ]
        );
        assert_eq!(sporks.get_spork(lottery).unwrap().value, "6000;200");
        assert_eq!(sporks.get_spork(enforcement).unwrap().value, "2");

        // an unsigned multi-value entry is not kept
        let mut unsigned = signed(&kp, lottery, "1;1", 3000);
        unsigned.signature = vec![0x1f; 65];
        sporks.handle_spork(3, unsigned).await;
        assert_eq!(sporks.spork_count(), 4);
    }

    /// Divi Core writes each spork it adds to its spork database and loads one
    /// per id at start (spork.cpp:192-211, :255)
    #[tokio::test]
    async fn stored_sporks_are_loaded_after_a_restart() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let key = kp.public_key().to_bytes();
        let dir = tempfile::tempdir().unwrap();
        let lottery = SPORK_16_LOTTERY_TICKET_MIN_VALUE;
        let enforcement = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        {
            let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
            let sporks = SporkManager::with_key(quiet_peers(), Some(key.clone()), Some(db));
            sporks
                .handle_spork(1, signed(&kp, enforcement, "1", 1000))
                .await;
            sporks
                .handle_spork(1, signed(&kp, lottery, "5000;100", 1000))
                .await;
            sporks
                .handle_spork(1, signed(&kp, lottery, "6000;200", 2000))
                .await;
        }
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let sporks = SporkManager::with_key(quiet_peers(), Some(key), Some(db));
        assert_eq!(sporks.get_spork(enforcement).unwrap().value, "1");
        assert_eq!(sporks.get_spork(lottery).unwrap().value, "6000;200");
        assert_eq!(sporks.spork_count(), 2);
    }

    #[test]
    fn spork_keys_by_network() {
        use crate::constants::*;
        assert_eq!(spork_key(&MAINNET_MAGIC).unwrap()[0], 0x02);
        assert_eq!(spork_key(&REGTEST_MAGIC), spork_key(&TESTNET_MAGIC));
        assert!(spork_key(&PRIVATEDIVI_MAINNET_MAGIC).is_none());
    }

    /// Divi keeps its keys; PrivateDivi testnet and regtest take the key pinned
    /// from PrivateDivi Core 408ad01e (chainparams.cpp:444, regtest inherits it
    /// at :458); the relaunched PrivateDivi mainnet and other magics stay unmapped
    #[test]
    fn spork_authority_by_network() {
        use crate::constants::*;
        let pinned = hex::decode(PRIVATEDIVI_TESTNET_SPORK_KEY).unwrap();
        assert_eq!(
            spork_authority(&MAINNET_MAGIC),
            SporkAuthority::Divi(hex::decode(MAINNET_SPORK_KEY).unwrap())
        );
        for magic in [TESTNET_MAGIC, REGTEST_MAGIC] {
            assert_eq!(
                spork_authority(&magic),
                SporkAuthority::Divi(hex::decode(TESTNET_SPORK_KEY).unwrap())
            );
        }
        for magic in [PRIVATEDIVI_TESTNET_MAGIC, PRIVATEDIVI_REGTEST_MAGIC] {
            assert_eq!(
                spork_authority(&magic),
                SporkAuthority::PrivateDivi(pinned.clone())
            );
            assert_eq!(spork_key(&magic).as_deref(), Some(&pinned[..]));
        }
        assert_eq!(
            spork_authority(&PRIVATEDIVI_MAINNET_MAGIC),
            SporkAuthority::Unmapped
        );
        assert_eq!(spork_authority(&[0, 0, 0, 0]), SporkAuthority::Unmapped);
        assert_eq!(pinned.len(), 33);
        assert_eq!(
            PRIVATEDIVI_REFERENCE_REVISION,
            "408ad01e929543c7d11586b06fe8d26de8460539"
        );
    }

    /// A row as an earlier release stored it: any bytes for a signature
    fn store_row(db: &ChainDatabase, spork: &SporkMessage) {
        db.put_metadata(&db_key(spork.spork_id), &spork.serialize())
            .unwrap();
    }

    fn row(db: &ChainDatabase, key: &[u8]) -> Option<Vec<u8>> {
        db.get_metadata(key).unwrap()
    }

    fn unsigned(id: i32, value: &str, time: i64) -> SporkMessage {
        SporkMessage {
            spork_id: id,
            value: value.into(),
            time_signed: time,
            signature: vec![0x1f; 65],
        }
    }

    fn peers_on(magic: crate::constants::Magic) -> Arc<PeerManager> {
        PeerManager::new(crate::PeerManagerConfig {
            magic,
            dns_seeds: vec![],
            static_peers: vec![],
            listen_addr: None,
            ..Default::default()
        })
    }

    fn score(peers: &PeerManager, id: PeerId) -> i32 {
        peers.scoring().get_stats(id).unwrap().misbehavior_score
    }

    /// With no authority a spork, even a well-signed one, is not stored,
    /// activated, handed to the chain, relayed or asked for; the peer that sent
    /// it is not scored and its spork sync still completes
    #[tokio::test]
    async fn unmapped_authority_refuses_sporks_without_scoring() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let consensus = SharedSporks::default();
        let peers = quiet_peers();
        let sporks = SporkManager::with_authority(
            Arc::clone(&peers),
            SporkAuthority::Unmapped,
            Some(Arc::clone(&db)),
            consensus.clone(),
        );
        let mut sender = test_peer(&peers, 1);
        let mut other = test_peer(&peers, 2);
        peers
            .scoring()
            .register_peer(1, "127.0.0.1".parse().unwrap());

        sporks.handle_sporkcount(1, 2).await;
        received(&mut sender);
        let value = SPORK_15_BLOCK_VALUE;
        let entry = signed(&kp, value, "5000;100", 1000);
        sporks.handle_spork(1, entry.clone()).await;
        let mut forged = signed(&kp, SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT, "1", 1000);
        forged.signature[10] ^= 1;
        sporks.handle_spork(1, forged).await;

        assert_eq!(score(&peers, 1), 0);
        assert!(sporks.is_peer_synced(1));
        assert_eq!(sporks.spork_count(), 0);
        assert!(sporks.spork_by_hash(&entry.hash()).is_none());
        assert!(consensus.read().entries(value).is_empty());
        assert!(row(&db, &db_key(value)).is_none());
        assert!(received(&mut other).is_empty(), "nothing relayed");

        received(&mut sender);
        sporks
            .handle_inv(1, &[InvItem::new(InvType::Spork, entry.hash())])
            .await;
        assert!(received(&mut sender).is_empty(), "nothing asked for");
    }

    /// A PrivateDivi authority checks what arrives as Divi Core does: a bad
    /// signature scores 100 and is not kept; a good one is kept and relayed
    #[tokio::test]
    async fn privatedivi_authority_checks_sporks_on_receipt() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let peers = quiet_peers();
        let sporks = SporkManager::with_authority(
            Arc::clone(&peers),
            SporkAuthority::PrivateDivi(kp.public_key().to_bytes()),
            None,
            Default::default(),
        );
        let _sender = test_peer(&peers, 1);
        let mut other = test_peer(&peers, 2);
        peers
            .scoring()
            .register_peer(1, "127.0.0.1".parse().unwrap());
        let id = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;

        sporks.handle_spork(1, unsigned(id, "1", 1000)).await;
        assert!(sporks.get_spork(id).is_none());
        assert_eq!(score(&peers, 1), BAD_SPORK_SCORE as i32);
        assert!(received(&mut other).is_empty());

        sporks.handle_spork(1, signed(&kp, id, "2", 2000)).await;
        assert_eq!(sporks.get_spork(id).unwrap().value, "2");
        assert!(!received(&mut other).is_empty());
    }

    /// Rows stored before an authority was mapped are re-checked at start: one
    /// that verifies loads; one that does not is quarantined, not handed to the
    /// chain, and its row kept. When a verified spork replaces it, the old row
    /// is first copied to its quarantine key. No hold on a mapped network.
    #[tokio::test]
    async fn privatedivi_stored_sporks_are_checked_again_after_a_restart() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let authority = SporkAuthority::PrivateDivi(kp.public_key().to_bytes());
        let dir = tempfile::tempdir().unwrap();
        let enforcement = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        let value = SPORK_15_BLOCK_VALUE;
        let forged = unsigned(value, "1;1", 1000);
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            store_row(&db, &signed(&kp, enforcement, "7", 1000));
            store_row(&db, &forged);
        }

        let consensus = SharedSporks::default();
        {
            let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
            let sporks = SporkManager::with_authority(
                quiet_peers(),
                authority.clone(),
                Some(Arc::clone(&db)),
                consensus.clone(),
            );
            assert_eq!(sporks.get_spork(enforcement).unwrap().value, "7");
            assert!(sporks.get_spork(value).is_none());
            assert!(consensus.read().entries(value).is_empty());
            assert_eq!(sporks.quarantined().len(), 1);
            let held = &sporks.quarantined()[0];
            let decoded = held.decoded.as_ref().unwrap();
            assert_eq!(
                (held.spork_id, decoded.value.as_str(), decoded.time_signed),
                (value, "1;1", 1000)
            );
            assert_eq!(
                held.reason,
                QuarantineReason::InvalidSignature(SporkVerifyError::InvalidClassicalSignature)
            );
            assert_eq!(held.raw, forged.serialize());
            assert!(sporks.store_hold().is_none());
            assert_eq!(row(&db, &db_key(value)), Some(forged.serialize()));

            sporks
                .handle_spork(1, signed(&kp, value, "5000;100", 2000))
                .await;
            assert_eq!(
                consensus.read().entries(value),
                &[SporkEntry::new("5000;100", 2000)]
            );
            assert_eq!(
                row(&db, &quarantine_db_key(value)),
                Some(forged.serialize())
            );
        }

        let restarted = SharedSporks::default();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let sporks = SporkManager::with_authority(
            quiet_peers(),
            authority,
            Some(db.clone()),
            restarted.clone(),
        );
        assert!(sporks.quarantined().is_empty());
        assert_eq!(
            restarted.read().entries(value),
            &[SporkEntry::new("5000;100", 2000)]
        );
        assert_eq!(
            row(&db, &quarantine_db_key(value)),
            Some(forged.serialize())
        );
    }

    /// With no authority, stored rows are not loaded after a restart and are
    /// not changed. They raise a hold: `try_with_chain` refuses to start until
    /// the operator acknowledges the fingerprint of exactly these rows.
    #[tokio::test]
    async fn unmapped_stored_sporks_are_held_not_loaded_or_deleted() {
        use crate::constants::PRIVATEDIVI_MAINNET_MAGIC;
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let dir = tempfile::tempdir().unwrap();
        let enforcement = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        let value = SPORK_15_BLOCK_VALUE;
        let rows = [
            signed(&kp, enforcement, "1600000000", 1000),
            unsigned(value, "5000;100", 1000),
        ];
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            for spork in &rows {
                store_row(&db, spork);
            }
        }
        let open = || Arc::new(ChainDatabase::open(dir.path()).unwrap());

        let consensus = SharedSporks::default();
        let held = SporkManager::try_with_chain(
            peers_on(PRIVATEDIVI_MAINNET_MAGIC),
            open(),
            consensus.clone(),
            None,
        )
        .err()
        .and_then(held_by)
        .expect("held");
        assert_eq!(held.quarantined.len(), 2);
        assert!(held
            .quarantined
            .iter()
            .all(|q| q.reason == QuarantineReason::NoAuthority));
        assert!(consensus.read().entries(value).is_empty());
        let report = held.to_string();
        assert!(report.contains(&held.fingerprint));
        assert!(report.contains(SPORK_HOLD_ACK_ENV));
        assert!(report.contains("5000;100"));

        // the same rows give the same fingerprint; a wrong one does not release it
        let again = SporkManager::try_with_chain(
            peers_on(PRIVATEDIVI_MAINNET_MAGIC),
            open(),
            Default::default(),
            Some("00"),
        )
        .err()
        .and_then(held_by)
        .expect("still held");
        assert_eq!(again.fingerprint, held.fingerprint);

        let sporks = SporkManager::try_with_chain(
            peers_on(PRIVATEDIVI_MAINNET_MAGIC),
            open(),
            consensus.clone(),
            Some(held.fingerprint.as_str()),
        )
        .expect("acknowledged");
        assert_eq!(sporks.spork_count(), 0);
        assert!(sporks.get_spork(enforcement).is_none());
        assert!(consensus.read().entries(value).is_empty());
        drop(sporks);

        let db = open();
        for spork in &rows {
            assert_eq!(row(&db, &db_key(spork.spork_id)), Some(spork.serialize()));
            assert!(row(&db, &quarantine_db_key(spork.spork_id)).is_none());
        }

        // an empty store raises no hold
        let empty = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(empty.path()).unwrap());
        assert!(SporkManager::try_with_chain(
            peers_on(PRIVATEDIVI_MAINNET_MAGIC),
            db,
            Default::default(),
            None
        )
        .is_ok());
    }

    fn held_by(err: SporkStartError) -> Option<SporkStoreHold> {
        match err {
            SporkStartError::Held(hold) => Some(hold),
            SporkStartError::Unreadable(_) => None,
        }
    }

    /// Rows that do not decode, carry trailing bytes or hold a spork of
    /// another id are quarantined, never taken as absent: with no authority
    /// they hold the start; with a PrivateDivi authority they do not load,
    /// even when the spork they hold is well signed. Divi skips or loads them
    /// as before.
    #[tokio::test]
    async fn malformed_and_misplaced_rows_are_quarantined_not_absent() {
        use crate::constants::{PRIVATEDIVI_MAINNET_MAGIC, REGTEST_MAGIC};
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let dir = tempfile::tempdir().unwrap();
        let garbage = vec![0x01, 0x02, 0x03];
        let mut trailing = signed(&kp, SPORK_13_BLOCK_PAYMENTS, "1;1", 1000).serialize();
        trailing.push(0);
        let misplaced = signed(&kp, SPORK_14_TX_FEE, "10000;100000", 1000);
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            db.put_metadata(&db_key(SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT), &garbage)
                .unwrap();
            db.put_metadata(&db_key(SPORK_13_BLOCK_PAYMENTS), &trailing)
                .unwrap();
            db.put_metadata(&db_key(SPORK_15_BLOCK_VALUE), &misplaced.serialize())
                .unwrap();
        }
        let open = || Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let reasons = |held: &[QuarantinedSpork]| {
            held.iter()
                .map(|q| (q.spork_id, q.reason.clone()))
                .collect::<Vec<_>>()
        };
        let expected = |last: QuarantineReason| {
            vec![
                (
                    SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT,
                    QuarantineReason::Undecodable(
                        SporkMessage::deserialize(&garbage).unwrap_err().to_string(),
                    ),
                ),
                (
                    SPORK_13_BLOCK_PAYMENTS,
                    QuarantineReason::Undecodable("trailing or non-canonical bytes".into()),
                ),
                (SPORK_15_BLOCK_VALUE, last),
            ]
        };
        let mismatch = QuarantineReason::IdMismatch {
            decoded_id: SPORK_14_TX_FEE,
        };

        // no authority: held, with these rows in the fingerprint
        let hold = SporkManager::try_with_chain(
            peers_on(PRIVATEDIVI_MAINNET_MAGIC),
            open(),
            Default::default(),
            None,
        )
        .err()
        .and_then(held_by)
        .expect("held");
        assert_eq!(reasons(&hold.quarantined[..]), expected(mismatch.clone()));
        assert!(hold.quarantined[0].decoded.is_none());
        assert_eq!(hold.quarantined[0].raw, garbage);
        assert!(hold.to_string().contains("does not decode"));

        // a PrivateDivi authority that signed the rows: still none loads
        let consensus = SharedSporks::default();
        let sporks = SporkManager::with_authority(
            quiet_peers(),
            SporkAuthority::PrivateDivi(kp.public_key().to_bytes()),
            Some(open()),
            consensus.clone(),
        );
        assert_eq!(reasons(sporks.quarantined()), expected(mismatch));
        assert_eq!(sporks.spork_count(), 0);
        assert!(consensus.read().entries(SPORK_14_TX_FEE).is_empty());
        assert!(consensus.read().entries(SPORK_15_BLOCK_VALUE).is_empty());
        drop(sporks);

        // Divi: the garbage row is skipped, the others load as decoded, unchanged
        let sporks =
            SporkManager::try_with_chain(peers_on(REGTEST_MAGIC), open(), Default::default(), None)
                .expect("no hold");
        assert!(sporks.quarantined().is_empty());
        assert_eq!(
            sporks.get_spork(SPORK_14_TX_FEE).unwrap().value,
            "10000;100000"
        );
        drop(sporks);

        let db = open();
        assert_eq!(
            row(&db, &db_key(SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT)),
            Some(garbage)
        );
        assert_eq!(row(&db, &db_key(SPORK_13_BLOCK_PAYMENTS)), Some(trailing));
        assert_eq!(
            row(&db, &db_key(SPORK_15_BLOCK_VALUE)),
            Some(misplaced.serialize())
        );
    }

    /// A row that cannot be read is not an empty row: on PrivateDivi and
    /// unmapped networks the start stops, no acknowledgement releases it, and
    /// a verified spork does not overwrite the unread row. Divi only warns.
    #[tokio::test]
    async fn unreadable_rows_stop_the_start_and_cannot_be_acknowledged() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let id = SPORK_15_BLOCK_VALUE;
        let injected = || StorageError::Deserialization("injected read failure".into());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());

        for authority in [
            SporkAuthority::Unmapped,
            SporkAuthority::PrivateDivi(kp.public_key().to_bytes()),
        ] {
            let mut sporks = SporkManager::with_authority(
                quiet_peers(),
                authority.clone(),
                Some(Arc::clone(&db)),
                Default::default(),
            );
            let raw = unsigned(SPORK_14_TX_FEE, "1;1", 1000).serialize();
            Arc::get_mut(&mut sporks).unwrap().load_rows(vec![
                (id, Err(injected())),
                (SPORK_14_TX_FEE, Ok(Some(raw))),
            ]);
            let fingerprint = sporks.store_hold().map(|hold| hold.fingerprint);
            for ack in [None, Some("00"), fingerprint.as_deref()] {
                match sporks.check_start(ack) {
                    Err(SporkStartError::Unreadable(rows)) => {
                        assert_eq!(
                            rows,
                            vec![UnreadableSpork {
                                spork_id: id,
                                error: injected().to_string(),
                            }]
                        );
                    }
                    other => panic!("{authority:?} ack {ack:?}: {other:?}"),
                }
            }
            let report = sporks.check_start(None).unwrap_err().to_string();
            assert!(report.contains("spork_10014"));
            assert!(report.contains("injected read failure"));
            assert!(report.contains(SPORK_HOLD_ACK_ENV));

            sporks
                .handle_spork(1, signed(&kp, id, "5000;100", 2000))
                .await;
            assert!(row(&db, &db_key(id)).is_none(), "{authority:?}");
            assert!(row(&db, &quarantine_db_key(id)).is_none());
        }

        let mut sporks = SporkManager::with_authority(
            quiet_peers(),
            SporkAuthority::Divi(kp.public_key().to_bytes()),
            None,
            Default::default(),
        );
        Arc::get_mut(&mut sporks)
            .unwrap()
            .load_rows(vec![(id, Err(injected()))]);
        assert!(sporks.check_start(None).is_ok());
    }

    /// A quarantine copy already in the database must hold the same bytes as
    /// the quarantined row before that row is replaced. Otherwise neither is
    /// replaced; the verified spork is still active until the next start.
    #[tokio::test]
    async fn quarantine_copy_must_match_before_a_row_is_replaced() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let id = SPORK_15_BLOCK_VALUE;
        let forged = unsigned(id, "1;1", 1000).serialize();
        let verified = signed(&kp, id, "5000;100", 2000);

        for (kept, replaced) in [(b"other".to_vec(), false), (forged.clone(), true)] {
            let dir = tempfile::tempdir().unwrap();
            let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
            db.put_metadata(&db_key(id), &forged).unwrap();
            db.put_metadata(&quarantine_db_key(id), &kept).unwrap();
            let consensus = SharedSporks::default();
            let sporks = SporkManager::with_authority(
                quiet_peers(),
                SporkAuthority::PrivateDivi(kp.public_key().to_bytes()),
                Some(Arc::clone(&db)),
                consensus.clone(),
            );
            assert_eq!(sporks.quarantined().len(), 1);
            sporks.handle_spork(1, verified.clone()).await;
            assert_eq!(
                consensus.read().entries(id),
                &[SporkEntry::new("5000;100", 2000)]
            );
            let stored = if replaced {
                verified.serialize()
            } else {
                forged.clone()
            };
            assert_eq!(row(&db, &db_key(id)), Some(stored));
            assert_eq!(row(&db, &quarantine_db_key(id)), Some(kept));
        }
    }

    /// PrivateDivi takes 65-byte classical signatures only, on receipt and at
    /// load, whatever `DIP-PQ-2` policy the manager is set to
    #[tokio::test]
    async fn privatedivi_takes_classical_signatures_only() {
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let id = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        let mut hybrid = signed(&kp, id, "1", 1000);
        hybrid.signature.resize(HYBRID_SPORK_SIG_LEN, 0);
        let length = SporkVerifyError::InvalidSignatureLength(HYBRID_SPORK_SIG_LEN);
        let authority = SporkAuthority::PrivateDivi(kp.public_key().to_bytes());

        let peers = quiet_peers();
        let sporks = SporkManager::with_authority(
            Arc::clone(&peers),
            authority.clone(),
            None,
            Default::default(),
        );
        sporks.set_auth_policy(SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: [0; PQ_LMS_SPORK_PUBKEY_LEN],
            network_magic: [0; 4],
        });
        let _sender = test_peer(&peers, 1);
        peers
            .scoring()
            .register_peer(1, "127.0.0.1".parse().unwrap());
        sporks.handle_spork(1, hybrid.clone()).await;
        assert!(sporks.get_spork(id).is_none());
        assert_eq!(score(&peers, 1), BAD_SPORK_SCORE as i32);

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        store_row(&db, &hybrid);
        let sporks =
            SporkManager::with_authority(quiet_peers(), authority, Some(db), Default::default());
        assert!(sporks.get_spork(id).is_none());
        assert_eq!(
            sporks.quarantined()[0].reason,
            QuarantineReason::InvalidSignature(length)
        );
    }

    /// Divi networks still load stored rows as Divi Core does, unchecked
    /// (spork.cpp LoadSporksFromDB), and raise no hold
    #[tokio::test]
    async fn divi_stored_sporks_still_load_unchecked() {
        use crate::constants::REGTEST_MAGIC;
        use crate::messages::spork_ids::*;
        let dir = tempfile::tempdir().unwrap();
        let id = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;
        {
            let db = ChainDatabase::open(dir.path()).unwrap();
            store_row(&db, &unsigned(id, "1", 1000));
        }
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let sporks =
            SporkManager::try_with_chain(peers_on(REGTEST_MAGIC), db, Default::default(), None)
                .expect("no hold");
        assert_eq!(sporks.get_spork(id).unwrap().value, "1");
        assert!(sporks.quarantined().is_empty());
    }

    // =========================================================================
    // DIP-PQ-2 (`P2.1` & `P2.2`) Hybrid secp256k1 + LMS-SHA256-M32-H10 Tests
    // =========================================================================

    fn test_lms_keypair() -> (LmsPrivateKey, [u8; PQ_LMS_SPORK_PUBKEY_LEN]) {
        let seed_hex = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";
        let seed = hex::decode(seed_hex).unwrap();
        let leaf =
            divi_crypto::pq::derive_pq_leaf(&seed, 301, 0, PqSchemeId::LmsSha256M32H10, 0).unwrap();
        let lms_sk = LmsPrivateKey::from_pq_leaf(&leaf).unwrap();
        let lms_pk = *lms_sk.public_key_bytes();
        (lms_sk, lms_pk)
    }

    #[test]
    fn dip_pq_2_constants_and_payload_hash_exact_formula() {
        assert_eq!(CLASSICAL_SPORK_SIG_LEN, 65);
        assert_eq!(PQ_LMS_SPORK_SIG_LEN, 2512);
        assert_eq!(PQ_LMS_SPORK_PUBKEY_LEN, 60);
        assert_eq!(HYBRID_SPORK_SIG_LEN, 2577);
        assert_eq!(SPORK_PQ_PAYLOAD_DOMAIN, b"DIVI-SPORK-PAYLOAD-V1");

        let sig65 = [0x42u8; 65];
        let direct_i64 = spork_pq_payload_hash_i64(10007, 1537971708, 1700000000, &sig65);
        let via_str = spork_pq_payload_hash(10007, "1537971708", 1700000000, &sig65);
        assert_eq!(direct_i64, via_str);

        // Verify exact manual SHA-256 preimage construction (106 bytes)
        let mut manual = Sha256::new();
        manual.update(b"DIVI-SPORK-PAYLOAD-V1");
        manual.update(10007i32.to_le_bytes());
        manual.update(1537971708i64.to_le_bytes());
        manual.update(1700000000i64.to_le_bytes());
        manual.update(sig65);
        let expected: [u8; 32] = manual.finalize().into();
        assert_eq!(direct_i64, expected);

        // Multi-value string sporks produce a distinct digest and never collide with integer sporks
        let multi_a = spork_pq_payload_hash(10015, "5000;100", 1700000000, &sig65);
        let multi_b = spork_pq_payload_hash(10015, "5000;200", 1700000000, &sig65);
        assert_ne!(multi_a, multi_b);
        assert_ne!(multi_a, direct_i64);
    }

    #[test]
    fn dip_pq_2_legacy_v1_accepted_under_classical_only_and_hybrid_optional() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (_lms_sk, lms_pk) = test_lms_keypair();

        let spork_v1 = signed(&kp, 10007, "1537971708", 1_700_000_000);
        assert_eq!(spork_v1.signature.len(), CLASSICAL_SPORK_SIG_LEN);
        assert!(!spork_v1.is_hybrid_v2());
        assert!(spork_v1.lms_signature().is_none());
        assert!(spork_v1.lms_leaf_index().is_none());

        assert_eq!(
            spork_v1.verify_with_policy(&classical_pub, &SporkAuthPolicy::ClassicalOnly),
            Ok(SporkAuthKind::ClassicalV1)
        );
        let opt_policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
        };
        assert_eq!(
            spork_v1.verify_with_policy(&classical_pub, &opt_policy),
            Ok(SporkAuthKind::ClassicalV1)
        );
        assert!(spork_v1.signature_is_valid(&classical_pub));
    }

    #[test]
    fn s11_spork_reheaded_signature_matches_cpp_recover_compact() {
        // Full-caller check: SporkMessage::verify_with_policy must mirror C++
        // CSporkMessage::CheckSignature, which tolerates any compact header byte
        // (RecoverCompact masks it) and compares CKeyIDs. Previously Rust gated on
        // header 31..=34, so a spork relayed by a C++ node with header 39+r was
        // rejected and the honest relaying peer scored 100 (S11).
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();

        let spork = signed(&kp, 10007, "1537971708", 1_700_000_000);
        assert_eq!(spork.signature.len(), CLASSICAL_SPORK_SIG_LEN);
        // honest signer emits a compressed header in 31..=34.
        assert!((31..=34).contains(&spork.signature[0]));
        assert_eq!(
            spork.verify_with_policy(&classical_pub, &SporkAuthPolicy::ClassicalOnly),
            Ok(SporkAuthKind::ClassicalV1)
        );

        // Re-head 31+r -> 39+r: keeps recid ((h-27)&3) and the compressed bit
        // ((h-27)&4); C++ accepts, so Rust must too.
        let mut reheaded = spork.clone();
        reheaded.signature[0] += 8;
        assert_eq!(
            reheaded.verify_with_policy(&classical_pub, &SporkAuthPolicy::ClassicalOnly),
            Ok(SporkAuthKind::ClassicalV1),
            "re-headed 39+r spork must stay valid (S11)"
        );
        assert!(reheaded.signature_is_valid(&classical_pub));

        // Clear the compressed bit (31+r -> 27+r): C++ recovers an uncompressed
        // key whose GetID no longer matches the compressed spork key, so both
        // clients reject.
        let mut uncompressed_hdr = spork.clone();
        uncompressed_hdr.signature[0] -= 4;
        assert_eq!(
            uncompressed_hdr.verify_with_policy(&classical_pub, &SporkAuthPolicy::ClassicalOnly),
            Err(SporkVerifyError::InvalidClassicalSignature),
            "uncompressed-flag header must not match a compressed spork key"
        );

        // A different key still fails.
        let other = divi_crypto::KeyPair::new_random();
        assert_eq!(
            spork.verify_with_policy(
                &other.public_key().to_bytes(),
                &SporkAuthPolicy::ClassicalOnly
            ),
            Err(SporkVerifyError::InvalidClassicalSignature)
        );
    }

    #[test]
    fn dip_pq_2_hybrid_v2_sign_roundtrip_and_verify_all_policies() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let spork_v2 = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1537971708",
            1_800_000_000,
        )
        .unwrap();

        assert_eq!(spork_v2.signature.len(), HYBRID_SPORK_SIG_LEN);
        assert!(spork_v2.is_hybrid_v2());
        assert_eq!(spork_v2.lms_leaf_index(), Some(0));
        assert_eq!(lms_sk.next_leaf_index(), 1);

        // Wire serialize / deserialize round-trip preserves exact 2,577-byte signature
        let wire_bytes = spork_v2.serialize();
        let decoded = SporkMessage::deserialize(&wire_bytes).unwrap();
        assert_eq!(decoded.spork_id, spork_v2.spork_id);
        assert_eq!(decoded.value, spork_v2.value);
        assert_eq!(decoded.time_signed, spork_v2.time_signed);
        assert_eq!(decoded.signature, spork_v2.signature);
        assert_eq!(decoded.hash(), spork_v2.hash());

        // Accepted under ClassicalOnly, HybridOptional, and HybridRequiredAfter
        assert!(decoded.signature_is_valid(&classical_pub));
        assert_eq!(
            decoded.verify_with_policy(&classical_pub, &SporkAuthPolicy::ClassicalOnly),
            Ok(SporkAuthKind::HybridV2LmsUnverified { lms_leaf_q: 0 })
        );
        assert_eq!(
            decoded.verify_with_policy(
                &classical_pub,
                &SporkAuthPolicy::HybridOptional {
                    pq_spork_pubkey: lms_pk,
                    network_magic: MAINNET_MAGIC,
                }
            ),
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q: 0 })
        );
        assert_eq!(
            decoded.verify_with_policy(
                &classical_pub,
                &SporkAuthPolicy::HybridRequiredAfter {
                    pq_spork_pubkey: lms_pk,
                    network_magic: MAINNET_MAGIC,
                    cutoff_time_signed: 1_750_000_000,
                }
            ),
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q: 0 })
        );
    }

    #[cfg(not(feature = "lms-volatile-test-signer"))]
    #[test]
    fn dip_pq_2_lms_signing_refused_but_verification_kept() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        assert!(matches!(
            sign_hybrid_spork_lms(
                kp.secret_key(),
                &mut lms_sk,
                MAINNET_MAGIC,
                10007,
                "1537971708",
                1_800_000_000,
            ),
            Err(SporkVerifyError::LmsSigningUnavailable)
        ));
        let mut spork = signed(&kp, 10015, "5000;100", 1_800_000_000);
        let classical_sig = spork.signature.clone();
        assert!(matches!(
            spork.attach_lms_signature(&mut lms_sk, MAINNET_MAGIC),
            Err(SporkVerifyError::LmsSigningUnavailable)
        ));
        assert_eq!(spork.signature, classical_sig);
        assert_eq!(lms_sk.next_leaf_index(), 0, "no leaf consumed");

        // Hybrid sporks from elsewhere still verify.
        let v2 = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1537971708",
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(
            v2.verify_with_policy(
                &classical_pub,
                &SporkAuthPolicy::HybridOptional {
                    pq_spork_pubkey: lms_pk,
                    network_magic: MAINNET_MAGIC,
                },
            ),
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q: 0 })
        );
    }

    #[test]
    fn dip_pq_2_attach_lms_signature_upgrades_v1_in_place() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let mut spork = signed(&kp, 10015, "5000;100", 1_800_000_000);
        let hash_before = spork.hash();
        let lms_sig = spork
            .attach_lms_signature_volatile(&mut lms_sk, MAINNET_MAGIC)
            .unwrap();
        assert_eq!(lms_sig.len(), PQ_LMS_SPORK_SIG_LEN);
        assert_eq!(spork.signature.len(), HYBRID_SPORK_SIG_LEN);
        // Inventory hash excludes signature so v1 and v2 share the same inventory hash
        assert_eq!(spork.hash(), hash_before);

        assert_eq!(
            spork.verify_with_policy(
                &classical_pub,
                &SporkAuthPolicy::HybridRequiredAfter {
                    pq_spork_pubkey: lms_pk,
                    network_magic: MAINNET_MAGIC,
                    cutoff_time_signed: 1_800_000_000,
                }
            ),
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q: 0 })
        );
    }

    #[test]
    fn dip_pq_2_cutoff_enforcement_boundary() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let cutoff = 1_800_000_000i64;
        let policy = SporkAuthPolicy::HybridRequiredAfter {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
            cutoff_time_signed: cutoff,
        };

        // 1 second before cutoff: 65-byte classical v1 is still accepted
        let pre_cutoff_v1 = signed(&kp, 10007, "1", cutoff - 1);
        assert_eq!(
            pre_cutoff_v1.verify_with_policy(&classical_pub, &policy),
            Ok(SporkAuthKind::ClassicalV1)
        );

        // Exact cutoff boundary (`time_signed == cutoff`): 65-byte v1 is REJECTED
        let at_cutoff_v1 = signed(&kp, 10007, "1", cutoff);
        assert_eq!(
            at_cutoff_v1.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::MissingPostQuantumSignatureAfterCutoff {
                time_signed: cutoff,
                cutoff_time_signed: cutoff,
            })
        );

        // After cutoff (`time_signed > cutoff`): 65-byte v1 is REJECTED
        let post_cutoff_v1 = signed(&kp, 10007, "1", cutoff + 500);
        assert_eq!(
            post_cutoff_v1.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::MissingPostQuantumSignatureAfterCutoff {
                time_signed: cutoff + 500,
                cutoff_time_signed: cutoff,
            })
        );

        // At and after cutoff: 2,577-byte hybrid v2 is ACCEPTED
        let at_cutoff_v2 = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            cutoff,
        )
        .unwrap();
        assert_eq!(
            at_cutoff_v2.verify_with_policy(&classical_pub, &policy),
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q: 0 })
        );
    }

    #[test]
    fn dip_pq_2_rejects_bit_flipped_classical_portion() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let mut spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();
        spork.signature[20] ^= 0x01;

        let policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
        };
        assert_eq!(
            spork.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidClassicalSignature)
        );
        assert!(!spork.signature_is_valid(&classical_pub));
    }

    #[test]
    fn dip_pq_2_rejects_bit_flipped_lms_portion() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let mut spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();
        // Flip 1 bit inside the LMOTS chain hash array of the LMS signature
        spork.signature[CLASSICAL_SPORK_SIG_LEN + 120] ^= 0x04;

        let policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
        };
        assert_eq!(
            spork.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::VerificationFailed
            ))
        );
    }

    #[test]
    fn dip_pq_2_rejects_non_canonical_lms_header_or_reserved_tail() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let base = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();

        // 1. Out-of-bounds leaf index q = 1024
        let mut bad_q = base.clone();
        bad_q.signature[65..69].copy_from_slice(&1024u32.to_be_bytes());
        assert!(!bad_q.signature_is_valid(&classical_pub));

        // 2. Non-zero reserved tail in last 4 bytes [2573..2577]
        let mut bad_tail = base;
        bad_tail.signature[HYBRID_SPORK_SIG_LEN - 1] = 1;
        assert!(!bad_tail.signature_is_valid(&classical_pub));
        let policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
        };
        assert!(matches!(
            bad_tail.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::NonCanonicalSignature { .. }
            ))
        ));
    }

    #[test]
    fn dip_pq_2_rejects_wrong_network_magic() {
        use crate::constants::{MAINNET_MAGIC, TESTNET_MAGIC};
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        // Signed on TESTNET_MAGIC, verified on MAINNET_MAGIC
        let spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            TESTNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();

        let mainnet_policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
        };
        assert_eq!(
            spork.verify_with_policy(&classical_pub, &mainnet_policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::VerificationFailed
            ))
        );
    }

    #[test]
    fn dip_pq_2_rejects_tampered_spork_id_value_or_time_signed() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "100",
            1_800_000_000,
        )
        .unwrap();
        let lms_suffix = spork.lms_signature().unwrap().to_vec();

        let policy = SporkAuthPolicy::HybridRequiredAfter {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
            cutoff_time_signed: 1_750_000_000,
        };

        // Even if an attacker has the classical private key and re-signs a modified spork_id,
        // value, or time_signed while grafting the valid LMS signature, verification MUST fail!
        for (tampered_id, tampered_val, tampered_time) in [
            (10008, "100", 1_800_000_000),
            (10007, "200", 1_800_000_000),
            (10007, "100", 1_800_000_001),
        ] {
            let mut forged = signed(&kp, tampered_id, tampered_val, tampered_time);
            forged.signature.extend_from_slice(&lms_suffix);
            assert_eq!(forged.signature.len(), HYBRID_SPORK_SIG_LEN);
            assert_eq!(
                forged.verify_with_policy(&classical_pub, &policy),
                Err(SporkVerifyError::InvalidPostQuantumSignature(
                    PqError::VerificationFailed
                ))
            );
        }
    }

    #[test]
    fn dip_pq_2_rejects_trailing_or_truncated_signature_lengths() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();

        let policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
        };

        // 2,578 bytes (trailing 0x00 byte)
        let mut trailing = spork.clone();
        trailing.signature.push(0x00);
        assert_eq!(
            trailing.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidSignatureLength(2578))
        );

        // 2,576 bytes (truncated by 1 byte)
        let mut truncated = spork.clone();
        truncated.signature.pop();
        assert_eq!(
            truncated.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidSignatureLength(2576))
        );

        // 66 bytes (classical + 1 extra byte)
        let mut bad66 = signed(&kp, 10007, "1", 1_800_000_000);
        bad66.signature.push(0x00);
        assert_eq!(
            bad66.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidSignatureLength(66))
        );

        // Empty signature
        let mut empty = spork;
        empty.signature.clear();
        assert_eq!(
            empty.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidSignatureLength(0))
        );
    }

    #[test]
    fn dip_pq_2_rejects_classical_signature_substitution_attack() {
        use crate::constants::MAINNET_MAGIC;
        let kp1 = divi_crypto::KeyPair::new_random();
        let kp2 = divi_crypto::KeyPair::new_random();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        // Sign hybrid v2 with kp1 + lms_sk
        let orig = sign_hybrid_spork_lms_volatile(
            kp1.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();

        // Substitute a valid classical signature from kp2 over the exact same (spork_id, value, time_signed)
        // while keeping the original LMS signature suffix. Even against kp2's classical public key,
        // LMS verification MUST fail because payload_hash_256 binds sig_secp256k1[65]!
        let mut substituted = signed(&kp2, 10007, "1", 1_800_000_000);
        substituted
            .signature
            .extend_from_slice(orig.lms_signature().unwrap());

        let policy = SporkAuthPolicy::HybridRequiredAfter {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
            cutoff_time_signed: 1_700_000_000,
        };
        assert_eq!(
            substituted.verify_with_policy(&kp2.public_key().to_bytes(), &policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::VerificationFailed
            ))
        );
    }

    #[tokio::test]
    async fn dip_pq_2_spork_manager_enforces_cutoff_and_tracks_lms_leaves() {
        use crate::constants::MAINNET_MAGIC;
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let cutoff = 1_800_000_000i64;
        let policy = SporkAuthPolicy::HybridRequiredAfter {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
            cutoff_time_signed: cutoff,
        };

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let peers = quiet_peers();
        let manager = SporkManager::with_key_and_policy(
            Arc::clone(&peers),
            Some(classical_pub.clone()),
            policy.clone(),
            Some(db),
        );
        let mut other = test_peer(&peers, 2);

        let enforcement = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;

        // 1. Pre-cutoff v1 spork is accepted and relayed
        let pre_v1 = signed(&kp, enforcement, "100", cutoff - 10);
        manager.handle_spork(1, pre_v1).await;
        assert_eq!(manager.get_spork(enforcement).unwrap().value, "100");
        assert_eq!(manager.last_lms_leaf_index(), None);
        assert!(!received(&mut other).is_empty());

        // 2. Post-cutoff v1 spork is REJECTED (active value stays "100", nothing relayed)
        let post_v1 = signed(&kp, enforcement, "999", cutoff + 10);
        manager.handle_spork(1, post_v1).await;
        assert_eq!(manager.get_spork(enforcement).unwrap().value, "100");
        assert!(received(&mut other).is_empty());

        // 3. Post-cutoff hybrid v2 spork (leaf q=0) is ACCEPTED, stored, and relayed
        let post_v2 = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            enforcement,
            "200",
            cutoff + 20,
        )
        .unwrap();
        manager.handle_spork(1, post_v2).await;
        assert_eq!(manager.get_spork(enforcement).unwrap().value, "200");
        assert_eq!(manager.last_lms_leaf_index(), Some(0));
        assert_eq!(manager.spork_lms_leaf_index(enforcement), Some(0));
        assert!(!received(&mut other).is_empty());

        // 4. Second post-cutoff hybrid v2 spork (leaf q=1) advances tracked leaf index to 1
        let post_v2_next = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            enforcement,
            "300",
            cutoff + 30,
        )
        .unwrap();
        manager.handle_spork(1, post_v2_next).await;
        assert_eq!(manager.get_spork(enforcement).unwrap().value, "300");
        assert_eq!(manager.last_lms_leaf_index(), Some(1));
        assert_eq!(manager.spork_lms_leaf_index(enforcement), Some(1));

        // 5. Restart from ChainDatabase restores the 2,577-byte hybrid spork and leaf index
        drop(manager);
        let db_reopened = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let restored = SporkManager::with_key_and_policy(
            quiet_peers(),
            Some(classical_pub),
            policy,
            Some(db_reopened),
        );
        let loaded = restored.get_spork(enforcement).unwrap();
        assert_eq!(loaded.value, "300");
        assert!(loaded.is_hybrid_v2());
        assert_eq!(restored.last_lms_leaf_index(), Some(1));
    }

    /// F2: under `ClassicalOnly` the `LMS` tail is only framing-checked. A forged tail is still
    /// accepted, as Divi Core accepts it, but it is reported as unverified and its leaf is never
    /// tracked, live or after a restart.
    #[tokio::test]
    async fn dip_pq_2_classical_only_hybrid_spork_lms_is_unverified_and_untracked() {
        use crate::constants::MAINNET_MAGIC;
        use crate::messages::spork_ids::*;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();
        let hybrid_policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
        };
        let id = SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT;

        let mut forged = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            id,
            "100",
            1_800_000_000,
        )
        .unwrap();
        // First LM-OTS chain value: any bytes keep the framing canonical
        forged.signature[CLASSICAL_SPORK_SIG_LEN + 40] ^= 0x01;

        assert!(forged.signature_is_valid(&classical_pub));
        assert_eq!(
            forged.verify_with_policy(&classical_pub, &SporkAuthPolicy::ClassicalOnly),
            Ok(SporkAuthKind::HybridV2LmsUnverified { lms_leaf_q: 0 })
        );
        assert_eq!(
            forged.verify_with_policy(&classical_pub, &hybrid_policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::VerificationFailed
            ))
        );

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let manager = SporkManager::with_key_and_policy(
            quiet_peers(),
            Some(classical_pub.clone()),
            SporkAuthPolicy::ClassicalOnly,
            Some(db),
        );
        manager.handle_spork(1, forged).await;
        assert_eq!(manager.get_spork(id).unwrap().value, "100");
        assert_eq!(manager.last_lms_leaf_index(), None);
        assert_eq!(manager.spork_lms_leaf_index(id), None);
        drop(manager);

        for policy in [SporkAuthPolicy::ClassicalOnly, hybrid_policy] {
            let restored = SporkManager::with_key_and_policy(
                quiet_peers(),
                Some(classical_pub.clone()),
                policy,
                Some(Arc::new(ChainDatabase::open(dir.path()).unwrap())),
            );
            assert_eq!(restored.get_spork(id).unwrap().value, "100");
            assert_eq!(restored.last_lms_leaf_index(), None);
            assert_eq!(restored.spork_lms_leaf_index(id), None);
        }
    }

    #[test]
    fn dip_pq_2_multi_value_hybrid_spork_roundtrip_and_tamper_rejection() {
        use crate::constants::MAINNET_MAGIC;
        use crate::messages::spork_ids::SPORK_14_TX_FEE;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            SPORK_14_TX_FEE,
            "10000;300;100000;20000;50;0",
            1_800_000_000,
        )
        .unwrap();

        let policy = SporkAuthPolicy::HybridRequiredAfter {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
            cutoff_time_signed: 1_800_000_000,
        };
        assert_eq!(
            spork.verify_with_policy(&classical_pub, &policy),
            Ok(SporkAuthKind::HybridV2 { lms_leaf_q: 0 })
        );

        // Re-signing a modified multi-value string with the classical key while keeping the LMS
        // signature must fail LMS verification
        let mut tampered = signed(
            &kp,
            SPORK_14_TX_FEE,
            "10000;300;100000;30000;60;0",
            1_800_000_000,
        );
        tampered
            .signature
            .extend_from_slice(spork.lms_signature().unwrap());
        assert_eq!(
            tampered.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::VerificationFailed
            ))
        );
    }

    #[test]
    fn dip_pq_2_rejects_wrong_lms_pubkey() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();

        let mut wrong_lms_pk = lms_pk;
        wrong_lms_pk[30] ^= 0x55;
        let policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: wrong_lms_pk,
            network_magic: MAINNET_MAGIC,
        };
        assert_eq!(
            spork.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::VerificationFailed
            ))
        );
    }

    #[test]
    fn dip_pq_2_rejects_non_canonical_lms_pubkey_encoding() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let spork = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "1",
            1_800_000_000,
        )
        .unwrap();

        // Non-zero reserved tail in pq_spork_pubkey[56..60]
        let mut bad_pk = lms_pk;
        bad_pk[59] = 0x01;
        let policy = SporkAuthPolicy::HybridOptional {
            pq_spork_pubkey: bad_pk,
            network_magic: MAINNET_MAGIC,
        };
        assert!(matches!(
            spork.verify_with_policy(&classical_pub, &policy),
            Err(SporkVerifyError::InvalidPostQuantumSignature(
                PqError::NonCanonicalPublicKey { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn dip_pq_2_set_auth_policy_transitions_live_manager() {
        use crate::constants::MAINNET_MAGIC;
        let kp = divi_crypto::KeyPair::new_random();
        let classical_pub = kp.public_key().to_bytes();
        let (mut lms_sk, lms_pk) = test_lms_keypair();

        let manager = SporkManager::with_key(quiet_peers(), Some(classical_pub), None);
        assert_eq!(manager.auth_policy(), SporkAuthPolicy::ClassicalOnly);

        let cutoff = 1_800_000_000i64;
        manager.set_auth_policy(SporkAuthPolicy::HybridRequiredAfter {
            pq_spork_pubkey: lms_pk,
            network_magic: MAINNET_MAGIC,
            cutoff_time_signed: cutoff,
        });

        // Post-cutoff v1 spork rejected after live policy transition
        manager
            .handle_spork(1, signed(&kp, 10007, "42", cutoff))
            .await;
        assert!(manager.get_spork(10007).is_none());

        // Post-cutoff v2 spork accepted
        let v2 = sign_hybrid_spork_lms_volatile(
            kp.secret_key(),
            &mut lms_sk,
            MAINNET_MAGIC,
            10007,
            "42",
            cutoff,
        )
        .unwrap();
        manager.handle_spork(1, v2).await;
        assert_eq!(manager.get_spork(10007).unwrap().value, "42");
    }
}
