// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Zcash v5 (NU5+) transparent transactions: serialization, the [ZIP 244] signature digest,
//! and HTLC funding / claim / refund building, signing and self-verification.
//!
//! The digest tree (header / transparent / sapling / orchard digests, combined with
//! personalized BLAKE2b-256) is hand-rolled from the [ZIP 244] spec and validated against the
//! official test vectors in `zip244_vectors.rs` (`tests::zip244_sighash_vectors`), rather than
//! depending on `zcash_primitives` — see `- decisions:` in `docs/plans/swap-poc/status/zec.md`.
//! Sapling/Orchard bundles are always empty here (this backend only ever builds
//! transparent-only transactions), but [`ParsedTx::parse`] still walks a *foreign* tx's
//! Sapling/Orchard byte ranges (opaque, fixed-size-per-record) so it can recompute the txid of
//! an arbitrary spend found by [`crate::ZecBackend::find_spend`].
//!
//! [ZIP 244]: https://zips.z.cash/zip-0244

use secp256k1::{All, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use divi_swap::htlc::{claim_script_sig, push_data, refund_script_sig, REFUND_SEQUENCE};
use divi_swap::{HtlcParams, SwapError};

use crate::address::{htlc_script_pubkey, TransparentAddress};

type Result<T> = std::result::Result<T, SwapError>;

/// NU5 `nVersionGroupId`.
pub const NU5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
/// `nVersion = 5`, with the overwinter high bit set, as serialized in `nVersion` LE32.
pub const V5_VERSION_BYTES: u32 = 0x8000_0005;

/// Outputs below this are uneconomical to spend (same floor as Bitcoin P2PKH dust).
pub const DUST_ZATOSHI: u64 = 294;

// ---- CompactSize -----------------------------------------------------------------------

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend((n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend((n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend(n.to_le_bytes());
    }
}

fn write_script(out: &mut Vec<u8>, script: &[u8]) {
    write_compact_size(out, script.len() as u64);
    out.extend(script);
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or_else(|| SwapError::Other("zec tx: unexpected end of data".into()))?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn compact_size(&mut self) -> Result<u64> {
        let tag = self.take(1)?[0];
        Ok(match tag {
            0..=0xfc => tag as u64,
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64,
            0xfe => u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64,
            0xff => u64::from_le_bytes(self.take(8)?.try_into().unwrap()),
        })
    }

    fn script(&mut self) -> Result<Vec<u8>> {
        let len = self.compact_size()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
}

// ---- Transparent tx parts ---------------------------------------------------------------

/// A transparent output reference, internal (not reversed) txid byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutPoint {
    /// The previous transaction's id.
    pub txid: [u8; 32],
    /// Output index.
    pub n: u32,
}

impl OutPoint {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.txid);
        out.extend(self.n.to_le_bytes());
    }
}

/// A transparent input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// The output being spent.
    pub prevout: OutPoint,
    /// Unlocking script.
    pub script_sig: Vec<u8>,
    /// `nSequence`.
    pub sequence: u32,
}

impl TxIn {
    fn write(&self, out: &mut Vec<u8>) {
        self.prevout.write(out);
        write_script(out, &self.script_sig);
        out.extend(self.sequence.to_le_bytes());
    }
}

/// A transparent output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// Value in zatoshi.
    pub value: u64,
    /// Locking script.
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.value.to_le_bytes());
        write_script(out, &self.script_pubkey);
    }
}

// ---- ZIP 244 digest tree ----------------------------------------------------------------

fn blake2b_person(person: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(person)
        .to_state();
    for p in parts {
        state.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

fn empty_digest(person: &[u8; 16]) -> [u8; 32] {
    blake2b_person(person, &[])
}

const PERS_HEADERS: &[u8; 16] = b"ZTxIdHeadersHash";
const PERS_TRANSPARENT: &[u8; 16] = b"ZTxIdTranspaHash";
const PERS_PREVOUTS: &[u8; 16] = b"ZTxIdPrevoutHash";
const PERS_SEQUENCE: &[u8; 16] = b"ZTxIdSequencHash";
const PERS_OUTPUTS: &[u8; 16] = b"ZTxIdOutputsHash";
const PERS_SAPLING: &[u8; 16] = b"ZTxIdSaplingHash";
const PERS_S_SPENDS: &[u8; 16] = b"ZTxIdSSpendsHash";
const PERS_S_SPENDS_C: &[u8; 16] = b"ZTxIdSSpendCHash";
const PERS_S_SPENDS_N: &[u8; 16] = b"ZTxIdSSpendNHash";
const PERS_S_OUT: &[u8; 16] = b"ZTxIdSOutputHash";
const PERS_S_OUT_C: &[u8; 16] = b"ZTxIdSOutC__Hash";
const PERS_S_OUT_M: &[u8; 16] = b"ZTxIdSOutM__Hash";
const PERS_S_OUT_N: &[u8; 16] = b"ZTxIdSOutN__Hash";
const PERS_ORCHARD: &[u8; 16] = b"ZTxIdOrchardHash";
const PERS_O_ACT_C: &[u8; 16] = b"ZTxIdOrcActCHash";
const PERS_O_ACT_M: &[u8; 16] = b"ZTxIdOrcActMHash";
const PERS_O_ACT_N: &[u8; 16] = b"ZTxIdOrcActNHash";
const PERS_AMOUNTS: &[u8; 16] = b"ZTxTrAmountsHash";
const PERS_SCRIPTS: &[u8; 16] = b"ZTxTrScriptsHash";
const PERS_TXIN: &[u8; 16] = b"Zcash___TxInHash";
const PERS_TXID_PREFIX: &[u8; 12] = b"ZcashTxHash_";

/// T.1: header digest.
fn header_digest(
    version_bytes: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    lock_time: u32,
    expiry_height: u32,
) -> [u8; 32] {
    blake2b_person(
        PERS_HEADERS,
        &[
            &version_bytes.to_le_bytes(),
            &version_group_id.to_le_bytes(),
            &consensus_branch_id.to_le_bytes(),
            &lock_time.to_le_bytes(),
            &expiry_height.to_le_bytes(),
        ],
    )
}

fn prevouts_digest(vin: &[TxIn]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(vin.len() * 36);
    for i in vin {
        i.prevout.write(&mut buf);
    }
    blake2b_person(PERS_PREVOUTS, &[&buf])
}

fn sequence_digest(vin: &[TxIn]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(vin.len() * 4);
    for i in vin {
        buf.extend(i.sequence.to_le_bytes());
    }
    blake2b_person(PERS_SEQUENCE, &[&buf])
}

fn outputs_digest(vout: &[TxOut]) -> [u8; 32] {
    let mut buf = Vec::new();
    for o in vout {
        o.write(&mut buf);
    }
    blake2b_person(PERS_OUTPUTS, &[&buf])
}

/// T.2: transparent digest.
fn transparent_digest(vin: &[TxIn], vout: &[TxOut]) -> [u8; 32] {
    if vin.is_empty() && vout.is_empty() {
        return empty_digest(PERS_TRANSPARENT);
    }
    let p = prevouts_digest(vin);
    let s = sequence_digest(vin);
    let o = outputs_digest(vout);
    blake2b_person(PERS_TRANSPARENT, &[&p, &s, &o])
}

/// Coinbase per the consensus definition: one input, null prevout.
fn is_coinbase(vin: &[TxIn]) -> bool {
    vin.len() == 1 && vin[0].prevout.txid == [0u8; 32] && vin[0].prevout.n == 0xffff_ffff
}

/// T.3 / T.4 digests of a Sapling or Orchard bundle, given the raw per-record byte blobs
/// already sliced out by [`ParsedTx::parse`]. Empty inputs mean "bundle absent" per spec.
struct ShieldedDigests;

impl ShieldedDigests {
    /// `spends`: each entry is the 96-byte `cv(32) || nullifier(32) || rk(32)` v5 spend
    /// record. `anchor`: the single shared Sapling anchor (only meaningful if non-empty).
    fn sapling(
        spends: &[[u8; 96]],
        anchor: [u8; 32],
        outputs: &[[u8; 756]],
        value_balance: i64,
    ) -> [u8; 32] {
        if spends.is_empty() && outputs.is_empty() {
            return empty_digest(PERS_SAPLING);
        }
        let spends_digest = if spends.is_empty() {
            empty_digest(PERS_S_SPENDS)
        } else {
            let mut compact = Vec::new();
            let mut noncompact = Vec::new();
            for s in spends {
                compact.extend(&s[32..64]); // nullifier
                noncompact.extend(&s[0..32]); // cv
                noncompact.extend(anchor);
                noncompact.extend(&s[64..96]); // rk
            }
            let c = blake2b_person(PERS_S_SPENDS_C, &[&compact]);
            let n = blake2b_person(PERS_S_SPENDS_N, &[&noncompact]);
            blake2b_person(PERS_S_SPENDS, &[&c, &n])
        };
        let outputs_digest = if outputs.is_empty() {
            empty_digest(PERS_S_OUT)
        } else {
            let mut compact = Vec::new();
            let mut memos = Vec::new();
            let mut noncompact = Vec::new();
            for o in outputs {
                // layout: cv(32) cmu(32) ephemeralKey(32) encCiphertext(580) outCipherText(80)
                compact.extend(&o[32..64]); // cmu
                compact.extend(&o[64..96]); // ephemeralKey
                compact.extend(&o[96..148]); // encCiphertext[0..52]
                memos.extend(&o[148..660]); // encCiphertext[52..564]
                noncompact.extend(&o[0..32]); // cv
                noncompact.extend(&o[660..676]); // encCiphertext[564..580]
                noncompact.extend(&o[676..756]); // outCipherText
            }
            let c = blake2b_person(PERS_S_OUT_C, &[&compact]);
            let m = blake2b_person(PERS_S_OUT_M, &[&memos]);
            let n = blake2b_person(PERS_S_OUT_N, &[&noncompact]);
            blake2b_person(PERS_S_OUT, &[&c, &m, &n])
        };
        blake2b_person(
            PERS_SAPLING,
            &[
                &spends_digest,
                &outputs_digest,
                &value_balance.to_le_bytes(),
            ],
        )
    }

    /// `actions`: each entry is the 820-byte `cv(32) nullifier(32) rk(32) cmx(32)
    /// ephemeralKey(32) encCiphertext(580) outCiphertext(80)` v5 action record.
    fn orchard(actions: &[[u8; 820]], flags: u8, value_balance: i64, anchor: [u8; 32]) -> [u8; 32] {
        if actions.is_empty() {
            return empty_digest(PERS_ORCHARD);
        }
        let mut compact = Vec::new();
        let mut memos = Vec::new();
        let mut noncompact = Vec::new();
        for a in actions {
            // layout: cv(32) nullifier(32) rk(32) cmx(32) ephemeralKey(32) encCiphertext(580) outCiphertext(80)
            compact.extend(&a[32..64]); // nullifier
            compact.extend(&a[96..128]); // cmx
            compact.extend(&a[128..160]); // ephemeralKey
            compact.extend(&a[160..212]); // encCiphertext[0..52]
            memos.extend(&a[212..724]); // encCiphertext[52..564]
            noncompact.extend(&a[0..32]); // cv
            noncompact.extend(&a[64..96]); // rk
            noncompact.extend(&a[724..740]); // encCiphertext[564..580]
            noncompact.extend(&a[740..820]); // outCiphertext
        }
        let c = blake2b_person(PERS_O_ACT_C, &[&compact]);
        let m = blake2b_person(PERS_O_ACT_M, &[&memos]);
        let n = blake2b_person(PERS_O_ACT_N, &[&noncompact]);
        blake2b_person(
            PERS_ORCHARD,
            &[&c, &m, &n, &[flags], &value_balance.to_le_bytes(), &anchor],
        )
    }
}

fn txid_personalization(consensus_branch_id: u32) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..12].copy_from_slice(PERS_TXID_PREFIX);
    p[12..].copy_from_slice(&consensus_branch_id.to_le_bytes());
    p
}

fn combine_txid(
    header: [u8; 32],
    transparent: [u8; 32],
    sapling: [u8; 32],
    orchard: [u8; 32],
    consensus_branch_id: u32,
) -> [u8; 32] {
    blake2b_person(
        &txid_personalization(consensus_branch_id),
        &[&header, &transparent, &sapling, &orchard],
    )
}

/// One transparent input being signed: its previous output's value and `scriptCode`
/// (the redeem script for a P2SH spend, the plain `scriptPubKey` for a P2PKH spend).
#[derive(Debug, Clone)]
pub struct SigInput {
    /// Value of the output this input spends, in zatoshi.
    pub value: u64,
    /// The script committed to by this input's signature.
    pub script_code: Vec<u8>,
}

/// S.2: the transparent part of the signature digest for signing/verifying input
/// `signed_index` (`None` for the shielded-signing variant, which never applies here).
#[allow(clippy::too_many_arguments)]
fn transparent_sig_digest(
    vin: &[TxIn],
    vout: &[TxOut],
    hash_type: u8,
    signed_index: Option<usize>,
    sig_inputs: &[SigInput],
) -> [u8; 32] {
    if is_coinbase(vin) || vin.is_empty() {
        return transparent_digest(vin, vout);
    }
    const ANYONECANPAY: u8 = 0x80;
    const SIGHASH_SINGLE: u8 = 0x03;
    const SIGHASH_NONE: u8 = 0x02;
    let anyone = hash_type & ANYONECANPAY != 0;
    let base = hash_type & 0x1f;

    let prevouts = if anyone {
        empty_digest(PERS_PREVOUTS)
    } else {
        prevouts_digest(vin)
    };
    let amounts = if anyone {
        empty_digest(PERS_AMOUNTS)
    } else {
        let mut buf = Vec::new();
        for s in sig_inputs {
            buf.extend(s.value.to_le_bytes());
        }
        blake2b_person(PERS_AMOUNTS, &[&buf])
    };
    let scripts = if anyone {
        empty_digest(PERS_SCRIPTS)
    } else {
        let mut buf = Vec::new();
        for s in sig_inputs {
            write_script(&mut buf, &s.script_code);
        }
        blake2b_person(PERS_SCRIPTS, &[&buf])
    };
    let sequence = if anyone {
        empty_digest(PERS_SEQUENCE)
    } else {
        sequence_digest(vin)
    };
    let outputs = if base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        outputs_digest(vout)
    } else if base == SIGHASH_SINGLE && signed_index.is_some_and(|i| i < vout.len()) {
        let mut buf = Vec::new();
        vout[signed_index.unwrap()].write(&mut buf);
        blake2b_person(PERS_OUTPUTS, &[&buf])
    } else {
        empty_digest(PERS_OUTPUTS)
    };
    let txin = match signed_index {
        Some(i) => {
            let mut buf = Vec::new();
            vin[i].prevout.write(&mut buf);
            buf.extend(sig_inputs[i].value.to_le_bytes());
            write_script(&mut buf, &sig_inputs[i].script_code);
            buf.extend(vin[i].sequence.to_le_bytes());
            blake2b_person(PERS_TXIN, &[&buf])
        }
        None => empty_digest(PERS_TXIN),
    };

    blake2b_person(
        PERS_TRANSPARENT,
        &[
            &[hash_type],
            &prevouts,
            &amounts,
            &scripts,
            &sequence,
            &outputs,
            &txin,
        ],
    )
}

/// S.2 / T.3: the full ZIP-244 signature digest (equal to the txid digest when
/// `signed_index` is `None` and `hash_type` is `SIGHASH_ALL`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn signature_digest(
    header: [u8; 32],
    consensus_branch_id: u32,
    vin: &[TxIn],
    vout: &[TxOut],
    hash_type: u8,
    signed_index: Option<usize>,
    sig_inputs: &[SigInput],
    sapling_digest: [u8; 32],
    orchard_digest: [u8; 32],
) -> [u8; 32] {
    let transparent = transparent_sig_digest(vin, vout, hash_type, signed_index, sig_inputs);
    blake2b_person(
        &txid_personalization(consensus_branch_id),
        &[&header, &transparent, &sapling_digest, &orchard_digest],
    )
}

pub(crate) const SIGHASH_ALL: u8 = 0x01;

// ---- A transparent-only v5 transaction we build ourselves --------------------------------

/// A Zcash v5 transaction with an empty Sapling bundle and an empty Orchard bundle: every
/// transaction this backend ever builds (funding, claim, refund).
#[derive(Debug, Clone)]
pub struct ZecTx {
    /// Read from the chain at build time (never hard-coded — brief, lane zec).
    pub consensus_branch_id: u32,
    /// `nLockTime`.
    pub lock_time: u32,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// Transparent inputs.
    pub vin: Vec<TxIn>,
    /// Transparent outputs.
    pub vout: Vec<TxOut>,
}

impl ZecTx {
    /// Full consensus serialization.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(V5_VERSION_BYTES.to_le_bytes());
        out.extend(NU5_VERSION_GROUP_ID.to_le_bytes());
        out.extend(self.consensus_branch_id.to_le_bytes());
        out.extend(self.lock_time.to_le_bytes());
        out.extend(self.expiry_height.to_le_bytes());
        write_compact_size(&mut out, self.vin.len() as u64);
        for i in &self.vin {
            i.write(&mut out);
        }
        write_compact_size(&mut out, self.vout.len() as u64);
        for o in &self.vout {
            o.write(&mut out);
        }
        out.push(0); // nSpendsSapling = 0
        out.push(0); // nOutputsSapling = 0
        out.push(0); // nActionsOrchard = 0
        out
    }

    fn header_digest(&self) -> [u8; 32] {
        header_digest(
            V5_VERSION_BYTES,
            NU5_VERSION_GROUP_ID,
            self.consensus_branch_id,
            self.lock_time,
            self.expiry_height,
        )
    }

    /// The transaction id.
    pub fn txid(&self) -> [u8; 32] {
        combine_txid(
            self.header_digest(),
            transparent_digest(&self.vin, &self.vout),
            empty_digest(PERS_SAPLING),
            empty_digest(PERS_ORCHARD),
            self.consensus_branch_id,
        )
    }

    /// The `SIGHASH_ALL` digest for signing/verifying input `index`. `sig_inputs` has one
    /// entry per `vin`, in order (value + scriptCode of the output each input spends).
    pub fn signature_digest(&self, index: usize, sig_inputs: &[SigInput]) -> [u8; 32] {
        signature_digest(
            self.header_digest(),
            self.consensus_branch_id,
            &self.vin,
            &self.vout,
            SIGHASH_ALL,
            Some(index),
            sig_inputs,
            empty_digest(PERS_SAPLING),
            empty_digest(PERS_ORCHARD),
        )
    }
}

/// A transaction read off the chain (ours or a counterparty's): fully parsed transparent
/// parts, Sapling/Orchard bundles reduced to their digests (we never need their content, only
/// whether the txid matches).
#[derive(Debug, Clone)]
pub struct ParsedTx {
    /// See [`ZecTx`].
    pub consensus_branch_id: u32,
    /// `nLockTime`.
    pub lock_time: u32,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// Transparent inputs, with their scriptSig.
    pub vin: Vec<TxIn>,
    /// Transparent outputs.
    pub vout: Vec<TxOut>,
    sapling_digest: [u8; 32],
    orchard_digest: [u8; 32],
}

impl ParsedTx {
    /// Parse a v5 (NU5+) transaction. Older (pre-NU5) versions are rejected: this backend
    /// only ever deals with transactions at or after NU5 activation.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let version_bytes = r.u32()?;
        if version_bytes != V5_VERSION_BYTES {
            return Err(SwapError::Other(format!(
                "zec tx: unsupported version bytes {version_bytes:#x} (want v5 NU5+)"
            )));
        }
        let version_group_id = r.u32()?;
        if version_group_id != NU5_VERSION_GROUP_ID {
            return Err(SwapError::Other(format!(
                "zec tx: unexpected version group id {version_group_id:#x}"
            )));
        }
        let consensus_branch_id = r.u32()?;
        let lock_time = r.u32()?;
        let expiry_height = r.u32()?;

        let nvin = r.compact_size()?;
        let mut vin = Vec::with_capacity(nvin as usize);
        for _ in 0..nvin {
            let txid: [u8; 32] = r.take(32)?.try_into().unwrap();
            let n = r.u32()?;
            let script_sig = r.script()?;
            let sequence = r.u32()?;
            vin.push(TxIn {
                prevout: OutPoint { txid, n },
                script_sig,
                sequence,
            });
        }

        let nvout = r.compact_size()?;
        let mut vout = Vec::with_capacity(nvout as usize);
        for _ in 0..nvout {
            let value = r.u64()?;
            let script_pubkey = r.script()?;
            vout.push(TxOut {
                value,
                script_pubkey,
            });
        }

        // Sapling: nSpendsSapling spend records (96 bytes each: cv|nullifier|rk), then
        // nOutputsSapling output records (756 bytes each), then valueBalance if either is
        // non-empty, then (if spends>0) the shared anchor + per-spend proofs(192)/sigs(64),
        // then per-output proofs(192) unconditionally, then (if either non-empty) bindingSig(64).
        let nspends = r.compact_size()? as usize;
        let mut spend_blobs = Vec::with_capacity(nspends);
        for _ in 0..nspends {
            spend_blobs.push(<[u8; 96]>::try_from(r.take(96)?).unwrap());
        }
        let noutputs = r.compact_size()? as usize;
        let mut output_blobs = Vec::with_capacity(noutputs);
        for _ in 0..noutputs {
            output_blobs.push(<[u8; 756]>::try_from(r.take(756)?).unwrap());
        }
        let has_sapling = nspends + noutputs > 0;
        let value_balance_sapling = if has_sapling { r.u64()? as i64 } else { 0 };
        let anchor = if nspends > 0 {
            let a: [u8; 32] = r.take(32)?.try_into().unwrap();
            r.take(192 * nspends)?; // spend proofs
            r.take(64 * nspends)?; // spend auth sigs
            a
        } else {
            [0u8; 32]
        };
        r.take(192 * noutputs)?; // output proofs (unconditional)
        if has_sapling {
            r.take(64)?; // binding sig
        }
        let sapling_digest =
            ShieldedDigests::sapling(&spend_blobs, anchor, &output_blobs, value_balance_sapling);

        // Orchard: nActionsOrchard action records (820 bytes each), then (if any) flags(1),
        // valueBalance(8), anchor(32), proofs (CompactSize-prefixed), per-action sigs(64),
        // binding sig(64).
        let nactions = r.compact_size()? as usize;
        let mut action_blobs = Vec::with_capacity(nactions);
        for _ in 0..nactions {
            action_blobs.push(<[u8; 820]>::try_from(r.take(820)?).unwrap());
        }
        let orchard_digest = if nactions > 0 {
            let flags = r.take(1)?[0];
            let value_balance = r.u64()? as i64;
            let o_anchor: [u8; 32] = r.take(32)?.try_into().unwrap();
            let proof_len = r.compact_size()? as usize;
            r.take(proof_len)?;
            r.take(64 * nactions)?; // per-action spend auth sigs
            r.take(64)?; // binding sig
            ShieldedDigests::orchard(&action_blobs, flags, value_balance, o_anchor)
        } else {
            empty_digest(PERS_ORCHARD)
        };

        if r.remaining() != 0 {
            return Err(SwapError::Other(format!(
                "zec tx: {} trailing byte(s) after parsing",
                r.remaining()
            )));
        }

        Ok(ParsedTx {
            consensus_branch_id,
            lock_time,
            expiry_height,
            vin,
            vout,
            sapling_digest,
            orchard_digest,
        })
    }

    /// The transaction id.
    pub fn txid(&self) -> [u8; 32] {
        let header = header_digest(
            V5_VERSION_BYTES,
            NU5_VERSION_GROUP_ID,
            self.consensus_branch_id,
            self.lock_time,
            self.expiry_height,
        );
        combine_txid(
            header,
            transparent_digest(&self.vin, &self.vout),
            self.sapling_digest,
            self.orchard_digest,
            self.consensus_branch_id,
        )
    }
}

// ---- HTLC funding / claim / refund -------------------------------------------------------

/// A spendable P2PKH coin of the engine key, as returned by `GetAddressUtxos`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    /// The coin.
    pub outpoint: OutPoint,
    /// Value in zatoshi.
    pub value: u64,
    /// The P2PKH `scriptPubKey` this coin pays (the scriptCode for signing it).
    pub script_pubkey: Vec<u8>,
}

/// Result of a funding build.
#[derive(Debug, Clone)]
pub struct BuiltFunding {
    /// Signed transaction.
    pub tx: ZecTx,
    /// Index of the HTLC output.
    pub htlc_vout: u32,
    /// Fee paid, zatoshi.
    pub fee: u64,
}

fn ceil_fee(zats_per_byte: u64, size: usize) -> u64 {
    zats_per_byte.max(1) * size as u64
}

/// Placeholder DER signature length used to size a probe transaction before signing (71-72
/// bytes is the real range; 72 never undersizes).
const DUMMY_SIG_LEN: usize = 72;

fn p2pkh_script_sig(sig: &[u8], pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::new();
    push_data(&mut s, sig);
    push_data(&mut s, pubkey);
    s
}

fn ecdsa_sign_all(secp: &Secp256k1<All>, sk: &SecretKey, digest: &[u8; 32]) -> Vec<u8> {
    let sig = secp.sign_ecdsa(&Message::from_digest(*digest), sk);
    let mut der = sig.serialize_der().to_vec();
    der.push(SIGHASH_ALL);
    der
}

/// Select coins (largest first), pay `amount` to the HTLC, send change to `pubkey`'s P2PKH
/// address, and sign every input.
#[allow(clippy::too_many_arguments)]
pub fn build_funding_tx(
    secp: &Secp256k1<All>,
    sk: &SecretKey,
    pubkey: &[u8; 33],
    coins: &[Coin],
    htlc: &HtlcParams,
    amount: u64,
    consensus_branch_id: u32,
    zats_per_byte: u64,
) -> Result<BuiltFunding> {
    htlc.validate()?;
    if amount < DUST_ZATOSHI {
        return Err(SwapError::InvalidParams(format!("amount {amount} is dust")));
    }
    let my_spk = TransparentAddress::p2pkh(pubkey).script_pubkey();
    let mut sorted = coins.to_vec();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.value));

    let htlc_spk = htlc_script_pubkey(&htlc.redeem_script());
    let mut chosen: Vec<Coin> = Vec::new();
    let mut total = 0u64;
    let mut needed = 0u64;
    for c in sorted {
        chosen.push(c);
        total += chosen.last().unwrap().value;
        let probe_size = funding_probe_size(&chosen, &htlc_spk, amount, Some(0), &my_spk);
        needed = amount + ceil_fee(zats_per_byte, probe_size);
        if total >= needed {
            break;
        }
    }
    if total < needed {
        return Err(SwapError::InsufficientFunds(format!(
            "have {total} zatoshi, need {needed} (amount {amount} + fee)"
        )));
    }

    let fee_with_change = needed - amount;
    let change = total - needed;
    let (change_opt, fee) = if change >= DUST_ZATOSHI {
        (Some(change), fee_with_change)
    } else {
        (None, total - amount)
    };

    let mut vout = vec![TxOut {
        value: amount,
        script_pubkey: htlc_spk,
    }];
    if let Some(c) = change_opt {
        vout.push(TxOut {
            value: c,
            script_pubkey: my_spk,
        });
    }
    let vin: Vec<TxIn> = chosen
        .iter()
        .map(|c| TxIn {
            prevout: c.outpoint,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        })
        .collect();
    let mut tx = ZecTx {
        consensus_branch_id,
        lock_time: 0,
        expiry_height: 0,
        vin,
        vout,
    };

    let sig_inputs: Vec<SigInput> = chosen
        .iter()
        .map(|c| SigInput {
            value: c.value,
            script_code: c.script_pubkey.clone(),
        })
        .collect();
    for i in 0..chosen.len() {
        let digest = tx.signature_digest(i, &sig_inputs);
        let sig = ecdsa_sign_all(secp, sk, &digest);
        tx.vin[i].script_sig = p2pkh_script_sig(&sig, pubkey);
    }

    Ok(BuiltFunding {
        tx,
        htlc_vout: 0,
        fee,
    })
}

/// Serialized size of a funding tx with dummy (but correctly-sized) P2PKH scriptSigs.
fn funding_probe_size(
    chosen: &[Coin],
    htlc_spk: &[u8],
    amount: u64,
    change: Option<u64>,
    my_spk: &[u8],
) -> usize {
    let dummy_sig = vec![0u8; DUMMY_SIG_LEN];
    let dummy_pubkey = [0u8; 33];
    let dummy_script_sig = p2pkh_script_sig(&dummy_sig, &dummy_pubkey);
    let mut vout = vec![TxOut {
        value: amount,
        script_pubkey: htlc_spk.to_vec(),
    }];
    if let Some(c) = change {
        vout.push(TxOut {
            value: c,
            script_pubkey: my_spk.to_vec(),
        });
    }
    let probe = ZecTx {
        consensus_branch_id: 0,
        lock_time: 0,
        expiry_height: 0,
        vin: chosen
            .iter()
            .map(|c| TxIn {
                prevout: c.outpoint,
                script_sig: dummy_script_sig.clone(),
                sequence: 0xffff_ffff,
            })
            .collect(),
        vout,
    };
    probe.serialize().len()
}

/// Which spend path to build.
#[derive(Debug, Clone, Copy)]
pub enum Spend<'a> {
    /// Claim with the preimage.
    Claim(&'a [u8; 32]),
    /// Refund after the locktime.
    Refund,
}

/// Build, sign and self-verify a claim or refund of the HTLC output `at` (`amount` zatoshi),
/// paying `amount − fee` to `pubkey`'s own P2PKH address.
#[allow(clippy::too_many_arguments)]
pub fn build_spend_tx(
    secp: &Secp256k1<All>,
    sk: &SecretKey,
    pubkey: &[u8; 33],
    htlc: &HtlcParams,
    at: OutPoint,
    amount: u64,
    spend: Spend<'_>,
    consensus_branch_id: u32,
    zats_per_byte: u64,
) -> Result<ZecTx> {
    htlc.validate()?;
    let (expected, role) = match spend {
        Spend::Claim(_) => (htlc.claim_pubkey, "claim"),
        Spend::Refund => (htlc.refund_pubkey, "refund"),
    };
    if *pubkey != expected {
        return Err(SwapError::InvalidParams(format!(
            "backend key is not the HTLC {role} key"
        )));
    }
    if let Spend::Claim(pre) = spend {
        let h: [u8; 32] = Sha256::digest(pre).into();
        if h != htlc.hash {
            return Err(SwapError::InvalidParams(
                "preimage does not hash to the HTLC hash".into(),
            ));
        }
    }
    let redeem = htlc.redeem_script();
    let (lock_time, sequence) = match spend {
        Spend::Claim(_) => (0, 0xffff_ffff),
        Spend::Refund => (htlc.locktime, REFUND_SEQUENCE),
    };
    let my_spk = TransparentAddress::p2pkh(pubkey).script_pubkey();
    let script_sig_for = |sig: Vec<u8>| match spend {
        Spend::Claim(pre) => claim_script_sig(&sig, pre, &redeem),
        Spend::Refund => refund_script_sig(&sig, &redeem),
    };

    let dummy_script_sig = script_sig_for(vec![0u8; DUMMY_SIG_LEN]);
    let probe = ZecTx {
        consensus_branch_id,
        lock_time,
        expiry_height: 0,
        vin: vec![TxIn {
            prevout: at,
            script_sig: dummy_script_sig,
            sequence,
        }],
        vout: vec![TxOut {
            value: amount,
            script_pubkey: my_spk.clone(),
        }],
    };
    let fee = ceil_fee(zats_per_byte, probe.serialize().len());
    let out_value = amount.checked_sub(fee).filter(|v| *v >= DUST_ZATOSHI);
    let out_value = out_value.ok_or_else(|| {
        SwapError::InsufficientFunds(format!("HTLC value {amount} does not cover fee {fee}"))
    })?;

    let mut tx = ZecTx {
        consensus_branch_id,
        lock_time,
        expiry_height: 0,
        vin: vec![TxIn {
            prevout: at,
            script_sig: Vec::new(),
            sequence,
        }],
        vout: vec![TxOut {
            value: out_value,
            script_pubkey: my_spk,
        }],
    };
    let sig_inputs = [SigInput {
        value: amount,
        script_code: redeem.clone(),
    }];
    let digest = tx.signature_digest(0, &sig_inputs);
    let sig = ecdsa_sign_all(secp, sk, &digest);
    tx.vin[0].script_sig = script_sig_for(sig);

    verify_htlc_spend(&tx, 0, &sig_inputs, &redeem)?;
    Ok(tx)
}

/// Run Zcash's transparent script interpreter over input `index` of `tx` against the HTLC's
/// P2SH output, with our own [ZIP 244] digest supplied as the signed message.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244
pub fn verify_htlc_spend(
    tx: &ZecTx,
    index: usize,
    sig_inputs: &[SigInput],
    redeem_script: &[u8],
) -> Result<()> {
    use zcash_script::interpreter::{CallbackTransactionSignatureChecker, Flags};
    use zcash_script::script::Raw;
    use zcash_script::signature::{HashType, SignedOutputs};

    let pub_key_script = htlc_script_pubkey(redeem_script);
    let raw = Raw::from_raw_parts(tx.vin[index].script_sig.clone(), pub_key_script);
    let tx_for_sighash = tx.clone();
    let sig_inputs_owned = sig_inputs.to_vec();
    let sighash = move |_script_code: &zcash_script::script::Code,
                        hash_type: &HashType|
          -> Option<[u8; 32]> {
        let base: u8 = match hash_type.signed_outputs() {
            SignedOutputs::All => 1,
            SignedOutputs::None => 2,
            SignedOutputs::Single => 3,
        };
        let byte = base | if hash_type.anyone_can_pay() { 0x80 } else { 0 };
        if byte != SIGHASH_ALL {
            return None;
        }
        Some(tx_for_sighash.signature_digest(index, &sig_inputs_owned))
    };
    let checker = CallbackTransactionSignatureChecker {
        sighash: &sighash,
        lock_time: tx.lock_time as i64,
        is_final: tx.vin[index].sequence == 0xffff_ffff,
    };
    let flags = Flags::P2SH
        | Flags::StrictEnc
        | Flags::LowS
        | Flags::NullDummy
        | Flags::MinimalData
        | Flags::CHECKLOCKTIMEVERIFY;
    match raw.eval(flags, &checker) {
        Ok(true) => Ok(()),
        Ok(false) => Err(SwapError::Rejected(
            "htlc spend fails script evaluation".into(),
        )),
        Err((component, e)) => Err(SwapError::Rejected(format!(
            "htlc spend fails script evaluation in {component:?}: {e:?}"
        ))),
    }
}

#[cfg(test)]
#[path = "zip244_vectors.rs"]
mod zip244_vectors;

#[cfg(test)]
mod tests {
    use secp256k1::Secp256k1;

    use divi_swap::htlc::new_preimage;

    use super::zip244_vectors::VECTORS;
    use super::*;

    /// The vectors JSON renders 32-byte values reversed ("zcash-flavoured" display order,
    /// `zcash_test_vectors/output.py` `tv_value_json`); our digests are in protocol order.
    fn hex32(s: &str) -> [u8; 32] {
        let mut b: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        b.reverse();
        b
    }

    /// Validate the hand-rolled digest tree against every official ZIP-244 test vector:
    /// https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/zip_0244.py
    #[test]
    fn zip244_sighash_vectors() {
        for (i, v) in VECTORS.iter().enumerate() {
            let raw = hex::decode(v.tx).unwrap();
            let parsed = ParsedTx::parse(&raw).unwrap_or_else(|e| panic!("vector {i}: {e}"));
            assert_eq!(parsed.txid(), hex32(v.txid), "vector {i}: txid");

            let header = header_digest(
                V5_VERSION_BYTES,
                NU5_VERSION_GROUP_ID,
                parsed.consensus_branch_id,
                parsed.lock_time,
                parsed.expiry_height,
            );
            let sig_inputs: Vec<SigInput> = v
                .amounts
                .iter()
                .zip(v.script_pubkeys.iter())
                .map(|(a, spk)| SigInput {
                    value: *a as u64,
                    script_code: hex::decode(spk).unwrap(),
                })
                .collect();

            let shielded = signature_digest(
                header,
                parsed.consensus_branch_id,
                &parsed.vin,
                &parsed.vout,
                SIGHASH_ALL,
                None,
                &sig_inputs,
                parsed.sapling_digest,
                parsed.orchard_digest,
            );
            assert_eq!(
                shielded,
                hex32(v.sighash_shielded),
                "vector {i}: sighash_shielded"
            );

            if let Some(idx) = v.transparent_input {
                let idx = idx as usize;
                for (hash_type, expected) in [
                    (0x01u8, v.sighash_all),
                    (0x02, v.sighash_none),
                    (0x03, v.sighash_single),
                    (0x81, v.sighash_all_anyone),
                    (0x82, v.sighash_none_anyone),
                    (0x83, v.sighash_single_anyone),
                ] {
                    let Some(exp) = expected else { continue };
                    let got = signature_digest(
                        header,
                        parsed.consensus_branch_id,
                        &parsed.vin,
                        &parsed.vout,
                        hash_type,
                        Some(idx),
                        &sig_inputs,
                        parsed.sapling_digest,
                        parsed.orchard_digest,
                    );
                    assert_eq!(got, hex32(exp), "vector {i}: hash_type {hash_type:#x}");
                }
            }
        }
    }

    const MAKER_KEY: [u8; 32] = [0x11; 32];
    const TAKER_KEY: [u8; 32] = [0x22; 32];
    const LOCKTIME: u32 = 1_900_000_000;
    const BRANCH_ID: u32 = 0xc2d6_d0b4; // NU5, same as the ZIP-244 test vectors.

    fn pubkey_of(k: &[u8; 32]) -> [u8; 33] {
        let secp = Secp256k1::new();
        SecretKey::from_slice(k)
            .unwrap()
            .public_key(&secp)
            .serialize()
    }

    /// HTLC where the taker key claims and the maker key refunds.
    fn htlc(hash: [u8; 32]) -> HtlcParams {
        HtlcParams {
            hash,
            claim_pubkey: pubkey_of(&TAKER_KEY),
            refund_pubkey: pubkey_of(&MAKER_KEY),
            locktime: LOCKTIME,
        }
    }

    fn outpoint() -> OutPoint {
        OutPoint {
            txid: [9; 32],
            n: 1,
        }
    }

    #[test]
    fn claim_script_executes() {
        let (pre, hash) = new_preimage();
        let h = htlc(hash);
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&TAKER_KEY).unwrap();
        let pk = pubkey_of(&TAKER_KEY);
        let tx = build_spend_tx(
            &secp,
            &sk,
            &pk,
            &h,
            outpoint(),
            20_000,
            Spend::Claim(&pre),
            BRANCH_ID,
            2,
        )
        .unwrap();
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.vin[0].sequence, 0xffff_ffff);
        assert!(tx.vout[0].value < 20_000);
        // build_spend_tx already ran verify_htlc_spend; re-run explicitly for clarity.
        let sig_inputs = [SigInput {
            value: 20_000,
            script_code: h.redeem_script(),
        }];
        verify_htlc_spend(&tx, 0, &sig_inputs, &h.redeem_script()).unwrap();
    }

    #[test]
    fn refund_script_executes() {
        let (_, hash) = new_preimage();
        let h = htlc(hash);
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&MAKER_KEY).unwrap();
        let pk = pubkey_of(&MAKER_KEY);
        let tx = build_spend_tx(
            &secp,
            &sk,
            &pk,
            &h,
            outpoint(),
            20_000,
            Spend::Refund,
            BRANCH_ID,
            2,
        )
        .unwrap();
        assert_eq!(tx.lock_time, LOCKTIME);
        assert_eq!(tx.vin[0].sequence, REFUND_SEQUENCE);
        let sig_inputs = [SigInput {
            value: 20_000,
            script_code: h.redeem_script(),
        }];
        verify_htlc_spend(&tx, 0, &sig_inputs, &h.redeem_script()).unwrap();
    }

    #[test]
    fn wrong_preimage_rejected() {
        let (_, hash) = new_preimage();
        let (wrong, _) = new_preimage();
        let h = htlc(hash);
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&TAKER_KEY).unwrap();
        let pk = pubkey_of(&TAKER_KEY);
        let err = build_spend_tx(
            &secp,
            &sk,
            &pk,
            &h,
            outpoint(),
            20_000,
            Spend::Claim(&wrong),
            BRANCH_ID,
            2,
        )
        .unwrap_err();
        assert!(matches!(err, SwapError::InvalidParams(_)), "{err:?}");

        // Even bypassing the early check, consensus rejects a claim against a different HTLC
        // (wrong hash commitment): build for `good`, verify against `other`.
        let (pre, good_hash) = new_preimage();
        let good = htlc(good_hash);
        let tx = build_spend_tx(
            &secp,
            &sk,
            &pk,
            &good,
            outpoint(),
            20_000,
            Spend::Claim(&pre),
            BRANCH_ID,
            2,
        )
        .unwrap();
        let other = htlc(hash);
        let sig_inputs = [SigInput {
            value: 20_000,
            script_code: other.redeem_script(),
        }];
        assert!(verify_htlc_spend(&tx, 0, &sig_inputs, &other.redeem_script()).is_err());
    }

    #[test]
    fn funding_selects_coins_and_change() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&TAKER_KEY).unwrap();
        let pk = pubkey_of(&TAKER_KEY);
        let my_spk = TransparentAddress::p2pkh(&pk).script_pubkey();
        let coin = |n: u8, value: u64| Coin {
            outpoint: OutPoint {
                txid: [n; 32],
                n: 0,
            },
            value,
            script_pubkey: my_spk.clone(),
        };
        let coins = [coin(1, 10_000), coin(2, 15_000), coin(3, 900_000)];
        let (_, hash) = new_preimage();
        let h = htlc(hash);

        // 20,000 needs the two smaller coins (largest-first selection).
        let f = build_funding_tx(&secp, &sk, &pk, &coins[..2], &h, 20_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f.tx.vin.len(), 2);
        assert_eq!(f.htlc_vout, 0);
        assert_eq!(f.tx.vout[0].value, 20_000);
        assert_eq!(
            f.tx.vout[0].script_pubkey,
            htlc_script_pubkey(&h.redeem_script())
        );
        assert_eq!(f.tx.vout[1].script_pubkey, my_spk);
        let real_size = f.tx.serialize().len();
        assert!(
            f.fee >= 2 * real_size as u64 - 4,
            "fee {} vs size {real_size}",
            f.fee
        );

        // A remainder below dust is folded into the fee instead of a change output.
        let f2 = build_funding_tx(&secp, &sk, &pk, &coins[1..2], &h, 14_500, BRANCH_ID, 2).unwrap();
        assert_eq!(f2.tx.vin.len(), 1);
        assert_eq!(f2.tx.vout.len(), 1, "no dust change");

        // Largest-first selection: a single big coin covers a request smaller than it.
        let f3 = build_funding_tx(&secp, &sk, &pk, &coins, &h, 500_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f3.tx.vin.len(), 1);

        // More than the biggest coin holds pulls in the next-largest too.
        let f4 = build_funding_tx(&secp, &sk, &pk, &coins, &h, 905_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f4.tx.vin.len(), 2);

        // More than the two biggest coins hold pulls in all three.
        let f5 = build_funding_tx(&secp, &sk, &pk, &coins, &h, 920_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f5.tx.vin.len(), 3);

        // Insufficient funds is reported as such.
        let err =
            build_funding_tx(&secp, &sk, &pk, &coins, &h, 5_000_000, BRANCH_ID, 2).unwrap_err();
        assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
    }
}
