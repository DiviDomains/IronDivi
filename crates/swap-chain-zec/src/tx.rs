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
/// NU6.3 (Ironwood) `nVersionGroupId` for v6 transactions — [ZIP 229]'s mandated constant,
/// confirmed against live testnet transactions (lane zec, 2026-10-11): every transaction
/// seen on `testnet.zec.rocks` over a 2000-block window is v6, this exact version group id.
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
pub const V6_VERSION_GROUP_ID: u32 = 0xD884_B698;
/// `nVersion = 6`, with the overwinter high bit set, as serialized in `nVersion` LE32. This
/// backend builds v6 transactions: the live testnet relays/mines v6 exclusively post-NU6.3
/// (see [`V6_VERSION_GROUP_ID`]), even for plain transparent transfers with no Ironwood
/// component — v5 is still consensus-valid per ZIP 229, but not what the network actually
/// accepts in practice right now.
pub const V6_VERSION_BYTES: u32 = 0x8000_0006;

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

// ZIP 229 (v6 / Ironwood): `orchard_digest` gets a new personalization for v6 (even when
// empty — the ZIP changes it unconditionally, "personalizations must be changed when what
// is hashed at that node changes", since v6 also drops the anchor into auth data), and the
// new Ironwood component digest reuses Orchard's sub-digest shape with its own
// personalizations. `sapling_digest`'s own wrapper personalization is unchanged for v6 (only
// its noncompact-spends child would change, which we never reach: we have zero spends).
const PERS_ORCHARD_V6: &[u8; 16] = b"ZTxIdOrchardH_v6";
const PERS_IRONWOOD_V6: &[u8; 16] = b"ZTxIdIronwd_H_v6";
const PERS_IW_ACT_C_V6: &[u8; 16] = b"ZTxIdIrnActCH_v6";
const PERS_IW_ACT_M_V6: &[u8; 16] = b"ZTxIdIrnActMH_v6";
const PERS_IW_ACT_N_V6: &[u8; 16] = b"ZTxIdIrnActNH_v6";
const PERS_S_SPENDS_N_V6: &[u8; 16] = b"ZTxIdSSpendNH_v6";

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
    /// `spends`: each entry is the 96-byte `cv(32) || nullifier(32) || rk(32)` spend record.
    /// `anchor`: the single shared Sapling anchor (only meaningful if non-empty). `v6`:
    /// whether to use the [ZIP 229] v6 noncompact-spends personalization and omit the
    /// anchor from it (the anchor moves to authorizing data in v6 — we never compute the
    /// auth digest, so for us this just means leaving it out). Everything else (compact
    /// digest, outputs, the `sapling_digest` wrapper personalization) is unchanged by v6.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    fn sapling(
        spends: &[[u8; 96]],
        anchor: [u8; 32],
        outputs: &[[u8; 756]],
        value_balance: i64,
        v6: bool,
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
                if !v6 {
                    noncompact.extend(anchor);
                }
                noncompact.extend(&s[64..96]); // rk
            }
            let c = blake2b_person(PERS_S_SPENDS_C, &[&compact]);
            let n_pers = if v6 {
                PERS_S_SPENDS_N_V6
            } else {
                PERS_S_SPENDS_N
            };
            let n = blake2b_person(n_pers, &[&noncompact]);
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
        let (c, m, n) =
            Self::orchard_action_sub_digests(actions, PERS_O_ACT_C, PERS_O_ACT_M, PERS_O_ACT_N);
        blake2b_person(
            PERS_ORCHARD,
            &[&c, &m, &n, &[flags], &value_balance.to_le_bytes(), &anchor],
        )
    }

    /// `orchard_digest_v6` ([ZIP 229]): same shape as [`Self::orchard`], but with the v6
    /// personalization and — since v6 moves the anchor to authorizing data — no anchor.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    fn orchard_v6(actions: &[[u8; 820]], flags: u8, value_balance: i64) -> [u8; 32] {
        if actions.is_empty() {
            return empty_digest(PERS_ORCHARD_V6);
        }
        let (c, m, n) =
            Self::orchard_action_sub_digests(actions, PERS_O_ACT_C, PERS_O_ACT_M, PERS_O_ACT_N);
        blake2b_person(
            PERS_ORCHARD_V6,
            &[&c, &m, &n, &[flags], &value_balance.to_le_bytes()],
        )
    }

    /// `ironwood_digest_v6` ([ZIP 229]): identical structure to [`Self::orchard_v6`] — the
    /// Ironwood component reuses the Orchard Action encoding — but with Ironwood's own
    /// personalizations.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    fn ironwood_v6(actions: &[[u8; 820]], flags: u8, value_balance: i64) -> [u8; 32] {
        if actions.is_empty() {
            return empty_digest(PERS_IRONWOOD_V6);
        }
        let (c, m, n) = Self::orchard_action_sub_digests(
            actions,
            PERS_IW_ACT_C_V6,
            PERS_IW_ACT_M_V6,
            PERS_IW_ACT_N_V6,
        );
        blake2b_person(
            PERS_IRONWOOD_V6,
            &[&c, &m, &n, &[flags], &value_balance.to_le_bytes()],
        )
    }

    /// The compact/memos/noncompact sub-digests shared by Orchard and Ironwood action
    /// groups (same 820-byte `OrchardAction` record, [ZIP 229] §"Ironwood Action
    /// descriptions use the same encoding as Orchard Actions").
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    fn orchard_action_sub_digests(
        actions: &[[u8; 820]],
        pers_c: &[u8; 16],
        pers_m: &[u8; 16],
        pers_n: &[u8; 16],
    ) -> ([u8; 32], [u8; 32], [u8; 32]) {
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
        (
            blake2b_person(pers_c, &[&compact]),
            blake2b_person(pers_m, &[&memos]),
            blake2b_person(pers_n, &[&noncompact]),
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

/// [ZIP 229] `txid_digest_v6`: like [`combine_txid`], but with an Ironwood component digest
/// appended as a fifth child (after `orchard_digest_v6`, which the caller must have computed
/// with the v6 personalization — see [`ShieldedDigests::orchard_v6`]).
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
fn combine_txid_v6(
    header: [u8; 32],
    transparent: [u8; 32],
    sapling: [u8; 32],
    orchard_v6: [u8; 32],
    ironwood_v6: [u8; 32],
    consensus_branch_id: u32,
) -> [u8; 32] {
    blake2b_person(
        &txid_personalization(consensus_branch_id),
        &[&header, &transparent, &sapling, &orchard_v6, &ironwood_v6],
    )
}

/// One transparent input being signed: its previous output's value and `scriptPubKey`.
///
/// ZIP 244 (S.2c and S.2g.iii) commits to the previous output's `scriptPubKey` — for a P2SH
/// HTLC that is the P2SH script, *not* the redeem script BIP 143 would use as `scriptCode`.
#[derive(Debug, Clone)]
pub struct SigInput {
    /// Value of the output this input spends, in zatoshi.
    pub value: u64,
    /// The `scriptPubKey` of the output this input spends.
    pub script_pubkey: Vec<u8>,
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
            write_script(&mut buf, &s.script_pubkey);
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
            write_script(&mut buf, &sig_inputs[i].script_pubkey);
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
/// `signed_index` is `None` and `hash_type` is `SIGHASH_ALL`). v5 only — this backend builds
/// v6 transactions ([`signature_digest_v6`]); this function is kept to validate the v5
/// algorithm against the official ZIP-244 test vectors (`zip244_sighash_vectors`).
#[cfg(test)]
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

/// [ZIP 229] v6 signature digest: identical to [`signature_digest`] (the transparent-input
/// sighash algorithm, S.2, is unchanged by ZIP 229) but with the Ironwood component digest
/// appended, mirroring [`combine_txid_v6`].
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
#[allow(clippy::too_many_arguments)]
pub(crate) fn signature_digest_v6(
    header: [u8; 32],
    consensus_branch_id: u32,
    vin: &[TxIn],
    vout: &[TxOut],
    hash_type: u8,
    signed_index: Option<usize>,
    sig_inputs: &[SigInput],
    sapling_digest: [u8; 32],
    orchard_digest_v6: [u8; 32],
    ironwood_digest_v6: [u8; 32],
) -> [u8; 32] {
    let transparent = transparent_sig_digest(vin, vout, hash_type, signed_index, sig_inputs);
    blake2b_person(
        &txid_personalization(consensus_branch_id),
        &[
            &header,
            &transparent,
            &sapling_digest,
            &orchard_digest_v6,
            &ironwood_digest_v6,
        ],
    )
}

pub(crate) const SIGHASH_ALL: u8 = 0x01;

// ---- A transparent-only v6 transaction we build ourselves --------------------------------

/// A Zcash v6 ([ZIP 229] / NU6.3 "Ironwood") transaction with empty Sapling, Orchard and
/// Ironwood bundles: every transaction this backend ever builds (funding, claim, refund).
/// v6, not v5: the live testnet relays/mines only v6 transactions post-NU6.3, even plain
/// transparent transfers — see [`V6_VERSION_BYTES`].
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
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
        out.extend(V6_VERSION_BYTES.to_le_bytes());
        out.extend(V6_VERSION_GROUP_ID.to_le_bytes());
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
        out.push(0); // nActionsIronwood = 0 (ZIP 229, new in v6)
        out
    }

    fn header_digest(&self) -> [u8; 32] {
        header_digest(
            V6_VERSION_BYTES,
            V6_VERSION_GROUP_ID,
            self.consensus_branch_id,
            self.lock_time,
            self.expiry_height,
        )
    }

    /// The transaction id.
    pub fn txid(&self) -> [u8; 32] {
        combine_txid_v6(
            self.header_digest(),
            transparent_digest(&self.vin, &self.vout),
            empty_digest(PERS_SAPLING),
            empty_digest(PERS_ORCHARD_V6),
            empty_digest(PERS_IRONWOOD_V6),
            self.consensus_branch_id,
        )
    }

    /// The `SIGHASH_ALL` digest for signing/verifying input `index`. `sig_inputs` has one
    /// entry per `vin`, in order (value + scriptCode of the output each input spends).
    pub fn signature_digest(&self, index: usize, sig_inputs: &[SigInput]) -> [u8; 32] {
        signature_digest_v6(
            self.header_digest(),
            self.consensus_branch_id,
            &self.vin,
            &self.vout,
            SIGHASH_ALL,
            Some(index),
            sig_inputs,
            empty_digest(PERS_SAPLING),
            empty_digest(PERS_ORCHARD_V6),
            empty_digest(PERS_IRONWOOD_V6),
        )
    }
}

/// A transaction read off the chain (ours or a counterparty's): fully parsed transparent
/// parts, Sapling/Orchard/Ironwood bundles reduced to their digests (we never need their
/// content, only whether the txid matches). Accepts both v5 (NU5) and v6 ([ZIP 229],
/// NU6.3 "Ironwood") transactions — the live testnet currently mints only v6, but v5 remains
/// consensus-valid, so a counterparty's spend could in principle still be v5.
///
/// [ZIP 229]: https://zips.z.cash/zip-0229
#[derive(Debug, Clone)]
pub struct ParsedTx {
    /// See [`ZecTx`]. 5 or 6.
    pub version: u32,
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
    /// Computed with the v5 or v6 personalization, matching [`Self::version`].
    orchard_digest: [u8; 32],
    /// `None` for a v5 transaction (no Ironwood component exists in that format).
    ironwood_digest: Option<[u8; 32]>,
}

impl ParsedTx {
    /// Parse a v5 (NU5+) or v6 ([ZIP 229], NU6.3+) transaction. Older (pre-NU5) versions are
    /// rejected: this backend only ever deals with transactions at or after NU5 activation.
    ///
    /// [ZIP 229]: https://zips.z.cash/zip-0229
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let version_bytes = r.u32()?;
        let (version, want_group_id) = match version_bytes {
            V5_VERSION_BYTES => (5u32, NU5_VERSION_GROUP_ID),
            V6_VERSION_BYTES => (6u32, V6_VERSION_GROUP_ID),
            other => {
                return Err(SwapError::Other(format!(
                    "zec tx: unsupported version bytes {other:#x} (want v5 NU5+ or v6 NU6.3+)"
                )))
            }
        };
        let version_group_id = r.u32()?;
        if version_group_id != want_group_id {
            return Err(SwapError::Other(format!(
                "zec tx: unexpected version group id {version_group_id:#x} for v{version}"
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
        let sapling_digest = ShieldedDigests::sapling(
            &spend_blobs,
            anchor,
            &output_blobs,
            value_balance_sapling,
            version >= 6,
        );

        // Orchard: nActionsOrchard action records (820 bytes each), then (if any) flags(1),
        // valueBalance(8), anchor(32), proofs (CompactSize-prefixed), per-action sigs(64),
        // binding sig(64). The wire layout is identical for v5 and v6; only the *digest*
        // formula differs (v6 excludes the anchor — ZIP 229 moves it to auth data — and uses
        // a v6-specific personalization even when `nactions == 0`).
        let nactions = r.compact_size()? as usize;
        let mut action_blobs = Vec::with_capacity(nactions);
        for _ in 0..nactions {
            action_blobs.push(<[u8; 820]>::try_from(r.take(820)?).unwrap());
        }
        let (orchard_flags, orchard_value_balance, orchard_anchor) = if nactions > 0 {
            let flags = r.take(1)?[0];
            let value_balance = r.u64()? as i64;
            let anchor: [u8; 32] = r.take(32)?.try_into().unwrap();
            let proof_len = r.compact_size()? as usize;
            r.take(proof_len)?;
            r.take(64 * nactions)?; // per-action spend auth sigs
            r.take(64)?; // binding sig
            (flags, value_balance, anchor)
        } else {
            (0, 0, [0u8; 32])
        };
        let orchard_digest = if version >= 6 {
            ShieldedDigests::orchard_v6(&action_blobs, orchard_flags, orchard_value_balance)
        } else {
            ShieldedDigests::orchard(
                &action_blobs,
                orchard_flags,
                orchard_value_balance,
                orchard_anchor,
            )
        };

        // Ironwood (v6 only, ZIP 229): same record shape as Orchard, reusing OrchardAction.
        let ironwood_digest = if version >= 6 {
            let nactions = r.compact_size()? as usize;
            let mut iw_blobs = Vec::with_capacity(nactions);
            for _ in 0..nactions {
                iw_blobs.push(<[u8; 820]>::try_from(r.take(820)?).unwrap());
            }
            let (flags, value_balance) = if nactions > 0 {
                let flags = r.take(1)?[0];
                let value_balance = r.u64()? as i64;
                r.take(32)?; // anchorIronwood (auth data in v6, excluded from the digest)
                let proof_len = r.compact_size()? as usize;
                r.take(proof_len)?;
                r.take(64 * nactions)?; // per-action spend auth sigs
                r.take(64)?; // binding sig
                (flags, value_balance)
            } else {
                (0, 0)
            };
            Some(ShieldedDigests::ironwood_v6(
                &iw_blobs,
                flags,
                value_balance,
            ))
        } else {
            None
        };

        if r.remaining() != 0 {
            return Err(SwapError::Other(format!(
                "zec tx: {} trailing byte(s) after parsing",
                r.remaining()
            )));
        }

        Ok(ParsedTx {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            vin,
            vout,
            sapling_digest,
            orchard_digest,
            ironwood_digest,
        })
    }

    /// The transaction id.
    pub fn txid(&self) -> [u8; 32] {
        let version_bytes = if self.version >= 6 {
            V6_VERSION_BYTES
        } else {
            V5_VERSION_BYTES
        };
        let version_group_id = if self.version >= 6 {
            V6_VERSION_GROUP_ID
        } else {
            NU5_VERSION_GROUP_ID
        };
        let header = header_digest(
            version_bytes,
            version_group_id,
            self.consensus_branch_id,
            self.lock_time,
            self.expiry_height,
        );
        let transparent = transparent_digest(&self.vin, &self.vout);
        match self.ironwood_digest {
            Some(ironwood) => combine_txid_v6(
                header,
                transparent,
                self.sapling_digest,
                self.orchard_digest,
                ironwood,
                self.consensus_branch_id,
            ),
            None => combine_txid(
                header,
                transparent,
                self.sapling_digest,
                self.orchard_digest,
                self.consensus_branch_id,
            ),
        }
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

/// [ZIP 317](https://zips.z.cash/zip-0317) conventional fee, zatoshi per logical action.
/// Zebra's NU7 mempool enforces this as a floor: a plain per-byte fee (a few hundred
/// zatoshi for our small txs) is rejected with "Unpaid actions is higher than the limit".
const ZIP317_MARGINAL_FEE: u64 = 5000;
/// Actions below this many are free (ZIP 317 "grace" allowance) — in practice this is the
/// floor every one of our single-HTLC txs hits, since they never reach 2 real actions.
const ZIP317_GRACE_ACTIONS: u64 = 2;
/// Transparent input weight: a logical action's worth of input bytes (ZIP 317 §Fee
/// calculation; `tx_in_total_size` is scaled by this instead of counting P2PKH inputs 1:1,
/// so unusually large scriptSigs still count as more than one action).
const ZIP317_IN_WEIGHT: u64 = 150;
/// Transparent output weight, same idea as [`ZIP317_IN_WEIGHT`] for outputs.
const ZIP317_OUT_WEIGHT: u64 = 34;

/// Serialized length of one transparent input or output, via its own `write`.
fn serialized_len(write: impl FnOnce(&mut Vec<u8>)) -> u64 {
    let mut v = Vec::new();
    write(&mut v);
    v.len() as u64
}

/// [ZIP 317](https://zips.z.cash/zip-0317) conventional fee for an all-transparent tx:
/// `marginal_fee * max(grace_actions, logical_actions)`, where (with no shielded actions)
/// `logical_actions = max(ceil(total vin bytes / in_weight), ceil(total vout bytes /
/// out_weight))`. This is what Zebra's mempool actually requires on NU7 testnet — a
/// per-byte rate (`ceil_fee`/`zats_per_byte`) alone is not enough, so callers take the
/// larger of the two.
fn zip317_fee(vin: &[TxIn], vout: &[TxOut]) -> u64 {
    let in_bytes: u64 = vin.iter().map(|t| serialized_len(|v| t.write(v))).sum();
    let out_bytes: u64 = vout.iter().map(|t| serialized_len(|v| t.write(v))).sum();
    let in_actions = in_bytes.div_ceil(ZIP317_IN_WEIGHT);
    let out_actions = out_bytes.div_ceil(ZIP317_OUT_WEIGHT);
    ZIP317_MARGINAL_FEE * in_actions.max(out_actions).max(ZIP317_GRACE_ACTIONS)
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
    // Seeded from the zero-input skeleton so a coin list with no entries at all (a fresh,
    // never-funded address) still reports InsufficientFunds instead of `needed` staying 0
    // and `total < needed` wrongly passing, which then underflows `needed - amount` below.
    let mut needed = amount
        + probe_fee(
            &funding_probe(&chosen, &htlc_spk, amount, Some(0), &my_spk),
            zats_per_byte,
        );
    for c in sorted {
        chosen.push(c);
        total += chosen.last().unwrap().value;
        let probe = funding_probe(&chosen, &htlc_spk, amount, Some(0), &my_spk);
        needed = amount + probe_fee(&probe, zats_per_byte);
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
            script_pubkey: c.script_pubkey.clone(),
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

/// A funding tx with dummy (but correctly-sized) P2PKH scriptSigs, for fee sizing before
/// the real coin selection is final.
fn funding_probe(
    chosen: &[Coin],
    htlc_spk: &[u8],
    amount: u64,
    change: Option<u64>,
    my_spk: &[u8],
) -> ZecTx {
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
    ZecTx {
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
    }
}

/// The fee a probe tx needs: the larger of the configured per-byte rate and the ZIP 317
/// conventional fee Zebra's NU7 mempool actually enforces (see [`zip317_fee`]).
fn probe_fee(probe: &ZecTx, zats_per_byte: u64) -> u64 {
    ceil_fee(zats_per_byte, probe.serialize().len()).max(zip317_fee(&probe.vin, &probe.vout))
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
    let fee = probe_fee(&probe, zats_per_byte);
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
        script_pubkey: htlc_script_pubkey(&redeem),
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
                    script_pubkey: hex::decode(spk).unwrap(),
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
            script_pubkey: htlc_script_pubkey(&h.redeem_script()),
        }];
        verify_htlc_spend(&tx, 0, &sig_inputs, &h.redeem_script()).unwrap();

        // Regression (live NU7 run, claim rejected "script verification failed"): ZIP 244
        // signs the P2SH scriptPubKey, so a digest over the redeem script must not verify.
        let redeem_inputs = [SigInput {
            value: 20_000,
            script_pubkey: h.redeem_script(),
        }];
        assert_ne!(
            tx.signature_digest(0, &redeem_inputs),
            tx.signature_digest(0, &sig_inputs)
        );
        assert!(verify_htlc_spend(&tx, 0, &redeem_inputs, &h.redeem_script()).is_err());

        // `ParsedTx::parse` (used by `find_spend`/`htlc_output` on a counterparty's raw tx)
        // must recompute the exact same txid for a v6 transaction we built ourselves.
        let parsed = ParsedTx::parse(&tx.serialize()).unwrap();
        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.txid(), tx.txid());
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
            script_pubkey: htlc_script_pubkey(&h.redeem_script()),
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
            script_pubkey: htlc_script_pubkey(&other.redeem_script()),
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
        // Sized so the ZIP 317 conventional fee (the real floor now — see
        // `zip317_fee_pins_expected_values`) stays at its 10,000 zat grace-action minimum for
        // up to 2 inputs, and steps up to 15,000 at 3 inputs (each adds ~148 bytes, crossing
        // the 150-byte-per-action line on the third).
        let coins = [coin(1, 50_000), coin(2, 60_000), coin(3, 200_000)];
        let (_, hash) = new_preimage();
        let h = htlc(hash);

        // 95,000 needs the two smaller coins (largest-first selection): the biggest of the
        // two (60,000) alone can't cover 95,000 + the 10,000 fee.
        let f = build_funding_tx(&secp, &sk, &pk, &coins[..2], &h, 95_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f.tx.vin.len(), 2);
        assert_eq!(f.htlc_vout, 0);
        assert_eq!(f.tx.vout[0].value, 95_000);
        assert_eq!(
            f.tx.vout[0].script_pubkey,
            htlc_script_pubkey(&h.redeem_script())
        );
        assert_eq!(f.tx.vout[1].script_pubkey, my_spk);
        assert_eq!(
            f.fee, 10_000,
            "1-2 inputs, 2 outputs stays at the grace floor"
        );
        assert_eq!(f.tx.vout[1].value, 110_000 - 95_000 - 10_000);

        // A remainder below dust (250 < 294) is folded into the fee instead of a change
        // output: 60,000 − 49,750 − 10,000 fee = 250.
        let f2 = build_funding_tx(&secp, &sk, &pk, &coins[1..2], &h, 49_750, BRANCH_ID, 2).unwrap();
        assert_eq!(f2.tx.vin.len(), 1);
        assert_eq!(f2.tx.vout.len(), 1, "no dust change");
        assert_eq!(f2.fee, 10_250);

        // Largest-first selection: a single big coin covers a request smaller than it.
        let f3 = build_funding_tx(&secp, &sk, &pk, &coins, &h, 150_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f3.tx.vin.len(), 1);
        assert_eq!(f3.fee, 10_000);

        // More than the biggest coin holds (less its fee) pulls in the next-largest too.
        let f4 = build_funding_tx(&secp, &sk, &pk, &coins, &h, 195_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f4.tx.vin.len(), 2);
        assert_eq!(f4.fee, 10_000);

        // More than the two biggest coins hold pulls in all three — and 3 inputs (444 bytes)
        // crosses into a 3rd ZIP 317 action, so the fee itself rises to 15,000.
        let f5 = build_funding_tx(&secp, &sk, &pk, &coins, &h, 255_000, BRANCH_ID, 2).unwrap();
        assert_eq!(f5.tx.vin.len(), 3);
        assert_eq!(f5.fee, 15_000, "3 inputs crosses into a 3rd logical action");

        // Insufficient funds is reported as such.
        let err =
            build_funding_tx(&secp, &sk, &pk, &coins, &h, 5_000_000, BRANCH_ID, 2).unwrap_err();
        assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");

        // A completely empty coin list (a fresh, never-funded address) must also report
        // InsufficientFunds, not panic with a subtract-with-overflow (the live dry run
        // example found this: `needed` must not stay seeded at 0 when the loop never runs).
        let err = build_funding_tx(&secp, &sk, &pk, &[], &h, 20_000, BRANCH_ID, 2).unwrap_err();
        assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
    }

    /// Pins the [ZIP 317](https://zips.z.cash/zip-0317) conventional fee for the tx shapes
    /// this backend actually builds — the real floor Zebra's NU7 mempool enforces (a plain
    /// per-byte fee of a few hundred zatoshi was rejected: "Unpaid actions is higher than
    /// the limit"). Byte sizes use the same dummy 72-byte signature every probe uses.
    #[test]
    fn zip317_fee_pins_expected_values() {
        let pk = pubkey_of(&TAKER_KEY);
        let dummy_sig = vec![0u8; DUMMY_SIG_LEN];
        let p2pkh_in = || TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                n: 0,
            },
            script_sig: p2pkh_script_sig(&dummy_sig, &pk),
            sequence: 0xffff_ffff,
        };
        let htlc_out = || TxOut {
            value: 1,
            script_pubkey: vec![0u8; 23], // a P2SH scriptPubKey's exact length
        };
        let p2pkh_out = || TxOut {
            value: 1,
            script_pubkey: vec![0u8; 25], // a P2PKH scriptPubKey's exact length
        };

        // 1 P2PKH input (148 bytes -> 1 action) + HTLC funding output + P2PKH change (66
        // bytes total -> 2 actions): the orchestrator's pinned funding-tx shape.
        assert_eq!(
            zip317_fee(&[p2pkh_in()], &[htlc_out(), p2pkh_out()]),
            10_000
        );
        // 1 input + 1 output: both round down to 1 action, but the 2-action grace floor
        // still applies.
        assert_eq!(zip317_fee(&[p2pkh_in()], &[p2pkh_out()]), 10_000);
        // 3 inputs (444 bytes -> 3 actions, 150 bytes/action) dominates the floor.
        assert_eq!(
            zip317_fee(&[p2pkh_in(), p2pkh_in(), p2pkh_in()], &[p2pkh_out()]),
            15_000
        );
        // 3 P2PKH outputs (34 bytes each -> 102 bytes -> exactly 3 actions) dominates too.
        assert_eq!(
            zip317_fee(&[p2pkh_in()], &[p2pkh_out(), p2pkh_out(), p2pkh_out()]),
            15_000
        );
    }
}
