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

//! Bloom filters and filtered blocks, as Divi Core serves them to light
//! clients (bloom.cpp, merkleblock.cpp): a peer loads a filter with
//! `filterload`, and is then told only of the transactions it matches and can
//! ask for a block as a `merkleblock` with the matched transactions.

use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::{OutPoint, Transaction};
use std::sync::atomic::{AtomicBool, Ordering};

/// Divi Core MAX_BLOOM_FILTER_SIZE (bloom.h): bytes of filter data
pub const MAX_BLOOM_FILTER_SIZE: usize = 36_000;
/// Divi Core MAX_HASH_FUNCS (bloom.h)
pub const MAX_HASH_FUNCS: u32 = 50;
/// Divi Core MAX_SCRIPT_ELEMENT_SIZE: the largest item a `filteradd` may carry
pub const MAX_FILTERADD_SIZE: usize = 520;

/// Divi Core's bloomflags (bloom.h): what a match adds to the filter
pub const BLOOM_UPDATE_NONE: u8 = 0;
pub const BLOOM_UPDATE_ALL: u8 = 1;
pub const BLOOM_UPDATE_P2PUBKEY_ONLY: u8 = 2;
pub const BLOOM_UPDATE_MASK: u8 = 3;

/// MurmurHash3 x86_32 as Divi Core's hash.cpp computes it
pub fn murmur3(seed: u32, data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h1 = seed;
    let blocks = data.len() / 4;
    for i in 0..blocks {
        let mut k1 = u32::from_le_bytes([
            data[4 * i],
            data[4 * i + 1],
            data[4 * i + 2],
            data[4 * i + 3],
        ]);
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = &data[blocks * 4..];
    let mut k1 = 0u32;
    if tail.len() == 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;
    h1
}

/// Divi Core's CBloomFilter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    data: Vec<u8>,
    hash_funcs: u32,
    tweak: u32,
    flags: u8,
    full: bool,
    empty: bool,
}

impl Default for BloomFilter {
    /// The filter every peer starts with, and the one `filterclear` leaves:
    /// it matches everything (CBloomFilter(), bloom.h)
    fn default() -> Self {
        BloomFilter {
            data: Vec::new(),
            hash_funcs: 0,
            tweak: 0,
            flags: 0,
            full: true,
            empty: false,
        }
    }
}

impl BloomFilter {
    /// A filter for `elements` items at false-positive rate `fp_rate`, within
    /// the protocol limits (CBloomFilter's constructor, bloom.cpp:23-39)
    pub fn new(elements: u32, fp_rate: f64, tweak: u32, flags: u8) -> Self {
        const LN2SQUARED: f64 = 0.480_453_013_918_201_4;
        const LN2: f64 = std::f64::consts::LN_2;
        let bits = ((-1.0 / LN2SQUARED * elements as f64 * fp_rate.ln()) as u32)
            .min(MAX_BLOOM_FILTER_SIZE as u32 * 8);
        let size = (bits / 8) as usize;
        let hash_funcs = ((size as f64 * 8.0 / elements as f64 * LN2) as u32).min(MAX_HASH_FUNCS);
        BloomFilter {
            data: vec![0; size],
            hash_funcs,
            tweak,
            flags,
            full: false,
            empty: false,
        }
    }

    /// A `filterload` payload: the data, hash function count, tweak and
    /// flags; read as Core reads it, a full filter until UpdateEmptyFull
    pub fn deserialize(payload: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let len = read_compact_size(payload, &mut pos)? as usize;
        let data = payload.get(pos..pos.checked_add(len)?)?.to_vec();
        pos += len;
        let u32_at = |p: usize| -> Option<u32> {
            Some(u32::from_le_bytes(payload.get(p..p + 4)?.try_into().ok()?))
        };
        let hash_funcs = u32_at(pos)?;
        let tweak = u32_at(pos + 4)?;
        let flags = *payload.get(pos + 8)?;
        Some(BloomFilter {
            data,
            hash_funcs,
            tweak,
            flags,
            full: true,
            empty: false,
        })
    }

    /// The filter as a `filterload` carries it
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 14);
        write_compact_size(&mut out, self.data.len() as u64);
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.hash_funcs.to_le_bytes());
        out.extend_from_slice(&self.tweak.to_le_bytes());
        out.push(self.flags);
        out
    }

    fn bit(&self, n: u32, item: &[u8]) -> usize {
        // 0xFBA4C795 spreads the seeds of the hash functions (bloom.cpp:42-46)
        let seed = n.wrapping_mul(0xFBA4_C795).wrapping_add(self.tweak);
        murmur3(seed, item) as usize % (self.data.len() * 8)
    }

    pub fn insert(&mut self, item: &[u8]) {
        if self.full {
            return;
        }
        for n in 0..self.hash_funcs {
            let i = self.bit(n, item);
            self.data[i >> 3] |= 1 << (7 & i);
        }
        self.empty = false;
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        if self.full {
            return true;
        }
        if self.empty {
            return false;
        }
        (0..self.hash_funcs).all(|n| {
            let i = self.bit(n, item);
            self.data[i >> 3] & (1 << (7 & i)) != 0
        })
    }

    pub fn insert_outpoint(&mut self, outpoint: &OutPoint) {
        self.insert(&outpoint_bytes(outpoint));
    }

    pub fn contains_outpoint(&self, outpoint: &OutPoint) -> bool {
        self.contains(&outpoint_bytes(outpoint))
    }

    /// IsWithinSizeConstraints (bloom.cpp:121-124)
    pub fn is_within_size_constraints(&self) -> bool {
        self.data.len() <= MAX_BLOOM_FILTER_SIZE && self.hash_funcs <= MAX_HASH_FUNCS
    }

    /// UpdateEmptyFull (bloom.cpp:178-189): a filter of all ones matches
    /// everything, one of all zeros nothing
    pub fn update_empty_full(&mut self) {
        self.full = self.data.iter().all(|&b| b == 0xff);
        self.empty = self.data.iter().all(|&b| b == 0);
    }

    /// IsRelevantAndUpdate (bloom.cpp:126-176): whether `tx` matches the
    /// filter, by its hash, a data push of an output script (and then, as the
    /// flags say, that output is added), an outpoint it spends, or a data push
    /// of an input script
    pub fn is_relevant_and_update(&mut self, tx: &Transaction) -> bool {
        if self.full {
            return true;
        }
        if self.empty {
            return false;
        }
        let txid = tx.txid();
        let mut found = self.contains(txid.as_bytes());
        for (i, out) in tx.vout.iter().enumerate() {
            let script = out.script_pubkey.as_bytes();
            for data in pushes(script) {
                if !data.is_empty() && self.contains(data) {
                    found = true;
                    let outpoint = OutPoint {
                        txid,
                        vout: i as u32,
                    };
                    match self.flags & BLOOM_UPDATE_MASK {
                        BLOOM_UPDATE_ALL => self.insert_outpoint(&outpoint),
                        BLOOM_UPDATE_P2PUBKEY_ONLY => {
                            use divi_script::{policy::solver, standard::ScriptType};
                            if matches!(
                                solver(script),
                                Some((ScriptType::PubKey, _)) | Some((ScriptType::Multisig, _))
                            ) {
                                self.insert_outpoint(&outpoint);
                            }
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
        if found {
            return true;
        }
        tx.vin.iter().any(|input| {
            self.contains_outpoint(&input.prevout)
                || pushes(input.script_sig.as_bytes()).any(|d| !d.is_empty() && self.contains(d))
        })
    }
}

/// An outpoint as Core serializes it for the filter: hash, then index
fn outpoint_bytes(outpoint: &OutPoint) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[..32].copy_from_slice(outpoint.txid.as_bytes());
    b[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
    b
}

/// The data of each operation of a script, stopping at the first that does
/// not parse, as Core's GetOp loop in IsRelevantAndUpdate
fn pushes(script: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut pc = 0usize;
    std::iter::from_fn(move || divi_script::get_op(script, &mut pc).map(|(_, data)| data))
}

/// A `filteradd` payload: one length-prefixed item (Core's vector read)
pub fn read_bytes(payload: &[u8]) -> Option<&[u8]> {
    let mut pos = 0usize;
    let len = read_compact_size(payload, &mut pos)? as usize;
    payload.get(pos..pos.checked_add(len)?)
}

fn read_compact_size(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    *pos += 1;
    let mut take = |n: usize| -> Option<u64> {
        let s = b.get(*pos..*pos + n)?;
        *pos += n;
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(s);
        Some(u64::from_le_bytes(v))
    };
    match first {
        0xfd => take(2),
        0xfe => take(4),
        0xff => take(8),
        n => Some(n as u64),
    }
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Divi Core's CPartialMerkleTree (merkleblock.cpp): the hashes and flag bits
/// that prove the matched transactions are in the block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialMerkleTree {
    pub transactions: u32,
    pub hashes: Vec<Hash256>,
    pub bits: Vec<bool>,
}

fn tree_width(transactions: u32, height: u32) -> u32 {
    (transactions + (1 << height) - 1) >> height
}

fn pair_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut both = [0u8; 64];
    both[..32].copy_from_slice(left.as_bytes());
    both[32..].copy_from_slice(right.as_bytes());
    Hash256::from_bytes(divi_crypto::hash::double_sha256(&both))
}

impl PartialMerkleTree {
    /// CPartialMerkleTree(vTxid, vMatch): TraverseAndBuild from the root
    pub fn build(txids: &[Hash256], matches: &[bool]) -> Self {
        let mut tree = PartialMerkleTree {
            transactions: txids.len() as u32,
            hashes: Vec::new(),
            bits: Vec::new(),
        };
        let mut height = 0;
        while tree_width(tree.transactions, height) > 1 {
            height += 1;
        }
        tree.traverse_and_build(height, 0, txids, matches);
        tree
    }

    fn calc_hash(&self, height: u32, pos: u32, txids: &[Hash256]) -> Hash256 {
        if height == 0 {
            return txids[pos as usize];
        }
        let left = self.calc_hash(height - 1, pos * 2, txids);
        let right = if pos * 2 + 1 < tree_width(self.transactions, height - 1) {
            self.calc_hash(height - 1, pos * 2 + 1, txids)
        } else {
            left
        };
        pair_hash(&left, &right)
    }

    fn traverse_and_build(&mut self, height: u32, pos: u32, txids: &[Hash256], matches: &[bool]) {
        let start = (pos as u64) << height;
        let end = (((pos + 1) as u64) << height).min(self.transactions as u64);
        let parent_of_match = (start..end).any(|p| matches[p as usize]);
        self.bits.push(parent_of_match);
        if height == 0 || !parent_of_match {
            let h = self.calc_hash(height, pos, txids);
            self.hashes.push(h);
        } else {
            self.traverse_and_build(height - 1, pos * 2, txids, matches);
            if pos * 2 + 1 < tree_width(self.transactions, height - 1) {
                self.traverse_and_build(height - 1, pos * 2 + 1, txids, matches);
            }
        }
    }

    /// The tree as a `merkleblock` carries it: count, hashes, then the bits
    /// packed eight to a byte, least significant first
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.transactions.to_le_bytes());
        write_compact_size(&mut out, self.hashes.len() as u64);
        for h in &self.hashes {
            out.extend_from_slice(h.as_bytes());
        }
        let mut bytes = vec![0u8; self.bits.len().div_ceil(8)];
        for (p, &bit) in self.bits.iter().enumerate() {
            bytes[p / 8] |= (bit as u8) << (p % 8);
        }
        write_compact_size(&mut out, bytes.len() as u64);
        out.extend_from_slice(&bytes);
        out
    }
}

/// A `merkleblock` for `block` under `filter` (CMerkleBlock, merkleblock.cpp):
/// its payload, and the index and txid of each matched transaction. Matching
/// updates the filter, as IsRelevantAndUpdate does.
pub fn merkle_block(block: &Block, filter: &mut BloomFilter) -> (Vec<u8>, Vec<(usize, Hash256)>) {
    let mut matched = Vec::new();
    let mut matches = Vec::with_capacity(block.transactions.len());
    let mut txids = Vec::with_capacity(block.transactions.len());
    for (i, tx) in block.transactions.iter().enumerate() {
        let txid = tx.txid();
        let hit = filter.is_relevant_and_update(tx);
        if hit {
            matched.push((i, txid));
        }
        matches.push(hit);
        txids.push(txid);
    }
    let mut payload = serialize(&block.header);
    payload.extend(PartialMerkleTree::build(&txids, &matches).serialize());
    (payload, matched)
}

/// A peer's bloom filter and whether it wants transactions announced (Divi
/// Core's CNode pfilter and fRelayTxes)
#[derive(Debug)]
pub struct PeerBloom {
    filter: parking_lot::Mutex<BloomFilter>,
    /// Off when the peer's `version` asked for no transaction relay, until a
    /// filter message turns it on (main.cpp:388-391, :914, :938)
    no_tx_relay: AtomicBool,
}

impl Default for PeerBloom {
    fn default() -> Self {
        PeerBloom {
            filter: parking_lot::Mutex::new(BloomFilter::default()),
            no_tx_relay: AtomicBool::new(false),
        }
    }
}

impl PeerBloom {
    pub fn set_relay(&self, relay: bool) {
        self.no_tx_relay.store(!relay, Ordering::Relaxed);
    }

    pub fn relays_txs(&self) -> bool {
        !self.no_tx_relay.load(Ordering::Relaxed)
    }

    pub fn filter(&self) -> parking_lot::MutexGuard<'_, BloomFilter> {
        self.filter.lock()
    }

    pub fn set_filter(&self, filter: BloomFilter) {
        *self.filter.lock() = filter;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::serialize::deserialize;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// Divi Core's hash_tests.cpp MurmurHash3 vectors
    #[test]
    fn murmur3_matches_core() {
        for (expected, seed, data) in [
            (0x0000_0000u32, 0x0000_0000u32, ""),
            (0x6a39_6f08, 0xFBA4_C795, ""),
            (0x81f1_6f39, 0xffff_ffff, ""),
            (0x514e_28b7, 0x0000_0000, "00"),
            (0xea3f_0b17, 0xFBA4_C795, "00"),
            (0xfd6c_f10d, 0x0000_0000, "ff"),
            (0x16c6_b7ab, 0x0000_0000, "0011"),
            (0x8eb5_1c3d, 0x0000_0000, "001122"),
            (0xb447_1bf8, 0x0000_0000, "00112233"),
            (0xe230_1fa8, 0x0000_0000, "0011223344"),
            (0xfc2e_4a15, 0x0000_0000, "001122334455"),
            (0xb074_502c, 0x0000_0000, "00112233445566"),
            (0x8034_d2a0, 0x0000_0000, "0011223344556677"),
            (0xb469_8def, 0x0000_0000, "001122334455667788"),
        ] {
            assert_eq!(murmur3(seed, &hex(data)), expected, "{seed:x} {data}");
        }
    }

    /// bloom_tests.cpp bloom_create_insert_serialize and _with_tweak
    #[test]
    fn create_insert_serialize_matches_core() {
        for (tweak, expected) in [
            (0u32, "03614e9b050000000000000001"),
            (2_147_483_649, "03ce4299050000000100008001"),
        ] {
            let mut f = BloomFilter::new(3, 0.01, tweak, BLOOM_UPDATE_ALL);
            f.insert(&hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
            assert!(f.contains(&hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")));
            assert!(!f.contains(&hex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")));
            f.insert(&hex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
            f.insert(&hex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
            assert_eq!(hex::encode(f.serialize()), expected);
            let read = BloomFilter::deserialize(&f.serialize()).unwrap();
            assert_eq!(read.serialize(), f.serialize());
        }
    }

    fn match_txs() -> (Transaction, Transaction) {
        let text = include_str!("../tests/data/bloom_match_txs.hex");
        let mut lines = text.lines();
        let tx: Transaction = deserialize(&hex(lines.next().unwrap())).unwrap();
        let spend: Transaction = deserialize(&hex(lines.next().unwrap())).unwrap();
        (tx, spend)
    }

    /// bloom_tests.cpp bloom_match: by hash, input signature and key, output
    /// address (and the spend of that output), and outpoint; and not otherwise
    #[test]
    fn is_relevant_and_update_matches_core() {
        let (tx, spend) = match_txs();
        assert_eq!(
            tx.txid().to_string(),
            "b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b"
        );
        let fresh = || BloomFilter::new(10, 0.000001, 0, BLOOM_UPDATE_ALL);
        let prev =
            Hash256::from_hex("90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b")
                .unwrap();

        let mut f = fresh();
        f.insert(tx.txid().as_bytes());
        assert!(f.is_relevant_and_update(&tx), "tx hash");
        for item in [
            "6bff7fcd4f8565ef406dd5d63d4ff94f318fe82027fd4dc451b04474019f74b4",
            "30450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a01",
            "046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339",
            "a266436d2965547608b9e15d9032a7b9d64fa431",
        ] {
            let mut f = fresh();
            f.insert(&hex(item));
            assert!(f.is_relevant_and_update(&tx), "{item}");
        }
        let mut f = fresh();
        f.insert(&hex("04943fdd508053c75000106d3bc6e2754dbcff19"));
        assert!(f.is_relevant_and_update(&tx), "output address");
        assert!(
            f.is_relevant_and_update(&spend),
            "the matched output was not added"
        );

        let mut f = fresh();
        f.insert_outpoint(&OutPoint {
            txid: prev,
            vout: 0,
        });
        assert!(f.is_relevant_and_update(&tx), "outpoint");

        for miss in [
            Hash256::from_hex("00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436")
                .unwrap()
                .as_bytes()
                .to_vec(),
            hex("0000006d2965547608b9e15d9032a7b9d64fa431"),
        ] {
            let mut f = fresh();
            f.insert(&miss);
            assert!(!f.is_relevant_and_update(&tx));
        }
        let mut f = fresh();
        f.insert_outpoint(&OutPoint {
            txid: prev,
            vout: 1,
        });
        assert!(
            !f.is_relevant_and_update(&tx),
            "another output of the same tx"
        );
    }

    /// A filter read from the wire is full until UpdateEmptyFull, and the
    /// default filter (every peer's first, and after filterclear) matches all
    #[test]
    fn empty_and_full_filters() {
        let (tx, _) = match_txs();
        assert!(BloomFilter::default().is_relevant_and_update(&tx));
        let mut zeros = BloomFilter::deserialize(&hex("0300000005000000000000000001")).unwrap();
        zeros.update_empty_full();
        assert!(!zeros.is_relevant_and_update(&tx));
        let mut ones = BloomFilter::deserialize(&hex("03ffffff05000000000000000001")).unwrap();
        ones.update_empty_full();
        assert!(ones.is_relevant_and_update(&tx));
        assert!(
            !BloomFilter::deserialize(&hex("03ffff")).is_some(),
            "short payload"
        );
    }

    fn extract(tree: &PartialMerkleTree) -> (Hash256, Vec<Hash256>) {
        fn walk(
            t: &PartialMerkleTree,
            height: u32,
            pos: u32,
            bit: &mut usize,
            hash: &mut usize,
            out: &mut Vec<Hash256>,
        ) -> Hash256 {
            let parent = t.bits[*bit];
            *bit += 1;
            if height == 0 || !parent {
                let h = t.hashes[*hash];
                *hash += 1;
                if height == 0 && parent {
                    out.push(h);
                }
                return h;
            }
            let left = walk(t, height - 1, pos * 2, bit, hash, out);
            let right = if pos * 2 + 1 < tree_width(t.transactions, height - 1) {
                walk(t, height - 1, pos * 2 + 1, bit, hash, out)
            } else {
                left
            };
            pair_hash(&left, &right)
        }
        let mut height = 0;
        while tree_width(tree.transactions, height) > 1 {
            height += 1;
        }
        let (mut bit, mut hash, mut out) = (0, 0, Vec::new());
        let root = walk(tree, height, 0, &mut bit, &mut hash, &mut out);
        (root, out)
    }

    /// bloom_tests.cpp merkle_block_3_and_serialize: the merkleblock bytes
    /// of a one-transaction block
    #[test]
    fn merkle_block_serializes_as_core() {
        let text = include_str!("../tests/data/merkle_block_3.hex");
        let mut lines = text.lines();
        let block: Block = deserialize(&hex(lines.next().unwrap())).unwrap();
        let expected = lines.next().unwrap();
        let mut f = BloomFilter::new(10, 0.000001, 0, BLOOM_UPDATE_ALL);
        f.insert(
            Hash256::from_hex("63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5")
                .unwrap()
                .as_bytes(),
        );
        let (payload, matched) = merkle_block(&block, &mut f);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].0, 0);
        assert_eq!(hex::encode(payload), expected);
    }

    /// bloom_tests.cpp merkle_block_1: the last of nine transactions, then
    /// also the eighth; the proof gives the block's merkle root
    #[test]
    fn merkle_block_proof_gives_the_root() {
        let block: Block =
            deserialize(&hex(include_str!("../tests/data/merkle_block_1.hex").trim())).unwrap();
        let txids: Vec<Hash256> = block.transactions.iter().map(|t| t.txid()).collect();
        let last =
            Hash256::from_hex("74d681e0e03bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20")
                .unwrap();
        let eighth =
            Hash256::from_hex("dd1fd2a6fc16404faf339881a90adbde7f4f728691ac62e8f168809cdfae1053")
                .unwrap();
        let mut f = BloomFilter::new(10, 0.000001, 0, BLOOM_UPDATE_ALL);
        f.insert(last.as_bytes());
        let (_, matched) = merkle_block(&block, &mut f);
        assert_eq!(matched, vec![(8, last)]);
        f.insert(eighth.as_bytes());
        let (_, matched) = merkle_block(&block, &mut f);
        assert_eq!(matched, vec![(7, eighth), (8, last)]);
        let matches: Vec<bool> = (0..txids.len()).map(|i| i == 7 || i == 8).collect();
        let tree = PartialMerkleTree::build(&txids, &matches);
        let (root, found) = extract(&tree);
        assert_eq!(root, block.header.merkle_root);
        assert_eq!(found, vec![eighth, last]);
    }
}
