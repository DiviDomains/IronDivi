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

//! Masternode payment votes (`mnw`) as Divi Core keeps them: each vote that
//! passes Core's checks counted for its payee under the block it is scored
//! with, one vote per masternode (MasternodePaymentData, MasternodePayeeData).
//! `getmasternodewinners` reads them.

use crate::flat_file::{self, cmp_u256, write_compact_size, write_varbytes, Header, Reader};
use crate::mn_list::{scoring_hash, MasternodeList, Refusal};
use divi_masternode::cpp_wire::CppWinner;
use divi_primitives::hash::Hash256;
use divi_storage::{Chain, NetworkType};
use divi_wallet::address::Address;
use divi_wallet::Network;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

/// MNPAYMENTS_SIGNATURES_TOTAL (masternode-payments.cpp:37)
const SIGNATURES_TOTAL: usize = 10;
/// CMasternodeSync::blockDepthUpToWhichToRequestMNWinners (masternode-sync.cpp:29)
const WINNER_DEPTH: i64 = 200;
/// Votes are kept this many blocks (MasternodePaymentData.cpp:52)
const KEEP_DEPTH: i64 = 1000;
/// ActiveProtocol() without -activeversion (version.cpp:11-17)
const ACTIVE_PROTOCOL: i32 = 70915;

/// The votes for one block (CMasternodeBlockPayees): its height, the payees
/// in the order they first got a vote, with their counts, and who voted
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BlockPayees {
    height: i32,
    payees: Vec<(Vec<u8>, u32)>,
    voters: HashSet<([u8; 32], u32)>,
}

/// The file Divi Core keeps the votes in, in its data directory, and its
/// magic message (MasternodeModule.cpp:272-274, :293-294)
pub const PAYMENTS_FILE: &str = "mnpayments.dat";
const PAYMENTS_MAGIC: &str = "magicMasternodePaymentsCache";

/// What reading mnpayments.dat came to, as CFlatDB::Read classes it
/// (flat-database.h, flat-database.cpp:18-60)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentsFile {
    /// Read: this many votes, before pruning
    Loaded(usize),
    /// No file: one is written at the next stop
    Missing,
    /// The checksum and the magic are right but the votes do not parse
    /// (IncorrectFormat): taken as empty, and the file is written anew
    BadFormat,
    /// Any other fault (the checksum, the magic message, the network's magic
    /// number): divid refuses to start and will not overwrite the file
    Invalid(&'static str),
}

#[derive(Default)]
pub struct MasternodeVotes {
    /// Every vote taken, by its hash, with the block it is scored with
    winners: RwLock<HashMap<[u8; 32], (CppWinner, Hash256)>>,
    /// The counts per scoring block
    blocks: RwLock<HashMap<Hash256, BlockPayees>>,
    /// The masternode sync is not finished (CMasternodeSync::IsSynced false),
    /// for votes that follow no sync; starts false
    sync_unfinished: std::sync::atomic::AtomicBool,
    /// The node's masternode sync, which decides once set
    sync: RwLock<Option<divi_masternode::mnsync::SharedMasternodeSync>>,
}

impl MasternodeVotes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the node's masternode sync is finished, which decides whether a
    /// vote's payee must be near the top of the queue and whether a bad
    /// signature costs its sender (masternode-payments.cpp:241-245, :320-328)
    pub fn set_sync_finished(&self, finished: bool) {
        self.sync_unfinished
            .store(!finished, std::sync::atomic::Ordering::Relaxed);
    }

    /// Follow the node's masternode sync: a vote is checked against its
    /// stage at the time (IsSynced, masternode-sync.cpp:55-58)
    pub fn follow_sync(&self, sync: divi_masternode::mnsync::SharedMasternodeSync) {
        *self.sync.write() = Some(sync);
    }

    fn sync_finished(&self) -> bool {
        if let Some(sync) = self.sync.read().as_ref() {
            return sync.lock().sync.is_synced();
        }
        !self
            .sync_unfinished
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn is_known(&self, hash: &[u8; 32]) -> bool {
        self.winners.read().contains_key(hash)
    }

    /// A vote taken, by hash, as an `mnw` payload (ShareMasternodeWinnerWithPeer,
    /// MasternodeModule.cpp:329-338)
    pub fn winner_bytes(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.winners.read().get(hash).map(|(w, _)| w.encode())
    }

    /// Every vote taken: the height it is for and its hash
    pub fn heights_and_hashes(&self) -> Vec<(i32, [u8; 32])> {
        self.winners
            .read()
            .iter()
            .map(|(hash, (winner, _))| (winner.height, *hash))
            .collect()
    }

    /// A vote from a peer, checked as Divi Core checks one
    /// (CheckMasternodeWinnerCandidate, CheckMasternodeWinnerValidity,
    /// masternode-payments.cpp:203-331), then counted. Ok(true) when it was
    /// new and taken, so it is to be relayed.
    pub fn accept(
        &self,
        chain: &Chain,
        list: &MasternodeList,
        payload: &[u8],
    ) -> Result<bool, Refusal> {
        let winner = CppWinner::decode(payload).map_err(|e| format!("{e:?}"))?;
        let hash = winner.hash();
        if self.is_known(&hash) {
            return Ok(false);
        }
        let tip = chain.height() as i64;
        let height = winner.height as i64;
        if height < tip - WINNER_DEPTH || height > tip + 20 {
            return Err(format!("winner out of range: height {height}, tip {tip}").into());
        }
        let scoring = scoring_hash(chain, height).ok_or("no scoring block for the height")?;
        list.check_collateral(chain);
        // Asks are timed on GetTime, the masternode's state on
        // GetAdjustedTime (MasternodeNetworkMessageManager.cpp:203,
        // MasternodeHelpers.cpp:175)
        let now = divi_primitives::clock::now();
        let adjusted = divi_primitives::clock::adjusted_now();
        // An unknown masternode is asked for (masternode-payments.cpp:223-228)
        let voter = list
            .entries()
            .into_iter()
            .find(|e| {
                e.mnb.vin.prevout_hash == winner.vin.prevout_hash
                    && e.mnb.vin.prevout_n == winner.vin.prevout_n
            })
            .ok_or_else(|| Refusal {
                ask: list.ask_entry(&winner.vin, now),
                ..Refusal::from("unknown masternode")
            })?;
        if voter.mnb.protocol_version < ACTIVE_PROTOCOL {
            return Err("masternode protocol too old".into());
        }
        if !voter.is_enabled(adjusted) {
            return Err("masternode is not active".into());
        }
        match list.rank(
            chain,
            &winner.vin.prevout_hash,
            &scoring,
            2 * SIGNATURES_TOTAL,
        ) {
            Some(r) if r <= SIGNATURES_TOTAL => {}
            _ => return Err(format!("masternode not in the top {SIGNATURES_TOTAL}").into()),
        }
        // A node whose masternode sync is finished takes only a payee near
        // the top of its own queue
        if self.sync_finished()
            && !list
                .payment_queue(chain, &scoring, height, Some(self))
                .iter()
                .take(2 * SIGNATURES_TOTAL)
                .any(|p| *p == winner.payee)
        {
            return Err("payee not in the top of the payment queue".into());
        }
        let voter_key = (winner.vin.prevout_hash, winner.vin.prevout_n);
        if self
            .blocks
            .read()
            .get(&scoring)
            .is_some_and(|b| b.voters.contains(&voter_key))
        {
            return Err("masternode already voted".into());
        }
        if !winner.signature_is_valid(&voter.mnb.pubkey_masternode) {
            // It may be a masternode this node has not synced: asked for
            // (masternode-payments.cpp:241-245)
            // It costs its sender only on a node whose sync is finished
            return Err(Refusal {
                ask: list.ask_entry(&winner.vin, now),
                ..Refusal::scored(
                    if self.sync_finished() { 20 } else { 0 },
                    "Invalid signature for mnwinner.",
                    "invalid signature",
                )
            });
        }
        self.record(winner, hash, scoring, tip);
        Ok(true)
    }

    fn record(&self, winner: CppWinner, hash: [u8; 32], scoring: Hash256, tip: i64) {
        let mut winners = self.winners.write();
        let mut blocks = self.blocks.write();
        let entry = blocks.entry(scoring).or_insert_with(|| BlockPayees {
            height: winner.height,
            ..BlockPayees::default()
        });
        entry
            .voters
            .insert((winner.vin.prevout_hash, winner.vin.prevout_n));
        match entry.payees.iter_mut().find(|(p, _)| *p == winner.payee) {
            Some((_, votes)) => *votes += 1,
            None => entry.payees.push((winner.payee.clone(), 1)),
        }
        winners.insert(hash, (winner, scoring));
        prune(&mut winners, &mut blocks, tip);
    }

    /// mnpayments.dat as Divi Core's CFlatDB writes it (flat-database.h
    /// Write): the magic message, the network's magic number, the votes as
    /// MasternodePaymentData serialises them for disk, and the double SHA-256
    /// of all that
    fn file_bytes(&self, network_magic: [u8; 4]) -> Vec<u8> {
        let winners = self.winners.read();
        let blocks = self.blocks.read();
        let mut out = Vec::new();
        write_varbytes(&mut out, PAYMENTS_MAGIC.as_bytes());
        out.extend_from_slice(&network_magic);
        // mapMasternodePayeeVotes: hash -> the vote with its scoring block (SER_DISK,
        // MasternodePaymentWinner.h:59-70), in std::map's order
        let mut hashes: Vec<&[u8; 32]> = winners.keys().collect();
        hashes.sort_by(|a, b| cmp_u256(a, b));
        write_compact_size(&mut out, hashes.len());
        for h in hashes {
            let (w, scoring) = &winners[h];
            out.extend_from_slice(h);
            out.extend_from_slice(&w.encode());
            out.extend_from_slice(scoring.as_bytes());
        }
        // mapMasternodeBlocks: scoring hash -> height, payees and voters
        // (MasternodePayeeData.h:25-29, :60-65)
        let mut scorings: Vec<&Hash256> = blocks.keys().collect();
        scorings.sort_by(|a, b| cmp_u256(a.as_bytes(), b.as_bytes()));
        write_compact_size(&mut out, scorings.len());
        for s in scorings {
            let b = &blocks[s];
            out.extend_from_slice(s.as_bytes());
            out.extend_from_slice(&b.height.to_le_bytes());
            write_compact_size(&mut out, b.payees.len());
            for (script, votes) in &b.payees {
                write_varbytes(&mut out, script);
                out.extend_from_slice(&(*votes as i32).to_le_bytes());
            }
            let mut voters: Vec<&([u8; 32], u32)> = b.voters.iter().collect();
            voters.sort_by(|a, b| cmp_u256(&a.0, &b.0).then(a.1.cmp(&b.1)));
            write_compact_size(&mut out, voters.len());
            for (hash, n) in voters {
                out.extend_from_slice(hash);
                out.extend_from_slice(&n.to_le_bytes());
            }
        }
        let checksum = divi_crypto::double_sha256(&out);
        out.extend_from_slice(&checksum);
        out
    }

    /// Write the votes to `path` at a stop, as SaveMasternodeDataToDisk does
    /// (MasternodeModule.cpp:284-297). Like CFlatDB::Dump it leaves a file it
    /// cannot read as its own alone. Ok(false) when it was left
    pub fn save(&self, path: &std::path::Path, network_magic: [u8; 4]) -> std::io::Result<bool> {
        if let PaymentsFile::Invalid(_) = read_file(path, network_magic).0 {
            return Ok(false);
        }
        let tmp = path.with_extension("dat.new");
        std::fs::write(&tmp, self.file_bytes(network_magic))?;
        std::fs::rename(&tmp, path)?;
        Ok(true)
    }

    /// Read the votes from `path` at a start, as LoadMasternodeDataFromDisk
    /// does (MasternodeModule.cpp:269-280), then drop the ones more than 1000
    /// blocks below `tip`, as pruneOutdatedMasternodeWinners does within the
    /// first minute (MasternodeModule.cpp:515-519). Votes already taken are
    /// kept. What the file came to is returned; Invalid stops a start
    pub fn load(&self, path: &std::path::Path, network_magic: [u8; 4], tip: i64) -> PaymentsFile {
        let (outcome, data) = read_file(path, network_magic);
        if let Some((winners, blocks)) = data {
            let mut w = self.winners.write();
            let mut b = self.blocks.write();
            for (hash, vote) in winners {
                w.entry(hash).or_insert(vote);
            }
            for (scoring, payees) in blocks {
                b.entry(scoring).or_insert(payees);
            }
            prune(&mut w, &mut b, tip);
        }
        outcome
    }

    /// The payees voted for the block scored with `scoring`, as
    /// ParsePayeesIntoPaymentsString writes them: "address:votes, ..." or
    /// "Unknown" (rpcmasternode.cpp:462-478)
    fn payments_string(&self, scoring: &Hash256, network: Network) -> String {
        let blocks = self.blocks.read();
        let Some(b) = blocks.get(scoring) else {
            return "Unknown".into();
        };
        if b.payees.is_empty() {
            return "Unknown".into();
        }
        b.payees
            .iter()
            .map(|(script, votes)| format!("{}:{}", script_address(script, network), votes))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `getmasternodewinners ( blocks "filter" )` as Divi Core answers it
    /// (rpcmasternode.cpp:489-578): heights from tip - blocks to tip + 19
    /// that have a scoring block, with their voted payees
    pub fn winners_json(&self, chain: &Chain, blocks: i64, filter: &str) -> serde_json::Value {
        let tip = chain.height() as i64;
        let network = match chain.network_type() {
            NetworkType::Mainnet => Network::Mainnet,
            NetworkType::Testnet => Network::Testnet,
            NetworkType::Regtest => Network::Regtest,
        };
        let mut out = Vec::new();
        let mut i = tip - blocks;
        while i < tip + 20 {
            let height = i;
            i += 1;
            let Some(scoring) = scoring_hash(chain, height) else {
                continue;
            };
            let payment = self.payments_string(&scoring, network);
            if !filter.is_empty() && !payment.contains(filter) {
                continue;
            }
            // Split on "," only, as boost's char_separator does: an address
            // after the first keeps the space before it
            let entry = |t: &str| {
                let (address, votes) = match t.find(':') {
                    Some(pos) => (&t[..pos], atoi(&t[pos + 1..])),
                    None => (t, 0),
                };
                serde_json::json!({"address": address, "nVotes": votes.max(0) as u64})
            };
            let winner = if payment.contains(',') {
                serde_json::Value::Array(payment.split(',').map(entry).collect())
            } else if !payment.contains("Unknown") {
                entry(&payment)
            } else {
                serde_json::json!({"address": payment, "nVotes": 0})
            };
            out.push(serde_json::json!({"nHeight": height, "winner": winner}));
        }
        serde_json::Value::Array(out)
    }

    /// PruneOldMasternodeWinnerData, which divid's masternode thread runs once
    /// a minute: the votes for heights more than 1000 below the tip go
    /// (MasternodeModule.cpp:515-519, masternode-payments.cpp:412-417)
    pub fn prune_old(&self, tip: i64) {
        if tip > 0 {
            prune(&mut self.winners.write(), &mut self.blocks.write(), tip);
        }
    }

    /// CMasternodePayments::IsScheduled (masternode-payments.cpp:332-352):
    /// whether `payee` has the most votes (GetPayee) for one of the heights
    /// from the tip to 8 above it, other than `not_height`
    pub fn is_scheduled(&self, chain: &Chain, payee: &[u8], not_height: i64) -> bool {
        let tip = chain.height() as i64;
        (0..=8)
            .filter(|h| tip + h != not_height)
            .any(|h| top_payee(&self.votes_for_height(chain, tip + h)).is_some_and(|p| p == payee))
    }

    /// CMasternodeBlockPayees::HasPayeeWithVotes (MasternodePayeeData.cpp:82-91)
    /// for the block scored at `height`
    pub fn has_payee_with_votes(
        &self,
        chain: &Chain,
        height: i64,
        payee: &[u8],
        required: u32,
    ) -> bool {
        self.votes_for_height(chain, height)
            .iter()
            .any(|(script, votes)| *votes >= required && script == payee)
    }

    /// The payee scripts and their votes for a height, highest count first
    /// as CMasternodeBlockPayees::GetPayee picks (the first of a tie)
    pub fn votes_for_height(&self, chain: &Chain, height: i64) -> Vec<(Vec<u8>, u32)> {
        let Some(scoring) = scoring_hash(chain, height) else {
            return Vec::new();
        };
        self.blocks
            .read()
            .get(&scoring)
            .map(|b| b.payees.clone())
            .unwrap_or_default()
    }
}

/// ExtractDestination of a payee script as an address string; an empty
/// string for a script that is not one (as CBitcoinAddress of no
/// destination)
fn script_address(script: &[u8], network: Network) -> String {
    if script.len() == 25 && script[..3] == [0x76, 0xa9, 0x14] && script[23..] == [0x88, 0xac] {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        return Address::from_pubkey_hash(divi_primitives::hash::Hash160::from_bytes(h), network)
            .to_base58();
    }
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[2..22]);
        return Address::p2sh(divi_primitives::hash::Hash160::from_bytes(h), network).to_base58();
    }
    String::new()
}

/// C atoi: leading spaces, a sign, digits up to the first other character
fn atoi(v: &str) -> i64 {
    let v = v.trim_start();
    let (neg, digits) = match v.as_bytes().first() {
        Some(b'-') => (true, &v[1..]),
        Some(b'+') => (false, &v[1..]),
        _ => (false, v),
    };
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    let n = digits[..end].parse::<i64>().unwrap_or(0);
    if neg {
        -n
    } else {
        n
    }
}

/// CMasternodeBlockPayees::GetPayee: the payee with the most votes, the
/// first of a tie (MasternodePayeeData.cpp:67-80)
fn top_payee(payees: &[(Vec<u8>, u32)]) -> Option<&[u8]> {
    let mut best: Option<(&[u8], u32)> = None;
    for (script, votes) in payees {
        if best.is_none_or(|(_, n)| *votes > n) {
            best = Some((script, *votes));
        }
    }
    best.map(|(script, _)| script)
}

/// pruneOutdatedMasternodeWinners: the votes for heights more than 1000
/// below `tip` go, with their block's counts (MasternodePaymentData.cpp:46-61)
fn prune(
    winners: &mut HashMap<[u8; 32], (CppWinner, Hash256)>,
    blocks: &mut HashMap<Hash256, BlockPayees>,
    tip: i64,
) {
    let old: Vec<[u8; 32]> = winners
        .iter()
        .filter(|(_, (w, _))| tip - w.height as i64 > KEEP_DEPTH)
        .map(|(h, _)| *h)
        .collect();
    for h in old {
        if let Some((_, s)) = winners.remove(&h) {
            blocks.remove(&s);
        }
    }
}

type FileVotes = (
    HashMap<[u8; 32], (CppWinner, Hash256)>,
    HashMap<Hash256, BlockPayees>,
);

/// The votes as MasternodePaymentData serialises them for disk
fn parse_votes(r: &mut Reader<'_>) -> Option<FileVotes> {
    let mut winners = HashMap::new();
    for _ in 0..r.compact_size()? {
        let hash: [u8; 32] = r.array()?;
        let vin = divi_masternode::cpp_wire::CppTxIn {
            prevout_hash: r.array()?,
            prevout_n: r.u32()?,
            script_sig: r.varbytes()?,
            sequence: r.u32()?,
        };
        let winner = CppWinner {
            vin,
            height: r.i32()?,
            payee: r.varbytes()?,
            signature: r.varbytes()?,
        };
        let scoring = Hash256(r.array()?);
        winners.insert(hash, (winner, scoring));
    }
    let mut blocks = HashMap::new();
    for _ in 0..r.compact_size()? {
        let scoring = Hash256(r.array()?);
        let height = r.i32()?;
        let mut payees = Vec::new();
        for _ in 0..r.compact_size()? {
            let script = r.varbytes()?;
            payees.push((script, r.i32()?.max(0) as u32));
        }
        let mut voters = HashSet::new();
        for _ in 0..r.compact_size()? {
            voters.insert((r.array()?, r.u32()?));
        }
        blocks.insert(
            scoring,
            BlockPayees {
                height,
                payees,
                voters,
            },
        );
    }
    Some((winners, blocks))
}

/// CFlatDB::Read of mnpayments.dat: the data and its checksum, then the magic
/// message, the network's magic number and the votes (flat-database.h,
/// flat-database.cpp:18-60)
fn read_file(path: &std::path::Path, network_magic: [u8; 4]) -> (PaymentsFile, Option<FileVotes>) {
    let data = match flat_file::read(path, PAYMENTS_MAGIC, network_magic) {
        Ok(data) => data,
        Err(Header::Missing) => return (PaymentsFile::Missing, None),
        Err(Header::BadFormat) => return (PaymentsFile::BadFormat, None),
        Err(Header::Invalid(why)) => return (PaymentsFile::Invalid(why), None),
    };
    let mut r = Reader::new(&data);
    match parse_votes(&mut r) {
        Some(votes) => (PaymentsFile::Loaded(votes.0.len()), Some(votes)),
        None => (PaymentsFile::BadFormat, None),
    }
}
