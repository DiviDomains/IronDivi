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

//! Masternode payment votes (`mnw`) as Divi Core keeps them: each vote that
//! passes Core's checks counted for its payee under the block it is scored
//! with, one vote per masternode (MasternodePaymentData, MasternodePayeeData).
//! `getmasternodewinners` reads them.

use crate::mn_list::{scoring_hash, MasternodeList};
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

/// The votes for one block (CMasternodeBlockPayees): the payees in the order
/// they first got a vote, with their counts, and who voted
#[derive(Debug, Clone, Default)]
struct BlockPayees {
    payees: Vec<(Vec<u8>, u32)>,
    voters: HashSet<([u8; 32], u32)>,
}

#[derive(Default)]
pub struct MasternodeVotes {
    /// Every vote taken, by its hash, with the block it is scored with
    winners: RwLock<HashMap<[u8; 32], (CppWinner, Hash256)>>,
    /// The counts per scoring block
    blocks: RwLock<HashMap<Hash256, BlockPayees>>,
}

impl MasternodeVotes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_known(&self, hash: &[u8; 32]) -> bool {
        self.winners.read().contains_key(hash)
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
    ) -> Result<bool, String> {
        let winner = CppWinner::decode(payload).map_err(|e| format!("{e:?}"))?;
        let hash = winner.hash();
        if self.is_known(&hash) {
            return Ok(false);
        }
        let tip = chain.height() as i64;
        let height = winner.height as i64;
        if height < tip - WINNER_DEPTH || height > tip + 20 {
            return Err(format!("winner out of range: height {height}, tip {tip}"));
        }
        let scoring = scoring_hash(chain, height).ok_or("no scoring block for the height")?;
        list.check_collateral(chain);
        let voter = list
            .entries()
            .into_iter()
            .find(|e| {
                e.mnb.vin.prevout_hash == winner.vin.prevout_hash
                    && e.mnb.vin.prevout_n == winner.vin.prevout_n
            })
            .ok_or("unknown masternode")?;
        if voter.mnb.protocol_version < ACTIVE_PROTOCOL {
            return Err("masternode protocol too old".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if !voter.is_enabled(now) {
            return Err("masternode is not active".into());
        }
        match list.rank(
            chain,
            &winner.vin.prevout_hash,
            &scoring,
            2 * SIGNATURES_TOTAL,
        ) {
            Some(r) if r <= SIGNATURES_TOTAL => {}
            _ => return Err(format!("masternode not in the top {SIGNATURES_TOTAL}")),
        }
        // A node whose masternode sync is finished (irondivid's always is)
        // takes only a payee near the top of its own queue
        let queue = list.payment_queue(chain, &scoring);
        if !queue
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
            return Err("invalid signature".into());
        }
        self.record(winner, hash, scoring, tip);
        Ok(true)
    }

    fn record(&self, winner: CppWinner, hash: [u8; 32], scoring: Hash256, tip: i64) {
        let mut winners = self.winners.write();
        let mut blocks = self.blocks.write();
        let entry = blocks.entry(scoring).or_default();
        entry
            .voters
            .insert((winner.vin.prevout_hash, winner.vin.prevout_n));
        match entry.payees.iter_mut().find(|(p, _)| *p == winner.payee) {
            Some((_, votes)) => *votes += 1,
            None => entry.payees.push((winner.payee.clone(), 1)),
        }
        winners.insert(hash, (winner, scoring));
        // pruneOutdatedMasternodeWinners
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
