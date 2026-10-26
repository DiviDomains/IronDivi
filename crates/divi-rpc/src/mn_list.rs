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

//! The masternodes the network announces, kept as Divi Core keeps them: the
//! broadcasts (`mnb`) in Core's wire format that pass its checks, in the order
//! they arrived (CMasternodeMan's vector), each with its last ping (`mnp`).
//! `listmasternodes` and `getmasternodecount` read this list. It is saved in
//! the datadir as Core saves mncache.dat, so it is there after a restart.

use crate::mn_broadcast::{find_collateral, ping_signature_valid, tier_for_collateral};
use divi_masternode::cpp_wire::{CppBroadcast, CppPing, CppTxIn};
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::transaction::OutPoint;
use divi_storage::{Chain, NetworkType};
use divi_wallet::address::Address;
use divi_wallet::Network;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::PathBuf;

/// MASTERNODE_MIN_CONFIRMATIONS (masternode.h:16)
const MIN_CONFIRMATIONS: u32 = 15;
/// MASTERNODE_MIN_MNP_SECONDS, MASTERNODE_MIN_MNB_SECONDS (masternode.h:17-18)
const MIN_MNP_SECONDS: i64 = 10 * 60;
const MIN_MNB_SECONDS: i64 = 5 * 60;
/// A ping names a block at most this far below the tip (masternodeman.cpp:342-352)
const PING_BLOCK_DEPTH: u32 = 24;
/// MASTERNODE_EXPIRATION_SECONDS, MASTERNODE_REMOVAL_SECONDS (masternode.h:20-21)
const EXPIRATION_SECONDS: i64 = 120 * 60;
const REMOVAL_SECONDS: i64 = 130 * 60;
/// MN_WINNER_MINIMUM_AGE as StableMasternodeCount uses it, on every network
/// (RpcMasternodeFeatures.cpp:26, :344)
const STABLE_AGE: i64 = 8000;
/// ActiveProtocol() without -activeversion (version.cpp:11-17, version.h:21)
const ACTIVE_PROTOCOL: i32 = 70915;
/// A height is scored with the block this far below it (MasternodeHelpers.cpp:80)
const SCORING_DEPTH: u32 = 101;

/// One masternode: its broadcast (whose `last_ping` is the last ping taken)
/// and whether its collateral was seen spent, which Core keeps for good once
/// set (masternodeman.cpp:160-161)
#[derive(Debug, Clone)]
pub struct NetworkMasternode {
    pub mnb: CppBroadcast,
    pub vin_spent: bool,
}

impl NetworkMasternode {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(Hash256(self.mnb.vin.prevout_hash), self.mnb.vin.prevout_n)
    }

    /// CMasternode::Status for the state CMasternodeMan::Check gives it
    /// (masternodeman.cpp:152-180, masternode.cpp:134-145)
    pub fn status(&self, now: i64) -> &'static str {
        if self.vin_spent {
            return "VIN_SPENT";
        }
        let since_ping = now - self.mnb.last_ping.sig_time;
        if since_ping > REMOVAL_SECONDS {
            "REMOVE"
        } else if since_ping > EXPIRATION_SECONDS {
            "EXPIRED"
        } else {
            "ENABLED"
        }
    }

    pub fn is_enabled(&self, now: i64) -> bool {
        self.status(now) == "ENABLED"
    }
}

/// Why a masternode message from a peer was not taken, and the misbehaviour
/// score Divi Core gives the peer for it (its nDoS, 0 for none) with the
/// cause it names
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub dos: u32,
    pub cause: &'static str,
    pub reason: String,
    /// A `dseg` payload to send the peer, asking it for the masternode
    /// (CMasternodeSync::AskForMN, masternode-sync.cpp:456-462)
    pub ask: Option<Vec<u8>>,
}

impl Refusal {
    pub(crate) fn scored(dos: u32, cause: &'static str, reason: impl Into<String>) -> Self {
        Refusal {
            dos,
            cause,
            reason: reason.into(),
            ask: None,
        }
    }
}

impl From<&str> for Refusal {
    fn from(reason: &str) -> Self {
        Refusal::scored(0, "", reason)
    }
}

impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Refusal::scored(0, "", reason)
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// The causes Divi Core names for these scores (masternodeman.cpp:428-466, :519-528)
const BAD_CONTEXT: &str = "Bad masternode broadcast context";
const MISMATCHED_VIN: &str = "Mismatched pubkey and vin for masternode";
const INVALID_PING: &str = "Invalid masternode ping";
const PING_FAILED: &str = "Ping update failed";

/// The inv types of masternode messages (protocol.h:136-144)
pub const INV_WINNER: u32 = 7;
pub const INV_BROADCAST: u32 = 14;
pub const INV_PING: u32 = 15;

#[derive(Default)]
pub struct MasternodeList {
    entries: RwLock<Vec<NetworkMasternode>>,
    path: RwLock<Option<PathBuf>>,
    /// The broadcasts and pings taken, by hash, which a peer may ask for
    /// (mapSeenMasternodeBroadcast, mapSeenMasternodePing)
    seen_broadcasts: RwLock<HashMap<[u8; 32], CppBroadcast>>,
    seen_pings: RwLock<HashMap<[u8; 32], CppPing>>,
    /// IsBlockchainSynced's state: synced once, and when it was last checked
    chain_synced: Mutex<(bool, i64)>,
    /// When each masternode may be asked for again
    /// (mWeAskedForMasternodeListEntry, MasternodeNetworkMessageManager.cpp:191-205)
    asked_entries: Mutex<HashMap<([u8; 32], u32), i64>>,
    /// Invs to relay, as CMasternodeBroadcast::Relay and CMasternodePing::Relay
    /// leave them for every peer (masternode.cpp:241-245, MasternodePing.cpp:17-21)
    relays: Mutex<Vec<(u32, [u8; 32])>>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl MasternodeList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep the list in `path` and read what is there
    pub fn set_path(&self, path: PathBuf) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let mut loaded = Vec::new();
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                let (Some(hex), spent) = (parts.next(), parts.next()) else {
                    continue;
                };
                if let Some(mnb) = hex::decode(hex)
                    .ok()
                    .and_then(|b| CppBroadcast::decode(&b).ok())
                {
                    loaded.push(NetworkMasternode {
                        mnb,
                        vin_spent: spent == Some("spent"),
                    });
                }
            }
            // Core keeps its seen broadcasts and pings in mncache.dat with the
            // list (MasternodeNetworkMessageManager.h:68-78), so after a restart
            // it still knows and serves them: each entry's broadcast and last ping
            {
                let mut broadcasts = self.seen_broadcasts.write();
                let mut pings = self.seen_pings.write();
                for e in &loaded {
                    broadcasts.insert(e.mnb.hash(), e.mnb.clone());
                    pings.insert(e.mnb.last_ping.hash(), e.mnb.last_ping.clone());
                }
            }
            *self.entries.write() = loaded;
        }
        *self.path.write() = Some(path);
    }

    fn save(&self) {
        let Some(path) = self.path.read().clone() else {
            return;
        };
        let text: String = self
            .entries
            .read()
            .iter()
            .map(|e| {
                format!(
                    "{} {}\n",
                    hex::encode(e.mnb.encode()),
                    if e.vin_spent { "spent" } else { "ok" }
                )
            })
            .collect();
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    /// A broadcast from a peer: checked as Divi Core checks one
    /// (CMasternodeBroadcast::CheckAndUpdate, CheckInputsAndAdd,
    /// CMasternodeMan::ProcessBroadcast), then added, or replacing an older
    /// broadcast of the same collateral. Ok(true) when the list changed.
    pub fn accept_broadcast(&self, chain: &Chain, payload: &[u8]) -> Result<bool, Refusal> {
        let mnb = CppBroadcast::decode(payload).map_err(|e| format!("{e:?}"))?;
        self.accept_decoded(chain, mnb, now())
    }

    fn accept_decoded(&self, chain: &Chain, mnb: CppBroadcast, now: i64) -> Result<bool, Refusal> {
        if self.seen_broadcasts.read().contains_key(&mnb.hash()) {
            return Ok(false);
        }
        // CheckMasternodeBroadcastContext (masternodeman.cpp:232-265)
        if mnb.sig_time > now + 3600 {
            return Err(Refusal::scored(
                1,
                BAD_CONTEXT,
                "signature too far in the future",
            ));
        }
        if !(0..=4).contains(&mnb.tier) {
            return Err(Refusal::scored(
                20,
                BAD_CONTEXT,
                format!("invalid tier {}", mnb.tier),
            ));
        }
        if mnb.protocol_version < ACTIVE_PROTOCOL {
            return Err("obsolete protocol version".into());
        }
        if !mnb.vin.script_sig.is_empty() {
            return Err("the input has a scriptSig".into());
        }
        if !mnb.signature_is_valid() {
            return Err(Refusal::scored(100, BAD_CONTEXT, "bad broadcast signature"));
        }
        let hash = Hash256(mnb.vin.prevout_hash);
        let outpoint = OutPoint::new(hash, mnb.vin.prevout_n);
        // UpdateMasternodeFromBroadcast (masternodeman.cpp:267-307): an older
        // broadcast is refused; a newer one with the same collateral key
        // replaces an enabled entry when that entry is five minutes old
        let mut changed = false;
        let existing_enabled = {
            let mut entries = self.entries.write();
            match entries.iter_mut().find(|e| e.outpoint() == outpoint) {
                None => false,
                Some(e) => {
                    if e.mnb.sig_time > mnb.sig_time {
                        return Err("older than the broadcast in the list".into());
                    }
                    let enabled = e.is_enabled(now);
                    if enabled
                        && e.mnb.pubkey_collateral == mnb.pubkey_collateral
                        && now - e.mnb.sig_time >= MIN_MNB_SECONDS
                        && mnb.sig_time > e.mnb.sig_time
                    {
                        // UpdateWithNewBroadcast, then its ping if it may be taken
                        let last_ping = e.mnb.last_ping.clone();
                        let ping = mnb.last_ping.clone();
                        e.mnb = CppBroadcast {
                            last_ping: last_ping.clone(),
                            ..mnb.clone()
                        };
                        if !ping_is_empty(&ping)
                            && check_ping(chain, &e.mnb, Some(&last_ping), &ping, now).is_ok()
                        {
                            e.mnb.last_ping = ping;
                            self.record_ping(&e.mnb);
                            self.relays.lock().push((INV_PING, e.mnb.last_ping.hash()));
                        }
                        // Relayed when enabled, but not kept as seen
                        // (masternodeman.cpp:296-303)
                        if e.is_enabled(now) {
                            self.relays.lock().push((INV_BROADCAST, mnb.hash()));
                        }
                        changed = true;
                    }
                    enabled
                }
            }
        };
        if changed {
            self.save();
        }
        // IsVinAssociatedWithPubkey (masternodeman.cpp:57-74): the collateral
        // pays the tier's amount to the broadcast's collateral key
        let mismatched = || {
            Refusal::scored(
                33,
                MISMATCHED_VIN,
                "collateral does not match the broadcast's key and tier",
            )
        };
        let coll = find_collateral(chain, &hash, mnb.vin.prevout_n).ok_or_else(mismatched)?;
        if tier_for_collateral(chain, coll.amount) != Some(mnb.tier)
            || coll.script != payee_script(&mnb)
        {
            return Err(mismatched());
        }
        // CheckInputsForMasternode (masternodeman.cpp:196-230), unless the
        // masternode is listed and enabled
        if !existing_enabled {
            if !matches!(chain.get_utxo(&outpoint), Ok(Some(u)) if u.value.0 == coll.amount) {
                return Err("collateral is spent".into());
            }
            let conf_height = coll.height + MIN_CONFIRMATIONS - 1;
            if conf_height > chain.height() {
                return Err(format!(
                    "collateral must have at least {MIN_CONFIRMATIONS} confirmations"
                )
                .into());
            }
            let conf = chain
                .get_block_index_by_height(conf_height)
                .ok()
                .flatten()
                .ok_or("no confirmation block")?;
            if conf.time as i64 > mnb.sig_time {
                return Err("signed before the collateral's confirmation block".into());
            }
        }
        // The attached ping, checked as for a masternode with no ping yet
        // (masternodeman.cpp:456-466)
        check_ping(chain, &mnb, None, &mnb.last_ping, now).map_err(|r| Refusal {
            cause: INVALID_PING,
            ..r
        })?;
        // Listed and enabled: nothing more to do (masternodeman.cpp:476-487)
        if existing_enabled {
            return Ok(changed);
        }
        self.seen_broadcasts.write().insert(mnb.hash(), mnb.clone());
        self.record_ping(&mnb);
        // Relayed unless its address is private or local, on regtest always
        // (masternodeman.cpp:495-499)
        if chain.network_type() == NetworkType::Regtest || !is_private_or_local(&mnb.ip) {
            self.relays.lock().push((INV_BROADCAST, mnb.hash()));
        }
        {
            let mut entries = self.entries.write();
            entries.retain(|e| e.outpoint() != outpoint);
            entries.push(NetworkMasternode {
                mnb,
                vin_spent: false,
            });
        }
        self.save();
        Ok(true)
    }

    /// recordLastPing: the masternode's last ping is seen, and so is the
    /// broadcast it belongs to with that ping (MasternodeNetworkMessageManager.cpp:246-256)
    fn record_ping(&self, mnb: &CppBroadcast) {
        self.seen_pings
            .write()
            .insert(mnb.last_ping.hash(), mnb.last_ping.clone());
        if let Some(seen) = self.seen_broadcasts.write().get_mut(&mnb.hash()) {
            seen.last_ping = mnb.last_ping.clone();
        }
    }

    /// IsBlockchainSynced, which divid's masternode messages wait for: the tip
    /// at most ten minutes old; once so it stays so, unless more than an hour
    /// passes between two checks (MasternodeHelpers.cpp:27-66,
    /// MasternodeModule.cpp:371-382)
    pub fn blockchain_synced(&self, chain: &Chain) -> bool {
        let now = now();
        let mut state = self.chain_synced.lock();
        let stalled = state.1 != 0 && now - state.1 > 3600;
        state.1 = now;
        if stalled {
            state.0 = false;
        }
        if !state.0 {
            state.0 = chain.tip().is_some_and(|t| t.time as i64 + 600 >= now);
        }
        state.0
    }

    /// recordMasternodeEntryRequestAttempt: the `dseg` payload asking for the
    /// masternode of `vin`, unless it was asked for in the last ten minutes
    /// (MasternodeNetworkMessageManager.cpp:191-205)
    pub fn ask_entry(&self, vin: &CppTxIn, now: i64) -> Option<Vec<u8>> {
        let mut asked = self.asked_entries.lock();
        let key = (vin.prevout_hash, vin.prevout_n);
        if asked.get(&key).is_some_and(|t| now < *t) {
            return None;
        }
        asked.retain(|_, t| now < *t);
        asked.insert(key, now + MIN_MNP_SECONDS);
        Some(vin.to_bytes())
    }

    /// The invs left to relay since the last call
    pub fn take_relays(&self) -> Vec<(u32, [u8; 32])> {
        std::mem::take(&mut *self.relays.lock())
    }

    /// A broadcast taken, by hash, as an `mnb` payload (ShareMasternodeBroadcastWithPeer)
    pub fn seen_broadcast(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.seen_broadcasts.read().get(hash).map(|m| m.encode())
    }

    /// A ping taken, by hash, as an `mnp` payload (ShareMasternodePingWithPeer)
    pub fn seen_ping(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.seen_pings.read().get(hash).map(|p| p.to_bytes())
    }

    /// Whether a broadcast or ping of this inv type and hash was taken
    /// (AlreadyHave, main.cpp:157-162)
    pub fn has(&self, inv_type: u32, hash: &[u8; 32]) -> bool {
        match inv_type {
            INV_BROADCAST => self.seen_broadcasts.read().contains_key(hash),
            INV_PING => self.seen_pings.read().contains_key(hash),
            _ => false,
        }
    }

    /// A ping from a peer: taken for an enabled masternode in the list when
    /// it passes CheckAndUpdatePing: its time, not too early after the last
    /// ping, signed by the masternode key, naming a known block at most 24
    /// below the tip (masternodeman.cpp:309-375, :504-534). Ok(true) when the
    /// ping was taken.
    pub fn accept_ping(&self, chain: &Chain, payload: &[u8]) -> Result<bool, Refusal> {
        let ping = CppPing::decode_bytes(payload).map_err(|e| format!("{e:?}"))?;
        if self.seen_pings.read().contains_key(&ping.hash()) {
            return Ok(false);
        }
        let now = now();
        {
            let mut entries = self.entries.write();
            let Some(e) = entries.iter_mut().find(|e| {
                e.mnb.vin.prevout_hash == ping.vin.prevout_hash
                    && e.mnb.vin.prevout_n == ping.vin.prevout_n
            }) else {
                // An unknown masternode is asked for (masternodeman.cpp:529-533)
                return Err(Refusal {
                    ask: self.ask_entry(&ping.vin, now),
                    ..Refusal::from("unknown masternode")
                });
            };
            if !e.is_enabled(now) {
                return Ok(false);
            }
            // A ping that costs its sender also asks it for the masternode
            // (masternodeman.cpp:519-533)
            check_ping(chain, &e.mnb, Some(&e.mnb.last_ping), &ping, now).map_err(|r| Refusal {
                cause: PING_FAILED,
                ask: (r.dos > 0)
                    .then(|| self.ask_entry(&ping.vin, now))
                    .flatten(),
                ..r
            })?;
            e.mnb.last_ping = ping;
            self.record_ping(&e.mnb);
            self.relays.lock().push((INV_PING, e.mnb.last_ping.hash()));
        }
        self.save();
        Ok(true)
    }

    /// Mark the masternodes whose collateral the active chain has spent
    /// (CMasternodeMan::Check's IsCoinSpent)
    pub fn check_collateral(&self, chain: &Chain) {
        let mut changed = false;
        {
            let mut entries = self.entries.write();
            for e in entries.iter_mut().filter(|e| !e.vin_spent) {
                if matches!(chain.get_utxo(&e.outpoint()), Ok(None)) {
                    e.vin_spent = true;
                    changed = true;
                }
            }
        }
        if changed {
            self.save();
        }
    }

    /// Drop the masternodes whose collateral is spent, whose last ping is
    /// past the removal time, or whose protocol is below the active one, with
    /// their seen broadcasts and the record of asking for them
    /// (MasternodeNetworkMessageManager.cpp:36-56, :132-155)
    pub fn remove_inactive(&self, now: i64) {
        let removed: Vec<NetworkMasternode> = {
            let mut entries = self.entries.write();
            let (gone, kept) = std::mem::take(&mut *entries).into_iter().partition(|e| {
                matches!(e.status(now), "VIN_SPENT" | "REMOVE")
                    || e.mnb.protocol_version < ACTIVE_PROTOCOL
            });
            *entries = kept;
            gone
        };
        if removed.is_empty() {
            return;
        }
        {
            let mut seen = self.seen_broadcasts.write();
            let mut asked = self.asked_entries.lock();
            for e in &removed {
                let vin = (e.mnb.vin.prevout_hash, e.mnb.vin.prevout_n);
                seen.retain(|_, b| (b.vin.prevout_hash, b.vin.prevout_n) != vin);
                asked.remove(&vin);
            }
        }
        self.save();
    }

    pub fn entries(&self) -> Vec<NetworkMasternode> {
        self.entries.read().clone()
    }

    /// `listmasternodes ( "filter" )` as Divi Core answers it
    /// (rpcmasternode.cpp:263-325, RpcMasternodeFeatures.cpp:279-324). Like
    /// divid it shows the state of the last check: it does not check the
    /// collateral itself (getmasternodecount and a timer do). `lastpaid`
    /// comes from the payment votes `votes` holds.
    pub fn list_json(
        &self,
        chain: &Chain,
        filter: Option<&str>,
        votes: Option<&crate::mn_votes::MasternodeVotes>,
    ) -> serde_json::Value {
        let now = now();
        let network = address_network(chain);
        let filter = filter.unwrap_or("");
        let mut out = Vec::new();
        let entries = self.entries();
        // numberOfBlocksToSearchBackForLastPayment (RpcMasternodeFeatures.cpp:289)
        let search_depth = entries.len() * 5 / 4;
        for e in entries {
            let txhash = Hash256(e.mnb.vin.prevout_hash).to_string();
            let status = e.status(now);
            let address = collateral_address(&e.mnb, network);
            if !filter.is_empty()
                && !txhash.contains(filter)
                && !status.contains(filter)
                && !address.contains(filter)
            {
                continue;
            }
            out.push(serde_json::json!({
                "network": network_name(&e.mnb),
                "txhash": txhash,
                "outidx": e.mnb.vin.prevout_n,
                "status": status,
                "addr": address,
                "version": e.mnb.protocol_version,
                "lastseen": e.mnb.last_ping.sig_time,
                "activetime": e.mnb.last_ping.sig_time - e.mnb.sig_time,
                "lastpaid": votes.map_or(0, |v| last_paid_time(chain, v, &e.mnb, search_depth)),
                "tier": tier_name(e.mnb.tier),
            }));
        }
        serde_json::Value::Array(out)
    }

    /// `getmasternodecount`'s eight counts as Divi Core gives them
    /// (rpcmasternode.cpp:327-358, RpcMasternodeFeatures.cpp:326-422); it
    /// checks every masternode first, as Core's counts call Check()
    pub fn counts(&self, chain: &Chain) -> MasternodeCounts {
        self.check_collateral(chain);
        let now = now();
        let entries = self.entries();
        let enabled: Vec<&NetworkMasternode> = entries
            .iter()
            .filter(|e| e.mnb.protocol_version >= ACTIVE_PROTOCOL && e.is_enabled(now))
            .collect();
        let mn_count = enabled.len();
        let tip = chain.height();
        // No queue before there is a block to score with, 101 below the tip
        // (GetBlockHashForScoring, MasternodeHelpers.cpp:75-86)
        let queue = match scoring_hash(chain, tip as i64) {
            Some(hash) => self.queue_from(chain, &entries, &hash, now).len(),
            None => 0,
        };
        let (mut ipv4, mut ipv6, mut onion) = (0, 0, 0);
        for e in &entries {
            match network_name(&e.mnb) {
                "ipv4" => ipv4 += 1,
                "ipv6" => ipv6 += 1,
                "onion" => onion += 1,
                _ => {}
            }
        }
        MasternodeCounts {
            total: entries.len(),
            stable: enabled
                .iter()
                .filter(|e| now - e.mnb.sig_time >= STABLE_AGE)
                .count(),
            enabled: mn_count,
            inqueue: queue,
            ipv4,
            ipv6,
            onion,
        }
    }
}

impl MasternodeList {
    /// GetMasternodePaymentQueue for a scoring block: the enabled
    /// masternodes in a pass that skips the young ones and, when it finds
    /// under a third of them, a second pass without that filter whose entries
    /// are added to the first's; then by score, highest first
    /// (masternode-payments.cpp:435-545). Each entry is the masternode's
    /// payee script (P2PKH of its collateral key).
    pub fn payment_queue(&self, chain: &Chain, scoring: &Hash256) -> Vec<Vec<u8>> {
        self.check_collateral(chain);
        self.queue_from(chain, &self.entries(), scoring, now())
    }

    fn queue_from(
        &self,
        chain: &Chain,
        entries: &[NetworkMasternode],
        scoring: &Hash256,
        now: i64,
    ) -> Vec<Vec<u8>> {
        let enabled: Vec<&NetworkMasternode> = entries
            .iter()
            .filter(|e| e.mnb.protocol_version >= ACTIVE_PROTOCOL && e.is_enabled(now))
            .collect();
        let mn_count = enabled.len();
        let tip = chain.height();
        let pass = |filter_sig_time: bool| -> Vec<&NetworkMasternode> {
            enabled
                .iter()
                .filter(|e| {
                    !(filter_sig_time
                        && e.mnb.sig_time + (mn_count as f64 * 2.6 * 60.0) as i64 > now)
                })
                .filter(|e| {
                    find_collateral(chain, &Hash256(e.mnb.vin.prevout_hash), e.mnb.vin.prevout_n)
                        .map(|c| (tip + 1).saturating_sub(c.height) as usize >= mn_count)
                        .unwrap_or(false)
                })
                .copied()
                .collect()
        };
        let mut queue = pass(true);
        if queue.len() < mn_count / 3 {
            queue.extend(pass(false));
        }
        let mut scored: Vec<([u8; 32], &NetworkMasternode)> = queue
            .into_iter()
            .map(|e| (calculate_score(&e.mnb, scoring), e))
            .collect();
        scored.sort_by(|a, b| cmp_u256(&b.0, &a.0));
        scored
            .into_iter()
            .map(|(_, e)| payee_script(&e.mnb))
            .collect()
    }

    /// GetMasternodeRank: the place of the masternode with collateral hash
    /// `vin_hash` among the ones old, recent and enabled enough to be ranked,
    /// by the compact form of their score, highest first; None past
    /// `check_num` (masternode-payments.cpp:548-620)
    pub fn rank(
        &self,
        chain: &Chain,
        vin_hash: &[u8; 32],
        scoring: &Hash256,
        check_num: usize,
    ) -> Option<usize> {
        let now = now();
        let min_age = if chain.network_type() == NetworkType::Regtest {
            25 * 60
        } else {
            STABLE_AGE
        };
        let mut ranked: Vec<(u32, [u8; 32])> = self
            .entries()
            .iter()
            .filter(|e| e.mnb.protocol_version >= ACTIVE_PROTOCOL)
            .filter(|e| now - e.mnb.sig_time >= min_age)
            .filter(|e| e.is_enabled(now))
            .map(|e| {
                (
                    get_compact(&calculate_score(&e.mnb, scoring)),
                    e.mnb.vin.prevout_hash,
                )
            })
            .collect();
        ranked.sort_by_key(|e| std::cmp::Reverse(e.0));
        ranked
            .iter()
            .take(check_num)
            .position(|(_, h)| h == vin_hash)
            .map(|i| i + 1)
    }
}

/// CNetAddr::IsRFC1918() || IsLocal() for a masternode's address
/// (netbase.cpp): 10/8, 172.16/12, 192.168/16, 127/8, 0/8 and ::1
fn is_private_or_local(ip: &[u8; 16]) -> bool {
    let v6 = std::net::Ipv6Addr::from(*ip);
    match v6.to_ipv4_mapped() {
        Some(v4) => v4.is_private() || v4.is_loopback() || v4.octets()[0] == 0,
        None => v6.is_loopback(),
    }
}

/// Whether a ping is the empty one CMasternodePing() makes (its operator==
/// compares the input and the block hash, MasternodePing.h:39-42)
fn ping_is_empty(ping: &CppPing) -> bool {
    ping.vin.prevout_hash == [0u8; 32]
        && ping.vin.prevout_n == u32::MAX
        && ping.block_hash == [0u8; 32]
}

/// CheckAndUpdatePing for the masternode of `mnb` whose last ping is `last`:
/// Ok when `ping` may be taken (masternodeman.cpp:309-375)
fn check_ping(
    chain: &Chain,
    mnb: &CppBroadcast,
    last: Option<&CppPing>,
    ping: &CppPing,
    now: i64,
) -> Result<(), Refusal> {
    if ping.sig_time > now + 3600 || ping.sig_time <= now - 3600 {
        return Err(Refusal::scored(1, "", "ping signature time out of range"));
    }
    if mnb.protocol_version < ACTIVE_PROTOCOL {
        return Err("no masternode of a compatible protocol".into());
    }
    // IsTooEarlyToReceivePingUpdate, measured from the new ping's time
    // (MasternodeHelpers.cpp:172-190)
    if last.is_some_and(|l| !ping_is_empty(l) && ping.sig_time - l.sig_time < MIN_MNP_SECONDS - 60)
    {
        return Err("ping arrived too early".into());
    }
    if !ping_signature_valid(mnb, ping) {
        return Err(Refusal::scored(33, "", "bad ping signature"));
    }
    let block = chain
        .get_block_index(&Hash256(ping.block_hash))
        .ok()
        .flatten()
        .ok_or("the ping names an unknown block")?;
    if block.height + PING_BLOCK_DEPTH < chain.height() {
        return Err("the ping names a block too far below the tip".into());
    }
    Ok(())
}

/// The block a height is scored with: its ancestor 101 below it on the
/// active chain (GetBlockHashForScoring, MasternodeHelpers.cpp:66-86)
pub fn scoring_hash(chain: &Chain, height: i64) -> Option<Hash256> {
    let at = height - SCORING_DEPTH as i64;
    if at < 0 || at > chain.height() as i64 {
        return None;
    }
    chain
        .get_block_index_by_height(at as u32)
        .ok()
        .flatten()
        .map(|b| b.hash)
}

/// GetHashRoundsForTierMasternodes (masternode.cpp:26-38)
fn hash_rounds(tier: i32) -> u32 {
    match tier {
        0 => 20,
        1 => 63,
        2 => 220,
        3 => 690,
        4 => 2400,
        _ => 0,
    }
}

/// CMasternode::CalculateScore: the scoring hash and `prevout.hash +
/// prevout.n` (a 256-bit sum), hashed with each round number; the highest
/// of the rounds' hashes (masternode.cpp:153-179)
pub fn calculate_score(mnb: &CppBroadcast, scoring: &Hash256) -> [u8; 32] {
    let mut aux = mnb.vin.prevout_hash;
    let mut carry = mnb.vin.prevout_n as u64;
    for b in aux.iter_mut() {
        if carry == 0 {
            break;
        }
        let sum = *b as u64 + (carry & 0xff);
        *b = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    let mut base = Vec::with_capacity(68);
    base.extend_from_slice(scoring.as_bytes());
    base.extend_from_slice(&aux);
    let mut best = [0u8; 32];
    for round in 0..hash_rounds(mnb.tier) {
        let mut data = base.clone();
        data.extend_from_slice(&(round as i32).to_le_bytes());
        let h = divi_crypto::double_sha256(&data);
        if cmp_u256(&h, &best) == std::cmp::Ordering::Greater {
            best = h;
        }
    }
    best
}

/// Compare two little-endian 256-bit numbers
fn cmp_u256(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

/// arith_uint256::GetCompact(false)
pub fn get_compact(n: &[u8; 32]) -> u32 {
    let mut size = 32usize;
    while size > 0 && n[size - 1] == 0 {
        size -= 1;
    }
    let low64 = |shift_bytes: usize| -> u64 {
        let mut v = 0u64;
        for i in 0..8 {
            let idx = shift_bytes + i;
            if idx < 32 {
                v |= (n[idx] as u64) << (8 * i);
            }
        }
        v
    };
    let mut compact: u32 = if size <= 3 {
        (low64(0) << (8 * (3 - size))) as u32
    } else {
        low64(size - 3) as u32
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | ((size as u32) << 24)
}

/// FindLastPayeePaymentTime (RpcMasternodeFeatures.cpp:244-277): the time of
/// the newest of the last `max_depth` active blocks for which the masternode
/// is a payee with at least two votes, plus its DeterministicTimeOffset; 0 if
/// none. A height with no block to score with stops the search at 0, as
/// divid's loop then stays on that block until the depth runs out.
pub fn last_paid_time(
    chain: &Chain,
    votes: &crate::mn_votes::MasternodeVotes,
    mnb: &CppBroadcast,
    max_depth: usize,
) -> i64 {
    let payee = payee_script(mnb);
    let mut index = chain.tip();
    let mut searched = 0;
    while let Some(block) = index.filter(|b| b.height > 0) {
        if searched >= max_depth {
            return 0;
        }
        searched += 1;
        if scoring_hash(chain, i64::from(block.height)).is_none() {
            return 0;
        }
        if votes.has_payee_with_votes(chain, i64::from(block.height), &payee, 2) {
            return i64::from(block.time.wrapping_add(deterministic_time_offset(mnb)));
        }
        index = chain.get_block_index(&block.prev_hash).ok().flatten();
    }
    0
}

/// CMasternode::DeterministicTimeOffset (masternode.cpp:219-227): the compact
/// form of the hash of the collateral input and the broadcast time, modulo 150
pub fn deterministic_time_offset(mnb: &CppBroadcast) -> u32 {
    let mut data = mnb.vin.to_bytes();
    data.extend_from_slice(&mnb.sig_time.to_le_bytes());
    get_compact(&divi_crypto::double_sha256(&data)) % 150
}

/// The script a masternode is paid to: P2PKH of its collateral key
pub fn payee_script(mnb: &CppBroadcast) -> Vec<u8> {
    let id: Hash160 = divi_crypto::hash160(&mnb.pubkey_collateral);
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(id.as_bytes());
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasternodeCounts {
    pub total: usize,
    pub stable: usize,
    pub enabled: usize,
    pub inqueue: usize,
    pub ipv4: usize,
    pub ipv6: usize,
    pub onion: usize,
}

fn address_network(chain: &Chain) -> Network {
    match chain.network_type() {
        NetworkType::Mainnet => Network::Mainnet,
        NetworkType::Testnet => Network::Testnet,
        NetworkType::Regtest => Network::Regtest,
    }
}

fn collateral_address(mnb: &CppBroadcast, network: Network) -> String {
    let id: Hash160 = divi_crypto::hash160(&mnb.pubkey_collateral);
    Address::from_pubkey_hash(id, network).to_base58()
}

/// GetNetworkName(CNetAddr::GetNetwork()) of the masternode's address:
/// "ipv4", "ipv6", "onion", or "" for an address that is not routable, such
/// as loopback (netbase.cpp)
fn network_name(mnb: &CppBroadcast) -> &'static str {
    let ip = std::net::Ipv6Addr::from(mnb.ip);
    if let Some(v4) = ip.to_ipv4_mapped() {
        let routable = !(v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_broadcast()
            || v4.is_documentation());
        return if routable { "ipv4" } else { "" };
    }
    if mnb.ip[..6] == [0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43] {
        return "onion";
    }
    if ip.is_loopback() || ip.is_unspecified() {
        return "";
    }
    "ipv6"
}

/// CMasternode::TierToString (masternode.cpp)
fn tier_name(tier: i32) -> &'static str {
    match tier {
        0 => "COPPER",
        1 => "SILVER",
        2 => "GOLD",
        3 => "PLATINUM",
        4 => "DIAMOND",
        _ => "INVALID",
    }
}
