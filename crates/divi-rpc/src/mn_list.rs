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

//! The masternodes the network announces, kept as Divi Core keeps them: the
//! broadcasts (`mnb`) in Core's wire format that pass its checks, in the order
//! they arrived (CMasternodeMan's vector), each with its last ping (`mnp`).
//! `listmasternodes` and `getmasternodecount` read this list. It is saved in
//! the datadir as Core saves mncache.dat, so it is there after a restart.

use crate::mn_broadcast::{find_collateral, ping_signature_valid, tier_for_collateral};
use divi_masternode::cpp_wire::{CppBroadcast, CppPing};
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::transaction::OutPoint;
use divi_storage::{Chain, NetworkType};
use divi_wallet::address::Address;
use divi_wallet::Network;
use parking_lot::RwLock;
use std::path::PathBuf;

/// MASTERNODE_MIN_CONFIRMATIONS (masternode.h:16)
const MIN_CONFIRMATIONS: u32 = 15;
/// MASTERNODE_MIN_MNP_SECONDS (masternode.h:17)
const MIN_MNP_SECONDS: i64 = 10 * 60;
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

#[derive(Default)]
pub struct MasternodeList {
    entries: RwLock<Vec<NetworkMasternode>>,
    path: RwLock<Option<PathBuf>>,
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
    pub fn accept_broadcast(&self, chain: &Chain, payload: &[u8]) -> Result<bool, String> {
        let mnb = CppBroadcast::decode(payload).map_err(|e| format!("{e:?}"))?;
        self.accept_decoded(chain, mnb, now())
    }

    fn accept_decoded(&self, chain: &Chain, mnb: CppBroadcast, now: i64) -> Result<bool, String> {
        if mnb.sig_time > now + 3600 {
            return Err("signature too far in the future".into());
        }
        if mnb.protocol_version < ACTIVE_PROTOCOL {
            return Err("obsolete protocol version".into());
        }
        if !mnb.signature_is_valid() {
            return Err("bad broadcast signature".into());
        }
        let ping = &mnb.last_ping;
        if ping.sig_time > now + 3600 || ping.sig_time <= now - 3600 {
            return Err("ping signature time out of range".into());
        }
        if !ping_signature_valid(&mnb, ping) {
            return Err("attached ping is invalid".into());
        }
        let hash = Hash256(mnb.vin.prevout_hash);
        {
            let entries = self.entries.read();
            if let Some(e) = entries.iter().find(|e| {
                e.mnb.vin.prevout_hash == mnb.vin.prevout_hash
                    && e.mnb.vin.prevout_n == mnb.vin.prevout_n
            }) {
                // CMasternodeMan::UpdateWithNewBroadcast: only a newer one replaces it
                if mnb.sig_time <= e.mnb.sig_time {
                    return Ok(false);
                }
            }
        }
        let coll = find_collateral(chain, &hash, mnb.vin.prevout_n)
            .ok_or("collateral not found in the active chain")?;
        if tier_for_collateral(chain, coll.amount) != Some(mnb.tier) {
            return Err("collateral amount does not match the tier".into());
        }
        let outpoint = OutPoint::new(hash, mnb.vin.prevout_n);
        if !matches!(chain.get_utxo(&outpoint), Ok(Some(_))) {
            return Err("collateral is spent".into());
        }
        if chain.height() + 1 < coll.height + MIN_CONFIRMATIONS {
            return Err(format!(
                "collateral must have at least {MIN_CONFIRMATIONS} confirmations"
            ));
        }
        {
            let mut entries = self.entries.write();
            match entries.iter_mut().find(|e| e.outpoint() == outpoint) {
                Some(e) => {
                    e.mnb = mnb;
                    e.vin_spent = false;
                }
                None => entries.push(NetworkMasternode {
                    mnb,
                    vin_spent: false,
                }),
            }
        }
        self.save();
        Ok(true)
    }

    /// A ping from a peer: taken for a masternode in the list when signed by
    /// its masternode key and not too early after the last one
    /// (CMasternodePing::CheckAndUpdate, masternodeman.cpp:303-360).
    /// Ok(true) when the ping was taken.
    pub fn accept_ping(&self, payload: &[u8]) -> Result<bool, String> {
        let ping = CppPing::decode_bytes(payload).map_err(|e| format!("{e:?}"))?;
        let now = now();
        if ping.sig_time > now + 3600 || ping.sig_time <= now - 3600 {
            return Err("ping signature time out of range".into());
        }
        let taken = {
            let mut entries = self.entries.write();
            let Some(e) = entries.iter_mut().find(|e| {
                e.mnb.vin.prevout_hash == ping.vin.prevout_hash
                    && e.mnb.vin.prevout_n == ping.vin.prevout_n
            }) else {
                return Ok(false);
            };
            // IsTooEarlyToReceivePingUpdate: MIN_MNP_SECONDS - 60 since the last
            if ping.sig_time - e.mnb.last_ping.sig_time < MIN_MNP_SECONDS - 60 {
                return Ok(false);
            }
            if !ping_signature_valid(&e.mnb, &ping) {
                return Err("bad ping signature".into());
            }
            e.mnb.last_ping = ping;
            true
        };
        if taken {
            self.save();
        }
        Ok(taken)
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

    pub fn entries(&self) -> Vec<NetworkMasternode> {
        self.entries.read().clone()
    }

    /// `listmasternodes ( "filter" )` as Divi Core answers it
    /// (rpcmasternode.cpp:263-325, RpcMasternodeFeatures.cpp:279-324). Like
    /// divid it shows the state of the last check: it does not check the
    /// collateral itself (getmasternodecount and a timer do).
    pub fn list_json(&self, chain: &Chain, filter: Option<&str>) -> serde_json::Value {
        let now = now();
        let network = address_network(chain);
        let filter = filter.unwrap_or("");
        let mut out = Vec::new();
        for e in self.entries() {
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
                "lastpaid": 0,
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
        // GetMasternodePaymentQueue: a pass that skips the young ones, and when
        // it finds under a third of them, a second pass without that filter
        // whose entries are added to the first's (masternode-payments.cpp:474-510)
        let pass = |filter_sig_time: bool| {
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
                .count()
        };
        // No queue before there is a block to score with, 101 below the tip
        // (GetBlockHashForScoring, MasternodeHelpers.cpp:75-86)
        let mut queue = 0;
        if tip >= SCORING_DEPTH {
            queue = pass(true);
            if queue < mn_count / 3 {
                queue += pass(false);
            }
        }
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
