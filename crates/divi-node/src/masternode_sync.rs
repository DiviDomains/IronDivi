// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The node side of Divi Core's masternode sync (ThreadMasternodeBackgroundSync,
//! MasternodeModule.cpp:472-531): once a second, while the chain is synced,
//! the sync takes a step with the peers it may ask; the requests it makes go
//! out as `dseg` and `mnget`, and the peers' `ssc` counts come back to it.

use divi_masternode::mnsync::{
    SharedMasternodeSync, SyncPeer, SyncRequest, SYNC_LIST, SYNC_MNW, WINNER_DEPTH,
};
use divi_network::message::{InvItem, InvType};
use divi_network::{NetworkMessage, PeerManager, SporkManager, SporkSyncState};
use divi_primitives::hash::Hash256;
use divi_rpc::mn_list::{MasternodeList, NetworkMasternode};
use divi_rpc::mn_votes::MasternodeVotes;
use divi_storage::chain::NetworkType;
use divi_storage::Chain;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

/// The fulfilled and pending requests across a restart (Core's netfulfilled.dat)
pub const NETFULFILLED_FILE: &str = "netfulfilled.list";

/// ActiveProtocol() without -activeversion (version.cpp:11-17)
pub const ACTIVE_PROTOCOL: i32 = 70915;

/// A peer's key in the fulfilled requests: the whole address on regtest, where
/// local peers share an IP, else the IP (netfulfilledman.cpp:14-22)
pub fn peer_key(addr: SocketAddr, regtest: bool) -> String {
    if regtest {
        addr.to_string()
    } else {
        addr.ip().to_string()
    }
}

/// CNetAddr::IsRFC1918() || IsLocal(): the peers the list-ask limits leave out
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0
                || o[0] == 127
                || o[0] == 10
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 172 && (16..32).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_local(IpAddr::V4(v4)))
        }
    }
}

/// CNetAddr::IsRFC1918(): a masternode on such an address is not announced
/// in an answer to `dseg` (masternode-sync.cpp:127-137)
pub fn is_rfc1918(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
    };
    let o = v4.octets();
    o[0] == 10 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16..32).contains(&o[1]))
}

/// The peers the sync may ask: inbound ones and those whose sporks are
/// synced (GetSporkSyncedOrInboundNodes, net.cpp:129-146), in the order they
/// connected
pub fn sync_peers(peers: &PeerManager, sporks: &SporkManager, regtest: bool) -> Vec<SyncPeer> {
    use std::sync::atomic::Ordering::Relaxed;
    let mut out: Vec<SyncPeer> = peers
        .get_peer_details()
        .into_iter()
        .filter(|(id, _, inbound, _, _)| {
            *inbound || sporks.peer_state(*id) == SporkSyncState::Synced
        })
        .map(|(id, addr, _, stats, _)| SyncPeer {
            id,
            key: peer_key(addr, regtest),
            ip: addr.ip().to_string(),
            local: is_local(addr.ip()),
            version: stats.version.load(Relaxed) as i32,
        })
        .collect();
    out.sort_by_key(|p| p.id);
    out
}

/// `dseg` with an empty CTxIn: a null prevout, an empty script and the final
/// sequence (masternode-sync.cpp:105-111)
pub fn whole_list_request() -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v.push(0);
    v.extend_from_slice(&u32::MAX.to_le_bytes());
    v
}

/// IsBlockchainSynced, for the message handlers and the sync task
pub fn blockchain_synced(sync: &SharedMasternodeSync, chain: &Chain, now: i64) -> bool {
    let tip_time = chain.tip().map(|t| t.time as i64);
    sync.lock().chain.check(now, tip_time, chain.is_importing())
}

/// Write the fulfilled and pending requests to the datadir
pub fn save(sync: &SharedMasternodeSync, data_dir: &Path) {
    let text = sync.lock().sync.requests.to_text();
    let path = data_dir.join(NETFULFILLED_FILE);
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, text)
        .and_then(|_| std::fs::rename(&tmp, &path))
        .is_err()
    {
        tracing::warn!("Could not write {}", path.display());
    }
}

/// Read them back at start; a missing file is an empty cache
pub fn load(sync: &SharedMasternodeSync, data_dir: &Path) {
    if let Ok(text) = std::fs::read_to_string(data_dir.join(NETFULFILLED_FILE)) {
        sync.lock().sync.requests.load_text(&text);
    }
}

/// One second of the sync thread (MasternodeModule.cpp:486-529): a restart
/// asked for by a stalled chain check, then a step while the chain is synced,
/// and the requests sent. Returns whether the chain was synced.
pub async fn tick(
    sync: &SharedMasternodeSync,
    chain: &Chain,
    peers: &Arc<PeerManager>,
    sporks: &SporkManager,
    now: i64,
) -> bool {
    {
        let mut state = sync.lock();
        if state.chain.take_resync_request() {
            state.sync.reset(now);
        }
    }
    if !blockchain_synced(sync, chain, now) {
        return false;
    }
    let regtest = chain.network_type() == NetworkType::Regtest;
    let asked = sync_peers(peers, sporks, regtest);
    let requests = sync.lock().sync.process(now, &asked, ACTIVE_PROTOCOL);
    for request in requests {
        let (peer, message) = match request {
            SyncRequest::MasternodeList(peer) => (
                peer,
                NetworkMessage::RequestMasternodeList(whole_list_request()),
            ),
            SyncRequest::Winners(peer) => {
                (peer, NetworkMessage::MasternodeWinnersRequest(WINNER_DEPTH))
            }
        };
        if let Err(e) = peers.send_to_peer(peer, message).await {
            tracing::debug!("Masternode sync: could not ask peer {}: {}", peer, e);
        }
    }
    true
}

/// A peer's `ssc`, taken while the chain is synced (ProcessMasternodeMessages,
/// MasternodeModule.cpp:377-382)
pub fn sync_status_count(
    sync: &SharedMasternodeSync,
    chain: &Chain,
    peer: Option<SocketAddr>,
    code: i32,
    count: i32,
    now: i64,
) {
    let Some(addr) = peer else {
        return;
    };
    if !blockchain_synced(sync, chain, now) {
        return;
    }
    let key = peer_key(addr, chain.network_type() == NetworkType::Regtest);
    sync.lock().sync.sync_status_count(&key, code, count, now);
}

/// What a `dseg` asks for: the whole list (an empty CTxIn) or one masternode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListRequest {
    Whole,
    One([u8; 32], u32),
}

/// Read a `dseg`'s CTxIn: prevout, script and sequence; the whole list when it
/// equals CTxIn() (masternode-sync.cpp:175-178)
pub fn parse_list_request(payload: &[u8]) -> Option<ListRequest> {
    let hash: [u8; 32] = payload.get(..32)?.try_into().ok()?;
    let n = u32::from_le_bytes(payload.get(32..36)?.try_into().ok()?);
    let (len, at): (usize, usize) = match *payload.get(36)? {
        0xfd => (
            u16::from_le_bytes(payload.get(37..39)?.try_into().ok()?) as usize,
            39,
        ),
        0xfe | 0xff => return None,
        b => (b as usize, 37),
    };
    let script_end = at.checked_add(len)?;
    let sequence = u32::from_le_bytes(payload.get(script_end..script_end + 4)?.try_into().ok()?);
    if hash == [0; 32] && n == u32::MAX && len == 0 && sequence == u32::MAX {
        Some(ListRequest::Whole)
    } else {
        Some(ListRequest::One(hash, n))
    }
}

/// NotifyPeerOfMasternode (masternode-sync.cpp:127-137): an enabled
/// masternode not on an RFC1918 address is announced
fn announced(mn: &NetworkMasternode, now: i64) -> bool {
    let ip = std::net::Ipv6Addr::from(mn.mnb.ip);
    let ip = ip
        .to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(ip));
    !is_rfc1918(ip) && mn.is_enabled(now)
}

/// The broadcasts an answer to the whole-list `dseg` announces, in the list's
/// order (SyncMasternodeListWithPeer, masternode-sync.cpp:138-152)
pub fn list_inventory(entries: &[NetworkMasternode], now: i64) -> Vec<[u8; 32]> {
    entries
        .iter()
        .filter(|mn| announced(mn, now))
        .map(|mn| mn.mnb.hash())
        .collect()
}

/// The votes an answer to `mnget <count>` announces: those within `count`
/// (at most 200) blocks of the highest, highest first
/// (SyncMasternodeWinnersWithPeer, masternode-sync.cpp:76-103)
pub fn winner_inventory(mut votes: Vec<(i32, [u8; 32])>, count: i32) -> Vec<[u8; 32]> {
    let count = count.min(WINNER_DEPTH);
    votes.sort_by_key(|(height, _)| std::cmp::Reverse(*height));
    let Some(&(start, _)) = votes.first() else {
        return Vec::new();
    };
    votes
        .into_iter()
        .take_while(|(height, _)| *height as i64 >= start as i64 - count as i64)
        .map(|(_, hash)| hash)
        .collect()
}

/// The `ssc` that ends an answer, then the announced items (Core pushes the
/// count at once and the items with the next inventory send)
async fn send_answer(
    peers: &Arc<PeerManager>,
    peer: u64,
    code: i32,
    inv_type: InvType,
    items: Vec<[u8; 32]>,
) {
    let count = NetworkMessage::SyncStatusCount {
        item_id: code,
        count: items.len() as i32,
    };
    let _ = peers.send_to_peer(peer, count).await;
    if !items.is_empty() {
        let inv = items
            .into_iter()
            .map(|h| InvItem::new(inv_type, Hash256(h)))
            .collect();
        let _ = peers.send_to_peer(peer, NetworkMessage::Inv(inv)).await;
    }
}

/// A peer's `dseg`, answered while the chain is synced (ProcessSyncUpdate,
/// masternode-sync.cpp:172-191): the whole list, which a non-local peer may
/// ask for once in three hours (else scored 34), or one masternode
#[allow(clippy::too_many_arguments)]
pub async fn answer_list_request(
    sync: &SharedMasternodeSync,
    chain: &Chain,
    list: &MasternodeList,
    peers: &Arc<PeerManager>,
    peer: u64,
    payload: &[u8],
    now: i64,
) {
    if !blockchain_synced(sync, chain, now) {
        return;
    }
    let (Some(addr), Some(request)) = (peers.peer_addr(peer), parse_list_request(payload)) else {
        return;
    };
    match request {
        ListRequest::Whole => {
            if !is_local(addr.ip())
                && sync
                    .lock()
                    .sync
                    .peer_asked_for_list_too_often(&addr.ip().to_string(), now)
            {
                peers.report_misbehavior_score(peer, 34, "Asked mn peer list too often");
                return;
            }
            let items = list_inventory(&list.entries(), now);
            send_answer(peers, peer, SYNC_LIST, InvType::MasternodeAnnounce, items).await;
        }
        ListRequest::One(hash, n) => {
            let found = list.entries().into_iter().find(|mn| {
                mn.mnb.vin.prevout_hash == hash && mn.mnb.vin.prevout_n == n && announced(mn, now)
            });
            if let Some(mn) = found {
                let inv = vec![InvItem::new(
                    InvType::MasternodeAnnounce,
                    Hash256(mn.mnb.hash()),
                )];
                let _ = peers.send_to_peer(peer, NetworkMessage::Inv(inv)).await;
            }
        }
    }
}

/// A peer's `mnget`, answered while the chain is synced (ProcessSyncUpdate,
/// masternode-sync.cpp:155-171): once per expiry of the request, a second
/// ask within it scored 20
pub async fn answer_winners_request(
    sync: &SharedMasternodeSync,
    chain: &Chain,
    votes: &MasternodeVotes,
    peers: &Arc<PeerManager>,
    peer: u64,
    count: i32,
    now: i64,
) {
    if !blockchain_synced(sync, chain, now) {
        return;
    }
    let Some(addr) = peers.peer_addr(peer) else {
        return;
    };
    let key = peer_key(addr, chain.network_type() == NetworkType::Regtest);
    let again = {
        let mut state = sync.lock();
        let again = state.sync.requests.has_fulfilled(&key, "mnget", now);
        if !again {
            state.sync.requests.add_fulfilled(&key, "mnget", now);
        }
        again
    };
    if again {
        peers.report_misbehavior_score(peer, 20, "Too recently asked for mn peer list");
        return;
    }
    let items = winner_inventory(votes.heights_and_hashes(), count);
    send_answer(peers, peer, SYNC_MNW, InvType::MasternodeWinner, items).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_whole_list_request_is_an_empty_ctxin() {
        let v = whole_list_request();
        assert_eq!(parse_list_request(&v), Some(ListRequest::Whole));
        let mut one = v.clone();
        one[0] = 7;
        assert_eq!(
            parse_list_request(&one),
            Some(ListRequest::One(one[..32].try_into().unwrap(), u32::MAX))
        );
        assert_eq!(parse_list_request(&v[..40]), None);
        assert_eq!(v.len(), 41);
        assert_eq!(&v[32..36], &[0xff; 4]);
        assert_eq!(v[36], 0);
        assert_eq!(&v[37..], &[0xff; 4]);
    }

    #[test]
    fn peers_are_keyed_with_the_port_on_regtest_only() {
        let a: SocketAddr = "127.0.0.2:5000".parse().unwrap();
        assert_eq!(peer_key(a, true), "127.0.0.2:5000");
        assert_eq!(peer_key(a, false), "127.0.0.2");
    }

    fn masternode(ip: [u8; 4], ping_time: i64, n: u32) -> NetworkMasternode {
        use divi_masternode::cpp_wire::{CppBroadcast, CppPing, CppTxIn};
        let vin = CppTxIn::new([n as u8; 32], n);
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..].copy_from_slice(&ip);
        NetworkMasternode {
            mnb: CppBroadcast {
                vin: vin.clone(),
                ip: mapped,
                port: 51476,
                pubkey_collateral: vec![2; 33],
                pubkey_masternode: vec![3; 33],
                signature: vec![],
                sig_time: 1_700_000_000 + n as i64,
                protocol_version: 70920,
                last_ping: CppPing {
                    vin,
                    block_hash: [0; 32],
                    sig_time: ping_time,
                    signature: vec![],
                },
                tier: 0,
            },
            vin_spent: false,
        }
    }

    /// Enabled masternodes not on an RFC1918 address, by their broadcast hash
    #[test]
    fn the_list_answer_leaves_out_private_and_expired_masternodes() {
        let now = 1_700_010_000;
        let entries = vec![
            masternode([127, 0, 0, 5], now - 60, 1),
            masternode([192, 168, 1, 5], now - 60, 2),
            masternode([127, 0, 0, 6], now - 3 * 60 * 60, 3),
            masternode([8, 8, 8, 8], now - 60, 4),
        ];
        assert_eq!(
            list_inventory(&entries, now),
            vec![entries[0].mnb.hash(), entries[3].mnb.hash()]
        );
    }

    /// The votes within the count of the highest, at most 200
    #[test]
    fn the_winners_answer_takes_the_last_blocks() {
        let votes: Vec<(i32, [u8; 32])> = [500, 100, 300, 299, 301]
            .iter()
            .map(|&h| (h, [h as u8; 32]))
            .collect();
        assert_eq!(
            winner_inventory(votes.clone(), 200),
            vec![[500u16 as u8; 32], [301u16 as u8; 32], [300u16 as u8; 32]]
        );
        assert_eq!(winner_inventory(votes.clone(), 1000).len(), 3);
        assert_eq!(winner_inventory(votes, 0), vec![[500u16 as u8; 32]]);
        assert!(winner_inventory(vec![], 200).is_empty());
    }

    #[test]
    fn local_and_private_addresses() {
        for (ip, local, rfc1918) in [
            ("127.0.0.2", true, false),
            ("10.1.2.3", true, true),
            ("172.16.0.1", true, true),
            ("172.32.0.1", false, false),
            ("192.168.1.1", true, true),
            ("8.8.8.8", false, false),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(is_local(ip), local, "{ip}");
            assert_eq!(is_rfc1918(ip), rfc1918, "{ip}");
        }
    }
}
