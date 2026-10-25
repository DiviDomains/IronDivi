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

use divi_masternode::mnsync::{SharedMasternodeSync, SyncPeer, SyncRequest, WINNER_DEPTH};
use divi_network::{NetworkMessage, PeerManager, SporkManager, SporkSyncState};
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_whole_list_request_is_an_empty_ctxin() {
        let v = whole_list_request();
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
