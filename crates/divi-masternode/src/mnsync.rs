// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The masternode sync of Divi Core 3.0.0 (CMasternodeSync,
//! masternode-sync.cpp; CNetFulfilledRequestManager, netfulfilledman.cpp): the
//! stages a node walks once its chain is synced, which peer it asks for the
//! masternode list (`dseg`) and the payment winners (`mnget`) at each tick, and
//! the counts its peers answer with (`ssc`).
//!
//! Times are Unix seconds from the caller, so the stages can be driven by a
//! test clock; the node passes Core's GetTime (mock time included).

use crate::cpp_wire::{write_compact_size, write_varbytes, Reader, WireError};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// MasternodeSyncCode (masternode-sync.h:40-48)
pub const SYNC_INITIAL: i32 = 0;
pub const SYNC_SPORKS: i32 = 1;
pub const SYNC_LIST: i32 = 2;
pub const SYNC_MNW: i32 = 3;
pub const SYNC_FAILED: i32 = 998;
pub const SYNC_FINISHED: i32 = 999;

/// masternode-sync.cpp:27-29
const SYNC_TIMEOUT: i64 = 5;
const SYNC_THRESHOLD: i32 = 2;
pub const WINNER_DEPTH: i32 = 200;

/// The request names of the two counted stages (masternode-sync.cpp:31-35)
pub const LIST_REQUEST: &str = "mnsync";
pub const WINNER_REQUEST: &str = "mnwsync";

/// How long Core waits before asking a non-local peer for its list again, and
/// before it answers such a peer's ask again
/// (MasternodeNetworkMessageManager.cpp:8, :157-189)
pub const DSEG_SECONDS: i64 = 3 * 60 * 60;

/// CChainParams::FulfilledRequestExpireTime: main 30 min, testnet and regtest
/// 5 min (chainparams.cpp:253, :442, :506)
pub fn fulfilled_expire_time(main: bool) -> i64 {
    if main {
        30 * 60
    } else {
        5 * 60
    }
}

/// CNetFulfilledRequestManager: requests made to and fulfilled by each peer,
/// each until it expires. A peer is its address with the port on regtest
/// (several local peers share an IP) and its IP elsewhere (SquashAddress).
#[derive(Debug, Clone, Default)]
pub struct FulfilledRequests {
    expire: i64,
    fulfilled: HashMap<String, HashMap<String, i64>>,
    pending: HashMap<String, HashMap<String, i64>>,
}

impl FulfilledRequests {
    pub fn new(expire: i64) -> Self {
        Self {
            expire,
            ..Default::default()
        }
    }

    pub fn add_fulfilled(&mut self, peer: &str, request: &str, now: i64) {
        self.fulfilled
            .entry(peer.to_string())
            .or_default()
            .insert(request.to_string(), now + self.expire);
    }

    pub fn has_fulfilled(&self, peer: &str, request: &str, now: i64) -> bool {
        self.fulfilled
            .get(peer)
            .and_then(|m| m.get(request))
            .is_some_and(|&until| until > now)
    }

    pub fn add_pending(&mut self, peer: &str, request: &str, now: i64) {
        self.pending
            .entry(peer.to_string())
            .or_default()
            .insert(request.to_string(), now + self.expire);
    }

    /// The pending request becomes a fulfilled one (netfulfilledman.cpp:70-80)
    pub fn fulfill_pending(&mut self, peer: &str, request: &str, now: i64) {
        if let Some(m) = self.pending.get_mut(peer) {
            m.remove(request);
            self.add_fulfilled(peer, request, now);
        }
    }

    pub fn has_pending(&self, peer: &str, request: &str, now: i64) -> bool {
        self.pending
            .get(peer)
            .and_then(|m| m.get(request))
            .is_some_and(|&until| now <= until)
    }

    /// CheckAndRemove: expired fulfilled requests go (pending ones stay, as in
    /// Core, and only stop counting)
    pub fn check_and_remove(&mut self, now: i64) {
        for m in self.fulfilled.values_mut() {
            m.retain(|_, until| now <= *until);
        }
        self.fulfilled.retain(|_, m| !m.is_empty());
    }

    /// Both maps as Divi Core serialises CNetFulfilledRequestManager into
    /// netfulfilled.dat (netfulfilledman.h:33-38): the fulfilled, then the
    /// pending, each its peers in CService order (16 address bytes, then the
    /// port big-endian, netbase.h:169-176; operator<, netbase.cpp:1202-1205)
    /// with their requests in name order and the time each expires
    pub fn to_file_data(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for map in [&self.fulfilled, &self.pending] {
            let mut services: BTreeMap<([u8; 16], u16), BTreeMap<&str, i64>> = BTreeMap::new();
            for (peer, requests) in map {
                let Some(service) = service_of(peer) else {
                    continue;
                };
                let entry = services.entry(service).or_default();
                for (request, until) in requests {
                    entry.entry(request.as_str()).or_insert(*until);
                }
            }
            write_compact_size(&mut out, services.len());
            for ((ip, port), requests) in services {
                out.extend_from_slice(&ip);
                out.extend_from_slice(&port.to_be_bytes());
                write_compact_size(&mut out, requests.len());
                for (request, until) in requests {
                    write_varbytes(&mut out, request.as_bytes());
                    out.extend_from_slice(&until.to_le_bytes());
                }
            }
        }
        out
    }

    /// Read `to_file_data`'s maps back as Core's ParseChunk does
    /// (flat-database.h:150-164). False when they do not parse
    /// (IncorrectFormat): then Core's Clear empties the fulfilled requests and
    /// keeps the pending ones read until then (netfulfilledman.cpp:142-146)
    pub fn read_file_data(&mut self, data: &[u8], regtest: bool) -> bool {
        let mut r = Reader::new(data);
        // std::map's Unserialize empties the map, then inserts what it reads
        self.fulfilled.clear();
        let read = read_requests(&mut r, &mut self.fulfilled, regtest).is_ok() && {
            self.pending.clear();
            read_requests(&mut r, &mut self.pending, regtest).is_ok()
        };
        if !read {
            self.fulfilled.clear();
        }
        read
    }
}

/// One map of requests from netfulfilled.dat; a peer goes in only once its
/// requests are all read, and a key seen before is not replaced (std::map)
fn read_requests(
    r: &mut Reader,
    map: &mut HashMap<String, HashMap<String, i64>>,
    regtest: bool,
) -> Result<(), WireError> {
    for _ in 0..r.compact_size()? {
        let ip: [u8; 16] = r.take(16)?.try_into().unwrap();
        let port = u16::from_be_bytes(r.take(2)?.try_into().unwrap());
        let mut requests = HashMap::new();
        for _ in 0..r.compact_size()? {
            let request = String::from_utf8_lossy(&r.varbytes()?).into_owned();
            let until = r.i64_le()?;
            requests.entry(request).or_insert(until);
        }
        map.entry(peer_of(ip, port, regtest)).or_insert(requests);
    }
    Ok(())
}

/// A peer's key as the CService Core keys it by: the address and port, or the
/// IP alone with port 0 (SquashAddress, netfulfilledman.cpp:14-22); an IPv4
/// address is held IPv4-mapped, as CNetAddr holds it
fn service_of(peer: &str) -> Option<([u8; 16], u16)> {
    let (ip, port) = match peer.parse::<SocketAddr>() {
        Ok(addr) => (addr.ip(), addr.port()),
        Err(_) => (peer.parse::<IpAddr>().ok()?, 0),
    };
    let ip = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    Some((ip, port))
}

/// The key of a CService read back: the address with the port on regtest, the
/// IP elsewhere, as the node keys its peers
fn peer_of(ip: [u8; 16], port: u16, regtest: bool) -> String {
    let ip = IpAddr::V6(Ipv6Addr::from(ip)).to_canonical();
    if regtest {
        SocketAddr::new(ip, port).to_string()
    } else {
        ip.to_string()
    }
}

/// A peer the sync may ask: an inbound peer or one whose sporks are synced
/// (GetSporkSyncedOrInboundNodes, net.cpp:129-146), in connection order
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPeer {
    pub id: u64,
    /// The peer's key in the fulfilled requests (FulfilledRequests)
    pub key: String,
    /// Its IP, for the list-ask limit of a non-local peer
    pub ip: String,
    /// Whether the IP is local or RFC1918, which the limit leaves out
    pub local: bool,
    pub version: i32,
}

/// A message the sync sends a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncRequest {
    /// `dseg` with an empty CTxIn: the whole masternode list
    MasternodeList(u64),
    /// `mnget 200`: the payment winners
    Winners(u64),
}

/// SyncAssets' outcome (masternode-sync.h:30-38)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assets {
    Fail,
    StageComplete,
    Success,
    Waiting,
    AtPeerLimit,
    Request,
}

/// CMasternodeSync, with the request manager it shares
#[derive(Debug, Clone)]
pub struct MasternodeSync {
    pub last_list_update: i64,
    pub last_winner_update: i64,
    pub last_failed_sync: i64,
    pub failed_sync_attempts: i32,
    pub broadcasts_received: i32,
    pub winners_received: i32,
    pub list_requests_fulfilled: i32,
    pub winner_requests_fulfilled: i32,
    pub status: i32,
    pub successive_requests: i32,
    stage_start: i64,
    last_process: i64,
    seen_broadcasts: HashMap<[u8; 32], i32>,
    seen_winners: HashMap<[u8; 32], i32>,
    /// mWeAskedForMasternodeList: when a non-local peer may be asked again
    asked_for_list: HashMap<String, i64>,
    /// mAskedUsForMasternodeList: when a non-local peer may ask us again
    asked_us_for_list: HashMap<String, i64>,
    pub requests: FulfilledRequests,
}

impl MasternodeSync {
    /// A sync at its first stage (the constructor's Reset,
    /// masternode-sync.cpp:37-53)
    pub fn new(now: i64, fulfilled_expire: i64) -> Self {
        let mut sync = Self {
            last_list_update: 0,
            last_winner_update: 0,
            last_failed_sync: 0,
            failed_sync_attempts: 0,
            broadcasts_received: 0,
            winners_received: 0,
            list_requests_fulfilled: 0,
            winner_requests_fulfilled: 0,
            status: SYNC_INITIAL,
            successive_requests: 0,
            stage_start: now,
            last_process: 0,
            seen_broadcasts: HashMap::new(),
            seen_winners: HashMap::new(),
            asked_for_list: HashMap::new(),
            asked_us_for_list: HashMap::new(),
            requests: FulfilledRequests::new(fulfilled_expire),
        };
        sync.reset(now);
        sync
    }

    /// Reset (masternode-sync.cpp:60-74): back to the first stage. The time of
    /// the last failure, the last tick and the request manager are kept.
    pub fn reset(&mut self, now: i64) {
        self.seen_broadcasts.clear();
        self.seen_winners.clear();
        self.last_list_update = 0;
        self.last_winner_update = 0;
        self.failed_sync_attempts = 0;
        self.broadcasts_received = 0;
        self.winners_received = 0;
        self.list_requests_fulfilled = 0;
        self.winner_requests_fulfilled = 0;
        self.status = SYNC_INITIAL;
        self.successive_requests = 0;
        self.stage_start = now;
    }

    /// IsSynced (masternode-sync.cpp:55-58)
    pub fn is_synced(&self) -> bool {
        self.status == SYNC_FINISHED
    }

    /// IsMasternodeListSynced (masternode-sync.cpp:391-394)
    pub fn is_list_synced(&self) -> bool {
        self.status > SYNC_LIST
    }

    /// ContinueToNextSyncStage (masternode-sync.cpp:255-275)
    fn next_stage(&mut self, now: i64) {
        self.status = match self.status {
            SYNC_INITIAL | SYNC_FAILED => SYNC_SPORKS,
            SYNC_SPORKS => SYNC_LIST,
            SYNC_LIST => SYNC_MNW,
            SYNC_MNW => SYNC_FINISHED,
            other => other,
        };
        self.successive_requests = 0;
        self.stage_start = now;
    }

    /// ShouldWaitForSync (masternode-sync.cpp:297-333): at most one tick in
    /// five seconds; a clock that went back or a pause of an hour starts
    /// over; a failed sync is retried a minute after it failed
    fn should_wait(&mut self, now: i64) -> bool {
        if self.last_process > now {
            self.reset(now);
            self.last_process = now;
            return true;
        }
        if now < self.last_process + SYNC_TIMEOUT {
            return true;
        }
        if now - self.last_process > 60 * 60 {
            self.reset(now);
            self.last_process = now;
            return true;
        }
        self.last_process = now;
        if self.status == SYNC_FAILED
            && self.last_failed_sync > 0
            && self.last_failed_sync + 60 < now
        {
            self.reset(now);
        } else if self.status == SYNC_FAILED {
            return true;
        }
        false
    }

    /// SyncAssets (masternode-sync.cpp:335-360)
    fn sync_assets(&mut self, peer: &str, now: i64, last_update: i64, request: &str) -> Assets {
        if last_update > 0
            && last_update < now - SYNC_TIMEOUT * 2
            && self.successive_requests >= SYNC_THRESHOLD
        {
            self.next_stage(now);
            return Assets::StageComplete;
        }
        if last_update == 0 && now - self.stage_start > SYNC_TIMEOUT * 5 {
            self.status = SYNC_FAILED;
            self.successive_requests = 0;
            self.last_failed_sync = now;
            self.failed_sync_attempts += 1;
            return Assets::Fail;
        }
        if self.requests.has_fulfilled(peer, request, now) {
            return Assets::Success;
        }
        if self.requests.has_pending(peer, request, now) {
            return Assets::Waiting;
        }
        if self.successive_requests >= SYNC_THRESHOLD * 3 {
            return Assets::AtPeerLimit;
        }
        self.requests.add_pending(peer, request, now);
        Assets::Request
    }

    /// SyncMasternodeList / SyncMasternodeWinners (masternode-sync.cpp:361-423):
    /// true to go on to the next peer
    fn sync_stage(
        &mut self,
        peer: &SyncPeer,
        now: i64,
        stage: i32,
        out: &mut Vec<SyncRequest>,
    ) -> bool {
        if self.status != stage {
            return true;
        }
        let (last, name) = if stage == SYNC_LIST {
            (self.last_list_update, LIST_REQUEST)
        } else {
            (self.last_winner_update, WINNER_REQUEST)
        };
        match self.sync_assets(&peer.key, now, last, name) {
            Assets::Fail | Assets::AtPeerLimit => false,
            Assets::Success | Assets::StageComplete | Assets::Waiting => true,
            Assets::Request => {
                if stage == SYNC_LIST {
                    // DsegUpdate: a non-local peer is asked at most once in
                    // DSEG_SECONDS, though the request still counts
                    if self.may_ask_for_list(peer, now) {
                        out.push(SyncRequest::MasternodeList(peer.id));
                    }
                } else {
                    out.push(SyncRequest::Winners(peer.id));
                }
                self.successive_requests += 1;
                false
            }
        }
    }

    /// recordDsegUpdateAttempt (MasternodeNetworkMessageManager.cpp:173-189)
    fn may_ask_for_list(&mut self, peer: &SyncPeer, now: i64) -> bool {
        if !peer.local {
            if let Some(&until) = self.asked_for_list.get(&peer.ip) {
                if now < until {
                    return false;
                }
            }
        }
        self.asked_for_list
            .insert(peer.ip.clone(), now + DSEG_SECONDS);
        true
    }

    /// peerHasRequestedMasternodeListTooOften
    /// (MasternodeNetworkMessageManager.cpp:157-171): a non-local peer's
    /// second ask for the whole list within DSEG_SECONDS (Core scores it 34,
    /// masternode-sync.cpp:113-126)
    pub fn peer_asked_for_list_too_often(&mut self, ip: &str, now: i64) -> bool {
        if let Some(&until) = self.asked_us_for_list.get(ip) {
            if now < until {
                return true;
            }
        }
        self.asked_us_for_list
            .insert(ip.to_string(), now + DSEG_SECONDS);
        false
    }

    /// mAskedUsForMasternodeList and mWeAskedForMasternodeList by IP, which
    /// Divi Core keeps in mncache.dat (MasternodeNetworkMessageManager.h:68-78)
    pub fn list_asks(&self) -> (&HashMap<String, i64>, &HashMap<String, i64>) {
        (&self.asked_us_for_list, &self.asked_for_list)
    }

    /// Drop the asks whose time is past (clearTimedOutMasternodeListRequestsFromPeers,
    /// clearTimedOutMasternodeListRequestsToPeers,
    /// MasternodeNetworkMessageManager.cpp:66-92)
    pub fn prune_list_asks(&mut self, now: i64) {
        self.asked_us_for_list.retain(|_, until| *until >= now);
        self.asked_for_list.retain(|_, until| *until >= now);
    }

    /// Put back the asks read from mncache.dat
    pub fn set_list_asks(
        &mut self,
        asked_us: HashMap<String, i64>,
        we_asked: HashMap<String, i64>,
    ) {
        self.asked_us_for_list = asked_us;
        self.asked_for_list = we_asked;
    }

    /// Process (masternode-sync.cpp:424-454), called once a second while the
    /// chain is synced. `peers` are the peers it may ask, in connection order;
    /// a peer below `active_protocol` is passed over. Returns what to send.
    pub fn process(
        &mut self,
        now: i64,
        peers: &[SyncPeer],
        active_protocol: i32,
    ) -> Vec<SyncRequest> {
        let mut out = Vec::new();
        if self.should_wait(now) {
            return out;
        }
        if self.status == SYNC_INITIAL {
            self.next_stage(now);
        }
        // No sync with fewer than three such peers
        if peers.len() < 3 {
            return out;
        }
        if self.status == SYNC_SPORKS {
            self.next_stage(now);
        }
        for peer in peers {
            if peer.version >= active_protocol
                && (!self.sync_stage(peer, now, SYNC_LIST, &mut out)
                    || !self.sync_stage(peer, now, SYNC_MNW, &mut out))
            {
                break;
            }
        }
        out
    }

    /// A peer's `ssc` (masternode-sync.cpp:192-224): counted when it answers
    /// a request of the current stage that is pending
    pub fn sync_status_count(&mut self, peer: &str, code: i32, items: i32, now: i64) {
        if self.status >= SYNC_FINISHED {
            return;
        }
        if code != SYNC_LIST && code != SYNC_MNW {
            return;
        }
        if code != self.status {
            return;
        }
        let name = if code == SYNC_LIST {
            LIST_REQUEST
        } else {
            WINNER_REQUEST
        };
        if self.requests.has_fulfilled(peer, name, now)
            || !self.requests.has_pending(peer, name, now)
        {
            return;
        }
        if code == SYNC_LIST {
            self.last_list_update = now;
            self.broadcasts_received += items;
            self.list_requests_fulfilled += 1;
        } else {
            self.last_winner_update = now;
            self.winners_received += items;
            self.winner_requests_fulfilled += 1;
        }
        self.requests.fulfill_pending(peer, name, now);
    }

    /// RecordMasternodeListUpdate (masternode-sync.cpp:227-239): a broadcast
    /// announced or taken during the list stage; `known` when the node has it
    pub fn record_list_update(&mut self, hash: [u8; 32], known: bool, now: i64) {
        if self.status != SYNC_LIST {
            return;
        }
        Self::record(
            &mut self.seen_broadcasts,
            &mut self.last_list_update,
            hash,
            known,
            now,
        );
    }

    /// RecordMasternodeWinnerUpdate (masternode-sync.cpp:241-253)
    pub fn record_winner_update(&mut self, hash: [u8; 32], known: bool, now: i64) {
        if self.status != SYNC_MNW {
            return;
        }
        Self::record(
            &mut self.seen_winners,
            &mut self.last_winner_update,
            hash,
            known,
            now,
        );
    }

    fn record(
        seen: &mut HashMap<[u8; 32], i32>,
        last: &mut i64,
        hash: [u8; 32],
        known: bool,
        now: i64,
    ) {
        if known {
            let n = seen.entry(hash).or_insert(0);
            if *n < SYNC_THRESHOLD {
                *last = now;
                *n += 1;
            }
        } else {
            *last = now;
            seen.entry(hash).or_insert(1);
        }
    }
}

/// IsBlockchainSynced (MasternodeHelpers.cpp:26-62): true once the tip is less
/// than ten minutes old, and from then on, unless the check was not made for
/// an hour (the node slept), which also asks the masternode sync to start over
#[derive(Debug, Clone)]
pub struct BlockchainSynced {
    synced: bool,
    last_checked: i64,
    resync_requested: bool,
}

impl BlockchainSynced {
    pub fn new(now: i64) -> Self {
        Self {
            synced: false,
            last_checked: now,
            resync_requested: false,
        }
    }

    /// `tip_time`: the tip's block time, if any; `importing`: a -reindex or
    /// -loadblock is running
    pub fn check(&mut self, now: i64, tip_time: Option<i64>, importing: bool) -> bool {
        let stalled = now - self.last_checked > 60 * 60;
        self.last_checked = now;
        if stalled {
            self.synced = false;
            self.resync_requested = true;
        }
        if self.synced {
            return true;
        }
        if importing {
            return false;
        }
        match tip_time {
            Some(t) if t + 60 * 10 >= now => {
                self.synced = true;
                true
            }
            _ => false,
        }
    }

    /// MasternodeResyncIsRequested and FulfilledMasternodeResyncRequest
    /// (MasternodeHelpers.cpp:16-24): true once after a stall
    pub fn take_resync_request(&mut self) -> bool {
        std::mem::take(&mut self.resync_requested)
    }
}

/// The node's masternode sync and its IsBlockchainSynced, shared by the sync
/// task, the message handlers and the RPCs (Core keeps both as globals)
#[derive(Debug, Clone)]
pub struct SyncState {
    pub sync: MasternodeSync,
    pub chain: BlockchainSynced,
}

pub type SharedMasternodeSync = Arc<Mutex<SyncState>>;

/// A sync at its first stage; `main` for the main network's request expiry
pub fn shared(now: i64, main: bool) -> SharedMasternodeSync {
    Arc::new(Mutex::new(SyncState {
        sync: MasternodeSync::new(now, fulfilled_expire_time(main)),
        chain: BlockchainSynced::new(now),
    }))
}

/// The status members `mnsync status` writes after IsBlockchainSynced, in
/// Divi Core's order (rpcmisc.cpp:203-213)
pub fn status_members(sync: &MasternodeSync) -> [(&'static str, i64); 10] {
    [
        ("timestampOfLastMasternodeListUpdate", sync.last_list_update),
        (
            "timestampOfLastMasternodeWinnerUpdate",
            sync.last_winner_update,
        ),
        ("timestampOfLastFailedSync", sync.last_failed_sync),
        (
            "countOfFailedSyncAttempts",
            sync.failed_sync_attempts as i64,
        ),
        (
            "nominalNumberOfMasternodeBroadcastsReceived",
            sync.broadcasts_received as i64,
        ),
        (
            "nominalNumberOfMasternodeWinnersReceived",
            sync.winners_received as i64,
        ),
        (
            "fulfilledMasternodeListSyncRequests",
            sync.list_requests_fulfilled as i64,
        ),
        (
            "fulfilledMasternodeWinnerSyncRequests",
            sync.winner_requests_fulfilled as i64,
        ),
        ("currentMasternodeSyncStatus", sync.status as i64),
        (
            "totalSuccessivePeerSyncRequests",
            sync.successive_requests as i64,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTO: i32 = 70915;

    fn peers(n: u64) -> Vec<SyncPeer> {
        (1..=n)
            .map(|id| SyncPeer {
                id,
                key: format!("127.0.0.{id}:5000"),
                ip: format!("127.0.0.{id}"),
                local: true,
                version: 70920,
            })
            .collect()
    }

    /// Ticks once a second from `from` to `to` (inclusive), as the sync
    /// thread does, answering every request with `ssc <stage> 0` at once
    fn run(
        sync: &mut MasternodeSync,
        peers: &[SyncPeer],
        from: i64,
        to: i64,
        answer: bool,
    ) -> Vec<(i64, SyncRequest)> {
        let mut sent = Vec::new();
        for now in from..=to {
            for r in sync.process(now, peers, PROTO) {
                sent.push((now, r));
                if answer {
                    let (id, code) = match r {
                        SyncRequest::MasternodeList(id) => (id, SYNC_LIST),
                        SyncRequest::Winners(id) => (id, SYNC_MNW),
                    };
                    let key = peers.iter().find(|p| p.id == id).unwrap().key.clone();
                    sync.sync_status_count(&key, code, 0, now);
                }
            }
        }
        sent
    }

    /// The first tick only starts the clock (a last tick an hour back resets);
    /// the next, five seconds on, leaves INITIAL for SPORKS, where a node
    /// with fewer than three peers stays
    #[test]
    fn with_fewer_than_three_peers_the_sync_stays_at_sporks() {
        let mut sync = MasternodeSync::new(1700001000, 300);
        assert_eq!(sync.status, SYNC_INITIAL);
        assert!(sync.process(1700001000, &peers(2), PROTO).is_empty());
        assert_eq!(sync.status, SYNC_INITIAL);
        assert!(sync.process(1700001004, &peers(2), PROTO).is_empty());
        assert_eq!(sync.status, SYNC_INITIAL);
        run(&mut sync, &peers(2), 1700001005, 1700002000, true);
        assert_eq!(sync.status, SYNC_SPORKS);
        assert_eq!(sync.successive_requests, 0);
    }

    /// Three answering peers: one asked per tick for the list, the next stage
    /// ten seconds after the last count, the same for the winners, then
    /// FINISHED
    #[test]
    fn three_answering_peers_take_the_sync_to_finished() {
        let p = peers(3);
        let mut sync = MasternodeSync::new(1700001000, 300);
        sync.process(1700001000, &p, PROTO);
        let sent = run(&mut sync, &p, 1700001001, 1700001100, true);
        assert_eq!(
            sent,
            vec![
                (1700001005, SyncRequest::MasternodeList(1)),
                (1700001010, SyncRequest::MasternodeList(2)),
                (1700001015, SyncRequest::MasternodeList(3)),
                (1700001030, SyncRequest::Winners(1)),
                (1700001035, SyncRequest::Winners(2)),
                (1700001040, SyncRequest::Winners(3)),
            ]
        );
        assert_eq!(sync.status, SYNC_FINISHED);
        assert_eq!(sync.list_requests_fulfilled, 3);
        assert_eq!(sync.winner_requests_fulfilled, 3);
        assert_eq!(sync.last_list_update, 1700001015);
        assert_eq!(sync.last_winner_update, 1700001040);
        assert!(sync.is_synced());
    }

    /// Peers that never answer: FAILED 25 s into the list stage, then INITIAL
    /// again a minute later and SPORKS, LIST again
    #[test]
    fn silent_peers_fail_the_sync_and_it_is_retried() {
        let p = peers(3);
        let mut sync = MasternodeSync::new(1700001000, 300);
        sync.process(1700001000, &p, PROTO);
        run(&mut sync, &p, 1700001001, 1700001030, false);
        assert_eq!(sync.status, SYNC_LIST);
        run(&mut sync, &p, 1700001031, 1700001035, false);
        assert_eq!(sync.status, SYNC_FAILED);
        assert_eq!(sync.last_failed_sync, 1700001035);
        assert_eq!(sync.failed_sync_attempts, 1);
        run(&mut sync, &p, 1700001036, 1700001095, false);
        assert_eq!(sync.status, SYNC_FAILED);
        // Reset at 1700001100 (failed + 60 < now), then SPORKS and LIST in the same tick
        run(&mut sync, &p, 1700001096, 1700001100, false);
        assert_eq!(sync.status, SYNC_LIST);
        assert_eq!(sync.failed_sync_attempts, 0);
    }

    /// Reset goes back to INITIAL but keeps the fulfilled requests: peers that
    /// answered within the expiry are not asked again, so with no new count
    /// the list stage fails
    #[test]
    fn reset_keeps_the_fulfilled_requests() {
        let p = peers(3);
        let mut sync = MasternodeSync::new(1700001000, 300);
        sync.process(1700001000, &p, PROTO);
        run(&mut sync, &p, 1700001001, 1700001100, true);
        assert!(sync.is_synced());
        sync.reset(1700001101);
        assert_eq!(sync.status, SYNC_INITIAL);
        let sent = run(&mut sync, &p, 1700001102, 1700001140, true);
        assert!(sent.is_empty(), "{sent:?}");
        assert_eq!(sync.status, SYNC_FAILED);
    }

    /// An ssc counts only for a pending request of the current stage, once
    #[test]
    fn ssc_counts_only_a_pending_request_of_the_stage() {
        let p = peers(3);
        let mut sync = MasternodeSync::new(1700001000, 300);
        sync.process(1700001000, &p, PROTO);
        sync.process(1700001005, &p, PROTO);
        assert_eq!(sync.status, SYNC_LIST);
        sync.sync_status_count(&p[1].key, SYNC_LIST, 4, 1700001006); // not asked
        sync.sync_status_count(&p[0].key, SYNC_MNW, 4, 1700001006); // another stage
        assert_eq!(sync.list_requests_fulfilled, 0);
        sync.sync_status_count(&p[0].key, SYNC_LIST, 4, 1700001006);
        sync.sync_status_count(&p[0].key, SYNC_LIST, 4, 1700001007);
        assert_eq!(sync.list_requests_fulfilled, 1);
        assert_eq!(sync.broadcasts_received, 4);
        assert_eq!(sync.last_list_update, 1700001006);
    }

    /// A clock that goes back, or an hour without a tick, starts over
    #[test]
    fn a_clock_jump_starts_the_sync_over() {
        let p = peers(3);
        let mut sync = MasternodeSync::new(1700001000, 300);
        sync.process(1700001000, &p, PROTO);
        sync.process(1700001005, &p, PROTO);
        assert_eq!(sync.status, SYNC_LIST);
        assert!(sync.process(1700000900, &p, PROTO).is_empty());
        assert_eq!(sync.status, SYNC_INITIAL);
        sync.process(1700000905, &p, PROTO);
        assert_eq!(sync.status, SYNC_LIST);
        assert!(sync.process(1700000905 + 3601, &p, PROTO).is_empty());
        assert_eq!(sync.status, SYNC_INITIAL);
    }

    /// A peer below the active protocol is passed over
    #[test]
    fn an_old_peer_is_not_asked() {
        let mut p = peers(3);
        p[0].version = 70900;
        let mut sync = MasternodeSync::new(1700001000, 300);
        sync.process(1700001000, &p, PROTO);
        assert_eq!(
            sync.process(1700001005, &p, PROTO),
            vec![SyncRequest::MasternodeList(2)]
        );
    }

    /// A non-local peer is sent dseg once in three hours, though the request
    /// is counted
    #[test]
    fn a_non_local_peer_is_asked_for_the_list_once() {
        let mut p = peers(3);
        p[0].local = false;
        let mut sync = MasternodeSync::new(1700001000, 300);
        assert!(sync.may_ask_for_list(&p[0], 1700001000));
        assert!(!sync.may_ask_for_list(&p[0], 1700001000 + DSEG_SECONDS - 1));
        assert!(sync.may_ask_for_list(&p[1], 1700001001));
        assert!(sync.may_ask_for_list(&p[1], 1700001002));
    }

    #[test]
    fn fulfilled_requests_expire_and_survive_a_restart() {
        let mut r = FulfilledRequests::new(300);
        r.add_pending("a", LIST_REQUEST, 100);
        assert!(r.has_pending("a", LIST_REQUEST, 400));
        assert!(!r.has_pending("a", LIST_REQUEST, 401));
        r.fulfill_pending("a", LIST_REQUEST, 150);
        assert!(!r.has_pending("a", LIST_REQUEST, 150));
        assert!(r.has_fulfilled("a", LIST_REQUEST, 449));
        assert!(!r.has_fulfilled("a", LIST_REQUEST, 450));
        r.add_pending("127.0.0.2:5001", WINNER_REQUEST, 100);
        let mut back = FulfilledRequests::new(300);
        assert!(back.read_file_data(&r.to_file_data(), true));
        // "a" is no address, so it is not in the file
        assert!(!back.has_fulfilled("a", LIST_REQUEST, 449));
        assert!(back.has_pending("127.0.0.2:5001", WINNER_REQUEST, 400));
        r.add_fulfilled("127.0.0.2:5000", LIST_REQUEST, 150);
        assert!(back.read_file_data(&r.to_file_data(), true));
        assert!(back.has_fulfilled("127.0.0.2:5000", LIST_REQUEST, 449));
        back.check_and_remove(451);
        assert!(!back.has_fulfilled("127.0.0.2:5000", LIST_REQUEST, 0));
    }

    /// netfulfilled.dat's maps byte for byte as Divi Core writes them: a
    /// count, each CService (IPv4-mapped address, port big-endian) with its
    /// requests (a string and an int64), peers in address order
    #[test]
    fn fulfilled_requests_are_written_as_core_serialises_them() {
        let mut r = FulfilledRequests::new(300);
        r.add_fulfilled("127.0.0.3:51476", LIST_REQUEST, 1000);
        r.add_fulfilled("127.0.0.2:51476", WINNER_REQUEST, 1000);
        r.add_fulfilled("127.0.0.2:51476", LIST_REQUEST, 1000);
        let service = |last: u8| {
            let mut s = vec![0u8; 10];
            s.extend_from_slice(&[0xff, 0xff, 127, 0, 0, last]);
            s.extend_from_slice(&[0xc9, 0x14]);
            s
        };
        let request = |name: &str| {
            let mut s = vec![name.len() as u8];
            s.extend_from_slice(name.as_bytes());
            s.extend_from_slice(&1300i64.to_le_bytes());
            s
        };
        let mut want = vec![2];
        want.extend(service(2));
        want.push(2);
        want.extend(request("mnsync"));
        want.extend(request("mnwsync"));
        want.extend(service(3));
        want.push(1);
        want.extend(request("mnsync"));
        // No pending requests
        want.push(0);
        assert_eq!(r.to_file_data(), want);

        // Elsewhere a peer is its IP, written with port 0
        let mut m = FulfilledRequests::new(1800);
        m.add_fulfilled("203.0.113.9", LIST_REQUEST, 0);
        let data = m.to_file_data();
        assert_eq!(
            &data[1..19],
            &[&[0u8; 10][..], &[0xff, 0xff, 203, 0, 113, 9, 0, 0]].concat()[..]
        );
        let mut back = FulfilledRequests::new(1800);
        assert!(back.read_file_data(&data, false));
        assert!(back.has_fulfilled("203.0.113.9", LIST_REQUEST, 1799));
    }

    /// Maps that do not parse leave the fulfilled requests empty and keep the
    /// pending ones read before the fault, as Core's ParseChunk and Clear do
    #[test]
    fn fulfilled_requests_that_do_not_parse_are_cleared_as_core_clears_them() {
        let mut r = FulfilledRequests::new(300);
        r.add_fulfilled("127.0.0.2:1", LIST_REQUEST, 0);
        r.add_pending("127.0.0.2:2", LIST_REQUEST, 0);
        r.add_pending("127.0.0.2:3", LIST_REQUEST, 0);
        let data = r.to_file_data();
        let mut back = FulfilledRequests::new(300);
        // Cut inside the second pending peer
        assert!(!back.read_file_data(&data[..data.len() - 3], true));
        assert!(!back.has_fulfilled("127.0.0.2:1", LIST_REQUEST, 0));
        assert!(back.has_pending("127.0.0.2:2", LIST_REQUEST, 0));
        assert!(!back.has_pending("127.0.0.2:3", LIST_REQUEST, 0));
    }

    #[test]
    fn blockchain_synced_latches_and_a_stall_resets_it() {
        let mut b = BlockchainSynced::new(1000);
        assert!(!b.check(1000, Some(0), false));
        assert!(!b.check(1001, Some(1001), true));
        assert!(b.check(1002, Some(1001), false));
        // Latched: an old tip later does not matter
        assert!(b.check(2500, Some(1001), false));
        let mut b = BlockchainSynced::new(1000);
        assert!(b.check(1000, Some(1000), false));
        assert!(b.check(2000, Some(0), false));
        assert!(!b.take_resync_request());
        // More than an hour since the last check: not synced, a resync asked
        assert!(!b.check(2000 + 3601, Some(0), false));
        assert!(b.take_resync_request());
        assert!(!b.take_resync_request());
    }

    #[test]
    fn record_updates_count_each_hash_twice_at_most() {
        let p = peers(3);
        let mut sync = MasternodeSync::new(1700001000, 300);
        sync.record_list_update([1; 32], false, 1700000999);
        assert_eq!(sync.last_list_update, 0, "only during the list stage");
        sync.process(1700001000, &p, PROTO);
        sync.process(1700001005, &p, PROTO);
        sync.record_list_update([1; 32], false, 1700001006);
        sync.record_list_update([1; 32], true, 1700001007);
        sync.record_list_update([1; 32], true, 1700001008);
        assert_eq!(sync.last_list_update, 1700001007);
    }
}
