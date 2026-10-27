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

//! Peer manager for handling multiple peer connections
//!
//! Manages peer discovery, connection limits, and message routing.

use crate::connection::Connection;
use crate::constants::Magic;
use crate::error::NetworkError;
use crate::message::{InvItem, InvType};
use crate::peer::{PeerEvent, PeerHandle, PeerId};
use crate::scoring::{Misbehavior, MisbehaviourOutcome, PeerScoring};
use crate::NetworkMessage;
use divi_primitives::hash::Hash256;

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// How long Divi Core's DNS seed thread waits for peers before it asks the
/// seeds, when the address book has addresses (net.cpp:1020)
const DNS_SEED_DELAY: Duration = Duration::from_secs(11);

/// Reads the node's current chain height
pub type HeightSource = Arc<dyn Fn() -> u32 + Send + Sync>;

/// Takes a peer task's name off the running list when it ends, however
struct TaskDone(Arc<parking_lot::Mutex<HashMap<u64, String>>>, u64);

impl Drop for TaskDone {
    fn drop(&mut self) {
        self.0.lock().remove(&self.1);
    }
}

/// Looks a DNS seed up: given "host:port", its addresses. The system
/// resolver unless one is set ([`PeerManager::set_seed_resolver`])
pub type SeedResolver = Arc<
    dyn Fn(String) -> futures::future::BoxFuture<'static, std::io::Result<Vec<SocketAddr>>>
        + Send
        + Sync,
>;

/// What `try_send_to_peer` did
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrySend {
    /// Queued
    Sent,
    /// The peer's queue is full: try again later
    Full,
    /// No such peer, or it is going
    Gone,
}

/// Configuration for the peer manager
#[derive(Debug, Clone)]
pub struct PeerManagerConfig {
    /// Maximum number of outbound connections
    pub max_outbound: usize,
    /// Maximum number of inbound connections
    pub max_inbound: usize,
    /// Network magic bytes
    pub magic: Magic,
    /// DNS seeds for peer discovery
    pub dns_seeds: Vec<String>,
    /// Static peers to connect to
    pub static_peers: Vec<SocketAddr>,
    /// `-connect` and `-addnode` peers given by host name while a proxy is set:
    /// dialled through `proxy` by name, the proxy resolving them (Divi Core
    /// ConnectSocketByName with a name proxy, netbase.cpp:631-660; net.cpp:1221-1236)
    pub named_peers: Vec<(String, u16)>,
    /// Listen address for inbound connections
    pub listen_addr: Option<SocketAddr>,
    /// Default P2P port for DNS seed resolution
    pub default_port: u16,
    /// SOCKS5 proxy for outbound connections to IPv4 and IPv6 peers (C++ `-proxy`,
    /// with `-proxyrandomize`). When set, no such connection is made directly and
    /// DNS seeds are not resolved locally; a peer at an address that is not
    /// routable (127.0.0.1, a private network) is dialled directly, as Divi
    /// Core keeps no proxy for those (netbase.cpp:620-629).
    pub proxy: Option<crate::socks5::Proxy>,
    /// The proxy for onion peers (Divi Core's NET_TOR proxy: `-onion`, else
    /// `-proxy`) and whether onion is reachable (`-proxy`, `-onion`; not with
    /// `-onion=0`; net.cpp:1774-1800). The Tor controller changes both later.
    pub tor_proxy: Option<crate::socks5::Proxy>,
    pub tor_reachable: bool,
    /// `static_peers` are `-connect` peers (dialled by address and port, as
    /// Divi Core dials `-connect`) rather than `-addnode` and built-in peers
    pub connect_only: bool,
    /// Inbound peers from these networks are whitelisted (Divi Core -whitelist)
    pub whitelist: Vec<crate::Subnet>,
    /// More listen addresses; every peer coming in on one is whitelisted
    /// (Divi Core -whitebind)
    pub white_listen: Vec<SocketAddr>,
    /// More listen addresses (the -bind addresses after the first), their
    /// peers not whitelisted
    pub more_listen: Vec<SocketAddr>,
    /// `-seednode` peers: each dialled once, asked for addresses and dropped
    /// after its answer, `-connect` or not (Divi Core AddOneShot,
    /// net.cpp:1071-1084, :1096, :1112, :1842-1843)
    pub seed_nodes: Vec<String>,
    /// Query the DNS seeds at start (Divi Core -dnsseed, after -connect
    /// soft-set it off; net.cpp:1448-1450, :1683-1685)
    pub dns_seed: bool,
    /// Query them even when the address book has addresses (-forcednsseed)
    pub force_dns_seed: bool,
}

/// The check Divi Core makes before a dial (net.cpp OpenNetworkConnection,
/// ConnectNode, ThreadOpenConnections)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRule {
    /// `-connect` and `addnode … onetry` dial by name: skipped only while a
    /// peer with this exact address and port is connected (FindNode(pszDest))
    ByName,
    /// `-addnode`, `addnode … add` and the built-in peers: skipped while any
    /// peer from this IP is connected or being dialled, inbound or outbound
    /// (FindNode(CNetAddr))
    ByAddress,
    /// Peers found through DNS seeds: as `ByAddress`, and at most one
    /// outbound peer per network group (ThreadOpenConnections setConnected)
    Automatic,
}

/// Divi Core CNetAddr::GetGroup for an IP address: /16 for IPv4 (also when
/// mapped into IPv6), /32 for IPv6; local addresses form one group and
/// unroutable ones another
fn net_group(ip: IpAddr) -> Vec<u8> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() || v4.is_unspecified() {
                vec![0]
            } else if v4.is_private()
                || v4.is_link_local()
                || v4.is_documentation()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
            {
                vec![1]
            } else {
                vec![4, o[0], o[1]]
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if v6.is_loopback() || v6.is_unspecified() {
                vec![0]
            } else if (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
            {
                vec![1]
            } else {
                let o = v6.octets();
                vec![6, o[0], o[1], o[2], o[3]]
            }
        }
    }
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        PeerManagerConfig {
            max_outbound: 16,
            max_inbound: 109,
            magic: crate::MAINNET_MAGIC,
            dns_seeds: vec!["autoseeds.diviseed.diviproject.org".to_string()],
            static_peers: vec![
                "178.62.195.16:51472".parse().unwrap(),
                "178.62.221.33:51472".parse().unwrap(),
                "178.128.251.20:51472".parse().unwrap(),
            ],
            named_peers: Vec::new(),
            listen_addr: None,
            default_port: 51472, // Mainnet P2P port
            proxy: None,
            tor_proxy: None,
            tor_reachable: false,
            connect_only: false,
            whitelist: Vec::new(),
            white_listen: Vec::new(),
            more_listen: Vec::new(),
            seed_nodes: Vec::new(),
            dns_seed: true,
            force_dns_seed: false,
        }
    }
}

/// Added node entry (manually added via RPC)
#[derive(Debug, Clone)]
pub struct AddedNode {
    /// The node as it was given (divid keeps and matches the text, net.cpp:1183-1206)
    pub name: String,
    /// Address of the node
    pub addr: SocketAddr,
    /// Whether we're currently connected to this node
    pub connected: bool,
    /// Whether connection attempt is in progress
    pub connecting: bool,
}

/// Manages connections to multiple peers
pub struct PeerManager {
    /// Configuration
    config: PeerManagerConfig,
    /// Connected peers
    peers: RwLock<HashMap<PeerId, PeerHandle>>,
    /// Our best block height
    our_height: RwLock<u32>,
    /// Service bits advertised in our version message
    our_services: AtomicU64,
    /// Event channel sender
    event_tx: broadcast::Sender<PeerEvent>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Set once the node has begun to stop: no peer is accepted, dialled or
    /// looked up from then on, as Divi Core interrupts and joins its net
    /// threads first when it shuts down (divid.cpp:42-53)
    stopping: AtomicBool,
    /// The seed lookup in place of the system resolver, when set
    seed_resolver: RwLock<Option<SeedResolver>>,
    /// The lookup of a -seednode name in place of the system resolver, when set
    name_resolver: RwLock<Option<SeedResolver>>,
    /// The tasks this manager spawns (listeners, dials, connections, the seed
    /// lookup), so a stop can wait for them as Divi Core's join_all waits for
    /// its net threads (divid.cpp:42-53); and the names of those running
    tasks: tokio_util::task::TaskTracker,
    running: Arc<parking_lot::Mutex<HashMap<u64, String>>>,
    next_task: AtomicU64,
    /// Peer scoring and ban management
    scoring: PeerScoring,
    /// Nonces of our version messages on open connections (self-connection check)
    local_nonces: crate::connection::LocalNonces,
    /// The node's own addresses (Divi Core mapLocalHost)
    local_addresses: RwLock<Arc<crate::local::LocalAddresses>>,
    /// The onion network's proxy and whether onion is reachable, which the Tor
    /// controller changes once it has authenticated (torcontrol.cpp:533-541)
    tor: RwLock<(Option<crate::socks5::Proxy>, bool)>,
    /// Named peers connected (the peer each one is) and being dialled
    named_connected: RwLock<HashMap<String, PeerId>>,
    named_dialling: RwLock<HashSet<String>>,
    /// Added nodes, in the order they were added: -addnode, then the addnode
    /// RPC (Divi Core's vAddedNodes list, net.cpp:1218)
    added_nodes: RwLock<Vec<(String, SocketAddr)>>,
    /// Addresses currently being connected to (connection attempt in progress)
    connecting_addrs: RwLock<HashSet<SocketAddr>>,
    /// Total bytes sent across all peers (cumulative since node start)
    total_bytes_sent: Arc<AtomicU64>,
    /// Total bytes received across all peers (cumulative since node start)
    total_bytes_recv: Arc<AtomicU64>,
    /// Per-address backoff state for static peer reconnection attempts.
    ///
    /// Tracks (consecutive_failures, last_attempt_time) so that repeatedly-failing
    /// peers are skipped for exponentially longer periods (up to 30 minutes).
    static_peer_backoff: RwLock<HashMap<SocketAddr, (u32, Instant)>>,
    /// Reads the current chain height for version messages (set by the node)
    height_source: RwLock<Option<HeightSource>>,
    /// The node's active spork count, which an inbound peer is told after its
    /// version (main.cpp:417-419)
    spork_count_source: RwLock<Option<HeightSource>>,
    /// Listeners bound before the node starts (bind_listeners): address,
    /// whether its peers are whitelisted, socket. None until bound.
    prebound: parking_lot::Mutex<Option<Vec<(SocketAddr, bool, TcpListener)>>>,
    /// Inbound connections accepted whose handshake has not finished yet
    inbound_handshaking: AtomicUsize,
    /// Addresses of other nodes learnt from peers (Divi Core's addrman)
    address_book: Arc<crate::addrbook::AddressBook>,
    /// What each peer is known to have of the address gossip
    gossip: crate::gossip::Gossip,
    /// `-seednode` peers not yet reached (Divi Core vOneShots)
    one_shots: parking_lot::Mutex<std::collections::VecDeque<String>>,
    /// Connected peers that go after their addr (Divi Core fOneShot)
    one_shot_peers: RwLock<HashSet<PeerId>>,
    /// The clock the manager, its connections, bans and address book read
    /// (the system clock unless a test gives one it moves on)
    clock: crate::peer_clock::PeerClock,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new(config: PeerManagerConfig) -> Arc<Self> {
        Self::with_clock(config, crate::peer_clock::PeerClock::system())
    }

    /// A peer manager on `clock`: its waits between dials, the static peers'
    /// back-off and its connections' timeouts on the clock's `now`, bans on
    /// its `time` and the address book on its `adjusted_time`
    pub fn with_clock(config: PeerManagerConfig, clock: crate::peer_clock::PeerClock) -> Arc<Self> {
        let config_magic = config.magic;
        let seed_nodes = config.seed_nodes.clone();
        let tor = (config.tor_proxy, config.tor_reachable);
        let (event_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, _) = broadcast::channel(1);

        Arc::new(PeerManager {
            config,
            peers: RwLock::new(HashMap::new()),
            our_height: RwLock::new(0),
            our_services: AtomicU64::new(crate::constants::services::NODE_NETWORK),
            event_tx,
            shutdown_tx,
            stopping: AtomicBool::new(false),
            seed_resolver: RwLock::new(None),
            name_resolver: RwLock::new(None),
            tasks: tokio_util::task::TaskTracker::new(),
            running: Default::default(),
            next_task: AtomicU64::new(0),
            scoring: PeerScoring::with_clock(clock.clone()),
            local_nonces: Default::default(),
            local_addresses: RwLock::new(Arc::new(Default::default())),
            tor: RwLock::new(tor),
            named_connected: RwLock::new(HashMap::new()),
            named_dialling: RwLock::new(HashSet::new()),
            added_nodes: RwLock::new(Vec::new()),
            connecting_addrs: RwLock::new(HashSet::new()),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_recv: Arc::new(AtomicU64::new(0)),
            static_peer_backoff: RwLock::new(HashMap::new()),
            height_source: RwLock::new(None),
            spork_count_source: RwLock::new(None),
            prebound: parking_lot::Mutex::new(None),
            inbound_handshaking: AtomicUsize::new(0),
            address_book: Arc::new(crate::addrbook::AddressBook::with_clock(
                config_magic,
                clock.clone(),
            )),
            gossip: crate::gossip::Gossip::new(),
            one_shots: parking_lot::Mutex::new(seed_nodes.into()),
            one_shot_peers: RwLock::new(HashSet::new()),
            clock,
        })
    }

    /// The clock the manager reads
    pub fn clock(&self) -> &crate::peer_clock::PeerClock {
        &self.clock
    }

    /// The addresses learnt from peers
    pub fn address_book(&self) -> &Arc<crate::addrbook::AddressBook> {
        &self.address_book
    }

    /// The address gossip of the connected peers
    pub fn gossip(&self) -> &crate::gossip::Gossip {
        &self.gossip
    }

    /// Whether a peer we dialled has yet to send its sporks, so that Divi Core sends it
    /// nothing of its own (CNode::CanSendMessagesToPeer, Node.cpp:1025-1034)
    pub fn waiting_for_sporks(&self, peer_id: PeerId) -> bool {
        self.peers
            .read()
            .get(&peer_id)
            .is_some_and(|h| h.stats.sporks_wait.load(Ordering::Acquire))
    }

    /// The peer's sporks are in: nothing is held back from it from now on, and its
    /// first ping goes now, before what the node sends it next (Divi Core pings
    /// before SendMessages, net.cpp:871-893)
    pub fn sporks_arrived(&self, peer_id: PeerId) {
        if let Some(handle) = self.peers.read().get(&peer_id) {
            if handle.stats.sporks_arrived() {
                let _ = handle.try_send(NetworkMessage::Ping(0));
            }
        }
    }

    /// Send what was held back from a peer while its sporks were out: after the
    /// sync is started with it, as Divi Core's SendMessages asks for blocks before it
    /// sends the inventory it kept (main.cpp:1304-1330)
    pub fn release_held(&self, peer_id: PeerId) {
        if let Some(handle) = self.peers.read().get(&peer_id) {
            if handle.stats.sporks_wait.load(Ordering::Acquire) {
                return;
            }
            for msg in handle.stats.take_held() {
                let _ = handle.try_send(msg);
            }
        }
    }

    /// Whether a connected peer is a `-seednode` peer, dropped after its addr
    pub fn is_one_shot(&self, peer_id: PeerId) -> bool {
        self.one_shot_peers.read().contains(&peer_id)
    }

    /// Dial addresses learnt from peers into free outbound slots, as Divi Core
    /// dials from its address manager (net.cpp:1086-1179): an address the
    /// book selects, not one tried in the last 10 minutes (until 30 tries)
    /// nor off the network's port (until 50), at most 100 tries a slot; not
    /// with -connect, which dials only its own peers
    fn dial_learnt(self: &Arc<Self>) {
        if self.config.connect_only {
            return;
        }
        // GetAdjustedTime (net.cpp:1147)
        let now = self.clock.adjusted_time();
        let local = self.local_addresses();
        let mut slots = self.config.max_outbound;
        while slots > 0 && self.can_connect_outbound() {
            slots -= 1;
            let mut found = None;
            for tries in 1..=100 {
                let Some((addr, last_try)) = self.address_book.select() else {
                    return;
                };
                // A network -onlynet left out is not dialled (net.cpp:1164-1165)
                if local.is_limited(&addr.ip()) {
                    continue;
                }
                if now - last_try < 600 && tries < 30 {
                    continue;
                }
                if addr.port() != self.config.default_port && tries < 50 {
                    continue;
                }
                if self.is_banned(&addr.ip()) || !self.claim_dial(addr, DialRule::Automatic) {
                    continue;
                }
                found = Some(addr);
                break;
            }
            let Some(addr) = found else {
                return;
            };
            debug!("Dialling learnt address {}", addr);
            let self_clone = Arc::clone(self);
            self.spawn_task(format!("dial of learnt address {addr}"), async move {
                if let Err(e) = self_clone.connect_to_peer(addr).await {
                    debug!("Failed to connect to learnt address {}: {}", addr, e);
                }
            });
        }
    }

    /// Dial the `-seednode` peers not reached yet, each as a one-shot peer;
    /// one that cannot be reached is tried again on the next pass
    fn dial_one_shots(self: &Arc<Self>) {
        let pending: Vec<String> = self.one_shots.lock().drain(..).collect();
        for dest in pending {
            let self_clone = Arc::clone(self);
            self.spawn_task(format!("dial of one-shot peer {dest}"), async move {
                let reached = match self_clone.resolve(&dest).await {
                    Some(addr) => {
                        self_clone.claim_dial(addr, DialRule::ByName)
                            && Arc::clone(&self_clone)
                                .connect_peer(addr, true)
                                .await
                                .is_ok()
                    }
                    None => false,
                };
                if !reached {
                    debug!("-seednode {} not reached; trying again later", dest);
                    self_clone.one_shots.lock().push_back(dest);
                }
            });
        }
    }

    /// `ip:port`, `ip` (the network's port) or a name to look up (not
    /// through a proxy, which would see the lookup)
    async fn resolve(&self, dest: &str) -> Option<SocketAddr> {
        if let Ok(addr) = dest.parse::<SocketAddr>() {
            return Some(addr);
        }
        if let Ok(ip) = dest.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, self.config.default_port));
        }
        if self.config.proxy.is_some() {
            return None;
        }
        let with_port = if dest.contains(':') {
            dest.to_string()
        } else {
            format!("{}:{}", dest, self.config.default_port)
        };
        // Raced against the stop, as the seed lookup
        let resolver = self.name_resolver.read().clone();
        let lookup = async {
            match resolver {
                Some(resolve) => resolve(with_port).await,
                None => tokio::net::lookup_host(with_port)
                    .await
                    .map(|a| a.collect()),
            }
        };
        self.until_stop(lookup).await?.ok()?.into_iter().next()
    }

    /// The network magic of this peer manager's network
    pub fn magic(&self) -> crate::constants::Magic {
        self.config.magic
    }

    /// Get a reference to peer scoring
    pub fn scoring(&self) -> &PeerScoring {
        &self.scoring
    }

    /// Report misbehavior for a peer
    pub fn report_misbehavior(&self, peer_id: PeerId, reason: Misbehavior) {
        if self.scoring.record_misbehavior(peer_id, reason) {
            // Peer was banned, disconnect them
            self.disconnect(peer_id);
        }
    }

    /// Divi Core's `Misbehaving`: add a misbehaviour score to a peer (0 does
    /// nothing); a peer reaching the ban threshold is disconnected and,
    /// unless local, banned for the ban time
    pub fn report_misbehavior_score(
        &self,
        peer_id: PeerId,
        score: u32,
        cause: &str,
    ) -> MisbehaviourOutcome {
        let ip = self.scoring.get_stats(peer_id).map(|s| s.ip);
        let outcome = self.scoring.record_misbehavior_score(
            peer_id,
            score.min(i32::MAX as u32) as i32,
            cause,
        );
        match (outcome, ip) {
            // Every connection from the banned address goes
            (MisbehaviourOutcome::Banned, Some(ip)) => self.disconnect_ip(ip),
            (MisbehaviourOutcome::Scored, _) => {}
            _ => self.disconnect(peer_id),
        }
        outcome
    }

    /// Divi Core bans a peer whose protocol version is too old
    /// (`PeerBanningService::Ban` after `DisconnectOldProtocol`), local or not
    fn ban_obsolete(&self, ip: std::net::IpAddr, error: &NetworkError) {
        if let NetworkError::VersionMismatch { peer, required } = error {
            let (_, duration) = self.scoring.ban_policy();
            self.ban_ip(
                ip,
                duration,
                format!("obsolete version {} (need {})", peer, required),
            );
        }
    }

    /// Check if an IP is banned
    pub fn is_banned(&self, ip: &std::net::IpAddr) -> bool {
        self.scoring.is_banned(ip)
    }

    /// Ban an IP address
    pub fn ban_ip(&self, ip: std::net::IpAddr, duration: Duration, reason: impl Into<String>) {
        self.scoring.ban_ip(ip, duration, reason);
        self.disconnect_ip(ip);
    }

    /// Disconnect every peer connected from `ip`
    fn disconnect_ip(&self, ip: std::net::IpAddr) {
        let peers_to_disconnect: Vec<_> = self
            .peers
            .read()
            .iter()
            .filter(|(_, handle)| {
                if let std::net::SocketAddr::V4(addr) = handle.addr {
                    std::net::IpAddr::V4(*addr.ip()) == ip
                } else if let std::net::SocketAddr::V6(addr) = handle.addr {
                    std::net::IpAddr::V6(*addr.ip()) == ip
                } else {
                    false
                }
            })
            .map(|(id, _)| *id)
            .collect();

        for peer_id in peers_to_disconnect {
            self.disconnect(peer_id);
        }
    }

    /// Unban an IP address
    pub fn unban_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.scoring.unban_ip(ip)
    }

    /// Get retry delay for connecting to an address
    pub fn retry_delay(&self, addr: SocketAddr) -> Duration {
        self.scoring.retry_delay(addr.ip())
    }

    /// Subscribe to peer events
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.event_tx.subscribe()
    }

    /// Get shutdown signal receiver
    pub fn shutdown_signal(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Update our best block height
    pub fn set_height(&self, height: u32) {
        *self.our_height.write() = height;
    }

    /// Read the height for version messages from `source` from now on, as
    /// Divi Core reads its chain height in each PushVersion (Node.cpp:994)
    pub fn set_height_source(&self, source: HeightSource) {
        *self.height_source.write() = Some(source);
    }

    /// Read the spork count an inbound peer is told from `source`
    pub fn set_spork_count_source(&self, source: HeightSource) {
        *self.spork_count_source.write() = Some(source);
    }

    /// The height a new version message names
    fn current_height(&self) -> u32 {
        match self.height_source.read().as_ref() {
            Some(source) => source(),
            None => *self.our_height.read(),
        }
    }

    /// Set the service bits we advertise to peers. A node that has pruned
    /// block bodies must clear `NODE_NETWORK` and set `NODE_NETWORK_LIMITED`.
    pub fn set_services(&self, services: u64) {
        self.our_services.store(services, Ordering::Relaxed);
    }

    /// Set the node's own addresses, before any connection starts
    pub fn set_local_addresses(&self, local: crate::local::LocalAddresses) {
        *self.local_addresses.write() = Arc::new(local);
    }

    /// The node's own addresses
    pub fn local_addresses(&self) -> Arc<crate::local::LocalAddresses> {
        Arc::clone(&self.local_addresses.read())
    }

    /// Service bits we currently advertise
    pub fn services(&self) -> u64 {
        self.our_services.load(Ordering::Relaxed)
    }

    /// Connected peers that advertise `NODE_NETWORK`, i.e. keep every block
    pub fn full_history_peers(&self) -> Vec<PeerId> {
        self.peers
            .read()
            .iter()
            .filter(|(_, p)| {
                p.stats.services.load(Ordering::Relaxed) & crate::constants::services::NODE_NETWORK
                    != 0
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get current peer count
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Get list of connected peer addresses
    pub fn peer_addresses(&self) -> Vec<SocketAddr> {
        self.peers.read().values().map(|p| p.addr).collect()
    }

    /// Get list of connected peer IDs
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.read().keys().copied().collect()
    }

    /// Peer IDs of all connected peers whose remote IP equals `ip` (any port)
    pub fn peer_ids_for_ip(&self, ip: std::net::IpAddr) -> Vec<PeerId> {
        self.peers
            .read()
            .iter()
            .filter(|(_, p)| p.addr.ip() == ip)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Peer ID of the connected peer with exactly this socket address
    pub fn peer_id_for_addr(&self, addr: &SocketAddr) -> Option<PeerId> {
        self.peers
            .read()
            .iter()
            .find(|(_, p)| &p.addr == addr)
            .map(|(id, _)| *id)
    }

    /// Check if a specific peer is currently connected
    pub fn is_peer_connected(&self, peer_id: PeerId) -> bool {
        self.peers.read().contains_key(&peer_id)
    }

    /// The address of a connected peer
    pub fn peer_addr(&self, peer_id: PeerId) -> Option<SocketAddr> {
        self.peers.read().get(&peer_id).map(|p| p.addr)
    }

    /// A connected peer's live stats, with its bloom filter
    pub fn peer_stats(&self, peer_id: PeerId) -> Option<Arc<crate::peer::LivePeerStats>> {
        self.peers
            .read()
            .get(&peer_id)
            .map(|p| Arc::clone(&p.stats))
    }

    /// Whether a connected peer dialled us
    pub fn is_inbound(&self, peer_id: PeerId) -> bool {
        self.peers.read().get(&peer_id).is_some_and(|p| p.inbound)
    }

    /// Get peer info for RPC (address and inbound status)
    pub fn get_peer_info(&self) -> Vec<(SocketAddr, bool)> {
        self.peers
            .read()
            .values()
            .map(|p| (p.addr, p.inbound))
            .collect()
    }

    /// Get detailed peer info for RPC: (id, addr, inbound, live stats, ban score)
    pub fn get_peer_details(
        &self,
    ) -> Vec<(
        PeerId,
        SocketAddr,
        bool,
        Arc<crate::peer::LivePeerStats>,
        i64,
    )> {
        self.peers
            .read()
            .values()
            .map(|p| {
                let ban = self
                    .scoring
                    .get_stats(p.id)
                    .map(|s| s.misbehavior_score as i64)
                    .unwrap_or(0);
                (p.id, p.addr, p.inbound, p.stats.clone(), ban)
            })
            .collect()
    }

    /// Check if we have room for more outbound connections
    pub fn can_connect_outbound(&self) -> bool {
        let outbound_count = self.peers.read().values().filter(|p| !p.inbound).count();
        outbound_count < self.config.max_outbound
    }

    /// Get count of inbound connections
    pub fn inbound_count(&self) -> usize {
        self.peers.read().values().filter(|p| p.inbound).count()
    }

    /// Whether another inbound connection may be taken: fewer inbound peers,
    /// counting those still in their handshake, than `max_inbound`
    pub fn has_inbound_room(&self) -> bool {
        self.inbound_count() + self.inbound_handshaking.load(Ordering::SeqCst)
            < self.config.max_inbound
    }

    /// Get count of outbound connections
    pub fn outbound_count(&self) -> usize {
        self.peers.read().values().filter(|p| !p.inbound).count()
    }

    /// The network's P2P port, used for an address given without one
    pub fn default_port(&self) -> u16 {
        self.config.default_port
    }

    /// Add a node manually (via RPC addnode command)
    ///
    /// This adds the node to the list of nodes we should try to stay connected to.
    pub fn add_node(&self, addr: SocketAddr) -> bool {
        self.add_node_as(addr.to_string(), addr)
    }

    /// Add a node by the text it was given as: divid keeps the text and
    /// refuses only the same text again (net.cpp:1183-1206), so two texts of
    /// one address are two entries, dialled once
    pub fn add_node_as(&self, name: String, addr: SocketAddr) -> bool {
        let mut added = self.added_nodes.write();
        if added.iter().any(|(n, _)| *n == name) {
            return false; // Already added
        }
        info!("Added node: {}", name);
        added.push((name, addr));
        true
    }

    /// Remove the added node given as `name` (divid compares the text)
    pub fn remove_added_node_as(&self, name: &str) -> bool {
        let removed = {
            let mut added = self.added_nodes.write();
            let before = added.len();
            added.retain(|(n, _)| n != name);
            added.len() != before
        };
        if removed {
            info!("Removed node: {}", name);
        }
        removed
    }

    /// Remove a manually added node
    pub fn remove_added_node(&self, addr: &SocketAddr) -> bool {
        let removed = {
            let mut added = self.added_nodes.write();
            let before = added.len();
            added.retain(|(_, a)| a != addr);
            added.len() != before
        };
        if removed {
            info!("Removed node: {}", addr);
        }
        removed
    }

    /// Get info about added nodes
    pub fn get_added_node_info(&self) -> Vec<AddedNode> {
        let added = self.added_nodes.read();
        // the dialled set before the peers, as claim_dial takes them
        let connecting = self.connecting_addrs.read();
        let peers = self.peers.read();

        let connected_addrs: HashSet<_> = peers.values().map(|p| p.addr).collect();

        added
            .iter()
            .map(|(name, addr)| AddedNode {
                name: name.clone(),
                addr: *addr,
                connected: connected_addrs.contains(addr),
                connecting: connecting.contains(addr),
            })
            .collect()
    }

    /// Check if an address is a manually added node
    pub fn is_added_node(&self, addr: &SocketAddr) -> bool {
        self.added_nodes.read().iter().any(|(_, a)| a == addr)
    }

    /// The addresses to listen on, each with whether its peers are
    /// whitelisted: the listen address, the other -bind addresses, and each
    /// -whitebind address, whose peers are (net.cpp:1808-1823)
    fn listen_addresses(&self) -> Vec<(SocketAddr, bool)> {
        self.config
            .listen_addr
            .iter()
            .chain(self.config.more_listen.iter())
            .map(|a| (*a, false))
            .chain(self.config.white_listen.iter().map(|a| (*a, true)))
            .collect()
    }

    /// Bind the listeners before the node starts: the listen address and each
    /// -whitebind address. As Divi Core, an address that cannot be bound is
    /// reported ("Unable to bind to ... on this computer", net.cpp:1355-1365,
    /// reported by Bind, net.cpp:1638-1649), and the node does not start when
    /// none could be bound ("Failed to listen on any port. Use -listen=0 if
    /// you want this.", net.cpp:1829-1831). Before, a listener that could not
    /// bind only logged it, and the node ran on without listening.
    pub async fn bind_listeners(&self) -> Result<(), String> {
        // A node started again after a stop takes and dials peers again
        self.stopping.store(false, Ordering::SeqCst);
        let wanted = self.listen_addresses();
        let mut bound = Vec::new();
        let mut failures = Vec::new();
        for (addr, white) in wanted.iter().copied() {
            match TcpListener::bind(addr).await {
                Ok(listener) => bound.push((addr, white, listener)),
                Err(e) => {
                    let why = if e.kind() == std::io::ErrorKind::AddrInUse {
                        "Divi Core or irondivid is probably already running.".to_string()
                    } else {
                        format!("(bind returned error {e})")
                    };
                    let msg = format!("Unable to bind to {addr} on this computer. {why}");
                    error!("{}", msg);
                    failures.push(msg);
                }
            }
        }
        if !wanted.is_empty() && bound.is_empty() {
            return Err(format!(
                "{} Failed to listen on any port. Use -listen=0 if you want this.",
                failures.join(" ")
            ));
        }
        *self.prebound.lock() = Some(bound);
        Ok(())
    }

    /// Start the peer manager
    pub async fn start(self: Arc<Self>) -> Result<(), NetworkError> {
        info!("Starting peer manager");

        // Start listeners for inbound connections
        let listeners = self.listen_addresses();
        // The sockets bind_listeners bound, when it ran; else bind each here
        let to_run: Vec<(SocketAddr, bool, Option<TcpListener>)> = match self.prebound.lock().take()
        {
            Some(bound) => bound
                .into_iter()
                .map(|(addr, white, listener)| (addr, white, Some(listener)))
                .collect(),
            None => listeners
                .into_iter()
                .map(|(addr, white)| (addr, white, None))
                .collect(),
        };
        let listener_handles: Vec<_> = to_run
            .into_iter()
            .map(|(listen_addr, white, bound)| {
                let self_clone = Arc::clone(&self);
                self.spawn_task(format!("listener on {listen_addr}"), async move {
                    if let Err(e) = self_clone.run_listener(listen_addr, white, bound).await {
                        error!("Listener error: {}", e);
                    }
                })
            })
            .collect();

        // -seednode peers, -connect or not (net.cpp:1096, :1112)
        self.dial_one_shots();

        // Connect to static peers first (they report accurate heights)
        let rule = self.static_rule();
        let static_handles: Vec<_> = self
            .config
            .static_peers
            .clone()
            .into_iter()
            .filter(|addr| self.can_connect_outbound() && self.claim_dial(*addr, rule))
            .map(|addr| {
                let self_clone = Arc::clone(&self);
                self.spawn_task(format!("dial of static peer {addr}"), async move {
                    if let Err(e) = self_clone.connect_to_peer(addr).await {
                        warn!(
                            "Failed to connect to static peer {}: {}",
                            crate::peer_log::address(addr),
                            e
                        );
                    }
                })
            })
            .collect();

        // Wait for static peer connections to complete before DNS discovery
        for handle in static_handles {
            let _ = handle.await;
        }
        self.dial_named();

        // Then addresses learnt from peers, then DNS seeds
        self.dial_learnt();
        if self.config.dns_seed {
            self.spawn_task(
                "DNS seed lookup".to_string(),
                Arc::clone(&self).seed_from_dns(),
            );
        } else {
            info!("DNS seeding disabled");
        }

        // Wait for the listeners (if started)
        for handle in listener_handles {
            let _ = handle.await;
        }

        Ok(())
    }

    /// SOCKS5 proxy used for outbound connections, if any
    pub fn proxy(&self) -> Option<crate::socks5::Proxy> {
        self.config.proxy
    }

    /// The onion network's proxy, if any (Divi Core GetProxy(NET_TOR))
    pub fn tor_proxy(&self) -> Option<crate::socks5::Proxy> {
        self.tor.read().0
    }

    /// Whether onion was made reachable (Divi Core vfReachable[NET_TOR])
    pub fn tor_reachable(&self) -> bool {
        self.tor.read().1
    }

    /// Set the onion network's proxy (Divi Core SetProxy(NET_TOR, ...))
    pub fn set_tor_proxy(&self, proxy: Option<crate::socks5::Proxy>) {
        self.tor.write().0 = proxy;
    }

    /// Mark onion reachable or not (Divi Core SetReachable(NET_TOR, ...))
    pub fn set_tor_reachable(&self, reachable: bool) {
        self.tor.write().1 = reachable;
    }

    /// The proxy a connection to `addr` goes through: Divi Core's GetProxy for
    /// the address's network: the onion proxy for an onion address, `-proxy`
    /// for another routable one, and none for an address that is not routable
    /// (ConnectSocket, netbase.cpp:620-629)
    fn proxy_for(&self, addr: &SocketAddr) -> Option<crate::socks5::Proxy> {
        if crate::local::is_onion(&addr.ip()) {
            self.tor_proxy()
        } else if crate::local::is_routable(&addr.ip()) {
            self.config.proxy
        } else {
            None
        }
    }

    /// Divi Core's DNS seed thread (net.cpp:1015-1060): the seeds are asked
    /// only when addresses are needed, that is with an empty address book,
    /// with -forcednsseed, or when fewer than two peers are connected 11 s
    /// after the start
    async fn seed_from_dns(self: Arc<Self>) {
        if !self.address_book.is_empty() && !self.config.force_dns_seed {
            // Divi Core's dnsseed thread sleeps interruptibly and is joined at
            // shutdown (net.cpp:1020-1022, divid.cpp:42-53): the wait ends when
            // the node stops, and then nothing is looked up. Subscribed before
            // the flag is read, so a stop is seen either way
            let mut shutdown = self.shutdown_tx.subscribe();
            if self.is_stopping() {
                return;
            }
            tokio::select! {
                _ = self.clock.sleep(DNS_SEED_DELAY) => {}
                _ = shutdown.recv() => return,
            }
            if self.is_stopping() {
                return;
            }
            if self.peer_count() >= 2 {
                info!("P2P peers available. Skipped DNS seeding.");
                return;
            }
        }
        info!("Loading addresses from DNS seeds (could take a while)");
        let found = Arc::clone(&self).discover_peers().await;
        info!("{} addresses found from DNS seeds", found);
    }

    /// Look up the DNS seeds: their addresses go into the address book and,
    /// unless -connect, are dialled into free outbound slots. How many were found.
    async fn discover_peers(self: Arc<Self>) -> usize {
        if self.config.dns_seeds.is_empty() {
            debug!("No DNS seeds configured; skipping DNS peer discovery");
            return 0;
        }
        if let Some(proxy) = self.config.proxy.map(|p| p.addr) {
            // A local lookup would reveal the node outside the proxy
            info!(
                "Proxy {} set: not resolving DNS seeds locally; using configured peers only",
                proxy
            );
            return 0;
        }
        let mut found = 0;

        for seed in &self.config.dns_seeds {
            if self.is_stopping() {
                break;
            }
            debug!("Resolving DNS seed: {}", seed);

            let name = format!("{}:{}", seed, self.config.default_port);
            let resolver = self.seed_resolver.read().clone();
            // Raced against the stop, so a resolver that hangs does not hold it;
            // an abandoned system lookup ends on its own thread and holds
            // nothing the node needs
            let lookup = async {
                match resolver {
                    Some(resolve) => resolve(name).await,
                    None => tokio::net::lookup_host(name).await.map(|a| a.collect()),
                }
            };
            let Some(resolved) = self.until_stop(lookup).await else {
                debug!("DNS seed {} not looked up: the node is stopping", seed);
                break;
            };
            // A lookup that returns once the node has begun to stop adds
            // nothing: Divi Core's dnsseed thread is interrupted and joined at
            // shutdown (divid.cpp:42-53)
            if self.is_stopping() {
                debug!("DNS seed {} answered after the stop began; not used", seed);
                break;
            }
            match resolved {
                Ok(addrs) => {
                    // Into the book, as divid adds what a seed gives (net.cpp ThreadDNSAddressSeed)
                    found += addrs.len();
                    self.address_book.add_seeds(&addrs);
                    let local = self.local_addresses();
                    for addr in addrs {
                        if self.config.connect_only {
                            break;
                        }
                        if self.can_connect_outbound() {
                            // A seed address dialled at once: as from the
                            // book, not in a network -onlynet left out
                            // (net.cpp:1164-1165)
                            if local.is_limited(&addr.ip())
                                || !self.claim_dial(addr, DialRule::Automatic)
                            {
                                continue;
                            }
                            info!("Discovered peer: {}", crate::peer_log::address(addr));
                            let self_clone = Arc::clone(&self);
                            self.spawn_task(format!("dial of seed address {addr}"), async move {
                                if let Err(e) = self_clone.connect_to_peer(addr).await {
                                    debug!("Failed to connect to discovered peer {}: {}", addr, e);
                                }
                            });
                        } else {
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }
        found
    }

    /// Run the inbound connection listener
    /// (`bound`: the socket bind_listeners bound for `addr`, else bind it now)
    async fn run_listener(
        self: Arc<Self>,
        addr: SocketAddr,
        white: bool,
        bound: Option<TcpListener>,
    ) -> Result<(), NetworkError> {
        // Subscribed before the stop flag is read, so a stop is seen either
        // way: by the flag, or by the signal sent after it. Nothing is bound
        // once the node has begun to stop
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        if self.is_stopping() {
            return Ok(());
        }
        let listener = match bound {
            Some(listener) => listener,
            None => TcpListener::bind(addr).await?,
        };
        info!("Listening for connections on {}", addr);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Listener shutting down");
                    break;
                }

                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            // Accepted as the node began to stop: not taken
                            if self.is_stopping() {
                                drop(stream);
                                break;
                            }
                            info!("Accepted connection from {}", crate::peer_log::address(peer_addr));

                            // Divi Core counts every inbound connection, handshake
                            // done or not, against -maxconnections less the outbound
                            // slots; outbound peers do not use them (net.cpp:744-759)
                            if !self.has_inbound_room() {
                                // divid's text, in its "net" debug category (net.cpp:757-759)
                                debug!("connection from {} dropped (full)", peer_addr);
                                continue;
                            }

                            self.inbound_handshaking.fetch_add(1, Ordering::SeqCst);
                            let self_clone = Arc::clone(&self);
                            self.spawn_task(format!("inbound connection from {peer_addr}"), async move {
                                let pm = Arc::clone(&self_clone);
                                if let Err(e) = self_clone.handle_inbound(stream, white).await {
                                    debug!("Inbound connection error from {}: {}", peer_addr, e);
                                }
                                pm.inbound_handshaking.fetch_sub(1, Ordering::SeqCst);
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// The rule for the configured static peers
    fn static_rule(&self) -> DialRule {
        if self.config.connect_only {
            DialRule::ByName
        } else {
            DialRule::ByAddress
        }
    }

    /// Whether Divi Core would dial `addr` now under `rule`. If so the address
    /// is marked as being dialled, so a second dial to it (or, by address, to
    /// its IP) is skipped until `connect_to_peer` has finished with it.
    pub fn claim_dial(&self, addr: SocketAddr, rule: DialRule) -> bool {
        self.claim_dial_with(addr, rule, || {})
    }

    /// `claim_dial`, with `between` run after the dialled set is locked and
    /// before the connected peers are read: the moment a dial that is just
    /// finishing could be missed. `connect_peer` stores the peer and only then
    /// removes the address from the dialled set, and the set stays locked here
    /// while the peers are read, so an address is always in one of the two (it
    /// was read from the peers first, which let a second dial in between)
    fn claim_dial_with(&self, addr: SocketAddr, rule: DialRule, between: impl FnOnce()) -> bool {
        let mut connecting = self.connecting_addrs.write();
        between();
        let peers: Vec<(SocketAddr, bool)> = self
            .peers
            .read()
            .values()
            .map(|p| (p.addr, p.inbound))
            .collect();
        let taken = match rule {
            DialRule::ByName => connecting.contains(&addr) || peers.iter().any(|(a, _)| *a == addr),
            DialRule::ByAddress | DialRule::Automatic => {
                connecting.iter().any(|a| a.ip() == addr.ip())
                    || peers.iter().any(|(a, _)| a.ip() == addr.ip())
            }
        };
        let group_taken = rule == DialRule::Automatic && {
            let group = net_group(addr.ip());
            connecting.iter().any(|a| net_group(a.ip()) == group)
                || peers
                    .iter()
                    .any(|(a, inbound)| !inbound && net_group(a.ip()) == group)
        };
        if taken || group_taken {
            debug!("Not dialling {} ({:?}): already connected", addr, rule);
            return false;
        }
        connecting.insert(addr);
        true
    }

    /// Whether a dial to `addr` is under way
    pub fn is_dialling(&self, addr: &SocketAddr) -> bool {
        self.connecting_addrs.read().contains(addr)
    }

    /// Dial `addr` once, now (RPC `addnode … onetry`)
    pub fn connect_once(self: &Arc<Self>, addr: SocketAddr) {
        if self.is_banned(&addr.ip()) || !self.claim_dial(addr, DialRule::ByName) {
            return;
        }
        let self_clone = Arc::clone(self);
        self.spawn_task(format!("dial of {addr}"), async move {
            if let Err(e) = self_clone.connect_to_peer(addr).await {
                debug!("Failed to connect to {}: {}", addr, e);
            }
        });
    }

    /// Connect to a specific peer
    pub async fn connect_to_peer(
        self: Arc<Self>,
        addr: SocketAddr,
    ) -> Result<PeerId, NetworkError> {
        self.connect_peer(addr, false).await
    }

    /// Connect to a peer; a one-shot peer is dropped after its addr
    async fn connect_peer(
        self: Arc<Self>,
        addr: SocketAddr,
        one_shot: bool,
    ) -> Result<PeerId, NetworkError> {
        // No peer is dialled once the node has begun to stop
        if self.is_stopping() {
            self.connecting_addrs.write().remove(&addr);
            return Err(NetworkError::ConnectionRefused(
                "the node is stopping".to_string(),
            ));
        }
        // Check if IP is banned
        if self.is_banned(&addr.ip()) {
            self.connecting_addrs.write().remove(&addr);
            return Err(NetworkError::ConnectionRefused(format!(
                "{} is banned",
                addr.ip()
            )));
        }

        // Mark address as connecting
        self.connecting_addrs.write().insert(addr);

        let our_height = self.current_height();

        // Raced against the stop, whatever -timeout gives the connect
        let connect = Connection::connect(
            addr,
            self.proxy_for(&addr),
            self.config.magic,
            our_height,
            self.services(),
            self.event_tx.clone(),
            self.shutdown_tx.subscribe(),
            self.bytes_sent_counter(),
            self.bytes_recv_counter(),
            Arc::clone(&self.local_nonces),
            self.local_addresses(),
        );
        let result = match self.until_stop(connect).await {
            Some(result) => {
                // Tried, in the address book, once the connect is made or has
                // failed, whatever dialled it; not when the proxy itself
                // could not be reached (ConnectNode, net.cpp:520-538)
                if !matches!(&result, Err(e) if crate::socks5::proxy_unreachable(e)) {
                    self.address_book.attempt(addr);
                }
                result
            }
            None => Err(NetworkError::ConnectionRefused(
                "the node is stopping".to_string(),
            )),
        };

        let (conn, handle) = match result {
            Ok((conn, handle)) => (
                conn.with_spork_count(self.spork_count_source.read().clone())
                    .with_clock(self.clock.clone()),
                handle,
            ),
            Err(e) => {
                self.connecting_addrs.write().remove(&addr);
                return Err(e);
            }
        };

        let peer_id = handle.id;

        // Register with scoring system
        self.scoring.register_peer(peer_id, addr.ip());
        self.scoring.reset_connection_failures(peer_id);

        // Store the handle, then stop counting the address as being dialled
        self.peers.write().insert(peer_id, handle);
        if one_shot {
            self.one_shot_peers.write().insert(peer_id);
        }
        self.connecting_addrs.write().remove(&addr);

        // Run the connection handler
        let self_clone = Arc::clone(&self);
        self.spawn_task(format!("connection to {addr}"), async move {
            if let Err(e) = conn.run().await {
                debug!("Connection to {} ended: {}", addr, e);
                self_clone.ban_obsolete(addr.ip(), &e);
            }
            // Remove peer on disconnect
            self_clone.peers.write().remove(&peer_id);
            self_clone.one_shot_peers.write().remove(&peer_id);
            self_clone.scoring.unregister_peer(peer_id);
        });

        Ok(peer_id)
    }

    /// Dial each named peer that is neither connected nor being dialled,
    /// through the proxy by name
    fn dial_named(self: &Arc<Self>) {
        let Some(proxy) = self.config.proxy else {
            return;
        };
        for (host, port) in self.config.named_peers.clone() {
            if !self.can_connect_outbound() {
                break;
            }
            let key = format!("{host}:{port}");
            let connected = self
                .named_connected
                .read()
                .get(&key)
                .is_some_and(|id| self.peers.read().contains_key(id));
            if connected || !self.named_dialling.write().insert(key.clone()) {
                continue;
            }
            let self_clone = Arc::clone(self);
            self.spawn_task(format!("dial of {host}:{port}"), async move {
                if let Err(e) = Arc::clone(&self_clone)
                    .connect_to_named(&host, port, proxy)
                    .await
                {
                    debug!(
                        "Failed to connect to {}:{} via the proxy: {}",
                        host, port, e
                    );
                }
                self_clone.named_dialling.write().remove(&key);
            });
        }
    }

    /// Dial `host:port` through `proxy` by name
    async fn connect_to_named(
        self: Arc<Self>,
        host: &str,
        port: u16,
        proxy: crate::socks5::Proxy,
    ) -> Result<PeerId, NetworkError> {
        // Raced against the stop, whatever -timeout gives the connect
        let connect = Connection::connect_named(
            host,
            port,
            proxy,
            self.config.magic,
            self.current_height(),
            self.services(),
            self.event_tx.clone(),
            self.shutdown_tx.subscribe(),
            self.bytes_sent_counter(),
            self.bytes_recv_counter(),
            Arc::clone(&self.local_nonces),
            self.local_addresses(),
        );
        let (conn, handle) = self
            .until_stop(connect)
            .await
            .ok_or_else(|| NetworkError::ConnectionRefused("the node is stopping".to_string()))??;
        let conn = conn.with_clock(self.clock.clone());
        let peer_id = handle.id;
        let addr = handle.addr;
        self.scoring.register_peer(peer_id, addr.ip());
        self.scoring.reset_connection_failures(peer_id);
        self.peers.write().insert(peer_id, handle);
        self.named_connected
            .write()
            .insert(format!("{host}:{port}"), peer_id);
        let self_clone = Arc::clone(&self);
        self.spawn_task(format!("connection to {addr}"), async move {
            if let Err(e) = conn.run().await {
                debug!("Connection to {} ended: {}", addr, e);
            }
            self_clone.peers.write().remove(&peer_id);
            self_clone.scoring.unregister_peer(peer_id);
        });
        Ok(peer_id)
    }

    /// Whether an inbound peer from `ip` is whitelisted: it came in on a
    /// -whitebind address or is in a -whitelist network (net.cpp:742)
    fn whitelisted_inbound(&self, ip: IpAddr, white_listener: bool) -> bool {
        white_listener || self.config.whitelist.iter().any(|n| n.contains(ip))
    }

    /// Whether a connected peer is whitelisted
    pub fn is_whitelisted(&self, peer_id: PeerId) -> bool {
        self.scoring
            .get_stats(peer_id)
            .is_some_and(|s| s.whitelisted)
    }

    /// Handle an inbound connection
    async fn handle_inbound(
        self: Arc<Self>,
        stream: tokio::net::TcpStream,
        white_listener: bool,
    ) -> Result<PeerId, NetworkError> {
        // Get peer address and check if banned; a whitelisted peer comes in
        // although its address is banned (net.cpp:760)
        let peer_addr = stream.peer_addr()?;
        let whitelisted = self.whitelisted_inbound(peer_addr.ip(), white_listener);
        if !whitelisted && self.is_banned(&peer_addr.ip()) {
            // divid's text (net.cpp:760-762)
            info!("connection from {} dropped (banned)", peer_addr);
            return Err(NetworkError::ConnectionRefused(format!(
                "{} is banned",
                peer_addr.ip()
            )));
        }

        let our_height = self.current_height();

        let (conn, handle) = Connection::accept(
            stream,
            self.config.magic,
            our_height,
            self.services(),
            self.event_tx.clone(),
            self.shutdown_tx.subscribe(),
            self.bytes_sent_counter(),
            self.bytes_recv_counter(),
            Arc::clone(&self.local_nonces),
            self.local_addresses(),
        )
        .await?;
        let conn = conn
            .with_spork_count(self.spork_count_source.read().clone())
            .with_clock(self.clock.clone());

        let peer_id = handle.id;
        let addr = handle.addr;

        // Register with scoring system
        self.scoring.register_peer(peer_id, addr.ip());
        if whitelisted {
            self.scoring.set_whitelisted(peer_id);
        }

        // Store the handle
        self.peers.write().insert(peer_id, handle);

        // Run the connection handler
        let self_clone = Arc::clone(&self);
        self.spawn_task(format!("inbound connection from {addr}"), async move {
            if let Err(e) = conn.run().await {
                debug!("Inbound connection ended: {}", e);
                self_clone.ban_obsolete(addr.ip(), &e);
            }
            // Remove peer on disconnect
            self_clone.peers.write().remove(&peer_id);
            self_clone.scoring.unregister_peer(peer_id);
        });

        Ok(peer_id)
    }

    /// Register a peer handle directly (tests capture its outbound messages).
    #[cfg(test)]
    pub(crate) fn insert_test_peer(&self, handle: PeerHandle) {
        self.peers.write().insert(handle.id, handle);
    }

    /// Drop a test peer, as a disconnect does
    #[cfg(test)]
    pub(crate) fn remove_test_peer(&self, id: PeerId) {
        self.peers.write().remove(&id);
    }

    /// The live stats of a test peer (tests set its services)
    #[cfg(test)]
    pub(crate) fn test_peer_stats(&self, id: PeerId) -> Option<Arc<crate::peer::LivePeerStats>> {
        self.peers.read().get(&id).map(|p| Arc::clone(&p.stats))
    }

    /// Send a message to a specific peer
    pub async fn send_to_peer(
        &self,
        peer_id: PeerId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        let handle = self.peers.read().get(&peer_id).cloned();

        if let Some(handle) = handle {
            handle
                .send(msg)
                .await
                .map_err(|_| NetworkError::Disconnected)?;
            Ok(())
        } else {
            Err(NetworkError::PeerNotFound(peer_id))
        }
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast(&self, msg: NetworkMessage) {
        let peers = self.peers.read();
        for (peer_id, handle) in peers.iter() {
            if let Err(e) = handle.try_send(msg.clone()) {
                debug!("Failed to broadcast to peer {}: {}", peer_id, e);
            }
        }
    }

    /// Queue a timed ping to every connected peer (the `ping` RPC); each pong updates
    /// that peer's pingtime
    pub fn ping_all(&self) {
        self.broadcast(NetworkMessage::Ping(0));
    }

    /// Relay a raw C++-format masternode broadcast (`mnb`) to all connected peers
    pub fn broadcast_masternode_broadcast(&self, bytes: Vec<u8>) {
        self.broadcast(NetworkMessage::MasternodeBroadcast(bytes));
    }

    /// Broadcast a block inv to all connected peers (standard Bitcoin inv/getdata protocol).
    ///
    /// Instead of pushing full block data, we announce the block hash via an `inv` message.
    /// Peers that don't have the block will respond with `getdata`, and we serve the full
    /// block in response. This matches the standard Bitcoin/Divi block announcement protocol.
    pub fn broadcast_block_inv(&self, block_hash: Hash256) {
        let inv_item = InvItem::new(InvType::Block, block_hash);
        let msg = NetworkMessage::Inv(vec![inv_item]);
        let peers = self.peers.read();
        let peer_count = peers.len();
        for (peer_id, handle) in peers.iter() {
            if let Err(e) = handle.try_send(msg.clone()) {
                debug!("Failed to send block inv to peer {}: {}", peer_id, e);
            }
        }
        info!("Broadcast block inv {} to {} peers", block_hash, peer_count);
    }

    /// Broadcast a block inv to all connected peers except the one specified.
    ///
    /// Used when relaying a block received from a peer to all other peers.
    pub fn broadcast_block_inv_except(&self, block_hash: Hash256, exclude: PeerId) {
        let inv_item = InvItem::new(InvType::Block, block_hash);
        let msg = NetworkMessage::Inv(vec![inv_item]);
        let peers = self.peers.read();
        let mut sent_count = 0;
        for (peer_id, handle) in peers.iter() {
            if *peer_id != exclude {
                if let Err(e) = handle.try_send(msg.clone()) {
                    debug!("Failed to send block inv to peer {}: {}", peer_id, e);
                } else {
                    sent_count += 1;
                }
            }
        }
        debug!(
            "Relayed block inv {} to {} peers (excluding {})",
            block_hash, sent_count, exclude
        );
    }

    /// The node took a message of `size` bytes from `peer_id`: that peer may
    /// be read again once it is within the receive limits
    pub fn message_taken(&self, peer_id: PeerId, size: u64) {
        if let Some(handle) = self.peers.read().get(&peer_id) {
            handle.stats.message_taken(size);
        }
    }

    /// Bytes queued for `peer_id` and not yet written; None for no such peer
    pub fn send_queued(&self, peer_id: PeerId) -> Option<u64> {
        self.peers
            .read()
            .get(&peer_id)
            .map(|h| h.stats.send_queued_bytes.load(Ordering::Relaxed))
    }

    /// Queue a message for `peer_id` without waiting
    pub fn try_send_to_peer(&self, peer_id: PeerId, msg: NetworkMessage) -> TrySend {
        let Some(handle) = self.peers.read().get(&peer_id).cloned() else {
            return TrySend::Gone;
        };
        match handle.try_send(msg) {
            Ok(()) => TrySend::Sent,
            Err(e) if matches!(*e, tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                TrySend::Full
            }
            Err(_) => TrySend::Gone,
        }
    }

    /// The node missed messages it cannot count: every peer may be read again
    pub fn clear_receive_queues(&self) {
        for handle in self.peers.read().values() {
            handle.stats.clear_queued();
        }
    }

    /// Broadcast a message to all peers except one
    pub fn broadcast_except(&self, msg: NetworkMessage, exclude: PeerId) {
        let peers = self.peers.read();
        for (peer_id, handle) in peers.iter() {
            if *peer_id != exclude {
                if let Err(e) = handle.try_send(msg.clone()) {
                    debug!("Failed to broadcast to peer {}: {}", peer_id, e);
                }
            }
        }
    }

    /// Disconnect a peer
    pub fn disconnect(&self, peer_id: PeerId) {
        if self.peers.write().remove(&peer_id).is_some() {
            debug!("Disconnected peer {}", peer_id);
        }
    }

    /// The node has begun to stop: from now on no peer is accepted, dialled
    /// or looked up, and the listeners, the open connections and the seed
    /// lookup end, as Divi Core interrupts and joins its net threads before
    /// the rest of its shutdown (divid.cpp:42-53, net.cpp:1440-1470)
    pub fn stop_network(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        // A socket bound for a listener that has not started yet closes now
        self.prebound.lock().take();
        let _ = self.shutdown_tx.send(());
    }

    /// Spawn one of the peer tasks, under `name`, tracked so a stop waits for it
    fn spawn_task<F>(&self, name: String, task: F) -> tokio::task::JoinHandle<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let id = self.next_task.fetch_add(1, Ordering::Relaxed);
        self.running.lock().insert(id, name);
        let done = TaskDone(Arc::clone(&self.running), id);
        self.tasks.spawn(async move {
            let _done = done;
            task.await;
        })
    }

    /// Wait, `bound` at most, until every peer task has ended, as Divi Core's
    /// shutdown waits for its net threads (join_all, divid.cpp:42-53). The
    /// names of those still running at the bound, sorted; none when all ended
    pub async fn join_tasks(&self, bound: Duration) -> Vec<String> {
        self.tasks.close();
        let ended = tokio::time::timeout(bound, self.tasks.wait()).await.is_ok();
        // A node started again spawns its tasks anew
        self.tasks.reopen();
        if ended {
            return Vec::new();
        }
        let mut left: Vec<String> = self.running.lock().values().cloned().collect();
        left.sort();
        left
    }

    /// `work` until it ends, or None once the node has begun to stop: Divi
    /// Core interrupts its net threads at shutdown (divid.cpp:42-53), and
    /// irondivid ends where they would wait on (a lookup, a connect, a write).
    /// Subscribed before the flag is read, so a stop is seen either way
    async fn until_stop<T>(&self, work: impl std::future::Future<Output = T>) -> Option<T> {
        let mut stop = self.shutdown_tx.subscribe();
        if self.is_stopping() {
            return None;
        }
        tokio::select! {
            out = work => Some(out),
            _ = stop.recv() => None,
        }
    }

    /// Look DNS seeds up with `resolver` instead of the system resolver, so a
    /// test controls what a seed gives and when
    pub fn set_seed_resolver(&self, resolver: SeedResolver) {
        *self.seed_resolver.write() = Some(resolver);
    }

    /// Look -seednode names up with `resolver` instead of the system
    /// resolver, so a test controls what a name gives and when
    pub fn set_name_resolver(&self, resolver: SeedResolver) {
        *self.name_resolver.write() = Some(resolver);
    }

    /// Whether the node has begun to stop (see [`Self::stop_network`])
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Disconnect all peers
    pub fn disconnect_all(&self) {
        let _ = self.shutdown_tx.send(());
        self.peers.write().clear();
    }

    /// Get network traffic totals across all peers
    ///
    /// Returns (total_bytes_sent, total_bytes_received)
    pub fn get_net_totals(&self) -> (u64, u64) {
        let sent = self.total_bytes_sent.load(Ordering::Relaxed);
        let recv = self.total_bytes_recv.load(Ordering::Relaxed);
        (sent, recv)
    }

    /// Get reference to total bytes sent counter (for Connection to update)
    pub(crate) fn bytes_sent_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.total_bytes_sent)
    }

    /// Get reference to total bytes received counter (for Connection to update)
    pub(crate) fn bytes_recv_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.total_bytes_recv)
    }

    /// Get set of currently connected peer addresses
    pub fn connected_addresses(&self) -> HashSet<SocketAddr> {
        self.peers.read().values().map(|p| p.addr).collect()
    }

    /// Compute exponential backoff duration for a given consecutive failure count.
    ///
    /// Starts at 30 seconds, doubles each failure, capped at 30 minutes.
    /// Peers that have failed 5+ times will be skipped for at least 16 minutes.
    fn backoff_duration(failures: u32) -> Duration {
        // base = 30s, cap = 30 min
        let base_secs = 30u64;
        let max_secs = 30 * 60u64; // 30 minutes
        let multiplier = 2u64.saturating_pow(failures.saturating_sub(1).min(10));
        Duration::from_secs((base_secs.saturating_mul(multiplier)).min(max_secs))
    }

    /// Check whether a static peer is ready to retry based on its backoff state.
    ///
    /// Returns `true` if we should attempt a connection (i.e., enough time has passed).
    fn peer_backoff_ready(&self, addr: SocketAddr) -> bool {
        let backoff = self.static_peer_backoff.read();
        match backoff.get(&addr) {
            None => true, // Never attempted — go ahead
            Some((failures, last_attempt)) => {
                if *failures == 0 {
                    return true;
                }
                self.clock.now().saturating_duration_since(*last_attempt)
                    >= Self::backoff_duration(*failures)
            }
        }
    }

    /// Record a static-peer connection failure, incrementing its backoff counter.
    fn record_static_peer_failure(&self, addr: SocketAddr) {
        let mut backoff = self.static_peer_backoff.write();
        let now = self.clock.now();
        let entry = backoff.entry(addr).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        let delay = Self::backoff_duration(entry.0);
        debug!(
            "Static peer {} failure #{} — next retry in {:.0}s",
            addr,
            entry.0,
            delay.as_secs_f64()
        );
    }

    /// Record a successful connection to a static peer, resetting its backoff.
    fn record_static_peer_success(&self, addr: SocketAddr) {
        self.static_peer_backoff.write().remove(&addr);
    }

    /// The `-connect` peers dialled again and again, as Divi Core's
    /// ThreadOpenConnections does with -connect (net.cpp:1094-1105): each
    /// address in turn, then a pause of 500 ms per earlier round (at most ten)
    /// after each and 500 ms at the end of the round, for as long as the node
    /// runs. A peer that is connected or being dialled is skipped, as
    /// OpenNetworkConnection skips a name it has (net.cpp:FindNode); there is
    /// no backoff, ban check or outbound limit for these, as there is none in
    /// Core for a named connection. Without -connect it returns at once.
    pub async fn run_connect_loop(self: Arc<Self>) {
        if !self.config.connect_only || self.config.static_peers.is_empty() {
            return;
        }
        let pause = Duration::from_millis(500);
        // earlier rounds, counted up to the cap of the pause
        let mut round = 0u32;
        loop {
            for addr in self.config.static_peers.clone() {
                if self.claim_dial(addr, DialRule::ByName) {
                    let self_clone = Arc::clone(&self);
                    self.spawn_task(format!("dial of -connect peer {addr}"), async move {
                        if let Err(e) = self_clone.connect_to_peer(addr).await {
                            debug!("Failed to connect to -connect peer {}: {}", addr, e);
                        }
                    });
                }
                for _ in 0..round {
                    self.clock.sleep(pause).await;
                }
            }
            self.clock.sleep(pause).await;
            round = (round + 1).min(10);
        }
    }

    /// The added nodes (-addnode, addnode add), dialled as Divi Core's
    /// added-node thread dials them (ThreadOpenAddedConnections,
    /// net.cpp:1239-1270): each one not connected, then 500 ms, and the
    /// round again two minutes later, for as long as the node runs, with no
    /// back-off. It runs beside the -connect loop and counts no outbound slot,
    /// whatever -maxconnections says, since Divi Core f8c0d2e67 took its
    /// semaphore grant out; a banned address is not dialled (net.cpp:1283)
    /// but has its 500 ms
    async fn run_added_loop(self: Arc<Self>) {
        let pause = Duration::from_millis(500);
        let round = Duration::from_secs(120);
        loop {
            // Each address once, however many texts name it
            let mut added: Vec<SocketAddr> = Vec::new();
            for (_, addr) in self.added_nodes.read().iter() {
                if !added.contains(addr) {
                    added.push(*addr);
                }
            }
            for addr in added {
                // A connected node is not in divid's list for the round
                if self.peers.read().values().any(|p| p.addr == addr) {
                    continue;
                }
                if !self.is_banned(&addr.ip()) && self.claim_dial(addr, DialRule::ByAddress) {
                    info!(
                        "Reconnecting to added node: {}",
                        crate::peer_log::address(addr)
                    );
                    let self_clone = Arc::clone(&self);
                    self.spawn_task(format!("dial of added node {addr}"), async move {
                        if let Err(e) = self_clone.connect_to_peer(addr).await {
                            debug!("Failed to reconnect to added node {}: {}", addr, e);
                        }
                    });
                }
                self.clock.sleep(pause).await;
            }
            self.clock.sleep(round).await;
        }
    }

    /// Periodic maintenance: the added nodes on their own loop
    /// (`run_added_loop`), and every 30 seconds, if we've dropped below
    /// `max_outbound`, static peers (with exponential backoff for
    /// repeatedly-failing peers), then DNS seeds.
    ///
    /// Backoff schedule for static peers (consecutive failures → min wait before retry):
    ///   1 failure  → 30 s
    ///   2 failures → 1 min
    ///   3 failures → 2 min
    ///   4 failures → 4 min
    ///   5 failures → 8 min
    ///   6 failures → 16 min
    ///   7+ failures → 30 min (cap)
    pub async fn run_maintenance(self: Arc<Self>) {
        tokio::join!(
            Arc::clone(&self).run_added_loop(),
            self.run_outbound_maintenance()
        );
    }

    /// The 30-second pass of `run_maintenance`
    async fn run_outbound_maintenance(self: Arc<Self>) {
        let mut interval = self.clock.interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            self.dial_one_shots();

            let outbound = self.outbound_count();
            let target = self.config.max_outbound;

            if outbound >= target {
                continue;
            }

            info!(
                "Peer maintenance: {}/{} outbound peers, attempting reconnection",
                outbound, target
            );

            // 1. Try static peers (with exponential backoff for known-failing
            // peers); -connect peers have run_connect_loop instead
            if self.can_connect_outbound() && !self.config.connect_only {
                let static_peers = self.config.static_peers.clone();
                let rule = self.static_rule();
                for addr in static_peers {
                    if !self.can_connect_outbound() {
                        break;
                    }
                    if self.is_banned(&addr.ip()) {
                        continue;
                    }
                    if !self.peer_backoff_ready(addr) {
                        debug!("Skipping static peer {} (in backoff)", addr);
                        continue;
                    }
                    if !self.claim_dial(addr, rule) {
                        continue;
                    }
                    info!(
                        "Reconnecting to static peer: {}",
                        crate::peer_log::address(addr)
                    );
                    let self_clone = Arc::clone(&self);
                    self.spawn_task(format!("dial of static peer {addr}"), async move {
                        let self_for_record = Arc::clone(&self_clone);
                        match self_clone.connect_to_peer(addr).await {
                            Ok(_) => {
                                self_for_record.record_static_peer_success(addr);
                            }
                            Err(e) => {
                                debug!("Failed to reconnect to static peer {}: {}", addr, e);
                                self_for_record.record_static_peer_failure(addr);
                            }
                        }
                    });
                }
            }

            // 2. Peers named by host name, through the proxy
            self.dial_named();

            // 3. Addresses learnt from peers
            self.dial_learnt();

            // 4. Re-query DNS seeds as last resort
            if self.can_connect_outbound()
                && self.config.dns_seed
                && !self.config.connect_only
                && !self.config.dns_seeds.is_empty()
            {
                info!("Re-querying DNS seeds for peers");
                Arc::clone(&self).discover_peers().await;
            }
        }
    }
}

/// Create a peer manager with mainnet configuration
pub fn mainnet_peer_manager(listen_addr: Option<SocketAddr>) -> Arc<PeerManager> {
    let config = PeerManagerConfig {
        magic: crate::MAINNET_MAGIC,
        dns_seeds: vec!["autoseeds.diviseed.diviproject.org".to_string()],
        static_peers: vec![
            "178.62.195.16:51472".parse().unwrap(),
            "178.62.221.33:51472".parse().unwrap(),
            "178.128.251.20:51472".parse().unwrap(),
        ],
        listen_addr,
        ..Default::default()
    };
    PeerManager::new(config)
}

/// Create a peer manager with testnet configuration
pub fn testnet_peer_manager(listen_addr: Option<SocketAddr>) -> Arc<PeerManager> {
    let config = PeerManagerConfig {
        magic: crate::TESTNET_MAGIC,
        dns_seeds: vec!["autoseeds.tiviseed.diviproject.org".to_string()],
        listen_addr,
        default_port: 51474, // Testnet P2P port
        ..Default::default()
    };
    PeerManager::new(config)
}

/// Create a peer manager with regtest configuration
pub fn regtest_peer_manager(listen_addr: Option<SocketAddr>) -> Arc<PeerManager> {
    let config = PeerManagerConfig {
        magic: crate::REGTEST_MAGIC,
        dns_seeds: vec![],
        listen_addr,
        ..Default::default()
    };
    PeerManager::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_handle(addr: &str, inbound: bool) -> PeerHandle {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        PeerHandle {
            id: crate::peer::new_peer_id(),
            addr: addr.parse().unwrap(),
            tx,
            inbound,
            stats: Default::default(),
        }
    }

    /// A dial that finishes while a second is being claimed (connect_peer stores
    /// the peer, then drops the address from the dialled set) must not let the
    /// second through: Divi Core's OpenNetworkConnection finds the node with the
    /// name it dials (net.cpp, FindNode) and does not dial it twice. The node
    /// used to read the peers first and lock the dialled set after, so a dial
    /// that finished in between was in neither.
    #[test]
    fn claim_dial_sees_a_dial_that_finishes_meanwhile() {
        let pm = PeerManager::new(PeerManagerConfig {
            magic: crate::REGTEST_MAGIC,
            connect_only: true,
            dns_seeds: vec![],
            ..Default::default()
        });
        let addr = sa("127.0.0.1:51477");
        assert!(pm.claim_dial(addr, DialRule::ByName), "the first dial");
        let (started, go) = std::sync::mpsc::channel::<()>();
        let finisher = {
            let pm = Arc::clone(&pm);
            std::thread::spawn(move || {
                go.recv().unwrap();
                let handle = test_handle("127.0.0.1:51477", false);
                pm.peers.write().insert(handle.id, handle);
                pm.connecting_addrs.write().remove(&addr);
            })
        };
        // the first dial finishes inside the claim of the second
        let second = pm.claim_dial_with(addr, DialRule::ByName, || {
            started.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        finisher.join().unwrap();
        assert!(!second, "a second dial to the same peer got through");
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// The learnt addresses `dial_learnt` picks, under `-onlynet` `only`. Each
    /// dial goes through a proxy on a closed local port, so none leaves the
    /// machine; the picks are read before any dial task runs.
    fn learnt_dials(only: &[crate::local::Network]) -> HashSet<SocketAddr> {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let pm = PeerManager::new(PeerManagerConfig {
            magic: crate::REGTEST_MAGIC,
            dns_seeds: vec![],
            default_port: 51476,
            proxy: Some(crate::socks5::Proxy {
                addr: closed,
                randomize_credentials: true,
            }),
            ..Default::default()
        });
        let local = crate::local::LocalAddresses::new(true, true, 51476);
        local.limit_to(only);
        pm.set_local_addresses(local);
        pm.address_book
            .add_seeds(&[sa("1.2.3.4:51476"), sa("[2a00:1450:4001:80b::200e]:51476")]);
        pm.dial_learnt();
        let picked = pm.connecting_addrs.read().clone();
        picked
    }

    /// -onlynet: a learnt address of a network it leaves out is not dialled
    /// (net.cpp:1164-1165), one of a network it names is
    #[tokio::test]
    async fn onlynet_keeps_learnt_addresses_of_a_limited_network_from_being_dialled() {
        let (v4, v6) = (sa("1.2.3.4:51476"), sa("[2a00:1450:4001:80b::200e]:51476"));
        let picked = learnt_dials(&[crate::local::Network::Ipv6]);
        assert!(!picked.contains(&v4), "{picked:?}");
        assert!(picked.contains(&v6), "{picked:?}");
        // Without -onlynet both are dialled
        let picked = learnt_dials(&[]);
        assert!(picked.contains(&v4) && picked.contains(&v6), "{picked:?}");
    }

    #[test]
    fn dial_rules_follow_divi_core() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        pm.insert_test_peer(test_handle("127.0.0.3:40000", true));
        pm.insert_test_peer(test_handle("8.8.1.1:51472", false));

        // By address: any peer from the IP, inbound or outbound, blocks the dial
        assert!(!pm.claim_dial(sa("127.0.0.3:51472"), DialRule::ByAddress));
        assert!(!pm.claim_dial(sa("8.8.1.1:51473"), DialRule::ByAddress));
        assert!(pm.claim_dial(sa("8.8.2.2:51472"), DialRule::ByAddress));
        // A dial in progress blocks its IP too
        assert!(!pm.claim_dial(sa("8.8.2.2:51473"), DialRule::ByAddress));

        // By name: only the exact address and port
        assert!(pm.claim_dial(sa("127.0.0.3:51472"), DialRule::ByName));
        assert!(!pm.claim_dial(sa("127.0.0.3:51472"), DialRule::ByName));
        assert!(!pm.claim_dial(sa("127.0.0.3:40000"), DialRule::ByName));

        // Automatic: one outbound peer per /16; inbound peers do not take the group
        assert!(!pm.claim_dial(sa("8.8.9.9:51472"), DialRule::Automatic));
        assert!(pm.claim_dial(sa("9.9.9.9:51472"), DialRule::Automatic));
        pm.insert_test_peer(test_handle("5.5.1.1:40000", true));
        assert!(pm.claim_dial(sa("5.5.2.2:51472"), DialRule::Automatic));
    }

    #[test]
    fn net_groups_are_divi_core_s() {
        assert_eq!(net_group("1.2.3.4".parse().unwrap()), vec![4, 1, 2]);
        assert_eq!(
            net_group("1.2.3.4".parse().unwrap()),
            net_group("::ffff:1.2.200.1".parse().unwrap())
        );
        assert_ne!(
            net_group("1.2.3.4".parse().unwrap()),
            net_group("1.3.3.4".parse().unwrap())
        );
        assert_eq!(
            net_group("127.0.0.1".parse().unwrap()),
            net_group("::1".parse().unwrap())
        );
        assert_eq!(
            net_group("10.0.0.1".parse().unwrap()),
            net_group("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            net_group("2001:470:1:2::1".parse().unwrap()),
            net_group("2001:470:ffff::1".parse().unwrap())
        );
    }

    #[test]
    fn test_peer_manager_creation() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert_eq!(pm.peer_count(), 0);
    }

    #[test]
    fn test_mainnet_config() {
        let pm = mainnet_peer_manager(None);
        assert_eq!(pm.config.magic, crate::MAINNET_MAGIC);
    }

    #[test]
    fn test_testnet_config() {
        let pm = testnet_peer_manager(None);
        assert_eq!(pm.config.magic, crate::TESTNET_MAGIC);
    }

    /// Log sink for `tracing` output in one test.
    #[derive(Clone, Default)]
    struct LogBuf(Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_no_dns_discovery_log_when_seed_list_empty() {
        let buf = LogBuf::default();
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        // current-thread runtime: the default subscriber covers the awaited call
        let _guard = tracing::subscriber::set_default(subscriber);

        let pm = regtest_peer_manager(None);
        assert!(pm.config.dns_seeds.is_empty());
        Arc::clone(&pm).discover_peers().await;
        tracing::info!("log capture marker");

        let logs = String::from_utf8(buf.0.lock().clone()).unwrap();
        assert!(
            logs.contains("log capture marker"),
            "capture not working: {:?}",
            logs
        );
        assert!(
            !logs.contains("Discovering peers from DNS seeds"),
            "empty seed list still logged discovery: {:?}",
            logs
        );
    }

    /// The log of `f` run on a current-thread runtime
    async fn logs_of<F: std::future::Future<Output = ()>>(f: F) -> String {
        let buf = LogBuf::default();
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        f.await;
        let logs = String::from_utf8(buf.0.lock().clone()).unwrap();
        logs
    }

    /// Divi Core's DNS seed thread asks the seeds at once with an empty
    /// address book or -forcednsseed, and logs it in its words (net.cpp:1034, :1059)
    #[tokio::test]
    async fn dns_seeds_are_asked_at_once_with_an_empty_book_or_forced() {
        let pm = regtest_peer_manager(None);
        assert!(pm.address_book.is_empty());
        let logs = logs_of(Arc::clone(&pm).seed_from_dns()).await;
        assert!(
            logs.contains("Loading addresses from DNS seeds (could take a while)")
                && logs.contains("0 addresses found from DNS seeds"),
            "{logs}"
        );

        let forced = PeerManager::new(PeerManagerConfig {
            magic: crate::REGTEST_MAGIC,
            dns_seeds: vec![],
            force_dns_seed: true,
            ..Default::default()
        });
        let public = crate::message::NetAddr::from_ipv4([11, 2, 7, 9], 51476, 1);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        forced
            .address_book
            .add(&[(now, public)], "127.0.0.12".parse().unwrap());
        assert_eq!(forced.address_book.len(), 1);
        // No 11 s wait: well within the timeout
        let logs = logs_of(async {
            tokio::time::timeout(Duration::from_secs(5), Arc::clone(&forced).seed_from_dns())
                .await
                .expect("asked at once");
        })
        .await;
        assert!(logs.contains("Loading addresses from DNS seeds"), "{logs}");
    }

    #[test]
    fn test_regtest_config() {
        let pm = regtest_peer_manager(None);
        assert_eq!(pm.config.magic, crate::REGTEST_MAGIC);
        assert!(pm.config.dns_seeds.is_empty());
    }

    #[test]
    fn test_height_update() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        pm.set_height(12345);
        assert_eq!(*pm.our_height.read(), 12345);
    }

    /// Divi Core keeps its added nodes as a list, in the order they were
    /// added: the -addnode values first (net.cpp:1218), then addnode RPC
    /// calls (rpcnet.cpp:170-185); getaddednodeinfo lists them in that order
    #[test]
    fn added_nodes_keep_their_order() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addrs: Vec<SocketAddr> = (1..=10)
            .map(|i| format!("10.0.0.{}:51472", 11 - i).parse().unwrap())
            .collect();
        for a in &addrs {
            assert!(pm.add_node(*a));
        }
        let listed: Vec<SocketAddr> = pm.get_added_node_info().iter().map(|n| n.addr).collect();
        assert_eq!(listed, addrs);
        assert!(pm.remove_added_node(&addrs[4]));
        let listed: Vec<SocketAddr> = pm.get_added_node_info().iter().map(|n| n.addr).collect();
        let mut rest = addrs.clone();
        rest.remove(4);
        assert_eq!(listed, rest);
    }

    #[test]
    fn test_added_nodes() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addr: SocketAddr = "192.168.1.100:51472".parse().unwrap();

        // Initially no added nodes
        assert!(pm.get_added_node_info().is_empty());
        assert!(!pm.is_added_node(&addr));

        // Add a node
        assert!(pm.add_node(addr));
        assert!(pm.is_added_node(&addr));
        assert_eq!(pm.get_added_node_info().len(), 1);

        // Adding same node again returns false
        assert!(!pm.add_node(addr));
        assert_eq!(pm.get_added_node_info().len(), 1);

        // Remove the node
        assert!(pm.remove_added_node(&addr));
        assert!(!pm.is_added_node(&addr));
        assert!(pm.get_added_node_info().is_empty());

        // Removing non-existent node returns false
        assert!(!pm.remove_added_node(&addr));
    }

    #[test]
    fn test_connecting_status() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addr: SocketAddr = "192.168.1.100:51472".parse().unwrap();

        // Add a node
        pm.add_node(addr);

        // Initially not connecting (no connection attempt started)
        let info = pm.get_added_node_info();
        assert_eq!(info.len(), 1);
        assert!(!info[0].connected);
        assert!(!info[0].connecting);

        // Manually add to connecting_addrs to simulate connection in progress
        pm.connecting_addrs.write().insert(addr);

        // Now should show as connecting
        let info = pm.get_added_node_info();
        assert!(!info[0].connected);
        assert!(info[0].connecting);

        // Remove from connecting
        pm.connecting_addrs.write().remove(&addr);

        // Back to not connecting
        let info = pm.get_added_node_info();
        assert!(!info[0].connected);
        assert!(!info[0].connecting);
    }

    // ============================================================
    // MISSING TESTS: ban, score, peer counts, PrivateDivi configs
    // ============================================================

    #[test]
    fn test_ban_ip_and_check() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();

        // Initially not banned
        assert!(!pm.is_banned(&ip));

        // Ban the IP
        pm.ban_ip(ip, std::time::Duration::from_secs(3600), "test ban");

        // Now it should be banned
        assert!(pm.is_banned(&ip));
    }

    #[test]
    fn test_unban_ip() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let ip: std::net::IpAddr = "10.0.0.6".parse().unwrap();

        pm.ban_ip(ip, std::time::Duration::from_secs(3600), "test");
        assert!(pm.is_banned(&ip));

        pm.unban_ip(&ip);
        assert!(!pm.is_banned(&ip));
    }

    #[test]
    fn test_banned_ip_not_connected_peers() {
        // Banning an IP should not cause panic when no peers are connected
        let pm = PeerManager::new(PeerManagerConfig::default());
        let ip: std::net::IpAddr = "10.0.0.7".parse().unwrap();

        // Ban with no peers — should not panic
        pm.ban_ip(ip, std::time::Duration::from_secs(3600), "test");
        assert!(pm.is_banned(&ip));
        assert_eq!(pm.peer_count(), 0);
    }

    #[test]
    fn test_peer_count_starts_at_zero() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert_eq!(pm.peer_count(), 0);
        assert_eq!(pm.inbound_count(), 0);
        assert_eq!(pm.outbound_count(), 0);
    }

    #[test]
    fn test_can_connect_outbound_when_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.can_connect_outbound());
    }

    /// Divi Core's inbound limit (net.cpp:757): inbound peers only, so
    /// outbound peers never take an inbound slot
    #[test]
    fn inbound_room_counts_inbound_peers_only() {
        let pm = PeerManager::new(PeerManagerConfig {
            max_inbound: 1,
            ..PeerManagerConfig::default()
        });
        for i in 0..16 {
            pm.insert_test_peer(test_handle(&format!("10.0.{}.1:51476", i), false));
        }
        assert!(
            pm.has_inbound_room(),
            "outbound peers used the inbound slot"
        );
        pm.insert_test_peer(test_handle("10.1.0.1:40000", true));
        assert!(
            !pm.has_inbound_room(),
            "a second inbound peer would be taken"
        );

        let none = PeerManager::new(PeerManagerConfig {
            max_inbound: 0,
            ..PeerManagerConfig::default()
        });
        assert!(!none.has_inbound_room());
    }

    #[test]
    fn test_peer_addresses_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.peer_addresses().is_empty());
    }

    #[test]
    fn test_connected_peers_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.connected_peers().is_empty());
    }

    #[test]
    fn test_get_peer_info_empty() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        assert!(pm.get_peer_info().is_empty());
    }

    #[test]
    fn test_privatedivi_mainnet_peer_manager() {
        use crate::constants::PRIVATEDIVI_MAINNET_MAGIC;
        let config = PeerManagerConfig {
            magic: PRIVATEDIVI_MAINNET_MAGIC,
            ..Default::default()
        };
        let pm = PeerManager::new(config);
        assert_eq!(pm.config.magic, PRIVATEDIVI_MAINNET_MAGIC);
        assert_eq!(pm.config.magic, [0x70, 0xd2, 0x76, 0x11]);
    }

    #[test]
    fn test_privatedivi_testnet_peer_manager() {
        use crate::constants::PRIVATEDIVI_TESTNET_MAGIC;
        let config = PeerManagerConfig {
            magic: PRIVATEDIVI_TESTNET_MAGIC,
            default_port: 52474,
            ..Default::default()
        };
        let pm = PeerManager::new(config);
        assert_eq!(pm.config.magic, PRIVATEDIVI_TESTNET_MAGIC);
        assert_eq!(pm.config.magic, [0x70, 0xd1, 0x76, 0x12]);
        assert_eq!(pm.config.default_port, 52474);
    }

    #[test]
    fn test_add_multiple_nodes() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:51472".parse().unwrap(),
            "10.0.0.2:51472".parse().unwrap(),
            "10.0.0.3:51472".parse().unwrap(),
        ];

        for addr in &addrs {
            assert!(pm.add_node(*addr));
        }

        assert_eq!(pm.get_added_node_info().len(), 3);

        // All should be registered
        for addr in &addrs {
            assert!(pm.is_added_node(addr));
        }
    }

    /// An address in Divi Core's OnionCat range (fd87:d87e:eb43::/48): routable,
    /// and not reachable from the host without Tor
    fn onion_test_ip() -> std::net::IpAddr {
        "fd87:d87e:eb43:1:2:3:4:5".parse().unwrap()
    }

    fn local_only(listen_addr: Option<SocketAddr>, proxy: Option<SocketAddr>) -> PeerManagerConfig {
        PeerManagerConfig {
            magic: crate::REGTEST_MAGIC,
            dns_seeds: vec![],
            static_peers: vec![],
            listen_addr,
            proxy: proxy.map(|addr| crate::socks5::Proxy {
                addr,
                randomize_credentials: true,
            }),
            tor_proxy: proxy.map(|addr| crate::socks5::Proxy {
                addr,
                randomize_credentials: true,
            }),
            tor_reachable: proxy.is_some(),
            ..Default::default()
        }
    }

    /// With a proxy set, the outbound P2P connection to a routable peer goes
    /// through it (SOCKS5 CONNECT to the peer, with random credentials) and
    /// completes the handshake end to end. The client names an onion (OnionCat)
    /// address, routable to Divi Core and never dialled directly here; the stub
    /// opens the local server in its place, so nothing leaves the host.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_outbound_connection_goes_through_socks5_proxy() {
        // The listener is bound before start runs, so a port taken since free_port is
        // reported at once and another is tried
        let (server, listen) = {
            let mut found = None;
            for _ in 0..5 {
                let listen = SocketAddr::from(([127, 0, 0, 1], divi_test_support::free_port()));
                let server = PeerManager::new(local_only(Some(listen), None));
                if server.bind_listeners().await.is_ok() {
                    found = Some((server, listen));
                    break;
                }
            }
            found.expect("a listening port could be bound in 5 tries")
        };
        tokio::spawn(Arc::clone(&server).start());
        let (proxy, seen, greetings) = crate::socks5::stub::start_redirecting(listen).await;
        let client = PeerManager::new(local_only(None, Some(proxy)));
        assert_eq!(client.proxy().map(|p| p.addr), Some(proxy));
        let routable = SocketAddr::new(onion_test_ip(), listen.port());

        let mut connected = false;
        for _ in 0..50 {
            if Arc::clone(&client).connect_to_peer(routable).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected, "could not connect through the proxy");
        // Handshake done over the proxied stream: the server sees one inbound peer
        let mut inbound = 0;
        for _ in 0..50 {
            inbound = server.inbound_count();
            if inbound == 1 && client.outbound_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(inbound, 1);
        assert_eq!(client.outbound_count(), 1);
        // The onion address goes to the proxy as its .onion name
        let name = format!(
            "{}:{}",
            crate::local::onion_name(&routable.ip()).unwrap(),
            routable.port()
        );
        assert!(!seen.lock().is_empty() && seen.lock().iter().all(|t| *t == name));
        assert!(greetings.lock().iter().all(|(_, creds)| creds.is_some()));
        client.disconnect_all();
        server.disconnect_all();
    }

    /// A peer at an address that is not routable (127.0.0.1) is dialled
    /// directly even with a proxy set: Divi Core has no proxy for that network
    /// (netbase.cpp:620-629)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unroutable_peer_is_dialled_without_the_proxy() {
        let listen = SocketAddr::from(([127, 0, 0, 1], divi_test_support::free_port()));
        let server = PeerManager::new(local_only(Some(listen), None));
        tokio::spawn(Arc::clone(&server).start());
        let (proxy, seen, _) = crate::socks5::stub::start_recording().await;
        let client = PeerManager::new(local_only(None, Some(proxy)));
        let mut connected = false;
        for _ in 0..50 {
            if Arc::clone(&client).connect_to_peer(listen).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected, "could not connect directly");
        assert!(
            seen.lock().is_empty(),
            "went through the proxy: {:?}",
            seen.lock()
        );
        client.disconnect_all();
        server.disconnect_all();
    }

    /// A dead proxy must fail the connection, never fall back to connecting directly.
    #[tokio::test]
    async fn test_dead_proxy_does_not_fall_back_to_direct() {
        // A routable onion (OnionCat) target: a direct dial of it fails on the
        // host, so nothing leaves it even if the proxy were skipped
        let dead_proxy = SocketAddr::from(([127, 0, 0, 1], divi_test_support::free_port()));
        let client = PeerManager::new(local_only(None, Some(dead_proxy)));
        let routable = SocketAddr::new(onion_test_ip(), 51476);
        let err = Arc::clone(&client).connect_to_peer(routable).await;
        assert!(err.is_err());
        assert!(
            err.unwrap_err().to_string().contains("cannot reach proxy"),
            "did not try the proxy"
        );
    }

    #[test]
    fn test_net_totals_start_at_zero() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let (sent, recv) = pm.get_net_totals();
        assert_eq!(sent, 0);
        assert_eq!(recv, 0);
    }

    #[test]
    fn test_scoring_register_unregister() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let peer_id: crate::peer::PeerId = 999;
        let ip: std::net::IpAddr = "192.168.5.5".parse().unwrap();

        pm.scoring().register_peer(peer_id, ip);
        assert!(pm.scoring().get_stats(peer_id).is_some());

        pm.scoring().unregister_peer(peer_id);
        assert!(pm.scoring().get_stats(peer_id).is_none());
    }

    #[test]
    fn test_misbehavior_reporting_no_panic_without_peer() {
        // Reporting misbehavior for a non-registered peer should not panic
        let pm = PeerManager::new(PeerManagerConfig::default());
        let peer_id: crate::peer::PeerId = 42;
        pm.report_misbehavior(peer_id, crate::scoring::Misbehavior::InvalidMessage);
        // No panic = success
    }

    #[test]
    fn test_disconnect_nonexistent_peer_no_panic() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        // Disconnecting a non-existent peer should not panic
        pm.disconnect(9999);
    }

    #[test]
    fn test_retry_delay_fresh_ip() {
        let pm = PeerManager::new(PeerManagerConfig::default());
        let addr: SocketAddr = "10.0.0.9:51472".parse().unwrap();
        // Retry delay for a fresh IP should be 1 second (no failures)
        let delay = pm.retry_delay(addr);
        assert_eq!(delay, std::time::Duration::from_secs(1));
    }

    /// A -connect peer that is down is dialled again within seconds once it
    /// is up, as Divi Core's ThreadOpenConnections tries the -connect
    /// addresses again and again (net.cpp:1094-1105), with no backoff
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_peer_is_dialled_again_once_it_is_up() {
        // A bound socket that does not listen yet refuses connects and keeps its port
        // from every other process: the peer is "down" until listen() is called on it
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = socket.local_addr().unwrap();
        let pm = PeerManager::new(PeerManagerConfig {
            magic: crate::REGTEST_MAGIC,
            static_peers: vec![addr],
            connect_only: true,
            dns_seeds: vec![],
            ..Default::default()
        });
        // The peer is down at first: the first dials fail
        tokio::spawn(Arc::clone(&pm).run_connect_loop());
        tokio::time::sleep(Duration::from_secs(4)).await;
        let listener = socket.listen(16).unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(12), listener.accept()).await;
        assert!(
            accepted.is_ok(),
            "no dial within 12 s of the peer coming up"
        );
    }
}
