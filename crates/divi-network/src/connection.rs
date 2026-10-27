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

//! TCP connection handling and message framing
//!
//! Handles reading and writing network messages over TCP.
//! Uses tokio-util's FramedRead for cancellation-safe message reading.

use crate::codec::{Decoded, DiviCodec};
use crate::constants::{Magic, MAX_MESSAGE_SIZE, MIN_PEER_PROTO_VERSION};
use crate::error::NetworkError;
use crate::message::NetAddr;
use crate::peer::{
    new_peer_id, LivePeerStats, PeerDirection, PeerEvent, PeerHandle, PeerId, PeerInfo, PeerState,
};
use crate::version::VersionMessage;
use crate::{NetworkMessage, USER_AGENT};

use futures::StreamExt;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, trace, warn};

/// Timeout for connection establishment in milliseconds: Divi Core's
/// -timeout, default 5000 (net.cpp DEFAULT_CONNECT_TIMEOUT)
static CONNECT_TIMEOUT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(5000);

/// Set the connection timeout (Divi Core's -timeout, at least 1 ms)
pub fn set_connect_timeout_ms(ms: u64) {
    CONNECT_TIMEOUT_MS.store(ms.max(1), std::sync::atomic::Ordering::Relaxed);
}

/// The connection timeout in force
pub fn connect_timeout() -> Duration {
    Duration::from_millis(CONNECT_TIMEOUT_MS.load(std::sync::atomic::Ordering::Relaxed))
}

/// Divi Core CheckForInnactivity: a peer that has sent nothing, or been sent
/// nothing, this long after the connection opened is dropped (Node.cpp:819-822)
const FIRST_DATA_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for reading a message
const READ_TIMEOUT: Duration = Duration::from_secs(90);

/// Divi Core's PING_INTERVAL (Node.cpp:1045): a keepalive ping goes out this
/// long after the last ping was sent, when none is unanswered
const PING_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// Channel buffer size for outgoing messages
/// Messages that may wait for a peer's connection; what getdata answers put
/// there is bounded in bytes by -maxsendbuffer (crate::buffers)
const OUTBOUND_BUFFER: usize = 10_000;

/// Connection handler for a single peer
pub struct Connection {
    /// Peer ID
    peer_id: PeerId,
    /// TCP stream
    stream: TcpStream,
    /// Peer info
    info: PeerInfo,
    /// Network magic bytes
    magic: Magic,
    /// Our best block height
    our_height: u32,
    /// Service bits we advertise in our version message
    our_services: u64,
    /// Channel to receive messages to send
    outbound_rx: mpsc::Receiver<NetworkMessage>,
    /// Channel to send events
    event_tx: broadcast::Sender<PeerEvent>,
    /// Shutdown signal receiver
    shutdown_rx: broadcast::Receiver<()>,
    /// Global counter for total bytes sent (shared across all connections)
    total_bytes_sent: Arc<AtomicU64>,
    /// Global counter for total bytes received (shared across all connections)
    total_bytes_recv: Arc<AtomicU64>,
    /// Shared live stats for RPC
    stats: Arc<LivePeerStats>,
    /// Nonces of the version messages this node has sent (shared by its connections)
    local_nonces: LocalNonces,
    /// The nonce of our version message on this connection, removed when it ends
    sent_nonce: Option<NonceGuard>,
    /// The node's own addresses (our address in the version message)
    local: Arc<crate::local::LocalAddresses>,
    /// The node's active spork count, told to an inbound peer
    spork_count: Option<crate::peer_manager::HeightSource>,
}

/// Nonces in the version messages a node has sent on its open connections:
/// a version arriving with one of them comes from the node itself (Divi Core
/// `CNode::IsSelfConnection`)
pub type LocalNonces = Arc<parking_lot::Mutex<std::collections::HashSet<u64>>>;

/// Removes a sent nonce from the node's set when the connection ends
struct NonceGuard {
    nonces: LocalNonces,
    nonce: u64,
}

impl Drop for NonceGuard {
    fn drop(&mut self) {
        self.nonces.lock().remove(&self.nonce);
    }
}

impl Connection {
    /// Connect to a peer (outbound), through the SOCKS5 `proxy` when one is given
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        addr: SocketAddr,
        proxy: Option<crate::socks5::Proxy>,
        magic: Magic,
        our_height: u32,
        our_services: u64,
        event_tx: broadcast::Sender<PeerEvent>,
        shutdown_rx: broadcast::Receiver<()>,
        total_bytes_sent: Arc<AtomicU64>,
        total_bytes_recv: Arc<AtomicU64>,
        local_nonces: LocalNonces,
        local: Arc<crate::local::LocalAddresses>,
    ) -> Result<(Self, PeerHandle), NetworkError> {
        // Establish TCP connection with timeout; never fall back to a direct
        // connection when the proxy fails
        let stream = match proxy {
            Some(proxy) => {
                info!(
                    "Connecting to {} via proxy {}",
                    crate::peer_log::address(addr),
                    proxy.addr
                );
                timeout(connect_timeout(), crate::socks5::connect(proxy, addr))
                    .await
                    .map_err(|_| NetworkError::Timeout)??
            }
            None => {
                info!("Connecting to {}", crate::peer_log::address(addr));
                timeout(connect_timeout(), TcpStream::connect(addr))
                    .await
                    .map_err(|_| NetworkError::Timeout)?
                    .map_err(|e| NetworkError::Connection(e.to_string()))?
            }
        };

        Self::outbound(
            addr,
            stream,
            magic,
            our_height,
            our_services,
            event_tx,
            shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
            local_nonces,
            local,
        )
    }

    /// Connect to `host:port` through `proxy`, the proxy resolving `host` (Divi
    /// Core's ConnectSocketByName with a name proxy, netbase.cpp:631-660). The
    /// peer's address is 0.0.0.0:0, as divid has none for it.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_named(
        host: &str,
        port: u16,
        proxy: crate::socks5::Proxy,
        magic: Magic,
        our_height: u32,
        our_services: u64,
        event_tx: broadcast::Sender<PeerEvent>,
        shutdown_rx: broadcast::Receiver<()>,
        total_bytes_sent: Arc<AtomicU64>,
        total_bytes_recv: Arc<AtomicU64>,
        local_nonces: LocalNonces,
        local: Arc<crate::local::LocalAddresses>,
    ) -> Result<(Self, PeerHandle), NetworkError> {
        // A host name names the peer as an address would (-logips)
        let dest = if crate::peer_log::log_ips() {
            format!("{}:{}", host, port)
        } else {
            "a peer".to_string()
        };
        info!("Connecting to {} via proxy {}", dest, proxy.addr);
        let stream = timeout(
            connect_timeout(),
            crate::socks5::connect_to_name(proxy, host, port),
        )
        .await
        .map_err(|_| NetworkError::Timeout)??;
        Self::outbound(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            stream,
            magic,
            our_height,
            our_services,
            event_tx,
            shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
            local_nonces,
            local,
        )
    }

    /// The connection on an open outbound stream to `addr`
    #[allow(clippy::too_many_arguments)]
    fn outbound(
        addr: SocketAddr,
        stream: TcpStream,
        magic: Magic,
        our_height: u32,
        our_services: u64,
        event_tx: broadcast::Sender<PeerEvent>,
        shutdown_rx: broadcast::Receiver<()>,
        total_bytes_sent: Arc<AtomicU64>,
        total_bytes_recv: Arc<AtomicU64>,
        local_nonces: LocalNonces,
        local: Arc<crate::local::LocalAddresses>,
    ) -> Result<(Self, PeerHandle), NetworkError> {
        // Set TCP options
        stream.set_nodelay(true)?;

        let peer_id = new_peer_id();
        let info = PeerInfo::new_outbound(peer_id, addr);

        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        let stats = Arc::new(LivePeerStats::default());
        stats.sporks_wait.store(true, Ordering::Release);

        let handle = PeerHandle {
            id: peer_id,
            addr,
            tx: outbound_tx,
            inbound: false, // This is an outbound connection (we connected to them)
            stats: stats.clone(),
        };

        let conn = Connection {
            peer_id,
            stream,
            info,
            magic,
            our_height,
            our_services,
            outbound_rx,
            event_tx,
            shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
            stats,
            local_nonces,
            sent_nonce: None,
            local,
            spork_count: None,
        };

        Ok((conn, handle))
    }

    /// Accept an inbound connection
    #[allow(clippy::too_many_arguments)]
    pub async fn accept(
        stream: TcpStream,
        magic: Magic,
        our_height: u32,
        our_services: u64,
        event_tx: broadcast::Sender<PeerEvent>,
        shutdown_rx: broadcast::Receiver<()>,
        total_bytes_sent: Arc<AtomicU64>,
        total_bytes_recv: Arc<AtomicU64>,
        local_nonces: LocalNonces,
        local: Arc<crate::local::LocalAddresses>,
    ) -> Result<(Self, PeerHandle), NetworkError> {
        let addr = stream.peer_addr()?;
        info!(
            "Accepting connection from {}",
            crate::peer_log::address(addr)
        );

        stream.set_nodelay(true)?;

        let peer_id = new_peer_id();
        let info = PeerInfo::new_inbound(peer_id, addr);

        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        let stats = Arc::new(LivePeerStats::default());

        let handle = PeerHandle {
            id: peer_id,
            addr,
            tx: outbound_tx,
            inbound: true, // This is an inbound connection (they connected to us)
            stats: stats.clone(),
        };

        let conn = Connection {
            peer_id,
            stream,
            info,
            magic,
            our_height,
            our_services,
            outbound_rx,
            event_tx,
            shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
            stats,
            local_nonces,
            sent_nonce: None,
            local,
            spork_count: None,
        };

        Ok((conn, handle))
    }

    /// Tell an inbound peer the spork count `source` gives
    pub fn with_spork_count(mut self, source: Option<crate::peer_manager::HeightSource>) -> Self {
        self.spork_count = source;
        self
    }

    /// Read the connection's times from `clock` (the system clock unless a test
    /// gives one it moves on)
    pub fn with_clock(mut self, clock: crate::peer_clock::PeerClock) -> Self {
        // The times the connection was made with move on to the clock's, which
        // a test may have moved on already (nothing moves on the system clock)
        let by = clock.skipped();
        let info = &mut self.info;
        info.connected_at += by;
        info.last_recv += by;
        info.last_send += by;
        let secs = by.as_secs();
        info.conn_unix += secs;
        info.last_recv_unix += secs;
        info.last_send_unix += secs;
        info.clock = clock;
        self
    }

    /// Run the connection handler
    pub async fn run(mut self) -> Result<(), NetworkError> {
        // Perform handshake, which a stop ends: it reads without the message
        // loop's watch on the shutdown signal, and Divi Core's net thread,
        // interrupted at shutdown, takes no more of a peer's version
        // (divid.cpp:42-53). The receiver subscribed with the connection sees
        // a stop sent even before this; the message loop takes a new one
        let fresh = self.shutdown_rx.resubscribe();
        let mut stop = std::mem::replace(&mut self.shutdown_rx, fresh);
        let handshake = tokio::select! {
            result = self.handshake() => result,
            _ = stop.recv() => Err(NetworkError::Connection("the node is stopping".into())),
        };
        if let Err(e) = handshake {
            error!(
                "Handshake failed with {}: {}",
                crate::peer_log::peer(self.peer_id, self.info.addr),
                e
            );
            let _ = self.event_tx.send(PeerEvent::Disconnected {
                peer_id: self.peer_id,
                reason: e.to_string(),
            });
            return Err(e);
        }

        // Divi Core's "receive version message" line (main.cpp:456-461)
        info!(
            "receive version message: {}: version {}, blocks={}, us={}, {}",
            self.info.user_agent().unwrap_or("unknown"),
            self.info.version.as_ref().map_or(0, |v| v.version),
            self.info.start_height,
            self.info
                .version
                .as_ref()
                .map_or_else(String::new, |v| v.addr_recv.socket_addr().to_string()),
            crate::peer_log::peer(self.peer_id, self.info.addr)
        );

        // The peer's services are readable before anyone hears of it: block
        // download picks peers by NODE_NETWORK
        self.info.publish(&self.stats);

        // Notify connection established
        if let Some(version) = self.info.version.clone() {
            let _ = self.event_tx.send(PeerEvent::Connected {
                peer_id: self.peer_id,
                addr: self.info.addr,
                version,
            });
        }

        // Main message loop, raced against the stop: its writes to a peer that
        // no longer reads wait outside the loop's own watch on the signal.
        // Divi Core's sends never wait (MSG_DONTWAIT, SocketChannel.cpp:11-13)
        let (peer_id, event_tx) = (self.peer_id, self.event_tx.clone());
        tokio::select! {
            result = self.message_loop() => result,
            _ = stop.recv() => {
                let _ = event_tx.send(PeerEvent::Disconnected {
                    peer_id,
                    reason: "the node is stopping".to_string(),
                });
                Ok(())
            }
        }
    }

    /// Perform version handshake
    async fn handshake(&mut self) -> Result<(), NetworkError> {
        // getpeerinfo lists a peer from its connection on, with start height
        // -1 until a version names one (Divi Core nStartingHeight, Node.cpp:561)
        self.info.publish(&self.stats);

        // For outbound connections, we send version first
        // For inbound, we wait for their version first
        if self.info.direction == PeerDirection::Outbound {
            self.send_version().await?;
            self.info.state = PeerState::VersionSent;
        }

        // Wait for their version, as long as Divi Core keeps a peer that has not
        // sent one: its inactivity rules apply from the start (Node.cpp:812-834)
        let their_version = self.recv_version().await?;

        debug!(
            "Received version from {}: height={}, user_agent={}",
            self.info.addr, their_version.start_height, their_version.user_agent
        );

        // Divi Core DisconnectOldProtocol: reject, disconnect (and the peer
        // manager bans the address)
        if their_version.version < MIN_PEER_PROTO_VERSION {
            let _ = self
                .send_message(reject(
                    "version",
                    REJECT_OBSOLETE,
                    &format!("Version must be {} or greater", MIN_PEER_PROTO_VERSION),
                ))
                .await;
            return Err(NetworkError::VersionMismatch {
                peer: their_version.version,
                required: MIN_PEER_PROTO_VERSION,
            });
        }

        // Divi Core IsSelfConnection: our own version came back
        if self.local_nonces.lock().contains(&their_version.nonce) {
            info!(
                "Connected to self at {}, disconnecting",
                crate::peer_log::peer(self.peer_id, self.info.addr)
            );
            return Err(NetworkError::Connection("connected to self".into()));
        }

        // Store their version info
        self.info.time_offset = their_version.timestamp - self.info.clock.time();
        let their_time = their_version.timestamp;
        // An inbound peer names the address it reached us at (Divi Core
        // main.cpp:402-404 SeenLocal)
        if self.info.direction == PeerDirection::Inbound {
            let ours = their_version.addr_recv.socket_addr();
            if crate::local::is_routable(&ours.ip()) {
                self.local.seen(&ours);
            }
        }
        self.info.services = their_version.services;
        self.info.start_height = their_version.start_height;
        // fRelayTxes from the version message, true when it names none
        // (Divi Core main.cpp:388-391)
        self.stats.bloom.set_relay(their_version.relay);
        self.info.version = Some(their_version);
        self.info.state = PeerState::VersionReceived;
        // Divi Core keeps the version's fields as it reads them (main.cpp:372-391),
        // so getpeerinfo shows them before the verack
        self.info.publish(&self.stats);

        // If inbound, now send our version
        if self.info.direction == PeerDirection::Inbound {
            self.send_version().await?;
        }

        // Send verack
        self.send_message(NetworkMessage::Verack).await?;
        // A sample of the network's time, last of the version message's work, so
        // the version we sent an inbound peer has the offset as it was before
        // (Divi Core AddTimeData after PushVersion and verack, main.cpp:407-465)
        crate::timedata::add_time_data(self.info.addr.ip(), their_time);

        // Then, as Divi Core's version handler: an inbound peer is told the
        // spork count, an outbound one asked for addresses (main.cpp:417-442)
        if self.info.direction == PeerDirection::Inbound {
            let count = self.spork_count.as_ref().map_or(0, |source| source());
            self.send_message(NetworkMessage::SporkCount(count)).await?;
        } else {
            self.send_message(NetworkMessage::GetAddr).await?;
        }

        // Divi Core counts the peer as connected once its version is handled
        // (RecordSuccessfullConnection, main.cpp:454): what goes out to a peer
        // with a version (sporkcount, ping, getblocks, getaddr) goes now, and
        // what the peer sends is handled as it comes, its verack included
        // (main.cpp:484-514 checks only for the version)
        self.info.state = PeerState::Connected;
        Ok(())
    }

    /// A fresh nonce for our version message, recorded in the node's set
    fn new_local_nonce(&mut self) -> u64 {
        let nonce = loop {
            let n: u64 = rand::random();
            if self.local_nonces.lock().insert(n) {
                break n;
            }
        };
        self.sent_nonce = Some(NonceGuard {
            nonces: Arc::clone(&self.local_nonces),
            nonce,
        });
        nonce
    }

    /// Send our version message
    async fn send_version(&mut self) -> Result<(), NetworkError> {
        // Divi Core CNode::PushVersion (Node.cpp:992-1005): the peer's address
        // when routable, else 0.0.0.0:0, and our best address for it, else
        // 0.0.0.0 with our listen port
        let peer = self.info.addr;
        let addr_recv = if crate::local::is_routable(&peer.ip()) {
            NetAddr::from_socket_addr(peer, crate::constants::services::NODE_NETWORK)
        } else {
            NetAddr::from_ipv4([0, 0, 0, 0], 0, crate::constants::services::NODE_NETWORK)
        };
        let version = VersionMessage {
            version: crate::constants::protocol_version(),
            services: self.our_services,
            // GetAdjustedTime to an inbound peer, GetTime to one we dialled, both on
            // the clock setmocktime sets (Node.cpp:995-996)
            timestamp: if self.info.direction == PeerDirection::Inbound {
                self.info.clock.adjusted_time()
            } else {
                self.info.clock.time()
            },
            addr_recv,
            addr_from: self
                .local
                .version_address(Some(&self.info.addr.ip()), self.our_services),
            nonce: self.new_local_nonce(),
            user_agent: USER_AGENT.to_string(),
            start_height: self.our_height as i32,
            relay: true,
        };

        self.send_message(NetworkMessage::Version(version)).await
    }

    /// Wait for version message (during handshake - uses blocking read, ok because no select!)
    async fn recv_version(&mut self) -> Result<VersionMessage, NetworkError> {
        loop {
            match self.read_message_handshake().await? {
                Some(Decoded::Message(NetworkMessage::Version(v))) => return Ok(v),
                Some(Decoded::Malformed { command, error }) if command == "version" => {
                    self.reject_malformed(&command, &error).await?;
                }
                // Divi Core does not even parse a message that comes before
                // the version: Misbehaving(1) and ignore it
                Some(Decoded::Message(msg)) => self.before_version(msg.command()),
                Some(Decoded::Malformed { command, .. }) => self.before_version(&command),
                None => {}
            }
        }
    }

    fn before_version(&self, command: &str) {
        debug!("{} from {} before its version", command, self.info.addr);
        let _ = self.event_tx.send(PeerEvent::Misbehavior {
            peer_id: self.peer_id,
            score: 1,
            reason: "Version message has not arrived before other handshake steps".into(),
        });
    }

    /// Divi Core's answer to a message that does not parse
    async fn reject_malformed(&mut self, command: &str, error: &str) -> Result<(), NetworkError> {
        debug!(
            "{} from {} does not parse: {}",
            command, self.info.addr, error
        );
        match malformed_reject(command) {
            Some(answer) => self.send_message(answer).await,
            None => Ok(()),
        }
    }

    /// Read a message during handshake (not cancellation-safe, but OK since no
    /// select!). It reads exactly one message, so nothing is buffered past it,
    /// and applies the codec's framing rules: `None` is a skipped message.
    /// Fill `buf` from a peer that has not sent its version, counting each
    /// part as it arrives. Each read waits only until `handshake_deadline` as it
    /// stands then, so bytes that came move it; a timeout drops the peer, so
    /// a message cut off by it is not lost to anyone
    async fn read_counted(&mut self, buf: &mut [u8]) -> Result<(), NetworkError> {
        use tokio::io::AsyncReadExt;
        let mut got = 0;
        while got < buf.len() {
            let deadline = handshake_deadline(&self.info);
            let now = self.info.clock.now();
            if now >= deadline {
                info!(
                    "{} sent no version in time ({} bytes in, {} out), disconnecting",
                    crate::peer_log::peer(self.peer_id, self.info.addr),
                    self.info.bytes_recv,
                    self.info.bytes_sent
                );
                return Err(NetworkError::Timeout);
            }
            // Waits no longer than a check of the clock, which a test may move on;
            // a read cut off by it has taken nothing, and is made again
            let wait = (deadline - now).min(self.info.clock.check_interval());
            let Ok(read) = timeout(wait, self.stream.read(&mut buf[got..])).await else {
                continue;
            };
            let n = read?;
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            got += n;
            self.info.bytes_recv += n as u64;
            self.info.last_recv = self.info.clock.now();
            self.info.last_recv_unix = self.info.clock.time().max(0) as u64;
            self.total_bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn read_message_handshake(&mut self) -> Result<Option<Decoded>, NetworkError> {
        use crate::message::{MessageHeader, HEADER_SIZE};

        // Every byte counts as it comes, part of a message or not, as Divi Core
        // records each read (Node.cpp:160-164, :292): a peer that sends half a
        // message has sent something
        let mut header_buf = [0u8; HEADER_SIZE];
        self.read_counted(&mut header_buf).await?;
        let header = MessageHeader::deserialize(&header_buf)?;
        if !header.validate_magic(&self.magic) {
            return Err(NetworkError::InvalidMagic);
        }
        if header.payload_size > MAX_MESSAGE_SIZE {
            return Err(NetworkError::MessageTooLarge {
                size: header.payload_size,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Read the payload as it arrives instead of reserving all of it
        // up front for a size the peer has only announced
        let size = header.payload_size as usize;
        let mut payload = Vec::new();
        let mut chunk = [0u8; 8192];
        while payload.len() < size {
            let want = (size - payload.len()).min(chunk.len());
            self.read_counted(&mut chunk[..want]).await?;
            payload.extend_from_slice(&chunk[..want]);
        }

        if !header.command_is_valid() || !header.validate_checksum(&payload) {
            debug!("Skipping a damaged message from {}", self.info.addr);
            return Ok(None);
        }
        let command = header.command_string();
        Ok(Some(
            match NetworkMessage::deserialize(&command, &payload) {
                Ok(message) => Decoded::Message(message),
                Err(e) => Decoded::Malformed {
                    command,
                    error: e.to_string(),
                },
            },
        ))
    }

    /// Main message processing loop using cancellation-safe FramedRead
    async fn message_loop(self) -> Result<(), NetworkError> {
        let Connection {
            peer_id,
            stream,
            mut info,
            magic,
            our_height: _,
            our_services: _,
            mut outbound_rx,
            event_tx,
            mut shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
            stats,
            local_nonces: _,
            local: _,
            spork_count: _,
            // Kept until the loop ends: the nonce leaves the node's set then
            sent_nonce: _nonce_guard,
        } = self;

        // Split stream for concurrent read/write
        let (reader, mut writer) = tokio::io::split(stream);

        // Wrap reader in FramedRead with our codec - this is CANCELLATION SAFE!
        let codec = DiviCodec::new(magic).with_clock(info.clock.clone());
        let mut framed = FramedRead::new(reader, codec);

        // Keepalive pings as Divi Core's MaybeSendPing: the first goes out now,
        // after what the version handler sent and before anything else, as the
        // message handler sends it before SendMessages (net.cpp:871-893); then
        // one each PING_INTERVAL after the last ping sent (a `ping` call included)
        let mut ping_timer = tokio::time::interval(info.clock.check_interval());
        let mut last_ping_sent = None;
        // A peer we dialled is sent no ping until its sporks are in (Node.cpp:1032)
        if !stats.sporks_wait.load(Ordering::Acquire) {
            if let Err(e) = Self::send_first_ping(
                &mut writer,
                &mut info,
                magic,
                &total_bytes_sent,
                &mut last_ping_sent,
            )
            .await
            {
                error!(
                    "Failed to send keepalive ping to {}: {}",
                    crate::peer_log::peer(peer_id, info.addr),
                    e
                );
            }
        }

        // What the connection answers itself (pongs, rejects), each behind the
        // peer's messages before it that the node has not handled yet
        let mut waiting: VecDeque<(u64, NetworkMessage)> = VecDeque::new();

        loop {
            info.publish(&stats);
            // Not read while its messages the node has not taken pass the
            // limits (Divi Core IsAvailableToReceive, Node.cpp:335-339)
            let can_receive = stats.can_receive();
            tokio::select! {
                biased;

                // Check for shutdown signal (highest priority)
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, disconnecting from {}", crate::peer_log::peer(peer_id, info.addr));
                    break;
                }

                // Handle outgoing messages. The channel closes when the peer
                // manager drops this peer (disconnect, ban): end the connection.
                msg = outbound_rx.recv() => {
                    let Some(msg) = msg else {
                        info!("Disconnecting from {} (dropped by the peer manager)", crate::peer_log::peer(peer_id, info.addr));
                        break;
                    };
                    if let Err(e) = Self::write_queued(&mut writer, &mut info, magic, &total_bytes_sent, &stats, &mut last_ping_sent, msg).await {
                        error!("Failed to send message to {}: {}", crate::peer_log::peer(peer_id, info.addr), e);
                        break;
                    }
                }

                // Proactive keepalive ping
                _ = ping_timer.tick() => {
                    if inactivity_exceeded(info.last_send, last_bytes_in(&info, framed.decoder()), info.ping_time, info.clock.now()) {
                        info!("{} inactive for {:?}, disconnecting", crate::peer_log::peer(peer_id, info.addr), TIMEOUT_INTERVAL);
                        break;
                    }
                    let now = info.clock.now();
                    // none before the first, which waits for a dialled peer's sporks
                    if last_ping_sent.is_some()
                        && keepalive_ping_due(info.ping_nonce.is_some(), last_ping_sent, now)
                    {
                        let nonce = rand::random();
                        info.ping_nonce = Some(nonce);
                        info.ping_time = Some(now);
                        last_ping_sent = Some(now);
                        if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, NetworkMessage::Ping(nonce)).await {
                            error!("Failed to send keepalive ping to {}: {}", crate::peer_log::peer(peer_id, info.addr), e);
                            break;
                        }
                    }
                }

                // The node took a message: read again if there is room, and
                // write the answers whose turn has come
                _ = stats.recv_space.notified(), if !can_receive || !waiting.is_empty() => {
                    if let Err(e) = Self::write_turns(&mut writer, &mut info, magic, &total_bytes_sent, &stats, &mut last_ping_sent, &mut outbound_rx, &mut waiting).await {
                        error!("Failed to send message to {}: {}", crate::peer_log::peer(peer_id, info.addr), e);
                        break;
                    }
                }

                // Handle incoming messages - framed.next() IS CANCELLATION SAFE!
                result = timeout(READ_TIMEOUT, framed.next()), if can_receive => {
                    match result {
                        Ok(Some(Ok(Decoded::Malformed { command, .. }))) if command == "version" => {
                            let bytes_received = framed.decoder_mut().take_bytes_consumed();
                            info.bytes_recv += bytes_received;
                            total_bytes_recv.fetch_add(bytes_received, Ordering::Relaxed);
                            Self::answer_in_turn(&stats, &mut waiting, duplicate_version_reject());
                            if let Err(e) = Self::write_turns(&mut writer, &mut info, magic, &total_bytes_sent, &stats, &mut last_ping_sent, &mut outbound_rx, &mut waiting).await {
                                error!("Failed to send reject to {}: {}", crate::peer_log::peer(peer_id, info.addr), e);
                                break;
                            }
                            let _ = event_tx.send(duplicate_version(peer_id));
                        }
                        Ok(Some(Ok(Decoded::Malformed { command, error }))) => {
                            let bytes_received = framed.decoder_mut().take_bytes_consumed();
                            info.bytes_recv += bytes_received;
                            info.last_recv = info.clock.now();
                            info.last_recv_unix = info.clock.time().max(0) as u64;
                            total_bytes_recv.fetch_add(bytes_received, Ordering::Relaxed);
                            debug!("{} from {} does not parse: {}", command, info.addr, error);
                            if command == "pong" {
                                // Divi Core reads a pong without throwing: under 8
                                // bytes ends the ping untimed ("Short payload",
                                // Node.cpp:790-794)
                                info.ping_nonce = None;
                                info.ping_time = None;
                            }
                            if let Some(answer) = malformed_reject(&command) {
                                Self::answer_in_turn(&stats, &mut waiting, answer);
                                if let Err(e) = Self::write_turns(&mut writer, &mut info, magic, &total_bytes_sent, &stats, &mut last_ping_sent, &mut outbound_rx, &mut waiting).await {
                                    error!("Failed to send reject to {}: {}", crate::peer_log::peer(peer_id, info.addr), e);
                                    break;
                                }
                            }
                        }
                        Ok(Some(Ok(Decoded::Message(msg)))) => {
                            // Exact bytes the codec took off the wire for this message
                            let bytes_received = framed.decoder_mut().take_bytes_consumed();

                            // Update stats
                            info.bytes_recv += bytes_received;
                            info.last_recv = info.clock.now();
                            info.last_recv_unix = info.clock.time().max(0) as u64;
                            info.last_message_command = Some(msg.command().to_string());
                            total_bytes_recv.fetch_add(bytes_received, Ordering::Relaxed);

                            trace!("Received {} from {}", msg.command(), info.addr);

                            Self::handle_message(
                                &mut info, peer_id, &event_tx, &stats, &mut waiting, msg, bytes_received
                            );
                            if let Err(e) = Self::write_turns(&mut writer, &mut info, magic, &total_bytes_sent, &stats, &mut last_ping_sent, &mut outbound_rx, &mut waiting).await {
                                warn!("Error answering {}: {}", crate::peer_log::peer(peer_id, info.addr), e);
                            }
                        }
                        Ok(Some(Err(e))) => {
                            error!("Error reading from {}: {}", crate::peer_log::peer(peer_id, info.addr), e);
                            break;
                        }
                        Ok(None) => {
                            // Stream ended (connection closed)
                            info!("Connection closed by {}", crate::peer_log::peer(peer_id, info.addr));
                            break;
                        }
                        Err(_) => {
                            // A quiet peer gets no extra ping: the keepalive above
                            // runs on its own interval, as in Divi Core
                            if inactivity_exceeded(info.last_send, last_bytes_in(&info, framed.decoder()), info.ping_time, info.clock.now()) {
                                info!("{} inactive for {:?}, disconnecting", crate::peer_log::peer(peer_id, info.addr), TIMEOUT_INTERVAL);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Notify disconnection
        let _ = event_tx.send(PeerEvent::Disconnected {
            peer_id,
            reason: "connection closed".to_string(),
        });

        Ok(())
    }

    /// Handle a received message: what the connection answers itself waits
    /// in `waiting` for its turn
    fn handle_message(
        info: &mut PeerInfo,
        peer_id: PeerId,
        event_tx: &broadcast::Sender<PeerEvent>,
        stats: &LivePeerStats,
        waiting: &mut VecDeque<(u64, NetworkMessage)>,
        msg: NetworkMessage,
        size: u64,
    ) {
        match &msg {
            // The peer's verack: nothing waits for it, but a peer we dialled
            // is marked currently connected (main.cpp:498-507)
            NetworkMessage::Verack => {
                if info.direction == PeerDirection::Outbound {
                    stats.verack_received.store(true, Ordering::Release);
                }
            }
            // Divi Core: one version per connection
            NetworkMessage::Version(_) => {
                Self::answer_in_turn(stats, waiting, duplicate_version_reject());
                let _ = event_tx.send(duplicate_version(peer_id));
            }
            NetworkMessage::Ping(nonce) => {
                Self::answer_in_turn(stats, waiting, NetworkMessage::Pong(*nonce));
            }
            NetworkMessage::Pong(nonce) => {
                // Divi Core ProcessReceivedPong (Node.cpp:754-808): our nonce
                // ends the ping and times it; nonce 0 ends it untimed (a bug
                // in the other implementation); another nonce leaves it
                // outstanding (pings may overlap)
                if let Some(sent_nonce) = info.ping_nonce {
                    if sent_nonce == *nonce {
                        if let Some(ping_time) = info.ping_time {
                            // Microseconds: a LAN or localhost round trip is well under 1 ms
                            let latency = info.clock.now().saturating_duration_since(ping_time);
                            info.ping_latency_us = Some((latency.as_micros() as u64).max(1));
                        }
                        info.ping_nonce = None;
                        info.ping_time = None;
                    } else if *nonce == 0 {
                        debug!("Pong with nonce 0 from {}: ping cancelled", info.addr);
                        info.ping_nonce = None;
                        info.ping_time = None;
                    }
                }
            }
            _ => {
                // Log all messages for debugging
                trace!("Received {} message from peer {}", msg.command(), peer_id);

                // Forward to event handler for processing; counted until
                // the node has handled it (none left to count with no node)
                stats.message_queued(size);
                let sent = event_tx.send(PeerEvent::Message {
                    peer_id,
                    message: msg,
                    size,
                });
                if sent.is_err() {
                    stats.message_taken(size);
                }
            }
        }
    }

    /// Queue an answer the connection gives itself (a pong, a reject) behind
    /// the peer's messages handed to the node before it
    fn answer_in_turn(
        stats: &LivePeerStats,
        waiting: &mut VecDeque<(u64, NetworkMessage)>,
        msg: NetworkMessage,
    ) {
        waiting.push_back((stats.recv_handed.load(Ordering::Acquire), msg));
    }

    /// Write the answers whose turn has come: the node has handled every
    /// message before them. What the node queued for the peer meanwhile goes
    /// first, as it answers those earlier messages
    #[allow(clippy::too_many_arguments)]
    async fn write_turns<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        info: &mut PeerInfo,
        magic: Magic,
        total_bytes_sent: &Arc<AtomicU64>,
        stats: &LivePeerStats,
        last_ping_sent: &mut Option<std::time::Instant>,
        outbound_rx: &mut mpsc::Receiver<NetworkMessage>,
        waiting: &mut VecDeque<(u64, NetworkMessage)>,
    ) -> Result<(), NetworkError> {
        loop {
            let taken = stats.recv_taken.load(Ordering::Acquire);
            match waiting.front() {
                Some((handed, _)) if *handed <= taken => {}
                _ => return Ok(()),
            }
            while let Ok(msg) = outbound_rx.try_recv() {
                Self::write_queued(
                    writer,
                    info,
                    magic,
                    total_bytes_sent,
                    stats,
                    last_ping_sent,
                    msg,
                )
                .await?;
            }
            if let Some((_, msg)) = waiting.pop_front() {
                Self::write_message(writer, info, magic, total_bytes_sent, msg).await?;
            }
        }
    }

    /// The first keepalive ping, after what the version handler sent and before anything else
    async fn send_first_ping<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        info: &mut PeerInfo,
        magic: Magic,
        total_bytes_sent: &Arc<AtomicU64>,
        last_ping_sent: &mut Option<std::time::Instant>,
    ) -> Result<(), NetworkError> {
        let nonce = rand::random();
        info.ping_nonce = Some(nonce);
        info.ping_time = Some(info.clock.now());
        *last_ping_sent = info.ping_time;
        Self::write_message(
            writer,
            info,
            magic,
            total_bytes_sent,
            NetworkMessage::Ping(nonce),
        )
        .await
    }

    /// Write a message the node queued for the peer, counted until written
    /// as Divi Core's nSendSize. A queued ping (the `ping` RPC) gets a fresh
    /// nonce and is timed like the keep-alive, so its pong updates pingtime
    /// (C++ fPingQueued)
    async fn write_queued<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        info: &mut PeerInfo,
        magic: Magic,
        total_bytes_sent: &Arc<AtomicU64>,
        stats: &LivePeerStats,
        last_ping_sent: &mut Option<std::time::Instant>,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        let queued = msg.wire_size();
        if stats.holds_back(&msg) {
            // Divi Core keeps these for a peer whose sporks are out
            stats.send_written(queued);
            stats.hold(msg);
            return Ok(());
        }
        let msg = match msg {
            NetworkMessage::Ping(_) => {
                let nonce = rand::random();
                info.ping_nonce = Some(nonce);
                info.ping_time = Some(info.clock.now());
                *last_ping_sent = info.ping_time;
                NetworkMessage::Ping(nonce)
            }
            other => other,
        };
        let written = Self::write_message(writer, info, magic, total_bytes_sent, msg).await;
        stats.send_written(queued);
        written
    }

    /// Write a message to a writer
    async fn write_message<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        info: &mut PeerInfo,
        magic: Magic,
        total_bytes_sent: &Arc<AtomicU64>,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        let bytes = msg.to_bytes(magic)?;

        writer.write_all(&bytes).await?;
        writer.flush().await?;

        // Update stats
        let bytes_sent = bytes.len() as u64;
        info.bytes_sent += bytes_sent;
        info.last_send = info.clock.now();
        info.last_send_unix = info.clock.time().max(0) as u64;
        total_bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);

        // Log outgoing messages for debugging
        trace!("Sent {} to peer at {}", msg.command(), info.addr);
        Ok(())
    }

    /// Send a message (for handshake phase)
    async fn send_message(&mut self, msg: NetworkMessage) -> Result<(), NetworkError> {
        let bytes = msg.to_bytes(self.magic)?;

        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;

        let bytes_sent = bytes.len() as u64;
        self.info.bytes_sent += bytes_sent;
        self.info.last_send = self.info.clock.now();
        self.info.last_send_unix = self.info.clock.time().max(0) as u64;
        self.total_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);

        trace!("Sent {} to {}", msg.command(), self.info.addr);
        Ok(())
    }
}

/// Divi Core reject codes
const REJECT_MALFORMED: u8 = 0x01;
const REJECT_OBSOLETE: u8 = 0x11;
const REJECT_DUPLICATE: u8 = 0x12;

fn reject(command: &str, code: u8, reason: &str) -> NetworkMessage {
    NetworkMessage::Reject(crate::messages::RejectMessage {
        message: command.to_string(),
        code,
        reason: reason.to_string(),
        data: Vec::new(),
    })
}

/// The `reject` Divi Core sends for a message that does not parse
/// (main.cpp:1054). None for a `reject`, which Divi Core reads only with
/// -debug and whose parse errors it swallows (main.cpp:940-962), for
/// `headers`, which it never reads (main.cpp:669, HeadersFirstSyncingActive
/// is false on every network): answering those could only start an
/// exchange of rejects; and for a short `pong`, which Divi Core reads by
/// the bytes it has (Node.cpp:759-794).
fn malformed_reject(command: &str) -> Option<NetworkMessage> {
    match command {
        "reject" | "headers" | "pong" => None,
        _ => Some(reject(command, REJECT_MALFORMED, "error parsing message")),
    }
}

fn duplicate_version_reject() -> NetworkMessage {
    reject("version", REJECT_DUPLICATE, "Duplicate version message")
}

fn duplicate_version(peer_id: PeerId) -> PeerEvent {
    PeerEvent::Misbehavior {
        peer_id,
        score: 1,
        reason: "Duplicated version message".into(),
    }
}

/// Divi Core `CheckForInnactivity`: disconnect after this long without
/// sending anything, without receiving anything, or with a ping unanswered
const TIMEOUT_INTERVAL: Duration = Duration::from_secs(20 * 60);

/// True once nothing has been sent to a peer, nothing received from it, or a
/// ping left unanswered, for longer than `TIMEOUT_INTERVAL` (Node.cpp:823-832;
/// the sending timeout drops a peer we keep nothing to send, such as a peer we
/// dialled that never sends its sporks)
fn inactivity_exceeded(
    last_send: std::time::Instant,
    last_recv: std::time::Instant,
    ping_sent: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    now.saturating_duration_since(last_send) > TIMEOUT_INTERVAL
        || now.saturating_duration_since(last_recv) > TIMEOUT_INTERVAL
        || ping_sent.is_some_and(|sent| now.saturating_duration_since(sent) > TIMEOUT_INTERVAL)
}

/// When bytes last came from the peer: its last whole message, or later bytes
/// of a message not yet whole (Divi Core's receive clock counts bytes,
/// Node.cpp:160-164)
fn last_bytes_in(info: &PeerInfo, codec: &DiviCodec) -> std::time::Instant {
    codec
        .last_arrival()
        .map_or(info.last_recv, |at| at.max(info.last_recv))
}

/// When a peer that has not sent its version is dropped: 60 s after the
/// connection opened while nothing has come from it or gone to it (an inbound
/// peer is sent nothing before its version), else 20 minutes after the last
/// data either way (Divi Core CheckForInnactivity, Node.cpp:819-828)
fn handshake_deadline(info: &PeerInfo) -> std::time::Instant {
    if info.bytes_recv == 0 || info.bytes_sent == 0 {
        info.connected_at + FIRST_DATA_TIMEOUT
    } else {
        info.last_send.min(info.last_recv) + TIMEOUT_INTERVAL
    }
}

/// Divi Core MaybeSendPing (Node.cpp:1043-1069): a keepalive ping is due when
/// none is unanswered and none was sent in the last PING_INTERVAL
fn keepalive_ping_due(
    ping_unanswered: bool,
    last_ping_sent: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    !ping_unanswered
        && last_ping_sent.is_none_or(|sent| now.saturating_duration_since(sent) >= PING_INTERVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Divi Core's PING_INTERVAL: 2 minutes (Node.cpp:1045)
    #[test]
    fn ping_interval_is_two_minutes() {
        assert_eq!(PING_INTERVAL, Duration::from_secs(120));
    }

    /// A keepalive ping 2 minutes after the last ping sent, and not while one
    /// is unanswered (Divi Core MaybeSendPing, Node.cpp:1043-1069)
    #[test]
    fn keepalive_pings_two_minutes_apart() {
        let start = std::time::Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        assert!(
            keepalive_ping_due(false, None, start),
            "the first one at once"
        );
        assert!(!keepalive_ping_due(false, Some(start), at(30)));
        assert!(!keepalive_ping_due(false, Some(start), at(119)));
        assert!(keepalive_ping_due(false, Some(start), at(120)));
        assert!(
            !keepalive_ping_due(true, Some(start), at(300)),
            "one unanswered"
        );
    }

    /// Divi Core's -timeout default: 5000 ms
    #[test]
    fn test_connect_timeout() {
        assert_eq!(connect_timeout(), Duration::from_millis(5000));
    }

    /// Before its version, Divi Core drops a peer 60 s after the connection
    /// opened if nothing came from it or nothing went to it (Node.cpp:819-822),
    /// otherwise 20 minutes after the last data
    #[test]
    fn a_peer_without_a_version_is_dropped_as_divi_core_does() {
        let mut info = PeerInfo::new_inbound(1, "127.0.0.1:1".parse().unwrap());
        let open = info.connected_at;
        assert_eq!(handshake_deadline(&info), open + Duration::from_secs(60));
        // something came in, but an inbound peer is sent nothing before its version
        info.bytes_recv = 24;
        assert_eq!(handshake_deadline(&info), open + Duration::from_secs(60));
        // both ways: 20 minutes from the older of the last send and receive
        info.bytes_sent = 24;
        info.last_send = open + Duration::from_secs(1);
        info.last_recv = open + Duration::from_secs(50);
        assert_eq!(
            handshake_deadline(&info),
            open + Duration::from_secs(1) + Duration::from_secs(20 * 60)
        );
    }

    /// Divi Core CheckForInnactivity: 20 minutes without data, or with a ping unanswered
    #[test]
    fn inactive_peers_time_out_after_twenty_minutes() {
        let start = std::time::Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        assert!(!inactivity_exceeded(at(1200), start, None, at(20 * 60)));
        assert!(inactivity_exceeded(at(1200), start, None, at(20 * 60 + 1)));
        // Data keeps coming but the ping is never answered
        assert!(!inactivity_exceeded(
            at(1200),
            at(1199),
            Some(start),
            at(1200)
        ));
        assert!(inactivity_exceeded(
            at(1200),
            at(1200),
            Some(start),
            at(1201)
        ));
        assert!(!inactivity_exceeded(at(1200), at(1200), None, at(1201)));
        // Data keeps coming but nothing is sent: the sending timeout
        // (Node.cpp:823-825), as for a dialled peer that never sends its sporks
        assert!(!inactivity_exceeded(start, at(1200), None, at(20 * 60)));
        assert!(inactivity_exceeded(start, at(1200), None, at(20 * 60 + 1)));
    }
}
