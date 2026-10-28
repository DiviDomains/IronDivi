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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;
use tokio_util::codec::FramedRead;
use tracing::{debug, trace, warn};

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

/// Timeout for handshake completion
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for reading a message
const READ_TIMEOUT: Duration = Duration::from_secs(90);

/// Divi Core's PING_INTERVAL (Node.cpp:1045): a keepalive ping goes out this
/// long after the last ping was sent, when none is unanswered
const PING_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// How often the connection checks whether a keepalive ping is due (Divi Core
/// checks on each pass of its send loop, about every 100 ms)
const PING_CHECK: Duration = Duration::from_secs(1);

/// Channel buffer size for outgoing messages
const OUTBOUND_BUFFER: usize = 100;

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
        proxy: Option<SocketAddr>,
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
                debug!("Connecting to peer {} via proxy {}", addr, proxy);
                timeout(connect_timeout(), crate::socks5::connect(proxy, addr))
                    .await
                    .map_err(|_| NetworkError::Timeout)??
            }
            None => {
                debug!("Connecting to peer {}", addr);
                timeout(connect_timeout(), TcpStream::connect(addr))
                    .await
                    .map_err(|_| NetworkError::Timeout)?
                    .map_err(|e| NetworkError::Connection(e.to_string()))?
            }
        };

        // Set TCP options
        stream.set_nodelay(true)?;

        let peer_id = new_peer_id();
        let info = PeerInfo::new_outbound(peer_id, addr);

        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);
        let stats = Arc::new(LivePeerStats::default());

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
        debug!("Accepting connection from {}", addr);

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
        };

        Ok((conn, handle))
    }

    /// Run the connection handler
    pub async fn run(mut self) -> Result<(), NetworkError> {
        // Perform handshake
        if let Err(e) = self.handshake().await {
            debug!("Handshake failed with {}: {}", self.info.addr, e);
            let _ = self.event_tx.send(PeerEvent::Disconnected {
                peer_id: self.peer_id,
                reason: e.to_string(),
            });
            return Err(e);
        }

        debug!(
            "Handshake complete with {} ({}), height {}",
            self.info.addr,
            self.info.user_agent().unwrap_or("unknown"),
            self.info.start_height
        );

        // Send BIP 130 sendheaders message
        if let Err(e) = self.send_message(NetworkMessage::SendHeaders).await {
            debug!("Failed to send sendheaders to {}: {}", self.info.addr, e);
        }

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

        // Main message loop
        self.message_loop().await
    }

    /// Perform version handshake
    async fn handshake(&mut self) -> Result<(), NetworkError> {
        // For outbound connections, we send version first
        // For inbound, we wait for their version first
        if self.info.direction == PeerDirection::Outbound {
            self.send_version().await?;
            self.info.state = PeerState::VersionSent;
        }

        // Wait for their version (with timeout)
        let their_version = timeout(HANDSHAKE_TIMEOUT, self.recv_version())
            .await
            .map_err(|_| NetworkError::Timeout)??;

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
            debug!("Connected to self at {}, disconnecting", self.info.addr);
            return Err(NetworkError::Connection("connected to self".into()));
        }

        // Store their version info
        self.info.time_offset = their_version.timestamp - divi_primitives::clock::now();
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
        self.info.version = Some(their_version);
        self.info.state = PeerState::VersionReceived;

        // If inbound, now send our version
        if self.info.direction == PeerDirection::Inbound {
            self.send_version().await?;
        }

        // Send verack
        self.send_message(NetworkMessage::Verack).await?;

        // Wait for their verack
        timeout(HANDSHAKE_TIMEOUT, self.recv_verack())
            .await
            .map_err(|_| NetworkError::Timeout)??;

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
            // GetTime or GetAdjustedTime, both from the mocked clock (Node.cpp PushVersion)
            timestamp: divi_primitives::clock::now(),
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

    /// Wait for verack message (during handshake - uses blocking read, ok because no select!)
    async fn recv_verack(&mut self) -> Result<(), NetworkError> {
        loop {
            match self.read_message_handshake().await? {
                Some(Decoded::Message(NetworkMessage::Verack)) => return Ok(()),
                Some(Decoded::Message(NetworkMessage::Version(_))) => {
                    self.send_message(duplicate_version_reject()).await?;
                    let _ = self.event_tx.send(duplicate_version(self.peer_id));
                }
                Some(Decoded::Malformed { command, .. }) if command == "version" => {
                    self.send_message(duplicate_version_reject()).await?;
                    let _ = self.event_tx.send(duplicate_version(self.peer_id));
                }
                Some(Decoded::Message(msg)) => {
                    debug!("Ignoring {} during handshake", msg.command());
                }
                Some(Decoded::Malformed { command, error }) => {
                    self.reject_malformed(&command, &error).await?;
                }
                None => {}
            }
        }
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
    async fn read_message_handshake(&mut self) -> Result<Option<Decoded>, NetworkError> {
        use crate::message::{MessageHeader, HEADER_SIZE};
        use tokio::io::AsyncReadExt;

        let mut header_buf = [0u8; HEADER_SIZE];
        self.stream.read_exact(&mut header_buf).await?;
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
        let mut payload = Vec::new();
        (&mut self.stream)
            .take(u64::from(header.payload_size))
            .read_to_end(&mut payload)
            .await?;
        if payload.len() != header.payload_size as usize {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }

        let bytes_received = HEADER_SIZE as u64 + header.payload_size as u64;
        self.info.bytes_recv += bytes_received;
        self.info.last_recv = std::time::Instant::now();
        self.info.last_recv_unix = crate::peer::unix_now();
        self.total_bytes_recv
            .fetch_add(bytes_received, Ordering::Relaxed);

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
            // Kept until the loop ends: the nonce leaves the node's set then
            sent_nonce: _nonce_guard,
        } = self;

        // Split stream for concurrent read/write
        let (reader, mut writer) = tokio::io::split(stream);

        // Wrap reader in FramedRead with our codec - this is CANCELLATION SAFE!
        let codec = DiviCodec::new(magic);
        let mut framed = FramedRead::new(reader, codec);

        // Keepalive pings as Divi Core's MaybeSendPing: the first check comes at
        // once, so a ping goes out right after the handshake, then one each
        // PING_INTERVAL after the last ping sent (a `ping` call included)
        let mut ping_timer = tokio::time::interval(PING_CHECK);
        let mut last_ping_sent: Option<std::time::Instant> = None;

        loop {
            info.publish(&stats);
            tokio::select! {
                biased;

                // Check for shutdown signal (highest priority)
                _ = shutdown_rx.recv() => {
                    debug!("Shutdown signal received, disconnecting from {}", info.addr);
                    break;
                }

                // Handle outgoing messages. The channel closes when the peer
                // manager drops this peer (disconnect, ban): end the connection.
                msg = outbound_rx.recv() => {
                    let Some(msg) = msg else {
                        debug!("Disconnecting from {} (dropped by the peer manager)", info.addr);
                        break;
                    };
                    // A queued ping (the `ping` RPC) gets a fresh nonce and is timed like the
                    // keep-alive, so its pong updates pingtime (C++ fPingQueued)
                    let msg = match msg {
                        NetworkMessage::Ping(_) => {
                            let nonce = rand::random();
                            info.ping_nonce = Some(nonce);
                            info.ping_time = Some(std::time::Instant::now());
                            last_ping_sent = info.ping_time;
                            NetworkMessage::Ping(nonce)
                        }
                        other => other,
                    };
                    if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, msg).await {
                        debug!("Failed to send message to {}: {}", info.addr, e);
                        break;
                    }
                }

                // Proactive keepalive ping
                _ = ping_timer.tick() => {
                    if inactivity_exceeded(info.last_recv, info.ping_time, std::time::Instant::now()) {
                        debug!("{} inactive for {:?}, disconnecting", info.addr, TIMEOUT_INTERVAL);
                        break;
                    }
                    let now = std::time::Instant::now();
                    if keepalive_ping_due(info.ping_nonce.is_some(), last_ping_sent, now) {
                        let nonce = rand::random();
                        info.ping_nonce = Some(nonce);
                        info.ping_time = Some(now);
                        last_ping_sent = Some(now);
                        if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, NetworkMessage::Ping(nonce)).await {
                            debug!("Failed to send keepalive ping to {}: {}", info.addr, e);
                            break;
                        }
                    }
                }

                // Handle incoming messages - framed.next() IS CANCELLATION SAFE!
                result = timeout(READ_TIMEOUT, framed.next()) => {
                    match result {
                        Ok(Some(Ok(Decoded::Malformed { command, .. }))) if command == "version" => {
                            let bytes_received = framed.decoder_mut().take_bytes_consumed();
                            info.bytes_recv += bytes_received;
                            total_bytes_recv.fetch_add(bytes_received, Ordering::Relaxed);
                            if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, duplicate_version_reject()).await {
                                debug!("Failed to send reject to {}: {}", info.addr, e);
                                break;
                            }
                            let _ = event_tx.send(duplicate_version(peer_id));
                        }
                        Ok(Some(Ok(Decoded::Malformed { command, error }))) => {
                            let bytes_received = framed.decoder_mut().take_bytes_consumed();
                            info.bytes_recv += bytes_received;
                            info.last_recv = std::time::Instant::now();
                            info.last_recv_unix = crate::peer::unix_now();
                            total_bytes_recv.fetch_add(bytes_received, Ordering::Relaxed);
                            debug!("{} from {} does not parse: {}", command, info.addr, error);
                            if let Some(answer) = malformed_reject(&command) {
                                if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, answer).await {
                                    debug!("Failed to send reject to {}: {}", info.addr, e);
                                    break;
                                }
                            }
                        }
                        Ok(Some(Ok(Decoded::Message(msg)))) => {
                            // Exact bytes the codec took off the wire for this message
                            let bytes_received = framed.decoder_mut().take_bytes_consumed();

                            // Update stats
                            info.bytes_recv += bytes_received;
                            info.last_recv = std::time::Instant::now();
                            info.last_recv_unix = crate::peer::unix_now();
                            info.last_message_command = Some(msg.command().to_string());
                            total_bytes_recv.fetch_add(bytes_received, Ordering::Relaxed);

                            trace!("Received {} from {}", msg.command(), info.addr);

                            if let Err(e) = Self::handle_message(
                                &mut writer, &mut info, magic, &total_bytes_sent, peer_id, &event_tx, msg
                            ).await {
                                warn!("Error handling message from {}: {}", info.addr, e);
                            }
                        }
                        Ok(Some(Err(e))) => {
                            debug!("Error reading from {}: {}", info.addr, e);
                            break;
                        }
                        Ok(None) => {
                            // Stream ended (connection closed)
                            debug!("Connection closed by {}", info.addr);
                            break;
                        }
                        Err(_) => {
                            // A quiet peer gets no extra ping: the keepalive above
                            // runs on its own interval, as in Divi Core
                            if inactivity_exceeded(info.last_recv, info.ping_time, std::time::Instant::now()) {
                                debug!("{} inactive for {:?}, disconnecting", info.addr, TIMEOUT_INTERVAL);
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

    /// Handle a received message
    async fn handle_message<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        info: &mut PeerInfo,
        magic: Magic,
        total_bytes_sent: &Arc<AtomicU64>,
        peer_id: PeerId,
        event_tx: &broadcast::Sender<PeerEvent>,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        match &msg {
            // Divi Core: one version per connection
            NetworkMessage::Version(_) => {
                Self::write_message(
                    writer,
                    info,
                    magic,
                    total_bytes_sent,
                    duplicate_version_reject(),
                )
                .await?;
                let _ = event_tx.send(duplicate_version(peer_id));
            }
            NetworkMessage::Ping(nonce) => {
                // Respond with pong
                Self::write_message(
                    writer,
                    info,
                    magic,
                    total_bytes_sent,
                    NetworkMessage::Pong(*nonce),
                )
                .await?;
            }
            NetworkMessage::Pong(nonce) => {
                // Check if this matches our ping
                if let Some(sent_nonce) = info.ping_nonce {
                    if sent_nonce == *nonce {
                        if let Some(ping_time) = info.ping_time {
                            // Microseconds: a LAN or localhost round trip is well under 1 ms
                            info.ping_latency_us =
                                Some((ping_time.elapsed().as_micros() as u64).max(1));
                        }
                        info.ping_nonce = None;
                        info.ping_time = None;
                    }
                }
            }
            _ => {
                // Log all messages for debugging
                trace!("Received {} message from peer {}", msg.command(), peer_id);

                // Forward to event handler for processing
                let _ = event_tx.send(PeerEvent::Message {
                    peer_id,
                    message: msg,
                });
            }
        }

        Ok(())
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
        info.last_send = std::time::Instant::now();
        info.last_send_unix = crate::peer::unix_now();
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
        self.info.last_send = std::time::Instant::now();
        self.info.last_send_unix = crate::peer::unix_now();
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
/// -debug and whose parse errors it swallows (main.cpp:940-962), and for
/// `headers`, which it never reads (main.cpp:669, HeadersFirstSyncingActive
/// is false on every network): answering those could only start an
/// exchange of rejects.
fn malformed_reject(command: &str) -> Option<NetworkMessage> {
    match command {
        "reject" | "headers" => None,
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
/// receiving anything, or with a ping unanswered
const TIMEOUT_INTERVAL: Duration = Duration::from_secs(20 * 60);

/// True once a peer has been silent, or has left a ping unanswered, for
/// longer than `TIMEOUT_INTERVAL`
fn inactivity_exceeded(
    last_recv: std::time::Instant,
    ping_sent: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    now.saturating_duration_since(last_recv) > TIMEOUT_INTERVAL
        || ping_sent.is_some_and(|sent| now.saturating_duration_since(sent) > TIMEOUT_INTERVAL)
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

    #[test]
    fn test_handshake_timeout() {
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(30));
    }

    /// Divi Core CheckForInnactivity: 20 minutes without data, or with a ping unanswered
    #[test]
    fn inactive_peers_time_out_after_twenty_minutes() {
        let start = std::time::Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        assert!(!inactivity_exceeded(start, None, at(20 * 60)));
        assert!(inactivity_exceeded(start, None, at(20 * 60 + 1)));
        // Data keeps coming but the ping is never answered
        assert!(!inactivity_exceeded(at(1199), Some(start), at(1200)));
        assert!(inactivity_exceeded(at(1200), Some(start), at(1201)));
        assert!(!inactivity_exceeded(at(1200), None, at(1201)));
    }
}
