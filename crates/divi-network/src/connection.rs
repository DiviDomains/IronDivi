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

use crate::codec::DiviCodec;
use crate::constants::{services, Magic, MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION};
use crate::error::NetworkError;
use crate::message::NetAddr;
use crate::peer::{new_peer_id, PeerDirection, PeerEvent, PeerHandle, PeerId, PeerInfo, PeerState};
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
use tracing::{debug, error, info, trace, warn};

/// Timeout for connection establishment
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for handshake completion
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for reading a message
const READ_TIMEOUT: Duration = Duration::from_secs(90);

/// Interval for proactive keepalive pings (must be < C++ node's 60s inactivity timeout)
const PING_INTERVAL: Duration = Duration::from_secs(30);

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
}

impl Connection {
    /// Connect to a peer (outbound)
    pub async fn connect(
        addr: SocketAddr,
        magic: Magic,
        our_height: u32,
        event_tx: broadcast::Sender<PeerEvent>,
        shutdown_rx: broadcast::Receiver<()>,
        total_bytes_sent: Arc<AtomicU64>,
        total_bytes_recv: Arc<AtomicU64>,
    ) -> Result<(Self, PeerHandle), NetworkError> {
        info!("Connecting to peer {}", addr);

        // Establish TCP connection with timeout
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::Connection(e.to_string()))?;

        // Set TCP options
        stream.set_nodelay(true)?;

        let peer_id = new_peer_id();
        let info = PeerInfo::new_outbound(peer_id, addr);

        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);

        let handle = PeerHandle {
            id: peer_id,
            addr,
            tx: outbound_tx,
            inbound: false, // This is an outbound connection (we connected to them)
        };

        let conn = Connection {
            peer_id,
            stream,
            info,
            magic,
            our_height,
            outbound_rx,
            event_tx,
            shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
        };

        Ok((conn, handle))
    }

    /// Accept an inbound connection
    pub async fn accept(
        stream: TcpStream,
        magic: Magic,
        our_height: u32,
        event_tx: broadcast::Sender<PeerEvent>,
        shutdown_rx: broadcast::Receiver<()>,
        total_bytes_sent: Arc<AtomicU64>,
        total_bytes_recv: Arc<AtomicU64>,
    ) -> Result<(Self, PeerHandle), NetworkError> {
        let addr = stream.peer_addr()?;
        info!("Accepting connection from {}", addr);

        stream.set_nodelay(true)?;

        let peer_id = new_peer_id();
        let info = PeerInfo::new_inbound(peer_id, addr);

        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER);

        let handle = PeerHandle {
            id: peer_id,
            addr,
            tx: outbound_tx,
            inbound: true, // This is an inbound connection (they connected to us)
        };

        let conn = Connection {
            peer_id,
            stream,
            info,
            magic,
            our_height,
            outbound_rx,
            event_tx,
            shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
        };

        Ok((conn, handle))
    }

    /// Run the connection handler
    pub async fn run(mut self) -> Result<(), NetworkError> {
        // Perform handshake
        if let Err(e) = self.handshake().await {
            error!("Handshake failed with {}: {}", self.info.addr, e);
            let _ = self.event_tx.send(PeerEvent::Disconnected {
                peer_id: self.peer_id,
                reason: e.to_string(),
            });
            return Err(e);
        }

        info!(
            "Handshake complete with {} ({}), height {}",
            self.info.addr,
            self.info.user_agent().unwrap_or("unknown"),
            self.info.start_height
        );

        // Send BIP 130 sendheaders message
        if let Err(e) = self.send_message(NetworkMessage::SendHeaders).await {
            debug!("Failed to send sendheaders to {}: {}", self.info.addr, e);
        }

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

        // Validate version
        if their_version.version < MIN_PEER_PROTO_VERSION as i32 {
            return Err(NetworkError::VersionMismatch {
                peer: their_version.version,
                required: MIN_PEER_PROTO_VERSION as i32,
            });
        }

        // Store their version info
        self.info.services = their_version.services;
        self.info.start_height = their_version.start_height as u32;
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

    /// Send our version message
    async fn send_version(&mut self) -> Result<(), NetworkError> {
        let version = VersionMessage {
            version: PROTOCOL_VERSION as i32,
            services: services::NODE_NETWORK,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            addr_recv: NetAddr::from_ipv4([0, 0, 0, 0], 0, 0),
            addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, services::NODE_NETWORK),
            nonce: rand::random(),
            user_agent: USER_AGENT.to_string(),
            start_height: self.our_height as i32,
            relay: true,
        };

        self.send_message(NetworkMessage::Version(version)).await
    }

    /// Wait for version message (during handshake - uses blocking read, ok because no select!)
    async fn recv_version(&mut self) -> Result<VersionMessage, NetworkError> {
        loop {
            let msg = self.read_message_handshake().await?;
            match msg {
                NetworkMessage::Version(v) => return Ok(v),
                _ => {
                    debug!("Ignoring {} during handshake", msg.command());
                }
            }
        }
    }

    /// Wait for verack message (during handshake - uses blocking read, ok because no select!)
    async fn recv_verack(&mut self) -> Result<(), NetworkError> {
        loop {
            let msg = self.read_message_handshake().await?;
            match msg {
                NetworkMessage::Verack => return Ok(()),
                _ => {
                    debug!("Ignoring {} during handshake", msg.command());
                }
            }
        }
    }

    /// Read a message during handshake (not cancellation-safe, but OK since no select!)
    async fn read_message_handshake(&mut self) -> Result<NetworkMessage, NetworkError> {
        use crate::message::{MessageHeader, HEADER_SIZE};
        use tokio::io::AsyncReadExt;

        // Read header
        let mut header_buf = [0u8; HEADER_SIZE];
        self.stream.read_exact(&mut header_buf).await?;
        let header = MessageHeader::deserialize(&header_buf)?;

        // Validate magic
        if !header.validate_magic(&self.magic) {
            return Err(NetworkError::InvalidMagic);
        }

        // Read payload
        let mut payload = vec![0u8; header.payload_size as usize];
        if header.payload_size > 0 {
            self.stream.read_exact(&mut payload).await?;
        }

        // Validate checksum
        if !header.validate_checksum(&payload) {
            return Err(NetworkError::InvalidChecksum);
        }

        // Update stats
        let bytes_received = HEADER_SIZE as u64 + header.payload_size as u64;
        self.info.bytes_recv += bytes_received;
        self.info.last_recv = std::time::Instant::now();
        self.total_bytes_recv
            .fetch_add(bytes_received, Ordering::Relaxed);

        // Deserialize
        let command = header.command_string();
        NetworkMessage::deserialize(&command, &payload)
    }

    /// Main message processing loop using cancellation-safe FramedRead
    async fn message_loop(self) -> Result<(), NetworkError> {
        let Connection {
            peer_id,
            stream,
            mut info,
            magic,
            our_height: _,
            mut outbound_rx,
            event_tx,
            mut shutdown_rx,
            total_bytes_sent,
            total_bytes_recv,
        } = self;

        // Split stream for concurrent read/write
        let (reader, mut writer) = tokio::io::split(stream);

        // Wrap reader in FramedRead with our codec - this is CANCELLATION SAFE!
        let codec = DiviCodec::new(magic);
        let mut framed = FramedRead::new(reader, codec);

        // Proactive keepalive timer to prevent C++ node's inactivity timeout (~60s)
        let mut ping_timer = tokio::time::interval(PING_INTERVAL);
        ping_timer.tick().await; // Consume the immediate first tick

        loop {
            tokio::select! {
                biased;

                // Check for shutdown signal (highest priority)
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, disconnecting from {}", info.addr);
                    break;
                }

                // Handle outgoing messages
                Some(msg) = outbound_rx.recv() => {
                    if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, msg).await {
                        error!("Failed to send message to {}: {}", info.addr, e);
                        break;
                    }
                }

                // Proactive keepalive ping
                _ = ping_timer.tick() => {
                    let nonce = rand::random();
                    info.ping_nonce = Some(nonce);
                    info.ping_time = Some(std::time::Instant::now());
                    if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, NetworkMessage::Ping(nonce)).await {
                        error!("Failed to send keepalive ping to {}: {}", info.addr, e);
                        break;
                    }
                }

                // Handle incoming messages - framed.next() IS CANCELLATION SAFE!
                result = timeout(READ_TIMEOUT, framed.next()) => {
                    match result {
                        Ok(Some(Ok(msg))) => {
                            // Calculate approximate bytes received for this message
                            // Note: This is an approximation based on the command.
                            // For accurate tracking, we'd need to track bytes in the codec itself.
                            // For now, we use the message size as a proxy (header + payload).
                            use crate::message::HEADER_SIZE;
                            let msg_bytes = msg.to_bytes(magic).map(|b| b.len()).unwrap_or(0);
                            let bytes_received = msg_bytes as u64;

                            // Update stats
                            info.bytes_recv += bytes_received;
                            info.last_recv = std::time::Instant::now();
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
                            error!("Error reading from {}: {}", info.addr, e);
                            break;
                        }
                        Ok(None) => {
                            // Stream ended (connection closed)
                            info!("Connection closed by {}", info.addr);
                            break;
                        }
                        Err(_) => {
                            // Timeout - send ping
                            debug!("Read timeout from {}, sending ping", info.addr);
                            let nonce = rand::random();
                            info.ping_nonce = Some(nonce);
                            info.ping_time = Some(std::time::Instant::now());
                            if let Err(e) = Self::write_message(&mut writer, &mut info, magic, &total_bytes_sent, NetworkMessage::Ping(nonce)).await {
                                error!("Failed to send ping to {}: {}", info.addr, e);
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
                            info.ping_latency_ms = Some(ping_time.elapsed().as_millis() as u64);
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
        self.total_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);

        trace!("Sent {} to {}", msg.command(), self.info.addr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_timeout() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn test_handshake_timeout() {
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(30));
    }
}
