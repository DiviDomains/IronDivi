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

//! Peer representation and state management
//!
//! Represents a connected peer on the Divi network.

use crate::version::VersionMessage;
use crate::NetworkMessage;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::mpsc;

/// Unique identifier for a peer
pub type PeerId = u64;

/// Global peer ID counter
static PEER_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a new unique peer ID
pub fn new_peer_id() -> PeerId {
    PEER_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// State of a peer connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Initial state, TCP connection being established
    Connecting,
    /// Version message sent, awaiting their version
    VersionSent,
    /// Received their version, sent verack, awaiting their verack
    VersionReceived,
    /// Handshake complete, fully connected
    Connected,
    /// Disconnecting
    Disconnecting,
    /// Disconnected
    Disconnected,
}

/// Direction of the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    /// We initiated the connection
    Outbound,
    /// They connected to us
    Inbound,
}

/// Information about a connected peer
#[derive(Debug)]
pub struct PeerInfo {
    /// Unique peer identifier
    pub id: PeerId,
    /// Remote address
    pub addr: SocketAddr,
    /// Connection direction
    pub direction: PeerDirection,
    /// Current state
    pub state: PeerState,
    /// Version info (after handshake)
    pub version: Option<VersionMessage>,
    /// Services offered by the peer
    pub services: u64,
    /// The height the peer named in its version message; -1 before one
    /// came or when it named none (Divi Core nStartingHeight, Node.cpp:561)
    pub start_height: i32,
    /// Time of connection
    pub connected_at: Instant,
    /// Last message received time
    pub last_recv: Instant,
    /// Last message sent time
    pub last_send: Instant,
    /// The node's clock at the connection, the last message received and the
    /// last sent, in Unix seconds (Core's nTimeConnected, nLastRecv, nLastSend
    /// from GetTime, which setmocktime sets)
    pub conn_unix: u64,
    pub last_recv_unix: u64,
    pub last_send_unix: u64,
    /// Bytes received
    pub bytes_recv: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Last ping nonce sent
    pub ping_nonce: Option<u64>,
    /// Last ping time
    pub ping_time: Option<Instant>,
    /// Last ping round trip in microseconds
    pub ping_latency_us: Option<u64>,
    /// Peer clock minus ours, in seconds, from its version message
    pub time_offset: i64,
    /// Misbehavior score (for banning)
    pub misbehavior_score: u32,
    /// Last message command received (for debugging)
    pub last_message_command: Option<String>,
    /// Last message payload size (for debugging)
    pub last_message_size: u32,
}

impl PeerInfo {
    /// Create new peer info for an outbound connection
    pub fn new_outbound(id: PeerId, addr: SocketAddr) -> Self {
        let now = Instant::now();
        PeerInfo {
            id,
            addr,
            direction: PeerDirection::Outbound,
            state: PeerState::Connecting,
            version: None,
            services: 0,
            start_height: -1,
            connected_at: now,
            last_recv: now,
            last_send: now,
            conn_unix: unix_now(),
            last_recv_unix: unix_now(),
            last_send_unix: unix_now(),
            bytes_recv: 0,
            bytes_sent: 0,
            ping_nonce: None,
            ping_time: None,
            ping_latency_us: None,
            time_offset: 0,
            misbehavior_score: 0,
            last_message_command: None,
            last_message_size: 0,
        }
    }

    /// Create new peer info for an inbound connection
    pub fn new_inbound(id: PeerId, addr: SocketAddr) -> Self {
        let mut info = Self::new_outbound(id, addr);
        info.direction = PeerDirection::Inbound;
        info
    }

    /// Check if handshake is complete
    pub fn is_connected(&self) -> bool {
        self.state == PeerState::Connected
    }

    /// Get user agent string
    pub fn user_agent(&self) -> Option<&str> {
        self.version.as_ref().map(|v| v.user_agent.as_str())
    }

    /// Add misbehavior score
    pub fn add_misbehavior(&mut self, score: u32) -> u32 {
        self.misbehavior_score = self.misbehavior_score.saturating_add(score);
        self.misbehavior_score
    }

    /// Check if peer should be banned (score >= 100)
    pub fn should_ban(&self) -> bool {
        self.misbehavior_score >= 100
    }
}

/// Message to send to a peer
#[derive(Debug)]
pub struct PeerMessage {
    /// Target peer ID
    pub peer_id: PeerId,
    /// Message to send
    pub message: NetworkMessage,
}

/// Event from the peer handler
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// Peer connected (handshake complete)
    Connected {
        peer_id: PeerId,
        addr: SocketAddr,
        version: VersionMessage,
    },
    /// Peer disconnected
    Disconnected { peer_id: PeerId, reason: String },
    /// Message received from peer
    Message {
        peer_id: PeerId,
        message: NetworkMessage,
        /// Its size on the wire, header included
        size: u64,
    },
    /// Peer misbehaved
    Misbehavior {
        peer_id: PeerId,
        score: u32,
        reason: String,
    },
}

/// Live per-peer statistics shared between the connection task and RPC readers
#[derive(Debug, Default)]
pub struct LivePeerStats {
    /// Bytes sent to the peer
    pub bytes_sent: AtomicU64,
    /// Bytes received from the peer
    pub bytes_recv: AtomicU64,
    /// Unix time of the last send (0 = never)
    pub last_send: AtomicU64,
    /// Unix time of the last receive (0 = never)
    pub last_recv: AtomicU64,
    /// Unix time the connection was established
    pub conn_time: AtomicU64,
    /// Last ping round trip in microseconds (0 = none yet)
    pub ping_us: AtomicU64,
    /// Unix time in microseconds the outstanding ping was sent (0 = none outstanding)
    pub ping_sent_us: AtomicU64,
    /// Peer clock minus ours, in seconds, from its version message
    pub time_offset: AtomicI64,
    /// Peer's advertised protocol version
    pub version: AtomicU64,
    /// Peer's advertised services
    pub services: AtomicU64,
    /// Peer's advertised start height (-1 when it named none)
    pub start_height: AtomicI64,
    /// Peer's user agent
    pub subver: parking_lot::Mutex<String>,
    /// Bytes and number of this peer's messages handed to the node and not
    /// yet taken: the peer is not read while they pass the limits
    /// (crate::buffers)
    pub recv_queued_bytes: AtomicU64,
    pub recv_queued_msgs: AtomicU64,
    /// This peer's messages handed to the node, and taken by it once handled,
    /// since the connection began: what the connection answers itself (a
    /// pong, a reject) waits until the node has handled every message before
    /// it, as Divi Core handles a peer's messages one at a time, in order
    /// (main.cpp:1023-1077)
    pub recv_handed: AtomicU64,
    pub recv_taken: AtomicU64,
    /// Woken when the node takes one of this peer's messages
    pub recv_space: tokio::sync::Notify,
    /// Bytes queued for the peer and not yet written (Divi Core nSendSize)
    pub send_queued_bytes: AtomicU64,
    /// The peer's bloom filter and transaction relay flag (not published by
    /// the connection: the filter messages change them)
    pub bloom: crate::bloom::PeerBloom,
}

impl LivePeerStats {
    /// Whether the peer may be read: its waiting messages are within
    /// -maxreceivebuffer and MAX_QUEUED_MESSAGES
    pub fn can_receive(&self) -> bool {
        self.recv_queued_bytes.load(Ordering::Relaxed) <= crate::buffers::max_receive_buffer()
            && self.recv_queued_msgs.load(Ordering::Relaxed) < crate::buffers::MAX_QUEUED_MESSAGES
    }

    /// A message of `bytes` handed to the node
    pub fn message_queued(&self, bytes: u64) {
        self.recv_queued_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.recv_queued_msgs.fetch_add(1, Ordering::Relaxed);
        self.recv_handed.fetch_add(1, Ordering::Relaxed);
    }

    /// The node took a message of `bytes`, and has handled it
    pub fn message_taken(&self, bytes: u64) {
        // Never below 0: a count cleared after missed messages may be smaller
        let sub = |a: &AtomicU64, n: u64| {
            let mut v = a.load(Ordering::Relaxed);
            while let Err(now) = a.compare_exchange_weak(
                v,
                v.saturating_sub(n),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                v = now;
            }
        };
        sub(&self.recv_queued_bytes, bytes);
        sub(&self.recv_queued_msgs, 1);
        // Release: what the node queued for the peer before is seen with it
        self.recv_taken.fetch_add(1, Ordering::Release);
        self.recv_space.notify_one();
    }

    /// A queued message of `bytes` was written (or will not be)
    pub fn send_written(&self, bytes: u64) {
        let mut v = self.send_queued_bytes.load(Ordering::Relaxed);
        while let Err(now) = self.send_queued_bytes.compare_exchange_weak(
            v,
            v.saturating_sub(bytes),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            v = now;
        }
        // Room again: getdata waiting for this peer can be answered
        let max = crate::buffers::max_send_buffer();
        if v >= max && v.saturating_sub(bytes) < max {
            crate::buffers::send_space().notify_one();
        }
    }

    /// Forget what is waiting (the node missed messages it cannot count)
    pub fn clear_queued(&self) {
        self.recv_queued_bytes.store(0, Ordering::Relaxed);
        self.recv_queued_msgs.store(0, Ordering::Relaxed);
        self.recv_taken
            .store(self.recv_handed.load(Ordering::Relaxed), Ordering::Release);
        self.recv_space.notify_one();
    }
}

/// The node's clock in Unix seconds (mocked by setmocktime)
pub fn unix_now() -> u64 {
    divi_primitives::clock::now().max(0) as u64
}

/// Current Unix time in microseconds
pub fn unix_now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

impl PeerInfo {
    /// Publish this connection's counters to the shared stats
    pub fn publish(&self, live: &LivePeerStats) {
        live.bytes_sent.store(self.bytes_sent, Ordering::Relaxed);
        live.bytes_recv.store(self.bytes_recv, Ordering::Relaxed);
        live.last_send.store(self.last_send_unix, Ordering::Relaxed);
        live.last_recv.store(self.last_recv_unix, Ordering::Relaxed);
        live.conn_time.store(self.conn_unix, Ordering::Relaxed);
        live.ping_us
            .store(self.ping_latency_us.unwrap_or(0), Ordering::Relaxed);
        let now_us = unix_now_us();
        let ping_sent_us = match (self.ping_nonce, self.ping_time) {
            (Some(_), Some(t)) => now_us.saturating_sub(t.elapsed().as_micros() as u64),
            _ => 0,
        };
        live.ping_sent_us.store(ping_sent_us, Ordering::Relaxed);
        live.time_offset.store(self.time_offset, Ordering::Relaxed);
        live.services.store(self.services, Ordering::Relaxed);
        live.start_height
            .store(self.start_height as i64, Ordering::Relaxed);
        if let Some(v) = &self.version {
            live.version.store(v.version as u64, Ordering::Relaxed);
            let mut sv = live.subver.lock();
            if *sv != v.user_agent {
                *sv = v.user_agent.clone();
            }
        }
    }
}

/// Handle for sending messages to a peer
#[derive(Debug, Clone)]
pub struct PeerHandle {
    /// Peer ID
    pub id: PeerId,
    /// Peer address
    pub addr: SocketAddr,
    /// Channel to send messages
    pub tx: mpsc::Sender<NetworkMessage>,
    /// Whether this is an inbound connection (they connected to us)
    pub inbound: bool,
    /// Live statistics published by the connection task
    pub stats: std::sync::Arc<LivePeerStats>,
}

impl PeerHandle {
    /// Send a message to this peer
    // SendError hands the unsent message back to the caller; boxing it would
    // change every call site for no runtime benefit.
    #[allow(clippy::result_large_err)]
    pub async fn send(
        &self,
        msg: NetworkMessage,
    ) -> Result<(), mpsc::error::SendError<NetworkMessage>> {
        let size = msg.wire_size();
        self.stats
            .send_queued_bytes
            .fetch_add(size, Ordering::Relaxed);
        let sent = self.tx.send(msg).await;
        if sent.is_err() {
            self.stats.send_written(size);
        }
        sent
    }

    /// Try to send a message without blocking
    pub fn try_send(
        &self,
        msg: NetworkMessage,
    ) -> Result<(), Box<mpsc::error::TrySendError<NetworkMessage>>> {
        let size = msg.wire_size();
        self.stats
            .send_queued_bytes
            .fetch_add(size, Ordering::Relaxed);
        self.tx.try_send(msg).map_err(|e| {
            self.stats.send_written(size);
            Box::new(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_is_not_read_while_the_node_has_its_messages_waiting() {
        let stats = LivePeerStats::default();
        assert!(stats.can_receive());
        for _ in 0..crate::buffers::MAX_QUEUED_MESSAGES {
            stats.message_queued(100);
        }
        assert!(!stats.can_receive());
        stats.message_taken(100);
        assert!(stats.can_receive());
        // Over -maxreceivebuffer in bytes with one message waiting
        stats.clear_queued();
        stats.message_queued(crate::buffers::max_receive_buffer() + 1);
        assert!(!stats.can_receive());
        stats.message_taken(crate::buffers::max_receive_buffer() + 1);
        assert!(stats.can_receive());
        // A count cleared after missed messages does not go below zero
        stats.message_taken(500);
        assert_eq!(stats.recv_queued_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(stats.recv_queued_msgs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_peer_id_generation() {
        let id1 = new_peer_id();
        let id2 = new_peer_id();
        assert_ne!(id1, id2);
        assert!(id2 > id1);
    }

    #[test]
    fn test_peer_info_outbound() {
        let addr: SocketAddr = "127.0.0.1:51472".parse().unwrap();
        let info = PeerInfo::new_outbound(1, addr);

        assert_eq!(info.direction, PeerDirection::Outbound);
        assert_eq!(info.state, PeerState::Connecting);
        assert!(!info.is_connected());
    }

    #[test]
    fn test_peer_info_inbound() {
        let addr: SocketAddr = "192.168.1.1:51472".parse().unwrap();
        let info = PeerInfo::new_inbound(2, addr);

        assert_eq!(info.direction, PeerDirection::Inbound);
    }

    #[test]
    fn test_misbehavior_scoring() {
        let addr: SocketAddr = "127.0.0.1:51472".parse().unwrap();
        let mut info = PeerInfo::new_outbound(1, addr);

        assert!(!info.should_ban());

        info.add_misbehavior(50);
        assert!(!info.should_ban());

        info.add_misbehavior(50);
        assert!(info.should_ban());
    }
}
