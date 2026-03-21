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
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Best block height known by peer
    pub start_height: u32,
    /// Time of connection
    pub connected_at: Instant,
    /// Last message received time
    pub last_recv: Instant,
    /// Last message sent time
    pub last_send: Instant,
    /// Bytes received
    pub bytes_recv: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Last ping nonce sent
    pub ping_nonce: Option<u64>,
    /// Last ping time
    pub ping_time: Option<Instant>,
    /// Ping latency in milliseconds
    pub ping_latency_ms: Option<u64>,
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
            start_height: 0,
            connected_at: now,
            last_recv: now,
            last_send: now,
            bytes_recv: 0,
            bytes_sent: 0,
            ping_nonce: None,
            ping_time: None,
            ping_latency_ms: None,
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
    },
    /// Peer misbehaved
    Misbehavior {
        peer_id: PeerId,
        score: u32,
        reason: String,
    },
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
}

impl PeerHandle {
    /// Send a message to this peer
    pub async fn send(
        &self,
        msg: NetworkMessage,
    ) -> Result<(), mpsc::error::SendError<NetworkMessage>> {
        self.tx.send(msg).await
    }

    /// Try to send a message without blocking
    pub fn try_send(
        &self,
        msg: NetworkMessage,
    ) -> Result<(), mpsc::error::TrySendError<NetworkMessage>> {
        self.tx.try_send(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
