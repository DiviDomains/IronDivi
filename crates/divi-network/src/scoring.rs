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

//! Peer scoring and ban management
//!
//! Tracks peer behavior and assigns scores. Peers with low scores
//! are disconnected and potentially banned.

use crate::peer::PeerId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Misbehavior reasons and their penalty scores
#[derive(Debug, Clone, Copy)]
pub enum Misbehavior {
    /// Invalid block header
    InvalidBlockHeader,
    /// Invalid transaction
    InvalidTransaction,
    /// Invalid message format
    InvalidMessage,
    /// Sent unrequested data
    UnrequestedData,
    /// Too many messages (DoS attempt)
    MessageFlood,
    /// Connection timeout
    Timeout,
    /// Protocol violation
    ProtocolViolation,
    /// Sent duplicate data
    DuplicateData,
    /// Invalid proof-of-work/stake
    InvalidProof,
    /// Checkpoint mismatch
    CheckpointMismatch,
}

impl Misbehavior {
    /// Get the penalty score for this misbehavior
    pub fn penalty(&self) -> i32 {
        match self {
            Misbehavior::InvalidBlockHeader => 100,
            Misbehavior::InvalidTransaction => 50,
            Misbehavior::InvalidMessage => 20,
            Misbehavior::UnrequestedData => 10,
            Misbehavior::MessageFlood => 50,
            Misbehavior::Timeout => 5,
            Misbehavior::ProtocolViolation => 100,
            Misbehavior::DuplicateData => 5,
            Misbehavior::InvalidProof => 100,
            Misbehavior::CheckpointMismatch => 100,
        }
    }
}

/// Statistics for a single peer
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Peer ID
    pub peer_id: PeerId,
    /// IP address
    pub ip: IpAddr,
    /// When the peer connected
    pub connected_at: Instant,
    /// Current misbehavior score (higher = worse)
    pub misbehavior_score: i32,
    /// Number of successful blocks received
    pub blocks_received: u64,
    /// Number of successful transactions received
    pub txs_received: u64,
    /// Number of messages received
    pub messages_received: u64,
    /// Average ping latency in milliseconds
    pub avg_latency_ms: u64,
    /// Last ping latency
    pub last_latency_ms: u64,
    /// Number of pings sent
    pub pings_sent: u64,
    /// Number of pongs received
    pub pongs_received: u64,
    /// Last activity time
    pub last_activity: Instant,
    /// Number of connection failures (for retry backoff)
    pub connection_failures: u32,
    /// Last connection attempt
    pub last_connect_attempt: Option<Instant>,
}

impl PeerStats {
    /// Create new peer stats
    pub fn new(peer_id: PeerId, ip: IpAddr) -> Self {
        let now = Instant::now();
        PeerStats {
            peer_id,
            ip,
            connected_at: now,
            misbehavior_score: 0,
            blocks_received: 0,
            txs_received: 0,
            messages_received: 0,
            avg_latency_ms: 0,
            last_latency_ms: 0,
            pings_sent: 0,
            pongs_received: 0,
            last_activity: now,
            connection_failures: 0,
            last_connect_attempt: None,
        }
    }

    /// Record a ping response
    pub fn record_pong(&mut self, latency_ms: u64) {
        self.pongs_received += 1;
        self.last_latency_ms = latency_ms;
        // Rolling average
        if self.avg_latency_ms == 0 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = (self.avg_latency_ms * 7 + latency_ms) / 8;
        }
        self.last_activity = Instant::now();
    }

    /// Record misbehavior
    pub fn record_misbehavior(&mut self, reason: Misbehavior) {
        let penalty = reason.penalty();
        self.misbehavior_score += penalty;
        debug!(
            "Peer {} misbehavior: {:?} (+{} = {})",
            self.peer_id, reason, penalty, self.misbehavior_score
        );
    }

    /// Check if peer should be banned
    pub fn should_ban(&self) -> bool {
        self.misbehavior_score >= 100
    }

    /// Check if peer is responsive
    pub fn is_responsive(&self) -> bool {
        // Consider unresponsive if no activity in 5 minutes
        self.last_activity.elapsed() < Duration::from_secs(300)
    }

    /// Get reliability score (0-100, higher is better)
    pub fn reliability_score(&self) -> u32 {
        let mut score = 100u32;

        // Penalize for misbehavior
        score = score.saturating_sub(self.misbehavior_score as u32);

        // Bonus for successful data
        if self.blocks_received > 10 {
            score = score.saturating_add(5);
        }
        if self.txs_received > 100 {
            score = score.saturating_add(5);
        }

        // Penalize for high latency
        if self.avg_latency_ms > 5000 {
            score = score.saturating_sub(20);
        } else if self.avg_latency_ms > 2000 {
            score = score.saturating_sub(10);
        }

        // Penalize for ping failures
        if self.pings_sent > 5 && self.pongs_received < self.pings_sent / 2 {
            score = score.saturating_sub(15);
        }

        score.min(100)
    }
}

/// Ban entry for an IP address
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// IP address
    pub ip: IpAddr,
    /// When the ban was created
    pub created_at: Instant,
    /// Ban duration
    pub duration: Duration,
    /// Reason for the ban
    pub reason: String,
}

impl BanEntry {
    /// Create a new ban entry
    pub fn new(ip: IpAddr, duration: Duration, reason: impl Into<String>) -> Self {
        BanEntry {
            ip,
            created_at: Instant::now(),
            duration,
            reason: reason.into(),
        }
    }

    /// Check if the ban has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.duration
    }

    /// Get remaining ban time
    pub fn remaining(&self) -> Duration {
        self.duration.saturating_sub(self.created_at.elapsed())
    }
}

/// Default ban duration (24 hours)
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Short ban duration for minor offenses (1 hour)
pub const SHORT_BAN_DURATION: Duration = Duration::from_secs(60 * 60);

/// Peer scoring and ban management
pub struct PeerScoring {
    /// Stats for connected peers
    stats: RwLock<HashMap<PeerId, PeerStats>>,
    /// Banned IP addresses
    bans: RwLock<HashMap<IpAddr, BanEntry>>,
    /// Rate limiting: messages per IP per second
    rate_limits: RwLock<HashMap<IpAddr, RateLimit>>,
    /// Ban threshold score
    ban_threshold: i32,
}

/// Rate limiting state for an IP
#[derive(Debug, Clone)]
struct RateLimit {
    /// Message count in current window
    count: u32,
    /// Window start time
    window_start: Instant,
}

impl Default for PeerScoring {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerScoring {
    /// Create a new peer scoring instance
    pub fn new() -> Self {
        PeerScoring {
            stats: RwLock::new(HashMap::new()),
            bans: RwLock::new(HashMap::new()),
            rate_limits: RwLock::new(HashMap::new()),
            ban_threshold: 100,
        }
    }

    /// Register a new peer
    pub fn register_peer(&self, peer_id: PeerId, ip: IpAddr) {
        self.stats
            .write()
            .insert(peer_id, PeerStats::new(peer_id, ip));
        debug!("Registered peer {} ({})", peer_id, ip);
    }

    /// Unregister a peer
    pub fn unregister_peer(&self, peer_id: PeerId) {
        self.stats.write().remove(&peer_id);
    }

    /// Get peer stats
    pub fn get_stats(&self, peer_id: PeerId) -> Option<PeerStats> {
        self.stats.read().get(&peer_id).cloned()
    }

    /// Get all peer stats
    pub fn all_stats(&self) -> Vec<PeerStats> {
        self.stats.read().values().cloned().collect()
    }

    /// Record misbehavior for a peer
    pub fn record_misbehavior(&self, peer_id: PeerId, reason: Misbehavior) -> bool {
        let mut stats = self.stats.write();
        if let Some(peer_stats) = stats.get_mut(&peer_id) {
            peer_stats.record_misbehavior(reason);

            if peer_stats.should_ban() {
                let ip = peer_stats.ip;
                drop(stats);
                self.ban_ip(
                    ip,
                    DEFAULT_BAN_DURATION,
                    format!("Misbehavior: {:?}", reason),
                );
                return true;
            }
        }
        false
    }

    /// Record successful block receipt
    pub fn record_block(&self, peer_id: PeerId) {
        let mut stats = self.stats.write();
        if let Some(peer_stats) = stats.get_mut(&peer_id) {
            peer_stats.blocks_received += 1;
            peer_stats.last_activity = Instant::now();
        }
    }

    /// Record successful transaction receipt
    pub fn record_transaction(&self, peer_id: PeerId) {
        let mut stats = self.stats.write();
        if let Some(peer_stats) = stats.get_mut(&peer_id) {
            peer_stats.txs_received += 1;
            peer_stats.last_activity = Instant::now();
        }
    }

    /// Record message receipt (for rate limiting)
    pub fn record_message(&self, peer_id: PeerId) {
        let mut stats = self.stats.write();
        if let Some(peer_stats) = stats.get_mut(&peer_id) {
            peer_stats.messages_received += 1;
            peer_stats.last_activity = Instant::now();
        }
    }

    /// Record ping sent
    pub fn record_ping(&self, peer_id: PeerId) {
        let mut stats = self.stats.write();
        if let Some(peer_stats) = stats.get_mut(&peer_id) {
            peer_stats.pings_sent += 1;
        }
    }

    /// Record pong received
    pub fn record_pong(&self, peer_id: PeerId, latency_ms: u64) {
        let mut stats = self.stats.write();
        if let Some(peer_stats) = stats.get_mut(&peer_id) {
            peer_stats.record_pong(latency_ms);
        }
    }

    /// Check rate limit for an IP (returns true if limit exceeded)
    pub fn check_rate_limit(&self, ip: IpAddr, max_per_second: u32) -> bool {
        let mut limits = self.rate_limits.write();
        let now = Instant::now();

        let entry = limits.entry(ip).or_insert(RateLimit {
            count: 0,
            window_start: now,
        });

        // Reset window if more than 1 second has passed
        if entry.window_start.elapsed() >= Duration::from_secs(1) {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        if entry.count > max_per_second {
            warn!(
                "Rate limit exceeded for IP {}: {} msgs/sec",
                ip, entry.count
            );
            true
        } else {
            false
        }
    }

    /// Ban an IP address
    pub fn ban_ip(&self, ip: IpAddr, duration: Duration, reason: impl Into<String>) {
        let reason = reason.into();
        info!("Banning IP {} for {:?}: {}", ip, duration, reason);
        self.bans
            .write()
            .insert(ip, BanEntry::new(ip, duration, reason));
    }

    /// Unban an IP address
    pub fn unban_ip(&self, ip: &IpAddr) -> bool {
        if self.bans.write().remove(ip).is_some() {
            info!("Unbanned IP {}", ip);
            true
        } else {
            false
        }
    }

    /// Check if an IP is banned
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let bans = self.bans.read();
        if let Some(entry) = bans.get(ip) {
            if entry.is_expired() {
                drop(bans);
                self.bans.write().remove(ip);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Get ban info for an IP
    pub fn get_ban(&self, ip: &IpAddr) -> Option<BanEntry> {
        self.bans.read().get(ip).cloned()
    }

    /// Get all active bans
    pub fn list_bans(&self) -> Vec<BanEntry> {
        // Clean up expired bans
        self.bans.write().retain(|_, entry| !entry.is_expired());
        self.bans.read().values().cloned().collect()
    }

    /// Clear all bans
    pub fn clear_bans(&self) {
        self.bans.write().clear();
        info!("Cleared all bans");
    }

    /// Get peers sorted by reliability (best first)
    pub fn peers_by_reliability(&self) -> Vec<(PeerId, u32)> {
        let stats = self.stats.read();
        let mut peers: Vec<_> = stats
            .iter()
            .map(|(id, s)| (*id, s.reliability_score()))
            .collect();
        peers.sort_by(|a, b| b.1.cmp(&a.1));
        peers
    }

    /// Get the best peer for requesting data
    pub fn best_peer(&self) -> Option<PeerId> {
        self.peers_by_reliability().first().map(|(id, _)| *id)
    }

    /// Calculate retry delay with exponential backoff
    pub fn retry_delay(&self, ip: IpAddr) -> Duration {
        let stats = self.stats.read();

        // Find stats for this IP (might be from a previous connection)
        let failures = stats
            .values()
            .find(|s| s.ip == ip)
            .map(|s| s.connection_failures)
            .unwrap_or(0);

        // Exponential backoff: 1s, 2s, 4s, 8s, ... up to 5 minutes
        let base_delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(300);

        let multiplier = 2u32.saturating_pow(failures.min(10));
        let delay = base_delay.saturating_mul(multiplier);

        delay.min(max_delay)
    }

    /// Record a connection failure for retry backoff
    pub fn record_connection_failure(&self, ip: IpAddr) {
        let mut stats = self.stats.write();

        // Find or create stats for this IP
        for stat in stats.values_mut() {
            if stat.ip == ip {
                stat.connection_failures += 1;
                stat.last_connect_attempt = Some(Instant::now());
                return;
            }
        }
    }

    /// Reset connection failures after successful connection
    pub fn reset_connection_failures(&self, peer_id: PeerId) {
        let mut stats = self.stats.write();
        if let Some(stat) = stats.get_mut(&peer_id) {
            stat.connection_failures = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_misbehavior_penalties() {
        assert_eq!(Misbehavior::InvalidBlockHeader.penalty(), 100);
        assert_eq!(Misbehavior::Timeout.penalty(), 5);
    }

    #[test]
    fn test_peer_stats() {
        let mut stats = PeerStats::new(1, "127.0.0.1".parse().unwrap());
        assert_eq!(stats.misbehavior_score, 0);
        assert!(stats.reliability_score() >= 90);

        stats.record_misbehavior(Misbehavior::Timeout);
        assert_eq!(stats.misbehavior_score, 5);
    }

    #[test]
    fn test_peer_scoring() {
        let scoring = PeerScoring::new();
        let peer_id: PeerId = 1;
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        scoring.register_peer(peer_id, ip);
        assert!(scoring.get_stats(peer_id).is_some());

        scoring.record_block(peer_id);
        let stats = scoring.get_stats(peer_id).unwrap();
        assert_eq!(stats.blocks_received, 1);
    }

    #[test]
    fn test_banning() {
        let scoring = PeerScoring::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!scoring.is_banned(&ip));

        scoring.ban_ip(ip, Duration::from_secs(3600), "Test ban");
        assert!(scoring.is_banned(&ip));

        let bans = scoring.list_bans();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, ip);

        scoring.unban_ip(&ip);
        assert!(!scoring.is_banned(&ip));
    }

    #[test]
    fn test_rate_limiting() {
        let scoring = PeerScoring::new();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        // Should not exceed initially
        for _ in 0..10 {
            assert!(!scoring.check_rate_limit(ip, 100));
        }

        // Should exceed after 100 messages
        for _ in 0..100 {
            scoring.check_rate_limit(ip, 100);
        }
        assert!(scoring.check_rate_limit(ip, 100));
    }

    #[test]
    fn test_misbehavior_auto_ban() {
        let scoring = PeerScoring::new();
        let peer_id: PeerId = 2;
        let ip: IpAddr = "10.0.0.3".parse().unwrap();

        scoring.register_peer(peer_id, ip);

        // Should not be banned yet
        let banned = scoring.record_misbehavior(peer_id, Misbehavior::Timeout);
        assert!(!banned);
        assert!(!scoring.is_banned(&ip));

        // Should be banned after serious misbehavior
        let banned = scoring.record_misbehavior(peer_id, Misbehavior::InvalidBlockHeader);
        assert!(banned);
        assert!(scoring.is_banned(&ip));
    }

    #[test]
    fn test_retry_backoff() {
        let scoring = PeerScoring::new();
        let ip: IpAddr = "10.0.0.4".parse().unwrap();

        // Initial delay should be 1 second
        assert_eq!(scoring.retry_delay(ip), Duration::from_secs(1));
    }

    #[test]
    fn test_reliability_score() {
        let mut stats = PeerStats::new(3, "127.0.0.1".parse().unwrap());

        // Good peer should have high score
        assert!(stats.reliability_score() >= 90);

        // Misbehavior reduces score
        stats.record_misbehavior(Misbehavior::InvalidMessage);
        assert!(stats.reliability_score() < 100);

        // Serious misbehavior results in low score
        stats.record_misbehavior(Misbehavior::InvalidBlockHeader);
        assert!(stats.reliability_score() < 50);
    }
}
