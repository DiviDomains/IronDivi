// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Who may hold how many connections, for the RPC server and the Electrum
//! server. A table counts the connections of each peer (an IPv4 address, or
//! an IPv6 /64, which is what one subscriber holds), so that one peer cannot
//! take every slot, and keeps the last slots for peers that hold few.
//!
//! The local host is exempt from the per-peer limit, as everything behind a
//! reverse proxy on the same host appears to come from it; it still counts
//! towards the total.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use parking_lot::Mutex;

/// What one table allows
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    /// Connections held at once, all peers together
    pub total: usize,
    /// Connections one peer may hold
    pub per_peer: usize,
    /// The last `reserved` of the `total` go only to peers holding fewer than
    /// `reserved_peer_max` connections
    pub reserved: usize,
    pub reserved_peer_max: usize,
}

/// Why a connection was not admitted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Total,
    PerPeer,
    Reserved,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::Total => "too many connections",
            Refusal::PerPeer => "too many connections from this peer",
            Refusal::Reserved => "remaining connections are kept for new peers",
        })
    }
}

/// An IPv4-mapped IPv6 address as its IPv4 address, an IPv6 address as its
/// /64, an IPv4 address as itself: the unit a peer's connections are counted in
pub fn peer_group(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        },
    }
}

/// Whether `ip` is the local host, mapped IPv4 included
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback(),
            None => v6.is_loopback(),
        },
    }
}

#[derive(Default)]
struct State {
    total: usize,
    peers: HashMap<IpAddr, usize>,
}

/// The connections held now. Admitting a peer returns a guard that gives the
/// connection back when dropped.
pub struct PeerTable {
    limits: PeerLimits,
    state: Mutex<State>,
}

impl PeerTable {
    pub fn new(limits: PeerLimits) -> Arc<Self> {
        Arc::new(PeerTable {
            limits,
            state: Mutex::new(State::default()),
        })
    }

    /// Takes a connection for `ip`, or says why not
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<PeerGuard, Refusal> {
        let local = is_local(ip);
        let group = peer_group(ip);
        let mut state = self.state.lock();
        if state.total >= self.limits.total {
            return Err(Refusal::Total);
        }
        if !local {
            let held = state.peers.get(&group).copied().unwrap_or(0);
            if held >= self.limits.per_peer {
                return Err(Refusal::PerPeer);
            }
            let open_to_all = self.limits.total.saturating_sub(self.limits.reserved);
            if state.total >= open_to_all && held >= self.limits.reserved_peer_max {
                return Err(Refusal::Reserved);
            }
            *state.peers.entry(group).or_insert(0) += 1;
        }
        state.total += 1;
        Ok(PeerGuard {
            table: self.clone(),
            group: (!local).then_some(group),
        })
    }

    /// Connections held now
    pub fn total(&self) -> usize {
        self.state.lock().total
    }

    /// Connections `ip`'s peer holds now (none are counted for the local host)
    pub fn held_by(&self, ip: IpAddr) -> usize {
        self.state
            .lock()
            .peers
            .get(&peer_group(ip))
            .copied()
            .unwrap_or(0)
    }
}

/// One admitted connection
pub struct PeerGuard {
    table: Arc<PeerTable>,
    group: Option<IpAddr>,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut state = self.table.state.lock();
        state.total = state.total.saturating_sub(1);
        if let Some(group) = self.group {
            if let Some(held) = state.peers.get_mut(&group) {
                *held = held.saturating_sub(1);
                if *held == 0 {
                    state.peers.remove(&group);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn table(
        total: usize,
        per_peer: usize,
        reserved: usize,
        reserved_peer_max: usize,
    ) -> Arc<PeerTable> {
        PeerTable::new(PeerLimits {
            total,
            per_peer,
            reserved,
            reserved_peer_max,
        })
    }

    #[test]
    fn one_peer_cannot_take_every_connection() {
        let t = table(10, 3, 0, 0);
        let held: Vec<_> = (0..3)
            .map(|_| t.admit(ip("203.0.113.7")).unwrap())
            .collect();
        assert_eq!(t.admit(ip("203.0.113.7")).err(), Some(Refusal::PerPeer));
        // another peer is served, and the first one again once it lets go
        let other = t.admit(ip("203.0.113.8")).unwrap();
        drop(held);
        assert_eq!(t.held_by(ip("203.0.113.7")), 0);
        assert!(t.admit(ip("203.0.113.7")).is_ok());
        drop(other);
    }

    #[test]
    fn the_last_connections_are_kept_for_peers_that_hold_few() {
        let t = table(10, 9, 2, 2);
        let mut heavy: Vec<_> = (0..8)
            .map(|_| t.admit(ip("198.51.100.1")).unwrap())
            .collect();
        // 8 of 10 are taken; the heavy peer already holds more than the
        // reserve allows
        assert_eq!(t.admit(ip("198.51.100.1")).err(), Some(Refusal::Reserved));
        let a = t.admit(ip("198.51.100.2")).unwrap();
        let b = t.admit(ip("198.51.100.3")).unwrap();
        assert_eq!(t.admit(ip("198.51.100.4")).err(), Some(Refusal::Total));
        heavy.pop();
        drop((a, b));
        assert_eq!(t.total(), 7);
    }

    #[test]
    fn ipv6_peers_are_counted_by_64_and_mapped_addresses_as_ipv4() {
        let t = table(10, 2, 0, 0);
        let _a = t.admit(ip("2001:db8:1:2::1")).unwrap();
        let _b = t.admit(ip("2001:db8:1:2:ffff::9")).unwrap();
        assert_eq!(
            t.admit(ip("2001:db8:1:2::77")).err(),
            Some(Refusal::PerPeer)
        );
        assert!(t.admit(ip("2001:db8:1:3::1")).is_ok());
        let _c = t.admit(ip("192.0.2.5")).unwrap();
        let _d = t.admit(ip("::ffff:192.0.2.5")).unwrap();
        assert_eq!(t.held_by(ip("192.0.2.5")), 2);
        assert_eq!(t.admit(ip("192.0.2.5")).err(), Some(Refusal::PerPeer));
    }

    #[test]
    fn the_local_host_is_exempt_from_the_peer_limits_but_not_the_total() {
        let t = table(4, 1, 1, 1);
        let held: Vec<_> = (0..3).map(|_| t.admit(ip("127.0.0.1")).unwrap()).collect();
        assert_eq!(t.held_by(ip("127.0.0.1")), 0);
        let _six = t.admit(ip("::1")).unwrap();
        assert_eq!(t.admit(ip("127.0.0.1")).err(), Some(Refusal::Total));
        drop(held);
        assert_eq!(t.total(), 1);
    }
}
