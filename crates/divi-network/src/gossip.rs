// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Address gossip per peer, as Divi Core's CNode keeps it: the addresses a
//! peer is known to have (setAddrKnown, Node.cpp:563, :901-904), whether a
//! getaddr to it is still unanswered (fGetAddr, main.cpp:441, :554-555) and
//! whether it is a one-shot peer, dropped after its addr (fOneShot,
//! main.cpp:556-557). From these: where an `addr` message goes on
//! (main.cpp:521-560, net.cpp:1498-1522) and what a getaddr is answered with
//! (main.cpp:863-869, Node.cpp:919-932, main.cpp:1087-1104).

use crate::local::is_routable;
use crate::message::NetAddr;
use crate::peer::PeerId;
use parking_lot::Mutex;
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

/// At most this many addresses in one addr message, and in a getaddr
/// answer (MAX_ADDR_TO_SEND, Node.cpp:922)
pub const MAX_ADDR_TO_SEND: usize = 1000;
/// An addr message with more is refused (main.cpp:529)
pub const MAX_ADDR_MESSAGE: usize = 1000;
/// Addresses of a message of at most this many are relayed (main.cpp:545)
const RELAY_MAX_ENTRIES: usize = 10;
/// The addresses a peer is known to have, the oldest forgotten first
/// (mruset setAddrKnown(5000), Node.cpp:563)
const KNOWN_CAPACITY: usize = 5000;
/// Relayed only if newer than this (main.cpp:538)
const RELAY_MAX_AGE: u32 = 10 * 60;

type Key = ([u8; 16], u16);

fn key(a: &NetAddr) -> Key {
    (a.ip, a.port)
}

fn ip_of(b: &[u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(*b);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// A network irondivid connects to: IPv4 and IPv6, not onion (no onion
/// proxy, so getnetworkinfo lists onion as not reachable). Divi Core keeps
/// no address of a network it cannot reach and relays it to one peer only
/// (main.cpp:544-551).
pub fn reachable(a: &NetAddr) -> bool {
    !crate::local::is_tor(&a.ip)
}

/// An addr time as Divi Core reads it: at or before 100000000, or more than
/// ten minutes ahead, it is five days ago (main.cpp:540-541)
pub fn read_time(time: u32, now: u32) -> u32 {
    if time <= 100_000_000 || time > now.saturating_add(10 * 60) {
        now.saturating_sub(5 * 24 * 60 * 60)
    } else {
        time
    }
}

#[derive(Default)]
struct Known {
    order: VecDeque<Key>,
    set: HashSet<Key>,
}

impl Known {
    fn contains(&self, k: &Key) -> bool {
        self.set.contains(k)
    }

    fn insert(&mut self, k: Key) {
        if self.set.insert(k) {
            self.order.push_back(k);
            if self.order.len() > KNOWN_CAPACITY {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

#[derive(Default)]
struct Peer {
    known: Known,
    asked: bool,
    one_shot: bool,
}

/// What came of an addr message
#[derive(Debug, Default, PartialEq)]
pub struct Received {
    /// The addresses to keep in the book, with their times as read
    pub keep: Vec<(u32, NetAddr)>,
    /// Addresses to send on, each with the peer to send them to
    pub relay: Vec<(PeerId, Vec<(u32, NetAddr)>)>,
    /// The sender is a one-shot peer: drop it now
    pub disconnect: bool,
}

/// The gossip state of every connected peer
pub struct Gossip {
    peers: Mutex<HashMap<PeerId, Peer>>,
    salt: [u8; 32],
}

impl Default for Gossip {
    fn default() -> Self {
        Self::new()
    }
}

impl Gossip {
    pub fn new() -> Self {
        Gossip {
            peers: Mutex::new(HashMap::new()),
            salt: rand::thread_rng().gen(),
        }
    }

    /// A peer finished its handshake; a one-shot peer goes after its addr
    pub fn connected(&self, peer: PeerId, one_shot: bool) {
        self.peers.lock().entry(peer).or_default().one_shot = one_shot;
    }

    /// A peer left
    pub fn disconnected(&self, peer: PeerId) {
        self.peers.lock().remove(&peer);
    }

    /// A getaddr was sent to the peer (fGetAddr, main.cpp:441)
    pub fn asked(&self, peer: PeerId) {
        self.peers.lock().entry(peer).or_default().asked = true;
    }

    /// An addr message of at most 1000 entries from `from`, while `peers` are
    /// connected (main.cpp:533-557): each address is known to the sender; one
    /// of a message of at most 10, routable, newer than ten minutes, and not
    /// in answer to our getaddr, goes to the two peers (one if its network is
    /// not reachable) its hash picks for the day, the sender among them, but
    /// not to one that has it; one of a reachable network is kept
    /// `now` is the network-adjusted clock, which dates the addresses
    /// (main.cpp:536); `day_now` the node's own, which picks the day's peers
    /// (net.cpp:1508)
    pub fn received(
        &self,
        from: PeerId,
        addrs: &[(u32, NetAddr)],
        peers: &[PeerId],
        now: u32,
        day_now: u32,
    ) -> Received {
        let mut map = self.peers.lock();
        let mut out = Received::default();
        let asked = map.get(&from).is_some_and(|p| p.asked);
        let mut relay: HashMap<PeerId, Vec<(u32, NetAddr)>> = HashMap::new();
        for (time, addr) in addrs {
            let time = read_time(*time, now);
            map.entry(from).or_default().known.insert(key(addr));
            let reachable = reachable(addr);
            if time > now.saturating_sub(RELAY_MAX_AGE)
                && !asked
                && addrs.len() <= RELAY_MAX_ENTRIES
                && is_routable(&ip_of(&addr.ip))
            {
                for to in self.relay_to(addr, peers, if reachable { 2 } else { 1 }, day_now) {
                    let p = map.entry(to).or_default();
                    if !p.known.contains(&key(addr)) {
                        p.known.insert(key(addr));
                        relay.entry(to).or_default().push((time, addr.clone()));
                    }
                }
            }
            if reachable {
                out.keep.push((time, addr.clone()));
            }
        }
        let sender = map.entry(from).or_default();
        if addrs.len() < MAX_ADDR_MESSAGE {
            sender.asked = false;
        }
        out.disconnect = sender.one_shot;
        out.relay = relay.into_iter().collect();
        out.relay.sort_by_key(|(p, _)| *p);
        out
    }

    /// The `n` peers an address goes to: the same for a day at a time
    /// (DeterministicallyRelayAddressToLimitedPeers, net.cpp:1498-1522)
    fn relay_to(&self, addr: &NetAddr, peers: &[PeerId], n: usize, now: u32) -> Vec<PeerId> {
        let addr_hash = u64::from_le_bytes(
            divi_crypto::double_sha256(&addr.ip)[..8]
                .try_into()
                .expect("8 bytes"),
        );
        let day = (now as u64).wrapping_add(addr_hash) / (24 * 60 * 60);
        let mut ranked: Vec<([u8; 32], PeerId)> = peers
            .iter()
            .map(|&p| {
                let mut h = self.salt.to_vec();
                h.extend_from_slice(&addr.ip);
                h.extend_from_slice(&day.to_le_bytes());
                h.extend_from_slice(&p.to_le_bytes());
                (divi_crypto::double_sha256(&h), p)
            })
            .collect();
        ranked.sort();
        ranked.into_iter().take(n).map(|(_, p)| p).collect()
    }

    /// The answer to a getaddr from `to`, from the book's sample: the
    /// addresses it is not known to have, at most 1000 (later ones take the
    /// place of one at random), each then known to it (main.cpp:865-868,
    /// Node.cpp:919-932, main.cpp:1087-1104)
    pub fn answer(&self, to: PeerId, sample: Vec<(u32, NetAddr)>) -> Vec<(u32, NetAddr)> {
        let mut map = self.peers.lock();
        let peer = map.entry(to).or_default();
        let mut rng = rand::thread_rng();
        let mut out: Vec<(u32, NetAddr)> = Vec::new();
        for entry in sample {
            if peer.known.contains(&key(&entry.1)) {
                continue;
            }
            if out.len() >= MAX_ADDR_TO_SEND {
                let at = rng.gen_range(0..out.len());
                out[at] = entry;
            } else {
                out.push(entry);
            }
        }
        out.retain(|(_, a)| {
            let k = key(a);
            let new = !peer.known.contains(&k);
            peer.known.insert(k);
            new
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u32 = 1_700_000_000;

    fn public(k: u16) -> NetAddr {
        NetAddr::from_ipv4([11 + (k / 256) as u8, (k % 256) as u8, 7, 9], 51476, 1)
    }

    fn onion() -> NetAddr {
        let ip: Ipv6Addr = "fd87:d87e:eb43:1234:5678:9abc:def0:1234".parse().unwrap();
        NetAddr {
            services: 1,
            ip: ip.octets(),
            port: 51476,
        }
    }

    fn connected(g: &Gossip, peers: &[PeerId]) {
        for &p in peers {
            g.connected(p, false);
        }
    }

    #[test]
    fn times_are_read_as_divid_reads_them() {
        let five_days = 5 * 24 * 60 * 60;
        assert_eq!(read_time(0, NOW), NOW - five_days);
        assert_eq!(read_time(100_000_000, NOW), NOW - five_days);
        assert_eq!(read_time(NOW + 600, NOW), NOW + 600);
        assert_eq!(read_time(NOW + 601, NOW), NOW - five_days);
        assert_eq!(read_time(NOW - 3600, NOW), NOW - 3600);
    }

    #[test]
    fn a_short_fresh_message_goes_to_the_other_peer_not_back() {
        let g = Gossip::new();
        connected(&g, &[1, 2]);
        let addrs: Vec<_> = (0..10).map(|k| (NOW, public(k))).collect();
        let r = g.received(1, &addrs, &[1, 2], NOW, NOW);
        // With two peers both are picked: the sender has them, so only peer 2 gets them
        assert_eq!(r.relay, vec![(2, addrs.clone())]);
        assert_eq!(r.keep, addrs);
        // Peer 2 is known to have them now: not sent again
        let again = g.received(1, &addrs[..1], &[1, 2], NOW, NOW);
        assert!(again.relay.is_empty());
    }

    #[test]
    fn what_is_not_relayed() {
        let g = Gossip::new();
        connected(&g, &[1, 2]);
        // more than 10 entries
        let eleven: Vec<_> = (0..11).map(|k| (NOW, public(k))).collect();
        assert!(g.received(1, &eleven, &[1, 2], NOW, NOW).relay.is_empty());
        // older than ten minutes, or a time read as five days ago
        for t in [NOW - 601, NOW + 601, 0] {
            assert!(g
                .received(1, &[(t, public(20))], &[1, 2], NOW, NOW)
                .relay
                .is_empty());
        }
        // not routable
        let local = NetAddr::from_ipv4([10, 1, 2, 3], 51476, 1);
        assert!(g
            .received(1, &[(NOW, local)], &[1, 2], NOW, NOW)
            .relay
            .is_empty());
        // in answer to our getaddr, until a message of fewer than 1000 came
        g.asked(1);
        assert!(g
            .received(1, &[(NOW, public(30))], &[1, 2], NOW, NOW)
            .relay
            .is_empty());
        assert_eq!(
            g.received(1, &[(NOW, public(31))], &[1, 2], NOW, NOW)
                .relay
                .len(),
            1
        );
    }

    #[test]
    fn an_onion_address_is_not_kept_and_goes_to_one_peer() {
        let g = Gossip::new();
        connected(&g, &[1, 2, 3]);
        let r = g.received(1, &[(NOW, onion())], &[1, 2, 3], NOW, NOW);
        assert!(r.keep.is_empty());
        assert!(r.relay.len() <= 1);
        assert!(!reachable(&onion()));
        assert!(reachable(&public(1)));
    }

    #[test]
    fn relays_pick_the_same_peers_for_one_address() {
        let g = Gossip::new();
        let peers: Vec<PeerId> = (1..=20).collect();
        let a = g.relay_to(&public(1), &peers, 2, NOW);
        assert_eq!(a.len(), 2);
        assert_eq!(a, g.relay_to(&public(1), &peers, 2, NOW + 60));
        // Different addresses spread over the peers
        let all: HashSet<PeerId> = (0..50)
            .flat_map(|k| g.relay_to(&public(k), &peers, 2, NOW))
            .collect();
        assert!(all.len() > 5, "{all:?}");
    }

    #[test]
    fn a_getaddr_answer_leaves_out_what_the_peer_has() {
        let g = Gossip::new();
        connected(&g, &[1]);
        let mine: Vec<_> = (0..5).map(|k| (NOW, public(k))).collect();
        g.received(1, &mine, &[1], NOW, NOW);
        let sample: Vec<_> = (0..10).map(|k| (NOW, public(k))).collect();
        let answer = g.answer(1, sample.clone());
        assert_eq!(answer, sample[5..].to_vec(), "not the addresses it sent");
        // A second getaddr on the connection: nothing it was given before
        assert!(g.answer(1, sample).is_empty());
    }

    #[test]
    fn a_getaddr_answer_is_at_most_1000() {
        let g = Gossip::new();
        let sample: Vec<_> = (0..2500).map(|k| (NOW, public(k))).collect();
        let answer = g.answer(1, sample.clone());
        assert_eq!(answer.len(), MAX_ADDR_TO_SEND);
        let all: HashSet<_> = sample.iter().map(|(_, a)| key(a)).collect();
        let distinct: HashSet<_> = answer.iter().map(|(_, a)| key(a)).collect();
        assert_eq!(distinct.len(), MAX_ADDR_TO_SEND);
        assert!(distinct.is_subset(&all));
        // The rest may come with a second getaddr
        assert_eq!(g.answer(1, sample).len(), 1000);
    }

    #[test]
    fn a_one_shot_peer_goes_after_its_addr() {
        let g = Gossip::new();
        g.connected(7, true);
        g.asked(7);
        let r = g.received(7, &[(NOW, public(1))], &[7], NOW, NOW);
        assert!(r.disconnect);
        assert!(
            !g.received(8, &[(NOW, public(2))], &[7, 8], NOW, NOW)
                .disconnect
        );
    }
}
