// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The node's own addresses as peers may reach it: Divi Core's `mapLocalHost`
//! (NetworkLocalAddressHelpers.cpp). They come from -externalip, a routable
//! -bind address and the machine's interfaces, are scored as Core scores
//! them, name us in our version message and are listed by `getnetworkinfo`.

use crate::message::NetAddr;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Address a local interface listens on
pub const LOCAL_IF: i32 = 1;
/// Address explicitly bound to
pub const LOCAL_BIND: i32 = 2;
/// Address explicitly specified (-externalip)
pub const LOCAL_MANUAL: i32 = 4;

/// The 16-byte form Core keys addresses by (IPv4 mapped into IPv6)
fn bytes(ip: &IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn from_bytes(b: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(b);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

fn is_tor(b: &[u8; 16]) -> bool {
    b[..6] == [0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43]
}

/// Divi Core CNetAddr::IsValid (netbase.cpp:840-873): not unspecified, not a
/// documentation address, not 0.0.0.0 or 255.255.255.255
pub fn is_valid(ip: &IpAddr) -> bool {
    let b = bytes(ip);
    !(b[..9] == [0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        || b == [0; 16]
        || b[..4] == [0x20, 0x01, 0x0D, 0xB8] // RFC3849
        || *ip == IpAddr::V4(Ipv4Addr::BROADCAST)
        || *ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// Divi Core CNetAddr::IsRoutable (netbase.cpp:875-878, the RFC tests :744-833)
pub fn is_routable(ip: &IpAddr) -> bool {
    if !is_valid(ip) {
        return false;
    }
    let b = bytes(ip);
    match ip {
        IpAddr::V4(v4) => {
            let [a, bb, c, _] = v4.octets();
            !(*v4 == Ipv4Addr::BROADCAST
                || a == 0
                || a == 127 // IsLocal
                || a == 10 // RFC1918
                || (a == 192 && bb == 168)
                || (a == 172 && (16..=31).contains(&bb))
                || (a == 198 && (bb == 18 || bb == 19)) // RFC2544
                || (a == 169 && bb == 254) // RFC3927
                || (a == 100 && (64..=127).contains(&bb)) // RFC6598
                || (a == 192 && bb == 0 && c == 2) // RFC5737
                || (a == 198 && bb == 51 && c == 100)
                || (a == 203 && bb == 0 && c == 113))
        }
        IpAddr::V6(v6) => {
            !(b[..8] == [0xFE, 0x80, 0, 0, 0, 0, 0, 0] // RFC4862
                || ((b[0] & 0xFE) == 0xFC && !is_tor(&b)) // RFC4193
                || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && (b[3] & 0xF0) == 0x10) // RFC4843
                || *v6 == Ipv6Addr::LOCALHOST)
        }
    }
}

/// Divi Core's networks as GetReachabilityFrom sees them (netbase.cpp:1019-1031)
#[derive(Clone, Copy, PartialEq, Eq)]
enum Net {
    Unroutable,
    Ipv4,
    Ipv6,
    Tor,
    Teredo,
    Unknown,
}

fn ext_network(ip: Option<&IpAddr>) -> Net {
    let Some(ip) = ip else {
        return Net::Unknown;
    };
    let b = bytes(ip);
    if b[..4] == [0x20, 0x01, 0, 0] {
        return Net::Teredo; // RFC4380
    }
    if !is_routable(ip) {
        Net::Unroutable
    } else if ip.is_ipv4() {
        Net::Ipv4
    } else if is_tor(&b) {
        Net::Tor
    } else {
        Net::Ipv6
    }
}

/// Divi Core CNetAddr::GetReachabilityFrom (netbase.cpp:1033-1106)
fn reachability(ours: &IpAddr, partner: Option<&IpAddr>) -> i32 {
    const UNREACHABLE: i32 = 0;
    const DEFAULT: i32 = 1;
    const TEREDO: i32 = 2;
    const IPV6_WEAK: i32 = 3;
    const IPV4: i32 = 4;
    const IPV6_STRONG: i32 = 5;
    const PRIVATE: i32 = 6;
    if !is_routable(ours) {
        return UNREACHABLE;
    }
    let b = bytes(ours);
    // RFC3964, RFC6052, RFC6145: tunnelled IPv6
    let tunnel = (b[0] == 0x20 && b[1] == 0x02)
        || b[..12] == [0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0]
        || b[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0];
    let ours = ext_network(Some(ours));
    match (ext_network(partner), ours) {
        (Net::Ipv4, Net::Ipv4) => IPV4,
        (Net::Ipv4, _) => DEFAULT,
        (Net::Ipv6, Net::Teredo) => TEREDO,
        (Net::Ipv6, Net::Ipv4) => IPV4,
        (Net::Ipv6, Net::Ipv6) if tunnel => IPV6_WEAK,
        (Net::Ipv6, Net::Ipv6) => IPV6_STRONG,
        (Net::Ipv6, _) => DEFAULT,
        (Net::Tor, Net::Ipv4) => IPV4,
        (Net::Tor, Net::Tor) => PRIVATE,
        (Net::Tor, _) => DEFAULT,
        (Net::Teredo, Net::Teredo) => TEREDO,
        (Net::Teredo, Net::Ipv6) => IPV6_WEAK,
        (Net::Teredo, Net::Ipv4) => IPV4,
        (Net::Teredo, _) => DEFAULT,
        (_, Net::Teredo) => TEREDO,
        (_, Net::Ipv6) => IPV6_WEAK,
        (_, Net::Ipv4) => IPV4,
        (_, Net::Tor) => PRIVATE,
        (_, _) => DEFAULT,
    }
}

#[derive(Clone, Copy)]
struct Entry {
    score: i32,
    port: u16,
}

/// One `getnetworkinfo` "localaddresses" row
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddress {
    pub address: IpAddr,
    pub port: u16,
    pub score: i32,
}

/// The node's local addresses (Divi Core mapLocalHost and its flags)
pub struct LocalAddresses {
    map: RwLock<BTreeMap<[u8; 16], Entry>>,
    listen: bool,
    discover: bool,
    port: u16,
}

impl LocalAddresses {
    /// `listen`: -listen; `discover`: -discover; `port`: the listen port (-port)
    pub fn new(listen: bool, discover: bool, port: u16) -> Self {
        LocalAddresses {
            map: RwLock::new(BTreeMap::new()),
            listen,
            discover,
            port,
        }
    }

    /// The listen port (Divi Core GetListenPort)
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Learn a local address (Divi Core AddLocal, NetworkLocalAddressHelpers.cpp:82-107):
    /// routable only, and below LOCAL_MANUAL only with -discover. A known
    /// address keeps the higher score, plus one.
    pub fn add(&self, addr: SocketAddr, score: i32) -> bool {
        if !is_routable(&addr.ip()) || (!self.discover && score < LOCAL_MANUAL) {
            return false;
        }
        let mut map = self.map.write();
        let key = bytes(&addr.ip());
        match map.get_mut(&key) {
            Some(e) if score < e.score => {}
            Some(e) => {
                e.score = score + 1;
                e.port = addr.port();
            }
            None => {
                map.insert(
                    key,
                    Entry {
                        score,
                        port: addr.port(),
                    },
                );
            }
        }
        true
    }

    /// An inbound peer saw us at `addr` (Divi Core SeenLocal, :143-152)
    pub fn seen(&self, addr: &SocketAddr) -> bool {
        match self.map.write().get_mut(&bytes(&addr.ip())) {
            Some(e) => {
                e.score += 1;
                true
            }
            None => false,
        }
    }

    /// The best local address for `partner` (Divi Core GetLocal, :177-197)
    fn best_for(&self, partner: Option<&IpAddr>) -> Option<SocketAddr> {
        if !self.listen {
            return None;
        }
        let mut best: Option<(i32, i32, SocketAddr)> = None;
        for (key, e) in self.map.read().iter() {
            let ip = from_bytes(*key);
            let reach = reachability(&ip, partner);
            if best.is_none_or(|(r, s, _)| reach > r || (reach == r && e.score > s)) {
                best = Some((reach, e.score, SocketAddr::new(ip, e.port)));
            }
        }
        best.map(|(_, _, a)| a)
    }

    /// Our address in a version message to `partner` (Divi Core GetLocalAddress,
    /// :203-213): the best local address, else 0.0.0.0 with the listen port
    pub fn version_address(&self, partner: Option<&IpAddr>, services: u64) -> NetAddr {
        let addr = self
            .best_for(partner)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], self.port)));
        NetAddr {
            services,
            ip: bytes(&addr.ip()),
            port: addr.port(),
        }
    }

    /// Every local address, in Divi Core's order (GetLocalHostData, :53-63)
    pub fn list(&self) -> Vec<LocalAddress> {
        self.map
            .read()
            .iter()
            .map(|(key, e)| LocalAddress {
                address: from_bytes(*key),
                port: e.port,
                score: e.score,
            })
            .collect()
    }
}

impl Default for LocalAddresses {
    /// Listening, discovering, no port: what a node has before it is configured
    fn default() -> Self {
        LocalAddresses::new(true, true, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn routable_follows_divi_core() {
        for (addr, routable) in [
            ("1.2.3.4", true),
            ("8.8.4.4", true),
            ("10.1.2.3", false),
            ("192.168.1.1", false),
            ("172.16.0.1", false),
            ("172.32.0.1", true),
            ("127.0.0.1", false),
            ("0.0.0.0", false),
            ("255.255.255.255", false),
            ("169.254.1.1", false),
            ("100.64.0.1", false),
            ("198.18.0.1", false),
            ("192.0.2.1", false),
            ("198.51.100.1", false),
            ("203.0.113.5", false),
            ("2600:1700::43", true),
            ("::1", false),
            ("::", false),
            ("fe80::1", false),
            ("fc00::1", false),
            ("fd87:d87e:eb43::1", true), // Tor's OnionCat range
            ("2001:db8::1", false),
            ("2001:10::1", false),
        ] {
            assert_eq!(is_routable(&ip(addr)), routable, "{addr}");
        }
    }

    #[test]
    fn add_scores_as_divi_core() {
        let local = LocalAddresses::new(true, true, 51472);
        assert!(!local.add("10.0.0.1:51472".parse().unwrap(), LOCAL_IF));
        assert!(local.add("1.2.3.4:51472".parse().unwrap(), LOCAL_MANUAL));
        // a lower score leaves it, the same or higher raises it by one more
        assert!(local.add("1.2.3.4:51472".parse().unwrap(), LOCAL_IF));
        assert_eq!(local.list()[0].score, LOCAL_MANUAL);
        assert!(local.add("1.2.3.4:9999".parse().unwrap(), LOCAL_MANUAL));
        assert_eq!(
            local.list(),
            vec![LocalAddress {
                address: ip("1.2.3.4"),
                port: 9999,
                score: LOCAL_MANUAL + 1
            }]
        );
        assert!(local.seen(&"1.2.3.4:1".parse().unwrap()));
        assert!(!local.seen(&"5.6.7.8:1".parse().unwrap()));
        assert_eq!(local.list()[0].score, LOCAL_MANUAL + 2);
    }

    #[test]
    fn without_discover_only_manual_addresses_count() {
        let local = LocalAddresses::new(true, false, 51472);
        assert!(!local.add("8.8.4.4:51472".parse().unwrap(), LOCAL_IF));
        assert!(!local.add("8.8.4.4:51472".parse().unwrap(), LOCAL_BIND));
        assert!(local.add("8.8.4.4:51472".parse().unwrap(), LOCAL_MANUAL));
    }

    #[test]
    fn version_address_is_the_best_for_the_peer() {
        let local = LocalAddresses::new(true, true, 51472);
        let none = local.version_address(Some(&ip("5.6.7.8")), 1);
        assert_eq!((none.ip, none.port), (bytes(&ip("0.0.0.0")), 51472));
        local.add(SocketAddr::new(ip("2600:1700::43"), 51472), LOCAL_IF);
        local.add("1.2.3.4:51472".parse().unwrap(), LOCAL_IF);
        // an IPv4 peer gets our IPv4 address, an IPv6 peer our IPv6 one
        let v4 = local.version_address(Some(&ip("5.6.7.8")), 1);
        assert_eq!(from_bytes(v4.ip), ip("1.2.3.4"));
        let v6 = local.version_address(Some(&ip("2a00::1")), 1);
        assert_eq!(from_bytes(v6.ip), ip("2600:1700::43"));
        // not listening: nobody can reach us, so no address
        let quiet = LocalAddresses::new(false, true, 51472);
        quiet.add("1.2.3.4:51472".parse().unwrap(), LOCAL_MANUAL);
        let v = quiet.version_address(None, 1);
        assert_eq!((from_bytes(v.ip), v.port), (ip("0.0.0.0"), 51472));
    }

    #[test]
    fn listed_in_divi_core_order() {
        let local = LocalAddresses::new(true, true, 1);
        local.add(SocketAddr::new(ip("2600:1700::43"), 1), LOCAL_IF);
        local.add(SocketAddr::new(ip("8.8.4.4"), 1), LOCAL_IF);
        local.add(SocketAddr::new(ip("1.2.3.4"), 1), LOCAL_IF);
        let order: Vec<IpAddr> = local.list().into_iter().map(|a| a.address).collect();
        // Core's map orders the 16-byte form: IPv4 (::ffff:a.b.c.d) first
        assert_eq!(
            order,
            vec![ip("1.2.3.4"), ip("8.8.4.4"), ip("2600:1700::43")]
        );
    }
}
