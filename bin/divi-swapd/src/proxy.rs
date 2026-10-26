// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Which socket peers the rate limiter believes when they name the client in
//! `X-Forwarded-For` / `X-Real-IP` (config `trust_proxy_headers` and `trusted_proxies`).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use serde::Deserialize;

/// `trusted_proxies` when the config leaves it out: the loopback addresses, where a proxy on the
/// same host (the shipped nginx snippet) connects from.
pub const DEFAULT_TRUSTED_PROXIES: [&str; 2] = ["127.0.0.1/32", "::1/128"];

/// An IP network: an address and a prefix length. Parsed from `a.b.c.d/n` or `x:y::z/n`, or a
/// bare address (one host, `/32` or `/128`). Bits set past the prefix are refused
/// (`10.0.0.1/8`): a typo there would trust a different set of peers than the one written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

/// An address as a number and its width in bits.
fn bits(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(a) => (u32::from(a).into(), 32),
        IpAddr::V6(a) => (a.into(), 128),
    }
}

/// `v` with all but its top `prefix` bits (of `width`) cleared.
fn masked(v: u128, width: u8, prefix: u8) -> u128 {
    v & u128::MAX
        .checked_shl(u32::from(width - prefix))
        .unwrap_or(0)
}

impl IpCidr {
    /// The network `addr/prefix`; `None` when the prefix is longer than the address or bits are
    /// set past it.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let (v, width) = bits(addr);
        (prefix <= width && masked(v, width, prefix) == v).then_some(IpCidr { addr, prefix })
    }

    /// Whether `ip` is in the network. An IPv4-mapped IPv6 peer (`::ffff:a.b.c.d`, how a
    /// dual-stack listener sees an IPv4 client) is matched as the IPv4 address it carries.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (net, width) = bits(self.addr);
        let (v, w) = bits(ip.to_canonical());
        w == width && masked(v, width, self.prefix) == net
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?} is not an IP address or network (a.b.c.d/n, x::y/n)");
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| bad())?;
        let prefix = match prefix {
            Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => p.parse().map_err(|_| bad())?,
            Some(_) => return Err(bad()),
            None => bits(addr).1,
        };
        IpCidr::new(addr, prefix).ok_or_else(|| {
            format!("{s:?}: the prefix is too long, or bits are set past it (write the network)")
        })
    }
}

impl TryFrom<String> for IpCidr {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        s.parse()
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// [`DEFAULT_TRUSTED_PROXIES`], parsed.
pub fn default_trusted_proxies() -> Vec<IpCidr> {
    DEFAULT_TRUSTED_PROXIES
        .iter()
        .map(|s| s.parse().expect("built-in network"))
        .collect()
}

/// The peers whose proxy headers name the client: `trusted_proxies` with `trust_proxy_headers`
/// on, nothing with it off ([`ProxyTrust::off`], the default). A request from any other peer
/// (or with no peer address) is keyed on the peer, whatever its headers say.
#[derive(Debug, Clone, Default)]
pub struct ProxyTrust(Arc<Vec<IpCidr>>);

impl ProxyTrust {
    /// The headers are never read.
    pub fn off() -> Self {
        ProxyTrust::default()
    }

    /// Believe the headers of peers in `proxies`.
    pub fn proxies(proxies: impl IntoIterator<Item = IpCidr>) -> Self {
        ProxyTrust(Arc::new(proxies.into_iter().collect()))
    }

    /// Believe the headers of a proxy on this host ([`DEFAULT_TRUSTED_PROXIES`]).
    pub fn loopback() -> Self {
        ProxyTrust::proxies(default_trusted_proxies())
    }

    /// Whether a request from `peer` may name its client in the proxy headers.
    pub fn trusts(&self, peer: IpAddr) -> bool {
        self.0.iter().any(|n| n.contains(peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpCidr {
        s.parse().unwrap()
    }

    #[test]
    fn networks_parse_and_match() {
        let ten = net("10.0.0.0/8");
        assert!(ten.contains(ip("10.255.1.2")));
        assert!(!ten.contains(ip("11.0.0.1")));
        assert!(
            ten.contains(ip("::ffff:10.0.0.1")),
            "IPv4-mapped peer from a dual-stack listener"
        );
        assert!(
            !ten.contains(ip("::a00:1")),
            "IPv4-compatible is not mapped"
        );
        let host = net("192.0.2.7");
        assert_eq!(host, net("192.0.2.7/32"));
        assert!(host.contains(ip("192.0.2.7")) && !host.contains(ip("192.0.2.8")));
        let v6 = net("fd00::/8");
        assert!(v6.contains(ip("fdab::1")) && !v6.contains(ip("fe80::1")));
        assert!(!v6.contains(ip("10.0.0.1")), "families never cross");
        assert!(net("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(!net("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(net("::/0").contains(ip("2001:db8::1")));
        assert!(net("::1").contains(ip("::1")));
        assert_eq!(net("fd00::/8").to_string(), "fd00::/8");
    }

    #[test]
    fn malformed_networks_are_refused() {
        for s in [
            "",
            "nonsense",
            "10.0.0.0/",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/+8",
            "10.0.0.0/8/8",
            "10.0.0.1/8",
            "fd00::1/8",
            " 10.0.0.0/8",
        ] {
            assert!(s.parse::<IpCidr>().is_err(), "{s:?} parsed");
        }
    }

    #[test]
    fn the_default_trusts_loopback_only() {
        let t = ProxyTrust::loopback();
        assert!(t.trusts(ip("127.0.0.1")) && t.trusts(ip("::1")));
        assert!(t.trusts(ip("::ffff:127.0.0.1")));
        assert!(!t.trusts(ip("127.0.0.2")), "127.0.0.1/32, not 127/8");
        assert!(!t.trusts(ip("203.0.113.9")));
        assert!(
            !t.trusts(ip("0.0.0.0")),
            "a router served without a peer address"
        );
        assert!(!ProxyTrust::off().trusts(ip("127.0.0.1")));
    }
}
