// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! RPC access control
//!
//! Every request passes, in order: the peer address check (`rpcallowip`,
//! loopback always allowed), the `Host` header check (an IP literal,
//! `localhost` or an `rpcallowhost` entry, so DNS rebinding cannot reach the
//! port from a web page), the `Origin` check (browsers may call the RPC only
//! from an `rpcalloworigin` origin) and HTTP Basic authentication against
//! `rpcuser`/`rpcpassword` (or the cookie) and `rpcauth` entries. The
//! authenticated user's `rpcwhitelist` then limits the methods it may call.
//!
//! The option names and semantics follow Bitcoin Core's `rpcauth`,
//! `rpcwhitelist`, `rpcwhitelistdefault` and `rpcallowip`.

use crate::auth_cookie::COOKIE_AUTH_USER;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

/// Access-control settings of the RPC server.
#[derive(Debug, Clone, Default)]
pub struct AccessConfig {
    /// `rpcauth=<user>:<salt>$<hmac>` entries: the hex HMAC-SHA256 of the
    /// password keyed with the salt, as written by Bitcoin Core's rpcauth.py.
    pub rpcauth: Vec<String>,
    /// `rpcwhitelist=<user>:<method>,<method>` entries. Several entries for
    /// one user intersect.
    pub whitelist: Vec<String>,
    /// `rpcwhitelistdefault`: whether a user without a whitelist entry is
    /// denied every method. Defaults to true once any whitelist is set.
    pub whitelist_default: Option<bool>,
    /// `rpcallowip` entries: addresses or CIDR ranges that may connect besides
    /// loopback.
    pub allow_ips: Vec<String>,
    /// `rpcalloworigin` entries: exact browser origins (`https://host:port`)
    /// allowed to call the RPC. Without any, a request carrying an `Origin`
    /// header is refused.
    pub allow_origins: Vec<String>,
    /// `rpcallowhost` entries: host names accepted in the `Host` header besides
    /// IP literals and `localhost`.
    pub allow_hosts: Vec<String>,
}

/// An IPv4 or IPv6 network, `addr/prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.trim().parse::<IpAddr>().ok()?, Some(p.trim())),
            None => (s.trim().parse::<IpAddr>().ok()?, None),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => match p.parse::<u8>() {
                Ok(n) if n <= max => n,
                // a dotted netmask, as Bitcoin Core also accepts (255.255.255.0)
                _ => match (addr, p.parse::<IpAddr>().ok()?) {
                    (IpAddr::V4(_), IpAddr::V4(mask)) => {
                        let m = u32::from(mask);
                        if m.leading_ones() + m.trailing_zeros() != 32 {
                            return None;
                        }
                        m.leading_ones() as u8
                    }
                    _ => return None,
                },
            },
        };
        Some(IpNet { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (canonical(self.addr), ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// An IPv4-mapped IPv6 address compares as its IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

enum Credential {
    Plain {
        user: String,
        password: String,
    },
    Hmac {
        user: String,
        salt: String,
        hmac: Vec<u8>,
    },
}

/// What an authenticated request may call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodGrant {
    /// Every method.
    All,
    /// Only these methods.
    Only(HashSet<String>),
}

impl MethodGrant {
    /// Whether `method` may be called.
    pub fn allows(&self, method: &str) -> bool {
        match self {
            MethodGrant::All => true,
            MethodGrant::Only(set) => set.contains(method),
        }
    }
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// The peer address is not loopback and not in `rpcallowip` (HTTP 403).
    Peer,
    /// The `Host` header is missing or names a host that is not allowed (HTTP 403).
    Host,
    /// The request comes from a browser origin that is not allowed (HTTP 403).
    Origin,
    /// No valid credentials (HTTP 401).
    Unauthorized,
}

/// Access-control state built once at startup.
pub struct RpcAccess {
    credentials: Vec<Credential>,
    whitelists: HashMap<String, HashSet<String>>,
    whitelist_default: bool,
    allow_nets: Vec<IpNet>,
    allow_origins: Vec<String>,
    allow_hosts: Vec<String>,
}

impl std::fmt::Debug for RpcAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcAccess")
            .field("credentials", &self.credentials.len())
            .field("whitelisted_users", &self.whitelists.len())
            .field("allow_nets", &self.allow_nets)
            .field("allow_origins", &self.allow_origins)
            .field("allow_hosts", &self.allow_hosts)
            .finish()
    }
}

impl RpcAccess {
    /// Build the access state. A malformed `rpcauth`, `rpcwhitelist` or
    /// `rpcallowip` entry is an error, so a typo never widens access.
    pub fn new(
        username: Option<&str>,
        password: Option<&str>,
        config: &AccessConfig,
    ) -> Result<Self, String> {
        let mut credentials = Vec::new();
        if let (Some(u), Some(p)) = (username, password) {
            if !u.is_empty() && !p.is_empty() {
                credentials.push(Credential::Plain {
                    user: u.to_string(),
                    password: p.to_string(),
                });
            }
        }
        for entry in &config.rpcauth {
            credentials.push(parse_rpcauth(entry)?);
        }

        let mut whitelists: HashMap<String, HashSet<String>> = HashMap::new();
        for entry in &config.whitelist {
            let (user, methods) = entry.split_once(':').unwrap_or((entry.as_str(), ""));
            let user = user.trim();
            if user.is_empty() {
                return Err(format!("invalid rpcwhitelist entry {entry:?}: no user"));
            }
            let methods: HashSet<String> = methods
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(String::from)
                .collect();
            whitelists
                .entry(user.to_string())
                .and_modify(|set| set.retain(|m| methods.contains(m)))
                .or_insert(methods);
        }
        let whitelist_default = config
            .whitelist_default
            .unwrap_or(!config.whitelist.is_empty());

        let allow_nets = config
            .allow_ips
            .iter()
            .map(|s| IpNet::parse(s).ok_or_else(|| format!("invalid rpcallowip {s:?}")))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RpcAccess {
            credentials,
            whitelists,
            whitelist_default,
            allow_nets,
            allow_origins: config
                .allow_origins
                .iter()
                .map(|o| o.trim().trim_end_matches('/').to_ascii_lowercase())
                .collect(),
            allow_hosts: config
                .allow_hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .collect(),
        })
    }

    /// Whether any credential can authenticate at all.
    pub fn has_credentials(&self) -> bool {
        !self.credentials.is_empty()
    }

    /// Whether `rpcallowip` admits more than loopback.
    pub fn allows_remote_peers(&self) -> bool {
        !self.allow_nets.is_empty()
    }

    /// Whether credentials other than the cookie are configured.
    fn has_explicit_credentials(&self) -> bool {
        self.credentials.iter().any(|c| match c {
            Credential::Plain { user, .. } => user != COOKIE_AUTH_USER,
            Credential::Hmac { .. } => true,
        })
    }

    /// Refuse a bind address that would expose the RPC beyond loopback unless
    /// explicit credentials and an `rpcallowip` range are both configured.
    pub fn check_bind(&self, bind: SocketAddr) -> Result<(), String> {
        if !self.has_credentials() {
            return Err("RPC has no credentials: refusing to start".into());
        }
        if canonical(bind.ip()).is_loopback() {
            return Ok(());
        }
        if !self.has_explicit_credentials() {
            return Err(format!(
                "RPC bind address {bind} is not loopback: set rpcuser/rpcpassword or rpcauth \
                 (the cookie is for local clients only) and rpcallowip"
            ));
        }
        if !self.allows_remote_peers() {
            return Err(format!(
                "RPC bind address {bind} is not loopback: set rpcallowip to the addresses \
                 allowed to connect"
            ));
        }
        Ok(())
    }

    /// Whether a connection from `peer` may be served.
    pub fn peer_allowed(&self, peer: IpAddr) -> bool {
        canonical(peer).is_loopback() || self.allow_nets.iter().any(|n| n.contains(peer))
    }

    /// Whether the `Host` header names an allowed host. A missing header is
    /// refused; IP literals and `localhost` are always accepted.
    pub fn host_allowed(&self, host: Option<&str>) -> bool {
        let Some(host) = host.map(str::trim).filter(|h| !h.is_empty()) else {
            return false;
        };
        let name = if let Some(rest) = host.strip_prefix('[') {
            // [v6]:port
            match rest.split_once(']') {
                Some((v6, _)) => return v6.parse::<std::net::Ipv6Addr>().is_ok(),
                None => return false,
            }
        } else {
            match host.rsplit_once(':') {
                Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
                _ => host,
            }
        };
        if name.parse::<std::net::Ipv4Addr>().is_ok() {
            return true;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        name == "localhost" || self.allow_hosts.iter().any(|h| *h == name)
    }

    /// Whether a request with this `Origin` header may be served. Requests
    /// without one (every non-browser client) pass.
    pub fn origin_allowed(&self, origin: Option<&str>) -> bool {
        match origin {
            None => true,
            Some(o) => {
                let o = o.trim().trim_end_matches('/').to_ascii_lowercase();
                self.allow_origins.iter().any(|a| *a == o)
            }
        }
    }

    /// Browser origins configured with `rpcalloworigin`.
    pub fn allowed_origins(&self) -> &[String] {
        &self.allow_origins
    }

    /// The user an `Authorization` header authenticates as, if any. Every
    /// credential is checked so the time taken does not depend on which matched.
    pub fn authenticate(&self, authorization: Option<&str>) -> Option<String> {
        use base64::Engine;

        // The scheme as Divi Core takes it: "Basic " exactly (rpcserver.cpp:492)
        let encoded = authorization?.strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (user, password) = decoded.split_once(':')?;

        let mut matched: Option<&str> = None;
        for credential in &self.credentials {
            let ok = match credential {
                Credential::Plain {
                    user: u,
                    password: p,
                } => constant_time_eq(
                    format!("{user}:{password}").as_bytes(),
                    format!("{u}:{p}").as_bytes(),
                ),
                Credential::Hmac {
                    user: u,
                    salt,
                    hmac,
                } => {
                    let mut mac = Hmac::<Sha256>::new_from_slice(salt.as_bytes())
                        .expect("HMAC takes any key length");
                    mac.update(password.as_bytes());
                    let user_ok = constant_time_eq(user.as_bytes(), u.as_bytes());
                    let mac_ok = mac.verify_slice(hmac).is_ok();
                    user_ok & mac_ok
                }
            };
            if ok && matched.is_none() {
                matched = Some(user);
            }
        }
        matched.map(String::from)
    }

    /// The methods `user` may call.
    pub fn grant_for(&self, user: &str) -> MethodGrant {
        match self.whitelists.get(user) {
            Some(set) => MethodGrant::Only(set.clone()),
            None if self.whitelist_default => MethodGrant::Only(HashSet::new()),
            None => MethodGrant::All,
        }
    }

    /// Run every check for one request and return the caller's grant.
    pub fn check(
        &self,
        peer: Option<IpAddr>,
        host: Option<&str>,
        origin: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<MethodGrant, Denial> {
        // Without a known peer address the request is refused: fail closed.
        if !peer.is_some_and(|p| self.peer_allowed(p)) {
            return Err(Denial::Peer);
        }
        if !self.host_allowed(host) {
            return Err(Denial::Host);
        }
        if !self.origin_allowed(origin) {
            return Err(Denial::Origin);
        }
        let user = self
            .authenticate(authorization)
            .ok_or(Denial::Unauthorized)?;
        Ok(self.grant_for(&user))
    }
}

fn parse_rpcauth(entry: &str) -> Result<Credential, String> {
    let invalid = || "invalid rpcauth entry: expected <user>:<salt>$<hmac>".to_string();
    let (user, rest) = entry.split_once(':').ok_or_else(invalid)?;
    let (salt, hmac) = rest.split_once('$').ok_or_else(invalid)?;
    let hmac = hex::decode(hmac.trim()).map_err(|_| invalid())?;
    if user.is_empty() || salt.is_empty() || hmac.len() != 32 {
        return Err(invalid());
    }
    Ok(Credential::Hmac {
        user: user.to_string(),
        salt: salt.to_string(),
        hmac,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    fn rpcauth_line(user: &str, salt: &str, password: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(salt.as_bytes()).unwrap();
        mac.update(password.as_bytes());
        format!("{user}:{salt}${}", hex::encode(mac.finalize().into_bytes()))
    }

    fn access(config: AccessConfig) -> RpcAccess {
        RpcAccess::new(Some("alice"), Some("s3cret"), &config).unwrap()
    }

    #[test]
    fn node01_rpcauth_hmac_verifies() {
        // user foo's HMAC was computed independently with Python's hmac module
        let a = access(AccessConfig {
            rpcauth: vec![
                "foo:cb77f0957de88ff388cf817ddbc7273$2f463c4fcb7547b038eba7c2e6fe3bf0e27ec1efd65ddd35ae3bafe11501fe8d".into(),
                rpcauth_line("bob", "0011aabb", "hunter2"),
            ],
            ..Default::default()
        });
        assert_eq!(
            a.authenticate(Some(&basic(
                "foo",
                "X4IJCcJmQQMI3Tp9ZBvy9B8-uIfc7M6hOyYZpkNoh-c="
            ))),
            Some("foo".into())
        );
        assert_eq!(
            a.authenticate(Some(&basic("bob", "hunter2"))),
            Some("bob".into())
        );
        assert_eq!(a.authenticate(Some(&basic("bob", "hunter3"))), None);
        assert_eq!(a.authenticate(Some(&basic("foo", "hunter2"))), None);
        assert_eq!(
            a.authenticate(Some(&basic("alice", "s3cret"))),
            Some("alice".into())
        );
        assert_eq!(a.authenticate(Some(&basic("alice", "s3cre"))), None);
        assert_eq!(a.authenticate(None), None);

        for bad in [
            "foo",
            "foo:salt",
            "foo:salt$zz",
            "foo:salt$00",
            ":s$".to_string().as_str(),
        ] {
            assert!(
                RpcAccess::new(
                    None,
                    None,
                    &AccessConfig {
                        rpcauth: vec![bad.into()],
                        ..Default::default()
                    }
                )
                .is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn node01_host_header_blocks_dns_rebinding() {
        let a = access(AccessConfig {
            allow_hosts: vec!["node.lan".into()],
            ..Default::default()
        });
        for ok in [
            "127.0.0.1",
            "127.0.0.1:51471",
            "localhost",
            "LocalHost:51471",
            "[::1]:51471",
            "10.1.2.3:9",
            "node.lan:51471",
            "NODE.lan",
        ] {
            assert!(a.host_allowed(Some(ok)), "{ok}");
        }
        for bad in [
            "evil.example",
            "evil.example:51471",
            "localhost.evil.example",
            "127.0.0.1.nip.io",
            "[::1",
            "",
        ] {
            assert!(!a.host_allowed(Some(bad)), "{bad}");
        }
        assert!(!a.host_allowed(None));
    }

    #[test]
    fn node01_origin_must_be_configured() {
        let a = access(AccessConfig::default());
        assert!(a.origin_allowed(None));
        assert!(!a.origin_allowed(Some("https://evil.example")));
        assert!(!a.origin_allowed(Some("null")));
        let a = access(AccessConfig {
            allow_origins: vec!["https://wallet.example/".into()],
            ..Default::default()
        });
        assert!(a.origin_allowed(Some("https://wallet.example")));
        assert!(!a.origin_allowed(Some("https://wallet.example.evil")));
    }

    #[test]
    fn node12_allowip_and_loopback() {
        let a = access(AccessConfig {
            allow_ips: vec![
                "10.0.0.0/8".into(),
                "192.168.1.0/255.255.255.0".into(),
                "2001:db8::/32".into(),
                "203.0.113.7".into(),
            ],
            ..Default::default()
        });
        for ok in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "10.9.8.7",
            "192.168.1.200",
            "2001:db8::5",
            "203.0.113.7",
            "::ffff:10.0.0.1",
        ] {
            assert!(a.peer_allowed(ok.parse().unwrap()), "{ok}");
        }
        for bad in ["11.0.0.1", "192.168.2.1", "2001:db9::1", "203.0.113.8"] {
            assert!(!a.peer_allowed(bad.parse().unwrap()), "{bad}");
        }
        let lo = access(AccessConfig::default());
        assert!(!lo.peer_allowed("10.0.0.1".parse().unwrap()));
        for bad in ["10.0.0.0/33", "garbage", "10.0.0.0/255.0.255.0"] {
            assert!(
                RpcAccess::new(
                    None,
                    None,
                    &AccessConfig {
                        allow_ips: vec![bad.into()],
                        ..Default::default()
                    }
                )
                .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn node12_non_loopback_bind_needs_explicit_credentials_and_allowip() {
        let any: SocketAddr = "0.0.0.0:51471".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:51471".parse().unwrap();

        let none = RpcAccess::new(None, None, &AccessConfig::default()).unwrap();
        assert!(none.check_bind(lo).is_err(), "no credentials at all");

        let cookie =
            RpcAccess::new(Some(COOKIE_AUTH_USER), Some("ab"), &AccessConfig::default()).unwrap();
        assert!(cookie.check_bind(lo).is_ok());
        let allow = AccessConfig {
            allow_ips: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        let cookie_allow = RpcAccess::new(Some(COOKIE_AUTH_USER), Some("ab"), &allow).unwrap();
        assert!(
            cookie_allow.check_bind(any).is_err(),
            "cookie is local-only"
        );

        assert!(
            access(AccessConfig::default()).check_bind(any).is_err(),
            "no rpcallowip"
        );
        assert!(access(allow.clone()).check_bind(any).is_ok());
        let via_rpcauth = RpcAccess::new(
            Some(COOKIE_AUTH_USER),
            Some("ab"),
            &AccessConfig {
                rpcauth: vec![rpcauth_line("u", "s", "p")],
                ..allow
            },
        )
        .unwrap();
        assert!(via_rpcauth.check_bind(any).is_ok());
    }

    #[test]
    fn node12_whitelists_follow_bitcoin_core() {
        // No whitelist: everyone may call everything
        assert_eq!(
            access(AccessConfig::default()).grant_for("alice"),
            MethodGrant::All
        );

        let a = access(AccessConfig {
            whitelist: vec![
                "watch:getblockcount, getbalance,getinfo".into(),
                "watch:getblockcount,getinfo".into(),
                "nobody:".into(),
            ],
            ..Default::default()
        });
        let watch = a.grant_for("watch");
        assert!(watch.allows("getblockcount") && watch.allows("getinfo"));
        assert!(!watch.allows("getbalance"), "entries intersect");
        assert!(!watch.allows("dumpprivkey"));
        assert!(!a.grant_for("nobody").allows("getblockcount"));
        // whitelistdefault is on once any whitelist exists
        assert!(!a.grant_for("alice").allows("getblockcount"));

        let a = access(AccessConfig {
            whitelist: vec!["watch:getinfo".into()],
            whitelist_default: Some(false),
            ..Default::default()
        });
        assert_eq!(a.grant_for("alice"), MethodGrant::All);
        assert!(!a.grant_for("watch").allows("sendtoaddress"));
    }

    #[test]
    fn node01_check_order_and_fail_closed() {
        let a = access(AccessConfig::default());
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let good = basic("alice", "s3cret");
        assert_eq!(
            a.check(Some(lo), Some("127.0.0.1"), None, Some(&good)),
            Ok(MethodGrant::All)
        );
        assert_eq!(
            a.check(None, Some("127.0.0.1"), None, Some(&good)),
            Err(Denial::Peer)
        );
        assert_eq!(
            a.check(
                Some("8.8.8.8".parse().unwrap()),
                Some("127.0.0.1"),
                None,
                Some(&good)
            ),
            Err(Denial::Peer)
        );
        assert_eq!(
            a.check(Some(lo), Some("evil.example"), None, Some(&good)),
            Err(Denial::Host)
        );
        assert_eq!(
            a.check(
                Some(lo),
                Some("localhost"),
                Some("https://evil.example"),
                Some(&good)
            ),
            Err(Denial::Origin)
        );
        assert_eq!(
            a.check(Some(lo), Some("localhost"), None, None),
            Err(Denial::Unauthorized)
        );
    }
}
