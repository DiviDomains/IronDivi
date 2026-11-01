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

//! Networks as Divi Core's CSubNet reads them (-rpcallowip, -whitelist)

/// A network as Divi Core's CSubNet reads an -rpcallowip or -whitelist
/// value: a single IP, `ip/bits` or `ip/netmask`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    network: std::net::IpAddr,
    mask: std::net::IpAddr,
}

impl Subnet {
    /// Parse a subnet; None if it is not a valid one
    pub fn parse(text: &str) -> Option<Subnet> {
        use std::net::IpAddr;
        let (ip, mask) = match text.split_once('/') {
            Some((ip, mask)) => (ip.parse::<IpAddr>().ok()?, Some(mask)),
            None => (text.parse::<IpAddr>().ok()?, None),
        };
        let bits = match ip {
            IpAddr::V4(_) => 32u32,
            IpAddr::V6(_) => 128,
        };
        let mask = match mask {
            None => mask_of(ip, bits),
            Some(m) => match m.parse::<u32>() {
                Ok(n) if n <= bits => mask_of(ip, n),
                Ok(_) => return None,
                Err(_) => {
                    let m = m.parse::<IpAddr>().ok()?;
                    if m.is_ipv4() != ip.is_ipv4() {
                        return None;
                    }
                    m
                }
            },
        };
        Some(Subnet {
            network: apply_mask(ip, mask),
            mask,
        })
    }

    /// Whether `ip` is in the subnet
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        let ip = match ip {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V6(v6)),
            v4 => v4,
        };
        ip.is_ipv4() == self.network.is_ipv4() && apply_mask(ip, self.mask) == self.network
    }

    /// Divi Core always lets the local host in (127.0.0.0/8 and ::1)
    pub fn loopback() -> [Subnet; 2] {
        [
            Subnet::parse("127.0.0.0/8").unwrap(),
            Subnet::parse("::1").unwrap(),
        ]
    }
}

fn mask_of(ip: std::net::IpAddr, bits: u32) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::MAX.checked_shl(32 - bits).unwrap_or(0))),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(
            u128::MAX.checked_shl(128 - bits).unwrap_or(0),
        )),
    }
}

fn apply_mask(ip: std::net::IpAddr, mask: std::net::IpAddr) -> std::net::IpAddr {
    use std::net::IpAddr;
    match (ip, mask) {
        (IpAddr::V4(a), IpAddr::V4(m)) => IpAddr::V4((u32::from(a) & u32::from(m)).into()),
        (IpAddr::V6(a), IpAddr::V6(m)) => IpAddr::V6((u128::from(a) & u128::from(m)).into()),
        (a, _) => a,
    }
}
