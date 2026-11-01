// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The machine's own addresses, as Divi Core's Discover reads them
//! (net.cpp:1385-1425): every IPv4 and IPv6 address of an interface that is
//! up and not the loopback. Which of them count is decided by the node
//! (routable addresses only).

use std::net::IpAddr;

#[cfg(unix)]
pub fn addresses() -> Vec<IpAddr> {
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    let mut out = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, which is walked read-only and freed once
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut ifa = list;
        while !ifa.is_null() {
            let entry = &*ifa;
            ifa = entry.ifa_next;
            if entry.ifa_addr.is_null() || (entry.ifa_flags & libc::IFF_UP as u32) == 0 {
                continue;
            }
            let name = CStr::from_ptr(entry.ifa_name).to_string_lossy();
            if name == "lo" || name == "lo0" {
                continue;
            }
            match i32::from((*entry.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        sin.sin_addr.s_addr,
                    ))));
                }
                libc::AF_INET6 => {
                    let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                    out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                }
                _ => {}
            }
        }
        libc::freeifaddrs(list);
    }
    out
}

#[cfg(not(unix))]
pub fn addresses() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn loopback_is_never_listed() {
        for ip in super::addresses() {
            assert!(!ip.is_loopback(), "{ip}");
        }
    }
}
