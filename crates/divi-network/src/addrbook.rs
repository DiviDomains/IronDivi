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

//! Addresses of other nodes learnt from `addr` messages and outbound peers,
//! kept across restarts in `peers.dat`, as Divi Core's address manager and
//! CAddrDB keep them: stored from `addr` (main.cpp:521-558), a share of them
//! given to an inbound `getaddr` (main.cpp:863-869, addrman GetAddr), written
//! at a clean stop and every 15 minutes, read at start, and a file that does
//! not read started over (net.cpp:1060-1068, :1431-1438).
//!
//! The file is irondivid's own format (Divi Core never reads irondivid's data
//! directory): a header, the network magic, the entries and a double SHA-256
//! of all of it.

use crate::local::is_routable;
use crate::message::NetAddr;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// The file name, Divi Core's
pub const FILE_NAME: &str = "peers.dat";
/// How often the book is written while the node runs (DUMP_ADDRESSES_INTERVAL, net.cpp:83)
pub const DUMP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(900);

/// At most as many as Divi Core's tables hold (1024 x 64 new, 256 x 64 tried)
const MAX_ENTRIES: usize = 1024 * 64 + 256 * 64;
/// A getaddr answer: this share of the book, at most this many (addrman.h
/// ADDRMAN_GETADDR_MAX_PCT, ADDRMAN_GETADDR_MAX)
const GETADDR_MAX_PCT: usize = 23;
const GETADDR_MAX: usize = 2500;
/// An address learnt from a peer counts as two hours older (main.cpp:553)
const TIME_PENALTY: u32 = 2 * 60 * 60;
/// Not given out once this old (addrman IsTerrible: ADDRMAN_HORIZON_DAYS)
const HORIZON: u32 = 30 * 24 * 60 * 60;

const HEADER: &[u8; 8] = b"IRDPEERS";
const ENTRY_LEN: usize = 16 + 2 + 8 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    services: u64,
    time: u32,
}

/// The address book
pub struct AddressBook {
    entries: Mutex<HashMap<SocketAddr, Known>>,
    path: Mutex<Option<PathBuf>>,
    magic: [u8; 4],
}

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn to_socket(addr: &NetAddr) -> SocketAddr {
    let ip = std::net::Ipv6Addr::from(addr.ip);
    let ip = match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    };
    SocketAddr::new(ip, addr.port)
}

fn to_net(addr: &SocketAddr, services: u64) -> NetAddr {
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    NetAddr {
        services,
        ip: ip.octets(),
        port: addr.port(),
    }
}

fn dsha(data: &[u8]) -> [u8; 32] {
    divi_crypto::double_sha256(data)
}

impl AddressBook {
    /// An empty book for the network with this message start
    pub fn new(magic: [u8; 4]) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            path: Mutex::new(None),
            magic,
        }
    }

    /// Keep the book in `dir/peers.dat`, and read what is there. A file that
    /// does not read (cut short, damaged, another network's) leaves the book
    /// empty, and the next write replaces it (net.cpp:1431-1438).
    pub fn open(&self, dir: &Path) -> usize {
        let path = dir.join(FILE_NAME);
        *self.path.lock() = Some(path.clone());
        let read = std::fs::read(&path)
            .ok()
            .and_then(|bytes| self.decode(&bytes));
        let n = match read {
            Some(entries) => {
                let n = entries.len();
                *self.entries.lock() = entries;
                n
            }
            None => {
                tracing::info!("Invalid or missing peers.dat; recreating");
                0
            }
        };
        tracing::info!("Loaded {} addresses from peers.dat", n);
        n
    }

    fn decode(&self, bytes: &[u8]) -> Option<HashMap<SocketAddr, Known>> {
        let body_len = bytes.len().checked_sub(32)?;
        let (body, sum) = bytes.split_at(body_len);
        if dsha(body) != sum || body.len() < 16 || &body[..8] != HEADER || body[8..12] != self.magic
        {
            return None;
        }
        let count = u32::from_le_bytes(body[12..16].try_into().ok()?) as usize;
        let data = &body[16..];
        if data.len() != count.checked_mul(ENTRY_LEN)? {
            return None;
        }
        let mut out = HashMap::with_capacity(count);
        for e in data.as_chunks::<ENTRY_LEN>().0 {
            let net = NetAddr {
                ip: e[..16].try_into().ok()?,
                port: u16::from_be_bytes([e[16], e[17]]),
                services: u64::from_le_bytes(e[18..26].try_into().ok()?),
            };
            let time = u32::from_le_bytes(e[26..30].try_into().ok()?);
            out.insert(
                to_socket(&net),
                Known {
                    services: net.services,
                    time,
                },
            );
        }
        Some(out)
    }

    fn encode(&self) -> Vec<u8> {
        let entries = self.entries.lock();
        let mut out = Vec::with_capacity(16 + entries.len() * ENTRY_LEN + 32);
        out.extend_from_slice(HEADER);
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (addr, k) in entries.iter() {
            let net = to_net(addr, k.services);
            out.extend_from_slice(&net.ip);
            out.extend_from_slice(&net.port.to_be_bytes());
            out.extend_from_slice(&k.services.to_le_bytes());
            out.extend_from_slice(&k.time.to_le_bytes());
        }
        let sum = dsha(&out);
        out.extend_from_slice(&sum);
        out
    }

    /// Write the book (through a temporary file, so a stop part way leaves
    /// the last whole file)
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = self.path.lock().clone() else {
            return Ok(());
        };
        let tmp = path.with_extension("dat.new");
        std::fs::write(&tmp, self.encode())?;
        std::fs::rename(&tmp, &path)
    }

    /// Store the addresses of an `addr` message (main.cpp:538-553): routable
    /// ones only; a time that is unset or more than ten minutes ahead counts
    /// as five days ago; each is two hours older than the peer says
    pub fn add(&self, addrs: &[(u32, NetAddr)]) -> usize {
        self.add_at(addrs, now())
    }

    fn add_at(&self, addrs: &[(u32, NetAddr)], now: u32) -> usize {
        let mut entries = self.entries.lock();
        let mut added = 0;
        for (time, net) in addrs {
            let addr = to_socket(net);
            if !is_routable(&addr.ip()) || addr.port() == 0 {
                continue;
            }
            let time = if *time <= 100_000_000 || *time > now.saturating_add(600) {
                now.saturating_sub(5 * 24 * 60 * 60)
            } else {
                *time
            };
            let time = time.saturating_sub(TIME_PENALTY);
            match entries.get_mut(&addr) {
                Some(k) => {
                    k.time = k.time.max(time);
                    k.services |= net.services;
                }
                None => {
                    if entries.len() >= MAX_ENTRIES {
                        // Room for it: the address heard of longest ago goes
                        if let Some(oldest) =
                            entries.iter().min_by_key(|(_, k)| k.time).map(|(a, _)| *a)
                        {
                            entries.remove(&oldest);
                        }
                    }
                    entries.insert(
                        addr,
                        Known {
                            services: net.services,
                            time,
                        },
                    );
                    added += 1;
                }
            }
        }
        added
    }

    /// An outbound peer that answered: kept with the time now (addrman Good)
    pub fn connected(&self, addr: SocketAddr, services: u64) {
        let net = to_net(&addr, services);
        self.add_at(&[(now().saturating_add(TIME_PENALTY), net)], now());
    }

    /// The answer to a getaddr: 23% of the book, at most 2500, at random,
    /// leaving out addresses not heard of for 30 days (addrman GetAddr_)
    pub fn sample(&self) -> Vec<(u32, NetAddr)> {
        let now = now();
        let entries = self.entries.lock();
        let n = (entries.len() * GETADDR_MAX_PCT / 100).min(GETADDR_MAX);
        let mut fresh: Vec<_> = entries
            .iter()
            .filter(|(_, k)| k.time.saturating_add(HORIZON) >= now && k.time <= now + 600)
            .map(|(a, k)| (k.time, to_net(a, k.services)))
            .collect();
        fresh.shuffle(&mut rand::thread_rng());
        fresh.truncate(n);
        fresh
    }

    /// Up to `n` addresses to dial, at random
    pub fn candidates(&self, n: usize) -> Vec<SocketAddr> {
        let mut all: Vec<SocketAddr> = self.entries.lock().keys().copied().collect();
        all.shuffle(&mut rand::thread_rng());
        all.truncate(n);
        all
    }

    /// How many addresses the book holds
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the book is empty
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> NetAddr {
        NetAddr::from_ipv4([a, b, c, d], port, 1)
    }

    fn public(k: u8) -> NetAddr {
        v4(20 + k, k.wrapping_mul(7), 3, 4, 51476)
    }

    #[test]
    fn only_routable_addresses_are_kept() {
        let book = AddressBook::new(MAGIC);
        let now = 1_700_000_000;
        let added = book.add_at(
            &[
                (now, public(1)),
                (now, v4(127, 0, 0, 3, 51476)),
                (now, v4(10, 0, 0, 1, 51476)),
                (now, v4(192, 168, 1, 1, 51476)),
                (now, v4(192, 0, 2, 1, 51476)),
                (now, public(2)),
            ],
            now,
        );
        assert_eq!(added, 2);
        assert_eq!(book.len(), 2);
    }

    #[test]
    fn times_are_read_as_divid_reads_them() {
        let book = AddressBook::new(MAGIC);
        let now = 1_700_000_000;
        book.add_at(
            &[
                (5, public(1)),
                (now + 3600, public(2)),
                (now - 60, public(3)),
            ],
            now,
        );
        let e = book.entries.lock();
        let t = |n: NetAddr| e[&to_socket(&n)].time;
        let five_days = 5 * 24 * 60 * 60;
        assert_eq!(t(public(1)), now - five_days - TIME_PENALTY);
        assert_eq!(t(public(2)), now - five_days - TIME_PENALTY);
        assert_eq!(t(public(3)), now - 60 - TIME_PENALTY);
    }

    #[test]
    fn getaddr_gets_23_percent() {
        let book = AddressBook::new(MAGIC);
        let addrs: Vec<_> = (0..100).map(|k| (now(), public(k))).collect();
        book.add(&addrs);
        assert_eq!(book.len(), 100);
        let sample = book.sample();
        assert_eq!(sample.len(), 23);
        let all: std::collections::HashSet<_> = addrs.iter().map(|(_, a)| to_socket(a)).collect();
        assert!(sample.iter().all(|(_, a)| all.contains(&to_socket(a))));
        // Fewer than five: 23% of them is none, as in divid
        let small = AddressBook::new(MAGIC);
        small.add(&addrs[..4]);
        assert!(small.sample().is_empty());
    }

    #[test]
    fn the_book_is_kept_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let book = AddressBook::new(MAGIC);
        assert_eq!(book.open(dir.path()), 0);
        book.add(&(0..50).map(|k| (now(), public(k))).collect::<Vec<_>>());
        book.save().unwrap();
        let again = AddressBook::new(MAGIC);
        assert_eq!(again.open(dir.path()), 50);
        assert_eq!(
            again.entries.lock().clone(),
            book.entries.lock().clone(),
            "the same addresses, services and times"
        );
    }

    #[test]
    fn a_file_that_does_not_read_is_started_over() {
        let dir = tempfile::tempdir().unwrap();
        let book = AddressBook::new(MAGIC);
        book.open(dir.path());
        book.add(&(0..10).map(|k| (now(), public(k))).collect::<Vec<_>>());
        book.save().unwrap();
        let whole = std::fs::read(dir.path().join(FILE_NAME)).unwrap();
        let mut flipped = whole.clone();
        flipped[20] ^= 1;
        for bad in [
            Vec::new(),
            whole[..whole.len() / 2].to_vec(),
            flipped,
            vec![7u8; 300],
        ] {
            std::fs::write(dir.path().join(FILE_NAME), &bad).unwrap();
            let b = AddressBook::new(MAGIC);
            assert_eq!(b.open(dir.path()), 0);
            b.save().unwrap();
            let rewritten = std::fs::read(dir.path().join(FILE_NAME)).unwrap();
            assert_ne!(rewritten, bad, "the next write replaces the file");
            assert_eq!(AddressBook::new(MAGIC).open(dir.path()), 0);
        }
        // Another network's book is not this one's
        std::fs::write(dir.path().join(FILE_NAME), &whole).unwrap();
        assert_eq!(
            AddressBook::new([0xdf, 0xa0, 0x8d, 0x8f]).open(dir.path()),
            0
        );
    }
}
