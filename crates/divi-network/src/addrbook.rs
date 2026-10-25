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

//! Addresses of other nodes learnt from `addr` messages and DNS seeds, kept
//! as Divi Core's address manager keeps them (addrman.h, addrman.cpp):
//!
//! - an address not yet connected to sits in up to 8 of 1024 "new" buckets of
//!   64 places, the bucket chosen from its /16 (or /32) and that of the peer
//!   that told of it, so one source group reaches at most 64 buckets; a place
//!   that is taken keeps its address (addrman.cpp:247-313);
//! - an address connected to moves to one of 256 "tried" buckets
//!   (addrman.cpp:150-246);
//! - there is one entry per IP (addrman.h:184), the places hash with a random
//!   key of the book's own;
//! - a getaddr answer is 23% of the book, at most 2500, leaving out terrible
//!   entries (addrman.cpp:451-469), and an address to dial is chosen half from
//!   each table, weighted by its record (addrman.cpp:334-371).
//!
//! The book is kept in `peers.dat` in Divi Core's own layout (AddrDB.cpp:26-57,
//! addrman.h:276-420): the network magic, the tables and a double SHA-256 of
//! both. So divid reads irondivid's file and irondivid divid's. A file of
//! irondivid's older layout (`IRDPEERS`) is still read. The file is written at
//! a clean stop and every 15 minutes, read at start, and a file that does not
//! read is started over (net.cpp:1060-1068, :1431-1438).

use crate::local::is_routable;
use crate::message::NetAddr;
use parking_lot::Mutex;
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

/// The file name, Divi Core's
pub const FILE_NAME: &str = "peers.dat";
/// How often the book is written while the node runs (DUMP_ADDRESSES_INTERVAL, net.cpp:83)
pub const DUMP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(900);
/// An address learnt from a peer counts as two hours older (main.cpp:553)
pub const TIME_PENALTY: i64 = 2 * 60 * 60;

// addrman.h:130-163
const TRIED_BUCKET_COUNT: usize = 256;
const NEW_BUCKET_COUNT: usize = 1024;
const BUCKET_SIZE: usize = 64;
const TRIED_BUCKETS_PER_GROUP: u64 = 8;
const NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 64;
const NEW_BUCKETS_PER_ADDRESS: u32 = 8;
const HORIZON_DAYS: i64 = 30;
const RETRIES: i32 = 3;
const MAX_FAILURES: i32 = 10;
const MIN_FAIL_DAYS: i64 = 7;
const GETADDR_MAX_PCT: usize = 23;
const GETADDR_MAX: usize = 2500;

/// Each entry on disk carries the writer's CLIENT_VERSION (CAddress, SER_DISK;
/// Divi Core 3.0.0's, clientversion.h:43)
const DISK_VERSION: i32 = 3_000_000;
/// The format version and key size addrman writes (addrman.h:280-282)
const FORMAT_VERSION: u8 = 1;
const KEY_SIZE: u8 = 32;
/// irondivid's older file: a header, the magic, a count and entries of
/// address, port, services and time
const LEGACY_HEADER: &[u8; 8] = b"IRDPEERS";
const LEGACY_ENTRY_LEN: usize = 16 + 2 + 8 + 4;
const EMPTY: i32 = -1;

/// The address manager's clock: GetAdjustedTime, the node's clock plus the
/// network time offset (addrman.h:97-100, :509-560; addrman.cpp:258)
fn now() -> i64 {
    divi_primitives::clock::adjusted_now()
}

fn dsha(data: &[u8]) -> [u8; 32] {
    divi_crypto::double_sha256(data)
}

/// uint256::GetLow64 of a double SHA-256: its first 8 bytes, little-endian
fn hash64(data: &[u8]) -> u64 {
    u64::from_le_bytes(dsha(data)[..8].try_into().expect("8 bytes"))
}

/// A std::vector<unsigned char> as CHashWriter writes it (all are short here)
fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
    out.push(v.len() as u8);
    out.extend_from_slice(v);
}

fn ip16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn ip_of(b: &[u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(*b);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// CNetAddr::GetGroup (netbase.cpp:952-1010): what buckets are chosen by
pub(crate) fn group(b: &[u8; 16]) -> Vec<u8> {
    const UNROUTABLE: u8 = 0;
    const IPV4: u8 = 1;
    const IPV6: u8 = 2;
    const TOR: u8 = 3;
    // Every local or unroutable address is of one group
    if !is_routable(&ip_of(b)) {
        return vec![UNROUTABLE];
    }
    let ipv4 = b[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    let rfc6145 = b[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0];
    let rfc6052 = b[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
    let (class, mut start, mut bits) = if ipv4 || rfc6145 || rfc6052 {
        (IPV4, 12, 16)
    } else if b[..2] == [0x20, 0x02] {
        // 6to4: the IPv4 address inside
        (IPV4, 2, 16)
    } else if b[..4] == [0x20, 0x01, 0, 0] {
        // Teredo: the IPv4 address inside, inverted
        return vec![IPV4, b[12] ^ 0xff, b[13] ^ 0xff];
    } else if crate::local::is_tor(b) {
        (TOR, 6, 4)
    } else if b[..4] == [0x20, 0x01, 0x04, 0x70] {
        // he.net: /36
        (IPV6, 0, 36)
    } else {
        (IPV6, 0, 32)
    };
    let mut out = vec![class];
    while bits >= 8 {
        out.push(b[start]);
        start += 1;
        bits -= 8;
    }
    if bits > 0 {
        out.push(b[start] | ((1u8 << bits) - 1));
    }
    out
}

/// An entry: CAddrInfo (addrman.h:24-104)
#[derive(Debug, Clone, PartialEq)]
struct Info {
    ip: [u8; 16],
    port: u16,
    services: u64,
    time: u32,
    source: [u8; 16],
    last_success: i64,
    last_try: i64,
    attempts: i32,
    ref_count: u32,
    in_tried: bool,
    random_pos: usize,
}

impl Info {
    fn new(ip: [u8; 16], port: u16, services: u64, time: u32, source: [u8; 16]) -> Self {
        Info {
            ip,
            port,
            services,
            time,
            source,
            last_success: 0,
            last_try: 0,
            attempts: 0,
            ref_count: 0,
            in_tried: false,
            random_pos: 0,
        }
    }

    /// CService::GetKey (netbase.cpp:1236-1244)
    fn key(&self) -> [u8; 18] {
        let mut k = [0u8; 18];
        k[..16].copy_from_slice(&self.ip);
        k[16..].copy_from_slice(&self.port.to_be_bytes());
        k
    }

    fn socket(&self) -> SocketAddr {
        SocketAddr::new(ip_of(&self.ip), self.port)
    }

    fn net(&self) -> NetAddr {
        NetAddr {
            services: self.services,
            ip: self.ip,
            port: self.port,
        }
    }

    /// GetTriedBucket (addrman.cpp:13-18)
    fn tried_bucket(&self, key: &[u8; 32]) -> usize {
        let mut h = key.to_vec();
        put_vec(&mut h, &self.key());
        let hash1 = hash64(&h);
        let mut h = key.to_vec();
        put_vec(&mut h, &group(&self.ip));
        h.extend_from_slice(&(hash1 % TRIED_BUCKETS_PER_GROUP).to_le_bytes());
        (hash64(&h) % TRIED_BUCKET_COUNT as u64) as usize
    }

    /// GetNewBucket (addrman.cpp:20-26)
    fn new_bucket(&self, key: &[u8; 32], source: &[u8; 16]) -> usize {
        let source_group = group(source);
        let mut h = key.to_vec();
        put_vec(&mut h, &group(&self.ip));
        put_vec(&mut h, &source_group);
        let hash1 = hash64(&h);
        let mut h = key.to_vec();
        put_vec(&mut h, &source_group);
        h.extend_from_slice(&(hash1 % NEW_BUCKETS_PER_SOURCE_GROUP).to_le_bytes());
        (hash64(&h) % NEW_BUCKET_COUNT as u64) as usize
    }

    /// GetBucketPosition (addrman.cpp:28-32)
    fn position(&self, key: &[u8; 32], new: bool, bucket: usize) -> usize {
        let mut h = key.to_vec();
        h.push(if new { b'N' } else { b'K' });
        h.extend_from_slice(&(bucket as i32).to_le_bytes());
        put_vec(&mut h, &self.key());
        (hash64(&h) % BUCKET_SIZE as u64) as usize
    }

    /// IsTerrible (addrman.cpp:34-55)
    fn is_terrible(&self, now: i64) -> bool {
        let time = self.time as i64;
        if self.last_try != 0 && self.last_try >= now - 60 {
            return false;
        }
        time > now + 10 * 60
            || time == 0
            || now - time > HORIZON_DAYS * 24 * 60 * 60
            || (self.last_success == 0 && self.attempts >= RETRIES)
            || (now - self.last_success > MIN_FAIL_DAYS * 24 * 60 * 60
                && self.attempts >= MAX_FAILURES)
    }

    /// GetChance (addrman.cpp:57-77)
    fn chance(&self, now: i64) -> f64 {
        let since_try = (now - self.last_try).max(0);
        let mut chance = 1.0;
        if since_try < 60 * 10 {
            chance *= 0.01;
        }
        chance * 0.66f64.powi(self.attempts.clamp(0, 8))
    }
}

/// The tables: CAddrMan's state (addrman.h:166-200)
struct Tables {
    key: [u8; 32],
    id_count: i32,
    info: HashMap<i32, Info>,
    by_ip: HashMap<[u8; 16], i32>,
    random: Vec<i32>,
    n_new: usize,
    n_tried: usize,
    new: Vec<[i32; BUCKET_SIZE]>,
    tried: Vec<[i32; BUCKET_SIZE]>,
}

impl Tables {
    fn empty(key: [u8; 32]) -> Self {
        Tables {
            key,
            id_count: 0,
            info: HashMap::new(),
            by_ip: HashMap::new(),
            random: Vec::new(),
            n_new: 0,
            n_tried: 0,
            new: vec![[EMPTY; BUCKET_SIZE]; NEW_BUCKET_COUNT],
            tried: vec![[EMPTY; BUCKET_SIZE]; TRIED_BUCKET_COUNT],
        }
    }

    fn fresh() -> Self {
        Self::empty(rand::thread_rng().gen())
    }

    fn len(&self) -> usize {
        self.random.len()
    }

    fn find(&self, ip: &[u8; 16]) -> Option<i32> {
        self.by_ip.get(ip).copied()
    }

    /// Create (addrman.cpp:91-99)
    fn create(&mut self, info: Info) -> i32 {
        let id = self.id_count;
        self.id_count += 1;
        let mut info = info;
        info.random_pos = self.random.len();
        self.by_ip.insert(info.ip, id);
        self.info.insert(id, info);
        self.random.push(id);
        id
    }

    /// SwapRandom (addrman.cpp:101-119)
    fn swap_random(&mut self, a: usize, b: usize) {
        if a == b {
            return;
        }
        let (id_a, id_b) = (self.random[a], self.random[b]);
        self.info.get_mut(&id_a).expect("entry").random_pos = b;
        self.info.get_mut(&id_b).expect("entry").random_pos = a;
        self.random.swap(a, b);
    }

    /// Delete (addrman.cpp:121-133): a new entry no bucket refers to
    fn delete(&mut self, id: i32) {
        let pos = self.info[&id].random_pos;
        let last = self.random.len() - 1;
        self.swap_random(pos, last);
        self.random.pop();
        if let Some(info) = self.info.remove(&id) {
            self.by_ip.remove(&info.ip);
        }
        self.n_new -= 1;
    }

    /// ClearNew (addrman.cpp:135-148)
    fn clear_new(&mut self, bucket: usize, pos: usize) {
        let id = self.new[bucket][pos];
        if id == EMPTY {
            return;
        }
        self.new[bucket][pos] = EMPTY;
        let info = self.info.get_mut(&id).expect("entry");
        info.ref_count -= 1;
        if info.ref_count == 0 {
            self.delete(id);
        }
    }

    /// MakeTried (addrman.cpp:150-196)
    fn make_tried(&mut self, id: i32) {
        let key = self.key;
        let info = self.info[&id].clone();
        for bucket in 0..NEW_BUCKET_COUNT {
            let pos = info.position(&key, true, bucket);
            if self.new[bucket][pos] == id {
                self.new[bucket][pos] = EMPTY;
                self.info.get_mut(&id).expect("entry").ref_count -= 1;
            }
        }
        self.n_new -= 1;

        let tried_bucket = info.tried_bucket(&key);
        let tried_pos = info.position(&key, false, tried_bucket);
        let evict = self.tried[tried_bucket][tried_pos];
        if evict != EMPTY {
            // The entry there goes back to the new table, over what is in its place
            self.tried[tried_bucket][tried_pos] = EMPTY;
            self.n_tried -= 1;
            let old = {
                let old = self.info.get_mut(&evict).expect("entry");
                old.in_tried = false;
                old.clone()
            };
            let bucket = old.new_bucket(&key, &old.source);
            let pos = old.position(&key, true, bucket);
            self.clear_new(bucket, pos);
            self.info.get_mut(&evict).expect("entry").ref_count = 1;
            self.new[bucket][pos] = evict;
            self.n_new += 1;
        }
        self.tried[tried_bucket][tried_pos] = id;
        self.n_tried += 1;
        self.info.get_mut(&id).expect("entry").in_tried = true;
    }

    /// Good_ (addrman.cpp:198-245): a peer at this address answered
    fn good(&mut self, ip: &[u8; 16], port: u16, now: i64) {
        let Some(id) = self.find(ip) else {
            return;
        };
        let key = self.key;
        let info = self.info.get_mut(&id).expect("entry");
        if info.port != port {
            return;
        }
        info.last_success = now;
        info.last_try = now;
        info.attempts = 0;
        if info.in_tried {
            return;
        }
        let info = info.clone();
        let start = rand::thread_rng().gen_range(0..NEW_BUCKET_COUNT);
        let in_new = (0..NEW_BUCKET_COUNT)
            .map(|n| (n + start) % NEW_BUCKET_COUNT)
            .any(|b| self.new[b][info.position(&key, true, b)] == id);
        if in_new {
            self.make_tried(id);
        }
    }

    /// Add_ (addrman.cpp:247-313); true if the address is new
    fn add(
        &mut self,
        addr: &NetAddr,
        time: u32,
        source: &[u8; 16],
        penalty: i64,
        now: i64,
    ) -> bool {
        if !is_routable(&ip_of(&addr.ip)) {
            return false;
        }
        let key = self.key;
        let mut is_new = false;
        let id = match self.find(&addr.ip) {
            Some(id) => {
                let info = self.info.get_mut(&id).expect("entry");
                // Update the time now and then
                let online = now - (time as i64) < 24 * 60 * 60;
                let update_interval = if online { 60 * 60 } else { 24 * 60 * 60 };
                if time != 0
                    && (info.time == 0
                        || (info.time as i64) < time as i64 - update_interval - penalty)
                {
                    info.time = (time as i64 - penalty).max(0) as u32;
                }
                info.services |= addr.services;
                // Nothing new; already tried; in as many buckets as it may be
                if time == 0 || (info.time != 0 && time <= info.time) {
                    return false;
                }
                if info.in_tried || info.ref_count == NEW_BUCKETS_PER_ADDRESS {
                    return false;
                }
                // Each further bucket twice as hard to get into
                let factor = 1u32 << info.ref_count;
                if factor > 1 && rand::thread_rng().gen_range(0..factor) != 0 {
                    return false;
                }
                id
            }
            None => {
                let mut info = Info::new(addr.ip, addr.port, addr.services, time, *source);
                info.time = (time as i64 - penalty).max(0) as u32;
                self.n_new += 1;
                is_new = true;
                self.create(info)
            }
        };
        let info = self.info[&id].clone();
        let bucket = info.new_bucket(&key, source);
        let pos = info.position(&key, true, bucket);
        if self.new[bucket][pos] != id {
            let mut insert = self.new[bucket][pos] == EMPTY;
            if !insert {
                let there = &self.info[&self.new[bucket][pos]];
                // Over a terrible one, or one in other buckets too
                if there.is_terrible(now) || (there.ref_count > 1 && info.ref_count == 0) {
                    insert = true;
                }
            }
            if insert {
                self.clear_new(bucket, pos);
                self.info.get_mut(&id).expect("entry").ref_count += 1;
                self.new[bucket][pos] = id;
            } else if info.ref_count == 0 {
                self.delete(id);
            }
        }
        is_new
    }

    /// Attempt_ (addrman.cpp:315-332)
    fn attempt(&mut self, ip: &[u8; 16], port: u16, now: i64) {
        if let Some(id) = self.find(ip) {
            let info = self.info.get_mut(&id).expect("entry");
            if info.port == port {
                info.last_try = now;
                info.attempts += 1;
            }
        }
    }

    /// Select_ (addrman.cpp:334-371)
    fn select(&self, now: i64) -> Option<Info> {
        if self.len() == 0 {
            return None;
        }
        let mut rng = rand::thread_rng();
        let tried = self.n_tried > 0 && (self.n_new == 0 || rng.gen_range(0..2) == 0);
        let table = if tried { &self.tried } else { &self.new };
        let mut factor = 1.0;
        loop {
            let bucket = rng.gen_range(0..table.len());
            let pos = rng.gen_range(0..BUCKET_SIZE);
            let id = table[bucket][pos];
            if id == EMPTY {
                continue;
            }
            let info = &self.info[&id];
            if (rng.gen_range(0..1u32 << 30) as f64)
                < factor * info.chance(now) * (1u32 << 30) as f64
            {
                return Some(info.clone());
            }
            factor *= 1.2;
        }
    }

    /// GetAddr_ (addrman.cpp:451-469)
    fn get_addr(&mut self, now: i64) -> Vec<(u32, NetAddr)> {
        let n = (GETADDR_MAX_PCT * self.random.len() / 100).min(GETADDR_MAX);
        let mut out = Vec::with_capacity(n);
        let mut rng = rand::thread_rng();
        for k in 0..self.random.len() {
            if out.len() >= n {
                break;
            }
            let pick = rng.gen_range(k..self.random.len());
            self.swap_random(k, pick);
            let info = &self.info[&self.random[k]];
            if !info.is_terrible(now) {
                out.push((info.time, info.net()));
            }
        }
        out
    }

    /// Serialize (addrman.h:276-326), inside CAddrDB's magic and checksum (AddrDB.cpp:26-57)
    fn encode(&self, magic: &[u8; 4]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 50 + self.len() * 62 + NEW_BUCKET_COUNT * 4 + 32);
        out.extend_from_slice(magic);
        out.push(FORMAT_VERSION);
        out.push(KEY_SIZE);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&(self.n_new as i32).to_le_bytes());
        out.extend_from_slice(&(self.n_tried as i32).to_le_bytes());
        out.extend_from_slice(&((NEW_BUCKET_COUNT as i32) ^ (1 << 30)).to_le_bytes());
        let mut ids: Vec<i32> = self.info.keys().copied().collect();
        ids.sort_unstable();
        // The new entries, numbered as written; then the tried ones
        let mut index = HashMap::new();
        for id in &ids {
            let info = &self.info[id];
            if info.ref_count > 0 {
                index.insert(*id, index.len() as i32);
                put_info(&mut out, info);
            }
        }
        for id in &ids {
            let info = &self.info[id];
            if info.in_tried {
                put_info(&mut out, info);
            }
        }
        for bucket in &self.new {
            let held: Vec<i32> = bucket.iter().filter(|&&id| id != EMPTY).copied().collect();
            out.extend_from_slice(&(held.len() as i32).to_le_bytes());
            for id in held {
                out.extend_from_slice(&index[&id].to_le_bytes());
            }
        }
        let sum = dsha(&out);
        out.extend_from_slice(&sum);
        out
    }

    /// Unserialize (addrman.h:328-420): a file that does not read is None
    fn decode(body: &[u8]) -> Option<Self> {
        let mut r = Reader { b: body, at: 0 };
        let version = r.u8()?;
        if r.u8()? != KEY_SIZE {
            return None;
        }
        let key: [u8; 32] = r.take(32)?.try_into().ok()?;
        let n_new = r.i32()?;
        let n_tried = r.i32()?;
        let mut n_buckets = r.i32()?;
        if version != 0 {
            n_buckets ^= 1 << 30;
        }
        if n_new < 0 || n_tried < 0 || n_new as usize > NEW_BUCKET_COUNT * BUCKET_SIZE {
            return None;
        }
        let mut t = Tables::empty(key);
        let positions_usable = version == 1 && n_buckets == NEW_BUCKET_COUNT as i32;
        for n in 0..n_new {
            let mut info = r.info()?;
            info.random_pos = t.random.len();
            if !positions_usable {
                // Placed by its own source alone
                let bucket = info.new_bucket(&key, &info.source);
                let pos = info.position(&key, true, bucket);
                if t.new[bucket][pos] == EMPTY {
                    t.new[bucket][pos] = n;
                    info.ref_count += 1;
                }
            }
            t.by_ip.insert(info.ip, n);
            t.info.insert(n, info);
            t.random.push(n);
        }
        t.id_count = n_new;
        t.n_new = n_new as usize;
        let mut lost = 0;
        for _ in 0..n_tried {
            let mut info = r.info()?;
            let bucket = info.tried_bucket(&key);
            let pos = info.position(&key, false, bucket);
            if t.tried[bucket][pos] == EMPTY {
                let id = t.id_count;
                info.random_pos = t.random.len();
                info.in_tried = true;
                t.random.push(id);
                t.by_ip.insert(info.ip, id);
                t.info.insert(id, info);
                t.tried[bucket][pos] = id;
                t.id_count += 1;
            } else {
                lost += 1;
            }
        }
        t.n_tried = n_tried as usize - lost;
        for bucket in 0..n_buckets.max(0) as usize {
            let size = r.i32()?;
            for _ in 0..size.max(0) {
                let index = r.i32()?;
                if index >= 0 && index < n_new {
                    let info = t.info.get_mut(&index).expect("entry");
                    let pos = info.position(&key, true, bucket);
                    if positions_usable
                        && t.new[bucket][pos] == EMPTY
                        && info.ref_count < NEW_BUCKETS_PER_ADDRESS
                    {
                        info.ref_count += 1;
                        t.new[bucket][pos] = index;
                    }
                }
            }
        }
        // New entries no bucket took (collisions) go
        let orphans: Vec<i32> = t
            .info
            .iter()
            .filter(|(_, i)| !i.in_tried && i.ref_count == 0)
            .map(|(id, _)| *id)
            .collect();
        for id in orphans {
            t.delete(id);
        }
        Some(t)
    }
}

fn put_info(out: &mut Vec<u8>, info: &Info) {
    // CAddress on disk: nVersion, nTime, nServices, CService; then source, nLastSuccess, nAttempts
    out.extend_from_slice(&DISK_VERSION.to_le_bytes());
    out.extend_from_slice(&info.time.to_le_bytes());
    out.extend_from_slice(&info.services.to_le_bytes());
    out.extend_from_slice(&info.ip);
    out.extend_from_slice(&info.port.to_be_bytes());
    out.extend_from_slice(&info.source);
    out.extend_from_slice(&info.last_success.to_le_bytes());
    out.extend_from_slice(&info.attempts.to_le_bytes());
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let out = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn info(&mut self) -> Option<Info> {
        let _version = self.i32()?;
        let time = u32::from_le_bytes(self.take(4)?.try_into().ok()?);
        let services = u64::from_le_bytes(self.take(8)?.try_into().ok()?);
        let ip: [u8; 16] = self.take(16)?.try_into().ok()?;
        let port = u16::from_be_bytes(self.take(2)?.try_into().ok()?);
        let source: [u8; 16] = self.take(16)?.try_into().ok()?;
        let last_success = i64::from_le_bytes(self.take(8)?.try_into().ok()?);
        let attempts = self.i32()?;
        let mut info = Info::new(ip, port, services, time, source);
        info.last_success = last_success;
        info.attempts = attempts;
        Some(info)
    }
}

/// The address book
pub struct AddressBook {
    tables: Mutex<Tables>,
    path: Mutex<Option<PathBuf>>,
    magic: [u8; 4],
}

impl AddressBook {
    /// An empty book for the network with this message start
    pub fn new(magic: [u8; 4]) -> Self {
        Self {
            tables: Mutex::new(Tables::fresh()),
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
            Some(tables) => {
                let n = tables.len();
                *self.tables.lock() = tables;
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

    /// CAddrDB::Read (AddrDB.cpp:59-109): the checksum over all before it, the
    /// network magic, then the tables
    fn decode(&self, bytes: &[u8]) -> Option<Tables> {
        let body_len = bytes.len().checked_sub(32)?;
        let (body, sum) = bytes.split_at(body_len);
        if dsha(body) != sum {
            return None;
        }
        if body.starts_with(LEGACY_HEADER) {
            return self.decode_legacy(body);
        }
        if body.len() < 4 || body[..4] != self.magic {
            return None;
        }
        Tables::decode(&body[4..])
    }

    /// irondivid's older file: each address is added as if it told of itself
    fn decode_legacy(&self, body: &[u8]) -> Option<Tables> {
        if body.len() < 16 || body[8..12] != self.magic {
            return None;
        }
        let count = u32::from_le_bytes(body[12..16].try_into().ok()?) as usize;
        let data = &body[16..];
        if data.len() != count.checked_mul(LEGACY_ENTRY_LEN)? {
            return None;
        }
        let mut t = Tables::fresh();
        let now = now();
        for e in data.as_chunks::<LEGACY_ENTRY_LEN>().0 {
            let net = NetAddr {
                ip: e[..16].try_into().ok()?,
                port: u16::from_be_bytes([e[16], e[17]]),
                services: u64::from_le_bytes(e[18..26].try_into().ok()?),
            };
            let time = u32::from_le_bytes(e[26..30].try_into().ok()?);
            t.add(&net, time, &net.ip, 0, now);
        }
        Some(t)
    }

    /// Write the book (through a temporary file, so a stop part way leaves
    /// the last whole file)
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = self.path.lock().clone() else {
            return Ok(());
        };
        let bytes = self.tables.lock().encode(&self.magic);
        let tmp = path.with_extension("dat.new");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)
    }

    /// Store the addresses of an `addr` message from a peer at `source`, their
    /// times already read as divid reads them (main.cpp:538-553), each two
    /// hours older than the peer says. An address on port 0, which nothing
    /// can connect to, is left out (divid keeps it). The number new to the book.
    pub fn add(&self, addrs: &[(u32, NetAddr)], source: IpAddr) -> usize {
        self.add_at(addrs, source, TIME_PENALTY, now())
    }

    fn add_at(&self, addrs: &[(u32, NetAddr)], source: IpAddr, penalty: i64, now: i64) -> usize {
        let source = ip16(source);
        let mut t = self.tables.lock();
        addrs
            .iter()
            .filter(|(_, net)| net.port != 0)
            .filter(|(time, net)| t.add(net, *time, &source, penalty, now))
            .count()
    }

    /// Addresses a DNS seed gave, from 3 to 7 days ago as divid dates them
    /// (net.cpp ThreadDNSAddressSeed), the seed's first address as their source
    pub fn add_seeds(&self, addrs: &[SocketAddr]) {
        let Some(source) = addrs.first() else {
            return;
        };
        let now = now();
        let mut rng = rand::thread_rng();
        let dated: Vec<(u32, NetAddr)> = addrs
            .iter()
            .map(|a| {
                let ago = 3 * 24 * 60 * 60 + rng.gen_range(0..4 * 24 * 60 * 60);
                ((now - ago).max(0) as u32, to_net(a, 1))
            })
            .collect();
        self.add_at(&dated, source.ip(), 0, now);
    }

    /// An outbound peer at `addr` answered its version (addrman Good, main.cpp:443)
    pub fn good(&self, addr: SocketAddr) {
        self.tables
            .lock()
            .good(&ip16(addr.ip()), addr.port(), now());
    }

    /// A connection to `addr` is being made (addrman Attempt, net.cpp:530, :538)
    pub fn attempt(&self, addr: SocketAddr) {
        self.tables
            .lock()
            .attempt(&ip16(addr.ip()), addr.port(), now());
    }

    /// The answer to a getaddr: 23% of the book, at most 2500, at random,
    /// leaving out terrible entries (addrman GetAddr_)
    pub fn sample(&self) -> Vec<(u32, NetAddr)> {
        self.tables.lock().get_addr(now())
    }

    /// An address to dial and when it was last tried (addrman Select)
    pub fn select(&self) -> Option<(SocketAddr, i64)> {
        self.tables
            .lock()
            .select(now())
            .map(|i| (i.socket(), i.last_try))
    }

    /// How many addresses the book holds
    pub fn len(&self) -> usize {
        self.tables.lock().len()
    }

    /// Whether the book is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn to_net(addr: &SocketAddr, services: u64) -> NetAddr {
    NetAddr {
        services,
        ip: ip16(addr.ip()),
        port: addr.port(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> NetAddr {
        NetAddr::from_ipv4([a, b, c, d], port, 1)
    }

    /// A public address in a /16 of its own
    fn public(k: u16) -> NetAddr {
        v4(11 + (k / 256) as u8, (k % 256) as u8, 7, 9, 51476)
    }

    fn feeder() -> IpAddr {
        "127.0.0.12".parse().unwrap()
    }

    fn socket(n: &NetAddr) -> SocketAddr {
        SocketAddr::new(ip_of(&n.ip), n.port)
    }

    fn book_with(n: u16, time: u32) -> AddressBook {
        let book = AddressBook::new(MAGIC);
        book.add_at(
            &(0..n).map(|k| (time, public(k))).collect::<Vec<_>>(),
            feeder(),
            TIME_PENALTY,
            time as i64,
        );
        book
    }

    #[test]
    fn only_routable_addresses_with_a_port_are_kept() {
        let book = AddressBook::new(MAGIC);
        let now = 1_700_000_000;
        let added = book.add_at(
            &[
                (now, public(1)),
                (now, v4(127, 0, 0, 3, 51476)),
                (now, v4(10, 0, 0, 1, 51476)),
                (now, v4(192, 168, 1, 1, 51476)),
                (now, v4(192, 0, 2, 1, 51476)),
                (now, v4(31, 4, 4, 4, 0)),
                (now, public(2)),
            ],
            feeder(),
            TIME_PENALTY,
            now as i64,
        );
        assert_eq!(added, 2);
        assert_eq!(book.len(), 2);
    }

    #[test]
    fn a_kept_address_is_two_hours_older() {
        let now = 1_700_000_000u32;
        let book = book_with(1, now - 60);
        let t = book.tables.lock();
        let info = t.info.values().next().unwrap();
        assert_eq!(info.time as i64, (now - 60) as i64 - TIME_PENALTY);
    }

    #[test]
    fn one_entry_per_ip_whatever_the_port() {
        let now = 1_700_000_000u32;
        let book = book_with(1, now);
        let mut other = public(0);
        other.port = 51999;
        book.add_at(&[(now + 7200, other)], feeder(), TIME_PENALTY, now as i64);
        assert_eq!(book.len(), 1);
        let t = book.tables.lock();
        assert_eq!(
            t.info.values().next().unwrap().port,
            51476,
            "the first port stays"
        );
    }

    #[test]
    fn one_source_group_reaches_at_most_64_new_buckets() {
        let now = 1_700_000_000u32;
        let book = book_with(5000, now);
        let t = book.tables.lock();
        let used = t
            .new
            .iter()
            .filter(|b| b.iter().any(|&id| id != EMPTY))
            .count();
        assert!(used <= 64, "{used} buckets");
        assert!(t.len() <= 64 * BUCKET_SIZE);
        // 5000 addresses into 4096 places: about 2900 find a free one
        assert!((2600..3200).contains(&t.len()), "{} kept", t.len());
    }

    #[test]
    fn getaddr_gets_23_percent_and_leaves_out_terrible_ones() {
        let now = super::now() as u32;
        let book = book_with(100, now);
        let n = book.len();
        let sample = book.sample();
        assert_eq!(sample.len(), 23 * n / 100);
        // Fewer than five: 23% of them is none, as in divid
        assert!(book_with(4, now).sample().is_empty());
        // Not heard of for 30 days: left out
        let old = book_with(100, now - 31 * 24 * 60 * 60);
        assert!(old.sample().is_empty());
    }

    #[test]
    fn a_good_address_moves_to_tried_and_can_be_selected() {
        let now = super::now() as u32;
        let book = book_with(10, now);
        let (addr, n_new) = {
            let t = book.tables.lock();
            (t.info.values().next().unwrap().socket(), t.n_new)
        };
        book.good(addr);
        {
            let t = book.tables.lock();
            assert_eq!((t.n_new, t.n_tried), (n_new - 1, 1));
            let id = t.find(&ip16(addr.ip())).unwrap();
            assert!(t.info[&id].in_tried);
            assert_eq!(t.info[&id].ref_count, 0);
        }
        // Another port is another service: not this entry
        book.good(SocketAddr::new(addr.ip(), 1));
        assert_eq!(book.tables.lock().n_tried, 1);
        let picked = book.select().unwrap().0;
        assert!((0..10).map(|k| socket(&public(k))).any(|a| a == picked));
        book.attempt(addr);
        let t = book.tables.lock();
        let id = t.find(&ip16(addr.ip())).unwrap();
        assert_eq!(t.info[&id].attempts, 1);
    }

    #[test]
    fn the_book_is_kept_across_a_restart_in_divid_s_layout() {
        let dir = tempfile::tempdir().unwrap();
        let now = super::now() as u32;
        let book = book_with(0, now);
        assert_eq!(book.open(dir.path()), 0);
        book.add(
            &(0..50).map(|k| (now, public(k))).collect::<Vec<_>>(),
            feeder(),
        );
        book.good(socket(&public(7)));
        book.save().unwrap();
        let bytes = std::fs::read(dir.path().join(FILE_NAME)).unwrap();
        // CAddrDB: magic, then addrman format 1 with a 32-byte key
        assert_eq!(&bytes[..4], &MAGIC);
        assert_eq!((bytes[4], bytes[5]), (1, 32));
        let n_buckets = i32::from_le_bytes(bytes[46..50].try_into().unwrap());
        assert_eq!(n_buckets, 1024 ^ (1 << 30));

        let again = AddressBook::new(MAGIC);
        assert_eq!(again.open(dir.path()), book.len());
        let (a, b) = (book.tables.lock(), again.tables.lock());
        assert_eq!(a.key, b.key);
        assert_eq!((a.n_new, a.n_tried), (b.n_new, b.n_tried));
        let entries = |t: &Tables| {
            let mut v: Vec<_> = t
                .info
                .values()
                .map(|i| (i.ip, i.port, i.time, i.services, i.in_tried, i.ref_count))
                .collect();
            v.sort();
            v
        };
        assert_eq!(entries(&a), entries(&b));
        // Every entry back in its place (ids are numbered afresh on reading)
        let places = |t: &Tables, table: &Vec<[i32; BUCKET_SIZE]>| -> Vec<Vec<Option<[u8; 16]>>> {
            table
                .iter()
                .map(|b| {
                    b.iter()
                        .map(|&id| (id != EMPTY).then(|| t.info[&id].ip))
                        .collect()
                })
                .collect()
        };
        assert!(places(&a, &a.new) == places(&b, &b.new));
        assert!(places(&a, &a.tried) == places(&b, &b.tried));
    }

    /// A peers.dat divid 3.0.0 wrote on regtest after an addr of 10 public
    /// addresses from 127.0.1.9 (scripts/addr-gossip): read, every entry is
    /// found where divid's key puts it, so the bucket hashing is divid's
    #[test]
    fn reads_a_peers_dat_divid_wrote() {
        let bytes = include_bytes!("../tests/data/peers-divid-regtest.dat");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), bytes).unwrap();
        let book = AddressBook::new(MAGIC);
        assert_eq!(book.open(dir.path()), 10);
        let t = book.tables.lock();
        let source = ip16("127.0.1.9".parse().unwrap());
        for info in t.info.values() {
            assert_eq!(info.source, source);
            assert_eq!(
                info.ref_count,
                1,
                "{:?} not where divid put it",
                info.socket()
            );
            let bucket = info.new_bucket(&t.key, &info.source);
            assert_eq!(
                t.new[bucket][info.position(&t.key, true, bucket)],
                t.find(&info.ip).unwrap()
            );
        }
        drop(t);
        // And written again, byte for byte what divid wrote
        book.save().unwrap();
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME)).unwrap(), bytes);
    }

    #[test]
    fn an_older_irondivid_file_is_read() {
        let now = super::now() as u32;
        let mut body = LEGACY_HEADER.to_vec();
        body.extend_from_slice(&MAGIC);
        body.extend_from_slice(&3u32.to_le_bytes());
        for k in 0..3 {
            let n = public(k);
            body.extend_from_slice(&n.ip);
            body.extend_from_slice(&n.port.to_be_bytes());
            body.extend_from_slice(&n.services.to_le_bytes());
            body.extend_from_slice(&(now - 600).to_le_bytes());
        }
        let sum = dsha(&body);
        body.extend_from_slice(&sum);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), &body).unwrap();
        let book = AddressBook::new(MAGIC);
        assert_eq!(book.open(dir.path()), 3);
        let t = book.tables.lock();
        assert!(t.info.values().all(|i| i.time == now - 600));
    }

    #[test]
    fn a_file_that_does_not_read_is_started_over() {
        let dir = tempfile::tempdir().unwrap();
        let book = AddressBook::new(MAGIC);
        book.open(dir.path());
        let now = super::now() as u32;
        book.add(
            &(0..10).map(|k| (now, public(k))).collect::<Vec<_>>(),
            feeder(),
        );
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

    #[test]
    fn groups_are_divid_s() {
        let g = |s: &str| group(&ip16(s.parse().unwrap()));
        assert_eq!(g("1.2.3.4"), vec![1, 1, 2]);
        assert_eq!(g("127.0.0.12"), vec![0]);
        assert_eq!(g("10.1.2.3"), vec![0]);
        assert_eq!(g("2a01:4f8:c0c:1234::2"), vec![2, 0x2a, 0x01, 0x04, 0xf8]);
        assert_eq!(g("2001:470:1:2::3"), vec![2, 0x20, 0x01, 0x04, 0x70, 0x0f]);
        assert_eq!(g("2002:102:304::1"), vec![1, 1, 2]);
        assert_eq!(g("fd87:d87e:eb43:1234::1"), vec![3, 0x1f]);
    }
}
