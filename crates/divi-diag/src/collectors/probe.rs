// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.15: the network probe. It goes only to the DNS seeds compiled into
//! this release (`divi_primitives::test_vectors::dns_seeds`), never to
//! anything from a config file or a log, and never to the receiver (§8.4
//! probes that only after consent). It writes results only: no address,
//! no seed answer, no peer user agent.
//!
//! For each network a data dir uses (divi mainnet when none was found):
//! DNS resolution yes/no and time, a TCP connect to up to two of the
//! answers on the P2P port, and one `version` exchange on the first that
//! connects, which gives the peer's height and our clock offset from its
//! timestamp. The connection is closed after their `version`; no `verack`
//! is sent, so the peer never counts us as a peer.

use super::head;
use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `divi-network` `PROTOCOL_VERSION` (a test checks it)
pub const PROTOCOL_VERSION: i32 = 70915;
const DNS_SECS: u64 = 10;
const CONNECT_SECS: u64 = 5;
const READ_SECS: u64 = 8;

/// One network the probe can reach: seeds, P2P port and message magic
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Net {
    pub name: &'static str,
    pub seeds: &'static [&'static str],
    pub port: u16,
    pub magic: [u8; 4],
}

/// The compiled-in networks with DNS seeds (regtest has none)
pub fn networks() -> Vec<Net> {
    use divi_primitives::test_vectors::dns_seeds::{divi, privatedivi};
    vec![
        Net { name: "main", seeds: divi::MAINNET, port: 51472, magic: [0xdf, 0xa0, 0x8d, 0x8f] },
        Net { name: "testnet", seeds: divi::TESTNET, port: 51474, magic: [0xdf, 0xa0, 0x8d, 0x78] },
        Net { name: "privatedivi main", seeds: privatedivi::MAINNET, port: 52472, magic: [0x70, 0xd2, 0x76, 0x11] },
        Net { name: "privatedivi testnet", seeds: privatedivi::TESTNET, port: 52474, magic: [0x70, 0xd1, 0x76, 0x12] },
    ]
}

/// The error class B2.15 records: never the message text, which can hold
/// an address
pub fn class(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => "refused",
        K::TimedOut | K::WouldBlock => "timeout",
        K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe => "reset by peer",
        K::UnexpectedEof => "closed by peer",
        K::NotFound => "DNS: no such name",
        K::PermissionDenied => "denied (firewall or sandbox)",
        K::AddrNotAvailable => "no route (address not available)",
        _ => match e.raw_os_error() {
            Some(libc::ENETUNREACH) => "network unreachable",
            Some(libc::EHOSTUNREACH) => "host unreachable",
            _ if e.to_string().contains("failed to lookup address") || e.to_string().contains("Name or service") => "DNS",
            _ => "other",
        },
    }
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    let a = Sha256::digest(b);
    Sha256::digest(a).into()
}

/// A wire message: magic, command padded to 12, length, checksum, payload
pub fn message(magic: [u8; 4], cmd: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + payload.len());
    m.extend_from_slice(&magic);
    let mut c = [0u8; 12];
    c[..cmd.len()].copy_from_slice(cmd.as_bytes());
    m.extend_from_slice(&c);
    m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    m.extend_from_slice(&sha256d(payload)[..4]);
    m.extend_from_slice(payload);
    m
}

/// Our `version` payload, laid out as `divi-network` `VersionMessage`:
/// both addresses zero (nothing about this host goes out), no services,
/// height 0, no relay
pub fn version_payload(now: i64, nonce: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    p.extend_from_slice(&0u64.to_le_bytes());
    p.extend_from_slice(&now.to_le_bytes());
    p.extend_from_slice(&[0u8; 26]); // addr_recv
    p.extend_from_slice(&[0u8; 26]); // addr_from
    p.extend_from_slice(&nonce.to_le_bytes());
    let ua = concat!("/irondivi-diag:", env!("CARGO_PKG_VERSION"), "/");
    p.push(ua.len() as u8);
    p.extend_from_slice(ua.as_bytes());
    p.extend_from_slice(&0i32.to_le_bytes());
    p.push(0);
    p
}

/// What we keep of the peer's `version`
#[derive(Debug, PartialEq, Eq)]
pub struct TheirVersion {
    pub version: i32,
    pub timestamp: i64,
    pub height: Option<i32>,
}

/// Parse a `version` payload (the fields after the receiver's address are
/// optional, as in Divi Core)
pub fn parse_version(p: &[u8]) -> Option<TheirVersion> {
    if p.len() < 20 + 26 {
        return None;
    }
    let version = i32::from_le_bytes(p[0..4].try_into().ok()?);
    let timestamp = i64::from_le_bytes(p[12..20].try_into().ok()?);
    let mut i = 20 + 26 + 26 + 8;
    let height = (|| {
        let first = *p.get(i)?;
        let (n, w) = match first {
            0xfd => (u16::from_le_bytes(p.get(i + 1..i + 3)?.try_into().ok()?) as usize, 3),
            0xfe | 0xff => return None,
            n => (n as usize, 1),
        };
        i += w + n;
        Some(i32::from_le_bytes(p.get(i..i + 4)?.try_into().ok()?))
    })();
    Some(TheirVersion { version, timestamp, height })
}

/// Read messages until `version` (at most 4, payloads up to 1 MB)
pub fn read_version(s: &mut impl Read, magic: [u8; 4]) -> Result<TheirVersion, String> {
    for _ in 0..4 {
        let mut h = [0u8; 24];
        s.read_exact(&mut h).map_err(|e| class(&e).to_string())?;
        if h[0..4] != magic {
            return Err("wrong network magic (not a node of this network, or a middlebox)".into());
        }
        let len = u32::from_le_bytes(h[16..20].try_into().unwrap()) as usize;
        if len > 1 << 20 {
            return Err(format!("message of {len} bytes"));
        }
        let mut p = vec![0u8; len];
        s.read_exact(&mut p).map_err(|e| class(&e).to_string())?;
        if sha256d(&p)[..4] != h[20..24] {
            return Err("checksum mismatch".into());
        }
        let cmd: Vec<u8> = h[4..16].iter().copied().take_while(|&b| b != 0).collect();
        if cmd == b"version" {
            return parse_version(&p).ok_or_else(|| "version message too short".into());
        }
    }
    Err("no version message in the first 4 messages".into())
}

fn now_secs_f() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Resolve on a thread so a hung resolver costs at most `DNS_SECS`
fn resolve(host: &'static str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = (host, port).to_socket_addrs().map(|i| i.collect::<Vec<_>>());
        let _ = tx.send(r);
    });
    match rx.recv_timeout(Duration::from_secs(DNS_SECS)) {
        Ok(Ok(v)) if v.is_empty() => Err("DNS: no addresses".into()),
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(match class(&e) {
            "other" => "DNS".into(),
            c => c.to_string(),
        }),
        Err(_) => Err(format!("DNS: timeout after {DNS_SECS} s")),
    }
}

/// The handshake on one connected stream
fn handshake(mut s: TcpStream, net: &Net) -> Result<(TheirVersion, f64), String> {
    let _ = s.set_read_timeout(Some(Duration::from_secs(READ_SECS)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(READ_SECS)));
    let nonce: u64 = rand::random();
    let sent = now_secs_f();
    s.write_all(&message(net.magic, "version", &version_payload(sent as i64, nonce)))
        .map_err(|e| class(&e).to_string())?;
    let v = read_version(&mut s, net.magic)?;
    let got = now_secs_f();
    // their clock minus ours at the midpoint of the exchange
    let offset = v.timestamp as f64 - (sent + got) / 2.0;
    Ok((v, offset))
}

fn probe_net(o: &mut Out, net: &Net) {
    outln!(o);
    outln!(o, "network {} (P2P port {}):", net.name, net.port);
    let mut connected: Vec<(usize, TcpStream)> = Vec::new();
    let mut tried = 0;
    let start = Instant::now();
    for (si, seed) in net.seeds.iter().enumerate() {
        // keep the whole probe inside its 30 s: DNS for further seeds stops
        // once the connects are done or 12 s have gone
        if si > 0 && (tried >= 2 || start.elapsed() > Duration::from_secs(12)) {
            outln!(o, "  seeds {} to {}: not resolved (two connects done, or 12 s gone)", si + 1, net.seeds.len());
            break;
        }
        let t = Instant::now();
        let r = resolve(seed, net.port);
        let ms = t.elapsed().as_millis();
        let addrs = match r {
            Ok(a) => {
                let v4 = a.iter().filter(|x| x.is_ipv4()).count();
                outln!(o, "  seed {}: DNS ok in {ms} ms ({} answers: {v4} IPv4, {} IPv6)", si + 1, a.len(), a.len() - v4);
                a
            }
            Err(c) => {
                outln!(o, "  seed {}: DNS failed in {ms} ms: {c}", si + 1);
                continue;
            }
        };
        // two seeds' addresses at most; IPv4 first, then IPv6
        let mut order: Vec<&SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).collect();
        order.extend(addrs.iter().filter(|a| a.is_ipv6()));
        for a in order {
            if tried >= 2 {
                break;
            }
            tried += 1;
            let t = Instant::now();
            match TcpStream::connect_timeout(a, Duration::from_secs(CONNECT_SECS)) {
                Ok(s) => {
                    outln!(o, "  connect {tried} ({}): ok in {} ms", fam(a), t.elapsed().as_millis());
                    connected.push((tried, s));
                }
                Err(e) => outln!(o, "  connect {tried} ({}): failed in {} ms: {}", fam(a), t.elapsed().as_millis(), class(&e)),
            }
        }
    }
    if tried == 0 {
        outln!(o, "  no TCP connect tried (no address resolved)");
    }
    if connected.is_empty() {
        outln!(o, "  version handshake: not tried (no connection)");
    }
    // a peer may drop us (full, or our zero addresses): try the next one
    for (n, s) in connected {
        match handshake(s, net) {
            Ok((v, off)) => {
                outln!(o, "  version handshake (connect {n}): ok; their protocol {}, their height {}", v.version,
                    v.height.map(|h| h.to_string()).unwrap_or_else(|| "(not sent)".into()));
                outln!(o, "  clock offset (their clock minus ours): {off:+.1} s{}",
                    if off.abs() > 70.0 * 60.0 { "  (over 70 min: blocks will be refused)" } else { "" });
                break;
            }
            Err(c) => outln!(o, "  version handshake (connect {n}): failed: {c}"),
        }
    }
}

fn fam(a: &SocketAddr) -> &'static str {
    if a.is_ipv4() { "IPv4" } else { "IPv6" }
}

/// The network to probe: the first one a data dir uses, else divi mainnet
pub fn wanted(ctx: &Ctx) -> Vec<Net> {
    let all = networks();
    let mut v: Vec<Net> = Vec::new();
    for d in &ctx.datadirs {
        if let Some(n) = all.iter().find(|n| n.name == d.network) {
            if !v.contains(n) {
                v.push(n.clone());
            }
        }
    }
    if v.is_empty() && !ctx.datadirs.iter().any(|d| d.network.ends_with("regtest")) {
        v.push(all[0].clone());
    }
    // the §B4 budget is 30 s: DNS 10 + two connects 5 + handshake 8 fit once
    v.truncate(1);
    v
}

pub fn probe(ctx: &Ctx, o: &mut Out) {
    o.file("host/probe.txt");
    head(o, "B2.15 network probe (compiled-in DNS seeds only; results, no addresses)");
    if ctx.offline {
        outln!(o, "skipped: --offline");
        return;
    }
    let proxy = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()));
    outln!(o, "proxy variables set: {} (the probe connects directly; P2P does not use them)", if proxy { "yes" } else { "no" });
    let nets = wanted(ctx);
    if nets.is_empty() {
        outln!(o, "nothing to probe: regtest has no seeds");
    }
    for n in &nets {
        probe_net(o, n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_roundtrip() {
        let p = version_payload(1_700_000_000, 7);
        let v = parse_version(&p).unwrap();
        assert_eq!(v, TheirVersion { version: PROTOCOL_VERSION, timestamp: 1_700_000_000, height: Some(0) });
        // the minimal form: no fields after addr_recv
        let v = parse_version(&p[..46]).unwrap();
        assert_eq!(v.height, None);
    }

    #[test]
    fn reads_version_after_other_messages() {
        let magic = networks()[0].magic;
        let mut w = message(magic, "sendheaders", &[]);
        w.extend(message(magic, "version", &version_payload(5, 1)));
        let v = read_version(&mut &w[..], magic).unwrap();
        assert_eq!(v.timestamp, 5);
        let mut bad = message(magic, "version", &version_payload(5, 1));
        bad[22] ^= 1;
        assert!(read_version(&mut &bad[..], magic).unwrap_err().contains("checksum"));
        assert!(read_version(&mut &w[..], [1, 2, 3, 4]).unwrap_err().contains("magic"));
    }

    #[test]
    fn loopback_handshake() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let net = Net { name: "test", seeds: &[], port: addr.port(), magic: [9, 9, 9, 9] };
        let srv = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let v = read_version(&mut s, [9, 9, 9, 9]).unwrap();
            assert_eq!(v.version, PROTOCOL_VERSION);
            let ts = now_secs_f() as i64 + 100;
            let mut p = version_payload(ts, 2);
            let n = p.len();
            p[n - 5..n - 1].copy_from_slice(&12345i32.to_le_bytes());
            s.write_all(&message([9, 9, 9, 9], "version", &p)).unwrap();
        });
        let s = TcpStream::connect(addr).unwrap();
        let (v, off) = handshake(s, &net).unwrap();
        srv.join().unwrap();
        assert_eq!(v.height, Some(12345));
        assert!((off - 100.0).abs() < 3.0, "{off}");
    }
}
