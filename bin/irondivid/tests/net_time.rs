// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The network time offset as Divi Core keeps it from its peers' version
//! messages (timedata.cpp:45-105), reported by getinfo and getnetworkinfo
//! (rpcmisc.cpp:147, rpcnet.cpp:374). Every wait is bounded.

#![cfg(unix)]

use divi_test_support::start_node;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::fd::FromRawFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const REGTEST_MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];
const WAIT: Duration = Duration::from_secs(30);

/// One JSON-RPC call (test:test); None while the server is not up
fn try_rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok()?;
    let start = resp.find("\r\n\r\n")? + 4;
    let reply: Value = serde_json::from_str(&resp[start..]).ok()?;
    assert!(reply["error"].is_null(), "{method}: {}", reply["error"]);
    Some(reply["result"].clone())
}

struct Daemon {
    child: Child,
    rpc_port: u16,
    p2p_port: u16,
}

fn command(datadir: &Path, rpc_port: u16, p2p_port: u16, extra: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcport={rpc_port}"))
        .arg(format!("-port={p2p_port}"))
        .args([
            "-bind=127.0.0.1",
            "-rpcuser=test",
            "-rpcpassword=test",
            "-staking=0",
        ])
        .args(extra);
    cmd
}

impl Daemon {
    fn start(datadir: &Path, extra: &[&str]) -> Daemon {
        let (child, rpc_port, p2p_port) = start_node(
            datadir,
            |rpc_port, p2p_port| {
                let mut cmd = command(datadir, rpc_port, p2p_port, extra);
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", json!([])).is_some(),
        );
        Daemon {
            child,
            rpc_port,
            p2p_port,
        }
    }

    fn rpc(&self, method: &str) -> Value {
        self.rpc_with(method, json!([]))
    }

    fn rpc_with(&self, method: &str, params: Value) -> Value {
        try_rpc(self.rpc_port, method, params).unwrap_or_else(|| panic!("{method}"))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = REGTEST_MAGIC.to_vec();
    let mut name = [0u8; 12];
    name[..command.len()].copy_from_slice(command.as_bytes());
    m.extend_from_slice(&name);
    m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    m.extend_from_slice(&divi_crypto::double_sha256(payload)[..4]);
    m.extend_from_slice(payload);
    m
}

fn rand_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        ^ u64::from(std::process::id())
}

/// The payload of the next `command` message (others skipped), within WAIT
fn expect(s: &mut TcpStream, command: &str) -> Vec<u8> {
    s.set_read_timeout(Some(WAIT)).unwrap();
    loop {
        let mut header = [0u8; 24];
        s.read_exact(&mut header).expect("message header");
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).expect("message payload");
        let end = header[4..16].iter().position(|&b| b == 0).unwrap_or(12);
        if &header[4..4 + end] == command.as_bytes() {
            return payload;
        }
    }
}

/// A version message sent at `time`
fn version_at(time: i64) -> Vec<u8> {
    let addr = |a: SocketAddr| {
        let mut v = 1u64.to_le_bytes().to_vec();
        let ip = match a.ip() {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(v6) => v6.octets(),
        };
        v.extend_from_slice(&ip);
        v.extend_from_slice(&a.port().to_be_bytes());
        v
    };
    let mut v = 70915i32.to_le_bytes().to_vec();
    v.extend_from_slice(&1u64.to_le_bytes());
    v.extend_from_slice(&time.to_le_bytes());
    v.extend_from_slice(&addr("0.0.0.0:0".parse().unwrap()));
    v.extend_from_slice(&addr("0.0.0.0:0".parse().unwrap()));
    v.extend_from_slice(&rand_nonce().to_le_bytes());
    v.push(7);
    v.extend_from_slice(b"/raw:1/");
    v.extend_from_slice(&0i32.to_le_bytes());
    v.push(1);
    v
}

/// A TCP connection to `to` from the local address `from`, so each test peer
/// has an address of its own (Divi Core takes one sample per address)
fn connect_from(from: Ipv4Addr, to: SocketAddr) -> TcpStream {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0, "socket");
        let sa = |ip: Ipv4Addr, port: u16| libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        let local = sa(from, 0);
        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        assert_eq!(
            libc::bind(fd, &local as *const _ as *const libc::sockaddr, len),
            0,
            "bind {from}"
        );
        let SocketAddr::V4(to) = to else {
            panic!("IPv4 only")
        };
        let remote = sa(*to.ip(), to.port());
        assert_eq!(
            libc::connect(fd, &remote as *const _ as *const libc::sockaddr, len),
            0,
            "connect from {from}"
        );
        TcpStream::from_raw_fd(fd)
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A peer from 127.0.0.`n` whose version message is `skew` seconds off our
/// clock; kept open until dropped
fn peer(d: &Daemon, n: u8, skew: i64) -> TcpStream {
    let mut s = connect_from(
        Ipv4Addr::new(127, 0, 0, n),
        SocketAddr::from(([127, 0, 0, 1], d.p2p_port)),
    );
    s.write_all(&frame("version", &version_at(unix_now() + skew)))
        .unwrap();
    expect(&mut s, "version");
    expect(&mut s, "verack");
    s.write_all(&frame("verack", &[])).unwrap();
    s
}

fn offsets(d: &Daemon) -> (Value, Value) {
    (
        d.rpc("getinfo")["timeoffset"].clone(),
        d.rpc("getnetworkinfo")["timeoffset"].clone(),
    )
}

/// Wait (bounded) until getinfo and getnetworkinfo give an offset within a
/// second of `want` (the node reads its clock a moment after the peer did)
fn wait_offset(d: &Daemon, want: i64) {
    let near = |v: &Value| v.as_i64().is_some_and(|o| (o - want).abs() <= 1);
    let deadline = Instant::now() + WAIT;
    loop {
        let (info, net) = offsets(d);
        if near(&info) && near(&net) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "offset {want}: getinfo {info}, getnetworkinfo {net}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Four peers 10 minutes ahead make the offset +600: our 0 and their four
/// samples are five, an odd count (timedata.cpp:77-82). It stays after they
/// leave, and a peer from an address already sampled changes nothing
#[test]
fn the_offset_is_the_median_of_the_peers_version_times() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), &[]);
    assert_eq!(offsets(&d), (json!(0), json!(0)));
    let mut peers: Vec<TcpStream> = (10..13).map(|n| peer(&d, n, 600)).collect();
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        offsets(&d),
        (json!(0), json!(0)),
        "three peers: four samples"
    );
    peers.push(peer(&d, 13, 600));
    wait_offset(&d, 600);
    drop(peers);
    // Gone peers keep their samples; the same addresses add none
    let again: Vec<TcpStream> = (10..14).map(|n| peer(&d, n, -600)).collect();
    std::thread::sleep(Duration::from_secs(1));
    wait_offset(&d, 600);
    drop(again);
}

/// Four peers 80 minutes ahead: past 70 minutes the offset is 0, and with no
/// peer within 5 minutes of us the node warns that its clock may be wrong, in
/// getinfo's errors (timedata.cpp:81-101, rpcmisc.cpp:156)
#[test]
fn a_median_past_seventy_minutes_warns() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), &[]);
    let _peers: Vec<TcpStream> = (20..24).map(|n| peer(&d, n, 80 * 60)).collect();
    let warning = "Warning: Please check that your computer's date and time are correct! If your clock is wrong DIVI Core will not work properly.";
    let deadline = Instant::now() + WAIT;
    while d.rpc("getinfo")["errors"] != warning {
        assert!(
            Instant::now() < deadline,
            "errors: {}",
            d.rpc("getinfo")["errors"]
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(offsets(&d), (json!(0), json!(0)));
    assert_eq!(d.rpc("getmininginfo")["errors"], warning);
}

/// A node whose peers put the network 30 minutes ahead: four raw peers from
/// 127.0.0.`first`.. (`skew` seconds off), the offset waited for
fn ahead(d: &Daemon, first: u8, skew: i64) -> Vec<TcpStream> {
    let peers = (first..first + 4).map(|n| peer(d, n, skew)).collect();
    wait_offset(d, skew);
    peers
}

/// A block 2 h 30 min ahead of the clock is too new on local time (CheckBlock:
/// at most 2 hours past GetAdjustedTime for a PoW block,
/// BlockCheckingHelpers.cpp:29-31) and taken with a network offset of +1 h
#[test]
fn the_future_block_limit_is_on_the_adjusted_clock() {
    // A node that makes the block, its clock set 2 h 30 min ahead
    let miner_dir = tempfile::tempdir().unwrap();
    let miner = Daemon::start(miner_dir.path(), &[]);
    miner.rpc_with("setmocktime", json!([unix_now() + 9000]));
    miner.rpc_with("setgenerate", json!([1]));

    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), &[]);
    let _peers = ahead(&d, 30, 3600);
    // The node fetches it from the miner. The miner's own version, 2 h 30 min
    // ahead, is a sixth sample: an even count, so the offset stays
    d.rpc_with(
        "addnode",
        json!([format!("127.0.0.1:{}", miner.p2p_port), "onetry"]),
    );
    let deadline = Instant::now() + WAIT;
    while d.rpc("getblockcount") != json!(1) {
        assert!(
            Instant::now() < deadline,
            "the block 2 h 30 min ahead was not taken; offset {:?}",
            offsets(&d)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The blocks the node makes carry the adjusted time (BlockFactory.cpp:77,
/// BlockProofProver.cpp:36)
#[test]
fn blocks_made_carry_the_adjusted_time() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), &[]);
    let _peers = ahead(&d, 40, 1800);
    let before = unix_now();
    d.rpc_with("setgenerate", json!([1]));
    let block = d.rpc_with("getblock", json!([d.rpc("getbestblockhash")]));
    let time = block["time"].as_i64().unwrap();
    assert!(
        (before + 1795..=unix_now() + 1805).contains(&time),
        "block time {time}, clock {before}"
    );
}
