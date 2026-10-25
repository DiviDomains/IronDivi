// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The proxy, onion, Tor control, -dns and -upnp options as divid reads them
//! (net.cpp:1690-1800, init.cpp:1621, torcontrol.cpp): what irondivid does at
//! start and what getnetworkinfo then shows. Every node and stand-in here is on
//! 127.0.0.1.

#![cfg(unix)]

use divi_test_support::free_port;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// POST one JSON-RPC call; None while the server is not up.
/// "dGVzdDp0ZXN0" is base64 of test:test
fn try_rpc(port: u16, method: &str, params: &Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let start = response.find("\r\n\r\n")? + 4;
    serde_json::from_str(&response[start..]).ok()
}

/// How a start ended: up (with the node, to call and stop), or an exit code
/// and stderr
enum Started {
    Up(Node),
    Exited(i32, String),
}

struct Node {
    child: Child,
    port: u16,
}

impl Node {
    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply =
            try_rpc(self.port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method}: {reply}");
        reply["result"].clone()
    }

    /// getnetworkinfo's entry for `name` (ipv4, ipv6, onion)
    fn network(&self, name: &str) -> Value {
        let info = self.rpc("getnetworkinfo", json!([]));
        info["networks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no {name} in {info}"))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = try_rpc(self.port, "stop", &json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a regtest irondivid on 127.0.0.1 with `extra` options (no peers)
fn start(datadir: &Path, extra: &[&str]) -> Started {
    let (port, p2p_port) = (free_port(), free_port());
    let stderr = datadir.join("stderr.txt");
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false", "-discover=0"])
        // No Tor controller (it would try 127.0.0.1:9051) unless the test
        // names its own control port
        .args((!extra.iter().any(|a| a.starts_with("-torcontrol"))).then_some("-listenonion=0"))
        .args(["--connect", "127.0.0.1:1"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let text = std::fs::read_to_string(&stderr).unwrap_or_default();
            return Started::Exited(status.code().unwrap_or(-1), text);
        }
        if try_rpc(port, "getblockcount", &json!([])).is_some() {
            return Started::Up(Node { child, port });
        }
        assert!(Instant::now() < deadline, "irondivid did not start");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn up(datadir: &Path, extra: &[&str]) -> Node {
    match start(datadir, extra) {
        Started::Up(node) => node,
        Started::Exited(code, text) => panic!("{extra:?}: exit {code}: {text}"),
    }
}

/// With -proxy the IPv4 and IPv6 networks name it, with random credentials
/// unless -proxyrandomize=0 (net.cpp:1761-1779, rpcnet.cpp:326); -proxy=0 and
/// -noproxy set none
#[test]
fn proxy_and_proxyrandomize_in_getnetworkinfo() {
    for (options, proxy, randomize) in [
        (vec!["-proxy=127.0.0.1:9"], "127.0.0.1:9", true),
        (
            vec!["-proxy=127.0.0.1:9", "-proxyrandomize=0"],
            "127.0.0.1:9",
            false,
        ),
        (vec!["-proxy=0"], "", false),
        (vec!["-noproxy"], "", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let node = up(dir.path(), &options);
        for net in ["ipv4", "ipv6"] {
            let n = node.network(net);
            assert_eq!(n["proxy"], proxy, "{options:?} {n}");
            assert_eq!(
                n["proxy_randomize_credentials"], randomize,
                "{options:?} {n}"
            );
        }
    }
}

/// What a SOCKS5 stand-in on 127.0.0.1 was asked: per connection, the
/// methods offered and the CONNECT address type and destination
type Socks5Seen = std::sync::Arc<std::sync::Mutex<Vec<(Vec<u8>, u8, String)>>>;

fn read_n(c: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    c.read_exact(&mut b).map(|_| b)
}

/// One SOCKS5 exchange: take username/password when offered, record the
/// CONNECT, refuse it
fn socks5_serve(c: &mut TcpStream, record: &Socks5Seen) -> std::io::Result<()> {
    let head = read_n(c, 2)?;
    let methods = read_n(c, head[1] as usize)?;
    let auth = methods.contains(&2);
    c.write_all(&[5, if auth { 2 } else { 0 }])?;
    if auth {
        let user = read_n(c, 2)?;
        read_n(c, user[1] as usize)?;
        let len = read_n(c, 1)?;
        read_n(c, len[0] as usize)?;
        c.write_all(&[1, 0])?;
    }
    let req = read_n(c, 4)?;
    let dest = match req[3] {
        1 => {
            let b = read_n(c, 4)?;
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        3 => {
            let len = read_n(c, 1)?;
            String::from_utf8_lossy(&read_n(c, len[0] as usize)?).into_owned()
        }
        _ => {
            let b: [u8; 16] = read_n(c, 16)?.try_into().unwrap();
            std::net::Ipv6Addr::from(b).to_string()
        }
    };
    read_n(c, 2)?;
    record.lock().unwrap().push((methods, req[3], dest));
    c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
}

/// A SOCKS5 stand-in on 127.0.0.1 that records each CONNECT and refuses it
fn socks5_stand_in() -> (u16, Socks5Seen) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Socks5Seen = Default::default();
    let record = seen.clone();
    std::thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let record = record.clone();
            std::thread::spawn(move || {
                let _ = socks5_serve(&mut c, &record);
            });
        }
    });
    (port, seen)
}

/// The destination goes to the proxy as a name, an onion address as its
/// .onion name (netbase.cpp:379-386, CNetAddr::ToStringIP); irondivid sent
/// the binary address. The onion target is never reachable off the proxy.
#[test]
fn proxy_destination_is_sent_as_a_name() {
    let (socks, seen) = socks5_stand_in();
    let dir = tempfile::tempdir().unwrap();
    let proxy = format!("-proxy=127.0.0.1:{socks}");
    // abcdefghij234567.onion as an OnionCat address
    let connect = "-connect=[fd87:d87e:eb43:44:3214:c742:75be:77df]:51476";
    let node = up(dir.path(), &[proxy.as_str(), connect]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while seen.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(node);
    let seen = seen.lock().unwrap().clone();
    assert!(!seen.is_empty(), "nothing reached the proxy");
    for (_, atyp, dest) in &seen {
        assert_eq!(
            (*atyp, dest.as_str()),
            (3, "abcdefghij234567.onion"),
            "{seen:?}"
        );
    }
}

/// The onion network: not limited by default; reachable through -proxy, or
/// through -onion's own proxy, not with -onion=0 (net.cpp:1774-1800)
#[test]
fn onion_network_in_getnetworkinfo() {
    for (options, proxy, reachable) in [
        (vec![], "", false),
        (vec!["-proxy=127.0.0.1:9"], "127.0.0.1:9", true),
        (vec!["-onion=127.0.0.1:8"], "127.0.0.1:8", true),
        (
            vec!["-proxy=127.0.0.1:9", "-onion=127.0.0.1:8"],
            "127.0.0.1:8",
            true,
        ),
        (vec!["-proxy=127.0.0.1:9", "-onion=0"], "127.0.0.1:9", false),
        (vec!["-proxy=127.0.0.1:9", "-noonion"], "127.0.0.1:9", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let node = up(dir.path(), &options);
        let n = node.network("onion");
        assert_eq!(n["limited"], false, "{options:?} {n}");
        assert_eq!(n["reachable"], reachable, "{options:?} {n}");
        assert_eq!(n["proxy"], proxy, "{options:?} {n}");
    }
}

/// A -onion that does not resolve stops the start (net.cpp:1790-1794)
#[test]
fn bad_onion_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    match start(dir.path(), &["-onion=notahost.invalid"]) {
        Started::Exited(code, text) => {
            assert_ne!(code, 0);
            assert!(
                text.contains("Invalid -onion address or hostname: 'notahost.invalid'"),
                "{text}"
            );
        }
        Started::Up(_) => panic!("started with a bad -onion"),
    }
}

/// An onion peer is dialled through -onion's proxy, not -proxy's
/// (SetProxy(NET_TOR), net.cpp:1797)
#[test]
fn onion_peer_goes_through_the_onion_proxy() {
    let (socks, seen) = socks5_stand_in();
    let (onion, onion_seen) = socks5_stand_in();
    let dir = tempfile::tempdir().unwrap();
    let proxy = format!("-proxy=127.0.0.1:{socks}");
    let onion_proxy = format!("-onion=127.0.0.1:{onion}");
    let node = up(
        dir.path(),
        &[
            proxy.as_str(),
            onion_proxy.as_str(),
            "-connect=abcdefghij234567.onion:51476",
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while onion_seen.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(node);
    let got = onion_seen.lock().unwrap().clone();
    assert!(!got.is_empty(), "nothing reached the onion proxy");
    assert!(
        got.iter()
            .all(|(_, atyp, d)| *atyp == 3 && d == "abcdefghij234567.onion"),
        "{got:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "went through -proxy: {:?}",
        seen.lock().unwrap()
    );
}

fn exit_text(datadir: &Path, extra: &[&str]) -> String {
    match start(datadir, extra) {
        Started::Exited(code, text) => {
            assert_ne!(code, 0, "{extra:?}");
            text
        }
        Started::Up(_) => panic!("{extra:?}: started"),
    }
}

/// With -dns=0 a host name is not looked up: a -proxy or -externalip host
/// name stops the start (net.cpp:1759, :1767-1771, :1834-1839)
#[test]
fn dns_off_refuses_host_names_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let text = exit_text(dir.path(), &["-dns=0", "-proxy=localhost:9"]);
    assert!(
        text.contains("Invalid -proxy address or hostname: 'localhost:9'"),
        "{text}"
    );
    let dir = tempfile::tempdir().unwrap();
    let text = exit_text(dir.path(), &["-dns=0", "-externalip=localhost"]);
    assert!(
        text.contains("Cannot resolve -externalip address: 'localhost'"),
        "{text}"
    );
}

/// Whether a -connect peer named by host name is dialled: with -dns it is
/// resolved and dialled, with -dns=0 not (ConnectSocketByName,
/// netbase.cpp:640-652)
#[test]
fn dns_off_does_not_dial_a_peer_host_name() {
    for (dns, dialled) in [("-dns=1", true), ("-dns=0", false)] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let connect = format!(
            "-connect=localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let dir = tempfile::tempdir().unwrap();
        let node = up(dir.path(), &[dns, connect.as_str()]);
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut got = false;
        while !got && Instant::now() < deadline {
            got = listener.accept().is_ok();
            std::thread::sleep(Duration::from_millis(200));
        }
        drop(node);
        assert_eq!(got, dialled, "{dns}");
    }
}

/// With a proxy a peer host name goes to the proxy unresolved, whatever -dns
/// says (net.cpp:1221-1236, netbase.cpp:654-660)
#[test]
fn proxy_gets_a_peer_host_name() {
    for dns in ["-dns=1", "-dns=0"] {
        let (socks, seen) = socks5_stand_in();
        let dir = tempfile::tempdir().unwrap();
        let proxy = format!("-proxy=127.0.0.1:{socks}");
        let node = up(
            dir.path(),
            &[dns, proxy.as_str(), "-connect=localhost:51476"],
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while seen.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        drop(node);
        let got = seen.lock().unwrap().clone();
        assert!(!got.is_empty(), "{dns}: nothing reached the proxy");
        assert!(
            got.iter()
                .all(|(_, atyp, d)| *atyp == 3 && d == "localhost"),
            "{dns}: {got:?}"
        );
    }
}

/// What a fake Tor control port on 127.0.0.1 was sent, one line each
type ControlSeen = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// A fake Tor control port on 127.0.0.1 that offers `methods`, takes any
/// AUTHENTICATE and gives the onion service SERVICE_ID
fn tor_control_stand_in(methods: &'static str) -> (u16, ControlSeen) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: ControlSeen = Default::default();
    let record = seen.clone();
    std::thread::spawn(move || {
        for c in listener.incoming().flatten() {
            let record = record.clone();
            std::thread::spawn(move || {
                let mut w = c.try_clone().unwrap();
                for line in std::io::BufRead::lines(std::io::BufReader::new(c)) {
                    let Ok(line) = line else { break };
                    let out = if line == "PROTOCOLINFO 1" {
                        format!("250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods}\r\n250 OK\r\n")
                    } else if line.starts_with("AUTHENTICATE") {
                        "250 OK\r\n".to_string()
                    } else if line.starts_with("ADD_ONION ") {
                        format!("250-ServiceID={SERVICE_ID}\r\n250-PrivateKey=RSA1024:not-a-real-key\r\n250 OK\r\n")
                    } else {
                        "510 Unrecognized command\r\n".to_string()
                    };
                    record.lock().unwrap().push(line);
                    if w.write_all(out.as_bytes()).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, seen)
}

const SERVICE_ID: &str = "abcdefghij234567";

fn wait_until(mut done: impl FnMut() -> bool, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    done()
}

/// With -listenonion the node asks the control port for a hidden service on
/// its listen port and advertises it: a local address with LOCAL_MANUAL,
/// onion reachable through 127.0.0.1:9050, the key kept in the datadir
/// (torcontrol.cpp:491-548)
#[test]
fn tor_controller_advertises_the_onion_service() {
    let (control, seen) = tor_control_stand_in("NULL");
    let dir = tempfile::tempdir().unwrap();
    let torcontrol = format!("-torcontrol=127.0.0.1:{control}");
    let node = up(dir.path(), &["-listenonion=1", torcontrol.as_str()]);
    let name = format!("{SERVICE_ID}.onion");
    let mut local = Value::Null;
    assert!(
        wait_until(
            || {
                local = node.rpc("getnetworkinfo", json!([]))["localaddresses"].clone();
                local
                    .as_array()
                    .is_some_and(|l| l.iter().any(|a| a["address"] == name))
            },
            30
        ),
        "{local}"
    );
    let got = seen.lock().unwrap().clone();
    assert_eq!(got[..2], ["PROTOCOLINFO 1", "AUTHENTICATE"]);
    let port = got[2]
        .strip_prefix("ADD_ONION NEW:RSA1024 Port=")
        .and_then(|r| r.split_once(','))
        .map(|(p, to)| (p.to_string(), to.to_string()))
        .unwrap_or_else(|| panic!("{got:?}"));
    assert_eq!(port.1, format!("127.0.0.1:{}", port.0));
    assert_eq!(
        local,
        json!([{"address": name, "port": port.0, "score": "4"}])
    );
    let onion = node.network("onion");
    assert_eq!(onion["reachable"], true, "{onion}");
    assert_eq!(onion["proxy"], "127.0.0.1:9050", "{onion}");
    assert_eq!(onion["proxy_randomize_credentials"], false, "{onion}");
    drop(node);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("onion_private_key")).unwrap(),
        "RSA1024:not-a-real-key"
    );
}

/// -torpassword goes to the control port quoted, with HASHEDPASSWORD
/// (torcontrol.cpp:650-659); the value here is a fixed fake
#[test]
fn torpassword_is_sent_for_hashedpassword() {
    let (control, seen) = tor_control_stand_in("HASHEDPASSWORD");
    let dir = tempfile::tempdir().unwrap();
    let torcontrol = format!("-torcontrol=127.0.0.1:{control}");
    let node = up(
        dir.path(),
        &[
            "-listenonion=1",
            torcontrol.as_str(),
            "-torpassword=dummy-not-a-password",
        ],
    );
    assert!(wait_until(|| seen.lock().unwrap().len() >= 3, 30));
    drop(node);
    let got = seen.lock().unwrap().clone();
    assert_eq!(got[1], r#"AUTHENTICATE "dummy-not-a-password""#);
}

/// -listenonion is on by default but off under -listen=0 unless given
/// (DEFAULT_LISTEN_ONION, net.cpp:1706-1711); -bind makes -listen=1
#[test]
fn listenonion_default_and_listen_off() {
    for (extra, contacted) in [
        (&[][..], true),
        (&["-listen=0"][..], false),
        (&["-listen=0", "-listenonion=1"][..], true),
        (&["-listenonion=0"][..], false),
    ] {
        let (control, seen) = tor_control_stand_in("NULL");
        let dir = tempfile::tempdir().unwrap();
        let torcontrol = format!("-torcontrol=127.0.0.1:{control}");
        let mut args = vec![torcontrol.as_str()];
        args.extend(extra);
        let node = up(dir.path(), &args);
        let got = wait_until(
            || !seen.lock().unwrap().is_empty(),
            if contacted { 30 } else { 5 },
        );
        drop(node);
        assert_eq!(got, contacted, "{extra:?}");
    }
}

/// -upnp is an option irondivid takes, not "not supported; ignored". The
/// row uses -upnp=0 only: -upnp=1 would send SSDP on the LAN
#[test]
fn upnp_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let node = up(dir.path(), &["-upnp=0"]);
    drop(node);
    let read = |p: &str| std::fs::read_to_string(dir.path().join(p)).unwrap_or_default();
    let text = read("stderr.txt") + &read("debug.log") + &read("regtest/debug.log");
    assert!(text.contains("Initializing node"), "no log: {text}");
    assert!(!text.contains("-upnp is not supported"), "{text}");
}
