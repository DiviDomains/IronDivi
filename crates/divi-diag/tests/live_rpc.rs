// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.16 against a mock JSON-RPC server: the private values in each answer
//! (peer and local addresses, the masternode outpoint, balances, the
//! credentials) never reach the output; a node that does not answer is
//! reported as a timeout, which is what sends diag to the A17 snapshot.

use divi_diag::collectors::live::{self, CallError, Rpc};
use divi_diag::frame::Out;
use divi_diag::redact::{Known, Redactor};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

const PRIVATE: &[&str] = &[
    "203.0.113.77",
    "198.51.100.23",
    "192.0.2.9",
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    "DHfrxHzGWW1fLVZ7RCeN1W2V8RANW3TUxr",
    "1234.56789",
    "s3cretpass",
    "rpcu5er",
];

fn answer(method: &str) -> String {
    match method {
        "getblockchaininfo" => r#"{"chain":"main","blocks":100,"headers":101,"bestblockhash":"00ab","difficulty":1.5,"chainwork":"ff"}"#.into(),
        "getnetworkinfo" => r#"{"version":1,"subversion":"/x/","protocolversion":70915,"connections":2,
            "networks":[{"name":"ipv4","limited":false,"reachable":true,"proxy":"192.0.2.9:9050"}],
            "localaddresses":[{"address":"203.0.113.77","port":51472,"score":1}]}"#.into(),
        "getpeerinfo" => r#"[{"id":1,"addr":"198.51.100.23:51472","addrlocal":"203.0.113.77:51472","version":70915,"inbound":false},
            {"id":2,"addr":"10.0.0.5:51472","inbound":true}]"#.into(),
        "getstakingstatus" => r#"{"validtime":true,"haveconnections":true,"walletunlocked":false,"staking status":false,"staking_balance":1234.56789,"stake split threshold":20000.0}"#.into(),
        "getmasternodestatus" => r#"{"txhash":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","outputidx":1,
            "netaddr":"203.0.113.77:51472","addr":"DHfrxHzGWW1fLVZ7RCeN1W2V8RANW3TUxr","status":4,"message":"Masternode successfully started"}"#.into(),
        "getwalletinfo" => r#"{"walletversion":61000,"balance":1234.56789,"txcount":3,"unlocked_until":0,"encryption_status":"locked"}"#.into(),
        "getdiaginfo" => r#"{"build":"x","diag_key":"abcdef","peers":[{"address":"198.51.100.23"}],"balance":1234.56789}"#.into(),
        _ => return format!(r#"{{"result":null,"error":{{"code":-32601,"message":"Method not found"}},"id":"diag"}}"#),
    }
}

/// Serve canned answers; each request checks the Basic credentials
fn serve(chunked: bool) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut got = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let t = String::from_utf8_lossy(&got).to_string();
                if let Some(i) = t.find("\r\n\r\n") {
                    let len: usize = t.lines().find_map(|l| l.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
                    if got.len() >= i + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let t = String::from_utf8_lossy(&got).to_string();
            // "rpcu5er:s3cretpass"
            if !t.contains("Authorization: Basic cnBjdTVlcjpzM2NyZXRwYXNz") {
                let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
                continue;
            }
            let body = &t[t.find("\r\n\r\n").unwrap() + 4..];
            let v: serde_json::Value = serde_json::from_str(body).unwrap();
            let m = v["method"].as_str().unwrap();
            let a = answer(m);
            let out = if a.starts_with("{\"result\"") { a } else { format!(r#"{{"result":{a},"error":null,"id":"diag"}}"#) };
            let resp = if chunked {
                let (x, y) = out.split_at(out.len() / 2);
                format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{x}\r\n{:x}\r\n{y}\r\n0\r\n\r\n", x.len(), y.len())
            } else {
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{out}", out.len())
            };
            let _ = s.write_all(resp.as_bytes());
        }
    });
    a
}

fn redactor() -> Redactor {
    Redactor::new([7; 32], &Known::default())
}

fn report(chunked: bool) -> String {
    let rpc = Rpc::new(serve(chunked), "rpcu5er", "s3cretpass", "cookie");
    let mut o = Out::capture();
    live::rpc_report(&mut o, &redactor(), &rpc, Duration::from_secs(5)).unwrap();
    o.captured()
}

#[test]
fn private_values_never_reach_the_output() {
    for chunked in [false, true] {
        let s = report(chunked);
        for p in PRIVATE {
            assert!(!s.contains(p), "{p} leaked:\n{s}");
        }
        assert!(s.contains("getblockchaininfo: answered"), "{s}");
        assert!(s.contains("blocks: 100"), "{s}");
        assert!(s.contains("2 peers"), "{s}");
        assert!(s.contains("addr=public peer-"), "{s}");
        assert!(s.contains("addr=private peer-"), "{s}");
        assert!(s.contains("fields not kept: addrlocal"), "{s}");
        assert!(s.contains("localaddresses: 1 entries (removed)"), "{s}");
        assert!(s.contains("proxy=set"), "{s}");
        assert!(s.contains("outpoint: outpoint-"), "{s}");
        assert!(s.contains("netaddr: public peer-"), "{s}");
        assert!(s.contains("balance: 100 % of the total (amount withheld)"), "{s}");
        assert!(s.contains("unlocked_until: locked (0)"), "{s}");
        assert!(s.contains("diag_key: (removed)"), "{s}");
        assert!(s.contains("getmempoolinfo: not available on this node"), "{s}");
        assert!(s.contains("staking status: false"), "{s}");
        assert!(s.contains("staking_balance: more than 0 (amount withheld)"), "{s}");
        assert!(!s.contains("20000"), "{s}");
    }
}

#[test]
fn wrong_credentials_are_reported_without_them() {
    let rpc = Rpc::new(serve(false), "rpcu5er", "wrong", "cookie");
    let mut o = Out::capture();
    assert_eq!(live::rpc_report(&mut o, &redactor(), &rpc, Duration::from_secs(5)), Err(CallError::Auth));
    let s = o.captured();
    assert!(s.contains("credentials refused"), "{s}");
    assert!(!s.contains("wrong") && !s.contains("rpcu5er"), "{s}");
}

#[test]
fn a_node_that_does_not_answer_is_a_timeout() {
    // accepts the connection, reads, never answers: the A17 case
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut keep = Vec::new();
        for s in l.incoming() {
            keep.push(s.unwrap());
        }
    });
    let rpc = Rpc::new(a, "u", "p", "cookie");
    let mut o = Out::capture();
    let t = Instant::now();
    assert_eq!(live::rpc_report(&mut o, &redactor(), &rpc, Duration::from_secs(2)), Err(CallError::Timeout));
    assert!(t.elapsed() < Duration::from_secs(4));
}

#[test]
fn nothing_listening_is_refused() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let rpc = Rpc::new(a, "u", "p", "cookie");
    let mut o = Out::capture();
    assert_eq!(live::rpc_report(&mut o, &redactor(), &rpc, Duration::from_secs(2)), Err(CallError::Refused));
}

#[test]
fn default_ports_match_divi_network() {
    use divi_network::constants as c;
    assert_eq!(live::default_port("main", false), c::DEFAULT_RPC_PORT_MAINNET);
    assert_eq!(live::default_port("testnet", false), c::DEFAULT_RPC_PORT_TESTNET);
    assert_eq!(live::default_port("regtest", false), c::DEFAULT_RPC_PORT_REGTEST);
    assert_eq!(live::default_port("main", true), c::DEFAULT_RPC_PORT_PRIVATEDIVI_MAINNET);
    assert_eq!(live::default_port("testnet", true), c::DEFAULT_RPC_PORT_PRIVATEDIVI_TESTNET);
    assert_eq!(live::default_port("regtest", true), c::DEFAULT_RPC_PORT_PRIVATEDIVI_REGTEST);
}

/// The A17 request: the mirror copy (found through the A14 path record),
/// then the data-dir copy; an incident written in reply is copied, and an
/// events.log budget line is reported as a refusal
#[test]
fn snapshot_request_is_written_and_answered() {
    use divi_diag::ctx::{Ctx, DataDir, Node};
    let t = tempfile::tempdir().unwrap();
    let dd = t.path().join("data");
    let mirror_root = t.path().join("state");
    let id = mirror_root.join("abc123");
    std::fs::create_dir_all(id.join("running")).unwrap();
    std::fs::create_dir_all(&dd).unwrap();
    std::fs::write(id.join("running/4242"), format!("datadir={}\npid=4242\n", dd.display())).unwrap();
    std::fs::write(id.join("events.log"), "old line\n").unwrap();
    let d = DataDir { n: 1, path: dd.clone(), chain: dd.clone(), network: "main".into(), ..Default::default() };
    let node = Node { pid: 4242, uid: Some(divi_diag::util::euid()), ..Default::default() };
    let ctx = Ctx { mirror_roots: vec![mirror_root], ..Default::default() };
    assert_eq!(live::mirror_dir(&ctx, &d).as_deref(), Some(id.as_path()));

    // the "node": answers the request with an incident and a budget line
    let idc = id.clone();
    let th = std::thread::spawn(move || {
        let req = idc.join("diag/snapshot-request");
        let t0 = Instant::now();
        while !req.exists() && t0.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::create_dir_all(idc.join("incidents")).unwrap();
        std::fs::write(idc.join("incidents/snap-1.txt"), "thread 1 futex_wait\n").unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(idc.join("events.log")).unwrap();
        f.write_all(b"incident budget exhausted\n").unwrap();
    });
    let mut o = Out::capture();
    live::snapshot(&mut o, &ctx, &d, &node, "datadir-1");
    th.join().unwrap();
    let s = o.captured();
    assert!(s.contains("snapshot request: mirror copy written"), "{s}");
    assert!(s.contains("snapshot request: data-dir copy written"), "{s}");
    assert!(dd.join("diag/snapshot-request").exists());
    assert!(s.contains("snapshot incident: snap-1.txt"), "{s}");
    assert!(s.contains("--- datadir-1/incidents/snap-1.txt\nthread 1 futex_wait"), "{s}");
    assert!(s.contains("snapshot refused: budget"), "{s}");
}
