// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! irondivid with -rest=1 serves Divi Core's REST interface on the RPC port
//! without credentials (rest.cpp, rpcserver.cpp:1019-1033); without it, and
//! for any other path, the answer is divid's plain `404 Not Found`.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// (status, Content-Type, body) of a request without credentials; None while
/// nothing listens
fn request(
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    auth: bool,
) -> Option<(u16, String, Vec<u8>)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
    let auth = if auth {
        "Authorization: Basic dGVzdDp0ZXN0\r\n"
    } else {
        ""
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok()?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.split_whitespace().nth(1)?.parse().ok()?;
    let ctype = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-type: ")
                .map(String::from)
        })
        .unwrap_or_default();
    Some((status, ctype, raw[split + 4..].to_vec()))
}

struct Daemon {
    child: Child,
    rpc: u16,
}

impl Daemon {
    fn start(datadir: &Path, rest: bool) -> Daemon {
        let rpc = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={rpc}"))
            .arg(format!("-port={}", free_port()))
            .args([
                "-bind=127.0.0.1",
                "-rpcuser=test",
                "-rpcpassword=test",
                "-staking=0",
            ])
            .arg(format!("-rest={}", u8::from(rest)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn irondivid");
        let mut d = Daemon { child, rpc };
        let deadline = Instant::now() + Duration::from_secs(120);
        while d.genesis().is_none() {
            assert!(d.child.try_wait().unwrap().is_none(), "irondivid exited");
            assert!(Instant::now() < deadline, "RPC did not come up");
            std::thread::sleep(Duration::from_millis(250));
        }
        d
    }

    fn genesis(&self) -> Option<String> {
        let body = r#"{"method":"getblockhash","params":[0],"id":1}"#;
        let (status, _, reply) = request(self.rpc, "POST", "/", body, true)?;
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_slice(&reply).ok()?;
        v["result"].as_str().map(String::from)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn rest_is_served_without_credentials_when_on() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), true);
    let genesis = d.genesis().unwrap();
    let (status, ctype, body) = request(
        d.rpc,
        "GET",
        &format!("/rest/block/notxdetails/{genesis}.json"),
        "",
        false,
    )
    .unwrap();
    assert_eq!(
        (status, ctype.as_str()),
        (200, "application/json"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    let block: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(block["hash"], genesis);
    assert_eq!(
        request(d.rpc, "GET", "/rest/tx/xyz.json", "", false).unwrap(),
        (400, "text/plain".into(), b"Invalid hash: xyz\r\n".to_vec())
    );
    assert_eq!(
        request(d.rpc, "GET", "/foo", "", false).unwrap(),
        (404, "text/plain".into(), b"Not Found".to_vec())
    );
}

#[test]
fn rest_is_off_by_default_as_divid() {
    let dir = tempfile::tempdir().unwrap();
    let d = Daemon::start(dir.path(), false);
    let genesis = d.genesis().unwrap();
    assert_eq!(
        request(
            d.rpc,
            "GET",
            &format!("/rest/block/{genesis}.json"),
            "",
            false
        )
        .unwrap(),
        (404, "text/plain".into(), b"Not Found".to_vec())
    );
}
