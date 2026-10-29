// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! irondivid started with divid's -rpckeepalive=0 closes each RPC connection
//! after its reply, as divid does (rpcserver.cpp:1014-1017).

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One getblockcount on a new connection: the reply's Connection header and
/// whether the node then closed the connection (within 2 s); None while the
/// RPC server does not answer
fn call(port: u16) -> Option<(String, bool)> {
    let body = r#"{"method":"getblockcount","params":[],"id":1}"#;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    // test:test
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    if !head.starts_with("HTTP/1.1 200") {
        return None;
    }
    let field = |name: &str| {
        head.split("\r\n")
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let len: usize = field("content-length").parse().unwrap_or(0);
    while buf.len() < end + 4 + len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let closed = matches!(stream.read(&mut chunk), Ok(0));
    Some((field("connection"), closed))
}

#[test]
fn rpckeepalive_0_closes_each_rpc_connection() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .args([
            "-regtest".to_string(),
            format!("-datadir={}", dir.path().display()),
            format!("-rpcport={rpc_port}"),
            format!("-port={}", free_port()),
            "-bind=127.0.0.1".into(),
            "-rpcuser=test".into(),
            "-rpcpassword=test".into(),
            "-disablewallet".into(),
            "-rpckeepalive=0".into(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn irondivid");
    let mut node = Node(child);
    let deadline = Instant::now() + Duration::from_secs(120);
    let reply = loop {
        if let Some(reply) = call(rpc_port) {
            break reply;
        }
        assert!(node.0.try_wait().unwrap().is_none(), "irondivid exited");
        assert!(Instant::now() < deadline, "RPC server did not come up");
        std::thread::sleep(Duration::from_millis(250));
    };
    assert_eq!(reply, ("close".to_string(), true));
}
