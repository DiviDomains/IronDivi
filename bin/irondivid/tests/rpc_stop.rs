// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The `stop` RPC must shut the daemon down the same way SIGTERM does.

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

/// POST one JSON-RPC call; None while the server is not up yet.
fn rpc(port: u16, method: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":[]}}"#);
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let start = response.find("\r\n\r\n")? + 4;
    Some(response[start..].to_string())
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn rpc_stop_exits_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let p2p_port = free_port();

    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("--regtest")
        .arg("--datadir")
        .arg(dir.path())
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false"])
        // RPC always requires credentials; "dGVzdDp0ZXN0" is base64 of test:test
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn irondivid");
    let mut node = KillOnDrop(child);

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(body) = rpc(rpc_port, "getblockcount") {
            assert!(body.contains("\"result\""), "getblockcount: {body}");
            break;
        }
        assert!(
            node.0.try_wait().unwrap().is_none(),
            "irondivid exited before its RPC server came up"
        );
        assert!(Instant::now() < deadline, "RPC server did not come up");
        std::thread::sleep(Duration::from_millis(250));
    }

    let reply = rpc(rpc_port, "stop").expect("stop reply");
    assert!(reply.contains("DIVI server stopping"), "stop: {reply}");

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "irondivid still running 30 s after the stop RPC"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        status.success(),
        "irondivid exit status after stop: {status}"
    );
    assert!(
        rpc(rpc_port, "getblockcount").is_none(),
        "RPC still answering after stop"
    );
}
