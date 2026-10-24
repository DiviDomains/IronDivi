// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Block files are imported beside start-up, as Divi Core imports them on a
//! thread of their own (init.cpp:1580): the RPC server answers while a
//! -loadblock file is still being read. bootstrap.dat is read from Divi
//! Core's network data directory, <datadir>/regtest on regtest
//! (chainparamsbase.cpp:68, init.cpp:698-699).

#![cfg(unix)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// A free port in 53720-53749, the range these tests may use
fn port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    for _ in 0..30 {
        let p = 53720 + NEXT.fetch_add(1, Ordering::Relaxed) % 30;
        if TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
    panic!("no free port in 53720-53749");
}

/// POST one JSON-RPC call; None while the server is not up
fn try_rpc(port: u16, method: &str, params: &Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
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

/// A regtest irondivid on `datadir` with no peers; "dGVzdDp0ZXN0" is base64
/// of test:test
fn irondivid(datadir: &Path, rpc_port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcport={rpc_port}"))
        .arg(format!("-port={}", port()))
        .args(["-bind=127.0.0.1", "-connect=127.0.0.1:1"])
        .args(["-rpcuser=test", "-rpcpassword=test"])
        .env("WALLET_LOOKAHEAD", "5")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

struct Daemon {
    child: Child,
    rpc_port: u16,
}

impl Daemon {
    fn spawn(datadir: &Path, extra: &[String]) -> Daemon {
        let rpc_port = port();
        let child = irondivid(datadir, rpc_port)
            .args(extra)
            .spawn()
            .expect("spawn irondivid");
        Daemon { child, rpc_port }
    }

    /// Wait at most `secs` for the RPC server to answer
    fn answers_within(&mut self, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return false;
            }
            if try_rpc(self.rpc_port, "getblockcount", &json!([])).is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply =
            try_rpc(self.rpc_port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
        reply["result"].clone()
    }

    fn height_reaches(&self, height: u64, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.rpc("getblockcount", json!([])).as_u64() == Some(height) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }

    fn stop(mut self) {
        let _ = try_rpc(self.rpc_port, "stop", &json!([]));
        let deadline = Instant::now() + Duration::from_secs(90);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A regtest chain of `n` blocks from a node of its own, exported as a block
/// file (--export-chain writes bootstrap.dat in Divi Core's format)
fn exported_chain(dir: &Path, n: u64) -> Vec<u8> {
    let source = dir.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let mut node = Daemon::spawn(&source, &[]);
    assert!(node.answers_within(120), "source node did not start");
    node.rpc("setgenerate", json!([n]));
    node.stop();
    let out = dir.join("export");
    let mut child = irondivid(&source, port())
        .args(["--export-chain", "--export-start", "0", "--export-end"])
        .arg(n.to_string())
        .arg("--export-output")
        .arg(&out)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "--export-chain did not finish");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::fs::read(out.join("bootstrap.dat")).unwrap()
}

/// The RPC server answers while a -loadblock file is still being read. The
/// file is a named pipe nobody writes to until the server has answered; a
/// node that imports before it serves RPC never answers.
#[test]
fn rpc_answers_while_a_block_file_is_imported() {
    let dir = tempfile::tempdir().unwrap();
    let file = exported_chain(dir.path(), 15);

    let fifo = dir.path().join("blocks.fifo");
    let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

    let datadir = dir.path().join("node");
    std::fs::create_dir_all(&datadir).unwrap();
    let mut node = Daemon::spawn(&datadir, &[format!("-loadblock={}", fifo.display())]);
    let answered = node.answers_within(60);

    // Feed the pipe in any case, so a node blocked on it can finish
    let writer = std::thread::spawn(move || {
        let mut pipe = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        pipe.write_all(&file).unwrap();
    });
    assert!(
        answered,
        "the RPC server did not answer while the block file was being read"
    );
    assert_eq!(
        node.rpc("getblockcount", json!([])),
        0,
        "imported before the file was written"
    );
    writer.join().unwrap();
    assert!(
        node.height_reaches(15, 60),
        "the block file was not imported"
    );
    node.stop();
}

/// bootstrap.dat is read from <datadir>/regtest on regtest, where divid
/// keeps it, and renamed bootstrap.dat.old there
#[test]
fn bootstrap_dat_is_read_from_the_network_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = exported_chain(dir.path(), 12);

    let datadir = dir.path().join("node");
    std::fs::create_dir_all(datadir.join("regtest")).unwrap();
    std::fs::write(datadir.join("regtest").join("bootstrap.dat"), &file).unwrap();
    let mut node = Daemon::spawn(&datadir, &[]);
    assert!(node.answers_within(120), "node did not start");
    assert!(
        node.height_reaches(12, 60),
        "regtest/bootstrap.dat was not imported"
    );
    node.stop();
    assert!(!datadir.join("regtest").join("bootstrap.dat").exists());
    assert!(datadir.join("regtest").join("bootstrap.dat.old").exists());
}
