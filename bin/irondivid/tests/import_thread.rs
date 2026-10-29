// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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

use divi_test_support::{free_port, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
        .arg(format!("-port={}", free_port()))
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
    /// Start a node on `datadir` and wait until its RPC server answers
    fn start(datadir: &Path, extra: &[String]) -> Daemon {
        let (child, rpc_port, _) = start_node(
            datadir,
            |rpc_port, _| {
                let mut cmd = irondivid(datadir, rpc_port);
                cmd.args(extra);
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", &json!([])).is_some(),
        );
        Daemon { child, rpc_port }
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
    let node = Daemon::start(&source, &[]);
    node.rpc("setgenerate", json!([n]));
    node.stop();
    let out = dir.join("export");
    let mut child = irondivid(&source, free_port())
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
    // The RPC server must answer while the file is still unwritten: a node
    // that does not is stopped by `start`, which fails with its log
    let node = Daemon::start(&datadir, &[format!("-loadblock={}", fifo.display())]);

    let writer = std::thread::spawn(move || {
        let mut pipe = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        pipe.write_all(&file).unwrap();
    });
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
    let node = Daemon::start(&datadir, &[]);
    assert!(
        node.height_reaches(12, 60),
        "regtest/bootstrap.dat was not imported"
    );
    node.stop();
    assert!(!datadir.join("regtest").join("bootstrap.dat").exists());
    assert!(datadir.join("regtest").join("bootstrap.dat.old").exists());
}
