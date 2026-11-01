// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A block the node cannot write stops it, as Divi Core's AbortNode does
//! (ValidationState.cpp:17-27): `*** System error: ...` in the log, the
//! "fatal internal error" line on stderr, and a shutdown, after which a start
//! without the limit finds the chain it had. The write fails because the node
//! runs under a file size limit (RLIMIT_FSIZE, SIGXFSZ ignored), so no disk is
//! filled.

#![cfg(target_os = "linux")]

use divi_test_support::start_node;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

/// POST one JSON-RPC call; None when nothing answers
fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .ok()?;
    let body = serde_json::json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
        .to_string();
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

fn height(port: u16) -> Option<u64> {
    rpc(port, "getblockcount", serde_json::json!([]))?["result"].as_u64()
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The node's command; output to the console, so the log needs no file
fn node(dir: &Path, rpc_port: u16, p2p_port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("--regtest")
        .arg("--datadir")
        .arg(dir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &p2p_port.to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false"])
        .args([
            "--rpcuser",
            "test",
            "--rpcpassword",
            "test",
            "--printtoconsole",
        ])
        .stdin(Stdio::null());
    cmd
}

/// Bytes up to the last non-zero byte of the largest file under `dir`
fn largest_file(dir: &Path) -> u64 {
    let mut largest = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                let used = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
                largest = largest.max(used as u64);
            }
        }
    }
    largest
}

/// Every line `child` prints on stdout and stderr, collected as it comes
fn collect(child: &mut Child) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let out: Box<dyn Read + Send> = Box::new(child.stdout.take().unwrap());
    let err: Box<dyn Read + Send> = Box::new(child.stderr.take().unwrap());
    for stream in [out, err] {
        let lines = Arc::clone(&lines);
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                lines.lock().unwrap().push(line);
            }
        });
    }
    lines
}

fn limited(mut cmd: Command, limit: u64) -> Command {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let lim = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

/// Wait (bounded) until the node on `port` is at `want`
fn reaches(port: u16, want: u64, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if height(port) == Some(want) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// A follower with no wallet, so only the blocks it is sent are written, runs
/// under a file size limit a little above the largest file it holds; the
/// miner sends it blocks until one cannot be written
#[test]
fn a_block_that_cannot_be_written_stops_the_node() {
    let miner_dir = tempfile::tempdir().unwrap();
    let (child, miner_rpc, miner_p2p) = start_node(
        miner_dir.path(),
        |rpc_port, p2p_port| {
            let mut cmd = node(miner_dir.path(), rpc_port, p2p_port);
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            cmd
        },
        |rpc_port| height(rpc_port).is_some(),
    );
    let _miner = KillOnDrop(child);
    rpc(miner_rpc, "setgenerate", serde_json::json!([20])).expect("setgenerate");

    let dir = tempfile::tempdir().unwrap();
    let follower = |rpc_port, p2p_port| {
        let mut cmd = node(dir.path(), rpc_port, p2p_port);
        cmd.args([
            "--disablewallet",
            "--listen=0",
            &format!("--connect=127.0.0.1:{miner_p2p}"),
        ]);
        cmd
    };
    // The chain so far, written with no limit
    let (child, rpc_port, p2p_port) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut cmd = follower(rpc_port, p2p_port);
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            cmd
        },
        |rpc_port| height(rpc_port).is_some(),
    );
    let mut first = KillOnDrop(child);
    assert!(reaches(rpc_port, 20, 120), "the follower syncs");
    rpc(rpc_port, "stop", serde_json::json!([])).expect("stop");
    assert!(first.0.wait().unwrap().success(), "a clean stop");

    // Again, with every file limited to a little more than the largest holds
    let limit = largest_file(dir.path()) + 128 * 1024;
    let mut limited = KillOnDrop(
        limited(follower(rpc_port, p2p_port), limit)
            .spawn()
            .expect("spawn irondivid"),
    );
    let lines = collect(&mut limited.0);
    assert!(
        reaches(rpc_port, 20, 120),
        "the follower answers under the limit"
    );

    // Blocks until one cannot be written: then the follower stops on its own
    let mut last = 20;
    let deadline = Instant::now() + Duration::from_secs(900);
    let status = loop {
        if let Some(status) = limited.0.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        rpc(miner_rpc, "setgenerate", serde_json::json!([10])).expect("setgenerate");
        let target = height(miner_rpc).unwrap();
        if reaches(rpc_port, target, 60) {
            last = target;
            continue;
        }
        // Not taken: a failed write. The node has 60 s to stop.
        last = height(rpc_port).unwrap_or(last);
        let until = Instant::now() + Duration::from_secs(60);
        while limited.0.try_wait().unwrap().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(200));
        }
        break limited.0.try_wait().unwrap();
    };
    std::thread::sleep(Duration::from_millis(500));
    let printed = lines.lock().unwrap().join("\n");
    let tail: Vec<&str> = printed.lines().rev().take(15).collect();
    assert!(
        status.is_some(),
        "irondivid still runs after a failed write (height {last}); it printed:\n{}",
        tail.join("\n")
    );
    assert!(
        printed.contains("*** System error"),
        "no `*** System error` line; it printed:\n{}",
        tail.join("\n")
    );
    assert!(
        printed.contains("A fatal internal error occured, see debug.log for details"),
        "no fatal error line on stderr"
    );

    // Without the limit (and no peer) it starts again on the chain it had
    let (child, rpc_port, _) = start_node(
        dir.path(),
        |rpc_port, p2p_port| {
            let mut cmd = node(dir.path(), rpc_port, p2p_port);
            cmd.args(["--disablewallet", "--listen=0"])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| height(rpc_port).is_some(),
    );
    let _again = KillOnDrop(child);
    let now = height(rpc_port).unwrap();
    assert!(now >= last, "height {now} after the restart, {last} before");
}
