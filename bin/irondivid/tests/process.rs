// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! irondivid as a process, as divid is one: its pid file, a second start on
//! its data directory, a stop during start-up, and -daemon (divid.cpp,
//! init.cpp, util.cpp).

#![cfg(unix)]

use divi_test_support::{free_port, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WALLET_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";

/// POST one JSON-RPC call; None while the server is not up
fn try_rpc(port: u16, method: &str, params: &Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
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

/// irondivid on regtest in `datadir` with no peers
fn irondivid(datadir: &Path, rpc_port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &free_port().to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false"])
        .args(["--connect", "127.0.0.1:1"])
        // "dGVzdDp0ZXN0" is base64 of test:test
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .env("WALLET_MNEMONIC", WALLET_MNEMONIC)
        .env("WALLET_LOOKAHEAD", "5")
        .env_remove("WALLET_HDSEED")
        .env_remove("WALLET_MNEMONIC_PASSPHRASE");
    cmd
}

struct Daemon {
    child: Child,
    rpc_port: u16,
}

impl Daemon {
    fn start(datadir: &Path) -> Daemon {
        let (child, rpc_port, _) = start_node(
            datadir,
            |rpc_port, _| {
                let mut cmd = irondivid(datadir, rpc_port);
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", &json!([])).is_some(),
        );
        Daemon { child, rpc_port }
    }

    fn stop(mut self) {
        try_rpc(self.rpc_port, "stop", &json!([])).expect("stop");
        wait_exit(&mut self.child, 60).expect("irondivid did not exit");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The exit code once `child` has ended, within `secs`
fn wait_exit(child: &mut Child, secs: u64) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status.code().unwrap_or(-1));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// divid's pid file names the process and ends in a newline (CreatePidFile,
/// util.cpp:122-128), and goes at a clean stop (init.cpp:396)
#[test]
fn pid_file_names_the_process_with_a_newline() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path());
    let pid = std::fs::read_to_string(dir.path().join("divid.pid")).unwrap();
    assert_eq!(pid, format!("{}\n", daemon.child.id()));
    daemon.stop();
    assert!(!dir.path().join("divid.pid").exists());
}

/// A second start on the data directory of a running node stops at the lock
/// and leaves the running node's pid file alone: divid writes its pid file
/// only once it holds the lock (init.cpp:850-861, :1470)
#[test]
fn second_start_leaves_the_running_nodes_pid_file() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path());
    let first = std::fs::read_to_string(dir.path().join("divid.pid")).unwrap();
    let mut second = irondivid(dir.path(), free_port())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert_eq!(wait_exit(&mut second, 60), Some(1));
    let mut err = String::new();
    second
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(
        err.contains("Cannot obtain a lock on data directory"),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("divid.pid")).ok(),
        Some(first)
    );
    daemon.stop();
}

/// A SIGTERM while the node is still starting (here during the -rescan of a
/// start) stops it with exit code 1: divid's init returns !fRequestShutdown
/// (init.cpp:1536-1539, :1661) and divid.cpp:180 turns that into 1
#[test]
fn a_stop_during_start_exits_with_one() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path());
    for _ in 0..8 {
        try_rpc(daemon.rpc_port, "setgenerate", &json!([50])).expect("setgenerate");
    }
    daemon.stop();
    let pid_file = dir.path().join("divid.pid");
    let mut child = irondivid(dir.path(), free_port())
        .arg("-rescan")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !pid_file.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let code = wait_exit(&mut child, 120);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(code, Some(1));
    assert!(!pid_file.exists());
}

/// `-daemon`: started from `cwd` with stdout and stderr to files there; the
/// parent's exit code, its stdout, and the child's pid from its pid file once
/// it answers RPC
fn start_daemon(datadir: &Path, cwd: &Path) -> (Option<i32>, String, Option<u32>, u16) {
    let rpc_port = free_port();
    let out = cwd.join("out");
    let mut parent = irondivid(datadir, rpc_port)
        .arg("-daemon")
        .current_dir(cwd)
        .stdout(std::fs::File::create(&out).unwrap())
        .stderr(std::fs::File::create(cwd.join("err")).unwrap())
        .spawn()
        .unwrap();
    let code = wait_exit(&mut parent, 60);
    let deadline = Instant::now() + Duration::from_secs(120);
    while try_rpc(rpc_port, "getblockcount", &json!([])).is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let child = std::fs::read_to_string(datadir.join("divid.pid"))
        .ok()
        .and_then(|p| p.trim().parse().ok());
    (
        code,
        std::fs::read_to_string(&out).unwrap(),
        child,
        rpc_port,
    )
}

/// Stop the `-daemon` child by RPC and wait for it to go, killing it after a
/// minute
fn stop_daemon(child: Option<u32>, rpc_port: u16) {
    let _ = try_rpc(rpc_port, "stop", &json!([]));
    if let Some(pid) = child {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
}

/// divid's `-daemon` prints "DIVI server starting" on stdout, and its parent
/// exits 0 (divid.cpp:122-131)
#[test]
fn daemon_parent_says_divi_server_starting() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let (code, out, child, rpc_port) = start_daemon(dir.path(), cwd.path());
    stop_daemon(child, rpc_port);
    assert_eq!(code, Some(0));
    assert_eq!(out.lines().next(), Some("DIVI server starting"), "{out}");
    assert!(child.is_some(), "the child answered and wrote its pid file");
}

/// divid's `-daemon` child keeps the working directory and the standard
/// streams it was started with: it calls setsid and nothing else
/// (divid.cpp:132-139)
#[test]
fn daemon_child_keeps_its_directory_and_streams() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let (code, _, child, rpc_port) = start_daemon(dir.path(), cwd.path());
    let pid = child.expect("the child answered and wrote its pid file");
    let where_ = std::fs::read_link(format!("/proc/{pid}/cwd")).ok();
    let stdout = std::fs::read_link(format!("/proc/{pid}/fd/1")).ok();
    stop_daemon(child, rpc_port);
    assert_eq!(code, Some(0));
    assert_eq!(where_, Some(cwd.path().to_path_buf()));
    assert_eq!(stdout, Some(cwd.path().join("out")));
}

/// A start and a clean stop write on stderr only what divid writes there:
/// its warnings and errors (InitWarning, InitError, noui.cpp:38-40), here the
/// warning about an unencrypted wallet it gives at every start (init.cpp:1227-1232)
#[test]
fn a_start_and_a_stop_write_only_divids_warning_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let err = dir.path().join("stderr");
    let mut child = irondivid(dir.path(), rpc_port)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&err).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while try_rpc(rpc_port, "getblockcount", &json!([])).is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = try_rpc(rpc_port, "stop", &json!([]));
    let code = wait_exit(&mut child, 60);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(code, Some(0));
    assert_eq!(
        std::fs::read_to_string(&err).unwrap(),
        "Warning: Make sure to encrypt your wallet and delete all non-encrypted backups after you verified that wallet works!\n"
    );
}
