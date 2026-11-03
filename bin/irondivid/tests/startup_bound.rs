// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The start-up bound (diag plan A1, A18's `-startuptimeout`).
//!
//! A FIFO where `peers.dat` belongs holds start-up in `db-open`: the read
//! blocks until a writer opens it, which never happens, and the start-up
//! thread uses no CPU meanwhile. With `-startuptimeout=2` the run ends with
//! code 10 and an `exit` record naming the phase, in the data directory's
//! runs.log and in the mirror's. Without it the node keeps waiting and
//! writes one incident and one events.log line.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A data directory whose peers.dat is a FIFO no one writes to
fn stalling_datadir(dir: &Path) -> PathBuf {
    let data = dir.join("data");
    std::fs::create_dir(&data).unwrap();
    let fifo = std::ffi::CString::new(data.join("peers.dat").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    data
}

fn start(dir: &Path, data: &Path, args: &[&str], env: &[(&str, &str)]) -> KillOnDrop {
    let state = dir.join("state");
    let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("-regtest")
        .arg(format!("-datadir={}", data.display()))
        .arg(format!("-rpcport={}", free_port()))
        .arg(format!("-port={}", free_port()))
        .args([
            "-bind=127.0.0.1",
            "-staking=0",
            "-rpcuser=test",
            "-rpcpassword=test",
        ])
        .args(args)
        // The A14 mirror under the test's own directory
        .env("HOME", dir)
        .env("XDG_STATE_HOME", &state)
        .envs(env.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    KillOnDrop(child)
}

fn wait_for_file(path: &Path, what: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(what) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "no {what:?} in {}:\n{text}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Every runs.log under `dir`
fn find_runs_logs(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            find_runs_logs(&p, out);
        } else if p.file_name().is_some_and(|n| n == "runs.log") {
            out.push(p);
        }
    }
}

#[test]
fn startuptimeout_ends_a_stalled_start_with_code_10() {
    let dir = tempfile::tempdir().unwrap();
    let data = stalling_datadir(dir.path());
    let mut node = start(dir.path(), &data, &["-startuptimeout=2"], &[]);
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the stalled start did not end");
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(status.code(), Some(10));

    let reason = " reason=\"start-up stalled in db-open\" ";
    let log = std::fs::read_to_string(data.join("diag/runs.log")).unwrap();
    let exit = log.lines().find(|l| l.contains(" exit code=")).expect(&log);
    assert!(exit.contains(" exit code=10 run=1 "), "{log}");
    assert!(exit.contains(reason), "{log}");

    let mut mirrors = Vec::new();
    find_runs_logs(&dir.path().join("state"), &mut mirrors);
    assert_eq!(mirrors.len(), 1, "{mirrors:?}");
    let mirror = std::fs::read_to_string(&mirrors[0]).unwrap();
    assert!(
        mirror
            .lines()
            .any(|l| l.contains(" exit code=10 ") && l.contains(reason)),
        "{mirror}"
    );

    let info = std::fs::read_to_string(data.join("diag/incidents/1/info.txt")).unwrap();
    assert!(info.contains("startup-stall"), "{info}");
    assert!(info.contains("phase=db-open"), "{info}");
    assert!(info.contains("exit=yes"), "{info}");
    let events = std::fs::read_to_string(data.join("diag/events.log")).unwrap();
    assert!(events.contains(" phase db-open running 2 s"), "{events}");
}

#[test]
fn without_startuptimeout_a_stall_is_written_down_and_the_node_waits() {
    let dir = tempfile::tempdir().unwrap();
    let data = stalling_datadir(dir.path());
    let mut node = start(
        dir.path(),
        &data,
        &[],
        &[("IRONDIVI_TEST_STARTUP_BOUND_S", "2")],
    );
    let events = wait_for_file(&data.join("diag/events.log"), " phase db-open running 2 s");
    assert!(events.contains("kind=startup-stall"), "{events}");
    let info = wait_for_file(&data.join("diag/incidents/1/info.txt"), "phase=db-open");
    assert!(info.contains("exit=no"), "{info}");
    // Still waiting, with no exit record
    std::thread::sleep(Duration::from_secs(3));
    assert!(node.0.try_wait().unwrap().is_none(), "the node ended");
    let log = std::fs::read_to_string(data.join("diag/runs.log")).unwrap();
    assert!(!log.contains(" exit code="), "{log}");
    let events = std::fs::read_to_string(data.join("diag/events.log")).unwrap();
    assert_eq!(
        events.matches(" phase db-open running").count(),
        1,
        "once a phase: {events}"
    );
}
