// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `<datadir>/diag/runs.log` (diag.md A1): every run is numbered, its
//! start-up phases, the stop request and the exit are recorded, and no
//! line holds an option's value.

use divi_test_support::start_node;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The RPC password; it must never reach runs.log
const SECRET: &str = "zq7xsecret";
/// base64 of "test:zq7xsecret"
const AUTH: &str = "dGVzdDp6cTd4c2VjcmV0";

fn rpc(port: u16, method: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let body = format!(r#"{{"jsonrpc":"1.0","id":1,"method":"{method}","params":[]}}"#);
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Basic {AUTH}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

fn runs_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("diag").join("runs.log")).unwrap_or_default()
}

fn start(dir: &Path) -> (KillOnDrop, u16) {
    let (child, rpc_port, _) = start_node(
        dir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("-regtest")
                .arg(format!("-datadir={}", dir.display()))
                .arg(format!("-rpcport={rpc_port}"))
                .arg(format!("-port={p2p_port}"))
                .args(["-bind=127.0.0.1", "-staking=0", "-rpcuser=test"])
                .arg(format!("-rpcpassword={SECRET}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount").is_some(),
    );
    (KillOnDrop(child), rpc_port)
}

fn wait_exit(node: &mut KillOnDrop) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "irondivid did not stop within 60 s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The record kinds of each line, with its name= for phases
fn kinds(log: &str) -> Vec<String> {
    log.lines()
        .map(|l| {
            let mut words = l.split(' ').skip(2);
            let kind = words.next().unwrap_or("").to_string();
            if kind == "phase" {
                format!(
                    "phase:{}",
                    words.next().unwrap_or("").trim_start_matches("name=")
                )
            } else {
                kind
            }
        })
        .collect()
}

#[test]
fn each_run_records_its_start_phases_stop_and_exit() {
    let dir = tempfile::tempdir().unwrap();

    // Run 1: stopped by SIGTERM
    let (mut node, _) = start(dir.path());
    let pid = node.0.id().to_string();
    let killed = Command::new("kill").args(["-TERM", &pid]).status().unwrap();
    assert!(killed.success());
    assert!(wait_exit(&mut node).success());

    // Run 2: stopped by the stop RPC
    let (mut node, rpc_port) = start(dir.path());
    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());

    let log = runs_log(dir.path());
    let run = [
        "start",
        "phase:config",
        "phase:datadir",
        "phase:lock",
        "phase:db-open",
        "phase:network",
        "phase:wallet-load",
        "phase:staking",
        "phase:rpc",
        "phase:running",
        "stop-requested",
        "exit",
    ];
    let expected: Vec<String> = run
        .iter()
        .chain(run.iter())
        .map(|s| s.to_string())
        .collect();
    assert_eq!(kinds(&log), expected, "{log}");

    let lines: Vec<&str> = log.lines().collect();
    assert!(lines[0].contains(" start run=1 "), "{log}");
    assert!(lines[12].contains(" start run=2 "), "{log}");
    assert!(lines[0].contains(" network=regtest/divi "), "{log}");
    assert!(lines[0].contains(" daemon=no "), "{log}");
    assert!(
        lines[10].ends_with(" stop-requested by=signal=TERM"),
        "{log}"
    );
    assert!(lines[22].ends_with(" stop-requested by=rpc"), "{log}");
    for i in [11, 23] {
        assert!(lines[i].contains(" exit code=0 "), "{log}");
        assert!(lines[i].contains(" peak_rss_kb="), "{log}");
    }
    // <RFC 3339 UTC µs> mono=<s.µs> <kind>
    for line in &lines {
        let mut words = line.split(' ');
        let time = words.next().unwrap();
        assert!(
            time.len() == 27 && time.ends_with('Z') && time.as_bytes()[10] == b'T',
            "{line}"
        );
        assert!(words.next().unwrap().starts_with("mono="), "{line}");
    }
    assert!(
        !log.contains(SECRET),
        "an option's value is in runs.log:\n{log}"
    );
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        let m = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        (
            m(&dir.path().join("diag")),
            m(&dir.path().join("diag/runs.log")),
        )
    };
    assert_eq!(mode, (0o700, 0o600));
    assert!(
        marker(dir.path()).is_none(),
        "a clean stop left the A2 marker"
    );
}

/// An exit through `die()` once the data directory is known is recorded,
/// with its code and a reason that names the option, not its value
#[test]
fn a_refused_option_is_recorded_as_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("-regtest")
        .arg(format!("-datadir={}", dir.path().display()))
        .args(["-onlynet=zq7xsentinel", "-rpcuser=test"])
        .arg(format!("-rpcpassword={SECRET}"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let log = runs_log(dir.path());
    assert_eq!(kinds(&log), ["start", "phase:config", "exit"], "{log}");
    let exit = log.lines().last().unwrap();
    assert!(exit.contains(" exit code=2 "), "{log}");
    assert!(exit.contains("-onlynet"), "{log}");
    assert!(
        !log.contains("zq7xsentinel") && !log.contains(SECRET),
        "{log}"
    );
}

/// -daemon: the grandchild records the pids it forked through and that the
/// process had one thread at the first fork (diag.md §3: no thread starts
/// before the forks)
#[cfg(target_os = "linux")]
#[test]
fn a_daemon_records_its_forks_with_one_thread() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = divi_test_support::free_port();
    let out = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("-regtest")
        .arg("-daemon")
        .arg(format!("-datadir={}", dir.path().display()))
        .arg(format!("-rpcport={rpc_port}"))
        .arg(format!("-port={}", divi_test_support::free_port()))
        .args(["-listen=0", "-staking=0", "-rpcuser=test"])
        .arg(format!("-rpcpassword={SECRET}"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let wait_for = |what: &str| {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let log = runs_log(dir.path());
            if log.contains(what) {
                return log;
            }
            assert!(Instant::now() < deadline, "no {what:?} in runs.log:\n{log}");
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    let log = wait_for("phase name=running");
    let daemon = log
        .lines()
        .find(|l| l.contains(" daemon pid="))
        .expect(&log);
    assert!(daemon.ends_with(" threads_at_fork=1"), "{log}");
    let pid = daemon
        .split(' ')
        .find_map(|w| w.strip_prefix("pid="))
        .unwrap()
        .to_string();
    assert!(
        log.lines().next().unwrap().contains(" daemon=yes "),
        "{log}"
    );

    let killed = Command::new("kill").args(["-TERM", &pid]).status().unwrap();
    assert!(killed.success());
    let log = wait_for(" exit code=0 ");
    assert!(log.contains(" stop-requested by=signal=TERM"), "{log}");
}

fn marker(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join("diag").join("irondivid.running")).ok()
}

/// A2: a run killed with SIGKILL leaves its marker, and the next start
/// records it as `unclean-previous` after taking the lock; a clean stop
/// removes the marker
#[test]
fn a_killed_run_leaves_its_marker_for_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, _) = start(dir.path());
    let pid = node.0.id().to_string();
    let m = marker(dir.path()).expect("the marker while running");
    assert!(
        m.lines().any(|l| l == "run=1") && m.contains(&format!("\npid={pid}\n")),
        "{m}"
    );
    assert!(!m.contains(SECRET), "{m}");
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.path().join("diag/irondivid.running");
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode, 0o600);

    let killed = Command::new("kill").args(["-KILL", &pid]).status().unwrap();
    assert!(killed.success());
    wait_exit(&mut node);
    assert!(marker(dir.path()).is_some(), "SIGKILL left no marker");

    let (mut node, rpc_port) = start(dir.path());
    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());
    assert!(marker(dir.path()).is_none(), "a clean stop left the marker");

    let log = runs_log(dir.path());
    let kinds = kinds(&log);
    let second = kinds.iter().rposition(|k| k == "start").unwrap();
    assert_eq!(
        kinds[second..second + 5],
        [
            "start",
            "phase:config",
            "phase:datadir",
            "phase:lock",
            "unclean-previous"
        ],
        "{log}"
    );
    let unclean = log
        .lines()
        .find(|l| l.contains(" unclean-previous "))
        .unwrap();
    assert!(
        unclean.contains(&format!(" unclean-previous run=1 pid={pid} ")),
        "{log}"
    );
    assert!(unclean.contains(" stop=- "), "{log}");
    assert!(unclean.contains(" exit_recorded=no "), "{log}");
    if cfg!(target_os = "linux") {
        // Same boot, same PID 1, no OOM kill: nothing else explains it
        assert!(
            unclean.contains(" verdict=no-trace boot=same pid1=same "),
            "{log}"
        );
    }
    assert_eq!(log.matches(" unclean-previous ").count(), 1, "{log}");
}

/// A2: a second irondivid refused at the lock (exit 4) neither reads nor
/// removes the running node's marker
#[test]
fn a_second_instance_refused_at_the_lock_leaves_the_marker() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, rpc_port) = start(dir.path());
    let before = marker(dir.path()).expect("the marker while running");
    let out = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .arg("-regtest")
        .arg(format!("-datadir={}", dir.path().display()))
        .arg(format!("-rpcport={}", divi_test_support::free_port()))
        .arg(format!("-port={}", divi_test_support::free_port()))
        .args(["-listen=0", "-staking=0", "-rpcuser=test"])
        .arg(format!("-rpcpassword={SECRET}"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = marker(dir.path()).expect("the second instance removed the marker");
    let id = |m: &str| -> Vec<String> {
        m.lines()
            .filter(|l| l.starts_with("run=") || l.starts_with("pid="))
            .map(String::from)
            .collect()
    };
    assert_eq!(id(&after), id(&before));
    let log = runs_log(dir.path());
    assert!(!log.contains(" unclean-previous "), "{log}");
    assert!(log.contains(" exit code=4 "), "{log}");

    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());
    assert!(marker(dir.path()).is_none(), "a clean stop left the marker");
}
