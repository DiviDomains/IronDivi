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
    start_with(dir, &[])
}

fn start_with(dir: &Path, env: &[(&str, &str)]) -> (KillOnDrop, u16) {
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
                .envs(env.iter().copied())
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

    // Run 1: stopped by SIGTERM, sent by this process
    let (mut node, _) = start(dir.path());
    assert_eq!(unsafe { libc::kill(node.0.id() as i32, libc::SIGTERM) }, 0);
    assert!(wait_exit(&mut node).success());

    // Run 2: SIGHUP reopens debug.log and the node keeps running; then the
    // stop RPC
    let (mut node, rpc_port) = start(dir.path());
    assert_eq!(unsafe { libc::kill(node.0.id() as i32, libc::SIGHUP) }, 0);
    wait_for(dir.path(), " signal signo=HUP ");
    assert!(rpc(rpc_port, "getblockcount").is_some());
    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());

    let log = runs_log(dir.path());
    let run = |signal: bool| {
        let mut kinds = vec![
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
        ];
        if signal {
            kinds.push("signal");
        }
        kinds.extend(["stop-requested", "exit"]);
        kinds
    };
    let expected: Vec<String> = run(true)
        .into_iter()
        .chain(run(true))
        .map(String::from)
        .collect();
    assert_eq!(kinds(&log), expected, "{log}");

    let lines: Vec<&str> = log.lines().collect();
    assert!(lines[0].contains(" start run=1 "), "{log}");
    assert!(lines[13].contains(" start run=2 "), "{log}");
    assert!(lines[0].contains(" network=regtest/divi "), "{log}");
    assert!(lines[0].contains(" daemon=no "), "{log}");
    // The sender: this test process, its command line masked
    let me = std::process::id();
    let uid = unsafe { libc::getuid() };
    assert!(
        lines[10].contains(&format!(
            " signal signo=TERM code=SI_USER pid={me} uid={uid} sender=read comm=\"runs_log"
        )),
        "{log}"
    );
    assert!(lines[10].contains(" action=stop count=1"), "{log}");
    let cmd = lines[10].split(" cmd=\"").nth(1).unwrap();
    let cmd = &cmd[..cmd.find('"').unwrap()];
    assert!(cmd.starts_with("runs_log") && !cmd.contains('/'), "{log}");
    assert!(
        lines[11].ends_with(" stop-requested by=signal=TERM"),
        "{log}"
    );
    assert!(
        lines[23].contains(" signal signo=HUP code=SI_USER "),
        "{log}"
    );
    assert!(lines[23].contains(" action=reopen-log"), "{log}");
    assert!(lines[24].ends_with(" stop-requested by=rpc"), "{log}");
    for i in [12, 25] {
        assert!(lines[i].contains(" exit code=0 "), "{log}");
        assert!(lines[i].contains(" peak_rss_kb="), "{log}");
        assert!(lines[i].ends_with(" sigpipe=0 epipe=0"), "{log}");
    }
    assert_eq!(log.matches(" stop-requested ").count(), 2, "{log}");
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

/// The runs.log text once it holds `what` (two minutes at most)
fn wait_for(dir: &Path, what: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let log = runs_log(dir);
        if log.contains(what) {
            return log;
        }
        assert!(Instant::now() < deadline, "no {what:?} in runs.log:\n{log}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A3: the second stop signal is recorded and ignored; the third ends the
/// process with code 10 from the signal handler, which writes the exit
/// record itself and leaves the marker, so the next start finds the exit
#[test]
fn a_third_stop_signal_ends_the_run_with_code_10() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, _) = start(dir.path());
    let pid = node.0.id() as i32;
    // All three pending at once, so the node cannot finish stopping between
    // them: stopped, three different stop signals (two of the same kind
    // would merge), then resumed
    for signo in [
        libc::SIGSTOP,
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGCONT,
    ] {
        assert_eq!(unsafe { libc::kill(pid, signo) }, 0);
    }
    assert_eq!(wait_exit(&mut node).code(), Some(10));
    assert!(
        marker(dir.path()).is_some(),
        "the third signal removed the marker"
    );
    let log = runs_log(dir.path());
    assert!(
        log.lines()
            .any(|l| l.contains(" code=SI_USER pid=") && l.ends_with(" action=exit count=3")),
        "{log}"
    );
    let exit = log.lines().find(|l| l.contains(" exit code=")).expect(&log);
    assert!(exit.contains(" exit code=10 run=1 "), "{log}");
    assert!(exit.contains(" reason=\"a third stop signal\" "), "{log}");
    assert!(exit.ends_with(" sigpipe=0 epipe=0"), "{log}");
    assert_eq!(exit.split(' ').next().unwrap().len(), 27, "{log}");

    let (mut node, rpc_port) = start(dir.path());
    let log = runs_log(dir.path());
    let unclean = log
        .lines()
        .find(|l| l.contains(" unclean-previous "))
        .expect(&log);
    assert!(unclean.contains(" verdict=exit-recorded "), "{log}");
    assert!(unclean.contains(" exit_recorded=yes "), "{log}");
    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());
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
        // The dead run's memory counters survive the marker's replacement
        assert!(
            unclean.contains(" prev.memory.") || unclean.contains(" prev.meminfo."),
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

fn crash_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("diag").join("crash.log")).unwrap_or_default()
}

/// A4: a supervised task's panic ends that task alone; it is recorded in
/// runs.log without its message, which goes to crash.log. A main-thread
/// panic ends the run with 101 through `die`, whose exit record replaces
/// the marker
#[test]
fn a_task_panic_is_recorded_and_a_main_panic_exits_101() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, rpc_port) = start_with(
        dir.path(),
        &[("IRONDIVI_TEST_PANIC", "task,task-error,main")],
    );
    let log = wait_for(dir.path(), " task=\"test-panic\" ");
    let panic = log.lines().find(|l| l.contains(" panic ")).expect(&log);
    assert!(panic.ends_with(" ends_node=no"), "{log}");
    assert!(panic.contains("tasks.rs:"), "{log}");
    assert!(rpc(rpc_port, "getblockcount").is_some(), "the node stopped");

    // events.log: the panic (no message) and the error, by name; the
    // panic is an incident and one in health's count
    let events = wait_for_file(dir.path(), "diag/events.log", "cause=error");
    let failed = events
        .lines()
        .find(|l| l.contains(" task-failed ") && l.contains(" cause=panic "))
        .unwrap_or_else(|| panic!("{events}"));
    assert!(failed.contains(" task=\"test-panic\" "), "{events}");
    assert!(events.contains(" cause=error task=\"test-error\""), "{events}");
    assert!(!events.contains("stays in"), "{events}");
    let info = std::fs::read_to_string(dir.path().join("diag/incidents/1/info.txt")).unwrap();
    assert!(info.starts_with("kind=panic\n"), "{info}");
    assert!(dir.path().join("diag/incidents/1/ring.txt").exists());
    let health = wait_for_file(dir.path(), "diag/health.log", " panics=1 ");
    assert!(!health.contains(" panics=2 "), "{health}");

    rpc(rpc_port, "stop").expect("stop reply");
    assert_eq!(wait_exit(&mut node).code(), Some(101));
    assert!(marker(dir.path()).is_none(), "the exit record left the marker");
    let log = runs_log(dir.path());
    assert!(!log.contains("stays in crash.log"), "{log}");
    assert_eq!(log.matches(" panic ").count(), 2, "{log}");
    assert!(
        log.lines()
            .any(|l| l.contains(" panic thread=\"main\" ") && l.ends_with(" ends_node=yes")),
        "{log}"
    );
    let exit = log.lines().find(|l| l.contains(" exit code=")).expect(&log);
    assert!(exit.contains(" exit code=101 run=1 "), "{log}");
    assert!(
        exit.contains(" reason=\"Error: the node's main task panicked\" "),
        "{log}"
    );
    let crash = crash_log(dir.path());
    assert_eq!(crash.matches("stays in crash.log").count(), 2, "{crash}");
    assert!(crash.contains("\nbacktrace:\n"), "{crash}");
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.path().join("diag/crash.log");
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode, 0o600);
}

/// Wait for `what` in `<dir>/<name>`; returns the file
fn wait_for_file(dir: &Path, name: &str, what: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let text = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        if text.contains(what) {
            return text;
        }
        assert!(Instant::now() < deadline, "no {what:?} in {name}:\n{text}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A6: health.log gets a line at start and every 10 s, with every group of
/// fields; the dumpable check's value is in it
#[test]
fn health_writes_a_line_with_each_group_of_fields() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, rpc_port) = start(dir.path());
    let health = wait_for_file(dir.path(), "diag/health.log", " health run=1 ");
    let line = health.lines().next().unwrap();
    for field in [
        " rss_kb=",
        " fds=",
        " fd_source=",
        " cpu_s=",
        " io_blocks_in=",
        " load=",
        " disk_free_mb=",
        " suspended_s=",
        " clock_synced=",
        " height=0 ",
        " lag=0 ",
        " peers_in=0 ",
        " mempool_txs=0 ",
        " staking=",
        " panics=0 ",
        " dropped_lines=",
        " sigpipe=0 ",
        " rpc_calls=n/a ",
        " dumpable=",
        " dumpable_resets=0",
    ] {
        assert!(line.contains(field), "{field}: {line}");
    }
    assert!(line.contains(" fd_source=fd/ "), "{line}");
    // A second line, at the 10 s tick, reads the dumpable check's value
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let health = std::fs::read_to_string(dir.path().join("diag/health.log")).unwrap();
        if health.lines().count() >= 2 {
            let second = health.lines().nth(1).unwrap();
            assert!(second.contains(" dumpable=0 "), "{second}");
            break;
        }
        assert!(Instant::now() < deadline, "{health}");
        std::thread::sleep(Duration::from_millis(200));
    }
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.path().join("diag/health.log");
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode, 0o600);
    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());
}

/// A4: a critical task that returns an error ends the node through die()
/// with code 10, naming it and the error
#[test]
fn a_critical_task_error_ends_the_run_with_code_10() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = start_with(dir.path(), &[("IRONDIVI_TEST_PANIC", "critical-error")]).0;
    assert_eq!(wait_exit(&mut node).code(), Some(10));
    let log = runs_log(dir.path());
    let exit = log.lines().find(|l| l.contains(" exit code=")).expect(&log);
    assert!(
        exit.contains(" reason=\"Error: test-error: test error\" "),
        "{log}"
    );
    assert!(marker(dir.path()).is_none());
}

/// A4: a critical task's or thread's panic ends the node with code 10,
/// naming it
#[test]
fn a_critical_panic_ends_the_run_with_code_10() {
    for what in ["critical-task", "critical-thread"] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = start_with(dir.path(), &[("IRONDIVI_TEST_PANIC", what)]).0;
        assert_eq!(wait_exit(&mut node).code(), Some(10), "{what}");
        let log = runs_log(dir.path());
        let panic = log.lines().find(|l| l.contains(" panic ")).expect(&log);
        assert!(panic.ends_with(" ends_node=yes"), "{what}: {log}");
        let exit = log.lines().find(|l| l.contains(" exit code=")).expect(&log);
        assert!(exit.contains(" exit code=10 run=1 "), "{what}: {log}");
        assert!(
            exit.contains(" reason=\"Error: test-panic panicked\" "),
            "{what}: {log}"
        );
        assert!(!log.contains("stays in crash.log"), "{what}: {log}");
        assert!(
            crash_log(dir.path()).contains("stays in crash.log"),
            "{what}"
        );
        assert!(marker(dir.path()).is_none(), "{what}");
    }
}

/// A5: a fatal signal is written to crash.log (record, frames, the debug
/// ring, end line) and the process still ends by that signal; the next run
/// names it as the cause. A Rust stack overflow keeps std's message and
/// abort, and the record names the thread
#[cfg(debug_assertions)]
#[test]
fn a_fatal_signal_is_recorded_and_ends_the_run_by_that_signal() {
    use std::os::unix::process::ExitStatusExt;
    for (what, signo, name) in [
        ("segv", libc::SIGSEGV, "SEGV"),
        ("abort", libc::SIGABRT, "ABRT"),
        ("overflow", libc::SIGABRT, "SEGV"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut node = start_with(dir.path(), &[("IRONDIVI_TEST_CRASH", what)]).0;
        let status = wait_exit(&mut node);
        assert_eq!(status.signal(), Some(signo), "{what}: {status:?}");
        let crash = crash_log(dir.path());
        let record = crash
            .lines()
            .find(|l| l.contains(" fatal-signal run=1 "))
            .unwrap_or_else(|| panic!("{what}: {crash}"));
        assert!(record.contains(&format!(" signal={name} ")), "{what}: {crash}");
        assert!(record.contains(" thread=\"test-crash\" "), "{what}: {crash}");
        assert!(record.contains(" sent=no"), "{what}: {crash}");
        assert!(crash.contains(" fatal-signal-end run=1"), "{what}: {crash}");
        assert!(crash.contains("debug ring (A8"), "{what}: {crash}");
        if cfg!(target_os = "linux") {
            assert!(crash.contains(" frame #0 0x"), "{what}: {crash}");
            assert!(crash.contains("irondivid"), "{what}: maps: {crash}");
        }
        assert!(marker(dir.path()).is_some(), "{what}: no marker left");

        // The next run gives the record as the cause
        let (mut node, rpc_port) = start(dir.path());
        rpc(rpc_port, "stop").expect("stop reply");
        assert!(wait_exit(&mut node).success());
        let log = runs_log(dir.path());
        let unclean = log
            .lines()
            .find(|l| l.contains(" unclean-previous "))
            .unwrap_or_else(|| panic!("{what}: {log}"));
        assert!(
            unclean.contains(&format!(" verdict=crash signal={name} ")),
            "{what}: {log}"
        );
        assert!(unclean.contains(" crash_log=record "), "{what}: {log}");
    }
}

/// A5: a fatal signal another process sends is recorded with its sender,
/// still ends the run by that signal, and the next run says who sent it
#[test]
fn a_fatal_signal_sent_by_another_process_names_the_sender() {
    use std::os::unix::process::ExitStatusExt;
    let dir = tempfile::tempdir().unwrap();
    let (mut node, _) = start(dir.path());
    assert_eq!(unsafe { libc::kill(node.0.id() as i32, libc::SIGSEGV) }, 0);
    let status = wait_exit(&mut node);
    assert_eq!(status.signal(), Some(libc::SIGSEGV), "{status:?}");
    let crash = crash_log(dir.path());
    let record = crash
        .lines()
        .find(|l| l.contains(" fatal-signal run=1 "))
        .unwrap_or_else(|| panic!("{crash}"));
    assert!(record.contains(" signal=SEGV "), "{crash}");
    assert!(
        record.contains(&format!(" sent=yes si_pid={} ", std::process::id())),
        "{crash}"
    );
    assert!(crash.contains(" fatal-signal-end run=1"), "{crash}");

    let (mut node, rpc_port) = start(dir.path());
    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());
    let log = runs_log(dir.path());
    let unclean = log
        .lines()
        .find(|l| l.contains(" unclean-previous "))
        .unwrap_or_else(|| panic!("{log}"));
    assert!(unclean.contains(" verdict=sent-by comm="), "{log}");
    assert!(unclean.contains(" crash_log=record "), "{log}");
}

/// A7: diag/startup/<run>.txt holds the masked argv, the config keys with
/// their sources, the environment's names, and no secret or path
#[test]
fn the_startup_record_masks_secrets_and_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, rpc_port) = start_with(
        dir.path(),
        &[("IRONDIVI_SECRETX", "topsecret9"), ("RUST_BACKTRACE", "1")],
    );
    let text = wait_for_file(dir.path(), "diag/startup/1.txt", "\ncwd=\"");
    assert!(text.starts_with("startup run=1 "), "{text}");
    for want in [
        "-rpcpassword=<v>",
        "-datadir=<v>",
        "-staking=0",
        "rpcpassword source=argument value=<set>\n",
        "staking source=argument value=0\n",
        "regtest source=argument",
        "defaults=",
        "\nIRONDIVI_SECRETX\n",
        "\nRUST_BACKTRACE=\"1\"\n",
        "\n[rlimits]\ncore soft=",
        "nofile soft=",
        "\n[build]\ntarget=",
    ] {
        assert!(text.contains(want), "{want}: {text}");
    }
    #[cfg(target_os = "linux")]
    for want in ["\ndumpable=0\n", "\nNoNewPrivs=", "\nfs_type="] {
        assert!(text.contains(want), "{want}: {text}");
    }
    let datadir = dir.path().display().to_string();
    for absent in [SECRET, "topsecret9", datadir.as_str()] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.path().join("diag/startup/1.txt");
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode, 0o600);
    rpc(rpc_port, "stop").expect("stop reply");
    assert!(wait_exit(&mut node).success());
}
