// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Helpers shared by the workspace's tests that start a node or a server:
//! a port to listen on, and a bounded wait for a started irondivid that
//! names the cause when the node exits instead.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// How long a started node may take to answer: a loaded host can take far
/// longer than an idle one
pub const START_WAIT: Duration = Duration::from_secs(120);

/// A port nothing listens on now, for a node or server to listen on, or for a
/// test that needs a port with no listener.
///
/// The port is bound later, so it must not be handed to anyone else in
/// between. A port from 127.0.0.1:0 comes from the kernel's ephemeral range
/// (32768-60999 on Linux, 49152-65535 on macOS), which every outgoing
/// connection and every other 127.0.0.1:0 on the host also draws from; a
/// fixed range walked in the same order by every process gives two test runs
/// at once the same ports. These ports are below the ephemeral range and
/// picked at random.
pub fn free_port() -> u16 {
    let seed = RandomState::new();
    for i in 0u32..1000 {
        let mut h = seed.build_hasher();
        h.write_u32(i);
        let port = 20000 + (h.finish() % 12768) as u16;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port in 20000-32767");
}

/// The node's debug.log in `datadir` (regtest writes it there, other networks
/// in the network's folder); empty if there is none yet
fn read_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("regtest").join("debug.log")))
        .unwrap_or_default()
}

/// How long the node's debug.log is now: what a new start appends comes
/// after this
pub fn log_len(datadir: &Path) -> usize {
    read_log(datadir).len()
}

/// The last lines of the node's debug.log in `datadir`, for a failure
/// message: a node that exits at start says why only there
pub fn log_tail(datadir: &Path) -> String {
    let log = read_log(datadir);
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

/// Whether the node logged, after `from`, that a port it was given is taken
pub fn port_taken_since(datadir: &Path, from: usize) -> bool {
    read_log(datadir)
        .get(from..)
        .is_some_and(|new| new.contains("Address already in use"))
}

/// How a started node came up
#[derive(Debug, PartialEq, Eq)]
pub enum Started {
    /// It answers, and every port it was given was free
    Up,
    /// A port it was given was taken by another process between its choice
    /// and the node's bind; the node has been stopped
    PortTaken,
}

/// Wait up to `START_WAIT` for `up` to be true for the node `child` started
/// on `datadir`, whose debug.log was `log_from` long before the start.
///
/// A port can be taken by another process between `free_port` and the
/// node's bind: the node then exits (RPC) or runs without a listener (P2P).
/// Either way it is stopped and `PortTaken` returned, for the caller to start
/// it again on new ports. Any other exit, or no answer in time (the node is
/// then stopped), panics with the end of its log.
pub fn wait_up(
    child: &mut Child,
    datadir: &Path,
    log_from: usize,
    mut up: impl FnMut() -> bool,
) -> Started {
    let deadline = Instant::now() + START_WAIT;
    while !up() {
        if let Some(status) = child.try_wait().unwrap() {
            if port_taken_since(datadir, log_from) {
                return Started::PortTaken;
            }
            panic!(
                "irondivid exited ({status}) before its RPC server came up; its log ends:\n{}",
                log_tail(datadir)
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "RPC server did not come up within {} s; its log ends:\n{}",
                START_WAIT.as_secs(),
                log_tail(datadir)
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if port_taken_since(datadir, log_from) {
        let _ = child.kill();
        let _ = child.wait();
        return Started::PortTaken;
    }
    Started::Up
}

/// Wait for a started node as `wait_up` does, for a node whose ports cannot
/// be changed by the caller: a taken port panics too
pub fn wait_started(child: &mut Child, datadir: &Path, up: impl FnMut() -> bool) {
    let from = log_len(datadir);
    if wait_up(child, datadir, from, up) == Started::PortTaken {
        panic!(
            "a port given to irondivid was taken; its log ends:\n{}",
            log_tail(datadir)
        );
    }
}

/// How many times `start_node` starts a node on new ports
pub const START_TRIES: usize = 5;

/// Start a node on ports from `free_port` and wait until it answers.
///
/// `command(rpc_port, p2p_port)` makes the command for a node on `datadir`;
/// `up(rpc_port)` says whether it answers. A node that lost a port to
/// another process is started again on new ports. Returns the running node
/// and its RPC and P2P ports.
pub fn start_node(
    datadir: &Path,
    mut command: impl FnMut(u16, u16) -> Command,
    mut up: impl FnMut(u16) -> bool,
) -> (Child, u16, u16) {
    for _ in 0..START_TRIES {
        let (rpc_port, p2p_port) = (free_port(), free_port());
        let from = log_len(datadir);
        let mut child = command(rpc_port, p2p_port)
            .spawn()
            .expect("spawn irondivid");
        if wait_up(&mut child, datadir, from, || up(rpc_port)) == Started::Up {
            return (child, rpc_port, p2p_port);
        }
    }
    panic!(
        "irondivid lost a port {START_TRIES} times; its log ends:\n{}",
        log_tail(datadir)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_port_is_below_the_ephemeral_range_and_random() {
        let ports: Vec<u16> = (0..20).map(|_| free_port()).collect();
        assert!(
            ports.iter().all(|p| (20000..32768).contains(p)),
            "{ports:?}"
        );
        assert!(ports.iter().any(|p| *p != ports[0]), "{ports:?}");
    }

    #[test]
    fn log_tail_keeps_the_last_15_lines() {
        let dir = tempfile_dir();
        let log: String = (1..=20).map(|i| format!("line {i}\n")).collect();
        std::fs::write(dir.join("debug.log"), log).unwrap();
        let tail = log_tail(&dir);
        assert!(
            tail.starts_with("line 6\n") && tail.ends_with("line 20"),
            "{tail}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wait_started_names_an_early_exit_and_its_log() {
        let dir = tempfile_dir();
        std::fs::write(dir.join("debug.log"), "Address already in use\n").unwrap();
        let mut child = std::process::Command::new("false").spawn().unwrap();
        let d = dir.clone();
        let err =
            std::panic::catch_unwind(move || wait_started(&mut child, &d, || false)).unwrap_err();
        let text = err.downcast_ref::<String>().unwrap();
        assert!(
            text.contains("exited") && text.contains("Address already in use"),
            "{text}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_taken_port_after_the_start_is_reported_as_such() {
        let dir = tempfile_dir();
        std::fs::write(
            dir.join("debug.log"),
            "an earlier start: Address already in use\n",
        )
        .unwrap();
        let from = log_len(&dir);
        // A node that exits with nothing new in its log is a failure, not a taken port
        let mut child = std::process::Command::new("false").spawn().unwrap();
        let d = dir.clone();
        assert!(std::panic::catch_unwind(move || wait_up(&mut child, &d, from, || false)).is_err());
        // One that logged a taken port is started again
        let log = format!(
            "{}RPC server error: IO error: Address already in use\n",
            read_log(&dir)
        );
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "printf '%s' '{log}' > {}",
                dir.join("debug.log").display()
            ))
            .spawn()
            .unwrap();
        assert_eq!(
            wait_up(&mut child, &dir, from, || false),
            Started::PortTaken
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A new empty directory (this crate has no dependencies, so no tempfile)
    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "divi-test-support-{}-{}",
            std::process::id(),
            free_port()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
