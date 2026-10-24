// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
use std::process::Child;
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

/// The last lines of the node's debug.log in `datadir`, for a failure
/// message: a node that exits at start says why only there
pub fn log_tail(datadir: &Path) -> String {
    let log = std::fs::read_to_string(datadir.join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("regtest").join("debug.log")))
        .unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

/// Wait up to `START_WAIT` for `up` to be true for the node `child` started
/// on `datadir`; panic with the end of its log if it exits first or never
/// answers
pub fn wait_started(child: &mut Child, datadir: &Path, mut up: impl FnMut() -> bool) {
    let deadline = Instant::now() + START_WAIT;
    while !up() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "irondivid exited ({status}) before its RPC server came up; its log ends:\n{}",
                log_tail(datadir)
            );
        }
        assert!(
            Instant::now() < deadline,
            "RPC server did not come up within {} s; its log ends:\n{}",
            START_WAIT.as_secs(),
            log_tail(datadir)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_port_is_below_the_ephemeral_range_and_bindable() {
        for _ in 0..20 {
            let port = free_port();
            assert!((20000..32768).contains(&port), "{port}");
            TcpListener::bind(("127.0.0.1", port)).unwrap();
        }
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
