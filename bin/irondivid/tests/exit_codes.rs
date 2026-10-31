// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! irondivid's exit codes (diag.md R3): every exit goes through `die`, which
//! writes the reason, flushes the log and ends with the code of its class.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn run(args: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("irondivid {args:?} did not exit within 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn datadir(dir: &Path) -> String {
    format!("-datadir={}", dir.display())
}

#[test]
fn help_and_version_exit_1() {
    for flag in ["-help", "-version"] {
        let out = run(&[flag.into()]);
        assert_eq!(out.status.code(), Some(1), "{flag}");
    }
}

#[test]
fn an_option_s_value_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    // An irondivid option whose value the parser refuses (divid itself
    // ignores unknown options and reads a bad number as 0)
    let out = run(&[datadir(dir.path()), "-export-start=x".into()]);
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    let out = run(&[datadir(dir.path()), "-testnet".into(), "-regtest".into()]);
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn an_invalid_config_line_exits_3_without_its_text() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("divi.conf"), "regtest=1\nrpcpassword hunter2\n").unwrap();
    let out = run(&[datadir(dir.path())]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("(line 2)"), "{stderr}");
    assert!(!stderr.contains("hunter2"), "{stderr}");
}

#[test]
fn a_missing_data_directory_exits_4() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(&[datadir(&dir.path().join("absent"))]);
    assert_eq!(out.status.code(), Some(4), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_locked_data_directory_exits_4() {
    let dir = tempfile::tempdir().unwrap();
    let lock = std::fs::File::create(dir.path().join(".lock")).unwrap();
    lock.try_lock().expect("take the data directory's lock");
    let out = run(&[
        datadir(dir.path()),
        "-regtest".into(),
        "-rpcuser=test".into(),
        "-rpcpassword=test".into(),
        format!("-rpcport={}", divi_test_support::free_port()),
        format!("-port={}", divi_test_support::free_port()),
        "-listen=0".into(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(stderr.contains("Cannot obtain a lock on data directory"), "{stderr}");
    drop(lock);
}

#[test]
fn a_p2p_port_in_use_exits_7() {
    let dir = tempfile::tempdir().unwrap();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let out = run(&[
        datadir(dir.path()),
        "-regtest".into(),
        "-rpcuser=test".into(),
        "-rpcpassword=test".into(),
        format!("-rpcport={}", divi_test_support::free_port()),
        "-bind=127.0.0.1".into(),
        format!("-port={port}"),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(7), "{stderr}");
    assert!(stderr.contains("Failed to listen on any port"), "{stderr}");
    drop(held);
}

/// Only `die` ends the process with a code: any other exit would skip the
/// log flush or the R3 code
#[test]
fn no_other_exit_path_in_the_crate() {
    // Split, so this file does not match itself if it is ever moved into src
    let needle = concat!("process", "::exit");
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    let mut found = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                for (n, line) in text.lines().enumerate() {
                    if line.contains(needle) {
                        found.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                    }
                }
            }
        }
    }
    assert!(found.is_empty(), "exits that bypass die():\n{}", found.join("\n"));
}
