// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A refused start leaves its reason in debug.log, as divid's InitError
//! does (noui.cpp:38-40), on a loaded host too: the file log's writer thread
//! may not have run when the process ends, and the last lines must still be
//! written.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The last CPU this process may run on
fn a_cpu() -> usize {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    assert_eq!(unsafe { libc::sched_getaffinity(0, size, &mut set) }, 0);
    (0..libc::CPU_SETSIZE as usize)
        .rev()
        .find(|&c| unsafe { libc::CPU_ISSET(c, &set) })
        .expect("a CPU")
}

/// Run the calling thread (or the process about to exec) on `cpu` only
fn pin_to(cpu: usize) -> std::io::Result<()> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_SET(cpu, &mut set) };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    match unsafe { libc::sched_setaffinity(0, size, &set) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// A start refused before the node runs (a mnemonic passphrase over 256
/// characters), made on one CPU shared with busy threads, so the log's writer
/// thread is unlikely to have run when the process ends
#[test]
fn a_refused_start_on_a_busy_cpu_leaves_its_reason_in_debug_log() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("divi.conf"),
        format!("regtest=1\nmnemonicpassphrase={}\n", "p".repeat(257)),
    )
    .unwrap();
    let cpu = a_cpu();

    // Eight busy threads on that CPU, until the node has exited
    let busy = Arc::new(AtomicBool::new(true));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let busy = Arc::clone(&busy);
            std::thread::spawn(move || {
                pin_to(cpu).unwrap();
                while busy.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            })
        })
        .collect();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg(format!("-datadir={}", dir.path().display()))
        .args(["-rpcuser=test", "-rpcpassword=test"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe { cmd.pre_exec(move || pin_to(cpu)) };
    let mut child = cmd.spawn().expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    busy.store(false, Ordering::Relaxed);
    for t in threads {
        t.join().unwrap();
    }

    let status = status.expect("irondivid did not exit within 120 s");
    assert!(!status.success(), "the start was not refused");
    let log = std::fs::read_to_string(dir.path().join("debug.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    assert!(
        log.contains("Mnemonic passphrase is too long, must be at most 256 characters"),
        "the reason is not in debug.log; it ends:\n{}",
        lines[lines.len().saturating_sub(10)..].join("\n")
    );
}
