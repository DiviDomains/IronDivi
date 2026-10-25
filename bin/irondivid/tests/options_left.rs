// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The divid options no other script compared, as divid takes them
//! (scripts/options-left).

#![cfg(unix)]

use divi_test_support::{free_port, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// One JSON-RPC call on 127.0.0.1 with test:test; None until the server is up
fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    // "dGVzdDp0ZXN0" is base64 of test:test
    let request = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (_, body) = response.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
}

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The arguments every node here starts with
fn base_args(datadir: &Path) -> Vec<String> {
    vec![
        "-regtest".to_string(),
        format!("-datadir={}", datadir.display()),
        "-bind=127.0.0.1".into(),
        "-rpcuser=test".into(),
        "-rpcpassword=test".into(),
        "-staking=0".into(),
        "-connect=127.0.0.1:1".into(),
    ]
}

/// A regtest irondivid on `datadir` with `extra`, once its RPC answers
fn start(datadir: &Path, extra: &[String]) -> (Node, u16) {
    let (child, rpc_port, _) = start_node(
        datadir,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.args(base_args(datadir))
                .args([format!("-rpcport={rpc_port}"), format!("-port={p2p_port}")])
                .args(extra)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| rpc(rpc_port, "getblockcount", json!([])).is_some(),
    );
    (Node(child), rpc_port)
}

/// debug.log, once the node that wrote it has stopped
fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("debug.log")).unwrap_or_default()
}

/// A start with `extra` that is expected to end by itself, within 120 s
fn run_to_exit(datadir: &Path, extra: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .args(base_args(datadir))
        .args([
            format!("-rpcport={}", free_port()),
            format!("-port={}", free_port()),
        ])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("irondivid did not exit within 120 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.wait_with_output().unwrap()
}

/// The lines of stderr that report an error
fn errors(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.starts_with("Error"))
        .map(String::from)
        .collect()
}

/// -socks given at all, and a true -tor, stop the start with divid's error
/// (init.cpp:775-781); -tor=0 starts
#[test]
fn socks_and_a_true_tor_are_refused_as_divid_refuses_them() {
    let socks = "Error: Error: Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported.";
    let tor = "Error: Error: Unsupported argument -tor found, use -onion.";
    for (arg, line) in [
        ("-socks=5", socks),
        ("-socks=0", socks),
        ("-socks", socks),
        ("-tor", tor),
        ("-tor=1", tor),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let out = run_to_exit(dir.path(), &[arg.to_string()]);
        assert_eq!(errors(&out), [line], "{arg}");
        assert_eq!(out.status.code(), Some(1), "{arg}");
    }
    let dir = tempfile::tempdir().unwrap();
    let (_node, port) = start(dir.path(), &["-tor=0".into()]);
    assert!(rpc(port, "getblockcount", json!([])).is_some());
}

/// A true -debugnet or -benchmark draws divid's warning, in debug.log and on
/// stderr (init.cpp:773-774, :786-787), and the node starts; =0 draws none
#[test]
fn debugnet_and_benchmark_draw_divid_s_warning() {
    for (arg, line) in [
        (
            "-debugnet",
            "Warning: Warning: Unsupported argument -debugnet ignored, use -debug=net.",
        ),
        (
            "-benchmark=1",
            "Warning: Warning: Unsupported argument -benchmark ignored, use -debug=bench.",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (node, _) = start(dir.path(), &[arg.into()]);
        drop(node);
        let log = debug_log(dir.path());
        let named: Vec<&str> = log
            .lines()
            .filter(|l| l.contains(&arg[..arg.find('=').unwrap_or(arg.len())]))
            .collect();
        assert_eq!(named.len(), 1, "{arg}: {named:?}");
        assert!(named[0].ends_with(line), "{arg}: {named:?}");
    }
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = start(dir.path(), &["-debugnet=0".into(), "-bogusmarker".into()]);
    drop(node);
    let log = debug_log(dir.path());
    assert!(
        log.contains("Unknown option -bogusmarker; ignored"),
        "{log}"
    );
    assert!(!log.contains("-debugnet"), "{log}");
}

/// The options divid takes and does nothing outside with, or reads for parts
/// irondivid does not have, start without a line, as in divid: the help-only
/// -windowtitle, -printstakemodifier, -printcoinstake (LicenseAndInfo.cpp:150,
/// :215-216), the wallet database's -dblogsize and -privdb (db.cpp:101,
/// dbenv.cpp:68), -help-debug without -help, and the block index's
/// -safe_shutdown and -recoverblockdb (BlockIndexLoading.cpp:258-283)
#[test]
fn divid_s_silent_options_start_without_a_line() {
    let options = [
        "windowtitle",
        "printstakemodifier",
        "printcoinstake",
        "dblogsize",
        "privdb",
        "help-debug",
        "safe_shutdown",
        "recoverblockdb",
    ];
    let dir = tempfile::tempdir().unwrap();
    let mut args: Vec<String> = options.iter().map(|o| format!("-{o}=1")).collect();
    // the unknown option's line shows the warnings were written
    args.push("-bogusmarker".into());
    let (node, _) = start(dir.path(), &args);
    drop(node);
    let log = debug_log(dir.path());
    assert!(
        log.contains("Unknown option -bogusmarker; ignored"),
        "{log}"
    );
    for o in options {
        assert!(!log.contains(&format!("-{o}")), "a line for -{o}: {log}");
    }
}

/// divid's test aids for parts irondivid does not let an option change are
/// named as not supported, not as unknown (docs/divid-differences.md S2)
#[test]
fn divid_s_test_aids_are_named_as_not_supported() {
    let options = [
        "accountlabels",
        "activeversion",
        "manual_fork",
        "override_mnpayee",
        "prunewalletconfs",
        "stakeupdatetime",
    ];
    let dir = tempfile::tempdir().unwrap();
    let args: Vec<String> = options.iter().map(|o| format!("-{o}=1")).collect();
    let (node, _) = start(dir.path(), &args);
    drop(node);
    let log = debug_log(dir.path());
    for o in options {
        let line = format!("Option -{o} is not supported by irondivid; ignored");
        assert!(log.contains(&line), "no {line:?}: {log}");
    }
}

/// -mocktime sets the node's clock at the start (divid.cpp:140-143): a block
/// made then carries that time; 0 (or a word) leaves the real clock
#[test]
fn mocktime_sets_the_clock_a_block_is_made_with() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mock = now + 2 * 86_400;
    for (value, expect_mock) in [(mock.to_string(), true), ("abc".to_string(), false)] {
        let dir = tempfile::tempdir().unwrap();
        let (_node, port) = start(dir.path(), &[format!("-mocktime={value}")]);
        let made = rpc(port, "setgenerate", json!([1])).unwrap();
        assert!(made["error"].is_null(), "{made}");
        let best = rpc(port, "getbestblockhash", json!([])).unwrap()["result"].clone();
        let block = rpc(port, "getblock", json!([best])).unwrap()["result"].clone();
        let time = block["time"].as_i64().unwrap();
        if expect_mock {
            assert_eq!(time, mock, "-mocktime={value}");
        } else {
            assert!(
                (time - now).abs() < 900,
                "-mocktime={value}: {time} vs {now}"
            );
        }
    }
}

/// -blockversion sets the version of the blocks made on regtest
/// (BlockFactory.cpp:90-95); one below 3 makes a block the node refuses
/// (bad-version, ChainExtensionService.cpp:350-352), so setgenerate fails
#[test]
fn blockversion_is_the_version_of_the_blocks_made() {
    let dir = tempfile::tempdir().unwrap();
    let (node, port) = start(dir.path(), &["-blockversion=7".into()]);
    let made = rpc(port, "setgenerate", json!([1])).unwrap();
    assert!(made["error"].is_null(), "{made}");
    let best = rpc(port, "getbestblockhash", json!([])).unwrap()["result"].clone();
    let block = rpc(port, "getblock", json!([best])).unwrap()["result"].clone();
    assert_eq!(block["version"], 7, "{block}");
    drop(node);

    let dir = tempfile::tempdir().unwrap();
    let (_node, port) = start(dir.path(), &["-blockversion=1".into()]);
    let made = rpc(port, "setgenerate", json!([1])).unwrap();
    assert_eq!(made["error"]["code"], -25, "{made}");
    assert_eq!(made["error"]["message"], "failed to generate a valid block");
}

/// -testsafemode puts the server in divid's safe mode: getinfo's errors say
/// so and the calls divid's table does not mark okSafeMode answer -2
/// (Warnings.cpp:32-33, rpcserver.cpp:1049-1054); -disablesafemode lets them
/// run, the errors unchanged
#[test]
fn testsafemode_refuses_what_divid_refuses_in_safe_mode() {
    for (extra, refused) in [(None, true), (Some("-disablesafemode"), false)] {
        let dir = tempfile::tempdir().unwrap();
        let mut args = vec!["-testsafemode".to_string()];
        args.extend(extra.map(String::from));
        let (_node, port) = start(dir.path(), &args);
        let info = rpc(port, "getinfo", json!([])).unwrap();
        assert_eq!(info["result"]["errors"], "testsafemode enabled", "{args:?}");
        let balance = rpc(port, "getbalance", json!([])).unwrap();
        if refused {
            assert_eq!(balance["error"]["code"], -2, "{balance}");
            assert_eq!(
                balance["error"]["message"],
                "Safe mode: testsafemode enabled"
            );
        } else {
            assert!(balance["error"].is_null(), "{balance}");
        }
        // getblockcount is okSafeMode
        let count = rpc(port, "getblockcount", json!([])).unwrap();
        assert!(count["error"].is_null(), "{count}");
    }
}

/// The wallet's scan at each start logs divid's line, from the wallet's best
/// block (the genesis block for a new wallet) to the tip (wallet.cpp:292-294)
#[test]
fn the_start_logs_divid_s_scanning_line() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (_node, port) = start(dir.path(), &[]);
        let made = rpc(port, "setgenerate", json!([3])).unwrap();
        assert!(made["error"].is_null(), "{made}");
    }
    assert!(
        debug_log(dir.path()).contains("Scanning... from height 0 to 0"),
        "first start"
    );
    std::fs::remove_file(dir.path().join("debug.log")).unwrap();
    drop(start(dir.path(), &[]));
    let log = debug_log(dir.path());
    assert!(log.contains("Scanning... from height 3 to 3"), "{log}");
}

/// -force_rescan scans the wallet from the genesis block at the start, and
/// logs it under divid's word for a scan not asked for with -rescan
/// (wallet.cpp:261-262, :292-294)
#[test]
fn force_rescan_scans_from_the_genesis_block() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (_node, port) = start(dir.path(), &[]);
        let made = rpc(port, "setgenerate", json!([3])).unwrap();
        assert!(made["error"].is_null(), "{made}");
    }
    std::fs::remove_file(dir.path().join("debug.log")).unwrap();
    drop(start(dir.path(), &["-force_rescan".into()]));
    let log = debug_log(dir.path());
    assert!(log.contains("Scanning... from height 0 to 3"), "{log}");
    assert!(!log.contains("Rescanning"), "{log}");
}

/// A start refused for a stated reason writes divid's InitError line to
/// debug.log as well as to stderr (noui.cpp:38-40)
#[test]
fn a_refused_start_writes_its_error_to_debug_log() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_to_exit(dir.path(), &["-checklevel=4".into()]);
    let line = "Error: Error: Unsupported argument -checklevel found. Checklevel must be level 4.";
    assert_eq!(errors(&out), [line]);
    let log = debug_log(dir.path());
    let named: Vec<&str> = log.lines().filter(|l| l.contains("-checklevel")).collect();
    assert_eq!(named.len(), 1, "{log}");
    assert!(named[0].ends_with(line), "{log}");
}

/// The start's check of the last blocks finds one too far in the future of
/// the clock, as divid's VerifyDB does with CheckBlock (verifyDb.cpp:95-97):
/// blocks made a day ahead with setmocktime refuse the next start on the real
/// clock
#[test]
fn the_start_check_refuses_blocks_from_the_future() {
    let ahead = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86_400;
    let dir = tempfile::tempdir().unwrap();
    {
        let (_node, port) = start(dir.path(), &[]);
        let set = rpc(port, "setmocktime", json!([ahead])).unwrap();
        assert!(set["error"].is_null(), "{set}");
        let made = rpc(port, "setgenerate", json!([3])).unwrap();
        assert!(made["error"].is_null(), "{made}");
    }
    let out = run_to_exit(dir.path(), &[]);
    assert_eq!(
        errors(&out)[..1],
        ["Error: Corrupted block database detected"]
    );
    assert_eq!(out.status.code(), Some(1));
}
