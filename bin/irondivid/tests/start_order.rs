// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! What a start that fails has already done, by the stage of divid's
//! InitializeDivi (init.cpp:1343-1661) it fails at: the files left in the
//! data directory and the first error line.

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
        .args(["--listen=0", "--staking=false"])
        .args(["--connect", "127.0.0.1:1"])
        // "dGVzdDp0ZXN0" is base64 of test:test
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .env("WALLET_MNEMONIC", WALLET_MNEMONIC)
        .env("WALLET_LOOKAHEAD", "5")
        .env_remove("WALLET_HDSEED")
        .env_remove("WALLET_MNEMONIC_PASSPHRASE");
    cmd
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

/// A data directory with a chain and a wallet: one start and a clean stop
fn started_once(datadir: &Path) {
    let (mut child, rpc_port, _) = start_node(
        datadir,
        |rpc_port, _| {
            let mut cmd = irondivid(datadir, rpc_port);
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            cmd
        },
        |rpc_port| try_rpc(rpc_port, "getblockcount", &json!([])).is_some(),
    );
    try_rpc(rpc_port, "stop", &json!([])).expect("stop");
    let code = wait_exit(&mut child, 60);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(code, Some(0));
}

/// The chain database can no longer be opened: divid's block index load
/// fails here (init.cpp:1503-1531, step 7)
fn damage_chain(datadir: &Path) {
    std::fs::write(datadir.join("chainstate").join("CURRENT"), b"garbage").unwrap();
}

/// A start that fails: its exit code and its stderr
fn failed_start(cmd: &mut Command) -> (Option<i32>, String) {
    let out = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The names in `dir`; none when it is not there
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|r| {
            r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// With -hdseed (or -mnemonic) divid moves the wallet there out of the way in
/// step 4, before its pid file and before the chain (CheckWalletFileExists,
/// init.cpp:864-888, :1464): a start that then fails at the chain has moved it
#[test]
fn a_seed_restore_moves_the_wallet_before_the_chain_is_opened() {
    let dir = tempfile::tempdir().unwrap();
    started_once(dir.path());
    damage_chain(dir.path());
    // The seed in divi.conf, not on the command line (BIP32 test vector 1)
    std::fs::write(
        dir.path().join("divi.conf"),
        "hdseed=000102030405060708090a0b0c0d0e0f\n",
    )
    .unwrap();
    let (code, err) = failed_start(&mut irondivid(dir.path(), free_port()));
    assert_eq!(code, Some(1), "{err}");
    let names = names(dir.path());
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("wallet") && n.ends_with(".moved")),
        "the wallet was not moved: {names:?}"
    );
    assert!(!dir.path().join("wallet").exists(), "{names:?}");
}

/// divid backs the wallet up in step 5, after its pid file and before the
/// network and the chain (BackupWallet, init.cpp:1479): a start that then
/// fails at the chain has made the copy
#[test]
fn the_wallet_is_backed_up_before_the_chain_is_opened() {
    let dir = tempfile::tempdir().unwrap();
    started_once(dir.path());
    let backups = dir.path().join("backups");
    let before = names(&backups).len();
    damage_chain(dir.path());
    let (code, err) = failed_start(&mut irondivid(dir.path(), free_port()));
    assert_eq!(code, Some(1), "{err}");
    assert_eq!(names(&backups).len(), before + 1, "{:?}", names(&backups));
}

/// divid reads masternode.conf, and makes it when it is missing, in step 10,
/// after the chain and the wallet (InitializeMasternodeIfRequested,
/// init.cpp:1595, MasternodeModule.cpp:211-217): a start that fails at the
/// chain has not made it
#[test]
fn masternode_conf_is_not_made_by_a_start_that_fails_at_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    started_once(dir.path());
    let conf = dir.path().join("masternode.conf");
    std::fs::remove_file(&conf).unwrap();
    damage_chain(dir.path());
    let (code, err) = failed_start(&mut irondivid(dir.path(), free_port()));
    assert_eq!(code, Some(1), "{err}");
    assert!(!conf.exists(), "{:?}", names(dir.path()));
}

/// -masternode with no such masternode in masternode.conf stops divid in
/// step 10 (init.cpp:1595-1597), after it has made its wallet in step 8
#[test]
fn the_masternode_check_comes_after_the_wallet_is_made() {
    let dir = tempfile::tempdir().unwrap();
    let (code, err) = failed_start(irondivid(dir.path(), free_port()).arg("-masternode=1"));
    assert_eq!(code, Some(1), "{err}");
    assert!(
        err.lines()
            .any(|l| l == "Error: Unknown masternode configuration for masternode=<alias>."),
        "{err}"
    );
    assert!(
        dir.path().join("wallet").exists(),
        "{:?}",
        names(dir.path())
    );
}
