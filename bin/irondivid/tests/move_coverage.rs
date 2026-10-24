// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Moving from divid, the cases `move_from_core.rs` does not start
//! irondivid for: Core's testnet3 folder, a plain file or a Core folder given
//! as the wallet, a wallet made from `-hdseed`, the masternode.conf lock with
//! `-mnconflock=0` and lines it cannot use, the default data folder beside
//! Core's, and the bulk wallet dump neither program has.

#![cfg(unix)]

use divi_test_support::{free_port, start_node};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const WALLET_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";

/// BIP32 test vector 1; Divi Core 3.0.0 on regtest started with
/// `-hdseed=000102030405060708090a0b0c0d0e0f` gives this address at
/// m/44'/1'/0'/0/0
const SEED: &str = "000102030405060708090a0b0c0d0e0f";
const CORE_FIRST_ADDRESS: &str = "y7VQ7R3SDRxzNuUsUuFzuq2FT1uVtW8iBz";

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

/// irondivid for `network` with no peers; `datadir` None leaves the default
fn irondivid(datadir: Option<&Path>, network: &str, rpc_port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg(network);
    if let Some(d) = datadir {
        cmd.arg("--datadir").arg(d);
    }
    cmd.args(["--rpcport", &rpc_port.to_string()])
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

/// Run until irondivid exits by itself, at most `secs` seconds; None if it
/// was still running (it is then stopped)
fn run_to_exit(mut cmd: Command, secs: u64) -> Option<Output> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return Some(child.wait_with_output().unwrap());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

struct Daemon {
    child: Child,
    rpc_port: u16,
}

impl Daemon {
    /// Start the node `command(rpc_port)` makes (with `irondivid`), whose
    /// data directory is `datadir`, and wait for its RPC
    fn start(datadir: &Path, mut command: impl FnMut(u16) -> Command) -> Daemon {
        // `irondivid` takes a new P2P port from free_port for each start
        let (child, rpc_port, _) = start_node(
            datadir,
            |rpc_port, _| {
                let mut cmd = command(rpc_port);
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd
            },
            |rpc_port| try_rpc(rpc_port, "getblockcount", &json!([])).is_some(),
        );
        Daemon { child, rpc_port }
    }

    fn call(&self, method: &str, params: Value) -> Value {
        try_rpc(self.rpc_port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"))
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply = self.call(method, params.clone());
        assert!(
            reply["error"].is_null(),
            "{method} {params}: {}",
            reply["error"]
        );
        reply["result"].clone()
    }

    fn stop(mut self) {
        self.rpc("stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "irondivid did not exit");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Every file under `dir` with its contents, to show nothing was written
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                out.push((p.display().to_string(), Vec::new()));
                stack.push(p);
            } else {
                out.push((p.display().to_string(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// The first page of a Berkeley DB btree file, as Divi Core writes wallet.dat
fn core_wallet_file(path: &Path) {
    let mut page = vec![0u8; 4096];
    page[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
    page[100..108].copy_from_slice(b"walletdb");
    std::fs::write(path, page).unwrap();
}

/// Divi Core's chain data for one network folder `d`: block files and the
/// LevelDB block index and chainstate
fn core_chain_data(d: &Path) {
    let leveldb = |p: &Path| {
        std::fs::create_dir_all(p).unwrap();
        std::fs::write(p.join("CURRENT"), "MANIFEST-000002\n").unwrap();
        std::fs::write(p.join("MANIFEST-000002"), [0u8; 16]).unwrap();
        std::fs::write(p.join("LOG"), "Recovering log #1\n").unwrap();
        std::fs::write(p.join("000003.ldb"), [1u8; 32]).unwrap();
    };
    leveldb(&d.join("blocks/index"));
    leveldb(&d.join("chainstate"));
    std::fs::write(d.join("blocks/blk00000.dat"), [0xfa, 0xbf, 0xb5, 0xda]).unwrap();
    core_wallet_file(&d.join("wallet.dat"));
}

fn debug_log(datadir: &Path) -> String {
    std::fs::read_to_string(datadir.join("debug.log")).unwrap_or_default()
}

/// A Core datadir that has only a testnet3/ folder, given to a testnet
/// irondivid at its root or at testnet3/ itself, is refused and left alone
#[test]
fn core_testnet3_folder_is_refused_and_left_alone() {
    for given in ["", "testnet3"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        core_chain_data(&root.join("testnet3"));
        std::fs::write(root.join("divi.conf"), "rpcuser=core\nrpcpassword=core\n").unwrap();
        let before = snapshot(root);
        let datadir = root.join(given);
        let out = run_to_exit(irondivid(Some(&datadir), "--testnet", free_port()), 30)
            .unwrap_or_else(|| panic!("{given:?}: irondivid kept running"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{given:?}");
        assert!(
            stderr.contains("is a Divi Core data directory"),
            "{given:?}: {stderr}"
        );
        assert!(snapshot(root) == before, "{given:?}: files changed");
    }
}

/// `--wallet` at a file that is not a wallet, or at a Core folder holding
/// wallet.dat, is refused with a plain message before anything is written
#[test]
fn wallet_option_at_a_plain_file_or_a_core_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().join("irondivi");
    std::fs::create_dir_all(&datadir).unwrap();
    let notes = dir.path().join("notes.txt");
    std::fs::write(&notes, "not a wallet").unwrap();
    let core = dir.path().join("divi");
    std::fs::create_dir_all(&core).unwrap();
    core_wallet_file(&core.join("wallet.dat"));
    let before = (snapshot(&core), std::fs::read(&notes).unwrap());

    for (wallet, says) in [
        (&notes, "is a file; irondivid's wallet is a folder"),
        (&core, "holds a Divi Core wallet.dat"),
    ] {
        let mut cmd = irondivid(Some(&datadir), "--regtest", free_port());
        cmd.arg("--wallet").arg(wallet);
        let out = run_to_exit(cmd, 60).unwrap_or_else(|| panic!("{wallet:?}: kept running"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{wallet:?}");
        assert!(stderr.contains(says), "{wallet:?}: {stderr}");
        assert!(
            snapshot(&datadir).is_empty(),
            "{wallet:?}: written before the refusal"
        );
    }
    assert!(
        (snapshot(&core), std::fs::read(&notes).unwrap()) == before,
        "files changed"
    );
}

/// `-hdseed` on a first start makes the wallet Divi Core makes from that
/// seed, shown by dumphdinfo with an empty mnemonic; a seed that is not hex
/// is named in the log and the wallet comes from the mnemonic instead, as in
/// Core (wallet.cpp:2286-2297)
#[test]
fn hdseed_option_makes_cores_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path(), |rpc_port| {
        let mut cmd = irondivid(Some(dir.path()), "--regtest", rpc_port);
        cmd.arg(format!("-hdseed={SEED}"));
        cmd
    });
    let info = daemon.rpc("validateaddress", json!([CORE_FIRST_ADDRESS]));
    assert_eq!(info["ismine"], true, "{info}");
    let hd = daemon.rpc("dumphdinfo", json!([]));
    assert_eq!(hd["hdseed"], SEED);
    assert_eq!(hd["mnemonic"], "");
    daemon.stop();
    assert!(!debug_log(dir.path()).contains(SEED), "the seed was logged");

    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path(), |rpc_port| {
        let mut cmd = irondivid(Some(dir.path()), "--regtest", rpc_port);
        cmd.arg("-hdseed=not-hex");
        cmd
    });
    let hd = daemon.rpc("dumphdinfo", json!([]));
    assert_eq!(
        hd["mnemonic"],
        WALLET_MNEMONIC
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    );
    daemon.stop();
    assert!(
        debug_log(dir.path()).contains("-hdseed is not a hex seed"),
        "no warning for a seed that is not hex"
    );
}

/// The masternode.conf collateral lock is always on: `-mnconflock=0` is
/// named as not supported and the entry is still locked. A line with too
/// few fields is skipped, a collateral that is not a txid is named in the
/// log, and irondivid starts with the entries it can use.
#[test]
fn masternode_conf_lock_is_always_on_and_unusable_lines_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path();
    let txid = "52e93b7c00000000000000000000000000000000000000000000000000009434";
    std::fs::write(
        datadir.join("masternode.conf"),
        format!(
            "# Masternode config file\n\
             mn1 127.0.0.1:51476 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg {txid} 1\n\
             short line\n\
             mn2 127.0.0.2:51476 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg not-a-txid 0\n"
        ),
    )
    .unwrap();
    let daemon = Daemon::start(datadir, |rpc_port| {
        let mut cmd = irondivid(Some(datadir), "--regtest", rpc_port);
        cmd.arg("-mnconflock=0");
        cmd
    });
    assert_eq!(
        daemon.rpc("listlockunspent", json!([])),
        json!([{"txid": txid, "vout": 1}])
    );
    daemon.stop();
    let log = debug_log(datadir);
    assert!(
        log.contains("Option -mnconflock is not supported by irondivid; ignored"),
        "{log}"
    );
    assert!(
        log.contains("masternode.conf entry mn2: collateral not-a-txid 0"),
        "{log}"
    );
}

/// With no --datadir irondivid keeps to ~/.irondivi/<network>, and a Divi
/// Core ~/.divi beside it is not read or changed
#[test]
fn default_data_folder_is_kept_apart_from_cores() {
    let home = tempfile::tempdir().unwrap();
    let core = home.path().join(".divi");
    core_chain_data(&core.join("regtest"));
    std::fs::write(core.join("divi.conf"), "rpcuser=core\nrpcpassword=core\n").unwrap();
    let before = snapshot(&core);
    // With no -datadir the node uses $HOME/.irondivi
    Daemon::start(&home.path().join(".irondivi"), |rpc_port| {
        let mut cmd = irondivid(None, "--regtest", rpc_port);
        cmd.env("HOME", home.path());
        cmd
    })
    .stop();
    let own = home.path().join(".irondivi/regtest");
    assert!(own.join("chainstate").is_dir(), "no chainstate in {own:?}");
    assert!(own.join("wallet").is_dir(), "no wallet in {own:?}");
    assert!(snapshot(&core) == before, "~/.divi changed");
}

/// Neither divid 3.0.0 nor irondivid has a bulk wallet dump or import
/// (rpcserver.cpp:421-441): both answer "Method not found", so keys move one
/// by one with dumpprivkey / importprivkey
#[test]
fn bulk_wallet_dump_is_not_there_as_in_divid() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(dir.path(), |rpc_port| {
        irondivid(Some(dir.path()), "--regtest", rpc_port)
    });
    for (method, params) in [
        (
            "dumpwallet",
            json!([dir.path().join("dump.txt").to_string_lossy()]),
        ),
        (
            "importwallet",
            json!([dir.path().join("dump.txt").to_string_lossy()]),
        ),
    ] {
        let reply = daemon.call(method, params);
        assert_eq!(reply["error"]["code"], -32601, "{method}: {reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .starts_with("Method not found"),
            "{method}: {reply}"
        );
    }
    assert!(!dir.path().join("dump.txt").exists());
    daemon.stop();
}
