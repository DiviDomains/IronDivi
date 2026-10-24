// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `--export-chain` reads the chain database the node keeps: the exported
//! blocks are the node's blocks (and rebuild them byte for byte), a range past
//! the tip is refused, and a data directory without a chain is refused with
//! nothing written into it.

#![cfg(unix)]

use divi_primitives::block::{Block, BlockHeader};
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::Transaction;
use divi_storage::BlockExport;
use divi_test_support::{free_port, wait_started};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// POST one JSON-RPC call; None while the server is not up
fn try_rpc(port: u16, method: &str, params: &Value) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
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

/// A regtest irondivid on `datadir` with no peers; "dGVzdDp0ZXN0" is base64
/// of test:test
fn irondivid(datadir: &Path, rpc_port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg("--regtest")
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &free_port().to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false"])
        .args(["--connect", "127.0.0.1:1"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .env("WALLET_LOOKAHEAD", "5");
    cmd
}

/// `--export-chain` of heights `start..=end` from `datadir` into `out`, run
/// to its exit (at most 120 s)
fn export(datadir: &Path, start: u32, end: u32, out: &Path) -> Output {
    let mut cmd = irondivid(datadir, free_port());
    cmd.arg("--export-chain")
        .args(["--export-start", &start.to_string()])
        .args(["--export-end", &end.to_string()])
        .arg("--export-output")
        .arg(out)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("--export-chain did not finish");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.wait_with_output().unwrap()
}

struct Daemon {
    child: Child,
    rpc_port: u16,
}

impl Daemon {
    fn start(datadir: &Path) -> Daemon {
        let rpc_port = free_port();
        let child = irondivid(datadir, rpc_port)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn irondivid");
        let mut daemon = Daemon { child, rpc_port };
        wait_started(&mut daemon.child, datadir, || {
            try_rpc(rpc_port, "getblockcount", &json!([])).is_some()
        });
        daemon
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let reply =
            try_rpc(self.rpc_port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
        assert!(reply["error"].is_null(), "{method} {params}: {reply}");
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

/// Every file under `dir` with its contents
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

/// The block an exported file describes, rebuilt from its fields
fn rebuild(e: &BlockExport) -> Block {
    Block {
        header: BlockHeader {
            version: e.version,
            prev_block: Hash256::from_hex(&e.prev_hash).unwrap(),
            merkle_root: Hash256::from_hex(&e.merkle_root).unwrap(),
            time: e.timestamp,
            bits: e.bits,
            nonce: e.nonce,
            accumulator_checkpoint: Hash256::from_hex(&e.accumulator_checkpoint).unwrap(),
        },
        transactions: e
            .transactions
            .iter()
            .map(|t| deserialize::<Transaction>(&hex::decode(&t.hex).unwrap()).unwrap())
            .collect(),
        block_sig: hex::decode(&e.block_sig).unwrap(),
    }
}

/// Mined proof-of-work and proof-of-stake blocks, exported from the stopped
/// node's data directory, are the blocks `getblock` gives
#[test]
fn exported_blocks_are_the_nodes_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().join("node");
    std::fs::create_dir_all(&datadir).unwrap();

    // 101 proof-of-work blocks, then 3 proof-of-stake blocks (with a block
    // signature) from the coins mined above
    let daemon = Daemon::start(&datadir);
    daemon.rpc("setgenerate", json!([101]));
    daemon.rpc("setgenerate", json!([3]));
    let n = daemon.rpc("getblockcount", json!([])).as_u64().unwrap() as u32;
    assert_eq!(n, 104);
    let raw: Vec<String> = (0..=n)
        .map(|h| {
            let hash = daemon.rpc("getblockhash", json!([h]));
            daemon
                .rpc("getblock", json!([hash, 0]))
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let tip = daemon.rpc("getbestblockhash", json!([]));
    daemon.stop();

    let out = dir.path().join("export");
    let o = export(&datadir, 0, n, &out);
    assert!(
        o.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    for (h, raw) in raw.iter().enumerate() {
        let path = out.join(format!("blocks/{h:08}.json"));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("height {h}: {path:?} not written"));
        let exported: BlockExport = serde_json::from_str(&text).unwrap();
        let block: Block = deserialize(&hex::decode(raw).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&exported).unwrap(),
            serde_json::to_value(BlockExport::from_block(&block, h as u32)).unwrap(),
            "height {h}"
        );
        assert_eq!(
            hex::encode(serialize(&rebuild(&exported))),
            *raw,
            "height {h}"
        );
        if h as u32 == n {
            assert!(
                !exported.block_sig.is_empty(),
                "no block signature on the PoS tip"
            );
        }
    }
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["chain"], "regtest", "{manifest}");
    assert_eq!(manifest["block_count"], n + 1, "{manifest}");
    assert_eq!(manifest["export_complete"], true, "{manifest}");
    assert_eq!(manifest["tip_hash"], tip, "{manifest}");
    assert!(
        !datadir.join("blocks").exists(),
        "a blocks/ folder was made in the data directory"
    );

    // Past the tip: refused, nothing written
    let past = dir.path().join("past");
    let o = export(&datadir, 0, n + 1, &past);
    assert!(!o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("above the chain height"), "{stderr}");
    assert!(!past.exists(), "a refused export wrote {past:?}");
}

/// A data directory with no chain database: a plain error naming the folder,
/// and nothing written into the data directory or the output folder
#[test]
fn data_directory_without_a_chain_is_refused_and_left_empty() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().join("empty");
    std::fs::create_dir_all(&datadir).unwrap();
    let out = dir.path().join("export");
    let o = export(&datadir, 0, 10, &out);
    assert!(
        !o.status.success(),
        "export of an empty data directory succeeded"
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("No chain database in"), "{stderr}");
    assert!(
        stderr.contains(&datadir.join("chainstate").display().to_string()),
        "{stderr}"
    );
    assert!(snapshot(&datadir).is_empty(), "{:?}", snapshot(&datadir));
    assert!(!out.exists(), "the output folder was made");
}
