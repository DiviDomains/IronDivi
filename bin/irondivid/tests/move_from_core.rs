// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Starting irondivid where Divi Core's files are: a Core data directory and
//! a Core wallet.dat given as the wallet are refused with a plain message and
//! left as they were, a wallet.dat beside irondivid's wallet is named in the
//! log, a chain database is not opened as another network, and the collateral
//! of every masternode.conf entry stays locked across a send and a restart.

#![cfg(unix)]

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_test_support::{free_port, wait_started};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const WALLET_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";
const OTHER_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn first_address(mnemonic: &str) -> divi_wallet::Address {
    let hd = HdWallet::from_mnemonic(mnemonic, None, ChainMode::Divi).unwrap();
    WalletDb::with_hd_wallet(Network::Regtest, hd)
        .new_receiving_address()
        .unwrap()
}

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

/// The irondivid command for `network` on `datadir`, with no peers
fn irondivid(datadir: &Path, network: &str, rpc_port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
    cmd.arg(network)
        .arg("--datadir")
        .arg(datadir)
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &free_port().to_string()])
        .args(["--bind", "127.0.0.1", "--staking=false"])
        .args(["--connect", "127.0.0.1:1"])
        // RPC always requires credentials; "dGVzdDp0ZXN0" is base64 of test:test
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .env("WALLET_MNEMONIC", WALLET_MNEMONIC)
        .env("WALLET_LOOKAHEAD", "5");
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
    fn start(datadir: &Path) -> Daemon {
        let rpc_port = free_port();
        let child = irondivid(datadir, "--regtest", rpc_port)
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

/// Append `n` PoW blocks paying 1250 DIVI each to `to` to the chain store of a
/// stopped node (regtest has no miner RPC)
fn mine_offline(datadir: &Path, to: &divi_wallet::Address, n: u32) {
    let db = Arc::new(ChainDatabase::open(datadir.join("chainstate")).unwrap());
    let chain = Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    for i in 0..n {
        let tip = chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = (now - 86_400 + 60 * i).max(tip.time + 1);
        block.header.bits = 0x207fffff;
        // BIP34: the coinbase starts with the height
        let mut sig = divi_storage::bip34_height_script(height);
        sig.extend_from_slice(&height.to_le_bytes());
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * 100_000_000),
                Script::new_p2pkh(to.hash.as_bytes()),
            )],
            lock_time: 0,
        });
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        chain.accept_block(block).unwrap();
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

/// Divi Core's data directory for `net` (empty: mainnet): block files, the
/// LevelDB block index and chainstate, wallet.dat
fn core_datadir(root: &Path, net: &str) {
    let d = root.join(net);
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
    std::fs::write(
        root.join("divi.conf"),
        "rpcuser=core\nrpcpassword=core\nserver=1\n",
    )
    .unwrap();
}

#[test]
fn core_datadir_is_refused_and_left_alone() {
    // (Core network folder made, datadir given, irondivid network): the Core
    // mainnet folder, Core's regtest folder, and the root of a Core regtest-only
    // layout
    for (net, given, network) in [
        ("", "", "--testnet"),
        ("regtest", "regtest", "--regtest"),
        ("regtest", "", "--regtest"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        core_datadir(root, net);
        let before = snapshot(root);
        let datadir = root.join(given);
        let out = run_to_exit(irondivid(&datadir, network, free_port()), 30)
            .unwrap_or_else(|| panic!("{datadir:?} {network}: irondivid kept running"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{datadir:?} {network}");
        assert!(
            stderr.contains("is a Divi Core data directory"),
            "{datadir:?} {network}: {stderr}"
        );
        assert!(
            snapshot(root) == before,
            "{datadir:?} {network}: files changed"
        );
    }
}

#[test]
fn wallet_option_at_a_core_wallet_file_gives_a_plain_message() {
    let dir = tempfile::tempdir().unwrap();
    let core = dir.path().join("divi");
    std::fs::create_dir_all(&core).unwrap();
    core_wallet_file(&core.join("wallet.dat"));
    // -datadir must exist, as divid's
    let datadir = dir.path().join("irondivi");
    std::fs::create_dir_all(&datadir).unwrap();
    let before = snapshot(&core);
    let mut cmd = irondivid(&datadir, "--regtest", free_port());
    cmd.arg("--wallet").arg(core.join("wallet.dat"));
    let out = run_to_exit(cmd, 60).expect("irondivid kept running");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("is a Divi Core wallet file (Berkeley DB)"),
        "{stderr}"
    );
    assert!(stderr.contains("recovery phrase"), "{stderr}");
    assert!(snapshot(&core) == before, "wallet.dat changed");
    assert!(
        snapshot(&datadir).is_empty(),
        "nothing written before the refusal"
    );
}

#[test]
fn wallet_dat_in_the_datadir_is_named_in_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path();
    let wallet_dat = datadir.join("wallet.dat");
    core_wallet_file(&wallet_dat);
    let before = std::fs::read(&wallet_dat).unwrap();
    Daemon::start(datadir).stop();
    let log = std::fs::read_to_string(datadir.join("debug.log")).unwrap();
    let line = log
        .lines()
        .find(|l| l.contains("wallet.dat is a Divi Core wallet file"))
        .unwrap_or_else(|| panic!("no wallet.dat warning in the log:\n{log}"));
    assert!(line.contains("WARN"), "{line}");
    assert!(line.contains("does not read wallet.dat"), "{line}");
    assert!(line.contains("Imported keys"), "{line}");
    assert_eq!(
        std::fs::read(&wallet_dat).unwrap(),
        before,
        "wallet.dat changed"
    );
}

#[test]
fn chain_datadir_of_another_network_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path();
    Daemon::start(datadir).stop();
    // Without a wallet nothing else notices the network
    for extra in [&[][..], &["--disablewallet"][..]] {
        let mut cmd = irondivid(datadir, "--testnet", free_port());
        cmd.args(extra);
        let out = run_to_exit(cmd, 60).unwrap_or_else(|| {
            panic!("{extra:?}: testnet irondivid kept running on a regtest datadir")
        });
        assert!(!out.status.success(), "{extra:?}");
        let log = std::fs::read_to_string(datadir.join("debug.log")).unwrap();
        let refusals = log
            .matches("made for regtest, but irondivid was started for testnet")
            .count();
        assert!(refusals > extra.len(), "{extra:?}: {log}");
    }
    // The regtest node still starts on it
    Daemon::start(datadir).stop();
}

fn outpoints(v: &Value) -> Vec<(String, u64)> {
    let mut out: Vec<_> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            (
                u["txid"].as_str().unwrap().to_string(),
                u["vout"].as_u64().unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn masternode_collateral_stays_locked_across_a_send_and_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path();
    Daemon::start(datadir).stop();
    mine_offline(datadir, &first_address(WALLET_MNEMONIC), 3);
    // Regtest coinbases mature after 20 blocks: 22 more blocks to someone else
    mine_offline(datadir, &first_address(OTHER_MNEMONIC), 22);

    let daemon = Daemon::start(datadir);
    let coins = outpoints(&daemon.rpc("listunspent", json!([])));
    assert_eq!(coins.len(), 3, "{coins:?}");
    daemon.stop();
    let collateral = coins[1].clone();
    std::fs::write(
        datadir.join("masternode.conf"),
        format!(
            "# Masternode config file\nmn1 127.0.0.1:51476 \
             93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg {} {}\n",
            collateral.0, collateral.1
        ),
    )
    .unwrap();

    let daemon = Daemon::start(datadir);
    assert_eq!(
        outpoints(&daemon.rpc("listlockunspent", json!([]))),
        vec![collateral.clone()]
    );
    // More than the two free coins hold: refused rather than spending the collateral
    let other = first_address(OTHER_MNEMONIC).to_string();
    let reply = daemon.call("sendtoaddress", json!([other, 2600.0]));
    assert!(
        !reply["error"].is_null(),
        "send took the collateral: {reply}"
    );
    // A large send the free coins cover leaves the collateral unspent
    daemon.rpc("sendtoaddress", json!([other, 2400.0]));
    let out = daemon.rpc("gettxout", json!([collateral.0, collateral.1, true]));
    assert!(!out.is_null(), "collateral spent");
    daemon.stop();

    let daemon = Daemon::start(datadir);
    assert_eq!(
        outpoints(&daemon.rpc("listlockunspent", json!([]))),
        vec![collateral.clone()]
    );
    let out = daemon.rpc("gettxout", json!([collateral.0, collateral.1, true]));
    assert!(!out.is_null(), "collateral spent");
    daemon.stop();
}
