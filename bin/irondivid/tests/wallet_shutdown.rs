// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! An unconfirmed send must survive the daemon ending, however it ends.
//!
//! Each test funds a regtest wallet, sends to another wallet with no block
//! mined, ends irondivid one way (RPC stop, SIGTERM, SIGINT, SIGKILL right
//! after sendtoaddress returned), starts it again on the same datadir and
//! checks that the send is still listed, its inputs are still spent and it
//! is back in the mempool so it can still confirm.

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
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const WALLET_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";
const OTHER_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// First receiving address of a wallet restored from `mnemonic`
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
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let start = response.find("\r\n\r\n")? + 4;
    serde_json::from_str(&response[start..]).ok()
}

fn rpc(port: u16, method: &str, params: Value) -> Value {
    let reply = try_rpc(port, method, &params).unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(
        reply["error"].is_null(),
        "{method} {params}: {}",
        reply["error"]
    );
    reply["result"].clone()
}

struct Daemon {
    child: Child,
    rpc_port: u16,
}

impl Daemon {
    fn start(datadir: &Path) -> Daemon {
        let rpc_port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_irondivid"))
            .arg("--regtest")
            .arg("--datadir")
            .arg(datadir)
            .args(["--rpcport", &rpc_port.to_string()])
            .args(["--port", &free_port().to_string()])
            .args(["--bind", "127.0.0.1", "--staking=false"])
            .env("WALLET_MNEMONIC", WALLET_MNEMONIC)
            .env("WALLET_LOOKAHEAD", "5")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn irondivid");
        let mut daemon = Daemon { child, rpc_port };
        let deadline = Instant::now() + Duration::from_secs(120);
        while try_rpc(rpc_port, "getblockcount", &json!([])).is_none() {
            assert!(
                daemon.child.try_wait().unwrap().is_none(),
                "irondivid exited before its RPC server came up"
            );
            assert!(Instant::now() < deadline, "RPC server did not come up");
            std::thread::sleep(Duration::from_millis(250));
        }
        daemon
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        rpc(self.rpc_port, method, params)
    }

    fn signal(&self, sig: libc::c_int) {
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, sig) },
            0
        );
    }

    /// Wait for the process to end; true if it exited with status 0
    fn wait(mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.success();
            }
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
        block.header.version = 1;
        block.header.prev_block = tip.hash;
        block.header.time = (now - 86_400 + 60 * i).max(tip.time + 1);
        block.header.bits = 0x207fffff;
        let mut sig = vec![0x04];
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
        chain.accept_block(block).unwrap();
    }
}

fn unspent(daemon: &Daemon) -> BTreeSet<(String, u64)> {
    daemon
        .rpc("listunspent", json!([0]))
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            (
                u["txid"].as_str().unwrap().to_string(),
                u["vout"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn listed(daemon: &Daemon, txid: &str) -> Vec<Value> {
    daemon
        .rpc("listtransactions", json!(["*", 100]))
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["txid"] == txid)
        .cloned()
        .collect()
}

enum End {
    RpcStop,
    Signal(libc::c_int),
}

fn send_then_end(how: End) {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path();

    // First start creates the chain store and restores the wallet
    let daemon = Daemon::start(datadir);
    daemon.rpc("stop", json!([]));
    assert!(daemon.wait());
    mine_offline(datadir, &first_address(WALLET_MNEMONIC), 3);

    let daemon = Daemon::start(datadir);
    assert_eq!(daemon.rpc("getblockcount", json!([])), json!(3));
    let before = unspent(&daemon);
    assert_eq!(before.len(), 3, "funding coins: {before:?}");

    let other = first_address(OTHER_MNEMONIC).to_string();
    let txid = daemon.rpc("sendtoaddress", json!([other, 10.0]));
    let txid = txid.as_str().unwrap().to_string();
    let after_send = unspent(&daemon);
    let spent: Vec<_> = before.difference(&after_send).cloned().collect();
    assert_eq!(spent.len(), 1, "send spends one coin");
    assert_eq!(listed(&daemon, &txid).len(), 1);

    let clean = match how {
        End::RpcStop => {
            assert_eq!(daemon.rpc("stop", json!([])), json!("Divi server stopping"));
            true
        }
        End::Signal(sig) => {
            daemon.signal(sig);
            sig != libc::SIGKILL
        }
    };
    let status_ok = daemon.wait();
    if clean {
        assert!(status_ok, "daemon did not exit cleanly");
    }

    let daemon = Daemon::start(datadir);
    let rows = listed(&daemon, &txid);
    assert_eq!(rows.len(), 1, "unconfirmed send lost: {rows:?}");
    assert_eq!(rows[0]["category"], "send");
    assert_eq!(rows[0]["confirmations"], 0);
    let now = unspent(&daemon);
    assert!(
        spent.iter().all(|op| !now.contains(op)),
        "input of the unconfirmed send is spendable again: {now:?}"
    );
    assert_eq!(now, after_send);
    // Back in the mempool, so it can still be mined
    let mempool = daemon.rpc("getrawmempool", json!([]));
    assert!(
        mempool
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == &json!(txid)),
        "send not resubmitted to the mempool: {mempool}"
    );
}

#[test]
fn unconfirmed_send_survives_rpc_stop() {
    send_then_end(End::RpcStop);
}

#[test]
fn unconfirmed_send_survives_sigterm() {
    send_then_end(End::Signal(libc::SIGTERM));
}

#[test]
fn unconfirmed_send_survives_sigint() {
    send_then_end(End::Signal(libc::SIGINT));
}

#[test]
fn unconfirmed_send_survives_kill_9() {
    send_then_end(End::Signal(libc::SIGKILL));
}
