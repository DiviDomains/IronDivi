// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! irondivid started the way divid is started: divid's command-line form,
//! divid's refusals, -server, -rpcallowip, -blocknotify, -walletnotify, the
//! pid file and -wallet behave as in Divi Core 3.0.0.

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
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The HTTP status and JSON body of one call to `ip:port`; None if the
/// connection fails
fn http_rpc(ip: IpAddr, port: u16, method: &str, params: &Value) -> Option<(u16, Value)> {
    let mut stream = TcpStream::connect((ip, port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
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
    let status = response.split_whitespace().nth(1)?.parse().ok()?;
    let start = response.find("\r\n\r\n")? + 4;
    Some((
        status,
        serde_json::from_str(&response[start..]).unwrap_or(Value::Null),
    ))
}

fn local(port: u16, method: &str, params: Value) -> Option<Value> {
    let (_, body) = http_rpc("127.0.0.1".parse().unwrap(), port, method, &params)?;
    assert!(body["error"].is_null(), "{method}: {}", body["error"]);
    Some(body["result"].clone())
}

struct Daemon {
    child: Child,
    rpc_port: u16,
}

impl Daemon {
    /// Start irondivid with `args`; wait for RPC unless `rpc` is false
    fn start(args: &[String], env: &[(&str, &str)], rpc_port: u16, rpc: bool) -> Daemon {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
        cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn irondivid");
        let mut daemon = Daemon { child, rpc_port };
        if rpc {
            let deadline = Instant::now() + Duration::from_secs(120);
            while local(rpc_port, "getblockcount", json!([])).is_none() {
                assert!(
                    daemon.child.try_wait().unwrap().is_none(),
                    "irondivid exited before its RPC server came up"
                );
                assert!(Instant::now() < deadline, "RPC server did not come up");
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        daemon
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        local(self.rpc_port, method, params).unwrap_or_else(|| panic!("{method}: no reply"))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// divid's form of the options this test runs a regtest node with
fn divid_args(datadir: &Path, rpc_port: u16) -> Vec<String> {
    vec![
        "-regtest".into(),
        format!("-datadir={}", datadir.display()),
        format!("-rpcport={}", rpc_port),
        format!("-port={}", free_port()),
        "-bind=127.0.0.1".into(),
        "-rpcuser=test".into(),
        "-rpcpassword=test".into(),
    ]
}

/// Run `cmd` to its exit; panic if it is still running after 30 s
fn output_within(cmd: &mut Command) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irondivid");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("irondivid did not exit within 30 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.wait_with_output().unwrap()
}

/// Wait up to 20 s for `f` to be true
fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Append `n` proof-of-work blocks paying 1250 DIVI each to `to` to a stopped
/// node's chain (regtest has no mining RPC)
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

/// A divid command line starts the node: `-name=value` options, an unknown
/// option and a negated one are taken as divid takes them
#[test]
fn divid_command_line_starts_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let mut args = divid_args(dir.path(), rpc_port);
    args.extend([
        "-foo=bar".into(),
        "-nosuchoption".into(),
        "-nolisten".into(),
    ]);
    let daemon = Daemon::start(&args, &[], rpc_port, true);
    assert_eq!(daemon.rpc("getblockcount", json!([])), json!(0));
}

/// divid's start-up refusals and -help / -version, exit code 1 (divid.cpp)
#[test]
fn start_up_refusals_are_divid_s() {
    let bin = env!("CARGO_BIN_EXE_irondivid");
    let missing = std::env::temp_dir().join("irondivid-no-such-datadir-for-this-test");
    let out = output_within(Command::new(bin).arg(format!("-datadir={}", missing.display())));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        format!(
            "Error: Specified data directory \"{}\" does not exist.\n",
            missing.display()
        )
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(!missing.exists(), "the data directory was created");

    let dir = tempfile::tempdir().unwrap();
    let out = output_within(
        Command::new(bin)
            .arg(format!("-datadir={}", dir.path().display()))
            .args(["-testnet", "-regtest"]),
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Error: Invalid combination of -regtest and -testnet.\n"
    );
    assert_eq!(out.status.code(), Some(1));

    for flag in ["-help", "-?", "-version"] {
        let out = output_within(Command::new(bin).arg(flag));
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("IronDivi Daemon version v"),
            "{flag}"
        );
        assert_eq!(out.status.code(), Some(1), "{flag}");
    }
}

/// -server=0: the node runs, with no RPC server
#[test]
fn server_0_runs_without_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let mut args = divid_args(dir.path(), rpc_port);
    args.push("-server=0".into());
    let mut daemon = Daemon::start(&args, &[], rpc_port, false);
    std::thread::sleep(Duration::from_secs(5));
    assert!(
        daemon.child.try_wait().unwrap().is_none(),
        "irondivid exited"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", rpc_port)).is_err(),
        "RPC is served"
    );
}

/// This host's address on another interface than the loopback, if any
fn non_loopback_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// -rpcallowip: the server listens on every interface and answers only the
/// local host and the allowed subnets; others get HTTP 403
/// (rpcserver.cpp:633-706)
#[test]
fn rpcallowip_lets_the_allowed_subnets_in() {
    let Some(ip) = non_loopback_ip() else {
        eprintln!("no non-loopback address on this host; nothing to check");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let mut args = divid_args(dir.path(), rpc_port);
    args.push("-rpcallowip=192.0.2.0/24".into());
    let daemon = Daemon::start(&args, &[], rpc_port, true);
    let (status, _) = http_rpc(ip, rpc_port, "getblockcount", &json!([])).expect("connects");
    assert_eq!(status, 403);
    drop(daemon);

    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let mut args = divid_args(dir.path(), rpc_port);
    args.push(format!("-rpcallowip={}", ip));
    let _daemon = Daemon::start(&args, &[], rpc_port, true);
    let (status, body) = http_rpc(ip, rpc_port, "getblockcount", &json!([])).expect("connects");
    assert_eq!((status, body["result"].clone()), (200, json!(0)));
}

/// -blocknotify runs its command with the new tip's hash whenever the best
/// block changes; -walletnotify with the txid of each wallet transaction
/// added or updated
#[test]
fn blocknotify_and_walletnotify_run_their_commands() {
    let dir = tempfile::tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let first = WalletDb::with_hd_wallet(Network::Regtest, hd)
        .new_receiving_address()
        .unwrap();
    mine_offline(dir.path(), &first, 25);
    let blocks = dir.path().join("blocks.txt");
    let txs = dir.path().join("txs.txt");
    std::fs::write(
        dir.path().join("divi.conf"),
        format!(
            "blocknotify=echo %s >> {}\nwalletnotify=echo %s >> {}\n",
            blocks.display(),
            txs.display()
        ),
    )
    .unwrap();
    let rpc_port = free_port();
    let daemon = Daemon::start(
        &divid_args(dir.path(), rpc_port),
        &[("WALLET_MNEMONIC", MNEMONIC), ("WALLET_LOOKAHEAD", "5")],
        rpc_port,
        true,
    );
    let tip = daemon.rpc("getbestblockhash", json!([]));
    let tip = tip.as_str().unwrap().to_string();
    daemon.rpc("invalidateblock", json!([tip]));
    let previous = daemon.rpc("getbestblockhash", json!([]));
    daemon.rpc("reconsiderblock", json!([tip]));
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    assert!(
        eventually(|| read(&blocks).lines().any(|l| l == tip)
            && read(&blocks).contains(previous.as_str().unwrap())),
        "blocknotify wrote: {:?}",
        read(&blocks)
    );

    let to = daemon.rpc("getnewaddress", json!([]));
    let txid = daemon.rpc("sendtoaddress", json!([to, 1]));
    let txid = txid.as_str().unwrap().to_string();
    assert!(
        eventually(|| read(&txs).lines().any(|l| l == txid)),
        "walletnotify wrote: {:?}",
        read(&txs)
    );
}

/// With -daemon the pid goes to divid.pid in the data directory, or to -pid
/// (util.cpp:115-119); -wallet names a wallet within the data directory
#[test]
fn pid_file_and_wallet_are_in_the_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("irondivi.conf"), "wallet=w2\n").unwrap();
    let rpc_port = free_port();
    let status = Command::new(env!("CARGO_BIN_EXE_irondivid"))
        .args(["--daemon", "--regtest", "--datadir"])
        .arg(dir.path())
        .args(["--rpcport", &rpc_port.to_string()])
        .args(["--port", &free_port().to_string(), "--bind", "127.0.0.1"])
        .args(["--rpcuser", "test", "--rpcpassword", "test"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let pid_file = dir.path().join("divid.pid");
    let pid = eventually(|| pid_file.exists()).then(|| {
        std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap()
    });
    let up = eventually(|| local(rpc_port, "getblockcount", json!([])).is_some());
    let wallet_dir = dir.path().join("w2").exists();
    // Stop it however it was started
    let _ = local(rpc_port, "stop", json!([]));
    std::thread::sleep(Duration::from_secs(2));
    if let Some(pid) = pid {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    assert!(pid.is_some(), "no divid.pid in the data directory");
    assert!(up, "the daemon did not come up");
    assert!(wallet_dir, "-wallet=w2 is not in the data directory");
}
