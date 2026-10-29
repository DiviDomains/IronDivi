// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
use divi_test_support::{
    free_port, log_len, log_tail, port_taken_since, wait_up, Started, START_TRIES,
};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";

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
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Basic dGVzdDp0ZXN0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    /// Start irondivid with `args`; wait for RPC unless `rpc` is false. A
    /// node that lost its -rpcport or -port to another process is started
    /// again with new ones; `rpc_port` of the result is the one it uses.
    fn start(args: &[String], env: &[(&str, &str)], rpc_port: u16, rpc: bool) -> Daemon {
        let datadir = PathBuf::from(
            args.iter()
                .find_map(|a| a.strip_prefix("-datadir="))
                .unwrap_or_default(),
        );
        let (mut args, mut rpc_port) = (args.to_vec(), rpc_port);
        for _ in 0..START_TRIES {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.args(&args).stdout(Stdio::null()).stderr(Stdio::null());
            for (k, v) in env {
                cmd.env(k, v);
            }
            let from = log_len(&datadir);
            let mut child = cmd.spawn().expect("spawn irondivid");
            if !rpc
                || wait_up(&mut child, &datadir, from, || {
                    local(rpc_port, "getblockcount", json!([])).is_some()
                }) == Started::Up
            {
                return Daemon { child, rpc_port };
            }
            rpc_port = free_port();
            for a in args.iter_mut() {
                if a.starts_with("-rpcport=") {
                    *a = format!("-rpcport={rpc_port}");
                } else if a.starts_with("-port=") {
                    *a = format!("-port={}", free_port());
                }
            }
        }
        panic!(
            "irondivid lost a port {START_TRIES} times; its log ends:\n{}",
            log_tail(&datadir)
        );
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

/// Run `cmd` to its exit; panic if it is still running after 120 s (a slow,
/// loaded host can take far longer than an idle one)
fn output_within(cmd: &mut Command) -> Output {
    let mut child = cmd
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

/// SIGKILL `pid` if it is still an irondivid (a pid read from a pid file may
/// have exited, and its number be reused, by the time it is killed)
fn kill_irondivid(pid: i32) {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let is_irondivid = String::from_utf8_lossy(&cmdline).contains("irondivid");
    if is_irondivid || !Path::new("/proc/self").exists() {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// Wait up to 120 s for `f` to be true, as long as `Daemon::start` waits for
/// RPC: a node started on a loaded host can take far longer than 20 s
fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
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

/// divid refuses any -checklevel at start, whatever the level
/// (init.cpp:782-784); -checkblocks is taken
#[test]
fn checklevel_is_refused_at_start() {
    let bin = env!("CARGO_BIN_EXE_irondivid");
    for level in ["0", "3", "4"] {
        let dir = tempfile::tempdir().unwrap();
        let out = output_within(
            Command::new(bin)
                .arg(format!("-datadir={}", dir.path().display()))
                .args([
                    "-regtest",
                    "-checkblocks=1",
                    &format!("-checklevel={level}"),
                ]),
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            text.contains("Unsupported argument -checklevel found. Checklevel must be level 4."),
            "-checklevel={level}: {text}"
        );
        assert!(!out.status.success(), "-checklevel={level} started");
    }
}

/// A start the node refuses prints divid's InitError line, "Error: " and the
/// reason alone (noui.cpp:38-40), and exits 1 (divid.cpp:180): a changed
/// -txindex without -reindex (init.cpp:1104-1105) and a -sporkkey that is not
/// the network's spork key (init.cpp:971-974)
#[test]
fn refused_starts_print_divid_s_error_line() {
    // The lines of stderr that report an error ("Logging to ..." comes first)
    let errors = |out: &Output| -> Vec<String> {
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|l| l.starts_with("Error"))
            .map(String::from)
            .collect()
    };
    let bin = env!("CARGO_BIN_EXE_irondivid");
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let mut args = divid_args(dir.path(), rpc_port);
    args.push("-txindex=0".into());
    drop(Daemon::start(&args, &[], rpc_port, true));

    let mut args = divid_args(dir.path(), free_port());
    args.push("-txindex=1".into());
    let out = output_within(Command::new(bin).args(&args));
    assert_eq!(
        errors(&out),
        ["Error: You need to rebuild the database using -reindex to change -txindex"]
    );
    assert_eq!(out.status.code(), Some(1));

    // A key made here, in divi.conf: not regtest's spork key
    let key = divi_crypto::keys::SecretKey::new_random();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(key.as_bytes());
    let wif = divi_wallet::encode_wif(&bytes, true, Network::Testnet);
    let fresh = tempfile::tempdir().unwrap();
    std::fs::write(fresh.path().join("divi.conf"), format!("sporkkey={wif}\n")).unwrap();
    let out = output_within(Command::new(bin).args(divid_args(fresh.path(), free_port())));
    assert_eq!(
        errors(&out),
        ["Error: Unable to sign spork message, wrong key?"]
    );
    assert_eq!(out.status.code(), Some(1));
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
    let (status, _) = http_rpc(ip, daemon.rpc_port, "getblockcount", &json!([])).expect("connects");
    assert_eq!(status, 403);
    drop(daemon);

    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let mut args = divid_args(dir.path(), rpc_port);
    args.push(format!("-rpcallowip={}", ip));
    let daemon = Daemon::start(&args, &[], rpc_port, true);
    let (status, body) =
        http_rpc(ip, daemon.rpc_port, "getblockcount", &json!([])).expect("connects");
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

/// -rescan scans the wallet from the first block when it loads
/// (init.cpp:1242, wallet.cpp:279-313), and -salvagewallet sets -rescan
/// (init.cpp:763-766): a key imported without a rescan shows its coins after
/// such a start, and not after a plain one
#[test]
fn rescan_and_salvagewallet_find_the_coins_of_a_key_imported_without_rescan() {
    let dir = tempfile::tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let first = WalletDb::with_hd_wallet(Network::Regtest, hd)
        .new_receiving_address()
        .unwrap();
    mine_offline(dir.path(), &first, 25);
    let rpc_port = free_port();
    let args = divid_args(dir.path(), rpc_port);
    let wif = {
        let daemon = Daemon::start(
            &args,
            &[("WALLET_MNEMONIC", MNEMONIC), ("WALLET_LOOKAHEAD", "5")],
            rpc_port,
            true,
        );
        let to = daemon.rpc("getnewaddress", json!([]));
        daemon.rpc("sendtoaddress", json!([to, 3]));
        daemon.rpc("setgenerate", json!([1]));
        daemon.rpc("dumpprivkey", json!([to]))
    };
    let start = |wallet: &str, extra: &[&str]| {
        let mut args = args.clone();
        args.push(format!("-wallet={wallet}"));
        args.extend(extra.iter().map(|a| a.to_string()));
        Daemon::start(&args, &[], rpc_port, true)
    };
    for (wallet, option) in [("w-rescan", "-rescan"), ("w-salvage", "-salvagewallet")] {
        let daemon = start(wallet, &[]);
        daemon.rpc("importprivkey", json!([wif, "", false]));
        assert_eq!(daemon.rpc("getbalance", json!([])), json!(0.0));
        drop(daemon);
        let daemon = start(wallet, &[]);
        assert_eq!(
            daemon.rpc("getbalance", json!([])),
            json!(0.0),
            "{wallet}: a plain start does not rescan"
        );
        drop(daemon);
        let daemon = start(wallet, &[option]);
        assert_eq!(
            daemon.rpc("getbalance", json!([])),
            json!(3.0),
            "{wallet}: {option} finds the imported key's coin"
        );
    }
}

/// -keypool sets how many keys of each chain the keypool is topped up to
/// (wallet.cpp:2071-2080). A new wallet is filled to it and gives one key to
/// the default key (wallet.cpp:342-356); a key taken is topped up first; a
/// load leaves the pool as it is (wallet.cpp:2122-2131); keypoolrefill tops
/// it up to the current -keypool. The numbers are divid's.
#[test]
fn keypool_option_sets_the_keypool_size() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let start = |keypool: u32| {
        let mut args = divid_args(dir.path(), rpc_port);
        args.push(format!("-keypool={keypool}"));
        Daemon::start(&args, &[], rpc_port, true)
    };
    let size = |d: &Daemon| d.rpc("getwalletinfo", json!([]))["keypoolsize"].clone();
    let daemon = start(5);
    assert_eq!(size(&daemon), json!(9), "a new wallet with -keypool=5");
    daemon.rpc("getnewaddress", json!([]));
    assert_eq!(size(&daemon), json!(9), "after getnewaddress");
    drop(daemon);
    let daemon = start(8);
    assert_eq!(size(&daemon), json!(9), "loaded with -keypool=8");
    daemon.rpc("keypoolrefill", json!([]));
    assert_eq!(size(&daemon), json!(16), "keypoolrefill with -keypool=8");
}

/// -upgradewallet limits the version a new wallet may have; one below the
/// base wallet version, as a bare -upgradewallet is (read as 0), stops the
/// start, while the client version itself gives the latest
/// (wallet.cpp:183, :1963-1971; init.cpp:1175). An existing wallet is not
/// checked.
#[test]
fn upgradewallet_below_the_base_version_refuses_a_new_wallet() {
    let bin = env!("CARGO_BIN_EXE_irondivid");
    let dir = tempfile::tempdir().unwrap();
    let mut args = divid_args(dir.path(), free_port());
    args.push("-upgradewallet".into());
    let out = output_within(Command::new(bin).args(&args));
    let errors: Vec<String> = String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.starts_with("Error"))
        .map(String::from)
        .collect();
    assert_eq!(
        errors,
        ["Error: Error loading wallet.dat: database load failure"]
    );
    assert_eq!(out.status.code(), Some(1));

    for option in ["-upgradewallet=3000000", "-upgradewallet"] {
        let rpc_port = free_port();
        let mut args = divid_args(dir.path(), rpc_port);
        args.push(option.into());
        let daemon = Daemon::start(&args, &[], rpc_port, true);
        assert_eq!(
            daemon.rpc("getwalletinfo", json!([]))["walletversion"],
            json!(120200),
            "{option}"
        );
    }
}

/// -walletnotify runs each time divid's wallet adds or updates a
/// transaction (wallet.cpp:1283): a send twice (CommitTransaction, then the
/// mempool, :1878) and its block once
#[test]
fn walletnotify_runs_as_often_as_divid_s() {
    let dir = tempfile::tempdir().unwrap();
    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let first = WalletDb::with_hd_wallet(Network::Regtest, hd)
        .new_receiving_address()
        .unwrap();
    mine_offline(dir.path(), &first, 25);
    let txs = dir.path().join("txs.txt");
    std::fs::write(
        dir.path().join("divi.conf"),
        format!("walletnotify=echo %s >> {}\n", txs.display()),
    )
    .unwrap();
    let rpc_port = free_port();
    let daemon = Daemon::start(
        &divid_args(dir.path(), rpc_port),
        &[("WALLET_MNEMONIC", MNEMONIC), ("WALLET_LOOKAHEAD", "5")],
        rpc_port,
        true,
    );
    let count = |txid: &str| {
        std::fs::read_to_string(&txs)
            .unwrap_or_default()
            .lines()
            .filter(|l| *l == txid)
            .count()
    };
    let settled = |txid: &str, n: usize| {
        let reached = eventually(|| count(txid) >= n);
        // Nothing more comes for this step
        std::thread::sleep(Duration::from_secs(2));
        reached && count(txid) == n
    };

    let to = daemon.rpc("getnewaddress", json!([]));
    let txid = daemon.rpc("sendtoaddress", json!([to, 1]));
    let txid = txid.as_str().unwrap().to_string();
    assert!(settled(&txid, 2), "send: {} calls", count(&txid));

    daemon.rpc("setgenerate", json!([1]));
    assert!(settled(&txid, 3), "block: {} calls", count(&txid));
}

/// With -daemon the pid goes to divid.pid in the data directory, or to -pid
/// (util.cpp:115-119); -wallet names a wallet within the data directory
#[test]
fn pid_file_and_wallet_are_in_the_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("irondivi.conf"), "wallet=w2\n").unwrap();
    let pid_file = dir.path().join("divid.pid");
    // The file can exist before the pid is written into it
    let read_pid = || {
        std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|p| p.trim().parse::<i32>().ok())
    };
    // The daemon forks away, so a lost port shows only in its log: then it
    // is started again on new ports
    let (mut rpc_port, mut pid, mut up) = (0, None, false);
    for _ in 0..START_TRIES {
        rpc_port = free_port();
        let from = log_len(dir.path());
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
        eventually(|| {
            pid = read_pid();
            pid.is_some()
        });
        up = eventually(|| {
            local(rpc_port, "getblockcount", json!([])).is_some()
                || port_taken_since(dir.path(), from)
        });
        if !port_taken_since(dir.path(), from) {
            break;
        }
        if let Some(pid) = pid.take() {
            kill_irondivid(pid);
        }
        let _ = std::fs::remove_file(&pid_file);
    }
    let wallet_dir = dir.path().join("w2").exists();
    // Stop it however it was started
    let _ = local(rpc_port, "stop", json!([]));
    std::thread::sleep(Duration::from_secs(2));
    if let Some(pid) = pid {
        kill_irondivid(pid);
    }
    assert!(pid.is_some(), "no divid.pid in the data directory");
    assert!(up, "the daemon did not come up");
    assert!(wallet_dir, "-wallet=w2 is not in the data directory");
}

/// A new wallet is made from mnemonic= in divi.conf, as Divi Core takes
/// -mnemonic from its file (wallet.cpp:2298-2304): BasicSwap seeds divid
/// that way, started with -noconnect -nodnsseed -nolisten. The phrase is
/// never written to the log.
#[test]
fn mnemonic_in_divi_conf_seeds_a_new_wallet() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("divi.conf"),
        format!("regtest=1\nmnemonic={MNEMONIC}\n"),
    )
    .unwrap();
    let rpc_port = free_port();
    let mut args = divid_args(dir.path(), rpc_port);
    args.retain(|a| a != "-bind=127.0.0.1");
    args.extend(["-noconnect", "-nodnsseed", "-nolisten"].map(String::from));
    let daemon = Daemon::start(&args, &[], rpc_port, true);

    let hd = HdWallet::from_mnemonic(MNEMONIC, None, ChainMode::Divi).unwrap();
    let first = WalletDb::with_hd_wallet(Network::Regtest, hd)
        .new_receiving_address()
        .unwrap();
    let info = daemon.rpc("validateaddress", json!([first.to_string()]));
    assert_eq!(info["ismine"], true, "{info}");
    assert_eq!(daemon.rpc("getconnectioncount", json!([])), 0);
    drop(daemon);

    let log = std::fs::read_to_string(dir.path().join("regtest").join("debug.log"))
        .or_else(|_| std::fs::read_to_string(dir.path().join("debug.log")))
        .unwrap_or_default();
    assert!(!log.is_empty(), "no debug.log");
    assert!(!log.contains(MNEMONIC), "the mnemonic was logged");
}

/// With -mnemonicpassphrase and no -mnemonic a new wallet gets new words and
/// that passphrase, as Divi Core's GenerateNewHDChain (wallet.cpp:2298-2307,
/// hdchain.cpp:56-67): its first address is the one the dumped words give
/// with the passphrase. An existing wallet is left as it is, and a
/// passphrase over 256 characters stops the start of a new wallet.
#[test]
fn mnemonicpassphrase_alone_makes_new_words_with_it() {
    const PASSPHRASE: &str = "regtest passphrase 1";
    let first_address = |words: &str, passphrase: Option<&str>| {
        let hd = HdWallet::from_mnemonic(words, passphrase, ChainMode::Divi).unwrap();
        WalletDb::with_hd_wallet(Network::Regtest, hd)
            .new_receiving_address()
            .unwrap()
            .to_string()
    };

    // A new wallet
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("divi.conf"),
        format!("regtest=1\nmnemonicpassphrase={PASSPHRASE}\n"),
    )
    .unwrap();
    let rpc_port = free_port();
    let daemon = Daemon::start(&divid_args(dir.path(), rpc_port), &[], rpc_port, true);
    let info = daemon.rpc("dumphdinfo", json!([]));
    let words = info["mnemonic"].as_str().unwrap().to_string();
    assert_eq!(words.split_whitespace().count(), 24);
    assert_eq!(info["mnemonicpassphrase"], PASSPHRASE);
    let mine = |a: &str| daemon.rpc("validateaddress", json!([a]))["ismine"].clone();
    assert_eq!(mine(&first_address(&words, Some(PASSPHRASE))), true);
    assert_eq!(mine(&first_address(&words, None)), false);
    drop(daemon);
    let log = std::fs::read_to_string(dir.path().join("debug.log")).unwrap_or_default();
    assert!(!log.is_empty(), "no debug.log");
    assert!(!log.contains(&words) && !log.contains(PASSPHRASE));

    // An existing wallet is unchanged by a passphrase given later
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let daemon = Daemon::start(&divid_args(dir.path(), rpc_port), &[], rpc_port, true);
    let before = daemon.rpc("dumphdinfo", json!([]));
    drop(daemon);
    std::fs::write(
        dir.path().join("divi.conf"),
        format!("regtest=1\nmnemonicpassphrase={PASSPHRASE}\n"),
    )
    .unwrap();
    let rpc_port = free_port();
    let daemon = Daemon::start(&divid_args(dir.path(), rpc_port), &[], rpc_port, true);
    assert_eq!(daemon.rpc("dumphdinfo", json!([])), before);
    assert_eq!(before["mnemonicpassphrase"], "");
    drop(daemon);

    // Over 256 characters: no wallet is made and the node does not start
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("divi.conf"),
        format!("regtest=1\nmnemonicpassphrase={}\n", "p".repeat(257)),
    )
    .unwrap();
    let out = output_within(
        Command::new(env!("CARGO_BIN_EXE_irondivid")).args(divid_args(dir.path(), free_port())),
    );
    assert!(!out.status.success());
    let log = std::fs::read_to_string(dir.path().join("debug.log")).unwrap_or_default()
        + &String::from_utf8_lossy(&out.stderr)
        + &String::from_utf8_lossy(&out.stdout);
    assert!(
        log.contains("Mnemonic passphrase is too long, must be at most 256 characters"),
        "{log}"
    );
    assert!(
        !dir.path().join("wallet").exists() && !dir.path().join("regtest").join("wallet").exists()
    );
}

/// Without -daemon divid writes divid.pid too (init.cpp:1470) and removes it
/// at a clean stop and after a failed start (init.cpp:396)
#[test]
fn pid_file_is_written_without_daemon_and_removed_at_the_end() {
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port();
    let pid_file = dir.path().join("divid.pid");
    let daemon = Daemon::start(
        &divid_args(dir.path(), rpc_port),
        &[("WALLET_MNEMONIC", MNEMONIC)],
        rpc_port,
        true,
    );
    let written = std::fs::read_to_string(&pid_file).unwrap_or_default();
    assert_eq!(written.trim(), daemon.child.id().to_string(), "divid.pid");
    daemon.rpc("stop", json!([]));
    assert!(
        eventually(|| !pid_file.exists()),
        "divid.pid left after a clean stop"
    );
    drop(daemon);

    // A start that fails after the pid file is written: the chain database
    // belongs to regtest, the node is started for testnet
    let mut args = divid_args(dir.path(), free_port());
    args[0] = "-testnet".into();
    let out = output_within(Command::new(env!("CARGO_BIN_EXE_irondivid")).args(&args));
    assert!(!out.status.success());
    assert!(!pid_file.exists(), "divid.pid left after a failed start");
}
