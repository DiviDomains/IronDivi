// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Wallet options divid reads, and irondivid with them: -createwalletbackups,
//! -monthlybackups, -vault_min, and -txconfirmtarget / -sendfreetransactions
//! (which divid takes and does nothing with).

#![cfg(unix)]

use divi_test_support::{free_port, log_tail, start_on};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// POST one JSON-RPC call; None while the server is not up
fn try_rpc(port: u16, method: &str, params: &Value, timeout: Duration) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
    // "dGVzdDp0ZXN0" is base64 of test:test
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

fn ok(port: u16, method: &str, params: Value) -> Value {
    let reply = try_rpc(port, method, &params, Duration::from_secs(120))
        .unwrap_or_else(|| panic!("{method}: no reply"));
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(datadir: &Path, rpc_port: &mut u16, p2p_port: &mut u16, extra: &[&str]) -> Node {
    Node(start_on(
        datadir,
        rpc_port,
        p2p_port,
        |rpc_port, p2p_port| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
            cmd.arg("--regtest")
                .arg("--datadir")
                .arg(datadir)
                .args(["--rpcport", &rpc_port.to_string()])
                .args(["--port", &p2p_port.to_string()])
                .args(["--bind", "127.0.0.1", "--staking=false", "--listen=false"])
                .args(["--rpcuser", "test", "--rpcpassword", "test"])
                .args(extra)
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd
        },
        |rpc_port| {
            try_rpc(
                rpc_port,
                "getblockcount",
                &json!([]),
                Duration::from_secs(10),
            )
            .is_some()
        },
    ))
}

/// Stop the node with the RPC stop and wait (bounded) until it exits
fn stop(mut node: Node, rpc_port: u16) {
    let _ = try_rpc(rpc_port, "stop", &json!([]), Duration::from_secs(30));
    let deadline = Instant::now() + Duration::from_secs(60);
    while node.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The folder named `name` somewhere under `root`
fn find_dir(root: &Path, name: &str) -> Option<PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == name) {
                    return Some(path);
                }
                dirs.push(path);
            }
        }
    }
    None
}

fn entries(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

/// -createwalletbackups=<n>: the backup at start keeps n in backups/
/// (init.cpp:938, WalletBackupCreator.cpp:85-121); 0 makes none and removes
/// none
#[test]
fn createwalletbackups_sets_the_count_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc_port, mut p2p_port) = (free_port(), free_port());
    // A start that makes the wallet, then three that back it up
    stop(
        start(dir.path(), &mut rpc_port, &mut p2p_port, &[]),
        rpc_port,
    );
    for i in 0..3 {
        stop(
            start(
                dir.path(),
                &mut rpc_port,
                &mut p2p_port,
                &["-createwalletbackups=2"],
            ),
            rpc_port,
        );
        // A backup is named by the minute and not made again under a name
        // already there, so the new one is renamed to leave the next start
        // its name
        let backups = find_dir(dir.path(), "backups").expect("backups/");
        for entry in std::fs::read_dir(&backups).unwrap().flatten() {
            let path = entry.path();
            if !path.to_string_lossy().ends_with("-kept") {
                let mut renamed = path.clone().into_os_string();
                renamed.push(format!("-{i}-kept"));
                std::fs::rename(&path, renamed).unwrap();
            }
        }
    }
    let backups = find_dir(dir.path(), "backups").expect("backups/");
    assert_eq!(entries(&backups), 2, "two kept");
    stop(
        start(
            dir.path(),
            &mut rpc_port,
            &mut p2p_port,
            &["-createwalletbackups=0"],
        ),
        rpc_port,
    );
    assert_eq!(entries(&backups), 2, "none made, none removed");
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// -monthlybackups=<n>: a day after start (on mock time on regtest) the node
/// makes a monthly backup when the newest is a month old, n kept
/// (init.cpp:1284, LegacyWalletDatabaseEndpointFactory.cpp:75-121); 0 makes
/// none
#[test]
fn monthlybackups_sets_the_count_and_zero_leaves_it_off() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc_port, mut p2p_port) = (free_port(), free_port());
    stop(
        start(dir.path(), &mut rpc_port, &mut p2p_port, &[]),
        rpc_port,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let later = now + 31 * 24 * 3600;
    // The time suffix of the backup made at start
    let suffix = {
        let n = start(
            dir.path(),
            &mut rpc_port,
            &mut p2p_port,
            &["-monthlybackups=0"],
        );
        let monthly = find_dir(dir.path(), "monthlyBackups").expect("monthlyBackups/");
        let before = names(&monthly);
        assert_eq!(before.len(), 1, "the backup at start: {before:?}");
        ok(rpc_port, "setmocktime", json!([later]));
        std::thread::sleep(Duration::from_secs(4));
        assert_eq!(names(&monthly), before, "0: no monthly backup");
        stop(n, rpc_port);
        before[0].rsplit_once('.').unwrap().1.to_string()
    };
    let n = start(
        dir.path(),
        &mut rpc_port,
        &mut p2p_port,
        &["-monthlybackups=1"],
    );
    let monthly = find_dir(dir.path(), "monthlyBackups").expect("monthlyBackups/");
    ok(rpc_port, "setmocktime", json!([later]));
    let deadline = Instant::now() + Duration::from_secs(30);
    while names(&monthly).iter().any(|n| n.ends_with(&suffix)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    let after = names(&monthly);
    stop(n, rpc_port);
    assert_eq!(after.len(), 1, "one kept: {after:?}");
    assert!(
        !after[0].ends_with(&suffix),
        "made on the mock date: {after:?}"
    );
}

/// -txconfirmtarget and -sendfreetransactions are in divid's help only
/// (LicenseAndInfo.cpp:135, :143): it takes them without a word, and so does
/// irondivid
#[test]
fn txconfirmtarget_and_sendfreetransactions_are_taken_silently() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc_port, mut p2p_port) = (free_port(), free_port());
    let n = start(
        dir.path(),
        &mut rpc_port,
        &mut p2p_port,
        &["-txconfirmtarget=25", "-sendfreetransactions=1"],
    );
    stop(n, rpc_port);
    let log = std::fs::read_to_string(dir.path().join("regtest").join("debug.log"))
        .or_else(|_| std::fs::read_to_string(dir.path().join("debug.log")))
        .unwrap_or_default();
    assert!(!log.is_empty(), "debug.log written");
    for option in ["txconfirmtarget", "sendfreetransactions"] {
        let warned = log
            .lines()
            .find(|l| l.contains(&format!("-{option} ")) || l.contains(&format!("-{option};")));
        assert!(
            warned.is_none(),
            "{option}: {warned:?}\n{}",
            log_tail(dir.path())
        );
    }
}

/// What getcoinavailability counts stakable beyond the plain coins: the
/// managed vault coins
fn stakable_vault_coins(port: u16) -> i64 {
    let coins = ok(port, "getcoinavailability", json!([]));
    let divi = |v: &Value| (v.as_f64().unwrap() * 1e8).round() as i64;
    (divi(&coins["Stakable"]) - divi(&coins["Spendable"])) / 100_000_000
}

/// -vault_min=<n>: managed vault coins below n DIVI are not stakable
/// (AvailableUtxoCollector.cpp:22, AvailableUtxoCalculator.cpp:22-27)
#[test]
fn vault_min_leaves_smaller_vault_coins_out_of_staking() {
    // An owner key the managing wallet does not hold
    let other = tempfile::tempdir().unwrap();
    let (mut rpc_port, mut p2p_port) = (free_port(), free_port());
    let n = start(other.path(), &mut rpc_port, &mut p2p_port, &[]);
    let owner = ok(rpc_port, "getnewaddress", json!([]));
    stop(n, rpc_port);

    let dir = tempfile::tempdir().unwrap();
    let n = start(dir.path(), &mut rpc_port, &mut p2p_port, &[]);
    ok(rpc_port, "setgenerate", json!([100]));
    let manager = ok(rpc_port, "getnewaddress", json!([]));
    let vault = format!("{}:{}", owner.as_str().unwrap(), manager.as_str().unwrap());
    ok(rpc_port, "fundvault", json!([vault, 100]));
    ok(rpc_port, "fundvault", json!([vault, 1000]));
    ok(rpc_port, "setgenerate", json!([1]));
    assert_eq!(stakable_vault_coins(rpc_port), 1100, "both by default");
    stop(n, rpc_port);

    let n = start(
        dir.path(),
        &mut rpc_port,
        &mut p2p_port,
        &["-vault_min=500"],
    );
    assert_eq!(stakable_vault_coins(rpc_port), 1000, "the 100 left out");
    stop(n, rpc_port);
}

/// A 2-key staking vault script: OP_IF <owner> OP_ELSE OP_REQUIRE_COINSTAKE
/// <manager> OP_ENDIF OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG
fn vault_hex(owner: &[u8], manager: &[u8]) -> String {
    let mut script = vec![0x63, 0x14];
    script.extend_from_slice(owner);
    script.extend_from_slice(&[0x67, 0xb9, 0x14]);
    script.extend_from_slice(manager);
    script.extend_from_slice(&[0x68, 0x78, 0xa9, 0x88, 0xac]);
    hex::encode(script)
}

/// -whitelisted_vault registers, at each load, a vault the wallet holds the
/// manager key of and not the owner key; an owned vault, a script that is no
/// vault and text that is not hex are left out. The registration stays in
/// the wallet, so a later start without the option still has it
/// (init.cpp:1182-1201, wallet.cpp:1992-2003, wallet_ismine.cpp:80-91)
#[test]
fn whitelisted_vaults_are_registered_as_divid_registers_them() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc, mut p2p) = (free_port(), free_port());
    let node = start(dir.path(), &mut rpc, &mut p2p, &[]);
    let key_hash = |n: &Value| {
        let a: divi_wallet::Address = n.as_str().unwrap().parse().unwrap();
        a.hash.as_bytes().to_vec()
    };
    let manager = key_hash(&ok(rpc, "getnewaddress", json!([])));
    let owner = key_hash(&ok(rpc, "getnewaddress", json!([])));
    let registered = |rpc: u16| {
        let reply = ok(rpc, "getcoinavailability", json!([]));
        reply["vaults"].as_array().unwrap().len()
    };
    assert_eq!(registered(rpc), 0);
    stop(node, rpc);

    let managed = format!("-whitelisted_vault={}", vault_hex(&[0x42; 20], &manager));
    let owned = format!("-whitelisted_vault={}", vault_hex(&owner, &[0x43; 20]));
    let p2pkh = format!("-whitelisted_vault=76a914{}88ac", hex::encode(&manager));
    let node = start(
        dir.path(),
        &mut rpc,
        &mut p2p,
        &[&managed, &owned, &p2pkh, "-whitelisted_vault=nothex"],
    );
    assert_eq!(registered(rpc), 1);
    stop(node, rpc);

    let node = start(dir.path(), &mut rpc, &mut p2p, &[]);
    assert_eq!(registered(rpc), 1);
    stop(node, rpc);
}

/// -hdseed is logged with divid's texts: a hex seed with -mnemonic is
/// preferred, logged at every start, a wallet there or not (init.cpp:945-951);
/// a seed that is not hex is logged when a new wallet is made
/// (wallet.cpp:2295-2297)
#[test]
fn hdseed_is_logged_as_divid_logs_it() {
    const PREFER: &str = "parameter interaction: can't use -hdseed and -mnemonic/-mnemonicpassphrase together, will prefer -seed";
    const INCORRECT: &str = "Incorrect seed, generating random one instead";
    let log = |dir: &Path| std::fs::read_to_string(dir.join("debug.log")).unwrap_or_default();
    let seed = format!("-hdseed={}", "5a".repeat(32));
    let words = "-mnemonic=these words are dropped unread";
    let (mut rpc, mut p2p) = (free_port(), free_port());

    let dir = tempfile::tempdir().unwrap();
    stop(start(dir.path(), &mut rpc, &mut p2p, &[&seed, words]), rpc);
    assert!(log(dir.path()).contains(PREFER), "{}", log(dir.path()));
    assert!(!log(dir.path()).contains(INCORRECT), "{}", log(dir.path()));
    // A wallet already there: logged all the same
    std::fs::remove_file(dir.path().join("debug.log")).unwrap();
    stop(start(dir.path(), &mut rpc, &mut p2p, &[&seed, words]), rpc);
    assert!(log(dir.path()).contains(PREFER), "{}", log(dir.path()));

    let dir = tempfile::tempdir().unwrap();
    stop(
        start(dir.path(), &mut rpc, &mut p2p, &["-hdseed=nothex"]),
        rpc,
    );
    assert!(log(dir.path()).contains(INCORRECT), "{}", log(dir.path()));
    assert!(!log(dir.path()).contains(PREFER), "{}", log(dir.path()));
}

/// -prunewalletconfs leaves out of memory, at the start, a wallet transaction
/// whose coins of ours are all spent by a transaction at least max(N, 20)
/// blocks deep and none of whose inputs comes from one kept, and logs the
/// counts; the wallet file keeps it, so a start without the option lists it
/// again (wallet.cpp:900-920, :1162-1240; init.cpp:1574-1577)
#[test]
fn prunewalletconfs_leaves_deeply_spent_transactions_out() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc, mut p2p) = (free_port(), free_port());
    let node = start(dir.path(), &mut rpc, &mut p2p, &[]);
    ok(rpc, "setgenerate", json!([30]));
    // The coinbase of block 1, swept alone to an address not ours
    let hash = ok(rpc, "getblockhash", json!([1]));
    let coinbase = ok(rpc, "getblock", json!([hash]))["tx"][0].clone();
    let others: Vec<Value> = ok(rpc, "listunspent", json!([0]))
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["txid"] != coinbase)
        .map(|u| json!({"txid": u["txid"], "vout": u["vout"]}))
        .collect();
    ok(rpc, "lockunspent", json!([false, others]));
    let elsewhere = divi_wallet::Address::from_pubkey_hash(
        divi_primitives::hash::Hash160::from_bytes([0x42; 20]),
        divi_wallet::Network::Regtest,
    );
    let sweep = ok(
        rpc,
        "sendtoaddress",
        json!([elsewhere.to_string(), 1, "sweep_funds"]),
    );
    ok(rpc, "setgenerate", json!([25]));
    stop(node, rpc);

    let known = |txid: &Value| {
        try_rpc(
            rpc,
            "gettransaction",
            &json!([txid]),
            Duration::from_secs(60),
        )
        .unwrap()["error"]
            .is_null()
    };
    let log = || std::fs::read_to_string(dir.path().join("debug.log")).unwrap_or_default();
    let node = start(dir.path(), &mut rpc, &mut p2p, &["-prunewalletconfs=5"]);
    assert!(!known(&coinbase), "the swept coinbase is still listed");
    assert!(!known(&sweep), "its sweep is still listed");
    let line = log()
        .lines()
        .rev()
        .find(|l| l.contains("Pruned wallet transactions loaded to memory: Original "))
        .map(str::to_string);
    assert!(line.is_some(), "{}", log());
    stop(node, rpc);

    let node = start(dir.path(), &mut rpc, &mut p2p, &[]);
    assert!(
        known(&coinbase) && known(&sweep),
        "a start without the option lists them again"
    );
    stop(node, rpc);
}

/// Whether `text` is in the node's debug.log within 10 seconds (the log is
/// written behind the calls)
fn logged(dir: &Path, text: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let log = std::fs::read_to_string(dir.join("debug.log")).unwrap_or_default();
        if log.contains(text) {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// At the end of the start the log has divid's "Key Pool size = <n>" and
/// "Address Book size = <n>" (init.cpp:1613-1618)
#[test]
fn the_start_logs_the_key_pool_and_address_book_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc, mut p2p) = (free_port(), free_port());
    let node = start(dir.path(), &mut rpc, &mut p2p, &[]);
    let pool = ok(rpc, "getwalletinfo", json!([]))["keypoolsize"].clone();
    assert!(logged(dir.path(), &format!("Key Pool size = {pool}")));
    assert!(logged(dir.path(), "Address Book size = "));
    stop(node, rpc);
}

/// backupwallet logs divid's "copied wallet.dat to <path>" with the path
/// written (walletdb.cpp:619)
#[test]
fn backupwallet_logs_where_it_copied_the_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc, mut p2p) = (free_port(), free_port());
    let node = start(dir.path(), &mut rpc, &mut p2p, &[]);
    let dest = dir.path().join("copy.dat");
    ok(rpc, "backupwallet", json!([dest.to_str().unwrap()]));
    assert!(logged(
        dir.path(),
        &format!("copied wallet.dat to {}", dest.display())
    ));
    stop(node, rpc);
}

/// encryptwallet and walletpassphrasechange log divid's lines with the key
/// derivation count (wallet.cpp:949, :836)
#[test]
fn encryption_logs_its_derivation_count() {
    let dir = tempfile::tempdir().unwrap();
    let (mut rpc, mut p2p) = (free_port(), free_port());
    let node = start(dir.path(), &mut rpc, &mut p2p, &[]);
    // Throwaway test passphrases, over RPC
    ok(rpc, "encryptwallet", json!(["first-throwaway"]));
    ok(rpc, "walletpassphrase", json!(["first-throwaway", 60]));
    ok(
        rpc,
        "walletpassphrasechange",
        json!(["first-throwaway", "second-throwaway"]),
    );
    assert!(logged(
        dir.path(),
        "Encrypting Wallet with an nDeriveIterations of "
    ));
    assert!(logged(
        dir.path(),
        "Wallet passphrase changed to an nDeriveIterations of "
    ));
    stop(node, rpc);
}
