// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! §10 item 5 regtest 4-node log symmetry & canary release gate (`docs/plans/diag.md`):
//!
//! Runs a test `irondivid` node (`T`) connected to 3 regtest peers (`P1`, `P2`, `P3`)
//! across all three required log configurations (`default`, `-debug=net`, `-debug`) and
//! verifies:
//! - **O1 own vs. peer PoS block symmetry**: contiguous `Connected block` heights in
//!   `debug.log`, zero removed pre-A11 staker/wallet per-block lines, identical between-block
//!   log shapes around own staked PoS blocks, wallet-paying/spending peer blocks, and
//!   unrelated peer blocks, and weekly bucketing of `Connected block` in `divi-diag` packages.
//! - **Sync-state release gate**: zero steady-state sync-state lines (`Block sync complete`,
//!   `Header sync complete`, `Exiting IBD mode`, `Sync progress`, `Sync stalled`) across
//!   steady-state own and peer PoS block advances.
//! - **R14-1 own vs. peer transaction relay symmetry**: `sendtoaddress`, `sendmany`,
//!   `sendrawtransaction`, unconfirmed wallet tx resubmit on restart, and peer-originated
//!   transactions relayed through `T` emit identical normalized log format sequences (zero
//!   per-tx relay/mempool lines naming txids or splitting counts by origin, and `ThreadRPCServer`
//!   method names masked by rule (b) in packaged logs).
//! - **A10 `getdiaginfo`, A12 `SIGUSR1` incident & §6.3 `divi-diag` package scan**: live
//!   `getdiaginfo` (`diag_key` HMACs + `known_values` pages), `SIGUSR1` incident generation
//!   within the 4096-line ring window of an own staked PoS block, live `divi_diag::run`
//!   packaging with exit code `0` and zero excluded files, and zero canary leaks across all
//!   raw and packaged files.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("diag") {
        std::process::exit(divi_diag::run(&args[2..]));
    }
    if args.iter().any(|a| a == "--list") {
        println!("regtest_4_node_tx_and_block_log_symmetry_canary: test");
        println!("\n1 test, 0 benchmarks");
        return;
    }
    if args.iter().any(|a| a == "--ignored") {
        println!("\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored\n");
        return;
    }
    #[cfg(unix)]
    unix::run_all();
}

#[cfg(unix)]
mod unix {
    use divi_test_support::{free_port, start_on};
    use serde_json::{json, Value};
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const LABEL_A: &str = "CANARY-LABEL-7f3e";
    const LABEL_B: &str = "CANARY-LABEL-8b2c";
    const NOTIFY_TAG: &str = "CANARY-NOTIFY-5c1d";
    const TEST_RPC_USER: &str = "testuser";
    const TEST_RPC_PASS: &str = "CANARY-RPCPASS-9a4e";
    const PEER_RPC_USER: &str = "peeruser";
    const PEER_RPC_PASS: &str = "peerpass";

    fn basic_auth(user: &str, pass: &str) -> String {
        divi_diag::scanner::base64(format!("{user}:{pass}").as_bytes())
    }

    fn try_rpc(
        port: u16,
        user: &str,
        pass: &str,
        method: &str,
        params: &Value,
        timeout: Duration,
    ) -> Option<Value> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        let body =
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let auth = basic_auth(user, pass);
        let req = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Basic {auth}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(req.as_bytes()).ok()?;
        let mut resp = String::new();
        stream.read_to_string(&mut resp).ok()?;
        let (_, payload) = resp.split_once("\r\n\r\n")?;
        serde_json::from_str(payload).ok()
    }

    struct Node {
        child: Child,
        rpc_port: u16,
        p2p_port: u16,
        user: String,
        pass: String,
    }

    impl Node {
        #[allow(clippy::too_many_arguments)]
        fn start(
            datadir: &Path,
            home_dir: &Path,
            state_dir: &Path,
            rpc_port: &mut u16,
            p2p_port: &mut u16,
            user: &str,
            pass: &str,
            extra: &[String],
        ) -> Self {
            let u = user.to_string();
            let p = pass.to_string();
            let u_ready = u.clone();
            let p_ready = p.clone();
            let child = start_on(
                datadir,
                rpc_port,
                p2p_port,
                |rport, pport| {
                    let conf_content = format!(
                        "regtest=1\nrpcuser={u}\nrpcpassword={p}\nrpcport={rport}\nport={pport}\n"
                    );
                    let _ = std::fs::write(datadir.join("irondivi.conf"), conf_content);
                    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irondivid"));
                    cmd.env_remove("RUST_LOG")
                        .env("HOME", home_dir)
                        .env("XDG_STATE_HOME", state_dir)
                        .arg("-regtest")
                        .arg(format!("-datadir={}", datadir.display()))
                        .arg(format!("-rpcport={rport}"))
                        .arg(format!("-port={pport}"))
                        .arg("-bind=127.0.0.1")
                        .arg(format!("-rpcuser={u}"))
                        .arg(format!("-rpcpassword={p}"))
                        .arg("-staking=0")
                        .args(extra)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    cmd
                },
                |rport| {
                    try_rpc(
                        rport,
                        &u_ready,
                        &p_ready,
                        "getblockcount",
                        &json!([]),
                        Duration::from_secs(10),
                    )
                    .is_some()
                },
            );
            Node {
                child,
                rpc_port: *rpc_port,
                p2p_port: *p2p_port,
                user: u,
                pass: p,
            }
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }

        fn rpc(&self, method: &str, params: Value) -> Value {
            try_rpc(
                self.rpc_port,
                &self.user,
                &self.pass,
                method,
                &params,
                Duration::from_secs(120),
            )
            .unwrap_or_else(|| panic!("{method} on port {}: no reply", self.rpc_port))
        }

        fn ok(&self, method: &str, params: Value) -> Value {
            let reply = self.rpc(method, params);
            assert!(reply["error"].is_null(), "{method} failed: {reply}");
            reply["result"].clone()
        }

        fn stop(mut self) {
            let _ = try_rpc(
                self.rpc_port,
                &self.user,
                &self.pass,
                "stop",
                &json!([]),
                Duration::from_secs(30),
            );
            let deadline = Instant::now() + Duration::from_secs(60);
            while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for Node {
        fn drop(&mut self) {
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.child.try_wait().unwrap().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    fn wait_height(nodes: &[&Node], height: u64, label: &str) {
        wait_until(label, 90, || {
            nodes
                .iter()
                .all(|n| n.ok("getblockcount", json!([])).as_u64() == Some(height))
        });
    }

    fn wait_mempool(nodes: &[&Node], txid: &str, label: &str) {
        let want = Value::String(txid.to_string());
        wait_until(label, 60, || {
            nodes.iter().all(|n| {
                n.ok("getrawmempool", json!([]))
                    .as_array()
                    .is_some_and(|a| a.contains(&want))
            })
        });
    }

    fn both_orders(hex: &str) -> [String; 2] {
        let bytes: Vec<&str> = (0..hex.len()).step_by(2).map(|i| &hex[i..i + 2]).collect();
        [hex.to_string(), bytes.into_iter().rev().collect()]
    }

    fn read_debug_log(datadir: &Path) -> String {
        for cand in [datadir.join("regtest/debug.log"), datadir.join("debug.log")] {
            if let Ok(b) = std::fs::read(&cand) {
                return String::from_utf8_lossy(&b).into_owned();
            }
        }
        String::new()
    }

    /// Collect all non-RocksDB text files written under `dir`.
    fn text_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            if d.join("CURRENT").is_file() {
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                if name == "irondivi.conf" || name == ".cookie" || name == ".lock" {
                    continue;
                }
                let in_diag = p
                    .strip_prefix(dir)
                    .ok()
                    .is_some_and(|r| r.components().any(|c| c.as_os_str() == "diag"));
                if in_diag
                    || name.contains(".log")
                    || name.ends_with(".txt")
                    || name.ends_with(".tail")
                    || name.ends_with(".json")
                {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }

    /// Collect all regular files inside a `divi-diag` output package.
    fn pkg_files(pkg: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![pkg.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }

    /// Strip Divi Core `YYYY-MM-DD HH:MM:SS ` or RFC3339 `YYYY-MM-DDTHH:MM:SS...Z ` prefix
    /// and normalize numbers/hex so format shapes can be compared across own and peer txs.
    fn strip_ts(line: &str) -> &str {
        let b = line.as_bytes();
        if b.len() > 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b' '
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b' '
        {
            &line[20..]
        } else if b.len() > 20 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' {
            line.split_once(' ').map_or(line, |(_, rest)| rest)
        } else {
            line
        }
    }

    fn normalize_format(line: &str) -> String {
        let msg = strip_ts(line).trim();
        let mut tokens = Vec::new();
        for tok in msg.split_whitespace() {
            let clean = tok.trim_matches(|c: char| ",:;()[]{}".contains(c));
            if clean.len() == 64 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
                tokens.push("<HASH64>".to_string());
            } else if !clean.is_empty()
                && clean
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
                && clean.chars().any(|c| c.is_ascii_digit())
            {
                tokens.push("<N>".to_string());
            } else if let Some((k, _)) = clean.split_once('=') {
                tokens.push(format!("{k}=<V>"));
            } else {
                tokens.push(tok.to_string());
            }
        }
        tokens.join(" ")
    }

    /// Filter out background RPC/periodic noise (`ThreadRPCServer`, hourly `[counted]`,
    /// the test's own intentional `-walletnotify=false` / `-blocknotify=false` R12-2 hooks,
    /// P2P ping/pong, and the named own-only Divi Core `wallet.rs`/`keystore.rs` commit lines
    /// per `docs/plans/diag.md` §10 item 5 R14-1, which are separately verified to be removed
    /// and weekly-counted in the `divi-diag` package and never linked to relay/mempool lines)
    /// when comparing tx relay/mempool windows.
    fn is_own_wallet_commit_line(m: &str) -> bool {
        m.starts_with("CommitTransaction:")
            || m.starts_with("CTransaction(")
            || m.starts_with("CTxIn(")
            || m.starts_with("CTxOut(")
            || m.starts_with("keypool ")
            || m.contains(": Relaying wtx ")
            || m.starts_with("SendMoney -> CommitTransaction()")
            || m.starts_with("Generated new change address:")
    }

    fn tx_relevant_formats(lines: &[&str]) -> Vec<String> {
        lines
            .iter()
            .map(|l| strip_ts(l).trim())
            .filter(|m| {
                !m.is_empty()
                    && !m.starts_with("ThreadRPCServer ")
                    && !m.starts_with("RPC request: ")
                    && !m.starts_with("Received P2P message from peer ")
                    && !m.starts_with("[counted]")
                    && !m.contains("runCommand error: walletnotify (")
                    && !m.contains("runCommand error: blocknotify (")
                    && !is_own_wallet_commit_line(m)
                    && !m.starts_with("Not dialling ")
                    && !m.starts_with("Added time data")
                    && !m.ends_with(": getaddr")
                    && !m.ends_with(": addr")
                    && !m.contains("ping")
                    && !m.contains("pong")
            })
            .map(normalize_format)
            .collect()
    }

    fn connected_height(line: &str) -> Option<(u64, String)> {
        let msg = strip_ts(line).trim();
        let rest = msg.strip_prefix("Connected block ")?;
        let (hash, h_str) = rest.split_once(" at height ")?;
        let height: u64 = h_str.trim().parse().ok()?;
        Some((height, hash.trim().to_string()))
    }

    fn run_for_config(config_label: &str, log_flags: &[&str]) {
        eprintln!("=== §10 canary configuration: {config_label} ({log_flags:?}) ===");
        let root = tempfile::tempdir().expect("tempdir");
        let home_dir = root.path().join("home");
        let state_dir = root.path().join("state");
        let dir_t = root.path().join("node_t");
        let dir_p1 = root.path().join("peer_1");
        let dir_p2 = root.path().join("peer_2");
        let dir_p3 = root.path().join("peer_3");
        for d in [&home_dir, &state_dir, &dir_t, &dir_p1, &dir_p2, &dir_p3] {
            std::fs::create_dir_all(d).unwrap();
        }

        let (mut rpc_p1, mut p2p_p1) = (free_port(), free_port());
        let (mut rpc_p2, mut p2p_p2) = (free_port(), free_port());
        let (mut rpc_p3, mut p2p_p3) = (free_port(), free_port());
        let (mut rpc_t, mut p2p_t) = (free_port(), free_port());

        let peer_extra = vec!["-listen=1".to_string()];
        let p1 = Node::start(
            &dir_p1,
            &home_dir,
            &state_dir,
            &mut rpc_p1,
            &mut p2p_p1,
            PEER_RPC_USER,
            PEER_RPC_PASS,
            &peer_extra,
        );
        let p2 = Node::start(
            &dir_p2,
            &home_dir,
            &state_dir,
            &mut rpc_p2,
            &mut p2p_p2,
            PEER_RPC_USER,
            PEER_RPC_PASS,
            &peer_extra,
        );
        let p3 = Node::start(
            &dir_p3,
            &home_dir,
            &state_dir,
            &mut rpc_p3,
            &mut p2p_p3,
            PEER_RPC_USER,
            PEER_RPC_PASS,
            &peer_extra,
        );

        let mut t_extra = vec![
            "-listen=1".to_string(),
            format!("-connect=127.0.0.1:{}", p1.p2p_port),
            format!("-connect=127.0.0.1:{}", p2.p2p_port),
            format!("-connect=127.0.0.1:{}", p3.p2p_port),
            format!("-walletnotify=false {NOTIFY_TAG}-w-%s"),
            format!("-blocknotify=false {NOTIFY_TAG}-b-%s"),
        ];
        for &f in log_flags {
            t_extra.push(f.to_string());
        }

        let t = Node::start(
            &dir_t,
            &home_dir,
            &state_dir,
            &mut rpc_t,
            &mut p2p_t,
            TEST_RPC_USER,
            TEST_RPC_PASS,
            &t_extra,
        );

        wait_until("T connected to all 3 peers", 60, || {
            t.ok("getconnectioncount", json!([])).as_u64() == Some(3)
                && p1.ok("getconnectioncount", json!([])).as_u64() >= Some(1)
                && p2.ok("getconnectioncount", json!([])).as_u64() >= Some(1)
                && p3.ok("getconnectioncount", json!([])).as_u64() >= Some(1)
        });

        let addr_t_a = t
            .ok("getnewaddress", json!([LABEL_A]))
            .as_str()
            .unwrap()
            .to_string();
        let addr_t_b = t
            .ok("getnewaddress", json!([LABEL_B]))
            .as_str()
            .unwrap()
            .to_string();
        let addr_p1 = p1
            .ok("getnewaddress", json!([]))
            .as_str()
            .unwrap()
            .to_string();
        let addr_p2 = p2
            .ok("getnewaddress", json!([]))
            .as_str()
            .unwrap()
            .to_string();
        let addr_p3 = p3
            .ok("getnewaddress", json!([]))
            .as_str()
            .unwrap()
            .to_string();

        // Initial PoW setup (heights 1..=100) + first PoS transition block (height 101)
        // so T, P1, and P2 all hold matured UTXOs (coinbase_maturity = 20 on regtest).
        t.ok("setgenerate", json!([35]));
        wait_height(&[&t, &p1, &p2, &p3], 35, "height 35");
        p1.ok("setgenerate", json!([35]));
        wait_height(&[&t, &p1, &p2, &p3], 70, "height 70");
        p2.ok("setgenerate", json!([30]));
        wait_height(&[&t, &p1, &p2, &p3], 100, "height 100 (LAST_POW_BLOCK)");
        p1.ok("setgenerate", json!([1]));
        wait_height(&[&t, &p1, &p2, &p3], 101, "height 101 (steady-state PoS)");

        // ------------------------------------------------------------------
        // Phase A: R14-1 Own vs. Peer Transaction Relay Symmetry
        // ------------------------------------------------------------------
        let mark_lines = || read_debug_log(&dir_t).lines().count();
        let slice_since = |start: usize| -> Vec<String> {
            read_debug_log(&dir_t)
                .lines()
                .skip(start)
                .map(String::from)
                .collect()
        };

        // 1. Unrelated peer tx (P1 -> P2, relayed by T to P2 & P3)
        let l0 = mark_lines();
        let tx_peer_unrelated = p1
            .ok("sendtoaddress", json!([addr_p2, 2.34567891]))
            .as_str()
            .unwrap()
            .to_string();
        wait_mempool(
            &[&t, &p1, &p2, &p3],
            &tx_peer_unrelated,
            "tx_peer_unrelated",
        );
        let win_peer_unrelated = slice_since(l0);

        // 2. Peer tx paying T (P2 -> T, relayed by T to P1 & P3)
        let l0 = mark_lines();
        let tx_peer_to_t = p2
            .ok("sendtoaddress", json!([addr_t_a, 3.45678912]))
            .as_str()
            .unwrap()
            .to_string();
        wait_mempool(&[&t, &p1, &p2, &p3], &tx_peer_to_t, "tx_peer_to_t");
        let win_peer_to_t = slice_since(l0);

        // 3. Own sendtoaddress (T -> P3, broadcast to P1, P2, P3)
        let l0 = mark_lines();
        let tx_own_sendto = t
            .ok("sendtoaddress", json!([addr_p3, 1.23456789]))
            .as_str()
            .unwrap()
            .to_string();
        wait_mempool(&[&t, &p1, &p2, &p3], &tx_own_sendto, "tx_own_sendto");
        let win_own_sendto = slice_since(l0);

        // 4. Own sendmany (T -> {P1, P2}, broadcast to P1, P2, P3)
        let l0 = mark_lines();
        let mut many_obj = serde_json::Map::new();
        many_obj.insert(addr_p1.clone(), json!(1.11111111));
        many_obj.insert(addr_p2.clone(), json!(1.22222222));
        let tx_own_sendmany = t
            .ok("sendmany", json!(["", Value::Object(many_obj)]))
            .as_str()
            .unwrap()
            .to_string();
        wait_mempool(&[&t, &p1, &p2, &p3], &tx_own_sendmany, "tx_own_sendmany");
        let win_own_sendmany = slice_since(l0);

        // 5. Own sendrawtransaction (T builds, signs, submits raw tx)
        let unspent = t.ok("listunspent", json!([25, 9999999]));
        let utxo = unspent
            .as_array()
            .unwrap()
            .iter()
            .find(|u| {
                u["spendable"].as_bool() == Some(true) && u["amount"].as_f64().unwrap_or(0.0) > 5.0
            })
            .expect("mature spendable UTXO on T");
        let utxo_txid = utxo["txid"].as_str().unwrap().to_string();
        let utxo_vout = utxo["vout"].as_u64().unwrap();
        let utxo_amt = utxo["amount"].as_f64().unwrap();
        let change_addr = t
            .ok("getnewaddress", json!([]))
            .as_str()
            .unwrap()
            .to_string();
        let send_amt = 1.33333333;
        let fee = 0.01;
        let change_amt = ((utxo_amt - send_amt - fee) * 1e8).round() / 1e8;
        let mut raw_outs = serde_json::Map::new();
        raw_outs.insert(addr_p3.clone(), json!(send_amt));
        raw_outs.insert(change_addr.clone(), json!(change_amt));
        let raw_unsigned = t
            .ok(
                "createrawtransaction",
                json!([[{"txid": utxo_txid, "vout": utxo_vout}], Value::Object(raw_outs)]),
            )
            .as_str()
            .unwrap()
            .to_string();
        let signed = t.ok("signrawtransaction", json!([raw_unsigned]));
        assert_eq!(signed["complete"].as_bool(), Some(true), "{signed}");
        let signed_hex = signed["hex"].as_str().unwrap().to_string();

        let l0 = mark_lines();
        let tx_own_raw = t
            .ok("sendrawtransaction", json!([signed_hex]))
            .as_str()
            .unwrap()
            .to_string();
        wait_mempool(&[&t, &p1, &p2, &p3], &tx_own_raw, "tx_own_raw");
        let win_own_raw = slice_since(l0);

        // Trigger an RPC error naming T's canary address (verifies A15 error masking)
        let err_reply = t.rpc("sendtoaddress", json!([addr_t_a, 90_000_000_000.0]));
        assert!(!err_reply["error"].is_null(), "{err_reply}");

        // Confirm Phase A mempool transactions in height 102
        p1.ok("setgenerate", json!([1]));
        wait_height(&[&t, &p1, &p2, &p3], 102, "height 102");

        // ------------------------------------------------------------------
        // Phase B: O1 Own vs. Peer PoS Block Symmetry & Sync-State Gate
        // ------------------------------------------------------------------
        let steady_block_log_start = mark_lines();

        // Height 103: unrelated peer PoS block #1
        p1.ok("setgenerate", json!([1]));
        wait_height(&[&t, &p1, &p2, &p3], 103, "height 103 (unrelated peer #1)");

        // Height 104: peer PoS block paying T
        let tx_pay_104 = p2
            .ok("sendtoaddress", json!([addr_t_b, 4.56789123]))
            .as_str()
            .unwrap()
            .to_string();
        wait_mempool(&[&t, &p1, &p2, &p3], &tx_pay_104, "tx_pay_104");
        p2.ok("setgenerate", json!([1]));
        wait_height(&[&t, &p1, &p2, &p3], 104, "height 104 (peer paying T)");

        // Height 105: unrelated peer PoS block #2
        p1.ok("setgenerate", json!([1]));
        wait_height(&[&t, &p1, &p2, &p3], 105, "height 105 (unrelated peer #2)");

        // Height 106: T stakes its OWN PoS block and relays it to all 3 peers!
        let own_hashes = t.ok("setgenerate", json!([1]));
        let own_block_hash = own_hashes[0].as_str().unwrap().to_string();
        wait_height(
            &[&t, &p1, &p2, &p3],
            106,
            "height 106 (own staked PoS block)",
        );
        let own_block = t.ok("getblock", json!([own_block_hash]));
        let own_coinstake_txid = own_block["tx"][1]
            .as_str()
            .expect("PoS coinstake tx")
            .to_string();

        // Take a SIGUSR1 incident on T within the 4096-line debug ring window of own stake
        unsafe { libc::kill(t.pid() as libc::pid_t, libc::SIGUSR1) };
        wait_until("SIGUSR1 incident written under diag/incidents", 30, || {
            [
                dir_t.join("diag/incidents"),
                dir_t.join("regtest/diag/incidents"),
            ]
            .iter()
            .any(|inc_dir| {
                std::fs::read_dir(inc_dir).ok().is_some_and(|rd| {
                    rd.flatten().any(|e| {
                        std::fs::read(e.path().join("getdiaginfo.json"))
                            .ok()
                            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                            .is_some()
                    })
                })
            })
        });

        // Query A10 `getdiaginfo` on T over loopback with diag_key + paginated known_values
        let diag_key_hex = "a5".repeat(32);
        let mut kv_values: BTreeSet<String> = BTreeSet::new();
        let mut page = 0u64;
        loop {
            let diag_info = t.ok(
                "getdiaginfo",
                json!([{"diag_key": diag_key_hex, "known_values": page}]),
            );
            let diag_str = diag_info.to_string();
            assert!(
                !diag_str.contains(&diag_key_hex),
                "[{config_label}] getdiaginfo leaked diag_key: {diag_str}"
            );
            if page == 0 {
                assert!(
                    diag_info["wallet"]["loaded"].as_bool() == Some(true),
                    "[{config_label}] missing wallet summary in getdiaginfo: {diag_info}"
                );
                assert!(
                    diag_info["pseudonym_map"].is_object(),
                    "[{config_label}] missing pseudonym_map in getdiaginfo: {diag_info}"
                );
            }
            for entry in diag_info["known_values"]["values"]
                .as_array()
                .expect("known_values.values array")
            {
                if let Some(v) = entry["value"].as_str() {
                    kv_values.insert(v.to_string());
                }
            }
            if diag_info["known_values"]["has_more"].as_bool() != Some(true) {
                break;
            }
            page += 1;
            assert!(
                page < 32,
                "[{config_label}] known_values pagination runaway"
            );
        }
        assert!(
            page >= 1,
            "[{config_label}] expected multi-page known_values over keypool + wallet txs"
        );
        for expected in [
            &addr_t_a,
            &addr_t_b,
            &tx_own_sendto,
            &tx_own_sendmany,
            &tx_own_raw,
            &own_coinstake_txid,
        ] {
            assert!(
                kv_values.contains(expected),
                "[{config_label}] expected {expected} in getdiaginfo known_values"
            );
        }

        // Height 107: peer PoS block spending from T
        let tx_spend_107 = t
            .ok("sendtoaddress", json!([addr_p1, 1.44444444]))
            .as_str()
            .unwrap()
            .to_string();
        wait_mempool(&[&t, &p1, &p2, &p3], &tx_spend_107, "tx_spend_107");
        p1.ok("setgenerate", json!([1]));
        wait_height(
            &[&t, &p1, &p2, &p3],
            107,
            "height 107 (peer spending from T)",
        );

        // Height 108: unrelated peer PoS block #3
        p2.ok("setgenerate", json!([1]));
        wait_height(&[&t, &p1, &p2, &p3], 108, "height 108 (unrelated peer #3)");

        // ------------------------------------------------------------------
        // Phase C: Live `divi_diag::run` Packaging & §6.3 Scanner Verification
        // ------------------------------------------------------------------
        // Stop peers cleanly so T is the sole live node discovered in this isolated environment.
        p1.stop();
        p2.stop();
        p3.stop();

        let pkg_dir = root.path().join("diag_pkg");
        let prev_home = std::env::var_os("HOME");
        let prev_xdg = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("HOME", &home_dir);
        std::env::set_var("XDG_STATE_HOME", &state_dir);
        let diag_args = vec![
            "--datadir".to_string(),
            dir_t.display().to_string(),
            "--conf".to_string(),
            dir_t.join("irondivi.conf").display().to_string(),
            "--out".to_string(),
            pkg_dir.display().to_string(),
            "--offline".to_string(),
            "--no-run".to_string(),
            "--no-submit".to_string(),
            "--no-fsync-test".to_string(),
        ];
        let diag_rc = divi_diag::run(&diag_args);
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        assert_eq!(
            diag_rc, 0,
            "[{config_label}] divi_diag::run exited with {diag_rc}"
        );

        let summary_txt =
            std::fs::read_to_string(pkg_dir.join("00-SUMMARY.txt")).expect("00-SUMMARY.txt");
        let manifest_txt =
            std::fs::read_to_string(pkg_dir.join("02-manifest.txt")).expect("02-manifest.txt");
        assert!(
            !summary_txt.contains("Left out by the final scan"),
            "[{config_label}] §6.3 scanner left out files:\n{summary_txt}"
        );
        assert!(
            !manifest_txt.contains("# left out:"),
            "[{config_label}] manifest records left-out files:\n{manifest_txt}"
        );
        let live_node_txt = std::fs::read_to_string(pkg_dir.join("datadir-1/live-node.txt"))
            .expect("datadir-1/live-node.txt");
        assert!(
            live_node_txt.contains("getdiaginfo: answered"),
            "[{config_label}] live collector did not get getdiaginfo:\n{live_node_txt}"
        );

        // ------------------------------------------------------------------
        // Phase D: Unconfirmed Wallet Tx Resubmit on Restart (`resubmit_wallet_txs`)
        // ------------------------------------------------------------------
        let tx_resubmit = t
            .ok("sendtoaddress", json!([addr_p3, 1.55555555]))
            .as_str()
            .unwrap()
            .to_string();
        t.stop();

        let restart_extra: Vec<String> = {
            let mut v = vec![
                "-listen=0".to_string(),
                format!("-walletnotify=false {NOTIFY_TAG}-w-%s"),
                format!("-blocknotify=false {NOTIFY_TAG}-b-%s"),
            ];
            for &f in log_flags {
                v.push(f.to_string());
            }
            v
        };
        let t_restarted = Node::start(
            &dir_t,
            &home_dir,
            &state_dir,
            &mut rpc_t,
            &mut p2p_t,
            TEST_RPC_USER,
            TEST_RPC_PASS,
            &restart_extra,
        );
        assert!(
            t_restarted
                .ok("getrawmempool", json!([]))
                .as_array()
                .unwrap()
                .contains(&Value::String(tx_resubmit.clone())),
            "[{config_label}] unconfirmed wallet send was not resubmitted to mempool on restart"
        );
        t_restarted.stop();

        // ------------------------------------------------------------------
        // Phase E: Symmetry, Sync-State Gate & Zero-Canary Assertions
        // ------------------------------------------------------------------
        let full_log = read_debug_log(&dir_t);
        let all_lines: Vec<&str> = full_log.lines().collect();
        let steady_lines = &all_lines[steady_block_log_start.min(all_lines.len())..];

        // E1. Contiguous Connected block heights 103..=108 in raw debug.log (at -debug,
        // where `Connected block` is emitted at debug level; at default/-debug=net ensure
        // zero own-block asymmetry lines exist).
        let connected: Vec<(usize, u64, String)> = steady_lines
            .iter()
            .enumerate()
            .filter_map(|(idx, l)| connected_height(l).map(|(h, hash)| (idx, h, hash)))
            .collect();
        if log_flags.contains(&"-debug") {
            let heights: Vec<u64> = connected.iter().map(|(_, h, _)| *h).collect();
            assert_eq!(
                heights,
                vec![103, 104, 105, 106, 107, 108],
                "[{config_label}] Connected block heights had gaps or duplicates: {connected:?}"
            );
            let idx_of = |h: u64| connected.iter().find(|x| x.1 == h).unwrap().0;
            // Between Connected(105) and Connected(107) around own block 106, verify zero
            // wallet-connect / staker-success lines distinguish own block 106 or wallet blocks
            // 104/107 from unrelated peer blocks 103/105/108.
            let around_own = &steady_lines[idx_of(105) + 1..idx_of(107)];
            for line in around_own {
                assert!(
                    !line.contains("Staked block")
                        && !line.contains("Self-accepted")
                        && !line.contains("Wallet incremental save")
                        && !(line.contains("Received ") && line.contains(" in tx ")),
                    "[{config_label}] asymmetric line around own PoS block 106: {line}"
                );
            }
        }

        // E2. Forbidden pre-A11 own-block / wallet-listener lines absent everywhere in raw debug.log
        const FORBIDDEN_RAW: &[&str] = &[
            "Staked block ",
            "Self-accepted staked block",
            "Self-accepted block",
            "Broadcast own block",
            "Wallet incremental save complete",
            "Mempool wallet tx",
        ];
        for bad in FORBIDDEN_RAW {
            assert!(
                !full_log.contains(bad),
                "[{config_label}] forbidden pre-A11 log format {bad:?} found in raw debug.log"
            );
        }

        // E3. Sync-state release gate: zero steady-state sync-state lines across steady_lines
        const FORBIDDEN_SYNC_STATE: &[&str] = &[
            "Block sync complete",
            "Header sync complete",
            "Exiting IBD mode",
            "Sync progress",
            "Sync stalled",
        ];
        for line in steady_lines {
            for sync_pat in FORBIDDEN_SYNC_STATE {
                assert!(
                    !line.contains(sync_pat),
                    "[{config_label}] steady-state sync-state leak {sync_pat:?}: {line}"
                );
            }
        }

        // E4. R14-1 Own vs. Peer Transaction Log Symmetry + R13-1 txid-pseudonym non-linkage
        let fmt_peer_unrelated = tx_relevant_formats(
            &win_peer_unrelated
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        for (name, win) in [
            ("peer_to_t", &win_peer_to_t),
            ("own_sendto", &win_own_sendto),
            ("own_sendmany", &win_own_sendmany),
            ("own_raw", &win_own_raw),
        ] {
            let refs: Vec<&str> = win.iter().map(String::as_str).collect();
            let fmts = tx_relevant_formats(&refs);
            assert_eq!(
                fmts, fmt_peer_unrelated,
                "[{config_label}] R14-1 tx relay/mempool format mismatch in {name} vs peer_unrelated:\n  {name}: {fmts:?} (raw: {win:?})\n  peer_unrelated: {fmt_peer_unrelated:?} (raw: {win_peer_unrelated:?})"
            );
            if log_flags.contains(&"-debug") {
                assert!(
                    win.iter().any(|l| {
                        l.contains("Received P2P message from peer ") && l.ends_with(": getdata")
                    }),
                    "[{config_label}] expected outbound P2P relay getdata in {name} window: {win:?}"
                );
            }
        }

        // R13-1: no `wtx-<hex>` pseudonym appearing in a wallet-commit line may appear
        // in any non-wallet relay or mempool line.
        let mut commit_wtx_pseudonyms = BTreeSet::new();
        for line in &all_lines {
            let m = strip_ts(line).trim();
            if is_own_wallet_commit_line(m) {
                for part in m.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
                    if part.starts_with("wtx-") {
                        commit_wtx_pseudonyms.insert(part.to_string());
                    }
                }
            }
        }
        assert!(
            !commit_wtx_pseudonyms.is_empty(),
            "[{config_label}] expected wtx-* pseudonyms in own wallet commit lines"
        );
        for line in &all_lines {
            let m = strip_ts(line).trim();
            if !is_own_wallet_commit_line(m) {
                for p in &commit_wtx_pseudonyms {
                    assert!(
                        !m.contains(p.as_str()),
                        "[{config_label}] R13-1 linkage: wallet pseudonym {p} appeared in non-wallet line: {line}"
                    );
                }
            }
        }

        // E5. Zero private canary leaks across ALL raw files written by T, A15 `diag/sent-txids`
        // isolation, zero txid leaks in INFO/Part-A raw files, and strict own-vs-peer symmetry
        // on any DEBUG raw lines (`ring.txt`, `-debug=net`, `-debug`) that mention public txids.
        let private_canaries = vec![
            LABEL_A.to_string(),
            LABEL_B.to_string(),
            NOTIFY_TAG.to_string(),
            TEST_RPC_PASS.to_string(),
            addr_t_a.clone(),
            addr_t_b.clone(),
            change_addr.clone(),
            "1.23456789".to_string(),
            "123456789".to_string(),
            "2.34567891".to_string(),
            "3.45678912".to_string(),
            "4.56789123".to_string(),
            "1.11111111".to_string(),
            "1.22222222".to_string(),
            "1.33333333".to_string(),
            "1.44444444".to_string(),
            "1.55555555".to_string(),
        ];
        let mut txid_canaries = Vec::new();
        for txid in [
            &tx_peer_unrelated,
            &tx_peer_to_t,
            &tx_own_sendto,
            &tx_own_sendmany,
            &tx_own_raw,
            &own_coinstake_txid,
            &tx_pay_104,
            &tx_spend_107,
            &tx_resubmit,
        ] {
            txid_canaries.extend(both_orders(txid));
        }

        // Verify A15 `diag/sent-txids` exists locally (`0600`), records `sendrawtransaction`,
        // never records peer txids, and is never copied into `pkg_dir`.
        let sent_txids_path = dir_t.join("diag/sent-txids");
        assert!(
            sent_txids_path.is_file(),
            "[{config_label}] expected diag/sent-txids to record sendrawtransaction"
        );
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&sent_txids_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o600,
                "[{config_label}] diag/sent-txids must have mode 0600, got {mode:o}"
            );
            let sent_body = std::fs::read_to_string(&sent_txids_path).unwrap();
            assert!(
                sent_body.contains(&tx_own_raw),
                "[{config_label}] diag/sent-txids missing sendrawtransaction txid"
            );
            assert!(
                !sent_body.contains(&tx_peer_unrelated) && !sent_body.contains(&tx_peer_to_t),
                "[{config_label}] diag/sent-txids must not record peer transactions"
            );
        }

        let raw_files = text_files(&dir_t);
        let mut notify_logged = 0usize;
        let mut raw_hits = Vec::new();
        let is_debug_log_mode = !log_flags.is_empty();
        for f in &raw_files {
            let fname = f.file_name().unwrap().to_string_lossy().into_owned();
            if fname == "key" {
                continue;
            }
            let text = String::from_utf8_lossy(&std::fs::read(f).unwrap()).into_owned();
            notify_logged += text.matches("runCommand error: walletnotify (").count();
            notify_logged += text.matches("runCommand error: blocknotify (").count();
            // Private canaries (labels, addresses, exact amounts, notify tags, credentials)
            // must NEVER appear in ANY raw file (including `sent-txids` and `ring.txt`).
            for c in &private_canaries {
                for line in text.lines().filter(|l| l.contains(c.as_str())) {
                    raw_hits.push(format!("raw {}: {c}: {line}", f.display()));
                }
            }
            if fname == "sent-txids" {
                continue;
            }
            let is_debug_stream = fname == "ring.txt"
                || (is_debug_log_mode && (fname == "debug.log" || fname.ends_with(".tail")));
            if !is_debug_stream {
                for c in &txid_canaries {
                    for line in text.lines().filter(|l| l.contains(c.as_str())) {
                        raw_hits.push(format!("raw {}: {c}: {line}", f.display()));
                    }
                }
            } else {
                // In DEBUG streams (`ring.txt`, `-debug=net`, `-debug`), consensus/P2P/mempool
                // log public 64-hex txids symmetrically for every block/relay tx; verify every
                // line mentioning an own txid has the exact normalized format of a peer txid line.
                let mut peer_shapes = BTreeSet::new();
                for line in text.lines() {
                    if line.contains(&tx_peer_unrelated) || line.contains(&tx_peer_to_t) {
                        peer_shapes.insert(normalize_format(line));
                    }
                }
                for own_tx in [&tx_own_sendto, &tx_own_sendmany, &tx_own_raw] {
                    for line in text.lines().filter(|l| l.contains(own_tx.as_str())) {
                        let shape = normalize_format(line);
                        if !peer_shapes.contains(&shape) {
                            raw_hits.push(format!(
                                "raw {} asymmetric own-tx DEBUG line ({shape}): {line}",
                                f.display()
                            ));
                        }
                    }
                }
            }
        }
        assert!(
            notify_logged > 0,
            "[{config_label}] expected failing walletnotify/blocknotify lines to be logged by kind"
        );
        assert!(
            raw_hits.is_empty(),
            "[{config_label}] canary leaked or asymmetric raw node files:\n{}",
            raw_hits.join("\n")
        );

        // E6. Package-level checks: zero private OR txid canaries anywhere in the package,
        // `sent-txids` absent, zero unmasked send RPC method names outside A15's intentional
        // `rpc-methods.log` / `rpc-methods-reserved.log`, and own-wallet commit + `Connected block`
        // lines removed in place and weekly-bucketed (`[week of ...]`).
        let mut pkg_hits = Vec::new();
        let mut saw_a15_rpc_methods = false;
        for f in pkg_files(&pkg_dir) {
            let rel = f
                .strip_prefix(&pkg_dir)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if rel.contains("sent-txids") {
                pkg_hits.push(format!("pkg {rel}: private sent-txids leaked into package"));
            }
            let text = String::from_utf8_lossy(&std::fs::read(&f).unwrap()).into_owned();
            for c in private_canaries.iter().chain(txid_canaries.iter()) {
                for line in text.lines().filter(|l| l.contains(c.as_str())) {
                    pkg_hits.push(format!("pkg {rel}: {c}: {line}"));
                }
            }
            let is_a15_methods_log =
                rel.ends_with("rpc-methods.log") || rel.ends_with("rpc-methods-reserved.log");
            if is_a15_methods_log {
                if text.contains("method=sendtoaddress transport=jsonrpc caller=loopback result=ok")
                {
                    saw_a15_rpc_methods = true;
                }
            } else {
                for send_m in [
                    "method=sendtoaddress",
                    "method=sendmany",
                    "method=sendrawtransaction",
                ] {
                    if text.contains(send_m) {
                        pkg_hits.push(format!("pkg {rel}: unmasked {send_m}"));
                    }
                }
            }
            for line in text.lines() {
                if line.trim_start().starts_with('[') {
                    continue;
                }
                for removed_pat in [
                    "CommitTransaction:",
                    "CTransaction(",
                    "CTxIn(",
                    "CTxOut(",
                    "Relaying wtx",
                    "keypool reserve",
                    "keypool keep",
                ] {
                    if line.contains(removed_pat) {
                        pkg_hits.push(format!(
                            "pkg {rel}: unremoved standing line ({removed_pat}): {line}"
                        ));
                    }
                }
                if (rel.ends_with("debug.log") || rel.ends_with(".tail"))
                    && (line.contains("Connected block ") || line.contains("runCommand error:"))
                {
                    pkg_hits.push(format!(
                        "pkg {rel}: unbucketed per-block/notify line: {line}"
                    ));
                }
            }
            if rel != "02-manifest.txt" {
                for tx10 in [
                    &tx_own_sendto[..10],
                    &tx_own_sendmany[..10],
                    &tx_own_raw[..10],
                    &own_coinstake_txid[..10],
                ] {
                    if text.contains(tx10) {
                        pkg_hits.push(format!("pkg {rel}: 10-hex txid prefix {tx10} leaked"));
                    }
                }
            }
        }
        assert!(
            saw_a15_rpc_methods,
            "[{config_label}] expected A15 rpc-methods.log in package to record parameterless sendtoaddress"
        );
        assert!(
            pkg_hits.is_empty(),
            "[{config_label}] package symmetry/redaction failures:\n{}",
            pkg_hits.join("\n")
        );
    }

    pub fn run_all() {
        run_for_config("default", &[]);
        run_for_config("-debug=net", &["-debug=net"]);
        run_for_config("-debug", &["-debug"]);
        println!("\ntest regtest_4_node_tx_and_block_log_symmetry_canary ... ok\n");
    }
}
