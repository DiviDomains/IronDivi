// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! irondivi-cli run as a divi-cli script runs it: the same command line gives
//! the same stdout, stderr and exit code as Divi Core 3.0.0's divi-cli. Each
//! expected output is what divi-cli printed against the same recorded reply.

use divi_test_support::free_port;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A reply of the fake node
#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    delay: Duration,
}

fn ok(result: &str) -> Reply {
    Reply {
        status: 200,
        body: format!(r#"{{"result":{},"error":null,"id":1}}"#, result),
        delay: Duration::ZERO,
    }
}

fn http(status: u16, body: &str) -> Reply {
    Reply {
        status,
        body: body.to_string(),
        delay: Duration::ZERO,
    }
}

fn rpc_error(code: i64, message: &str) -> Reply {
    http(
        500,
        &format!(
            r#"{{"result":null,"error":{{"code":{},"message":"{}"}},"id":1}}"#,
            code, message
        ),
    )
}

/// A fake node on `port`: answers each request with the next reply (the last
/// one repeats) and records the request bodies
struct Fake {
    port: u16,
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Fake {
    fn start(replies: Vec<Reply>) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        Fake::serve(listener, replies, port)
    }

    /// Start listening on a free port only after `after`
    fn start_later(replies: Vec<Reply>, after: Duration) -> Fake {
        let port = free_port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        std::thread::spawn(move || {
            std::thread::sleep(after);
            let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
            serve_loop(listener, replies, log);
        });
        Fake { port, requests }
    }

    fn serve(listener: TcpListener, replies: Vec<Reply>, port: u16) -> Fake {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        std::thread::spawn(move || serve_loop(listener, replies, log));
        Fake { port, requests }
    }
}

fn serve_loop(listener: TcpListener, replies: Vec<Reply>, log: Arc<Mutex<Vec<serde_json::Value>>>) {
    let mut n = 0;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let reply = replies[n.min(replies.len() - 1)].clone();
        n += 1;
        let log = log.clone();
        std::thread::spawn(move || answer(stream, reply, log));
    }
}

fn answer(stream: TcpStream, reply: Reply, log: Arc<Mutex<Vec<serde_json::Value>>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap();
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    if let Ok(v) = serde_json::from_slice(&body) {
        log.lock().unwrap().push(v);
    }
    std::thread::sleep(reply.delay);
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply.status,
        reply.body.len(),
        reply.body
    );
}

/// stdout, stderr and exit code of one irondivi-cli run (killed after `limit`)
struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn cli(args: &[&str], limit: Duration) -> Run {
    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivi-cli"))
        .args(args)
        .env(
            "HOME",
            std::env::temp_dir().join("irondivi-cli-compat-no-home"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > limit {
            child.kill().unwrap();
            panic!("irondivi-cli {:?} still running after {:?}", args, limit);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    Run {
        stdout,
        stderr,
        code: status.code().unwrap_or(-1),
    }
}

/// A data directory whose divi.conf points at `port`, as a divi-cli user has
fn datadir(port: u16) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("divi.conf"),
        format!("rpcuser=u\nrpcpassword=p\nrpcport={}\n", port),
    )
    .unwrap();
    dir
}

fn dd(dir: &tempfile::TempDir) -> String {
    format!("-datadir={}", dir.path().display())
}

/// Connection options both IronDivi's older and current command lines read
fn conn(port: u16) -> Vec<String> {
    [
        "--rpcport",
        &port.to_string(),
        "--rpcuser",
        "u",
        "--rpcpassword",
        "p",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn with(mut first: Vec<String>, rest: &[&str]) -> Vec<String> {
    first.extend(rest.iter().map(|s| s.to_string()));
    first
}

fn cli_owned(args: &[String], limit: Duration) -> Run {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    cli(&args, limit)
}

const LIMIT: Duration = Duration::from_secs(20);

fn expect(run: &Run, stdout: &str, stderr: &str, code: i32) {
    assert_eq!(
        (run.stdout.as_str(), run.stderr.as_str(), run.code),
        (stdout, stderr, code)
    );
}

/// -rpcwait retries a refused connection every second until the node is up,
/// and a warmup error (-28) the same way (divi-cli.cpp:156-191)
#[test]
fn rpcwait_waits_for_the_node_and_its_warmup() {
    let fake = Fake::start_later(vec![ok("12")], Duration::from_secs(2));
    let run = cli_owned(
        &with(conn(fake.port), &["-rpcwait", "getblockcount"]),
        LIMIT,
    );
    expect(&run, "12\n", "", 0);

    let fake = Fake::start(vec![
        rpc_error(-28, "Loading block index..."),
        rpc_error(-28, "Verifying blocks..."),
        ok(r#""ready""#),
    ]);
    let run = cli_owned(
        &with(conn(fake.port), &["-rpcwait", "getbestblockhash"]),
        LIMIT,
    );
    expect(&run, "ready\n", "", 0);
    assert_eq!(fake.requests.lock().unwrap().len(), 3);

    // Without -rpcwait the warmup error is the answer
    let fake = Fake::start(vec![rpc_error(-28, "Loading block index...")]);
    let run = cli_owned(&with(conn(fake.port), &["getblockcount"]), LIMIT);
    expect(
        &run,
        "",
        "error: {\"code\":-28,\"message\":\"Loading block index...\"}\n",
        28,
    );
}

/// Results are printed as divi-cli prints them: null as nothing, a string
/// bare, reals with 8 decimals, objects in the node's order with four-space
/// indents and `"key" : value`, other bytes than printable ASCII as \u00XX
#[test]
fn results_print_as_divi_cli_prints_them() {
    let cases = [
        ("null", ""),
        (r#""00ab""#, "00ab\n"),
        ("12", "12\n"),
        ("12.5", "12.50000000\n"),
        ("true", "true\n"),
        ("[]", "[\n]\n"),
        (
            r#"{"b":1,"a":[1,2.5,"x",{}],"c":{"d":null,"e":[]},"f":0.1,"g":1e-9,"h":"\u0001\t\"/","u":"é"}"#,
            "{\n    \"b\" : 1,\n    \"a\" : [\n        1,\n        2.50000000,\n        \"x\",\n        {\n        }\n    ],\n    \"c\" : {\n        \"d\" : null,\n        \"e\" : [\n        ]\n    },\n    \"f\" : 0.10000000,\n    \"g\" : 0.00000000,\n    \"h\" : \"\\u0001\\t\\\"/\",\n    \"u\" : \"\\u00C3\\u00A9\"\n}\n",
        ),
    ];
    for (result, printed) in cases {
        let fake = Fake::start(vec![ok(result)]);
        let run = cli_owned(&with(conn(fake.port), &["getinfo"]), LIMIT);
        expect(&run, printed, "", 0);
    }
}

/// Errors go to stderr as divi-cli writes them, and the exit code is the
/// absolute value of the RPC error code (as an exit status, its low byte);
/// every other failure exits 1 (divi-cli.cpp:118-131, 166-173, 194-196)
#[test]
fn errors_and_exit_codes_are_divi_cli_s() {
    let cases: Vec<(Reply, &str, i32)> = vec![
        (
            rpc_error(-5, "Invalid address"),
            "error: {\"code\":-5,\"message\":\"Invalid address\"}\n",
            5,
        ),
        (
            http(
                404,
                r#"{"result":null,"error":{"code":-32601,"message":"Method not found"},"id":1}"#,
            ),
            "error: {\"code\":-32601,\"message\":\"Method not found\"}\n",
            89,
        ),
        (
            http(
                400,
                r#"{"result":null,"error":{"code":-8,"message":"bad","extra":1},"id":1}"#,
            ),
            "error: {\"code\":-8,\"message\":\"bad\",\"extra\":1}\n",
            8,
        ),
        (
            http(401, ""),
            "error: incorrect rpcuser or rpcpassword (authorization failed)\n",
            1,
        ),
        (http(403, "x"), "error: server returned HTTP error 403\n", 1),
        (http(200, ""), "error: no response from server\n", 1),
        (
            http(200, "nope"),
            "error: couldn't parse reply from server\n",
            1,
        ),
        (
            http(200, "{}"),
            "error: expected reply to have result, error and id properties\n",
            1,
        ),
        (
            http(200, r#"{"result":null,"error":"str","id":1}"#),
            "error: value is type str, expected obj\n",
            1,
        ),
    ];
    for (reply, stderr, code) in cases {
        let fake = Fake::start(vec![reply]);
        let run = cli_owned(&with(conn(fake.port), &["m"]), LIMIT);
        expect(&run, "", stderr, code);
    }

    // Nothing listening
    let port = free_port();
    let run = cli_owned(&with(conn(port), &["getblockcount"]), LIMIT);
    expect(&run, "", "error: couldn't connect to server\n", 1);
}

/// Every argument that is a JSON value as a whole is sent as that value,
/// whatever the method (rpcclient.cpp:17-36); reals are rounded to 8 decimals
#[test]
fn arguments_are_sent_as_divi_cli_sends_them() {
    let fake = Fake::start(vec![ok("null")]);
    let run = cli_owned(
        &with(
            conn(fake.port),
            &[
                "m",
                "1234",
                "true",
                "1e3",
                "null",
                "[1,2]",
                "{\"a\":1}",
                "abc",
                "1abc",
                " 1",
                "01",
                "+1",
                ".5",
                "0.123456789",
                "",
            ],
        ),
        LIMIT,
    );
    expect(&run, "", "", 0);
    let fake2 = Fake::start(vec![ok("null")]);
    let run = cli_owned(
        &with(conn(fake2.port), &["setaccount", "yAddr", "1234"]),
        LIMIT,
    );
    expect(&run, "", "", 0);
    let sent = fake.requests.lock().unwrap()[0]["params"].clone();
    assert_eq!(
        sent,
        serde_json::json!([
            1234, true, 1000.0, null, [1, 2], {"a": 1}, "abc", "1abc", 1, 1, 1, 0.5,
            0.12345679, ""
        ])
    );
    assert_eq!(
        fake2.requests.lock().unwrap()[0]["params"],
        serde_json::json!(["yAddr", 1234])
    );
}

/// divi-cli's options: `-name=value` (or `--name=value`) before the method,
/// unknown ones ignored, `-noname` negating; later options are parameters
#[test]
fn options_are_read_as_divi_cli_reads_them() {
    let fake = Fake::start(vec![ok("7")]);
    let dir = datadir(fake.port);
    let run = cli(
        &[
            &dd(&dir),
            "-foo=bar",
            "-nosuchthing",
            "-norpcwait",
            "m",
            "-regtest",
            "x",
        ],
        LIMIT,
    );
    expect(&run, "7\n", "", 0);
    assert_eq!(
        fake.requests.lock().unwrap()[0]["params"],
        serde_json::json!(["-regtest", "x"])
    );
    let run = cli(
        &[&format!("--datadir={}", dir.path().display()), "m"],
        LIMIT,
    );
    expect(&run, "7\n", "", 0);

    // A command-line value wins over the file, whose first value wins
    let run = cli(&[&dd(&dir), "-rpcport=1", "m"], LIMIT);
    expect(&run, "", "error: couldn't connect to server\n", 1);
    std::fs::write(
        dir.path().join("divi.conf"),
        format!(
            "rpcuser=u\nrpcpassword=p\nrpcport={}\nrpcport=1\n",
            fake.port
        ),
    )
    .unwrap();
    let run = cli(&[&dd(&dir), "m"], LIMIT);
    expect(&run, "7\n", "", 0);

    // -conf is relative to the data directory
    std::fs::write(dir.path().join("divi.conf"), "rpcport=1\n").unwrap();
    std::fs::write(
        dir.path().join("alt.conf"),
        format!("rpcuser=u\nrpcpassword=p\nrpcport={}\n", fake.port),
    )
    .unwrap();
    let run = cli(&[&dd(&dir), "-conf=alt.conf", "m"], LIMIT);
    expect(&run, "7\n", "", 0);
}

/// divi-cli's start-up errors and messages (divi-cli.cpp:46-83, 87-91, 148)
#[test]
fn start_up_messages_and_exit_codes_are_divi_cli_s() {
    let version = format!(
        "IronDivi RPC client version v{}\n",
        env!("CARGO_PKG_VERSION")
    );
    for args in [&[][..], &["-help"], &["-?"]] {
        let run = cli(args, LIMIT);
        expect(&run, &version, "", 1);
    }
    let run = cli(&["-version"], LIMIT);
    assert!(run.stdout.starts_with(&version), "{}", run.stdout);
    assert_eq!((run.stderr.as_str(), run.code), ("", 1));

    let dir = datadir(1);
    let run = cli(&[&dd(&dir)], LIMIT);
    expect(&run, "", "error: too few parameters\n", 1);

    let run = cli(&["-datadir=/nonexistent/x", "getblockcount"], LIMIT);
    expect(
        &run,
        "",
        "Error: Specified data directory \"/nonexistent/x\" does not exist.\n",
        1,
    );

    let run = cli(&[&dd(&dir), "-testnet", "-regtest", "m"], LIMIT);
    expect(
        &run,
        "",
        "Error: Invalid combination of -regtest and -testnet.\n",
        1,
    );

    std::fs::write(dir.path().join("divi.conf"), "").unwrap();
    let run = cli(&[&dd(&dir), "-rpcport=1", "m"], LIMIT);
    expect(
        &run,
        "",
        &format!(
            "error: You must set rpcpassword=<password> in the configuration file:\n{}\n\
             If the file does not exist, create it with owner-readable-only file permissions.\n",
            dir.path().join("divi.conf").display()
        ),
        1,
    );
}
