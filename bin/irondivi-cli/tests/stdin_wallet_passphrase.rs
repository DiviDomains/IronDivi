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

//! `--stdinwalletpassphrase` end to end: the binary talks to a one-shot fake
//! RPC server that records the request it gets.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

/// Run irondivi-cli with `args`, feeding `stdin`; return the JSON-RPC request body
fn request_sent(args: &[&str], stdin: &str) -> serde_json::Value {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                length = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        let reply = r#"{"result":null,"error":null,"id":1}"#;
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            reply.len(),
            reply
        )
        .unwrap();
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivi-cli"))
        .args(["--rpcconnect", "127.0.0.1", "--rpcport", &port])
        .args(["--rpcuser", "u", "--rpcpassword", "p"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("not echoed 42"),
        "passphrase echoed"
    );
    server.join().unwrap()
}

#[test]
fn stdinwalletpassphrase_sends_the_passphrase_as_first_param() {
    let req = request_sent(
        &["--stdinwalletpassphrase", "walletpassphrase", "0", "true"],
        "my pass phrase\n",
    );
    assert_eq!(req["method"], "walletpassphrase");
    assert_eq!(
        req["params"],
        serde_json::json!(["my pass phrase", 0, true])
    );
}

#[test]
fn stdinwalletpassphrase_keeps_a_numeric_passphrase_a_string() {
    let req = request_sent(
        &["--stdinwalletpassphrase", "walletpassphrase", "60"],
        "not echoed 42\n",
    );
    assert_eq!(req["params"], serde_json::json!(["not echoed 42", 60]));
    let req = request_sent(&["--stdinwalletpassphrase", "encryptwallet"], "1234\n");
    assert_eq!(req["params"], serde_json::json!(["1234"]));
}

#[test]
fn stdinwalletpassphrase_change_reads_old_and_new() {
    let req = request_sent(
        &["--stdinwalletpassphrase", "walletpassphrasechange"],
        "old pass\nnew pass\n",
    );
    assert_eq!(req["params"], serde_json::json!(["old pass", "new pass"]));
}

/// As divi-cli (rpcclient.cpp:17-36): every argument that is a JSON value as
/// a whole is sent as that value, whatever the method; only passphrases read
/// with --stdinwalletpassphrase stay strings
#[test]
fn arguments_that_are_json_are_sent_as_json() {
    let req = request_sent(&["setaccount", "yAddr", "1234"], "");
    assert_eq!(req["params"], serde_json::json!(["yAddr", 1234]));

    let req = request_sent(&["sendtoaddress", "yAddr", "1.5", "100", "null"], "");
    assert_eq!(req["params"], serde_json::json!(["yAddr", 1.5, 100, null]));

    let req = request_sent(&["createrawtransaction", "[]", "{\"yAddr\":2}"], "");
    assert_eq!(req["params"], serde_json::json!([[], {"yAddr": 2}]));
}
