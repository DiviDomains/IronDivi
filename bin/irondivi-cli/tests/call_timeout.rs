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

//! A call the node takes long to answer (a rescan, a send from a big wallet,
//! stop) is waited for, as Divi Core's divi-cli waits with no time limit on
//! its socket (divi-cli.cpp:94).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_call_longer_than_30_seconds_is_waited_for() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
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
        reader.read_exact(&mut body).unwrap();
        // Longer than the 30 s irondivi-cli used to give a call
        std::thread::sleep(Duration::from_secs(32));
        let reply = r#"{"result":"done","error":null,"id":1}"#;
        let mut stream = stream;
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            reply.len(),
            reply
        );
    });

    let start = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_irondivi-cli"))
        .args(["--rpcport", &port, "--rpcuser", "u", "--rpcpassword", "p"])
        .arg("rescanblockchain")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(60) {
            child.kill().unwrap();
            panic!("irondivi-cli still running after 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
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
    assert_eq!(
        (stdout.as_str(), stderr.as_str(), status.success()),
        ("done\n", "", true)
    );
    assert!(start.elapsed() >= Duration::from_secs(32));
}
