// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! -rpckeepalive as Divi Core 3.0.0 has it: with it off, every reply closes
//! its connection, whatever the request asks (rpcserver.cpp:1014-1017); with
//! it on (the default) an HTTP/1.1 request keeps the connection.

use divi_rpc::{create_router_with_auth, RpcConfig, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

struct Served {
    addr: SocketAddr,
    _runtime: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn served(keep_alive: bool) -> Served {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
    let server = Arc::new(RpcServer::new(chain));
    let config = RpcConfig {
        username: Some("test".into()),
        password: Some("test".into()),
        keep_alive,
        ..RpcConfig::default()
    };
    let router = create_router_with_auth(server, &config);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    runtime.spawn(async move { axum::serve(listener, router).await });
    Served {
        addr,
        _runtime: runtime,
        _dir: dir,
    }
}

/// One getblockcount on a fresh connection with `extra` headers: the reply's
/// Connection header, and whether the server then closed the connection
/// (within 2 s)
fn call(addr: SocketAddr, extra: &str) -> (String, bool) {
    let body = r#"{"method":"getblockcount","params":[],"id":1}"#;
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(
            format!(
                "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\
                 Content-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        let n = stream.read(&mut chunk).expect("a reply");
        assert!(n > 0, "closed before a reply");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let connection = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let len: usize = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < end + 4 + len {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "closed inside the body");
        buf.extend_from_slice(&chunk[..n]);
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let closed = matches!(stream.read(&mut chunk), Ok(0));
    (connection, closed)
}

#[test]
fn rpckeepalive_off_closes_every_connection() {
    let s = served(false);
    for extra in ["", "Connection: keep-alive\r\n"] {
        assert_eq!(
            call(s.addr, extra),
            ("close".to_string(), true),
            "with {extra:?}"
        );
    }
}

#[test]
fn rpckeepalive_on_keeps_an_http_1_1_connection() {
    let s = served(true);
    assert_eq!(call(s.addr, ""), ("keep-alive".to_string(), false));
    assert_eq!(
        call(s.addr, "Connection: close\r\n"),
        ("close".to_string(), true)
    );
}
