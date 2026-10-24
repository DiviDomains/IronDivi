// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The RPC HTTP layer as Divi Core 3.0.0 has it (rpcprotocol.cpp,
//! rpcserver.cpp ServiceConnection / HTTPReq_JSONRPC), over raw HTTP.

use divi_rpc::{create_router_with_auth, RpcConfig, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const AUTH: &str = "Basic dGVzdDp0ZXN0"; // test:test

struct Served {
    addr: SocketAddr,
    _runtime: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn served() -> Served {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
    let server = Arc::new(RpcServer::new(chain));
    let config = RpcConfig {
        username: Some("test".into()),
        password: Some("test".into()),
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

struct Reply {
    status_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn request(method: &str, path: &str, auth: Option<&str>, body: &str, extra: &str) -> Vec<u8> {
    let auth = auth
        .map(|a| format!("Authorization: {a}\r\n"))
        .unwrap_or_default();
    format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{auth}{extra}\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Send the requests on one connection; each reply (None once the connection
/// is closed) and whether it was closed after the last
fn exchange(addr: SocketAddr, requests: &[Vec<u8>]) -> (Vec<Option<Reply>>, bool) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut buf = Vec::new();
    let mut replies = Vec::new();
    let mut closed = false;
    for req in requests {
        if closed || stream.write_all(req).is_err() {
            replies.push(None);
            continue;
        }
        let reply = loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let mut lines = head.split("\r\n");
                let status_line = lines.next().unwrap_or("").to_string();
                let headers: Vec<(String, String)> = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                    .collect();
                let len: usize = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                while buf.len() < end + 4 + len {
                    let mut chunk = [0u8; 65536];
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let body_end = (end + 4 + len).min(buf.len());
                let body = String::from_utf8_lossy(&buf[end + 4..body_end]).to_string();
                buf.drain(..body_end);
                break Some(Reply {
                    status_line,
                    headers,
                    body,
                });
            }
            let mut chunk = [0u8; 65536];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    closed = true;
                    break None;
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        replies.push(reply);
    }
    if !closed {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut one = [0u8; 1];
        closed = matches!(stream.read(&mut one), Ok(0));
    }
    (replies, closed)
}

fn one(addr: SocketAddr, req: Vec<u8>) -> Reply {
    exchange(addr, &[req]).0.remove(0).expect("a reply")
}

const GOOD: &str = r#"{"method":"getblockcount","params":[],"id":1}"#;

/// No or wrong credentials: Divi Core's 401 (rpcprotocol.cpp:85-105), after a
/// 250 ms delay when credentials were given (rpcserver.cpp:940-956); the scheme
/// must be "Basic " as written (rpcserver.cpp:492)
#[test]
fn credentials_are_refused_as_divid_refuses_them() {
    let s = served();
    let close = "Connection: close\r\n";
    let r = one(s.addr, request("POST", "/", None, GOOD, close));
    assert_eq!(r.status_line, "HTTP/1.0 401 Authorization Required");
    assert_eq!(r.header("content-type"), Some("text/html"));
    assert_eq!(
        r.header("www-authenticate"),
        Some("Basic realm=\"jsonrpc\"")
    );
    assert_eq!(r.body.len(), 296);
    assert!(r.body.contains("<H1>401 Unauthorized.</H1>"));

    let lower = AUTH.replace("Basic ", "basic ");
    let r = one(s.addr, request("POST", "/", Some(&lower), GOOD, close));
    assert!(r.status_line.contains(" 401 "), "{}", r.status_line);

    let t = Instant::now();
    one(
        s.addr,
        request("POST", "/", Some("Basic d3Jvbmc6d3Jvbmc="), GOOD, close),
    );
    assert!(
        t.elapsed() >= Duration::from_millis(240),
        "{:?}",
        t.elapsed()
    );
    let t = Instant::now();
    one(s.addr, request("POST", "/", None, GOOD, close));
    assert!(
        t.elapsed() < Duration::from_millis(200),
        "{:?}",
        t.elapsed()
    );
}

/// GET is served as POST; another path, a query or another method is not
/// (rpcprotocol.cpp:138-160, rpcserver.cpp:1019-1031)
#[test]
fn methods_and_paths_as_divid() {
    let s = served();
    let close = "Connection: close\r\n";
    let r = one(s.addr, request("GET", "/", Some(AUTH), GOOD, close));
    assert!(r.status_line.contains(" 200 "), "{}", r.status_line);
    assert!(r.body.contains("\"result\":0"), "{}", r.body);
    for path in ["/x", "/?a=1"] {
        let r = one(s.addr, request("POST", path, None, GOOD, close));
        assert_eq!(r.status_line, "HTTP/1.1 404 Not Found", "{path}");
        assert_eq!(r.header("content-type"), Some("text/plain"));
        assert_eq!(r.header("connection"), Some("close"));
        assert_eq!(r.body, "Not Found");
    }
    let r = one(s.addr, request("PUT", "/", Some(AUTH), GOOD, ""));
    assert!(r.status_line.contains(" 405 "), "{}", r.status_line);
    assert_eq!(r.header("connection"), Some("close"));
}

/// Every reply names the connection: kept after a 200 on HTTP/1.1, closed
/// after an error reply (rpcprotocol.cpp:239-245, rpcserver.cpp:500-511)
#[test]
fn connection_is_kept_after_a_reply_and_closed_after_an_error() {
    let s = served();
    let good = request("POST", "/", Some(AUTH), GOOD, "");
    let (replies, closed) = exchange(s.addr, &[good.clone(), good.clone()]);
    for r in &replies {
        let r = r.as_ref().expect("both answered");
        assert_eq!(r.header("connection"), Some("keep-alive"));
    }
    assert!(!closed);

    let bad = request(
        "POST",
        "/",
        Some(AUTH),
        r#"{"method":"getblockhash","params":[99],"id":1}"#,
        "",
    );
    let (replies, closed) = exchange(s.addr, &[bad, good]);
    let first = replies[0].as_ref().unwrap();
    assert!(first.status_line.contains(" 500 "), "{}", first.status_line);
    assert_eq!(first.header("connection"), Some("close"));
    assert!(replies[1].is_none(), "no second reply after an error");
    assert!(closed);
}

/// Bodies up to Divi Core's MAX_SIZE (32 MiB, serialize.h:34) are read; a
/// declared larger one is not, and is a parse error (rpcprotocol.cpp:218-220)
#[test]
fn bodies_up_to_divid_s_max_size() {
    let s = served();
    let close = "Connection: close\r\n";
    let big = format!("{}{GOOD}", " ".repeat(3 * 1024 * 1024));
    let r = one(s.addr, request("POST", "/", Some(AUTH), &big, close));
    assert!(r.status_line.contains(" 200 "), "{}", r.status_line);

    let too_big = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: {AUTH}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        0x0200_0000 + 1
    );
    let r = one(s.addr, too_big.into_bytes());
    assert!(r.status_line.contains(" 500 "), "{}", r.status_line);
    assert!(r.body.contains("\"code\":-32700"), "{}", r.body);
    assert!(r.body.contains("Parse error"), "{}", r.body);
}

/// Of two equal keys json_spirit's find_value takes the first
#[test]
fn of_two_equal_keys_the_first_counts() {
    let s = served();
    let body = r#"{"method":"nosuchmethod","method":"getblockcount","id":1}"#;
    let r = one(
        s.addr,
        request("POST", "/", Some(AUTH), body, "Connection: close\r\n"),
    );
    assert!(r.status_line.contains(" 404 "), "{}", r.status_line);
    assert!(r.body.contains("-32601"), "{}", r.body);
}
