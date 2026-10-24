// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The JSON-RPC envelope over HTTP is Divi Core 3.0.0's (rpcserver.cpp
//! HTTPReq_JSONRPC, JSONRequest::parse, ErrorReply; rpcprotocol.cpp
//! JSONRPCReplyObj; json_spirit_writer_template.h): any request object with a
//! "method" is served, replies always carry "result", "error" and "id",
//! errors answer HTTP 500 (400 for -32600, 404 for -32601), and reals are
//! written with 8 decimals.

use divi_rpc::{create_router_with_auth, RpcConfig, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USER: &str = "u";
const PASS: &str = "p";

struct Node {
    addr: std::net::SocketAddr,
    _dir: tempfile::TempDir,
}

async fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
    let server = Arc::new(RpcServer::new(chain));
    let config = RpcConfig {
        username: Some(USER.into()),
        password: Some(PASS.into()),
        ..RpcConfig::default()
    };
    let router = create_router_with_auth(server, &config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    Node { addr, _dir: dir }
}

/// POST `body` to "/" and return the HTTP status and the reply body
async fn post(node: &Node, body: &str) -> (u16, String) {
    use base64::Engine;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASS}"));
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
         Authorization: Basic {auth}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        node.addr,
        body.len()
    );
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(node.addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    };
    let response = tokio::time::timeout(Duration::from_secs(20), exchange)
        .await
        .expect("RPC reply within 20 s");
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("bad HTTP response: {response:?}"));
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

#[tokio::test]
async fn request_without_jsonrpc_member_is_served() {
    let n = node().await;
    // python-bitcoinrpc, divi-cli and most exchange code send no "jsonrpc"
    let (status, body) = post(&n, r#"{"method":"getblockcount","params":[],"id":7}"#).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "{\"result\":0,\"error\":null,\"id\":7}\n")
    );
    let (status, body) = post(&n, r#"{"version":"1.1","method":"getblockcount","id":"x"}"#).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "{\"result\":0,\"error\":null,\"id\":\"x\"}\n")
    );
    let (status, body) = post(&n, r#"{"method":"getblockcount","params":null}"#).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "{\"result\":0,\"error\":null,\"id\":null}\n")
    );
}

#[tokio::test]
async fn error_replies_carry_null_result_and_http_status() {
    let n = node().await;
    let (status, body) = post(
        &n,
        r#"{"jsonrpc":"1.0","method":"nosuch","params":[],"id":1}"#,
    )
    .await;
    assert_eq!(
        (status, body.as_str()),
        (404, "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}\n")
    );
    let (status, body) = post(&n, r#"{"method":"getblockhash","params":[99999],"id":2}"#).await;
    assert_eq!(status, 500, "{body}");
    assert!(
        body.starts_with("{\"result\":null,\"error\":{\"code\":"),
        "{body}"
    );
    assert!(body.ends_with(",\"id\":2}\n"), "{body}");
}

#[tokio::test]
async fn malformed_requests_get_core_codes() {
    let n = node().await;
    let cases: [(&str, u16, &str); 6] = [
        (
            r#"{"method":"#,
            500,
            r#"{"result":null,"error":{"code":-32700,"message":"Parse error"},"id":null}"#,
        ),
        (
            r#""getblockcount""#,
            500,
            r#"{"result":null,"error":{"code":-32700,"message":"Top-level object parse error"},"id":null}"#,
        ),
        (
            r#"{"params":[],"id":1}"#,
            400,
            r#"{"result":null,"error":{"code":-32600,"message":"Missing method"},"id":1}"#,
        ),
        (
            r#"{"method":5,"id":1}"#,
            400,
            r#"{"result":null,"error":{"code":-32600,"message":"Method must be a string"},"id":1}"#,
        ),
        (
            r#"{"method":"getblockcount","params":{},"id":1}"#,
            400,
            r#"{"result":null,"error":{"code":-32600,"message":"Params must be an array"},"id":1}"#,
        ),
        (
            r#"{"method":"getblockcount","params":"x","id":[1]}"#,
            400,
            r#"{"result":null,"error":{"code":-32600,"message":"Params must be an array"},"id":[1]}"#,
        ),
    ];
    for (request, want_status, want_body) in cases {
        let (status, body) = post(&n, request).await;
        assert_eq!(
            (status, body.trim_end()),
            (want_status, want_body),
            "request {request}"
        );
    }
}

#[tokio::test]
async fn batch_replies_one_entry_per_request() {
    let n = node().await;
    let (status, body) = post(
        &n,
        r#"[{"method":"getblockcount","id":1},{"method":"nosuch","id":2},5]"#,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        "[{\"result\":0,\"error\":null,\"id\":1},\
         {\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":2},\
         {\"result\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request object\"},\"id\":null}]\n"
    );
}

#[tokio::test]
async fn reals_are_written_with_eight_decimals() {
    let n = node().await;
    let (_, body) = post(&n, r#"{"method":"getinfo","params":[],"id":1}"#).await;
    assert!(body.contains("\"relayfee\":0.00010000"), "{body}");
    assert!(body.contains("\"balance\":0.00000000"), "{body}");
    let (_, body) = post(&n, r#"{"method":"getdifficulty","params":[],"id":1}"#).await;
    let value = body
        .strip_prefix("{\"result\":")
        .and_then(|b| b.split(',').next())
        .unwrap();
    let decimals = value.split_once('.').map(|(_, d)| d.len());
    assert_eq!(decimals, Some(8), "{body}");
}
