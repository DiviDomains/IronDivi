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

//! Divi Core's REST interface (rest.cpp), served on the RPC port beside the
//! JSON-RPC paths and, as in divid, without credentials.
//!
//! divid sends a path starting `/rest/` to REST when -rest is on (default
//! off) and answers any other path but the JSON-RPC ones `404 Not Found`
//! (rpcserver.cpp:1019-1033); the RPC server's outer layer makes that choice
//! and passes the REST paths here. REST serves three prefixes (rest.cpp:238-242):
//! `/rest/tx/<txid>`, `/rest/block/notxdetails/<hash>` and
//! `/rest/block/<hash>`, each with `.bin`, `.hex` or `.json`. Each answer is
//! built from the RPC reply divid builds it from (getrawtransaction, getblock,
//! decoderawtransaction), so the two never differ.

use crate::protocol::{write_core_json, Params, Request, RequestId};
use crate::server::RpcServer;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode, Uri, Version},
    response::{IntoResponse, Response},
    Router,
};
use divi_primitives::block::Block;
use divi_primitives::serialize::{deserialize, serialize};
use serde_json::{json, Value};
use std::sync::Arc;

/// A reply format (rest.cpp:33-48)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Undef,
    Binary,
    Hex,
    Json,
}

/// The request text split at its dots: the first part and the format the
/// second part names (rest.cpp ParseDataFormat, :65-75). A missing, empty or
/// unknown second part is no format; parts after the second are ignored.
fn parse_format(req: &str) -> (&str, Format) {
    let mut parts = req.split('.');
    let first = parts.next().unwrap_or("");
    let format = match parts.next() {
        Some("bin") => Format::Binary,
        Some("hex") => Format::Hex,
        Some("json") => Format::Json,
        _ => Format::Undef,
    };
    (first, format)
}

/// rest.cpp ParseHashStr (:93-100): 64 hex digits
fn valid_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn text(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

/// divid's HTTPError(HTTP_NOT_FOUND) (rpcprotocol.cpp:85-108)
fn not_found() -> Response {
    crate::http::error_page(StatusCode::NOT_FOUND)
}

/// A REST error: the message and CRLF, as text (rest.cpp:263-265)
fn rest_error(status: StatusCode, message: String) -> Response {
    text(status, format!("{message}\r\n"))
}

fn format_not_found() -> Response {
    rest_error(
        StatusCode::NOT_FOUND,
        "output format not found (available: .bin, .hex, .json)".into(),
    )
}

/// A reply in `format` from the object `json` and the serialized `hex`;
/// `missing` answers when the object cannot be built
fn reply(
    format: Format,
    json: impl FnOnce() -> Option<Value>,
    hex: &str,
    missing: impl FnOnce() -> Response,
) -> Response {
    match format {
        Format::Binary => match hex::decode(hex) {
            Ok(bytes) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                bytes,
            )
                .into_response(),
            Err(_) => not_found(),
        },
        Format::Hex => text(StatusCode::OK, format!("{hex}\n")),
        Format::Json => match json() {
            Some(value) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                format!("{}\n", write_core_json(&value)),
            )
                .into_response(),
            None => missing(),
        },
        Format::Undef => format_not_found(),
    }
}

/// The members of divid's TxToJSON (JsonTxHelpers.cpp:39-95); irondivid's
/// getrawtransaction adds others, which REST leaves out
const TX_FIELDS: &[&str] = &[
    "txid",
    "baretxid",
    "version",
    "locktime",
    "vin",
    "vout",
    "blockhash",
    "confirmations",
    "time",
    "blocktime",
];

/// The members of divid's blockToJSON (JsonBlockHelpers.cpp:38-77); irondivid's
/// getblock adds others, which REST leaves out
const BLOCK_FIELDS: &[&str] = &[
    "hash",
    "confirmations",
    "size",
    "height",
    "version",
    "merkleroot",
    "acc_checkpoint",
    "tx",
    "time",
    "nonce",
    "bits",
    "difficulty",
    "chainwork",
    "previousblockhash",
    "nextblockhash",
    "moneysupply",
];

/// `value` with only the members in `fields`
fn only(mut value: Value, fields: &[&str]) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.retain(|k, _| fields.contains(&k.as_str()));
    }
    value
}

/// A transaction object with TxToJSON's members only, at every level: inputs
/// (JsonTxHelpers.cpp:46-60), outputs and their scriptPubKey (:63-72, :15-37)
fn tx_as_divid(value: Value) -> Value {
    let mut value = only(value, TX_FIELDS);
    let each = |items: Option<&mut Value>, fields: &[&str], inner: (&str, &[&str])| {
        if let Some(Value::Array(items)) = items {
            for item in items.iter_mut() {
                *item = only(item.take(), fields);
                if let Some(nested) = item.get_mut(inner.0) {
                    *nested = only(nested.take(), inner.1);
                }
            }
        }
    };
    each(
        value.get_mut("vin"),
        &["coinbase", "txid", "vout", "scriptSig", "sequence"],
        ("scriptSig", &["asm", "hex"]),
    );
    each(
        value.get_mut("vout"),
        &["value", "n", "scriptPubKey"],
        (
            "scriptPubKey",
            &["asm", "hex", "reqSigs", "type", "addresses"],
        ),
    );
    value
}

/// An RPC call's result, or None when it fails
fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Option<Value> {
    let response = server.handle_request(Request {
        jsonrpc: "1.0".into(),
        id: RequestId::Null,
        method: method.into(),
        params: Params::Array(params),
    });
    match (response.result, response.error) {
        (Some(result), None) => Some(result),
        _ => None,
    }
}

/// `/rest/tx/<txid>.<format>` (rest.cpp rest_tx, :181-230): the hash, then the
/// transaction (mempool, transaction index or block), then the format
fn rest_tx(server: &RpcServer, req: &str) -> Response {
    let (hash, format) = parse_format(req);
    if !valid_hash(hash) {
        return rest_error(StatusCode::BAD_REQUEST, format!("Invalid hash: {hash}"));
    }
    let txid = hash.to_ascii_lowercase();
    let Some(verbose) = call(server, "getrawtransaction", vec![json!(txid), json!(1)]) else {
        return rest_error(StatusCode::NOT_FOUND, format!("{hash} not found"));
    };
    let raw = verbose["hex"].as_str().unwrap_or_default().to_string();
    // divid's TxToJSON: getrawtransaction's reply with TxToJSON's members only
    let json = || Some(tx_as_divid(verbose.clone()));
    reply(format, json, &raw, not_found)
}

/// `/rest/block/<hash>` and `/rest/block/notxdetails/<hash>` (rest.cpp
/// rest_block, :102-163): the hash, then the block, then the format. With tx
/// details each transaction is the object decoderawtransaction gives
/// (blockToJSON with TxToJSON(tx, 0), JsonBlockHelpers.cpp:38-77).
fn rest_block(server: &RpcServer, req: &str, tx_details: bool) -> Response {
    let (hash, format) = parse_format(req);
    if !valid_hash(hash) {
        return rest_error(StatusCode::BAD_REQUEST, format!("Invalid hash: {hash}"));
    }
    let lower = hash.to_ascii_lowercase();
    let not_found_here = || rest_error(StatusCode::NOT_FOUND, format!("{hash} not found"));
    let (Some(verbose), Some(raw)) = (
        call(server, "getblock", vec![json!(lower), json!(true)]),
        call(server, "getblock", vec![json!(lower), json!(false)]),
    ) else {
        return not_found_here();
    };
    let raw = raw.as_str().unwrap_or_default().to_string();
    let json = || {
        if !tx_details {
            return Some(only(verbose.clone(), BLOCK_FIELDS));
        }
        let block: Block = hex::decode(&raw)
            .ok()
            .and_then(|bytes| deserialize(&bytes).ok())?;
        let txs: Option<Vec<Value>> = block
            .transactions
            .iter()
            .map(|tx| {
                call(
                    server,
                    "decoderawtransaction",
                    vec![json!(hex::encode(serialize(tx)))],
                )
                .map(tx_as_divid)
            })
            .collect();
        let mut value = only(verbose.clone(), BLOCK_FIELDS);
        value["tx"] = Value::Array(txs?);
        Some(value)
    };
    reply(format, json, &raw, not_found_here)
}

/// Answer `uri` (the path and query as sent) as divid's ServiceConnection
/// answers a path other than `/` (rpcserver.cpp:1019-1033, rest.cpp:244-270)
fn answer(server: &RpcServer, enabled: bool, uri: &str) -> Response {
    if !enabled || !uri.starts_with("/rest/") {
        return not_found();
    }
    if let Some(req) = uri.strip_prefix("/rest/tx/") {
        return rest_tx(server, req);
    }
    if let Some(req) = uri.strip_prefix("/rest/block/notxdetails/") {
        return rest_block(server, req, false);
    }
    if let Some(req) = uri.strip_prefix("/rest/block/") {
        return rest_block(server, req, true);
    }
    not_found()
}

/// The router for every path but the JSON-RPC ones, without credentials:
/// REST when `enabled` (Divi Core -rest, default off), else `404 Not Found`
pub fn router(server: Arc<RpcServer>, enabled: bool) -> Router {
    Router::new()
        .fallback(
            move |State(server): State<Arc<RpcServer>>,
                  version: Version,
                  headers: HeaderMap,
                  uri: Uri| async move {
                let text = uri
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| uri.path().to_string());
                let mut res = answer(&server, enabled, &text);
                // A 200 keeps the connection as a JSON-RPC reply does, every
                // error closes it (rest.cpp:138-152, :264; rpcserver.cpp:1031)
                let status = res.status();
                let keep = crate::http::keep_alive(version, &headers);
                res.headers_mut().insert(
                    header::CONNECTION,
                    crate::http::connection_header(status, keep),
                );
                res
            },
        )
        .with_state(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::ChainMode;
    use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn server() -> (Arc<RpcServer>, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let genesis = chain.tip().unwrap().hash.to_string();
        (Arc::new(RpcServer::new(chain)), dir, genesis)
    }

    /// Serve `router` on a loopback port and send one request as is: (status,
    /// Content-Type, body)
    async fn send(router: &Router, method: &str, path: &str, body: &str) -> (u16, String, Vec<u8>) {
        let (status, head, body) =
            exchange(router, method, path, body, "Connection: close\r\n").await;
        (status, header_of(&head, "content-type"), body)
    }

    fn header_of(head: &str, name: &str) -> String {
        head.lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix(&format!("{name}: "))
                    .map(String::from)
            })
            .unwrap_or_default()
    }

    /// One request with `extra` headers: (status, head, body)
    async fn exchange(
        router: &Router,
        method: &str,
        path: &str,
        body: &str,
        extra: &str,
    ) -> (u16, String, Vec<u8>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        // Read the head, then the body by its Content-Length: a kept
        // connection does not end
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let split = loop {
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before the head");
            raw.extend_from_slice(&buf[..n]);
        };
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        let len: usize = header_of(&head, "content-length").parse().unwrap();
        let mut body = raw[split + 4..].to_vec();
        while body.len() < len {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before the body");
            body.extend_from_slice(&buf[..n]);
        }
        (status, head, body)
    }

    async fn get(router: &Router, path: &str) -> (u16, String, Vec<u8>) {
        send(router, "GET", path, "").await
    }

    #[test]
    fn formats_are_read_as_divid_reads_them() {
        assert_eq!(parse_format("ab.json"), ("ab", Format::Json));
        assert_eq!(parse_format("ab.hex"), ("ab", Format::Hex));
        assert_eq!(parse_format("ab.bin"), ("ab", Format::Binary));
        assert_eq!(parse_format("ab"), ("ab", Format::Undef));
        assert_eq!(parse_format("ab."), ("ab", Format::Undef));
        assert_eq!(parse_format("ab.xml"), ("ab", Format::Undef));
        // only the second part counts; a query stays in it
        assert_eq!(parse_format("ab.json.hex"), ("ab", Format::Json));
        assert_eq!(parse_format("ab.json?x=1"), ("ab", Format::Undef));
        assert!(valid_hash(&"aB".repeat(32)));
        assert!(!valid_hash(&"a".repeat(63)));
        assert!(!valid_hash(&"g".repeat(64)));
    }

    #[tokio::test]
    async fn off_by_default_and_other_paths_are_not_found() {
        let (server, _dir, genesis) = server();
        let off = router(server.clone(), false);
        for path in [
            format!("/rest/block/{genesis}.json"),
            "/foo".into(),
            "/rest/".into(),
        ] {
            assert_eq!(
                get(&off, &path).await,
                (404, "text/plain".into(), b"Not Found".to_vec()),
                "{path}"
            );
        }
        let on = router(server, true);
        for path in [
            "/foo",
            "/rest/",
            "/rest/chaininfo.json",
            "/rest/headers/5/x.json",
        ] {
            assert_eq!(
                get(&on, path).await,
                (404, "text/plain".into(), b"Not Found".to_vec()),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn errors_come_in_divid_s_order() {
        let (server, _dir, genesis) = server();
        let on = router(server, true);
        let unknown = "ab".repeat(32);
        let no_format = "output format not found (available: .bin, .hex, .json)\r\n".to_string();
        let cases: Vec<(String, u16, String)> = vec![
            (
                "/rest/tx/xyz.json".into(),
                400,
                "Invalid hash: xyz\r\n".into(),
            ),
            (
                "/rest/tx/xyz.xml".into(),
                400,
                "Invalid hash: xyz\r\n".into(),
            ),
            (
                format!("/rest/tx/{unknown}.json"),
                404,
                format!("{unknown} not found\r\n"),
            ),
            (
                format!("/rest/tx/{unknown}.xml"),
                404,
                format!("{unknown} not found\r\n"),
            ),
            (
                format!("/rest/block/{unknown}.json"),
                404,
                format!("{unknown} not found\r\n"),
            ),
            (format!("/rest/block/{genesis}.xml"), 404, no_format.clone()),
            (format!("/rest/block/{genesis}"), 404, no_format),
        ];
        for (path, status, body) in cases {
            assert_eq!(
                get(&on, &path).await,
                (status, "text/plain".into(), body.into_bytes()),
                "{path}"
            );
        }
    }

    /// Through the server's own router: REST needs no credentials (divid checks
    /// them only for JSON-RPC, rpcserver.cpp:1019-1033), JSON-RPC still does
    #[tokio::test]
    async fn rest_needs_no_credentials_and_json_rpc_still_does() {
        let (server, _dir, genesis) = server();
        let config = crate::server::RpcConfig {
            username: Some("u".into()),
            password: Some("p".into()),
            rest: true,
            ..Default::default()
        };
        let app = crate::server::create_router_with_auth(server, &config);
        let (status, ctype, _) = get(&app, &format!("/rest/block/{genesis}.json")).await;
        assert_eq!((status, ctype.as_str()), (200, "application/json"));
        let rpc = send(
            &app,
            "POST",
            "/",
            r#"{"method":"getblockcount","params":[],"id":1}"#,
        )
        .await;
        assert_eq!(rpc.0, 401);
        assert_eq!(get(&app, "/foo").await.0, 404);
    }

    #[tokio::test]
    async fn blocks_in_each_format() {
        let (server, _dir, genesis) = server();
        let raw = call(&server, "getblock", vec![json!(genesis), json!(false)]).unwrap();
        let raw = raw.as_str().unwrap();
        let on = router(server.clone(), true);

        let (status, ctype, body) = get(&on, &format!("/rest/block/{genesis}.hex")).await;
        assert_eq!((status, ctype.as_str()), (200, "text/plain"));
        assert_eq!(body, format!("{raw}\n").into_bytes());

        let (status, ctype, body) = get(&on, &format!("/rest/block/{genesis}.bin")).await;
        assert_eq!((status, ctype.as_str()), (200, "application/octet-stream"));
        assert_eq!(body, hex::decode(raw).unwrap());

        // without tx details: getblock's reply with blockToJSON's members, as
        // divid writes it; with them: each tx decoded, TxToJSON's members only
        let plain = only(
            call(&server, "getblock", vec![json!(genesis), json!(true)]).unwrap(),
            BLOCK_FIELDS,
        );
        let (status, ctype, body) =
            get(&on, &format!("/rest/block/notxdetails/{genesis}.json")).await;
        assert_eq!((status, ctype.as_str()), (200, "application/json"));
        assert_eq!(body, format!("{}\n", write_core_json(&plain)).into_bytes());
        assert!(plain.get("mediantime").is_none() && plain.get("hash").is_some());

        let (_, _, body) = get(&on, &format!("/rest/block/{genesis}.json")).await;
        let got: Value = serde_json::from_slice(&body).unwrap();
        let txs = got["tx"].as_array().unwrap();
        assert_eq!(txs.len(), plain["tx"].as_array().unwrap().len());
        assert_eq!(txs[0]["txid"], plain["tx"][0]);
        for tx in txs {
            for key in tx.as_object().unwrap().keys() {
                assert!(TX_FIELDS.contains(&key.as_str()), "{key}");
            }
            assert!(
                tx.get("blockhash").is_none(),
                "TxToJSON(tx, 0) has no block fields"
            );
            for out in tx["vout"].as_array().unwrap() {
                for key in out.as_object().unwrap().keys() {
                    assert!(
                        ["value", "n", "scriptPubKey"].contains(&key.as_str()),
                        "{key}"
                    );
                }
            }
        }
        let keys: Vec<&String> = got.as_object().unwrap().keys().collect();
        let plain_keys: Vec<&String> = plain.as_object().unwrap().keys().collect();
        assert_eq!(keys, plain_keys);
    }

    /// On the RPC port: REST without credentials and only when on, beside
    /// integration's HTTP rules (405 for other methods, 404 for other paths);
    /// a 200 keeps the connection, an error closes it, as divid
    #[tokio::test]
    async fn on_the_rpc_port_as_divid() {
        let (server, _dir, genesis) = server();
        let config = |rest| crate::server::RpcConfig {
            username: Some("u".into()),
            password: Some("p".into()),
            rest,
            ..Default::default()
        };
        let on = crate::server::create_router_with_auth(server.clone(), &config(true));
        let off = crate::server::create_router_with_auth(server, &config(false));
        let path = format!("/rest/block/{genesis}.hex");

        let (status, head, _) = exchange(&on, "GET", &path, "", "").await;
        assert_eq!(status, 200);
        assert_eq!(header_of(&head, "connection"), "keep-alive");
        let (status, head, _) = exchange(&on, "POST", &path, "", "Connection: close\r\n").await;
        assert_eq!(status, 200);
        assert_eq!(header_of(&head, "connection"), "close");
        let (status, head, body) = exchange(&on, "GET", "/rest/tx/xyz.json", "", "").await;
        assert_eq!((status, body), (400, b"Invalid hash: xyz\r\n".to_vec()));
        assert_eq!(header_of(&head, "connection"), "close");

        for (router, path) in [(&on, "/foo".to_string()), (&off, path.clone())] {
            let (status, head, body) = exchange(router, "GET", &path, "", "").await;
            assert_eq!((status, body), (404, b"Not Found".to_vec()), "{path}");
            assert_eq!(header_of(&head, "content-type"), "text/plain");
            assert_eq!(header_of(&head, "connection"), "close");
        }
        let (status, _, _) = exchange(&on, "PUT", &path, "", "").await;
        assert_eq!(status, 405);
        // the JSON-RPC path still asks for credentials
        let (status, _, _) = exchange(&on, "POST", "/", "{}", "Connection: close\r\n").await;
        assert_eq!(status, 401);
    }
}
