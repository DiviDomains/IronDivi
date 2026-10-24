// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `help` must cover exactly the methods the dispatcher accepts.

use divi_rpc::{Params, Request, RequestId, Response, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams};
use std::collections::BTreeSet;
use std::sync::Arc;

fn server() -> (RpcServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let chain = Arc::new(Chain::new(db, ChainParams::default()).unwrap());
    (RpcServer::new(chain), dir)
}

fn call(server: &RpcServer, method: &str, params: Vec<serde_json::Value>) -> Response {
    server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    })
}

/// Every method name the dispatcher matches on, read from the source of `dispatch`.
fn dispatched_methods() -> BTreeSet<String> {
    let src = include_str!("../src/server.rs");
    let start = src.find("fn dispatch(&self").expect("dispatch");
    let end = start + src[start..].find("fn help(&self").expect("help");
    let mut names = BTreeSet::new();
    for line in src[start..end].lines() {
        // Match arms: `"a" => ...`, `"a" | "b" => ...`, or one name per line in a `|` chain
        let mut rest = line.trim_start().trim_start_matches('|').trim_start();
        while let Some(r) = rest.strip_prefix('"') {
            let Some(q) = r.find('"') else { break };
            let after = r[q + 1..].trim_start();
            if !(after.is_empty() || after.starts_with("=>") || after.starts_with('|')) {
                break;
            }
            names.insert(r[..q].to_string());
            rest = after.trim_start_matches('|').trim_start();
        }
    }
    names
}

/// Every method name in the call list `help` is built from (the `methods` of
/// `help` in the source)
fn listed_methods() -> BTreeSet<String> {
    let src = include_str!("../src/server.rs");
    let start = src.find("let methods = vec![").expect("methods");
    let end = start + src[start..].find("];").expect("end of methods");
    src[start..end]
        .lines()
        .skip(1)
        .map(|l| l.trim().trim_end_matches(',').trim_matches('"'))
        .filter(|l| !l.is_empty() && !l.starts_with("=="))
        .map(String::from)
        .collect()
}

#[test]
fn help_covers_every_dispatched_method() {
    let (server, _dir) = server();
    let dispatched = dispatched_methods();
    assert!(
        dispatched.len() > 100,
        "parsed {} methods",
        dispatched.len()
    );

    // The parse is right: each name reaches a handler, not "Method not found"
    for m in &dispatched {
        if m == "stop" {
            continue; // reaching the handler would ask the node to shut down
        }
        // (a regtest-only method off regtest is "Method disabled", -32601 too)
        if let Some(e) = call(&server, m, vec![]).error {
            // -32601 here is never "Method not found": either a call that
            // works on regtest only ("Method disabled: ...") or a wallet call
            // on a node without a wallet (rpcserver.cpp:1043-1047)
            assert!(
                e.code != -32601
                    || e.message.starts_with("Method disabled")
                    || e.message == "Method unavailable due to manually disabled wallet",
                "{m} is not dispatched"
            );
        }
    }

    // `help` lists these as Divi Core lists them (usage lines, Core's
    // categories), so the names are read from the list it is built from
    let listed = listed_methods();
    assert!(call(&server, "help", vec![]).result.is_some(), "help");

    let unlisted: Vec<_> = dispatched.difference(&listed).collect();
    assert!(unlisted.is_empty(), "missing from `help`: {unlisted:?}");
    let extra: Vec<_> = listed.difference(&dispatched).collect();
    assert!(extra.is_empty(), "`help` lists unknown methods: {extra:?}");

    let mut no_text = Vec::new();
    for m in &dispatched {
        let r = call(&server, "help", vec![serde_json::json!(m)]);
        match r.result.as_ref().and_then(|v| v.as_str()) {
            Some(text) if text.starts_with(m.as_str()) => {}
            _ => no_text.push(m.clone()),
        }
    }
    assert!(
        no_text.is_empty(),
        "`help <method>` has no text for: {no_text:?}"
    );
}
