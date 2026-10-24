// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Mining and mempool RPC replies as Divi Core 3.0.0's divid gives them
//! (rpcmining.cpp, rpcblockchain.cpp), checked against divid with
//! scripts/mining-replies/run.sh.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcError, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

fn server() -> (RpcServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    (RpcServer::new(chain), dir)
}

fn call(server: &RpcServer, method: &str, params: Vec<Value>) -> Response {
    server.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: method.to_string(),
        params: Params::Array(params),
    })
}

fn error(server: &RpcServer, method: &str, params: Vec<Value>) -> RpcError {
    let reply = call(server, method, params.clone());
    reply
        .error
        .unwrap_or_else(|| panic!("{method} {params:?} answered {:?}", reply.result))
}

/// A wrong number of arguments is answered with the method's help as a -1
/// error, before any argument is read (rpcmining.cpp:54, :123, :227, :253;
/// rpcblockchain.cpp:82, :557)
#[test]
fn wrong_argument_counts_answer_with_the_help() {
    let (server, _dir) = server();
    let txid = json!("11".repeat(32));
    for (method, params) in [
        ("getmininginfo", vec![json!("x")]),
        ("getmempoolinfo", vec![json!(1)]),
        ("getrawmempool", vec![json!(true), json!(1)]),
        ("prioritisetransaction", vec![txid.clone()]),
        ("prioritisetransaction", vec![txid.clone(), json!(0.0)]),
        (
            "prioritisetransaction",
            vec![txid, json!(0.0), json!(1), json!(1)],
        ),
        ("setgenerate", vec![]),
        ("setgenerate", vec![json!(1), json!(1)]),
        ("generateblock", vec![json!({}), json!(1)]),
    ] {
        let e = error(&server, method, params.clone());
        assert_eq!(e.code, -1, "{method} {params:?}: {}", e.message);
        let usage = e.message.lines().next().unwrap_or_default();
        assert!(
            usage.starts_with(method) && e.message.contains('\n'),
            "{method} {params:?}: {}",
            e.message
        );
    }
    // Core's usage line, which names the argument
    let e = error(&server, "getrawmempool", vec![json!(1), json!(2)]);
    assert!(
        e.message.starts_with("getrawmempool ( verbose )\n"),
        "{}",
        e.message
    );
}
