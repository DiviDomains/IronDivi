// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Mining and mempool RPC replies as Divi Core 3.0.0's divid gives them
//! (rpcmining.cpp, rpcblockchain.cpp), checked against divid with
//! scripts/mining-replies/run.sh.

use divi_primitives::hash::Hash256;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcError, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

fn server() -> (RpcServer, tempfile::TempDir) {
    server_on(NetworkType::Regtest)
}

fn server_on(network: NetworkType) -> (RpcServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain =
        Arc::new(Chain::new(db, ChainParams::for_network(network, ChainMode::Divi)).unwrap());
    // setgenerate and generateblock need a wallet: without one divid answers
    // -32601 before their own checks run (rpcserver.cpp:368-369, :1043-1047)
    let wallet = Arc::new(divi_wallet::WalletDb::with_hd_wallet(
        divi_wallet::Network::Regtest,
        divi_wallet::HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    (RpcServer::with_wallet(chain, wallet), dir)
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

fn result(server: &RpcServer, method: &str, params: Vec<Value>) -> Value {
    let reply = call(server, method, params);
    assert!(reply.error.is_none(), "{method}: {:?}", reply.error);
    reply.result.expect("result")
}

/// getmininginfo has divid's members only (rpcmining.cpp:229-236)
#[test]
fn getmininginfo_has_divids_members() {
    let (server, _dir) = server();
    let info = result(&server, "getmininginfo", vec![]);
    let mut keys: Vec<&str> = info
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "blocks",
            "chain",
            "difficulty",
            "errors",
            "pooledtx",
            "testnet"
        ],
        "{info}"
    );
    assert_eq!(info["chain"], "regtest");
    assert_eq!(info["testnet"], false);
    assert_eq!(info["pooledtx"], 0);
}

/// getrawmempool's verbose argument is a JSON boolean, as json_spirit's
/// get_bool takes it (rpcblockchain.cpp:110-112)
#[test]
fn getrawmempool_verbose_is_a_boolean() {
    let (server, _dir) = server();
    assert_eq!(result(&server, "getrawmempool", vec![]), json!([]));
    assert_eq!(
        result(&server, "getrawmempool", vec![json!(false)]),
        json!([])
    );
    for (arg, type_name) in [
        (json!(1), "int"),
        (json!("true"), "str"),
        (json!(null), "null"),
        (json!(1.5), "real"),
    ] {
        let e = error(&server, "getrawmempool", vec![arg.clone()]);
        assert_eq!(e.code, -1, "{arg}");
        assert_eq!(
            e.message,
            format!("value is type {type_name}, expected bool")
        );
    }
}

/// A pool that records what prioritisetransaction hands it
#[derive(Default)]
struct Deltas(Mutex<Vec<(Hash256, f64, i64)>>);

impl divi_rpc::blockchain::MempoolProvider for Deltas {
    fn get_txids(&self) -> Vec<Hash256> {
        Vec::new()
    }
    fn prioritise_transaction(&self, txid: &Hash256, priority: f64, fee: i64) -> bool {
        self.0.lock().push((*txid, priority, fee));
        true
    }
}

/// prioritisetransaction as Divi Core reads it (rpcmining.cpp:251-276): the
/// txid through ParseHashStr, the priority delta never read, the fee delta an
/// integer; the answer is true, for a transaction not in the pool as well
#[test]
fn prioritisetransaction_reads_its_arguments_as_divid() {
    let (server, _dir) = server();
    let pool = Arc::new(Deltas::default());
    server.set_mempool(pool.clone());
    let txid = "ab".repeat(32);

    // The priority delta may be anything: Core does not read it
    for priority in [json!(0.0), json!("x"), json!(null), json!([1])] {
        let r = result(
            &server,
            "prioritisetransaction",
            vec![json!(txid), priority, json!(1000)],
        );
        assert_eq!(r, json!(true));
    }
    // A short hex txid is padded as uint256::SetHex pads it
    result(
        &server,
        "prioritisetransaction",
        vec![json!("aa"), json!(0), json!(-5)],
    );
    let calls = pool.0.lock().clone();
    assert_eq!(calls.len(), 5);
    assert!(calls[..4]
        .iter()
        .all(|(t, _, fee)| t.to_string() == txid && *fee == 1000));
    assert_eq!(calls[4].0.to_string(), format!("{}aa", "0".repeat(62)));
    assert_eq!(calls[4].2, -5);

    for (args, message) in [
        (
            vec![json!("zz"), json!(0), json!(1)],
            "txid must be hexadecimal string (not 'zz')",
        ),
        (
            vec![json!("abc"), json!(0), json!(1)],
            "txid must be hexadecimal string (not 'abc')",
        ),
        (
            vec![json!(""), json!(0), json!(1)],
            "txid must be hexadecimal string (not '')",
        ),
        (
            vec![json!(1), json!(0), json!(1)],
            "value is type int, expected str",
        ),
        (
            vec![json!(txid), json!(0), json!("1000")],
            "value is type str, expected int",
        ),
        (
            vec![json!(txid), json!(0), json!(1.5)],
            "value is type real, expected int",
        ),
    ] {
        let e = error(&server, "prioritisetransaction", args.clone());
        assert_eq!((e.code, e.message.as_str()), (-1, message), "{args:?}");
    }
    assert_eq!(pool.0.lock().len(), 5, "a refused call changes nothing");
}

/// A coinstake (vin[0] not null, vout[0] empty, two outputs) paying OP_TRUE
const COINSTAKE: &str = concat!(
    "01000000",
    "01",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "00000000",
    "00",
    "ffffffff",
    "02",
    "0000000000000000",
    "00",
    "00e1f50500000000",
    "01",
    "51",
    "00000000"
);

/// generateblock checks its options before making a block, as Divi Core
/// (rpcmining.cpp:126-176): types in name order (-3), each extratx a string
/// (-1) that decodes (-22), the coinstake decoded and a coinstake (-8)
#[test]
fn generateblock_checks_its_options_as_divid() {
    let (server, _dir) = server();
    let plain_tx = COINSTAKE.replacen("02000000000000000000", "01000000000000000000", 1);
    for (options, code, message) in [
        (json!("x"), -3, "Expected type obj, got str".to_string()),
        (
            json!({"extratx": "x"}),
            -3,
            "Expected type array for extratx, got str".into(),
        ),
        (
            json!({"ignoreMempool": 1}),
            -3,
            "Expected type bool for ignoreMempool, got int".into(),
        ),
        (
            json!({"blockBitsShift": 1.5}),
            -3,
            "Expected type int for blockBitsShift, got real".into(),
        ),
        (
            json!({"coinstake": 1}),
            -3,
            "Expected type str for coinstake, got int".into(),
        ),
        // Name order: blockBitsShift is checked before extratx
        (
            json!({"extratx": "x", "blockBitsShift": "y"}),
            -3,
            "Expected type int for blockBitsShift, got str".into(),
        ),
        (
            json!({"extratx": [1]}),
            -1,
            "value is type int, expected str".into(),
        ),
        (json!({"extratx": ["zz"]}), -22, "TX decode failed".into()),
        (json!({"extratx": [""]}), -22, "TX decode failed".into()),
        (json!({"coinstake": "zz"}), -22, "TX decode failed".into()),
        (
            json!({"coinstake": plain_tx}),
            -8,
            "TX is not a coinstake".into(),
        ),
    ] {
        let e = error(&server, "generateblock", vec![options.clone()]);
        assert_eq!((e.code, e.message), (code, message), "{options}");
    }
    // Options that pass the checks reach the block maker (none here)
    let e = error(
        &server,
        "generateblock",
        vec![json!({"coinstake": COINSTAKE})],
    );
    assert_eq!(e.message, "generateblock needs a wallet to mine to");
}
