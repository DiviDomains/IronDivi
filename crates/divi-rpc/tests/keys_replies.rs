// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Key import/export and wallet-upkeep RPC replies as Divi Core 3.0.0's divid
//! gives them (rpcdump.cpp, rpcwallet.cpp), checked against divid with
//! scripts/keys-replies/run.sh.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcError, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

struct Node {
    server: RpcServer,
    wallet: Arc<WalletDb>,
    _dir: tempfile::TempDir,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    Node {
        server: RpcServer::with_wallet(chain, wallet.clone()),
        wallet,
        _dir: dir,
    }
}

impl Node {
    fn call(&self, method: &str, params: Vec<Value>) -> Response {
        self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        })
    }

    fn err(&self, method: &str, params: Vec<Value>) -> RpcError {
        let reply = self.call(method, params.clone());
        reply
            .error
            .unwrap_or_else(|| panic!("{method} {params:?} answered {:?}", reply.result))
    }
}

/// A wrong number of arguments is answered with the call's help as a -1 error,
/// before the wallet or any argument is looked at (rpcdump.cpp:43, :107, :172,
/// :251, :297; rpcwallet.cpp:2527, :2546)
#[test]
fn wrong_argument_counts_answer_with_the_help() {
    let n = node();
    let addr = n.wallet.new_receiving_address().unwrap().to_string();
    for (method, params) in [
        ("importprivkey", vec![]),
        (
            "importprivkey",
            vec![json!("k"), json!("l"), json!(true), json!(1)],
        ),
        ("importaddress", vec![]),
        (
            "importaddress",
            vec![json!(addr), json!("l"), json!(true), json!(1)],
        ),
        ("dumpprivkey", vec![]),
        ("dumpprivkey", vec![json!(addr), json!(1)]),
        ("backupwallet", vec![]),
        ("keypoolrefill", vec![json!(5), json!(5)]),
        ("bip38paperwallet", vec![]),
        ("bip38decrypt", vec![json!("k")]),
    ] {
        let e = n.err(method, params.clone());
        assert_eq!(e.code, -1, "{method} {params:?}: {}", e.message);
        assert!(
            e.message.starts_with(method) && e.message.contains('\n'),
            "{method} {params:?}: {}",
            e.message
        );
    }
}
