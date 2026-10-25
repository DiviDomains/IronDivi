// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet cases of Divi Core 3.0.0's divid that no other test compares,
//! checked against divid with scripts/wallet-gaps-2/run.sh.

use divi_primitives::hash::Hash160;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcError, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

struct Node {
    server: RpcServer,
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
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    Node {
        server: RpcServer::with_wallet(chain, wallet),
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

    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        let reply = self.call(method, params.clone());
        assert!(
            reply.error.is_none(),
            "{method} {params:?}: {:?}",
            reply.error
        );
        reply.result.expect("result")
    }
}

/// A P2PKH script in hex is watched, but its label is not stored: only an
/// address is put in the address book (rpcdump.cpp:126-128, :150-151)
#[test]
fn a_hex_script_is_watched_without_its_label() {
    let n = node();
    let hash = [0xab; 20];
    let address =
        Address::from_pubkey_hash(Hash160::from_bytes(hash), Network::Regtest).to_string();
    let script = format!("76a914{}88ac", hex::encode(hash));
    assert_eq!(
        n.ok(
            "importaddress",
            vec![json!(script), json!("hexlabel"), json!(false)]
        ),
        Value::Null
    );
    let info = n.ok("validateaddress", vec![json!(address)]);
    assert_eq!(info["iswatchonly"], json!(true), "{info}");
    assert!(info["account"].is_null(), "{info}");
    assert_eq!(
        n.ok("getaddressesbyaccount", vec![json!("hexlabel")]),
        json!([])
    );
    // Imported again as an address, it takes the label
    assert_eq!(
        n.ok(
            "importaddress",
            vec![json!(address), json!("named"), json!(false)]
        ),
        Value::Null
    );
    assert_eq!(
        n.ok("getaddressesbyaccount", vec![json!("named")]),
        json!([address])
    );
}

/// getcoinavailability reads its verbose flag with get_bool whenever it is
/// given, so null is a type error too (rpcwallet.cpp:828)
#[test]
fn getcoinavailability_refuses_a_null_flag() {
    let n = node();
    let e = n.err("getcoinavailability", vec![Value::Null]);
    assert_eq!(
        (e.code, e.message.as_str()),
        (-1, "value is type null, expected bool")
    );
    assert!(n.ok("getcoinavailability", vec![json!(false)]).is_object());
}
