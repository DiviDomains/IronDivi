// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The coin view's replies in the order Divi Core 3.0.0 writes them
//! (scripts/coin-view compares them on live nodes): members in insertion
//! order (json_spirit Object), the mempool in txid order (std::map), and the
//! outputs of createrawtransaction in the order given.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Node {
    chain: Arc<Chain>,
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
    let server = RpcServer::new(chain.clone());
    Node {
        chain,
        server,
        _dir: dir,
    }
}

impl Node {
    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        let r = self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        });
        assert!(
            r.error.is_none(),
            "{method}: {:?}",
            r.error.map(|e| e.message)
        );
        r.result.unwrap()
    }

    /// Mine a block whose coinbase pays 1250 DIVI to a key nobody holds
    fn mine(&self) -> Transaction {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * COIN),
                Script::new_p2pkh(Hash160::from_bytes([0x42; 20]).as_bytes()),
            )],
            lock_time: 0,
        });
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        let coinbase = block.transactions[0].clone();
        self.chain.accept_block(block).unwrap();
        self.server.set_height(height);
        coinbase
    }
}

fn keys(v: &Value) -> Vec<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

/// gettxout: bestblock, confirmations, value, scriptPubKey, version, coinbase
/// (rpcblockchain.cpp:389-399), then irondivid's coinstake; the scriptPubKey
/// as ScriptPubKeyToJSON writes it: asm, hex, reqSigs, type, addresses
/// (JsonTxHelpers.cpp:15-37)
#[test]
fn gettxout_members_are_in_cores_order() {
    let n = node();
    let coinbase = n.mine();
    let out = n.ok(
        "gettxout",
        vec![json!(coinbase.txid().to_string()), json!(0)],
    );
    assert_eq!(
        keys(&out),
        [
            "bestblock",
            "confirmations",
            "value",
            "scriptPubKey",
            "version",
            "coinbase",
            "coinstake"
        ]
    );
    assert_eq!(
        keys(&out["scriptPubKey"]),
        ["asm", "hex", "reqSigs", "type", "addresses"]
    );
}

/// gettxoutsetinfo: height, bestblock, transactions, txouts,
/// bytes_serialized, hash_serialized, total_amount (rpcblockchain.cpp:319-325),
/// then irondivid's bogosize
#[test]
fn gettxoutsetinfo_members_are_in_cores_order() {
    let n = node();
    n.mine();
    let info = n.ok("gettxoutsetinfo", vec![]);
    assert_eq!(
        keys(&info),
        [
            "height",
            "bestblock",
            "transactions",
            "txouts",
            "bytes_serialized",
            "hash_serialized",
            "total_amount",
            "bogosize"
        ]
    );
}

/// A pool whose transactions come out in the order given
struct Pool(Vec<Hash256>);

impl divi_rpc::blockchain::MempoolProvider for Pool {
    fn get_txids(&self) -> Vec<Hash256> {
        self.0.clone()
    }
    fn prioritise_transaction(&self, _: &Hash256, _: f64, _: i64) -> bool {
        false
    }
}

/// getrawmempool lists the txids in the order of divid's std::map<uint256>:
/// the order of the txids as shown (rpcblockchain.cpp:119, :143,
/// txmempool.cpp:283-291, uint256.cpp:139-147)
#[test]
fn getrawmempool_is_in_txid_order() {
    let n = node();
    let ids: Vec<Hash256> = ["99", "28", "5e", "a0"]
        .iter()
        .map(|first| Hash256::from_hex(&format!("{first}{}", "11".repeat(31))).unwrap())
        .collect();
    n.server.set_mempool(Arc::new(Pool(ids.clone())));
    let mut shown: Vec<String> = ids.iter().map(|h| h.to_string()).collect();
    shown.sort();
    assert_ne!(shown, ids.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    assert_eq!(n.ok("getrawmempool", vec![]), json!(shown));
}

/// createrawtransaction writes the outputs in the order the object gives them
/// (rpcrawtransaction.cpp:400-410)
#[test]
fn createrawtransaction_keeps_the_order_of_the_outputs() {
    let n = node();
    let coinbase = n.mine();
    // Two regtest addresses, the first given after the second in name order
    let address = |byte: u8| {
        divi_wallet::Address::from_pubkey_hash(
            Hash160::from_bytes([byte; 20]),
            divi_wallet::Network::Regtest,
        )
        .to_base58()
    };
    let (mut a, mut b) = (address(1), address(2));
    if a < b {
        std::mem::swap(&mut a, &mut b);
    }
    let body = format!(
        r#"[[{{"txid": "{}", "vout": 0}}], {{"{a}": 1, "{b}": 2}}]"#,
        coinbase.txid()
    );
    let params: Vec<Value> = serde_json::from_str(&body).unwrap();
    let hex = n.ok("createrawtransaction", params);
    let decoded = n.ok("decoderawtransaction", vec![hex]);
    assert_eq!(decoded["vout"][0]["scriptPubKey"]["addresses"][0], a);
    assert_eq!(decoded["vout"][1]["scriptPubKey"]["addresses"][0], b);
}
