// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Replies whose members and items come in the order Divi Core 3.0.0 writes
//! them (the replies scripts compare it on live nodes): an object's members in
//! the order its handler pushes them (json_spirit Object), irondivid's own
//! members after them, and lists in the order of the map divid takes them from.

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
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType, SearchIndex};
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Node {
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    server: RpcServer,
    _dir: tempfile::TempDir,
}

/// A regtest node with the transaction, address and spent indexes and a wallet
fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let mut chain = Chain::new(
        db.clone(),
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
    chain.enable_search_index(Arc::new(SearchIndex::new(db, true, true)));
    let chain = Arc::new(chain);
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain.clone(), wallet.clone());
    Node {
        chain,
        wallet,
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

    /// Mine a block with `txs` whose coinbase pays 1250 DIVI to `pay_to`; the
    /// wallet scans it
    fn mine(&self, txs: Vec<Transaction>, pay_to: &Address) -> Transaction {
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
                Script::new_p2pkh(pay_to.hash.as_bytes()),
            )],
            lock_time: 0,
        });
        block.transactions.extend(txs);
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        let time = block.header.time;
        let txs = block.transactions.clone();
        let hash = self.chain.accept_block(block).unwrap().hash;
        self.wallet.scan_block(hash, height, time, &txs);
        self.server.set_height(height);
        txs[0].clone()
    }
}

fn nobody() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

fn keys(v: &Value) -> Vec<&str> {
    v.as_object()
        .unwrap_or_else(|| panic!("not an object: {v}"))
        .keys()
        .map(String::as_str)
        .collect()
}

/// getblock: blockToJSON's members (JsonBlockHelpers.cpp:38-77), then
/// irondivid's mediantime and nTx
#[test]
fn getblock_members_are_in_cores_order() {
    let n = node();
    n.mine(vec![], &nobody());
    n.mine(vec![], &nobody());
    let hash = n.ok("getblockhash", vec![json!(1)]);
    assert_eq!(
        keys(&n.ok("getblock", vec![hash])),
        [
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
            "mediantime",
            "nTx"
        ]
    );
}

/// getblockheader: blockHeaderToJSON's members (JsonBlockHelpers.cpp:80-91),
/// then irondivid's own
#[test]
fn getblockheader_members_are_in_cores_order() {
    let n = node();
    n.mine(vec![], &nobody());
    n.mine(vec![], &nobody());
    let hash = n.ok("getblockhash", vec![json!(1)]);
    assert_eq!(
        keys(&n.ok("getblockheader", vec![hash])),
        [
            "version",
            "previousblockhash",
            "merkleroot",
            "time",
            "bits",
            "nonce",
            "hash",
            "confirmations",
            "height",
            "mediantime",
            "difficulty",
            "chainwork",
            "nTx",
            "nextblockhash"
        ]
    );
}
