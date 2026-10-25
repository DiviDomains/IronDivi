// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! A masternode set up and started on this node's wallet is listed as Divi
//! Core lists it: listmasternodes and getmasternodecount read the
//! masternodes the node took (its own broadcast first), in Core's form, and a
//! spent collateral shows once the masternodes are checked.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::mn_list::MasternodeList;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Node {
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    server: RpcServer,
    sent: Arc<Mutex<Vec<Transaction>>>,
    dir: tempfile::TempDir,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let mut chain = Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
    let chain = Arc::new(chain);
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain.clone(), wallet.clone());
    let list = Arc::new(MasternodeList::new());
    list.set_path(dir.path().join("masternodes.list"));
    server.set_masternode_list(list.clone());
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sink = sent.clone();
    server
        .wallet()
        .set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            sink.lock().push(tx);
            Ok(txid)
        }));
    Node {
        chain,
        wallet,
        server,
        sent,
        dir,
    }
}

impl Node {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, (i32, String)> {
        let r = self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        });
        match r.error {
            Some(e) => Err((e.code, e.message)),
            None => Ok(r.result.unwrap()),
        }
    }

    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        self.call(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    /// Mine a block with the transactions sent so far; the coinbase pays the wallet
    fn mine(&self) {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        let to = self.wallet.new_receiving_address().unwrap();
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * COIN),
                Script::new_p2pkh(to.hash.as_bytes()),
            )],
            lock_time: 0,
        });
        block.transactions.extend(self.sent.lock().drain(..));
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
    }

    fn mine_n(&self, n: usize) {
        for _ in 0..n {
            self.mine();
        }
    }
}

/// allocatefunds, setupmasternode and signmnbroadcast for `alias`: the
/// collateral (txhash, vout, address) and the signed broadcast
fn set_up(n: &Node, alias: &str, confirmations: usize) -> (String, u32, String, String) {
    let alloc = n.ok(
        "allocatefunds",
        vec![json!("masternode"), json!(alias), json!("copper")],
    );
    let txhash = alloc["txhash"].as_str().unwrap().to_string();
    let vout = alloc["vout"].as_u64().unwrap() as u32;
    n.mine_n(confirmations);
    let tx = n.ok("getrawtransaction", vec![json!(txhash), json!(1)]);
    let address = tx["vout"][vout as usize]["scriptPubKey"]["addresses"][0]
        .as_str()
        .unwrap()
        .to_string();
    let pubkey = n.ok("validateaddress", vec![json!(address)])["pubkey"].clone();
    let setup = n.ok(
        "setupmasternode",
        vec![
            json!(alias),
            json!(txhash),
            json!(vout.to_string()),
            pubkey,
            json!("127.0.0.2:53704"),
        ],
    );
    let signed = n.ok("signmnbroadcast", vec![setup["broadcast_data"].clone()]);
    (
        txhash,
        vout,
        address,
        signed["broadcast_data"].as_str().unwrap().to_string(),
    )
}

fn funded() -> Node {
    let n = node();
    n.mine_n(25);
    n
}

/// broadcaststartmasternode takes the broadcast into the node's own list
/// before relaying it (RpcMasternodeFeatures.cpp:80-121), and listmasternodes
/// gives Divi Core's fields (rpcmasternode.cpp:263-325): a loopback address
/// is no network (""), the address is the collateral's, the tier by name
#[test]
fn started_masternode_is_listed_as_divid_lists_it() {
    let n = funded();
    let (txhash, vout, address, signed) = set_up(&n, "mn1", 16);
    assert_eq!(n.ok("listmasternodes", vec![]), json!([]));
    assert_eq!(
        n.ok("broadcaststartmasternode", vec![json!(signed)]),
        json!({"status": "success"})
    );
    let listed = n.ok("listmasternodes", vec![]);
    let entry = &listed[0];
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    for (field, value) in [
        ("network", json!("")),
        ("txhash", json!(txhash)),
        ("outidx", json!(vout)),
        ("status", json!("ENABLED")),
        ("addr", json!(address)),
        ("version", json!(70915)),
        ("lastpaid", json!(0)),
        ("tier", json!("COPPER")),
    ] {
        assert_eq!(entry[field], value, "{field}: {listed}");
    }
    assert!(entry["lastseen"].as_i64().unwrap() > 0);
    // Filters on txhash, status or address (RpcMasternodeFeatures.cpp:293-301)
    assert_eq!(n.ok("listmasternodes", vec![json!("ENABLED")]), listed);
    assert_eq!(n.ok("listmasternodes", vec![json!(&address[2..9])]), listed);
    assert_eq!(n.ok("listmasternodes", vec![json!("nomatch")]), json!([]));
    // Below height 101 there is no block to score with, so no queue
    let count = n.ok("getmasternodecount", vec![]);
    for (field, value) in [
        ("total", 1),
        ("enabled", 1),
        ("obfcompat", 1),
        ("inqueue", 0),
        ("ipv4", 0),
    ] {
        assert_eq!(count[field], json!(value), "{field}: {count}");
    }
    // The list is kept in the datadir and read back, as mncache.dat
    let again = MasternodeList::new();
    again.set_path(n.dir.path().join("masternodes.list"));
    assert_eq!(again.list_json(&n.chain, None), listed);
}

/// A broadcast whose collateral has fewer than 15 confirmations is refused
/// (CheckInputsAndAdd, masternode.h:16): status failed, nothing listed
#[test]
fn broadcast_needs_fifteen_confirmations() {
    let n = funded();
    let (_, _, _, signed) = set_up(&n, "mn1", 10);
    assert_eq!(
        n.ok("broadcaststartmasternode", vec![json!(signed)]),
        json!({"status": "failed", "error": "Error processing broadcast"})
    );
    assert_eq!(n.ok("listmasternodes", vec![]), json!([]));
}

/// A spent collateral shows as VIN_SPENT once the masternodes are checked:
/// listmasternodes shows the last check's state, getmasternodecount checks
/// (masternodeman.cpp:152-180, RpcMasternodeFeatures.cpp:326-422)
#[test]
fn spent_collateral_shows_after_a_check() {
    let n = funded();
    let (txhash, vout, _, signed) = set_up(&n, "mn1", 16);
    n.ok("broadcaststartmasternode", vec![json!(signed)]);
    let hex = n.ok("getrawtransaction", vec![json!(txhash)]);
    let prev: Transaction =
        divi_primitives::serialize::deserialize(&hex::decode(hex.as_str().unwrap()).unwrap())
            .unwrap();
    let to = n.wallet.new_receiving_address().unwrap();
    let (mut tx, prevs) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(prev.txid(), vout),
            prev.vout[vout as usize].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(99 * COIN), &to)
        .build();
    TransactionSigner::new(n.wallet.keystore())
        .sign_all_inputs(&mut tx, &prevs)
        .unwrap();
    n.sent.lock().push(tx);
    n.mine();
    assert_eq!(
        n.ok("listmasternodes", vec![])[0]["status"],
        json!("ENABLED")
    );
    let count = n.ok("getmasternodecount", vec![]);
    assert_eq!(
        (count["total"].clone(), count["enabled"].clone()),
        (json!(1), json!(0))
    );
    assert_eq!(
        n.ok("listmasternodes", vec![])[0]["status"],
        json!("VIN_SPENT")
    );
}
