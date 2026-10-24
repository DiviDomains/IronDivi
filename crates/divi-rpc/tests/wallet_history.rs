// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet history as Divi Core 3.0.0's rpcwallet.cpp gives it: one entry per
//! output sent or received with its address, account and vout
//! (ParseTransactionDetails, GetAmounts), the transaction fields of
//! WalletTxToJSON, and listtransactions, listsinceblock and gettransaction
//! arguments and errors.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType, SearchIndex};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
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

    fn err(&self, method: &str, params: Vec<Value>) -> (i32, String) {
        match self.call(method, params) {
            Err(e) => e,
            Ok(v) => panic!("{method} answered {v}, expected an error"),
        }
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

/// A node whose wallet holds `values` (satoshis) on labelled addresses, paid
/// by one funder transaction, plus the funder and the submitted sends
struct Funded {
    n: Node,
    funder: Arc<WalletDb>,
    submitted: Arc<Mutex<Vec<Transaction>>>,
    addresses: Vec<Address>,
    funding: Transaction,
}

impl Funded {
    fn wallet(&self) -> &WalletDb {
        &self.n.wallet
    }
}

fn funded(values: &[i64]) -> Funded {
    let n = node();
    let submitted = Arc::new(Mutex::new(Vec::new()));
    let sink = submitted.clone();
    n.server
        .wallet()
        .set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            sink.lock().push(tx);
            Ok(txid)
        }));
    let funder = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let cb_addr = funder.new_receiving_address().unwrap();
    let coinbase = n.mine(vec![], &cb_addr);
    for _ in 0..20 {
        n.mine(vec![], &nobody());
    }
    let mut builder = TransactionBuilder::new().add_input(
        OutPoint::new(coinbase.txid(), 0),
        coinbase.vout[0].script_pubkey.clone(),
    );
    let mut addresses = Vec::new();
    for (i, value) in values.iter().enumerate() {
        let addr: Address = Address::from_base58(
            n.ok("getnewaddress", vec![json!(format!("acct{i}"))])
                .as_str()
                .unwrap(),
        )
        .unwrap();
        builder = builder.add_output_to_address(Amount::from_sat(*value), &addr);
        addresses.push(addr);
    }
    let rest = 1250 * COIN - values.iter().sum::<i64>() - COIN / 100;
    builder = builder.add_output_to_address(Amount::from_sat(rest), &nobody());
    let (mut tx, prev) = builder.build();
    TransactionSigner::new(funder.keystore())
        .sign_all_inputs(&mut tx, &prev)
        .unwrap();
    n.mine(vec![tx.clone()], &nobody());
    Funded {
        n,
        funder,
        submitted,
        addresses,
        funding: tx,
    }
}

/// A payment to two wallet addresses is two "receive" entries, each with its
/// address, account and vout, and Core's transaction fields
#[test]
fn receive_is_one_entry_per_output() {
    let f = funded(&[10 * COIN, 5 * COIN]);
    let list = f.n.ok("listtransactions", vec![]);
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 2, "{list:?}");
    // Core collects newest first in output order and reverses the whole
    // list, so one transaction's entries come last output first
    for (i, (entry, value)) in list.iter().rev().zip([10.0, 5.0]).enumerate() {
        assert_eq!(entry["category"], json!("receive"), "{entry}");
        assert_eq!(
            entry["address"],
            json!(f.addresses[i].to_base58()),
            "{entry}"
        );
        assert_eq!(entry["account"], json!(format!("acct{i}")), "{entry}");
        assert_eq!(entry["vout"], json!(i), "{entry}");
        assert_eq!(entry["amount"], json!(value), "{entry}");
        assert_eq!(entry["confirmations"], json!(1), "{entry}");
        assert_eq!(entry["bcconfirmations"], json!(1), "{entry}");
        assert_eq!(entry["blockindex"], json!(1), "{entry}");
        assert!(entry["blocktime"].is_u64(), "{entry}");
        assert!(entry["baretxid"].is_string(), "{entry}");
        assert_eq!(entry["walletconflicts"], json!([]), "{entry}");
        assert!(entry.get("fee").is_none(), "{entry}");
    }
    // the account filter keeps one
    let one = f.n.ok("listtransactions", vec![json!("acct1")]);
    assert_eq!(one.as_array().unwrap().len(), 1, "{one}");

    let txid = f.funding.txid().to_string();
    let t = f.n.ok("gettransaction", vec![json!(txid)]);
    assert_eq!(t["amount"], json!(15.0), "{t}");
    assert!(t.get("fee").is_none(), "{t}");
    assert_eq!(t["details"].as_array().unwrap().len(), 2, "{t}");
    assert!(t["details"][0].get("confirmations").is_none(), "{t}");
    assert_eq!(
        t["hex"],
        json!(hex::encode(divi_primitives::serialize::serialize(
            &f.funding
        )))
    );
}

/// A send is a "send" entry per payee with the fee, change left out;
/// gettransaction's amount is credit less debit and its fee positive
#[test]
fn send_entry_and_gettransaction_amounts() {
    let f = funded(&[10 * COIN]);
    let to = nobody().to_base58();
    let txid = f.n.ok("sendtoaddress", vec![json!(to), json!(4)]);
    let sent = f.submitted.lock().last().cloned().unwrap();
    assert_eq!(json!(sent.txid().to_string()), txid);
    f.n.mine(vec![sent.clone()], &nobody());
    let value_out: i64 = sent.vout.iter().map(|o| o.value.as_sat()).sum();
    let fee = 10 * COIN - value_out;
    assert!(fee > 0);

    let list = f.n.ok("listtransactions", vec![]);
    let last = list.as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["category"], json!("send"), "{list}");
    assert_eq!(last["address"], json!(to), "{last}");
    assert_eq!(last["amount"], json!(-4.0), "{last}");
    assert_eq!(last["fee"], json!(-(fee as f64) / COIN as f64), "{last}");
    assert_eq!(last["account"], json!(""), "{last}");
    assert_eq!(
        list.as_array().unwrap().len(),
        2,
        "change is not listed: {list}"
    );

    let t = f.n.ok("gettransaction", vec![txid]);
    assert_eq!(
        t["amount"],
        json!(-((4 * COIN + fee) as f64) / COIN as f64),
        "{t}"
    );
    assert_eq!(t["fee"], json!(fee as f64 / COIN as f64), "{t}");
}

/// A coinbase paying the wallet is "immature" until it matures, then
/// "generate"; both carry generated: true
#[test]
fn coinbase_categories() {
    let n = node();
    let addr = Address::from_base58(n.ok("getnewaddress", vec![]).as_str().unwrap()).unwrap();
    n.mine(vec![], &addr);
    let list = n.ok("listtransactions", vec![]);
    assert_eq!(list[0]["category"], json!("immature"), "{list}");
    assert_eq!(list[0]["generated"], json!(true), "{list}");
    for _ in 0..20 {
        n.mine(vec![], &nobody());
    }
    let list = n.ok("listtransactions", vec![]);
    assert_eq!(list[0]["category"], json!("generate"), "{list}");
}

/// Oldest first, the newest `count` after skipping `from`, the whole list
/// reversed at the end (rpcwallet.cpp:2280-2316)
#[test]
fn listtransactions_window_and_errors() {
    let f = funded(&[COIN, 2 * COIN, 3 * COIN]);
    let all: Vec<f64> =
        f.n.ok("listtransactions", vec![])
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["amount"].as_f64().unwrap())
            .collect();
    // one transaction: its outputs last first
    assert_eq!(all, vec![3.0, 2.0, 1.0]);
    let window: Vec<f64> =
        f.n.ok("listtransactions", vec![json!("*"), json!(1), json!(1)])
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["amount"].as_f64().unwrap())
            .collect();
    assert_eq!(window, vec![2.0]);
    assert_eq!(
        f.n.err("listtransactions", vec![json!("*"), json!(-1)]),
        (-8, "Negative count".to_string())
    );
    assert_eq!(
        f.n.err("listtransactions", vec![json!("*"), json!(1), json!(-1)]),
        (-8, "Negative from".to_string())
    );
}

/// listsinceblock: an unknown hash lists everything, a target below 1 is -8,
/// lastblock is the block target-1 below the tip (rpcwallet.cpp:2364-2450)
#[test]
fn listsinceblock_arguments() {
    let f = funded(&[COIN]);
    let r = f.n.ok("listsinceblock", vec![json!("00".repeat(32))]);
    assert_eq!(r["transactions"].as_array().unwrap().len(), 1, "{r}");
    let tip = f.n.ok("getbestblockhash", vec![]);
    assert_eq!(r["lastblock"], tip);
    let tip_hash = tip.as_str().unwrap().to_string();
    let r = f.n.ok("listsinceblock", vec![json!(tip_hash)]);
    assert_eq!(r["transactions"], json!([]), "{r}");
    assert_eq!(
        f.n.err("listsinceblock", vec![json!(""), json!(0)]),
        (-8, "Invalid parameter".to_string())
    );
}

/// gettransaction of an unknown or malformed txid (rpcwallet.cpp:2471-2472)
#[test]
fn gettransaction_errors() {
    let n = node();
    let unknown = (-5, "Invalid or non-wallet transaction id".to_string());
    assert_eq!(
        n.err("gettransaction", vec![json!("11".repeat(32))]),
        unknown
    );
    assert_eq!(n.err("gettransaction", vec![json!("zz")]), unknown);
}

/// listreceivedbyaddress gives bcconfirmations and txids, and with
/// includeempty the addresses that received nothing (rpcwallet.cpp:1793-1912)
#[test]
fn listreceivedbyaddress_fields() {
    let f = funded(&[COIN]);
    let empty = f.n.ok("getnewaddress", vec![]);
    let r = f.n.ok("listreceivedbyaddress", vec![]);
    let row = r
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["address"] == json!(f.addresses[0].to_base58()))
        .cloned()
        .unwrap_or_else(|| panic!("{r}"));
    assert_eq!(row["bcconfirmations"], json!(1), "{row}");
    assert_eq!(row["txids"], json!([f.funding.txid().to_string()]), "{row}");
    let with_empty = f.n.ok("listreceivedbyaddress", vec![json!(1), json!(true)]);
    assert!(
        with_empty
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["address"] == empty),
        "{with_empty}"
    );
    let _ = &f.funder;
}

/// A wallet send conflicted by another spend of its coin stays in the wallet
/// at depth -1, and both list each other in walletconflicts
/// (MerkleTxConfirmationNumberCalculator.cpp:43-47, wallet.cpp:889-898)
#[test]
fn conflicted_send_is_kept_at_depth_minus_one() {
    let f = funded(&[10 * COIN]);
    let coin = f.funding.clone();
    let to = nobody().to_base58();
    let txid = f.n.ok("sendtoaddress", vec![json!(to), json!(4)]);
    let sent = f.submitted.lock().last().cloned().unwrap();
    assert!(f.wallet().add_mempool_tx(&sent));

    // Someone else's spend of the same coin is mined instead
    let (mut other, prev) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(coin.txid(), 0),
            coin.vout[0].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(9 * COIN), &nobody())
        .build();
    TransactionSigner::new(f.n.wallet.keystore())
        .sign_all_inputs(&mut other, &prev)
        .unwrap();
    f.n.mine(vec![other.clone()], &nobody());

    let t = f.n.ok("gettransaction", vec![txid.clone()]);
    assert_eq!(t["confirmations"], json!(-1), "{t}");
    assert!(t.get("blockhash").is_none(), "{t}");
    let mut both = vec![other.txid().to_string(), sent.txid().to_string()];
    both.sort();
    assert_eq!(t["walletconflicts"], json!(both), "{t}");
    let listed = f.n.ok("listtransactions", vec![json!("*"), json!(100)]);
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["txid"] == txid && e["confirmations"] == json!(-1)),
        "{listed}"
    );
}

/// A wallet transaction of a block that is disconnected stays in the wallet at
/// depth -1 until a block has it again
#[test]
fn transaction_of_a_disconnected_block_is_kept() {
    let f = funded(&[10 * COIN]);
    let txid = f.funding.txid().to_string();
    let tip = f.n.ok("getbestblockhash", vec![]);
    f.n.ok("invalidateblock", vec![tip.clone()]);
    let t = f.n.ok("gettransaction", vec![json!(txid)]);
    assert_eq!(t["confirmations"], json!(-1), "{t}");
    assert_eq!(t["amount"], json!(10.0), "{t}");
    f.n.ok("reconsiderblock", vec![tip]);
    let t = f.n.ok("gettransaction", vec![json!(txid)]);
    assert_eq!(t["confirmations"], json!(1), "{t}");
}

/// getaccountaddress hands out the account's last address until something
/// pays it, then a new one (rpcwallet.cpp:315-375)
#[test]
fn getaccountaddress_moves_on_once_paid() {
    let f = funded(&[COIN]);
    let paid = f.addresses[0].to_base58();
    let next = f.n.ok("getaccountaddress", vec![json!("acct0")]);
    assert_ne!(next, json!(paid));
    assert_eq!(f.n.ok("getaccountaddress", vec![json!("acct0")]), next);
    let fresh = f.n.ok("getaccountaddress", vec![json!("unused")]);
    assert_eq!(f.n.ok("getaccountaddress", vec![json!("unused")]), fresh);
}

/// listsinceblock and listunspent come in txid order, the wallet map's order
/// in Divi Core (rpcwallet.cpp:2396-2402, rpcrawtransaction.cpp:296)
#[test]
fn listsinceblock_and_listunspent_in_txid_order() {
    let f = funded(&[COIN]);
    for _ in 0..3 {
        let addr = Address::from_base58(f.n.ok("getnewaddress", vec![]).as_str().unwrap()).unwrap();
        f.n.mine(vec![], &addr);
    }
    let since = f.n.ok("listsinceblock", vec![]);
    let ids: Vec<String> = since["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["txid"].as_str().unwrap().to_string())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    let unspent = f.n.ok("listunspent", vec![json!(0)]);
    let ids: Vec<String> = unspent
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["txid"].as_str().unwrap().to_string())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}
