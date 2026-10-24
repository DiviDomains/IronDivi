// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The received-by calls and the wallet replies next to them as Divi Core
//! 3.0.0 gives them; each test names the Core lines it follows.

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
    /// wallet catches up with the chain
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
        let txs = block.transactions.clone();
        self.chain.accept_block(block).unwrap();
        // As irondivid's block callback does, so the wallet knows the blocks
        // it scanned and leaves them when they are disconnected
        divi_rpc::wallet::sync_wallet_with_chain(&self.wallet, &self.chain);
        self.server.set_height(height);
        txs[0].clone()
    }
}

fn nobody() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

/// A node whose wallet holds `values` (satoshis) on labelled addresses, paid
/// by one funder transaction, plus the submitted sends
struct Funded {
    n: Node,
    submitted: Arc<Mutex<Vec<Transaction>>>,
    addresses: Vec<Address>,
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
        submitted,
        addresses,
    }
}

fn new_address(n: &Node, account: &str) -> Address {
    Address::from_base58(
        n.ok("getnewaddress", vec![json!(account)])
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

/// An address nobody here holds a key for
fn watched() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x24; 20]), Network::Regtest)
}

/// Send `amount` DIVI to `to` from the wallet and mine the send
fn send_and_mine(f: &Funded, to: &str, amount: f64) -> Transaction {
    f.n.ok("sendtoaddress", vec![json!(to), json!(amount)]);
    let sent = f.submitted.lock().last().cloned().unwrap();
    f.n.mine(vec![sent.clone()], &nobody());
    sent
}

/// getreceivedbyaddress counts what a watched address received
/// (computeMineType with watch-only, rpcwallet.cpp:1455), and getreceivedbyaccount
/// what the watched account's addresses received
#[test]
fn received_by_counts_watched_addresses() {
    let f = funded(&[10 * COIN]);
    let w = watched().to_base58();
    f.n.ok(
        "importaddress",
        vec![json!(w), json!("watch"), json!(false)],
    );
    send_and_mine(&f, &w, 3.0);
    assert_eq!(f.n.ok("getreceivedbyaddress", vec![json!(w)]), json!(3.0));
    assert_eq!(
        f.n.ok("getreceivedbyaddress", vec![json!(w), json!(0)]),
        json!(3.0)
    );
    assert_eq!(
        f.n.ok("getreceivedbyaccount", vec![json!("watch")]),
        json!(3.0)
    );
}

/// minconf is an int, any int: -1 counts what is unconfirmed too, and a null is
/// refused as json_spirit's get_int refuses it; minconf is read only for an
/// address of the wallet (rpcwallet.cpp:1455-1461), and before the account in
/// getreceivedbyaccount (:1517-1523)
#[test]
fn received_by_minconf_is_any_int() {
    let f = funded(&[10 * COIN]);
    let mine = f.addresses[0].to_base58();
    f.n.ok("sendtoaddress", vec![json!(mine), json!(2)]);
    // In the mempool: the wallet takes it from there, as irondivid's mempool
    // callback hands it over
    let sent = f.submitted.lock().last().cloned().unwrap();
    assert!(f.n.wallet.add_mempool_tx(&sent));
    assert_eq!(
        f.n.ok("getreceivedbyaddress", vec![json!(mine)]),
        json!(10.0)
    );
    assert_eq!(
        f.n.ok("getreceivedbyaddress", vec![json!(mine), json!(-1)]),
        json!(12.0)
    );
    assert_eq!(
        f.n.ok("getreceivedbyaccount", vec![json!("acct0"), json!(-1)]),
        json!(12.0)
    );
    let null_int = (-1, "value is type null, expected int".to_string());
    assert_eq!(
        f.n.err("getreceivedbyaddress", vec![json!(mine), Value::Null]),
        null_int
    );
    // An address the wallet does not have: 0 before minconf is read
    let other = nobody().to_base58();
    assert_eq!(
        f.n.ok("getreceivedbyaddress", vec![json!(other), Value::Null]),
        json!(0.0)
    );
    assert_eq!(
        f.n.ok("getreceivedbyaddress", vec![json!(other), json!("1")]),
        json!(0.0)
    );
    assert_eq!(
        f.n.err("getreceivedbyaccount", vec![json!(5), json!("1")]),
        (-1, "value is type str, expected int".to_string())
    );
    assert_eq!(
        f.n.err("getreceivedbyaccount", vec![Value::Null]),
        (-1, "value is type null, expected str".to_string())
    );
}

/// listreceivedbyaddress and listreceivedbyaccount refuse a null argument, and
/// getaccountaddress a null account, as their getters do (rpcwallet.cpp:550,
/// :1798-1808)
#[test]
fn null_arguments_are_refused() {
    let n = node();
    let null = |want: &str| (-1, format!("value is type null, expected {want}"));
    for method in ["listreceivedbyaddress", "listreceivedbyaccount"] {
        assert_eq!(n.err(method, vec![Value::Null]), null("int"), "{method}");
        assert_eq!(
            n.err(method, vec![json!(1), Value::Null]),
            null("bool"),
            "{method}"
        );
        assert_eq!(
            n.err(method, vec![json!(1), json!(true), Value::Null]),
            null("bool"),
            "{method}"
        );
    }
    assert_eq!(n.err("getaccountaddress", vec![Value::Null]), null("str"));
    let key = new_address(&n, "").to_base58();
    assert_eq!(
        n.err(
            "addmultisigaddress",
            vec![json!(1), json!([key]), Value::Null]
        ),
        null("str")
    );
}

/// The address book in Divi Core's order, a std::map of CTxDestination: key
/// addresses before script addresses, each by its hash as a uint160 compares,
/// from the last byte; and each address's txids in txid order (the wallet map)
#[test]
fn listreceivedbyaddress_in_address_book_order() {
    let f = funded(&[100 * COIN]);
    let mut keys = Vec::new();
    for _ in 0..6 {
        keys.push(new_address(&f.n, "many").to_base58());
    }
    let multisig = f.n.ok(
        "addmultisigaddress",
        vec![json!(1), json!([keys[0]]), json!("ms")],
    );
    let multisig2 = f.n.ok(
        "addmultisigaddress",
        vec![json!(1), json!([keys[1]]), json!("ms")],
    );
    for _ in 0..4 {
        send_and_mine(&f, &keys[2], 1.0);
    }
    let listed = f.n.ok("listreceivedbyaddress", vec![json!(0), json!(true)]);
    let listed = listed.as_array().unwrap();
    let order: Vec<String> = listed
        .iter()
        .map(|e| e["address"].as_str().unwrap().to_string())
        .collect();
    let mut want = order.clone();
    want.sort_by_key(|a| {
        let a = Address::from_base58(a).unwrap();
        let mut hash = a.hash.as_bytes().to_vec();
        hash.reverse();
        (a.addr_type == divi_wallet::AddressType::P2SH, hash)
    });
    assert_eq!(order, want);
    let last_two: Vec<&String> = order.iter().rev().take(2).collect();
    assert!(
        last_two.contains(&&multisig.as_str().unwrap().to_string()),
        "{order:?}"
    );
    assert!(
        last_two.contains(&&multisig2.as_str().unwrap().to_string()),
        "{order:?}"
    );
    let paid = listed
        .iter()
        .find(|e| e["address"] == json!(keys[2]))
        .unwrap();
    let txids: Vec<String> = paid["txids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect();
    assert_eq!(txids.len(), 4, "{paid}");
    let mut sorted = txids.clone();
    sorted.sort();
    assert_eq!(txids, sorted);
}
