// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Replies and errors that still differed from Divi Core 3.0.0 after the first
//! comparison: argument types (json_spirit getters), calls that need a wallet
//! on a node without one, sendrawtransaction's input check, the address and
//! spent index calls without the index, and getrawtransaction without the
//! transaction index.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    serialize::serialize,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType, SearchIndex};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Node {
    chain: Arc<Chain>,
    wallet: Option<Arc<WalletDb>>,
    server: RpcServer,
    _dir: tempfile::TempDir,
}

#[derive(Clone, Copy)]
struct Opts {
    txindex: bool,
    search: bool,
    wallet: bool,
}

const FULL: Opts = Opts {
    txindex: true,
    search: true,
    wallet: true,
};

fn node(o: Opts) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let mut chain = Chain::new(
        db.clone(),
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    if o.txindex {
        chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
    }
    if o.search {
        chain.enable_search_index(Arc::new(SearchIndex::new(db, true, true)));
    }
    let chain = Arc::new(chain);
    let (server, wallet) = if o.wallet {
        let wallet = Arc::new(WalletDb::with_hd_wallet(
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        ));
        (
            RpcServer::with_wallet(chain.clone(), wallet.clone()),
            Some(wallet),
        )
    } else {
        (RpcServer::new(chain.clone()), None)
    };
    server
        .wallet()
        .set_tx_submit(Arc::new(|tx: Transaction| Ok(tx.txid())));
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

    /// Mine a block with `txs` whose coinbase pays 1250 DIVI to `pay_to`
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
        if let Some(w) = &self.wallet {
            w.scan_block(hash, height, time, &txs);
        }
        self.server.set_height(height);
        txs[0].clone()
    }
}

fn nobody() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

/// A key the tests spend with, outside the node's wallet
fn spender() -> (Arc<WalletDb>, Address) {
    let w = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let a = w.new_receiving_address().unwrap();
    (w, a)
}

fn spend(w: &WalletDb, prev: &Transaction, n: u32, outs: &[(i64, &Address)]) -> Transaction {
    let mut b = TransactionBuilder::new().add_input(
        OutPoint::new(prev.txid(), n),
        prev.vout[n as usize].script_pubkey.clone(),
    );
    for (v, a) in outs {
        b = b.add_output_to_address(Amount::from_sat(*v), a);
    }
    let (mut tx, prevs) = b.build();
    TransactionSigner::new(w.keystore())
        .sign_all_inputs(&mut tx, &prevs)
        .unwrap();
    tx
}

/// Arguments of the wrong JSON type are refused as json_spirit's getters
/// refuse them: -1 "value is type X, expected Y", and nothing changes
/// (rpcwallet.cpp:273-275, :604-605, :1388, :2604; rpcmasternode.cpp:221;
/// rpcblockchain.cpp:269; rpcserver.cpp:1107-1108)
#[test]
fn wrong_argument_types_are_refused_as_json_spirit_refuses_them() {
    let n = node(FULL);
    let addr = n.ok("getnewaddress", vec![json!("old")]);
    let int_not_str = (-1, "value is type int, expected str".to_string());
    assert_eq!(
        n.err("setaccount", vec![addr.clone(), json!(1234)]),
        int_not_str
    );
    assert_eq!(n.ok("getaccount", vec![addr.clone()]), json!("old"));
    assert_eq!(
        n.err("signmessage", vec![addr.clone(), json!(true)]),
        (-1, "value is type bool, expected str".to_string())
    );
    // an unencrypted wallet is refused before the argument is read (-15)
    assert_eq!(
        n.err("walletpassphrase", vec![json!(1234), json!(1)]).0,
        -15
    );
    let dir = tempfile::tempdir().unwrap();
    let w = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    w.encrypt_wallet("pw").unwrap();
    w.lock();
    let locked = RpcServer::with_wallet(n.chain.clone(), w);
    let r = locked.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: "walletpassphrase".to_string(),
        params: Params::Array(vec![json!(1234), json!(1)]),
    });
    let e = r.error.expect("refused");
    assert_eq!((e.code, e.message), int_not_str);
    assert_eq!(
        n.err(
            "setupmasternode",
            vec![
                json!("mn1"),
                json!("00".repeat(32)),
                json!(0),
                json!("ab"),
                json!("1.2.3.4")
            ]
        ),
        int_not_str
    );
    let tip = n.ok("getbestblockhash", vec![]);
    assert_eq!(
        n.err("getblockheader", vec![tip, json!(1)]),
        (-1, "value is type int, expected bool".to_string())
    );
    assert_eq!(
        n.err("getbalance", vec![json!("*"), json!("1")]),
        (-1, "value is type str, expected int".to_string())
    );
}

/// Calls that need a wallet answer -32601 on a node without one
/// (rpcserver.cpp:1043-1047), setgenerate among them
#[test]
fn wallet_calls_without_a_wallet_are_unavailable() {
    let n = node(Opts {
        wallet: false,
        ..FULL
    });
    let unavailable = (
        -32601,
        "Method unavailable due to manually disabled wallet".to_string(),
    );
    for (method, params) in [
        ("setgenerate", vec![json!(1)]),
        ("getbalance", vec![]),
        ("getnewaddress", vec![]),
        ("listtransactions", vec![]),
        ("sendtoaddress", vec![json!(nobody().to_base58()), json!(1)]),
        ("getwalletinfo", vec![]),
    ] {
        assert_eq!(n.err(method, params), unavailable, "{method}");
    }
    // not a wallet call
    assert!(n.call("getblockcount", vec![]).is_ok());
    // getinfo leaves the wallet members out (rpcmisc.cpp:139-144)
    let info = n.ok("getinfo", vec![]);
    for member in [
        "walletversion",
        "balance",
        "keypoololdest",
        "keypoolsize",
        "paytxfee",
    ] {
        assert!(
            info.get(member).is_none(),
            "getinfo has {member} without a wallet"
        );
    }
    let with_wallet = node(FULL).ok("getinfo", vec![]);
    for member in ["walletversion", "balance"] {
        assert!(with_wallet.get(member).is_some(), "getinfo lacks {member}");
    }
}

/// sendrawtransaction checks that every input is in the chain or the mempool
/// before the mempool sees the transaction: a re-sent spend of a coin a block
/// already spent is -26 "Unknown inputs being spent", even when the funding
/// transaction still has another unspent output (rpcrawtransaction.cpp:810-826,
/// :875-881)
#[test]
fn spend_of_a_coin_spent_in_chain_is_unknown_inputs() {
    let n = node(FULL);
    let (w, me) = spender();
    let cb = n.mine(vec![], &me);
    for _ in 0..20 {
        n.mine(vec![], &nobody());
    }
    let a = spend(&w, &cb, 0, &[(600 * COIN, &me), (649 * COIN, &me)]);
    n.mine(vec![a.clone()], &nobody());
    let b = spend(&w, &a, 0, &[(599 * COIN, &nobody())]);
    n.mine(vec![b], &nobody());
    let c = spend(&w, &a, 0, &[(598 * COIN, &nobody())]);
    assert_eq!(
        n.err(
            "sendrawtransaction",
            vec![json!(hex::encode(serialize(&c)))]
        ),
        (-26, "Unknown inputs being spent".to_string())
    );
    // the other output of the same transaction is still spendable
    let d = spend(&w, &a, 1, &[(648 * COIN, &nobody())]);
    assert_eq!(
        n.ok(
            "sendrawtransaction",
            vec![json!(hex::encode(serialize(&d)))]
        ),
        json!(d.txid().to_string())
    );
}

/// Without the address and spent indexes the calls answer as divid does:
/// -5 "No information available for address" and "Unable to get spent info"
/// (rpcmisc.cpp:658, :760, :851, :976, :916-917)
#[test]
fn index_calls_without_the_index_answer_as_core() {
    let n = node(Opts {
        search: false,
        ..FULL
    });
    let addr = json!(nobody().to_base58());
    let no_info = (-5, "No information available for address".to_string());
    for method in [
        "getaddressbalance",
        "getaddressutxos",
        "getaddressdeltas",
        "getaddresstxids",
    ] {
        assert_eq!(
            n.err(method, vec![json!({ "addresses": [addr.clone()] })]),
            no_info,
            "{method}"
        );
    }
    assert_eq!(
        n.err(
            "getspentinfo",
            vec![json!({"txid": "11".repeat(32), "index": 0})]
        ),
        (-5, "Unable to get spent info".to_string())
    );
}

/// Without the transaction index, getrawtransaction still finds a confirmed
/// transaction with an unspent output through the coin set
/// (TransactionDiskAccessor.cpp:88-96, rpcrawtransaction.cpp:217)
#[test]
fn getrawtransaction_without_txindex_finds_unspent_coins() {
    let n = node(Opts {
        txindex: false,
        search: false,
        wallet: true,
    });
    let (w, me) = spender();
    let cb = n.mine(vec![], &me);
    for _ in 0..20 {
        n.mine(vec![], &nobody());
    }
    let raw = n.ok("getrawtransaction", vec![json!(cb.txid().to_string())]);
    assert_eq!(raw, json!(hex::encode(serialize(&cb))));
    let verbose = n.ok(
        "getrawtransaction",
        vec![json!(cb.txid().to_string()), json!(1)],
    );
    assert_eq!(verbose["confirmations"], json!(21), "{verbose}");
    assert!(verbose["blockhash"].is_string(), "{verbose}");

    // once every output is spent it is gone, as in divid without -txindex
    let a = spend(&w, &cb, 0, &[(1249 * COIN, &nobody())]);
    n.mine(vec![a], &nobody());
    assert_eq!(
        n.err("getrawtransaction", vec![json!(cb.txid().to_string())]),
        (-5, "No information available about transaction".to_string())
    );
}

/// lockunspent true with no list unlocks every coin, false with no list does
/// nothing, and entries are checked as Divi Core checks them
/// (rpcwallet.cpp:2742-2814)
#[test]
fn lockunspent_as_core() {
    let n = node(FULL);
    let me = Address::from_base58(n.ok("getnewaddress", vec![]).as_str().unwrap()).unwrap();
    let cb = n.mine(vec![], &me);
    let coin = json!([{"txid": cb.txid().to_string(), "vout": 0}]);
    assert_eq!(n.ok("lockunspent", vec![json!(false), coin]), json!(true));
    assert_eq!(n.ok("listlockunspent", vec![]).as_array().unwrap().len(), 1);
    assert_eq!(n.ok("lockunspent", vec![json!(false)]), json!(true));
    assert_eq!(n.ok("listlockunspent", vec![]).as_array().unwrap().len(), 1);
    assert_eq!(n.ok("lockunspent", vec![json!(true)]), json!(true));
    assert_eq!(n.ok("listlockunspent", vec![]), json!([]));

    let p = |entry: Value| vec![json!(false), json!([entry])];
    assert_eq!(
        n.err("lockunspent", p(json!(5))),
        (-8, "Invalid parameter, expected object".to_string())
    );
    assert_eq!(
        n.err("lockunspent", p(json!({"vout": 0}))),
        (-3, "Missing txid".to_string())
    );
    assert_eq!(
        n.err("lockunspent", p(json!({"txid": 5, "vout": 0}))),
        (-3, "Expected type str for txid, got int".to_string())
    );
    assert_eq!(
        n.err("lockunspent", p(json!({"txid": "zz", "vout": 0}))),
        (-8, "Invalid parameter, expected hex txid".to_string())
    );
    assert_eq!(
        n.err(
            "lockunspent",
            p(json!({"txid": "11".repeat(32), "vout": -1}))
        ),
        (-8, "Invalid parameter, vout must be positive".to_string())
    );
}

/// encryptwallet answers "Wallet reloaded!", as Divi Core 3.0.0 does after
/// reloading the encrypted wallet (rpcwallet.cpp:2732-2733)
#[test]
fn encryptwallet_reply_as_core() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(FULL);
    let w = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    let server = RpcServer::with_wallet(n.chain.clone(), w.clone());
    let r = server.handle_request(Request {
        jsonrpc: "1.0".to_string(),
        id: RequestId::Number(1),
        method: "encryptwallet".to_string(),
        params: Params::Array(vec![json!("pw")]),
    });
    assert_eq!(r.result, Some(json!("Wallet reloaded!")), "{:?}", r.error);
    assert!(w.is_encrypted() && w.is_locked());
}
