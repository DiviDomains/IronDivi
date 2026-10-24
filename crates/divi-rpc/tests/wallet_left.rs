// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet history as Divi Core 3.0.0 keeps it: watched outputs, account
//! balances, the notes a send keeps and the order transactions were first
//! seen in (wallet.cpp, rpcwallet.cpp).

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, WalletRpc};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Net {
    chain: Arc<Chain>,
    dir: tempfile::TempDir,
    funder: Arc<WalletDb>,
    wallet: Arc<WalletDb>,
    submitted: Arc<Mutex<Vec<Transaction>>>,
    miner: Address,
}

impl Net {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
        let mut chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap();
        chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
        let funder = Arc::new(WalletDb::with_hd_wallet(
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        ));
        // The wallet under test is on disk, so it can be opened again
        let wallet = Arc::new(
            WalletDb::create_persistent(
                &dir.path().join("wallet"),
                Network::Regtest,
                HdWallet::new(ChainMode::Divi).unwrap(),
            )
            .unwrap(),
        );
        Net {
            chain: Arc::new(chain),
            dir,
            funder,
            wallet,
            submitted: Arc::new(Mutex::new(Vec::new())),
            miner: Address::from_pubkey_hash(Hash160::from_bytes([0x99; 20]), Network::Regtest),
        }
    }

    fn rpc(&self) -> WalletRpc {
        self.rpc_for(&self.wallet)
    }

    fn rpc_for(&self, wallet: &Arc<WalletDb>) -> WalletRpc {
        let rpc = WalletRpc::with_wallet_and_chain(wallet.clone(), self.chain.clone());
        let submitted = self.submitted.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            submitted.lock().push(tx);
            Ok(txid)
        }));
        rpc.set_height(self.chain.height());
        rpc
    }

    /// Mine a block holding `txs`; both wallets scan it
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
        assert_eq!(self.chain.height(), height, "block was not connected");
        for w in [&self.funder, &self.wallet] {
            w.scan_block(hash, height, time, &txs);
        }
        txs[0].clone()
    }

    /// A mature coinbase of the funder
    fn mature_coin(&self) -> Transaction {
        let cb_addr = self.funder.new_receiving_address().unwrap();
        let coinbase = self.mine(vec![], &cb_addr);
        for _ in 0..20 {
            self.mine(vec![], &self.miner);
        }
        coinbase
    }

    /// A signed funder transaction paying `outputs` from one mature coinbase
    fn pay(&self, coinbase: &Transaction, outputs: &[(Address, i64)]) -> Transaction {
        let mut builder = TransactionBuilder::new().add_input(
            OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        );
        for (addr, value) in outputs {
            builder = builder.add_output_to_address(Amount::from_sat(*value), addr);
        }
        let rest = 1250 * COIN - outputs.iter().map(|(_, v)| v).sum::<i64>() - COIN / 100;
        builder = builder.add_output_to_address(Amount::from_sat(rest), &self.miner);
        let (mut tx, prev) = builder.build();
        TransactionSigner::new(self.funder.keystore())
            .sign_all_inputs(&mut tx, &prev)
            .unwrap();
        tx
    }

    /// The wallet under test holds `n` confirmed coins of 100 DIVI
    fn fund(&self, n: usize) {
        let coin = self.mature_coin();
        let outputs: Vec<(Address, i64)> = (0..n)
            .map(|_| (self.wallet.new_receiving_address().unwrap(), 100 * COIN))
            .collect();
        let tx = self.pay(&coin, &outputs);
        self.mine(vec![tx], &self.miner);
    }

    fn last_submitted(&self) -> Transaction {
        self.submitted
            .lock()
            .last()
            .cloned()
            .expect("a transaction was sent")
    }
}

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn watched_address(n: u8) -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([n; 20]), Network::Regtest)
}

fn rows_for(list: &Value, addr: &Address) -> Vec<Value> {
    list.as_array()
        .unwrap()
        .iter()
        .filter(|e| e["address"] == json!(addr.to_string()))
        .cloned()
        .collect()
}

fn divi(v: &Value) -> f64 {
    v.as_f64().unwrap()
}

/// The wallet sends to an address it watches (importaddress): divid records
/// its own send, and with includeWatchonly lists the watched output as a
/// receive too (GetAmounts with the watch-only filter, rpcwallet.cpp:112-182;
/// involvesWatchonly, :1843-1902; filter :2283-2284). The watched address's
/// account counts it (GetAccountBalance, rpcwallet.cpp:383-412); the wallet's
/// own balance does not grow.
#[test]
fn watched_output_of_a_wallet_send_is_listed_and_counted_in_its_account() {
    let net = Net::new();
    net.fund(2);
    let watched = watched_address(0x31);
    net.rpc()
        .import_address(&p(vec![
            json!(watched.to_string()),
            json!("watch"),
            json!(false),
        ]))
        .unwrap();
    net.rpc()
        .send_to_address(&p(vec![json!(watched.to_string()), json!(7)]))
        .unwrap();
    net.mine(vec![net.last_submitted()], &net.miner);
    let rpc = net.rpc();

    let with = rpc
        .list_transactions(&p(vec![json!("*"), json!(10), json!(0), json!(true)]))
        .unwrap();
    let rows = rows_for(&with, &watched);
    let receive: Vec<&Value> = rows.iter().filter(|r| r["category"] == "receive").collect();
    assert_eq!(receive.len(), 1, "{with}");
    assert_eq!(divi(&receive[0]["amount"]), 7.0);
    assert_eq!(receive[0]["involvesWatchonly"], json!(true));
    assert!(rows.iter().any(|r| r["category"] == "send"), "{with}");
    let without = rpc
        .list_transactions(&p(vec![json!("*"), json!(10), json!(0)]))
        .unwrap();
    assert!(
        rows_for(&without, &watched)
            .iter()
            .all(|r| r["category"] == "send"),
        "{without}"
    );

    for watch in [true, false] {
        let b = rpc
            .get_balance(&p(vec![json!("watch"), json!(1), json!(watch)]))
            .unwrap();
        assert_eq!(divi(&b), 7.0, "getbalance watch 1 {watch}");
    }
}

/// A transaction that pays the wallet and a watched address: both outputs
/// are listed with includeWatchonly, the watched one only then; the "" account
/// counts the watched output only with includeWatchonly
#[test]
fn transaction_paying_wallet_and_watched_address() {
    let net = Net::new();
    let watched = watched_address(0x32);
    net.rpc()
        .import_address(&p(vec![
            json!(watched.to_string()),
            json!(""),
            json!(false),
        ]))
        .unwrap();
    let mine = net.wallet.new_receiving_address().unwrap();
    let coin = net.mature_coin();
    net.mine(
        vec![net.pay(
            &coin,
            &[(mine.clone(), 5 * COIN), (watched.clone(), 3 * COIN)],
        )],
        &net.miner,
    );
    let rpc = net.rpc();
    let with = rpc
        .list_transactions(&p(vec![json!("*"), json!(10), json!(0), json!(true)]))
        .unwrap();
    assert_eq!(rows_for(&with, &mine).len(), 1, "{with}");
    assert_eq!(rows_for(&with, &watched).len(), 1, "{with}");
    let without = rpc
        .list_transactions(&p(vec![json!("*"), json!(10), json!(0)]))
        .unwrap();
    assert_eq!(rows_for(&without, &mine).len(), 1);
    assert!(rows_for(&without, &watched).is_empty());

    let plain = divi(
        &rpc.get_balance(&p(vec![json!(""), json!(1), json!(false)]))
            .unwrap(),
    );
    let watching = divi(
        &rpc.get_balance(&p(vec![json!(""), json!(1), json!(true)]))
            .unwrap(),
    );
    assert_eq!(plain, 5.0);
    assert_eq!(watching, 8.0);
}

/// sendtoaddress "metadata", sendfrom and sendmany keep their notes with the
/// transaction (mapValue: comment, to, FromAccount; rpcwallet.cpp:1346-1352,
/// :1636-1642, :1718-1723) and show them as divid does (:268-269), also after
/// the wallet is opened again
#[test]
fn send_notes_are_kept_and_shown() {
    let net = Net::new();
    net.fund(3);
    let to = net.funder.new_receiving_address().unwrap();
    let rpc = net.rpc();

    rpc.send_to_address(&p(vec![
        json!(to.to_string()),
        json!(1),
        json!("metadata"),
        json!("rent"),
        json!("landlord"),
    ]))
    .unwrap();
    let a = net.last_submitted();
    net.mine(vec![a.clone()], &net.miner);
    rpc.send_from(&p(vec![
        json!(""),
        json!(to.to_string()),
        json!(2),
        json!("dinner"),
        json!("bob"),
    ]))
    .unwrap();
    let b = net.last_submitted();
    net.mine(vec![b.clone()], &net.miner);
    let mut payees = serde_json::Map::new();
    payees.insert(to.to_string(), json!(3));
    rpc.send_many(&p(vec![json!(""), Value::Object(payees), json!("split")]))
        .unwrap();
    let c = net.last_submitted();
    net.mine(vec![c.clone()], &net.miner);

    let check = |rpc: &WalletRpc| {
        let get = |tx: &Transaction| {
            rpc.get_transaction(&p(vec![json!(tx.txid().to_string())]))
                .unwrap()
        };
        let ta = get(&a);
        assert_eq!(ta["comment"], "rent", "{ta}");
        assert_eq!(ta["to"], "landlord", "{ta}");
        assert!(ta.get("FromAccount").is_none(), "{ta}");
        let tb = get(&b);
        assert_eq!(
            (&tb["FromAccount"], &tb["comment"], &tb["to"]),
            (&json!(""), &json!("dinner"), &json!("bob")),
            "{tb}"
        );
        let tc = get(&c);
        assert_eq!(
            (&tc["FromAccount"], &tc["comment"]),
            (&json!(""), &json!("split")),
            "{tc}"
        );
        assert!(tc.get("to").is_none(), "{tc}");
        let list = rpc
            .list_transactions(&p(vec![json!("*"), json!(20)]))
            .unwrap();
        let row = list
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["txid"] == json!(a.txid().to_string()))
            .expect("listed")
            .clone();
        assert_eq!(row["comment"], "rent", "{row}");
    };
    check(&rpc);

    // Opened again (a copy, since this one stays open): the notes are on disk
    let copy_path = net.dir.path().join("wallet-copy");
    net.wallet.save().unwrap();
    net.wallet.backup_to(&copy_path).unwrap();
    let copy = Arc::new(WalletDb::open(&copy_path, Network::Regtest).unwrap());
    let rpc_again = net.rpc_for(&copy);
    check(&rpc_again);
}

/// Transactions of one block are listed in the order the wallet first saw
/// them (nOrderPos, wallet.cpp:1046), not by their place in the block
#[test]
fn transactions_of_one_block_are_listed_in_first_seen_order() {
    let net = Net::new();
    let first_coin = net.mature_coin();
    let second_coin = net.mature_coin();
    let a_addr = net.wallet.new_receiving_address().unwrap();
    let b_addr = net.wallet.new_receiving_address().unwrap();
    let a = net.pay(&first_coin, &[(a_addr, 4 * COIN)]);
    let b = net.pay(&second_coin, &[(b_addr, 6 * COIN)]);
    // The wallet sees b first (relayed), then the block holds a before b
    assert!(net.wallet.add_mempool_tx(&b));
    net.mine(vec![a.clone(), b.clone()], &net.miner);

    let list = net
        .rpc()
        .list_transactions(&p(vec![json!("*"), json!(10)]))
        .unwrap();
    let txids: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["txid"].as_str().unwrap().to_string())
        .collect();
    let pos = |tx: &Transaction| {
        txids
            .iter()
            .position(|t| *t == tx.txid().to_string())
            .expect("listed")
    };
    // Oldest first: b, then a
    assert!(pos(&b) < pos(&a), "{txids:?}");
}
