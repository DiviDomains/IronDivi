// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! listreceivedby*, listaccounts and listunspent as Divi Core 3.0.0 answers
//! them: from the address book, with watched addresses on request
//! (rpcwallet.cpp:1793-1912, :2320-2350; rpcrawtransaction.cpp:336-339).

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
    _dir: tempfile::TempDir,
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
            _dir: dir,
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

fn divi(v: &Value) -> f64 {
    v.as_f64().unwrap()
}

/// A funded address handed out by getnewaddress (so it is in the address book)
fn book_address(net: &Net) -> Address {
    let a = net.rpc().get_new_address(&Params::None).unwrap();
    Address::from_base58(a.as_str().unwrap()).unwrap()
}

/// ListReceived counts a watched address only with includeWatchonly, and
/// marks it involvesWatchonly (rpcwallet.cpp:1805-1809, :1843, :1874-1875)
#[test]
fn listreceived_counts_watched_addresses_on_request() {
    let net = Net::new();
    net.fund(2);
    let watched = watched_address(0x41);
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
        .list_received_by_address(&p(vec![json!(0), json!(true), json!(true)]))
        .unwrap();
    let row = with
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["address"] == json!(watched.to_string()))
        .unwrap_or_else(|| panic!("watched address missing: {with}"))
        .clone();
    assert_eq!(divi(&row["amount"]), 7.0, "{row}");
    assert_eq!(row["involvesWatchonly"], json!(true), "{row}");
    assert_eq!(row["account"], "watch");
    let without = rpc
        .list_received_by_address(&p(vec![json!(0), json!(false), json!(false)]))
        .unwrap();
    assert!(
        !without
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["address"] == json!(watched.to_string())),
        "{without}"
    );

    let accounts = rpc
        .list_received_by_account(&p(vec![json!(0), json!(true), json!(true)]))
        .unwrap();
    let watch = accounts
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["account"] == "watch")
        .unwrap_or_else(|| panic!("{accounts}"))
        .clone();
    assert_eq!(divi(&watch["amount"]), 7.0, "{watch}");
    assert_eq!(watch["involvesWatchonly"], json!(true));
}

/// listaccounts gives every address-book name its GetAccountBalance; the ""
/// account holds the unnamed addresses' coins (rpcwallet.cpp:2320-2350, :383-412)
#[test]
fn listaccounts_is_each_names_account_balance() {
    let net = Net::new();
    let coin = net.mature_coin();
    let plain = book_address(&net);
    let named = book_address(&net);
    net.rpc()
        .set_account(&p(vec![json!(named.to_string()), json!("savings")]))
        .unwrap();
    let watched = watched_address(0x42);
    net.rpc()
        .import_address(&p(vec![
            json!(watched.to_string()),
            json!("watch"),
            json!(false),
        ]))
        .unwrap();
    net.mine(
        vec![net.pay(
            &coin,
            &[(plain, 5 * COIN), (named, 3 * COIN), (watched, 2 * COIN)],
        )],
        &net.miner,
    );
    let rpc = net.rpc();
    let accounts = rpc.list_accounts(&Params::None).unwrap();
    assert_eq!(divi(&accounts[""]), 5.0, "{accounts}");
    assert_eq!(divi(&accounts["savings"]), 3.0, "{accounts}");
    assert!(accounts.get("watch").is_none(), "{accounts}");
    let with_watch = rpc.list_accounts(&p(vec![json!(1), json!(true)])).unwrap();
    assert_eq!(divi(&with_watch["watch"]), 2.0, "{with_watch}");
    for name in ["", "savings"] {
        assert_eq!(
            divi(&accounts[name]),
            divi(&rpc.get_balance(&p(vec![json!(name)])).unwrap()),
            "listaccounts and getbalance disagree for {name:?}"
        );
    }
}

/// listunspent names the account of an address-book address only; a coin of a
/// key the wallet never handed out has no account (rpcrawtransaction.cpp:336-339)
#[test]
fn listunspent_account_only_for_address_book_addresses() {
    let net = Net::new();
    let coin = net.mature_coin();
    let handed_out = book_address(&net);
    let pooled = net.wallet.new_receiving_address().unwrap();
    net.mine(
        vec![net.pay(
            &coin,
            &[(handed_out.clone(), 4 * COIN), (pooled.clone(), 6 * COIN)],
        )],
        &net.miner,
    );
    let list = net.rpc().list_unspent(&Params::None).unwrap();
    let find = |a: &Address| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|e| e["address"] == json!(a.to_string()))
            .unwrap_or_else(|| panic!("{a} not listed: {list}"))
            .clone()
    };
    assert_eq!(find(&handed_out)["account"], json!(""));
    assert!(find(&pooled).get("account").is_none(), "{}", find(&pooled));
}

/// Moving an account's unused current address to another account gives the
/// old account a new current address (setaccount, rpcwallet.cpp:609-615)
#[test]
fn setaccount_of_the_current_address_gives_the_old_account_a_new_one() {
    let net = Net::new();
    let rpc = net.rpc();
    let first = book_address(&net);
    assert_eq!(
        rpc.get_account_address(&p(vec![json!("")])).unwrap(),
        json!(first.to_string())
    );
    rpc.set_account(&p(vec![json!(first.to_string()), json!("moved")]))
        .unwrap();
    // The new address is in the address book at once, before anyone asks
    // for it (divid's listreceivedbyaddress 0 true lists it)
    let unnamed = rpc.get_addresses_by_account(&p(vec![json!("")])).unwrap();
    assert_eq!(unnamed.as_array().unwrap().len(), 1, "{unnamed}");
    let current = rpc.get_account_address(&p(vec![json!("")])).unwrap();
    assert_ne!(current, json!(first.to_string()));
    let unnamed = rpc.get_addresses_by_account(&p(vec![json!("")])).unwrap();
    assert_eq!(unnamed, json!([current]), "{unnamed}");

    // An address that is not the account's current one moves alone
    let second = book_address(&net);
    let third = book_address(&net);
    rpc.set_account(&p(vec![json!(second.to_string()), json!("moved")]))
        .unwrap();
    let unnamed = rpc.get_addresses_by_account(&p(vec![json!("")])).unwrap();
    assert_eq!(unnamed.as_array().unwrap().len(), 2, "{unnamed}");
    assert!(unnamed
        .as_array()
        .unwrap()
        .contains(&json!(third.to_string())));
}
