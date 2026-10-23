// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet sends on a regtest chain pick coins, pay fees and make change as
//! Divi Core 3.0.0's wallet does (wallet.cpp CreateTransaction,
//! MinimumFeeCoinSelectionAlgorithm.cpp, rpcwallet.cpp).

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

/// A regtest chain, a funder wallet with mature coins, and the wallet under test
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
        let new_wallet = || {
            Arc::new(WalletDb::with_hd_wallet(
                Network::Regtest,
                HdWallet::new(ChainMode::Divi).unwrap(),
            ))
        };
        Net {
            chain: Arc::new(chain),
            _dir: dir,
            funder: new_wallet(),
            wallet: new_wallet(),
            submitted: Arc::new(Mutex::new(Vec::new())),
            miner: Address::from_pubkey_hash(Hash160::from_bytes([0x99; 20]), Network::Regtest),
        }
    }

    fn rpc(&self) -> WalletRpc {
        let rpc = WalletRpc::with_wallet_and_chain(self.wallet.clone(), self.chain.clone());
        let submitted = self.submitted.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            submitted.lock().push(tx);
            Ok(txid)
        }));
        rpc
    }

    /// Mine a block holding `txs` whose coinbase pays 1250 DIVI to `pay_to`;
    /// both wallets scan it
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

    /// Give the wallet under test confirmed coins of exactly these values (in
    /// satoshis), on new addresses, from a mature coinbase of the funder
    fn fund(&self, values: &[i64]) -> Vec<Address> {
        let cb_addr = self.funder.new_receiving_address().unwrap();
        let coinbase = self.mine(vec![], &cb_addr);
        // Coinbase maturity 20 on regtest: spendable with 21 confirmations
        for _ in 0..20 {
            self.mine(vec![], &self.miner);
        }
        let mut builder = TransactionBuilder::new().add_input(
            OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        );
        let mut addresses = Vec::new();
        for value in values {
            let addr = self.wallet.new_receiving_address().unwrap();
            builder = builder.add_output_to_address(Amount::from_sat(*value), &addr);
            addresses.push(addr);
        }
        let rest = 1250 * COIN - values.iter().sum::<i64>() - COIN / 100;
        builder = builder.add_output_to_address(Amount::from_sat(rest), &self.miner);
        let (mut tx, prev) = builder.build();
        assert_eq!(
            TransactionSigner::new(self.funder.keystore())
                .sign_all_inputs(&mut tx, &prev)
                .unwrap(),
            1
        );
        self.mine(vec![tx], &self.miner);
        addresses
    }

    fn last_submitted(&self) -> Transaction {
        self.submitted
            .lock()
            .last()
            .cloned()
            .expect("a transaction was sent")
    }

    /// Fee of a transaction spending the wallet's confirmed coins
    fn fee_of(&self, tx: &Transaction) -> i64 {
        let value_in: i64 = tx
            .vin
            .iter()
            .map(|i| {
                self.chain
                    .get_utxo(&i.prevout)
                    .unwrap()
                    .expect("input on chain")
                    .value
                    .as_sat()
            })
            .sum();
        value_in - tx.vout.iter().map(|o| o.value.as_sat()).sum::<i64>()
    }
}

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn dest() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

fn paid_to(tx: &Transaction, addr: &Address) -> Vec<i64> {
    let script = Script::new_p2pkh(addr.hash.as_bytes());
    tx.vout
        .iter()
        .filter(|o| o.script_pubkey == script)
        .map(|o| o.value.as_sat())
        .collect()
}

/// A coin locked with lockunspent is never spent (Divi Core
/// AvailableUtxoCalculator.cpp:91)
#[test]
fn locked_coins_are_never_spent() {
    let net = Net::new();
    net.fund(&[50 * COIN, 30 * COIN]);
    let rpc = net.rpc();
    let coins: Vec<Value> = net
        .wallet
        .get_spendable_utxos(net.chain.height(), 1)
        .iter()
        .map(|u| json!({"txid": u.txid.to_string(), "vout": u.vout}))
        .collect();
    assert_eq!(coins.len(), 2);
    rpc.lock_unspent(&p(vec![json!(false), Value::Array(coins.clone())]))
        .unwrap();
    assert!(rpc
        .send_to_address(&p(vec![json!(dest().to_string()), json!(10.0)]))
        .is_err());
    assert!(net.submitted.lock().is_empty());

    // Unlock the 30 DIVI coin: the send uses it, never the locked 50
    let thirty = net
        .wallet
        .get_spendable_utxos(net.chain.height(), 1)
        .into_iter()
        .find(|u| u.value.as_sat() == 30 * COIN)
        .unwrap();
    rpc.lock_unspent(&p(vec![
        json!(true),
        json!([{"txid": thirty.txid.to_string(), "vout": thirty.vout}]),
    ]))
    .unwrap();
    rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(10.0)]))
        .unwrap();
    let tx = net.last_submitted();
    assert_eq!(tx.vin.len(), 1);
    assert_eq!(tx.vin[0].prevout, thirty.outpoint());
}

/// Our own unconfirmed change is not spent: Divi Core spends only confirmed
/// coins unless -spendzeroconfchange (wallet.cpp:1843)
#[test]
fn unconfirmed_change_is_not_spent() {
    let net = Net::new();
    net.fund(&[50 * COIN]);
    let rpc = net.rpc();
    rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(10.0)]))
        .unwrap();
    assert!(net.wallet.add_mempool_tx(&net.last_submitted()));
    assert!(rpc
        .send_to_address(&p(vec![json!(dest().to_string()), json!(10.0)]))
        .is_err());
    assert_eq!(net.submitted.lock().len(), 1);
}

/// The fee is Divi Core's estimate at the minimum relay fee: 2,260 sat for
/// one input, one payee and change, as a Core 3.0.0 wallet pays
#[test]
fn send_pays_divi_core_s_fee() {
    let net = Net::new();
    net.fund(&[1250 * COIN - 2 * COIN]);
    let rpc = net.rpc();
    rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(10.0)]))
        .unwrap();
    let tx = net.last_submitted();
    assert_eq!(net.fee_of(&tx), 2_260);
    assert_eq!(paid_to(&tx, &dest()), vec![10 * COIN]);
}

/// receiver_pays takes the fee from the payment; an unknown mode is refused
/// (Divi Core rpcwallet.cpp:1336-1356)
#[test]
fn receiver_pays_takes_the_fee_from_the_payment() {
    let net = Net::new();
    net.fund(&[100 * COIN]);
    let rpc = net.rpc();
    rpc.send_to_address(&p(vec![
        json!(dest().to_string()),
        json!(10.0),
        json!("receiver_pays"),
    ]))
    .unwrap();
    let tx = net.last_submitted();
    assert_eq!(paid_to(&tx, &dest()), vec![10 * COIN - net.fee_of(&tx)]);

    let err = rpc
        .send_to_address(&p(vec![
            json!(dest().to_string()),
            json!(1.0),
            json!("no_such_mode"),
        ]))
        .unwrap_err();
    assert!(format!("{:?}", err).contains("Unknown option"), "{:?}", err);
}

/// Selection keeps room for change that is not dust: a coin covering the
/// payment and fee with under 5,460 sat left takes a second coin with it
#[test]
fn selection_leaves_room_for_non_dust_change() {
    let net = Net::new();
    net.fund(&[10 * COIN + 2_260 + 1_000, COIN]);
    let rpc = net.rpc();
    rpc.send_to_address(&p(vec![json!(dest().to_string()), json!(10.0)]))
        .unwrap();
    let tx = net.last_submitted();
    assert_eq!(tx.vin.len(), 2);
    assert_eq!(net.fee_of(&tx), 3_740);
}

/// sendmany from a named account spends only that account's coins, and an
/// amount may be {"amount", "repetitions"} (Divi Core AccountCoinSelector,
/// parseMultiSendJson)
#[test]
fn sendmany_spends_the_account_s_coins_and_repeats_outputs() {
    let net = Net::new();
    let addrs = net.fund(&[20 * COIN, 100 * COIN]);
    net.wallet.set_account(&addrs[0], "savings");
    let rpc = net.rpc();

    let mut amounts = serde_json::Map::new();
    amounts.insert(dest().to_string(), json!(50.0));
    assert!(rpc
        .send_many(&p(vec![json!("savings"), Value::Object(amounts)]))
        .is_err());

    let mut amounts = serde_json::Map::new();
    amounts.insert(dest().to_string(), json!({"amount": 2.0, "repetitions": 3}));
    rpc.send_many(&p(vec![json!("savings"), Value::Object(amounts)]))
        .unwrap();
    let tx = net.last_submitted();
    assert_eq!(paid_to(&tx, &dest()), vec![2 * COIN; 3]);
    let savings = net
        .wallet
        .get_spendable_utxos(net.chain.height(), 1)
        .into_iter()
        .find(|u| u.value.as_sat() == 20 * COIN)
        .unwrap();
    assert_eq!(tx.vin.len(), 1);
    assert_eq!(tx.vin[0].prevout, savings.outpoint());
}

/// reclaimvaultfunds sends its change to a new key of the wallet, as Divi
/// Core does with no change script (rpcwallet.cpp:1158-1186, wallet.cpp:1905-1910)
#[test]
fn reclaim_change_goes_to_a_new_key() {
    let net = Net::new();
    net.fund(&[300 * COIN]);
    let rpc = net.rpc();
    let owner = net.wallet.new_receiving_address().unwrap();
    let manager = Address::from_pubkey_hash(Hash160::from_bytes([0x77; 20]), Network::Regtest);
    rpc.fund_vault(&p(vec![
        json!(format!("{}:{}", owner, manager)),
        json!(100.0),
    ]))
    .unwrap();
    let funding = net.last_submitted();
    net.mine(vec![funding], &net.miner);

    rpc.reclaim_vault_funds(&p(vec![json!(dest().to_string()), json!(10.0)]))
        .unwrap();
    let tx = net.last_submitted();
    let change: Vec<&TxOut> = tx
        .vout
        .iter()
        .filter(|o| o.script_pubkey != Script::new_p2pkh(dest().hash.as_bytes()))
        .collect();
    assert_eq!(change.len(), 1);
    assert!(change[0].script_pubkey.is_p2pkh(), "change is not P2PKH");
    assert!(net.wallet.is_mine_script(&change[0].script_pubkey));
}

/// listunspent leaves out locked coins and immature coinbase outputs, as
/// Divi Core's (which lists what AvailableCoins gives a send)
#[test]
fn listunspent_leaves_out_locked_and_immature_coins() {
    let net = Net::new();
    net.fund(&[50 * COIN, 30 * COIN]);
    // A fresh coinbase to the wallet: immature
    let reward_addr = net.wallet.new_receiving_address().unwrap();
    net.mine(vec![], &reward_addr);
    let rpc = net.rpc();
    let listed = |rpc: &WalletRpc| -> Vec<i64> {
        let mut v: Vec<i64> = rpc
            .list_unspent(&p(vec![]))
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|u| (u["amount"].as_f64().unwrap() * COIN as f64).round() as i64)
            .collect();
        v.sort();
        v
    };
    assert_eq!(listed(&rpc), vec![30 * COIN, 50 * COIN]);
    let fifty = net
        .wallet
        .get_spendable_utxos(net.chain.height(), 1)
        .into_iter()
        .find(|u| u.value.as_sat() == 50 * COIN)
        .unwrap();
    rpc.lock_unspent(&p(vec![
        json!(false),
        json!([{"txid": fifty.txid.to_string(), "vout": fifty.vout}]),
    ]))
    .unwrap();
    assert_eq!(listed(&rpc), vec![30 * COIN]);
}
