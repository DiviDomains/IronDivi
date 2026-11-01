// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet transactions that are not final yet, as Divi Core 3.0.0's wallet
//! treats them. A transaction in the mempool can be locked above the next
//! block: a block disconnected below its lock height gives it back to the
//! mempool (ChainTipManager.cpp:175-183 checks it with the tip still on its
//! block). Its coins are left out of AvailableCoins, so listunspent and a send
//! do not use them, while the unconfirmed balance still counts them
//! (AvailableUtxoCalculator.cpp:84, FilteredTransactionsCalculator.h:57-80).

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
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;
const SEQ_NOT_FINAL: u32 = 0xffff_fffe;

struct Node {
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    server: RpcServer,
    submitted: Arc<Mutex<Vec<Transaction>>>,
    _dir: tempfile::TempDir,
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
        let txs = block.transactions.clone();
        self.chain.accept_block(block).unwrap();
        divi_rpc::wallet::sync_wallet_with_chain(&self.wallet, &self.chain);
        self.server.set_height(height);
        txs[0].clone()
    }

    fn height(&self) -> u32 {
        self.chain.tip().unwrap().height
    }

    fn address(&self, account: &str) -> Address {
        Address::from_base58(
            self.ok("getnewaddress", vec![json!(account)])
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    /// Our own transaction, in the mempool, spending `coin` (worth `value`)
    /// to `outputs` with this lock time and every sequence not final
    fn own_locked(
        &self,
        coin: &TxOut,
        outpoint: OutPoint,
        outputs: &[(i64, &Address)],
        lock: u32,
    ) -> Transaction {
        let mut builder = TransactionBuilder::new().add_input(outpoint, coin.script_pubkey.clone());
        for (value, to) in outputs {
            builder = builder.add_output_to_address(Amount::from_sat(*value), to);
        }
        let (mut tx, prev) = builder.build();
        tx.lock_time = lock;
        for input in &mut tx.vin {
            input.sequence = SEQ_NOT_FINAL;
        }
        TransactionSigner::new(self.wallet.keystore())
            .sign_all_inputs(&mut tx, &prev)
            .unwrap();
        assert!(self.wallet.add_mempool_tx(&tx));
        tx
    }
}

fn nobody() -> Address {
    Address::from_pubkey_hash(Hash160::from_bytes([0x42; 20]), Network::Regtest)
}

/// A regtest node whose wallet holds two confirmed 100 DIVI coins, both paid
/// by one funder transaction; sends are recorded, not relayed
fn funded() -> (Node, Transaction) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain.clone(), wallet.clone());
    let submitted = Arc::new(Mutex::new(Vec::new()));
    let sink = submitted.clone();
    server
        .wallet()
        .set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            sink.lock().push(tx);
            Ok(txid)
        }));
    let n = Node {
        chain,
        wallet,
        server,
        submitted,
        _dir: dir,
    };
    let funder =
        WalletDb::with_hd_wallet(Network::Regtest, HdWallet::new(ChainMode::Divi).unwrap());
    let cb_addr = funder.new_receiving_address().unwrap();
    let coinbase = n.mine(vec![], &cb_addr);
    for _ in 0..20 {
        n.mine(vec![], &nobody());
    }
    let a = n.address("");
    let b = n.address("");
    let (mut tx, prev) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(100 * COIN), &a)
        .add_output_to_address(Amount::from_sat(100 * COIN), &b)
        .add_output_to_address(Amount::from_sat(1049 * COIN), &nobody())
        .build();
    TransactionSigner::new(funder.keystore())
        .sign_all_inputs(&mut tx, &prev)
        .unwrap();
    n.mine(vec![tx.clone()], &nobody());
    (n, tx)
}

fn unspent_txids(n: &Node, minconf: i64) -> Vec<String> {
    n.ok("listunspent", vec![json!(minconf)])
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["txid"].as_str().unwrap().to_string())
        .collect()
}

/// listunspent lists a coin of a mempool transaction only when the next block
/// could hold that transaction: IsFinalTx at the tip height plus one
/// (AvailableUtxoCalculator.cpp:84 with fOnlyConfirmed false, rpcrawtransaction.cpp:315)
#[test]
fn listunspent_leaves_out_a_coin_the_next_block_cannot_hold() {
    let (n, fund) = funded();
    let tip = n.height();
    let change = n.address("");
    let above = n.own_locked(
        &fund.vout[0],
        OutPoint::new(fund.txid(), 0),
        &[(99 * COIN, &change)],
        tip + 1,
    );
    let at_tip = n.own_locked(
        &fund.vout[1],
        OutPoint::new(fund.txid(), 1),
        &[(99 * COIN, &change)],
        tip,
    );
    let listed = unspent_txids(&n, 0);
    assert!(
        !listed.contains(&above.txid().to_string()),
        "a coin locked above the next block is listed"
    );
    assert!(
        listed.contains(&at_tip.txid().to_string()),
        "a coin final for the next block is not listed"
    );
    // getunconfirmedbalance has no finality check (WalletBalanceCalculator.cpp:31-36)
    assert_eq!(n.ok("getunconfirmedbalance", vec![]), json!(198.0));
    // ... nor has spendable_balance (WalletBalanceCalculator.cpp:80-87)
    assert_eq!(
        n.ok("getwalletinfo", vec![])["spendable_balance"],
        json!(198.0)
    );

    // One block later the next block can hold it
    n.mine(vec![], &nobody());
    assert!(unspent_txids(&n, 0).contains(&above.txid().to_string()));
}

/// A send with -spendzeroconfchange does not spend a coin the next block
/// cannot hold, so it never makes a transaction stuck behind its parent
/// (wallet.cpp:1848, AvailableUtxoCalculator.cpp:84)
#[test]
fn a_zero_conf_send_does_not_spend_a_coin_the_next_block_cannot_hold() {
    let (n, fund) = funded();
    n.wallet.set_spend_zero_conf_change(true);
    let tip = n.height();
    let change = n.address("");
    let above = n.own_locked(
        &fund.vout[0],
        OutPoint::new(fund.txid(), 0),
        &[(99 * COIN, &change)],
        tip + 1,
    );
    // The other coin alone cannot pay 150
    let refused = n.call(
        "sendtoaddress",
        vec![json!(nobody().to_base58()), json!(150.0)],
    );
    assert!(refused.is_err(), "sent {refused:?}");
    assert!(n.submitted.lock().is_empty());

    // Once the next block can hold it, its change can be spent
    n.mine(vec![], &nobody());
    n.ok(
        "sendtoaddress",
        vec![json!(nobody().to_base58()), json!(150.0)],
    );
    let sent = n.submitted.lock().last().cloned().unwrap();
    assert!(sent.vin.iter().any(|i| i.prevout.txid == above.txid()));
}
