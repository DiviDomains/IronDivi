// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Time locks in the wallet are read on Divi Core's clock, GetAdjustedTime:
//! the mocked time when one is set, plus the network offset
//! (TransactionFinalityHelpers.cpp:16-17, timedata.cpp:35-38). One test only:
//! the mocked time is the process's.

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
/// by one funder transaction; sends are kept here, not relayed
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
    let sink = Arc::new(Mutex::new(Vec::new()));
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

/// A payment time-locked between the node's clock and the system clock: Divi
/// Core's wallet holds it not final, so the received-by totals and an
/// account's balance leave it out (rpcwallet.cpp:400, :1473, :1821) and
/// listunspent leaves out our own such coin (AvailableUtxoCalculator.cpp:84),
/// until the clock passes the lock
#[test]
fn the_wallet_reads_time_locks_on_the_nodes_clock() {
    let (n, fund) = funded();
    let fin = n.address("fin");
    let change = n.address("");
    let lock = divi_primitives::clock::system_now() as u32 - 60;
    let received = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint::new(Hash256::from_bytes([7u8; 32]), 0),
            script_sig: Script::default(),
            sequence: SEQ_NOT_FINAL,
        }],
        vout: vec![TxOut::new(
            Amount::from_sat(5 * COIN),
            Script::new_p2pkh(fin.hash.as_bytes()),
        )],
        lock_time: lock,
    };
    assert!(n.wallet.add_mempool_tx(&received));
    let own = n.own_locked(
        &fund.vout[0],
        OutPoint::new(fund.txid(), 0),
        &[(99 * COIN, &change)],
        lock,
    );
    let fin = json!(fin.to_base58());
    let totals = |n: &Node| {
        let listed = n.ok("listreceivedbyaddress", vec![json!(0)]);
        let listed = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["address"] == fin)
            .map(|e| e["amount"].clone());
        (
            n.ok("getreceivedbyaddress", vec![fin.clone(), json!(0)]),
            n.ok("getreceivedbyaccount", vec![json!("fin"), json!(0)]),
            n.ok("getbalance", vec![json!("fin"), json!(0)]),
            listed,
            unspent_txids(n, 0).contains(&own.txid().to_string()),
        )
    };

    divi_primitives::clock::set_mock_time(i64::from(lock) - 600);
    let behind = totals(&n);
    divi_primitives::clock::set_mock_time(0);
    let past = totals(&n);

    assert_eq!(behind, (json!(0.0), json!(0.0), json!(0.0), None, false));
    assert_eq!(
        past,
        (json!(5.0), json!(5.0), json!(5.0), Some(json!(5.0)), true)
    );
}
