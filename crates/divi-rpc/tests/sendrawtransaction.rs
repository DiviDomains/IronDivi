// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! sendrawtransaction checks done before the mempool, as Divi Core 3.0.0
//! rpcrawtransaction.cpp: already confirmed (-27) and the fee cap (-26),
//! -maxtxfee, read over the chain's coins and the mempool's outputs.

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
use divi_rpc::{Params, WalletRpc};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use serde_json::json;
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Net {
    chain: Arc<Chain>,
    _dir: tempfile::TempDir,
    wallet: Arc<WalletDb>,
}

impl Net {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
        let chain = Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap();
        let wallet = Arc::new(WalletDb::with_hd_wallet(
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        ));
        Net {
            chain: Arc::new(chain),
            _dir: dir,
            wallet,
        }
    }

    fn rpc(&self) -> WalletRpc {
        let rpc = WalletRpc::with_wallet_and_chain(self.wallet.clone(), self.chain.clone());
        rpc.set_tx_submit(Arc::new(|tx: Transaction| Ok(tx.txid())));
        rpc
    }

    /// Mine a block with `txs`; its coinbase pays 1250 DIVI to `pay_to`
    fn mine(&self, txs: Vec<Transaction>, pay_to: &Address) -> Transaction {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        // BIP34: the coinbase starts with the height
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        let coinbase = Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * COIN),
                Script::new_p2pkh(pay_to.hash.as_bytes()),
            )],
            lock_time: 0,
        };
        block.transactions.push(coinbase.clone());
        block.transactions.extend(txs);
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        // Proof of work for the block's bits
        let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        self.chain.accept_block(block).unwrap();
        assert_eq!(self.chain.height(), height);
        coinbase
    }
}

fn spend(net: &Net, coinbase: &Transaction, pay: i64) -> Transaction {
    let to = Address::from_pubkey_hash(Hash160::from_bytes([0x77; 20]), Network::Regtest);
    spend_to(net, coinbase, pay, &to)
}

/// A spend of `prev`'s first output, paying `pay` to `to`
fn spend_to(net: &Net, prev: &Transaction, pay: i64, to: &Address) -> Transaction {
    let (mut tx, prev) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(prev.txid(), 0),
            prev.vout[0].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(pay), to)
        .build();
    TransactionSigner::new(net.wallet.keystore())
        .sign_all_inputs(&mut tx, &prev)
        .unwrap();
    tx
}

fn code(r: Result<serde_json::Value, divi_rpc::Error>) -> (i32, String) {
    match r {
        Err(divi_rpc::Error::Rpc(e)) => (e.code, e.message),
        other => panic!("expected an RPC error, got {:?}", other),
    }
}

fn raw(tx: &Transaction) -> Params {
    Params::Array(vec![json!(hex::encode(serialize(tx)))])
}

#[test]
fn confirmed_transaction_is_already_in_block_chain() {
    let net = Net::new();
    let me = net.wallet.new_receiving_address().unwrap();
    let cb = net.mine(vec![], &me);
    // Regtest coinbases mature after 20 blocks
    for _ in 0..20 {
        net.mine(vec![], &me);
    }
    let tx = spend(&net, &cb, 1249 * COIN);
    net.mine(vec![tx.clone()], &me);
    assert_eq!(
        code(net.rpc().send_raw_transaction(&raw(&tx))),
        (-27, "transaction already in block chain".to_string())
    );
}

#[test]
fn fee_above_100_divi_needs_allowhighfees() {
    let net = Net::new();
    let me = net.wallet.new_receiving_address().unwrap();
    let cb = net.mine(vec![], &me);
    // 150 DIVI of fee
    let tx = spend(&net, &cb, 1100 * COIN);
    let rpc = net.rpc();
    assert_eq!(
        code(rpc.send_raw_transaction(&raw(&tx))),
        (
            -26,
            "Fees being paid are in excess of maximum fee, but fee override is not provided"
                .to_string()
        )
    );
    let with_override = Params::Array(vec![json!(hex::encode(serialize(&tx))), json!(true)]);
    let txid = rpc.send_raw_transaction(&with_override).unwrap();
    assert_eq!(txid, json!(tx.txid().to_string()));
}

/// A mempool holding the given transactions
struct Pool(Vec<Transaction>);

impl divi_rpc::blockchain::MempoolProvider for Pool {
    fn get_txids(&self) -> Vec<Hash256> {
        self.0.iter().map(|t| t.txid()).collect()
    }
    fn get_transaction(&self, txid: &Hash256) -> Option<Transaction> {
        self.0.iter().find(|t| t.txid() == *txid).cloned()
    }
    fn prioritise_transaction(&self, _: &Hash256, _: f64, _: i64) -> bool {
        false
    }
}

const EXCESS: &str =
    "Fees being paid are in excess of maximum fee, but fee override is not provided";

/// The inputs' value is read over the mempool too (CCoinsViewMemPool,
/// rpcrawtransaction.cpp:810-826): a fee paid from a mempool output is held to
/// the cap, and a transaction already in the mempool is relayed again (:875)
#[test]
fn fee_paid_from_a_mempool_output_is_held_to_the_cap() {
    let net = Net::new();
    let me = net.wallet.new_receiving_address().unwrap();
    let cb = net.mine(vec![], &me);
    let parent = spend_to(&net, &cb, 1249 * COIN, &me);
    // 150 DIVI of fee, from the parent's output in the mempool only
    let child = spend(&net, &parent, 1099 * COIN);
    let rpc = net.rpc();
    rpc.set_mempool(Arc::new(Pool(vec![parent.clone()])));
    assert_eq!(
        code(rpc.send_raw_transaction(&raw(&child))),
        (-26, EXCESS.to_string())
    );
    let with_override = Params::Array(vec![json!(hex::encode(serialize(&child))), json!(true)]);
    assert_eq!(
        rpc.send_raw_transaction(&with_override).unwrap(),
        json!(child.txid().to_string())
    );
    rpc.set_mempool(Arc::new(Pool(vec![parent, child.clone()])));
    assert_eq!(
        rpc.send_raw_transaction(&raw(&child)).unwrap(),
        json!(child.txid().to_string()),
        "in the mempool already: relayed, the fee not checked"
    );
}

/// A mempool with no transactions whose -maxtxfee is `0`, in satoshis
struct Capped(i64);

impl divi_rpc::blockchain::MempoolProvider for Capped {
    fn get_txids(&self) -> Vec<Hash256> {
        Vec::new()
    }
    fn prioritise_transaction(&self, _: &Hash256, _: f64, _: i64) -> bool {
        false
    }
    fn max_tx_fee(&self) -> Amount {
        Amount::from_sat(self.0)
    }
}

/// The cap is -maxtxfee (FeeAndPriorityCalculator::SetMaxFee, init.cpp:844;
/// rpcrawtransaction.cpp:882), not always 100 DIVI
#[test]
fn fee_cap_is_maxtxfee() {
    let net = Net::new();
    let me = net.wallet.new_receiving_address().unwrap();
    let cb = net.mine(vec![], &me);
    // 0.001 DIVI of fee
    let tx = spend(&net, &cb, 1250 * COIN - 100_000);
    let rpc = net.rpc();
    rpc.set_mempool(Arc::new(Capped(20_000)));
    assert_eq!(
        code(rpc.send_raw_transaction(&raw(&tx))),
        (-26, EXCESS.to_string())
    );
    rpc.set_mempool(Arc::new(Capped(100_000)));
    assert_eq!(
        rpc.send_raw_transaction(&raw(&tx)).unwrap(),
        json!(tx.txid().to_string()),
        "a fee equal to the cap is taken"
    );
}
