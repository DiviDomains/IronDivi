// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! sendrawtransaction checks done before the mempool, as Divi Core 3.0.0
//! rpcrawtransaction.cpp: already confirmed (-27) and the fee cap (-26).

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash160,
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
        block.header.version = 1;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        let mut cb_sig = vec![0x04];
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
        self.chain.accept_block(block).unwrap();
        assert_eq!(self.chain.height(), height);
        coinbase
    }
}

fn spend(net: &Net, coinbase: &Transaction, pay: i64) -> Transaction {
    let to = Address::from_pubkey_hash(Hash160::from_bytes([0x77; 20]), Network::Regtest);
    let (mut tx, prev) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(pay), &to)
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
