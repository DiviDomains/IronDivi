// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A wallet send picks its coins and commits with no relayed transaction let
//! into the mempool in between, as Divi Core runs it under cs_main
//! (rpcserver.cpp:452-454, :1060-1093; the `tx` handler takes cs_main too,
//! main.cpp:726). Here a peer's transaction spending the same coin is relayed
//! at the worst moment on purpose: after the wallet has picked the coin and
//! before its own transaction reaches the mempool.

use divi_crypto::compute_merkle_root;
use divi_node::Mempool;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, WalletRpc};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

const COIN: i64 = 100_000_000;

/// Mine a block whose coinbase pays 1250 DIVI to `pay_to`; the wallet scans it
fn mine(chain: &Chain, wallet: &WalletDb, pay_to: &Address) -> Transaction {
    let tip = chain.tip().unwrap();
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
    block.header.merkle_root = compute_merkle_root(&block.transactions);
    let target = Hash256::from_compact(block.header.bits);
    while divi_crypto::compute_block_hash(&block.header) > target {
        block.header.nonce += 1;
    }
    let time = block.header.time;
    let txs = block.transactions.clone();
    let hash = chain.accept_block(block).unwrap().hash;
    wallet.scan_block(hash, height, time, &txs);
    txs[0].clone()
}

/// Fee of a transaction spending chain coins
fn fee_of(chain: &Chain, tx: &Transaction) -> Amount {
    let value_in: i64 = tx
        .vin
        .iter()
        .map(|i| {
            chain
                .get_utxo(&i.prevout)
                .unwrap()
                .expect("input")
                .value
                .as_sat()
        })
        .sum();
    Amount::from_sat(value_in - tx.vout.iter().map(|o| o.value.as_sat()).sum::<i64>())
}

#[test]
fn a_relayed_spend_of_the_same_coin_waits_for_the_send() {
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
    // The wallet's one coin: a coinbase, mature after 20 more blocks
    let own = wallet.new_receiving_address().unwrap();
    let other = Address::from_pubkey_hash(Hash160::from_bytes([0x99; 20]), Network::Regtest);
    let coinbase = mine(&chain, &wallet, &own);
    for _ in 0..20 {
        mine(&chain, &wallet, &other);
    }
    let coin = OutPoint::new(coinbase.txid(), 0);

    // The same coin spent elsewhere, as a peer holding the same key would
    // (both wallets in scripts/int-args come from one phrase)
    let (mut theirs, prev) = TransactionBuilder::new()
        .add_input(coin, coinbase.vout[0].script_pubkey.clone())
        .add_output_to_address(Amount::from_sat(1249 * COIN), &other)
        .build();
    TransactionSigner::new(wallet.keystore())
        .sign_all_inputs(&mut theirs, &prev)
        .unwrap();
    let their_fee = fee_of(&chain, &theirs);

    let mempool = Arc::new(Mempool::new(Default::default()));
    let mirror = wallet.clone();
    mempool.add_added_listener(Arc::new(move |tx: &Transaction| {
        mirror.add_mempool_tx(tx);
    }));
    let rpc = WalletRpc::with_wallet_and_chain(wallet.clone(), chain.clone());
    rpc.set_mempool(mempool.clone());

    // At submit the wallet has picked the coin: now the peer's transaction is
    // relayed from another thread, given up to a second to get in first
    let relayed: Arc<Mutex<Option<Result<Hash256, String>>>> = Arc::new(Mutex::new(None));
    let relay_thread = Arc::new(Mutex::new(None));
    {
        let mempool = mempool.clone();
        let chain = chain.clone();
        let relayed = relayed.clone();
        let relay_thread = relay_thread.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let (pool, theirs, result) = (mempool.clone(), theirs.clone(), relayed.clone());
            let handle = std::thread::spawn(move || {
                let out = pool
                    .add_relayed(theirs, their_fee)
                    .map_err(|e| e.to_string());
                *result.lock() = Some(out);
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while !handle.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            *relay_thread.lock() = Some(handle);
            let fee = fee_of(&chain, &tx);
            mempool
                .add(tx, fee)
                .map_err(|e| divi_rpc::TxSubmitError::Failed(e.to_string()))
        }));
    }

    let sent = rpc.send_to_address(&Params::Array(vec![
        serde_json::json!(other.to_string()),
        serde_json::json!(10),
    ]));
    if let Some(handle) = relay_thread.lock().take() {
        handle.join().unwrap();
    }
    let txid = sent.expect("the send commits: the relayed spend came after it");
    let in_pool: Vec<String> = mempool.get_txids().iter().map(|t| t.to_string()).collect();
    assert_eq!(
        in_pool,
        vec![txid.as_str().unwrap().to_string()],
        "the mempool holds the send and nothing else"
    );
    assert!(
        matches!(relayed.lock().as_ref(), Some(Err(e)) if e.contains("conflict")),
        "the relayed spend is refused as the conflict: {:?}",
        relayed.lock()
    );
}
