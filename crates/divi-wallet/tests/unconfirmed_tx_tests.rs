// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Unconfirmed wallet transactions must survive a restart.
//!
//! The wallet used to keep its mempool transactions (our sends, unconfirmed
//! receives) in memory only, so a stop, crash or kill before the next block
//! dropped an unconfirmed send from the history and made its inputs spendable
//! again. Each test below drops the wallet without calling `save()`, which is
//! what a kill -9 does, and opens it again from disk.

use divi_primitives::{
    amount::Amount,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_wallet::{Address, HdWallet, Network, WalletDb};
use std::path::Path;
use tempfile::tempdir;

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon about";
const COIN: i64 = 100_000_000;

fn spend(prevouts: &[(Hash256, u32)], outputs: Vec<(i64, Script)>) -> Transaction {
    Transaction {
        version: 1,
        vin: prevouts
            .iter()
            .map(|(txid, vout)| TxIn {
                prevout: OutPoint {
                    txid: *txid,
                    vout: *vout,
                },
                script_sig: Script::default(),
                sequence: 0xffffffff,
            })
            .collect(),
        vout: outputs
            .into_iter()
            .map(|(v, script_pubkey)| TxOut {
                value: Amount::from_sat(v),
                script_pubkey,
            })
            .collect(),
        lock_time: 0,
    }
}

fn stranger() -> Script {
    Script::new_p2pkh(&[0xaa; 20])
}

fn mine(addr: &Address) -> Script {
    Script::new_p2pkh(addr.hash.as_bytes())
}

fn open(path: &Path) -> WalletDb {
    WalletDb::open(path, Network::Regtest).unwrap()
}

/// A wallet on disk holding one confirmed 100 DIVI coin at height 100, saved
/// the way the per-block save leaves it. Returns the wallet, the funding tx
/// and a change address for the send.
fn funded(path: &Path) -> (WalletDb, Transaction, Address) {
    let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
    let wallet = WalletDb::create_persistent(path, Network::Regtest, hd).unwrap();
    let addr = wallet.new_receiving_address().unwrap();
    let change = wallet.new_change_address().unwrap();
    let fund = spend(
        &[(Hash256::from_bytes([9u8; 32]), 0)],
        vec![(100 * COIN, mine(&addr))],
    );
    wallet.scan_block(
        Hash256::from_bytes([1u8; 32]),
        100,
        1_000,
        std::slice::from_ref(&fund),
    );
    wallet.set_last_scan_height(100);
    wallet.save().unwrap();
    (wallet, fund, change)
}

/// Our own send: 100 in, 30 to a stranger, 69.99 change, 0.01 fee.
fn own_send(fund: &Transaction, change: &Address) -> Transaction {
    spend(
        &[(fund.txid(), 0)],
        vec![
            (30 * COIN, stranger()),
            (70 * COIN - 1_000_000, mine(change)),
        ],
    )
}

fn assert_send_kept(wallet: &WalletDb, fund: &Transaction, send: &Transaction) {
    let rec = wallet
        .get_transaction(&send.txid())
        .expect("unconfirmed send missing after restart");
    assert_eq!(rec.category, "send");
    assert!(rec.block_height.is_none());
    assert_eq!(rec.fee.unwrap().as_sat(), 1_000_000);
    assert!(
        wallet
            .get_transactions(None)
            .iter()
            .any(|t| t.txid == send.txid()),
        "send not listed"
    );
    // The input stays spent: only the change is spendable, never the 100 coin
    let spendable = wallet.get_spendable_utxos(100, 0);
    assert!(
        spendable.iter().all(|u| u.txid != fund.txid()),
        "input of the unconfirmed send is spendable again"
    );
    assert_eq!(spendable.len(), 1);
    assert_eq!(spendable[0].txid, send.txid());
    // The change is unconfirmed balance, not getbalance's (Divi Core)
    assert_eq!(wallet.get_balance().as_sat(), 0);
    assert_eq!(
        wallet.get_unconfirmed_balance().as_sat(),
        70 * COIN - 1_000_000
    );
    assert_eq!(wallet.mempool_tx_count(), 1);
}

#[test]
fn unconfirmed_send_survives_restart_without_save() {
    let dir = tempdir().unwrap();
    let (wallet, fund, change) = funded(dir.path());
    let send = own_send(&fund, &change);
    assert!(wallet.add_mempool_tx(&send));
    drop(wallet); // no save(): a kill -9 right after the send returned

    let wallet = open(dir.path());
    assert_send_kept(&wallet, &fund, &send);
}

#[test]
fn unconfirmed_send_survives_clean_shutdown_save() {
    let dir = tempdir().unwrap();
    let (wallet, fund, change) = funded(dir.path());
    let send = own_send(&fund, &change);
    assert!(wallet.add_mempool_tx(&send));
    wallet.save().unwrap(); // what stop / SIGTERM / SIGINT do
    drop(wallet);

    let wallet = open(dir.path());
    assert_send_kept(&wallet, &fund, &send);
    // A second restart does not duplicate it
    drop(wallet);
    let wallet = open(dir.path());
    assert_send_kept(&wallet, &fund, &send);
}

#[test]
fn unconfirmed_chain_of_sends_survives_restart() {
    let dir = tempdir().unwrap();
    let (wallet, fund, change) = funded(dir.path());
    let send = own_send(&fund, &change);
    assert!(wallet.add_mempool_tx(&send));
    // Spend our own unconfirmed change
    let child = spend(
        &[(send.txid(), 1)],
        vec![
            (10 * COIN, stranger()),
            (60 * COIN - 2_000_000, mine(&change)),
        ],
    );
    assert!(wallet.add_mempool_tx(&child));
    drop(wallet);

    let wallet = open(dir.path());
    assert_eq!(wallet.mempool_tx_count(), 2);
    let spendable = wallet.get_spendable_utxos(100, 0);
    assert_eq!(spendable.len(), 1);
    assert_eq!(spendable[0].txid, child.txid());
    assert_eq!(wallet.get_balance().as_sat(), 0);
    assert_eq!(
        wallet.get_unconfirmed_balance().as_sat(),
        60 * COIN - 2_000_000
    );
}

#[test]
fn unconfirmed_receive_survives_restart() {
    let dir = tempdir().unwrap();
    let (wallet, _fund, change) = funded(dir.path());
    let incoming = spend(
        &[(Hash256::from_bytes([7u8; 32]), 3)],
        vec![(5 * COIN, mine(&change)), (COIN, stranger())],
    );
    assert!(wallet.add_mempool_tx(&incoming));
    drop(wallet);

    let wallet = open(dir.path());
    let rec = wallet.get_transaction(&incoming.txid()).unwrap();
    assert_eq!(rec.category, "receive");
    assert_eq!(rec.amount, 5 * COIN);
    assert_eq!(wallet.get_unconfirmed_balance().as_sat(), 5 * COIN);
}

#[test]
fn confirmed_send_is_not_restored_as_unconfirmed() {
    let dir = tempdir().unwrap();
    let (wallet, fund, change) = funded(dir.path());
    let send = own_send(&fund, &change);
    assert!(wallet.add_mempool_tx(&send));
    wallet.scan_block(
        Hash256::from_bytes([2u8; 32]),
        101,
        1_060,
        std::slice::from_ref(&send),
    );
    wallet.set_last_scan_height(101);
    wallet.save_incremental().unwrap();
    assert_eq!(wallet.mempool_tx_count(), 0);
    drop(wallet);

    let wallet = open(dir.path());
    assert_eq!(wallet.mempool_tx_count(), 0);
    let rec = wallet.get_transaction(&send.txid()).unwrap();
    assert_eq!(rec.block_height, Some(101));
    assert_eq!(
        wallet
            .get_transactions(None)
            .iter()
            .filter(|t| t.txid == send.txid())
            .count(),
        1
    );
}

#[test]
fn evicted_send_is_forgotten_on_disk_too() {
    let dir = tempdir().unwrap();
    let (wallet, fund, change) = funded(dir.path());
    let send = own_send(&fund, &change);
    assert!(wallet.add_mempool_tx(&send));
    assert!(wallet.remove_mempool_tx(&send.txid()));
    drop(wallet);

    let wallet = open(dir.path());
    assert_eq!(wallet.mempool_tx_count(), 0);
    assert!(wallet.get_transaction(&send.txid()).is_none());
    assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
}

#[test]
fn send_conflicted_by_a_block_is_forgotten_on_disk_too() {
    let dir = tempdir().unwrap();
    let (wallet, fund, change) = funded(dir.path());
    let send = own_send(&fund, &change);
    assert!(wallet.add_mempool_tx(&send));
    // A different spend of the same coin confirms
    let other = spend(&[(fund.txid(), 0)], vec![(99 * COIN, stranger())]);
    wallet.scan_block(
        Hash256::from_bytes([3u8; 32]),
        101,
        1_060,
        std::slice::from_ref(&other),
    );
    wallet.set_last_scan_height(101);
    wallet.save_incremental().unwrap();
    assert_eq!(wallet.mempool_tx_count(), 0);
    drop(wallet);

    let wallet = open(dir.path());
    assert_eq!(wallet.mempool_tx_count(), 0);
    assert!(wallet.get_transaction(&send.txid()).is_none());
    assert_eq!(wallet.get_balance().as_sat(), 0);
}
