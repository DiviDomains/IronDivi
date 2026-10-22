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

//! Vault RPCs against a regtest chain: an owner wallet funds a vault that a
//! separate manager wallet registers, as on a real two-party setup. Expected
//! behaviour follows Divi Core 3.0.0 (wallet_ismine.cpp, AvailableUtxoCalculator.cpp,
//! rpcwallet.cpp).

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, WalletRpc};
use divi_script::StakingVaultScript;
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{Address, HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;
/// Value of the vault output funded in `setup`
const VAULT_DIVI: i64 = 1200;
/// The manager's own plain coin, paid by the owner in the funding transaction
const MANAGER_PLAIN_DIVI: i64 = 40;

/// A regtest chain with a transaction index, and the wallets that follow it
struct Net {
    chain: Arc<Chain>,
    _dir: tempfile::TempDir,
    wallets: Vec<Arc<WalletDb>>,
    /// Transactions handed to the submit callback of any RPC handler
    submitted: Arc<Mutex<Vec<Transaction>>>,
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
        Net {
            chain: Arc::new(chain),
            _dir: dir,
            wallets: Vec::new(),
            submitted: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn wallet(&mut self) -> Arc<WalletDb> {
        let hd = HdWallet::new(ChainMode::Divi).unwrap();
        let w = Arc::new(WalletDb::with_hd_wallet(Network::Regtest, hd));
        self.wallets.push(w.clone());
        w
    }

    fn rpc(&self, wallet: &Arc<WalletDb>) -> WalletRpc {
        let rpc = WalletRpc::with_wallet_and_chain(wallet.clone(), self.chain.clone());
        let submitted = self.submitted.clone();
        rpc.set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            submitted.lock().push(tx);
            Ok(txid)
        }));
        rpc
    }

    /// Mine a block holding `txs`, its coinbase paying 1250 DIVI to `pay_to`,
    /// and let every wallet scan it
    fn mine(&self, txs: Vec<Transaction>, pay_to: &Address) -> Hash256 {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 1;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        let mut cb_sig = vec![0x04];
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
        let time = block.header.time;
        let txs = block.transactions.clone();
        let hash = self.chain.accept_block(block).unwrap().hash;
        assert_eq!(self.chain.height(), height, "block was not connected");
        for w in &self.wallets {
            w.scan_block(hash, height, time, &txs);
        }
        hash
    }

    /// Mine everything the RPC handlers submitted so far
    fn mine_submitted(&self, pay_to: &Address) {
        let txs: Vec<Transaction> = self.submitted.lock().drain(..).collect();
        self.mine(txs, pay_to);
    }
}

fn p(v: Vec<Value>) -> Params {
    Params::Array(v)
}

fn vault_script(owner: &Address, manager: &Address) -> Script {
    let mut o = [0u8; 20];
    o.copy_from_slice(owner.hash.as_bytes());
    let mut m = [0u8; 20];
    m.copy_from_slice(manager.hash.as_bytes());
    StakingVaultScript::new(o, m).to_script()
}

/// The owner spends the output of a mined `coinbase` into vault owner:manager
/// (`vault_divi`), a plain payment of `plain_divi` to `plain_to`, and change;
/// returns the signed funding transaction.
fn fund_vault_tx(
    owner: &WalletDb,
    coinbase: &Transaction,
    vault: Script,
    vault_divi: i64,
    plain_to: &Address,
    plain_divi: i64,
    change: &Address,
) -> Transaction {
    let (mut tx, prev) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(coinbase.txid(), 0),
            coinbase.vout[0].script_pubkey.clone(),
        )
        .add_output(Amount::from_sat(vault_divi * COIN), vault)
        .add_output_to_address(Amount::from_sat(plain_divi * COIN), plain_to)
        .add_output_to_address(
            Amount::from_sat((1250 - vault_divi - plain_divi) * COIN - 10_000),
            change,
        )
        .build();
    let signed = TransactionSigner::new(owner.keystore())
        .sign_all_inputs(&mut tx, &prev)
        .unwrap();
    assert_eq!(signed, 1);
    tx
}

/// Owner wallet O and manager wallet M on one chain. O holds plain coins and
/// funds a 1200 DIVI vault O:M in the same transaction that pays M a plain
/// 40 DIVI coin. As on testnet the vault output is bigger than any plain coin
/// of M, so a largest-first selection that sees it picks it first. M has
/// registered the vault with addvault.
#[allow(dead_code)] // not every test reads every field
struct Setup {
    net: Net,
    owner: Arc<WalletDb>,
    manager: Arc<WalletDb>,
    owner_addr: Address,
    manager_addr: Address,
    manager_plain: Address,
    encoding: String,
    vault: Script,
    fund_txid: Hash256,
}

fn setup() -> Setup {
    let mut net = Net::new();
    let owner = net.wallet();
    let manager = net.wallet();
    let owner_cb = owner.new_receiving_address().unwrap();
    let owner_addr = owner.new_receiving_address().unwrap();
    let owner_change = owner.new_receiving_address().unwrap();
    let manager_addr = manager.new_receiving_address().unwrap();
    let manager_plain = manager.new_receiving_address().unwrap();
    let miner = Address::from_pubkey_hash(
        divi_primitives::hash::Hash160::from_bytes([0x99; 20]),
        Network::Regtest,
    );

    let cb_block = net.mine(vec![], &owner_cb);
    let cb_tx = net
        .chain
        .get_block(&cb_block)
        .unwrap()
        .unwrap()
        .transactions[0]
        .clone();
    net.mine(vec![], &miner);

    let vault = vault_script(&owner_addr, &manager_addr);
    let fund = fund_vault_tx(
        &owner,
        &cb_tx,
        vault.clone(),
        VAULT_DIVI,
        &manager_plain,
        MANAGER_PLAIN_DIVI,
        &owner_change,
    );
    let fund_txid = fund.txid();
    net.mine(vec![fund], &miner);
    net.mine(vec![], &miner);

    let encoding = format!("{}:{}", owner_addr, manager_addr);
    let manager_rpc = net.rpc(&manager);
    manager_rpc
        .add_vault(&p(vec![json!(encoding), json!(fund_txid.to_string())]))
        .unwrap();

    Setup {
        net,
        owner,
        manager,
        owner_addr,
        manager_addr,
        manager_plain,
        encoding,
        vault,
        fund_txid,
    }
}

fn divi(v: &Value) -> f64 {
    v.as_f64().unwrap_or_else(|| panic!("not a number: {}", v))
}

fn error_message(e: divi_rpc::Error) -> String {
    match e {
        divi_rpc::Error::Rpc(r) => r.message,
        other => format!("{:?}", other),
    }
}

// ---------------------------------------------------------------- IR-07

/// A manager with a registered vault can still spend its own plain coins:
/// coin selection must never pick the vault output it can only stake.
#[test]
fn manager_plain_send_never_selects_vault_output() {
    let s = setup();
    let rpc = s.net.rpc(&s.manager);
    let dest = s.owner.new_receiving_address().unwrap();
    let txid = rpc
        .send_to_address(&p(vec![json!(dest.to_string()), json!(5.0)]))
        .unwrap_or_else(|e| panic!("manager sendtoaddress failed: {}", error_message(e)));
    let sent = s.net.submitted.lock()[0].clone();
    assert_eq!(sent.txid().to_string(), txid.as_str().unwrap());
    // The vault is output 0 of the funding transaction
    let vault_outpoint = OutPoint::new(s.fund_txid, 0);
    for input in &sent.vin {
        assert_ne!(
            OutPoint::new(input.prevout.txid, input.prevout.vout),
            vault_outpoint,
            "a plain send spent the vault output"
        );
    }

    // Once mined, the manager has paid 5 DIVI plus fee out of its own coin and
    // still holds the whole vault (the vault output is unspent)
    s.net.mine_submitted(&s.owner_addr);
    let h = s.net.chain.height();
    assert!(s.net.chain.get_utxo(&vault_outpoint).unwrap().is_some());
    let left: i64 = s
        .manager
        .get_spendable_utxos(h, 1)
        .iter()
        .map(|u| u.value.as_sat())
        .sum();
    assert!(left > 34 * COIN && left < 35 * COIN, "{}", left);

    // fundvault from the manager wallet goes through the same selection
    let txid = rpc
        .fund_vault(&p(vec![json!(s.encoding), json!(10.0)]))
        .unwrap_or_else(|e| panic!("manager fundvault failed: {}", error_message(e)));
    assert!(txid.is_string());
}

/// The vault output is not part of the manager's Spendable set, and after
/// removevault it leaves the manager wallet altogether.
#[test]
fn manager_spendable_excludes_vault_before_and_after_removevault() {
    let s = setup();
    let rpc = s.net.rpc(&s.manager);
    let h = s.net.chain.height();

    let spendable_total = |w: &WalletDb| {
        w.get_spendable_utxos(h, 1)
            .iter()
            .map(|u| u.value.as_sat())
            .sum::<i64>()
    };
    assert_eq!(spendable_total(&s.manager), MANAGER_PLAIN_DIVI * COIN);
    let ca = rpc.get_coin_availability(&Params::None).unwrap();
    assert_eq!(divi(&ca["Spendable"]), MANAGER_PLAIN_DIVI as f64);

    rpc.remove_vault(&p(vec![json!(s.encoding), json!(s.fund_txid.to_string())]))
        .unwrap();
    assert_eq!(spendable_total(&s.manager), MANAGER_PLAIN_DIVI * COIN);
    let ca = rpc.get_coin_availability(&Params::None).unwrap();
    assert_eq!(divi(&ca["Spendable"]), MANAGER_PLAIN_DIVI as f64);
    assert_eq!(
        divi(&rpc.get_balance(&Params::None).unwrap()),
        MANAGER_PLAIN_DIVI as f64
    );
    let lu = rpc.list_unspent(&Params::None).unwrap();
    let vault_hex = hex::encode(s.vault.as_bytes());
    for u in lu.as_array().unwrap() {
        assert_ne!(u["scriptPubKey"], json!(vault_hex), "{}", u);
    }
}

/// While registered, listunspent must not call the vault output spendable for
/// the manager (it can only stake it).
#[test]
fn manager_listunspent_vault_not_spendable() {
    let s = setup();
    let rpc = s.net.rpc(&s.manager);
    let lu = rpc.list_unspent(&Params::None).unwrap();
    let vault_hex = hex::encode(s.vault.as_bytes());
    let vault_rows: Vec<_> = lu
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["scriptPubKey"] == json!(vault_hex))
        .collect();
    for u in vault_rows {
        assert_eq!(u["spendable"], json!(false), "{}", u);
    }
}
