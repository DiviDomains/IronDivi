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
        // The chain only warns on a bad input script, so check every
        // signature here: a test must not pass on an unsigned spend
        for tx in &txs {
            for (i, input) in tx.vin.iter().enumerate() {
                let prev = self
                    .chain
                    .get_utxo(&input.prevout)
                    .unwrap()
                    .expect("input spends an unknown coin");
                divi_script::verify_input(tx, i, &prev.script_pubkey, prev.value)
                    .unwrap_or_else(|e| panic!("input {} of {} fails: {:?}", i, tx.txid(), e));
            }
        }
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

// ----------------------------------------------------------------

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

// ----------------------------------------------------------------

/// The owner wallet alone (no manager key, vault never registered there) sees
/// its vault and reclaims from it. As in Divi Core, listunspent leaves vault
/// outputs out (ALL_SPENDABLE_COINS excludes owned and managed vaults); the
/// owner sees the vault in getcoinavailability.
#[test]
fn owner_only_wallet_sees_and_reclaims_vault() {
    let s = setup();
    assert!(!s.owner.is_mine(&s.manager_addr));
    assert!(s.owner.get_all_vaults().is_empty());
    let rpc = s.net.rpc(&s.owner);

    let ca = rpc.get_coin_availability(&Params::None).unwrap();
    assert_eq!(divi(&ca["Vaulted"]), VAULT_DIVI as f64, "{}", ca);
    let vault_hex = hex::encode(s.vault.as_bytes());
    let lu = rpc.list_unspent(&Params::None).unwrap();
    assert!(
        !lu.as_array()
            .unwrap()
            .iter()
            .any(|u| u["scriptPubKey"] == json!(vault_hex)),
        "vault output in listunspent: {}",
        lu
    );

    let dest = s.owner.new_receiving_address().unwrap();
    rpc.reclaim_vault_funds(&p(vec![json!(dest.to_string()), json!(40.0)]))
        .unwrap_or_else(|e| panic!("owner reclaim failed: {}", error_message(e)));
    let tx = s.net.submitted.lock()[0].clone();
    let vault_outpoint = OutPoint::new(s.fund_txid, 0);
    assert!(tx
        .vin
        .iter()
        .any(|i| OutPoint::new(i.prevout.txid, i.prevout.vout) == vault_outpoint));
    s.net.mine_submitted(&s.manager_plain);
    // The owner's signature verified (Net::mine) and the vault output is spent
    assert!(s.net.chain.get_utxo(&vault_outpoint).unwrap().is_none());
    assert!(s
        .owner
        .get_utxos()
        .iter()
        .any(|u| u.address == dest.to_string() && u.value.as_sat() == 40 * COIN));
}

/// The manager key alone gives nothing to reclaim (Divi Core: 0 available).
#[test]
fn manager_cannot_reclaim_vault() {
    let s = setup();
    let rpc = s.net.rpc(&s.manager);
    let dest = s.manager.new_receiving_address().unwrap();
    let e = rpc
        .reclaim_vault_funds(&p(vec![json!(dest.to_string()), json!(1.0)]))
        .unwrap_err();
    assert!(error_message(e).contains("No vault funds available to reclaim"));
    assert!(s.net.submitted.lock().is_empty());
}

// ----------------------------------------------------------------

/// getwalletinfo and getcoinavailability as Divi Core: the owner's vaulted
/// balance is the vault; the manager's managed vault is stakable only, in no
/// balance.
#[test]
fn vaulted_balance_owner_and_manager_views() {
    let s = setup();
    let owner_change = (1250 - VAULT_DIVI - MANAGER_PLAIN_DIVI) as f64 - 0.0001;

    let owner = s.net.rpc(&s.owner).get_wallet_info(&Params::None).unwrap();
    assert_eq!(
        divi(&owner["vaulted_balance"]),
        VAULT_DIVI as f64,
        "{}",
        owner
    );
    assert_eq!(
        divi(&owner["balance"]),
        VAULT_DIVI as f64 + owner_change,
        "{}",
        owner
    );
    assert_eq!(divi(&owner["spendable_balance"]), owner_change, "{}", owner);

    let manager = s
        .net
        .rpc(&s.manager)
        .get_wallet_info(&Params::None)
        .unwrap();
    assert_eq!(divi(&manager["vaulted_balance"]), 0.0, "{}", manager);
    assert_eq!(
        divi(&manager["balance"]),
        MANAGER_PLAIN_DIVI as f64,
        "{}",
        manager
    );
    assert_eq!(
        divi(&manager["spendable_balance"]),
        MANAGER_PLAIN_DIVI as f64,
        "{}",
        manager
    );
    assert_eq!(
        divi(&s.net.rpc(&s.manager).get_balance(&Params::None).unwrap()),
        MANAGER_PLAIN_DIVI as f64
    );

    let ca = s
        .net
        .rpc(&s.owner)
        .get_coin_availability(&Params::None)
        .unwrap();
    assert_eq!(divi(&ca["Vaulted"]), VAULT_DIVI as f64, "{}", ca);
    assert_eq!(divi(&ca["Stakable"]), owner_change, "{}", ca);
    assert_eq!(divi(&ca["Spendable"]), owner_change, "{}", ca);

    let ca = s
        .net
        .rpc(&s.manager)
        .get_coin_availability(&Params::None)
        .unwrap();
    assert_eq!(divi(&ca["Vaulted"]), 0.0, "{}", ca);
    assert_eq!(
        divi(&ca["Stakable"]),
        (VAULT_DIVI + MANAGER_PLAIN_DIVI) as f64,
        "{}",
        ca
    );
    assert_eq!(divi(&ca["Spendable"]), MANAGER_PLAIN_DIVI as f64, "{}", ca);

    // Verbose form names the vault by its encoding on both sides
    let ca = s
        .net
        .rpc(&s.owner)
        .get_coin_availability(&p(vec![json!(true)]))
        .unwrap();
    assert_eq!(
        ca["Vaulted"]["AllVaults"][0]["vault"],
        json!(s.encoding),
        "{}",
        ca
    );
    let ca = s
        .net
        .rpc(&s.manager)
        .get_coin_availability(&p(vec![json!(true)]))
        .unwrap();
    assert_eq!(
        ca["Stakable"]["AllVaults"][0]["vault"],
        json!(s.encoding),
        "{}",
        ca
    );
}

// ----------------------------------------------------------------

/// addvault on a funding output that is already spent is refused and adds no
/// balance (seen on testnet: re-add after the owner reclaimed the vault).
#[test]
fn addvault_refuses_spent_funding_output() {
    let mut s = setup();
    // The owner spends the whole vault output (signed by hand, owner branch)
    let dest = s.owner.new_receiving_address().unwrap();
    let (mut tx, prev) = TransactionBuilder::new()
        .add_input(OutPoint::new(s.fund_txid, 0), s.vault.clone())
        .add_output_to_address(Amount::from_sat(VAULT_DIVI * COIN - 10_000), &dest)
        .build();
    let signed = TransactionSigner::new(s.owner.keystore())
        .sign_all_inputs(&mut tx, &prev)
        .unwrap();
    assert_eq!(signed, 1);
    s.net.mine(vec![tx], &s.owner_addr);
    assert!(s
        .net
        .chain
        .get_utxo(&OutPoint::new(s.fund_txid, 0))
        .unwrap()
        .is_none());

    // A manager wallet that never saw the vault, holding the manager key
    let fresh = s.net.wallet();
    let manager_key = s
        .manager
        .keystore()
        .get_key(&s.manager_addr.hash)
        .unwrap()
        .secret
        .unwrap();
    fresh.import_key(manager_key, None);
    let rpc = s.net.rpc(&fresh);
    let e = rpc
        .add_vault(&p(vec![json!(s.encoding), json!(s.fund_txid.to_string())]))
        .unwrap_err();
    assert!(error_message(e).contains("already spent"));
    assert!(fresh.get_all_vaults().is_empty());
    let ca = rpc.get_coin_availability(&Params::None).unwrap();
    assert_eq!(divi(&ca["Stakable"]), 0.0, "{}", ca);
    assert_eq!(divi(&ca["Vaulted"]), 0.0, "{}", ca);
}

/// A funding output already spent by a transaction in the mempool is refused.
#[test]
fn addvault_refuses_funding_output_spent_in_mempool() {
    struct SpendsEverything;
    impl divi_rpc::blockchain::MempoolProvider for SpendsEverything {
        fn get_txids(&self) -> Vec<Hash256> {
            Vec::new()
        }
        fn prioritise_transaction(&self, _: &Hash256, _: f64, _: i64) -> bool {
            false
        }
        fn is_spent(&self, _: &OutPoint) -> bool {
            true
        }
    }
    let s = setup();
    let fresh_rpc = s.net.rpc(&s.manager);
    fresh_rpc
        .remove_vault(&p(vec![json!(s.encoding), json!(s.fund_txid.to_string())]))
        .unwrap();
    fresh_rpc.set_mempool(Arc::new(SpendsEverything));
    let e = fresh_rpc
        .add_vault(&p(vec![json!(s.encoding), json!(s.fund_txid.to_string())]))
        .unwrap_err();
    assert!(error_message(e).contains("already spent"));
    assert!(s.manager.get_all_vaults().is_empty());
}

// ----------------------------------------------------------------

/// The owner also holds the manager key and registers the vault (a
/// self-vault, as on testnet), so reclaim works even where the owner key
/// alone was not enough.
fn make_self_vault(s: &Setup) -> WalletRpc {
    let manager_key = s
        .manager
        .keystore()
        .get_key(&s.manager_addr.hash)
        .unwrap()
        .secret
        .unwrap();
    s.owner.import_key(manager_key, None);
    let rpc = s.net.rpc(&s.owner);
    rpc.add_vault(&p(vec![json!(s.encoding), json!(s.fund_txid.to_string())]))
        .unwrap();
    rpc
}

fn submitted_tx(s: &Setup) -> Transaction {
    let txs = s.net.submitted.lock();
    assert_eq!(txs.len(), 1);
    txs[0].clone()
}

fn output_to(tx: &Transaction, script: &Script) -> Vec<i64> {
    tx.vout
        .iter()
        .filter(|o| &o.script_pubkey == script)
        .map(|o| o.value.as_sat())
        .collect()
}

/// Default mode: the destination gets the full amount, the fee comes out of
/// the remainder, and the remainder goes back to the same vault script so it
/// keeps staking (seen on the manager after the block).
#[test]
fn reclaim_partial_keeps_remainder_in_vault() {
    let s = setup();
    let rpc = make_self_vault(&s);
    let dest = s.owner.new_receiving_address().unwrap();
    let res = rpc
        .reclaim_vault_funds(&p(vec![json!(dest.to_string()), json!(40.0)]))
        .unwrap();
    let tx = submitted_tx(&s);
    let fee = (divi(&res["fee"]) * COIN as f64).round() as i64;
    assert!(fee > 0);
    assert_eq!(
        output_to(&tx, &Script::new_p2pkh(dest.hash.as_bytes())),
        vec![40 * COIN]
    );
    assert_eq!(
        output_to(&tx, &s.vault),
        vec![(VAULT_DIVI - 40) * COIN - fee],
        "the rest of the vault left the vault"
    );

    s.net.mine_submitted(&s.owner_addr);
    let h = s.net.chain.height();
    let managed: i64 = s
        .manager
        .get_stakeable_vault_utxos(h, 1)
        .iter()
        .map(|(u, _)| u.value.as_sat())
        .sum();
    assert_eq!(managed, (VAULT_DIVI - 40) * COIN - fee);
}

/// receiver_pays: the fee comes out of the amount, the vault keeps the rest
/// untouched.
#[test]
fn reclaim_receiver_pays_takes_fee_from_amount() {
    let s = setup();
    let rpc = make_self_vault(&s);
    let dest = s.owner.new_receiving_address().unwrap();
    let res = rpc
        .reclaim_vault_funds(&p(vec![
            json!(dest.to_string()),
            json!(5.0),
            json!("receiver_pays"),
        ]))
        .unwrap();
    let tx = submitted_tx(&s);
    let fee = (divi(&res["fee"]) * COIN as f64).round() as i64;
    assert!(fee > 0);
    assert_eq!(
        output_to(&tx, &Script::new_p2pkh(dest.hash.as_bytes())),
        vec![5 * COIN - fee],
        "receiver_pays ignored"
    );
    assert_eq!(output_to(&tx, &s.vault), vec![(VAULT_DIVI - 5) * COIN]);
    s.net.mine_submitted(&s.owner_addr);
}

/// sweep_funds: everything goes to the destination minus the fee, the amount
/// argument is not used (Divi Core behaviour).
#[test]
fn reclaim_sweep_funds_sends_everything() {
    let s = setup();
    let rpc = make_self_vault(&s);
    let dest = s.owner.new_receiving_address().unwrap();
    let res = rpc
        .reclaim_vault_funds(&p(vec![
            json!(dest.to_string()),
            json!(1.0),
            json!("sweep_funds"),
        ]))
        .unwrap();
    let tx = submitted_tx(&s);
    let fee = (divi(&res["fee"]) * COIN as f64).round() as i64;
    assert_eq!(tx.vout.len(), 1, "sweep left change");
    assert_eq!(
        output_to(&tx, &Script::new_p2pkh(dest.hash.as_bytes())),
        vec![VAULT_DIVI * COIN - fee]
    );
    s.net.mine_submitted(&s.owner_addr);
}

/// An unknown fee mode is an error, as in Divi Core (-8).
#[test]
fn reclaim_unknown_fee_mode_is_refused() {
    let s = setup();
    let rpc = make_self_vault(&s);
    let dest = s.owner.new_receiving_address().unwrap();
    let e = rpc
        .reclaim_vault_funds(&p(vec![
            json!(dest.to_string()),
            json!(1.0),
            json!("fastest"),
        ]))
        .unwrap_err();
    match e {
        divi_rpc::Error::Rpc(r) => {
            assert_eq!(r.code, -8);
            assert_eq!(r.message, "Unknown option for reclaiming vault funds");
        }
        other => panic!("{:?}", other),
    }
    assert!(s.net.submitted.lock().is_empty());
}

// ----------------------------------------------------------------

/// debitvaultbyname pays from the named vault only, with the owner key alone,
/// and the rest stays in that vault (Divi Core sets the change to the vault).
#[test]
fn debitvaultbyname_spends_only_the_named_vault() {
    let mut s = setup();
    let rpc = s.net.rpc(&s.owner);
    // A second vault of the same owner with another manager
    let other_manager = s.net.wallet().new_receiving_address().unwrap();
    let other_encoding = format!("{}:{}", s.owner_addr, other_manager);
    rpc.fund_vault(&p(vec![json!(other_encoding), json!(5.0)]))
        .unwrap();
    s.net.mine_submitted(&s.manager_plain);
    let other_vault = vault_script(&s.owner_addr, &other_manager);

    let dest = s.manager.new_receiving_address().unwrap();
    let txid = rpc
        .debit_vault_by_name(&p(vec![
            json!(s.encoding),
            json!(dest.to_string()),
            json!(30.0),
        ]))
        .unwrap_or_else(|e| panic!("debitvaultbyname failed: {}", error_message(e)));
    let tx = submitted_tx(&s);
    assert_eq!(txid, json!(tx.txid().to_string()));
    assert_eq!(tx.vin.len(), 1);
    assert_eq!(
        OutPoint::new(tx.vin[0].prevout.txid, tx.vin[0].prevout.vout),
        OutPoint::new(s.fund_txid, 0)
    );
    assert_eq!(
        output_to(&tx, &Script::new_p2pkh(dest.hash.as_bytes())),
        vec![30 * COIN]
    );
    let back = output_to(&tx, &s.vault);
    assert_eq!(back.len(), 1);
    assert!(back[0] > (VAULT_DIVI - 31) * COIN && back[0] < (VAULT_DIVI - 30) * COIN);
    assert!(output_to(&tx, &other_vault).is_empty());
    s.net.mine_submitted(&s.owner_addr);

    // receiver_pays works here too
    rpc.debit_vault_by_name(&p(vec![
        json!(other_encoding),
        json!(dest.to_string()),
        json!(2.0),
        json!("receiver_pays"),
    ]))
    .unwrap();
    let tx = submitted_tx(&s);
    assert_eq!(output_to(&tx, &other_vault), vec![3 * COIN]);
}

/// Without the owner key (the manager) it is refused as in Divi Core, and a
/// malformed encoding is -5.
#[test]
fn debitvaultbyname_needs_owner_key() {
    let s = setup();
    let rpc = s.net.rpc(&s.manager);
    let dest = s.manager.new_receiving_address().unwrap();
    let e = rpc
        .debit_vault_by_name(&p(vec![
            json!(s.encoding),
            json!(dest.to_string()),
            json!(1.0),
        ]))
        .unwrap_err();
    match e {
        divi_rpc::Error::Rpc(r) => {
            assert_eq!(r.code, -5);
            assert!(
                r.message.starts_with("Vault owner key is unknown"),
                "{}",
                r.message
            );
        }
        other => panic!("{:?}", other),
    }
    let e = rpc
        .debit_vault_by_name(&p(vec![
            json!(s.manager_addr.to_string()),
            json!(dest.to_string()),
            json!(1.0),
        ]))
        .unwrap_err();
    match e {
        divi_rpc::Error::Rpc(r) => {
            assert_eq!((r.code, r.message.as_str()), (-5, "Invalid Vault Encoding"))
        }
        other => panic!("{:?}", other),
    }
    assert!(s.net.submitted.lock().is_empty());
}

// ----------------------------------------------------------------

/// removevault takes the encoding alone, as Divi Core; the two-argument form
/// still works.
#[test]
fn removevault_one_and_two_arguments() {
    let s = setup();
    let rpc = s.net.rpc(&s.manager);
    let res = rpc
        .remove_vault(&p(vec![json!(s.encoding)]))
        .unwrap_or_else(|e| panic!("one-argument removevault failed: {}", error_message(e)));
    assert_eq!(res["removal_status"], json!(true), "{}", res);
    assert!(s.manager.get_all_vaults().is_empty());

    rpc.add_vault(&p(vec![json!(s.encoding), json!(s.fund_txid.to_string())]))
        .unwrap();
    let res = rpc
        .remove_vault(&p(vec![json!(s.encoding), json!(s.fund_txid.to_string())]))
        .unwrap();
    assert_eq!(res["removal_status"], json!(true), "{}", res);
    assert_eq!(res["tx_hash"], json!(s.fund_txid.to_string()));
    assert!(s.manager.get_all_vaults().is_empty());
}

// ------------------------------------------------- vault change dust limit

/// Change that goes back to a vault is checked against the vault script's own
/// dust limit (larger than the P2PKH one): 5460 sat of change would be dust
/// there, so it goes to the fee instead of making the send unrelayable.
#[test]
fn reclaim_drops_change_below_the_vault_dust_limit() {
    let s = setup();
    let rpc = make_self_vault(&s);
    let vault_limit = TxOut::new(Amount::ZERO, s.vault.clone()).min_non_dust_value(10_000);
    assert!(
        vault_limit.as_sat() > 5460,
        "vault limit {}",
        vault_limit.as_sat()
    );

    // One vault input, payment plus change: the fee is 3000 sat
    let change = 5460;
    let amount = VAULT_DIVI * COIN - 3000 - change;
    let dest = s.owner.new_receiving_address().unwrap();
    rpc.reclaim_vault_funds(&p(vec![
        json!(dest.to_string()),
        json!(amount as f64 / COIN as f64),
    ]))
    .unwrap();
    let tx = submitted_tx(&s);
    assert_eq!(
        output_to(&tx, &Script::new_p2pkh(dest.hash.as_bytes())),
        vec![amount]
    );
    for out in &tx.vout {
        assert!(
            !out.is_dust_at(10_000),
            "dust output of {} sat",
            out.value.as_sat()
        );
    }
    assert!(output_to(&tx, &s.vault).is_empty());
}
