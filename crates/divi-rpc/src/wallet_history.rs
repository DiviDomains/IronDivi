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

//! Wallet history entries as Divi Core's rpcwallet.cpp builds them for
//! listtransactions, listsinceblock and gettransaction: one entry per output
//! sent or received (ParseTransactionDetails, GetAmounts), with the
//! transaction fields of WalletTxToJSON.

use crate::blockchain::MempoolProvider;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::script::Script;
use divi_primitives::transaction::Transaction;
use divi_storage::Chain;
use divi_wallet::{Address, Network, Ownership, WalletDb, WalletTx};
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

/// Divi Core's isminetype as the history sees it: vaults the wallet owns or
/// manages count as spendable (computeMineType(..., true), wallet.cpp:59-67)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mine {
    No,
    WatchOnly,
    Spendable,
}

/// Adds one entry (with the transaction fields when listing)
type PushEntry<'p> = dyn Fn(Map<String, Value>, &mut Vec<Value>) + 'p;

/// A wallet transaction with what its entries need
struct Loaded {
    tx: Transaction,
    /// Block hash, height, time and position, when the record names a block
    block: Option<(Hash256, u32, u32, usize)>,
}

/// What ListReceived counts for one destination
pub(crate) struct Tally {
    pub(crate) amount: i64,
    /// The fewest confirmations of its transactions (i64::MAX when none)
    pub(crate) confirmations: i64,
    pub(crate) txids: Vec<String>,
    pub(crate) watch_only: bool,
}

/// Builds history entries for one RPC call (lookups are cached for the call)
pub(crate) struct History<'a> {
    wallet: &'a WalletDb,
    chain: Option<&'a Chain>,
    mempool: Option<Arc<dyn MempoolProvider>>,
    network: Network,
    /// Divi Core's nMaturity (coinbaseConfirmationsForMaturity)
    maturity: u32,
    height: u32,
    unconfirmed: HashMap<Hash256, Transaction>,
    /// Transactions that left the chain or the mempool (raw when the wallet has it)
    detached: HashMap<Hash256, Option<Transaction>>,
    loaded: RefCell<HashMap<Hash256, Option<Rc<Loaded>>>>,
}

fn amount(sat: i64) -> Value {
    json!(sat as f64 / 100_000_000.0)
}

impl<'a> History<'a> {
    pub(crate) fn new(
        wallet: &'a WalletDb,
        chain: Option<&'a Chain>,
        mempool: Option<Arc<dyn MempoolProvider>>,
        network: Network,
        height: u32,
    ) -> Self {
        let unconfirmed = wallet
            .unconfirmed_transactions()
            .into_iter()
            .map(|tx| (tx.txid(), tx))
            .collect();
        let detached = wallet
            .detached_transactions()
            .into_iter()
            .map(|(id, d)| (id, d.tx))
            .collect();
        History {
            wallet,
            detached,
            chain,
            mempool,
            network,
            maturity: wallet.coinbase_maturity(),
            height,
            unconfirmed,
            loaded: RefCell::new(HashMap::new()),
        }
    }

    /// The wallet's records, oldest first (Core's OrderedTxItems order): by
    /// the position each was first seen at (nOrderPos, wallet.cpp:1046);
    /// records kept before positions were stored come first, by time, then
    /// block position
    pub(crate) fn ordered_records(&self) -> Vec<WalletTx> {
        let mut records = self.wallet.history_records();
        records.sort_by_key(|r| {
            let index = self.load(r).and_then(|l| l.block.map(|b| b.3)).unwrap_or(0);
            (
                self.wallet.order_position(&r.txid),
                r.timestamp,
                r.block_height.unwrap_or(u32::MAX),
                index,
            )
        });
        records
    }

    fn load(&self, record: &WalletTx) -> Option<Rc<Loaded>> {
        if let Some(hit) = self.loaded.borrow().get(&record.txid) {
            return hit.clone();
        }
        let found = self.load_uncached(record).map(Rc::new);
        self.loaded.borrow_mut().insert(record.txid, found.clone());
        found
    }

    fn load_uncached(&self, record: &WalletTx) -> Option<Loaded> {
        if let (Some(hash), Some(chain)) = (record.block_hash, self.chain) {
            if let Ok(Some(block)) = chain.get_block(&hash) {
                if let Some(pos) = block
                    .transactions
                    .iter()
                    .position(|t| t.txid() == record.txid)
                {
                    let height = record.block_height.unwrap_or_default();
                    return Some(Loaded {
                        tx: block.transactions[pos].clone(),
                        block: Some((hash, height, block.header.time, pos)),
                    });
                }
            }
            if let Ok(Some((tx, location))) = chain.get_transaction_with_location(&record.txid) {
                let index = chain.get_block_index(&location.block_hash).ok().flatten();
                return Some(Loaded {
                    tx,
                    block: index.map(|i| {
                        (
                            location.block_hash,
                            i.height,
                            i.time,
                            location.tx_index as usize,
                        )
                    }),
                });
            }
        }
        let tx = self
            .unconfirmed
            .get(&record.txid)
            .cloned()
            .or_else(|| {
                self.mempool
                    .as_ref()
                    .and_then(|m| m.get_transaction(&record.txid))
            })
            .or_else(|| self.detached.get(&record.txid).cloned().flatten());
        if let Some(tx) = tx {
            return Some(Loaded { tx, block: None });
        }
        // A transaction of a disconnected block: the transaction index still
        // names that block, which is no longer active
        let chain = self.chain?;
        let (tx, location) = chain
            .get_transaction_with_location(&record.txid)
            .ok()
            .flatten()?;
        let index = chain.get_block_index(&location.block_hash).ok().flatten();
        Some(Loaded {
            tx,
            block: index.map(|i| {
                (
                    location.block_hash,
                    i.height,
                    i.time,
                    location.tx_index as usize,
                )
            }),
        })
    }

    /// Divi Core's GetNumberOfBlockConfirmations
    /// (MerkleTxConfirmationNumberCalculator.cpp:43-47): the depth of the
    /// block if it is on the active chain, else 0 while in the mempool, else -1
    fn depth(&self, txid: &Hash256, loaded: &Loaded) -> i64 {
        if let (Some((hash, height, _, _)), Some(chain)) = (loaded.block, self.chain) {
            let active = chain
                .get_block_index_by_height(height)
                .ok()
                .flatten()
                .is_some_and(|i| i.hash == hash);
            if active && self.height >= height {
                return (self.height - height + 1) as i64;
            }
        }
        let in_mempool = match &self.mempool {
            Some(m) => m.get_transaction(txid).is_some(),
            None => self.unconfirmed.contains_key(txid),
        };
        if in_mempool {
            0
        } else {
            -1
        }
    }

    fn mine(&self, script: &Script) -> Mine {
        match self.wallet.ownership(script) {
            Ownership::No => Mine::No,
            Ownership::WatchOnly => Mine::WatchOnly,
            _ => Mine::Spendable,
        }
    }

    fn destination(&self, script: &Script) -> Option<Address> {
        use divi_script::Destination;
        match divi_script::extract_destination(script.as_bytes())? {
            Destination::PubKeyHash(h) => Some(Address::from_pubkey_hash(
                Hash160::from_bytes(h),
                self.network,
            )),
            Destination::ScriptHash(h) => Some(Address::p2sh(Hash160::from_bytes(h), self.network)),
        }
    }

    /// Divi Core's IsChange (wallet.cpp:125-140): ours, and either no
    /// destination or a key of the HD change chain
    fn is_change(&self, script: &Script) -> bool {
        if self.mine(script) == Mine::No {
            return false;
        }
        match self.destination(script) {
            None => true,
            Some(a) => script.is_p2pkh() && self.wallet.is_change_address(&a),
        }
    }

    /// The address book name of a destination ("" if none)
    fn account_of(&self, address: &Option<Address>) -> String {
        address
            .as_ref()
            .map(|a| self.wallet.get_account(a))
            .unwrap_or_default()
    }

    /// ParseScriptAsAddressString (rpcwallet.cpp:1999-2014)
    fn address_string(&self, script: &Script) -> String {
        if let Some(a) = self.destination(script) {
            a.to_base58()
        } else if divi_script::is_staking_vault_script(script) {
            "Staking Vault".to_string()
        } else {
            "Unknown address".to_string()
        }
    }

    /// The output an input spends, when the spent transaction is the wallet's
    /// (ComputeDebit looks only at wallet transactions)
    fn wallet_prevout(
        &self,
        tx: &Transaction,
        n: usize,
    ) -> Option<divi_primitives::transaction::TxOut> {
        let prevout = &tx.vin[n].prevout;
        let record = self.wallet.history_record(&prevout.txid)?;
        let prev = self.load(&record)?;
        prev.tx.vout.get(prevout.vout as usize).cloned()
    }

    fn requested(mine: Mine, watch: bool) -> bool {
        mine == Mine::Spendable || (watch && mine == Mine::WatchOnly)
    }

    /// getDebit: the value of the spent wallet outputs of the requested kinds
    fn debit(&self, tx: &Transaction, watch: bool) -> i64 {
        if tx.is_coinbase() {
            return 0;
        }
        (0..tx.vin.len())
            .filter_map(|n| self.wallet_prevout(tx, n))
            .filter(|out| Self::requested(self.mine(&out.script_pubkey), watch))
            .map(|out| out.value.as_sat())
            .sum()
    }

    /// getCredit: the value of the outputs of the requested kinds
    fn credit(&self, tx: &Transaction, watch: bool) -> i64 {
        tx.vout
            .iter()
            .filter(|out| Self::requested(self.mine(&out.script_pubkey), watch))
            .map(|out| out.value.as_sat())
            .sum()
    }

    fn change(&self, tx: &Transaction) -> i64 {
        tx.vout
            .iter()
            .filter(|out| self.is_change(&out.script_pubkey))
            .map(|out| out.value.as_sat())
            .sum()
    }

    /// AllInputsAreMine (rpcwallet.cpp:90-110)
    fn all_inputs_mine(&self, tx: &Transaction) -> bool {
        (0..tx.vin.len()).all(|n| {
            self.wallet_prevout(tx, n)
                .is_some_and(|out| self.mine(&out.script_pubkey) == Mine::Spendable)
        })
    }

    /// The value of every input, looked up in the chain or the mempool
    fn total_inputs(&self, tx: &Transaction) -> Option<i64> {
        let mut total = 0;
        for input in &tx.vin {
            let prev = self
                .chain
                .and_then(|c| c.get_transaction(&input.prevout.txid).ok().flatten())
                .or_else(|| self.unconfirmed.get(&input.prevout.txid).cloned())
                .or_else(|| {
                    self.mempool
                        .as_ref()
                        .and_then(|m| m.get_transaction(&input.prevout.txid))
                })?;
            total += prev.vout.get(input.prevout.vout as usize)?.value.as_sat();
        }
        Some(total)
    }

    /// WalletTxToJSON (rpcwallet.cpp:245-270)
    fn tx_fields(&self, record: &WalletTx, loaded: &Loaded, entry: &mut Map<String, Value>) {
        let depth = self.depth(&record.txid, loaded);
        entry.insert("confirmations".into(), json!(depth));
        entry.insert("bcconfirmations".into(), json!(depth));
        if loaded.tx.is_coinbase() || loaded.tx.is_coinstake() {
            entry.insert("generated".into(), json!(true));
        }
        if depth > 0 {
            if let Some((hash, _, time, index)) = loaded.block {
                entry.insert("blockhash".into(), json!(hash.to_string()));
                entry.insert("blockindex".into(), json!(index));
                entry.insert("blocktime".into(), json!(time));
            }
        }
        entry.insert("txid".into(), json!(record.txid.to_string()));
        entry.insert(
            "baretxid".into(),
            json!(crate::wallet::bare_txid(&loaded.tx).to_string()),
        );
        entry.insert("walletconflicts".into(), json!(self.conflicts(&loaded.tx)));
        entry.insert("time".into(), json!(record.timestamp));
        entry.insert("timereceived".into(), json!(record.timestamp));
        // The notes the send kept with the transaction (mapValue,
        // rpcwallet.cpp:268-269)
        for (key, value) in self.wallet.tx_notes(&record.txid) {
            entry.insert(key, json!(value));
        }
    }

    /// GetConflicts: wallet transactions spending an input of `tx`, `tx`
    /// itself included, when there is any other
    fn conflicts(&self, tx: &Transaction) -> Vec<String> {
        if tx.is_coinbase() {
            return Vec::new();
        }
        let txid = tx.txid();
        let mut found: Vec<Hash256> = Vec::new();
        for record in self.wallet.history_records() {
            if record.txid == txid {
                continue;
            }
            let Some(other) = self.load(&record) else {
                continue;
            };
            if other
                .tx
                .vin
                .iter()
                .any(|i| tx.vin.iter().any(|mine| mine.prevout == i.prevout))
            {
                found.push(record.txid);
            }
        }
        if found.is_empty() {
            return Vec::new();
        }
        found.push(txid);
        found.sort();
        found.iter().map(|h| h.to_string()).collect()
    }

    /// ParseTransactionDetails (rpcwallet.cpp:2016-2213): the entries of one
    /// wallet transaction for `account` ("*" for all)
    pub(crate) fn details(
        &self,
        record: &WalletTx,
        account: &str,
        min_depth: i64,
        long: bool,
        watch: bool,
        out: &mut Vec<Value>,
    ) {
        let Some(loaded) = self.load(record) else {
            return;
        };
        let tx = &loaded.tx;
        let all_accounts = account == "*";
        // wtx.strFromAccount: IronDivi keeps no "from" account
        let sent_account = "";
        let push = |mut entry: Map<String, Value>, out: &mut Vec<Value>| {
            if long {
                self.tx_fields(record, &loaded, &mut entry);
            }
            out.push(Value::Object(entry));
        };

        if tx.is_coinstake() {
            self.coinstake_details(&loaded, account, &push, out);
            return;
        }

        let all_from_me = self.all_inputs_mine(tx);
        let mut all_for_me = true;
        let mut matches_account = false;
        let mut addresses = Vec::new();
        for o in &tx.vout {
            all_for_me &= self.mine(&o.script_pubkey) == Mine::Spendable;
            let dest = self.destination(&o.script_pubkey);
            let name = self.account_of(&dest);
            matches_account |= all_accounts || name == account;
            addresses.push(json!({
                "address": self.address_string(&o.script_pubkey),
                "account": name,
            }));
        }

        if all_for_me && matches_account && all_from_me {
            let debit = self.debit(tx, false);
            let fee = debit - self.credit(tx, false);
            let mut entry = Map::new();
            entry.insert("category".into(), json!("move"));
            entry.insert("amount".into(), amount(debit - self.change(tx) - fee));
            entry.insert("fee".into(), amount(-fee));
            entry.insert("addresses".into(), json!(addresses));
            push(entry, out);
            return;
        }

        // GetAmounts (rpcwallet.cpp:112-182)
        let debit = self.debit(tx, watch);
        let value_out: i64 = tx.vout.iter().map(|o| o.value.as_sat()).sum();
        let fee = if debit > 0 {
            if all_from_me {
                debit - value_out
            } else {
                self.total_inputs(tx).map_or(0, |total| total - value_out)
            }
        } else {
            0
        };
        let mut sent = Vec::new();
        let mut received = Vec::new();
        for (n, o) in tx.vout.iter().enumerate() {
            let mine = self.mine(&o.script_pubkey);
            let skipped = !Self::requested(mine, watch);
            if debit > 0 && self.is_change(&o.script_pubkey) {
                continue;
            }
            if debit <= 0 && skipped {
                continue;
            }
            let entry = (
                self.destination(&o.script_pubkey),
                o.value.as_sat(),
                n,
                mine,
            );
            if debit > 0 {
                sent.push(entry.clone());
            }
            if !skipped {
                received.push(entry);
            }
        }

        if (!sent.is_empty() || fee != 0) && (all_accounts || account == sent_account) {
            for (dest, value, n, mine) in &sent {
                let mut entry = Map::new();
                if *mine == Mine::WatchOnly {
                    entry.insert("involvesWatchonly".into(), json!(true));
                }
                entry.insert("account".into(), json!(sent_account));
                if let Some(a) = dest {
                    entry.insert("address".into(), json!(a.to_base58()));
                }
                entry.insert("category".into(), json!("send"));
                entry.insert("amount".into(), amount(-value));
                entry.insert("vout".into(), json!(n));
                entry.insert("fee".into(), amount(-fee));
                push(entry, out);
            }
        }

        let depth = self.depth(&record.txid, &loaded);
        if !received.is_empty() && depth >= min_depth {
            for (dest, value, n, mine) in &received {
                let name = self.account_of(dest);
                if !(all_accounts || name == account) {
                    continue;
                }
                let mut entry = Map::new();
                if *mine == Mine::WatchOnly {
                    entry.insert("involvesWatchonly".into(), json!(true));
                }
                entry.insert("account".into(), json!(name));
                if let Some(a) = dest {
                    entry.insert("address".into(), json!(a.to_base58()));
                }
                let category = if tx.is_coinbase() {
                    if depth < 1 {
                        "orphan"
                    } else if self.blocks_to_maturity(depth) > 0 {
                        "immature"
                    } else {
                        "generate"
                    }
                } else {
                    "receive"
                };
                entry.insert("category".into(), json!(category));
                entry.insert("amount".into(), amount(*value));
                entry.insert("vout".into(), json!(n));
                push(entry, out);
            }
        }
    }

    /// GetAccountBalance (rpcwallet.cpp:383-412) with GetAccountAmounts
    /// (:187-242): for a named account, every output to an address of that
    /// name received and every spent output from one sent; for "", the
    /// outputs of the requested kinds whose address has no name. A receive
    /// counts at `min_depth`; transactions not final, immature or off the
    /// chain are left out. Satoshis.
    pub(crate) fn account_balance(&self, account: &str, min_depth: i64, watch: bool) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as u32);
        let labelled = |script: &Script| self.account_of(&self.destination(script));
        let counts = |script: &Script| {
            let label = labelled(script);
            if account.is_empty() {
                label.is_empty() && Self::requested(self.mine(script), watch)
            } else {
                label == account
            }
        };
        let mut balance = 0i64;
        for record in self.wallet.history_records() {
            let Some(loaded) = self.load(&record) else {
                continue;
            };
            let tx = &loaded.tx;
            let depth = self.depth(&record.txid, &loaded);
            let generated = tx.is_coinbase() || tx.is_coinstake();
            if !tx.is_final(self.height, now)
                || (generated && self.blocks_to_maturity(depth) > 0)
                || depth < 0
            {
                continue;
            }
            // previousOutputsSpent: collected only when the wallet is debited
            let mut sent = 0i64;
            if self.debit(tx, watch) > 0 && !tx.is_coinbase() {
                for n in 0..tx.vin.len() {
                    let prev = self.wallet_prevout(tx, n).or_else(|| {
                        let prevout = &tx.vin[n].prevout;
                        self.chain
                            .and_then(|c| c.get_transaction(&prevout.txid).ok().flatten())
                            .and_then(|p| p.vout.get(prevout.vout as usize).cloned())
                    });
                    if let Some(prev) = prev.filter(|p| counts(&p.script_pubkey)) {
                        sent += prev.value.as_sat();
                    }
                }
            }
            let received: i64 = tx
                .vout
                .iter()
                .filter(|out| counts(&out.script_pubkey))
                .map(|out| out.value.as_sat())
                .sum();
            if received != 0 && depth >= min_depth {
                balance += received;
            }
            balance -= sent;
        }
        balance
    }

    /// The tally of ListReceived (rpcwallet.cpp:1814-1844): for every
    /// destination, the outputs paid to it by wallet transactions that are
    /// not coinbases, final and at least `min_depth` deep, when the wallet owns
    /// the destination spendably (or watches it, with `watch`)
    pub(crate) fn received_tally(&self, min_depth: i64, watch: bool) -> HashMap<String, Tally> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as u32);
        let mut tally: HashMap<String, Tally> = HashMap::new();
        for record in self.ordered_records() {
            let Some(loaded) = self.load(&record) else {
                continue;
            };
            let tx = &loaded.tx;
            if tx.is_coinbase() || !tx.is_final(self.height, now) {
                continue;
            }
            let depth = self.depth(&record.txid, &loaded);
            if depth < min_depth {
                continue;
            }
            for out in &tx.vout {
                let Some(address) = self.destination(&out.script_pubkey) else {
                    continue;
                };
                let mine = self.mine(&address.script_pubkey());
                if !Self::requested(mine, watch) {
                    continue;
                }
                let item = tally.entry(address.to_base58()).or_insert(Tally {
                    amount: 0,
                    confirmations: i64::MAX,
                    txids: Vec::new(),
                    watch_only: false,
                });
                item.amount += out.value.as_sat();
                item.confirmations = item.confirmations.min(depth);
                item.txids.push(record.txid.to_string());
                item.watch_only |= mine == Mine::WatchOnly;
            }
        }
        tally
    }

    /// GetBlocksToMaturity (MerkleTxConfirmationNumberCalculator.cpp:54-59)
    fn blocks_to_maturity(&self, depth: i64) -> i64 {
        (self.maturity as i64 + 1 - depth).max(0)
    }

    /// The coinstake branch of ParseTransactionDetails (rpcwallet.cpp:2034-2107)
    fn coinstake_details(
        &self,
        loaded: &Loaded,
        account: &str,
        push: &PushEntry,
        out: &mut Vec<Value>,
    ) {
        let tx = &loaded.tx;
        let all_accounts = account == "*";
        let debit = self.debit(tx, false);
        // ComputeBlockHeightOfFirstConfirmation: the height of the block the
        // record names, active or not; 0 without one
        let block_height = loaded.block.map_or(0, |b| b.1);
        let confirmed = block_height > 0;
        let (stake_reward, lottery) = match self.chain {
            Some(chain) => {
                let (start, cycle) = chain.get_lottery_params();
                (
                    chain.block_rewards(block_height).stake.as_sat(),
                    confirmed && divi_consensus::is_lottery_block(block_height, start, cycle),
                )
            }
            None => (0, false),
        };
        let Some(staker) = tx.vout.get(1) else {
            return;
        };
        let staker_script = &staker.script_pubkey;
        let staker_mine = self.mine(staker_script);
        if staker_mine != Mine::No {
            if !all_accounts && !account.is_empty() {
                return;
            }
            let mut total = 0i64;
            let mut ambiguous = false;
            for o in tx.vout.iter().skip(1) {
                if &o.script_pubkey == staker_script {
                    total += o.value.as_sat().max(0);
                }
                if !ambiguous && total - debit > stake_reward {
                    ambiguous = true;
                }
            }
            let mut entry = Map::new();
            entry.insert(
                "involvesWatchonly".into(),
                json!(staker_mine == Mine::WatchOnly),
            );
            entry.insert("address".into(), json!(self.address_string(staker_script)));
            entry.insert("amount".into(), amount(total - debit));
            entry.insert("vout".into(), json!(1));
            entry.insert(
                "category".into(),
                json!(if ambiguous {
                    "stake_reward"
                } else {
                    "stake_reward+"
                }),
            );
            entry.insert("account".into(), json!(""));
            push(entry, out);
        }
        if confirmed {
            // Outputs of someone else's coinstake paying this wallet
            for (n, o) in tx.vout.iter().enumerate().skip(1) {
                let mine = self.mine(&o.script_pubkey);
                if mine == Mine::No || &o.script_pubkey == staker_script {
                    continue;
                }
                let dest = self.destination(&o.script_pubkey);
                let name = self.account_of(&dest);
                if !all_accounts && name != account {
                    continue;
                }
                let mut entry = Map::new();
                entry.insert("involvesWatchonly".into(), json!(mine == Mine::WatchOnly));
                entry.insert(
                    "address".into(),
                    json!(self.address_string(&o.script_pubkey)),
                );
                entry.insert("amount".into(), amount(o.value.as_sat()));
                entry.insert("vout".into(), json!(n));
                entry.insert(
                    "category".into(),
                    json!(if lottery { "lottery" } else { "mn_reward" }),
                );
                entry.insert("account".into(), json!(name));
                push(entry, out);
            }
        }
    }

    /// gettransaction (rpcwallet.cpp:2452-2490)
    pub(crate) fn transaction(&self, record: &WalletTx, watch: bool) -> Option<Value> {
        let loaded = self.load(record)?;
        let tx = &loaded.tx;
        let credit = self.credit(tx, watch);
        let debit = self.debit(tx, watch);
        let value_out: i64 = tx.vout.iter().map(|o| o.value.as_sat()).sum();
        let mut entry = Map::new();
        entry.insert("amount".into(), amount(credit - debit));
        if debit > 0 {
            entry.insert("fee".into(), amount(debit - value_out));
        }
        self.tx_fields(record, &loaded, &mut entry);
        let mut details = Vec::new();
        self.details(record, "*", 0, false, watch, &mut details);
        entry.insert("details".into(), json!(details));
        entry.insert(
            "hex".into(),
            json!(hex::encode(divi_primitives::serialize::serialize(tx))),
        );
        Some(Value::Object(entry))
    }
}
