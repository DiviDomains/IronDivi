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

//! Wallet database
//!
//! Persistent storage for wallet data including keys, addresses, and UTXOs.

use crate::address::{Address, Network};
use crate::at_rest::{self, KdfParams, MasterKey};
use crate::error::WalletError;
use crate::hd::HdWallet;
use crate::keystore::KeyStore;
use crate::persistence::{
    WalletDatabase, KEY_ENCRYPTED_MASTER_KEY, KEY_ENCRYPTED_MNEMONIC, KEY_ENCRYPTION_SALT,
    KEY_KDF_PARAMS,
};

use divi_primitives::amount::Amount;
use divi_primitives::hash::{Hash160, Hash256};
use divi_primitives::redact::{OwnOutpoint, WalletAddress, WalletAmount, WalletTxid};
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use divi_primitives::ChainMode;

use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};
use zeroize::Zeroizing;

/// Wallet UTXO
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    /// Transaction ID
    pub txid: Hash256,
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value: Amount,
    /// Script pubkey
    pub script_pubkey: Script,
    /// Block height (None if unconfirmed)
    pub height: Option<u32>,
    /// Whether this is from a coinbase transaction
    pub is_coinbase: bool,
    /// Whether this is from a coinstake transaction
    pub is_coinstake: bool,
    /// Address this UTXO belongs to
    pub address: String,
}

impl WalletUtxo {
    /// Create a new wallet UTXO
    pub fn new(
        txid: Hash256,
        vout: u32,
        value: Amount,
        script_pubkey: Script,
        address: String,
    ) -> Self {
        WalletUtxo {
            txid,
            vout,
            value,
            script_pubkey,
            height: None,
            is_coinbase: false,
            is_coinstake: false,
            address,
        }
    }

    /// Get the outpoint
    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid, self.vout)
    }

    /// Check if this UTXO is mature (for coinbase/coinstake)
    pub fn is_mature(&self, current_height: u32, maturity: u32) -> bool {
        if !self.is_coinbase && !self.is_coinstake {
            return true;
        }
        match self.height {
            Some(h) => current_height >= h + maturity,
            None => false, // Unconfirmed coinbase/coinstake not mature
        }
    }

    /// Get confirmations
    pub fn confirmations(&self, current_height: u32) -> u32 {
        match self.height {
            Some(h) if current_height >= h => current_height - h + 1,
            _ => 0,
        }
    }
}

/// Vault metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultMetadata {
    pub owner_address: String,
    pub manager_address: String,
    pub vault_script: Vec<u8>, // 50-byte vault script
    pub funding_txid: [u8; 32],
}

/// How the wallet relates to a vault output (Divi Core's ISMINE_OWNED_VAULT
/// and ISMINE_MANAGED_VAULT)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultRole {
    /// We hold the owner key: the coins are ours and can be reclaimed at any
    /// time; no registration is needed
    Owned,
    /// We hold the manager key and registered the vault with addvault: we may
    /// only stake it
    Managed,
}

/// How the wallet owns an output script (Divi Core's isminetype)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// Not the wallet's
    No,
    /// Watched only: never recorded as a coin
    WatchOnly,
    /// The wallet can sign for it
    Spendable,
    /// A vault whose owner key the wallet holds
    OwnedVault,
    /// A registered vault whose manager key the wallet holds
    ManagedVault,
}

/// Tracks which categories of wallet data have been modified since last save
#[derive(Default, Clone)]
struct DirtyFlags {
    metadata: bool,
    keys: bool,
    utxos: bool,
    spent: bool,
    transactions: bool,
    addresses: bool,
    accounts: bool,
    scripts: bool,
    vaults: bool,
}

impl DirtyFlags {
    fn any_dirty(&self) -> bool {
        self.metadata
            || self.keys
            || self.utxos
            || self.spent
            || self.transactions
            || self.addresses
            || self.accounts
            || self.scripts
            || self.vaults
    }

    fn clear(&mut self) {
        *self = DirtyFlags::default();
    }
}

/// UTXO, spent and transaction rows to delete from disk on the next save
#[derive(Default)]
struct PendingDeletes {
    utxos: HashSet<OutPoint>,
    spent: HashSet<OutPoint>,
    transactions: HashSet<Hash256>,
}

impl PendingDeletes {
    fn is_empty(&self) -> bool {
        self.utxos.is_empty() && self.spent.is_empty() && self.transactions.is_empty()
    }
}

/// Wallet transaction record
#[derive(Debug, Clone)]
pub struct WalletTx {
    /// Transaction ID
    pub txid: Hash256,
    /// Block hash (if confirmed)
    pub block_hash: Option<Hash256>,
    /// Block height (if confirmed)
    pub block_height: Option<u32>,
    /// Timestamp
    pub timestamp: u64,
    /// Net change to wallet balance
    pub amount: i64,
    /// Fee paid (if we sent it)
    pub fee: Option<Amount>,
    /// Category (receive, send, stake, etc.)
    pub category: String,
    /// Confirmations (updated on query)
    pub confirmations: u32,
}

/// A wallet transaction waiting in the mempool.
///
/// Kept beside the confirmed state rather than inside it: the confirmed UTXO
/// set, spent set and history are what the block scan updates, so a mempool
/// transaction never touches them. The raw transaction is stored on disk as
/// soon as the wallet sees it and the overlay is rebuilt from it on open, so
/// an unconfirmed send survives a restart or crash before the next block.
/// When the transaction confirms, the block scan records it as usual and the
/// entry is dropped; if it is evicted or conflicted, dropping the entry (here
/// and on disk) is enough.
/// Where a coin in the wallet's effective UTXO view came from
#[derive(Debug, Clone, Copy)]
enum CoinSource {
    /// Recorded from a block (the persisted UTXO set)
    Block,
    /// Output of a wallet transaction still in the mempool. Trusted when all
    /// its inputs are ours (Core's IsTrusted), e.g. our own change.
    Mempool { trusted: bool },
}

impl CoinSource {
    /// Counts toward Core's GetBalance and may be selected for spending
    fn is_trusted(self) -> bool {
        match self {
            CoinSource::Block => true,
            CoinSource::Mempool { trusted } => trusted,
        }
    }
}

/// A wallet transaction that left the chain or the mempool without
/// confirming: conflicted by another spend, evicted, or in a block that was
/// disconnected. Divi Core keeps such transactions in the wallet, at depth -1
/// (MerkleTxConfirmationNumberCalculator.cpp:43-47).
#[derive(Debug, Clone)]
pub struct DetachedTx {
    /// When the wallet first saw it
    pub timestamp: u64,
    /// The transaction, when the wallet had it (a disconnected block's
    /// transactions are left to the chain's transaction index)
    pub tx: Option<divi_primitives::transaction::Transaction>,
}

#[derive(Debug, Clone)]
struct MempoolWalletTx {
    /// Every outpoint the transaction spends (ours or not), for conflict checks
    inputs: Vec<OutPoint>,
    /// The subset of `inputs` that belong to this wallet
    spends: Vec<OutPoint>,
    /// Outputs paying this wallet (height None)
    outputs: Vec<WalletUtxo>,
    /// Core's IsTrusted for a 0-conf transaction: every input is ours
    trusted: bool,
    /// History entry shown by listtransactions/gettransaction (block_height None)
    record: WalletTx,
    /// The transaction itself, to store and to resubmit after a restart
    tx: divi_primitives::transaction::Transaction,
}

/// Wallet database
/// Called with the txid of a wallet transaction each time the wallet adds or
/// updates it, as Divi Core's NotifyTransactionChanged NEW or UPDATED
/// (wallet.cpp:1283): committed by a send, seen in the mempool, in a block
/// connected or disconnected, or found by a scan.
pub type TxListener = std::sync::Arc<dyn Fn(&Hash256) + Send + Sync>;

pub struct WalletDb {
    /// Key store
    keystore: KeyStore,
    /// Network
    network: Network,
    /// Wallet UTXOs
    utxos: RwLock<HashMap<OutPoint, WalletUtxo>>,
    /// Spent outpoints (to detect double-spends)
    spent: RwLock<HashSet<OutPoint>>,
    /// Transaction history
    transactions: RwLock<HashMap<Hash256, WalletTx>>,
    /// Addresses we've seen transactions for
    used_addresses: RwLock<HashSet<String>>,
    /// Database for persistence
    db: Option<Arc<WalletDatabase>>,
    /// Whether the wallet is encrypted
    encrypted: RwLock<bool>,
    /// Whether the wallet is locked
    locked: RwLock<bool>,
    /// Last scanned block height
    last_scan_height: RwLock<u32>,
    /// Account to addresses mapping
    accounts: RwLock<HashMap<String, Vec<String>>>,
    /// Address to account mapping
    address_accounts: RwLock<HashMap<String, String>>,
    /// Redeem scripts (for P2SH addresses, especially multisig)
    scripts: RwLock<HashMap<Hash160, Script>>,
    /// Vault metadata storage
    vaults: RwLock<HashMap<Vec<u8>, VaultMetadata>>,
    /// Coins `lockunspent` set aside. In memory only, as Divi Core's
    /// `setLockedCoins`; neither staked nor spent while locked.
    locked_coins: RwLock<HashSet<OutPoint>>,
    /// How the wallet is unlocked: timer and staking-only flag
    unlock: RwLock<UnlockState>,
    /// Decrypted master key (in memory only when unlocked). Unlock and
    /// change_passphrase hold the write lock while they rewrite records, so no
    /// key is written in a format that is being replaced.
    decrypted_master_key: RwLock<Option<MasterKey>>,
    /// Tracks which data categories have been modified since last save
    dirty: RwLock<DirtyFlags>,
    /// Spent UTXOs with spending height - for reorg restoration (in-memory only)
    spent_utxo_data: RwLock<HashMap<OutPoint, (WalletUtxo, u32)>>,
    /// Wallet transactions in the mempool (stored on disk as raw transactions)
    mempool_txs: RwLock<HashMap<Hash256, MempoolWalletTx>>,
    /// Wallet transactions that left the chain or the mempool unconfirmed
    /// (stored on disk), listed at depth -1 as Divi Core lists them
    detached_txs: RwLock<HashMap<Hash256, DetachedTx>>,
    /// Serializes block scanning: live block notifications, the startup
    /// catch-up, reorg rollback and rescans must not interleave, or a spend
    /// can be scanned before the coin it spends and be lost
    scan_lock: Mutex<()>,
    /// Told each wallet transaction added or seen again (-walletnotify)
    tx_listener: RwLock<Option<TxListener>>,
    /// Rows removed from memory that must also be deleted from disk on the
    /// next save (a save only writes what is in memory)
    pending_deletes: RwLock<PendingDeletes>,
    /// Hashes of the most recently scanned blocks by height (in memory), so a
    /// sync notices a chain switch it was not told about (invalidateblock,
    /// a missed reorg notification) and rolls back to the fork first
    scanned_hashes: RwLock<BTreeMap<u32, Hash256>>,
    /// Divi Core's -vault: addvault and removevault change the wallet only
    /// when it is on (wallet.cpp:152, :693-716)
    vault_mode: std::sync::atomic::AtomicBool,
    /// Divi Core's -spendzeroconfchange: a send may also use unconfirmed
    /// outputs of our own transactions (wallet.cpp:1848)
    spend_zero_conf_change: std::sync::atomic::AtomicBool,
    /// The relay fee rate the wallet pays, satoshis per 1000 bytes (Divi
    /// Core's -minrelaytxfee, which its wallet follows: rpcwallet.cpp:470-473)
    relay_fee_per_kb: std::sync::atomic::AtomicI64,
    /// The highest fee a send may pay, satoshis (Divi Core's -maxtxfee:
    /// MinimumFeeCoinSelectionAlgorithm.cpp:97, wallet.cpp:1559-1562)
    max_tx_fee: std::sync::atomic::AtomicI64,
    /// The position each transaction was first seen at, and the next one
    /// (Divi Core's nOrderPos, the order listtransactions follows)
    tx_order: RwLock<(HashMap<Hash256, u64>, u64)>,
    /// Notes kept with a transaction by the call that sent it (Divi Core's
    /// mapValue: comment, to, FromAccount), in key order as Core's std::map
    tx_notes: RwLock<HashMap<Hash256, BTreeMap<String, String>>>,
}

/// Unlock state of an encrypted wallet (Divi Core `walletStakingOnly` plus the
/// `walletpassphrase` timer of rpcserver.cpp `UnlockWalletBriefly`)
#[derive(Debug, Clone, Copy, Default)]
struct UnlockState {
    /// When the current unlock ends; None means until `walletlock`
    until: Option<Instant>,
    /// Keys are in memory for staking only: sends and key exports are refused
    staking_only: bool,
    /// When `until` passes, go back to staking-only instead of locking
    revert_to_staking: bool,
}

/// How many recently scanned block hashes the wallet remembers
const SCANNED_HASHES_KEPT: usize = 10_000;

/// How many of them are saved with the scan height (more than Divi's deepest
/// reorganization of 100 blocks)
const SCANNED_HASHES_SAVED: usize = 128;

impl WalletDb {
    /// Create a new in-memory wallet
    pub fn new(network: Network) -> Self {
        WalletDb {
            keystore: KeyStore::new(network),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: None,
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults: RwLock::new(HashMap::new()),
            locked_coins: RwLock::new(HashSet::new()),
            unlock: RwLock::new(UnlockState::default()),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
            mempool_txs: RwLock::new(HashMap::new()),
            detached_txs: RwLock::new(HashMap::new()),
            scan_lock: Mutex::new(()),
            tx_listener: RwLock::new(None),
            pending_deletes: RwLock::new(PendingDeletes::default()),
            scanned_hashes: RwLock::new(BTreeMap::new()),
            vault_mode: std::sync::atomic::AtomicBool::new(false),
            spend_zero_conf_change: std::sync::atomic::AtomicBool::new(false),
            relay_fee_per_kb: std::sync::atomic::AtomicI64::new(crate::send::MIN_RELAY_FEE_PER_KB),
            max_tx_fee: std::sync::atomic::AtomicI64::new(crate::send::DEFAULT_MAX_TX_FEE.as_sat()),
            tx_order: RwLock::new((HashMap::new(), 0)),
            tx_notes: RwLock::new(HashMap::new()),
        }
    }

    /// Create wallet with HD wallet
    pub fn with_hd_wallet(network: Network, wallet: HdWallet) -> Self {
        let wallet = with_core_coin_type(wallet, network);
        WalletDb {
            keystore: KeyStore::with_hd_wallet(network, wallet),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: None,
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults: RwLock::new(HashMap::new()),
            locked_coins: RwLock::new(HashSet::new()),
            unlock: RwLock::new(UnlockState::default()),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
            mempool_txs: RwLock::new(HashMap::new()),
            detached_txs: RwLock::new(HashMap::new()),
            scan_lock: Mutex::new(()),
            tx_listener: RwLock::new(None),
            pending_deletes: RwLock::new(PendingDeletes::default()),
            scanned_hashes: RwLock::new(BTreeMap::new()),
            vault_mode: std::sync::atomic::AtomicBool::new(false),
            spend_zero_conf_change: std::sync::atomic::AtomicBool::new(false),
            relay_fee_per_kb: std::sync::atomic::AtomicI64::new(crate::send::MIN_RELAY_FEE_PER_KB),
            max_tx_fee: std::sync::atomic::AtomicI64::new(crate::send::DEFAULT_MAX_TX_FEE.as_sat()),
            tx_order: RwLock::new((HashMap::new(), 0)),
            tx_notes: RwLock::new(HashMap::new()),
        }
    }

    /// Open a persistent wallet from disk
    pub fn open(path: &Path, network: Network) -> Result<Self, WalletError> {
        let db = WalletDatabase::open(path)?;
        let db = Arc::new(db);

        let vaults = RwLock::new(HashMap::new());

        let mut wallet = WalletDb {
            keystore: KeyStore::new(network),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: Some(Arc::clone(&db)),
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults,
            locked_coins: RwLock::new(HashSet::new()),
            unlock: RwLock::new(UnlockState::default()),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
            mempool_txs: RwLock::new(HashMap::new()),
            detached_txs: RwLock::new(HashMap::new()),
            scan_lock: Mutex::new(()),
            tx_listener: RwLock::new(None),
            pending_deletes: RwLock::new(PendingDeletes::default()),
            scanned_hashes: RwLock::new(BTreeMap::new()),
            vault_mode: std::sync::atomic::AtomicBool::new(false),
            spend_zero_conf_change: std::sync::atomic::AtomicBool::new(false),
            relay_fee_per_kb: std::sync::atomic::AtomicI64::new(crate::send::MIN_RELAY_FEE_PER_KB),
            max_tx_fee: std::sync::atomic::AtomicI64::new(crate::send::DEFAULT_MAX_TX_FEE.as_sat()),
            tx_order: RwLock::new((HashMap::new(), 0)),
            tx_notes: RwLock::new(HashMap::new()),
        };

        // Load wallet data from database
        wallet.load()?;

        // Load vaults from disk
        let vault_list = db.load_vaults()?;
        {
            let mut vaults_map = wallet.vaults.write();
            for (key, metadata) in vault_list {
                vaults_map.insert(key, metadata);
            }
        }
        // Needs keys, UTXOs, spent set, history and vaults loaded first
        wallet.restore_unconfirmed_txs(&db)?;
        wallet.restore_detached_txs(&db)?;
        debug!("Restored {} vaults", wallet.vaults.read().len());

        // Wallets written before removevault dropped its outputs still hold them
        wallet.prune_unowned_vault_utxos();

        Ok(wallet)
    }

    /// Rebuild the mempool overlay from the unconfirmed transactions on disk.
    /// A stored transaction that has since confirmed, or whose coin was spent
    /// by a confirmed transaction, is dropped from disk instead, together with
    /// the stored transactions that spend its outputs.
    fn restore_unconfirmed_txs(&self, db: &WalletDatabase) -> Result<(), WalletError> {
        let mut stored = Vec::new();
        for (timestamp, raw) in db.load_unconfirmed_txs()? {
            match divi_primitives::deserialize::<divi_primitives::transaction::Transaction>(&raw) {
                Ok(tx) => stored.push((timestamp, tx)),
                Err(e) => tracing::warn!("Skipping unreadable unconfirmed wallet tx: {}", e),
            }
        }
        let mut restored = 0;
        let mut dropped = HashSet::new();
        for (timestamp, tx) in parents_first(stored) {
            let txid = tx.txid();
            let orphaned = tx.vin.iter().any(|i| dropped.contains(&i.prevout.txid));
            let confirmed = matches!(
                self.transactions.read().get(&txid),
                Some(t) if t.block_height.is_some()
            );
            let conflicted = {
                let spent = self.spent.read();
                tx.vin.iter().any(|i| {
                    !i.prevout.is_null()
                        && spent.contains(&OutPoint::new(i.prevout.txid, i.prevout.vout))
                })
            };
            if orphaned || confirmed || conflicted || !self.track_mempool_tx(&tx, Some(timestamp)) {
                debug!(
                    "Dropping stored unconfirmed wallet tx {}",
                    WalletTxid::of(txid)
                );
                db.remove_unconfirmed_tx(&txid)?;
                if !confirmed {
                    // Its outputs never existed, so whatever spends them is void too
                    dropped.insert(txid);
                    self.detach(txid, timestamp, Some(tx.clone()));
                }
            } else {
                restored += 1;
            }
        }
        if restored > 0 {
            info!("Restored {} unconfirmed wallet transaction(s)", restored);
        }
        Ok(())
    }

    /// Load the detached transactions stored on disk, forgetting those the
    /// wallet has since recorded from a block or holds in the mempool overlay
    fn restore_detached_txs(&self, db: &WalletDatabase) -> Result<(), WalletError> {
        for (txid, timestamp, raw) in db.load_detached_txs()? {
            if self.is_recorded(&txid) {
                db.remove_detached_tx(&txid)?;
                continue;
            }
            let tx = if raw.is_empty() {
                None
            } else {
                match divi_primitives::deserialize(&raw) {
                    Ok(tx) => Some(tx),
                    Err(e) => {
                        tracing::warn!(
                            "Skipping unreadable detached wallet tx {}: {}",
                            WalletTxid::of(txid),
                            e
                        );
                        continue;
                    }
                }
            };
            self.detached_txs
                .write()
                .insert(txid, DetachedTx { timestamp, tx });
        }
        Ok(())
    }

    /// Recorded from a block, or in the mempool overlay
    fn is_recorded(&self, txid: &Hash256) -> bool {
        matches!(self.transactions.read().get(txid), Some(t) if t.block_height.is_some())
            || self.mempool_txs.read().contains_key(txid)
    }

    /// Keep a wallet transaction that left the chain or the mempool unconfirmed
    fn detach(
        &self,
        txid: Hash256,
        timestamp: u64,
        tx: Option<divi_primitives::transaction::Transaction>,
    ) {
        if self.is_recorded(&txid) {
            return;
        }
        let raw = tx
            .as_ref()
            .map(divi_primitives::serialize)
            .unwrap_or_default();
        {
            let mut detached = self.detached_txs.write();
            if let Some(known) = detached.get(&txid) {
                if known.tx.is_some() || tx.is_none() {
                    return;
                }
            }
            detached.insert(txid, DetachedTx { timestamp, tx });
        }
        if let Some(ref db) = self.db {
            if let Err(e) = db.store_detached_tx(&txid, timestamp, &raw) {
                tracing::warn!(
                    "Failed to store detached wallet tx {}: {}",
                    WalletTxid::of(txid),
                    e
                );
            }
        }
    }

    /// A detached transaction is in a block or the mempool again
    fn reattach(&self, txid: &Hash256) {
        if self.detached_txs.write().remove(txid).is_some() {
            if let Some(ref db) = self.db {
                if let Err(e) = db.remove_detached_tx(txid) {
                    tracing::warn!(
                        "Failed to forget detached wallet tx {}: {}",
                        WalletTxid::of(txid),
                        e
                    );
                }
            }
        }
    }

    /// Wallet transactions that left the chain or the mempool unconfirmed
    pub fn detached_transactions(&self) -> Vec<(Hash256, DetachedTx)> {
        self.detached_txs
            .read()
            .iter()
            .map(|(id, d)| (*id, d.clone()))
            .collect()
    }

    /// Every wallet transaction as Divi Core's wallet keeps them: recorded,
    /// in the mempool, and detached (block fields empty)
    pub fn history_records(&self) -> Vec<WalletTx> {
        let mut list = self.get_transactions(None);
        let known: HashSet<Hash256> = list.iter().map(|t| t.txid).collect();
        list.extend(
            self.detached_txs
                .read()
                .iter()
                .filter(|(id, _)| !known.contains(id))
                .map(|(id, d)| Self::detached_record(*id, d)),
        );
        list
    }

    /// One wallet transaction, detached ones included
    pub fn history_record(&self, txid: &Hash256) -> Option<WalletTx> {
        self.get_transaction(txid).or_else(|| {
            self.detached_txs
                .read()
                .get(txid)
                .map(|d| Self::detached_record(*txid, d))
        })
    }

    fn detached_record(txid: Hash256, d: &DetachedTx) -> WalletTx {
        WalletTx {
            txid,
            block_hash: None,
            block_height: None,
            timestamp: d.timestamp,
            amount: 0,
            fee: None,
            category: String::new(),
            confirmations: 0,
        }
    }

    /// Unconfirmed wallet transactions, parents before children, to resubmit
    /// to the mempool after a restart
    pub fn unconfirmed_transactions(&self) -> Vec<divi_primitives::transaction::Transaction> {
        let txs = self
            .mempool_txs
            .read()
            .values()
            .map(|e| (e.record.timestamp, e.tx.clone()))
            .collect();
        parents_first(txs).into_iter().map(|(_, tx)| tx).collect()
    }

    /// Migrate the wallet's chain_mode for future key derivations.
    /// Existing keys (stored as raw bytes) are unaffected.
    /// This rebuilds the in-memory HdWallet with the new chain_mode
    /// and persists the change to the database.
    pub fn migrate_chain_mode(&self, new_mode: ChainMode) -> Result<(), WalletError> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| WalletError::Storage("No database".into()))?;

        let stored_mode = db.load_chain_mode()?;
        if stored_mode == Some(new_mode) {
            return Ok(()); // Already correct
        }

        if let Some(mnemonic) = db.load_mnemonic()? {
            let passphrase = db.load_mnemonic_passphrase()?;
            let mut hd_wallet =
                HdWallet::from_mnemonic(&mnemonic, passphrase.as_deref(), new_mode)?;
            // A Divi wallet keeps a testnet coin type it was made with
            if let (ChainMode::Divi, Some(coin_type)) = (new_mode, db.load_hd_coin_type()?) {
                if coin_type != crate::hd::PRIVATEDIVI_COIN_TYPE {
                    hd_wallet = hd_wallet.with_coin_type(coin_type);
                }
            }
            db.store_hd_coin_type(hd_wallet.coin_type())?;
            self.keystore.set_hd_wallet(hd_wallet);
            db.store_chain_mode(new_mode)?;
            info!("Migrated wallet chain_mode to {:?}", new_mode);
        } else if let Some(seed) = db.load_hd_seed()? {
            let mut hd_wallet = HdWallet::from_seed(&seed, new_mode)?;
            if let (ChainMode::Divi, Some(coin_type)) = (new_mode, db.load_hd_coin_type()?) {
                if coin_type != crate::hd::PRIVATEDIVI_COIN_TYPE {
                    hd_wallet = hd_wallet.with_coin_type(coin_type);
                }
            }
            db.store_hd_coin_type(hd_wallet.coin_type())?;
            self.keystore.set_hd_wallet(hd_wallet);
            db.store_chain_mode(new_mode)?;
            info!("Migrated wallet chain_mode to {:?}", new_mode);
        }

        Ok(())
    }

    /// Create a new persistent wallet with HD wallet
    pub fn create_persistent(
        path: &Path,
        network: Network,
        wallet: HdWallet,
    ) -> Result<Self, WalletError> {
        let db = WalletDatabase::open(path)?;
        let db = Arc::new(db);

        // Store mnemonic, network, chain mode and coin type
        let wallet = with_core_coin_type(wallet, network);
        if let Some(mnemonic) = wallet.mnemonic() {
            db.store_mnemonic(mnemonic)?;
        }
        if let Some(passphrase) = wallet.mnemonic_passphrase() {
            db.store_mnemonic_passphrase(passphrase)?;
        }
        if let Some(seed) = wallet.seed() {
            db.store_hd_seed(seed)?;
        }
        db.store_network(network)?;

        // Store chain mode and coin type for the same HD derivation on future loads
        db.store_chain_mode(wallet.chain_mode())?;
        db.store_hd_coin_type(wallet.coin_type())?;

        let wallet_db = WalletDb {
            keystore: KeyStore::with_hd_wallet(network, wallet),
            network,
            utxos: RwLock::new(HashMap::new()),
            spent: RwLock::new(HashSet::new()),
            transactions: RwLock::new(HashMap::new()),
            used_addresses: RwLock::new(HashSet::new()),
            db: Some(db),
            encrypted: RwLock::new(false),
            locked: RwLock::new(false),
            last_scan_height: RwLock::new(0),
            accounts: RwLock::new(HashMap::new()),
            address_accounts: RwLock::new(HashMap::new()),
            scripts: RwLock::new(HashMap::new()),
            vaults: RwLock::new(HashMap::new()),
            locked_coins: RwLock::new(HashSet::new()),
            unlock: RwLock::new(UnlockState::default()),
            decrypted_master_key: RwLock::new(None),
            dirty: RwLock::new(DirtyFlags::default()),
            spent_utxo_data: RwLock::new(HashMap::new()),
            mempool_txs: RwLock::new(HashMap::new()),
            detached_txs: RwLock::new(HashMap::new()),
            scan_lock: Mutex::new(()),
            tx_listener: RwLock::new(None),
            pending_deletes: RwLock::new(PendingDeletes::default()),
            scanned_hashes: RwLock::new(BTreeMap::new()),
            vault_mode: std::sync::atomic::AtomicBool::new(false),
            spend_zero_conf_change: std::sync::atomic::AtomicBool::new(false),
            relay_fee_per_kb: std::sync::atomic::AtomicI64::new(crate::send::MIN_RELAY_FEE_PER_KB),
            max_tx_fee: std::sync::atomic::AtomicI64::new(crate::send::DEFAULT_MAX_TX_FEE.as_sat()),
            tx_order: RwLock::new((HashMap::new(), 0)),
            tx_notes: RwLock::new(HashMap::new()),
        };

        Ok(wallet_db)
    }

    /// Load wallet data from database
    fn load(&mut self) -> Result<(), WalletError> {
        let db = match &self.db {
            Some(db) => db,
            None => {
                info!("No database, starting with empty wallet");
                return Ok(());
            }
        };

        // Load and verify network
        if let Some(stored_network) = db.load_network()? {
            if stored_network != self.network {
                return Err(WalletError::Storage(format!(
                    "Network mismatch: wallet is {:?}, expected {:?}",
                    stored_network, self.network
                )));
            }
        }

        {
            let mut order = self.tx_order.write();
            for (txid, position) in db.load_tx_order()? {
                order.0.insert(txid, position);
                order.1 = order.1.max(position + 1);
            }
        }
        for (txid, raw) in db.load_tx_notes()? {
            match serde_json::from_slice::<BTreeMap<String, String>>(&raw) {
                Ok(notes) => {
                    self.tx_notes.write().insert(txid, notes);
                }
                Err(e) => debug!(
                    "Skipping unreadable notes of {}: {}",
                    WalletTxid::of(txid),
                    e
                ),
            }
        }

        // Load mnemonic and restore HD wallet
        if let Some(mnemonic) = db.load_mnemonic()? {
            let passphrase = db.load_mnemonic_passphrase()?;
            let hd_wallet = stored_hd_wallet(db, &mnemonic, passphrase.as_deref())?;
            debug!(
                "Restored HD wallet from mnemonic (chain_mode={:?}, coin type {})",
                hd_wallet.chain_mode(),
                hd_wallet.coin_type()
            );
            self.keystore.set_hd_wallet(hd_wallet);
        } else if let Some(seed) = db.load_hd_seed()? {
            self.keystore.set_hd_wallet(stored_seed_wallet(db, &seed)?);
        } else if let Some(ids) = db.load_hd_public_ids()? {
            // Encrypted wallet: the seed stays locked, its public ids do not
            self.keystore.set_hd_public_ids(ids);
        }

        // Load HD indices
        let (receiving, change) = db.load_indices()?;
        self.keystore.set_indices(receiving, change);
        debug!(
            "Restored indices: receiving={}, change={}",
            receiving, change
        );

        // Load keys
        let keys = db.load_keys()?;
        for (hash, entry) in keys {
            self.keystore.add_key_with_hash(hash, entry);
        }
        debug!("Restored {} keys", self.keystore.key_count());

        // Load UTXOs
        let utxos = db.load_utxos()?;
        {
            let mut utxo_map = self.utxos.write();
            for (outpoint, utxo) in utxos {
                utxo_map.insert(outpoint, utxo);
            }
        }
        debug!("Restored {} UTXOs", self.utxos.read().len());

        // Load spent outpoints
        let spent = db.load_spent()?;
        {
            let mut spent_set = self.spent.write();
            for outpoint in spent {
                spent_set.insert(outpoint);
            }
        }
        debug!("Restored {} spent outpoints", self.spent.read().len());

        // Safety: remove any UTXOs that are also in the spent set
        // (should not happen with correct save(), but handles legacy data)
        {
            let spent_set = self.spent.read();
            let mut utxo_map = self.utxos.write();
            let before = utxo_map.len();
            utxo_map.retain(|outpoint, _| !spent_set.contains(outpoint));
            let removed = before - utxo_map.len();
            if removed > 0 {
                info!("Removed {} stale UTXOs that were in spent set", removed);
            }
        }

        // Load transactions
        let transactions = db.load_transactions()?;
        {
            let mut tx_map = self.transactions.write();
            for tx in transactions {
                tx_map.insert(tx.txid, tx);
            }
        }
        debug!("Restored {} transactions", self.transactions.read().len());

        // Load used addresses
        let addresses = db.load_used_addresses()?;
        {
            let mut addr_set = self.used_addresses.write();
            for addr in addresses {
                addr_set.insert(addr);
            }
        }
        debug!(
            "Restored {} used addresses",
            self.used_addresses.read().len()
        );

        // Load encrypted flag
        *self.encrypted.write() = db.load_encrypted()?;
        if *self.encrypted.read() {
            // Secrets are on disk only in encrypted form: start locked
            *self.locked.write() = true;
        }

        // Load last scan height
        *self.last_scan_height.write() = db.load_last_scan_height()?;
        self.scanned_hashes
            .write()
            .extend(db.load_scanned_hashes()?);

        // Load accounts
        let accounts = db.load_accounts()?;
        {
            let mut accounts_map = self.accounts.write();
            for (account, mut addresses) in accounts {
                // Divi Core reads its "name" records in key order (the address
                // string after its length) and an account's current address is
                // the last one read (walletdb.cpp:242-251,
                // AddressBookManager.cpp:17-22), so after a restart it is the
                // greatest address, not the last one handed out
                addresses.sort_by(|a, b| (a.len(), a).cmp(&(b.len(), b)));
                accounts_map.insert(account, addresses);
            }
        }
        debug!("Restored {} accounts", self.accounts.read().len());

        // Load address to account mappings
        let address_accounts = db.load_address_accounts()?;
        {
            let mut addr_accounts_map = self.address_accounts.write();
            for (address, account) in address_accounts {
                addr_accounts_map.insert(address, account);
            }
        }
        debug!(
            "Restored {} address-account mappings",
            self.address_accounts.read().len()
        );

        let scripts = db.load_scripts()?;
        {
            let mut scripts_map = self.scripts.write();
            for (hash, script) in scripts {
                scripts_map.insert(hash, script);
            }
        }
        debug!("Restored {} redeem scripts", self.scripts.read().len());

        // Load spent UTXO data for reorg recovery
        let spent_utxo_entries = db.load_spent_utxo_data()?;
        {
            let mut spent_data = self.spent_utxo_data.write();
            for (outpoint, utxo, spent_height) in spent_utxo_entries {
                spent_data.insert(outpoint, (utxo, spent_height));
            }
        }
        debug!(
            "Restored {} spent UTXO data entries for reorg recovery",
            self.spent_utxo_data.read().len()
        );

        info!(
            "Wallet loaded: {} keys, {} UTXOs, {} transactions, {} accounts, {} scripts, balance = {}",
            self.keystore.key_count(),
            self.utxos.read().len(),
            self.transactions.read().len(),
            self.accounts.read().len(),
            self.scripts.read().len(),
            WalletAmount(self.get_balance().as_sat())
        );

        Ok(())
    }

    /// Add one key entry to a write batch. In an encrypted wallet the private key is
    /// written only as an encrypted blob (and never at all while locked, when there is
    /// no master key); the plain entry carries just the public data.
    fn put_key(
        &self,
        batch: &mut rocksdb::WriteBatch,
        db: &WalletDatabase,
        hash: &Hash160,
        entry: &crate::keystore::KeyEntry,
    ) {
        use crate::persistence::{serialize_key_entry, ENCRYPTED_SECRET_SUFFIX};

        if !*self.encrypted.read() {
            batch.put_cf(db.cf_keys(), hash.as_bytes(), serialize_key_entry(entry));
            return;
        }
        let mut stripped = entry.clone();
        let secret = stripped.secret.take();
        batch.put_cf(
            db.cf_keys(),
            hash.as_bytes(),
            serialize_key_entry(&stripped),
        );
        if let Some(secret) = secret {
            match self.decrypted_master_key.read().as_ref() {
                Some(master) => {
                    let mut suffixed = hash.as_bytes().to_vec();
                    suffixed.push(ENCRYPTED_SECRET_SUFFIX);
                    let blob = master.seal_record(&suffixed, secret.as_bytes());
                    batch.put_cf(db.cf_keys(), &suffixed, blob);
                }
                None => tracing::warn!("Refusing to write a private key unencrypted"),
            }
        }
    }

    /// Write the given keys (with the encrypted secret, on an encrypted wallet) and
    /// the HD indices in one synced batch. Every key the wallet creates or imports
    /// goes through here before it is handed out: the per-block `save_incremental`
    /// is too late, a lock or restart before the next block would lose the key.
    fn persist_keys(&self, hashes: &[Hash160]) -> Result<(), WalletError> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()),
        };
        let entries: Vec<_> = hashes
            .iter()
            .filter_map(|h| self.keystore.get_key(h).map(|e| (*h, e)))
            .collect();
        if *self.encrypted.read()
            && self.decrypted_master_key.read().is_none()
            && entries.iter().any(|(_, e)| e.secret.is_some())
        {
            // put_key would drop the secret; refuse rather than store a key without it
            return Err(WalletError::WalletLocked);
        }
        let mut batch = db.create_batch();
        for (hash, entry) in &entries {
            self.put_key(&mut batch, db, hash, entry);
        }
        let (receiving, change) = self.keystore.get_indices();
        batch.put_cf(
            db.cf_metadata(),
            b"receiving_index",
            receiving.to_le_bytes(),
        );
        batch.put_cf(db.cf_metadata(), b"change_index", change.to_le_bytes());
        db.write_batch_sync(batch)
    }

    /// Save wallet data to database
    pub fn save(&self) -> Result<(), WalletError> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()), // No persistence
        };
        use crate::persistence::{outpoint_key, serialize_tx, serialize_utxo};

        // One synced batch: a crash or kill during the save leaves the previous
        // save or this one on disk, never a mix of the two (e.g. a coin gone
        // from the UTXO table without the transaction that spent it)
        let mut batch = db.create_batch();

        // Save mnemonic (an encrypted wallet keeps only the encrypted copy)
        if !*self.encrypted.read() {
            if let Some(mnemonic) = self.keystore.mnemonic() {
                batch.put_cf(db.cf_metadata(), b"mnemonic", mnemonic.as_bytes());
            }
            if let Some(seed) = self.keystore.hd_seed() {
                batch.put_cf(db.cf_metadata(), crate::persistence::KEY_HD_SEED, &seed[..]);
            }
        }

        // Save network
        let network_val = match self.network {
            Network::Mainnet => b"mainnet".as_slice(),
            Network::Testnet => b"testnet".as_slice(),
            Network::Regtest => b"regtest".as_slice(),
        };
        batch.put_cf(db.cf_metadata(), b"network", network_val);

        // Save HD indices
        let (receiving, change) = self.keystore.get_indices();
        batch.put_cf(
            db.cf_metadata(),
            b"receiving_index",
            receiving.to_le_bytes(),
        );
        batch.put_cf(db.cf_metadata(), b"change_index", change.to_le_bytes());

        // Save keys
        for (hash, entry) in self.keystore.get_all_keys_with_hashes() {
            self.put_key(&mut batch, db, &hash, &entry);
        }

        // Delete rows dropped from memory (reorg, rescan) so they do not come
        // back on the next load; the rows written below come after them in the
        // batch and win over them
        let pending = self.pending_deletes_snapshot();
        Self::put_pending_deletes(&mut batch, db, &pending);

        // Save UTXOs and remove spent ones from the UTXO table.
        // First, delete any spent outpoints from the UTXO column family so they
        // don't reappear when the wallet is loaded next time.
        for outpoint in self.spent.read().iter() {
            let key = outpoint_key(outpoint);
            batch.delete_cf(db.cf_utxos(), &key);
            batch.put_cf(db.cf_spent(), &key, [1]);
        }

        // Then save current (unspent) UTXOs
        for (outpoint, utxo) in self.utxos.read().iter() {
            batch.put_cf(db.cf_utxos(), outpoint_key(outpoint), serialize_utxo(utxo));
        }

        // Save transactions
        for tx in self.transactions.read().values() {
            batch.put_cf(db.cf_transactions(), tx.txid.as_bytes(), serialize_tx(tx));
        }

        // Save used addresses
        for addr in self.used_addresses.read().iter() {
            batch.put_cf(db.cf_addresses(), addr.as_bytes(), [1]);
        }

        // Save encrypted flag
        batch.put_cf(
            db.cf_metadata(),
            b"encrypted",
            [*self.encrypted.read() as u8],
        );

        self.put_scan_state(&mut batch, db);

        // Save accounts
        for (account, addresses) in self.accounts.read().iter() {
            let key = format!("acc_{}", account);
            let value = serde_json::to_string(addresses)
                .map_err(|e| WalletError::Storage(format!("Failed to serialize account: {}", e)))?;
            batch.put_cf(db.cf_accounts(), key.as_bytes(), value.as_bytes());
        }

        // Save address to account mappings
        for (address, account) in self.address_accounts.read().iter() {
            let key = format!("addr_{}", address);
            batch.put_cf(db.cf_accounts(), key.as_bytes(), account.as_bytes());
        }

        for (hash, script) in self.scripts.read().iter() {
            batch.put_cf(db.cf_scripts(), hash.as_bytes(), script.as_bytes());
        }

        // Synced, so it is on disk when this returns; no memtable flush needed
        db.write_batch_sync(batch)?;
        self.clear_pending_deletes(&pending);
        stop_point!("wallet deletes written");

        // Clear dirty flags since everything was just written
        self.dirty.write().clear();

        debug!("Wallet saved to disk");
        Ok(())
    }

    fn pending_deletes_snapshot(&self) -> PendingDeletes {
        let p = self.pending_deletes.read();
        PendingDeletes {
            utxos: p.utxos.clone(),
            spent: p.spent.clone(),
            transactions: p.transactions.clone(),
        }
    }

    /// Forget deletes that have been written (new ones may have arrived since)
    fn clear_pending_deletes(&self, written: &PendingDeletes) {
        let mut p = self.pending_deletes.write();
        p.utxos.retain(|o| !written.utxos.contains(o));
        p.spent.retain(|o| !written.spent.contains(o));
        p.transactions.retain(|t| !written.transactions.contains(t));
    }

    fn put_pending_deletes(
        batch: &mut rocksdb::WriteBatch,
        db: &WalletDatabase,
        pending: &PendingDeletes,
    ) {
        use crate::persistence::outpoint_key;
        for outpoint in &pending.utxos {
            batch.delete_cf(db.cf_utxos(), outpoint_key(outpoint));
        }
        for outpoint in &pending.spent {
            batch.delete_cf(db.cf_spent(), outpoint_key(outpoint));
        }
        for txid in &pending.transactions {
            batch.delete_cf(db.cf_transactions(), txid.as_bytes());
        }
    }

    /// Save only the last scan height to database (lightweight, no flush)
    pub fn save_scan_height(&self) -> Result<(), WalletError> {
        if let Some(db) = &self.db {
            let mut batch = db.create_batch();
            self.put_scan_state(&mut batch, db);
            db.write_batch(batch)?;
        }
        Ok(())
    }

    /// The scan height and the hashes of the blocks scanned up to it, so a
    /// restart on a chain where those blocks were replaced rolls them back, as
    /// Divi Core's wallet starts from the fork of its best-block locator
    /// (wallet.cpp:258-293). Enough heights are kept to cover the deepest
    /// reorganization.
    fn put_scan_state(&self, batch: &mut rocksdb::WriteBatch, db: &WalletDatabase) {
        let last = *self.last_scan_height.read();
        batch.put_cf(db.cf_metadata(), b"last_scan_height", last.to_le_bytes());
        let recent: Vec<(u32, Hash256)> = self
            .scanned_hashes
            .read()
            .range(..=last)
            .rev()
            .take(SCANNED_HASHES_SAVED)
            .map(|(h, hash)| (*h, *hash))
            .collect();
        batch.put_cf(
            db.cf_metadata(),
            crate::persistence::KEY_SCANNED_HASHES,
            crate::persistence::encode_scanned_hashes(&recent),
        );
    }

    /// Incrementally save only dirty wallet data using an atomic WriteBatch.
    /// Much cheaper than full save() when only a few categories changed.
    pub fn save_incremental(&self) -> Result<(), WalletError> {
        use crate::persistence::{outpoint_key, serialize_tx, serialize_utxo};

        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()),
        };

        let flags = self.dirty.read().clone();
        let pending = self.pending_deletes_snapshot();
        if !flags.any_dirty() && pending.is_empty() {
            // Nothing changed — just persist scan height
            return self.save_scan_height();
        }

        let mut batch = db.create_batch();

        // Deletes go first so that rows written below win over them
        Self::put_pending_deletes(&mut batch, db, &pending);

        // Always update scan height
        self.put_scan_state(&mut batch, db);

        if flags.utxos || flags.spent {
            // Remove spent outpoints from UTXO CF and add to spent CF
            for outpoint in self.spent.read().iter() {
                let key = outpoint_key(outpoint);
                batch.delete_cf(db.cf_utxos(), &key);
                batch.put_cf(db.cf_spent(), &key, [1]);
            }

            // Write current UTXOs (only if utxos dirty)
            if flags.utxos {
                for (outpoint, utxo) in self.utxos.read().iter() {
                    let key = outpoint_key(outpoint);
                    let value = serialize_utxo(utxo);
                    batch.put_cf(db.cf_utxos(), &key, &value);
                }
            }
        }

        if flags.transactions {
            for tx in self.transactions.read().values() {
                let value = serialize_tx(tx);
                batch.put_cf(db.cf_transactions(), tx.txid.as_bytes(), &value);
            }
        }

        if flags.keys {
            for (hash, entry) in self.keystore.get_all_keys_with_hashes() {
                self.put_key(&mut batch, db, &hash, &entry);
            }
        }

        if flags.addresses {
            for addr in self.used_addresses.read().iter() {
                batch.put_cf(db.cf_addresses(), addr.as_bytes(), [1]);
            }
        }

        if flags.accounts {
            for (account, addresses) in self.accounts.read().iter() {
                let key = format!("acc_{}", account);
                let value = serde_json::to_string(addresses).map_err(|e| {
                    WalletError::Storage(format!("Failed to serialize account: {}", e))
                })?;
                batch.put_cf(db.cf_accounts(), key.as_bytes(), value.as_bytes());
            }
            for (address, account) in self.address_accounts.read().iter() {
                let key = format!("addr_{}", address);
                batch.put_cf(db.cf_accounts(), key.as_bytes(), account.as_bytes());
            }
        }

        if flags.metadata {
            if !*self.encrypted.read() {
                if let Some(mnemonic) = self.keystore.mnemonic() {
                    batch.put_cf(db.cf_metadata(), b"mnemonic", mnemonic.as_bytes());
                }
                if let Some(seed) = self.keystore.hd_seed() {
                    batch.put_cf(db.cf_metadata(), crate::persistence::KEY_HD_SEED, &seed[..]);
                }
            }
            let network_val = match self.network {
                Network::Mainnet => b"mainnet".as_slice(),
                Network::Testnet => b"testnet".as_slice(),
                Network::Regtest => b"regtest".as_slice(),
            };
            batch.put_cf(db.cf_metadata(), b"network", network_val);
            let (receiving, change) = self.keystore.get_indices();
            batch.put_cf(
                db.cf_metadata(),
                b"receiving_index",
                receiving.to_le_bytes(),
            );
            batch.put_cf(db.cf_metadata(), b"change_index", change.to_le_bytes());
            batch.put_cf(
                db.cf_metadata(),
                b"encrypted",
                [*self.encrypted.read() as u8],
            );
        }

        // Atomic write
        db.write_batch(batch)?;

        // Clear dirty flags
        self.dirty.write().clear();
        self.clear_pending_deletes(&pending);

        debug!("Wallet incremental save complete");
        Ok(())
    }

    /// Get last scanned block height
    pub fn last_scan_height(&self) -> u32 {
        *self.last_scan_height.read()
    }

    /// Set last scanned block height
    pub fn set_last_scan_height(&self, height: u32) {
        *self.last_scan_height.write() = height;
    }

    /// Get the keystore
    pub fn keystore(&self) -> &KeyStore {
        &self.keystore
    }

    /// Write a backup of the wallet to `destination`, as `backupwallet`: a
    /// consistent copy of the open database (a checkpoint, then copied, so the
    /// backup shares no file with the wallet). An existing folder that is not
    /// itself a wallet backup gets the copy inside it under the wallet's name,
    /// as Divi Core appends wallet.dat to a directory (walletdb.cpp:609-610);
    /// an earlier backup at the destination is replaced. Returns where it went.
    ///
    /// Only a backup this method wrote (it carries [`BACKUP_MARKER`]) is ever
    /// replaced: any other database (the live wallet, the chain, another
    /// program's store) or folder at the destination is refused, never removed.
    pub fn backup_to(&self, destination: &Path) -> Result<std::path::PathBuf, WalletError> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| WalletError::Storage("wallet has no database to back up".into()))?;
        let is_db = |p: &Path| p.join("CURRENT").exists();
        let is_backup = |p: &Path| is_db(p) && p.join(BACKUP_MARKER).is_file();
        if destination.is_dir() && is_db(destination) && !is_backup(destination) {
            return Err(WalletError::Storage(format!(
                "{} holds a database that is not a wallet backup; refusing to replace it",
                destination.display()
            )));
        }
        let name = db
            .path()
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| "wallet".into());
        let target = if destination.is_dir() && !is_backup(destination) {
            destination.join(&name)
        } else {
            destination.to_path_buf()
        };
        if target.is_file() {
            return Err(WalletError::Storage(format!(
                "{} is a file; give a folder name for the wallet backup",
                target.display()
            )));
        }
        if target.exists() && !is_backup(&target) {
            return Err(WalletError::Storage(format!(
                "{} exists and is not a wallet backup",
                target.display()
            )));
        }
        // Never the live wallet, nor a folder that holds it, even when it was
        // itself restored from a backup and so carries the marker
        if let (Ok(t), Ok(live)) = (target.canonicalize(), db.path().canonicalize()) {
            if live.starts_with(&t) {
                return Err(WalletError::Storage(format!(
                    "{} is the open wallet; give another place for the backup",
                    target.display()
                )));
            }
        }
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| WalletError::Storage(e.to_string()))?;
        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let mut checkpoint_name = std::ffi::OsString::from(".");
        checkpoint_name.push(&name);
        checkpoint_name.push(format!(".checkpoint-{stamp}"));
        let checkpoint = db
            .path()
            .parent()
            .unwrap_or(Path::new("."))
            .join(checkpoint_name);
        let mut staging = target.clone().into_os_string();
        staging.push(format!(".partial-{stamp}"));
        let staging = std::path::PathBuf::from(staging);

        let result = (|| {
            db.checkpoint_to(&checkpoint)?;
            crate::backup::copy_dir(&checkpoint, &staging)
                .map_err(|e| WalletError::Storage(format!("Failed to copy backup: {e}")))?;
            write_backup_marker(&staging.join(BACKUP_MARKER))?;
            if target.exists() {
                std::fs::remove_dir_all(&target)
                    .map_err(|e| WalletError::Storage(e.to_string()))?;
            }
            std::fs::rename(&staging, &target).map_err(|e| WalletError::Storage(e.to_string()))
        })();
        let _ = std::fs::remove_dir_all(&checkpoint);
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&staging);
        }
        result?;
        info!("Wallet backed up to {}", target.display());
        Ok(target)
    }

    pub fn database_path(&self) -> std::path::PathBuf {
        match &self.db {
            Some(db) => db.path().to_path_buf(),
            None => std::path::PathBuf::from("wallet.dat"),
        }
    }

    /// Get network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get coinbase maturity for this network (Divi Core nMaturity: mainnet 20,
    /// testnet 1, regtest 20; chainparams.cpp:184, :400, :479)
    pub fn coinbase_maturity(&self) -> u32 {
        match self.network {
            Network::Mainnet => 20,
            Network::Testnet => 1,
            Network::Regtest => 20,
        }
    }

    /// Generate a new receiving address
    pub fn new_receiving_address(&self) -> Result<Address, WalletError> {
        self.new_address(false)
    }

    /// Generate a new change address
    pub fn new_change_address(&self) -> Result<Address, WalletError> {
        self.new_address(true)
    }

    /// Hand out the next receiving or change key. As in Divi Core, a locked
    /// wallet hands out a pre-generated keypool key (its secret is already on
    /// disk, encrypted) and fails with `KeypoolRanOut` when none is left; an
    /// unlocked wallet derives the key and tops the keypool up. The key and the
    /// advanced index are stored before the address is returned.
    fn new_address(&self, is_change: bool) -> Result<Address, WalletError> {
        // Apply an expired timeout before reading the flag, so a timed-out
        // wallet does not derive from the seed it should have dropped
        self.is_locked();
        // Held until the key is stored, so a concurrent lock() cannot strip it first
        let locked = self.locked.read();
        let mut store = Vec::new();
        let addr = if *locked {
            self.keystore.take_from_keypool(is_change)?
        } else {
            // Divi Core tops the keypool up, then takes its oldest key
            // (wallet.cpp:2122-2156), so the pool is one short afterwards
            store = self.keystore.top_up_keypool(None).unwrap_or_default();
            if is_change {
                self.keystore.new_change_address()?
            } else {
                self.keystore.new_receiving_address()?
            }
        };
        self.dirty.write().keys = true;
        self.dirty.write().metadata = true; // receiving/change index changed
        store.push(addr.hash);
        self.persist_keys(&store)?;
        Ok(addr)
    }

    /// Derive the missing keypool keys (the seed must be in memory) and store
    /// them. Returns the number of keys added.
    pub fn top_up_keypool(&self) -> Result<u32, WalletError> {
        self.refill_keypool(None)
    }

    /// Get all wallet addresses
    pub fn get_addresses(&self) -> Vec<Address> {
        self.keystore.get_addresses()
    }

    /// Whether the wallet knows an address at all, spendable or watched
    /// (Divi Core's IsMine of its script is not ISMINE_NO)
    pub fn is_mine(&self, address: &Address) -> bool {
        self.ownership(&address.script_pubkey()) != Ownership::No
    }

    /// Whether an address is watched only (Divi Core's ISMINE_WATCH_ONLY)
    pub fn is_watch_only(&self, address: &Address) -> bool {
        self.ownership(&address.script_pubkey()) == Ownership::WatchOnly
    }

    /// Import a watch-only public key
    pub fn import_watch_only_pubkey(
        &self,
        pubkey: divi_crypto::keys::PublicKey,
        label: Option<String>,
    ) -> Address {
        let addr = self.keystore.import_watch_only(pubkey, label);
        self.dirty.write().keys = true;
        if let Err(e) = self.persist_keys(&[addr.hash]) {
            error!(
                "Failed to store watch-only key {}: {}",
                WalletAddress(&addr.to_string()),
                e
            );
        }
        addr
    }

    /// Import a watch-only address
    ///
    /// This allows tracking UTXOs sent to an address without having the private key.
    /// The address can be monitored for incoming transactions but cannot be used for spending.
    pub fn import_watch_only_address(
        &self,
        address: &Address,
        label: Option<String>,
    ) -> Result<(), crate::error::WalletError> {
        // Create a deterministic dummy public key from the address hash
        // This is a placeholder since we only have the address (hash), not the actual public key
        use divi_crypto::keys::SecretKey;

        let mut seed = [0u8; 32];
        seed[..20].copy_from_slice(address.hash.as_bytes());
        seed[20..].copy_from_slice(b"watch-only  ");

        let dummy_secret = SecretKey::from_bytes(&seed).map_err(|e| {
            crate::error::WalletError::InvalidKey(format!(
                "Failed to create watch-only entry: {}",
                e
            ))
        })?;
        let public = dummy_secret.public_key();

        // Import as watch-only, keyed by the original address hash (not the dummy pubkey hash)
        let entry = crate::keystore::KeyEntry::watch_only(public, label);
        self.keystore.add_key_with_hash(address.hash, entry);
        self.dirty.write().keys = true;
        self.persist_keys(&[address.hash])?;

        Ok(())
    }

    /// Check if an address is a change address
    ///
    /// Returns true if the address is derived from the HD wallet's change chain
    pub fn is_change_address(&self, address: &Address) -> bool {
        self.keystore.is_change_address(address)
    }

    /// Check if an address string is a change address
    ///
    /// Returns true if the address is derived from the HD wallet's change chain
    pub fn is_change_address_str(&self, address_str: &str) -> bool {
        if let Ok(address) = Address::from_base58(address_str) {
            self.keystore.is_change_address(&address)
        } else {
            false
        }
    }

    /// Get HD master key ID (hash160 of master public key, hex-encoded)
    ///
    /// Returns empty string if no HD wallet is configured
    pub fn hd_master_key_id(&self) -> String {
        self.keystore
            .hd_master_key_id()
            .map(hex::encode)
            .unwrap_or_default()
    }

    /// Whether the wallet records an output paying `script`: Divi Core keeps a
    /// transaction only when it pays or spends a spendable or vault output
    /// (wallet.cpp:1300-1305), so watched scripts never bring coins in.
    pub fn is_mine_script(&self, script: &Script) -> bool {
        matches!(
            self.ownership(script),
            Ownership::Spendable | Ownership::OwnedVault | Ownership::ManagedVault
        )
    }

    /// How the wallet owns `script`, as Divi Core's IsMine
    /// (wallet_ismine.cpp:37-113): P2PKH and P2PK of a wallet key, a bare
    /// multisig of wallet keys only, and P2SH by what its stored redeem script
    /// is are spendable; a vault is owned through its owner key or managed
    /// through its manager key once registered. Watched P2PKH and P2SH
    /// addresses, and redeem scripts stored without every key, are watch-only.
    pub fn ownership(&self, script: &Script) -> Ownership {
        use divi_script::standard::{extract_script_type, ScriptType};

        if self.is_watched_script(script) {
            return Ownership::WatchOnly;
        }
        let (kind, solutions) = extract_script_type(script.as_bytes());
        let has_signing_key = |hash: Hash160| {
            self.keystore
                .get_key(&hash)
                .is_some_and(|entry| !entry.is_watch_only)
        };
        match kind {
            ScriptType::PubKey => {
                if has_signing_key(divi_crypto::hash160(&solutions[0])) {
                    return Ownership::Spendable;
                }
            }
            ScriptType::PubKeyHash => {
                if has_signing_key(hash160_from(&solutions[0])) {
                    return Ownership::Spendable;
                }
            }
            ScriptType::ScriptHash => {
                if let Some(redeem) = self.get_script(&hash160_from(&solutions[0])) {
                    return match self.ownership(&redeem) {
                        // addmultisigaddress watches a redeem script it
                        // cannot spend (rpcwallet.cpp:1770-1771)
                        Ownership::No => Ownership::WatchOnly,
                        mine => mine,
                    };
                }
            }
            ScriptType::Vault => match self.vault_role(script) {
                Some(VaultRole::Owned) => return Ownership::OwnedVault,
                Some(VaultRole::Managed) => return Ownership::ManagedVault,
                None => {}
            },
            ScriptType::Multisig => {
                let keys = &solutions[1..solutions.len() - 1];
                if keys
                    .iter()
                    .all(|key| has_signing_key(divi_crypto::hash160(key)))
                {
                    return Ownership::Spendable;
                }
            }
            _ => {}
        }
        Ownership::No
    }

    /// A P2PKH or P2SH script imported with importaddress (Divi Core's
    /// HaveWatchOnly; IronDivi keeps the watched hash as a key entry)
    fn is_watched_script(&self, script: &Script) -> bool {
        let hash = match script.extract_p2pkh_hash() {
            Some(hash) => hash,
            None => match script.extract_p2sh_hash() {
                Some(hash) => hash,
                None => return false,
            },
        };
        self.keystore.is_watch_only(&Hash160::from_bytes(hash))
    }

    /// Our role for a vault script, as Divi Core's IsMine: the owner key makes
    /// it ours whether or not it is registered; the manager key counts only
    /// for a vault registered with addvault. None for any other script.
    pub fn vault_role(&self, script: &Script) -> Option<VaultRole> {
        let vault = divi_script::StakingVaultScript::from_script(script)?;
        let has_signing_key = |hash: [u8; 20]| {
            self.keystore
                .get_key(&Hash160::from_bytes(hash))
                .is_some_and(|entry| !entry.is_watch_only)
        };
        if has_signing_key(vault.owner_pubkey_hash) {
            return Some(VaultRole::Owned);
        }
        if has_signing_key(vault.vault_pubkey_hash)
            && self.vaults.read().contains_key(script.as_bytes())
        {
            return Some(VaultRole::Managed);
        }
        None
    }

    /// Add a UTXO to the wallet
    pub fn add_utxo(&self, utxo: WalletUtxo) {
        let outpoint = utxo.outpoint();
        debug!(
            "Adding UTXO {} ({})",
            OwnOutpoint(utxo.txid, utxo.vout),
            WalletAmount(utxo.value.as_sat())
        );
        self.utxos.write().insert(outpoint, utxo);
        self.dirty.write().utxos = true;
    }

    /// Remove a UTXO (mark as spent)
    pub fn spend_utxo(&self, outpoint: &OutPoint) -> Option<WalletUtxo> {
        self.spend_utxo_at_height(outpoint, None)
    }

    /// Remove a UTXO (mark as spent), optionally tracking the spending height for reorg support
    pub fn spend_utxo_at_height(
        &self,
        outpoint: &OutPoint,
        height: Option<u32>,
    ) -> Option<WalletUtxo> {
        let utxo = self.utxos.write().remove(outpoint);
        if let Some(ref u) = utxo {
            debug!("Spent UTXO {}", OwnOutpoint(outpoint.txid, outpoint.vout));
            self.spent.write().insert(*outpoint);
            if let Some(h) = height {
                self.spent_utxo_data
                    .write()
                    .insert(*outpoint, (u.clone(), h));
                // Persist to RocksDB so reorg recovery survives restart
                if let Some(ref db) = self.db {
                    if let Err(e) = db.store_spent_utxo_data(outpoint, u, h) {
                        debug!("Failed to persist spent_utxo_data: {}", e);
                    }
                }
            }
            let mut dirty = self.dirty.write();
            dirty.utxos = true;
            dirty.spent = true;
        }
        utxo
    }

    /// Check if we have a UTXO
    pub fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.utxos.read().contains_key(outpoint)
    }

    /// Get a UTXO
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<WalletUtxo> {
        self.utxos.read().get(outpoint).cloned()
    }

    /// Get all UTXOs, including outputs of wallet transactions in the mempool
    /// and excluding coins those transactions spend
    pub fn get_utxos(&self) -> Vec<WalletUtxo> {
        self.effective_utxos().into_iter().map(|(u, _)| u).collect()
    }

    /// Unspent coins as Core sees them: confirmed UTXOs not spent by a mempool
    /// transaction, plus our outputs of mempool transactions. The flag is
    /// Core's IsTrusted: true for confirmed coins and for outputs of mempool
    /// transactions that spend only our coins (our own change).
    fn effective_utxos(&self) -> Vec<(WalletUtxo, CoinSource)> {
        let overlay = self.mempool_txs.read();
        let spent: HashSet<OutPoint> = overlay
            .values()
            .flat_map(|e| e.spends.iter().copied())
            .collect();

        let mut result: Vec<(WalletUtxo, CoinSource)> = self
            .utxos
            .read()
            .values()
            .filter(|u| !spent.contains(&u.outpoint()))
            .map(|u| (u.clone(), CoinSource::Block))
            .collect();
        for entry in overlay.values() {
            for u in &entry.outputs {
                if !spent.contains(&u.outpoint()) {
                    result.push((
                        u.clone(),
                        CoinSource::Mempool {
                            trusted: entry.trusted,
                        },
                    ));
                }
            }
        }
        result
    }

    /// Every output the wallet has received, spent or not: confirmed coins
    /// still held, confirmed coins since spent, and outputs of wallet
    /// transactions in the mempool (height None). Core's received-by totals
    /// (getreceivedbyaddress and friends) sum over all of these.
    pub fn received_outputs(&self) -> Vec<WalletUtxo> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for u in self.utxos.read().values() {
            if seen.insert(u.outpoint()) {
                out.push(u.clone());
            }
        }
        for (u, _) in self.spent_utxo_data.read().values() {
            if seen.insert(u.outpoint()) {
                out.push(u.clone());
            }
        }
        for entry in self.mempool_txs.read().values() {
            for u in &entry.outputs {
                if seen.insert(u.outpoint()) {
                    out.push(u.clone());
                }
            }
        }
        out
    }

    /// Lock (`lock` true) or unlock a coin, as `lockunspent` does
    pub fn set_coin_locked(&self, outpoint: OutPoint, lock: bool) {
        let mut locked = self.locked_coins.write();
        if lock {
            locked.insert(outpoint);
        } else {
            locked.remove(&outpoint);
        }
    }

    /// Whether `lockunspent` locked this coin
    pub fn is_coin_locked(&self, outpoint: &OutPoint) -> bool {
        self.locked_coins.read().contains(outpoint)
    }

    /// Every coin `lockunspent` locked
    pub fn locked_coins(&self) -> Vec<OutPoint> {
        self.locked_coins.read().iter().copied().collect()
    }

    /// Outpoints spent by wallet transactions in the mempool
    fn mempool_spent(&self) -> HashSet<OutPoint> {
        self.mempool_txs
            .read()
            .values()
            .flat_map(|e| e.spends.iter().copied())
            .collect()
    }

    /// Get spendable UTXOs (mature and confirmed)
    ///
    /// Vault outputs are never included (Core's ALL_SPENDABLE_COINS): a
    /// manager can only stake them, and an owner spends them on purpose with
    /// reclaimvaultfunds or debitvaultbyname.
    ///
    /// Coins already spent by a mempool transaction are excluded. With
    /// `min_confirmations == 0`, our own unconfirmed change is included, but
    /// not unconfirmed coins from others (Core only spends trusted coins).
    pub fn get_spendable_utxos(
        &self,
        current_height: u32,
        min_confirmations: u32,
    ) -> Vec<WalletUtxo> {
        self.effective_utxos()
            .into_iter()
            .filter(|(_, source)| source.is_trusted())
            .map(|(utxo, _)| utxo)
            .filter(|utxo| self.ownership(&utxo.script_pubkey) == Ownership::Spendable)
            .filter(|utxo| {
                utxo.confirmations(current_height) >= min_confirmations
                    && utxo.is_mature(current_height, self.coinbase_maturity())
            })
            .collect()
    }

    /// Reconcile wallet UTXOs against the chain's UTXO set.
    /// Removes wallet UTXOs that the chain does not have (phantom UTXOs).
    ///
    /// This handles the case where IronDivi stakes a block that later gets orphaned,
    /// and the coinstake outputs remain as phantom UTXOs in the wallet after restart
    /// (because `spent_utxo_data` was in-memory only prior to persistence fix).
    ///
    /// Only coins at or below both `chain_height` and the wallet's scan height
    /// are checked: a coin in a block the chain has not reached yet (a chain
    /// being rebuilt) is not missing. A removed coin is forgotten rather than
    /// marked spent, so a later scan of its block brings it back if the chain
    /// does have it.
    ///
    /// The `chain_has_utxo` closure should return true if the outpoint exists in the
    /// chain UTXO database.
    pub fn reconcile_utxos<F>(&self, chain_height: u32, chain_has_utxo: F) -> u32
    where
        F: Fn(&OutPoint) -> bool,
    {
        let _scan = self.scan_lock.lock();
        let checked_to = chain_height.min(self.last_scan_height());
        let outpoints: Vec<OutPoint> = self
            .utxos
            .read()
            .iter()
            .filter(|(_, u)| u.height.is_some_and(|h| h <= checked_to))
            .map(|(op, _)| *op)
            .collect();
        let mut removed = 0u32;
        for outpoint in &outpoints {
            if !chain_has_utxo(outpoint) {
                if let Some(utxo) = self.utxos.write().remove(outpoint) {
                    info!(
                        "Reconciliation: removed phantom UTXO {} ({}, addr={})",
                        OwnOutpoint(outpoint.txid, outpoint.vout),
                        WalletAmount(utxo.value.as_sat()),
                        WalletAddress(&utxo.address)
                    );
                    self.pending_deletes.write().utxos.insert(*outpoint);
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            self.dirty.write().utxos = true;
            info!(
                "UTXO reconciliation complete: removed {} phantom UTXOs, {} remaining",
                removed,
                self.utxos.read().len()
            );
        } else {
            info!(
                "UTXO reconciliation complete: all {} wallet UTXOs up to height {} verified against chain",
                outpoints.len(),
                checked_to
            );
        }
        removed
    }

    /// Select UTXOs for a transaction using coin selection algorithm
    ///
    /// # Arguments
    /// * `target` - Target amount to send (excluding fee)
    /// * `fee_rate` - Fee rate in satoshis per byte
    /// * `num_outputs` - Number of outputs in the transaction
    /// * `current_height` - Current blockchain height
    /// * `min_confirmations` - Minimum confirmations required for UTXOs
    ///
    /// # Returns
    /// SelectionResult containing selected UTXOs, total value, fee, and change
    pub fn select_coins(
        &self,
        target: Amount,
        fee_rate: u64,
        num_outputs: usize,
        current_height: u32,
        min_confirmations: u32,
    ) -> Result<crate::coin_selection::SelectionResult, WalletError> {
        use crate::coin_selection::select;

        // Get spendable UTXOs
        let available_utxos = self.get_spendable_utxos(current_height, min_confirmations);

        if available_utxos.is_empty() {
            return Err(WalletError::InsufficientFunds {
                need: target.as_sat(),
                have: 0,
            });
        }

        // Use minimum selector (largest-first strategy)
        select::select_minimum(&available_utxos, target, fee_rate, num_outputs)
    }

    /// Coins a send may use, as Divi Core's `AvailableCoins` gives them to a
    /// send: confirmed (at least `min_confirmations`, never fewer than one),
    /// mature, unspent and not locked by `lockunspent`. Our own unconfirmed
    /// outputs are added only with `-spendzeroconfchange`, which is off by
    /// default: those of wallet transactions whose inputs are all ours
    /// (wallet.cpp:1848, AvailableUtxoCollector.cpp:33-43,
    /// AvailableUtxoCalculator.cpp:84-85). The send's coin selection orders them.
    pub fn get_send_candidates(
        &self,
        current_height: u32,
        min_confirmations: u32,
    ) -> Vec<WalletUtxo> {
        let zero_conf = self
            .spend_zero_conf_change
            .load(std::sync::atomic::Ordering::Relaxed);
        self.get_spendable_utxos(current_height, 0)
            .into_iter()
            .filter(|utxo| {
                let confirmations = utxo.confirmations(current_height);
                confirmations >= min_confirmations.max(1) || (zero_conf && confirmations == 0)
            })
            .filter(|utxo| !self.is_coin_locked(&utxo.outpoint()))
            .collect()
    }

    /// Unspent coins of the given ownership, confirmed or not, with where
    /// they come from. Coins spent by a wallet transaction in the mempool are
    /// left out, as Divi Core's IsSpent counts those spends.
    fn owned_coins(&self, wanted: &[Ownership]) -> Vec<(WalletUtxo, CoinSource)> {
        self.effective_utxos()
            .into_iter()
            .filter(|(u, _)| wanted.contains(&self.ownership(&u.script_pubkey)))
            .collect()
    }

    /// Confirmed, mature coins of the given ownership (Divi Core's
    /// CONFIRMED_AND_MATURE filter)
    fn confirmed_mature(&self, wanted: &[Ownership], current_height: u32) -> Amount {
        self.owned_coins(wanted)
            .into_iter()
            .filter(|(u, source)| {
                matches!(source, CoinSource::Block)
                    && u.height.is_some()
                    && u.is_mature(current_height, self.coinbase_maturity())
            })
            .fold(Amount::ZERO, |a, (u, _)| a + u.value)
    }

    /// Core's GetBalance (getbalance, getbalance "*"): confirmed, mature
    /// spendable coins and coins in vaults we own. Unconfirmed coins, our own
    /// change included, are getunconfirmedbalance's (wallet.cpp:1395-1402,
    /// FilteredTransactionsCalculator.h:62-78).
    pub fn get_balance(&self) -> Amount {
        self.confirmed_mature(
            &[Ownership::Spendable, Ownership::OwnedVault],
            self.last_scan_height(),
        )
    }

    /// Balance of `getbalance <account> minconf`: coins spent by a mempool
    /// transaction no longer count, our own unconfirmed change counts at any
    /// minconf, and unconfirmed coins from others count only at minconf 0.
    pub fn get_confirmed_balance(&self, current_height: u32, min_confirmations: u32) -> Amount {
        self.owned_coins(&[Ownership::Spendable, Ownership::OwnedVault])
            .into_iter()
            .filter(|(utxo, _)| utxo.is_mature(current_height, self.coinbase_maturity()))
            .filter(|(utxo, source)| match source {
                CoinSource::Block => utxo.confirmations(current_height) >= min_confirmations,
                CoinSource::Mempool { trusted } => *trusted || min_confirmations == 0,
            })
            .map(|(u, _)| u.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Core's GetUnconfirmedBalance: unconfirmed spendable coins, our own
    /// change as well as payments from others (wallet.cpp:1404-1412)
    pub fn get_unconfirmed_balance(&self) -> Amount {
        self.owned_coins(&[Ownership::Spendable])
            .into_iter()
            .filter(|(utxo, source)| match source {
                CoinSource::Block => utxo.height.is_none(),
                CoinSource::Mempool { .. } => true,
            })
            .map(|(u, _)| u.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Core's GetImmatureBalance: confirmed, immature spendable coins. A reward
    /// paid to a vault we own is in no balance until it matures
    /// (wallet.cpp:1414-1422).
    pub fn get_immature_balance(&self, current_height: u32, maturity: u32) -> Amount {
        self.owned_coins(&[Ownership::Spendable])
            .into_iter()
            .filter(|(utxo, source)| {
                matches!(source, CoinSource::Block)
                    && utxo.height.is_some()
                    && !utxo.is_mature(current_height, maturity)
            })
            .map(|(u, _)| u.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }

    /// Core's GetSpendableBalance (getwalletinfo spendable_balance):
    /// confirmed, mature spendable coins plus unconfirmed spendable outputs of
    /// transactions that spend only our spendable coins (WalletBalanceCalculator.cpp:73-81)
    pub fn get_spendable_balance(&self, current_height: u32) -> Amount {
        let unconfirmed = self
            .owned_coins(&[Ownership::Spendable])
            .into_iter()
            .filter(|(_, source)| matches!(source, CoinSource::Mempool { trusted: true }))
            .fold(Amount::ZERO, |a, (u, _)| a + u.value);
        self.confirmed_mature(&[Ownership::Spendable], current_height) + unconfirmed
    }

    /// Clear all wallet transactions, UTXOs, and spent tracking
    /// Used before rescanning to ensure clean state
    pub fn clear_transactions_and_utxos(&self) {
        info!("Clearing wallet transactions, UTXOs, and spent tracking");
        {
            let mut pending = self.pending_deletes.write();
            pending
                .transactions
                .extend(self.transactions.write().drain().map(|(txid, _)| txid));
            pending
                .utxos
                .extend(self.utxos.write().drain().map(|(outpoint, _)| outpoint));
            // A spent coin may still have a row in the UTXO table
            for outpoint in self.spent.write().drain() {
                pending.utxos.insert(outpoint);
                pending.spent.insert(outpoint);
            }
        }
        self.scanned_hashes.write().clear();
        for (outpoint, _) in self.spent_utxo_data.write().drain() {
            if let Some(ref db) = self.db {
                if let Err(e) = db.remove_spent_utxo_data(&outpoint) {
                    debug!("Failed to remove spent_utxo_data from disk: {}", e);
                }
            }
        }
        let mut dirty = self.dirty.write();
        dirty.transactions = true;
        dirty.utxos = true;
        dirty.spent = true;
    }

    /// Add a transaction to history
    pub fn add_transaction(&self, tx: WalletTx) {
        debug!("Adding transaction {} to history", WalletTxid(tx.txid));
        let (txid, confirmed) = (tx.txid, tx.block_height.is_some());
        self.note_first_seen(&txid);
        self.transactions.write().insert(tx.txid, tx);
        self.dirty.write().transactions = true;
        if confirmed {
            self.reattach(&txid);
        }
    }

    /// Get transaction history
    pub fn get_transactions(&self, count: Option<usize>) -> Vec<WalletTx> {
        let mut list: Vec<_> = self.transactions.read().values().cloned().collect();
        list.extend(self.mempool_txs.read().values().map(|e| e.record.clone()));

        // Sort by timestamp descending
        list.sort_by_key(|t| std::cmp::Reverse(t.timestamp));

        if let Some(n) = count {
            list.truncate(n);
        }
        list
    }

    /// Get a specific transaction
    pub fn get_transaction(&self, txid: &Hash256) -> Option<WalletTx> {
        if let Some(tx) = self.transactions.read().get(txid) {
            return Some(tx.clone());
        }
        self.mempool_txs.read().get(txid).map(|e| e.record.clone())
    }

    /// Mark an address as used
    pub fn mark_address_used(&self, address: &str) {
        self.used_addresses.write().insert(address.to_string());
        self.dirty.write().addresses = true;
    }

    /// Check if address has been used
    pub fn is_address_used(&self, address: &str) -> bool {
        self.used_addresses.read().contains(address)
    }

    /// Lock the wallet
    pub fn lock(&self) {
        // Held throughout, so no key is created between storing and stripping
        let mut locked = self.locked.write();
        *locked = true;
        // An encrypted wallet also drops every private key and the HD seed; they
        // are restored from their encrypted copies on unlock. An unencrypted
        // wallet has no other copy, so it only gets the flag.
        if *self.encrypted.read() {
            // Store every in-memory secret encrypted while the master key is still
            // here: unlock can only bring back what is on disk. If that write fails,
            // keep the keys in memory rather than lose them.
            let held: Vec<Hash160> = self
                .keystore
                .get_all_keys_with_hashes()
                .into_iter()
                .filter(|(_, e)| e.secret.is_some())
                .map(|(h, _)| h)
                .collect();
            match self.persist_keys(&held) {
                Ok(()) => self.keystore.strip_secrets(),
                Err(e) => {
                    error!(
                        "Could not store private keys before locking ({}); keeping {} keys in memory",
                        e,
                        held.len()
                    );
                    self.keystore.clear_hd_wallet();
                }
            }
        }
        // Clear decrypted master key from memory
        *self.decrypted_master_key.write() = None;
        *self.unlock.write() = UnlockState::default();
        drop(locked);
        info!("Wallet locked");
    }

    /// Unlock the wallet with passphrase for specified timeout
    pub fn unlock(&self, passphrase: &str, timeout_secs: u32) -> Result<(), WalletError> {
        self.unlock_for(passphrase, timeout_secs, false)
    }

    /// Unlock the wallet, fully or for staking only (`walletpassphrase` with
    /// stakingOnly). A timeout of 0 lasts until `walletlock`.
    ///
    /// As in Divi Core, a timed unlock given while the wallet is unlocked for
    /// staking only goes back to staking-only when it ends, rather than locking
    /// the wallet, so a short unlock to send does not stop staking.
    pub fn unlock_for(
        &self,
        passphrase: &str,
        timeout_secs: u32,
        staking_only: bool,
    ) -> Result<(), WalletError> {
        if !*self.encrypted.read() {
            // Not encrypted, nothing to unlock
            *self.locked.write() = false;
            return Ok(());
        }

        if passphrase.is_empty() {
            return Err(WalletError::InvalidPassphrase);
        }

        // Settle an earlier timed unlock that has run out before anything is
        // restored: if is_locked first noticed it further down, it would lock
        // the wallet and strip the keys and HD seed this unlock brings back
        let was_staking_only = self.is_unlocked_for_staking_only();

        // Load encryption metadata from database
        let db = self.db.as_ref().ok_or_else(|| {
            WalletError::Storage("Cannot unlock wallet without database".to_string())
        })?;

        // Held until the master key is installed: a key written meanwhile by
        // another thread would use the format this unlock may be replacing
        let mut master_slot = self.decrypted_master_key.write();
        let mut master = open_master(db, passphrase)?;

        // Decrypt everything first so a corrupt wallet is not left half-unlocked
        let records = decrypt_records(db, &master)?;
        let hd_wallet = match &records.mnemonic {
            Some(mnemonic) => {
                let mnemonic = std::str::from_utf8(mnemonic)
                    .map_err(|_| WalletError::Storage("corrupt encrypted mnemonic".into()))?;
                let passphrase = match &records.mnemonic_passphrase {
                    Some(bytes) => Some(std::str::from_utf8(bytes).map_err(|_| {
                        WalletError::Storage("corrupt encrypted passphrase".into())
                    })?),
                    None => None,
                };
                Some(stored_hd_wallet(db, mnemonic, passphrase)?)
            }
            None => match &records.hd_seed {
                Some(seed) => Some(stored_seed_wallet(db, seed)?),
                None => None,
            },
        };
        // A secret stored for another address would sign for the wrong key
        for (hash, secret) in &records.secrets {
            if let Some(entry) = self.keystore.get_key(hash) {
                if secret.public_key() != entry.public {
                    return Err(WalletError::Storage(format!(
                        "the encrypted private key for {} does not match its public key",
                        hex::encode(hash.as_bytes())
                    )));
                }
            }
        }

        // Wallets from older builds move to Argon2id and authenticated records
        if !master.aead {
            match migrate_legacy(db, passphrase, &master.key, &records) {
                Ok(()) => {
                    master.aead = true;
                    info!("Wallet encryption upgraded to Argon2id and XChaCha20-Poly1305");
                }
                Err(e) => warn!(
                    "Wallet encryption not upgraded, still readable as before: {}",
                    e
                ),
            }
        }
        // Keep the decrypted master key in memory so new keys can be stored encrypted
        *master_slot = Some(master);
        drop(master_slot);
        let OpenedRecords {
            mnemonic,
            mnemonic_passphrase,
            hd_seed,
            secrets,
        } = records;
        drop((mnemonic, mnemonic_passphrase, hd_seed));

        if let Some(hd) = hd_wallet {
            self.keystore.set_hd_wallet(hd);
            // Wallets encrypted before the ids were stored, or stored with an
            // older chain id, get them on unlock
            if let Some(ids) = self.keystore.hd_public_ids() {
                if db.load_hd_public_ids()? != Some(ids) {
                    db.store_hd_public_ids(&ids)?;
                }
            }
        }
        for (hash, secret) in secrets {
            self.keystore.restore_secret(&hash, secret);
        }

        // HD keys stored without their secret by older builds: derive them again
        let healed = self.keystore.restore_missing_hd_secrets();
        if !healed.is_empty() {
            info!(
                "Re-derived {} HD private keys that had no stored secret",
                healed.len()
            );
            if let Err(e) = self.persist_keys(&healed) {
                warn!("Failed to store re-derived private keys: {}", e);
            }
        }

        // As Divi Core's walletpassphrase: top the keypool up while the seed is
        // here, so getnewaddress keeps working after the wallet is locked again
        match self.keystore.top_up_keypool(None) {
            Ok(added) if !added.is_empty() => {
                if let Err(e) = self.persist_keys(&added) {
                    warn!("Failed to store keypool keys: {}", e);
                }
            }
            Ok(_) => {}
            Err(e) => debug!("Keypool not topped up on unlock: {}", e),
        }

        // Set unlock expiration time
        let expiration = if timeout_secs > 0 {
            Some(Instant::now() + std::time::Duration::from_secs(timeout_secs as u64))
        } else {
            None // Unlimited
        };
        *self.unlock.write() = UnlockState {
            until: expiration,
            staking_only,
            revert_to_staking: was_staking_only && expiration.is_some(),
        };

        *self.locked.write() = false;
        info!(
            "Wallet unlocked{} for {} seconds",
            if staking_only {
                " for staking only"
            } else {
                ""
            },
            timeout_secs
        );
        Ok(())
    }

    /// Check if wallet is locked
    pub fn is_locked(&self) -> bool {
        // Check if explicitly locked
        if *self.locked.read() {
            return true;
        }

        // Check if unlock has expired
        if self.is_auto_lock_expired() {
            let reverted = {
                let mut state = self.unlock.write();
                let expired = state.until.is_some_and(|t| Instant::now() >= t);
                if !expired {
                    None // another caller already handled it
                } else if state.revert_to_staking {
                    *state = UnlockState {
                        staking_only: true,
                        ..UnlockState::default()
                    };
                    Some(true)
                } else {
                    Some(false)
                }
            };
            match reverted {
                Some(true) => info!("Wallet unlock timed out; unlocked for staking only again"),
                Some(false) => {
                    // Auto-lock on timeout
                    self.lock();
                    return true;
                }
                None => {}
            }
        }

        *self.locked.read()
    }

    /// Apply timed unlocks when they run out, not only at the next call that
    /// checks: a thread looks twice a second and locks the wallet (dropping its
    /// secrets) once the timeout has passed. It holds a weak reference and ends
    /// with the wallet.
    pub fn start_auto_lock(wallet: &Arc<WalletDb>) {
        let weak = Arc::downgrade(wallet);
        let spawned = std::thread::Builder::new()
            .name("wallet-autolock".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                match weak.upgrade() {
                    Some(wallet) => {
                        if wallet.is_auto_lock_expired() {
                            wallet.is_locked();
                        }
                    }
                    None => break,
                }
            });
        if let Err(e) = spawned {
            error!("Could not start the wallet auto-lock thread: {}", e);
        }
    }

    /// Check if the auto-lock timeout has expired
    pub fn is_auto_lock_expired(&self) -> bool {
        if let Some(unlock_until) = self.unlock.read().until {
            Instant::now() >= unlock_until
        } else {
            false
        }
    }

    /// Unlocked for staking only (`walletpassphrase … true`): the staker can sign,
    /// sends and key exports are refused
    pub fn is_unlocked_for_staking_only(&self) -> bool {
        !self.is_locked() && self.unlock.read().staking_only
    }

    /// Unlocked for everything (Divi Core `IsFullyUnlocked`); always true for an
    /// unencrypted wallet
    pub fn is_fully_unlocked(&self) -> bool {
        !self.is_locked() && !self.unlock.read().staking_only
    }

    /// Check if wallet is encrypted
    pub fn is_encrypted(&self) -> bool {
        *self.encrypted.read()
    }

    /// Encryption state as reported by `getwalletinfo`:
    /// "unencrypted", "unlocked-for-staking", "locked" or "unlocked".
    pub fn encryption_status(&self) -> &'static str {
        if !self.is_encrypted() {
            "unencrypted"
        } else if self.is_unlocked_for_staking_only() {
            "unlocked-for-staking"
        } else if self.is_locked() {
            "locked"
        } else {
            "unlocked"
        }
    }

    /// Unix time at which the wallet re-locks; 0 when locked, unencrypted, or unlocked
    /// without a timeout.
    pub fn unlocked_until(&self) -> u64 {
        if !self.is_encrypted() || self.is_locked() {
            return 0;
        }
        match self.unlock.read().until {
            Some(t) => {
                let remaining = t.saturating_duration_since(Instant::now()).as_secs();
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    + remaining
            }
            None => 0,
        }
    }

    /// Encrypt the wallet with `passphrase`.
    ///
    /// A random 256-bit master key is generated and sealed under a key derived from
    /// the passphrase (Argon2id, random salt). The mnemonic and every private key
    /// are re-written encrypted under the master key (XChaCha20-Poly1305), the plaintext
    /// copies are deleted and compacted away, and the wallet is left locked.
    pub fn encrypt_wallet(&self, passphrase: &str) -> Result<(), WalletError> {
        use rand::RngCore;

        let mut encrypted = self.encrypted.write();
        if *encrypted {
            return Err(WalletError::AlreadyEncrypted);
        }
        if passphrase.is_empty() {
            return Err(WalletError::InvalidPassphrase);
        }
        let db = self.db.as_ref().ok_or_else(|| {
            WalletError::Storage("Cannot encrypt a wallet without a database".to_string())
        })?;

        let mut salt = vec![0u8; 16];
        let mut master_key = Zeroizing::new(vec![0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut master_key);

        let params = KdfParams::DEFAULT;
        let sealed_master = at_rest::seal_master_key(&master_key, passphrase, &salt, &params)?;
        let master = MasterKey {
            key: master_key,
            aead: true,
        };

        // Fill the keypool while the seed is still in the clear: the pool keys go
        // into the batch below, and a locked wallet hands out only pool keys
        if let Err(e) = self.keystore.top_up_keypool(None) {
            debug!("Keypool not topped up before encryption: {}", e);
        }

        // One atomic batch: either the wallet becomes encrypted or nothing changes.
        let mut batch = db.create_batch();
        for (hash, mut entry) in self.keystore.get_all_keys_with_hashes() {
            let secret = entry.secret.take();
            batch.put_cf(
                db.cf_keys(),
                hash.as_bytes(),
                crate::persistence::serialize_key_entry(&entry),
            );
            if let Some(secret) = secret {
                let mut suffixed = hash.as_bytes().to_vec();
                suffixed.push(crate::persistence::ENCRYPTED_SECRET_SUFFIX);
                let blob = master.seal_record(&suffixed, secret.as_bytes());
                batch.put_cf(db.cf_keys(), &suffixed, blob);
            }
        }
        if let Some(mnemonic) = self.keystore.mnemonic() {
            let mnemonic = Zeroizing::new(mnemonic);
            batch.put_cf(
                db.cf_metadata(),
                KEY_ENCRYPTED_MNEMONIC,
                master.seal_record(KEY_ENCRYPTED_MNEMONIC, mnemonic.as_bytes()),
            );
            batch.delete_cf(db.cf_metadata(), b"mnemonic");
        }
        if let Some(seed) = self.keystore.hd_seed() {
            batch.put_cf(
                db.cf_metadata(),
                crate::persistence::KEY_ENCRYPTED_HD_SEED,
                master.seal_record(crate::persistence::KEY_ENCRYPTED_HD_SEED, &seed),
            );
            batch.delete_cf(db.cf_metadata(), crate::persistence::KEY_HD_SEED);
        }
        if let Some(passphrase) = self.keystore.mnemonic_passphrase() {
            let passphrase = Zeroizing::new(passphrase);
            batch.put_cf(
                db.cf_metadata(),
                crate::persistence::KEY_ENCRYPTED_MNEMONIC_PASSPHRASE,
                master.seal_record(
                    crate::persistence::KEY_ENCRYPTED_MNEMONIC_PASSPHRASE,
                    passphrase.as_bytes(),
                ),
            );
            batch.delete_cf(
                db.cf_metadata(),
                crate::persistence::KEY_MNEMONIC_PASSPHRASE,
            );
        }
        let (receiving, change) = self.keystore.get_indices();
        batch.put_cf(
            db.cf_metadata(),
            b"receiving_index",
            receiving.to_le_bytes(),
        );
        batch.put_cf(db.cf_metadata(), b"change_index", change.to_le_bytes());
        // The seed is about to be locked away; keep its public ids readable
        if let Some(ids) = self.keystore.hd_public_ids() {
            batch.put_cf(
                db.cf_metadata(),
                crate::persistence::KEY_HD_PUBLIC_IDS,
                crate::persistence::encode_hd_public_ids(&ids),
            );
        }
        batch.put_cf(db.cf_metadata(), KEY_KDF_PARAMS, params.encode());
        batch.put_cf(db.cf_metadata(), KEY_ENCRYPTION_SALT, &salt);
        batch.put_cf(db.cf_metadata(), KEY_ENCRYPTED_MASTER_KEY, &sealed_master);
        batch.put_cf(db.cf_metadata(), b"encrypted", [1u8]);
        db.write_batch(batch)?;
        db.flush()?;
        // Overwritten plaintext can survive in old SST files until compaction
        db.compact_secret_cfs();

        *encrypted = true;
        drop(encrypted);
        // Every secret is in the batch above; lock() has nothing left to store
        self.keystore.strip_secrets();
        self.lock();
        info!("Wallet encrypted; it is now locked");
        Ok(())
    }

    /// Change the wallet passphrase. Does not require the wallet to be unlocked.
    pub fn change_passphrase(&self, old_pass: &str, new_pass: &str) -> Result<(), WalletError> {
        if !*self.encrypted.read() {
            return Err(WalletError::WalletNotEncrypted);
        }
        if old_pass.is_empty() || new_pass.is_empty() {
            return Err(WalletError::InvalidPassphrase);
        }
        let db = self.db.as_ref().ok_or_else(|| {
            WalletError::Storage("Cannot change passphrase without database".to_string())
        })?;

        let mut master_slot = self.decrypted_master_key.write();
        let master = open_master(db, old_pass)?;
        if master.aead {
            let mut batch = db.create_batch();
            put_sealed_master(&mut batch, db, &master.key, new_pass)?;
            db.write_batch_sync(batch)?;
        } else {
            // An older wallet: every record moves to the new format with the new
            // passphrase, so the old one can open nothing afterwards
            let records = decrypt_records(db, &master)?;
            migrate_legacy(db, new_pass, &master.key, &records)?;
            if let Some(unlocked) = master_slot.as_mut() {
                unlocked.aead = true;
            }
        }
        drop(master_slot);
        // The new salt and sealed master key went in as one synced write: a stop
        // here leaves the wallet opening with the new passphrase
        stop_point!("passphrase salt written");

        info!("Wallet passphrase changed successfully");
        Ok(())
    }

    /// Import a private key into the wallet
    ///
    /// Returns the address for the imported key.
    pub fn import_key(
        &self,
        secret: divi_crypto::keys::SecretKey,
        label: Option<String>,
    ) -> Address {
        self.import_key_with_compression(secret, true, label)
    }

    /// Import a private key in its compressed or uncompressed form (the WIF's flag)
    pub fn import_key_with_compression(
        &self,
        secret: divi_crypto::keys::SecretKey,
        compressed: bool,
        label: Option<String>,
    ) -> Address {
        let address = self
            .keystore
            .import_key_with_compression(secret, compressed, label);
        self.dirty.write().keys = true;
        if let Err(e) = self.persist_keys(&[address.hash]) {
            // Still held in memory; save() and lock() retry the write
            error!(
                "Failed to store imported key {}: {}",
                WalletAddress(&address.to_string()),
                e
            );
        }
        info!(
            "Imported key for address {}",
            WalletAddress(&address.to_string())
        );
        address
    }

    /// Get mnemonic (if available and fully unlocked)
    pub fn mnemonic(&self) -> Option<String> {
        // is_fully_unlocked() applies an expired timeout first
        if !self.is_fully_unlocked() {
            return None;
        }
        self.keystore.mnemonic()
    }

    /// The seed of a wallet made from a seed (no words); None while locked
    pub fn hd_seed(&self) -> Option<Zeroizing<Vec<u8>>> {
        if *self.locked.read() {
            return None;
        }
        self.keystore.hd_seed()
    }

    /// Path of the account the wallet's HD keys derive from, m/44'/coin'/0'
    pub fn hd_account_path(&self) -> Option<String> {
        self.keystore.hd_account_path()
    }

    /// BIP39 passphrase of the HD seed (if one was given and unlocked)
    pub fn mnemonic_passphrase(&self) -> Option<String> {
        if *self.locked.read() {
            return None;
        }
        self.keystore.mnemonic_passphrase()
    }

    /// Get key entry by address
    pub fn get_key_by_address(&self, address: &Address) -> Option<crate::keystore::KeyEntry> {
        self.keystore.get_key_by_address(address)
    }

    /// Get HD chain ID (SHA256 hash of master pubkey)
    pub fn get_hd_chain_id(&self) -> Option<String> {
        self.keystore.get_hd_chain_id()
    }

    /// Get the current keypool size (number of pre-generated unused keys)
    pub fn keypool_size(&self) -> u32 {
        self.keystore.keypool_size()
    }

    /// How many keys of each chain the keypool is filled to (-keypool)
    pub fn keypool_target(&self) -> u32 {
        self.keystore.keypool_target()
    }

    /// Get the timestamp of the oldest key in the keypool
    pub fn keypool_oldest(&self) -> u64 {
        self.keystore.keypool_oldest()
    }

    /// Refill the keypool by pre-generating keys up to the target size
    ///
    /// Returns the number of keys generated
    pub fn refill_keypool(&self, new_size: Option<u32>) -> Result<u32, WalletError> {
        let _locked = self.locked.read();
        let added = self.keystore.top_up_keypool(new_size)?;
        if !added.is_empty() {
            self.dirty.write().keys = true;
            self.persist_keys(&added)?;
        }
        Ok(added.len() as u32)
    }

    /// Scan a block for wallet transactions
    pub fn scan_block(
        &self,
        block_hash: Hash256,
        height: u32,
        block_time: u32,
        transactions: &[divi_primitives::transaction::Transaction],
    ) {
        for tx in transactions {
            self.scan_transaction(tx, Some(block_hash), Some(height), Some(block_time));
        }
    }

    /// Scan a transaction for wallet relevance
    pub fn scan_transaction(
        &self,
        tx: &divi_primitives::transaction::Transaction,
        block_hash: Option<Hash256>,
        height: Option<u32>,
        block_time: Option<u32>,
    ) {
        let txid = tx.txid();
        let is_coinbase = tx.is_coinbase();
        let is_coinstake = tx.is_coinstake();

        let mut received = Amount::ZERO;
        let mut sent = Amount::ZERO;
        let mut is_relevant = false;

        // Check outputs for coins we receive
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.is_empty() {
                continue;
            }

            if self.is_mine_script(&output.script_pubkey) {
                is_relevant = true;
                received += output.value;

                let address = self.output_address(&output.script_pubkey);

                let mut utxo = WalletUtxo::new(
                    txid,
                    vout as u32,
                    output.value,
                    output.script_pubkey.clone(),
                    address.clone(),
                );
                utxo.height = height;
                utxo.is_coinbase = is_coinbase;
                utxo.is_coinstake = is_coinstake;

                // Scanning a block again (rescan, catch-up overlap) must not
                // bring back a coin already seen spent
                if !self.spent.read().contains(&utxo.outpoint()) {
                    self.add_utxo(utxo);
                }
                if !address.is_empty() {
                    self.mark_address_used(&address);
                }

                trace!(
                    "Received {} to {} in tx {}",
                    WalletAmount(output.value.as_sat()),
                    WalletAddress(&address),
                    WalletTxid::of(txid)
                );
            }
        }

        // Check inputs for coins we spend
        for input in &tx.vin {
            if input.prevout.is_null() {
                continue; // Coinbase/coinstake marker
            }

            let outpoint = OutPoint::new(input.prevout.txid, input.prevout.vout);
            if let Some(utxo) = self.spend_utxo_at_height(&outpoint, height) {
                is_relevant = true;
                sent += utxo.value;
                trace!(
                    "Spent {} from {}",
                    WalletAmount(utxo.value.as_sat()),
                    OwnOutpoint(outpoint.txid, outpoint.vout)
                );
            } else if let Some(value) = height.and_then(|h| {
                // This block was scanned before and already spent the coin:
                // count it again so the history entry comes out the same
                self.spent_utxo_data
                    .read()
                    .get(&outpoint)
                    .filter(|(_, spent_height)| *spent_height == h)
                    .map(|(u, _)| u.value)
            }) {
                is_relevant = true;
                sent += value;
            }
        }

        // Record transaction if relevant
        if is_relevant {
            let net_amount = received.as_sat() - sent.as_sat();
            let category = if is_coinbase {
                "coinbase"
            } else if is_coinstake {
                "stake"
            } else if net_amount > 0 {
                "receive"
            } else {
                "send"
            };

            // Calculate fee for sent transactions
            // Fee = total inputs from our wallet - total outputs of the transaction
            // This only makes sense when we're the sender (sent > 0)
            let fee = if sent > Amount::ZERO && !is_coinbase && !is_coinstake {
                // Sum all outputs (not just ours)
                let total_outputs: Amount = tx
                    .vout
                    .iter()
                    .filter(|o| !o.is_empty())
                    .map(|o| o.value)
                    .fold(Amount::ZERO, |a, b| a + b);
                // Fee = inputs we spent - all outputs
                // Note: This is accurate when we funded the entire transaction
                // For partially-funded transactions, the fee attribution is approximate
                if sent > total_outputs {
                    Some(sent - total_outputs)
                } else {
                    None
                }
            } else {
                None
            };

            // The block time, so a scan of old blocks keeps each transaction's
            // own time, but never later than now: Divi Core's time of a wallet
            // transaction is at most when the wallet received it (nTimeSmart,
            // wallet.cpp:1052-1086), so one in a block dated ahead of the clock
            // counts from its arrival
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let timestamp = block_time.map_or(now, |t| u64::from(t).min(now));

            let wallet_tx = WalletTx {
                txid,
                block_hash,
                block_height: height,
                timestamp,
                amount: net_amount,
                fee,
                category: category.to_string(),
                confirmations: 0, // Will be updated on query
            };

            self.add_transaction(wallet_tx);
            debug!(
                "Wallet tx {} {} {}",
                category,
                WalletTxid::of(txid),
                WalletAmount(net_amount.abs())
            );
            self.tx_changed(&txid);
        }

        if block_hash.is_some() {
            self.drop_confirmed_from_mempool(tx);
        }
    }

    /// Label for an output we own: its address as Divi Core's
    /// ExtractDestination gives it (a P2PK output shows its key's P2PKH
    /// address, a bare multisig none), or "vault:<manager>"
    fn output_address(&self, script_pubkey: &Script) -> String {
        if let Some(hash_bytes) = script_pubkey.extract_p2pkh_hash() {
            let hash = divi_primitives::hash::Hash160::from_bytes(hash_bytes);
            Address::from_pubkey_hash(hash, self.network).to_string()
        } else if let Some(hash_bytes) = script_pubkey.extract_p2sh_hash() {
            Address::p2sh(Hash160::from_bytes(hash_bytes), self.network).to_string()
        } else if divi_script::standard::is_p2pk(script_pubkey.as_bytes()) {
            let pubkey_len = script_pubkey.as_bytes()[0] as usize;
            let hash = divi_crypto::hash160(&script_pubkey.as_bytes()[1..1 + pubkey_len]);
            Address::from_pubkey_hash(hash, self.network).to_string()
        } else if divi_script::standard::is_multisig(script_pubkey.as_bytes()).is_some() {
            String::new()
        } else if let Some(vault) = divi_script::StakingVaultScript::from_script(script_pubkey) {
            // For vault UTXOs, use vault: prefix with manager address
            let manager_hash = Hash160::from_bytes(vault.vault_pubkey_hash);
            format!(
                "vault:{}",
                Address::from_pubkey_hash(manager_hash, self.network)
            )
        } else {
            "unknown".to_string()
        }
    }

    /// Track a transaction that has entered the mempool.
    ///
    /// Returns true if it concerns this wallet. The raw transaction is stored
    /// (synced) before this returns, so a send is on disk before the RPC that
    /// made it answers; the confirmed state is left to the block scan, which
    /// records the transaction once it confirms.
    pub fn add_mempool_tx(&self, tx: &divi_primitives::transaction::Transaction) -> bool {
        let added = self.track_mempool_tx(tx, None);
        if added {
            self.tx_changed(&tx.txid());
        }
        added
    }

    /// Tell the listener about every later change of a wallet transaction
    pub fn set_tx_listener(&self, listener: TxListener) {
        *self.tx_listener.write() = Some(listener);
    }

    /// A send was signed and is handed to the node: Divi Core's
    /// CommitTransaction adds it to the wallet before the mempool sees it
    /// (wallet.cpp:1878), one notification of its own
    pub fn note_committed(&self, txid: &Hash256) {
        self.tx_changed(txid);
    }

    fn tx_changed(&self, txid: &Hash256) {
        let listener = self.tx_listener.read().clone();
        if let Some(listener) = listener {
            listener(txid);
        }
    }

    /// Add a transaction to the mempool overlay. `restored_time` is set when it
    /// comes from disk: it keeps its first-seen time and is not stored again.
    fn track_mempool_tx(
        &self,
        tx: &divi_primitives::transaction::Transaction,
        restored_time: Option<u64>,
    ) -> bool {
        if tx.is_coinbase() || tx.is_coinstake() {
            return false;
        }
        let txid = tx.txid();
        if matches!(self.transactions.read().get(&txid), Some(t) if t.block_height.is_some()) {
            return false;
        }

        // Ownership checks take keystore/vault locks, so do them before
        // locking the overlay
        let mut outputs = Vec::new();
        let mut received = Amount::ZERO;
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.is_empty() || !self.is_mine_script(&output.script_pubkey) {
                continue;
            }
            received += output.value;
            outputs.push(WalletUtxo::new(
                txid,
                vout as u32,
                output.value,
                output.script_pubkey.clone(),
                self.output_address(&output.script_pubkey),
            ));
        }

        let mut overlay = self.mempool_txs.write();
        if overlay.contains_key(&txid) {
            return false;
        }

        // Inputs we own: confirmed coins, or outputs of our other mempool txs
        let mut inputs = Vec::new();
        let mut spends = Vec::new();
        let mut sent = Amount::ZERO;
        let mut spends_vault = false;
        {
            let utxos = self.utxos.read();
            for input in &tx.vin {
                if input.prevout.is_null() {
                    continue;
                }
                let outpoint = OutPoint::new(input.prevout.txid, input.prevout.vout);
                inputs.push(outpoint);
                let coin = utxos.get(&outpoint).cloned().or_else(|| {
                    overlay
                        .get(&outpoint.txid)
                        .and_then(|e| e.outputs.iter().find(|u| u.vout == outpoint.vout).cloned())
                });
                if let Some(coin) = coin {
                    spends.push(outpoint);
                    sent += coin.value;
                    spends_vault |= divi_script::is_staking_vault_script(&coin.script_pubkey);
                }
            }
        }

        if spends.is_empty() && outputs.is_empty() {
            return false;
        }

        let net_amount = received.as_sat() - sent.as_sat();
        let fee = if sent > Amount::ZERO {
            let total_outputs = tx
                .vout
                .iter()
                .filter(|o| !o.is_empty())
                .map(|o| o.value)
                .fold(Amount::ZERO, |a, b| a + b);
            (sent > total_outputs).then(|| sent - total_outputs)
        } else {
            None
        };
        let category = if net_amount > 0 { "receive" } else { "send" };
        let record = WalletTx {
            txid,
            block_hash: None,
            block_height: None,
            timestamp: restored_time.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            }),
            amount: net_amount,
            fee,
            category: category.to_string(),
            confirmations: 0,
        };

        // Core trusts an unconfirmed transaction whose every input is a
        // spendable coin of ours (AvailableUtxoCalculator.cpp:33-43); a vault
        // coin is not spendable in that sense
        let trusted = spends.len() == inputs.len() && !spends_vault;
        // No log line: its time and txid beside the relay lines would pick
        // out the wallet's own transactions in debug.log
        let timestamp = record.timestamp;
        overlay.insert(
            txid,
            MempoolWalletTx {
                trusted,
                inputs,
                spends,
                outputs,
                record,
                tx: tx.clone(),
            },
        );
        drop(overlay);

        if restored_time.is_none() {
            if let Some(db) = &self.db {
                if let Err(e) =
                    db.store_unconfirmed_tx(&txid, timestamp, &divi_primitives::serialize(tx))
                {
                    tracing::error!(
                        "Failed to store unconfirmed wallet tx {}: {}",
                        WalletTxid::of(txid),
                        e
                    );
                }
            }
        }
        self.note_first_seen(&txid);
        self.reattach(&txid);
        true
    }

    /// Give `txid` the next position if the wallet has not seen it before
    fn note_first_seen(&self, txid: &Hash256) {
        let position = {
            let mut order = self.tx_order.write();
            if order.0.contains_key(txid) {
                return;
            }
            let position = order.1;
            order.0.insert(*txid, position);
            order.1 += 1;
            position
        };
        if let Some(db) = &self.db {
            if let Err(e) = db.store_tx_order(txid, position) {
                tracing::warn!(
                    "Failed to store the position of {}: {}",
                    WalletTxid::of(txid),
                    e
                );
            }
        }
    }

    /// The position at which the wallet first saw `txid` (None for a
    /// transaction recorded before positions were kept)
    pub fn order_position(&self, txid: &Hash256) -> Option<u64> {
        self.tx_order.read().0.get(txid).copied()
    }

    /// Keep `notes` with a transaction the wallet sent (Divi Core's mapValue;
    /// comment, to, FromAccount). Stored at once, synced.
    pub fn set_tx_notes(&self, txid: &Hash256, notes: BTreeMap<String, String>) {
        if notes.is_empty() {
            return;
        }
        if let Some(db) = &self.db {
            match serde_json::to_vec(&notes) {
                Ok(raw) => {
                    if let Err(e) = db.store_tx_notes(txid, &raw) {
                        tracing::error!(
                            "Failed to store the notes of {}: {}",
                            WalletTxid::of(txid),
                            e
                        );
                    }
                }
                Err(e) => tracing::error!(
                    "Failed to encode the notes of {}: {}",
                    WalletTxid::of(txid),
                    e
                ),
            }
        }
        self.tx_notes.write().insert(*txid, notes);
    }

    /// The notes kept with `txid`, in key order
    pub fn tx_notes(&self, txid: &Hash256) -> BTreeMap<String, String> {
        self.tx_notes.read().get(txid).cloned().unwrap_or_default()
    }

    /// Delete stored unconfirmed transactions that left the overlay
    fn forget_stored_unconfirmed(&self, txids: &[Hash256]) {
        if let Some(db) = &self.db {
            for txid in txids {
                if let Err(e) = db.remove_unconfirmed_tx(txid) {
                    tracing::warn!(
                        "Failed to forget unconfirmed wallet tx {}: {}",
                        WalletTxid::of(txid),
                        e
                    );
                }
            }
        }
    }

    /// Stop tracking a transaction that has left the mempool.
    ///
    /// The wallet mirrors the mempool, so only this entry is dropped; any
    /// child still in the mempool gets its own removal notice.
    pub fn remove_mempool_tx(&self, txid: &Hash256) -> bool {
        let removed = self.mempool_txs.write().remove(txid);
        if let Some(entry) = &removed {
            self.forget_stored_unconfirmed(&[*txid]);
            // Evicted unconfirmed: kept, at depth -1, as Divi Core keeps it
            self.detach(*txid, entry.record.timestamp, Some(entry.tx.clone()));
        }
        removed.is_some()
    }

    /// Number of wallet transactions currently tracked in the mempool
    pub fn mempool_tx_count(&self) -> usize {
        self.mempool_txs.read().len()
    }

    /// A transaction is now in a block: drop its mempool entry, and drop any
    /// other entry that double-spends one of its inputs, together with that
    /// entry's descendants (the node's mempool does not evict conflicts).
    fn drop_confirmed_from_mempool(&self, tx: &divi_primitives::transaction::Transaction) {
        let txid = tx.txid();
        let mut overlay = self.mempool_txs.write();
        if overlay.is_empty() {
            return;
        }
        let mut forgotten = Vec::new();
        if overlay.remove(&txid).is_some() {
            forgotten.push(txid);
        }

        let confirmed_inputs: HashSet<OutPoint> = tx
            .vin
            .iter()
            .filter(|i| !i.prevout.is_null())
            .map(|i| OutPoint::new(i.prevout.txid, i.prevout.vout))
            .collect();
        let mut doomed: Vec<Hash256> = overlay
            .iter()
            .filter(|(_, e)| e.inputs.iter().any(|op| confirmed_inputs.contains(op)))
            .map(|(id, _)| *id)
            .collect();
        let mut conflicted = Vec::new();
        while let Some(id) = doomed.pop() {
            if let Some(entry) = overlay.remove(&id) {
                forgotten.push(id);
                conflicted.push((id, entry.record.timestamp, entry.tx));
                info!(
                    "Dropped mempool wallet tx {} (conflicts with {})",
                    WalletTxid::of(id),
                    WalletTxid::of(txid)
                );
                doomed.extend(
                    overlay
                        .iter()
                        .filter(|(_, e)| e.inputs.iter().any(|op| op.txid == id))
                        .map(|(child, _)| *child),
                );
            }
        }
        drop(overlay);
        self.forget_stored_unconfirmed(&forgotten);
        for (id, timestamp, tx) in conflicted {
            self.detach(id, timestamp, Some(tx));
        }
    }

    /// Update confirmation counts for all transactions
    pub fn update_confirmations(&self, current_height: u32) {
        let mut txs = self.transactions.write();
        for tx in txs.values_mut() {
            tx.confirmations = match tx.block_height {
                Some(h) if current_height >= h => current_height - h + 1,
                _ => 0,
            };
        }
    }

    /// Handle a reorg: undo everything recorded from blocks above the fork
    /// point. The next [`sync_to_tip`](Self::sync_to_tip) scans the new
    /// branch from there.
    pub fn handle_reorg(&self, fork_height: u32) {
        info!("Handling reorg at fork height {}", fork_height);
        let _scan = self.scan_lock.lock();
        self.rollback_heights(fork_height.saturating_add(1), u32::MAX);
        let mut last = self.last_scan_height.write();
        if *last > fork_height {
            *last = fork_height;
        }
    }

    /// Undo what blocks at heights `start..=stop` recorded: their outputs and
    /// history entries go, and coins they spent come back unless those coins
    /// were themselves created in the range.
    fn rollback_heights(&self, start: u32, stop: u32) {
        let in_range = |h: u32| h >= start && h <= stop;
        let mut pending = self.pending_deletes.write();

        let removed_utxos = {
            let mut utxos = self.utxos.write();
            let gone: Vec<OutPoint> = utxos
                .iter()
                .filter(|(_, u)| u.height.is_some_and(in_range))
                .map(|(op, _)| *op)
                .collect();
            for op in &gone {
                utxos.remove(op);
                pending.utxos.insert(*op);
            }
            gone.len()
        };

        let mut disconnected = Vec::new();
        let removed_txs = {
            let mut txs = self.transactions.write();
            let gone: Vec<Hash256> = txs
                .iter()
                .filter(|(_, tx)| tx.block_height.is_some_and(in_range))
                .map(|(txid, _)| *txid)
                .collect();
            for txid in &gone {
                if let Some(record) = txs.remove(txid) {
                    disconnected.push((*txid, record.timestamp));
                }
                pending.transactions.insert(*txid);
            }
            gone.len()
        };

        self.scanned_hashes
            .write()
            .retain(|height, _| !in_range(*height));

        let mut restored = 0usize;
        {
            let mut spent_data = self.spent_utxo_data.write();
            let mut spent_set = self.spent.write();
            let mut utxos = self.utxos.write();

            let undone: Vec<(OutPoint, WalletUtxo)> = spent_data
                .iter()
                .filter(|(_, (_, spent_height))| in_range(*spent_height))
                .map(|(op, (utxo, _))| (*op, utxo.clone()))
                .collect();

            for (outpoint, utxo) in undone {
                spent_data.remove(&outpoint);
                spent_set.remove(&outpoint);
                pending.spent.insert(outpoint);
                if let Some(ref db) = self.db {
                    if let Err(e) = db.remove_spent_utxo_data(&outpoint) {
                        debug!("Failed to remove spent_utxo_data from disk: {}", e);
                    }
                }
                if utxo.height.is_some_and(in_range) {
                    // Created and spent in the range: the coin goes with its block
                    pending.utxos.insert(outpoint);
                    continue;
                }
                info!(
                    "Restoring UTXO {} ({}) spent at rolled-back height",
                    OwnOutpoint(outpoint.txid, outpoint.vout),
                    WalletAmount(utxo.value.as_sat())
                );
                pending.utxos.remove(&outpoint);
                utxos.insert(outpoint, utxo);
                restored += 1;
            }
        }

        info!(
            "Rolled back heights {}..={}: removed {} UTXOs and {} transactions, restored {} spent UTXOs",
            start, stop, removed_utxos, removed_txs, restored
        );

        {
            let mut dirty = self.dirty.write();
            dirty.utxos = true;
            dirty.transactions = true;
            dirty.spent = true;
        }
        drop(pending);
        // Kept, at depth -1, until a block or the mempool has them again;
        // Divi Core updates each one as its block is disconnected
        for (txid, timestamp) in disconnected {
            self.detach(txid, timestamp, None);
            self.tx_changed(&txid);
        }
    }

    /// Scan the active chain's blocks above the last scanned height, in
    /// height order, up to `tip_height`, and advance the scan height.
    ///
    /// `hash_at` and `get_block` return the active chain's block hash and
    /// block at a height. Every path that feeds blocks to the wallet goes
    /// through here (or through [`rescan`](Self::rescan)) under one lock, so a
    /// block is never skipped (e.g. the middle blocks of a reorg) and a spend
    /// is never scanned before the coin it spends. If the blocks last scanned
    /// are no longer in the active chain, what they recorded is rolled back
    /// first. The same holds when the chain is lower than the wallet's scan
    /// height (a rebuilt or reindexed chain): heights above the tip are rolled
    /// back and scanned again as the chain grows, as Divi Core restarts its
    /// wallet scan from the fork with the active chain. Returns the heights
    /// whose block could not be read; they are skipped.
    pub fn sync_to_tip<H, F>(&self, tip_height: u32, hash_at: H, mut get_block: F) -> Vec<u32>
    where
        H: Fn(u32) -> Option<Hash256>,
        F: FnMut(u32) -> Option<(Hash256, divi_primitives::block::Block)>,
    {
        let _scan = self.scan_lock.lock();

        let last = self.last_scan_height();
        let top = last.min(tip_height);
        let fork = self
            .find_fork(top, &hash_at)
            .or_else(|| (top < last).then_some(top));
        if let Some(fork) = fork {
            info!(
                "Wallet scanned blocks above {} that left the active chain; rolling back",
                fork
            );
            self.rollback_heights(fork + 1, u32::MAX);
            self.set_last_scan_height(fork);
        }

        let mut missing = Vec::new();
        let from = self.last_scan_height().saturating_add(1);
        for height in from..=tip_height {
            match get_block(height) {
                Some((hash, block)) => self.scan_active_block(hash, height, &block),
                None => missing.push(height),
            }
            self.set_last_scan_height(height);
        }
        missing
    }

    /// Highest height below `last` whose scanned block is still active, if
    /// the block scanned at `last` is not. Heights without a remembered hash
    /// are taken as still active.
    fn find_fork<H: Fn(u32) -> Option<Hash256>>(&self, last: u32, hash_at: &H) -> Option<u32> {
        let hashes = self.scanned_hashes.read();
        let mut height = last;
        while height > 0 {
            match hashes.get(&height) {
                Some(scanned) if hash_at(height) != Some(*scanned) => height -= 1,
                _ => break,
            }
        }
        (height < last).then_some(height)
    }

    /// Scan a block of the active chain and remember its hash
    fn scan_active_block(&self, hash: Hash256, height: u32, block: &divi_primitives::block::Block) {
        self.scan_block(hash, height, block.header.time, &block.transactions);
        let mut hashes = self.scanned_hashes.write();
        hashes.insert(height, hash);
        while hashes.len() > SCANNED_HASHES_KEPT {
            hashes.pop_first();
        }
    }

    /// Rescan heights `start..=stop` of the active chain (`rescanblockchain`).
    ///
    /// A full rescan (from 0 to the tip) rebuilds the wallet from nothing. A
    /// partial one rolls back only what the range recorded and scans it again,
    /// so coins and history outside the range are kept. Returns the number of
    /// blocks scanned and the first height that could not be read, if any
    /// (the scan stops there and the wallet re-scans from it later).
    pub fn rescan<F>(
        &self,
        start: u32,
        stop: u32,
        tip_height: u32,
        mut get_block: F,
    ) -> (u32, Option<u32>)
    where
        F: FnMut(u32) -> Option<(Hash256, divi_primitives::block::Block)>,
    {
        let _scan = self.scan_lock.lock();
        let full = start == 0 && stop >= tip_height;
        if full {
            self.clear_transactions_and_utxos();
        } else {
            self.rollback_heights(start, stop);
        }

        // A coin marked spent without a recorded spending block (dropped as
        // missing from the chain, or evicted by the staker) hides its output
        // from every scan. A scan up to the tip sees the coin's spend if
        // there is one, so such marks are lifted for it; those whose output
        // the scan does not meet are put back afterwards.
        let lifted: Vec<OutPoint> = if !full && stop >= tip_height {
            let data = self.spent_utxo_data.read();
            let mut spent = self.spent.write();
            let lifted: Vec<OutPoint> = spent
                .iter()
                .filter(|op| !data.contains_key(op))
                .copied()
                .collect();
            for op in &lifted {
                spent.remove(op);
            }
            lifted
        } else {
            Vec::new()
        };

        let mut scanned = 0u32;
        let mut unreadable = None;
        for height in start..=stop {
            match get_block(height) {
                Some((hash, block)) => {
                    self.scan_active_block(hash, height, &block);
                    scanned += 1;
                }
                None => {
                    unreadable = Some(height);
                    break;
                }
            }
        }

        if !lifted.is_empty() {
            // Same lock order as rollback_heights
            let mut pending = self.pending_deletes.write();
            let data = self.spent_utxo_data.read();
            let mut spent = self.spent.write();
            let utxos = self.utxos.read();
            let mut found = 0usize;
            for op in lifted {
                if utxos.contains_key(&op) || data.contains_key(&op) {
                    // Seen again: held now, or spent at a known height
                    if !spent.contains(&op) {
                        pending.spent.insert(op);
                    }
                    found += 1;
                } else {
                    spent.insert(op);
                }
            }
            if found > 0 {
                info!(
                    "Rescan found {} coin(s) marked spent without a spending block",
                    found
                );
                let mut dirty = self.dirty.write();
                dirty.utxos = true;
                dirty.spent = true;
            }
        }

        let last = self.last_scan_height();
        match unreadable {
            // Blocks from here on were rolled back but not scanned again
            Some(h) => self.set_last_scan_height(last.min(h.saturating_sub(1))),
            None if full || (start <= last.saturating_add(1) && stop > last) => {
                self.set_last_scan_height(stop)
            }
            None => {}
        }
        (scanned, unreadable)
    }

    pub fn set_account(&self, address: &Address, account: &str) {
        let addr_str = address.to_string();
        let mut accounts = self.accounts.write();
        let mut address_accounts = self.address_accounts.write();

        if let Some(old_account) = address_accounts.get(&addr_str) {
            if let Some(addresses) = accounts.get_mut(old_account) {
                addresses.retain(|a| a != &addr_str);
            }
        }

        address_accounts.insert(addr_str.clone(), account.to_string());
        accounts
            .entry(account.to_string())
            .or_default()
            .push(addr_str);
        self.dirty.write().accounts = true;
    }

    /// Set the account (label) of `address` and store it before returning, so a
    /// label given with a new key survives a restart before the next block.
    pub fn set_label(&self, address: &Address, label: &str) -> Result<(), WalletError> {
        let old = self.get_account(address);
        self.set_account(address, label);
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()),
        };
        let mut batch = db.create_batch();
        {
            let accounts = self.accounts.read();
            for account in [old.as_str(), label] {
                let addresses = accounts.get(account).cloned().unwrap_or_default();
                let value = serde_json::to_string(&addresses).map_err(|e| {
                    WalletError::Storage(format!("Failed to serialize account: {}", e))
                })?;
                batch.put_cf(
                    db.cf_accounts(),
                    format!("acc_{}", account).as_bytes(),
                    value.as_bytes(),
                );
            }
        }
        batch.put_cf(
            db.cf_accounts(),
            format!("addr_{}", address).as_bytes(),
            label.as_bytes(),
        );
        db.write_batch_sync(batch)
    }

    /// The address book: every address with its name (Divi Core's
    /// mapAddressBook; addresses the wallet handed out or was told about)
    pub fn address_book(&self) -> Vec<(String, String)> {
        let mut book: Vec<(String, String)> = self
            .address_accounts
            .read()
            .iter()
            .map(|(a, n)| (a.clone(), n.clone()))
            .collect();
        book.sort();
        book
    }

    /// Whether `address` has an address-book entry (its name may be "")
    pub fn in_address_book(&self, address: &Address) -> bool {
        self.address_accounts
            .read()
            .contains_key(&address.to_string())
    }

    pub fn get_account(&self, address: &Address) -> String {
        let addr_str = address.to_string();
        self.address_accounts
            .read()
            .get(&addr_str)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_addresses_by_account(&self, account: &str) -> Vec<String> {
        self.accounts
            .read()
            .get(account)
            .cloned()
            .unwrap_or_default()
    }

    pub fn list_accounts(&self) -> HashMap<String, Vec<String>> {
        self.accounts.read().clone()
    }

    pub fn add_script(&self, script: Script) -> Result<(), WalletError> {
        let script_hash = divi_crypto::hash160(script.as_bytes());
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(script_hash.as_ref());
        let hash160 = Hash160::from_bytes(hash_bytes);

        self.scripts.write().insert(hash160, script.clone());

        if let Some(db) = &self.db {
            db.store_script(&hash160, &script)?;
        }

        Ok(())
    }

    pub fn get_script(&self, script_hash: &Hash160) -> Option<Script> {
        self.scripts.read().get(script_hash).cloned()
    }

    /// Set the relay fee rate the wallet's sends pay (-minrelaytxfee)
    pub fn set_relay_fee_per_kb(&self, per_kb: i64) {
        self.relay_fee_per_kb
            .store(per_kb, std::sync::atomic::Ordering::Relaxed);
    }

    /// Set the highest fee the wallet's sends may pay (-maxtxfee)
    pub fn set_max_tx_fee(&self, sat: i64) {
        self.max_tx_fee
            .store(sat, std::sync::atomic::Ordering::Relaxed);
    }

    /// Fee rate and limit of the wallet's sends
    pub fn fee_policy(&self) -> crate::send::FeePolicy {
        crate::send::FeePolicy {
            per_kb: self
                .relay_fee_per_kb
                .load(std::sync::atomic::Ordering::Relaxed),
            max_fee: Amount::from_sat(self.max_tx_fee.load(std::sync::atomic::Ordering::Relaxed)),
        }
    }

    /// Turn Divi Core's -vault on or off
    pub fn set_vault_mode(&self, on: bool) {
        self.vault_mode
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Let sends use unconfirmed outputs of our own transactions (Divi
    /// Core's -spendzeroconfchange, off by default)
    pub fn set_spend_zero_conf_change(&self, on: bool) {
        self.spend_zero_conf_change
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether vaults may be added or removed (Divi Core's -vault)
    pub fn vault_mode(&self) -> bool {
        self.vault_mode.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Store vault metadata
    pub fn store_vault(&self, metadata: VaultMetadata) {
        self.vaults
            .write()
            .insert(metadata.vault_script.clone(), metadata.clone());

        if let Some(ref db) = self.db {
            db.store_vault(&metadata.vault_script, &metadata).ok();
        }
    }

    /// Get vault metadata by script
    pub fn get_vault(&self, vault_script: &[u8]) -> Option<VaultMetadata> {
        self.vaults.read().get(vault_script).cloned()
    }

    /// Remove vault metadata. Outputs of the vault that the wallet no longer
    /// owns once it is unregistered (the manager side) leave the wallet.
    pub fn remove_vault(&self, vault_script: &[u8]) -> bool {
        let removed = self.vaults.write().remove(vault_script).is_some();
        if removed {
            self.prune_unowned_vault_utxos();
        }

        if removed {
            if let Some(ref db) = self.db {
                db.remove_vault(vault_script).ok();
            }
        }

        removed
    }

    /// Get all vaults
    pub fn get_all_vaults(&self) -> Vec<VaultMetadata> {
        self.vaults.read().values().cloned().collect()
    }

    /// Drop vault outputs that are no longer the wallet's (is_mine_script is
    /// false for them, e.g. after removevault on the manager). They are not
    /// spent, so they are deleted rather than moved to the spent set; a later
    /// addvault brings them back.
    fn prune_unowned_vault_utxos(&self) -> usize {
        // Ownership checks take keystore/vault locks, so do them before
        // locking the UTXO set or the overlay
        let is_vault = |u: &&WalletUtxo| divi_script::is_staking_vault_script(&u.script_pubkey);
        let mut scripts: Vec<Script> = self
            .utxos
            .read()
            .values()
            .filter(is_vault)
            .map(|u| u.script_pubkey.clone())
            .collect();
        scripts.extend(
            self.mempool_txs
                .read()
                .values()
                .flat_map(|e| e.outputs.iter())
                .filter(is_vault)
                .map(|u| u.script_pubkey.clone()),
        );
        scripts.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        scripts.dedup();
        let unowned: HashSet<Vec<u8>> = scripts
            .into_iter()
            .filter(|script| !self.is_mine_script(script))
            .map(|script| script.as_bytes().to_vec())
            .collect();
        if unowned.is_empty() {
            return 0;
        }

        let doomed: Vec<OutPoint> = {
            let mut utxos = self.utxos.write();
            let doomed: Vec<OutPoint> = utxos
                .values()
                .filter(|u| unowned.contains(u.script_pubkey.as_bytes()))
                .map(|u| u.outpoint())
                .collect();
            for outpoint in &doomed {
                utxos.remove(outpoint);
            }
            doomed
        };
        if let Some(ref db) = self.db {
            for outpoint in &doomed {
                if let Err(e) = db.remove_utxo(outpoint) {
                    debug!(
                        "Failed to delete vault UTXO {}: {}",
                        OwnOutpoint(outpoint.txid, outpoint.vout),
                        e
                    );
                }
            }
        }
        for entry in self.mempool_txs.write().values_mut() {
            entry
                .outputs
                .retain(|u| !unowned.contains(u.script_pubkey.as_bytes()));
        }
        if !doomed.is_empty() {
            info!(
                "Dropped {} vault UTXOs the wallet no longer owns",
                doomed.len()
            );
        }
        doomed.len()
    }

    /// Whether the wallet can sign for an output it holds: P2PKH with a
    /// private key, or a vault through its owner key. A manager key alone
    /// cannot spend a vault output (OP_REQUIRE_COINSTAKE).
    pub fn can_spend_script(&self, script: &Script) -> bool {
        let hash = if let Some(hash_bytes) = script.extract_p2pkh_hash() {
            Hash160::from_bytes(hash_bytes)
        } else if let Some(vault) = divi_script::StakingVaultScript::from_script(script) {
            Hash160::from_bytes(vault.owner_pubkey_hash)
        } else {
            return false;
        };
        self.keystore
            .get_key(&hash)
            .is_some_and(|entry| !entry.is_watch_only)
    }

    /// Find vault UTXOs (UTXOs that pay to any tracked vault script)
    pub fn get_vault_utxos(&self, current_height: u32, min_confirmations: u32) -> Vec<WalletUtxo> {
        let mempool_spent = self.mempool_spent();
        let vaults = self.vaults.read();
        let vault_scripts: std::collections::HashSet<_> =
            vaults.keys().map(|k| k.as_slice()).collect();

        self.utxos
            .read()
            .values()
            .filter(|utxo| {
                if mempool_spent.contains(&utxo.outpoint()) {
                    return false;
                }
                let confs = utxo.confirmations(current_height);
                confs >= min_confirmations
                    && utxo.is_mature(current_height, self.coinbase_maturity())
                    && vault_scripts.contains(utxo.script_pubkey.as_bytes())
            })
            .cloned()
            .collect()
    }

    /// Core's GetVaultedBalance: confirmed, mature coins in vaults we own. A
    /// vault we only manage is not vaulted for us (Core counts it as stakable).
    pub fn get_vaulted_balance(&self) -> Amount {
        self.confirmed_mature(&[Ownership::OwnedVault], self.last_scan_height())
    }

    /// Vault outputs we own (owner key held), confirmed and mature, not spent
    /// by a mempool transaction: what reclaimvaultfunds may spend
    pub fn get_owned_vault_utxos(
        &self,
        current_height: u32,
        min_confirmations: u32,
    ) -> Vec<WalletUtxo> {
        self.effective_utxos()
            .into_iter()
            .filter(|(_, source)| source.is_trusted())
            .map(|(utxo, _)| utxo)
            .filter(|utxo| {
                utxo.confirmations(current_height) >= min_confirmations
                    && utxo.is_mature(current_height, self.coinbase_maturity())
            })
            .filter(|utxo| self.vault_role(&utxo.script_pubkey) == Some(VaultRole::Owned))
            .collect()
    }

    /// Get vault UTXOs suitable for staking, with their parsed vault script
    ///
    /// Returns (utxo, vault_script_parsed) pairs where the vault is registered,
    /// we have the manager key and not the owner key: a vault we own is not
    /// staked, as in Divi Core.
    pub fn get_stakeable_vault_utxos(
        &self,
        current_height: u32,
        min_confirmations: u32,
    ) -> Vec<(WalletUtxo, divi_script::StakingVaultScript)> {
        let mempool_spent = self.mempool_spent();
        let vaults = self.vaults.read();
        // Pre-parse all registered vault scripts
        let vault_scripts: HashMap<Vec<u8>, divi_script::StakingVaultScript> = vaults
            .keys()
            .filter_map(|k| {
                let script = Script::from_bytes(k.clone());
                divi_script::StakingVaultScript::from_script(&script).map(|v| (k.clone(), v))
            })
            .collect();

        self.utxos
            .read()
            .values()
            .filter_map(|utxo| {
                if mempool_spent.contains(&utxo.outpoint()) {
                    return None;
                }
                let confs = utxo.confirmations(current_height);
                if confs < min_confirmations
                    || !utxo.is_mature(current_height, self.coinbase_maturity())
                {
                    return None;
                }
                let script_bytes = utxo.script_pubkey.as_bytes().to_vec();
                vault_scripts
                    .get(&script_bytes)
                    .map(|vault| (utxo.clone(), vault.clone()))
            })
            .collect::<Vec<_>>()
            .into_iter()
            // Divi Core stakes managed vault coins only: a vault whose owner
            // key is in the wallet is owned, even when the manager key is too
            // (AvailableUtxoCalculator.cpp:28-31)
            .filter(|(utxo, _)| self.vault_role(&utxo.script_pubkey) == Some(VaultRole::Managed))
            .collect()
    }
}

/// The wallet's HD seed from its mnemonic, with the stored chain mode and coin
/// type (wallets made before the coin type was stored keep the chain mode's)
fn stored_hd_wallet(
    db: &WalletDatabase,
    mnemonic: &str,
    passphrase: Option<&str>,
) -> Result<HdWallet, WalletError> {
    let chain_mode = db.load_chain_mode()?.unwrap_or(ChainMode::Divi);
    let hd_wallet = HdWallet::from_mnemonic(mnemonic, passphrase, chain_mode)?;
    Ok(match db.load_hd_coin_type()? {
        Some(coin_type) => hd_wallet.with_coin_type(coin_type),
        None => hd_wallet,
    })
}

/// The HD wallet of a wallet made from a seed, with the stored chain mode and
/// coin type
fn stored_seed_wallet(db: &WalletDatabase, seed: &[u8]) -> Result<HdWallet, WalletError> {
    let chain_mode = db.load_chain_mode()?.unwrap_or(ChainMode::Divi);
    let hd_wallet = HdWallet::from_seed(seed, chain_mode)?;
    Ok(match db.load_hd_coin_type()? {
        Some(coin_type) => hd_wallet.with_coin_type(coin_type),
        None => hd_wallet,
    })
}

/// A new wallet derives with Divi Core's coin type for its network
fn with_core_coin_type(wallet: HdWallet, network: Network) -> HdWallet {
    let coin_type = crate::hd::core_coin_type(wallet.chain_mode(), network == Network::Mainnet);
    wallet.with_coin_type(coin_type)
}

/// File `backup_to` puts in every backup it writes: only a folder holding it
/// may be replaced by a later backup (an earlier backup, never another database)
pub const BACKUP_MARKER: &str = "IRONDIVI_WALLET_BACKUP";

fn write_backup_marker(path: &Path) -> Result<(), WalletError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(path)
        .and_then(|mut f| f.write_all(b"irondivid wallet backup\n"))
        .map_err(|e| WalletError::Storage(format!("Failed to mark backup: {e}")))
}

/// A 20-byte hash taken from a script solution
fn hash160_from(bytes: &[u8]) -> Hash160 {
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&bytes[..20]);
    Hash160::from_bytes(hash)
}

/// The database key of a private key's encrypted record: `hash160 || 0x01`
fn secret_record_key(hash: &Hash160) -> Vec<u8> {
    let mut key = hash.as_bytes().to_vec();
    key.push(crate::persistence::ENCRYPTED_SECRET_SUFFIX);
    key
}

/// Open the wallet's master key with `passphrase`, in whichever format it is stored
fn open_master(db: &WalletDatabase, passphrase: &str) -> Result<MasterKey, WalletError> {
    let (salt, sealed) = db
        .load_encryption_metadata()?
        .ok_or(WalletError::WrongPassphrase)?;
    match db.load_kdf_params()? {
        Some(params) => Ok(MasterKey {
            key: at_rest::open_master_key(&sealed, passphrase, &salt, &params)?,
            aead: true,
        }),
        None => {
            let key = at_rest::legacy::derive_key_from_passphrase(passphrase, &salt);
            Ok(MasterKey {
                key: at_rest::legacy::open_master_key(&sealed, &key)?,
                aead: false,
            })
        }
    }
}

/// Every record an encrypted wallet keeps under its master key, opened
struct OpenedRecords {
    mnemonic: Option<Zeroizing<Vec<u8>>>,
    /// BIP39 passphrase of the mnemonic, when one was given
    mnemonic_passphrase: Option<Zeroizing<Vec<u8>>>,
    /// Seed of a wallet made from a seed, no words (Divi Core's -hdseed)
    hd_seed: Option<Zeroizing<Vec<u8>>>,
    secrets: Vec<(Hash160, divi_crypto::keys::SecretKey)>,
}

/// Open a metadata record sealed under its own key name, if it is stored
fn open_metadata_record(
    master: &MasterKey,
    record_key: &[u8],
    blob: Option<Vec<u8>>,
) -> Result<Option<Zeroizing<Vec<u8>>>, WalletError> {
    match blob {
        Some(blob) => Ok(Some(master.open_record(record_key, &blob)?)),
        None => Ok(None),
    }
}

/// Decrypt the mnemonic, its passphrase, the HD seed and every private key
/// stored encrypted
fn decrypt_records(db: &WalletDatabase, master: &MasterKey) -> Result<OpenedRecords, WalletError> {
    use crate::persistence::{KEY_ENCRYPTED_HD_SEED, KEY_ENCRYPTED_MNEMONIC_PASSPHRASE};
    let mnemonic = open_metadata_record(
        master,
        KEY_ENCRYPTED_MNEMONIC,
        db.load_encrypted_mnemonic()?,
    )?;
    let mnemonic_passphrase = open_metadata_record(
        master,
        KEY_ENCRYPTED_MNEMONIC_PASSPHRASE,
        db.load_encrypted_mnemonic_passphrase()?,
    )?;
    let hd_seed =
        open_metadata_record(master, KEY_ENCRYPTED_HD_SEED, db.load_encrypted_hd_seed()?)?;
    let mut secrets = Vec::new();
    for (hash, blob) in db.load_encrypted_secrets()? {
        let bytes = master.open_record(&secret_record_key(&hash), &blob)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::Storage("corrupt encrypted private key".into()))?;
        let secret = divi_crypto::keys::SecretKey::from_bytes(&arr)
            .map_err(|e| WalletError::Storage(format!("corrupt private key: {}", e)))?;
        secrets.push((hash, secret));
    }
    Ok(OpenedRecords {
        mnemonic,
        mnemonic_passphrase,
        hd_seed,
        secrets,
    })
}

/// Add the master key, sealed under `passphrase` with a fresh salt at the
/// default cost, to `batch`
fn put_sealed_master(
    batch: &mut rocksdb::WriteBatch,
    db: &WalletDatabase,
    master_key: &[u8],
    passphrase: &str,
) -> Result<(), WalletError> {
    use rand::RngCore;
    let mut salt = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let params = KdfParams::DEFAULT;
    let sealed = at_rest::seal_master_key(master_key, passphrase, &salt, &params)?;
    batch.put_cf(db.cf_metadata(), KEY_KDF_PARAMS, params.encode());
    batch.put_cf(db.cf_metadata(), KEY_ENCRYPTION_SALT, &salt);
    batch.put_cf(db.cf_metadata(), KEY_ENCRYPTED_MASTER_KEY, sealed);
    Ok(())
}

/// Rewrite an older wallet's encrypted records in the current format, keeping
/// its master key: Argon2id for the passphrase key, XChaCha20-Poly1305 for every
/// record. One synced batch, so a crash leaves either format whole.
fn migrate_legacy(
    db: &WalletDatabase,
    passphrase: &str,
    master_key: &[u8],
    records: &OpenedRecords,
) -> Result<(), WalletError> {
    use crate::persistence::{KEY_ENCRYPTED_HD_SEED, KEY_ENCRYPTED_MNEMONIC_PASSPHRASE};
    let master = MasterKey {
        key: Zeroizing::new(master_key.to_vec()),
        aead: true,
    };
    let mut batch = db.create_batch();
    put_sealed_master(&mut batch, db, master_key, passphrase)?;
    let metadata = [
        (KEY_ENCRYPTED_MNEMONIC, &records.mnemonic),
        (
            KEY_ENCRYPTED_MNEMONIC_PASSPHRASE,
            &records.mnemonic_passphrase,
        ),
        (KEY_ENCRYPTED_HD_SEED, &records.hd_seed),
    ];
    for (record_key, plain) in metadata {
        if let Some(plain) = plain {
            batch.put_cf(
                db.cf_metadata(),
                record_key,
                master.seal_record(record_key, plain),
            );
        }
    }
    for (hash, secret) in &records.secrets {
        let record_key = secret_record_key(hash);
        let blob = master.seal_record(&record_key, secret.as_bytes());
        batch.put_cf(db.cf_keys(), &record_key, blob);
    }
    db.write_batch_sync(batch)?;
    db.flush()?;
    // The old records were readable with the old passphrase alone
    db.compact_secret_cfs();
    Ok(())
}

/// Order transactions oldest first, moving each child after the parents it
/// spends from within the list
fn parents_first(
    mut txs: Vec<(u64, divi_primitives::transaction::Transaction)>,
) -> Vec<(u64, divi_primitives::transaction::Transaction)> {
    txs.sort_by_key(|(timestamp, _)| *timestamp);
    let mut pending: HashSet<Hash256> = txs.iter().map(|(_, tx)| tx.txid()).collect();
    let mut ordered = Vec::with_capacity(txs.len());
    while !txs.is_empty() {
        let ready = txs
            .iter()
            .position(|(_, tx)| tx.vin.iter().all(|i| !pending.contains(&i.prevout.txid)))
            .unwrap_or(0);
        let (timestamp, tx) = txs.remove(ready);
        pending.remove(&tx.txid());
        ordered.push((timestamp, tx));
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdWallet;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn create_test_wallet() -> WalletDb {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        WalletDb::with_hd_wallet(Network::Mainnet, wallet)
    }

    /// Divi Core's time of a wallet transaction is at most when the wallet
    /// received it (nTimeSmart, wallet.cpp:1052-1086): a block dated ahead of
    /// the clock does not date its transactions in the future; an older block
    /// keeps its own time
    #[test]
    fn transaction_time_is_never_ahead_of_its_arrival() {
        use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
        let wallet = create_test_wallet();
        let ours = wallet.new_receiving_address().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let paying = |tag: u8| Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: Hash256::from_bytes([tag; 32]),
                    vout: 0,
                },
                script_sig: Script::default(),
                sequence: 0xffffffff,
            }],
            vout: vec![TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: Script::new_p2pkh(ours.hash.as_bytes()),
            }],
            lock_time: 0,
        };
        let ahead = paying(7);
        wallet.scan_transaction(
            &ahead,
            Some(Hash256::from_bytes([8; 32])),
            Some(10),
            Some((now + 3600) as u32),
        );
        let time = wallet.get_transaction(&ahead.txid()).unwrap().timestamp;
        assert!(time <= now + 1, "{time} is ahead of {now}");
        let old = paying(9);
        wallet.scan_transaction(
            &old,
            Some(Hash256::from_bytes([10; 32])),
            Some(11),
            Some(1_000_000),
        );
        assert_eq!(
            wallet.get_transaction(&old.txid()).unwrap().timestamp,
            1_000_000
        );
    }

    #[test]
    fn test_wallet_creation() {
        let wallet = WalletDb::new(Network::Mainnet);
        assert_eq!(wallet.get_balance(), Amount::ZERO);
    }

    #[test]
    fn test_wallet_with_hd() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();
        assert!(wallet.is_mine(&addr));
    }

    #[test]
    fn test_add_utxo() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();

        let mut utxo = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        utxo.height = Some(1);

        wallet.add_utxo(utxo.clone());

        assert!(wallet.has_utxo(&utxo.outpoint()));
        assert_eq!(wallet.get_balance(), Amount::from_sat(100_000_000));
    }

    #[test]
    fn test_spend_utxo() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();

        let mut utxo = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        let outpoint = utxo.outpoint();
        utxo.height = Some(1);

        wallet.add_utxo(utxo);
        assert_eq!(wallet.get_balance(), Amount::from_sat(100_000_000));

        wallet.spend_utxo(&outpoint);
        assert_eq!(wallet.get_balance(), Amount::ZERO);
    }

    #[test]
    fn test_confirmed_balance() {
        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();

        // Unconfirmed UTXO
        let mut utxo1 = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(50_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        utxo1.height = None;

        // Confirmed UTXO
        let mut utxo2 = WalletUtxo::new(
            Hash256::from_bytes([2u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        utxo2.height = Some(100);

        wallet.add_utxo(utxo1);
        wallet.add_utxo(utxo2);

        // At height 105, only utxo2 has 6 confirmations
        assert_eq!(
            wallet.get_confirmed_balance(105, 1),
            Amount::from_sat(100_000_000)
        );
        assert_eq!(
            wallet.get_unconfirmed_balance(),
            Amount::from_sat(50_000_000)
        );
    }

    #[test]
    fn test_lock_unlock() {
        let wallet = create_test_wallet();

        assert!(!wallet.is_locked());
        wallet.lock();
        assert!(wallet.is_locked());

        // Should fail when locked
        assert!(wallet.new_receiving_address().is_err());

        wallet.unlock("", 0).unwrap();
        assert!(!wallet.is_locked());

        // Should work when unlocked
        assert!(wallet.new_receiving_address().is_ok());
    }

    #[test]
    fn test_transaction_history() {
        let wallet = create_test_wallet();

        let tx = WalletTx {
            txid: Hash256::from_bytes([1u8; 32]),
            block_hash: Some(Hash256::from_bytes([2u8; 32])),
            block_height: Some(100),
            timestamp: 1000000,
            amount: 100_000_000,
            fee: None,
            category: "receive".to_string(),
            confirmations: 10,
        };

        wallet.add_transaction(tx.clone());

        let history = wallet.get_transactions(None);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].txid, tx.txid);
    }

    #[test]
    fn test_utxo_maturity() {
        let mut utxo = WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(100_000_000),
            Script::default(),
            "test".to_string(),
        );
        utxo.is_coinbase = true;
        utxo.height = Some(100);

        // At height 150, coinbase at 100 is not mature (need 100 confirmations)
        assert!(!utxo.is_mature(150, 100));

        // At height 200, coinbase at 100 is mature
        assert!(utxo.is_mature(200, 100));

        // Regular UTXO is always mature
        utxo.is_coinbase = false;
        assert!(utxo.is_mature(100, 100));
    }

    #[test]
    fn test_account_management() {
        let wallet = create_test_wallet();
        let addr1 = wallet.new_receiving_address().unwrap();
        let addr2 = wallet.new_receiving_address().unwrap();

        wallet.set_account(&addr1, "savings");
        wallet.set_account(&addr2, "checking");

        assert_eq!(wallet.get_account(&addr1), "savings");
        assert_eq!(wallet.get_account(&addr2), "checking");

        let savings_addrs = wallet.get_addresses_by_account("savings");
        assert_eq!(savings_addrs.len(), 1);
        assert!(savings_addrs.contains(&addr1.to_string()));

        wallet.set_account(&addr1, "checking");
        assert_eq!(wallet.get_account(&addr1), "checking");
        let checking_addrs = wallet.get_addresses_by_account("checking");
        assert_eq!(checking_addrs.len(), 2);
    }

    #[test]
    fn test_account_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            let addr1 = wallet.new_receiving_address().unwrap();
            let addr2 = wallet.new_receiving_address().unwrap();

            wallet.set_account(&addr1, "test_account");
            wallet.set_account(&addr2, "another_account");

            wallet.save().unwrap();
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();
            let accounts = wallet.list_accounts();

            assert!(accounts.contains_key("test_account"));
            assert!(accounts.contains_key("another_account"));
            assert_eq!(accounts.get("test_account").unwrap().len(), 1);
            assert_eq!(accounts.get("another_account").unwrap().len(), 1);
        }
    }

    #[test]
    fn test_script_storage() {
        let wallet = create_test_wallet();

        let script_bytes = vec![
            0x51, 0x21, 0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x21, 0x03, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x52,
            0xae,
        ];
        let script = Script::from_bytes(script_bytes);

        wallet.add_script(script.clone()).unwrap();

        let script_hash = divi_crypto::hash160(script.as_bytes());
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(script_hash.as_ref());
        let hash160 = Hash160::from_bytes(hash_bytes);

        let retrieved = wallet.get_script(&hash160);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().as_bytes(), script.as_bytes());
    }

    #[test]
    fn test_script_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        let script_bytes = vec![
            0x51, 0x21, 0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x52, 0xae,
        ];
        let script = Script::from_bytes(script_bytes.clone());

        let script_hash = divi_crypto::hash160(&script_bytes);
        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(script_hash.as_ref());
        let hash160 = Hash160::from_bytes(hash_bytes);

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            wallet.add_script(script.clone()).unwrap();
            wallet.save().unwrap();
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

            let retrieved = wallet.get_script(&hash160);
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().as_bytes(), script.as_bytes());
        }
    }

    #[test]
    fn test_vault_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        let vault_script = vec![1u8; 50];
        let funding_txid = [2u8; 32];

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            let metadata = VaultMetadata {
                owner_address: "DOwnerAddress123".to_string(),
                manager_address: "DManagerAddress456".to_string(),
                vault_script: vault_script.clone(),
                funding_txid,
            };

            wallet.store_vault(metadata);
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

            let retrieved = wallet.get_vault(&vault_script);
            assert!(retrieved.is_some());
            let metadata = retrieved.unwrap();
            assert_eq!(metadata.owner_address, "DOwnerAddress123");
            assert_eq!(metadata.manager_address, "DManagerAddress456");
            assert_eq!(metadata.vault_script, vault_script);
            assert_eq!(metadata.funding_txid, funding_txid);

            let all_vaults = wallet.get_all_vaults();
            assert_eq!(all_vaults.len(), 1);
        }
    }

    #[test]
    fn test_vault_removal_persistence() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet.dat");

        let vault_script = vec![3u8; 50];
        let funding_txid = [4u8; 32];

        {
            let wallet_hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet =
                WalletDb::create_persistent(&wallet_path, Network::Mainnet, wallet_hd).unwrap();

            let metadata = VaultMetadata {
                owner_address: "DOwnerAddress789".to_string(),
                manager_address: "DManagerAddress012".to_string(),
                vault_script: vault_script.clone(),
                funding_txid,
            };

            wallet.store_vault(metadata);
            assert!(wallet.get_vault(&vault_script).is_some());

            let removed = wallet.remove_vault(&vault_script);
            assert!(removed);
            assert!(wallet.get_vault(&vault_script).is_none());
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();

            let retrieved = wallet.get_vault(&vault_script);
            assert!(retrieved.is_none());

            let all_vaults = wallet.get_all_vaults();
            assert_eq!(all_vaults.len(), 0);
        }
    }

    #[test]
    fn test_fee_calculation_for_sent_transactions() {
        use divi_primitives::transaction::{OutPoint as TxOutPoint, Transaction, TxIn, TxOut};

        let wallet = create_test_wallet();
        let addr = wallet.new_receiving_address().unwrap();
        let change_addr = wallet.new_change_address().unwrap();

        // First, add a UTXO to the wallet (1 DIVI = 100_000_000 satoshis)
        let input_txid = Hash256::from_bytes([1u8; 32]);
        let input_value = Amount::from_sat(100_000_000); // 1 DIVI
        let input_utxo = WalletUtxo::new(
            input_txid,
            0,
            input_value,
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        wallet.add_utxo(input_utxo);

        // Create a transaction that spends the UTXO
        // Send 0.9 DIVI to external, 0.09 DIVI change back to wallet, 0.01 DIVI fee
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: TxOutPoint {
                    txid: input_txid,
                    vout: 0,
                },
                script_sig: Script::default(),
                sequence: 0xffffffff,
            }],
            vout: vec![
                // Output to external address (not ours) - 0.9 DIVI
                TxOut {
                    value: Amount::from_sat(90_000_000),
                    script_pubkey: Script::new_p2pkh(&[0xaa; 20]), // Some external address
                },
                // Change back to our wallet - 0.09 DIVI
                TxOut {
                    value: Amount::from_sat(9_000_000),
                    script_pubkey: Script::new_p2pkh(change_addr.hash.as_bytes()),
                },
            ],
            lock_time: 0,
        };

        // Scan the transaction
        let block_hash = Hash256::from_bytes([2u8; 32]);
        wallet.scan_transaction(&tx, Some(block_hash), Some(100), Some(1000000));

        // Verify the transaction was recorded with correct fee
        let wallet_tx = wallet.get_transaction(&tx.txid()).unwrap();

        // Category should be "send" since we spent more than we received back
        assert_eq!(wallet_tx.category, "send");

        // Fee should be: inputs (100M) - total outputs (90M + 9M) = 1M satoshis = 0.01 DIVI
        assert!(wallet_tx.fee.is_some());
        let fee = wallet_tx.fee.unwrap();
        assert_eq!(fee.as_sat(), 1_000_000); // 0.01 DIVI fee

        // Net amount should be change received (9M) - sent (100M) = -91M
        // (negative because we're sending)
        assert_eq!(wallet_tx.amount, 9_000_000 - 100_000_000);
    }

    // -------- chain_mode persistence: PrivateDivi round-trip --------

    #[test]
    fn test_privatedivi_chain_mode_persists_and_restores_coin_type() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("wallet_pd.dat");

        // Derive and record what address index 0 looks like before save
        let addr_before = {
            let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::PrivateDivi).unwrap();
            // coin_type must be 801
            assert_eq!(hd.coin_type(), 801);
            let wallet = WalletDb::create_persistent(&wallet_path, Network::Mainnet, hd).unwrap();
            let addr = wallet.new_receiving_address().unwrap();
            wallet.save().unwrap();
            addr
        };

        // Re-open and derive again: the restored coin_type must still be 801
        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();
            let addr_after = wallet.new_receiving_address().unwrap();
            // The second open resumes from index 1 (index 0 was already issued),
            // but we can verify chain_mode is correct by checking the keystore has
            // the same PrivateDivi-derived key for index 0.
            assert!(wallet.is_mine(&addr_before));
            // addr_after is index 1 in the PrivateDivi path — it must differ from
            // what Divi's path would produce at index 1.
            let divi_wallet = WalletDb::with_hd_wallet(
                Network::Mainnet,
                HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap(),
            );
            // Drain to index 1 for Divi
            let _ = divi_wallet.new_receiving_address().unwrap();
            let divi_addr_1 = divi_wallet.new_receiving_address().unwrap();
            // PrivateDivi address at index 1 must differ from Divi address at index 1
            assert_ne!(addr_after.to_string(), divi_addr_1.to_string());
        }
    }

    // -------- last_scan_height set / get --------

    #[test]
    fn test_set_get_last_scan_height() {
        let wallet = create_test_wallet();

        assert_eq!(wallet.last_scan_height(), 0);
        wallet.set_last_scan_height(42_000);
        assert_eq!(wallet.last_scan_height(), 42_000);
    }

    #[test]
    fn test_last_scan_height_persists() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("scan_height_test.dat");

        {
            let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
            let wallet = WalletDb::create_persistent(&wallet_path, Network::Mainnet, hd).unwrap();
            wallet.set_last_scan_height(99_999);
            wallet.save().unwrap();
        }

        {
            let wallet = WalletDb::open(&wallet_path, Network::Mainnet).unwrap();
            assert_eq!(wallet.last_scan_height(), 99_999);
        }
    }

    // -------- UTXO confirmations helper --------

    #[test]
    fn save_is_one_atomic_write() {
        // A save made of separate writes can be cut short by a crash or kill,
        // leaving part of it on disk; one batch is all or nothing.
        let dir = tempfile::tempdir().unwrap();
        let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(dir.path(), Network::Mainnet, hd).unwrap();
        let addr = wallet.new_receiving_address().unwrap();
        wallet.add_utxo(WalletUtxo::new(
            Hash256::from_bytes([1u8; 32]),
            0,
            Amount::from_sat(5_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        ));
        wallet.add_utxo(WalletUtxo::new(
            Hash256::from_bytes([2u8; 32]),
            0,
            Amount::from_sat(7_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        ));
        wallet.spend_utxo(&OutPoint::new(Hash256::from_bytes([2u8; 32]), 0));
        wallet.set_account(&addr, "label");
        wallet.set_last_scan_height(7);

        let db = wallet.db.as_ref().unwrap();
        let seq = db.latest_sequence_number();
        wallet.save().unwrap();
        // WAL records written after `seq`
        assert_eq!(db.write_batches_since(seq).unwrap(), 1);

        drop(wallet);
        let wallet = WalletDb::open(dir.path(), Network::Mainnet).unwrap();
        assert_eq!(wallet.last_scan_height(), 7);
        assert_eq!(wallet.get_utxos().len(), 1);
        assert_eq!(wallet.get_account(&addr), "label");
        assert!(wallet.is_mine(&addr));
    }

    #[test]
    fn test_utxo_confirmations_confirmed() {
        let utxo = WalletUtxo {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
            value: Amount::from_sat(1_000),
            script_pubkey: Script::default(),
            height: Some(100),
            is_coinbase: false,
            is_coinstake: false,
            address: "test".to_string(),
        };

        // At current height 105: 105 - 100 + 1 = 6 confirmations
        assert_eq!(utxo.confirmations(105), 6);
        // At current height 100: 1 confirmation
        assert_eq!(utxo.confirmations(100), 1);
        // At height 99 (before conf): 0
        assert_eq!(utxo.confirmations(99), 0);
    }

    #[test]
    fn test_utxo_confirmations_unconfirmed() {
        let utxo = WalletUtxo {
            txid: Hash256::from_bytes([2u8; 32]),
            vout: 0,
            value: Amount::from_sat(1_000),
            script_pubkey: Script::default(),
            height: None, // unconfirmed
            is_coinbase: false,
            is_coinstake: false,
            address: "test".to_string(),
        };

        assert_eq!(utxo.confirmations(1_000_000), 0);
    }

    // -------- coinbase_maturity by network --------

    #[test]
    fn test_coinbase_maturity_mainnet_is_20() {
        let wallet = WalletDb::new(Network::Mainnet);
        assert_eq!(wallet.coinbase_maturity(), 20);
    }

    #[test]
    fn test_coinbase_maturity_testnet_is_1() {
        let wallet = WalletDb::new(Network::Testnet);
        assert_eq!(wallet.coinbase_maturity(), 1);
    }

    // -------- get_spendable_utxos excludes immature coinbase --------

    #[test]
    fn test_spendable_utxos_excludes_immature_coinbase() {
        let wallet = create_test_wallet(); // Mainnet → maturity = 20
        let addr = wallet.new_receiving_address().unwrap();

        // Coinbase confirmed at height 100.
        // is_mature() uses: current_height >= h + maturity → current_height >= 120
        let mut cb_utxo = WalletUtxo::new(
            Hash256::from_bytes([0xc0; 32]),
            0,
            Amount::from_sat(5_000_000),
            Script::new_p2pkh(addr.hash.as_bytes()),
            addr.to_string(),
        );
        cb_utxo.is_coinbase = true;
        cb_utxo.height = Some(100);

        wallet.add_utxo(cb_utxo.clone());

        // At height 120: 120 >= 100 + 20 → mature (boundary)
        let spendable_mature = wallet.get_spendable_utxos(120, 1);
        assert_eq!(
            spendable_mature.len(),
            1,
            "Should be spendable at exactly the maturity boundary"
        );

        // At height 119: 119 < 100 + 20 → NOT mature
        let spendable_immature = wallet.get_spendable_utxos(119, 1);
        assert_eq!(
            spendable_immature.len(),
            0,
            "Should not be spendable before maturity boundary"
        );
    }

    // -------- mempool overlay (unconfirmed transactions) --------

    mod mempool_overlay {
        use super::*;
        use divi_primitives::transaction::{OutPoint as TxOutPoint, Transaction, TxIn, TxOut};

        const COIN: i64 = 100_000_000;

        fn spend(prevouts: &[(Hash256, u32)], outputs: Vec<(i64, Script)>) -> Transaction {
            Transaction {
                version: 1,
                vin: prevouts
                    .iter()
                    .map(|(txid, vout)| TxIn {
                        prevout: TxOutPoint {
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

        /// Wallet holding one confirmed 100 DIVI coin at height 100.
        fn funded() -> (WalletDb, Transaction) {
            let wallet = create_test_wallet();
            let addr = wallet.new_receiving_address().unwrap();
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
            assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
            (wallet, fund)
        }

        /// Our own send: 100 in, 30 to a stranger, 69.99 change, 0.01 fee.
        fn own_send(wallet: &WalletDb, fund: &Transaction) -> Transaction {
            let change = wallet.new_change_address().unwrap();
            spend(
                &[(fund.txid(), 0)],
                vec![
                    (30 * COIN, stranger()),
                    (70 * COIN - 1_000_000, mine(&change)),
                ],
            )
        }

        #[test]
        fn own_send_is_trusted_before_confirmation() {
            let (wallet, fund) = funded();
            let tx = own_send(&wallet, &fund);
            assert!(wallet.add_mempool_tx(&tx));
            assert_eq!(wallet.mempool_tx_count(), 1);

            // The spent input is gone; our change is spendable at 0 confirmations.
            let spendable = wallet.get_spendable_utxos(100, 0);
            assert!(spendable.iter().all(|u| u.txid != fund.txid()));
            assert_eq!(spendable.len(), 1);
            assert_eq!(spendable[0].txid, tx.txid());
            assert!(wallet.get_spendable_utxos(100, 1).is_empty());

            // Core: getbalance counts confirmed coins only; the change is in
            // getunconfirmedbalance and spendable_balance until it confirms.
            assert_eq!(wallet.get_balance().as_sat(), 0);
            assert_eq!(
                wallet.get_confirmed_balance(100, 1).as_sat(),
                70 * COIN - 1_000_000
            );
            assert_eq!(
                wallet.get_unconfirmed_balance().as_sat(),
                70 * COIN - 1_000_000
            );
            assert_eq!(
                wallet.get_spendable_balance(100).as_sat(),
                70 * COIN - 1_000_000
            );

            let rec = wallet.get_transaction(&tx.txid()).unwrap();
            assert_eq!(rec.category, "send");
            assert_eq!(rec.fee.unwrap().as_sat(), 1_000_000);
            assert!(rec.block_height.is_none());
        }

        #[test]
        fn own_send_confirms_without_duplicates() {
            let (wallet, fund) = funded();
            let tx = own_send(&wallet, &fund);
            wallet.add_mempool_tx(&tx);
            let before = wallet.get_transactions(None).len();

            wallet.scan_block(
                Hash256::from_bytes([2u8; 32]),
                101,
                1_060,
                std::slice::from_ref(&tx),
            );

            assert_eq!(wallet.mempool_tx_count(), 0);
            assert_eq!(wallet.get_transactions(None).len(), before);
            let rec = wallet.get_transaction(&tx.txid()).unwrap();
            assert_eq!(rec.category, "send");
            assert_eq!(rec.block_height, Some(101));
            assert!(wallet.spent.read().contains(&OutPoint::new(fund.txid(), 0)));
            assert_eq!(wallet.get_balance().as_sat(), 70 * COIN - 1_000_000);
            // The mempool's own remove after the block is a harmless no-op.
            assert!(!wallet.remove_mempool_tx(&tx.txid()));
        }

        #[test]
        fn incoming_from_stranger_is_untrusted() {
            let wallet = create_test_wallet();
            let addr = wallet.new_receiving_address().unwrap();
            let tx = spend(
                &[(Hash256::from_bytes([7u8; 32]), 3)],
                vec![(5 * COIN, mine(&addr))],
            );
            assert!(wallet.add_mempool_tx(&tx));

            assert_eq!(wallet.get_balance().as_sat(), 0);
            assert_eq!(wallet.get_confirmed_balance(100, 1).as_sat(), 0);
            assert_eq!(wallet.get_confirmed_balance(100, 0).as_sat(), 5 * COIN);
            assert_eq!(wallet.get_unconfirmed_balance().as_sat(), 5 * COIN);
            assert!(wallet.get_spendable_utxos(100, 0).is_empty());

            let utxos = wallet.get_utxos();
            assert_eq!(utxos.len(), 1);
            assert_eq!(utxos[0].confirmations(100), 0);
            assert_eq!(
                wallet.get_transaction(&tx.txid()).unwrap().category,
                "receive"
            );
        }

        #[test]
        fn unrelated_tx_is_ignored() {
            let (wallet, _) = funded();
            let tx = spend(
                &[(Hash256::from_bytes([5u8; 32]), 0)],
                vec![(COIN, stranger())],
            );
            assert!(!wallet.add_mempool_tx(&tx));
            assert_eq!(wallet.mempool_tx_count(), 0);
        }

        #[test]
        fn remove_reverts_state() {
            let (wallet, fund) = funded();
            let tx = own_send(&wallet, &fund);
            wallet.add_mempool_tx(&tx);
            assert!(wallet.remove_mempool_tx(&tx.txid()));

            assert_eq!(wallet.mempool_tx_count(), 0);
            assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
            assert!(wallet.get_transaction(&tx.txid()).is_none());
            let spendable = wallet.get_spendable_utxos(101, 1);
            assert_eq!(spendable.len(), 1);
            assert_eq!(spendable[0].txid, fund.txid());
        }

        #[test]
        fn conflicting_block_drops_entry_and_descendants() {
            let (wallet, fund) = funded();
            let tx = own_send(&wallet, &fund);
            wallet.add_mempool_tx(&tx);
            // A child spending the unconfirmed change.
            let child = spend(&[(tx.txid(), 1)], vec![(69 * COIN, stranger())]);
            assert!(wallet.add_mempool_tx(&child));
            assert_eq!(wallet.mempool_tx_count(), 2);

            // A different tx spending the same coin confirms instead.
            let other = spend(&[(fund.txid(), 0)], vec![(99 * COIN, stranger())]);
            wallet.scan_block(Hash256::from_bytes([3u8; 32]), 101, 1_060, &[other]);

            assert_eq!(wallet.mempool_tx_count(), 0);
            assert!(wallet.get_transaction(&tx.txid()).is_none());
            assert!(wallet.get_transaction(&child.txid()).is_none());
            assert_eq!(wallet.get_balance().as_sat(), 0);
        }

        #[test]
        fn overlay_is_restored_on_open() {
            use tempfile::tempdir;

            let dir = tempdir().unwrap();
            let path = dir.path().join("overlay.dat");
            let tx;
            {
                let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
                let wallet = WalletDb::create_persistent(&path, Network::Mainnet, hd).unwrap();
                let addr = wallet.new_receiving_address().unwrap();
                tx = spend(
                    &[(Hash256::from_bytes([7u8; 32]), 0)],
                    vec![(5 * COIN, mine(&addr))],
                );
                assert!(wallet.add_mempool_tx(&tx));
                wallet.save_incremental().unwrap();
                wallet.save().unwrap();
            }
            // Stored apart from the confirmed state, and back in the overlay on open
            let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
            assert_eq!(wallet.mempool_tx_count(), 1);
            assert_eq!(wallet.get_utxos().len(), 1);
            assert!(wallet.utxos.read().is_empty());
            let rec = wallet.get_transaction(&tx.txid()).unwrap();
            assert!(rec.block_height.is_none());
            assert!(wallet.transactions.read().is_empty());
        }

        #[test]
        fn unconfirmed_transactions_come_back_parents_first() {
            let (wallet, fund) = funded();
            let tx = own_send(&wallet, &fund);
            let child = spend(&[(tx.txid(), 1)], vec![(69 * COIN, stranger())]);
            assert!(wallet.add_mempool_tx(&tx));
            assert!(wallet.add_mempool_tx(&child));
            // Same first-seen second, child listed first: order must follow the spend
            for entry in wallet.mempool_txs.write().values_mut() {
                entry.record.timestamp = 5;
            }
            let swapped = parents_first(vec![(5, child.clone()), (5, tx.clone())]);
            assert_eq!(swapped[0].1.txid(), tx.txid());
            assert_eq!(wallet.unconfirmed_transactions(), vec![tx, child]);
        }
    }

    /// A wallet damaged by an older build holds an HD key with no encrypted
    /// secret (the stored record is public-key only). Unlock re-derives the
    /// secret from the HD path and stores it, so the key is owned again.
    #[test]
    fn unlock_rederives_hd_key_stored_without_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(&path, Network::Testnet, hd).unwrap();
        wallet.save().unwrap();
        wallet.encrypt_wallet("pw").unwrap();
        wallet.unlock("pw", 60).unwrap();
        let addr = wallet.new_receiving_address().unwrap();
        let expected = wallet.get_key_by_address(&addr).unwrap().secret.unwrap();
        wallet.lock();
        // What a lock before the next block left on disk: the public-key-only
        // record (written by the next save while locked) and no encrypted secret
        wallet.save().unwrap();
        {
            let db = wallet.db.as_ref().unwrap();
            let mut suffixed = addr.hash.as_bytes().to_vec();
            suffixed.push(crate::persistence::ENCRYPTED_SECRET_SUFFIX);
            let mut batch = db.create_batch();
            batch.delete_cf(db.cf_keys(), &suffixed);
            db.write_batch(batch).unwrap();
        }
        drop(wallet);

        for _ in 0..2 {
            let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
            assert!(wallet.is_mine(&addr));
            wallet.unlock("pw", 60).unwrap();
            let secret = wallet.get_key_by_address(&addr).unwrap().secret.unwrap();
            assert_eq!(secret.as_bytes(), expected.as_bytes());
        }
        // The healed secret is on disk now, not just re-derived each time
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        let db = wallet.db.as_ref().unwrap();
        assert!(db
            .load_encrypted_secrets()
            .unwrap()
            .iter()
            .any(|(h, _)| *h == addr.hash));
    }

    /// Confirmed-state accounting: blocks scanned twice, reorgs, restarts
    mod chain_accounting {
        mod crash;

        use super::*;
        use divi_primitives::block::Block;
        use divi_primitives::transaction::{OutPoint as TxOutPoint, Transaction, TxIn, TxOut};

        const COIN: i64 = 100_000_000;
        const CHANGE: i64 = 70 * COIN - 1_000_000;

        fn tx(prevouts: &[(Hash256, u32)], outputs: Vec<(i64, Script)>) -> Transaction {
            Transaction {
                version: 1,
                vin: prevouts
                    .iter()
                    .map(|(txid, vout)| TxIn {
                        prevout: TxOutPoint {
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

        fn block_hash(height: u32, branch: u8) -> Hash256 {
            let mut b = [branch; 32];
            b[..4].copy_from_slice(&height.to_le_bytes());
            Hash256::from_bytes(b)
        }

        fn scan(wallet: &WalletDb, height: u32, txs: &[Transaction]) {
            wallet.scan_block(block_hash(height, 0), height, 1_000 + height, txs);
        }

        /// `fund` pays the wallet 100 DIVI; `send` spends it: 30 to a
        /// stranger, 69.99 change back to the wallet, 0.01 fee.
        fn fixture(wallet: &WalletDb) -> (Transaction, Transaction) {
            let addr = wallet.new_receiving_address().unwrap();
            let change = wallet.new_change_address().unwrap();
            let fund = tx(
                &[(Hash256::from_bytes([9u8; 32]), 0)],
                vec![(100 * COIN, mine(&addr))],
            );
            let send = tx(
                &[(fund.txid(), 0)],
                vec![(30 * COIN, stranger()), (CHANGE, mine(&change))],
            );
            (fund, send)
        }

        fn outpoints(wallet: &WalletDb) -> HashSet<OutPoint> {
            wallet.get_utxos().iter().map(|u| u.outpoint()).collect()
        }

        #[test]
        fn rescanned_block_does_not_bring_back_spent_coin() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            scan(&wallet, 1, std::slice::from_ref(&fund));
            scan(&wallet, 2, std::slice::from_ref(&send));
            // A catch-up or rescan reads block 1 again
            scan(&wallet, 1, std::slice::from_ref(&fund));

            assert!(!wallet.has_utxo(&OutPoint::new(fund.txid(), 0)));
            assert_eq!(wallet.get_balance().as_sat(), CHANGE);
        }

        #[test]
        fn rescanned_block_keeps_history_amount() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            scan(&wallet, 1, std::slice::from_ref(&fund));
            scan(&wallet, 2, std::slice::from_ref(&send));
            let first = wallet.get_transaction(&send.txid()).unwrap();
            scan(&wallet, 2, std::slice::from_ref(&send));
            let again = wallet.get_transaction(&send.txid()).unwrap();

            assert_eq!(first.amount, -(30 * COIN + 1_000_000));
            assert_eq!(again.amount, first.amount);
            assert_eq!(again.fee, first.fee);
            assert_eq!(again.category, "send");
        }

        #[test]
        fn received_outputs_include_spent_and_mempool_coins() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            scan(&wallet, 1, std::slice::from_ref(&fund));
            scan(&wallet, 2, std::slice::from_ref(&send));
            let incoming = tx(
                &[(Hash256::from_bytes([8u8; 32]), 0)],
                vec![(5 * COIN, mine(&wallet.new_receiving_address().unwrap()))],
            );
            assert!(wallet.add_mempool_tx(&incoming));

            let received: HashMap<OutPoint, Option<u32>> = wallet
                .received_outputs()
                .iter()
                .map(|u| (u.outpoint(), u.height))
                .collect();
            assert_eq!(
                received,
                HashMap::from([
                    (OutPoint::new(fund.txid(), 0), Some(1)),
                    (OutPoint::new(send.txid(), 1), Some(2)),
                    (OutPoint::new(incoming.txid(), 0), None),
                ])
            );
        }

        #[test]
        fn send_candidates_are_confirmed_unlocked_coins() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let small = tx(
                &[(Hash256::from_bytes([7u8; 32]), 0)],
                vec![(COIN, mine(&wallet.new_receiving_address().unwrap()))],
            );
            let other = tx(
                &[(Hash256::from_bytes([8u8; 32]), 0)],
                vec![(2 * COIN, mine(&wallet.new_receiving_address().unwrap()))],
            );
            scan(&wallet, 1, &[fund, small.clone(), other.clone()]);
            assert!(wallet.add_mempool_tx(&send));

            let coins = |wallet: &WalletDb, minconf| -> HashSet<OutPoint> {
                wallet
                    .get_send_candidates(1, minconf)
                    .iter()
                    .map(|u| u.outpoint())
                    .collect()
            };
            // Our unconfirmed change is not spent (Divi Core without
            // -spendzeroconfchange), nor counted by getbalance
            let expected: HashSet<OutPoint> = [
                OutPoint::new(small.txid(), 0),
                OutPoint::new(other.txid(), 0),
            ]
            .into();
            assert_eq!(coins(&wallet, 1), expected);
            assert_eq!(coins(&wallet, 0), expected);
            assert_eq!(wallet.get_balance().as_sat(), 3 * COIN);
            assert_eq!(wallet.get_unconfirmed_balance().as_sat(), CHANGE);
            // A locked coin is not spent
            wallet.set_coin_locked(OutPoint::new(other.txid(), 0), true);
            assert_eq!(coins(&wallet, 1), [OutPoint::new(small.txid(), 0)].into());
            // An explicit higher minconf
            assert!(wallet.get_send_candidates(1, 2).is_empty());
        }

        #[test]
        fn balance_leaves_out_watch_only_coins() {
            let wallet = create_test_wallet();
            let watched =
                Address::from_pubkey_hash(Hash160::from_bytes([0xbb; 20]), Network::Mainnet);
            wallet.import_watch_only_address(&watched, None).unwrap();
            let pay = tx(
                &[(Hash256::from_bytes([7u8; 32]), 0)],
                vec![(5 * COIN, Script::new_p2pkh(watched.hash.as_bytes()))],
            );
            scan(&wallet, 1, std::slice::from_ref(&pay));
            // Divi Core records no coin paid only to a watched script
            // (wallet.cpp:1292-1311)
            assert!(wallet.get_utxos().is_empty());
            assert!(wallet.get_transactions(None).is_empty());
            assert_eq!(wallet.get_balance().as_sat(), 0);
            assert_eq!(wallet.get_confirmed_balance(1, 1).as_sat(), 0);
            assert!(wallet.get_send_candidates(1, 1).is_empty());
        }

        #[test]
        fn reorg_does_not_restore_coin_created_above_fork() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let spend_change = tx(&[(send.txid(), 1)], vec![(CHANGE - 1_000_000, stranger())]);
            scan(&wallet, 1, std::slice::from_ref(&fund));
            scan(&wallet, 2, std::slice::from_ref(&send));
            scan(&wallet, 3, std::slice::from_ref(&spend_change));
            assert_eq!(wallet.get_balance().as_sat(), 0);

            wallet.handle_reorg(1);

            // Blocks 2 and 3 are gone: the funding coin is back, and the change
            // created (and spent) above the fork does not exist
            assert_eq!(
                outpoints(&wallet),
                HashSet::from([OutPoint::new(fund.txid(), 0)])
            );
            assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
            assert!(wallet.get_transaction(&send.txid()).is_none());
        }

        /// -walletnotify's points, Divi Core's addToWallet (wallet.cpp:1283):
        /// a send committed, then seen in the mempool, its block, the block
        /// disconnected, and the mempool again
        #[test]
        fn tx_listener_hears_each_wallet_change() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let heard = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let into = std::sync::Arc::clone(&heard);
            wallet.set_tx_listener(std::sync::Arc::new(move |txid: &Hash256| {
                into.lock().unwrap().push(*txid)
            }));
            let count =
                |txid: Hash256| heard.lock().unwrap().iter().filter(|t| **t == txid).count();

            scan(&wallet, 1, std::slice::from_ref(&fund));
            assert_eq!(count(fund.txid()), 1, "received in a block");
            wallet.note_committed(&send.txid());
            assert!(wallet.add_mempool_tx(&send));
            assert_eq!(count(send.txid()), 2, "committed, then in the mempool");
            scan(&wallet, 2, std::slice::from_ref(&send));
            assert_eq!(count(send.txid()), 3, "in a block");
            wallet.handle_reorg(1);
            assert_eq!(count(send.txid()), 4, "its block disconnected");
            assert!(wallet.add_mempool_tx(&send));
            assert_eq!(count(send.txid()), 5, "back in the mempool");
            assert_eq!(count(fund.txid()), 1, "below the fork, untouched");
        }

        #[test]
        fn reorged_tx_mined_again_restores_its_outputs() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let spend_change = tx(&[(send.txid(), 1)], vec![(CHANGE - 1_000_000, stranger())]);
            scan(&wallet, 1, std::slice::from_ref(&fund));
            scan(&wallet, 2, std::slice::from_ref(&send));
            scan(&wallet, 3, std::slice::from_ref(&spend_change));
            wallet.handle_reorg(1);
            // The new branch mines `send` again but not `spend_change`
            wallet.scan_block(block_hash(2, 1), 2, 1_002, std::slice::from_ref(&send));

            assert_eq!(
                outpoints(&wallet),
                HashSet::from([OutPoint::new(send.txid(), 1)])
            );
            assert_eq!(wallet.get_balance().as_sat(), CHANGE);
        }

        #[test]
        fn reorg_rollback_survives_restart() {
            use tempfile::tempdir;

            let dir = tempdir().unwrap();
            let path = dir.path().join("reorg.dat");
            let (fund, send);
            {
                let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
                let wallet = WalletDb::create_persistent(&path, Network::Mainnet, hd).unwrap();
                (fund, send) = fixture(&wallet);
                wallet.save().unwrap();
                scan(&wallet, 1, std::slice::from_ref(&fund));
                wallet.save_incremental().unwrap();
                scan(&wallet, 2, std::slice::from_ref(&send));
                wallet.save_incremental().unwrap();

                wallet.handle_reorg(1);
                wallet.save_incremental().unwrap();
                assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
            }
            let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
            assert_eq!(
                outpoints(&wallet),
                HashSet::from([OutPoint::new(fund.txid(), 0)])
            );
            assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
            assert!(wallet.get_transaction(&send.txid()).is_none());
        }

        /// An active chain for `sync_to_tip`: blocks at heights 1.., hashed
        /// per branch so two branches differ
        struct TestChain(Vec<Block>, u8);

        impl TestChain {
            fn new(branch: u8, blocks: &[&[Transaction]]) -> Self {
                TestChain(
                    blocks
                        .iter()
                        .map(|txs| Block {
                            transactions: txs.to_vec(),
                            ..Default::default()
                        })
                        .collect(),
                    branch,
                )
            }

            fn hash_at(&self, h: u32) -> Option<Hash256> {
                (h >= 1 && h as usize <= self.0.len()).then(|| block_hash(h, self.1))
            }

            fn block_at(&self, h: u32) -> Option<(Hash256, Block)> {
                Some((self.hash_at(h)?, self.0[h as usize - 1].clone()))
            }

            fn sync(&self, wallet: &WalletDb) -> Vec<u32> {
                wallet.sync_to_tip(
                    self.0.len() as u32,
                    |h| self.hash_at(h),
                    |h| self.block_at(h),
                )
            }
        }

        #[test]
        fn sync_scans_every_block_of_a_reorg() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let branch_a = TestChain::new(0, &[std::slice::from_ref(&fund), &[]]);
            assert!(branch_a.sync(&wallet).is_empty());
            assert_eq!(wallet.last_scan_height(), 2);

            // Branch B replaces block 2 and adds 3. The spend sits in the middle
            // block, which is not the block that triggered the reorg.
            let branch_b = TestChain::new(
                1,
                &[
                    std::slice::from_ref(&fund),
                    std::slice::from_ref(&send),
                    &[],
                ],
            );
            wallet.handle_reorg(1);
            assert_eq!(wallet.last_scan_height(), 1);
            branch_b.sync(&wallet);

            assert_eq!(
                outpoints(&wallet),
                HashSet::from([OutPoint::new(send.txid(), 1)])
            );
            assert_eq!(wallet.last_scan_height(), 3);
        }

        #[test]
        fn sync_rolls_back_chain_switch_it_was_not_told_about() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let branch_a = TestChain::new(
                0,
                &[std::slice::from_ref(&fund), std::slice::from_ref(&send)],
            );
            branch_a.sync(&wallet);
            assert_eq!(wallet.get_balance().as_sat(), CHANGE);

            // invalidateblock on block 2, then two new blocks without the send;
            // no reorg notification reaches the wallet
            let branch_b = TestChain::new(1, &[std::slice::from_ref(&fund), &[], &[]]);
            let switched = |h: u32| {
                if h == 1 {
                    Some(block_hash(1, 0))
                } else {
                    branch_b.hash_at(h)
                }
            };
            wallet.sync_to_tip(3, switched, |h| branch_b.block_at(h));

            assert_eq!(
                outpoints(&wallet),
                HashSet::from([OutPoint::new(fund.txid(), 0)])
            );
            assert_eq!(wallet.get_balance().as_sat(), 100 * COIN);
            assert!(wallet.get_transaction(&send.txid()).is_none());
            assert_eq!(wallet.last_scan_height(), 3);
        }

        #[test]
        fn sync_scans_in_order_from_last_height() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let chain = TestChain::new(
                0,
                &[
                    &[],
                    std::slice::from_ref(&fund),
                    std::slice::from_ref(&send),
                ],
            );
            // A notification for block 3 arrives while the wallet is at 0: the
            // funding block 2 is scanned first, so the spend in 3 is not lost
            let mut order = Vec::new();
            wallet.sync_to_tip(
                3,
                |h| chain.hash_at(h),
                |h| {
                    order.push(h);
                    chain.block_at(h)
                },
            );
            assert_eq!(order, vec![1, 2, 3]);
            assert_eq!(wallet.get_balance().as_sat(), CHANGE);

            // Already at the tip: nothing is scanned again
            let mut again = 0;
            wallet.sync_to_tip(
                3,
                |h| chain.hash_at(h),
                |_| {
                    again += 1;
                    None
                },
            );
            assert_eq!(again, 0);
        }

        #[test]
        fn sync_skips_unreadable_block() {
            let wallet = create_test_wallet();
            let (fund, _) = fixture(&wallet);
            let chain = TestChain::new(0, &[std::slice::from_ref(&fund), &[], &[]]);
            let missing = wallet.sync_to_tip(
                3,
                |h| chain.hash_at(h),
                |h| (h != 2).then(|| chain.block_at(h)).flatten(),
            );
            assert_eq!(missing, vec![2]);
            assert_eq!(wallet.last_scan_height(), 3);
        }

        #[test]
        fn chain_rebuild_restores_coins_after_sync() {
            use tempfile::tempdir;

            let dir = tempdir().unwrap();
            let path = dir.path().join("rebuild.dat");
            let (fund, send);
            let chain;
            {
                let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
                let wallet = WalletDb::create_persistent(&path, Network::Mainnet, hd).unwrap();
                (fund, send) = fixture(&wallet);
                chain = TestChain::new(
                    0,
                    &[
                        std::slice::from_ref(&fund),
                        std::slice::from_ref(&send),
                        &[],
                    ],
                );
                chain.sync(&wallet);
                wallet.save().unwrap();
                assert_eq!(wallet.get_balance().as_sat(), CHANGE);
            }

            // Restart on an empty chain (chainstate deleted): the startup sync,
            // then reconciliation against a UTXO set that has nothing yet
            let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
            TestChain::new(0, &[]).sync(&wallet);
            wallet.reconcile_utxos(0, |_| false);
            wallet.save_incremental().unwrap();

            // The chain syncs again; the wallet follows it block by block
            chain.sync(&wallet);
            assert_eq!(
                outpoints(&wallet),
                HashSet::from([OutPoint::new(send.txid(), 1)])
            );
            assert_eq!(wallet.get_balance().as_sat(), CHANGE);
            assert!(wallet.get_transaction(&fund.txid()).is_some());
            assert_eq!(wallet.last_scan_height(), 3);
        }

        #[test]
        fn reconcile_keeps_coins_above_the_chain_tip() {
            let wallet = create_test_wallet();
            let addr = wallet.new_receiving_address().unwrap();
            let low = tx(
                &[(Hash256::from_bytes([1u8; 32]), 0)],
                vec![(5 * COIN, mine(&addr))],
            );
            let high = tx(
                &[(Hash256::from_bytes([2u8; 32]), 0)],
                vec![(7 * COIN, mine(&addr))],
            );
            let chain = TestChain::new(
                0,
                &[std::slice::from_ref(&low), std::slice::from_ref(&high)],
            );
            chain.sync(&wallet);

            // The chain is back at height 1 and has neither coin
            assert_eq!(wallet.reconcile_utxos(1, |_| false), 1);
            assert_eq!(
                outpoints(&wallet),
                HashSet::from([OutPoint::new(high.txid(), 0)])
            );

            // The dropped coin is not marked spent: a scan of its block finds it
            wallet.rescan(1, 1, 2, |h| chain.block_at(h));
            assert_eq!(wallet.get_balance().as_sat(), 12 * COIN);
        }

        #[test]
        fn partial_rescan_finds_coin_marked_spent_without_a_block() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let chain = TestChain::new(
                0,
                &[
                    std::slice::from_ref(&fund),
                    std::slice::from_ref(&send),
                    &[],
                ],
            );
            chain.sync(&wallet);
            // Dropped earlier as missing from the chain, with no spending block
            let change = OutPoint::new(send.txid(), 1);
            wallet.spend_utxo(&change);
            assert_eq!(wallet.get_balance().as_sat(), 0);

            // rescanblockchain from the coin's block
            let (scanned, unreadable) = wallet.rescan(2, 3, 3, |h| chain.block_at(h));
            assert_eq!((scanned, unreadable), (2, None));
            assert_eq!(outpoints(&wallet), HashSet::from([change]));
            assert_eq!(wallet.get_balance().as_sat(), CHANGE);

            // and from below it
            wallet.spend_utxo(&change);
            wallet.rescan(1, 3, 3, |h| chain.block_at(h));
            assert_eq!(outpoints(&wallet), HashSet::from([change]));
        }

        #[test]
        fn partial_rescan_keeps_marked_coin_spent_in_range() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let spend_change = tx(&[(send.txid(), 1)], vec![(CHANGE - 1_000_000, stranger())]);
            let chain = TestChain::new(
                0,
                &[
                    std::slice::from_ref(&fund),
                    std::slice::from_ref(&send),
                    &[],
                    std::slice::from_ref(&spend_change),
                ],
            );
            // The wallet missed block 4 and dropped the change coin
            wallet.sync_to_tip(3, |h| chain.hash_at(h), |h| chain.block_at(h));
            let change = OutPoint::new(send.txid(), 1);
            wallet.spend_utxo(&change);

            wallet.rescan(2, 4, 4, |h| chain.block_at(h));
            assert!(outpoints(&wallet).is_empty());
            assert_eq!(wallet.get_balance().as_sat(), 0);
            assert!(wallet.get_transaction(&spend_change.txid()).is_some());
        }

        #[test]
        fn rescan_stopping_below_tip_keeps_spent_mark() {
            let wallet = create_test_wallet();
            let (fund, send) = fixture(&wallet);
            let chain = TestChain::new(
                0,
                &[
                    std::slice::from_ref(&fund),
                    std::slice::from_ref(&send),
                    &[],
                ],
            );
            chain.sync(&wallet);
            // The spend may lie above the range, so the mark stays
            wallet.spend_utxo(&OutPoint::new(send.txid(), 1));
            wallet.rescan(2, 2, 3, |h| chain.block_at(h));
            assert!(outpoints(&wallet).is_empty());
        }
    }

    mod vaults {
        use super::*;
        use divi_primitives::transaction::{OutPoint as TxOutPoint, Transaction, TxIn, TxOut};

        const COIN: i64 = 100_000_000;

        /// A non-coinbase transaction paying `outputs`, spending a coin of nobody
        fn pay(outputs: Vec<(i64, Script)>) -> Transaction {
            Transaction {
                version: 1,
                vin: vec![TxIn {
                    prevout: TxOutPoint {
                        txid: Hash256::from_bytes([0xee; 32]),
                        vout: 0,
                    },
                    script_sig: Script::default(),
                    sequence: 0xffffffff,
                }],
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

        fn hash20(addr: &Address) -> [u8; 20] {
            let mut h = [0u8; 20];
            h.copy_from_slice(addr.hash.as_bytes());
            h
        }

        fn register(wallet: &WalletDb, owner: [u8; 20], manager: &Address, script: &Script) {
            wallet.store_vault(VaultMetadata {
                owner_address: Address::from_pubkey_hash(
                    Hash160::from_bytes(owner),
                    wallet.network(),
                )
                .to_string(),
                manager_address: manager.to_string(),
                vault_script: script.as_bytes().to_vec(),
                funding_txid: [0u8; 32],
            });
        }

        /// a manager's registered vault output is never part of the
        /// plain spendable set, so ordinary coin selection cannot pick it.
        #[test]
        fn manager_vault_output_is_not_spendable() {
            let wallet = create_test_wallet();
            let manager = wallet.new_receiving_address().unwrap();
            let plain = wallet.new_receiving_address().unwrap();
            let vault =
                divi_script::StakingVaultScript::new([0x11; 20], hash20(&manager)).to_script();
            register(&wallet, [0x11; 20], &manager, &vault);
            let tx = pay(vec![
                (500 * COIN, vault.clone()),
                (50 * COIN, Script::new_p2pkh(plain.hash.as_bytes())),
            ]);
            wallet.scan_transaction(&tx, Some(Hash256::from_bytes([1; 32])), Some(10), None);
            assert_eq!(wallet.get_utxos().len(), 2, "manager tracks its vault");

            let spendable = wallet.get_spendable_utxos(20, 1);
            assert_eq!(spendable.len(), 1);
            assert_eq!(spendable[0].value.as_sat(), 50 * COIN);
            let selection = wallet
                .select_coins(Amount::from_sat(COIN), 10, 2, 20, 1)
                .unwrap();
            assert!(selection
                .utxos
                .iter()
                .all(|u| !divi_script::is_staking_vault_script(&u.script_pubkey)));
        }

        /// removevault on the manager drops the vault outputs, and the
        /// drop survives a restart. A wallet written by 0.2.6 (vault removed,
        /// outputs left behind) is cleaned when it is opened.
        #[test]
        fn removevault_drops_manager_vault_outputs_persistently() {
            use tempfile::tempdir;

            let dir = tempdir().unwrap();
            let path = dir.path().join("manager.dat");
            let vault;
            {
                let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
                let wallet = WalletDb::create_persistent(&path, Network::Mainnet, hd).unwrap();
                let manager = wallet.new_receiving_address().unwrap();
                vault =
                    divi_script::StakingVaultScript::new([0x22; 20], hash20(&manager)).to_script();
                register(&wallet, [0x22; 20], &manager, &vault);
                let tx = pay(vec![(500 * COIN, vault.clone())]);
                wallet.scan_transaction(&tx, Some(Hash256::from_bytes([2; 32])), Some(10), None);
                wallet.save().unwrap();
                assert_eq!(wallet.get_utxos().len(), 1);

                assert!(wallet.remove_vault(vault.as_bytes()));
                assert!(wallet.get_utxos().is_empty(), "removed vault still held");
                assert_eq!(wallet.get_balance(), Amount::ZERO);
                wallet.save_incremental().unwrap();
            }
            let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
            assert!(wallet.get_vault(vault.as_bytes()).is_none());
            assert!(
                wallet.get_utxos().is_empty(),
                "removed vault output came back after restart"
            );
            assert_eq!(wallet.get_balance(), Amount::ZERO);
        }

        /// a wallet left by 0.2.6 removevault (metadata gone, the vault
        /// output still stored) drops that output when it is opened.
        #[test]
        fn open_drops_vault_outputs_left_by_old_removevault() {
            use tempfile::tempdir;

            let dir = tempdir().unwrap();
            let path = dir.path().join("old-manager.dat");
            {
                let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
                let wallet = WalletDb::create_persistent(&path, Network::Mainnet, hd).unwrap();
                let manager = wallet.new_receiving_address().unwrap();
                let vault =
                    divi_script::StakingVaultScript::new([0x33; 20], hash20(&manager)).to_script();
                register(&wallet, [0x33; 20], &manager, &vault);
                let tx = pay(vec![(500 * COIN, vault.clone())]);
                wallet.scan_transaction(&tx, Some(Hash256::from_bytes([3; 32])), Some(10), None);
                wallet.save().unwrap();
                // What 0.2.6 removevault did: forget the metadata only
                wallet.vaults.write().remove(vault.as_bytes());
                wallet
                    .db
                    .as_ref()
                    .unwrap()
                    .remove_vault(vault.as_bytes())
                    .unwrap();
                assert_eq!(wallet.get_utxos().len(), 1);
            }
            let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
            assert!(wallet.get_utxos().is_empty());
            assert_eq!(wallet.get_balance(), Amount::ZERO);
            drop(wallet);
            // and the deletion reached the disk
            let wallet = WalletDb::open(&path, Network::Mainnet).unwrap();
            assert!(wallet.db.as_ref().unwrap().load_utxos().unwrap().is_empty());
        }

        /// A registered vault whose owner and manager keys are both in the
        /// wallet is owned, and Divi Core does not stake owned vault coins
        /// (AvailableUtxoCalculator.cpp:28-31): only a vault managed for
        /// someone else is staked.
        #[test]
        fn vault_with_owner_and_manager_keys_is_not_staked() {
            let wallet = create_test_wallet();
            let owner = wallet.new_receiving_address().unwrap();
            let manager = wallet.new_receiving_address().unwrap();
            let vault =
                divi_script::StakingVaultScript::new(hash20(&owner), hash20(&manager)).to_script();
            register(&wallet, hash20(&owner), &manager, &vault);
            let tx = pay(vec![(300 * COIN, vault.clone())]);
            wallet.scan_transaction(&tx, Some(Hash256::from_bytes([6; 32])), Some(10), None);

            assert_eq!(wallet.vault_role(&vault), Some(VaultRole::Owned));
            assert!(wallet.get_stakeable_vault_utxos(20, 1).is_empty());

            // The same vault managed for someone else is staked
            let other = wallet.new_receiving_address().unwrap();
            let managed =
                divi_script::StakingVaultScript::new([0x55; 20], hash20(&other)).to_script();
            register(&wallet, [0x55; 20], &other, &managed);
            let tx = pay(vec![(300 * COIN, managed.clone())]);
            wallet.scan_transaction(&tx, Some(Hash256::from_bytes([7; 32])), Some(10), None);
            let stakeable = wallet.get_stakeable_vault_utxos(20, 1);
            assert_eq!(stakeable.len(), 1);
            assert_eq!(stakeable[0].0.script_pubkey, managed);
        }

        /// `lockunspent` locks a coin for the whole wallet, in memory
        #[test]
        fn locked_coin_is_recorded_until_unlocked() {
            let wallet = create_test_wallet();
            let coin = TxOutPoint::new(Hash256::from_bytes([8; 32]), 1);
            assert!(!wallet.is_coin_locked(&coin));
            wallet.set_coin_locked(coin, true);
            assert!(wallet.is_coin_locked(&coin));
            assert_eq!(wallet.locked_coins(), vec![coin]);
            wallet.set_coin_locked(coin, false);
            assert!(!wallet.is_coin_locked(&coin));
            assert!(wallet.locked_coins().is_empty());
        }

        /// the owner key alone makes a vault output ours (registered
        /// or not), outside the plain spendable set and not stakeable.
        #[test]
        fn owner_key_alone_tracks_vault_as_owned() {
            let wallet = create_test_wallet();
            let owner = wallet.new_receiving_address().unwrap();
            let vault =
                divi_script::StakingVaultScript::new(hash20(&owner), [0x44; 20]).to_script();
            let tx = pay(vec![(300 * COIN, vault.clone())]);
            wallet.scan_transaction(&tx, Some(Hash256::from_bytes([4; 32])), Some(10), None);

            assert!(wallet.is_mine_script(&vault));
            assert_eq!(wallet.vault_role(&vault), Some(VaultRole::Owned));
            assert_eq!(wallet.get_utxos().len(), 1);
            assert!(wallet.get_spendable_utxos(20, 1).is_empty());
            assert_eq!(wallet.get_owned_vault_utxos(20, 1).len(), 1);
            assert!(wallet.get_stakeable_vault_utxos(20, 1).is_empty());

            // Registering it (fundvault does) does not let the owner stake it
            register(
                &wallet,
                hash20(&owner),
                &Address::from_pubkey_hash(Hash160::from_bytes([0x44; 20]), wallet.network()),
                &vault,
            );
            assert!(wallet.get_stakeable_vault_utxos(20, 1).is_empty());
            // and removevault does not drop the owner's coins
            assert!(wallet.remove_vault(vault.as_bytes()));
            assert_eq!(wallet.get_owned_vault_utxos(20, 1).len(), 1);
        }

        /// A stake reward paid to a vault we own is in no balance until it
        /// matures: Divi Core's getimmaturebalance counts spendable coins
        /// only, getbalance mature ones (wallet.cpp:1395-1422)
        #[test]
        fn owned_vault_reward_is_not_immature_balance() {
            let wallet = create_test_wallet();
            let owner = wallet.new_receiving_address().unwrap();
            let vault =
                divi_script::StakingVaultScript::new(hash20(&owner), [0x44; 20]).to_script();
            let mut coinstake = pay(vec![(0, Script::default()), (300 * COIN, vault)]);
            coinstake.vout[0].value = Amount::ZERO;
            assert!(coinstake.is_coinstake());
            wallet.scan_transaction(
                &coinstake,
                Some(Hash256::from_bytes([4; 32])),
                Some(10),
                None,
            );
            wallet.set_last_scan_height(15);

            assert_eq!(wallet.get_immature_balance(15, 20), Amount::ZERO);
            assert_eq!(wallet.get_balance(), Amount::ZERO);
            wallet.set_last_scan_height(30);
            assert_eq!(wallet.get_balance(), Amount::from_sat(300 * COIN));
        }

        /// The manager key counts only for a registered vault.
        #[test]
        fn manager_key_needs_registration() {
            let wallet = create_test_wallet();
            let manager = wallet.new_receiving_address().unwrap();
            let vault =
                divi_script::StakingVaultScript::new([0x55; 20], hash20(&manager)).to_script();
            assert_eq!(wallet.vault_role(&vault), None);
            register(&wallet, [0x55; 20], &manager, &vault);
            assert_eq!(wallet.vault_role(&vault), Some(VaultRole::Managed));
        }
    }

    fn timed_encrypted_wallet(dir: &std::path::Path) -> (Arc<WalletDb>, Address) {
        let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet =
            WalletDb::create_persistent(&dir.join("wallet"), Network::Testnet, hd).unwrap();
        wallet.save().unwrap();
        wallet.encrypt_wallet("pw").unwrap();
        wallet.unlock("pw", 60).unwrap();
        let addr = wallet.new_receiving_address().unwrap();
        wallet.lock();
        (Arc::new(wallet), addr)
    }

    /// NODE-6: a timed unlock drops the secrets when it runs out, even if no
    /// RPC call comes along to check the lock.
    #[test]
    fn node06_timed_unlock_relocks_without_a_caller() {
        let dir = tempfile::tempdir().unwrap();
        let (wallet, addr) = timed_encrypted_wallet(dir.path());
        wallet.unlock("pw", 1).unwrap();
        assert!(wallet.get_key_by_address(&addr).unwrap().secret.is_some());
        WalletDb::start_auto_lock(&wallet);
        std::thread::sleep(std::time::Duration::from_millis(2_200));
        // Read the keystore directly: is_locked() would lock it itself
        assert!(wallet.get_key_by_address(&addr).unwrap().secret.is_none());
        assert!(*wallet.locked.read());
    }

    /// NODE-6: the auto-lock thread ends with the wallet.
    #[test]
    fn node06_auto_lock_thread_lets_the_wallet_go() {
        let dir = tempfile::tempdir().unwrap();
        let (wallet, _) = timed_encrypted_wallet(dir.path());
        WalletDb::start_auto_lock(&wallet);
        let weak = Arc::downgrade(&wallet);
        drop(wallet);
        assert!(weak.upgrade().is_none());
    }

    /// NODE-16: the mnemonic is not given out after the unlock has run out,
    /// nor while unlocked for staking only.
    #[test]
    fn node16_mnemonic_needs_a_live_full_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (wallet, _) = timed_encrypted_wallet(dir.path());
        wallet.unlock_for("pw", 60, true).unwrap();
        assert!(wallet.mnemonic().is_none());
        wallet.lock();
        wallet.unlock("pw", 1).unwrap();
        assert!(wallet.mnemonic().is_some());
        std::thread::sleep(std::time::Duration::from_millis(1_200));
        assert!(wallet.mnemonic().is_none());
    }

    /// NODE-16: no new key is derived from the seed after the unlock has run
    /// out; as when locked, the address comes from the pre-generated keypool.
    #[test]
    fn node16_new_address_after_timeout_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (wallet, _) = timed_encrypted_wallet(dir.path());
        wallet.unlock("pw", 1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1_200));
        let pool_before = wallet.keypool_size();
        assert!(pool_before > 0);
        let addr = wallet.new_receiving_address().unwrap();
        assert!(*wallet.locked.read());
        assert_eq!(wallet.keypool_size(), pool_before - 1);
        assert!(wallet.is_mine(&addr));
    }

    fn files_containing(dir: &std::path::Path, needle: &[u8]) -> Vec<std::path::PathBuf> {
        let mut hits = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                hits.extend(files_containing(&path, needle));
            } else if std::fs::read(&path)
                .unwrap()
                .windows(needle.len())
                .any(|w| w == needle)
            {
                hits.push(path);
            }
        }
        hits
    }

    /// NODE-9: after encryptwallet no file in the wallet directory still holds
    /// the plaintext seed, including the write-ahead log, which other column
    /// families with unflushed writes would otherwise keep alive.
    #[test]
    fn node09_encryptwallet_leaves_no_plaintext_seed_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(&path, Network::Testnet, hd).unwrap();
        wallet.save().unwrap();
        wallet.new_receiving_address().unwrap();
        // An unflushed write in an unrelated column family
        wallet.db.as_ref().unwrap().mark_address_used("x").unwrap();
        assert!(!files_containing(&path, TEST_MNEMONIC.as_bytes()).is_empty());

        wallet.encrypt_wallet("pw").unwrap();
        drop(wallet);
        assert_eq!(
            files_containing(&path, TEST_MNEMONIC.as_bytes()),
            Vec::<std::path::PathBuf>::new()
        );
        // The encrypted wallet still opens and unlocks
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        wallet.unlock("pw", 60).unwrap();
        assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
    }

    // Wallet encryption at rest (NODE-7, NODE-8, NODE-19)

    const LEGACY_PASSPHRASE: &str = "legacy fixture passphrase";

    /// A copy of a wallet written by a build before Argon2id (PBKDF2 and
    /// AES-256-CBC): the test mnemonic, two receiving addresses, one change
    /// address, and imported keys 0x11.. (compressed) and 0x22.. (uncompressed)
    fn legacy_wallet() -> (tempfile::TempDir, std::path::PathBuf) {
        fn copy(from: &std::path::Path, to: &std::path::Path) {
            std::fs::create_dir_all(to).unwrap();
            for entry in std::fs::read_dir(from).unwrap() {
                let entry = entry.unwrap();
                let target = to.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy(&entry.path(), &target);
                } else {
                    std::fs::copy(entry.path(), target).unwrap();
                }
            }
        }
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/legacy_wallet_v1");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        copy(&fixture.join("walletdb"), &path);
        (dir, path)
    }

    fn legacy_fixture_addresses() -> Vec<String> {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/legacy_wallet_v1/addresses.txt");
        std::fs::read_to_string(fixture)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Every address of the fixture is there, and every key has its secret
    fn assert_fixture_keys_whole(wallet: &WalletDb) {
        let mut addresses: Vec<String> = wallet
            .get_addresses()
            .iter()
            .map(|a| a.to_string())
            .collect();
        addresses.sort();
        for expected in legacy_fixture_addresses() {
            assert!(addresses.contains(&expected), "missing {expected}");
        }
        assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
        let keys = wallet.keystore.get_all_keys_with_hashes();
        for (_, entry) in &keys {
            if !entry.is_watch_only {
                let secret = entry.secret.as_ref().expect("secret restored");
                assert!(secret.public_key() == entry.public);
            }
        }
        for byte in [0x11u8, 0x22] {
            let secret = divi_crypto::keys::SecretKey::from_bytes(&[byte; 32]).unwrap();
            let entry = keys
                .iter()
                .find(|(_, e)| e.public == secret.public_key())
                .expect("imported key present");
            assert_eq!(
                entry.1.secret.as_ref().unwrap().as_bytes(),
                secret.as_bytes()
            );
            assert_eq!(entry.1.compressed, byte == 0x11);
        }
    }

    /// Replace the stored blob of each encrypted private key with `f(index, blob)`
    fn rewrite_secret_blobs(wallet: &WalletDb, f: impl Fn(usize, &[Vec<u8>]) -> Vec<u8>) {
        let db = wallet.db.as_ref().unwrap();
        let secrets = db.load_encrypted_secrets().unwrap();
        let blobs: Vec<Vec<u8>> = secrets.iter().map(|(_, b)| b.clone()).collect();
        let mut batch = db.create_batch();
        for (i, (hash, _)) in secrets.iter().enumerate() {
            batch.put_cf(db.cf_keys(), secret_record_key(hash), f(i, &blobs));
        }
        db.write_batch_sync(batch).unwrap();
    }

    #[test]
    fn node07_legacy_wallet_opens_and_moves_to_argon2id() {
        let (_dir, path) = legacy_wallet();
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        let db = wallet.db.as_ref().unwrap();
        assert_eq!(
            db.load_kdf_params().unwrap(),
            None,
            "fixture is the old format"
        );
        let (old_salt, _) = db.load_encryption_metadata().unwrap().unwrap();
        assert!(matches!(
            wallet.unlock("not the passphrase", 0),
            Err(WalletError::WrongPassphrase)
        ));
        assert_eq!(db.load_kdf_params().unwrap(), None);

        wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
        assert_fixture_keys_whole(&wallet);
        let db = wallet.db.as_ref().unwrap();
        assert_eq!(db.load_kdf_params().unwrap(), Some(KdfParams::DEFAULT));
        assert_ne!(db.load_encryption_metadata().unwrap().unwrap().0, old_salt);
        // A key made after the upgrade is stored in the new format too
        let fresh = wallet.new_receiving_address().unwrap();
        wallet.lock();
        drop(wallet);

        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        assert!(matches!(
            wallet.unlock("not the passphrase", 0),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.unlock(LEGACY_PASSPHRASE, 0).unwrap();
        assert_fixture_keys_whole(&wallet);
        let entry = wallet.keystore.get_key(&fresh.hash).unwrap();
        assert!(entry.secret.is_some());
        // Every record now opens only as an authenticated record
        let master = MasterKey {
            key: Zeroizing::new(
                wallet
                    .decrypted_master_key
                    .read()
                    .as_ref()
                    .unwrap()
                    .key
                    .to_vec(),
            ),
            aead: false,
        };
        let db = wallet.db.as_ref().unwrap();
        for (hash, blob) in db.load_encrypted_secrets().unwrap() {
            assert!(master
                .open_record(&secret_record_key(&hash), &blob)
                .is_err());
        }
    }

    #[test]
    fn node07_change_passphrase_moves_a_legacy_wallet() {
        let (_dir, path) = legacy_wallet();
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        assert!(matches!(
            wallet.change_passphrase("not the passphrase", "new passphrase"),
            Err(WalletError::WrongPassphrase)
        ));
        wallet
            .change_passphrase(LEGACY_PASSPHRASE, "new passphrase")
            .unwrap();
        let db = wallet.db.as_ref().unwrap();
        assert_eq!(db.load_kdf_params().unwrap(), Some(KdfParams::DEFAULT));
        drop(wallet);

        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        assert!(matches!(
            wallet.unlock(LEGACY_PASSPHRASE, 0),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.unlock("new passphrase", 0).unwrap();
        assert_fixture_keys_whole(&wallet);
    }

    #[test]
    fn node07_new_wallets_store_the_argon2id_cost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(&path, Network::Testnet, hd).unwrap();
        wallet.new_receiving_address().unwrap();
        wallet.encrypt_wallet("pw").unwrap();
        let db = wallet.db.as_ref().unwrap();
        assert_eq!(db.load_kdf_params().unwrap(), Some(KdfParams::DEFAULT));
        assert!(matches!(
            wallet.unlock("wrong", 0),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.change_passphrase("pw", "pw2").unwrap();
        assert!(matches!(
            wallet.unlock("pw", 0),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.unlock("pw2", 0).unwrap();
        assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));

        // A cost record this build does not know is refused, not guessed at
        let mut batch = db.create_batch();
        batch.put_cf(db.cf_metadata(), KEY_KDF_PARAMS, [9u8; 13]);
        db.write_batch_sync(batch).unwrap();
        wallet.lock();
        assert!(matches!(
            wallet.unlock("pw2", 0),
            Err(WalletError::Storage(_))
        ));
    }

    #[test]
    fn node08_changed_or_swapped_records_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let hd = HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap();
        let wallet = WalletDb::create_persistent(&path, Network::Testnet, hd).unwrap();
        wallet.new_receiving_address().unwrap();
        wallet.new_receiving_address().unwrap();
        wallet.encrypt_wallet("pw").unwrap();
        let db = wallet.db.as_ref().unwrap();
        let original = db.load_encrypted_secrets().unwrap();
        assert!(original.len() >= 2);
        let restore = |wallet: &WalletDb| {
            let db = wallet.db.as_ref().unwrap();
            let mut batch = db.create_batch();
            for (hash, blob) in &original {
                batch.put_cf(db.cf_keys(), secret_record_key(hash), blob);
            }
            db.write_batch_sync(batch).unwrap();
        };

        // One flipped bit in a private key record
        rewrite_secret_blobs(&wallet, |i, blobs| {
            let mut blob = blobs[i].clone();
            if i == 0 {
                let last = blob.len() - 1;
                blob[last] ^= 0x01;
            }
            blob
        });
        assert!(matches!(
            wallet.unlock("pw", 0),
            Err(WalletError::Storage(_))
        ));
        assert!(wallet.is_locked());

        // Two records swapped
        restore(&wallet);
        rewrite_secret_blobs(&wallet, |i, blobs| blobs[(i + 1) % blobs.len()].clone());
        assert!(matches!(
            wallet.unlock("pw", 0),
            Err(WalletError::Storage(_))
        ));

        // The mnemonic changed, or moved into a key's record
        restore(&wallet);
        let mnemonic = db.load_encrypted_mnemonic().unwrap().unwrap();
        let mut flipped = mnemonic.clone();
        flipped[30] ^= 0x80;
        let mut batch = db.create_batch();
        batch.put_cf(db.cf_metadata(), KEY_ENCRYPTED_MNEMONIC, &flipped);
        db.write_batch_sync(batch).unwrap();
        assert!(matches!(
            wallet.unlock("pw", 0),
            Err(WalletError::Storage(_))
        ));
        let mut batch = db.create_batch();
        batch.put_cf(db.cf_metadata(), KEY_ENCRYPTED_MNEMONIC, &mnemonic);
        db.write_batch_sync(batch).unwrap();

        // The sealed master key changed
        let (salt, sealed) = db.load_encryption_metadata().unwrap().unwrap();
        let mut bad = sealed.clone();
        bad[40] ^= 0x01;
        db.store_encryption_metadata(&salt, &bad).unwrap();
        assert!(matches!(
            wallet.unlock("pw", 0),
            Err(WalletError::WrongPassphrase)
        ));
        db.store_encryption_metadata(&salt, &sealed).unwrap();

        wallet.unlock("pw", 0).unwrap();
        assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
    }

    #[test]
    fn node19_secret_under_another_address_is_refused() {
        // The old format has no authentication, so swapped records decrypt;
        // the public key check is what catches them
        let (_dir, path) = legacy_wallet();
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        rewrite_secret_blobs(&wallet, |i, blobs| blobs[(i + 1) % blobs.len()].clone());
        match wallet.unlock(LEGACY_PASSPHRASE, 0) {
            Err(WalletError::Storage(message)) => {
                assert!(
                    message.contains("does not match its public key"),
                    "{message}"
                )
            }
            other => panic!("expected a storage error, got {:?}", other.err()),
        }
        assert!(wallet.is_locked());
        // Nothing was migrated from the bad records
        assert_eq!(wallet.db.as_ref().unwrap().load_kdf_params().unwrap(), None);
    }

    // Seed-only and mnemonic+passphrase wallets at rest (NODE-7, NODE-9)

    const SEED_ONLY: [u8; 32] = [
        0x3c, 0x91, 0x07, 0xe4, 0x5a, 0xd2, 0x68, 0x1f, 0xb3, 0x2e, 0x84, 0xc6, 0x7d, 0x09, 0xf5,
        0x40, 0x9b, 0x13, 0xae, 0x62, 0xd8, 0x37, 0x5c, 0xe1, 0x0a, 0x76, 0xbf, 0x24, 0x8d, 0x59,
        0xc3, 0x6e,
    ];
    const BIP39_PASSPHRASE: &str = "an extra bip39 passphrase";

    /// Public keys of the first receiving keys `hd` derives as a new wallet
    fn reference_pubkeys(hd: HdWallet) -> Vec<divi_crypto::keys::PublicKey> {
        let hd = with_core_coin_type(hd, Network::Testnet);
        (0..60)
            .map(|i| {
                hd.derive_receiving(0, i)
                    .unwrap()
                    .secret_key()
                    .unwrap()
                    .public_key()
            })
            .collect()
    }

    fn assert_derived_from(
        wallet: &WalletDb,
        addresses: &[Address],
        reference: &[divi_crypto::keys::PublicKey],
    ) {
        for address in addresses {
            let entry = wallet.get_key_by_address(address).expect("address kept");
            assert!(
                reference.contains(&entry.public),
                "{address} not from the seed"
            );
            assert!(entry.secret.is_some(), "{address} has its secret");
        }
    }

    /// Rewrite an encrypted wallet's records in the format of builds before
    /// Argon2id (PBKDF2 and AES-256-CBC), as an older wallet on disk would be
    fn downgrade_to_legacy(wallet: &WalletDb, passphrase: &str) {
        use crate::persistence::{KEY_ENCRYPTED_HD_SEED, KEY_ENCRYPTED_MNEMONIC_PASSPHRASE};
        let db = wallet.db.as_ref().unwrap();
        let master = open_master(db, passphrase).unwrap();
        assert!(master.aead);
        let records = decrypt_records(db, &master).unwrap();
        let legacy = MasterKey {
            key: master.key.clone(),
            aead: false,
        };
        let salt = [0x5au8; 16];
        let key = at_rest::legacy::derive_key_from_passphrase(passphrase, &salt);
        let mut batch = db.create_batch();
        batch.delete_cf(db.cf_metadata(), KEY_KDF_PARAMS);
        batch.put_cf(db.cf_metadata(), KEY_ENCRYPTION_SALT, salt);
        batch.put_cf(
            db.cf_metadata(),
            KEY_ENCRYPTED_MASTER_KEY,
            at_rest::legacy::seal_master_key(&master.key, &key),
        );
        for (record_key, plain) in [
            (KEY_ENCRYPTED_MNEMONIC, &records.mnemonic),
            (
                KEY_ENCRYPTED_MNEMONIC_PASSPHRASE,
                &records.mnemonic_passphrase,
            ),
            (KEY_ENCRYPTED_HD_SEED, &records.hd_seed),
        ] {
            if let Some(plain) = plain {
                batch.put_cf(
                    db.cf_metadata(),
                    record_key,
                    legacy.seal_record(record_key, plain),
                );
            }
        }
        for (hash, secret) in &records.secrets {
            let record_key = secret_record_key(hash);
            batch.put_cf(
                db.cf_keys(),
                &record_key,
                legacy.seal_record(&record_key, secret.as_bytes()),
            );
        }
        db.write_batch_sync(batch).unwrap();
        assert_eq!(db.load_kdf_params().unwrap(), None);
    }

    /// No plaintext record and no file of the wallet holds any of `secrets`
    fn assert_no_plaintext(wallet: WalletDb, path: &std::path::Path, secrets: &[&[u8]]) {
        let db = wallet.db.as_ref().unwrap();
        assert_eq!(db.load_mnemonic().unwrap(), None);
        assert_eq!(db.load_mnemonic_passphrase().unwrap(), None);
        assert!(db.load_hd_seed().unwrap().is_none());
        drop(wallet);
        for secret in secrets {
            assert_eq!(
                files_containing(path, secret),
                Vec::<std::path::PathBuf>::new()
            );
        }
    }

    /// Encrypt, lock, unlock, change the passphrase and reopen a wallet; then
    /// move it from the older format; every step keeps the keys the seed derives
    fn at_rest_round_trip(
        hd: HdWallet,
        reference: HdWallet,
        secrets: &[&[u8]],
    ) -> (tempfile::TempDir, WalletDb) {
        let reference = reference_pubkeys(reference);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let wallet = WalletDb::create_persistent(&path, Network::Testnet, hd).unwrap();
        let mut addresses = vec![
            wallet.new_receiving_address().unwrap(),
            wallet.new_receiving_address().unwrap(),
        ];
        wallet.save().unwrap();
        assert_derived_from(&wallet, &addresses, &reference);
        for secret in secrets {
            assert!(!files_containing(&path, secret).is_empty());
        }

        wallet.encrypt_wallet("pw").unwrap();
        assert!(wallet.is_locked());
        assert!(wallet.hd_seed().is_none() && wallet.mnemonic_passphrase().is_none());
        wallet.unlock("pw", 0).unwrap();
        addresses.push(wallet.new_receiving_address().unwrap());
        assert_derived_from(&wallet, &addresses, &reference);
        wallet.lock();
        wallet.change_passphrase("pw", "pw2").unwrap();
        assert!(matches!(
            wallet.unlock("pw", 0),
            Err(WalletError::WrongPassphrase)
        ));
        let wallet = {
            drop(wallet);
            WalletDb::open(&path, Network::Testnet).unwrap()
        };
        wallet.unlock("pw2", 0).unwrap();
        addresses.push(wallet.new_receiving_address().unwrap());
        assert_derived_from(&wallet, &addresses, &reference);
        let seed = wallet.hd_seed();
        let passphrase = wallet.mnemonic_passphrase();
        wallet.lock();

        // The same wallet written by an older build moves to the new format
        downgrade_to_legacy(&wallet, "pw2");
        let wallet = {
            drop(wallet);
            WalletDb::open(&path, Network::Testnet).unwrap()
        };
        assert!(matches!(
            wallet.unlock("pw", 0),
            Err(WalletError::WrongPassphrase)
        ));
        wallet.unlock("pw2", 0).unwrap();
        let db = wallet.db.as_ref().unwrap();
        assert_eq!(db.load_kdf_params().unwrap(), Some(KdfParams::DEFAULT));
        assert_derived_from(&wallet, &addresses, &reference);
        assert_eq!(wallet.hd_seed(), seed);
        assert_eq!(wallet.mnemonic_passphrase(), passphrase);
        addresses.push(wallet.new_receiving_address().unwrap());
        assert_derived_from(&wallet, &addresses, &reference);
        wallet.lock();
        let wallet = {
            drop(wallet);
            WalletDb::open(&path, Network::Testnet).unwrap()
        };
        wallet.unlock("pw2", 0).unwrap();
        assert_derived_from(&wallet, &addresses, &reference);
        wallet.lock();
        assert_no_plaintext(wallet, &path, secrets);
        let wallet = WalletDb::open(&path, Network::Testnet).unwrap();
        (dir, wallet)
    }

    #[test]
    fn node09_seed_only_wallet_round_trips_encrypted() {
        let hd = || HdWallet::from_seed(&SEED_ONLY, ChainMode::Divi).unwrap();
        let (_dir, wallet) = at_rest_round_trip(hd(), hd(), &[&SEED_ONLY]);
        wallet.unlock("pw2", 0).unwrap();
        assert_eq!(
            wallet.hd_seed().as_deref().map(|s| &s[..]),
            Some(&SEED_ONLY[..])
        );
        assert!(wallet.mnemonic().is_none());
    }

    #[test]
    fn node09_mnemonic_with_passphrase_round_trips_encrypted() {
        let hd = || {
            HdWallet::from_mnemonic(TEST_MNEMONIC, Some(BIP39_PASSPHRASE), ChainMode::Divi).unwrap()
        };
        // Without its passphrase the mnemonic derives other keys
        let plain = reference_pubkeys(
            HdWallet::from_mnemonic(TEST_MNEMONIC, None, ChainMode::Divi).unwrap(),
        );
        assert!(!reference_pubkeys(hd()).iter().any(|k| plain.contains(k)));
        let (_dir, wallet) = at_rest_round_trip(
            hd(),
            hd(),
            &[TEST_MNEMONIC.as_bytes(), BIP39_PASSPHRASE.as_bytes()],
        );
        wallet.unlock("pw2", 0).unwrap();
        assert_eq!(wallet.mnemonic().as_deref(), Some(TEST_MNEMONIC));
        assert_eq!(
            wallet.mnemonic_passphrase().as_deref(),
            Some(BIP39_PASSPHRASE)
        );
    }
}
