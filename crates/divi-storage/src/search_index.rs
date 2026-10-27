// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Divi Core's address index (`-addressindex`: every receive and spend per
//! address, and the unspent outputs per address) and spent index
//! (`-spentindex`: which input spent an output), kept as Core keeps them
//! (IndexDatabaseUpdateCollector.cpp, BlockConnectionService.cpp:152-192,
//! addressindex.h, spentindex.h).
//!
//! Keys are laid out as Core serializes them, so entries come back in Core's
//! order: an address's receives and spends by height, position of the
//! transaction in its block, txid, input or output index, spending flag.

use crate::database::ChainDatabase;
use crate::error::StorageError;
use crate::spent_index::{SpentIndexKey, SpentIndexValue};
use divi_primitives::amount::Amount;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use std::collections::HashMap;
use std::sync::Arc;

/// Column family of the address deltas (Core's DB_ADDRESSINDEX)
pub const CF_ADDRESS_DELTA: &str = "address_delta";
/// Column family of the unspent outputs per address (Core's DB_ADDRESSUNSPENTINDEX)
pub const CF_ADDRESS_UNSPENT: &str = "address_unspent";
/// Column family mapping an Electrum script hash (sha256 of the output
/// script) to the address type and hash the address index files it under
pub const CF_SCRIPTHASH: &str = "scripthash";
/// Column family of the spent index (shared with `SpentIndex`)
const CF_SPENT: &str = crate::spent_index::CF_SPENT_INDEX;

/// Core's address type and hash for an output script
/// (`ComputeHashbytesAndAddressTypeForScript`, IndexDatabaseUpdateCollector.cpp:12-36):
/// a staking vault is type 3 under its owner key hash (bytes 2..22), P2SH type
/// 2, P2PKH type 1. Any other script is not indexed.
pub fn address_of_script(script: &[u8]) -> Option<(u8, [u8; 20])> {
    let hash =
        |range: std::ops::Range<usize>| -> [u8; 20] { script[range].try_into().expect("20 bytes") };
    if divi_script::is_staking_vault_script(&Script::from_bytes(script.to_vec())) {
        Some((3, hash(2..22)))
    } else if divi_script::is_p2sh(script) {
        Some((2, hash(2..22)))
    } else if divi_script::is_p2pkh(script) {
        Some((1, hash(3..23)))
    } else {
        None
    }
}

/// The Electrum script hash of an output script: its sha256, in the byte
/// order it is hashed (Electrum shows it reversed)
pub fn script_hash(script: &[u8]) -> [u8; 32] {
    divi_crypto::hash::sha256(script)
}

fn address_key(address_type: u8, hash: &[u8; 20]) -> [u8; 21] {
    let mut key = [0u8; 21];
    key[0] = address_type;
    key[1..].copy_from_slice(hash);
    key
}

/// The output script of an address the index files under `address_type` 1
/// (P2PKH) or 2 (P2SH); vault scripts (type 3) cannot be rebuilt from a hash
pub fn script_of_address(address_type: u8, hash: &[u8; 20]) -> Option<Vec<u8>> {
    match address_type {
        1 => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(hash);
            s.extend_from_slice(&[0x88, 0xac]);
            Some(s)
        }
        2 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(hash);
            s.push(0x87);
            Some(s)
        }
        _ => None,
    }
}

/// A receive or spend of an address (Core's `CAddressIndexKey`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressDeltaKey {
    pub address_type: u8,
    pub hash: [u8; 20],
    pub height: u32,
    /// Position of the transaction in its block
    pub tx_index: u32,
    pub txid: Hash256,
    /// Output index for a receive, input index for a spend
    pub index: u32,
    pub spending: bool,
}

impl AddressDeltaKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(66);
        key.push(self.address_type);
        key.extend_from_slice(&self.hash);
        key.extend_from_slice(&self.height.to_be_bytes());
        key.extend_from_slice(&self.tx_index.to_be_bytes());
        key.extend_from_slice(self.txid.as_bytes());
        key.extend_from_slice(&self.index.to_le_bytes());
        key.push(self.spending as u8);
        key
    }

    fn from_bytes(key: &[u8]) -> Option<Self> {
        if key.len() != 66 {
            return None;
        }
        Some(AddressDeltaKey {
            address_type: key[0],
            hash: key[1..21].try_into().ok()?,
            height: u32::from_be_bytes(key[21..25].try_into().ok()?),
            tx_index: u32::from_be_bytes(key[25..29].try_into().ok()?),
            txid: Hash256::from_bytes(key[29..61].try_into().ok()?),
            index: u32::from_le_bytes(key[61..65].try_into().ok()?),
            spending: key[65] != 0,
        })
    }
}

/// An unspent output of an address (Core's `CAddressUnspentKey`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressUnspentKey {
    pub address_type: u8,
    pub hash: [u8; 20],
    pub txid: Hash256,
    pub index: u32,
}

impl AddressUnspentKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(57);
        key.push(self.address_type);
        key.extend_from_slice(&self.hash);
        key.extend_from_slice(self.txid.as_bytes());
        key.extend_from_slice(&self.index.to_le_bytes());
        key
    }

    fn from_bytes(key: &[u8]) -> Option<Self> {
        if key.len() != 57 {
            return None;
        }
        Some(AddressUnspentKey {
            address_type: key[0],
            hash: key[1..21].try_into().ok()?,
            txid: Hash256::from_bytes(key[21..53].try_into().ok()?),
            index: u32::from_le_bytes(key[53..57].try_into().ok()?),
        })
    }
}

/// Core's `CAddressUnspentValue`: amount, script and height
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressUnspentValue {
    pub satoshis: i64,
    pub script: Script,
    pub height: i32,
}

impl AddressUnspentValue {
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12 + self.script.len());
        v.extend_from_slice(&self.satoshis.to_le_bytes());
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(self.script.as_bytes());
        v
    }

    fn from_bytes(v: &[u8]) -> Option<Self> {
        if v.len() < 12 {
            return None;
        }
        Some(AddressUnspentValue {
            satoshis: i64::from_le_bytes(v[0..8].try_into().ok()?),
            height: i32::from_le_bytes(v[8..12].try_into().ok()?),
            script: Script::from_bytes(v[12..].to_vec()),
        })
    }
}

/// What connecting or disconnecting one block writes to the indexes
#[derive(Debug, Default)]
pub struct IndexUpdates {
    /// Deltas to write (connect) or erase (disconnect)
    pub deltas: Vec<(AddressDeltaKey, i64)>,
    /// Unspent entries: `Some` to write, `None` to erase
    pub unspent: Vec<(AddressUnspentKey, Option<AddressUnspentValue>)>,
    /// Spent entries: `Some` to write, `None` to erase
    pub spent: Vec<(SpentIndexKey, Option<SpentIndexValue>)>,
}

/// The output a spent input refers to: its amount and script
pub type PrevOut = (Amount, Script);

/// Divi Core `IndexDatabaseUpdateCollector::RecordTransaction` for every
/// transaction of a block connected at `height` (IndexDatabaseUpdateCollector.cpp:38-97).
/// `prevouts` holds the outputs the block's inputs spend.
pub fn collect_connect(
    block: &Block,
    height: u32,
    prevouts: &HashMap<OutPoint, PrevOut>,
    address_index: bool,
    spent_index: bool,
) -> IndexUpdates {
    let mut updates = IndexUpdates::default();
    for (tx_index, tx) in block.transactions.iter().enumerate() {
        let txid = tx.txid();
        let tx_index = tx_index as u32;
        if !tx.is_coinbase() && (address_index || spent_index) {
            for (j, input) in tx.vin.iter().enumerate() {
                let Some((value, script)) = prevouts.get(&input.prevout) else {
                    continue;
                };
                let address = address_of_script(script.as_bytes());
                if address_index {
                    if let Some((address_type, hash)) = address {
                        updates.deltas.push((
                            AddressDeltaKey {
                                address_type,
                                hash,
                                height,
                                tx_index,
                                txid,
                                index: j as u32,
                                spending: true,
                            },
                            -value.as_sat(),
                        ));
                        updates.unspent.push((
                            AddressUnspentKey {
                                address_type,
                                hash,
                                txid: input.prevout.txid,
                                index: input.prevout.vout,
                            },
                            None,
                        ));
                    }
                }
                if spent_index {
                    let (address_type, hash) = address.unwrap_or((0, [0; 20]));
                    updates.spent.push((
                        SpentIndexKey::new(input.prevout.txid, input.prevout.vout),
                        Some(SpentIndexValue::new(
                            txid,
                            j as u32,
                            height as i32,
                            *value,
                            address_type,
                            hash,
                        )),
                    ));
                }
            }
        }
        if address_index {
            for (k, out) in tx.vout.iter().enumerate() {
                let Some((address_type, hash)) = address_of_script(out.script_pubkey.as_bytes())
                else {
                    continue;
                };
                updates.deltas.push((
                    AddressDeltaKey {
                        address_type,
                        hash,
                        height,
                        tx_index,
                        txid,
                        index: k as u32,
                        spending: false,
                    },
                    out.value.as_sat(),
                ));
                updates.unspent.push((
                    AddressUnspentKey {
                        address_type,
                        hash,
                        txid,
                        index: k as u32,
                    },
                    Some(AddressUnspentValue {
                        satoshis: out.value.as_sat(),
                        script: out.script_pubkey.clone(),
                        height: height as i32,
                    }),
                ));
            }
        }
    }
    updates
}

/// Divi Core `IndexDatabaseUpdateCollector::ReverseTransaction` for every
/// transaction of a block disconnected at `height`, last first
/// (IndexDatabaseUpdateCollector.cpp:99-170, BlockConnectionService.cpp:238-251).
/// A restored unspent entry carries the disconnected block's height, as in
/// Core (:125-129).
pub fn collect_disconnect(
    block: &Block,
    height: u32,
    prevouts: &HashMap<OutPoint, PrevOut>,
    address_index: bool,
    spent_index: bool,
) -> IndexUpdates {
    let mut updates = IndexUpdates::default();
    for (tx_index, tx) in block.transactions.iter().enumerate().rev() {
        let txid = tx.txid();
        let tx_index = tx_index as u32;
        if address_index {
            for (k, out) in tx.vout.iter().enumerate().rev() {
                let Some((address_type, hash)) = address_of_script(out.script_pubkey.as_bytes())
                else {
                    continue;
                };
                updates.deltas.push((
                    AddressDeltaKey {
                        address_type,
                        hash,
                        height,
                        tx_index,
                        txid,
                        index: k as u32,
                        spending: false,
                    },
                    out.value.as_sat(),
                ));
                updates.unspent.push((
                    AddressUnspentKey {
                        address_type,
                        hash,
                        txid,
                        index: k as u32,
                    },
                    None,
                ));
            }
        }
        if tx.is_coinbase() {
            continue;
        }
        for (j, input) in tx.vin.iter().enumerate().rev() {
            if address_index {
                if let Some((value, script)) = prevouts.get(&input.prevout) {
                    if let Some((address_type, hash)) = address_of_script(script.as_bytes()) {
                        updates.deltas.push((
                            AddressDeltaKey {
                                address_type,
                                hash,
                                height,
                                tx_index,
                                txid,
                                index: j as u32,
                                spending: true,
                            },
                            -value.as_sat(),
                        ));
                        updates.unspent.push((
                            AddressUnspentKey {
                                address_type,
                                hash,
                                txid: input.prevout.txid,
                                index: input.prevout.vout,
                            },
                            Some(AddressUnspentValue {
                                satoshis: value.as_sat(),
                                script: script.clone(),
                                height: height as i32,
                            }),
                        ));
                    }
                }
            }
            if spent_index {
                updates.spent.push((
                    SpentIndexKey::new(input.prevout.txid, input.prevout.vout),
                    None,
                ));
            }
        }
    }
    updates
}

/// The address and spent indexes of a chain database
pub struct SearchIndex {
    db: Arc<ChainDatabase>,
    address: bool,
    spent: bool,
}

impl SearchIndex {
    pub fn new(db: Arc<ChainDatabase>, address: bool, spent: bool) -> Self {
        SearchIndex { db, address, spent }
    }

    pub fn address_enabled(&self) -> bool {
        self.address
    }

    pub fn spent_enabled(&self) -> bool {
        self.spent
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.db
            .inner_db()
            .cf_handle(name)
            .ok_or_else(|| StorageError::ChainState(format!("{} column family not found", name)))
    }

    /// Remove every address and spent index entry, before the indexes are
    /// built again
    pub fn clear(&self) -> Result<(), StorageError> {
        let db = self.db.inner_db();
        for name in [
            CF_ADDRESS_DELTA,
            CF_ADDRESS_UNSPENT,
            CF_SPENT,
            CF_SCRIPTHASH,
        ] {
            let cf = self.cf(name)?;
            loop {
                let keys: Vec<Box<[u8]>> = db
                    .iterator_cf(cf, rocksdb::IteratorMode::Start)
                    .take(10_000)
                    .map(|item| item.map(|(k, _)| k))
                    .collect::<Result<_, _>>()
                    .map_err(StorageError::Database)?;
                if keys.is_empty() {
                    break;
                }
                let mut batch = rocksdb::WriteBatch::default();
                for key in keys {
                    batch.delete_cf(cf, key);
                }
                db.write(batch).map_err(StorageError::Database)?;
            }
        }
        Ok(())
    }

    /// Write the updates of a connected block (Core
    /// `ApplyConnectionUpdateIndexToDBs`, BlockConnectionService.cpp:152-174)
    pub fn apply_connect(&self, updates: &IndexUpdates) -> Result<(), StorageError> {
        self.apply(updates, false)
    }

    /// Write the updates of a disconnected block: its deltas erased, unspent
    /// entries updated, and spent entries erased only when the address index
    /// is on, as Core's `ApplyDisconnectionUpdateIndexToDBs` does
    /// (BlockConnectionService.cpp:176-196)
    pub fn apply_disconnect(&self, updates: &IndexUpdates) -> Result<(), StorageError> {
        self.apply(updates, true)
    }

    fn apply(&self, updates: &IndexUpdates, disconnect: bool) -> Result<(), StorageError> {
        let mut batch = rocksdb::WriteBatch::default();
        self.add_to_batch(&mut batch, updates, disconnect)?;
        self.db
            .inner_db()
            .write(batch)
            .map_err(StorageError::Database)
    }

    /// Add the updates of a connected (or disconnected) block to `batch`, so
    /// they are written with the block itself
    pub fn add_to_batch(
        &self,
        batch: &mut rocksdb::WriteBatch,
        updates: &IndexUpdates,
        disconnect: bool,
    ) -> Result<(), StorageError> {
        if self.address {
            let deltas = self.cf(CF_ADDRESS_DELTA)?;
            for (key, value) in &updates.deltas {
                if disconnect {
                    batch.delete_cf(deltas, key.to_bytes());
                } else {
                    batch.put_cf(deltas, key.to_bytes(), value.to_le_bytes());
                }
            }
            let unspent = self.cf(CF_ADDRESS_UNSPENT)?;
            let scripthash = self.cf(CF_SCRIPTHASH)?;
            for (key, value) in &updates.unspent {
                match value {
                    Some(value) => {
                        batch.put_cf(unspent, key.to_bytes(), value.to_bytes());
                        // The mapping does not depend on the chain, so a
                        // disconnect leaves it in place
                        if !disconnect {
                            batch.put_cf(
                                scripthash,
                                script_hash(value.script.as_bytes()),
                                address_key(key.address_type, &key.hash),
                            );
                        }
                    }
                    None => batch.delete_cf(unspent, key.to_bytes()),
                }
            }
        }
        let write_spent = if disconnect { self.address } else { self.spent };
        if write_spent {
            let spent = self.cf(CF_SPENT)?;
            for (key, value) in &updates.spent {
                match value {
                    Some(value) => batch.put_cf(spent, key.to_db_key(), value.to_bytes()),
                    None => batch.delete_cf(spent, key.to_db_key()),
                }
            }
        }
        Ok(())
    }

    /// The address type and hash an Electrum script hash is filed under, if
    /// any output with that script was ever indexed
    pub fn lookup_script_hash(
        &self,
        script_hash: &[u8; 32],
    ) -> Result<Option<(u8, [u8; 20])>, StorageError> {
        let cf = self.cf(CF_SCRIPTHASH)?;
        let value = self
            .db
            .inner_db()
            .get_cf(cf, script_hash)
            .map_err(StorageError::Database)?;
        Ok(value.and_then(|v| {
            if v.len() != 21 {
                return None;
            }
            Some((v[0], v[1..].try_into().ok()?))
        }))
    }

    /// Fill the script hash column family from the address index when it is
    /// empty but the address index is not, as on a node that built its
    /// address index before the column family existed. P2PKH and P2SH
    /// scripts are rebuilt from every address in the index; vault scripts
    /// come from the unspent outputs, so a vault that has no unspent output
    /// left is not found until the index is rebuilt. Returns how many
    /// entries it wrote.
    pub fn backfill_script_hashes(&self) -> Result<usize, StorageError> {
        let db = self.db.inner_db();
        let scripthash = self.cf(CF_SCRIPTHASH)?;
        if db
            .iterator_cf(scripthash, rocksdb::IteratorMode::Start)
            .next()
            .is_some()
        {
            return Ok(0);
        }
        let mut written = 0usize;
        let mut batch = rocksdb::WriteBatch::default();
        let mut last: Option<[u8; 21]> = None;
        let deltas = self.cf(CF_ADDRESS_DELTA)?;
        for item in db.iterator_cf(deltas, rocksdb::IteratorMode::Start) {
            let (key, _) = item.map_err(StorageError::Database)?;
            if key.len() < 21 {
                continue;
            }
            let prefix: [u8; 21] = key[..21].try_into().expect("21 bytes");
            if last == Some(prefix) {
                continue;
            }
            last = Some(prefix);
            let hash: [u8; 20] = prefix[1..].try_into().expect("20 bytes");
            if let Some(script) = script_of_address(prefix[0], &hash) {
                batch.put_cf(scripthash, script_hash(&script), prefix);
                written += 1;
            }
        }
        let unspent = self.cf(CF_ADDRESS_UNSPENT)?;
        for item in db.iterator_cf(unspent, rocksdb::IteratorMode::Start) {
            let (key, value) = item.map_err(StorageError::Database)?;
            if key.len() < 21 || key[0] != 3 {
                continue;
            }
            if let Some(value) = AddressUnspentValue::from_bytes(&value) {
                let prefix: [u8; 21] = key[..21].try_into().expect("21 bytes");
                batch.put_cf(scripthash, script_hash(value.script.as_bytes()), prefix);
                written += 1;
            }
        }
        db.write(batch).map_err(StorageError::Database)?;
        Ok(written)
    }

    /// An address's deltas in key order (Core `ReadAddressIndex`,
    /// txdb.cpp:403-450): with `start` and `end` both above zero only heights
    /// `start..=end`, otherwise all
    pub fn read_deltas(
        &self,
        address_type: u8,
        hash: &[u8; 20],
        start: u32,
        end: u32,
    ) -> Result<Vec<(AddressDeltaKey, i64)>, StorageError> {
        let ranged = start > 0 && end > 0;
        let mut prefix = vec![address_type];
        prefix.extend_from_slice(hash);
        let mut seek = prefix.clone();
        if ranged {
            seek.extend_from_slice(&start.to_be_bytes());
        }
        let cf = self.cf(CF_ADDRESS_DELTA)?;
        let mut out = Vec::new();
        let iter = self.db.inner_db().iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&seek, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, value) = item.map_err(StorageError::Database)?;
            if !key.starts_with(&prefix) {
                break;
            }
            let Some(key) = AddressDeltaKey::from_bytes(&key) else {
                continue;
            };
            if ranged && key.height > end {
                break;
            }
            let amount = i64::from_le_bytes(
                value[..8]
                    .try_into()
                    .map_err(|_| StorageError::Deserialization("address delta value".into()))?,
            );
            out.push((key, amount));
        }
        Ok(out)
    }

    /// An address's unspent outputs in key order (Core `ReadAddressUnspentIndex`)
    pub fn read_unspent(
        &self,
        address_type: u8,
        hash: &[u8; 20],
    ) -> Result<Vec<(AddressUnspentKey, AddressUnspentValue)>, StorageError> {
        let mut prefix = vec![address_type];
        prefix.extend_from_slice(hash);
        let cf = self.cf(CF_ADDRESS_UNSPENT)?;
        let mut out = Vec::new();
        let iter = self.db.inner_db().iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, value) = item.map_err(StorageError::Database)?;
            if !key.starts_with(&prefix) {
                break;
            }
            if let (Some(key), Some(value)) = (
                AddressUnspentKey::from_bytes(&key),
                AddressUnspentValue::from_bytes(&value),
            ) {
                out.push((key, value));
            }
        }
        Ok(out)
    }

    /// The spent index entry of an output (Core `ReadSpentIndex`)
    pub fn read_spent(&self, key: &SpentIndexKey) -> Result<Option<SpentIndexValue>, StorageError> {
        let cf = self.cf(CF_SPENT)?;
        match self
            .db
            .inner_db()
            .get_cf(cf, key.to_db_key())
            .map_err(StorageError::Database)?
        {
            Some(bytes) => Ok(Some(SpentIndexValue::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }
}

const FLAG_TXINDEX: &[u8] = b"flag_txindex";
const FLAG_ADDRESSINDEX: &[u8] = b"flag_addressindex";
const FLAG_SPENTINDEX: &[u8] = b"flag_spentindex";

/// Which indexes a chain database keeps. Divi Core writes these flags when the
/// block tree is created and from then on follows them, not the command line
/// (ChainExtensionService.cpp:700-706, init.cpp:1103-1106)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexFlags {
    pub txindex: bool,
    pub addressindex: bool,
    pub spentindex: bool,
}

impl IndexFlags {
    /// The flags stored with the chain database. A database holding only
    /// genesis takes `requested`, as a new Core block tree does. One written
    /// before the flags were kept (or installed from a snapshot) has no address
    /// or spent index entries, so both are off; its transaction index is taken
    /// from `requested`, since nothing records how it was kept.
    pub fn load_or_init(
        db: &ChainDatabase,
        chain_height: u32,
        requested: IndexFlags,
    ) -> Result<IndexFlags, StorageError> {
        let read = |key: &[u8]| -> Result<Option<bool>, StorageError> {
            Ok(db.get_metadata(key)?.map(|v| v.first() == Some(&b'1')))
        };
        if let (Some(txindex), Some(addressindex), Some(spentindex)) = (
            read(FLAG_TXINDEX)?,
            read(FLAG_ADDRESSINDEX)?,
            read(FLAG_SPENTINDEX)?,
        ) {
            return Ok(IndexFlags {
                txindex,
                addressindex,
                spentindex,
            });
        }
        let flags = if chain_height == 0 {
            requested
        } else {
            IndexFlags {
                txindex: requested.txindex,
                addressindex: false,
                spentindex: false,
            }
        };
        let byte = |b: bool| if b { b"1" } else { b"0" };
        db.put_metadata(FLAG_TXINDEX, byte(flags.txindex))?;
        db.put_metadata(FLAG_ADDRESSINDEX, byte(flags.addressindex))?;
        db.put_metadata(FLAG_SPENTINDEX, byte(flags.spentindex))?;
        Ok(flags)
    }

    /// The flags stored with the chain database, or None when none are (a
    /// database from before they were kept, or one installed from a snapshot)
    pub fn load(db: &ChainDatabase) -> Result<Option<IndexFlags>, StorageError> {
        let read = |key: &[u8]| -> Result<Option<bool>, StorageError> {
            Ok(db.get_metadata(key)?.map(|v| v.first() == Some(&b'1')))
        };
        Ok(
            match (
                read(FLAG_TXINDEX)?,
                read(FLAG_ADDRESSINDEX)?,
                read(FLAG_SPENTINDEX)?,
            ) {
                (Some(txindex), Some(addressindex), Some(spentindex)) => Some(IndexFlags {
                    txindex,
                    addressindex,
                    spentindex,
                }),
                _ => None,
            },
        )
    }

    /// Keep these flags with the chain database, as Divi Core writes them
    /// after a -reindex (txdb.cpp:513-523)
    pub fn store(&self, db: &ChainDatabase) -> Result<(), StorageError> {
        let byte = |b: bool| if b { b"1" } else { b"0" };
        db.put_metadata(FLAG_TXINDEX, byte(self.txindex))?;
        db.put_metadata(FLAG_ADDRESSINDEX, byte(self.addressindex))?;
        db.put_metadata(FLAG_SPENTINDEX, byte(self.spentindex))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(height: u32, tx_index: u32, spending: bool) -> (AddressDeltaKey, i64) {
        (
            AddressDeltaKey {
                address_type: 1,
                hash: [7; 20],
                height,
                tx_index,
                txid: Hash256::from_bytes([height as u8; 32]),
                index: 0,
                spending,
            },
            if spending { -5 } else { 5 },
        )
    }

    /// Deltas come back by height, then position in the block, across byte
    /// boundaries, and a range stops after its end (txdb.cpp ReadAddressIndex)
    #[test]
    fn deltas_read_in_cores_key_order() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let index = SearchIndex::new(db, true, true);
        let mut updates = IndexUpdates::default();
        for d in [
            delta(256, 0, false),
            delta(1, 2, false),
            delta(255, 1, true),
            delta(1, 0, false),
            delta(65_536, 0, false),
        ] {
            updates.deltas.push(d);
        }
        index.apply_connect(&updates).unwrap();
        let heights = |start, end| -> Vec<(u32, u32)> {
            index
                .read_deltas(1, &[7; 20], start, end)
                .unwrap()
                .into_iter()
                .map(|(k, _)| (k.height, k.tx_index))
                .collect()
        };
        assert_eq!(
            heights(0, 0),
            vec![(1, 0), (1, 2), (255, 1), (256, 0), (65_536, 0)]
        );
        assert_eq!(heights(2, 256), vec![(255, 1), (256, 0)]);
        assert!(index.read_deltas(1, &[8; 20], 0, 0).unwrap().is_empty());
        assert!(index.read_deltas(2, &[7; 20], 0, 0).unwrap().is_empty());
    }

    #[test]
    fn address_types_are_cores() {
        let vault = divi_script::StakingVaultScript::new([1; 20], [2; 20]).to_script();
        assert_eq!(address_of_script(vault.as_bytes()), Some((3, [1; 20])));
        assert_eq!(
            address_of_script(Script::new_p2sh(&[3; 20]).as_bytes()),
            Some((2, [3; 20]))
        );
        assert_eq!(
            address_of_script(Script::new_p2pkh(&[4; 20]).as_bytes()),
            Some((1, [4; 20]))
        );
        let mut p2pk = vec![33];
        p2pk.extend_from_slice(&[2; 33]);
        p2pk.push(0xac);
        assert_eq!(address_of_script(&p2pk), None);
        assert_eq!(address_of_script(&[0x6a, 0x01, 0x07]), None);
    }

    fn unspent(
        address_type: u8,
        hash: [u8; 20],
        script: Script,
    ) -> (AddressUnspentKey, Option<AddressUnspentValue>) {
        (
            AddressUnspentKey {
                address_type,
                hash,
                txid: Hash256::from_bytes([9; 32]),
                index: 0,
            },
            Some(AddressUnspentValue {
                satoshis: 5,
                script,
                height: 1,
            }),
        )
    }

    #[test]
    fn rebuilt_scripts_match_cores() {
        assert_eq!(
            script_of_address(1, &[4; 20]).unwrap(),
            Script::new_p2pkh(&[4; 20]).as_bytes()
        );
        assert_eq!(
            script_of_address(2, &[3; 20]).unwrap(),
            Script::new_p2sh(&[3; 20]).as_bytes()
        );
        assert_eq!(script_of_address(3, &[1; 20]), None);
    }

    /// A connected output files its script hash under its address, and a
    /// disconnect leaves it
    #[test]
    fn script_hashes_follow_connected_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let index = SearchIndex::new(db, true, true);
        let script = Script::new_p2pkh(&[4; 20]);
        let mut updates = IndexUpdates::default();
        updates.unspent.push(unspent(1, [4; 20], script.clone()));
        index.apply_connect(&updates).unwrap();
        let sh = script_hash(script.as_bytes());
        assert_eq!(index.lookup_script_hash(&sh).unwrap(), Some((1, [4; 20])));
        index.apply_disconnect(&updates).unwrap();
        assert_eq!(index.lookup_script_hash(&sh).unwrap(), Some((1, [4; 20])));
        assert_eq!(index.lookup_script_hash(&[0; 32]).unwrap(), None);
        // Already filled, so a backfill writes nothing
        assert_eq!(index.backfill_script_hashes().unwrap(), 0);
    }

    /// An address index built without script hashes gets them from its
    /// deltas (P2PKH, P2SH) and its unspent outputs (vaults)
    #[test]
    fn backfill_fills_an_old_index() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let index = SearchIndex::new(db.clone(), true, true);
        let vault = divi_script::StakingVaultScript::new([1; 20], [2; 20]).to_script();
        let mut updates = IndexUpdates::default();
        updates.deltas.push(delta(1, 0, false));
        updates.deltas.push(delta(2, 0, true));
        updates.unspent.push(unspent(3, [1; 20], vault.clone()));
        index.apply_connect(&updates).unwrap();
        // Forget the script hashes, as an index from before they existed
        let cf = db.inner_db().cf_handle(CF_SCRIPTHASH).unwrap();
        let keys: Vec<Box<[u8]>> = db
            .inner_db()
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .map(|i| i.unwrap().0)
            .collect();
        for k in keys {
            db.inner_db().delete_cf(cf, k).unwrap();
        }
        let p2pkh = script_hash(Script::new_p2pkh(&[7; 20]).as_bytes());
        assert_eq!(index.lookup_script_hash(&p2pkh).unwrap(), None);
        assert_eq!(index.backfill_script_hashes().unwrap(), 2);
        assert_eq!(
            index.lookup_script_hash(&p2pkh).unwrap(),
            Some((1, [7; 20]))
        );
        assert_eq!(
            index
                .lookup_script_hash(&script_hash(vault.as_bytes()))
                .unwrap(),
            Some((3, [1; 20]))
        );
    }
}
