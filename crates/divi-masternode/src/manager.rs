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

use crate::masternode::{Masternode, MasternodeBroadcast, MasternodeStatus, ServiceAddr};
use crate::tier::MasternodeTier;
use divi_primitives::amount::Amount;
use divi_primitives::error::Error;
use divi_primitives::serialize::{deserialize, serialize, Decodable, Encodable};
use divi_primitives::transaction::OutPoint;
use parking_lot::RwLock;
use rocksdb::DB;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum MasternodeError {
    #[error("Masternode not found: {0}")]
    NotFound(OutPoint),

    #[error("Masternode already exists: {0}")]
    AlreadyExists(OutPoint),

    #[error("Invalid tier")]
    InvalidTier,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),

    #[error("Collateral UTXO not found for outpoint: {0}")]
    CollateralNotFound(OutPoint),

    #[error("Collateral amount mismatch: expected {expected}, actual {actual}")]
    CollateralAmountMismatch { expected: i64, actual: i64 },

    #[error("Insufficient confirmations: required {required}, actual {actual}")]
    InsufficientConfirmations { required: u32, actual: u32 },

    #[error("Storage error: {0}")]
    Storage(String),
}

const CF_MASTERNODES: &str = "masternodes";

/// Wrapper for masternode persistence that includes ALL fields
/// (including time_last_checked which is not in the C++ wire format)
struct MasternodePersistence {
    vin: OutPoint,
    addr: ServiceAddr,
    pubkey_collateral: Vec<u8>,
    pubkey_masternode: Vec<u8>,
    sig_time: i64,
    last_dsq: i64,
    time_last_checked: i64,
    time_last_paid: i64,
    time_last_watchdog_vote: i64,
    status: MasternodeStatus,
    protocol_version: i32,
    tier: MasternodeTier,
    signature: Vec<u8>,
    pose_score: i32,
    pose_ban_height: Option<u32>,
}

impl From<&Masternode> for MasternodePersistence {
    fn from(mn: &Masternode) -> Self {
        MasternodePersistence {
            vin: mn.vin,
            addr: mn.addr,
            pubkey_collateral: mn.pubkey_collateral.clone(),
            pubkey_masternode: mn.pubkey_masternode.clone(),
            sig_time: mn.sig_time,
            last_dsq: mn.last_dsq,
            time_last_checked: mn.time_last_checked,
            time_last_paid: mn.time_last_paid,
            time_last_watchdog_vote: mn.time_last_watchdog_vote,
            status: mn.status,
            protocol_version: mn.protocol_version,
            tier: mn.tier,
            signature: mn.signature.clone(),
            pose_score: mn.pose_score,
            pose_ban_height: mn.pose_ban_height,
        }
    }
}

impl From<MasternodePersistence> for Masternode {
    fn from(p: MasternodePersistence) -> Self {
        Masternode {
            vin: p.vin,
            addr: p.addr,
            pubkey_collateral: p.pubkey_collateral,
            pubkey_masternode: p.pubkey_masternode,
            sig_time: p.sig_time,
            last_dsq: p.last_dsq,
            time_last_checked: p.time_last_checked,
            time_last_paid: p.time_last_paid,
            time_last_watchdog_vote: p.time_last_watchdog_vote,
            status: p.status,
            protocol_version: p.protocol_version,
            tier: p.tier,
            signature: p.signature,
            pose_score: p.pose_score,
            pose_ban_height: p.pose_ban_height,
        }
    }
}

impl Encodable for MasternodePersistence {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = 0;
        size += self.vin.encode(writer)?;
        size += self.addr.encode(writer)?;
        size += self.pubkey_collateral.encode(writer)?;
        size += self.pubkey_masternode.encode(writer)?;
        size += self.signature.encode(writer)?;
        size += self.sig_time.encode(writer)?;
        size += self.last_dsq.encode(writer)?;
        size += self.protocol_version.encode(writer)?;
        size += (self.status.to_u8() as i32).encode(writer)?;
        size += self.time_last_paid.encode(writer)?;
        size += self.time_last_watchdog_vote.encode(writer)?;
        size += self.time_last_checked.encode(writer)?; // Extra field for persistence
        size += self.tier.to_u8().encode(writer)?;
        size += self.pose_score.encode(writer)?;
        size += match self.pose_ban_height {
            Some(h) => {
                size += 1u8.encode(writer)?;
                h.encode(writer)?
            }
            None => 0u8.encode(writer)?,
        };
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        self.vin.encoded_size()
            + self.addr.encoded_size()
            + self.pubkey_collateral.encoded_size()
            + self.pubkey_masternode.encoded_size()
            + self.signature.encoded_size()
            + 8 // sig_time
            + 8 // last_dsq
            + 4 // protocol_version
            + 4 // status
            + 8 // time_last_paid
            + 8 // time_last_watchdog_vote
            + 8 // time_last_checked
            + 1 // tier
            + 4 // pose_score
            + 1 // pose_ban_height flag
            + if self.pose_ban_height.is_some() { 4 } else { 0 }
    }
}

impl Decodable for MasternodePersistence {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let vin = OutPoint::decode(reader)?;
        let addr = ServiceAddr::decode(reader)?;
        let pubkey_collateral = Vec::<u8>::decode(reader)?;
        let pubkey_masternode = Vec::<u8>::decode(reader)?;
        let signature = Vec::<u8>::decode(reader)?;
        let sig_time = i64::decode(reader)?;
        let last_dsq = i64::decode(reader)?;
        let protocol_version = i32::decode(reader)?;
        let status_raw = i32::decode(reader)?;
        let time_last_paid = i64::decode(reader)?;
        let time_last_watchdog_vote = i64::decode(reader)?;
        let time_last_checked = i64::decode(reader)?;
        let tier_byte = u8::decode(reader)?;
        let pose_score = i32::decode(reader)?;
        let pose_ban_flag = u8::decode(reader)?;
        let pose_ban_height = if pose_ban_flag != 0 {
            Some(u32::decode(reader)?)
        } else {
            None
        };

        Ok(MasternodePersistence {
            vin,
            addr,
            pubkey_collateral,
            pubkey_masternode,
            sig_time,
            last_dsq,
            time_last_checked,
            time_last_paid,
            time_last_watchdog_vote,
            status: MasternodeStatus::from_u8(status_raw as u8),
            protocol_version,
            tier: MasternodeTier::from_u8(tier_byte),
            signature,
            pose_score,
            pose_ban_height,
        })
    }
}

#[derive(Clone)]
pub struct MasternodeManager {
    masternodes: Arc<RwLock<HashMap<OutPoint, Masternode>>>,
    db: Option<Arc<DB>>,
}

impl MasternodeManager {
    pub fn new() -> Self {
        MasternodeManager {
            masternodes: Arc::new(RwLock::new(HashMap::new())),
            db: None,
        }
    }

    /// Create a new MasternodeManager with database persistence
    ///
    /// The database must have a column family named "masternodes" already created.
    /// All masternodes are automatically loaded from the database on initialization.
    /// Subsequent add/remove/update operations will be persisted automatically.
    ///
    /// # Example
    /// ```ignore
    /// use rocksdb::{DB, Options, ColumnFamilyDescriptor};
    /// use std::sync::Arc;
    ///
    /// let mut opts = Options::default();
    /// opts.create_if_missing(true);
    /// opts.create_missing_column_families(true);
    ///
    /// let cfs = vec![ColumnFamilyDescriptor::new("masternodes", Options::default())];
    /// let db = Arc::new(DB::open_cf_descriptors(&opts, path, cfs).unwrap());
    ///
    /// let manager = MasternodeManager::with_db(db)?;
    /// ```
    pub fn with_db(db: Arc<DB>) -> Result<Self, MasternodeError> {
        let manager = MasternodeManager {
            masternodes: Arc::new(RwLock::new(HashMap::new())),
            db: Some(db),
        };
        manager.load()?;
        Ok(manager)
    }

    /// Create database key from outpoint
    fn make_key(outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(outpoint.txid.as_bytes());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    /// Parse outpoint from database key
    fn parse_key(key: &[u8]) -> Result<OutPoint, MasternodeError> {
        if key.len() != 36 {
            return Err(MasternodeError::Database(
                "Invalid masternode key length".to_string(),
            ));
        }
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&key[0..32]);
        let txid = divi_primitives::hash::Hash256::from_bytes(txid_bytes);
        let vout = u32::from_le_bytes([key[32], key[33], key[34], key[35]]);
        Ok(OutPoint::new(txid, vout))
    }

    /// Save all masternodes to database
    ///
    /// This method is normally not needed as masternodes are persisted automatically
    /// on add/remove/update operations. However, it can be used for manual persistence
    /// or batch operations.
    pub fn save(&self) -> Result<(), MasternodeError> {
        if let Some(db) = &self.db {
            let cf = db
                .cf_handle(CF_MASTERNODES)
                .ok_or_else(|| MasternodeError::Database("masternodes CF not found".to_string()))?;
            let map = self.masternodes.read();
            for (outpoint, masternode) in map.iter() {
                let key = Self::make_key(outpoint);
                let persistence = MasternodePersistence::from(masternode);
                let data = serialize(&persistence);
                db.put_cf(cf, &key, &data)?;
            }
        }
        Ok(())
    }

    /// Load all masternodes from database
    pub fn load(&self) -> Result<(), MasternodeError> {
        if let Some(db) = &self.db {
            let cf = db
                .cf_handle(CF_MASTERNODES)
                .ok_or_else(|| MasternodeError::Database("masternodes CF not found".to_string()))?;
            let mut map = self.masternodes.write();
            map.clear();

            let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            for item in iter {
                let (key, value) = item?;
                let outpoint = Self::parse_key(&key)?;
                let persistence: MasternodePersistence = deserialize(&value)
                    .map_err(|e| MasternodeError::Serialization(e.to_string()))?;
                let masternode = Masternode::from(persistence);
                map.insert(outpoint, masternode);
            }
        }
        Ok(())
    }

    /// Persist a single masternode to database
    fn persist_masternode(
        &self,
        outpoint: &OutPoint,
        masternode: &Masternode,
    ) -> Result<(), MasternodeError> {
        if let Some(db) = &self.db {
            let cf = db
                .cf_handle(CF_MASTERNODES)
                .ok_or_else(|| MasternodeError::Database("masternodes CF not found".to_string()))?;
            let key = Self::make_key(outpoint);
            let persistence = MasternodePersistence::from(masternode);
            let data = serialize(&persistence);
            db.put_cf(cf, &key, &data)?;
        }
        Ok(())
    }

    /// Remove a masternode from database
    fn remove_from_db(&self, outpoint: &OutPoint) -> Result<(), MasternodeError> {
        if let Some(db) = &self.db {
            let cf = db
                .cf_handle(CF_MASTERNODES)
                .ok_or_else(|| MasternodeError::Database("masternodes CF not found".to_string()))?;
            let key = Self::make_key(outpoint);
            db.delete_cf(cf, &key)?;
        }
        Ok(())
    }

    pub fn add(&self, mnb: MasternodeBroadcast) -> Result<(), MasternodeError> {
        let outpoint = mnb.vin;
        let mut map = self.masternodes.write();

        if map.contains_key(&outpoint) {
            return Err(MasternodeError::AlreadyExists(outpoint));
        }

        let masternode = mnb.to_masternode();
        self.persist_masternode(&outpoint, &masternode)?;
        map.insert(outpoint, masternode);
        Ok(())
    }

    pub fn remove(&self, outpoint: OutPoint) -> Result<(), MasternodeError> {
        let mut map = self.masternodes.write();
        map.remove(&outpoint)
            .ok_or(MasternodeError::NotFound(outpoint))?;
        self.remove_from_db(&outpoint)?;
        Ok(())
    }

    pub fn get(&self, outpoint: OutPoint) -> Option<Masternode> {
        let map = self.masternodes.read();
        map.get(&outpoint).cloned()
    }

    pub fn get_all(&self) -> Vec<Masternode> {
        let map = self.masternodes.read();
        map.values().cloned().collect()
    }

    pub fn get_enabled(&self) -> Vec<Masternode> {
        let map = self.masternodes.read();
        map.values().filter(|mn| mn.is_enabled()).cloned().collect()
    }

    pub fn get_by_tier(&self, tier: MasternodeTier) -> Vec<Masternode> {
        let map = self.masternodes.read();
        map.values().filter(|mn| mn.tier == tier).cloned().collect()
    }

    pub fn get_by_status(&self, status: MasternodeStatus) -> Vec<Masternode> {
        let map = self.masternodes.read();
        map.values()
            .filter(|mn| mn.status == status)
            .cloned()
            .collect()
    }

    pub fn count(&self) -> usize {
        let map = self.masternodes.read();
        map.len()
    }

    pub fn count_enabled(&self) -> usize {
        let map = self.masternodes.read();
        map.values().filter(|mn| mn.is_enabled()).count()
    }

    pub fn count_by_tier(&self, tier: MasternodeTier) -> usize {
        let map = self.masternodes.read();
        map.values().filter(|mn| mn.tier == tier).count()
    }

    pub fn update_status(
        &self,
        outpoint: OutPoint,
        status: MasternodeStatus,
    ) -> Result<(), MasternodeError> {
        let mut map = self.masternodes.write();
        let mn = map
            .get_mut(&outpoint)
            .ok_or(MasternodeError::NotFound(outpoint))?;
        mn.update_status(status);
        self.persist_masternode(&outpoint, mn)?;
        Ok(())
    }

    pub fn update_last_seen(&self, outpoint: OutPoint, time: i64) -> Result<(), MasternodeError> {
        let mut map = self.masternodes.write();
        let mn = map
            .get_mut(&outpoint)
            .ok_or(MasternodeError::NotFound(outpoint))?;
        mn.update_last_seen(time);
        self.persist_masternode(&outpoint, mn)?;
        Ok(())
    }

    pub fn mark_as_paid(&self, outpoint: OutPoint, time: i64) -> Result<(), MasternodeError> {
        let mut map = self.masternodes.write();
        let mn = map
            .get_mut(&outpoint)
            .ok_or(MasternodeError::NotFound(outpoint))?;
        mn.mark_as_paid(time);
        self.persist_masternode(&outpoint, mn)?;
        Ok(())
    }

    pub fn clear(&self) {
        let mut map = self.masternodes.write();
        map.clear();
        if let Some(db) = &self.db {
            if let Some(cf) = db.cf_handle(CF_MASTERNODES) {
                let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
                let keys: Vec<_> = iter
                    .filter_map(|item| item.ok().map(|(k, _)| k.to_vec()))
                    .collect();

                for key in keys {
                    let _ = db.delete_cf(cf, &key);
                }
            }
        }
    }

    pub fn contains(&self, outpoint: OutPoint) -> bool {
        let map = self.masternodes.read();
        map.contains_key(&outpoint)
    }

    /// Increase PoSe score for a masternode
    ///
    /// Returns true if the masternode should be banned (score >= 100)
    pub fn increase_pose_score(
        &self,
        outpoint: &OutPoint,
        score_increase: i32,
    ) -> Result<bool, MasternodeError> {
        let mut map = self.masternodes.write();
        let mn = map
            .get_mut(outpoint)
            .ok_or(MasternodeError::NotFound(*outpoint))?;

        mn.pose_score = mn.pose_score.saturating_add(score_increase);
        let should_ban = mn.pose_score >= 100;

        self.persist_masternode(outpoint, mn)?;
        Ok(should_ban)
    }

    /// Decrease PoSe score for a masternode (forgiveness)
    ///
    /// Score cannot go below 0
    pub fn decrease_pose_score(
        &self,
        outpoint: &OutPoint,
        score_decrease: i32,
    ) -> Result<(), MasternodeError> {
        let mut map = self.masternodes.write();
        let mn = map
            .get_mut(outpoint)
            .ok_or(MasternodeError::NotFound(*outpoint))?;

        mn.pose_score = mn.pose_score.saturating_sub(score_decrease).max(0);

        self.persist_masternode(outpoint, mn)?;
        Ok(())
    }

    /// Check if a masternode should be PoSe-banned
    ///
    /// Returns true if pose_score >= 100
    pub fn check_pose_ban(&self, outpoint: &OutPoint) -> Result<bool, MasternodeError> {
        let map = self.masternodes.read();
        let mn = map
            .get(outpoint)
            .ok_or(MasternodeError::NotFound(*outpoint))?;

        Ok(mn.pose_score >= 100)
    }

    /// Ban a masternode for PoSe violations
    ///
    /// Sets status to PoseBan and records the ban height
    pub fn pose_ban_masternode(
        &self,
        outpoint: &OutPoint,
        ban_height: u32,
    ) -> Result<(), MasternodeError> {
        let mut map = self.masternodes.write();
        let mn = map
            .get_mut(outpoint)
            .ok_or(MasternodeError::NotFound(*outpoint))?;

        mn.status = MasternodeStatus::PoseBan;
        mn.pose_ban_height = Some(ban_height);

        self.persist_masternode(outpoint, mn)?;
        Ok(())
    }

    /// Verify that a masternode's collateral UTXO exists and is valid
    ///
    /// This method checks:
    /// 1. The UTXO exists in the chain database
    /// 2. The UTXO amount matches the tier's collateral requirement
    /// 3. The UTXO has at least 15 confirmations
    ///
    /// # Arguments
    /// * `outpoint` - The collateral outpoint to verify
    /// * `chain_db` - Reference to the chain database to query UTXOs
    /// * `current_height` - Current blockchain height for confirmation checking
    ///
    /// # Returns
    /// `Ok(true)` if collateral is valid, `Err` otherwise
    pub fn verify_collateral(
        &self,
        outpoint: &OutPoint,
        chain_db: &dyn UtxoProvider,
        current_height: u64,
    ) -> Result<bool, MasternodeError> {
        // Query UTXO set for the outpoint
        let utxo = chain_db
            .get_utxo(outpoint)
            .map_err(|e| MasternodeError::Storage(e.to_string()))?
            .ok_or(MasternodeError::CollateralNotFound(*outpoint))?;

        // Get the masternode to check tier
        let map = self.masternodes.read();
        let mn = map
            .get(outpoint)
            .ok_or(MasternodeError::NotFound(*outpoint))?;

        // Verify amount matches tier collateral requirement
        let expected_amount = mn.tier.collateral_amount();
        let actual_amount = utxo.value.as_sat();

        if actual_amount != expected_amount {
            return Err(MasternodeError::CollateralAmountMismatch {
                expected: expected_amount,
                actual: actual_amount,
            });
        }

        // Verify UTXO has >= 15 confirmations
        const MASTERNODE_MIN_CONFIRMATIONS: u32 = 15;
        let confirmations = current_height.saturating_sub(utxo.height as u64) as u32;

        if confirmations < MASTERNODE_MIN_CONFIRMATIONS {
            return Err(MasternodeError::InsufficientConfirmations {
                required: MASTERNODE_MIN_CONFIRMATIONS,
                actual: confirmations,
            });
        }

        Ok(true)
    }

    /// Check all masternodes for spent collateral
    ///
    /// This method should be called on each new block to detect when masternode
    /// collateral has been spent. Masternodes with spent collateral should be
    /// marked with VinSpent status.
    ///
    /// # Arguments
    /// * `chain_db` - Reference to the chain database to query UTXOs
    /// * `_current_height` - Current blockchain height (reserved for future use)
    ///
    /// # Returns
    /// Vector of outpoints for masternodes whose collateral has been spent
    pub fn check_spent_collateral(
        &mut self,
        chain_db: &dyn UtxoProvider,
        _current_height: u64,
    ) -> Vec<OutPoint> {
        let mut spent_collateral = Vec::new();
        let mut map = self.masternodes.write();

        for (outpoint, mn) in map.iter_mut() {
            // Skip if already marked as spent
            if mn.status == MasternodeStatus::VinSpent
                || mn.status == MasternodeStatus::OutpointSpent
            {
                continue;
            }

            // Check if UTXO still exists
            match chain_db.get_utxo(outpoint) {
                Ok(Some(_)) => {
                    // UTXO still exists, all good
                }
                Ok(None) => {
                    // UTXO was spent
                    mn.update_status(MasternodeStatus::VinSpent);
                    spent_collateral.push(*outpoint);

                    // Persist the status change
                    if let Err(e) = self.persist_masternode(outpoint, mn) {
                        error!("Failed to persist masternode status change: {}", e);
                    }
                }
                Err(e) => {
                    // Database error - log but don't mark as spent
                    error!("Error checking UTXO for masternode {}: {}", outpoint, e);
                }
            }
        }

        spent_collateral
    }
}

/// Simplified UTXO information for collateral verification
///
/// This is a lightweight struct that contains only the fields needed for
/// masternode collateral verification. It avoids a circular dependency on
/// the divi-storage crate.
#[derive(Debug, Clone)]
pub struct Utxo {
    /// Value in satoshis
    pub value: Amount,
    /// Height of the block that contains this UTXO
    pub height: u32,
}

impl Utxo {
    pub fn new(value: Amount, height: u32) -> Self {
        Utxo { value, height }
    }
}

/// Trait for abstracting UTXO queries to enable testing and decouple from storage
///
/// Implementers should provide UTXO lookup functionality. The main implementation
/// will be in divi-storage's ChainDatabase, but this allows the masternode manager
/// to verify collateral without depending on the storage crate.
pub trait UtxoProvider {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, Box<dyn std::error::Error>>;
}

impl Default for MasternodeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masternode::{MasternodeBroadcast, ServiceAddr};
    use crate::tier::MasternodeTier;
    use std::net::{Ipv6Addr, SocketAddrV6};

    fn create_test_broadcast(vout: u32, tier: MasternodeTier) -> MasternodeBroadcast {
        let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
        MasternodeBroadcast::new(
            OutPoint::new(divi_primitives::hash::Hash256::zero(), vout),
            addr,
            vec![1, 2, 3],
            vec![4, 5, 6],
            tier,
            70000,
            1234567890,
        )
    }

    #[test]
    fn test_manager_creation() {
        let manager = MasternodeManager::new();
        assert_eq!(manager.count(), 0);
        assert_eq!(manager.count_enabled(), 0);
    }

    #[test]
    fn test_add_masternode() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        assert!(manager.add(mnb.clone()).is_ok());
        assert_eq!(manager.count(), 1);
        assert!(manager.contains(mnb.vin));
    }

    #[test]
    fn test_add_duplicate_fails() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        assert!(manager.add(mnb.clone()).is_ok());
        assert!(matches!(
            manager.add(mnb.clone()),
            Err(MasternodeError::AlreadyExists(_))
        ));
    }

    #[test]
    fn test_remove_masternode() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        assert_eq!(manager.count(), 1);

        assert!(manager.remove(mnb.vin).is_ok());
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_fails() {
        let manager = MasternodeManager::new();
        let outpoint = OutPoint::new(divi_primitives::hash::Hash256::zero(), 0);

        assert!(matches!(
            manager.remove(outpoint),
            Err(MasternodeError::NotFound(_))
        ));
    }

    #[test]
    fn test_get_masternode() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Gold);

        manager.add(mnb.clone()).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.tier, MasternodeTier::Gold);
        assert_eq!(mn.protocol_version, 70000);
    }

    #[test]
    fn test_get_all() {
        let manager = MasternodeManager::new();
        manager
            .add(create_test_broadcast(0, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(1, MasternodeTier::Silver))
            .unwrap();
        manager
            .add(create_test_broadcast(2, MasternodeTier::Gold))
            .unwrap();

        let all = manager.get_all();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_get_enabled() {
        let manager = MasternodeManager::new();
        let mnb1 = create_test_broadcast(0, MasternodeTier::Copper);
        let mnb2 = create_test_broadcast(1, MasternodeTier::Silver);

        manager.add(mnb1.clone()).unwrap();
        manager.add(mnb2.clone()).unwrap();

        manager
            .update_status(mnb1.vin, MasternodeStatus::Enabled)
            .unwrap();

        let enabled = manager.get_enabled();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].tier, MasternodeTier::Copper);
    }

    #[test]
    fn test_get_by_tier() {
        let manager = MasternodeManager::new();
        manager
            .add(create_test_broadcast(0, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(1, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(2, MasternodeTier::Gold))
            .unwrap();

        let copper = manager.get_by_tier(MasternodeTier::Copper);
        assert_eq!(copper.len(), 2);

        let gold = manager.get_by_tier(MasternodeTier::Gold);
        assert_eq!(gold.len(), 1);
    }

    #[test]
    fn test_get_by_status() {
        let manager = MasternodeManager::new();
        let mnb1 = create_test_broadcast(0, MasternodeTier::Copper);
        let mnb2 = create_test_broadcast(1, MasternodeTier::Silver);

        manager.add(mnb1.clone()).unwrap();
        manager.add(mnb2.clone()).unwrap();

        manager
            .update_status(mnb1.vin, MasternodeStatus::Enabled)
            .unwrap();

        let enabled = manager.get_by_status(MasternodeStatus::Enabled);
        assert_eq!(enabled.len(), 1);

        let pre_enabled = manager.get_by_status(MasternodeStatus::PreEnabled);
        assert_eq!(pre_enabled.len(), 1);
    }

    #[test]
    fn test_count_methods() {
        let manager = MasternodeManager::new();
        manager
            .add(create_test_broadcast(0, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(1, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(2, MasternodeTier::Gold))
            .unwrap();

        assert_eq!(manager.count(), 3);
        assert_eq!(manager.count_enabled(), 0);
        assert_eq!(manager.count_by_tier(MasternodeTier::Copper), 2);
        assert_eq!(manager.count_by_tier(MasternodeTier::Gold), 1);
    }

    #[test]
    fn test_update_status() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        assert_eq!(manager.count_enabled(), 0);

        manager
            .update_status(mnb.vin, MasternodeStatus::Enabled)
            .unwrap();
        assert_eq!(manager.count_enabled(), 1);

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.status, MasternodeStatus::Enabled);
    }

    #[test]
    fn test_update_last_seen() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        manager.update_last_seen(mnb.vin, 999).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.time_last_checked, 999);
    }

    #[test]
    fn test_mark_as_paid() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        manager.mark_as_paid(mnb.vin, 1000).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.time_last_paid, 1000);
    }

    #[test]
    fn test_clear() {
        let manager = MasternodeManager::new();
        manager
            .add(create_test_broadcast(0, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(1, MasternodeTier::Silver))
            .unwrap();

        assert_eq!(manager.count(), 2);
        manager.clear();
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_contains() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        assert!(!manager.contains(mnb.vin));
        manager.add(mnb.clone()).unwrap();
        assert!(manager.contains(mnb.vin));
    }

    #[test]
    fn test_persistence_save_load() {
        use rocksdb::{ColumnFamilyDescriptor, Options, DB};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![ColumnFamilyDescriptor::new(
            CF_MASTERNODES,
            Options::default(),
        )];
        let db = Arc::new(DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap());

        // Create manager with database
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        assert_eq!(manager.count(), 0);

        // Add some masternodes
        manager
            .add(create_test_broadcast(0, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(1, MasternodeTier::Silver))
            .unwrap();
        manager
            .add(create_test_broadcast(2, MasternodeTier::Gold))
            .unwrap();

        assert_eq!(manager.count(), 3);

        // Create a new manager with the same database
        let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
        assert_eq!(manager2.count(), 3);

        // Verify the loaded data
        let all = manager2.get_all();
        assert_eq!(all.len(), 3);

        let copper = manager2.get_by_tier(MasternodeTier::Copper);
        assert_eq!(copper.len(), 1);

        let silver = manager2.get_by_tier(MasternodeTier::Silver);
        assert_eq!(silver.len(), 1);

        let gold = manager2.get_by_tier(MasternodeTier::Gold);
        assert_eq!(gold.len(), 1);
    }

    #[test]
    fn test_persistence_remove() {
        use rocksdb::{ColumnFamilyDescriptor, Options, DB};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![ColumnFamilyDescriptor::new(
            CF_MASTERNODES,
            Options::default(),
        )];
        let db = Arc::new(DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap());

        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        assert_eq!(manager.count(), 1);

        // Remove the masternode
        manager.remove(mnb.vin).unwrap();
        assert_eq!(manager.count(), 0);

        // Create a new manager and verify it's empty
        let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
        assert_eq!(manager2.count(), 0);
    }

    #[test]
    fn test_persistence_update_status() {
        use rocksdb::{ColumnFamilyDescriptor, Options, DB};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![ColumnFamilyDescriptor::new(
            CF_MASTERNODES,
            Options::default(),
        )];
        let db = Arc::new(DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap());

        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        manager
            .update_status(mnb.vin, MasternodeStatus::Enabled)
            .unwrap();

        // Reload and verify status persisted
        let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
        let mn = manager2.get(mnb.vin).unwrap();
        assert_eq!(mn.status, MasternodeStatus::Enabled);
    }

    #[test]
    fn test_persistence_update_last_seen() {
        use rocksdb::{ColumnFamilyDescriptor, Options, DB};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![ColumnFamilyDescriptor::new(
            CF_MASTERNODES,
            Options::default(),
        )];
        let db = Arc::new(DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap());

        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        manager.update_last_seen(mnb.vin, 123456).unwrap();

        // Reload and verify last_seen persisted
        let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
        let mn = manager2.get(mnb.vin).unwrap();
        assert_eq!(mn.time_last_checked, 123456);
    }

    #[test]
    fn test_persistence_mark_as_paid() {
        use rocksdb::{ColumnFamilyDescriptor, Options, DB};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![ColumnFamilyDescriptor::new(
            CF_MASTERNODES,
            Options::default(),
        )];
        let db = Arc::new(DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap());

        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        manager.mark_as_paid(mnb.vin, 789012).unwrap();

        // Reload and verify last_paid persisted
        let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
        let mn = manager2.get(mnb.vin).unwrap();
        assert_eq!(mn.time_last_paid, 789012);
    }

    #[test]
    fn test_persistence_clear() {
        use rocksdb::{ColumnFamilyDescriptor, Options, DB};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![ColumnFamilyDescriptor::new(
            CF_MASTERNODES,
            Options::default(),
        )];
        let db = Arc::new(DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap());

        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        manager
            .add(create_test_broadcast(0, MasternodeTier::Copper))
            .unwrap();
        manager
            .add(create_test_broadcast(1, MasternodeTier::Silver))
            .unwrap();

        assert_eq!(manager.count(), 2);
        manager.clear();
        assert_eq!(manager.count(), 0);

        // Verify database is also cleared
        let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
        assert_eq!(manager2.count(), 0);
    }

    #[test]
    fn test_in_memory_mode_still_works() {
        // Verify backward compatibility - in-memory mode without database
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);

        manager.add(mnb.clone()).unwrap();
        assert_eq!(manager.count(), 1);

        manager.remove(mnb.vin).unwrap();
        assert_eq!(manager.count(), 0);
    }

    // ============================================================
    // COLLATERAL VERIFICATION TESTS
    // Added for Phase C.3 - UTXO collateral verification
    // ============================================================

    struct MockUtxoProvider {
        utxos: HashMap<OutPoint, Utxo>,
    }

    impl MockUtxoProvider {
        fn new() -> Self {
            MockUtxoProvider {
                utxos: HashMap::new(),
            }
        }

        fn add_utxo(&mut self, outpoint: OutPoint, value: i64, height: u32) {
            self.utxos
                .insert(outpoint, Utxo::new(Amount::from_sat(value), height));
        }
    }

    impl UtxoProvider for MockUtxoProvider {
        fn get_utxo(
            &self,
            outpoint: &OutPoint,
        ) -> Result<Option<Utxo>, Box<dyn std::error::Error>> {
            Ok(self.utxos.get(outpoint).cloned())
        }
    }

    #[test]
    fn test_verify_collateral_success() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        let mut utxo_provider = MockUtxoProvider::new();
        // Copper tier requires 100,000 DIVI = 10,000,000,000,000 satoshis
        utxo_provider.add_utxo(mnb.vin, 10_000_000_000_000, 100);

        // At height 120, we have 20 confirmations (>= 15 required)
        let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 120);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_collateral_not_found() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        let utxo_provider = MockUtxoProvider::new();
        // No UTXO added

        let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 120);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MasternodeError::CollateralNotFound(_)
        ));
    }

    #[test]
    fn test_verify_collateral_amount_mismatch() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        let mut utxo_provider = MockUtxoProvider::new();
        // Wrong amount - should be 10,000,000,000,000 for Copper
        utxo_provider.add_utxo(mnb.vin, 5_000_000_000_000, 100);

        let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 120);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MasternodeError::CollateralAmountMismatch { .. }
        ));
    }

    #[test]
    fn test_verify_collateral_insufficient_confirmations() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        let mut utxo_provider = MockUtxoProvider::new();
        utxo_provider.add_utxo(mnb.vin, 10_000_000_000_000, 100);

        // At height 110, we only have 10 confirmations (< 15 required)
        let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 110);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MasternodeError::InsufficientConfirmations { .. }
        ));
    }

    #[test]
    fn test_verify_collateral_all_tiers() {
        let manager = MasternodeManager::new();

        // Test all tier amounts
        let tiers_and_amounts = [
            (MasternodeTier::Copper, 10_000_000_000_000i64),
            (MasternodeTier::Silver, 30_000_000_000_000i64),
            (MasternodeTier::Gold, 100_000_000_000_000i64),
            (MasternodeTier::Platinum, 300_000_000_000_000i64),
            (MasternodeTier::Diamond, 1_000_000_000_000_000i64),
        ];

        for (idx, (tier, expected_amount)) in tiers_and_amounts.iter().enumerate() {
            let mnb = create_test_broadcast(idx as u32, *tier);
            manager.add(mnb.clone()).unwrap();

            let mut utxo_provider = MockUtxoProvider::new();
            utxo_provider.add_utxo(mnb.vin, *expected_amount, 100);

            let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 120);
            assert!(
                result.is_ok(),
                "Failed to verify collateral for tier {:?}",
                tier
            );
        }
    }

    #[test]
    fn test_check_spent_collateral_none_spent() {
        let mut manager = MasternodeManager::new();
        let mnb1 = create_test_broadcast(0, MasternodeTier::Copper);
        let mnb2 = create_test_broadcast(1, MasternodeTier::Silver);
        manager.add(mnb1.clone()).unwrap();
        manager.add(mnb2.clone()).unwrap();

        let mut utxo_provider = MockUtxoProvider::new();
        utxo_provider.add_utxo(mnb1.vin, 10_000_000_000_000, 100);
        utxo_provider.add_utxo(mnb2.vin, 30_000_000_000_000, 100);

        let spent = manager.check_spent_collateral(&utxo_provider, 200);
        assert_eq!(spent.len(), 0);
    }

    #[test]
    fn test_check_spent_collateral_one_spent() {
        let mut manager = MasternodeManager::new();
        let mnb1 = create_test_broadcast(0, MasternodeTier::Copper);
        let mnb2 = create_test_broadcast(1, MasternodeTier::Silver);
        manager.add(mnb1.clone()).unwrap();
        manager.add(mnb2.clone()).unwrap();

        let mut utxo_provider = MockUtxoProvider::new();
        // Only mnb2 has UTXO (mnb1's was spent)
        utxo_provider.add_utxo(mnb2.vin, 30_000_000_000_000, 100);

        let spent = manager.check_spent_collateral(&utxo_provider, 200);
        assert_eq!(spent.len(), 1);
        assert_eq!(spent[0], mnb1.vin);

        // Verify status was updated
        let mn1 = manager.get(mnb1.vin).unwrap();
        assert_eq!(mn1.status, MasternodeStatus::VinSpent);

        let mn2 = manager.get(mnb2.vin).unwrap();
        assert_eq!(mn2.status, MasternodeStatus::PreEnabled);
    }

    #[test]
    fn test_check_spent_collateral_already_marked_spent() {
        let mut manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();
        manager
            .update_status(mnb.vin, MasternodeStatus::VinSpent)
            .unwrap();

        let utxo_provider = MockUtxoProvider::new();
        // No UTXO, but already marked as spent

        let spent = manager.check_spent_collateral(&utxo_provider, 200);
        // Should not be added to spent list again
        assert_eq!(spent.len(), 0);
    }

    #[test]
    fn test_verify_collateral_minimum_confirmations_boundary() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Gold);
        manager.add(mnb.clone()).unwrap();

        let mut utxo_provider = MockUtxoProvider::new();
        utxo_provider.add_utxo(mnb.vin, 100_000_000_000_000, 1000);

        // Test exactly 14 confirmations (should fail)
        let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 1014);
        assert!(result.is_err());

        // Test exactly 15 confirmations (should succeed)
        let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 1015);
        assert!(result.is_ok());
    }

    // ============================================================
    // POSE (PROOF OF SERVICE) TESTS
    // Added for MN-007 - PoSe score tracking and banning
    // ============================================================

    #[test]
    fn test_pose_initial_score_zero() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 0);
        assert_eq!(mn.pose_ban_height, None);
    }

    #[test]
    fn test_pose_increase_score() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        let should_ban = manager.increase_pose_score(&mnb.vin, 20).unwrap();
        assert!(!should_ban);

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 20);
    }

    #[test]
    fn test_pose_increase_score_to_ban_threshold() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Increase score to 99 (not banned)
        let should_ban = manager.increase_pose_score(&mnb.vin, 99).unwrap();
        assert!(!should_ban);

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 99);

        // Increase by 1 more (total 100, should ban)
        let should_ban = manager.increase_pose_score(&mnb.vin, 1).unwrap();
        assert!(should_ban);

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 100);
    }

    #[test]
    fn test_pose_increase_score_above_threshold() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Increase score directly to 120 (over threshold)
        let should_ban = manager.increase_pose_score(&mnb.vin, 120).unwrap();
        assert!(should_ban);

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 120);
    }

    #[test]
    fn test_pose_decrease_score() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Increase score to 50
        manager.increase_pose_score(&mnb.vin, 50).unwrap();

        // Decrease by 20
        manager.decrease_pose_score(&mnb.vin, 20).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 30);
    }

    #[test]
    fn test_pose_decrease_score_below_zero() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Increase score to 10
        manager.increase_pose_score(&mnb.vin, 10).unwrap();

        // Try to decrease by 20 (should stop at 0)
        manager.decrease_pose_score(&mnb.vin, 20).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 0);
    }

    #[test]
    fn test_pose_check_ban_below_threshold() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        manager.increase_pose_score(&mnb.vin, 50).unwrap();

        let should_ban = manager.check_pose_ban(&mnb.vin).unwrap();
        assert!(!should_ban);
    }

    #[test]
    fn test_pose_check_ban_at_threshold() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        manager.increase_pose_score(&mnb.vin, 100).unwrap();

        let should_ban = manager.check_pose_ban(&mnb.vin).unwrap();
        assert!(should_ban);
    }

    #[test]
    fn test_pose_check_ban_above_threshold() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        manager.increase_pose_score(&mnb.vin, 150).unwrap();

        let should_ban = manager.check_pose_ban(&mnb.vin).unwrap();
        assert!(should_ban);
    }

    #[test]
    fn test_pose_ban_masternode() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        manager.increase_pose_score(&mnb.vin, 100).unwrap();
        manager.pose_ban_masternode(&mnb.vin, 12345).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.status, MasternodeStatus::PoseBan);
        assert_eq!(mn.pose_ban_height, Some(12345));
    }

    #[test]
    fn test_pose_banned_masternode_not_in_enabled_list() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Enable masternode first
        manager
            .update_status(mnb.vin, MasternodeStatus::Enabled)
            .unwrap();
        assert_eq!(manager.count_enabled(), 1);

        // Ban masternode
        manager.pose_ban_masternode(&mnb.vin, 12345).unwrap();

        // Should no longer be in enabled list
        assert_eq!(manager.count_enabled(), 0);
    }

    #[test]
    fn test_pose_score_persistence() {
        use rocksdb::{ColumnFamilyDescriptor, Options, DB};
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![ColumnFamilyDescriptor::new(
            CF_MASTERNODES,
            Options::default(),
        )];
        let db = Arc::new(DB::open_cf_descriptors(&opts, dir.path(), cfs).unwrap());

        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Increase PoSe score
        manager.increase_pose_score(&mnb.vin, 75).unwrap();
        manager.pose_ban_masternode(&mnb.vin, 12345).unwrap();

        // Reload from database
        let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
        let mn = manager2.get(mnb.vin).unwrap();

        // Verify PoSe data persisted
        assert_eq!(mn.pose_score, 75);
        assert_eq!(mn.pose_ban_height, Some(12345));
        assert_eq!(mn.status, MasternodeStatus::PoseBan);
    }

    #[test]
    fn test_pose_score_multiple_increments() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Simulate multiple failed pings
        for _ in 0..4 {
            manager.increase_pose_score(&mnb.vin, 20).unwrap();
        }

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 80);
    }

    #[test]
    fn test_pose_forgiveness_over_time() {
        let manager = MasternodeManager::new();
        let mnb = create_test_broadcast(0, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();

        // Score increases
        manager.increase_pose_score(&mnb.vin, 60).unwrap();

        // Forgiveness
        manager.decrease_pose_score(&mnb.vin, 10).unwrap();
        manager.decrease_pose_score(&mnb.vin, 10).unwrap();

        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.pose_score, 40);
    }
}
