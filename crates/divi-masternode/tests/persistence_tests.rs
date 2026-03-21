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

//! Comprehensive tests for masternode persistence and collateral verification
//!
//! Tests for Phase C implementation:
//! - Masternode RocksDB persistence
//! - Collateral verification (amount, confirmations)
//! - Spent collateral detection

use divi_masternode::{
    MasternodeBroadcast, MasternodeError, MasternodeManager, MasternodeStatus, MasternodeTier,
    ServiceAddr, Utxo, UtxoProvider,
};
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::OutPoint;
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use tempfile::tempdir;

const CF_MASTERNODES: &str = "masternodes";

// ============================================================
// MOCK UTXO PROVIDER FOR TESTING
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

    #[allow(dead_code)]
    fn remove_utxo(&mut self, outpoint: &OutPoint) {
        self.utxos.remove(outpoint);
    }
}

impl UtxoProvider for MockUtxoProvider {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, Box<dyn std::error::Error>> {
        Ok(self.utxos.get(outpoint).cloned())
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

fn create_test_broadcast(vout: u32, tier: MasternodeTier) -> MasternodeBroadcast {
    let addr = ServiceAddr::new(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));
    MasternodeBroadcast::new(
        OutPoint::new(Hash256::zero(), vout),
        addr,
        vec![1, 2, 3],
        vec![4, 5, 6],
        tier,
        70000,
        1234567890,
    )
}

fn create_db(path: &std::path::Path) -> Arc<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let cfs = vec![ColumnFamilyDescriptor::new(
        CF_MASTERNODES,
        Options::default(),
    )];
    Arc::new(DB::open_cf_descriptors(&opts, path, cfs).unwrap())
}

// ============================================================
// PERSISTENCE TESTS
// ============================================================

#[test]
fn test_persistence_roundtrip() {
    let dir = tempdir().unwrap();
    let db = create_db(dir.path());

    let manager = MasternodeManager::with_db(db.clone()).unwrap();

    // Add 100 masternodes with different tiers
    for i in 0..100 {
        let tier = match i % 5 {
            0 => MasternodeTier::Copper,
            1 => MasternodeTier::Silver,
            2 => MasternodeTier::Gold,
            3 => MasternodeTier::Platinum,
            _ => MasternodeTier::Diamond,
        };

        let mnb = create_test_broadcast(i, tier);
        manager.add(mnb).unwrap();
    }

    assert_eq!(manager.count(), 100);

    // Reload from database
    let manager2 = MasternodeManager::with_db(db.clone()).unwrap();
    assert_eq!(manager2.count(), 100);

    // Verify all tiers are present
    assert_eq!(manager2.count_by_tier(MasternodeTier::Copper), 20);
    assert_eq!(manager2.count_by_tier(MasternodeTier::Silver), 20);
    assert_eq!(manager2.count_by_tier(MasternodeTier::Gold), 20);
    assert_eq!(manager2.count_by_tier(MasternodeTier::Platinum), 20);
    assert_eq!(manager2.count_by_tier(MasternodeTier::Diamond), 20);
}

#[test]
fn test_persistence_update_operations() {
    let dir = tempdir().unwrap();
    let db = create_db(dir.path());

    let mnb = create_test_broadcast(0, MasternodeTier::Copper);
    let outpoint = mnb.vin;

    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        manager.add(mnb).unwrap();

        // Update status
        manager
            .update_status(outpoint, MasternodeStatus::Enabled)
            .unwrap();

        // Update last seen
        manager.update_last_seen(outpoint, 999888777).unwrap();

        // Mark as paid
        manager.mark_as_paid(outpoint, 111222333).unwrap();
    }

    // Reload and verify all updates persisted
    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        let mn = manager.get(outpoint).unwrap();

        assert_eq!(mn.status, MasternodeStatus::Enabled);
        assert_eq!(mn.time_last_checked, 999888777);
        assert_eq!(mn.time_last_paid, 111222333);
    }
}

#[test]
fn test_persistence_removal() {
    let dir = tempdir().unwrap();
    let db = create_db(dir.path());

    let mnb1 = create_test_broadcast(0, MasternodeTier::Copper);
    let mnb2 = create_test_broadcast(1, MasternodeTier::Silver);

    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        manager.add(mnb1.clone()).unwrap();
        manager.add(mnb2.clone()).unwrap();
        assert_eq!(manager.count(), 2);

        // Remove one
        manager.remove(mnb1.vin).unwrap();
        assert_eq!(manager.count(), 1);
    }

    // Reload and verify removal persisted
    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        assert_eq!(manager.count(), 1);
        assert!(!manager.contains(mnb1.vin));
        assert!(manager.contains(mnb2.vin));
    }
}

#[test]
fn test_persistence_clear() {
    let dir = tempdir().unwrap();
    let db = create_db(dir.path());

    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        for i in 0..10 {
            manager
                .add(create_test_broadcast(i, MasternodeTier::Copper))
                .unwrap();
        }
        assert_eq!(manager.count(), 10);

        manager.clear();
        assert_eq!(manager.count(), 0);
    }

    // Reload and verify clear persisted
    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        assert_eq!(manager.count(), 0);
    }
}

// ============================================================
// COLLATERAL VERIFICATION TESTS
// ============================================================

#[test]
fn test_collateral_verification_valid() {
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
fn test_collateral_verification_insufficient_amount() {
    let manager = MasternodeManager::new();
    let mnb = create_test_broadcast(0, MasternodeTier::Copper);
    manager.add(mnb.clone()).unwrap();

    let mut utxo_provider = MockUtxoProvider::new();
    // Wrong amount - should be 10,000,000,000,000 for Copper
    utxo_provider.add_utxo(mnb.vin, 5_000_000_000_000, 100);

    let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 120);
    assert!(result.is_err());

    match result.unwrap_err() {
        MasternodeError::CollateralAmountMismatch { expected, actual } => {
            assert_eq!(expected, 10_000_000_000_000);
            assert_eq!(actual, 5_000_000_000_000);
        }
        _ => panic!("Expected CollateralAmountMismatch error"),
    }
}

#[test]
fn test_collateral_verification_unconfirmed() {
    let manager = MasternodeManager::new();
    let mnb = create_test_broadcast(0, MasternodeTier::Gold);
    manager.add(mnb.clone()).unwrap();

    let mut utxo_provider = MockUtxoProvider::new();
    // Gold tier: 100,000 DIVI = 100,000,000,000,000 satoshis
    utxo_provider.add_utxo(mnb.vin, 100_000_000_000_000, 1000);

    // At height 1010, only 10 confirmations (< 15 required)
    let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 1010);
    assert!(result.is_err());

    match result.unwrap_err() {
        MasternodeError::InsufficientConfirmations { required, actual } => {
            assert_eq!(required, 15);
            assert_eq!(actual, 10);
        }
        _ => panic!("Expected InsufficientConfirmations error"),
    }
}

#[test]
fn test_collateral_verification_exactly_15_confirmations() {
    let manager = MasternodeManager::new();
    let mnb = create_test_broadcast(0, MasternodeTier::Silver);
    manager.add(mnb.clone()).unwrap();

    let mut utxo_provider = MockUtxoProvider::new();
    // Silver tier: 30,000 DIVI = 30,000,000,000,000 satoshis
    utxo_provider.add_utxo(mnb.vin, 30_000_000_000_000, 1000);

    // Test exactly 14 confirmations (should fail)
    let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 1014);
    assert!(result.is_err());

    // Test exactly 15 confirmations (should succeed)
    let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 1015);
    assert!(result.is_ok());
}

#[test]
fn test_collateral_verification_all_tiers() {
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
fn test_collateral_verification_not_found() {
    let manager = MasternodeManager::new();
    let mnb = create_test_broadcast(0, MasternodeTier::Platinum);
    manager.add(mnb.clone()).unwrap();

    let utxo_provider = MockUtxoProvider::new();
    // No UTXO added

    let result = manager.verify_collateral(&mnb.vin, &utxo_provider, 120);
    assert!(result.is_err());

    match result.unwrap_err() {
        MasternodeError::CollateralNotFound(outpoint) => {
            assert_eq!(outpoint, mnb.vin);
        }
        _ => panic!("Expected CollateralNotFound error"),
    }
}

// ============================================================
// SPENT COLLATERAL DETECTION TESTS
// ============================================================

#[test]
fn test_spent_collateral_detection_none_spent() {
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
fn test_spent_collateral_detection_one_spent() {
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
fn test_spent_collateral_detection_all_spent() {
    let mut manager = MasternodeManager::new();
    let mnb1 = create_test_broadcast(0, MasternodeTier::Gold);
    let mnb2 = create_test_broadcast(1, MasternodeTier::Platinum);
    let mnb3 = create_test_broadcast(2, MasternodeTier::Diamond);
    manager.add(mnb1.clone()).unwrap();
    manager.add(mnb2.clone()).unwrap();
    manager.add(mnb3.clone()).unwrap();

    let utxo_provider = MockUtxoProvider::new();
    // No UTXOs - all spent

    let spent = manager.check_spent_collateral(&utxo_provider, 200);
    assert_eq!(spent.len(), 3);

    // Verify all marked as spent
    assert_eq!(
        manager.get(mnb1.vin).unwrap().status,
        MasternodeStatus::VinSpent
    );
    assert_eq!(
        manager.get(mnb2.vin).unwrap().status,
        MasternodeStatus::VinSpent
    );
    assert_eq!(
        manager.get(mnb3.vin).unwrap().status,
        MasternodeStatus::VinSpent
    );
}

#[test]
fn test_spent_collateral_detection_already_marked_spent() {
    let mut manager = MasternodeManager::new();
    let mnb = create_test_broadcast(0, MasternodeTier::Copper);
    manager.add(mnb.clone()).unwrap();

    // Mark as already spent
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
fn test_spent_collateral_detection_outpoint_spent_status() {
    let mut manager = MasternodeManager::new();
    let mnb = create_test_broadcast(0, MasternodeTier::Silver);
    manager.add(mnb.clone()).unwrap();

    // Mark as OutpointSpent (different from VinSpent)
    manager
        .update_status(mnb.vin, MasternodeStatus::OutpointSpent)
        .unwrap();

    let utxo_provider = MockUtxoProvider::new();

    let spent = manager.check_spent_collateral(&utxo_provider, 200);
    // Should not be checked again
    assert_eq!(spent.len(), 0);
}

#[test]
fn test_spent_collateral_detection_persistence() {
    let dir = tempdir().unwrap();
    let db = create_db(dir.path());

    let mnb = create_test_broadcast(0, MasternodeTier::Gold);

    {
        let mut manager = MasternodeManager::with_db(db.clone()).unwrap();
        manager.add(mnb.clone()).unwrap();

        let utxo_provider = MockUtxoProvider::new();
        // UTXO spent

        let spent = manager.check_spent_collateral(&utxo_provider, 200);
        assert_eq!(spent.len(), 1);
    }

    // Reload and verify status persisted
    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        let mn = manager.get(mnb.vin).unwrap();
        assert_eq!(mn.status, MasternodeStatus::VinSpent);
    }
}

#[test]
fn test_spent_collateral_detection_partial() {
    let mut manager = MasternodeManager::new();

    // Add 10 masternodes
    let mut broadcasts = vec![];
    for i in 0..10 {
        let mnb = create_test_broadcast(i, MasternodeTier::Copper);
        manager.add(mnb.clone()).unwrap();
        broadcasts.push(mnb);
    }

    let mut utxo_provider = MockUtxoProvider::new();
    // Only half have UTXOs (even indices)
    for (i, mnb) in broadcasts.iter().enumerate() {
        if i % 2 == 0 {
            utxo_provider.add_utxo(mnb.vin, 10_000_000_000_000, 100);
        }
    }

    let spent = manager.check_spent_collateral(&utxo_provider, 200);
    assert_eq!(spent.len(), 5); // Half were spent

    // Verify odd indices are marked as spent
    for (i, mnb) in broadcasts.iter().enumerate() {
        let mn = manager.get(mnb.vin).unwrap();
        if i % 2 == 0 {
            assert_eq!(mn.status, MasternodeStatus::PreEnabled);
        } else {
            assert_eq!(mn.status, MasternodeStatus::VinSpent);
        }
    }
}

// ============================================================
// EDGE CASE TESTS
// ============================================================

#[test]
fn test_verify_collateral_masternode_not_found() {
    let manager = MasternodeManager::new();

    let mut utxo_provider = MockUtxoProvider::new();
    let outpoint = OutPoint::new(Hash256::zero(), 999);
    utxo_provider.add_utxo(outpoint, 10_000_000_000_000, 100);

    // Masternode doesn't exist
    let result = manager.verify_collateral(&outpoint, &utxo_provider, 120);
    assert!(result.is_err());

    match result.unwrap_err() {
        MasternodeError::NotFound(_) => {}
        _ => panic!("Expected NotFound error"),
    }
}

#[test]
fn test_spent_collateral_detection_enabled_masternodes() {
    let mut manager = MasternodeManager::new();
    let mnb = create_test_broadcast(0, MasternodeTier::Copper);
    manager.add(mnb.clone()).unwrap();

    // Enable the masternode
    manager
        .update_status(mnb.vin, MasternodeStatus::Enabled)
        .unwrap();

    let utxo_provider = MockUtxoProvider::new();
    // UTXO spent

    let spent = manager.check_spent_collateral(&utxo_provider, 200);
    assert_eq!(spent.len(), 1);

    // Even enabled masternodes should be marked as spent
    let mn = manager.get(mnb.vin).unwrap();
    assert_eq!(mn.status, MasternodeStatus::VinSpent);
}
