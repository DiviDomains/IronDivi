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

//! Benchmarks for masternode registry operations
//!
//! These benchmarks measure critical masternode performance:
//! - Registry save/load operations with varying sizes
//! - Masternode lookups
//! - Database persistence overhead
//!
//! Run with: cargo bench -p divi-masternode

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use divi_masternode::{
    MasternodeBroadcast, MasternodeManager, MasternodeStatus, MasternodeTier, ServiceAddr,
};
use divi_primitives::hash::Hash256;
use divi_primitives::transaction::OutPoint;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use tempfile::TempDir;

// ==================== Masternode Broadcast Creation Helpers ====================

fn create_test_masternode_broadcast(rng: &mut StdRng, index: u32) -> MasternodeBroadcast {
    let mut txid_bytes = [0u8; 32];
    rng.fill(&mut txid_bytes);

    let outpoint = OutPoint::new(Hash256::from_bytes(txid_bytes), index % 5);

    let mut pubkey_collateral_bytes = [0u8; 33];
    rng.fill(&mut pubkey_collateral_bytes[..]);
    pubkey_collateral_bytes[0] = 0x02; // Compressed public key marker

    let mut pubkey_masternode_bytes = [0u8; 33];
    rng.fill(&mut pubkey_masternode_bytes[..]);
    pubkey_masternode_bytes[0] = 0x03; // Compressed public key marker

    let ip = Ipv6Addr::new(
        rng.gen::<u16>(),
        rng.gen::<u16>(),
        rng.gen::<u16>(),
        rng.gen::<u16>(),
        rng.gen::<u16>(),
        rng.gen::<u16>(),
        rng.gen::<u16>(),
        rng.gen::<u16>(),
    );
    let port = 51472 + (index % 100) as u16;
    let addr = ServiceAddr::new(SocketAddrV6::new(ip, port, 0, 0));

    let tier = match index % 5 {
        0 => MasternodeTier::Copper,
        1 => MasternodeTier::Silver,
        2 => MasternodeTier::Gold,
        3 => MasternodeTier::Platinum,
        _ => MasternodeTier::Diamond,
    };

    let mut signature = [0u8; 71];
    rng.fill(&mut signature[..]);

    let timestamp = 1600000000 + (index as i64);

    MasternodeBroadcast {
        vin: outpoint,
        addr,
        pubkey_collateral: pubkey_collateral_bytes.to_vec(),
        pubkey_masternode: pubkey_masternode_bytes.to_vec(),
        sig_time: timestamp,
        protocol_version: 70922,
        tier,
        signature: signature.to_vec(),
    }
}

fn create_masternode_set(count: usize) -> Vec<MasternodeBroadcast> {
    let mut rng = StdRng::seed_from_u64(42);
    (0..count)
        .map(|i| create_test_masternode_broadcast(&mut rng, i as u32))
        .collect()
}

// ==================== In-Memory Operations ====================

fn bench_masternode_add_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("masternode_add");

    for count in [10, 100, 1000, 5000] {
        let masternodes = create_masternode_set(count);

        group.bench_with_input(BenchmarkId::new("add", count), &count, |b, _| {
            b.iter(|| {
                let manager = MasternodeManager::new();
                for mnb in &masternodes {
                    let _ = manager.add(black_box(mnb.clone()));
                }
            });
        });
    }

    group.finish();
}

fn bench_masternode_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("masternode_lookup");

    for count in [100, 1000, 5000, 10000] {
        let masternodes = create_masternode_set(count);
        let manager = MasternodeManager::new();

        // Populate manager
        for mnb in &masternodes {
            let _ = manager.add(mnb.clone());
        }

        // Benchmark lookups
        group.bench_with_input(BenchmarkId::new("get", count), &count, |b, _| {
            b.iter(|| {
                for mnb in &masternodes {
                    let _ = manager.get(black_box(mnb.vin));
                }
            });
        });
    }

    group.finish();
}

fn bench_masternode_filtering(c: &mut Criterion) {
    let mut group = c.benchmark_group("masternode_filtering");

    for count in [100, 1000, 5000, 10000] {
        let masternodes = create_masternode_set(count);
        let manager = MasternodeManager::new();

        for mnb in &masternodes {
            let _ = manager.add(mnb.clone());
        }

        // Benchmark getting all by tier
        group.bench_with_input(BenchmarkId::new("get_by_tier", count), &count, |b, _| {
            b.iter(|| {
                let _ = manager.get_by_tier(black_box(MasternodeTier::Gold));
            });
        });

        // Benchmark getting all by status
        group.bench_with_input(BenchmarkId::new("get_by_status", count), &count, |b, _| {
            b.iter(|| {
                let _ = manager.get_by_status(black_box(MasternodeStatus::Enabled));
            });
        });

        // Benchmark getting all enabled
        group.bench_with_input(
            BenchmarkId::new("get_all_enabled", count),
            &count,
            |b, _| {
                b.iter(|| {
                    let _ = manager.get_enabled();
                });
            },
        );
    }

    group.finish();
}

// ==================== Database Persistence Operations ====================

fn setup_test_db() -> (TempDir, Arc<DB>) {
    let temp_dir = TempDir::new().unwrap();
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let cfs = vec![ColumnFamilyDescriptor::new(
        "masternodes",
        Options::default(),
    )];
    let db = DB::open_cf_descriptors(&opts, temp_dir.path(), cfs).unwrap();

    (temp_dir, Arc::new(db))
}

fn bench_masternode_save_to_db(c: &mut Criterion) {
    let mut group = c.benchmark_group("masternode_db_save");

    for count in [100, 1000, 5000] {
        let masternodes = create_masternode_set(count);

        group.bench_with_input(BenchmarkId::new("save", count), &count, |b, _| {
            b.iter(|| {
                let (_temp_dir, db) = setup_test_db();
                let manager = MasternodeManager::with_db(db).unwrap();

                for mnb in &masternodes {
                    let _ = manager.add(mnb.clone());
                }

                // save() is called automatically on add, but benchmark explicit save
                let _ = manager.save();
            });
        });
    }

    group.finish();
}

fn bench_masternode_load_from_db(c: &mut Criterion) {
    let mut group = c.benchmark_group("masternode_db_load");

    for count in [100, 1000, 5000] {
        let masternodes = create_masternode_set(count);

        // Setup: Populate database
        let (_temp_dir, db) = setup_test_db();
        {
            let manager = MasternodeManager::with_db(db.clone()).unwrap();
            for mnb in &masternodes {
                let _ = manager.add(mnb.clone());
            }
            manager.save().unwrap();
        }

        group.bench_with_input(BenchmarkId::new("load", count), &count, |b, _| {
            b.iter(|| {
                let manager_with_db = MasternodeManager::with_db(db.clone()).unwrap();
                black_box(manager_with_db);
            });
        });
    }

    group.finish();
}

fn bench_masternode_full_persistence_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("masternode_persistence_cycle");

    for count in [100, 1000, 5000] {
        let masternodes = create_masternode_set(count);

        group.bench_with_input(BenchmarkId::new("save_and_load", count), &count, |b, _| {
            b.iter(|| {
                let (_temp_dir, db) = setup_test_db();

                // Save phase
                {
                    let manager = MasternodeManager::with_db(db.clone()).unwrap();
                    for mnb in &masternodes {
                        let _ = manager.add(mnb.clone());
                    }
                    manager.save().unwrap();
                }

                // Load phase
                {
                    let manager = MasternodeManager::with_db(db.clone()).unwrap();
                    black_box(manager);
                }
            });
        });
    }

    group.finish();
}

// ==================== Real-World Scenarios ====================

fn bench_realistic_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_scenarios");

    // Small network: 100 masternodes
    let small_masternodes = create_masternode_set(100);
    group.bench_function("small_network_100_masternodes", |b| {
        b.iter(|| {
            let manager = MasternodeManager::new();
            for mnb in &small_masternodes {
                let _ = manager.add(mnb.clone());
            }
            let enabled = manager.get_enabled();
            black_box(enabled);
        });
    });

    // Medium network: 1000 masternodes
    let medium_masternodes = create_masternode_set(1000);
    group.bench_function("medium_network_1000_masternodes", |b| {
        b.iter(|| {
            let manager = MasternodeManager::new();
            for mnb in &medium_masternodes {
                let _ = manager.add(mnb.clone());
            }
            let enabled = manager.get_enabled();
            black_box(enabled);
        });
    });

    // Large network: 5000 masternodes (TARGET)
    let large_masternodes = create_masternode_set(5000);
    group.bench_function("large_network_5000_masternodes", |b| {
        b.iter(|| {
            let manager = MasternodeManager::new();
            for mnb in &large_masternodes {
                let _ = manager.add(mnb.clone());
            }
            let enabled = manager.get_enabled();
            black_box(enabled);
        });
    });

    // Very large network: 10000 masternodes
    let huge_masternodes = create_masternode_set(10000);
    group.bench_function("huge_network_10000_masternodes", |b| {
        b.iter(|| {
            let manager = MasternodeManager::new();
            for mnb in &huge_masternodes {
                let _ = manager.add(mnb.clone());
            }
            let enabled = manager.get_enabled();
            black_box(enabled);
        });
    });

    group.finish();
}

fn bench_5000_masternode_save_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_5000_masternodes");

    let masternodes = create_masternode_set(5000);

    // Target: Load 5000 masternodes in < 1 second
    group.bench_function("save_5000_to_db", |b| {
        b.iter(|| {
            let (_temp_dir, db) = setup_test_db();
            let manager = MasternodeManager::with_db(db).unwrap();

            for mnb in &masternodes {
                let _ = manager.add(mnb.clone());
            }

            manager.save().unwrap();
        });
    });

    // Benchmark load separately
    let (_temp_dir, db) = setup_test_db();
    {
        let manager = MasternodeManager::with_db(db.clone()).unwrap();
        for mnb in &masternodes {
            let _ = manager.add(mnb.clone());
        }
        manager.save().unwrap();
    }

    group.bench_function("load_5000_from_db", |b| {
        b.iter(|| {
            let manager = MasternodeManager::with_db(db.clone()).unwrap();
            black_box(manager);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_masternode_add_operations,
    bench_masternode_lookup,
    bench_masternode_filtering,
    bench_masternode_save_to_db,
    bench_masternode_load_from_db,
    bench_masternode_full_persistence_cycle,
    bench_realistic_scenarios,
    bench_5000_masternode_save_load,
);

criterion_main!(benches);
