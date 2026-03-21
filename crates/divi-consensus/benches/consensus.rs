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

//! Benchmarks for Proof-of-Stake consensus operations
//!
//! These benchmarks measure the most critical consensus operations that are
//! directly comparable to the C++ Divi client:
//! - Kernel hash computation (compute_stake_hash)
//! - Target hit checking (stake_target_hit)
//! - Difficulty target calculations
//!
//! The PoS kernel hash is computed ~1000 times per second during staking,
//! so this is a critical hot path.
//!
//! Run with: cargo bench -p divi-consensus

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use divi_consensus::{
    bits_to_difficulty, compute_stake_hash, difficulty_to_bits, stake_target_hit, StakingData,
    Target,
};
use divi_primitives::{amount::Amount, hash::Hash256, transaction::OutPoint};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ==================== Kernel Hash Computation ====================

fn create_test_staking_data() -> StakingData {
    // Real test vector from Divi block 10k
    StakingData::new(
        470026099,  // nBits
        1538645320, // coinstake start time
        Hash256::from_hex("967b03e3c1daf39633ed73ffb29abfcab9ae5b384dc5b95dabee0890bf8b4546")
            .unwrap(),
        OutPoint::new(
            Hash256::from_hex("4266403b499375917920311b1af704805d3fa2d6d6f4e3217026618028423607")
                .unwrap(),
            1,
        ),
        Amount::from_sat(62542750000000),
        Hash256::from_hex("acf49c06030a7a76059a25b174dc7adcdc5f4ad36c91b564c585743af4829f7a")
            .unwrap(),
    )
}

fn bench_compute_stake_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("kernel_hash");

    let stake_modifier: u64 = 13260253192;
    let coinstake_time: u32 = 1538645320;
    let prevout_txid =
        Hash256::from_hex("4266403b499375917920311b1af704805d3fa2d6d6f4e3217026618028423607")
            .unwrap();
    let prevout_vout: u32 = 1;
    let timestamp: u32 = 1538663336;

    // This is THE critical hot path for staking
    group.bench_function("compute_stake_hash", |b| {
        b.iter(|| {
            compute_stake_hash(
                black_box(stake_modifier),
                black_box(coinstake_time),
                black_box(&prevout_txid),
                black_box(prevout_vout),
                black_box(timestamp),
            )
        });
    });

    // Test with different timestamps (simulating scanning)
    group.bench_function("compute_100_timestamps", |b| {
        b.iter(|| {
            for ts in timestamp..(timestamp + 100) {
                compute_stake_hash(
                    stake_modifier,
                    coinstake_time,
                    &prevout_txid,
                    prevout_vout,
                    ts,
                );
            }
        });
    });

    group.finish();
}

// ==================== Target Hit Checking ====================

fn bench_stake_target_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_hit");

    let staking_data = create_test_staking_data();
    let stake_modifier: u64 = 13260253192;
    let timestamp: u32 = 1538663336;
    let target = Target::from_compact(staking_data.n_bits);
    let value = staking_data.utxo_value.as_sat();
    let time_weight = (timestamp - staking_data.block_time_of_first_confirmation) as i64;

    // Compute hash once for target checking
    let hash_proof = compute_stake_hash(
        stake_modifier,
        staking_data.block_time_of_first_confirmation,
        &staking_data.utxo_being_staked.txid,
        staking_data.utxo_being_staked.vout,
        timestamp,
    );

    group.bench_function("stake_target_hit", |b| {
        b.iter(|| {
            stake_target_hit(
                black_box(&hash_proof),
                black_box(value),
                black_box(&target),
                black_box(time_weight),
            )
        });
    });

    // Full check (hash + target hit)
    group.bench_function("hash_and_target_check", |b| {
        b.iter(|| {
            let hash = compute_stake_hash(
                stake_modifier,
                staking_data.block_time_of_first_confirmation,
                &staking_data.utxo_being_staked.txid,
                staking_data.utxo_being_staked.vout,
                timestamp,
            );
            stake_target_hit(&hash, value, &target, time_weight)
        });
    });

    group.finish();
}

// ==================== Target/Difficulty Calculations ====================

fn bench_difficulty_target(c: &mut Criterion) {
    let mut group = c.benchmark_group("difficulty");

    let bits: u32 = 470026099;

    group.bench_function("bits_to_difficulty", |b| {
        b.iter(|| bits_to_difficulty(black_box(bits)));
    });

    let difficulty: f64 = 12345.67;
    group.bench_function("difficulty_to_bits", |b| {
        b.iter(|| difficulty_to_bits(black_box(difficulty)));
    });

    // Target operations
    let target = Target::from_compact(bits);

    group.bench_function("target_from_compact", |b| {
        b.iter(|| Target::from_compact(black_box(bits)));
    });

    group.bench_function("target_to_compact", |b| {
        b.iter(|| black_box(&target).to_compact());
    });

    group.finish();
}

// ==================== Staking Simulation ====================

fn bench_staking_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("staking_simulation");

    // Simulate staking with multiple UTXOs
    let mut rng = StdRng::seed_from_u64(42);

    // Create multiple staking data entries (simulating wallet UTXOs)
    let utxos: Vec<StakingData> = (0..10)
        .map(|i| {
            let mut hash_bytes = [0u8; 32];
            rng.fill(&mut hash_bytes);
            StakingData::new(
                470026099,
                1538645320 + i * 1000,
                Hash256::from_bytes(hash_bytes),
                OutPoint::new(Hash256::from_bytes(hash_bytes), i as u32 % 5),
                Amount::from_sat(rng.gen_range(1000_0000_0000..10000_0000_0000)),
                Hash256::from_bytes(hash_bytes),
            )
        })
        .collect();

    let stake_modifier: u64 = 13260253192;

    // Simulate one staking round: check all UTXOs across time range
    group.bench_function("stake_round_10_utxos_512_timestamps", |b| {
        b.iter(|| {
            let base_time = 1538663336u32;
            for utxo in &utxos {
                let target = Target::from_compact(utxo.n_bits);
                for ts in base_time..(base_time + 512) {
                    let hash = compute_stake_hash(
                        stake_modifier,
                        utxo.block_time_of_first_confirmation,
                        &utxo.utxo_being_staked.txid,
                        utxo.utxo_being_staked.vout,
                        ts,
                    );
                    let time_weight = (ts - utxo.block_time_of_first_confirmation) as i64;
                    if let Ok(true) =
                        stake_target_hit(&hash, utxo.utxo_value.as_sat(), &target, time_weight)
                    {
                        // Found a valid proof
                        break;
                    }
                }
            }
        });
    });

    // Just the hash computations (no target checking)
    group.bench_function("hash_only_10_utxos_512_timestamps", |b| {
        b.iter(|| {
            let base_time = 1538663336u32;
            for utxo in &utxos {
                for ts in base_time..(base_time + 512) {
                    compute_stake_hash(
                        stake_modifier,
                        utxo.block_time_of_first_confirmation,
                        &utxo.utxo_being_staked.txid,
                        utxo.utxo_being_staked.vout,
                        ts,
                    );
                }
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_compute_stake_hash,
    bench_stake_target_hit,
    bench_difficulty_target,
    bench_staking_simulation,
);

criterion_main!(benches);
