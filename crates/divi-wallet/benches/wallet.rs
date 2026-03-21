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

//! Benchmarks for wallet operations
//!
//! These benchmarks measure critical wallet performance:
//! - Coin selection from varying UTXO set sizes
//! - UTXO management operations
//! - Wallet database operations
//!
//! Run with: cargo bench -p divi-wallet

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_wallet::coin_selection::{select, CoinSelector, MinimumSelector};
use divi_wallet::wallet_db::WalletUtxo;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;

// ==================== UTXO Creation Helpers ====================

fn create_test_utxo(rng: &mut StdRng, index: u32, value_sat: i64) -> WalletUtxo {
    let mut txid_bytes = [0u8; 32];
    rng.fill(&mut txid_bytes);

    let mut utxo = WalletUtxo::new(
        Hash256::from_bytes(txid_bytes),
        index % 5,
        Amount::from_sat(value_sat),
        Script::default(),
        format!("bench_address_{}", index),
    );
    utxo.height = Some(100 + (index % 1000));
    utxo
}

fn create_utxo_set(count: usize, min_value: i64, max_value: i64) -> Vec<WalletUtxo> {
    let mut rng = StdRng::seed_from_u64(42);
    (0..count)
        .map(|i| {
            let value = rng.gen_range(min_value..=max_value);
            create_test_utxo(&mut rng, i as u32, value)
        })
        .collect()
}

// ==================== Coin Selection Benchmarks ====================

fn bench_coin_selection_varying_utxo_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("coin_selection_utxo_count");

    // Test with various UTXO set sizes
    for utxo_count in [10, 100, 1000, 10000] {
        let utxos = create_utxo_set(utxo_count, 1_000_000, 100_000_000); // 0.01 to 1 DIVI
        let target = Amount::from_sat(50_000_000); // 0.5 DIVI
        let fee_rate = 1000; // 1000 sats/byte
        let excluded = HashSet::new();

        group.bench_with_input(
            BenchmarkId::new("select_minimum", utxo_count),
            &utxo_count,
            |b, _| {
                b.iter(|| {
                    MinimumSelector.select(
                        black_box(&utxos),
                        black_box(target),
                        black_box(fee_rate),
                        black_box(1),
                        black_box(&excluded),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_coin_selection_varying_target(c: &mut Criterion) {
    let mut group = c.benchmark_group("coin_selection_target_size");

    let utxos = create_utxo_set(1000, 1_000_000, 100_000_000);
    let fee_rate = 1000;
    let excluded = HashSet::new();

    // Test with different target amounts
    for target_percent in [10, 25, 50, 75, 90] {
        let total: i64 = utxos.iter().map(|u| u.value.as_sat()).sum();
        let target = Amount::from_sat((total * target_percent) / 100);

        group.bench_with_input(
            BenchmarkId::new("target_percent", target_percent),
            &target_percent,
            |b, _| {
                b.iter(|| {
                    MinimumSelector.select(
                        black_box(&utxos),
                        black_box(target),
                        black_box(fee_rate),
                        black_box(1),
                        black_box(&excluded),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_coin_selection_with_exclusions(c: &mut Criterion) {
    let mut group = c.benchmark_group("coin_selection_exclusions");

    let utxos = create_utxo_set(1000, 1_000_000, 100_000_000);
    let target = Amount::from_sat(50_000_000);
    let fee_rate = 1000;

    // Test with varying numbers of excluded UTXOs
    for exclude_count in [0, 100, 500, 900] {
        let mut excluded = HashSet::new();
        for i in 0..exclude_count {
            excluded.insert(utxos[i].outpoint());
        }

        group.bench_with_input(
            BenchmarkId::new("excluded", exclude_count),
            &exclude_count,
            |b, _| {
                b.iter(|| {
                    MinimumSelector.select(
                        black_box(&utxos),
                        black_box(target),
                        black_box(fee_rate),
                        black_box(1),
                        black_box(&excluded),
                    )
                });
            },
        );
    }

    group.finish();
}

// ==================== Multiple Output Scenarios ====================

fn bench_coin_selection_multiple_outputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("coin_selection_outputs");

    let utxos = create_utxo_set(1000, 1_000_000, 100_000_000);
    let target = Amount::from_sat(50_000_000);
    let fee_rate = 1000;
    let excluded = HashSet::new();

    // Test with different numbers of outputs
    for output_count in [1, 2, 5, 10, 20] {
        group.bench_with_input(
            BenchmarkId::new("outputs", output_count),
            &output_count,
            |b, _| {
                b.iter(|| {
                    MinimumSelector.select(
                        black_box(&utxos),
                        black_box(target),
                        black_box(fee_rate),
                        black_box(output_count),
                        black_box(&excluded),
                    )
                });
            },
        );
    }

    group.finish();
}

// ==================== Realistic Wallet Scenarios ====================

fn bench_small_payment(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_scenarios");

    // Typical wallet: 50 UTXOs, small payment
    let utxos = create_utxo_set(50, 10_000_000, 500_000_000); // 0.1 to 5 DIVI
    let target = Amount::from_sat(5_000_000); // 0.05 DIVI
    let fee_rate = 1000;

    group.bench_function("small_payment_50_utxos", |b| {
        b.iter(|| {
            select::select_minimum(
                black_box(&utxos),
                black_box(target),
                black_box(fee_rate),
                black_box(1),
            )
        });
    });

    // Large wallet: 500 UTXOs, medium payment
    let large_utxos = create_utxo_set(500, 10_000_000, 1_000_000_000);
    let medium_target = Amount::from_sat(100_000_000); // 1 DIVI

    group.bench_function("medium_payment_500_utxos", |b| {
        b.iter(|| {
            select::select_minimum(
                black_box(&large_utxos),
                black_box(medium_target),
                black_box(fee_rate),
                black_box(1),
            )
        });
    });

    // Very large wallet: 5000 UTXOs, large payment
    let huge_utxos = create_utxo_set(5000, 10_000_000, 10_000_000_000);
    let large_target = Amount::from_sat(10_000_000_000); // 100 DIVI

    group.bench_function("large_payment_5000_utxos", |b| {
        b.iter(|| {
            select::select_minimum(
                black_box(&huge_utxos),
                black_box(large_target),
                black_box(fee_rate),
                black_box(1),
            )
        });
    });

    group.finish();
}

// ==================== Stress Tests ====================

fn bench_worst_case_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("worst_case");

    // Worst case: Need to select many small UTXOs to meet target
    let many_small_utxos = create_utxo_set(10000, 100_000, 500_000); // 0.001 to 0.005 DIVI
    let large_target = Amount::from_sat(5_000_000_000); // 50 DIVI
    let fee_rate = 1000;

    group.bench_function("many_small_utxos", |b| {
        b.iter(|| {
            let _ = select::select_minimum(
                black_box(&many_small_utxos),
                black_box(large_target),
                black_box(fee_rate),
                black_box(1),
            );
        });
    });

    // Best case: Single large UTXO covers target
    let one_large_utxo = create_utxo_set(1, 100_000_000_000, 100_000_000_000); // 1000 DIVI
    let small_target = Amount::from_sat(1_000_000); // 0.01 DIVI

    group.bench_function("single_large_utxo", |b| {
        b.iter(|| {
            select::select_minimum(
                black_box(&one_large_utxo),
                black_box(small_target),
                black_box(fee_rate),
                black_box(1),
            )
        });
    });

    group.finish();
}

// ==================== Confirmation-Based Selection ====================

fn bench_confirmation_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("confirmation_selection");

    let utxos = create_utxo_set(1000, 1_000_000, 100_000_000);
    let target = Amount::from_sat(50_000_000);
    let fee_rate = 1000;
    let current_height = 1100;

    // Test with different minimum confirmation requirements
    for min_confs in [1, 3, 6, 10] {
        group.bench_with_input(
            BenchmarkId::new("min_confirmations", min_confs),
            &min_confs,
            |b, &min_confs| {
                b.iter(|| {
                    select::select_by_confirmations(
                        black_box(&utxos),
                        black_box(target),
                        black_box(fee_rate),
                        black_box(1),
                        black_box(min_confs),
                        black_box(current_height),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_coin_selection_varying_utxo_count,
    bench_coin_selection_varying_target,
    bench_coin_selection_with_exclusions,
    bench_coin_selection_multiple_outputs,
    bench_small_payment,
    bench_worst_case_scenarios,
    bench_confirmation_selection,
);

criterion_main!(benches);
