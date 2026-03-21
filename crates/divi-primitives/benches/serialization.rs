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

//! Benchmarks for Divi primitive serialization
//!
//! These benchmarks measure operations that are directly comparable to the C++ Divi client:
//! - Block header serialization/deserialization
//! - Full block serialization/deserialization
//! - Transaction serialization/deserialization
//!
//! Run with: cargo bench -p divi-primitives

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use divi_primitives::{
    amount::Amount,
    block::{Block, BlockHeader},
    hash::Hash256,
    script::Script,
    serialize::{deserialize, serialize},
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ==================== Block Header Benchmarks ====================

fn create_test_header() -> BlockHeader {
    BlockHeader {
        version: 4,
        prev_block: Hash256::from_bytes([0xab; 32]),
        merkle_root: Hash256::from_bytes([0xcd; 32]),
        time: 1609459200,
        bits: 0x1d00ffff,
        nonce: 12345678,
        accumulator_checkpoint: Hash256::from_bytes([0xef; 32]),
    }
}

fn bench_block_header_serialize(c: &mut Criterion) {
    let header = create_test_header();
    let serialized = serialize(&header);

    let mut group = c.benchmark_group("block_header");
    group.throughput(Throughput::Bytes(serialized.len() as u64));

    group.bench_function("serialize", |b| {
        b.iter(|| serialize(black_box(&header)));
    });

    group.bench_function("deserialize", |b| {
        b.iter(|| deserialize::<BlockHeader>(black_box(&serialized)).unwrap());
    });

    group.bench_function("roundtrip", |b| {
        b.iter(|| {
            let bytes = serialize(black_box(&header));
            deserialize::<BlockHeader>(&bytes).unwrap()
        });
    });

    group.finish();
}

// ==================== Transaction Benchmarks ====================

fn create_p2pkh_script() -> Script {
    // Standard P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    let mut bytes = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20
    bytes.extend_from_slice(&[0u8; 20]); // 20 byte hash
    bytes.push(0x88); // OP_EQUALVERIFY
    bytes.push(0xac); // OP_CHECKSIG
    Script::from_bytes(bytes)
}

fn create_test_transaction(input_count: usize, output_count: usize) -> Transaction {
    let mut rng = StdRng::seed_from_u64(42);

    let vin: Vec<TxIn> = (0..input_count)
        .map(|_| {
            let mut txid_bytes = [0u8; 32];
            rng.fill(&mut txid_bytes);
            TxIn {
                prevout: OutPoint {
                    txid: Hash256::from_bytes(txid_bytes),
                    vout: rng.gen_range(0..10),
                },
                script_sig: Script::from_bytes(vec![0x48; 72]), // typical sig
                sequence: 0xffffffff,
            }
        })
        .collect();

    let vout: Vec<TxOut> = (0..output_count)
        .map(|_| TxOut {
            value: Amount::from_sat(rng.gen_range(1000..100_000_000)),
            script_pubkey: create_p2pkh_script(),
        })
        .collect();

    Transaction {
        version: 1,
        vin,
        vout,
        lock_time: 0,
    }
}

fn bench_transaction_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_serialize");

    // Test various transaction sizes
    for (inputs, outputs) in [(1, 2), (2, 2), (5, 5), (10, 10), (50, 50)] {
        let tx = create_test_transaction(inputs, outputs);
        let serialized = serialize(&tx);

        group.throughput(Throughput::Bytes(serialized.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("serialize", format!("{}in_{}out", inputs, outputs)),
            &tx,
            |b, tx| {
                b.iter(|| serialize(black_box(tx)));
            },
        );
    }

    group.finish();
}

fn bench_transaction_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_deserialize");

    for (inputs, outputs) in [(1, 2), (2, 2), (5, 5), (10, 10), (50, 50)] {
        let tx = create_test_transaction(inputs, outputs);
        let serialized = serialize(&tx);

        group.throughput(Throughput::Bytes(serialized.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("deserialize", format!("{}in_{}out", inputs, outputs)),
            &serialized,
            |b, data| {
                b.iter(|| deserialize::<Transaction>(black_box(data)).unwrap());
            },
        );
    }

    group.finish();
}

// ==================== Full Block Benchmarks ====================

fn create_test_block(tx_count: usize) -> Block {
    let header = create_test_header();
    let transactions: Vec<Transaction> = (0..tx_count)
        .map(|i| {
            if i == 0 {
                // Coinbase
                Transaction {
                    version: 1,
                    vin: vec![TxIn {
                        prevout: OutPoint::null(),
                        script_sig: Script::from_bytes(vec![0x03, 0x01, 0x02, 0x03]),
                        sequence: 0xffffffff,
                    }],
                    vout: vec![TxOut {
                        value: Amount::from_sat(1250_0000_0000),
                        script_pubkey: create_p2pkh_script(),
                    }],
                    lock_time: 0,
                }
            } else {
                create_test_transaction(2, 2)
            }
        })
        .collect();

    Block {
        header,
        transactions,
        block_sig: vec![0x30; 70],
    }
}

fn bench_block_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_serialize");

    for tx_count in [1, 5, 10, 50, 100, 500] {
        let block = create_test_block(tx_count);
        let serialized = serialize(&block);

        group.throughput(Throughput::Bytes(serialized.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("serialize", format!("{}txs", tx_count)),
            &block,
            |b, block| {
                b.iter(|| serialize(black_box(block)));
            },
        );
    }

    group.finish();
}

fn bench_block_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_deserialize");

    for tx_count in [1, 5, 10, 50, 100, 500] {
        let block = create_test_block(tx_count);
        let serialized = serialize(&block);

        group.throughput(Throughput::Bytes(serialized.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("deserialize", format!("{}txs", tx_count)),
            &serialized,
            |b, data| {
                b.iter(|| deserialize::<Block>(black_box(data)).unwrap());
            },
        );
    }

    group.finish();
}

// ==================== Script Benchmarks ====================

fn bench_script_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("script");

    // P2PKH script (most common)
    let p2pkh = create_p2pkh_script();
    let p2pkh_bytes = p2pkh.as_bytes().to_vec();

    group.bench_function("p2pkh_parse", |b| {
        b.iter(|| Script::from_bytes(black_box(p2pkh_bytes.clone())));
    });

    group.bench_function("p2pkh_is_p2pkh", |b| {
        b.iter(|| black_box(&p2pkh).is_p2pkh());
    });

    // OP_RETURN script
    let op_return = Script::new_op_return(&[0u8; 80]);
    group.bench_function("op_return_is_op_return", |b| {
        b.iter(|| black_box(&op_return).is_op_return());
    });

    group.finish();
}

// ==================== Hash256 Benchmarks ====================

fn bench_hash256_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash256");

    let hash = Hash256::from_bytes([0xab; 32]);

    group.bench_function("to_hex", |b| {
        b.iter(|| black_box(&hash).to_hex());
    });

    group.bench_function("from_hex", |b| {
        let hex = "abababababababababababababababababababababababababababababababab";
        b.iter(|| Hash256::from_hex(black_box(hex)).unwrap());
    });

    group.bench_function("is_zero", |b| {
        b.iter(|| black_box(&hash).is_zero());
    });

    group.finish();
}

// ==================== Amount Benchmarks ====================

fn bench_amount_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("amount");

    let amount = Amount::from_sat(123_456_789_000);

    group.bench_function("from_sat", |b| {
        b.iter(|| Amount::from_sat(black_box(123_456_789_000i64)));
    });

    group.bench_function("from_divi", |b| {
        b.iter(|| Amount::from_divi(black_box(1234)));
    });

    group.bench_function("as_divi", |b| {
        b.iter(|| black_box(&amount).as_divi());
    });

    group.bench_function("add", |b| {
        let a = Amount::from_sat(100_000_000);
        let bb = Amount::from_sat(200_000_000);
        b.iter(|| black_box(a) + black_box(bb));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_block_header_serialize,
    bench_transaction_serialize,
    bench_transaction_deserialize,
    bench_block_serialize,
    bench_block_deserialize,
    bench_script_parsing,
    bench_hash256_ops,
    bench_amount_ops,
);

criterion_main!(benches);
