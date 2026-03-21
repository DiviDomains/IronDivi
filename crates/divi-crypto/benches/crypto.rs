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

//! Benchmarks for cryptographic operations
//!
//! These benchmarks measure operations that are directly comparable to the C++ Divi client:
//! - SHA256 hashing (single and double)
//! - RIPEMD160 hashing
//! - Hash160 (RIPEMD160(SHA256))
//! - ECDSA signing and verification
//! - Key generation and derivation
//!
//! Run with: cargo bench -p divi-crypto

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use divi_crypto::{
    hash::{hash160, hash256, ripemd160, sha256},
    keys::{KeyPair, SecretKey},
    signature::{sign_hash, verify_hash},
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ==================== SHA256 Benchmarks ====================

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    // Test various data sizes (common in blockchain operations)
    for size in [32, 64, 80, 256, 1024, 4096, 65536] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| sha256(black_box(data)));
        });
    }

    group.finish();
}

// ==================== Double SHA256 (hash256) Benchmarks ====================

fn bench_hash256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash256_double_sha256");

    // Block header is 80 bytes (or 112+ for PoS with signature)
    // Transaction hashing varies widely
    for size in [32, 80, 112, 256, 1024, 4096] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| hash256(black_box(data)));
        });
    }

    // Specific benchmark for block header hashing (most critical path)
    let header_bytes = vec![0u8; 80];
    group.bench_function("block_header_80bytes", |b| {
        b.iter(|| hash256(black_box(&header_bytes)));
    });

    group.finish();
}

// ==================== RIPEMD160 Benchmarks ====================

fn bench_ripemd160(c: &mut Criterion) {
    let mut group = c.benchmark_group("ripemd160");

    for size in [20, 32, 64, 256] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| ripemd160(black_box(data)));
        });
    }

    group.finish();
}

// ==================== Hash160 Benchmarks ====================

fn bench_hash160(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash160");

    // Hash160 is used for address generation from public keys
    // Public keys are 33 bytes (compressed) or 65 bytes (uncompressed)
    for size in [33, 65] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| hash160(black_box(data)));
        });
    }

    // Typical public key (33 bytes compressed)
    let pubkey_bytes = vec![0x02; 33];
    group.bench_function("pubkey_33bytes", |b| {
        b.iter(|| hash160(black_box(&pubkey_bytes)));
    });

    group.finish();
}

// ==================== ECDSA Key Generation ====================

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_keygen");

    group.bench_function("generate_keypair", |b| {
        b.iter(KeyPair::new_random);
    });

    // From known bytes (deterministic)
    let secret_bytes = [0xab; 32];
    group.bench_function("from_secret_bytes", |b| {
        b.iter(|| SecretKey::from_bytes(black_box(&secret_bytes)).unwrap());
    });

    // Derive public key from secret
    let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
    group.bench_function("derive_pubkey", |b| {
        b.iter(|| black_box(&secret).public_key());
    });

    group.finish();
}

// ==================== ECDSA Signing ====================

fn bench_ecdsa_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_sign");

    let keypair = KeyPair::new_random();
    let secret = keypair.secret_key();
    let message = [0xab; 32];

    group.bench_function("sign_hash", |b| {
        b.iter(|| sign_hash(black_box(secret), black_box(&message)).unwrap());
    });

    // Sign different messages (to avoid any caching)
    let mut rng = StdRng::seed_from_u64(42);
    group.bench_function("sign_random_hashes", |b| {
        b.iter(|| {
            let mut msg_bytes = [0u8; 32];
            rng.fill(&mut msg_bytes);
            sign_hash(secret, black_box(&msg_bytes)).unwrap()
        });
    });

    group.finish();
}

// ==================== ECDSA Verification ====================

fn bench_ecdsa_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_verify");

    let keypair = KeyPair::new_random();
    let secret = keypair.secret_key();
    let pubkey = keypair.public_key();
    let message = [0xab; 32];
    let signature = sign_hash(secret, &message).unwrap();

    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            verify_hash(
                black_box(pubkey),
                black_box(&signature),
                black_box(&message),
            )
        });
    });

    // Batch verification simulation (verify multiple signatures)
    let signatures: Vec<_> = (0..10)
        .map(|i| {
            let msg = [i as u8; 32];
            let sig = sign_hash(secret, &msg).unwrap();
            (msg, sig)
        })
        .collect();

    group.bench_function("verify_10_signatures", |b| {
        b.iter(|| {
            for (msg, sig) in &signatures {
                verify_hash(black_box(pubkey), black_box(sig), black_box(msg));
            }
        });
    });

    group.finish();
}

// ==================== Combined Operations ====================

fn bench_address_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_derivation");

    // Full address derivation: generate keypair -> get pubkey -> hash160
    group.bench_function("full_address_from_new_key", |b| {
        b.iter(|| {
            let keypair = KeyPair::new_random();
            let pubkey = keypair.public_key();
            let pubkey_bytes = pubkey.serialize_compressed();
            hash160(&pubkey_bytes)
        });
    });

    // Just the hash part (from existing pubkey)
    let keypair = KeyPair::new_random();
    let pubkey = keypair.public_key();
    let pubkey_bytes = pubkey.serialize_compressed();

    group.bench_function("hash160_from_pubkey", |b| {
        b.iter(|| hash160(black_box(&pubkey_bytes)));
    });

    group.finish();
}

fn bench_transaction_signing_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx_signing_simulation");

    let keypair = KeyPair::new_random();
    let secret = keypair.secret_key();

    // Simulate signing a transaction with N inputs
    for input_count in [1, 2, 5, 10] {
        group.bench_with_input(
            BenchmarkId::new("sign_inputs", input_count),
            &input_count,
            |b, &count| {
                b.iter(|| {
                    for i in 0..count {
                        // Each input requires hashing the sighash preimage and signing
                        let sighash = hash256(&[i as u8; 256]); // Simulate sighash computation
                        let msg: [u8; 32] = sighash.as_ref().try_into().unwrap();
                        sign_hash(secret, black_box(&msg)).unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_hash256,
    bench_ripemd160,
    bench_hash160,
    bench_key_generation,
    bench_ecdsa_signing,
    bench_ecdsa_verification,
    bench_address_derivation,
    bench_transaction_signing_simulation,
);

criterion_main!(benches);
