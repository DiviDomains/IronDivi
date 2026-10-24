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

//! Memory the peer message decoders take before they refuse a payload.
//!
//! Sizes announced by a peer are only promises: Divi Core reserves at most
//! 5 MB for a vector before its items arrive (serialize.h, Unserialize of
//! std::vector) and grows its receive buffer at most 256 KiB ahead of the
//! bytes received (Node.cpp:80-84). The decoders here are held to a fixed
//! bound however large the announced sizes are.
//!
//! The allocator counts bytes in use for this whole test binary, so the
//! file holds a single test and nothing else runs beside it.

use bytes::BytesMut;
use divi_network::constants::{MAINNET_MAGIC, MAX_MESSAGE_SIZE};
use divi_network::{DiviCodec, MessageHeader, NetworkMessage};
use divi_primitives::block::BlockHeader;
use divi_primitives::compact::{CompactSize, MAX_SIZE};
use divi_primitives::serialize::{serialize, Encodable};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_util::codec::Decoder;

struct Counting;

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = IN_USE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        IN_USE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Most memory a decode may take above what was in use before it, for a
/// payload it refuses, whatever sizes the payload announces: one 5 MB
/// reservation for each of the vectors that can nest in a block
/// (transactions, inputs, script) and room to spare
const REFUSED_BOUND: usize = 16 * 1024 * 1024;

/// Bytes taken while `f` runs, above what was in use when it started
fn peak_during<R>(f: impl FnOnce() -> R) -> (usize, R) {
    let base = IN_USE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let r = f();
    (PEAK.load(Ordering::Relaxed) - base, r)
}

fn compact(n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    CompactSize(n).encode(&mut v).unwrap();
    v
}

/// Payloads whose announced sizes promise far more than they carry
fn lying_payloads() -> Vec<(&'static str, Vec<u8>)> {
    let max = compact(MAX_SIZE);
    let v4 = serialize(&BlockHeader {
        version: 4,
        ..Default::default()
    });
    let tx_head = |inputs: &[u8]| {
        let mut t = 1i32.to_le_bytes().to_vec();
        t.extend_from_slice(inputs);
        t
    };
    // One input whose script length is MAX_SIZE
    let mut one_input_huge_script = compact(1);
    one_input_huge_script.extend_from_slice(&[0u8; 36]);
    one_input_huge_script.extend_from_slice(&max);
    let tx_huge_script = tx_head(&one_input_huge_script);
    // No inputs, one output whose script length is MAX_SIZE
    let mut tx_huge_out = tx_head(&compact(0));
    tx_huge_out.extend(compact(1));
    tx_huge_out.extend_from_slice(&[0u8; 8]);
    tx_huge_out.extend_from_slice(&max);

    let mut out = Vec::new();
    for cmd in [
        "addr", "inv", "getdata", "notfound", "headers", "alert", "reject", "spork",
    ] {
        out.push((cmd, max.clone()));
    }
    out.push(("getblocks", [&70920i32.to_le_bytes()[..], &max].concat()));
    out.push(("getheaders", [&70920i32.to_le_bytes()[..], &max].concat()));
    out.push(("version", {
        let mut v = vec![0u8; 4 + 8 + 8 + 26 + 26 + 8];
        v.extend_from_slice(&max);
        v
    }));
    out.push((
        "spork",
        [&[0u8; 4][..], &compact(3), b"abc", &[0u8; 8], &max].concat(),
    ));
    out.push(("alert", [&compact(2)[..], b"ab", &max].concat()));
    out.push(("tx", tx_head(&max)));
    out.push(("tx", tx_huge_script.clone()));
    out.push(("tx", tx_huge_out.clone()));
    out.push(("block", [&v4[..], &max].concat()));
    // Block announcing MAX_SIZE transactions, the first announcing MAX_SIZE
    // inputs
    out.push(("block", [&v4[..], &max, &tx_head(&max)].concat()));
    // ... the first with one input whose script is MAX_SIZE long
    out.push(("block", [&v4[..], &max, &tx_huge_script].concat()));
    out.push(("block", [&v4[..], &max, &tx_huge_out].concat()));
    // ... the first announcing MAX_SIZE inputs, the first of them with a
    // script MAX_SIZE long: three nested reservations
    out.push((
        "block",
        [
            &v4[..],
            &max,
            &tx_head(&[&max[..], &[0u8; 36], &max].concat()),
        ]
        .concat(),
    ));
    // Many announced headers
    out.push(("headers", compact(1_000_000)));
    // Inventory that announces the most items a 2 MiB payload could hold
    out.push(("inv", compact(58_254)));
    out
}

#[test]
fn decoders_take_bounded_memory() {
    // Warm up anything allocated once (tracing callsites, lazy statics)
    for (cmd, p) in lying_payloads() {
        let _ = NetworkMessage::deserialize(cmd, &p);
    }

    let mut worst = 0usize;
    for (cmd, p) in lying_payloads() {
        let (peak, r) = peak_during(|| NetworkMessage::deserialize(cmd, &p));
        assert!(r.is_err(), "{} decoded from a lying payload", cmd);
        assert!(
            peak <= REFUSED_BOUND,
            "{}: {} bytes taken before refusing a {}-byte payload",
            cmd,
            peak,
            p.len()
        );
        worst = worst.max(peak);
    }
    println!("worst refused payload: {} bytes", worst);

    // Random payloads for every command: refused or not, memory stays
    // within the fixed bound plus a small multiple of the payload
    let mut runner = TestRunner::new(Config {
        cases: 512,
        failure_persistence: None,
        ..Config::default()
    });
    const COMMANDS: &[&str] = &[
        "version",
        "addr",
        "inv",
        "getdata",
        "notfound",
        "getblocks",
        "getheaders",
        "headers",
        "block",
        "tx",
        "reject",
        "alert",
        "spork",
    ];
    runner
        .run(
            &(
                prop::sample::select(COMMANDS),
                proptest::collection::vec(any::<u8>(), 0..2048),
            ),
            |(cmd, p)| {
                let (peak, _) = peak_during(|| NetworkMessage::deserialize(cmd, &p));
                prop_assert!(
                    peak <= REFUSED_BOUND,
                    "{}: {} bytes for {} random bytes",
                    cmd,
                    peak,
                    p.len()
                );
                Ok(())
            },
        )
        .unwrap();

    // A header that announces the largest payload, and no payload yet
    let mut header = MessageHeader::new(MAINNET_MAGIC, "block", &[]).serialize();
    header[16..20].copy_from_slice(&MAX_MESSAGE_SIZE.to_le_bytes());
    let (peak, buf) = peak_during(|| {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::from(&header[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        buf
    });
    println!("header alone: {} bytes", peak);
    assert!(
        peak <= 600 * 1024,
        "{} bytes taken for a payload not yet sent",
        peak
    );
    drop(buf);

    // The same header as the first message of a handshake
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let (event_tx, _) = tokio::sync::broadcast::channel(16);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let (conn, _handle) = divi_network::Connection::accept(
            stream,
            MAINNET_MAGIC,
            0,
            1,
            event_tx,
            shutdown_rx,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .await
        .unwrap();
        let task = tokio::spawn(conn.run());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut version = MessageHeader::new(MAINNET_MAGIC, "version", &[]).serialize();
        version[16..20].copy_from_slice(&MAX_MESSAGE_SIZE.to_le_bytes());
        let base = IN_USE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        peer.write_all(&version).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let peak = PEAK.load(Ordering::Relaxed) - base;
        println!("handshake header alone: {} bytes", peak);
        assert!(
            peak <= 600 * 1024,
            "{} bytes taken during the handshake for a payload not yet sent",
            peak
        );
        task.abort();
    });
}
