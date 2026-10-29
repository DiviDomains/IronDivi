// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Sizes inside a message: Divi Core's ReadCompactSize refuses a size above
//! MAX_SIZE (0x02000000), and vectors are filled as their items arrive, so a
//! small message announcing a huge count is just a parse error.
//!
//! Kept in its own test binary: without the limit the allocation fails and
//! aborts the whole process.

mod common;
use common::raw_peer::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn huge_counts_are_parse_errors() {
    let t = TestNode::start().await;
    let mut p = RawPeer::connect(&t, "127.0.0.2").await;
    p.handshake().await;

    // inv announcing 0xffffffff items, carrying one
    let mut inv = compact(0xffff_ffff);
    inv.extend_from_slice(&inv_payload(1, 1)[1..]);
    p.send("inv", &inv).await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(
        parse_reject(&reject),
        ("inv".into(), 0x01, "error parsing message".into())
    );

    // tx announcing 2^40 inputs
    let mut tx = 1i32.to_le_bytes().to_vec();
    tx.extend_from_slice(&compact(1 << 40));
    tx.extend_from_slice(&[0u8; 64]);
    p.send("tx", &tx).await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(parse_reject(&reject).0, "tx");

    // A size just within MAX_SIZE that the payload does not carry
    let mut addr = compact(0x0200_0000);
    addr.extend_from_slice(&[0u8; 30]);
    p.send("addr", &addr).await;
    let reject = p.expect("reject", WAIT).await.expect("reject");
    assert_eq!(parse_reject(&reject).0, "addr");

    assert!(p.alive().await);
}
