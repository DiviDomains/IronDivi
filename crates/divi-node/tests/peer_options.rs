// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Run-time peer options as Divi Core applies them: `-maxconnections` less
//! the 16 outbound slots is the number of inbound peers taken (net.cpp:757).

mod common;
use common::raw_peer::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_peers_stop_at_the_inbound_limit() {
    // -maxconnections=17: 16 outbound slots and one inbound
    let t = TestNode::start_with(|c| {
        c.p2p.max_outbound = 16;
        c.p2p.max_inbound = 1;
    })
    .await;
    let mut first = RawPeer::connect(&t, "127.0.0.2").await;
    first.handshake().await;

    let mut second = RawPeer::connect(&t, "127.0.0.3").await;
    second
        .send(
            "version",
            &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
        )
        .await;
    assert!(
        second.closed_within(WAIT).await,
        "a second inbound peer was taken with one inbound slot"
    );
    assert!(first.alive().await, "the first inbound peer was dropped");
}
