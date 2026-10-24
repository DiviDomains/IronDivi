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

//! What a connection answers to a message that does not parse, seen from
//! the peer's side of a loopback socket

use divi_network::constants::{MAINNET_MAGIC, PROTOCOL_VERSION};
use divi_network::{
    Connection, MessageHeader, NetAddr, NetworkMessage, PeerHandle, VersionMessage, HEADER_SIZE,
};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

async fn read_message(s: &mut TcpStream) -> NetworkMessage {
    let mut h = [0u8; HEADER_SIZE];
    s.read_exact(&mut h).await.unwrap();
    let header = MessageHeader::deserialize(&h).unwrap();
    let mut p = vec![0u8; header.payload_size as usize];
    s.read_exact(&mut p).await.unwrap();
    NetworkMessage::deserialize(&header.command_string(), &p).unwrap()
}

async fn send_raw(s: &mut TcpStream, command: &str, payload: &[u8]) {
    let mut f = MessageHeader::new(MAINNET_MAGIC, command, payload).serialize();
    f.extend_from_slice(payload);
    s.write_all(&f).await.unwrap();
}

async fn send(s: &mut TcpStream, m: NetworkMessage) {
    s.write_all(&m.to_bytes(MAINNET_MAGIC).unwrap())
        .await
        .unwrap();
}

/// A connected peer past the handshake, and what keeps the connection
/// open (its handle and shutdown sender)
async fn connected_peer() -> (TcpStream, (PeerHandle, broadcast::Sender<()>)) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut peer = TcpStream::connect(addr).await.unwrap();
    let (stream, _) = listener.accept().await.unwrap();

    let (event_tx, _) = broadcast::channel(64);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (conn, handle) = Connection::accept(
        stream,
        MAINNET_MAGIC,
        0,
        1,
        event_tx,
        shutdown_rx,
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Default::default(),
        Default::default(),
    )
    .await
    .unwrap();
    tokio::spawn(conn.run());

    send(
        &mut peer,
        NetworkMessage::Version(VersionMessage {
            version: PROTOCOL_VERSION,
            services: 1,
            timestamp: 0,
            addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 0, 0),
            addr_from: NetAddr::from_ipv4([127, 0, 0, 1], 0, 1),
            nonce: 0x5eed,
            user_agent: "/peer/".into(),
            start_height: 0,
            relay: true,
        }),
    )
    .await;
    assert!(matches!(
        read_message(&mut peer).await,
        NetworkMessage::Version(_)
    ));
    assert!(matches!(
        read_message(&mut peer).await,
        NetworkMessage::Verack
    ));
    send(&mut peer, NetworkMessage::Verack).await;
    (peer, (handle, shutdown_tx))
}

/// Messages up to the pong for `nonce`
async fn until_pong(peer: &mut TcpStream, nonce: u64) -> Vec<NetworkMessage> {
    let mut seen = Vec::new();
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), read_message(peer))
            .await
            .expect("no pong");
        if matches!(m, NetworkMessage::Pong(n) if n == nonce) {
            return seen;
        }
        seen.push(m);
    }
}

/// Divi Core answers a payload that does not parse with
/// `reject <command> 0x01 "error parsing message"` (main.cpp:1054); the
/// same holds here, as a control for the cases below
#[tokio::test]
async fn unparseable_spork_is_answered_with_a_reject() {
    let (mut peer, _keep) = connected_peer().await;
    send_raw(&mut peer, "spork", &[1, 2]).await;
    send(&mut peer, NetworkMessage::Ping(7)).await;
    let seen = until_pong(&mut peer, 7).await;
    assert!(seen
        .iter()
        .any(|m| matches!(m, NetworkMessage::Reject(r) if r.message == "spork" && r.code == 1)));
}

/// Divi Core reads a `reject` only with -debug and then swallows its parse
/// errors (main.cpp:940-962), and never reads `headers` at all
/// (main.cpp:669, HeadersFirstSyncingActive is false on every network,
/// chainparams.cpp:251, 360, 440): neither is ever answered with a reject
#[tokio::test]
async fn unparseable_reject_and_headers_get_no_answer() {
    let (mut peer, _keep) = connected_peer().await;
    // A reject whose command string claims 5 bytes and has none
    send_raw(&mut peer, "reject", &[5]).await;
    // A headers message announcing 2001 headers and carrying none
    send_raw(&mut peer, "headers", &[0xfd, 0xd1, 0x07]).await;
    send(&mut peer, NetworkMessage::Ping(8)).await;
    let seen = until_pong(&mut peer, 8).await;
    assert!(
        !seen.iter().any(|m| matches!(m, NetworkMessage::Reject(_))),
        "answered with {:?}",
        seen
    );
}
