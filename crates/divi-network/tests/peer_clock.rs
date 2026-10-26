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

//! When a connection drops a peer, on a clock the test moves on: minutes of
//! Divi Core's timeouts (CheckForInnactivity, Node.cpp:812-834) in
//! milliseconds of real time, over a loopback socket

use divi_network::constants::{MAINNET_MAGIC, PROTOCOL_VERSION};
use divi_network::{
    Connection, MessageHeader, NetAddr, NetworkMessage, PeerClock, PeerHandle, VersionMessage,
    HEADER_SIZE,
};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

/// How often the connections here check their clock
const CHECK: Duration = Duration::from_millis(20);
/// Real time long enough for a connection to act on a moved clock
const ACT: Duration = Duration::from_millis(200);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// What keeps a connection up: its handle and the shutdown sender
type Keep = (PeerHandle, broadcast::Sender<()>);

/// A peer that dialled us, on `clock`; nothing sent yet
async fn inbound(clock: &PeerClock) -> (TcpStream, Keep) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
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
    tokio::spawn(conn.with_clock(clock.clone()).run());
    (peer, (handle, shutdown_tx))
}

/// A peer we dialled, on `clock`; our version is on its way to it
async fn dialled(clock: &PeerClock) -> (TcpStream, Keep) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (event_tx, _) = broadcast::channel(64);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (conn, handle) = Connection::connect(
        listener.local_addr().unwrap(),
        None,
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
    let (peer, _) = listener.accept().await.unwrap();
    tokio::spawn(conn.with_clock(clock.clone()).run());
    (peer, (handle, shutdown_tx))
}

async fn send(s: &mut TcpStream, m: NetworkMessage) {
    s.write_all(&m.to_bytes(MAINNET_MAGIC).unwrap())
        .await
        .unwrap();
}

fn version() -> NetworkMessage {
    NetworkMessage::Version(VersionMessage {
        version: PROTOCOL_VERSION,
        services: 1,
        timestamp: divi_primitives::clock::now(),
        addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 0, 0),
        addr_from: NetAddr::from_ipv4([127, 0, 0, 1], 0, 1),
        nonce: rand::random(),
        user_agent: "/peer/".into(),
        start_height: 0,
        relay: true,
    })
}

/// Real time for the connection to read what the peer just sent, so that it
/// is timed before the test moves the clock on
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// A header naming 100 bytes of payload, then 40 of them: half a message
async fn send_half(s: &mut TcpStream, command: &str) {
    let payload = [7u8; 100];
    let mut f = MessageHeader::new(MAINNET_MAGIC, command, &payload).serialize();
    f.extend_from_slice(&payload[..40]);
    s.write_all(&f).await.unwrap();
    settle().await;
}

/// What the peer was sent: the messages that came within `within`, and
/// whether the connection was closed
async fn drain(s: &mut TcpStream, within: Duration) -> (Vec<NetworkMessage>, bool) {
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let mut h = [0u8; HEADER_SIZE];
        match tokio::time::timeout_at(deadline, s.read_exact(&mut h)).await {
            Err(_) => return (got, false),
            Ok(Err(_)) => return (got, true),
            Ok(Ok(_)) => {}
        }
        let header = MessageHeader::deserialize(&h).unwrap();
        let mut p = vec![0u8; header.payload_size as usize];
        if s.read_exact(&mut p).await.is_err() {
            return (got, true);
        }
        got.push(NetworkMessage::deserialize(&header.command_string(), &p).unwrap());
    }
}

/// Whether the connection is closed after the clock was moved on by `by`
async fn closed_after(s: &mut TcpStream, clock: &PeerClock, by: Duration) -> bool {
    clock.skip(by);
    drain(s, ACT).await.1
}

/// The pings in `got`, answered
async fn answer_pings(s: &mut TcpStream, got: &[NetworkMessage]) {
    for m in got {
        if let NetworkMessage::Ping(n) = m {
            send(s, NetworkMessage::Pong(*n)).await;
        }
    }
    settle().await;
}

/// An inbound peer past its handshake, its first ping answered
async fn handshaken(clock: &PeerClock) -> (TcpStream, Keep) {
    let (mut peer, keep) = inbound(clock).await;
    send(&mut peer, version()).await;
    send(&mut peer, NetworkMessage::Verack).await;
    let (got, closed) = drain(&mut peer, ACT).await;
    assert!(!closed);
    assert!(
        got.iter().any(|m| matches!(m, NetworkMessage::Ping(_))),
        "the first ping"
    );
    answer_pings(&mut peer, &got).await;
    (peer, keep)
}

/// Divi Core drops a peer that has sent nothing 60 s after the connection
/// opened, whichever side dialled (Node.cpp:819-822)
#[tokio::test]
async fn a_peer_that_dialled_us_and_sends_nothing_is_dropped_at_60_s() {
    let clock = PeerClock::skippable(CHECK);
    let (mut peer, _keep) = inbound(&clock).await;
    assert!(
        !closed_after(&mut peer, &clock, secs(58)).await,
        "inbound, at 58 s"
    );
    assert!(
        closed_after(&mut peer, &clock, secs(3)).await,
        "inbound, at 61 s"
    );
}

#[tokio::test]
async fn a_peer_we_dialled_that_sends_nothing_is_dropped_at_60_s() {
    let clock = PeerClock::skippable(CHECK);
    let (mut peer, _keep) = dialled(&clock).await;
    assert!(
        !closed_after(&mut peer, &clock, secs(58)).await,
        "dialled, at 58 s"
    );
    assert!(
        closed_after(&mut peer, &clock, secs(3)).await,
        "dialled, at 61 s"
    );
}

/// Half a version is something received (Node.cpp:160-164, :292): a peer we
/// dialled has also been sent our version, so it is kept to the 20-minute
/// checks; a peer that dialled us has been sent nothing, so it goes at 60 s
#[tokio::test]
async fn half_a_version_keeps_a_dialled_peer_to_the_20_minute_check() {
    let clock = PeerClock::skippable(CHECK);
    let (mut peer, _keep) = dialled(&clock).await;
    send_half(&mut peer, "version").await;
    assert!(
        !closed_after(&mut peer, &clock, secs(61)).await,
        "dialled, at 61 s"
    );
    assert!(
        !closed_after(&mut peer, &clock, secs(1130)).await,
        "dialled, at 1191 s"
    );
    assert!(
        closed_after(&mut peer, &clock, secs(15)).await,
        "dialled, at 1206 s"
    );
}

#[tokio::test]
async fn half_a_version_from_a_peer_that_dialled_us_is_dropped_at_60_s() {
    let clock = PeerClock::skippable(CHECK);
    let (mut peer, _keep) = inbound(&clock).await;
    send_half(&mut peer, "version").await;
    assert!(
        !closed_after(&mut peer, &clock, secs(58)).await,
        "inbound, at 58 s"
    );
    assert!(
        closed_after(&mut peer, &clock, secs(3)).await,
        "inbound, at 61 s"
    );
}

/// Half an inv after the handshake moves the receive clock: the peer is kept
/// 20 minutes from the half message, not from its last whole one
#[tokio::test]
async fn half_an_inv_moves_the_receive_clock() {
    let clock = PeerClock::skippable(CHECK);
    let (mut peer, _keep) = handshaken(&clock).await;
    // a keepalive ping is due two minutes on: answered, the last whole message
    clock.skip(secs(600));
    let (got, closed) = drain(&mut peer, ACT).await;
    assert!(!closed);
    answer_pings(&mut peer, &got).await;
    // 500 s on, another ping: not answered; half an inv instead
    clock.skip(secs(500));
    let (got, closed) = drain(&mut peer, ACT).await;
    assert!(!closed);
    assert!(
        got.iter().any(|m| matches!(m, NetworkMessage::Ping(_))),
        "the second ping"
    );
    send_half(&mut peer, "inv").await;
    // 1250 s after the last whole message, 750 s after the half one
    assert!(!closed_after(&mut peer, &clock, secs(750)).await, "kept");
    // 1250 s after the half one
    assert!(closed_after(&mut peer, &clock, secs(500)).await, "dropped");
}

/// A peer that answers every ping sends a whole message each time, which
/// resets the 20-minute receive check, and the ping check with it: it is kept
/// however long it stays
#[tokio::test]
async fn a_peer_that_answers_its_pings_is_kept() {
    let clock = PeerClock::skippable(CHECK);
    let (mut peer, _keep) = handshaken(&clock).await;
    for _ in 0..6 {
        clock.skip(secs(300));
        let (got, closed) = drain(&mut peer, Duration::from_millis(60)).await;
        assert!(!closed, "kept");
        answer_pings(&mut peer, &got).await;
    }
    // 30 minutes on, and up
    assert!(
        !closed_after(&mut peer, &clock, secs(0)).await,
        "kept after 30 minutes"
    );
}

/// One that stops answering goes 20 minutes after its last answer
#[tokio::test]
async fn a_peer_that_stops_answering_goes_20_minutes_after_its_last_answer() {
    let clock = PeerClock::skippable(CHECK);
    let (mut peer, _keep) = handshaken(&clock).await;
    clock.skip(secs(150));
    let (got, _) = drain(&mut peer, ACT).await;
    answer_pings(&mut peer, &got).await;
    assert!(
        !closed_after(&mut peer, &clock, secs(1190)).await,
        "1190 s after its answer"
    );
    assert!(
        closed_after(&mut peer, &clock, secs(20)).await,
        "1210 s after it"
    );
}
