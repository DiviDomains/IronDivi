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

//! The peer manager's clocks, moved on by the test: ban ends, the `-connect`
//! and added-node re-dials and the address book's last-try rule, hours of
//! Divi Core's schedule in milliseconds of real time.
//!
//! No dial leaves the host: every peer here has a routable address, so it is
//! dialled through a SOCKS5 proxy on 127.0.0.1 that reads where each dial
//! goes and closes it, and the dial fails.

use divi_network::{MisbehaviourOutcome, PeerClock, PeerManager, PeerManagerConfig, REGTEST_MAGIC};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How often the managers here check their clock
const CHECK: Duration = Duration::from_millis(2);
/// How long to wait for something that should happen
const WAIT: Duration = Duration::from_secs(5);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A manager with no seeds and no built-in peers, on the regtest port
fn config() -> PeerManagerConfig {
    PeerManagerConfig {
        magic: REGTEST_MAGIC,
        dns_seeds: vec![],
        dns_seed: false,
        static_peers: vec![],
        default_port: 51476,
        ..Default::default()
    }
}

/// Wait, if need be, until the system clock is early in a second, so the
/// next few steps of a test read the same whole second of it
async fn early_in_a_second() {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_millis() as u64;
    if ms > 600 {
        tokio::time::sleep(Duration::from_millis(1005 - ms)).await;
    }
}

/// Wait (bounded) until `what` holds
async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Wait until a wait begins on `clock` after the `seen` before; the count now
async fn next_sleep(clock: &PeerClock, seen: u64) -> u64 {
    wait_until("the manager waits on its clock", || {
        clock.sleeps_begun() > seen
    })
    .await;
    clock.sleeps_begun()
}

/// A SOCKS5 proxy that reads where each dial goes and then closes it
struct Proxy(TcpListener);

impl Proxy {
    async fn new() -> Self {
        Proxy(TcpListener::bind("127.0.0.1:0").await.unwrap())
    }

    fn config(&self) -> divi_network::socks5::Proxy {
        divi_network::socks5::Proxy {
            addr: self.0.local_addr().unwrap(),
            randomize_credentials: false,
        }
    }

    /// Where the next dial was going ("host:port"), within `within`
    async fn next(&self, within: Duration) -> Option<String> {
        let (mut stream, _) = tokio::time::timeout(within, self.0.accept())
            .await
            .ok()?
            .unwrap();
        Some(read_target(&mut stream).await.unwrap())
    }
}

/// The SOCKS5 greeting (answered: no authentication) and the CONNECT request
async fn read_target(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0]).await?;
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let host = match request[3] {
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        _ => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            format!("[{}]", std::net::Ipv6Addr::from(ip))
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(format!("{}:{}", host, u16::from_be_bytes(port)))
}

/// A ban ends at its time, not a second before, on the node's clock: Divi
/// Core bans until GetTime plus the ban time and holds the ban while
/// `currentTime < t` (PeerBanningService.cpp:36-62, main.cpp:1124); a
/// misbehaving peer is banned for -bantime (net.cpp:1674)
#[tokio::test]
async fn a_ban_ends_at_its_time_not_before() {
    let clock = PeerClock::skippable(CHECK);
    let pm = PeerManager::with_clock(config(), clock.clone());
    let ip = "203.0.113.7".parse().unwrap();

    early_in_a_second().await;
    pm.ban_ip(ip, secs(86_400), "setban");
    let ban = pm.scoring().get_ban(&ip).unwrap();
    assert_eq!(ban.until, ban.created + 86_400);
    clock.skip(secs(86_399));
    assert!(pm.is_banned(&ip), "the ban ended a second early");
    clock.skip(secs(1));
    assert!(!pm.is_banned(&ip), "the ban outlived its time");
    assert!(pm.scoring().list_bans().is_empty());

    early_in_a_second().await;
    pm.scoring().set_ban_policy(100, secs(60));
    pm.scoring().register_peer(7, ip);
    assert_eq!(
        pm.report_misbehavior_score(7, 100, "test"),
        MisbehaviourOutcome::Banned
    );
    clock.skip(secs(59));
    assert!(pm.is_banned(&ip), "the -bantime ban ended a second early");
    clock.skip(secs(1));
    assert!(!pm.is_banned(&ip), "the -bantime ban outlived its time");
}

/// A `-connect` peer that cannot be reached is dialled again and again on
/// divid's schedule (ThreadOpenConnections, net.cpp:1094-1105): after each
/// dial a pause of 500 ms for each earlier round, at most ten, then 500 ms.
/// The clock is walked in 500 ms steps, each once the loop waits; the steps
/// it dialled at are those of divid.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_connect_peer_is_redialled_on_divid_s_schedule() {
    let proxy = Proxy::new().await;
    let peer = sa("1.2.3.4:51476");
    let clock = PeerClock::skippable(CHECK);
    let pm = PeerManager::with_clock(
        PeerManagerConfig {
            static_peers: vec![peer],
            connect_only: true,
            proxy: Some(proxy.config()),
            ..config()
        },
        clock.clone(),
    );
    let task = tokio::spawn(Arc::clone(&pm).run_connect_loop());

    let mut dialled = Vec::new();
    let mut seen = 0;
    for step in 0..=77u32 {
        seen = next_sleep(&clock, seen).await;
        if pm.is_dialling(&peer) {
            assert_eq!(proxy.next(WAIT).await.as_deref(), Some("1.2.3.4:51476"));
            wait_until("the dial fails", || !pm.is_dialling(&peer)).await;
            dialled.push(step);
        }
        clock.skip(Duration::from_millis(500));
    }
    task.abort();
    // Round r dials after the pauses of the rounds before it: 1, 2, ... 11, 11
    assert_eq!(dialled, [0, 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 66, 77]);
}

/// An address tried in the last ten minutes is passed over while the book has
/// others (until 30 tries; ThreadOpenConnections, net.cpp:1147-1172), and
/// dialled again once ten minutes have passed: here a pass 570 s after its
/// try dials the other address, and the next, 30 s on, dials it
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_address_tried_in_the_last_ten_minutes_waits() {
    let proxy = Proxy::new().await;
    let clock = PeerClock::skippable(CHECK);
    let pm = PeerManager::with_clock(
        PeerManagerConfig {
            proxy: Some(proxy.config()),
            max_outbound: 1,
            ..config()
        },
        clock.clone(),
    );
    let (tried, fresh) = (sa("1.2.3.4:51476"), sa("5.6.7.8:51476"));
    let book = pm.address_book();
    book.add_seeds(&[tried]);
    book.add_seeds(&[fresh]);

    early_in_a_second().await;
    book.attempt(tried);
    clock.skip(secs(570));
    let task = tokio::spawn(Arc::clone(&pm).run_maintenance());
    assert_eq!(
        proxy.next(WAIT).await.as_deref(),
        Some("5.6.7.8:51476"),
        "570 s after its try the tried address was dialled"
    );
    wait_until("the dial fails", || !pm.is_dialling(&fresh)).await;
    clock.skip(secs(30));
    assert_eq!(
        proxy.next(WAIT).await.as_deref(),
        Some("1.2.3.4:51476"),
        "600 s after its try the tried address was not dialled"
    );
    task.abort();
}

/// Move `clock` on by `by`, then give what that wakes a moment to wait again
async fn step(clock: &PeerClock, by: Duration) {
    let seen = clock.sleeps_begun();
    clock.skip(by);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while clock.sleeps_begun() == seen && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// An added node that cannot be reached is dialled again two minutes on,
/// every time, as Divi Core's added-node thread dials (net.cpp:1239-1270:
/// each node, 500 ms, then two minutes), with no back-off: not before
/// 120.5 s after the last dial, and by 121 s
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_added_node_is_redialled_every_two_minutes() {
    let proxy = Proxy::new().await;
    let peer = sa("1.2.3.4:51476");
    let clock = PeerClock::skippable(CHECK);
    let pm = PeerManager::with_clock(
        PeerManagerConfig {
            proxy: Some(proxy.config()),
            ..config()
        },
        clock.clone(),
    );
    assert!(pm.add_node(peer));
    let task = tokio::spawn(Arc::clone(&pm).run_maintenance());
    assert_eq!(proxy.next(WAIT).await.as_deref(), Some("1.2.3.4:51476"));
    wait_until("the dial fails", || !pm.is_dialling(&peer)).await;

    for round in 1..=4 {
        step(&clock, Duration::from_millis(500)).await;
        step(&clock, Duration::from_millis(119_900)).await;
        assert!(
            proxy.next(Duration::from_millis(50)).await.is_none(),
            "round {round}: dialled again before 120.5 s"
        );
        let mut redialled = None;
        for _ in 0..6 {
            clock.skip(Duration::from_millis(100));
            if let Some(to) = proxy.next(Duration::from_millis(100)).await {
                redialled = Some(to);
                break;
            }
        }
        let to = redialled.unwrap_or_else(|| panic!("round {round}: not dialled by 121 s"));
        assert_eq!(to, "1.2.3.4:51476");
        wait_until("the dial fails", || !pm.is_dialling(&peer)).await;
    }
    task.abort();
}

/// Every dial by address marks the address tried in the address book once
/// the connect is made or has failed, whatever dialled it (an added node
/// here), as Divi Core's ConnectNode calls addrman Attempt
/// (net.cpp:520-538); not when the proxy itself cannot be reached
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_marks_the_address_tried_in_the_address_book() {
    let proxy = Proxy::new().await;
    let peer = sa("1.2.3.4:51476");
    let clock = PeerClock::skippable(CHECK);
    let pm = PeerManager::with_clock(
        PeerManagerConfig {
            proxy: Some(proxy.config()),
            // Only the added node is dialled: no picks from the book
            connect_only: true,
            ..config()
        },
        clock.clone(),
    );
    pm.address_book().add_seeds(&[peer]);
    assert_eq!(pm.address_book().select(), Some((peer, 0)));
    early_in_a_second().await;
    clock.skip(secs(1000));
    assert!(pm.add_node(peer));
    let task = tokio::spawn(Arc::clone(&pm).run_maintenance());
    assert_eq!(proxy.next(WAIT).await.as_deref(), Some("1.2.3.4:51476"));
    wait_until("the dial fails", || !pm.is_dialling(&peer)).await;
    task.abort();
    assert_eq!(
        pm.address_book().select(),
        Some((peer, clock.adjusted_time())),
        "the added node's dial did not mark it tried"
    );

    // A proxy that takes no connection: the address is not marked
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let clock = PeerClock::skippable(CHECK);
    let pm = PeerManager::with_clock(
        PeerManagerConfig {
            proxy: Some(divi_network::socks5::Proxy {
                addr: closed,
                randomize_credentials: false,
            }),
            connect_only: true,
            ..config()
        },
        clock.clone(),
    );
    pm.address_book().add_seeds(&[peer]);
    assert!(pm.add_node(peer));
    let task = tokio::spawn(Arc::clone(&pm).run_maintenance());
    // The dial is claimed before the manager waits again
    next_sleep(&clock, 1).await;
    wait_until("the dial fails", || !pm.is_dialling(&peer)).await;
    task.abort();
    assert_eq!(pm.address_book().select(), Some((peer, 0)));
}

/// A SOCKS5 proxy that is the peer it is asked for: it answers the CONNECT,
/// then sends its version (and, if `verack`, its verack) and hangs up once
/// it has our verack
async fn peer_behind(proxy: &Proxy, verack: bool) {
    use divi_network::constants::PROTOCOL_VERSION;
    use divi_network::{NetAddr, NetworkMessage, VersionMessage, HEADER_SIZE};
    let (mut s, _) = tokio::time::timeout(WAIT, proxy.0.accept())
        .await
        .unwrap()
        .unwrap();
    read_target(&mut s).await.unwrap();
    s.write_all(&[5, 0, 0, 1, 1, 2, 3, 4, 0xc9, 0x14])
        .await
        .unwrap();
    let send = |m: NetworkMessage| m.to_bytes(REGTEST_MAGIC).unwrap();
    let version = NetworkMessage::Version(VersionMessage {
        version: PROTOCOL_VERSION,
        services: 1,
        timestamp: divi_primitives::clock::now(),
        addr_recv: NetAddr::from_ipv4([127, 0, 0, 1], 0, 0),
        addr_from: NetAddr::from_ipv4([1, 2, 3, 4], 51476, 1),
        nonce: rand::random(),
        user_agent: "/peer/".into(),
        start_height: 0,
        relay: true,
    });
    s.write_all(&send(version)).await.unwrap();
    if verack {
        s.write_all(&send(NetworkMessage::Verack)).await.unwrap();
    }
    // Read until our verack has come
    let mut seen = Vec::new();
    while !seen.windows(6).any(|w| w == b"verack") {
        let mut buf = [0u8; HEADER_SIZE];
        let n = tokio::time::timeout(WAIT, s.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "closed before our verack");
        seen.extend_from_slice(&buf[..n]);
    }
}

/// A peer we dialled that sent its verack and no misbehaviour is dated now in
/// the address book when it goes, at most every 20 minutes, as divid's
/// CNodeState::Finalize calls addrman Connected (NodeState.cpp:38-40,
/// addrman.cpp:472-490); one that never sent its verack is not
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_goes_is_dated_now_in_the_address_book() {
    let proxy = Proxy::new().await;
    let peer = sa("1.2.3.4:51476");
    let clock = PeerClock::skippable(CHECK);
    let pm = PeerManager::with_clock(
        PeerManagerConfig {
            proxy: Some(proxy.config()),
            ..config()
        },
        clock.clone(),
    );
    let book = pm.address_book();
    book.add_seeds(&[peer]);
    let seeded = book.time_of(peer).unwrap();

    // No verack: the time stays
    let (dial, ()) = tokio::join!(
        Arc::clone(&pm).connect_to_peer(peer),
        peer_behind(&proxy, false)
    );
    dial.unwrap();
    wait_until("the peer goes", || pm.peer_count() == 0).await;
    assert_eq!(book.time_of(peer), Some(seeded), "dated without a verack");

    // A verack: the time is now
    early_in_a_second().await;
    let (dial, ()) = tokio::join!(
        Arc::clone(&pm).connect_to_peer(peer),
        peer_behind(&proxy, true)
    );
    dial.unwrap();
    wait_until("the peer goes", || pm.peer_count() == 0).await;
    let now = clock.adjusted_time() as u32;
    let dated = book.time_of(peer).unwrap();
    assert!(now - dated <= 1, "dated {dated}, now {now}");

    // Again within 20 minutes: not moved
    clock.skip(secs(1200));
    let (dial, ()) = tokio::join!(
        Arc::clone(&pm).connect_to_peer(peer),
        peer_behind(&proxy, true)
    );
    dial.unwrap();
    wait_until("the peer goes", || pm.peer_count() == 0).await;
    assert_eq!(book.time_of(peer), Some(dated), "moved within 20 minutes");
}
