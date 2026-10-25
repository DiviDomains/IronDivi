// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Address gossip as Divi Core does it: an outbound peer is asked for
//! addresses after its version (main.cpp:438-442); a -seednode peer is asked
//! and dropped after its answer (main.cpp:556-557); a short fresh addr goes on
//! to another peer (main.cpp:545-548); a getaddr answer leaves out what the
//! asking peer has (main.cpp:863-869, :1087-1104); an onion address is not
//! kept (main.cpp:544-551).

mod common;
use common::raw_peer::*;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// A public address in a /16 of its own
fn public(k: u16) -> Ipv4Addr {
    Ipv4Addr::new(11 + (k / 256) as u8, (k % 256) as u8, 7, 9)
}

fn entry(time: u32, ip16: [u8; 16], port: u16) -> Vec<u8> {
    let mut v = time.to_le_bytes().to_vec();
    v.extend_from_slice(&1u64.to_le_bytes());
    v.extend_from_slice(&ip16);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

fn addr_payload(addrs: &[(u32, Ipv4Addr)]) -> Vec<u8> {
    let mut v = compact(addrs.len() as u64);
    for (t, ip) in addrs {
        v.extend(entry(*t, ip.to_ipv6_mapped().octets(), 51476));
    }
    v
}

fn parse_addr(p: &[u8]) -> Vec<Ipv4Addr> {
    let (n, off) = match p[0] {
        0xfd => (u16::from_le_bytes([p[1], p[2]]) as usize, 3),
        n => (n as usize, 1),
    };
    (0..n)
        .filter_map(|k| {
            let e = &p[off + 30 * k..off + 30 * (k + 1)];
            let ip: [u8; 16] = e[12..28].try_into().unwrap();
            std::net::Ipv6Addr::from(ip).to_ipv4_mapped()
        })
        .collect()
}

/// Every address of the addr messages that come within `within`
async fn addresses(peer: &mut RawPeer, within: Duration) -> Vec<Ipv4Addr> {
    let deadline = tokio::time::Instant::now() + within;
    let mut out = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match peer.recv(left).await {
            Recv::Message(c, p) if c == "addr" => out.extend(parse_addr(&p)),
            Recv::Message(..) => continue,
            Recv::Closed | Recv::Timeout => return out,
        }
    }
}

/// A listener on `ip` that plays Divi Core's side of one connection the node
/// makes, handed back after the handshake
async fn accept_one(listener: &TcpListener) -> RawPeer {
    let (stream, from) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .expect("the node connects")
        .unwrap();
    let mut core = RawPeer {
        stream,
        ip: from.ip(),
    };
    assert!(core.expect("version", WAIT).await.is_some());
    core.send(
        "version",
        &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
    )
    .await;
    core.send("verack", &[]).await;
    core
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outbound_peer_is_asked_for_addresses() {
    let listener = TcpListener::bind("127.0.0.5:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let t = TestNode::start_with(|c| c.p2p.connect = vec![target.to_string()]).await;
    let mut core = accept_one(&listener).await;
    assert!(
        core.expect("getaddr", WAIT).await.is_some(),
        "no getaddr to an outbound peer"
    );
    drop(t);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seed_node_is_asked_and_dropped_after_its_answer() {
    let listener = TcpListener::bind("127.0.0.6:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let dead: SocketAddr = "127.0.0.6:1".parse().unwrap();
    let t = TestNode::start_with(|c| {
        c.p2p.connect = vec![dead.to_string()];
        c.p2p.seednode = vec![target.to_string()];
    })
    .await;
    let mut seed = accept_one(&listener).await;
    assert!(
        seed.expect("getaddr", WAIT).await.is_some(),
        "no getaddr to the seed"
    );
    assert!(seed.alive().await, "dropped before its answer");
    seed.send("addr", &addr_payload(&[(now(), public(1))]))
        .await;
    assert!(
        seed.closed_within(WAIT).await,
        "the seed is kept after its addr"
    );
    assert_eq!(t.node.peer_manager().address_book().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_fresh_addr_goes_on_to_another_peer() {
    let t = TestNode::start().await;
    let mut other = RawPeer::connect(&t, "127.0.0.3").await;
    other.handshake().await;
    let mut sender = RawPeer::connect(&t, "127.0.0.4").await;
    sender.handshake().await;
    sender
        .send(
            "addr",
            &addr_payload(&[(now(), public(1)), (now(), public(2))]),
        )
        .await;
    let got = addresses(&mut other, WAIT).await;
    assert_eq!(
        got.iter().copied().collect::<HashSet<_>>(),
        HashSet::from([public(1), public(2)]),
        "relayed: {got:?}"
    );
    // Not back to the sender
    assert!(addresses(&mut sender, QUIET).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_getaddr_answer_leaves_out_what_the_peer_has() {
    let t = TestNode::start().await;
    let mut sender = RawPeer::connect(&t, "127.0.0.3").await;
    sender.handshake().await;
    let old = now() - 3600;
    let sent: Vec<_> = (0..1000).map(|k| (old, public(k))).collect();
    sender.send("addr", &addr_payload(&sent)).await;
    let book = t.node.peer_manager().address_book();
    let deadline = tokio::time::Instant::now() + WAIT;
    while book.len() < 500 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let held = book.len();
    assert!(held > 500, "{held} kept");

    // The sender has every one of them
    sender.send("getaddr", &[]).await;
    assert!(addresses(&mut sender, QUIET).await.is_empty());

    // A new peer: 23% of the book, then on the same connection none again
    let mut asker = RawPeer::connect(&t, "127.0.0.4").await;
    asker.handshake().await;
    asker.send("getaddr", &[]).await;
    let first = addresses(&mut asker, QUIET).await;
    assert_eq!(first.len(), 23 * held / 100);
    asker.send("getaddr", &[]).await;
    let second: HashSet<_> = addresses(&mut asker, QUIET).await.into_iter().collect();
    assert!(
        first.iter().all(|a| !second.contains(a)),
        "an address given twice on one connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_onion_address_is_not_kept() {
    let t = TestNode::start().await;
    let mut sender = RawPeer::connect(&t, "127.0.0.3").await;
    sender.handshake().await;
    let onion: std::net::Ipv6Addr = "fd87:d87e:eb43:1234:5678:9abc:def0:1234".parse().unwrap();
    let mut payload = compact(2);
    payload.extend(entry(now() - 3600, onion.octets(), 51476));
    payload.extend(entry(
        now() - 3600,
        public(1).to_ipv6_mapped().octets(),
        51476,
    ));
    sender.send("addr", &payload).await;
    assert!(sender.alive().await);
    assert_eq!(
        t.node.peer_manager().address_book().len(),
        1,
        "only the IPv4 one"
    );
}
