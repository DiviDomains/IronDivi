// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `Node::stop` returns only once the peer tasks have ended, as Divi Core's
//! shutdown returns from `join_all` only when every net thread has
//! (divid.cpp:42-53): a peer caught in the middle of its handshake at the
//! stop has its connection closed by the time stop returns.
//!
//! No test leaves the host: the peers are raw sockets on 127.0.0.1.

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::ChainMode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long to wait for something that should happen
const WAIT: Duration = Duration::from_secs(10);
/// Regtest network magic
const MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];

/// A regtest node listening on 127.0.0.1:`port`, with no peers of its own
fn node(dir: &tempfile::TempDir, port: u16) -> Node {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen_addr = "127.0.0.1".into();
    config.p2p.port = port;
    config.p2p.listen = Some(true);
    config.p2p.enable_discovery = false;
    Node::new(config).unwrap()
}

/// A peer connected to 127.0.0.1:`port` once the node listens
async fn connect(port: u16) -> TcpStream {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)).await {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "the node never listened on {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    divi_crypto::double_sha256(data)
}

/// A framed `version` message
fn version_frame() -> Vec<u8> {
    let mut p = 70920i32.to_le_bytes().to_vec();
    p.extend_from_slice(&1u64.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    p.extend_from_slice(&now.to_le_bytes());
    for _ in 0..2 {
        p.extend_from_slice(&1u64.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        p.extend_from_slice(&51476u16.to_be_bytes());
    }
    p.extend_from_slice(&0x5eed_5eed_5eed_5eedu64.to_le_bytes());
    p.push(6);
    p.extend_from_slice(b"/join/");
    p.extend_from_slice(&0i32.to_le_bytes());
    p.push(1);
    let mut f = MAGIC.to_vec();
    let mut cmd = [0u8; 12];
    cmd[..7].copy_from_slice(b"version");
    f.extend_from_slice(&cmd);
    f.extend_from_slice(&(p.len() as u32).to_le_bytes());
    f.extend_from_slice(&sha256d(&p)[..4]);
    f.extend_from_slice(&p);
    f
}

/// Whether the node has closed `peer`'s connection: what it sent before is
/// read away, then the read must end (EOF or reset) within `within`
async fn closed_within(peer: &mut TcpStream, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline, peer.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => return false,
        }
    }
}

/// A peer that sent half its version when stop came: the node was waiting
/// for the rest in its handshake. By the time stop returns that task has
/// ended and the peer's connection is closed
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_half_way_through_its_version_is_closed_by_stop() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53804);
    n.start().await.unwrap();
    let mut peer = connect(53804).await;
    peer.write_all(&version_frame()[..30]).await.unwrap();
    // Taken by the node, which now waits for the rest of the version
    tokio::time::sleep(Duration::from_millis(500)).await;
    n.stop().await.unwrap();
    assert!(
        closed_within(&mut peer, Duration::from_millis(500)).await,
        "the connection of a peer in its handshake is still open after stop"
    );
}

/// A peer that sent its version and then nothing (no verack): its
/// connection is closed by the time stop returns
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_sent_only_its_version_is_closed_by_stop() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53805);
    n.start().await.unwrap();
    let mut peer = connect(53805).await;
    peer.write_all(&version_frame()).await.unwrap();
    // The node's version and verack come back
    let mut head = [0u8; 24];
    tokio::time::timeout(WAIT, peer.read_exact(&mut head))
        .await
        .expect("the node answers the version")
        .unwrap();
    n.stop().await.unwrap();
    assert!(
        closed_within(&mut peer, Duration::from_millis(500)).await,
        "the connection of a peer that sent only its version is still open after stop"
    );
}

/// How long stop takes on a node with no peer and nothing to do (printed for
/// the before-and-after comparison; it must stay well under the bounds)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_on_a_quiet_node_is_quick() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53806);
    n.start().await.unwrap();
    let _ = connect(53806).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let started = Instant::now();
    n.stop().await.unwrap();
    let took = started.elapsed();
    eprintln!("stop on a quiet node took {} ms", took.as_millis());
    assert!(took < Duration::from_secs(5), "stop took {took:?}");
}

/// A seed lookup still under way at the stop adds nothing when it returns:
/// stop waits for it, as Divi Core's join_all waits for the dnsseed thread
/// (divid.cpp:42-53), and what it gives after the stop began is dropped. The
/// fake resolver answers 240.0.0.77, an address of no host, after 3 s; with
/// -connect set nothing is dialled either way
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seed_lookup_that_returns_after_stop_adds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen_addr = "127.0.0.1".into();
    config.p2p.port = 53807;
    config.p2p.listen = Some(true);
    config.p2p.enable_discovery = false;
    config.p2p.connect = vec!["127.0.0.1:53817".into()];
    config.p2p.dns_seed = Some(true);
    config.p2p.force_dns_seed = true;
    config.network.dns_seeds = vec!["slow-seed.invalid".into()];
    let n = Node::new(config).unwrap();
    let resolver: divi_network::SeedResolver = std::sync::Arc::new(|_name: String| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok(vec!["240.0.0.77:51476".parse().unwrap()])
        })
    });
    n.peer_manager().set_seed_resolver(resolver);
    let book = n.peer_manager().address_book().clone();
    assert_eq!(book.len(), 0);
    n.start().await.unwrap();
    let _ = connect(53807).await;
    // The lookup has begun (start dials its -connect peer, refused at once,
    // then looks the seed up)
    tokio::time::sleep(Duration::from_secs(1)).await;
    n.stop().await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        book.len(),
        0,
        "the seed's address went into the address book after stop began"
    );
}
