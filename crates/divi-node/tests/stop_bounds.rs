// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A stop ends the peer tasks wherever they wait, as Divi Core's shutdown
//! interrupts its net threads before it joins them (divid.cpp:42-53): a seed
//! lookup that never answers, a dial under a -timeout far past the stop's
//! bound, a connection writing to a peer that no longer reads. Stop returns
//! well inside its 10-s bound for the peer tasks, with none of them left.
//!
//! No test leaves the host: the seed lookup is a fake resolver, the peers
//! are sockets on 127.0.0.2.

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::ChainMode;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// How long to wait for something that should happen
const WAIT: Duration = Duration::from_secs(10);
/// How long stop may take here: well inside the 10-s bound for peer tasks
const QUICK: Duration = Duration::from_secs(5);
/// Regtest network magic
const MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];

/// A regtest node listening on 127.0.0.2:`port`, configured by `edit`
fn node(dir: &tempfile::TempDir, port: u16, edit: impl FnOnce(&mut NodeConfig)) -> Node {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen_addr = "127.0.0.2".into();
    config.p2p.port = port;
    config.p2p.listen = Some(true);
    config.p2p.enable_discovery = false;
    edit(&mut config);
    Node::new(config).unwrap()
}

/// Wait (bounded) until 127.0.0.2:`port` takes a connection
async fn wait_listening(port: u16) {
    let deadline = Instant::now() + WAIT;
    while TcpStream::connect(("127.0.0.2", port)).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "the node never listened on {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Stop `n`; it must return within QUICK and leave no peer task running
async fn stop_quickly(n: &Node) {
    let started = Instant::now();
    n.stop().await.unwrap();
    let took = started.elapsed();
    let left = n.peer_manager().join_tasks(Duration::ZERO).await;
    assert!(left.is_empty(), "peer tasks left after stop: {left:?}");
    assert!(took < QUICK, "stop took {took:?}");
}

fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut f = MAGIC.to_vec();
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    f.extend_from_slice(&cmd);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(&divi_crypto::double_sha256(payload)[..4]);
    f.extend_from_slice(payload);
    f
}

fn version_payload() -> Vec<u8> {
    let mut p = 70920i32.to_le_bytes().to_vec();
    p.extend_from_slice(&1u64.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    p.extend_from_slice(&now.to_le_bytes());
    for _ in 0..2 {
        p.extend_from_slice(&1u64.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 2]);
        p.extend_from_slice(&51476u16.to_be_bytes());
    }
    p.extend_from_slice(&0x5eed_0bad_5eed_0badu64.to_le_bytes());
    p.push(8);
    p.extend_from_slice(b"/bounds/");
    p.extend_from_slice(&0i32.to_le_bytes());
    p.push(1);
    p
}

/// A seed lookup whose resolver never answers ends at the stop
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seed_lookup_that_never_answers_does_not_hold_the_stop() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53820, |c| {
        // -connect, so nothing a seed gave would be dialled
        c.p2p.connect = vec!["127.0.0.2:53830".into()];
        c.p2p.dns_seed = Some(true);
        c.p2p.force_dns_seed = true;
        c.network.dns_seeds = vec!["hang.invalid".into()];
    });
    let resolver: divi_network::SeedResolver =
        std::sync::Arc::new(|_name: String| Box::pin(std::future::pending()));
    n.peer_manager().set_seed_resolver(resolver);
    n.start().await.unwrap();
    wait_listening(53820).await;
    // The lookup has begun (start dials its -connect peer, refused at once)
    tokio::time::sleep(Duration::from_secs(1)).await;
    stop_quickly(&n).await;
}

/// A dial under a -timeout of a minute ends at the stop. The peer is a
/// listener whose accept queue is full, so a new connection to it is never
/// answered: the dial waits for its -timeout
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dial_under_a_long_timeout_does_not_hold_the_stop() {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:53831".parse().unwrap()).unwrap();
    let full = socket.listen(1).unwrap();
    // Fill its accept queue; none is ever accepted
    let mut held = Vec::new();
    for _ in 0..4 {
        if let Ok(Ok(s)) = tokio::time::timeout(
            Duration::from_millis(300),
            TcpStream::connect("127.0.0.2:53831"),
        )
        .await
        {
            held.push(s);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53821, |c| {
        c.p2p.connect = vec!["127.0.0.2:53831".into()];
        c.p2p.connect_timeout_ms = 60_000;
    });
    n.start().await.unwrap();
    wait_listening(53821).await;
    // The dial is under way, waiting for an answer that does not come
    tokio::time::sleep(Duration::from_secs(2)).await;
    stop_quickly(&n).await;
    drop((held, full));
}

/// A connection to a peer that no longer reads, its writes held by full
/// socket buffers, ends at the stop
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_to_a_peer_that_does_not_read_does_not_hold_the_stop() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53822, |_| {});
    n.start().await.unwrap();
    wait_listening(53822).await;
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut peer = socket
        .connect("127.0.0.2:53822".parse().unwrap())
        .await
        .unwrap();
    // The handshake: our version, then read until the node's verack
    peer.write_all(&frame("version", &version_payload()))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let mut head = [0u8; 24];
        tokio::time::timeout_at(deadline, peer.read_exact(&mut head))
            .await
            .expect("the node answers the version")
            .unwrap();
        let len = u32::from_le_bytes(head[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        peer.read_exact(&mut payload).await.unwrap();
        if &head[4..10] == b"verack" {
            break;
        }
    }
    peer.write_all(&frame("verack", &[])).await.unwrap();
    // Pings, never reading a pong: the node's writes fill the buffers and wait
    let (_reader, mut writer) = peer.into_split();
    let pings: Vec<u8> = (0..10_000u64)
        .flat_map(|k| frame("ping", &k.to_le_bytes()))
        .collect();
    let flood = tokio::spawn(async move {
        for _ in 0..200 {
            if writer.write_all(&pings).await.is_err() {
                return;
            }
        }
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    stop_quickly(&n).await;
    flood.abort();
}
