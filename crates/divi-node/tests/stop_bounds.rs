// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A stop ends the peer tasks wherever they wait, as Divi Core's shutdown
//! interrupts its net threads before it joins them (divid.cpp:42-53): a seed
//! lookup that never answers, a dial under a -timeout far past the stop's
//! bound. Stop returns well inside its 10-s bound for the peer tasks, with
//! none of them left.
//!
//! No test leaves the host: the seed lookup is a fake resolver, the peers
//! are sockets on 127.0.0.2.

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::ChainMode;
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};

/// How long to wait for something that should happen
const WAIT: Duration = Duration::from_secs(10);
/// How long stop may take here: well inside the 10-s bound for peer tasks
const QUICK: Duration = Duration::from_secs(5);

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
