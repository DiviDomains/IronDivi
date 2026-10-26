// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The node's network tasks end with `Node::stop`, as Divi Core's do: its
//! shutdown interrupts and joins the net threads (dnsseed, net, addcon,
//! opencon) before anything else (divid.cpp:42-53), then closes the listen
//! sockets (init.cpp:414-418, net.cpp:272-290). After stop the P2P port takes
//! no connection, no peer is dialled and no seed is looked up.
//!
//! No test leaves the host: peers are listeners on 127.0.0.1, and the seed is
//! an IP literal (240.0.0.77, an address of no host), which resolves without
//! DNS. With -connect set, a seed's addresses only go into the address book,
//! so its lookup shows there and is never dialled.

use divi_network::NetAddr;
use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::ChainMode;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

/// How long to wait for something that should happen
const WAIT: Duration = Duration::from_secs(10);

/// A regtest node listening on 127.0.0.1:`port`, configured by `edit`
fn node(dir: &tempfile::TempDir, port: u16, edit: impl FnOnce(&mut NodeConfig)) -> Node {
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen_addr = "127.0.0.1".into();
    config.p2p.port = port;
    config.p2p.listen = Some(true);
    config.p2p.enable_discovery = false;
    edit(&mut config);
    Node::new(config).unwrap()
}

/// Wait (bounded) until 127.0.0.1:`port` takes a connection
async fn wait_listening(port: u16) {
    let deadline = Instant::now() + WAIT;
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "the node never listened on {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether `listener` takes a connection within `within`
async fn dialled_within(listener: &TcpListener, within: Duration) -> bool {
    tokio::time::timeout(within, listener.accept())
        .await
        .is_ok()
}

/// After stop the P2P port refuses a connection: the listener is gone
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_p2p_port_refuses_connections_after_stop() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53800, |_| {});
    n.start().await.unwrap();
    wait_listening(53800).await;
    n.stop().await.unwrap();
    assert!(
        TcpStream::connect(("127.0.0.1", 53800)).await.is_err(),
        "the P2P port still takes connections after stop"
    );
}

/// After stop no -connect peer is dialled again: the peer the test holds is
/// dialled while the node runs, and not once stop has returned
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_peer_is_dialled_after_stop() {
    let peer = TcpListener::bind("127.0.0.1:53811").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53801, |c| {
        c.p2p.connect = vec!["127.0.0.1:53811".into()]
    });
    n.start().await.unwrap();
    // Dialled while running; the connection is closed, so the node dials again
    for _ in 0..2 {
        let (conn, _) = tokio::time::timeout(WAIT, peer.accept())
            .await
            .expect("the node dials its -connect peer")
            .unwrap();
        drop(conn);
    }
    n.stop().await.unwrap();
    // Anything already on its way is taken, then nothing may come
    while dialled_within(&peer, Duration::from_millis(200)).await {}
    assert!(
        !dialled_within(&peer, Duration::from_secs(5)).await,
        "the -connect peer was dialled after stop"
    );
}

/// After stop no seed is looked up: the seed task waits 11 s when the address
/// book has addresses (net.cpp:1020-1022, here 240.0.0.1), and stop comes
/// before that; its lookup would add the seed's address to the book
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_seed_is_looked_up_after_stop() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53802, |c| {
        c.p2p.connect = vec!["127.0.0.1:53812".into()];
        c.p2p.dns_seed = Some(true);
        c.network.dns_seeds = vec!["240.0.0.77".into()];
    });
    let book = n.peer_manager().address_book().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    book.add(
        &[(now, NetAddr::from_ipv4([240, 0, 0, 1], 51476, 1))],
        IpAddr::from([240, 0, 0, 1]),
    );
    let before = book.len();
    assert_eq!(before, 1, "the address book holds the one address");
    n.start().await.unwrap();
    wait_listening(53802).await;
    // Time for start to dial its -connect peer (refused at once) and start
    // the seed task, well inside the task's 11 s wait
    tokio::time::sleep(Duration::from_secs(2)).await;
    n.stop().await.unwrap();
    // Past the seed task's 11 s wait
    tokio::time::sleep(Duration::from_secs(13)).await;
    let seed: SocketAddr = "240.0.0.77:51476".parse().unwrap();
    assert_eq!(
        book.len(),
        before,
        "a seed was looked up after stop ({seed} went into the address book)"
    );
}

/// A stop right after start leaves no listening socket either: the socket
/// start binds before its listener runs is closed too (Divi Core closes its
/// listen sockets in CleanupP2PConnections whether or not the net thread
/// ever took a connection, net.cpp:272-290)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_right_after_start_leaves_the_p2p_port_closed() {
    let dir = tempfile::tempdir().unwrap();
    let n = node(&dir, 53803, |_| {});
    n.start().await.unwrap();
    n.stop().await.unwrap();
    assert!(
        TcpStream::connect(("127.0.0.1", 53803)).await.is_err(),
        "the P2P port still takes connections after stop"
    );
}
