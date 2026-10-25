// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! A long call does not hold up other connections: while one client waits
//! for keypoolrefill, another client's getblockcount is answered, as Divi
//! Core answers it from another of its RPC threads (rpcserver.cpp:755-757).
//! The server runs on a runtime of one worker thread, so a call that ran on
//! that worker would hold every other connection.

use divi_primitives::ChainMode;
use divi_rpc::{create_router_with_auth, RpcConfig, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// One call on its own connection; the reply's status line
fn call(addr: SocketAddr, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    stream
        .write_all(
            format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\
                 Connection: close\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    String::from_utf8_lossy(&reply)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[test]
fn a_short_call_is_answered_while_a_long_call_runs() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = Arc::new(RpcServer::with_wallet(chain, wallet));
    let config = RpcConfig {
        username: Some("test".into()),
        password: Some("test".into()),
        ..RpcConfig::default()
    };
    let router = create_router_with_auth(server, &config);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    runtime.spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });

    let long = std::thread::spawn(move || {
        let status = call(addr, r#"{"method":"keypoolrefill","params":[3000],"id":1}"#);
        (status, Instant::now())
    });
    std::thread::sleep(Duration::from_millis(300));
    let status = call(addr, r#"{"method":"getblockcount","params":[],"id":2}"#);
    let short_done = Instant::now();
    let (long_status, long_done) = long.join().unwrap();
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(long_status.starts_with("HTTP/1.1 200"), "{long_status}");
    assert!(
        short_done < long_done,
        "getblockcount waited for keypoolrefill ({:?} after it)",
        short_done - long_done
    );
}
