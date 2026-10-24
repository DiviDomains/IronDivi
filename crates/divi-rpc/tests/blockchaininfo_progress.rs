// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! getblockchaininfo reports the best header's height, as Divi Core does
//! (rpcblockchain.cpp getblockchaininfo), so a catching-up node does not
//! claim to be synced: clients such as BasicSwap take blocks / headers as
//! the sync progress when, as with divid, there is no verificationprogress.

use divi_network::{BlockSync, PeerManager, PeerManagerConfig};
use divi_primitives::block::BlockHeader;
use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

fn blockchain_info(server: &RpcServer) -> Value {
    let r = server.handle_request(Request {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: "getblockchaininfo".to_string(),
        params: Params::Array(vec![]),
    });
    assert!(r.error.is_none(), "{:?}", r.error);
    r.result.unwrap()
}

/// `count` regtest headers following on from `chain`'s tip
fn headers_after(chain: &Chain, count: usize) -> Vec<BlockHeader> {
    let tip = chain.tip().unwrap();
    let (mut prev, mut time) = (tip.hash, tip.time);
    let target = divi_primitives::hash::Hash256::from_compact(0x207fffff);
    (0..count)
        .map(|_| {
            time += 60;
            let mut header = BlockHeader {
                version: 4,
                prev_block: prev,
                time,
                bits: 0x207fffff,
                ..Default::default()
            };
            while divi_crypto::compute_block_hash(&header) > target {
                header.nonce += 1;
            }
            prev = divi_crypto::compute_block_hash(&header);
            header
        })
        .collect()
}

#[tokio::test]
async fn headers_is_the_best_header_height() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let params = ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi);
    let chain = Arc::new(Chain::new(db, params).unwrap());
    let server = RpcServer::new(chain.clone());
    let height = chain.height();

    // No sync handle: the node knows of nothing ahead of its tip
    let info = blockchain_info(&server);
    assert_eq!(info["blocks"], height);
    assert_eq!(info["headers"], height);
    // divid sends no verificationprogress
    assert!(info.get("verificationprogress").is_none(), "{info}");

    // Headers received ahead of their blocks count, a peer's claimed height does not
    let sync = BlockSync::new(
        chain.clone(),
        PeerManager::new(PeerManagerConfig::default()),
    );
    server.set_block_sync(sync.clone());
    sync.update_peer_height(1, height + 1000);
    assert_eq!(blockchain_info(&server)["headers"], height);

    tokio::time::timeout(
        Duration::from_secs(30),
        sync.handle_headers(1, headers_after(&chain, 5)),
    )
    .await
    .expect("handle_headers timed out");
    let info = blockchain_info(&server);
    assert_eq!(info["blocks"], height);
    assert_eq!(info["headers"], height + 5);
}
