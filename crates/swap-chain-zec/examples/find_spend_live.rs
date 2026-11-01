// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Read-only: scan `testnet.zec.rocks` compact blocks for a spend of `<txid>:<vout>` the
//! same way `ZecBackend::find_spend` does — no key needed, nothing signed or broadcast.
//! Prints how many transparent inputs each scanned range carried, so an empty `vin`
//! (lightwalletd stripping transparent data) is visible at a glance.
//!
//! ```sh
//! cargo run -p swap-chain-zec --example find_spend_live -- <txid-rpc-hex> <vout> <from-height>
//! ```

use swap_chain_zec::grpc::{LightwalletdClient, RetryPolicy};
use swap_chain_zec::TESTNET_LIGHTWALLETD;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [txid, vout, from] = args.as_slice() else {
        eprintln!("usage: find_spend_live <txid> <vout> <from-height>");
        std::process::exit(2);
    };
    let mut want = hex::decode(txid).expect("txid hex");
    want.reverse(); // RPC order -> internal order
    let vout: u32 = vout.parse().expect("vout");
    let from: u64 = from.parse().expect("from-height");

    let client = LightwalletdClient::new(
        vec![TESTNET_LIGHTWALLETD.to_string()],
        RetryPolicy::default(),
    )
    .expect("construct LightwalletdClient");
    let tip = client.latest_block().await.expect("latest_block").height;
    let last = tip.min(from + 199);
    let blocks = client.block_range(from, last).await.expect("block_range");
    let vins: usize = blocks
        .iter()
        .flat_map(|b| &b.vtx)
        .map(|t| t.vin.len())
        .sum();
    println!(
        "tip={tip} scanned={from}..={last} blocks={} transparent_inputs={vins}",
        blocks.len()
    );
    for b in &blocks {
        for t in &b.vtx {
            for (i, vin) in t.vin.iter().enumerate() {
                if vin.prevout_txid == want && vin.prevout_index == vout {
                    let mut id = t.txid.clone();
                    id.reverse();
                    println!(
                        "SPENT at height {} by {} input {i}",
                        b.height,
                        hex::encode(id)
                    );
                    return;
                }
            }
        }
    }
    println!("no spend found");
}
