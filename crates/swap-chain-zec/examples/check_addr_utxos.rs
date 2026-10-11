// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Read-only check of a transparent address's mined UTXOs on the real `testnet.zec.rocks`
//! chain — no key needed, nothing signed or broadcast. Used to confirm faucet funding
//! landed (and on which chain/height) without touching any secret.
//!
//! ```sh
//! cargo run -p swap-chain-zec --example check_addr_utxos -- tm... tm...
//! ```

use swap_chain_zec::grpc::{LightwalletdClient, RetryPolicy};
use swap_chain_zec::TESTNET_LIGHTWALLETD;

#[tokio::main]
async fn main() {
    let addrs: Vec<String> = std::env::args().skip(1).collect();
    if addrs.is_empty() {
        eprintln!("usage: check_addr_utxos <address>...");
        std::process::exit(2);
    }

    let client = LightwalletdClient::new(
        vec![TESTNET_LIGHTWALLETD.to_string()],
        RetryPolicy::default(),
    )
    .expect("construct LightwalletdClient");

    let tip = client
        .latest_block()
        .await
        .expect("latest_block (endpoint reachable)")
        .height;
    println!("tip_height={tip}");

    for addr in &addrs {
        let utxos = client
            .address_utxos(addr)
            .await
            .unwrap_or_else(|e| panic!("address_utxos({addr}): {e:?}"));
        if utxos.is_empty() {
            println!("{addr}: no confirmed UTXOs yet");
            continue;
        }
        let mut total: i64 = 0;
        for u in &utxos {
            let mut txid = u.txid.clone();
            txid.reverse();
            let confs = tip.saturating_sub(u.height) + 1;
            total += u.value_zat;
            println!(
                "{addr}: {} zat at height {} ({} confs) txid {} vout {}",
                u.value_zat,
                u.height,
                confs,
                hex::encode(&txid),
                u.index
            );
        }
        println!(
            "{addr}: total {total} zatoshi across {} utxo(s)",
            utxos.len()
        );
    }
}
