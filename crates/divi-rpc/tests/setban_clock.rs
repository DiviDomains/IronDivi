// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `setban … absolute` on the clock the ban is read on: the ban ends at the
//! time given on the node's clock (the one setmocktime sets, and a test moves
//! here), not that time less the system clock's now plus the node's.

use divi_network::{PeerClock, PeerManager, PeerManagerConfig, REGTEST_MAGIC};
use divi_rpc::{NetworkRpc, Params};
use serde_json::json;
use std::time::Duration;

#[test]
fn setban_absolute_ends_at_the_time_given_on_the_node_s_clock() {
    let clock = PeerClock::skippable(Duration::from_millis(10));
    let pm = PeerManager::with_clock(
        PeerManagerConfig {
            magic: REGTEST_MAGIC,
            dns_seeds: vec![],
            dns_seed: false,
            static_peers: vec![],
            ..Default::default()
        },
        clock.clone(),
    );
    let rpc = NetworkRpc::with_peer_manager(pm.clone());
    // The node's clock a day ahead of the system's
    clock.skip(Duration::from_secs(86_400));
    let until = clock.time() + 3600;
    rpc.set_ban(&Params::Array(vec![
        json!("192.0.2.13"),
        json!("add"),
        json!(until),
        json!(true),
    ]))
    .unwrap();
    let ban = pm
        .scoring()
        .get_ban(&"192.0.2.13".parse().unwrap())
        .unwrap();
    assert!(
        ban.until.abs_diff(until) <= 1,
        "ends at {}, not {until}",
        ban.until
    );
    clock.skip(Duration::from_secs(3602));
    assert!(!pm.is_banned(&"192.0.2.13".parse().unwrap()));
}
