// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Bans at start: Divi Core 3.0.0 keeps its bans in memory only
//! (PeerBanningService.cpp, a static map) and has no banlist.dat, so a node
//! starts with none, whatever a banlist.dat in its data directory holds. A
//! file in the layout later Bitcoin Core writes, with an entry past its time
//! and one still running, leaves irondivid with no ban at start either.

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::ChainMode;
use std::net::IpAddr;

/// Bitcoin Core's banlist.dat (CBanDB): the message start, the ban map (each
/// entry a CSubNet and a CBanEntry), then a double SHA-256 of all before
fn banlist(magic: [u8; 4], entries: &[(IpAddr, i64, i64)]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.push(entries.len() as u8);
    for (ip, created, until) in entries {
        let v6 = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => *v6,
        };
        out.extend_from_slice(&v6.octets());
        out.extend_from_slice(&[0xff; 16]);
        out.push(1);
        out.extend_from_slice(&1i32.to_le_bytes());
        out.extend_from_slice(&created.to_le_bytes());
        out.extend_from_slice(&until.to_le_bytes());
        out.push(1);
    }
    let sum = divi_crypto::double_sha256(&out);
    out.extend_from_slice(&sum);
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_starts_with_no_ban_whatever_banlist_dat_holds() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::regtest(ChainMode::Divi);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen = Some(false);
    config.p2p.enable_discovery = false;
    let now = divi_primitives::clock::now();
    let (past, running): (IpAddr, IpAddr) = (
        "203.0.113.8".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
    );
    std::fs::write(
        dir.path().join("banlist.dat"),
        banlist(
            config.network.magic,
            &[
                (past, now - 86_460, now - 60),
                (running, now - 60, now + 86_340),
            ],
        ),
    )
    .unwrap();

    let node = Node::new(config).unwrap();
    node.start().await.unwrap();
    let pm = node.peer_manager();
    let bans = pm.scoring().list_bans();
    let (past_banned, running_banned) = (pm.is_banned(&past), pm.is_banned(&running));
    node.stop().await.unwrap();
    assert!(bans.is_empty(), "bans at start: {bans:?}");
    assert!(!past_banned, "an entry past its time was read");
    assert!(!running_banned, "divid reads no banlist.dat");
}
