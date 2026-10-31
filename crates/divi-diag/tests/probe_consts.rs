// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.15 hand-rolls the P2P `version` exchange; these keep its constants
//! and layout equal to the node's.

use divi_diag::collectors::probe::{self, networks};
use divi_network::constants as c;
use divi_network::{MessageHeader, NetAddr, VersionMessage};

#[test]
fn constants_match_divi_network() {
    assert_eq!(probe::PROTOCOL_VERSION, c::PROTOCOL_VERSION);
    let n = networks();
    let want = [
        ("main", c::DEFAULT_PORT_MAINNET, c::MAINNET_MAGIC),
        ("testnet", c::DEFAULT_PORT_TESTNET, c::TESTNET_MAGIC),
        ("privatedivi main", c::DEFAULT_PORT_PRIVATEDIVI_MAINNET, c::PRIVATEDIVI_MAINNET_MAGIC),
        ("privatedivi testnet", c::DEFAULT_PORT_PRIVATEDIVI_TESTNET, c::PRIVATEDIVI_TESTNET_MAGIC),
    ];
    assert_eq!(n.len(), want.len());
    for (net, (name, port, magic)) in n.iter().zip(want) {
        assert_eq!((net.name, net.port, net.magic), (name, port, magic));
        assert!(!net.seeds.is_empty());
    }
}

#[test]
fn version_layout_matches_divi_network() {
    let zero = || NetAddr { services: 0, ip: [0; 16], port: 0 };
    let ours = probe::version_payload(1_700_000_000, 42);
    let theirs = VersionMessage {
        version: c::PROTOCOL_VERSION,
        services: 0,
        timestamp: 1_700_000_000,
        addr_recv: zero(),
        addr_from: zero(),
        nonce: 42,
        user_agent: concat!("/irondivi-diag:", env!("CARGO_PKG_VERSION"), "/").into(),
        start_height: 0,
        relay: false,
    };
    assert_eq!(ours, theirs.serialize());
    let m = probe::message(c::MAINNET_MAGIC, "version", &ours);
    let h = MessageHeader::new(c::MAINNET_MAGIC, "version", &ours);
    assert_eq!(&m[..24], &h.serialize()[..]);
}
