// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The dates of DNS seed addresses with a network time offset. The offset is
//! one for the process, so this file holds a single test.

use divi_network::addrbook::AddressBook;
use divi_network::{PeerClock, REGTEST_MAGIC};

/// divid dates a seed's addresses 3 to 7 days before GetTime, the node's own
/// clock, whatever the network time offset (net.cpp:1046); the address book
/// then reads them on the adjusted clock as any other
#[test]
fn seed_addresses_are_dated_on_the_node_s_clock() {
    let clock = PeerClock::system();
    divi_primitives::clock::set_time_offset(2 * 24 * 60 * 60);
    let book = AddressBook::with_clock(REGTEST_MAGIC, clock.clone());
    let seeds: Vec<std::net::SocketAddr> = (1..=50u8)
        .map(|k| format!("{k}.{k}.4.4:51476").parse().unwrap())
        .collect();
    book.add_seeds(&seeds);
    let now = clock.time();
    let dates: Vec<i64> = book.sample().iter().map(|(t, _)| *t as i64).collect();
    divi_primitives::clock::set_time_offset(0);
    assert!(!dates.is_empty());
    for date in dates {
        let ago = now - date;
        assert!(
            (3 * 86_400 - 1..=7 * 86_400 + 1).contains(&ago),
            "dated {ago} s before the node's clock"
        );
    }
}
