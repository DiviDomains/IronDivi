// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The clocks the chain reads, as Divi Core 3.0.0 reads them: a spork's time
//! for a block not yet in the active chain is GetAdjustedTime (spork.cpp:84-88),
//! the node's clock (setmocktime sets it) plus the network time offset.

mod common;

use common::*;
use divi_consensus::spork_values::{ids::LOTTERY_TICKET_MIN_VALUE as LOTTERY_SPORK, SporkEntry};
use divi_primitives::clock::{set_mock_time, set_time_offset, system_now};

/// The block being connected reads a spork signed after the system time but
/// before the node's network-adjusted time: the spork is in force for it
#[test]
fn a_spork_for_the_next_block_is_read_on_the_adjusted_clock() {
    let t = TestChain::new(regtest());
    t.extend_pow(3);
    let next = t.chain.height() + 1;
    let system = system_now();
    let signed = system + 3_000;
    t.chain
        .consensus_sporks()
        .write()
        .set(LOTTERY_SPORK, vec![SporkEntry::new("500;1", signed)]);

    // The system clock: not yet signed, the default holds
    set_mock_time(0);
    set_time_offset(0);
    let default = divi_consensus::LOTTERY_TICKET_MINIMUM;
    assert_eq!(t.chain.lottery_ticket_minimum(next), default);

    // setmocktime past the signing time
    set_mock_time(signed + 1);
    assert_eq!(t.chain.lottery_ticket_minimum(next), 500 * COIN);

    // The node's clock before it, the peers' offset past it
    set_mock_time(signed - 100);
    assert_eq!(t.chain.lottery_ticket_minimum(next), default);
    set_time_offset(101);
    assert_eq!(t.chain.lottery_ticket_minimum(next), 500 * COIN);

    // A block in the active chain keeps its own time
    assert_eq!(t.chain.lottery_ticket_minimum(next - 1), default);

    set_mock_time(0);
    set_time_offset(0);
}
