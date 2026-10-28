// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The initial block download ends on GetTime, the node's clock, which
//! setmocktime sets (ChainSyncHelpers.cpp:45-46), not the system clock and not
//! the network-adjusted one.

mod common;

use common::*;
use divi_primitives::clock::{set_mock_time, set_time_offset, system_now};

/// A chain whose blocks are days old is in the initial download on the system
/// clock, and out of it once the node's clock is set a minute past its tip
#[test]
fn the_initial_download_ends_on_the_node_s_clock() {
    set_mock_time(0);
    set_time_offset(0);
    let t = TestChain::new(regtest());
    t.extend_pow(3);
    assert!(i64::from(t.tip().time) < system_now() - 6 * 60 * 60);
    assert!(t.chain.is_initial_block_download());

    // The network offset does not count (GetTime, not GetAdjustedTime)
    set_time_offset(i64::from(t.tip().time) + 60 - system_now());
    assert!(t.chain.is_initial_block_download());
    set_time_offset(0);

    set_mock_time(i64::from(t.tip().time) + 60);
    assert!(!t.chain.is_initial_block_download());
    // Once out, out for good
    set_mock_time(0);
    assert!(!t.chain.is_initial_block_download());
}
