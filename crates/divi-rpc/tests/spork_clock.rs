// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `spork active`: a time spork is active once its time is past
//! GetAdjustedTime (spork.cpp:379), the node's clock, which setmocktime sets,
//! plus the network time offset, not the system clock.

use divi_primitives::clock::{set_mock_time, set_time_offset, system_now};
use divi_rpc::spork::SporkRpc;
use divi_rpc::Params;
use serde_json::json;

/// The default of SPORK_9_SUPERBLOCKS_ENABLED, 2099-01-01
const OFF_UNTIL: i64 = 4_070_908_800;

fn superblocks_active() -> serde_json::Value {
    let v = SporkRpc::new()
        .spork(&Params::Array(vec![json!("active")]))
        .unwrap();
    v["SPORK_9_SUPERBLOCKS_ENABLED"].clone()
}

#[test]
fn a_time_spork_is_active_on_the_adjusted_clock() {
    assert_eq!(superblocks_active(), false);
    set_mock_time(OFF_UNTIL + 1);
    assert_eq!(superblocks_active(), true);
    set_mock_time(OFF_UNTIL);
    assert_eq!(superblocks_active(), false);
    // The peers' offset moves it too
    set_time_offset(1);
    assert_eq!(superblocks_active(), true);
    set_mock_time(0);
    set_time_offset(0);
    assert!(system_now() < OFF_UNTIL);
    assert_eq!(superblocks_active(), false);
}
