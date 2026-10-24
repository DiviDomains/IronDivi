// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Helpers shared by the tests that start irondivid

// Each test file uses its own subset
#![allow(dead_code)]

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::TcpListener;
use std::path::Path;

/// A port nothing listens on now, for a node to listen on.
///
/// The node binds it seconds later, so the port must not be handed to anyone
/// else in between. A port from 127.0.0.1:0 comes from the kernel's ephemeral
/// range (32768-60999 on Linux, 49152-65535 on macOS), which every outgoing
/// connection on the host also draws from; on a busy host one of them can take
/// it first and the node exits at start. These ports are below that range,
/// and picked at random so that test processes running at the same time do
/// not try the same ports in the same order.
pub fn free_port() -> u16 {
    let seed = RandomState::new();
    for i in 0u32..1000 {
        let mut h = seed.build_hasher();
        h.write_u32(i);
        let port = 20000 + (h.finish() % 12768) as u16;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port in 20000-32767");
}

/// The last lines of the node's debug.log in `datadir`, for a failure
/// message: a node that exits at start says why only there
pub fn log_tail(datadir: &Path) -> String {
    let log = std::fs::read_to_string(datadir.join("debug.log"))
        .or_else(|_| std::fs::read_to_string(datadir.join("regtest").join("debug.log")))
        .unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}
