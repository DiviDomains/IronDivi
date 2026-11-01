// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Divi Core's per-peer buffers, -maxreceivebuffer and -maxsendbuffer: the
//! option times 1000 bytes, defaults 5000 and 1000 (Node.cpp:22-23).

use std::sync::atomic::{AtomicU64, Ordering};

static MAX_RECEIVE: AtomicU64 = AtomicU64::new(5_000 * 1_000);
static MAX_SEND: AtomicU64 = AtomicU64::new(1_000 * 1_000);

/// Messages of one peer that may wait for the node at once. The node takes
/// every peer's messages from one queue counted in messages, not bytes, so
/// beside divid's byte limit a peer may not have more than these waiting.
pub const MAX_QUEUED_MESSAGES: u64 = 4;

/// The byte limit an option value gives: divid's `1000 * GetArg(...)` made an
/// `unsigned int`, so a negative value wraps to a large one
pub fn option_bytes(value: i64) -> u64 {
    u64::from(1000i64.wrapping_mul(value) as u32)
}

/// -maxreceivebuffer, as the option's value
pub fn set_max_receive_buffer(value: i64) {
    MAX_RECEIVE.store(option_bytes(value), Ordering::Relaxed);
}

/// -maxsendbuffer, as the option's value
pub fn set_max_send_buffer(value: i64) {
    MAX_SEND.store(option_bytes(value), Ordering::Relaxed);
}

/// Bytes of a peer's messages, not yet taken by the node, over which the
/// peer is not read (Divi Core IsAvailableToReceive, Node.cpp:335-339)
pub fn max_receive_buffer() -> u64 {
    MAX_RECEIVE.load(Ordering::Relaxed)
}

/// Bytes queued for a peer at which no more of its getdata is answered
/// (Divi Core GetSendBufferStatus, Node.cpp:397-412)
pub fn max_send_buffer() -> u64 {
    MAX_SEND.load(Ordering::Relaxed)
}

/// Woken when a write takes a peer's queued bytes from -maxsendbuffer or
/// more to under it, so getdata waiting for that peer is answered at once
pub fn send_space() -> &'static tokio::sync::Notify {
    static SPACE: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    SPACE.get_or_init(tokio::sync::Notify::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_values_are_thousands_of_bytes_as_divid() {
        assert_eq!(option_bytes(5000), 5_000_000);
        assert_eq!(option_bytes(1), 1000);
        assert_eq!(option_bytes(0), 0);
        // 1000 * -1 as unsigned int
        assert_eq!(option_bytes(-1), 4_294_966_296);
    }
}
