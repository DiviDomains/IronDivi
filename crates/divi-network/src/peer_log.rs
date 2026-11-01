// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! How a peer is named in the log: Divi Core's -logips (default 0,
//! Logging.cpp:202). divid names a peer by its id, `peer=<n>`, and adds its
//! address only with -logips (Node.cpp:577-580, :1000-1003, main.cpp:456-461).

use crate::peer::PeerId;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

static LOG_IPS: AtomicBool = AtomicBool::new(false);

/// -logips: whether log lines carry peers' addresses
pub fn set_log_ips(on: bool) {
    LOG_IPS.store(on, Ordering::Relaxed);
}

/// Whether log lines carry peers' addresses (-logips)
pub fn log_ips() -> bool {
    LOG_IPS.load(Ordering::Relaxed)
}

/// A peer in a log line: `peer=<id>`, with its address after it under
/// -logips (`peer=<id> peeraddr=<address>`). Without an id (before the peer
/// has one): `a peer`, or its address under -logips.
pub struct Peer {
    pub addr: SocketAddr,
    pub id: Option<PeerId>,
}

/// A peer known by its id
pub fn peer(id: PeerId, addr: SocketAddr) -> Peer {
    Peer { addr, id: Some(id) }
}

/// A peer that has no id yet
pub fn address(addr: SocketAddr) -> Peer {
    Peer { addr, id: None }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.id, log_ips()) {
            (Some(id), true) => write!(f, "peer={} peeraddr={}", id, self.addr),
            (Some(id), false) => write!(f, "peer={}", id),
            (None, true) => write!(f, "{}", self.addr),
            (None, false) => write!(f, "a peer"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_address_is_shown_only_with_logips() {
        let addr: SocketAddr = "1.2.3.4:51472".parse().unwrap();
        set_log_ips(false);
        assert_eq!(peer(7, addr).to_string(), "peer=7");
        assert_eq!(address(addr).to_string(), "a peer");
        set_log_ips(true);
        assert_eq!(peer(7, addr).to_string(), "peer=7 peeraddr=1.2.3.4:51472");
        assert_eq!(address(addr).to_string(), "1.2.3.4:51472");
        set_log_ips(false);
    }
}
