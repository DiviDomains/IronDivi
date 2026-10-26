// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The clock a peer connection reads: its timeouts (the 60 s first-data check,
//! the 20-minute send, receive and ping checks, the wait for a version) and the
//! times they count from. It is the system's monotonic clock; a test may add a
//! skip to it, so that it sees minutes pass in milliseconds over a real socket.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often a connection looks at its clock for a timeout that has passed or a
/// keepalive ping that is due (Divi Core checks on each pass of its send loop,
/// about every 100 ms)
const CHECK: Duration = Duration::from_secs(1);

/// The clock of one connection (see the module)
#[derive(Debug, Clone)]
pub struct PeerClock {
    /// Milliseconds a test added; None on the system clock
    skip: Option<Arc<AtomicU64>>,
    /// How often the connection checks its timeouts
    check: Duration,
}

impl Default for PeerClock {
    fn default() -> Self {
        Self::system()
    }
}

impl PeerClock {
    /// The system's monotonic clock, checked every second
    pub fn system() -> Self {
        Self {
            skip: None,
            check: CHECK,
        }
    }

    /// The system clock plus what `skip` adds, checked every `check`: a test
    /// moves it on and sees the connection act within `check`
    pub fn skippable(check: Duration) -> Self {
        Self {
            skip: Some(Arc::new(AtomicU64::new(0))),
            check,
        }
    }

    /// Move the clock on by `by` (nothing on the system clock)
    pub fn skip(&self, by: Duration) {
        if let Some(skip) = &self.skip {
            skip.fetch_add(by.as_millis() as u64, Ordering::Relaxed);
        }
    }

    /// Now on this clock
    pub fn now(&self) -> Instant {
        let now = Instant::now();
        match &self.skip {
            None => now,
            Some(skip) => now + Duration::from_millis(skip.load(Ordering::Relaxed)),
        }
    }

    /// How often the connection checks its timeouts
    pub fn check_interval(&self) -> Duration {
        self.check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_is_not_moved_by_a_skip() {
        let clock = PeerClock::system();
        let before = Instant::now();
        clock.skip(Duration::from_secs(3600));
        assert!(clock.now() < before + Duration::from_secs(60));
        assert_eq!(clock.check_interval(), Duration::from_secs(1));
    }

    #[test]
    fn a_skippable_clock_moves_on_by_the_skips() {
        let clock = PeerClock::skippable(Duration::from_millis(20));
        let copy = clock.clone();
        let before = Instant::now();
        clock.skip(Duration::from_secs(60));
        clock.skip(Duration::from_secs(1140));
        assert!(
            copy.now() >= before + Duration::from_secs(1200),
            "a copy reads the same clock"
        );
        assert!(copy.now() < Instant::now() + Duration::from_secs(1201));
        assert_eq!(copy.check_interval(), Duration::from_millis(20));
    }
}
