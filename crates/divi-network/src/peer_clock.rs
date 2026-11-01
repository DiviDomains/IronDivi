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

//! The clock a peer connection reads: its timeouts (the 60 s first-data check,
//! the 20-minute send, receive and ping checks, the wait for a version) and the
//! times they count from. It is the system's monotonic clock; a test may add a
//! skip to it, so that it sees minutes pass in milliseconds over a real socket.
//!
//! The peer manager reads it too: its waits between dials (the `-connect` and
//! added-node rounds, the maintenance pass, the DNS seed delay) and the
//! static peers' back-off on the monotonic clock, as Divi Core sleeps for
//! them; ban ends on the node's clock (`time`, Divi Core GetTime, which
//! setmocktime sets); and the address book's times on the network-adjusted
//! clock (`adjusted_time`, GetAdjustedTime). One skip moves all three.

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
    /// Waits begun on a test's clock, so a test moves it on only once
    /// what it drives is waiting
    sleeps: Arc<AtomicU64>,
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
            sleeps: Default::default(),
            check: CHECK,
        }
    }

    /// The system clock plus what `skip` adds, checked every `check`: a test
    /// moves it on and sees the connection act within `check`
    pub fn skippable(check: Duration) -> Self {
        Self {
            skip: Some(Arc::new(AtomicU64::new(0))),
            sleeps: Default::default(),
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

    /// What a test added (nothing on the system clock)
    pub fn skipped(&self) -> Duration {
        self.skip.as_ref().map_or(Duration::ZERO, |skip| {
            Duration::from_millis(skip.load(Ordering::Relaxed))
        })
    }

    /// Whole seconds a test added
    fn skipped_secs(&self) -> i64 {
        self.skip
            .as_ref()
            .map_or(0, |skip| (skip.load(Ordering::Relaxed) / 1000) as i64)
    }

    /// The node's clock in Unix seconds (Divi Core GetTime: the mocked time
    /// when setmocktime set one), plus what a test added
    pub fn time(&self) -> i64 {
        divi_primitives::clock::now() + self.skipped_secs()
    }

    /// The network-adjusted clock in Unix seconds (Divi Core GetAdjustedTime:
    /// the node's clock plus the network time offset), plus what a test added
    pub fn adjusted_time(&self) -> i64 {
        divi_primitives::clock::adjusted_now() + self.skipped_secs()
    }

    /// Wait `by` on this clock: a sleep on the system clock; on a test's clock
    /// the wait ends within a check of the clock passing its end
    pub async fn sleep(&self, by: Duration) {
        if self.skip.is_none() {
            tokio::time::sleep(by).await;
            return;
        }
        let end = self.now() + by;
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        loop {
            let now = self.now();
            if now >= end {
                return;
            }
            tokio::time::sleep((end - now).min(self.check)).await;
        }
    }

    /// How many waits ([`PeerClock::sleep`], ticks) have begun on a test's
    /// clock (none are counted on the system clock)
    pub fn sleeps_begun(&self) -> u64 {
        self.sleeps.load(Ordering::SeqCst)
    }

    /// A tick now and then every `period` on this clock, as
    /// `tokio::time::interval` ticks (which it is on the system clock)
    pub fn interval(&self, period: Duration) -> Ticker {
        match self.skip {
            None => Ticker::System(tokio::time::interval(period)),
            Some(_) => Ticker::Skippable {
                clock: self.clone(),
                next: self.now(),
                period,
            },
        }
    }
}

/// Ticks of a [`PeerClock`] (see [`PeerClock::interval`])
#[derive(Debug)]
pub enum Ticker {
    /// The system clock's
    System(tokio::time::Interval),
    /// A test's clock: the next tick is due at `next`
    Skippable {
        clock: PeerClock,
        next: Instant,
        period: Duration,
    },
}

impl Ticker {
    /// Wait for the next tick
    pub async fn tick(&mut self) {
        match self {
            Ticker::System(interval) => {
                interval.tick().await;
            }
            Ticker::Skippable {
                clock,
                next,
                period,
            } => {
                clock
                    .sleep(next.saturating_duration_since(clock.now()))
                    .await;
                *next += *period;
            }
        }
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

    #[test]
    fn a_skip_moves_the_node_and_adjusted_clocks_by_whole_seconds() {
        let clock = PeerClock::skippable(Duration::from_millis(20));
        let (time, adjusted) = (clock.time(), clock.adjusted_time());
        clock.skip(Duration::from_millis(86_400_500));
        assert!((clock.time() - time - 86_400).abs() <= 1);
        assert!((clock.adjusted_time() - adjusted - 86_400).abs() <= 1);
        let system = PeerClock::system();
        system.skip(Duration::from_secs(86_400));
        assert!((system.time() - divi_primitives::clock::now()).abs() <= 1);
    }

    #[tokio::test]
    async fn a_sleep_on_a_skippable_clock_ends_when_the_clock_passes_it() {
        let clock = PeerClock::skippable(Duration::from_millis(5));
        let sleeper = {
            let clock = clock.clone();
            tokio::spawn(async move { clock.sleep(Duration::from_secs(120)).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!sleeper.is_finished(), "ended before the clock moved");
        clock.skip(Duration::from_secs(119));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!sleeper.is_finished(), "ended a second early");
        clock.skip(Duration::from_secs(1));
        tokio::time::timeout(Duration::from_secs(1), sleeper)
            .await
            .expect("ended once the clock passed it")
            .unwrap();
    }

    #[tokio::test]
    async fn a_skippable_ticker_ticks_now_and_then_every_period() {
        let clock = PeerClock::skippable(Duration::from_millis(5));
        let mut ticker = clock.interval(Duration::from_secs(30));
        tokio::time::timeout(Duration::from_millis(500), ticker.tick())
            .await
            .expect("the first tick is at once");
        let next = ticker.tick();
        tokio::pin!(next);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut next)
                .await
                .is_err(),
            "the second tick came before its period"
        );
        clock.skip(Duration::from_secs(30));
        tokio::time::timeout(Duration::from_millis(500), next)
            .await
            .expect("the second tick, a period on");
    }
}
