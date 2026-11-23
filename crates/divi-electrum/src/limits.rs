// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! What one Electrum session, and all of them together, may cost the node.
//! The numbers follow ElectrumX's defaults where it has them (see
//! docs/electrum-server.md, "Limits"); where it has none they are
//! IronDivi's own. Everything here is plain arithmetic on times the caller
//! passes in, so it is tested without a clock.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Largest request accepted, over any transport (ElectrumX MAX_RECV). A
/// standard Divi transaction is at most 100,000 bytes, 200,000 in hex.
pub const MAX_REQUEST_BYTES: usize = 1_000_000;
/// Largest reply sent (ElectrumX MAX_SEND), a batch's replies together
/// included
pub const MAX_RESPONSE_BYTES: usize = 8_100_000;
/// Most history entries one reply may carry: ElectrumX sizes it as
/// (MAX_SEND - 100) / 99, an entry being about 99 bytes of JSON
pub const MAX_HISTORY_ENTRIES: usize = (MAX_RESPONSE_BYTES - 100) / 99;
/// Most requests one batch may hold. ElectrumX has no limit of its own on a
/// batch, and wallets send few; this is IronDivi's. A larger batch is
/// refused whole, before any of it runs.
pub const MAX_BATCH_ITEMS: usize = 1000;
/// Most scripthashes one session may subscribe to
pub const MAX_SESSION_SUBSCRIPTIONS: usize = 20_000;
/// Most scripthashes all sessions together may subscribe to (IronDivi's own)
pub const MAX_TOTAL_SUBSCRIPTIONS: usize = 250_000;
/// Most script statuses a notification tick may recompute under one permit.
pub const TICK_CHUNK: usize = 4;
/// Maximum status chunks per session per real notification tick.
pub const TICK_BURST_CHUNKS: usize = 64;

/// A session's cost from which its requests are slowed (ElectrumX COST_SOFT_LIMIT)
pub const COST_SOFT_LIMIT: f64 = 1_000.0;
/// A session's cost at which it is disconnected (ElectrumX COST_HARD_LIMIT)
pub const COST_HARD_LIMIT: f64 = 10_000.0;
/// The delay of a request at the hard limit; between the limits it grows
/// linearly from none (ElectrumX REQUEST_SLEEP)
pub const REQUEST_SLEEP: Duration = Duration::from_millis(2_500);
/// Bytes, sent and received, that cost 1.0 (ElectrumX BANDWIDTH_UNIT_COST)
pub const BANDWIDTH_UNIT_BYTES: f64 = 5_000.0;
/// What a new session has cost (ElectrumX)
pub const CONNECTION_COST: f64 = 5.0;
/// What a message that is no request costs: a blank line, a WebSocket ping
pub const KEEPALIVE_COST: f64 = 0.1;

/// How long a session may go without a message before it is closed
/// (ElectrumX SESSION_TIMEOUT). Wallets send `server.ping` about every 450 s.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(600);
/// How long one request may take before it is answered with an error
/// (ElectrumX REQUEST_TIMEOUT)
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a write to a client may make no progress before the session is
/// closed (IronDivi's own)
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The least time between two notification checks that recompute statuses
const TICK_BASE: Duration = Duration::from_secs(1);
/// What each subscription adds to that time
const TICK_PER_SUBSCRIPTION: Duration = Duration::from_millis(2);

/// The cost of one request, before its size is counted: 1.0 is a
/// subscription to a script with a small history, as in ElectrumX
pub fn method_cost(method: &str) -> f64 {
    match method {
        "server.ping"
        | "server.version"
        | "server.banner"
        | "server.donation_address"
        | "server.peers.subscribe"
        | "server.features"
        | "mempool.get_fee_histogram"
        | "blockchain.relayfee"
        | "blockchain.estimatefee"
        | "blockchain.scripthash.unsubscribe" => 0.1,
        // A header chunk is public, bounded and the same for every client; a
        // sync from genesis asks for the whole chain in chunks of 2016 and
        // is not charged by size
        "blockchain.headers.subscribe" | "blockchain.block.header" | "blockchain.block.headers" => {
            0.5
        }
        "blockchain.scripthash.get_balance"
        | "blockchain.scripthash.get_history"
        | "blockchain.scripthash.get_mempool"
        | "blockchain.scripthash.listunspent"
        | "blockchain.scripthash.subscribe"
        | "blockchain.transaction.get" => 1.0,
        // Loads and hashes a whole block, or validates and relays
        "blockchain.transaction.get_merkle" | "blockchain.transaction.broadcast" => 5.0,
        _ => 1.0,
    }
}

/// Whether the size of a method's reply counts towards the cost: header
/// chunks do not (see [`method_cost`])
pub fn counts_bandwidth(method: &str) -> bool {
    !matches!(
        method,
        "blockchain.headers.subscribe" | "blockchain.block.header" | "blockchain.block.headers"
    )
}

/// What to do with a request
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    Proceed,
    /// Wait this long first
    Delay(Duration),
    /// Close the session
    Disconnect,
}

/// The cost a session has run up. It decays with time, slower for a session
/// with many subscriptions, which cost the node something all the time
/// (ElectrumX: hard limit / (10000 + 5 * subscriptions) per second).
#[derive(Debug, Clone)]
pub struct Budget {
    cost: f64,
    updated: Duration,
    subscriptions: usize,
}

impl Budget {
    pub fn new(now: Duration) -> Self {
        Budget {
            cost: CONNECTION_COST,
            updated: now,
            subscriptions: 0,
        }
    }

    pub fn cost(&self) -> f64 {
        self.cost
    }

    pub fn set_subscriptions(&mut self, now: Duration, subscriptions: usize) {
        self.decay(now);
        self.subscriptions = subscriptions;
    }

    fn decay(&mut self, now: Duration) {
        let elapsed = now.saturating_sub(self.updated).as_secs_f64();
        let per_second = COST_HARD_LIMIT / (10_000.0 + 5.0 * self.subscriptions as f64);
        self.cost = (self.cost - elapsed * per_second).max(0.0);
        self.updated = self.updated.max(now);
    }

    /// Adds `cost`, and says what the session has earned by now
    pub fn charge(&mut self, now: Duration, cost: f64) -> Verdict {
        self.decay(now);
        self.cost += cost;
        self.verdict()
    }

    /// Adds the cost of `bytes` sent or received
    pub fn charge_bytes(&mut self, now: Duration, bytes: usize) -> Verdict {
        self.charge(now, bytes as f64 / BANDWIDTH_UNIT_BYTES)
    }

    /// What the session has earned without a new charge
    pub fn verdict(&self) -> Verdict {
        if self.cost >= COST_HARD_LIMIT {
            Verdict::Disconnect
        } else if self.cost > COST_SOFT_LIMIT {
            let fraction = (self.cost - COST_SOFT_LIMIT) / (COST_HARD_LIMIT - COST_SOFT_LIMIT);
            Verdict::Delay(REQUEST_SLEEP.mul_f64(fraction))
        } else {
            Verdict::Proceed
        }
    }
}

/// When a session last sent a message
#[derive(Debug, Clone, Copy)]
pub struct IdleClock {
    last: Duration,
}

impl IdleClock {
    pub fn new(now: Duration) -> Self {
        IdleClock { last: now }
    }

    pub fn touch(&mut self, now: Duration) {
        self.last = self.last.max(now);
    }

    /// Whether the session has been silent for [`SESSION_TIMEOUT`]
    pub fn expired(&self, now: Duration) -> bool {
        now.saturating_sub(self.last) >= SESSION_TIMEOUT
    }
}

/// How often a session's subscribed statuses are recomputed: at most once a
/// second, and less often the more it has subscribed to, since each pass
/// reads the history of every one. Headers are not held back by it.
#[derive(Debug, Clone, Copy, Default)]
pub struct TickPacer {
    next: Duration,
}

impl TickPacer {
    pub fn ready(&self, now: Duration) -> bool {
        now >= self.next
    }

    /// Records a pass over `subscriptions` scripthashes finished at `now`
    pub fn ran(&mut self, now: Duration, subscriptions: usize) {
        let subscriptions = u32::try_from(subscriptions).unwrap_or(u32::MAX);
        self.next = now + TICK_BASE + TICK_PER_SUBSCRIPTION.saturating_mul(subscriptions);
    }
}

/// The subscriptions all sessions hold together
#[derive(Debug)]
pub struct SubscriptionPool {
    used: AtomicUsize,
    max: usize,
}

impl SubscriptionPool {
    pub fn new(max: usize) -> Self {
        SubscriptionPool {
            used: AtomicUsize::new(0),
            max,
        }
    }

    /// Takes one subscription, if there is one left
    // fetch_update is deprecated as of Rust 1.100 (renamed try_update);
    // kept so older toolchains still build
    #[allow(deprecated)]
    pub fn take(&self) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < self.max).then_some(used + 1)
            })
            .is_ok()
    }

    /// Whether none is left
    pub fn full(&self) -> bool {
        self.used() >= self.max
    }

    #[allow(deprecated)]
    pub fn give(&self, n: usize) {
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(n))
            });
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn history_limit_follows_the_response_limit() {
        assert_eq!(MAX_HISTORY_ENTRIES, 81_817);
        const { assert!(MAX_HISTORY_ENTRIES * 99 + 100 <= MAX_RESPONSE_BYTES) };
    }

    #[test]
    fn a_wallet_sync_stays_under_the_soft_limit() {
        // 300 subscriptions, 300 histories of a few transactions, 200
        // transactions fetched, a few headers, over a minute
        let mut budget = Budget::new(secs(0));
        let mut now = secs(0);
        let mut worst = Verdict::Proceed;
        let steps = [
            ("blockchain.scripthash.subscribe", 300, 150),
            ("blockchain.scripthash.get_history", 300, 400),
            ("blockchain.transaction.get", 200, 600),
            ("blockchain.headers.subscribe", 1, 400),
        ];
        for (method, count, bytes) in steps {
            for _ in 0..count {
                now += Duration::from_millis(50);
                budget.charge(now, method_cost(method));
                if counts_bandwidth(method) {
                    worst = budget.charge_bytes(now, bytes);
                }
            }
        }
        assert_eq!(worst, Verdict::Proceed);
        assert!(budget.cost() < COST_SOFT_LIMIT, "{}", budget.cost());
    }

    #[test]
    fn a_header_sync_from_genesis_is_not_throttled() {
        // 2,000 chunks of 2016 headers, as fast as they are asked for
        let mut budget = Budget::new(secs(0));
        for i in 0..2_000u64 {
            let now = Duration::from_millis(i * 20);
            assert_eq!(
                budget.charge(now, method_cost("blockchain.block.headers")),
                Verdict::Proceed
            );
        }
        assert!(budget.cost() <= COST_SOFT_LIMIT + CONNECTION_COST);
    }

    #[test]
    fn requests_are_delayed_between_the_limits_and_refused_at_the_hard_one() {
        let mut budget = Budget::new(secs(0));
        let now = secs(0);
        // 5.0 from the connection; the soft limit is crossed by this
        assert_eq!(
            budget.charge(now, COST_SOFT_LIMIT - CONNECTION_COST),
            Verdict::Proceed
        );
        let Verdict::Delay(small) = budget.charge(now, 1_000.0) else {
            panic!("expected a delay")
        };
        let Verdict::Delay(large) = budget.charge(now, 7_000.0) else {
            panic!("expected a delay")
        };
        assert!(small > Duration::ZERO && small < large && large < REQUEST_SLEEP);
        assert_eq!(budget.charge(now, 5_000.0), Verdict::Disconnect);
    }

    #[test]
    fn cost_decays_and_decays_slower_with_subscriptions() {
        let mut quiet = Budget::new(secs(0));
        quiet.charge(secs(0), 2_000.0);
        assert!(matches!(quiet.verdict(), Verdict::Delay(_)));
        // 1.0 per second without subscriptions
        assert_eq!(quiet.charge(secs(1_100), 0.0), Verdict::Proceed);

        let mut busy = Budget::new(secs(0));
        busy.set_subscriptions(secs(0), 20_000);
        busy.charge(secs(0), 2_000.0);
        // 10000 / (10000 + 100000) per second: about 0.09
        busy.charge(secs(1_100), 0.0);
        assert!(busy.cost() > 1_900.0, "{}", busy.cost());
    }

    #[test]
    fn a_clock_that_runs_backwards_adds_no_credit() {
        let mut budget = Budget::new(secs(100));
        budget.charge(secs(100), 50.0);
        let before = budget.cost();
        budget.charge(secs(10), 0.0);
        assert_eq!(budget.cost(), before);
    }

    #[test]
    fn a_session_is_idle_after_the_timeout_and_any_message_resets_it() {
        let mut idle = IdleClock::new(secs(0));
        assert!(!idle.expired(secs(599)));
        assert!(idle.expired(secs(600)));
        // a ping at 450 s, as wallets send it, keeps the session
        idle.touch(secs(450));
        assert!(!idle.expired(secs(1_049)));
        assert!(idle.expired(secs(1_050)));
    }

    #[test]
    fn statuses_are_recomputed_less_often_the_more_there_are() {
        let mut pacer = TickPacer::default();
        assert!(pacer.ready(secs(0)));
        pacer.ran(secs(10), 0);
        assert!(!pacer.ready(Duration::from_millis(10_999)));
        assert!(pacer.ready(secs(11)));
        pacer.ran(secs(20), 100);
        assert!(!pacer.ready(Duration::from_millis(21_199)));
        assert!(pacer.ready(Duration::from_millis(21_200)));
        pacer.ran(secs(30), MAX_SESSION_SUBSCRIPTIONS);
        assert!(pacer.ready(secs(71)));
        assert!(!pacer.ready(secs(70)));
    }

    #[test]
    fn the_subscription_pool_hands_out_no_more_than_it_has() {
        let pool = SubscriptionPool::new(3);
        assert!(pool.take() && pool.take() && pool.take());
        assert!(!pool.take());
        pool.give(2);
        assert_eq!(pool.used(), 1);
        assert!(pool.take());
        pool.give(10);
        assert_eq!(pool.used(), 0);
    }
}
