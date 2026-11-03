// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Timed waits on the node's main locks (diag plan A17)
//!
//! The crates that own the main locks take them through [`timed`]: a lock
//! that is free is taken at once and only its holder is noted (one relaxed
//! store); one that is not is waited for in a slot of a fixed table, which
//! the A17 watchdog reads without a lock ([`waiting`]). A wait of 1 s or
//! more is counted ([`counts`]) and handed to the one [`Sink`] the node
//! binary installs (its `events.log` line). The holder is the last task or
//! thread that took the lock, by name.

use std::cell::Cell;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The locks A17 names
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lock {
    /// `Chain::chain_lock`: connect, disconnect, reorganise
    Chain = 0,
    /// The mempool's transactions
    Mempool = 1,
    /// The peer manager's peers
    Peers = 2,
    /// The wallet's transactions
    Wallet = 3,
    /// The masternode list
    Masternodes = 4,
}

pub const LOCKS: usize = 5;

impl Lock {
    pub const ALL: [Lock; LOCKS] = [
        Lock::Chain,
        Lock::Mempool,
        Lock::Peers,
        Lock::Wallet,
        Lock::Masternodes,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Lock::Chain => "chain",
            Lock::Mempool => "mempool",
            Lock::Peers => "peers",
            Lock::Wallet => "wallet",
            Lock::Masternodes => "masternodes",
        }
    }

    fn from_u8(v: u8) -> Option<Lock> {
        Lock::ALL.get(usize::from(v)).copied()
    }
}

/// A wait that is recorded
pub const RECORDED: Duration = Duration::from_secs(1);

/// One wait of [`RECORDED`] or more, handed to the sink when it ends
#[derive(Debug)]
pub struct Wait {
    pub lock: Lock,
    pub waited: Duration,
    /// The task or thread that waited
    pub waiter: String,
    /// The last task or thread that took the lock before it was free
    pub holder: String,
}

pub type Sink = Box<dyn Fn(&Wait) + Send + Sync>;

static SINK: OnceLock<Sink> = OnceLock::new();

/// The node binary's sink, once; false when one is already there
pub fn install(sink: Sink) -> bool {
    SINK.set(sink).is_ok()
}

// Names: tasks and threads by a small number, so a holder is one store

const NAMES: usize = 1024;
static NAME_TABLE: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The number for `name` (1-based); 0 when the table is full
pub fn intern(name: &str) -> u16 {
    let mut t = NAME_TABLE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = t.iter().position(|n| n == name) {
        return (i + 1) as u16;
    }
    if t.len() >= NAMES {
        return 0;
    }
    t.push(name.to_string());
    t.len() as u16
}

/// The name for a number from [`intern`]
pub fn name_of(id: u16) -> String {
    if id == 0 {
        return "other".to_string();
    }
    let t = NAME_TABLE.lock().unwrap_or_else(|e| e.into_inner());
    t.get(usize::from(id) - 1)
        .cloned()
        .unwrap_or_else(|| "other".to_string())
}

thread_local! {
    /// The named task this thread is running now (0: none)
    static TASK: Cell<u16> = const { Cell::new(0) };
    /// This thread's own name's number (u16::MAX: not looked up yet)
    static THREAD: Cell<u16> = const { Cell::new(u16::MAX) };
}

/// While it lives, the thread runs the task `id` (from [`intern`])
pub struct InTask(u16);

pub fn enter_task(id: u16) -> InTask {
    InTask(TASK.with(|t| t.replace(id)))
}

impl Drop for InTask {
    fn drop(&mut self) {
        TASK.with(|t| t.set(self.0));
    }
}

/// The calling task's number, else its thread's
fn me() -> u16 {
    let task = TASK.try_with(Cell::get).unwrap_or(0);
    if task != 0 {
        return task;
    }
    THREAD
        .try_with(|t| {
            if t.get() == u16::MAX {
                let id = intern(std::thread::current().name().unwrap_or("unnamed"));
                t.set(id);
            }
            t.get()
        })
        .unwrap_or(0)
}

static HOLDER: [AtomicU16; LOCKS] = [const { AtomicU16::new(0) }; LOCKS];
static OVER: [AtomicU64; LOCKS] = [const { AtomicU64::new(0) }; LOCKS];
static LONGEST_MS: [AtomicU64; LOCKS] = [const { AtomicU64::new(0) }; LOCKS];

/// Waits in progress
const SLOTS: usize = 64;

struct Slot {
    /// Milliseconds since [`base`] plus one; 0 free, [`BUSY`] being filled
    start: AtomicU64,
    lock: AtomicU8,
    waiter: AtomicU16,
}

const BUSY: u64 = u64::MAX;
static TABLE: [Slot; SLOTS] = [const {
    Slot {
        start: AtomicU64::new(0),
        lock: AtomicU8::new(0),
        waiter: AtomicU16::new(0),
    }
}; SLOTS];

fn base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    *BASE.get_or_init(Instant::now)
}

fn now_ms() -> u64 {
    base().elapsed().as_millis() as u64
}

/// Take `lock`: `try_now` once, then `wait`, timed
#[inline]
pub fn timed<G>(lock: Lock, try_now: impl FnOnce() -> Option<G>, wait: impl FnOnce() -> G) -> G {
    let me = me();
    if let Some(g) = try_now() {
        HOLDER[lock as usize].store(me, Ordering::Relaxed);
        return g;
    }
    let holder = HOLDER[lock as usize].load(Ordering::Relaxed);
    let started = Instant::now();
    let slot = claim(lock, me);
    let g = wait();
    if let Some(s) = slot {
        TABLE[s].start.store(0, Ordering::Release);
    }
    HOLDER[lock as usize].store(me, Ordering::Relaxed);
    let waited = started.elapsed();
    if waited >= RECORDED {
        let i = lock as usize;
        OVER[i].fetch_add(1, Ordering::Relaxed);
        LONGEST_MS[i].fetch_max(waited.as_millis() as u64, Ordering::Relaxed);
        if let Some(sink) = SINK.get() {
            sink(&Wait {
                lock,
                waited,
                waiter: name_of(me),
                holder: name_of(holder),
            });
        }
    }
    g
}

fn claim(lock: Lock, waiter: u16) -> Option<usize> {
    let start = now_ms() + 1;
    for (i, s) in TABLE.iter().enumerate() {
        if s.start
            .compare_exchange(0, BUSY, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            s.lock.store(lock as u8, Ordering::Relaxed);
            s.waiter.store(waiter, Ordering::Relaxed);
            s.start.store(start, Ordering::Release);
            return Some(i);
        }
    }
    None
}

/// A wait in progress
#[derive(Debug, Clone)]
pub struct Waiting {
    pub lock: Lock,
    pub for_ms: u64,
    pub waiter: String,
    pub holder: String,
}

/// The waits in progress now, longest first
pub fn waiting() -> Vec<Waiting> {
    let now = now_ms();
    let mut out = Vec::new();
    for s in TABLE.iter() {
        let start = s.start.load(Ordering::Acquire);
        if start == 0 || start == BUSY {
            continue;
        }
        let lock = Lock::from_u8(s.lock.load(Ordering::Relaxed));
        let waiter = s.waiter.load(Ordering::Relaxed);
        if s.start.load(Ordering::Acquire) != start {
            continue;
        }
        let Some(lock) = lock else {
            continue;
        };
        out.push(Waiting {
            lock,
            for_ms: now.saturating_sub(start - 1),
            waiter: name_of(waiter),
            holder: name_of(HOLDER[lock as usize].load(Ordering::Relaxed)),
        });
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.for_ms));
    out
}

/// The last task or thread that took each lock
pub fn holders() -> Vec<(Lock, String)> {
    Lock::ALL
        .iter()
        .map(|&l| (l, name_of(HOLDER[l as usize].load(Ordering::Relaxed))))
        .collect()
}

/// Waits of 1 s or more since start, and the longest in ms, per lock.
/// Plain loads: async-signal-safe.
pub fn counts() -> [(Lock, u64, u64); LOCKS] {
    Lock::ALL.map(|l| {
        (
            l,
            OVER[l as usize].load(Ordering::Relaxed),
            LONGEST_MS[l as usize].load(Ordering::Relaxed),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn a_free_lock_is_taken_at_once_and_its_holder_noted() {
        let m = Mutex::new(5);
        let _task = enter_task(intern("free-lock-test"));
        let g = timed(
            Lock::Masternodes,
            || m.try_lock().ok(),
            || m.lock().unwrap(),
        );
        assert_eq!(*g, 5);
        let holder = holders()
            .into_iter()
            .find(|(l, _)| *l == Lock::Masternodes)
            .unwrap()
            .1;
        assert_eq!(holder, "free-lock-test");
    }

    #[test]
    fn a_long_wait_is_in_the_table_then_counted_with_its_holder() {
        let m = Mutex::new(());
        let ready = Barrier::new(2);
        let before = counts()[Lock::Chain as usize].1;
        // Scoped threads, named as tasks: the lock table sees the task names
        std::thread::scope(|s| {
            s.spawn(|| {
                let _task = enter_task(intern("lock-holder"));
                let g = timed(Lock::Chain, || m.try_lock().ok(), || m.lock().unwrap());
                ready.wait();
                std::thread::sleep(Duration::from_millis(1300));
                drop(g);
            });
            ready.wait();
            s.spawn(|| {
                let _task = enter_task(intern("lock-waiter"));
                let _g = timed(Lock::Chain, || m.try_lock().ok(), || m.lock().unwrap());
            });
            // The wait shows in the table while it lasts
            let mut seen = None;
            for _ in 0..100 {
                seen = waiting()
                    .into_iter()
                    .find(|w| w.lock == Lock::Chain && w.waiter == "lock-waiter");
                if seen.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let seen = seen.expect("the wait was never in the table");
            assert_eq!(seen.holder, "lock-holder");
        });
        let (_, over, longest) = counts()[Lock::Chain as usize];
        assert!(over > before, "{} {}", over, before);
        assert!(longest >= 1000, "{}", longest);
        assert!(waiting()
            .iter()
            .all(|w| !(w.lock == Lock::Chain && w.waiter == "lock-waiter")));
    }

    #[test]
    fn names_are_interned_once() {
        let a = intern("intern-test-a");
        assert_eq!(intern("intern-test-a"), a);
        assert_ne!(intern("intern-test-b"), a);
        assert_eq!(name_of(a), "intern-test-a");
        assert_eq!(name_of(0), "other");
    }
}
