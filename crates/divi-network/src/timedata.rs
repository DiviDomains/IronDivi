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

//! The network time offset as Divi Core keeps it (timedata.cpp:45-105): each
//! peer's version message gives one sample, its time less ours, once per
//! address for the life of the node; the offset is the median of the samples,
//! taken when there are at least 5 and an odd number of them, and only when it
//! is under 70 minutes; past that it is 0, and the node warns once that its
//! clock may be wrong.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use tracing::{info, warn};

/// Samples kept (CMedianFilter<int64_t> vTimeOffsets(200, 0))
const MAX_SAMPLES: usize = 200;
/// The largest offset taken from the peers (timedata.cpp:81)
const MAX_OFFSET: i64 = 70 * 60;
/// A peer this close to our clock, but not on it, means ours is fine
/// (timedata.cpp:91)
const CLOSE: i64 = 5 * 60;

/// Divi Core's warning when the peers' median is too far off (timedata.cpp:96)
pub const CLOCK_WARNING: &str = "Warning: Please check that your computer's date and time are correct! If your clock is wrong DIVI Core will not work properly.";

/// The samples and the addresses they came from
#[derive(Debug)]
pub struct TimeData {
    known: HashSet<IpAddr>,
    /// Oldest first; starts with one 0, our own clock (timedata.h:28-33)
    samples: VecDeque<i64>,
    warned: bool,
}

/// What one sample changed
#[derive(Debug, PartialEq, Eq)]
pub struct Added {
    /// The new offset, when the samples were counted (at least 5, odd)
    pub offset: Option<i64>,
    /// The clock warning, the first time it is due
    pub warn: bool,
}

impl Default for TimeData {
    fn default() -> Self {
        TimeData {
            known: HashSet::new(),
            samples: VecDeque::from([0]),
            warned: false,
        }
    }
}

impl TimeData {
    /// One peer's sample, `offset` = its time less ours (AddTimeData)
    pub fn add(&mut self, ip: IpAddr, offset: i64) -> Added {
        let none = Added {
            offset: None,
            warn: false,
        };
        // Ignore duplicates: one sample per address, ports aside (setKnown)
        if !self.known.insert(ip.to_canonical()) {
            return none;
        }
        if self.samples.len() == MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(offset);
        info!(
            "Added time data, samples {}, offset {:+} ({:+} minutes)",
            self.samples.len(),
            offset,
            offset / 60
        );
        // Only at 5 or more and an odd count (issue #4521 kept as Core has it)
        if self.samples.len() < 5 || self.samples.len().is_multiple_of(2) {
            return none;
        }
        let mut sorted: Vec<i64> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];
        let mut warn_now = false;
        let new_offset = if median.abs() < MAX_OFFSET {
            median
        } else {
            if !self.warned {
                // Nobody differs from us by a little: our clock is the odd one
                let close = sorted.iter().any(|&o| o != 0 && o.abs() < CLOSE);
                if !close {
                    self.warned = true;
                    warn_now = true;
                }
            }
            0
        };
        info!(
            "nTimeOffset = {:+}  ({:+} minutes)",
            new_offset,
            new_offset / 60
        );
        Added {
            offset: Some(new_offset),
            warn: warn_now,
        }
    }
}

static TIME_DATA: Mutex<Option<TimeData>> = Mutex::new(None);
static WARNING: OnceLock<fn(&str)> = OnceLock::new();

/// Where the clock warning goes besides the log (Core's Warnings::setMiscWarning,
/// shown as getinfo's and getmininginfo's "errors"); set once at start
pub fn on_clock_warning(show: fn(&str)) {
    let _ = WARNING.set(show);
}

/// The version message of the peer at `ip` gave its time `peer_time`: add the
/// sample and set the node's time offset (Core AddTimeData, called at the end
/// of the version message, main.cpp:465)
pub fn add_time_data(ip: IpAddr, peer_time: i64) {
    let offset = peer_time - divi_primitives::clock::now();
    let added = {
        let mut guard = TIME_DATA.lock().unwrap_or_else(|e| e.into_inner());
        guard.get_or_insert_with(TimeData::default).add(ip, offset)
    };
    if let Some(offset) = added.offset {
        divi_primitives::clock::set_time_offset(offset);
    }
    if added.warn {
        warn!("*** {}", CLOCK_WARNING);
        if let Some(show) = WARNING.get() {
            show(CLOCK_WARNING);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    /// The offset as Divi Core's filter gives it: counted at 4, 6, 8 peers
    /// (5, 7, 9 samples with our own 0), the median, one sample per address
    #[test]
    fn offset_is_the_median_at_odd_counts_of_five_or_more() {
        let mut t = TimeData::default();
        for n in 1..=3 {
            assert_eq!(t.add(ip(n), 600).offset, None, "{n} peers");
        }
        // 4 peers: samples 0, 600 x4 -> 600
        assert_eq!(t.add(ip(4), 600).offset, Some(600));
        // The same address again, another port or time: not a sample
        assert_eq!(t.add(ip(4), -9000).offset, None);
        // 5 peers: an even count, not counted
        assert_eq!(t.add(ip(5), -300).offset, None);
        // 6 peers: 0, 600 x4, -300, -300 -> sorted -300 -300 0 600 600 600 600 -> 600
        assert_eq!(t.add(ip(6), -300).offset, Some(600));
        // IPv4 and its IPv6-mapped form are one address
        let mapped = IpAddr::from(std::net::Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert_eq!(t.add(mapped, 1).offset, None);
        assert_eq!(t.samples.len(), 7);
    }

    /// Past 70 minutes the offset is 0, and the warning comes once, and only
    /// when no peer is within 5 minutes of us (timedata.cpp:81-101)
    #[test]
    fn a_median_past_seventy_minutes_is_zero_and_warns_once() {
        let mut t = TimeData::default();
        for n in 1..=3 {
            t.add(ip(n), 80 * 60);
        }
        assert_eq!(
            t.add(ip(4), 80 * 60),
            Added {
                offset: Some(0),
                warn: true
            }
        );
        t.add(ip(5), 80 * 60);
        assert_eq!(
            t.add(ip(6), 80 * 60),
            Added {
                offset: Some(0),
                warn: false
            },
            "once"
        );
        // 69 minutes is taken
        let mut t = TimeData::default();
        for n in 1..=3 {
            t.add(ip(n), 69 * 60);
        }
        assert_eq!(t.add(ip(4), 69 * 60).offset, Some(69 * 60));
        // A peer within 5 minutes (not on our clock) holds the warning back
        let mut t = TimeData::default();
        t.add(ip(1), 60);
        for n in 2..=4 {
            t.add(ip(n), -80 * 60);
        }
        assert_eq!(
            t.add(ip(5), -80 * 60).offset,
            None,
            "5 peers: an even count"
        );
        assert_eq!(
            t.add(ip(6), -80 * 60),
            Added {
                offset: Some(0),
                warn: false
            }
        );
    }

    /// The filter keeps the newest 200 samples, our 0 dropped first
    #[test]
    fn two_hundred_samples_are_kept() {
        let mut t = TimeData::default();
        for n in 0..250u32 {
            let b = n.to_be_bytes();
            t.add(IpAddr::from([10, b[1], b[2], b[3]]), 30);
        }
        assert_eq!(t.samples.len(), MAX_SAMPLES);
        assert!(t.samples.iter().all(|&s| s == 30));
    }
}
