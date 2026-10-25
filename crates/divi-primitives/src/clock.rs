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

//! The node's clock in Unix seconds, which `setmocktime` can set on regtest
//! (Divi Core utiltime.cpp: GetTime returns nMockTime when it is not 0)

use std::sync::atomic::{AtomicI64, Ordering};

static MOCK_TIME: AtomicI64 = AtomicI64::new(0);

/// Set the clock to `time`; 0 goes back to the system time (Core SetMockTime)
pub fn set_mock_time(time: i64) {
    MOCK_TIME.store(time, Ordering::Relaxed);
}

/// The mocked time, or 0 when the system time is used
pub fn mock_time() -> i64 {
    MOCK_TIME.load(Ordering::Relaxed)
}

/// Now in Unix seconds: the mocked time when one is set (Core GetTime)
pub fn now() -> i64 {
    match mock_time() {
        0 => system_now(),
        mock => mock,
    }
}

/// Now in Unix seconds from the system clock, whatever the mocked time
pub fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_time_is_used_until_it_is_cleared() {
        set_mock_time(1_600_000_000);
        assert_eq!(now(), 1_600_000_000);
        set_mock_time(-5);
        assert_eq!(now(), -5, "Core takes any value but 0");
        set_mock_time(0);
        assert!((now() - system_now()).abs() <= 1);
    }
}
