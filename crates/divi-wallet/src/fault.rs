// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Stop points for tests. A test arms a named point; when the code reaches it
//! the operation returns an error there, as if the process had died at that
//! moment, and the test reopens the database to see what is left on disk.
//! Compiled into test builds only.

use crate::error::WalletError;
use std::cell::Cell;

thread_local! {
    /// The armed point and how many more times it is passed before it stops
    static ARMED: Cell<Option<(&'static str, u32)>> = const { Cell::new(None) };
}

/// Stop at `point` after it has been passed `skip` times
pub(crate) fn arm(point: &'static str, skip: u32) {
    ARMED.with(|a| a.set(Some((point, skip))));
}

pub(crate) fn disarm() {
    ARMED.with(|a| a.set(None));
}

pub(crate) fn check(point: &'static str) -> Result<(), WalletError> {
    ARMED.with(|a| match a.get() {
        Some((armed, 0)) if armed == point => {
            a.set(None);
            Err(WalletError::Storage(format!("stopped at {point}")))
        }
        Some((armed, n)) if armed == point => {
            a.set(Some((armed, n - 1)));
            Ok(())
        }
        _ => Ok(()),
    })
}
