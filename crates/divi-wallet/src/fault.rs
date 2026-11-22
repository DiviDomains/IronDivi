// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Stop points for tests. A test arms a named point; when the code reaches it
//! the operation returns an error there, as if the process had died at that
//! moment, and the test reopens the database to see what is left on disk.
//! Compiled into test builds only.

use crate::error::WalletError;
use std::cell::Cell;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Mutex;
use std::time::Duration;

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

/// A pause armed by a test: the owner and point, and the two ends the paused
/// thread uses
struct Armed {
    owner: usize,
    point: &'static str,
    reached: SyncSender<()>,
    resume: Receiver<()>,
}

/// Shared by every thread (a pause holds one thread for another), so each is
/// keyed by its owner too: tests running at once do not hold each other
static PAUSES: Mutex<Vec<Armed>> = Mutex::new(Vec::new());

/// The test's side of a pause
pub(crate) struct Pause {
    reached: Receiver<()>,
    resume: SyncSender<()>,
}

impl Pause {
    /// Wait until a thread is held at the point
    pub(crate) fn reached(&self) {
        self.reached
            .recv_timeout(Duration::from_secs(30))
            .expect("no thread reached the pause point");
    }

    /// Let the held thread go on (dropping the pause does too)
    pub(crate) fn resume(self) {
        let _ = self.resume.send(());
    }
}

/// Hold the next thread that reaches `point` in an operation of `owner`
pub(crate) fn pause_at<T>(owner: &T, point: &'static str) -> Pause {
    let (reached_tx, reached_rx) = sync_channel(1);
    let (resume_tx, resume_rx) = sync_channel(1);
    PAUSES.lock().unwrap().push(Armed {
        owner: owner as *const T as usize,
        point,
        reached: reached_tx,
        resume: resume_rx,
    });
    Pause {
        reached: reached_rx,
        resume: resume_tx,
    }
}

pub(crate) fn pause(owner: usize, point: &'static str) {
    let armed = {
        let mut pauses = PAUSES.lock().unwrap_or_else(|e| e.into_inner());
        pauses
            .iter()
            .position(|a| a.owner == owner && a.point == point)
            .map(|i| pauses.swap_remove(i))
    };
    if let Some(armed) = armed {
        let _ = armed.reached.send(());
        let _ = armed.resume.recv();
    }
}
