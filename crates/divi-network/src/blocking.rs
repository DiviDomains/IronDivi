// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Synchronous chain, mempool and wallet work run off the async workers.
//!
//! [`run`] hands a closure to Tokio's blocking pool and waits for it in
//! place. The caller's task does not go on until the closure has returned,
//! so the order of the work is the order of the calls, as if the closure had
//! run inline; only the worker thread is released meanwhile, to serve the
//! sockets, timers and other tasks.
//!
//! The work is never detached. If the waiting task is dropped (aborted at
//! shutdown, say), the drop blocks until the closure has finished, as the
//! inline call it replaces would have: a shutdown that aborts a task and
//! then joins it still finds no block being connected behind its back.

use std::sync::mpsc;

/// Run `work` on the blocking pool and wait for it in place. A panic in
/// `work` is resumed in the caller.
pub async fn run<R, F>(work: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    // Nothing is ever sent: the sender is dropped when `work` returns or
    // unwinds, or when the pool drops the closure without running it.
    let (done, finished) = mpsc::sync_channel::<()>(0);
    let task = tokio::task::spawn_blocking(move || {
        let _done = done;
        work()
    });
    let mut wait = WaitOnDrop(Some(finished));
    let result = task.await;
    wait.0 = None;
    match result {
        Ok(value) => value,
        Err(error) => match error.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            // Only a runtime shutting down cancels a blocking task
            Err(error) => panic!("blocking work did not run: {error}"),
        },
    }
}

/// Blocks, when dropped armed, until the blocking closure is done
struct WaitOnDrop(Option<mpsc::Receiver<()>>);

impl Drop for WaitOnDrop {
    fn drop(&mut self) {
        if let Some(finished) = self.0.take() {
            // Returns once the sender is gone
            let _ = finished.recv();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn returns_the_value_and_runs_off_the_calling_thread() {
        let caller = std::thread::current().id();
        let (value, thread) = run(|| (7, std::thread::current().id())).await;
        assert_eq!(value, 7);
        assert_ne!(thread, caller);
    }

    #[tokio::test]
    async fn calls_complete_in_order() {
        let log = Arc::new(parking_lot::Mutex::new(Vec::new()));
        for i in 0..20u32 {
            let log = Arc::clone(&log);
            run(move || {
                // Later calls are quicker: order must not follow duration
                std::thread::sleep(Duration::from_micros(u64::from(20 - i) * 50));
                log.lock().push(i);
            })
            .await;
        }
        assert_eq!(*log.lock(), (0..20).collect::<Vec<_>>());
    }

    #[tokio::test]
    #[should_panic(expected = "work panicked")]
    async fn a_panic_reaches_the_caller() {
        run(|| panic!("work panicked")).await
    }

    /// A one-worker runtime keeps serving a timer while blocking work runs
    #[test]
    fn the_worker_serves_timers_meanwhile() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ticks = Arc::new(AtomicU32::new(0));
            let counter = Arc::clone(&ticks);
            let ticker = tokio::spawn(async move {
                let mut every = tokio::time::interval(Duration::from_millis(5));
                loop {
                    every.tick().await;
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            });
            tokio::task::yield_now().await;
            run(|| std::thread::sleep(Duration::from_millis(200))).await;
            ticker.abort();
            // About 40 ticks; inline, the sleep would have allowed at most 1
            assert!(ticks.load(Ordering::Relaxed) >= 10, "{ticks:?}");
        });
    }

    /// An aborted caller is joined only after its blocking work is done
    #[test]
    fn an_aborted_caller_waits_for_its_work() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let started = Arc::new(AtomicBool::new(false));
            let finished = Arc::new(AtomicBool::new(false));
            let (s, f) = (Arc::clone(&started), Arc::clone(&finished));
            let task = tokio::spawn(async move {
                run(move || {
                    s.store(true, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(300));
                    f.store(true, Ordering::SeqCst);
                })
                .await;
            });
            while !started.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let aborted_at = Instant::now();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert!(finished.load(Ordering::SeqCst));
            assert!(aborted_at.elapsed() >= Duration::from_millis(200));
        });
    }
}
