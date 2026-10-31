// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A4: the panic hook, and the only place in this crate that starts a task
//! or a thread (a test refuses any other).
//!
//! The hook writes each panic to `diag/crash.log`: thread, task, location,
//! message and backtrace. It writes a `panic` record to runs.log with the
//! thread, task and location only. The message can carry values, and
//! runs.log is read without asking. Then the default hook runs. What
//! happens next depends on where the panic was:
//! - a critical task or thread: the hook ends the node with exit 10
//!   (`die`), naming it;
//! - the main thread: main's `catch_unwind` exits 101. It is the only
//!   `catch_unwind` in the node (a test keeps it so), so a main-thread
//!   panic always ends the node. Before that `catch_unwind` is entered, the
//!   hook exits 101 itself;
//! - any other task or thread: it ends, and the node goes on. Its panic is
//!   also a `task-failed` record in events.log (name and place, no
//!   message), an incident (A12), and one more in health's `panics` count.
//!
//! A task started with the `_result` forms returns a `Result`: a critical
//! task's error ends the node
//! with `die(10, "Error: <name>: <error>")`; a supervised task's error is a
//! `task-failed cause=error` record in events.log with its name, and the
//! error text goes to debug.log through the logging layers.
//!
//! Blocking work goes through [`spawn_blocking`], which names it: its
//! panics are reported under that name, critical when the caller is.
//!
//! The default hook's message to stderr stays: it is the panic text, which
//! crash.log also holds, and stderr is the console (or /dev/null under
//! -daemon), never a file the node shares.
//!
//! Each crash.log entry ends with the debug ring (A8).
//!
//! Not yet: the A11 counters in the crash record, and A11's wrapping of
//! wallet values in the message. The node crates still start their own
//! tasks; a test keeps their number from growing.

use std::cell::Cell;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

/// `<datadir>/diag/crash.log`, once the data directory is known
static CRASH_LOG: OnceLock<PathBuf> = OnceLock::new();
/// Main has entered its `catch_unwind`
static MAIN_CAUGHT: AtomicBool = AtomicBool::new(false);
/// Panics of supervised tasks and threads since start (health, A6)
static PANICS: AtomicU64 = AtomicU64::new(0);

/// Panics of supervised tasks and threads since start
pub fn panics() -> u64 {
    PANICS.load(Ordering::Relaxed)
}

thread_local! {
    /// The name of a critical thread, on that thread
    static CRITICAL_THREAD: Cell<Option<&'static str>> = const { Cell::new(None) };
}

tokio::task_local! {
    /// The task being polled: its name, and whether it is critical
    static TASK: (&'static str, bool);
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The node cannot run without it: a panic ends the node with exit 10
    Critical,
    /// A panic ends it alone
    Supervised,
}

/// Install the hook; first thing in main
pub fn install_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let on_main = thread.name() == Some("main");
        let task = TASK.try_with(|t| *t).ok();
        let critical = CRITICAL_THREAD
            .with(|c| c.get())
            .or_else(|| task.filter(|t| t.1).map(|t| t.0));
        record(
            info,
            thread.name().unwrap_or("-"),
            task.map(|t| t.0),
            on_main || critical.is_some(),
        );
        previous(info);
        if let Some(name) = critical {
            crate::die(
                crate::exit_code::FAILED,
                format_args!("Error: {} panicked", name),
            );
        }
        if on_main && !MAIN_CAUGHT.load(Ordering::SeqCst) {
            crate::die(101, format_args!("Error: irondivid panicked"));
        }
    }));
}

/// crash.log goes into `<data_dir>/diag` from here on
pub fn set_data_dir(data_dir: &Path) {
    let _ = CRASH_LOG.set(data_dir.join("diag").join("crash.log"));
}

/// Main is about to enter its `catch_unwind`, which ends the node with 101
pub fn main_caught() {
    MAIN_CAUGHT.store(true, Ordering::SeqCst);
}

fn record(info: &std::panic::PanicHookInfo<'_>, thread: &str, task: Option<&str>, ends: bool) {
    let at = info
        .location()
        .map_or_else(|| "-".to_string(), |l| format!("{}:{}", l.file(), l.line()));
    let fields = format!(
        "thread={} task={} at={} ends_node={}",
        crate::runs_log::quote(thread),
        crate::runs_log::quote(task.unwrap_or("-")),
        crate::runs_log::quote(&at),
        crate::runs_log::yes(ends)
    );
    crate::runs_log::record("panic", &fields);
    if !ends {
        PANICS.fetch_add(1, Ordering::Relaxed);
        crate::events::event("task-failed", &format!("cause=panic {}", fields));
        if let Some(n) = crate::incidents::write("panic", &fields) {
            crate::events::event("incident", &format!("n={} kind=panic", n));
        }
    }

    let Some(path) = CRASH_LOG.get() else {
        return;
    };
    let payload = info.payload();
    let message = payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "(not text)".to_string());
    let mut entry = format!(
        "{} panic {} pid={}\nmessage: {}\nbacktrace:\n{}\ndebug ring (A8, oldest first):\n",
        crate::runs_log::utc_now(),
        fields,
        std::process::id(),
        crate::runs_log::quote(&message),
        std::backtrace::Backtrace::force_capture()
    );
    crate::log_delivery::RING.for_each(|l| entry.push_str(&String::from_utf8_lossy(l)));
    entry.push('\n');
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    if let Ok(mut file) = options.open(path) {
        use std::io::Write as _;
        if file.write_all(entry.as_bytes()).is_ok() {
            let _ = file.sync_data();
        }
    }
}

/// Start a task the node cannot run without: its panic ends the node (10)
pub fn spawn_critical<F>(name: &'static str, fut: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(TASK.scope((name, true), fut))
}

/// A critical task that can fail: its error ends the node like its panic,
/// through `die(10, "Error: <name>: <error>")`
pub fn spawn_critical_result<F, E>(name: &'static str, fut: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display,
{
    spawn_critical(name, async move {
        if let Err(e) = fut.await {
            crate::die(
                crate::exit_code::FAILED,
                format_args!("Error: {}: {}", name, e),
            );
        }
    })
}

/// Start a task whose panic ends it alone
pub fn spawn_supervised<F>(name: &'static str, fut: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(TASK.scope((name, false), fut))
}

/// A supervised task that can fail: its error ends it alone, and is
/// recorded
pub fn spawn_supervised_result<F, E>(name: &'static str, fut: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display,
{
    spawn_supervised(name, async move {
        if let Err(e) = fut.await {
            supervised_error(name, &e.to_string());
        }
    })
}

fn supervised_error(name: &str, error: &str) {
    tracing::warn!("task {} failed: {}", name, error);
    crate::events::event(
        "task-failed",
        &format!("cause=error task={}", crate::runs_log::quote(name)),
    );
}

/// Run blocking work on tokio's blocking pool as `name`; a panic in it is
/// critical when the calling task is
pub fn spawn_blocking<F, R>(name: &'static str, f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let critical = TASK.try_with(|t| t.1).unwrap_or(false);
    tokio::task::spawn_blocking(move || TASK.sync_scope((name, critical), f))
}

/// Start a named thread
pub fn thread<F>(
    name: &'static str,
    kind: Kind,
    f: F,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            // In the crash handler's table, with an alternate stack (A5)
            #[cfg(unix)]
            let _entered = crate::crash::enter_thread(name);
            if kind == Kind::Critical {
                CRITICAL_THREAD.with(|c| c.set(Some(name)));
            }
            f()
        })
}

/// Regtest only: `IRONDIVI_TEST_PANIC` lists the panics the A4 tests ask
/// for (`task`, `critical-task`, `critical-thread`, `main`), and the errors
/// (`task-error`, `critical-error`)
pub fn test_panic(regtest: bool, what: &str) -> bool {
    regtest && std::env::var("IRONDIVI_TEST_PANIC").is_ok_and(|v| v.split(',').any(|w| w == what))
}

/// Start the panics `IRONDIVI_TEST_PANIC` asks for once the node is running.
/// The critical ones wait 2 s, so a test sees RPC answer before the node ends
pub fn start_test_panics(regtest: bool) {
    let message = "test panic: this text stays in crash.log";
    let wait = std::time::Duration::from_secs(2);
    if test_panic(regtest, "task") {
        spawn_supervised("test-panic", async move { panic!("{}", message) });
    }
    if test_panic(regtest, "critical-task") {
        spawn_critical("test-panic", async move {
            tokio::time::sleep(wait).await;
            panic!("{}", message)
        });
    }
    if test_panic(regtest, "task-error") {
        spawn_supervised_result("test-error", async move {
            Err::<(), _>("test error: this text stays in debug.log")
        });
    }
    if test_panic(regtest, "critical-error") {
        spawn_critical_result("test-error", async move {
            tokio::time::sleep(wait).await;
            Err::<(), _>("test error")
        });
    }
    if test_panic(regtest, "critical-thread") {
        let _ = thread("test-panic", Kind::Critical, move || {
            std::thread::sleep(wait);
            panic!("{}", message)
        });
    }
}
