// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A8: how log lines reach `debug.log`, and the debug ring.
//!
//! Until the `running` phase each line is written on the calling thread,
//! so nothing logged during start-up can be lost. From then on a writer
//! thread writes them from a bounded queue; a caller that finds the queue
//! full waits up to 2 s, then drops its line and counts it. When the queue
//! drains, the count goes to `debug.log` and to runs.log (`dropped`).
//! [`flush`] waits 2 s at most.
//!
//! The ring holds the last [`RING_SLOTS`] lines at debug level for
//! IronDivi's own code (info for libraries), whatever level the user set.
//! It is a fixed buffer of atomics, so the A5 signal handler can read it
//! without a lock or an allocation. Lines whose callsite has a `counted`
//! field (the A11 counted sites) stay out of it; the filter is on the
//! ring's layer only, so they still reach `debug.log`, where [`Fields`]
//! leaves the `counted` field out.
//!
//! Not yet: A11's redaction of the ring (it holds the lines as written, in
//! files that are 0600 and stay on the machine), span fields in the ring,
//! and lines longer than [`LINE_BYTES`] are cut.

use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::layer::{Context, Layer};

/// Lines the queue holds before a caller waits
const QUEUE_LINES: usize = 65_536;
/// How long a caller waits for room, and [`flush`] for the writer
pub const BOUND: Duration = Duration::from_secs(2);

/// Where lines go: debug.log (or the console when there is no file)
static SINK: Mutex<Option<Box<dyn Write + Send>>> = Mutex::new(None);
/// Lines go through the writer thread
static ASYNC: AtomicBool = AtomicBool::new(false);
static QUEUE: Mutex<Queue> = Mutex::new(Queue {
    lines: VecDeque::new(),
    dropped: 0,
    pushed: 0,
    written: 0,
});
static NOT_EMPTY: Condvar = Condvar::new();
static NOT_FULL: Condvar = Condvar::new();
static WRITTEN: Condvar = Condvar::new();
/// Lines dropped since start, for health (A6)
static DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);

struct Queue {
    lines: VecDeque<Vec<u8>>,
    /// Dropped since the last `dropped` line
    dropped: u64,
    /// Lines queued, and lines the writer has written, since start
    pushed: u64,
    written: u64,
}

fn queue() -> std::sync::MutexGuard<'static, Queue> {
    QUEUE.lock().unwrap_or_else(|e| e.into_inner())
}

fn sink() -> std::sync::MutexGuard<'static, Option<Box<dyn Write + Send>>> {
    SINK.lock().unwrap_or_else(|e| e.into_inner())
}

/// debug.log from here on
pub fn set_sink(w: Box<dyn Write + Send>) {
    *sink() = Some(w);
}

/// Lines dropped since start (health, A6)
#[allow(dead_code)]
pub fn dropped_total() -> u64 {
    DROPPED_TOTAL.load(Ordering::Relaxed)
}

/// The `running` phase: start the writer thread. If it cannot start,
/// lines stay synchronous.
pub fn start_writer() {
    if sink().is_none() || ASYNC.load(Ordering::SeqCst) {
        return;
    }
    if crate::tasks::thread("log-writer", crate::tasks::Kind::Supervised, writer).is_ok() {
        ASYNC.store(true, Ordering::SeqCst);
    }
}

fn writer() {
    loop {
        let batch: Vec<Vec<u8>> = {
            let mut q = queue();
            while q.lines.is_empty() {
                q = NOT_EMPTY.wait(q).unwrap_or_else(|e| e.into_inner());
            }
            let batch = q.lines.drain(..).collect();
            NOT_FULL.notify_all();
            batch
        };
        let n = batch.len() as u64;
        {
            let mut out = sink();
            if let Some(w) = out.as_mut() {
                for line in &batch {
                    let _ = w.write_all(line);
                }
            }
        }
        let dropped = {
            let mut q = queue();
            q.written += n;
            WRITTEN.notify_all();
            if q.lines.is_empty() {
                std::mem::take(&mut q.dropped)
            } else {
                0
            }
        };
        if dropped > 0 {
            note_dropped(dropped);
        }
    }
}

/// The queue drained after a burst of dropped lines
fn note_dropped(n: u64) {
    crate::runs_log::record("dropped", &format!("lines={}", n));
    let line = format!(
        "{} WARN irondivid::log: {} log lines dropped: the debug.log writer was behind for {} s\n",
        crate::runs_log::utc_now(),
        n,
        BOUND.as_secs()
    );
    if let Some(w) = sink().as_mut() {
        let _ = w.write_all(line.as_bytes());
    }
}

fn deliver(buf: &[u8]) {
    if !ASYNC.load(Ordering::Acquire) {
        if let Some(w) = sink().as_mut() {
            let _ = w.write_all(buf);
        }
        return;
    }
    let deadline = Instant::now() + BOUND;
    let mut q = queue();
    while q.lines.len() >= QUEUE_LINES {
        let now = Instant::now();
        if now >= deadline {
            q.dropped += 1;
            DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q = NOT_FULL
            .wait_timeout(q, deadline - now)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
    q.lines.push_back(buf.to_vec());
    q.pushed += 1;
    NOT_EMPTY.notify_one();
}

/// Write out the lines queued so far, waiting [`BOUND`] at most
pub fn flush(bound: Duration) {
    let deadline = Instant::now() + bound;
    if ASYNC.load(Ordering::Acquire) {
        let mut q = queue();
        let target = q.pushed;
        while q.written < target {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            q = WRITTEN
                .wait_timeout(q, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
    // The writer may hold the file on a hung disk: do not wait past the bound
    loop {
        match SINK.try_lock() {
            Ok(mut s) => {
                if let Some(w) = s.as_mut() {
                    let _ = w.flush();
                }
                return;
            }
            Err(std::sync::TryLockError::Poisoned(e)) => {
                if let Some(w) = e.into_inner().as_mut() {
                    let _ = w.flush();
                }
                return;
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// The `MakeWriter` of debug.log: each formatted event is one `write`
#[derive(Clone, Copy, Default)]
pub struct DebugLog;

impl Write for DebugLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        deliver(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DebugLog {
    type Writer = DebugLog;
    fn make_writer(&'a self) -> DebugLog {
        DebugLog
    }
}

// ---- fields ----

/// The field formatter of debug.log and the ring: as tracing's default,
/// but the `counted` tag is left out, so a tagged line reads as before
#[derive(Clone, Copy, Default)]
pub struct Fields;

impl<'w> FormatFields<'w> for Fields {
    fn format_fields<R: RecordFields>(&self, mut writer: Writer<'w>, fields: R) -> fmt::Result {
        let mut v = FieldWriter {
            out: &mut writer,
            first: true,
            result: Ok(()),
        };
        fields.record(&mut v);
        v.result
    }
}

struct FieldWriter<'a, W: fmt::Write> {
    out: &'a mut W,
    first: bool,
    result: fmt::Result,
}

impl<W: fmt::Write> Visit for FieldWriter<'_, W> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.record_debug(field, &format_args!("{}", value))
        } else {
            self.record_debug(field, &value)
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let name = field.name();
        if self.result.is_err() || name == COUNTED || name.starts_with("log.") {
            return;
        }
        let sep = if self.first { "" } else { " " };
        self.first = false;
        self.result = if name == "message" {
            write!(self.out, "{}{:?}", sep, value)
        } else {
            let name = name.strip_prefix("r#").unwrap_or(name);
            write!(self.out, "{}{}={:?}", sep, name, value)
        };
    }
}

/// The tag of an A11 counted log site
pub const COUNTED: &str = "counted";

// ---- the ring ----

/// Lines the ring holds
pub const RING_SLOTS: usize = 4096;
const LINE_WORDS: usize = 40;
/// Longest line kept; longer ones are cut
pub const LINE_BYTES: usize = LINE_WORDS * 8;

struct Slot {
    /// 2n+1 while line n is written, 2n+2 once it is complete
    seq: AtomicU64,
    len: AtomicU32,
    data: [AtomicU64; LINE_WORDS],
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            seq: AtomicU64::new(0),
            len: AtomicU32::new(0),
            data: [const { AtomicU64::new(0) }; LINE_WORDS],
        }
    }
}

/// The last [`RING_SLOTS`] lines; a seqlock per slot, so reading takes no
/// lock and a line being written is skipped
pub struct Ring {
    head: AtomicU64,
    slots: [Slot; RING_SLOTS],
}

/// The node's ring
pub static RING: Ring = Ring::new();

impl Ring {
    pub const fn new() -> Ring {
        Ring {
            head: AtomicU64::new(0),
            slots: [const { Slot::new() }; RING_SLOTS],
        }
    }

    pub fn push(&self, line: &[u8]) {
        let n = self.head.fetch_add(1, Ordering::Relaxed);
        let slot = &self.slots[(n % RING_SLOTS as u64) as usize];
        slot.seq.store(2 * n + 1, Ordering::Relaxed);
        fence(Ordering::Release);
        let len = line.len().min(LINE_BYTES);
        for (i, word) in slot.data.iter().enumerate() {
            let start = i * 8;
            if start >= len {
                break;
            }
            let mut b = [0u8; 8];
            let end = (start + 8).min(len);
            b[..end - start].copy_from_slice(&line[start..end]);
            word.store(u64::from_ne_bytes(b), Ordering::Relaxed);
        }
        slot.len.store(len as u32, Ordering::Relaxed);
        slot.seq.store(2 * n + 2, Ordering::Release);
    }

    /// Each complete line, oldest first. Takes no lock and allocates
    /// nothing, so a signal handler may call it.
    pub fn for_each(&self, mut out: impl FnMut(&[u8])) {
        let head = self.head.load(Ordering::Acquire);
        let mut buf = [0u8; LINE_BYTES];
        for n in head.saturating_sub(RING_SLOTS as u64)..head {
            let slot = &self.slots[(n % RING_SLOTS as u64) as usize];
            let s1 = slot.seq.load(Ordering::Acquire);
            if s1 != 2 * n + 2 {
                continue;
            }
            let len = (slot.len.load(Ordering::Relaxed) as usize).min(LINE_BYTES);
            for (i, word) in slot.data.iter().enumerate() {
                if i * 8 >= len {
                    break;
                }
                buf[i * 8..i * 8 + 8]
                    .copy_from_slice(&word.load(Ordering::Relaxed).to_ne_bytes());
            }
            fence(Ordering::Acquire);
            if slot.seq.load(Ordering::Relaxed) != s1 {
                continue;
            }
            out(&buf[..len]);
        }
    }
}

impl Default for Ring {
    fn default() -> Self {
        Ring::new()
    }
}

/// Whether the ring takes events of this callsite: never a counted one;
/// debug for IronDivi's own code, info for libraries
pub fn ring_wants(meta: &Metadata<'_>) -> bool {
    if meta.fields().field(COUNTED).is_some() {
        return false;
    }
    let ours = crate::log_filter::OUR_TARGETS
        .iter()
        .any(|t| meta.target().starts_with(t));
    *meta.level() <= if ours { Level::DEBUG } else { Level::INFO }
}

/// The layer that copies events into a ring
pub struct RingLayer {
    ring: &'static Ring,
}

impl<S: Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut line = String::with_capacity(160);
        let _ = write!(
            line,
            "{} {:>5} {}: ",
            crate::runs_log::utc_now(),
            meta.level(),
            meta.target()
        );
        let mut v = FieldWriter {
            out: &mut line,
            first: true,
            result: Ok(()),
        };
        event.record(&mut v);
        line.push('\n');
        self.ring.push(line.as_bytes());
    }
}

/// The ring's layer with its own filter ([`ring_wants`]). The filter is on
/// this layer only: a counted line still reaches debug.log.
pub fn ring_layer<S>(ring: &'static Ring) -> impl Layer<S> + Send + Sync
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    RingLayer { ring }.with_filter(tracing_subscriber::filter::filter_fn(ring_wants))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;

    static TEST_RING: Ring = Ring::new();

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    fn ring_lines(ring: &Ring) -> Vec<String> {
        let mut v = Vec::new();
        ring.for_each(|l| v.push(String::from_utf8_lossy(l).into_owned()));
        v
    }

    #[test]
    fn counted_lines_reach_debug_log_untagged_and_stay_out_of_the_ring() {
        let buf = Buf::default();
        let file = tracing_subscriber::fmt::layer()
            .fmt_fields(Fields)
            .with_writer(buf.clone())
            .with_ansi(false)
            .without_time()
            .with_filter(tracing_subscriber::EnvFilter::new("debug"));
        let subscriber = tracing_subscriber::registry()
            .with(file)
            .with(ring_layer(&TEST_RING));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "divi_node::test", counted = true, peer = 7, "a line {}", 1);
            tracing::debug!(target: "divi_node::test", peer = 7, "a line {}", 1);
            tracing::debug!(target: "divi_node::test", "ring only {}", 2);
            tracing::debug!(target: "somelib", "a library debug line");
        });
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{}", text);
        // The counted line is still in debug.log, and reads as the untagged one
        assert_eq!(lines[0], lines[1], "{}", text);
        assert!(!text.contains("counted"), "{}", text);
        assert!(lines[0].ends_with("a line 1 peer=7"), "{}", text);

        let ring = ring_lines(&TEST_RING);
        assert_eq!(
            ring.iter().filter(|l| l.contains("a line 1")).count(),
            1,
            "{:?}",
            ring
        );
        assert!(ring.iter().all(|l| !l.contains("counted")), "{:?}", ring);
        assert!(ring.iter().any(|l| l.contains("ring only 2")), "{:?}", ring);
        // Libraries reach the ring at info only
        assert!(ring.iter().all(|l| !l.contains("library debug")), "{:?}", ring);
    }

    #[test]
    fn ring_keeps_the_last_lines_and_cuts_long_ones() {
        static RING3: Ring = Ring::new();
        let ring = &RING3;
        for i in 0..RING_SLOTS + 10 {
            ring.push(format!("line {}\n", i).as_bytes());
        }
        let lines = ring_lines(ring);
        assert_eq!(lines.len(), RING_SLOTS);
        assert_eq!(lines[0], "line 10\n");
        assert_eq!(lines[RING_SLOTS - 1], format!("line {}\n", RING_SLOTS + 9));
        ring.push(&[b'x'; LINE_BYTES + 50]);
        let last = ring_lines(ring).pop().unwrap();
        assert_eq!(last.len(), LINE_BYTES);
    }

    #[test]
    fn the_ring_ignores_the_configured_level() {
        // debug.log at warn; the ring still gets debug of our own code
        let buf = Buf::default();
        static RING2: Ring = Ring::new();
        let file = tracing_subscriber::fmt::layer()
            .fmt_fields(Fields)
            .with_writer(buf.clone())
            .with_filter(tracing_subscriber::EnvFilter::new("warn"));
        let subscriber = tracing_subscriber::registry()
            .with(file)
            .with(ring_layer(&RING2));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "irondivid", "detail for later");
        });
        assert!(buf.0.lock().unwrap().is_empty());
        assert!(ring_lines(&RING2).iter().any(|l| l.contains("detail for later")));
    }
}
