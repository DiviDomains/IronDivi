//! The hourly count lines of the A11 counted sites.
//!
//! A counted site writes no line of its own; it bumps its counter in
//! `divi_primitives::counted`. Every hour of the boot clock this module
//! writes one line per site, zeros included, in one fixed format at info:
//!
//! `count site=<key> n=<n> start=<utc> end=<utc> boot=<boot_id> synced=<yes|no|unknown>`
//!
//! The hour runs on the boot clock (CLOCK_BOOTTIME on Linux; on macOS
//! CLOCK_MONOTONIC, which counts through sleep there), checked by a 60 s
//! tick, so a wall-clock step neither shortens nor stretches it. The wall
//! times only label it; a window whose wall span is not an hour was
//! stretched or squeezed by a clock step, which the reader can see from
//! `start` and `end`.
//!
//! At a clean stop the partial hour's lines are written (`flush`). On an
//! abnormal end (`die`, a third stop signal, a fatal signal) the nonzero
//! counts of the current hour are copied raw into a `counts` record of
//! runs.log or the crash record, with plain loads: no lock, no allocation.

use crate::runs_log::RawLine;
use divi_primitives::counted::{Counters, COUNT, COUNTERS, KEYS};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// The window, in seconds of the boot clock
const HOUR: f64 = 3600.0;

/// How often the window is checked
const TICK: Duration = Duration::from_secs(60);

/// The open window: where it started on the boot clock and the wall clock
#[derive(Clone, Copy, Debug, PartialEq)]
struct Window {
    start_boot: f64,
    start_wall: i64,
}

static WINDOW: OnceLock<Mutex<Window>> = OnceLock::new();

/// Seconds on a clock that counts through suspend: CLOCK_BOOTTIME on
/// Linux; CLOCK_MONOTONIC elsewhere (on macOS it counts through sleep)
// time_t and c_long are 32 bits on some targets
#[allow(clippy::unnecessary_cast)]
fn boot_secs() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let id = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let id = libc::CLOCK_MONOTONIC;
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

fn now() -> Window {
    Window {
        start_boot: boot_secs(),
        start_wall: divi_primitives::clock::system_now(),
    }
}

/// Open the first window; idempotent
pub(crate) fn init() {
    WINDOW.get_or_init(|| Mutex::new(now()));
}

/// Whether the window that opened at `start_boot` is an hour old at
/// `boot_now`
fn due(start_boot: f64, boot_now: f64) -> bool {
    boot_now - start_boot >= HOUR
}

/// One line per site, in site order, zeros included
fn lines(counts: &[u32], start_wall: i64, end_wall: i64, boot: &str, synced: &str) -> Vec<String> {
    let start = crate::runs_log::format_utc(start_wall, 0);
    let end = crate::runs_log::format_utc(end_wall, 0);
    KEYS.iter()
        .zip(counts)
        .map(|(key, n)| {
            format!(
                "count site={} n={} start={} end={} boot={} synced={}",
                key, n, start, end, boot, synced
            )
        })
        .collect()
}

/// Close the window when `force` or when it is an hour old: write its
/// lines and open the next one
fn close(force: bool) {
    let Some(window) = WINDOW.get() else {
        return;
    };
    let mut window = window.lock().unwrap_or_else(|e| e.into_inner());
    let next = now();
    if !force && !due(window.start_boot, next.start_boot) {
        return;
    }
    let counts = COUNTERS.take();
    let boot = crate::running_marker::boot_id();
    let synced = crate::health::clock_synced();
    for line in lines(&counts, window.start_wall, next.start_wall, &boot, synced) {
        tracing::info!(target: "irondivid::counts", "{}", line);
    }
    *window = next;
}

/// The count task: check the window every minute
pub(crate) async fn run() {
    init();
    loop {
        tokio::time::sleep(TICK).await;
        close(false);
    }
}

/// At a clean stop: the partial hour's lines
pub(crate) fn flush() {
    close(true);
}

/// The nonzero counts of the open window as `counts` records, each handed
/// to `emit` (a record is cut before it would pass its 511 bytes). At
/// least one record, empty when nothing was counted. Plain loads, no reset,
/// no lock, no allocation: async-signal-safe.
pub(crate) fn raw_copy(emit: impl FnMut(&mut RawLine)) {
    raw_copy_of(&COUNTERS, emit)
}

fn raw_copy_of(counters: &Counters, mut emit: impl FnMut(&mut RawLine)) {
    let mut line = RawLine::new("counts");
    for (i, key) in KEYS.iter().enumerate().take(COUNT) {
        let n = counters.load(i);
        if n == 0 {
            continue;
        }
        // " " key "=" up to 10 digits
        if line.room() < key.len() + 12 {
            emit(&mut line);
            line = RawLine::new("counts");
        }
        line.text(" ").text(key).text("=").num(i64::from(n));
    }
    emit(&mut line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_hour_on_the_boot_clock() {
        assert!(!due(100.0, 100.0));
        assert!(!due(100.0, 3699.9));
        assert!(due(100.0, 3700.0));
        assert!(due(100.0, 9000.0));
    }

    #[test]
    fn one_line_per_site_zeros_included() {
        let mut counts = [0u32; COUNT];
        counts[1] = 7;
        let out = lines(&counts, 0, 3600, "b-1", "yes");
        assert_eq!(out.len(), COUNT);
        assert_eq!(
            out[0],
            format!(
                "count site={} n=0 start=1970-01-01T00:00:00.000000Z \
                 end=1970-01-01T01:00:00.000000Z boot=b-1 synced=yes",
                KEYS[0]
            )
        );
        assert!(out[1].starts_with(&format!("count site={} n=7 ", KEYS[1])));
        // The same shape for every site: only the key and the count differ
        for line in &out {
            let shape: Vec<&str> = line
                .split(' ')
                .map(|f| f.split('=').next().unwrap())
                .collect();
            assert_eq!(
                shape,
                ["count", "site", "n", "start", "end", "boot", "synced"]
            );
        }
    }

    #[test]
    fn raw_copy_splits_and_never_drops_a_pair() {
        let counters = Counters::new();
        for site in divi_primitives::counted::Site::ALL {
            counters.add(*site, 1_000_000_000);
        }
        let mut records = Vec::new();
        raw_copy_of(&counters, |l| records.push(l.as_str().to_string()));
        assert!(records.len() > 1, "{:?}", records);
        let mut seen = 0;
        for r in &records {
            assert!(r.len() <= 511);
            assert!(r.contains(" counts"));
            seen += KEYS
                .iter()
                .filter(|k| r.contains(&format!(" {}=", k)))
                .count();
        }
        assert_eq!(seen, COUNT);
        // Nothing counted: one empty record
        let mut records = Vec::new();
        raw_copy_of(&Counters::new(), |l| records.push(l.as_str().to_string()));
        assert_eq!(records.len(), 1);
        assert!(records[0].ends_with(" counts"), "{:?}", records);
    }
}
