// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `<datadir>/diag/runs.log` (diag.md A1): one line per start, start-up
//! phase, daemon fork, stop request and exit, so a run that ended can be
//! told from one that is still going, and why it ended.
//!
//! Each line is an RFC 3339 UTC time with microseconds, `mono=` (the
//! monotonic clock in seconds), the record's kind and `key=value` fields.
//! Every record is written by its caller with one `write` and then
//! `fdatasync`; `die()` writes the `exit` record this way before it ends the
//! process. (Interim: A8's writer thread and its `dropped` count are not
//! built yet, and records made before the data directory is known go
//! nowhere until A14's `_unresolved/` mirror exists.)
//!
//! No record holds an option's value, an address or anything about a block
//! or transaction: the lines are the same for every node.
//!
//! [`RawLine`] and [`raw_exit`] write a record without allocating or taking
//! a lock, for the signal handler's third stop signal (A3).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// The open runs.log; records are dropped until it is set
static FILE: OnceLock<File> = OnceLock::new();
/// FILE's descriptor, for [`RawLine`] (-1: not open)
static RAW_FD: AtomicI32 = AtomicI32::new(-1);
/// What `note_launch` saw before any fork
static LAUNCH: OnceLock<Launch> = OnceLock::new();
/// The pid that was started, and the intermediate one, when -daemon forked
static FIRST_PID: AtomicI32 = AtomicI32::new(0);
static MIDDLE_PID: AtomicI32 = AtomicI32::new(0);
/// Threads in the process just before the first fork (-1: not counted)
static THREADS_AT_FORK: AtomicI64 = AtomicI64::new(-1);
/// This run's number and `<datadir>/diag`, once runs.log is open
static RUN: OnceLock<(u64, PathBuf)> = OnceLock::new();
/// The phase entered last, and when
static PHASE: Mutex<Option<(&'static str, Instant)>> = Mutex::new(None);

struct Launch {
    at: Instant,
    ppid: i32,
    parent: String,
    how: &'static str,
}

/// Note when and how the process was started. Called first thing in
/// `main`, before the -daemon forks, which would hide the parent and the
/// terminal; it starts no thread.
pub fn note_launch() {
    let ppid = unsafe { libc::getppid() };
    let how = if std::env::var_os("INVOCATION_ID").is_some() {
        "systemd"
    } else if Path::new("/.dockerenv").exists() {
        "container"
    } else if unsafe { libc::isatty(0) == 1 || libc::isatty(2) == 1 } {
        "terminal"
    } else {
        "other"
    };
    let _ = LAUNCH.set(Launch {
        at: Instant::now(),
        ppid,
        parent: comm(ppid),
        how,
    });
}

/// Before the first -daemon fork: the pid that was started and the number
/// of threads (diag.md §3: no thread may exist before the forks)
pub fn note_first_fork() {
    FIRST_PID.store(unsafe { libc::getpid() }, Ordering::Relaxed);
    THREADS_AT_FORK.store(thread_count(), Ordering::Relaxed);
}

/// Before the second -daemon fork: the intermediate process's pid
pub fn note_second_fork() {
    MIDDLE_PID.store(unsafe { libc::getpid() }, Ordering::Relaxed);
}

/// Open `<data_dir>/diag/runs.log` and write the `start` record (and the
/// `daemon` record when the process forked). Failures are reported on the
/// log and leave runs.log off: it never stops the node.
pub fn open(data_dir: &Path, network: &str, daemon: bool) {
    if let Err(e) = try_open(data_dir) {
        tracing::warn!("diag/runs.log is not kept: {}", e);
        return;
    }
    let launch = LAUNCH.get();
    let run = last_run(&data_dir.join("diag").join("runs.log")) + 1;
    let _ = RUN.set((run, data_dir.join("diag")));
    let (uid, euid, gid) = unsafe { (libc::getuid(), libc::geteuid(), libc::getgid()) };
    let exe = std::env::current_exe()
        .map(|p| quote(&p.display().to_string()))
        .unwrap_or_else(|_| "-".into());
    record(
        "start",
        &format!(
            "run={} pid={} ppid={} parent={} uid={} euid={} gid={} exe={} version={} \
             network={} how={} daemon={} pid1={} kernel={}",
            run,
            unsafe { libc::getpid() },
            launch.map_or(0, |l| l.ppid),
            launch.map_or_else(|| "-".to_string(), |l| quote(&l.parent)),
            uid,
            euid,
            gid,
            exe,
            env!("CARGO_PKG_VERSION"),
            network,
            launch.map_or("other", |l| l.how),
            yes(daemon),
            yes(unsafe { libc::getpid() } == 1),
            quote(&kernel_release()),
        ),
    );
    if daemon {
        let threads = THREADS_AT_FORK.load(Ordering::Relaxed);
        record(
            "daemon",
            &format!(
                "pid={} first={} middle={} threads_at_fork={}",
                unsafe { libc::getpid() },
                FIRST_PID.load(Ordering::Relaxed),
                MIDDLE_PID.load(Ordering::Relaxed),
                if threads < 0 {
                    "-".to_string()
                } else {
                    threads.to_string()
                },
            ),
        );
    }
}

fn try_open(data_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = data_dir.join("diag");
    let created = !dir.exists();
    crate::private_files::ensure_private_dir(&dir, true)?;
    let path = dir.join("runs.log");
    let new_file = !path.exists();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    // The new entries themselves must survive a power loss, not only the
    // records written into them
    if new_file {
        File::open(&dir)?.sync_all()?;
    }
    if created {
        File::open(data_dir)?.sync_all()?;
    }
    let fd = file.as_raw_fd();
    if FILE.set(file).is_ok() {
        RAW_FD.store(fd, Ordering::Release);
    }
    Ok(())
}

/// The highest `run=` of a `start` record near the end of `path`; 0 if none
fn last_run(path: &Path) -> u64 {
    let Ok(mut f) = File::open(path) else {
        return 0;
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(65_536)));
    let mut bytes = Vec::new();
    let _ = f.read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|l| l.split_once(" start run=").map(|(_, r)| r))
        .filter_map(|r| r.split(' ').next()?.parse::<u64>().ok())
        .max()
        .unwrap_or(0)
}

/// Write one record: `<time> mono=<s> <kind> <fields>`, then fdatasync.
/// A no-op until runs.log is open; a write error is ignored (the node goes on).
pub fn record(kind: &str, fields: &str) {
    let Some(mut file) = FILE.get() else {
        return;
    };
    let line = format!("{} mono={} {} {}\n", utc_now(), mono_now(), kind, fields);
    if file.write_all(line.as_bytes()).is_ok() {
        let _ = file.sync_data();
    }
}

/// Once the data directory's lock is held: the A2 marker (and the
/// `unclean-previous` record when the last run left its marker behind)
pub fn marker_create() {
    if let Some((run, dir)) = RUN.get() {
        crate::running_marker::create(dir, *run);
    }
}

/// Enter start-up phase `name`; the record carries the phase before it and
/// how long that took
pub fn phase(name: &'static str) {
    let now = Instant::now();
    let prev = {
        let mut last = PHASE.lock().unwrap_or_else(|e| e.into_inner());
        last.replace((name, now))
    };
    let (prev_name, since) = match prev {
        Some((n, at)) => (n, at),
        None => ("launch", LAUNCH.get().map_or(now, |l| l.at)),
    };
    record(
        "phase",
        &format!(
            "name={} prev={} prev_ms={}{}",
            name,
            prev_name,
            now.duration_since(since).as_millis(),
            tid()
        ),
    );
    crate::running_marker::phase(name);
}

/// A stop was asked for, `by` what (`signal=TERM`, `rpc`, ...)
pub fn stop_requested(by: &str) {
    record("stop-requested", &format!("by={}", by));
    crate::running_marker::stop_requested(by);
}

/// The process is ending with `code`; `reason` is the line printed for it
pub fn exit(code: i32, reason: &str) {
    let uptime = LAUNCH.get().map_or(0.0, |l| l.at.elapsed().as_secs_f64());
    let (sigpipes, epipes) = crate::signals::counts();
    record(
        "exit",
        &format!(
            "code={} run={} pid={} uptime_s={:.3} peak_rss_kb={} reason={} sigpipe={} epipe={}",
            code,
            RUN.get().map_or(0, |r| r.0),
            std::process::id(),
            uptime,
            peak_rss_kb(),
            quote(reason),
            sigpipes,
            epipes
        ),
    );
    // The end is on record: the marker goes, last (A2)
    crate::running_marker::remove();
}

/// The `exit` record, written without allocating or locking (a signal
/// handler's); the marker is left for the next start, which reads this
/// record (`verdict=exit-recorded`)
pub fn raw_exit(code: i32, reason: &str, sigpipes: u64, epipes: u64) {
    let mut line = RawLine::new("exit");
    line.text(" code=")
        .num(i64::from(code))
        .text(" run=")
        .num(RUN.get().map_or(0, |r| r.0 as i64))
        .text(" pid=")
        .num(i64::from(unsafe { libc::getpid() }));
    if let Some(l) = LAUNCH.get() {
        let ms = l.at.elapsed().as_millis() as i64;
        line.text(" uptime_s=")
            .num(ms / 1000)
            .text(".")
            .padded(ms % 1000, 3);
    } else {
        line.text(" uptime_s=0.000");
    }
    line.text(" peak_rss_kb=")
        .num(peak_rss_kb())
        .text(" reason=\"")
        .text(reason)
        .text("\" sigpipe=")
        .num(sigpipes as i64)
        .text(" epipe=")
        .num(epipes as i64);
    line.write();
}

/// A record built in a fixed buffer and written with one `write` and
/// `fdatasync`: no allocation, no lock (async-signal-safe). Cut at 511 bytes.
pub struct RawLine {
    buf: [u8; 512],
    len: usize,
}

impl RawLine {
    /// `<time> mono=<s> <kind>`
    // time_t and c_long are 32 bits on some targets
    #[allow(clippy::unnecessary_cast)]
    pub fn new(kind: &str) -> RawLine {
        let mut line = RawLine {
            buf: [0; 512],
            len: 0,
        };
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        let secs = ts.tv_sec as i64;
        let (year, month, day) = civil(secs.div_euclid(86_400));
        let rem = secs.rem_euclid(86_400);
        line.padded(year, 4)
            .text("-")
            .padded(month, 2)
            .text("-")
            .padded(day, 2)
            .text("T")
            .padded(rem / 3600, 2)
            .text(":")
            .padded(rem % 3600 / 60, 2)
            .text(":")
            .padded(rem % 60, 2)
            .text(".")
            .padded(ts.tv_nsec as i64 / 1000, 6)
            .text("Z mono=");
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        line.num(ts.tv_sec as i64)
            .text(".")
            .padded(ts.tv_nsec as i64 / 1000, 6)
            .text(" ")
            .text(kind);
        line
    }

    pub fn text(&mut self, s: &str) -> &mut RawLine {
        let room = self.buf.len() - 1 - self.len;
        let n = s.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        self
    }

    pub fn num(&mut self, v: i64) -> &mut RawLine {
        self.padded(v, 1)
    }

    /// `v` in decimal, zero-padded to `width` digits
    pub fn padded(&mut self, v: i64, width: usize) -> &mut RawLine {
        let mut digits = [0u8; 20];
        let mut d = digits.len();
        let mut u = v.unsigned_abs();
        loop {
            d -= 1;
            digits[d] = b'0' + (u % 10) as u8;
            u /= 10;
            if u == 0 {
                break;
            }
        }
        while digits.len() - d < width.min(digits.len()) {
            d -= 1;
            digits[d] = b'0';
        }
        if v < 0 {
            self.text("-");
        }
        // ASCII digits
        self.text(std::str::from_utf8(&digits[d..]).unwrap_or(""))
    }

    /// Append the line to runs.log, then fdatasync; a no-op before it is open
    pub fn write(&mut self) {
        let fd = RAW_FD.load(Ordering::Acquire);
        if fd < 0 {
            return;
        }
        self.buf[self.len] = b'\n';
        unsafe {
            if libc::write(fd, self.buf.as_ptr().cast(), self.len + 1) > 0 {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                libc::fdatasync(fd);
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                libc::fsync(fd);
            }
        }
    }
}

pub(crate) fn yes(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// `"text"` on one line: quotes become `'`, control characters a space,
/// cut at 240 characters
pub(crate) fn quote(s: &str) -> String {
    let clean: String = s
        .chars()
        .take(240)
        .map(|c| match c {
            '"' => '\'',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    format!("\"{}\"", clean)
}

/// RFC 3339 UTC with microseconds
pub(crate) fn utc_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_utc(now.as_secs() as i64, now.subsec_micros())
}

fn format_utc(secs: i64, micros: u32) -> String {
    let (year, month, day) = civil(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        year,
        month,
        day,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        micros
    )
}

/// Days since 1970-01-01 to (year, month, day) (H. Hinnant,
/// "chrono-Compatible Low-Level Date Algorithms")
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The monotonic clock, seconds with microseconds
fn mono_now() -> String {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    format!("{}.{:06}", ts.tv_sec, ts.tv_nsec / 1000)
}

/// Peak resident set size in KiB (ru_maxrss is KiB on Linux, bytes on macOS)
fn peak_rss_kb() -> i64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return 0;
    }
    if cfg!(target_os = "macos") {
        ru.ru_maxrss as i64 / 1024
    } else {
        ru.ru_maxrss as i64
    }
}

fn kernel_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return "-".into();
    }
    unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// A process's command name (Linux); "-" elsewhere
fn comm(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "-".into())
}

/// Threads in this process (Linux); -1 elsewhere
fn thread_count() -> i64 {
    std::fs::read_dir("/proc/self/task").map_or(-1, |d| d.count() as i64)
}

/// ` tid=<n>`: the calling thread's kernel id (Linux), else empty
fn tid() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        format!(" tid={}", unsafe { libc::syscall(libc::SYS_gettid) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_times_are_rfc3339_with_microseconds() {
        assert_eq!(format_utc(0, 0), "1970-01-01T00:00:00.000000Z");
        // 2000-02-29 (a leap day in a century year divisible by 400)
        assert_eq!(
            format_utc(951_782_400 + 3661, 7),
            "2000-02-29T01:01:01.000007Z"
        );
        assert_eq!(
            format_utc(1_798_761_599, 999_999),
            "2026-12-31T23:59:59.999999Z"
        );
    }

    #[test]
    fn a_raw_line_matches_the_formatted_one() {
        let mut line = RawLine::new("signal");
        line.text(" n=").num(-42).text(" p=").padded(7, 3);
        let text = std::str::from_utf8(&line.buf[..line.len]).unwrap();
        let words: Vec<&str> = text.split(' ').collect();
        assert_eq!(words[0].len(), 27, "{text}");
        assert!(words[0].ends_with('Z') && words[0].as_bytes()[10] == b'T');
        assert!(words[1].starts_with("mono=") && words[1].contains('.'));
        assert_eq!(words[2..], ["signal", "n=-42", "p=007"]);
        let mut long = RawLine::new("x");
        long.text(&"y".repeat(600));
        assert_eq!(long.len, 511);
    }

    #[test]
    fn a_quoted_field_stays_on_one_line() {
        assert_eq!(quote("a \"b\"\nc"), "\"a 'b' c\"");
        assert_eq!(quote(&"x".repeat(500)).len(), 242);
    }

    #[test]
    fn the_run_number_follows_the_last_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runs.log");
        assert_eq!(last_run(&path), 0);
        std::fs::write(
            &path,
            "t mono=1 start run=4 pid=1\nt mono=2 exit code=0\nt mono=3 start run=5 pid=2\n",
        )
        .unwrap();
        assert_eq!(last_run(&path), 5);
    }
}
