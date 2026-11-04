// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The start-up bound (diag plan A1, as A18's `-startuptimeout` needs it).
//!
//! A thread started with the `config` phase checks once a second until
//! the `running` phase. A start-up gets 5 minutes (`<s>` seconds with
//! `-startuptimeout=<s>`), counted again from each new `phase` record and
//! each rise in the start-up thread's CPU time (Linux). When the bound runs
//! out it writes one incident and an events.log line for that phase, and
//! the node keeps running. Only with `-startuptimeout` does it then end
//! the run with code 10: the `exit` record goes to the A14 mirror first,
//! the data-directory writes run on a helper thread for at most 2 s, then
//! `_exit(10)`. The A2 marker stays, for the next start to read.

use std::time::{Duration, Instant};

/// The bound without `-startuptimeout`
const DEFAULT: Duration = Duration::from_secs(300);
/// How long the data-directory writes may take before `_exit`
const WRITES: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq)]
enum Verdict {
    Wait,
    /// Start-up is over: the thread ends
    Running,
    /// No progress in `phase` for the whole bound
    Expired(&'static str),
}

/// The state between checks; the clock and the readings are passed in
struct Watch {
    limit: Duration,
    phase: Option<(&'static str, Instant)>,
    cpu: Option<u64>,
    since: Instant,
    /// The bound ran out in the current phase (once per phase)
    fired: bool,
}

impl Watch {
    fn new(limit: Duration, now: Instant) -> Watch {
        Watch {
            limit,
            phase: None,
            cpu: None,
            since: now,
            fired: false,
        }
    }

    fn tick(
        &mut self,
        phase: Option<(&'static str, Instant)>,
        cpu: Option<u64>,
        now: Instant,
    ) -> Verdict {
        if phase.is_some_and(|(name, _)| name == "running") {
            return Verdict::Running;
        }
        if phase != self.phase {
            self.phase = phase;
            self.since = now;
            self.fired = false;
        }
        if cpu > self.cpu {
            self.since = now;
        }
        self.cpu = cpu.or(self.cpu);
        if !self.fired && now.duration_since(self.since) >= self.limit {
            self.fired = true;
            return Verdict::Expired(self.phase.map_or("launch", |p| p.0));
        }
        Verdict::Wait
    }
}

/// utime+stime of thread `tid`, in clock ticks
#[cfg(target_os = "linux")]
fn thread_cpu(tid: i64) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{}/stat", tid)).ok()?;
    cpu_of(&stat)
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu(_tid: i64) -> Option<u64> {
    None
}

/// Fields 14 and 15 of a `stat` line; the name may hold spaces
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn cpu_of(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut f = rest.split_whitespace().skip(11);
    Some(f.next()?.parse::<u64>().ok()? + f.next()?.parse::<u64>().ok()?)
}

fn this_tid() -> i64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        unsafe { libc::syscall(libc::SYS_gettid) }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        0
    }
}

/// `running <m> min`, or seconds for a bound under a minute
fn running_for(limit: Duration) -> String {
    let s = limit.as_secs();
    if s >= 60 {
        format!("running {} min", s / 60)
    } else {
        format!("running {} s", s)
    }
}

/// Start the bound; called on the start-up thread, which it watches.
/// `timeout` is `-startuptimeout`'s value; regtest only,
/// `IRONDIVI_TEST_STARTUP_BOUND_S` replaces the 5 minutes, for the tests.
pub fn start(timeout: Option<u64>, regtest: bool) {
    let exits = timeout.is_some();
    let limit = timeout.map(Duration::from_secs).unwrap_or_else(|| {
        std::env::var("IRONDIVI_TEST_STARTUP_BOUND_S")
            .ok()
            .filter(|_| regtest)
            .and_then(|v| v.parse().ok())
            .map_or(DEFAULT, Duration::from_secs)
    });
    let tid = this_tid();
    let started =
        crate::tasks::thread("startup-bound", crate::tasks::Kind::Supervised, move || {
            let mut w = Watch::new(limit, Instant::now());
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let now = Instant::now();
                match w.tick(crate::runs_log::current_phase(), thread_cpu(tid), now) {
                    Verdict::Wait => {}
                    Verdict::Running => return,
                    Verdict::Expired(phase) => expired(phase, limit, exits),
                }
            }
        });
    if let Err(e) = started {
        tracing::warn!("could not start the start-up bound: {}", e);
    }
}

fn expired(phase: &'static str, limit: Duration, exits: bool) {
    let detail = format!(
        "phase={}\nbound_s={}\nexit={}\n{}",
        phase,
        limit.as_secs(),
        crate::runs_log::yes(exits),
        crate::watchdog::threads().0
    );
    let note = format!("phase {} {}", phase, running_for(limit));
    if !exits {
        if let Some(n) = crate::incidents::write("startup-stall", &detail) {
            crate::events::event("incident", &format!("n={} kind=startup-stall", n));
        }
        crate::events::event("start-up", &note);
        return;
    }
    // (1) The exit record to the mirror, which a hung data-dir disk cannot
    // block
    // (with the open hour's counts ahead of it, as `die` writes them)
    let reason = format!("start-up stalled in {}", phase);
    let (sigpipes, epipes) = crate::signals::counts();
    let mut line = crate::runs_log::exit_line(crate::exit_code::FAILED, &reason, sigpipes, epipes);
    let (mirror, file) = crate::runs_log::fds();
    crate::counts::raw_copy(|l| l.write_to(mirror));
    line.write_to(mirror);
    // (2) The data-directory writes, for at most 2 s
    let (done, wait) = std::sync::mpsc::channel();
    let helper = crate::tasks::thread("startup-exit", crate::tasks::Kind::Supervised, move || {
        crate::counts::raw_copy(|l| l.write_to(file));
        line.write_to(file);
        crate::events::event("start-up", &note);
        if let Some(n) = crate::incidents::write("startup-stall", &detail) {
            crate::events::event("incident", &format!("n={} kind=startup-stall", n));
        }
        tracing::error!("{} (exit code {})", reason, crate::exit_code::FAILED);
        crate::console_line(false, format_args!("{}", reason));
        crate::flush_log();
        let _ = done.send(());
    });
    if helper.is_ok() {
        let _ = wait.recv_timeout(WRITES);
    }
    crate::mirror::remove_record();
    // (3) Whether or not they finished
    unsafe { libc::_exit(crate::exit_code::FAILED) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUND: Duration = Duration::from_secs(300);

    #[test]
    fn a_phase_without_progress_runs_out_once() {
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        let mut w = Watch::new(BOUND, t0);
        let p = Some(("db-open", t0));
        assert_eq!(w.tick(p, Some(5), at(1)), Verdict::Wait);
        assert_eq!(w.tick(p, Some(5), at(300)), Verdict::Wait);
        assert_eq!(w.tick(p, Some(5), at(301)), Verdict::Expired("db-open"));
        assert_eq!(w.tick(p, Some(5), at(900)), Verdict::Wait, "once a phase");
        // A new phase starts the count again, and may run out again
        let q = Some(("network", at(901)));
        assert_eq!(w.tick(q, Some(5), at(901)), Verdict::Wait);
        assert_eq!(w.tick(q, Some(5), at(1201)), Verdict::Expired("network"));
    }

    #[test]
    fn cpu_on_the_start_up_thread_is_progress() {
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        let mut w = Watch::new(BOUND, t0);
        let p = Some(("db-open", t0));
        assert_eq!(w.tick(p, Some(5), at(1)), Verdict::Wait);
        assert_eq!(w.tick(p, Some(6), at(250)), Verdict::Wait);
        assert_eq!(w.tick(p, Some(6), at(500)), Verdict::Wait);
        assert_eq!(w.tick(p, Some(6), at(550)), Verdict::Expired("db-open"));
        // No reading (not Linux, or refused) is no progress
        let mut w = Watch::new(BOUND, t0);
        assert_eq!(w.tick(p, None, at(1)), Verdict::Wait);
        assert_eq!(w.tick(p, None, at(301)), Verdict::Expired("db-open"));
    }

    #[test]
    fn the_running_phase_ends_the_watch() {
        let t0 = Instant::now();
        let mut w = Watch::new(BOUND, t0);
        let r = Some(("running", t0));
        assert_eq!(
            w.tick(r, None, t0 + Duration::from_secs(9999)),
            Verdict::Running
        );
    }

    #[test]
    fn cpu_is_read_past_a_name_with_spaces_and_parentheses() {
        let stat = "12 (a (b) c) S 1 2 3 4 5 6 7 8 9 10 70 30 0 0";
        assert_eq!(cpu_of(stat), Some(100));
        assert_eq!(cpu_of("12 (x) S 1"), None);
    }

    #[test]
    fn the_events_line_names_minutes_or_seconds() {
        assert_eq!(running_for(Duration::from_secs(300)), "running 5 min");
        assert_eq!(running_for(Duration::from_secs(2)), "running 2 s");
    }
}
