// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B6.1 `diag --capture <minutes> [--until <event>]`: a sample of the
//! running node every 10 s, for problems that come and go. It runs before
//! the B2 collection, so the normal collection is the full snapshot taken
//! when the capture ends (the time is up, an event fired, or Ctrl+C).
//!
//! Each sample, after the R1 (a) free-space check: the node's process
//! (alive, resident memory), `getblockcount` and `getconnectioncount`, the
//! load average, PSI (Linux) and free memory. No `getpeerinfo` detail.

use super::live::{self, CallError};
use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};

/// At most 7 days
pub const MAX_MINUTES: u64 = 7 * 24 * 60;
/// One sample every 10 s
const EVERY: Duration = Duration::from_secs(10);
/// The tip unchanged this long is a stall (the A12 stall threshold)
pub const STALL_SECS: u64 = 600;
/// Output cap; a 10 s sample line over 7 days stays far below it
const CAP_BYTES: u64 = 200 << 20;
/// The B6.1 events this version does not watch
const NOT_BUILT: &[&str] = &["fork", "ban", "incident"];

/// One `--until` event
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Until {
    /// the node process is gone
    Exit,
    /// the tip did not move for [`STALL_SECS`]
    Stall,
    /// the node's resident memory over N MB
    RssOver(u64),
    /// fewer than N connections
    PeersUnder(u64),
}

/// Parse one `--until` word: `exit`, `stall`, `rss>N` (MB), `peers<N`
pub fn parse_until(w: &str) -> Result<Until, String> {
    let w = w.trim();
    let num = |s: &str| s.trim().parse::<u64>().map_err(|_| format!("--until {w}: {s:?} is not a whole number"));
    if w == "exit" {
        Ok(Until::Exit)
    } else if w == "stall" {
        Ok(Until::Stall)
    } else if let Some(n) = w.strip_prefix("rss>") {
        Ok(Until::RssOver(num(n.trim_end_matches(['M', 'B', 'm', 'b']))?))
    } else if let Some(n) = w.strip_prefix("peers<") {
        Ok(Until::PeersUnder(num(n)?))
    } else if NOT_BUILT.contains(&w) {
        Err(format!("--until {w} is not in this version (exit, stall, rss>N, peers<N are)"))
    } else {
        Err(format!("--until {w}: unknown event (exit, stall, rss>N in MB, peers<N)"))
    }
}

/// What the parent hands the collector
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Plan {
    pub minutes: u64,
    pub until: Vec<Until>,
    /// the data dir whose node is watched
    pub datadir: Option<usize>,
}

/// The command that keeps a capture running after the terminal closes
pub fn keep_running_hint(args: &str) -> String {
    let mut s = format!("  in tmux:   tmux new -s irondivi-diag 'irondivi-cli diag {args}'\n");
    s.push_str(&format!("  in screen: screen -S irondivi-diag irondivi-cli diag {args}\n"));
    if cfg!(target_os = "linux") {
        s.push_str(&format!(
            "  systemd:   systemd-run --user --unit irondivi-diag-capture --working-directory \"$PWD\" irondivi-cli diag {args}\n"
        ));
    }
    s
}

fn load_avg() -> String {
    if cfg!(target_os = "linux") {
        crate::util::read_small(std::path::Path::new("/proc/loadavg"), 256)
            .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
            .unwrap_or_else(|| "?".into())
    } else {
        let t = crate::util::run_cmd("sysctl", &["-n", "vm.loadavg"], Duration::from_secs(2), 256).text();
        let t = t.trim().trim_start_matches('{').trim_end_matches('}').trim().to_string();
        if t.is_empty() {
            "?".into()
        } else {
            t
        }
    }
}

/// PSI `some avg10` for cpu, memory and io (Linux only)
fn psi() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let mut parts = Vec::new();
    for r in ["cpu", "memory", "io"] {
        let t = crate::util::read_small(std::path::Path::new(&format!("/proc/pressure/{r}")), 1024)?;
        let v = t
            .lines()
            .find(|l| l.starts_with("some"))
            .and_then(|l| l.split_whitespace().find_map(|f| f.strip_prefix("avg10=")))
            .unwrap_or("?");
        parts.push(format!("{r} {v}"));
    }
    Some(parts.join(" "))
}

fn alive(pid: u32) -> bool {
    let r = unsafe { libc::kill(pid as i32, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn num(r: Result<Value, CallError>) -> Result<u64, String> {
    match r {
        Ok(v) => v.as_u64().ok_or_else(|| "not a number".into()),
        Err(CallError::Timeout) => Err("slow".into()),
        Err(CallError::Refused) => Err("refused".into()),
        Err(CallError::Auth) => Err("auth".into()),
        Err(CallError::Rpc(c, _)) => Err(format!("error {c}")),
        Err(_) => Err("failed".into()),
    }
}

/// Which `--until` event the sample fires, if any
pub fn fired(until: &[Until], alive: bool, rss: Option<u64>, peers: Option<u64>, still: Duration) -> Option<String> {
    for u in until {
        match u {
            Until::Exit if !alive => return Some("exit: the node process is gone".into()),
            Until::Stall if alive && still >= Duration::from_secs(STALL_SECS) => {
                return Some(format!("stall: the tip did not move for {} s", still.as_secs()))
            }
            Until::RssOver(n) if rss.is_some_and(|r| r > n << 20) => {
                return Some(format!("rss>{n}: the node uses {} MB", rss.unwrap_or(0) >> 20))
            }
            Until::PeersUnder(n) if peers.is_some_and(|p| p < *n) => {
                return Some(format!("peers<{n}: {} connections", peers.unwrap_or(0)))
            }
            _ => {}
        }
    }
    None
}

pub fn capture(ctx: &Ctx, o: &mut Out) {
    o.file("capture/samples.txt");
    let plan = &ctx.capture;
    let Some(d) = plan.datadir.and_then(|n| ctx.datadirs.iter().find(|d| d.n == n)) else {
        outln!(o, "no data dir chosen: no capture");
        return;
    };
    let Some(node) = ctx.node_for(d) else {
        outln!(o, "no node is running on datadir-{}: no capture", d.n);
        return;
    };
    let rpc = live::rpc_for(d, Some(node)).ok();
    let until: Vec<String> = plan
        .until
        .iter()
        .map(|u| match u {
            Until::Exit => "exit".to_string(),
            Until::Stall => format!("stall ({STALL_SECS} s)"),
            Until::RssOver(n) => format!("rss>{n} MB"),
            Until::PeersUnder(n) => format!("peers<{n}"),
        })
        .collect();
    outln!(
        o,
        "capture of datadir-{} pid {} for {} min, a sample every {} s; until: {}; RPC: {}",
        d.n,
        node.pid,
        plan.minutes,
        EVERY.as_secs(),
        if until.is_empty() { "the time is up".into() } else { until.join(", ") },
        if rpc.is_some() { "yes" } else { "no credentials" }
    );
    outln!(o, "columns: time (UTC), seconds since start, node, rss MB, height, peers, load avg, free memory MB, PSI some avg10");
    let start = Instant::now();
    let total = Duration::from_secs(plan.minutes * 60);
    let mut bytes = 0u64;
    let mut last_tip: Option<u64> = None;
    let mut tip_since = Instant::now();
    let mut n = 0u64;
    let mut why_end = "the time is up".to_string();
    loop {
        if let Err(why) = crate::runner::room(&ctx.out_dir, ctx) {
            why_end = format!("free space: {why}");
            break;
        }
        let up = alive(node.pid);
        let rss = if up { crate::runner::rss_of(node.pid) } else { None };
        let (height, peers) = match (&rpc, up) {
            (Some(r), true) => (
                num(live::call(r, "getblockcount", Value::Array(vec![]), Duration::from_secs(2))),
                num(live::call(r, "getconnectioncount", Value::Array(vec![]), Duration::from_secs(2))),
            ),
            _ => (Err("-".into()), Err("-".into())),
        };
        if let Ok(h) = height {
            if last_tip != Some(h) {
                last_tip = Some(h);
                tip_since = Instant::now();
            }
        }
        let free = crate::mem::free_memory(Some(node.pid)).bytes;
        let show = |r: &Result<u64, String>| match r {
            Ok(v) => v.to_string(),
            Err(e) => e.clone(),
        };
        let line = format!(
            "{} +{}s {} {} {} {} load {} free {}{}",
            &crate::util::rfc3339(crate::util::now_secs())[11..19],
            start.elapsed().as_secs(),
            if up { "up" } else { "GONE" },
            rss.map(|r| (r >> 20).to_string()).unwrap_or_else(|| "-".into()),
            show(&height),
            show(&peers),
            load_avg(),
            free.map(|f| (f >> 20).to_string()).unwrap_or_else(|| "?".into()),
            psi().map(|p| format!(" psi {p}")).unwrap_or_default(),
        );
        n += 1;
        if bytes + line.len() as u64 + 1 > CAP_BYTES {
            why_end = format!("the {} MB output cap", CAP_BYTES >> 20);
            break;
        }
        bytes += line.len() as u64 + 1;
        outln!(o, "{line}");
        // each sample reaches the package now: Ctrl+C kills this collector
        o.flush();
        if let Some(e) = fired(&plan.until, up, rss, peers.ok(), tip_since.elapsed()) {
            why_end = format!("event {e}");
            break;
        }
        if !up && !plan.until.contains(&Until::Exit) {
            why_end = "the node process is gone".into();
            break;
        }
        // the next sample is due at n * EVERY from the start; the last one
        // falls on the end itself (a 1 min capture: 0 s to 60 s, 7 samples)
        if EVERY * n as u32 > total {
            break;
        }
        let next = start + EVERY * n as u32;
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
    }
    outln!(o, "capture ended after {} s and {n} samples: {why_end}", start.elapsed().as_secs());
    o.file("capture/ended.txt");
    outln!(o, "{why_end}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn until_words() {
        assert_eq!(parse_until("exit"), Ok(Until::Exit));
        assert_eq!(parse_until("stall"), Ok(Until::Stall));
        assert_eq!(parse_until("rss>4000"), Ok(Until::RssOver(4000)));
        assert_eq!(parse_until("rss>4000MB"), Ok(Until::RssOver(4000)));
        assert_eq!(parse_until("peers<3"), Ok(Until::PeersUnder(3)));
        assert!(parse_until("fork").unwrap_err().contains("not in this version"));
        assert!(parse_until("rss>lots").is_err());
        assert!(parse_until("crash").is_err());
    }

    #[test]
    fn events_fire() {
        let all = [Until::Exit, Until::Stall, Until::RssOver(100), Until::PeersUnder(2)];
        let s = Duration::from_secs(1);
        assert_eq!(fired(&all, true, Some(50 << 20), Some(5), s), None);
        assert!(fired(&all, false, None, None, s).unwrap().starts_with("exit"));
        assert!(fired(&all, true, Some(200 << 20), Some(5), s).unwrap().starts_with("rss>100"));
        assert!(fired(&all, true, Some(50 << 20), Some(1), s).unwrap().starts_with("peers<2"));
        assert!(fired(&all, true, None, None, Duration::from_secs(STALL_SECS)).unwrap().starts_with("stall"));
        // an RPC that does not answer is not "0 peers"
        assert_eq!(fired(&[Until::PeersUnder(2)], true, None, None, s), None);
        assert_eq!(fired(&[], false, None, None, s), None);
    }
}
