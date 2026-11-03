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
//!
//! The `fork`, `ban` and `incident` events compare against what was there
//! when the capture started, so an old fork, ban or incident never fires:
//! `fork` is a new `getchaintips` tip off the best chain (a `valid-fork` or
//! `invalid` tip, or headers that leave the best chain below its tip; the
//! headers of a peer just ahead are not a fork); `ban` is a new
//! `listbanned` entry; `incident` is a new entry in the A12 incident
//! folders (`<datadir>/diag/incidents/`, and the A14 mirror's). Event lines
//! carry heights, counts, a status and a kind, never a hash or an address.

use super::live::{self, CallError};
use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// At most 7 days
pub const MAX_MINUTES: u64 = 7 * 24 * 60;
/// One sample every 10 s
const EVERY: Duration = Duration::from_secs(10);
/// The tip unchanged this long is a stall (the A12 stall threshold)
pub const STALL_SECS: u64 = 600;
/// Output cap; a 10 s sample line over 7 days stays far below it
const CAP_BYTES: u64 = 200 << 20;

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
    /// a new chain tip off the best chain
    Fork,
    /// a new entry in the node's ban list
    Ban,
    /// a new A12 incident
    Incident,
}

/// Parse one `--until` word: `exit`, `stall`, `fork`, `ban`, `incident`,
/// `rss>N` (MB), `peers<N`
pub fn parse_until(w: &str) -> Result<Until, String> {
    let w = w.trim();
    let num = |s: &str| {
        s.trim()
            .parse::<u64>()
            .map_err(|_| format!("--until {w}: {s:?} is not a whole number"))
    };
    if w == "exit" {
        Ok(Until::Exit)
    } else if w == "stall" {
        Ok(Until::Stall)
    } else if w == "fork" {
        Ok(Until::Fork)
    } else if w == "ban" {
        Ok(Until::Ban)
    } else if w == "incident" {
        Ok(Until::Incident)
    } else if let Some(n) = w.strip_prefix("rss>") {
        Ok(Until::RssOver(num(
            n.trim_end_matches(['M', 'B', 'm', 'b'])
        )?))
    } else if let Some(n) = w.strip_prefix("peers<") {
        Ok(Until::PeersUnder(num(n)?))
    } else {
        Err(format!(
            "--until {w}: unknown event (exit, stall, fork, ban, incident, rss>N in MB, peers<N)"
        ))
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
    s.push_str(&format!(
        "  in screen: screen -S irondivi-diag irondivi-cli diag {args}\n"
    ));
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
        let t = crate::util::run_cmd("sysctl", &["-n", "vm.loadavg"], Duration::from_secs(2), 256)
            .text();
        let t = t
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim()
            .to_string();
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
        let t =
            crate::util::read_small(std::path::Path::new(&format!("/proc/pressure/{r}")), 1024)?;
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
pub fn fired(
    until: &[Until],
    alive: bool,
    rss: Option<u64>,
    peers: Option<u64>,
    still: Duration,
) -> Option<String> {
    for u in until {
        match u {
            Until::Exit if !alive => return Some("exit: the node process is gone".into()),
            Until::Stall if alive && still >= Duration::from_secs(STALL_SECS) => {
                return Some(format!(
                    "stall: the tip did not move for {} s",
                    still.as_secs()
                ))
            }
            Until::RssOver(n) if rss.is_some_and(|r| r > n << 20) => {
                return Some(format!(
                    "rss>{n}: the node uses {} MB",
                    rss.unwrap_or(0) >> 20
                ))
            }
            Until::PeersUnder(n) if peers.is_some_and(|p| p < *n) => {
                return Some(format!("peers<{n}: {} connections", peers.unwrap_or(0)))
            }
            _ => {}
        }
    }
    None
}

/// The non-active tips of a `getchaintips` answer, by hash
pub fn side_tips(tips: &Value) -> BTreeSet<String> {
    tips.as_array()
        .into_iter()
        .flatten()
        .filter(|t| t["status"].as_str() != Some("active"))
        .filter_map(|t| t["hash"].as_str().map(str::to_string))
        .collect()
}

/// A tip in `tips` that was not in `start` and is a fork: `valid-fork` or
/// `invalid`, or any other status whose branch leaves the best chain below
/// the best tip (headers that only extend the best chain are a peer ahead)
pub fn new_fork(start: &BTreeSet<String>, tips: &Value) -> Option<String> {
    let all = tips.as_array()?;
    let best = all
        .iter()
        .find(|t| t["status"].as_str() == Some("active"))?["height"]
        .as_u64()?;
    for t in all {
        let (Some(h), Some(st)) = (t["hash"].as_str(), t["status"].as_str()) else {
            continue;
        };
        if st == "active" || start.contains(h) {
            continue;
        }
        let height = t["height"].as_u64().unwrap_or(0);
        let len = t["branchlen"].as_u64().unwrap_or(0);
        let from = height.saturating_sub(len);
        if st == "valid-fork" || st == "invalid" || from < best {
            return Some(format!(
                "fork: a new {st} tip of {len} block(s) leaves the best chain at height {from} (best chain at {best})"
            ));
        }
    }
    None
}

/// The entries of a `listbanned` answer, as address and creation time
pub fn bans(list: &Value) -> BTreeSet<String> {
    list.as_array()
        .into_iter()
        .flatten()
        .map(|b| {
            format!(
                "{} {}",
                b["address"].as_str().unwrap_or("?"),
                b["ban_created"]
            )
        })
        .collect()
}

/// New bans in `list` since `start`: the count and their reasons, never
/// the address
pub fn new_bans(start: &BTreeSet<String>, list: &Value) -> Option<String> {
    let new: Vec<&Value> = list
        .as_array()?
        .iter()
        .filter(|b| {
            !start.contains(&format!(
                "{} {}",
                b["address"].as_str().unwrap_or("?"),
                b["ban_created"]
            ))
        })
        .collect();
    if new.is_empty() {
        return None;
    }
    let mut why: Vec<String> = new
        .iter()
        .map(|b| {
            b["ban_reason"]
                .as_str()
                .filter(|r| !r.is_empty())
                .unwrap_or("no reason given")
                .to_string()
        })
        .collect();
    why.sort();
    why.dedup();
    Some(format!(
        "ban: {} new ban(s) (reason: {})",
        new.len(),
        why.join("; ")
    ))
}

/// The A12 incident folders of the watched data dir
fn incident_dirs(ctx: &Ctx, d: &crate::ctx::DataDir) -> Vec<PathBuf> {
    let mut v = vec![
        d.chain.join("diag/incidents"),
        d.path.join("diag/incidents"),
    ];
    if let Some(m) = live::mirror_dir(ctx, d) {
        v.push(m.join("incidents"));
        v.push(m.join("diag/incidents"));
    }
    v.dedup();
    v
}

/// The entries of the incident folders, each as `<folder n>/<name>`; None
/// when no folder could be listed in 1 s (a hung disk)
fn incident_entries(dirs: &[PathBuf]) -> Option<(BTreeSet<String>, usize)> {
    let dirs = dirs.to_vec();
    live::bounded(1, move || {
        let mut seen = BTreeSet::new();
        let mut readable = 0;
        for (i, d) in dirs.iter().enumerate() {
            if let Ok(rd) = std::fs::read_dir(d) {
                readable += 1;
                for e in rd.flatten() {
                    seen.insert(format!("{i}/{}", e.file_name().to_string_lossy()));
                }
            }
        }
        (seen, readable)
    })
}

/// The `kind=` of a new incident (A12 `info.txt`), when it can be read
fn incident_kind(dirs: &[PathBuf], entry: &str) -> String {
    let Some((i, name)) = entry.split_once('/') else {
        return "kind unknown".into();
    };
    let Some(d) = i.parse::<usize>().ok().and_then(|i| dirs.get(i)) else {
        return "kind unknown".into();
    };
    let p = d.join(name).join("info.txt");
    live::bounded(1, move || crate::util::read_small(&p, 4096))
        .flatten()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("kind=").map(|k| k.trim().to_string()))
        })
        .filter(|k| {
            !k.is_empty()
                && k.len() <= 32
                && k.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
        .map(|k| format!("kind {k}"))
        .unwrap_or_else(|| "kind unknown".into())
}

/// What the `fork`, `ban` and `incident` events compare against
struct Watch {
    tips: Option<BTreeSet<String>>,
    bans: Option<BTreeSet<String>>,
    incidents: Option<BTreeSet<String>>,
    dirs: Vec<PathBuf>,
}

/// The `fork`, `ban` or `incident` event this sample fires, if any; a
/// call that fails or times out fires nothing
fn watch_fired(w: &Watch, rpc: Option<&live::Rpc>, t: Duration) -> Option<String> {
    if let (Some(start), Some(r)) = (&w.tips, rpc) {
        if let Some(e) = live::call(r, "getchaintips", Value::Array(vec![]), t)
            .ok()
            .and_then(|v| new_fork(start, &v))
        {
            return Some(e);
        }
    }
    if let (Some(start), Some(r)) = (&w.bans, rpc) {
        if let Some(e) = live::call(r, "listbanned", Value::Array(vec![]), t)
            .ok()
            .and_then(|v| new_bans(start, &v))
        {
            return Some(e);
        }
    }
    if let Some(start) = &w.incidents {
        if let Some((now, _)) = incident_entries(&w.dirs) {
            let new: Vec<&String> = now.difference(start).collect();
            if let Some(first) = new.first() {
                return Some(format!(
                    "incident: {} new A12 incident(s), the first {}",
                    new.len(),
                    incident_kind(&w.dirs, first)
                ));
            }
        }
    }
    None
}

pub fn capture(ctx: &Ctx, o: &mut Out) {
    o.file("capture/samples.txt");
    let plan = &ctx.capture;
    let Some(d) = plan
        .datadir
        .and_then(|n| ctx.datadirs.iter().find(|d| d.n == n))
    else {
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
            Until::Fork => "fork".to_string(),
            Until::Ban => "ban".to_string(),
            Until::Incident => "incident".to_string(),
        })
        .collect();
    outln!(
        o,
        "capture of datadir-{} pid {} for {} min, a sample every {} s; until: {}; RPC: {}",
        d.n,
        node.pid,
        plan.minutes,
        EVERY.as_secs(),
        if until.is_empty() {
            "the time is up".into()
        } else {
            until.join(", ")
        },
        if rpc.is_some() {
            "yes"
        } else {
            "no credentials"
        }
    );
    let two = Duration::from_secs(2);
    let mut watch = Watch {
        tips: None,
        bans: None,
        incidents: None,
        dirs: incident_dirs(ctx, d),
    };
    for u in &plan.until {
        match (u, &rpc) {
            (Until::Fork, Some(r)) => {
                match live::call(r, "getchaintips", Value::Array(vec![]), two) {
                    Ok(v) => {
                        let t = side_tips(&v);
                        outln!(
                            o,
                            "fork watch: {} tip(s) off the best chain at the start (not events)",
                            t.len()
                        );
                        watch.tips = Some(t);
                    }
                    Err(e) => outln!(
                        o,
                        "fork watch: not watched: getchaintips failed ({})",
                        num(Err(e)).unwrap_err()
                    ),
                }
            }
            (Until::Ban, Some(r)) => match live::call(r, "listbanned", Value::Array(vec![]), two) {
                Ok(v) => {
                    let b = bans(&v);
                    outln!(o, "ban watch: {} ban(s) at the start (not events)", b.len());
                    watch.bans = Some(b);
                }
                Err(e) => outln!(
                    o,
                    "ban watch: not watched: listbanned failed ({})",
                    num(Err(e)).unwrap_err()
                ),
            },
            (Until::Fork | Until::Ban, None) => {
                outln!(
                    o,
                    "{} watch: not watched: no RPC credentials",
                    if *u == Until::Fork { "fork" } else { "ban" }
                )
            }
            (Until::Incident, _) => match incident_entries(&watch.dirs) {
                Some((e, readable)) => {
                    outln!(
                        o,
                        "incident watch: {} incident(s) at the start (not events) in {readable} of {} folder(s) that exist and can be read",
                        e.len(),
                        watch.dirs.len()
                    );
                    watch.incidents = Some(e);
                }
                None => outln!(
                    o,
                    "incident watch: not watched: the incident folders did not list in 1 s"
                ),
            },
            _ => {}
        }
    }
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
        let rss = if up {
            crate::runner::rss_of(node.pid)
        } else {
            None
        };
        let (height, peers) = match (&rpc, up) {
            (Some(r), true) => (
                num(live::call(
                    r,
                    "getblockcount",
                    Value::Array(vec![]),
                    Duration::from_secs(2),
                )),
                num(live::call(
                    r,
                    "getconnectioncount",
                    Value::Array(vec![]),
                    Duration::from_secs(2),
                )),
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
            rss.map(|r| (r >> 20).to_string())
                .unwrap_or_else(|| "-".into()),
            show(&height),
            show(&peers),
            load_avg(),
            free.map(|f| (f >> 20).to_string())
                .unwrap_or_else(|| "?".into()),
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
        let mut event = fired(&plan.until, up, rss, peers.ok(), tip_since.elapsed());
        if event.is_none() && up {
            event = watch_fired(&watch, rpc.as_ref(), two);
        }
        if let Some(e) = event {
            outln!(o, "event {e}");
            o.flush();
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
    outln!(
        o,
        "capture ended after {} s and {n} samples: {why_end}",
        start.elapsed().as_secs()
    );
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
        assert_eq!(parse_until("fork"), Ok(Until::Fork));
        assert_eq!(parse_until("ban"), Ok(Until::Ban));
        assert_eq!(parse_until("incident"), Ok(Until::Incident));
        assert!(parse_until("rss>lots").is_err());
        assert!(parse_until("crash").is_err());
    }

    #[test]
    fn only_a_new_tip_off_the_best_chain_is_a_fork() {
        let tip = |h: u64, hash: &str, len: u64, st: &str| serde_json::json!({"height": h, "hash": hash, "branchlen": len, "status": st});
        let old = Value::Array(vec![
            tip(100, "a", 0, "active"),
            tip(50, "old", 1, "valid-fork"),
        ]);
        let start = side_tips(&old);
        assert_eq!(start.len(), 1);
        assert_eq!(new_fork(&start, &old), None);
        // a peer's headers just ahead of the best tip
        let ahead = Value::Array(vec![
            tip(100, "a", 0, "active"),
            tip(103, "h", 3, "headers-only"),
        ]);
        assert_eq!(new_fork(&start, &ahead), None);
        // headers that leave the best chain below its tip
        let side = Value::Array(vec![
            tip(100, "a", 0, "active"),
            tip(101, "s", 3, "valid-headers"),
        ]);
        assert!(new_fork(&start, &side).unwrap().contains("at height 98"));
        // a reorg: the old tip is now a valid-fork tip
        let reorg = Value::Array(vec![
            tip(101, "b", 0, "active"),
            tip(100, "feedface", 1, "valid-fork"),
        ]);
        let e = new_fork(&start, &reorg).unwrap();
        assert!(
            e.starts_with(
                "fork: a new valid-fork tip of 1 block(s) leaves the best chain at height 99"
            ),
            "{e}"
        );
        assert!(!e.contains("feedface"));
        // an invalid block at the tip
        let inv = Value::Array(vec![tip(99, "p", 0, "active"), tip(100, "a", 1, "invalid")]);
        assert!(new_fork(&start, &inv).unwrap().contains("invalid"));
    }

    #[test]
    fn only_a_new_ban_fires_and_never_names_the_address() {
        let b = |a: &str, t: u64, r: &str| serde_json::json!({"address": a, "ban_created": t, "banned_until": t + 86400, "ban_reason": r});
        let old = Value::Array(vec![b("10.0.0.1", 5, "manually added")]);
        let start = bans(&old);
        assert_eq!(new_bans(&start, &old), None);
        let now = Value::Array(vec![
            b("10.0.0.1", 5, "manually added"),
            b("10.9.8.7", 9, "node misbehaving"),
        ]);
        let e = new_bans(&start, &now).unwrap();
        assert_eq!(e, "ban: 1 new ban(s) (reason: node misbehaving)");
        assert!(!e.contains("10.9.8.7"));
    }

    #[test]
    fn a_new_incident_folder_fires_with_its_kind() {
        let root = std::env::temp_dir().join(format!("diag-cap-inc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("1")).unwrap();
        let dirs = vec![root.clone(), root.join("absent")];
        let w = Watch {
            tips: None,
            bans: None,
            incidents: incident_entries(&dirs).map(|e| e.0),
            dirs: dirs.clone(),
        };
        assert_eq!(incident_entries(&dirs).unwrap().1, 1);
        assert_eq!(watch_fired(&w, None, Duration::from_secs(1)), None);
        std::fs::create_dir_all(root.join("2")).unwrap();
        std::fs::write(root.join("2/info.txt"), "kind=stall\nrun=3\n").unwrap();
        assert_eq!(
            watch_fired(&w, None, Duration::from_secs(1)).as_deref(),
            Some("incident: 1 new A12 incident(s), the first kind stall")
        );
        std::fs::create_dir_all(root.join("3")).unwrap();
        std::fs::write(root.join("3/info.txt"), "kind=../../x y\n").unwrap();
        let _ = std::fs::remove_dir_all(root.join("2"));
        assert_eq!(
            watch_fired(&w, None, Duration::from_secs(1)).as_deref(),
            Some("incident: 1 new A12 incident(s), the first kind unknown")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn events_fire() {
        let all = [
            Until::Exit,
            Until::Stall,
            Until::RssOver(100),
            Until::PeersUnder(2),
        ];
        let s = Duration::from_secs(1);
        assert_eq!(fired(&all, true, Some(50 << 20), Some(5), s), None);
        assert!(fired(&all, false, None, None, s)
            .unwrap()
            .starts_with("exit"));
        assert!(fired(&all, true, Some(200 << 20), Some(5), s)
            .unwrap()
            .starts_with("rss>100"));
        assert!(fired(&all, true, Some(50 << 20), Some(1), s)
            .unwrap()
            .starts_with("peers<2"));
        assert!(
            fired(&all, true, None, None, Duration::from_secs(STALL_SECS))
                .unwrap()
                .starts_with("stall")
        );
        // an RPC that does not answer is not "0 peers"
        assert_eq!(fired(&[Until::PeersUnder(2)], true, None, None, s), None);
        assert_eq!(fired(&[], false, None, None, s), None);
    }
}
