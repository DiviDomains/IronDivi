// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.14 run table, B2.10 node logs, B2.11 kernel and system log, B2.12
//! core dumps and crash stores.
//!
//! The Part A files (`runs.log`, `crash.log`, `events.log`, ...) are written
//! by the node side, which is being built at the same time; every reader
//! here works from the plan's stated format (Part A, "File layout" and A1)
//! and reports a file that is not there as absent.

use super::{cmd_block_t, head, LINUX};
use crate::ctx::{Ctx, DataDir};
use crate::frame::Out;
use crate::oldlog;
use crate::outln;
use crate::redact::Redactor;
use crate::util;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The `diag/` folders of a data dir: the chain dir's first, then the base
/// dir's when they differ (Part A puts `diag/` in the data dir; for testnet
/// and regtest the plan does not say which of the two, see gaps)
fn diag_dirs(d: &DataDir) -> Vec<PathBuf> {
    let mut v = vec![d.chain.join("diag")];
    if d.path != d.chain {
        v.push(d.path.join("diag"));
    }
    v
}

fn find_diag_file(d: &DataDir, name: &str) -> Option<PathBuf> {
    diag_dirs(d).into_iter().map(|p| p.join(name)).find(|p| p.exists())
}

// ---------------------------------------------------------------- records

/// One Part A record: `<rfc3339> <monotonic> [kind] key=value ...`
#[derive(Debug, Default, Clone)]
pub struct Record {
    pub time: String,
    pub kind: String,
    pub fields: BTreeMap<String, String>,
}

impl Record {
    pub fn get(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| self.fields.get(*k).map(String::as_str))
    }
}

/// Split `key=value` tokens, honouring `key="quoted value"`
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
        } else if c == '\\' && quoted {
            esc = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c.is_whitespace() && !quoted {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse one record. The plan fixes the first two fields (time, monotonic
/// seconds) and key=value after them, but not where the kind goes: it is
/// taken as the third token when that has no `=`, else from `kind=`.
pub fn parse_record(line: &str) -> Option<Record> {
    let t = tokens(line);
    if t.len() < 2 || !t[0].contains('T') || !t[0].as_bytes()[0].is_ascii_digit() {
        return None;
    }
    let mut r = Record { time: t[0].clone(), ..Default::default() };
    let mut rest = &t[2..];
    if t[1].contains('=') {
        // no monotonic field
        rest = &t[1..];
    }
    if let Some(first) = rest.first() {
        if !first.contains('=') {
            r.kind = first.clone();
            rest = &rest[1..];
        }
    }
    for kv in rest {
        if let Some((k, v)) = kv.split_once('=') {
            r.fields.insert(k.to_string(), v.to_string());
        }
    }
    if r.kind.is_empty() {
        r.kind = r.fields.get("kind").cloned().unwrap_or_default();
    }
    Some(r)
}

#[derive(Debug, Default, Clone)]
pub struct Run {
    pub start: String,
    pub pid: String,
    pub version: String,
    pub sha: String,
    pub binary: String,
    pub kernel: String,
    pub boot: String,
    pub container: String,
    pub config: String,
    pub how: String,
    pub last_phase: String,
    pub end: String,
    pub uptime: String,
    pub peak_rss: String,
    pub notes: Vec<String>,
}

fn short(s: &str, n: usize) -> String {
    s.trim_start_matches("sha256:").chars().take(n).collect()
}

/// Group runs.log records into runs (A1). `unclean-previous` is written at
/// the start of the run after the one it is about, so it attaches to the
/// run before.
pub fn runs_from_records(recs: &[Record]) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for r in recs {
        match r.kind.as_str() {
            "start" => {
                runs.push(Run {
                    start: r.time.clone(),
                    pid: r.get(&["pid"]).unwrap_or("").into(),
                    version: r.get(&["version", "ver"]).unwrap_or("").into(),
                    sha: short(r.get(&["git", "git_sha", "sha", "commit"]).unwrap_or(""), 10),
                    binary: short(r.get(&["binary_sha256", "bin_sha256", "sha256", "binary_hash"]).unwrap_or(""), 12),
                    kernel: r.get(&["kernel", "kernel_release"]).unwrap_or("").into(),
                    boot: r.get(&["boot_id", "boot"]).unwrap_or("").into(),
                    container: r.get(&["container"]).unwrap_or("").into(),
                    config: short(r.get(&["config_sha256", "conf_sha256", "config_hash"]).unwrap_or(""), 12),
                    how: r.get(&["how", "started_by", "start"]).unwrap_or("").into(),
                    ..Default::default()
                });
            }
            "start-hash" => {
                if let Some(run) = runs.last_mut() {
                    if let Some(h) = r.get(&["binary_sha256", "bin_sha256", "sha256", "binary_hash"]) {
                        run.binary = short(h, 12);
                    }
                }
            }
            "phase" => {
                if let Some(run) = runs.last_mut() {
                    run.last_phase = r.get(&["phase", "name"]).unwrap_or("?").into();
                }
            }
            "daemon" => {
                if let Some(run) = runs.last_mut() {
                    run.notes.push("forked (-daemon)".into());
                    if let Some(p) = r.get(&["pid"]) {
                        run.pid = p.into();
                    }
                }
            }
            "stop-requested" => {
                if let Some(run) = runs.last_mut() {
                    run.notes.push(format!("stop requested by {}", r.get(&["by", "via", "source"]).unwrap_or("?")));
                }
            }
            "exit" => {
                if let Some(run) = runs.last_mut() {
                    run.end = match (r.get(&["code"]), r.get(&["signal"])) {
                        (_, Some(s)) => format!("signal {s}"),
                        (Some(c), _) => format!("exit {c}{}", r.get(&["reason"]).map(|x| format!(" ({x})")).unwrap_or_default()),
                        _ => "exit".into(),
                    };
                    run.uptime = r.get(&["uptime"]).unwrap_or("").into();
                    run.peak_rss = r.get(&["peak_rss", "rss_peak", "maxrss"]).unwrap_or("").into();
                }
            }
            "unclean-previous" => {
                let n = runs.len();
                if n >= 2 {
                    let prev = &mut runs[n - 2];
                    if prev.end.is_empty() {
                        prev.end = format!("unclean ({})", r.get(&["verdict"]).unwrap_or("marker left behind"));
                    }
                }
            }
            "dropped" => {
                if let Some(run) = runs.last_mut() {
                    run.notes.push(format!("{} log lines dropped", r.get(&["count", "n"]).unwrap_or("?")));
                }
            }
            _ => {}
        }
    }
    runs
}

fn table(runs: &[Run], running_pid: Option<u32>) -> Vec<String> {
    let mut out = vec![format!(
        "{:<27} {:<10} {:<10} {:<14} {:<12} {:<30} {:<10} {:<9} notes",
        "start", "version", "sha", "started by", "last phase", "end", "uptime", "peak rss"
    )];
    let mut prev: Option<&Run> = None;
    let last = runs.len().saturating_sub(1);
    for (i, r) in runs.iter().enumerate() {
        let mut notes = r.notes.clone();
        if let Some(p) = prev {
            for (what, a, b) in [
                ("version", &p.version, &r.version),
                ("binary", &p.binary, &r.binary),
                ("kernel", &p.kernel, &r.kernel),
                ("boot", &p.boot, &r.boot),
                ("container", &p.container, &r.container),
                ("config", &p.config, &r.config),
            ] {
                if !a.is_empty() && !b.is_empty() && a != b {
                    notes.push(format!("{what} changed"));
                }
            }
        }
        let end = if !r.end.is_empty() {
            r.end.clone()
        } else if i == last && running_pid.is_some() {
            "running".into()
        } else {
            "no exit record".into()
        };
        out.push(format!(
            "{:<27} {:<10} {:<10} {:<14} {:<12} {:<30} {:<10} {:<9} {}",
            r.start,
            or_dash(&r.version),
            or_dash(&r.sha),
            or_dash(&r.how),
            or_dash(&r.last_phase),
            end,
            or_dash(&r.uptime),
            or_dash(&r.peak_rss),
            notes.join("; ")
        ));
        prev = Some(r);
    }
    out
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

/// debug.log and its rotations, oldest first (by mtime)
pub(crate) fn debug_logs(d: &DataDir) -> Vec<PathBuf> {
    let mut v: Vec<(i64, PathBuf)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dir in [&d.chain, &d.path] {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("debug.log") && seen.insert(e.path()) {
                if let Ok(md) = e.metadata() {
                    if md.is_file() {
                        v.push((util::mtime_secs(&md), e.path()));
                    }
                }
            }
        }
    }
    v.sort();
    v.into_iter().map(|x| x.1).collect()
}

/// Runs reconstructed from debug.log banners when there is no runs.log
/// (a node from before Part A)
pub fn runs_from_debug_log(text: &str) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for l in text.lines() {
        let ts = l.split_whitespace().next().unwrap_or("").to_string();
        if let Some(p) = l.find("IronDivi v") {
            let ver = l[p + 10..].split_whitespace().next().unwrap_or("").to_string();
            runs.push(Run { start: ts, version: ver, ..Default::default() });
        } else if l.contains("IronDivi shutdown complete") {
            if let Some(r) = runs.last_mut() {
                r.end = format!("clean shutdown line {ts}");
            }
        } else if let Some(p) = l.find("Chain: ") {
            if let Some(r) = runs.last_mut() {
                r.notes.push(l[p..].trim().to_string());
            }
        }
    }
    for r in runs.iter_mut() {
        if r.end.is_empty() {
            r.end = "no clean shutdown line".into();
        }
    }
    runs
}

/// B2.14
pub fn runs(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    if ctx.datadirs.is_empty() {
        outln!(o, "no data dir found; no run table");
        return;
    }
    for d in &ctx.datadirs {
        o.file(&format!("datadir-{}/run-table.txt", d.n));
        match find_diag_file(d, "runs.log") {
            Some(p) => {
                let (bytes, cut) = match util::read_tail(&p, 8 << 20) {
                    Ok(x) => x,
                    Err(e) => {
                        outln!(o, "runs.log {}: {}", r.path_of(&p), util::io_err(&e));
                        continue;
                    }
                };
                let text = util::escape_bytes(&bytes);
                let recs: Vec<Record> = text.lines().filter_map(parse_record).collect();
                let runs = runs_from_records(&recs);
                outln!(o, "source: runs.log ({} records{})", recs.len(), if cut { ", last 8 MB" } else { "" });
                let rows = table(&runs, d.running_pid);
                // newest last; at most the last 50 runs
                let skip = rows.len().saturating_sub(51);
                outln!(o, "{}", rows[0]);
                for l in rows.iter().skip(1.max(skip)) {
                    outln!(o, "{l}");
                }
            }
            None => {
                outln!(o, "source: debug.log banners (no diag/runs.log: a node from before Part A)");
                let mut all = Vec::new();
                for p in debug_logs(d) {
                    // banners only; a big log is scanned in full but not kept
                    match std::fs::read(&p) {
                        Ok(b) => all.extend(runs_from_debug_log(&String::from_utf8_lossy(&b))),
                        Err(e) => outln!(o, "{}: {}", r.path_of(&p), util::io_err(&e)),
                    }
                }
                if all.is_empty() {
                    outln!(o, "no runs found");
                    continue;
                }
                if d.running_pid.is_some() {
                    if let Some(last) = all.last_mut() {
                        if last.end == "no clean shutdown line" {
                            last.end = "running".into();
                        }
                    }
                }
                let rows = table(&all, None);
                let skip = rows.len().saturating_sub(51);
                outln!(o, "{}", rows[0]);
                for l in rows.iter().skip(1.max(skip)) {
                    outln!(o, "{l}");
                }
            }
        }
    }
}

// ---------------------------------------------------------------- B2.10

/// Part A files copied as they are (capped); `sent-txids` (A15) is private
/// and never listed here
const PART_A_FILES: &[&str] = &[
    "runs.log",
    "crash.log",
    "events.log",
    "chain-events.log",
    "health.log",
    "rpc-methods.log",
    "rpc-methods-reserved.log",
    "irondivid.running",
];
const PART_A_DIRS_COPY: &[&str] = &["startup", "incidents"];
/// Listed only until the §6 scanner exists (their contents are raw network
/// and transaction data)
const PART_A_DIRS_LIST: &[&str] = &["invalid", "rejected-tx", "bad-messages"];
const NEVER: &[&str] = &["sent-txids"];

const FULL_TAIL: u64 = 16 << 20;
const REDUCED_CAP: usize = 8 << 20;

fn copy_capped(o: &mut Out, r: &Redactor, rel: &str, p: &Path, cap: u64) {
    match util::read_tail(p, cap) {
        Ok((b, cut)) => {
            o.file(rel);
            if cut {
                outln!(o, "[first part cut: kept the last {}]", util::human(cap));
            }
            o.write(oldlog::filter(&util::escape_bytes(&b), r).render().as_bytes());
        }
        Err(e) => {
            o.file("logs-errors.txt");
            outln!(o, "{rel}: {}", util::io_err(&e));
        }
    }
}

fn is_problem_line(l: &str) -> bool {
    l.contains(" WARN ") || l.contains(" ERROR ") || l.contains("panicked") || l.contains("IronDivi v") || l.contains("Chain: ") || l.contains("shutdown complete")
}

/// The reduced form of an old log: banners and warnings in full (capped),
/// then a count of lines per hour
fn reduce(text: &str, r: &Redactor, budget: &mut usize, o: &mut Out) {
    let f = oldlog::filter(text, r);
    let text = f.text.as_str();
    let mut hours: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut kept = 0usize;
    let mut dropped = 0u64;
    for l in text.lines() {
        let warn = is_problem_line(l);
        if l.len() >= 13 && l.as_bytes()[0].is_ascii_digit() {
            let e = hours.entry(l[..13].to_string()).or_default();
            e.0 += 1;
            if warn {
                e.1 += 1;
            }
        }
        if warn {
            if *budget > l.len() {
                *budget -= l.len() + 1;
                outln!(o, "{l}");
                kept += 1;
            } else {
                dropped += 1;
            }
        }
    }
    outln!(o, "-- {kept} banner and WARN/ERROR lines kept{}", if dropped > 0 { format!(", {dropped} more over the cap") } else { String::new() });
    outln!(o, "-- lines per hour (all kept, warn+error):");
    for (h, (n, w)) in hours {
        outln!(o, "{h}  {n:>8} {w:>6}");
    }
    let removed = oldlog::Filtered { counts: f.counts, removed: f.removed, ..Default::default() };
    o.write(removed.render().as_bytes());
}

/// B2.10
pub fn logs(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    for d in &ctx.datadirs {
        let base = format!("datadir-{}/logs", d.n);
        let logs = debug_logs(d);
        o.file(&format!("{base}/README.txt"));
        outln!(o, "debug.log: the last {} in full (debug.log), older parts and rotations reduced to", util::human(FULL_TAIL));
        outln!(o, "banners, warnings and errors plus a count per hour (debug-older.txt).");
        outln!(o, "Every copy went through the §6.2 old-log filter: per-block, staker and failure-only");
        outln!(o, "lines are counted (weekly or daily, bucketed) instead of kept; wallet-module lines keep");
        outln!(o, "their words only, each argument masked as <num>, <str>, <addr> or <arg>.");
        let mut versions: Vec<String> = Vec::new();
        let mut budget = REDUCED_CAP;
        let newest = logs.iter().rev().find(|p| p.file_name().map(|n| n == "debug.log").unwrap_or(false)).cloned();
        for p in &logs {
            let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            let is_newest = Some(p) == newest.as_ref();
            let bytes = match std::fs::read(p) {
                Ok(b) => b,
                Err(e) => {
                    outln!(o, "{}: {}", r.path_of(p), util::io_err(&e));
                    continue;
                }
            };
            let text = String::from_utf8_lossy(&bytes);
            for v in runs_from_debug_log(&text) {
                if !versions.contains(&v.version) {
                    versions.push(v.version);
                }
            }
            if is_newest {
                let len = bytes.len() as u64;
                if len > FULL_TAIL {
                    let cut = (len - FULL_TAIL) as usize;
                    let cut = bytes[cut..].iter().position(|&b| b == b'\n').map(|x| cut + x + 1).unwrap_or(cut);
                    o.file(&format!("{base}/debug-older.txt"));
                    outln!(o, "=== debug.log, the first {} (before the full tail)", util::human(cut as u64));
                    reduce(&String::from_utf8_lossy(&bytes[..cut]), &r, &mut budget, o);
                    o.file(&format!("{base}/debug.log"));
                    outln!(o, "[first {} cut: in debug-older.txt reduced]", util::human(cut as u64));
                    o.write(oldlog::filter(&util::escape_bytes(&bytes[cut..]), &r).render().as_bytes());
                } else {
                    o.file(&format!("{base}/debug.log"));
                    o.write(oldlog::filter(&util::escape_bytes(&bytes), &r).render().as_bytes());
                }
            } else {
                o.file(&format!("{base}/debug-older.txt"));
                outln!(o, "=== {name} ({})", util::human(bytes.len() as u64));
                reduce(&text, &r, &mut budget, o);
            }
        }
        o.file(&format!("{base}/README.txt"));
        if logs.is_empty() {
            outln!(o, "no debug.log found in the data dir");
        }
        outln!(o, "versions seen in the logs: {}", if versions.is_empty() { "-".into() } else { versions.join(", ") });

        // Part A files
        let mut any = false;
        for dd in diag_dirs(d) {
            if !dd.is_dir() {
                continue;
            }
            any = true;
            for f in PART_A_FILES {
                let p = dd.join(f);
                if p.exists() {
                    copy_capped(o, &r, &format!("{base}/diag/{f}"), &p, 8 << 20);
                } else {
                    o.file(&format!("{base}/README.txt"));
                    outln!(o, "diag/{f}: absent");
                }
            }
            // rotations of the Part A logs and rpc-aggregate*.log
            if let Ok(rd) = std::fs::read_dir(&dd) {
                let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
                names.sort();
                for n in names {
                    if NEVER.iter().any(|x| n.starts_with(x)) || PART_A_FILES.contains(&n.as_str()) {
                        continue;
                    }
                    let p = dd.join(&n);
                    let rotated = PART_A_FILES.iter().any(|f| n.starts_with(&format!("{f}.")));
                    if p.is_file() && (rotated || n.starts_with("rpc-aggregate")) {
                        copy_capped(o, &r, &format!("{base}/diag/{n}"), &p, 4 << 20);
                    }
                }
            }
            for sub in PART_A_DIRS_COPY {
                copy_dir(o, &r, &dd.join(sub), &format!("{base}/diag/{sub}"), 16 << 20);
            }
            for sub in PART_A_DIRS_LIST {
                o.file(&format!("{base}/README.txt"));
                let p = dd.join(sub);
                match std::fs::read_dir(&p) {
                    Ok(rd) => {
                        let mut n = 0u64;
                        let mut size = 0u64;
                        for e in rd.flatten() {
                            n += 1;
                            size += e.metadata().map(|m| m.len()).unwrap_or(0);
                        }
                        outln!(o, "diag/{sub}/: {n} files, {} (listed only; contents wait for the §6 scanner)", util::human(size));
                    }
                    Err(_) => outln!(o, "diag/{sub}/: absent"),
                }
            }
        }
        if !any {
            o.file(&format!("{base}/README.txt"));
            outln!(o, "no diag/ folder in the data dir: a node from before Part A, or one that never started");
        }
    }

    // A14 mirrors
    for (k, root) in ctx.mirror_roots.iter().enumerate() {
        let rel = format!("mirrors/root-{}", k + 1);
        o.file(&format!("{rel}/README.txt"));
        outln!(o, "mirror root {}: {}", k + 1, r.path_of(root));
        if !root.exists() {
            outln!(o, "absent");
            continue;
        }
        copy_dir(o, &r, root, &rel, 16 << 20);
    }
    if ctx.mirror_roots.is_empty() {
        o.file("mirrors/README.txt");
        outln!(o, "no mirror locations apply on this host");
    }
}

/// Copy a folder's files (recursively, no symlinks), newest first up to `cap`
fn copy_dir(o: &mut Out, r: &Redactor, dir: &Path, rel: &str, cap: u64) {
    let mut files: Vec<(i64, PathBuf, u64)> = Vec::new();
    collect_files(dir, &mut files, 0);
    if files.is_empty() {
        return;
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    let mut used = 0u64;
    for (_, p, len) in files {
        let sub = p.strip_prefix(dir).unwrap_or(&p).to_string_lossy().to_string();
        if NEVER.iter().any(|x| sub.contains(x)) {
            continue;
        }
        if used >= cap {
            o.file(&format!("{rel}/README.txt"));
            outln!(o, "{sub}: not copied, over the {} cap", util::human(cap));
            continue;
        }
        let take = len.min(cap - used).min(4 << 20);
        used += take;
        copy_capped(o, &r, &format!("{rel}/{sub}"), &p, take);
    }
}

fn collect_files(dir: &Path, out: &mut Vec<(i64, PathBuf, u64)>, depth: usize) {
    if depth > 4 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(md) = std::fs::symlink_metadata(e.path()) else { continue };
        if md.is_dir() {
            collect_files(&e.path(), out, depth + 1);
        } else if md.is_file() {
            out.push((util::mtime_secs(&md), e.path(), md.len()));
        }
    }
}

// ---------------------------------------------------------------- B2.11

fn kernel_filter(l: &str, pids: &[String]) -> bool {
    let low = l.to_ascii_lowercase();
    const PATS: &[&str] = &[
        "irondivid", "tokio-runtime-w", "rocksdb:", "out of memory", "oom-kill", "oom_reaper", "invoked oom-killer",
        "killed process", "segfault", "general protection", "traps:", "hung_task", "blocked for more than",
        "i/o error", "ext4-fs", "xfs", "btrfs", "zfs", "mmc", "nvme", "blk_update_request", "buffer i/o",
        "thermal", "under-voltage", "undervoltage", "clocksource", "pm: suspend", "pm: resume", "suspend entry",
        "suspend exit", "seccomp", "avc:", "apparmor=\"denied\"", "memory cgroup",
    ];
    PATS.iter().any(|p| low.contains(p)) || pids.iter().any(|p| low.contains(&format!("[{p}]")) || low.contains(&format!("pid={p} ")) || low.contains(&format!("pid {p}")))
}

/// Reduce an OOM report's process table to the killed task and the node's
/// tasks (the rest is every other user's process list)
fn reduce_oom(lines: Vec<String>, pids: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_table = false;
    let mut hidden = 0;
    for l in lines {
        let low = l.to_ascii_lowercase();
        if low.contains("tasks state (memory values in pages)") || low.contains("[  pid  ]") {
            in_table = true;
            out.push(l);
            continue;
        }
        if in_table {
            let row = l.contains("] ") && l.rsplit_once(']').map(|x| x.0.contains('[')).unwrap_or(false) && l.matches(char::is_numeric).count() > 6;
            if row && !low.contains("oom-kill") && !low.contains("out of memory") && !low.contains("killed process") {
                if low.contains("irondivi") || pids.iter().any(|p| l.contains(&format!("[{:>7}]", p)) || l.contains(&format!("[{p}]"))) {
                    out.push(l);
                } else {
                    hidden += 1;
                }
                continue;
            }
            in_table = false;
            if hidden > 0 {
                out.push(format!("  [{hidden} other processes' rows left out]"));
                hidden = 0;
            }
        }
        out.push(l);
    }
    out
}

/// Drop the hostname from `short-iso` journal lines (`<time> <host> <ident>: ...`)
fn strip_host(l: &str) -> String {
    let mut it = l.splitn(3, ' ');
    match (it.next(), it.next(), it.next()) {
        (Some(t), Some(_host), Some(rest)) if t.len() > 18 && t.as_bytes()[0].is_ascii_digit() => format!("{t} {rest}"),
        _ => l.to_string(),
    }
}

fn runs_log_pids(ctx: &Ctx) -> Vec<String> {
    let mut v: Vec<String> = ctx.node_pids().iter().map(|p| p.to_string()).collect();
    for d in &ctx.datadirs {
        if let Some(p) = find_diag_file(d, "runs.log") {
            if let Ok((b, _)) = util::read_tail(&p, 1 << 20) {
                for r in String::from_utf8_lossy(&b).lines().filter_map(parse_record) {
                    if let Some(pid) = r.get(&["pid"]) {
                        if !v.iter().any(|x| x == pid) {
                            v.push(pid.to_string());
                        }
                    }
                }
            }
        }
    }
    v
}

fn filtered(o: &mut Out, title: &str, text: &str, pids: &[String], host_strip: bool) {
    let lines: Vec<String> = text
        .lines()
        .map(|l| if host_strip { strip_host(l) } else { l.to_string() })
        .collect();
    // keep a matching line, and every line of an OOM report around it
    let mut keep = Vec::new();
    let mut in_oom = false;
    for l in lines {
        let low = l.to_ascii_lowercase();
        if low.contains("invoked oom-killer") {
            in_oom = true;
        }
        if in_oom || kernel_filter(&l, pids) {
            keep.push(l);
        }
        if low.contains("killed process") || low.contains("oom_reaper") {
            in_oom = false;
        }
    }
    let keep = reduce_oom(keep, pids);
    head(o, title);
    outln!(o, "{} matching lines", keep.len());
    let skip = keep.len().saturating_sub(5000);
    for l in keep.into_iter().skip(skip) {
        outln!(o, "{}", mask_quoted_cmdlines(&l));
    }
}

/// B2.11
pub fn kernel(ctx: &Ctx, o: &mut Out) {
    o.file("kernel/kernel.txt");
    let pids = runs_log_pids(ctx);
    outln!(o, "Kernel and system log lines about the node, memory, storage, power and sandboxing.");
    outln!(o, "Every other line is left out; OOM process tables keep only the killed task and the node.");
    if !LINUX {
        let r = util::run_cmd(
            "log",
            &["show", "--last", "7d", "--style", "syslog", "--predicate",
              "process == \"irondivid\" OR eventMessage CONTAINS[c] \"irondivi\" OR (process == \"kernel\" AND (eventMessage CONTAINS[c] \"memorystatus\" OR eventMessage CONTAINS[c] \"jetsam\" OR eventMessage CONTAINS[c] \"I/O error\" OR eventMessage CONTAINS[c] \"apfs\" AND eventMessage CONTAINS[c] \"error\"))"],
            Duration::from_secs(20),
            8 << 20,
        );
        head(o, "log show (7 days)");
        if !r.ok() {
            outln!(o, "[{}]", r.status_line());
        }
        let text: String = r.text().lines().map(strip_host_syslog).collect::<Vec<_>>().join("\n");
        let lines: Vec<&str> = text.lines().collect();
        let skip = lines.len().saturating_sub(5000);
        for l in lines.into_iter().skip(skip) {
            outln!(o, "{l}");
        }
        return;
    }
    let mut got = false;
    if util::which("journalctl").is_some() {
        let r = util::run_cmd("journalctl", &["-k", "-o", "short-iso", "--since", "-7d", "--no-pager", "-q"], Duration::from_secs(20), 32 << 20);
        if r.ok() && !r.stdout.is_empty() {
            filtered(o, "journalctl -k (7 days, hostname left out)", &r.text(), &pids, true);
            got = true;
        } else {
            head(o, "journalctl -k");
            outln!(o, "[{}] {}", r.status_line(), util::escape_bytes(&r.stderr).lines().next().unwrap_or(""));
        }
    }
    {
        let r = util::run_cmd("dmesg", &["-T"], Duration::from_secs(10), 8 << 20);
        if r.ok() {
            filtered(o, "dmesg -T (kernel ring buffer)", &r.text(), &pids, false);
            got = true;
        } else {
            head(o, "dmesg -T");
            outln!(o, "[{}] {}", r.status_line(), util::escape_bytes(&r.stderr).lines().next().unwrap_or(""));
        }
    }
    for f in ["/var/log/kern.log", "/var/log/messages", "/var/log/syslog"] {
        if !got || f != "/var/log/syslog" {
            match util::read_tail(Path::new(f), 32 << 20) {
                Ok((b, _)) => {
                    let t = String::from_utf8_lossy(&b);
                    let t: String = t.lines().map(strip_host_syslog).collect::<Vec<_>>().join("\n");
                    filtered(o, &format!("{f} (hostname left out)"), &t, &pids, false);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    head(o, f);
                    outln!(o, "{}", util::io_err(&e));
                }
            }
        }
    }
    if util::which("logread").is_some() {
        let r = util::run_cmd("logread", &[], Duration::from_secs(10), 8 << 20);
        let t: String = r.text().lines().map(strip_host_syslog).collect::<Vec<_>>().join("\n");
        filtered(o, "logread (busybox syslog)", &t, &pids, false);
    }
}

/// The kernel quotes whole command lines in some messages (`ptrace attach
/// of "python3 -I /x/y secret"[123] was attempted by "cat ..."[456]`):
/// keep only the program's name, since arguments can hold anything
fn mask_quoted_cmdlines(l: &str) -> String {
    let mut out = String::with_capacity(l.len());
    let mut rest = l;
    while let Some(a) = rest.find('"') {
        let Some(b) = rest[a + 1..].find('"') else { break };
        let inner = &rest[a + 1..a + 1 + b];
        let after = &rest[a + 2 + b..];
        out.push_str(&rest[..a]);
        if after.starts_with('[') && inner.contains(' ') {
            let prog = inner.split(' ').next().unwrap_or("");
            let prog = prog.rsplit('/').next().unwrap_or(prog);
            out.push_str(&format!("\"{prog} <args>\""));
        } else {
            out.push('"');
            out.push_str(inner);
            out.push('"');
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Classic syslog `Mon dd hh:mm:ss host ident: msg`: drop the host
fn strip_host_syslog(l: &str) -> String {
    let t: Vec<&str> = l.splitn(5, ' ').collect();
    // "Oct", "30", "12:00:00", host, rest  (or "Oct", "", " 3", ... for one-digit days)
    if t.len() == 5 && t[0].len() == 3 && t[0].chars().all(|c| c.is_ascii_alphabetic()) && t[2].contains(':') {
        return format!("{} {} {} {}", t[0], t[1], t[2], t[4]);
    }
    if t.len() == 5 && t[0].len() == 3 && t[1].is_empty() {
        let rest: Vec<&str> = l.splitn(6, ' ').collect();
        if rest.len() == 6 && rest[3].contains(':') {
            return format!("{} {} {} {}", rest[0], rest[2], rest[3], rest[5]);
        }
    }
    l.to_string()
}

// ---------------------------------------------------------------- B2.12

/// B2.12
pub fn crashes(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("crashes/crashes.txt");
    outln!(o, "Core dumps can hold the wallet's keys in memory. diag does not copy any core;");
    outln!(o, "it reports where they are so you can delete them (as root: rm the file, or");
    outln!(o, "`coredumpctl list irondivid` then remove the matching files under /var/lib/systemd/coredump).");
    if LINUX {
        head(o, "core settings");
        outln!(o, "kernel.core_pattern = {}", super::one("/proc/sys/kernel/core_pattern"));
        outln!(o, "kernel.core_uses_pid = {}", super::one("/proc/sys/kernel/core_uses_pid"));
        outln!(o, "fs.suid_dumpable = {}", super::one("/proc/sys/fs/suid_dumpable"));
        if util::which("coredumpctl").is_some() {
            head(o, "systemd-coredump");
            cmd_block_t(o, "coredumpctl", &["list", "--no-pager", "-q", "irondivid"], 15, 1 << 20);
            let info = util::run_cmd("coredumpctl", &["info", "--no-pager", "-q", "irondivid"], Duration::from_secs(20), 8 << 20);
            if info.ok() {
                outln!(o, "-- coredumpctl info (Signal, Timestamp, Disk Size and the first thread's frames only)");
                let mut frames = 0;
                let mut in_thread = false;
                for l in info.text().lines() {
                    let t = l.trim_start();
                    if t.starts_with("PID:") {
                        outln!(o);
                        frames = 0;
                        in_thread = false;
                    }
                    if ["Signal:", "Timestamp:", "Disk Size:", "Storage:"].iter().any(|k| t.starts_with(k)) {
                        if t.starts_with("Storage:") {
                            outln!(o, "Storage: {}", if t.contains("present") { "present" } else if t.contains("missing") { "missing" } else { "?" });
                        } else {
                            outln!(o, "{t}");
                        }
                    } else if t.starts_with("Stack trace of thread") {
                        in_thread = frames == 0;
                        if in_thread {
                            outln!(o, "Stack trace of the first thread:");
                        }
                    } else if in_thread && t.starts_with('#') && t.contains("0x") && frames < 40 {
                        outln!(o, "  {t}");
                        frames += 1;
                    } else if t.is_empty() {
                        in_thread = false;
                    }
                }
            }
        } else {
            outln!(o, "coredumpctl: not installed");
        }

        head(o, "apport (/var/crash)");
        match std::fs::read_dir("/var/crash") {
            Ok(rd) => {
                let mut found = false;
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().to_string();
                    if !n.contains("irondivi") {
                        continue;
                    }
                    found = true;
                    outln!(o, "-- {} ({})", r.path(&n), util::human(e.metadata().map(|m| m.len()).unwrap_or(0)));
                    apport_fields(o, &e.path());
                }
                if !found {
                    outln!(o, "no irondivi crash report");
                }
            }
            Err(e) => outln!(o, "/var/crash: {}", util::io_err(&e)),
        }
        head(o, "abrt");
        for dir in ["/var/spool/abrt", "/var/tmp/abrt"] {
            if let Ok(rd) = std::fs::read_dir(dir) {
                let mut n = 0;
                for e in rd.flatten() {
                    let exe = std::fs::read_to_string(e.path().join("executable")).unwrap_or_default();
                    if exe.contains("irondivi") {
                        n += 1;
                    }
                }
                outln!(o, "{dir}: {n} irondivi problem dirs (listed only)");
            }
        }
    } else {
        head(o, "macOS crash reports (~/Library/Logs/DiagnosticReports, /Library/Logs/DiagnosticReports)");
        let mut dirs = vec![PathBuf::from("/Library/Logs/DiagnosticReports")];
        if let Some(h) = util::user_home(util::uid()) {
            dirs.push(h.join("Library/Logs/DiagnosticReports"));
        }
        let mut any = false;
        for d in dirs {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("irondivid") && (n.ends_with(".ips") || n.ends_with(".crash")) {
                    any = true;
                    outln!(o, "-- {n}");
                    ips_frames(o, &e.path());
                }
            }
        }
        if !any {
            outln!(o, "no irondivid crash report");
        }
    }

    head(o, "core files in the data dirs and the node's working dirs");
    let mut dirs: Vec<PathBuf> = ctx.datadirs.iter().flat_map(|d| [d.path.clone(), d.chain.clone()]).collect();
    dirs.extend(ctx.nodes.iter().filter_map(|n| n.cwd.clone()));
    dirs.sort();
    dirs.dedup();
    let mut any = false;
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n == "core" || n.starts_with("core.") {
                any = true;
                let md = e.metadata().ok();
                outln!(
                    o,
                    "{}  {}  {}",
                    r.path_of(&e.path()),
                    util::human(md.as_ref().map(|m| m.len()).unwrap_or(0)),
                    md.map(|m| util::rfc3339(util::mtime_secs(&m))).unwrap_or_default()
                );
            }
        }
    }
    if !any {
        outln!(o, "none");
    }
}

/// apport files are `Key: value` with indented continuation lines; read
/// streaming and keep only the allowed keys (CoreDump is base64 and huge)
fn apport_fields(o: &mut Out, p: &Path) {
    use std::io::BufRead;
    let Ok(f) = std::fs::File::open(p) else {
        outln!(o, "  (not readable)");
        return;
    };
    let mut keep = false;
    let mut n = 0;
    for l in std::io::BufReader::new(f).split(b'\n').map_while(Result::ok) {
        if l.first().map(|b| *b == b' ').unwrap_or(false) {
            if keep && n < 60 {
                outln!(o, "  {}", util::escape_bytes(&l));
                n += 1;
            }
            continue;
        }
        let s = util::escape_bytes(&l);
        keep = ["StacktraceTop:", "Signal:", "Date:", "SignalName:"].iter().any(|k| s.starts_with(k));
        if keep {
            outln!(o, "  {s}");
        }
    }
}

/// The faulting thread's frames of a macOS `.ips` report (two JSON documents:
/// a header line, then the body)
fn ips_frames(o: &mut Out, p: &Path) {
    let Ok(b) = util::read_bytes_capped(p, 8 << 20) else {
        outln!(o, "  (not readable)");
        return;
    };
    let text = String::from_utf8_lossy(&b);
    let body = text.split_once('\n').map(|x| x.1).unwrap_or(&text);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        outln!(o, "  (not an .ips JSON report)");
        return;
    };
    if let Some(t) = v.get("captureTime") {
        outln!(o, "  time: {t}");
    }
    if let Some(e) = v.get("exception") {
        outln!(o, "  exception: {} {}", e.get("type").cloned().unwrap_or_default(), e.get("signal").cloned().unwrap_or_default());
    }
    let images = v.get("usedImages").and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let ft = v.get("faultingThread").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    if let Some(th) = v.get("threads").and_then(|x| x.as_array()).and_then(|a| a.get(ft)) {
        for f in th.get("frames").and_then(|x| x.as_array()).into_iter().flatten().take(40) {
            let img = f.get("imageIndex").and_then(|x| x.as_u64()).and_then(|i| images.get(i as usize));
            let name = img.and_then(|i| i.get("name")).and_then(|x| x.as_str()).unwrap_or("?");
            outln!(
                o,
                "    {} +{} {}",
                name,
                f.get("imageOffset").cloned().unwrap_or_default(),
                f.get("symbol").and_then(|x| x.as_str()).unwrap_or("")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn kernel_cmdlines_masked() {
        let l = r#"ptrace attach of "python3 -I /mnt/x/secret arg"[2421045] was attempted by "cat /proc/1/syscall"[2680157]"#;
        assert_eq!(
            super::mask_quoted_cmdlines(l),
            r#"ptrace attach of "python3 <args>"[2421045] was attempted by "cat <args>"[2680157]"#
        );
        let a = r#"apparmor="DENIED" name="x""#;
        assert_eq!(super::mask_quoted_cmdlines(a), a);
    }

    use super::*;

    #[test]
    fn record_kinds() {
        let r = parse_record("2026-10-30T01:02:03.000004Z 123.456 start pid=7 version=0.3.0 how=systemd").unwrap();
        assert_eq!(r.kind, "start");
        assert_eq!(r.get(&["pid"]), Some("7"));
        let r = parse_record("2026-10-30T01:02:03.000004Z 123.456 kind=exit code=0 reason=\"stopped by rpc\"").unwrap();
        assert_eq!(r.kind, "exit");
        assert_eq!(r.get(&["reason"]), Some("stopped by rpc"));
        assert!(parse_record("garbage").is_none());
    }

    #[test]
    fn run_grouping() {
        let text = "2026-10-30T01:00:00.000000Z 1.0 start pid=7 version=0.3.0 kernel=5.15\n\
                    2026-10-30T01:00:01.000000Z 2.0 phase phase=db-open\n\
                    2026-10-30T02:00:00.000000Z 1.0 start pid=9 version=0.3.1 kernel=5.15\n\
                    2026-10-30T02:00:00.100000Z 1.1 unclean-previous verdict=killed\n\
                    2026-10-30T02:00:01.000000Z 2.0 phase phase=running\n\
                    2026-10-30T03:00:00.000000Z 3.0 exit code=0 uptime=3600\n";
        let recs: Vec<Record> = text.lines().filter_map(parse_record).collect();
        let runs = runs_from_records(&recs);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].last_phase, "db-open");
        assert!(runs[0].end.starts_with("unclean"));
        assert_eq!(runs[1].end, "exit 0");
        let t = table(&runs, None);
        assert!(t[2].contains("version changed"));
    }

    #[test]
    fn debug_log_banners() {
        let t = "2026-10-27T03:37:51Z  INFO irondivid:   IronDivi v0.2.7\n\
                 2026-10-27T03:37:51Z  INFO irondivid: Chain: Divi (mainnet)\n\
                 2026-10-27T04:00:00Z  INFO irondivid: IronDivi shutdown complete\n\
                 2026-10-28T03:37:51Z  INFO irondivid:   IronDivi v0.2.8\n";
        let r = runs_from_debug_log(t);
        assert_eq!(r.len(), 2);
        assert!(r[0].end.starts_with("clean"));
        assert_eq!(r[1].end, "no clean shutdown line");
        assert_eq!(r[1].version, "v0.2.8".trim_start_matches('v'));
    }

    #[test]
    fn host_stripping() {
        assert_eq!(strip_host("2026-10-30T01:02:03+0000 myhost kernel: oops"), "2026-10-30T01:02:03+0000 kernel: oops");
        assert_eq!(strip_host_syslog("Oct 30 01:02:03 myhost kernel: oops"), "Oct 30 01:02:03 kernel: oops");
        assert_eq!(strip_host_syslog("Oct  3 01:02:03 myhost kernel: oops"), "Oct 3 01:02:03 kernel: oops");
    }

    #[test]
    fn oom_table_reduced() {
        let lines = vec![
            "x invoked oom-killer: gfp_mask=0x0".to_string(),
            "[  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name".to_string(),
            "[    100]  1000   100   123456    7890    1234567        0             0 bash".to_string(),
            "[    200]  1000   200   123456    7890    1234567        0             0 irondivid".to_string(),
            "Out of memory: Killed process 200 (irondivid)".to_string(),
        ];
        let r = reduce_oom(lines, &["200".into()]);
        assert!(r.iter().any(|l| l.contains("irondivid") && l.starts_with('[')));
        assert!(!r.iter().any(|l| l.contains("bash")));
        assert!(r.iter().any(|l| l.contains("1 other")));
    }
}
