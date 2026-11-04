// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B6.2 `--host` for the LXC family: LXD, Incus, plain LXC and Proxmox
//! `pct`. The runtime is found by asking each in turn (`detect`).
//!
//! What it collects: the runtime's view of the container (LXD and Incus
//! `query /1.0/instances/<name>` and its `/state`, `info --show-log`; plain
//! LXC's config file, `lxc-info` and its log; Proxmox `pct config`, `pct
//! status` and the task index), the container cgroup's `memory.events`,
//! `memory.max`, `memory.peak` (where the kernel has it), `pids.max` and
//! `pids.events` while the cgroup exists, the host kernel log lines for
//! that cgroup (OOM kills, seccomp records of the node, AppArmor denials
//! of the container's profile), and the node's own `runs.log`, read through the runtime.
//!
//! None of these runtimes but Proxmox records how a container stopped, and
//! the cgroup and its counters go when it stops. A stopped container's end
//! is therefore read from what lasts: the kernel log (an OOM kill always
//! leaves an `oom-kill:` line naming the cgroup) and the node's runs.log (a
//! clean stop leaves SIGTERM from the container's init and an exit record; a
//! SIGKILL leaves no exit record). The verdict says OOM only on an
//! `oom_kill` count above zero or a kernel OOM line for the cgroup.

use super::{finish, kernel_log, parse_audit, parse_rfc3339, syscall_name, Audit, Pack, CAP};
use crate::collectors::logs::{parse_record, runs_from_records, Record};
use crate::redact::Known;
use crate::util;
use crate::Options;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Lxd,
    Incus,
    Lxc,
    Proxmox,
}

impl Runtime {
    pub fn name(self) -> &'static str {
        match self {
            Runtime::Lxd => "LXD",
            Runtime::Incus => "Incus",
            Runtime::Lxc => "LXC",
            Runtime::Proxmox => "Proxmox",
        }
    }
    fn cli(self) -> &'static str {
        match self {
            Runtime::Lxd => "lxc",
            Runtime::Incus => "incus",
            Runtime::Lxc => "lxc-info",
            Runtime::Proxmox => "pct",
        }
    }
    /// The runtime's clean stop and its hard stop
    fn stops(self) -> (&'static str, &'static str) {
        match self {
            Runtime::Lxd => ("lxc stop", "lxc stop --force"),
            Runtime::Incus => ("incus stop", "incus stop --force"),
            Runtime::Lxc => ("lxc-stop", "lxc-stop --kill"),
            Runtime::Proxmox => ("pct shutdown", "pct stop"),
        }
    }
}

/// A container name diag passes to a runtime: letters, digits, `-_.`
pub fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && !n.starts_with('.')
        && !n.starts_with('-')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

const T: Duration = Duration::from_secs(30);

fn first_err(c: &util::CmdOut) -> String {
    let e = String::from_utf8_lossy(&c.stderr);
    format!(
        "{} {}",
        c.status_line(),
        e.lines().next().unwrap_or("").trim()
    )
}

/// The Proxmox id for `name`: the id itself, or the container whose
/// `hostname:` is `name`
fn pct_id(name: &str) -> Option<String> {
    if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
        return Some(name.to_string());
    }
    let dir = std::fs::read_dir("/etc/pve/lxc").ok()?;
    for e in dir.flatten() {
        let p = e.path();
        let Some(id) = p.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
            continue;
        };
        if p.extension().and_then(|x| x.to_str()) != Some("conf") {
            continue;
        }
        let text = util::read_small(&p, 1 << 20).unwrap_or_default();
        if parse_pct_conf(&text).hostname.as_deref() == Some(name) {
            return Some(id);
        }
    }
    None
}

/// The plain-LXC config file of `name`, if one exists
fn lxc_config(name: &str) -> Option<PathBuf> {
    let mut dirs = Vec::new();
    let lp = util::run_cmd("lxc-config", &["lxc.lxcpath"], T, 4096);
    if lp.ok() {
        dirs.push(PathBuf::from(lp.text().trim()));
    }
    dirs.push(PathBuf::from("/var/lib/lxc"));
    if let Some(h) = std::env::var_os("HOME") {
        dirs.push(Path::new(&h).join(".local/share/lxc"));
    }
    dirs.into_iter()
        .map(|d| d.join(name).join("config"))
        .find(|p| p.is_file())
}

/// Which runtime has a container called `name`: Proxmox, Incus, LXD, then
/// plain LXC. `tried` gets one line per runtime asked.
pub fn detect(name: &str, tried: &mut Vec<String>) -> Option<Runtime> {
    if util::which("pct").is_some() || Path::new("/etc/pve").is_dir() {
        if let Some(id) = pct_id(name) {
            if Path::new(&format!("/etc/pve/lxc/{id}.conf")).is_file()
                || util::run_cmd("pct", &["status", &id], T, 4096).ok()
            {
                return Some(Runtime::Proxmox);
            }
        }
        tried.push(format!("pct: no container {name}"));
    } else {
        tried.push("pct: not on PATH".into());
    }
    for (rt, cli) in [(Runtime::Incus, "incus"), (Runtime::Lxd, "lxc")] {
        if util::which(cli).is_none() {
            tried.push(format!("{cli}: not on PATH"));
            continue;
        }
        let q = util::run_cmd(cli, &["query", &format!("/1.0/instances/{name}")], T, CAP);
        if q.ok() {
            return Some(rt);
        }
        tried.push(format!("{cli} query: {}", first_err(&q)));
    }
    if lxc_config(name).is_some() {
        return Some(Runtime::Lxc);
    }
    if util::which("lxc-info").is_some() {
        let i = util::run_cmd("lxc-info", &["-n", name], T, 64 << 10);
        if i.ok() {
            return Some(Runtime::Lxc);
        }
        tried.push(format!("lxc-info: {}", first_err(&i)));
    } else {
        tried.push("lxc-info: not on PATH".into());
    }
    None
}

// ---- parsers (pure, tested) ----

/// A kernel `oom-kill:` line
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OomKill {
    pub time: String,
    pub constraint: String,
    pub oom_memcg: String,
    pub task_memcg: String,
    pub task: String,
    pub pid: u32,
}

/// `... oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=...,
/// oom_memcg=/lxc.payload.x,task_memcg=/lxc.payload.x,task=irondivid,pid=915504,uid=1000000`
pub fn parse_oom_kill(line: &str) -> Option<OomKill> {
    let i = line.find("oom-kill:")?;
    let mut k = OomKill {
        time: line.split_whitespace().next().unwrap_or("").to_string(),
        ..Default::default()
    };
    for kv in line[i + 9..].trim().split(',') {
        let Some((a, b)) = kv.split_once('=') else {
            continue;
        };
        match a {
            "constraint" => k.constraint = b.into(),
            "oom_memcg" => k.oom_memcg = b.into(),
            "task_memcg" => k.task_memcg = b.into(),
            "task" => k.task = b.into(),
            "pid" => k.pid = b.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some(k)
}

/// Is cgroup path `memcg` the container cgroup `cg` (`/lxc.payload.x`) or below it?
pub fn in_cgroup(cg: &str, memcg: &str) -> bool {
    memcg == cg || memcg.strip_prefix(cg).is_some_and(|r| r.starts_with('/'))
}

/// The kernel log lines about the container: its OOM kills (and the
/// `Killed process` line of each), the node's seccomp records and the
/// AppArmor denials of the container's profile
pub fn kernel_lines(text: &str, cg: &str, apparmor: Option<&str>) -> (Vec<String>, Vec<OomKill>) {
    let mut ooms = Vec::new();
    for l in text.lines() {
        if let Some(k) = parse_oom_kill(l) {
            if in_cgroup(cg, &k.task_memcg)
                || (!k.oom_memcg.is_empty() && in_cgroup(cg, &k.oom_memcg))
            {
                ooms.push(k);
            }
        }
    }
    let pids: Vec<String> = ooms
        .iter()
        .map(|k| format!("Killed process {} ", k.pid))
        .collect();
    let keep = |l: &str| {
        parse_oom_kill(l).is_some_and(|k| ooms.contains(&k))
            || pids.iter().any(|p| l.contains(p.as_str()))
            || (l.contains("type=1326") && l.contains("comm=\"irondivid\""))
            || apparmor.is_some_and(|a| {
                l.contains("apparmor=\"DENIED\"") && l.contains(&format!("profile=\"{a}"))
            })
    };
    (
        text.lines()
            .filter(|l| keep(l))
            .map(str::to_string)
            .collect(),
        ooms,
    )
}

/// `key value` lines of memory.events / pids.events
pub fn events_count(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        (w.next()? == key).then(|| w.next()?.parse().ok()).flatten()
    })
}

/// What `pct config <id>` (or /etc/pve/lxc/<id>.conf) says
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PctConf {
    pub memory_mb: Option<u64>,
    pub swap_mb: Option<u64>,
    pub hostname: Option<String>,
    pub macs: Vec<String>,
    pub ips: Vec<String>,
    /// The config without its description (`#` lines) and snapshots
    pub kept: String,
}

pub fn parse_pct_conf(text: &str) -> PctConf {
    let mut c = PctConf::default();
    for l in text.lines() {
        if l.starts_with('[') {
            break; // snapshots and pending changes
        }
        if l.starts_with('#') || l.trim().is_empty() {
            continue;
        }
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim();
        let k = k.trim();
        if k == "description" {
            continue;
        }
        c.kept.push_str(l);
        c.kept.push('\n');
        match k {
            "memory" => c.memory_mb = v.parse().ok(),
            "swap" => c.swap_mb = v.parse().ok(),
            "hostname" => c.hostname = Some(v.to_string()),
            _ if k.starts_with("net") => {
                for kv in v.split(',') {
                    let Some((a, b)) = kv.split_once('=') else {
                        continue;
                    };
                    match a {
                        "hwaddr" => c.macs.push(b.to_string()),
                        "ip" | "ip6" | "gw" | "gw6" if !matches!(b, "dhcp" | "auto" | "manual") => {
                            c.ips.push(b.split('/').next().unwrap_or(b).to_string())
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    c
}

/// One Proxmox task: `UPID:node:pid:pstart:start:type:id:user: end status`
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Task {
    pub node: String,
    pub start: i64,
    pub end: Option<i64>,
    pub kind: String,
    pub id: String,
    pub user: String,
    pub status: String,
}

pub fn parse_upid_line(line: &str) -> Option<Task> {
    let mut w = line.split_whitespace();
    let upid = w.next()?;
    let p: Vec<&str> = upid.split(':').collect();
    if p.len() < 8 || p[0] != "UPID" {
        return None;
    }
    let end = w.next().and_then(|e| i64::from_str_radix(e, 16).ok());
    Some(Task {
        node: p[1].into(),
        start: i64::from_str_radix(p[4], 16).ok()?,
        end,
        kind: p[5].into(),
        id: p[6].into(),
        user: p[7].into(),
        status: w.collect::<Vec<_>>().join(" "),
    })
}

/// `key = value` lines of a plain LXC config
pub fn parse_lxc_conf(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// The node's last run in its runs.log
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LastRun {
    pub start: String,
    /// "exit 0 (stopped)", "signal …", or "" when there is no exit record
    pub end: String,
    /// The time of the last record of the run
    pub last_time: String,
    /// SIGTERM (or PWR/INT) from pid 1, the container's init
    pub term_from_init: bool,
    pub notes: Vec<String>,
    pub runs: usize,
}

pub fn last_run(text: &str) -> Option<LastRun> {
    let recs: Vec<Record> = text.lines().filter_map(parse_record).collect();
    let runs = runs_from_records(&recs);
    let last = runs.last()?;
    let idx = recs.iter().rposition(|r| r.kind == "start")?;
    let tail = &recs[idx..];
    let term_from_init = tail.iter().any(|r| {
        r.kind == "signal"
            && r.get(&["pid"]) == Some("1")
            && matches!(
                r.get(&["signo", "signal"]),
                Some("TERM" | "SIGTERM" | "15" | "PWR" | "SIGPWR" | "30" | "INT" | "SIGINT" | "2")
            )
    });
    Some(LastRun {
        start: last.start.clone(),
        end: last.end.clone(),
        last_time: tail.last().map(|r| r.time.clone()).unwrap_or_default(),
        term_from_init,
        notes: last.notes.clone(),
        runs: runs.len(),
    })
}

/// Everything the verdict reads
#[derive(Debug, Clone)]
pub struct Ev<'a> {
    pub rt: Runtime,
    pub running: bool,
    /// memory.events oom_kill while the cgroup exists
    pub oom_kill: Option<u64>,
    pub mem_limit: &'a str,
    pub ooms: &'a [OomKill],
    pub seccomp: Option<&'a Audit>,
    pub apparmor_denials: usize,
    /// (pids.max, pids.events max)
    pub pids_hit: Option<(String, u64)>,
    pub klog_ok: bool,
    /// rfc3339 the kernel log was read from
    pub since: &'a str,
    /// the node's host pid when it is alive in the container
    pub node_pid: Option<u32>,
    pub last: Option<&'a LastRun>,
    /// host boot time, epoch seconds
    pub btime: i64,
    /// Proxmox: the container's last stop task
    pub stop_task: Option<&'a Task>,
}

fn not_oom(e: &Ev) -> String {
    if !e.klog_ok {
        return "OOM not ruled out: the host kernel log was not readable".into();
    }
    let count = match e.oom_kill {
        Some(n) => format!("memory.events oom_kill {n}"),
        None => "the oom_kill count is gone with the cgroup".into(),
    };
    format!("not a memory-limit kill (no OOM line for the container's cgroup in the kernel log since {}; {count})", e.since)
}

/// How the container (and the node in it) ended, in one line (B6.2)
pub fn verdict(e: &Ev) -> String {
    let state = if e.running {
        "the container is still running"
    } else {
        "the container is stopped"
    };
    let mut v = verdict_core(e, state);
    if let Some((max, n)) = &e.pids_hit {
        if *n > 0 {
            v.push_str(&format!(
                "; the container hit its pids limit ({max}) {n} times"
            ));
        }
    }
    if e.apparmor_denials > 0 {
        v.push_str(&format!(
            "; {} AppArmor denials for the container in the kernel log",
            e.apparmor_denials
        ));
    }
    v
}

fn verdict_core(e: &Ev, state: &str) -> String {
    if let Some(a) = e.seccomp.filter(|a| a.sig == 31) {
        let name = syscall_name(&a.arch, a.syscall).unwrap_or("not in diag's table");
        return format!(
            "the node was killed by seccomp (SIGSYS): system call {} ({name}) is forbidden (kernel audit record); {state}",
            a.syscall
        );
    }
    if let Some(k) = e.ooms.last() {
        let who = if k.task.starts_with("irondivid") {
            format!("the node ({}, host pid {})", k.task, k.pid)
        } else {
            format!("{} (host pid {}) in the container", k.task, k.pid)
        };
        let count = e
            .oom_kill
            .map(|n| format!(", memory.events oom_kill {n}"))
            .unwrap_or_default();
        let n = if e.ooms.len() > 1 {
            format!("; {} OOM kills since {}", e.ooms.len(), e.since)
        } else {
            String::new()
        };
        let alive = match (e.running, e.node_pid) {
            (true, Some(p)) if p != k.pid => format!("; a node runs again (host pid {p})"),
            _ => String::new(),
        };
        if k.constraint == "CONSTRAINT_MEMCG" {
            return format!(
                "{who} was killed at the container's memory limit ({}; kernel OOM line at {}{count}{n}); {state}{alive}",
                e.mem_limit, k.time
            );
        }
        return format!(
            "{who} was killed by the host kernel's OOM killer ({}, kernel line at {}: the host ran out of memory, not the container's limit{count}); {state}{alive}",
            k.constraint, k.time
        );
    }
    if let Some(n) = e.oom_kill.filter(|&n| n > 0) {
        return format!(
            "memory.events counts oom_kill {n}: a process in the container was killed at its memory limit ({}), but the kernel log since {} has no line naming it; {state}",
            e.mem_limit, e.since
        );
    }
    if e.running {
        if let Some(p) = e.node_pid {
            return format!("the container is running and the node (irondivid, host pid {p}) is alive: it has not ended");
        }
        return match e.last {
            Some(l) if !l.end.is_empty() => format!("the container is running but no node runs in it; the node's last run ended: {} (runs.log)", l.end),
            Some(l) => format!(
                "the container is running but no node runs in it; the node's last run has no exit record after {}: it got SIGKILL or died without a record; {}",
                l.last_time,
                not_oom(e)
            ),
            None => format!("the container is running but no node runs in it, and the node's runs.log was not found; {}", not_oom(e)),
        };
    }
    let (soft, hard) = e.rt.stops();
    let Some(l) = e.last else {
        return format!("the container is stopped; the node's runs.log was not found, so how the node ended is not known; {}", not_oom(e));
    };
    if !l.end.is_empty() {
        if l.end.starts_with("exit 0") && l.term_from_init {
            return format!(
                "stopped cleanly: the container's init sent SIGTERM (`{soft}`, or a shutdown inside) and the node exited with code 0 (runs.log, run started {})",
                l.start
            );
        }
        let why = if l.term_from_init {
            "after SIGTERM from the container's init"
        } else {
            "with no stop from the container's init"
        };
        return format!(
            "the container is stopped; the node's last run ended {why}: {} (runs.log)",
            l.end
        );
    }
    let last_t = parse_rfc3339(&l.last_time).unwrap_or(0);
    if e.btime > 0 && last_t > 0 && e.btime > last_t {
        return format!(
            "the host rebooted while the node ran (host boot at {}, after the node's last record at {}): the node never shut down",
            util::rfc3339(e.btime),
            l.last_time
        );
    }
    if let Some(t) = e.stop_task.filter(|t| t.start >= last_t) {
        let what = match t.kind.as_str() {
            "vzstop" => "`pct stop` (a hard stop: the node got SIGKILL)".to_string(),
            "vzshutdown" => {
                "`pct shutdown` that the node did not finish (no exit record)".to_string()
            }
            k => format!("a Proxmox {k} task"),
        };
        return format!(
            "stopped by {what}, task at {} ({}); {}",
            util::rfc3339(t.start),
            if t.status.is_empty() {
                "running"
            } else {
                t.status.as_str()
            },
            not_oom(e)
        );
    }
    let init = if l.term_from_init {
        "after SIGTERM from the container's init, with no exit record"
    } else {
        "with no exit record"
    };
    format!(
        "stopped without the node shutting down: its last run ends {init} after {}, so the node got SIGKILL (`{hard}`, a `{soft}` that timed out, or the container's init was killed); {}",
        l.last_time,
        not_oom(e)
    )
}

// ---- collection ----

#[derive(Default)]
struct Facts {
    status: String,
    running: bool,
    mem_limit: String,
    started: Option<i64>,
    cg_names: Vec<String>,
    apparmor: Option<String>,
    init_pid: Option<u32>,
    stop_task: Option<Task>,
    /// (where it was read, text)
    runs_log: Option<(String, String)>,
}

/// The paths a node's runs.log may be at inside the container
fn runs_paths(o: &Options, homes: &[String]) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    if let Some(d) = &o.datadir {
        dirs.push(d.display().to_string());
    }
    for d in ["/root/.irondivi", "/var/lib/irondivi", "/data"] {
        dirs.push(d.into());
    }
    for h in homes {
        if valid_name(h) {
            dirs.push(format!("/home/{h}/.irondivi"));
        }
    }
    let mut out = Vec::new();
    for d in dirs {
        for sub in ["diag", "testnet/diag", "regtest/diag", "privatedivi/diag"] {
            out.push(format!("{}/{sub}/runs.log", d.trim_end_matches('/')));
        }
    }
    out
}

fn collect_lxd(
    rt: Runtime,
    name: &str,
    o: &Options,
    known: &mut Known,
    files: &mut Vec<(String, String)>,
) -> Facts {
    let cli = rt.cli();
    let mut f = Facts::default();
    let q = util::run_cmd(cli, &["query", &format!("/1.0/instances/{name}")], T, CAP);
    let mut inst: serde_json::Value = serde_json::from_slice(&q.stdout).unwrap_or_default();
    let st = util::run_cmd(
        cli,
        &["query", &format!("/1.0/instances/{name}/state")],
        T,
        CAP,
    );
    let state: serde_json::Value = serde_json::from_slice(&st.stdout).unwrap_or_default();
    let s = |v: &serde_json::Value, p: &str| {
        v.pointer(p)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };
    f.status = s(&inst, "/status");
    f.running = f.status.eq_ignore_ascii_case("running");
    let cfg = inst.get("expanded_config").cloned().unwrap_or_default();
    f.mem_limit = match cfg.get("limits.memory").and_then(|x| x.as_str()) {
        Some(m) => format!("limits.memory {m}"),
        None => "no limits.memory: the host's memory".into(),
    };
    if let Some(m) = cfg.as_object() {
        for (k, v) in m {
            let v = v.as_str().unwrap_or("");
            if v.is_empty() {
                continue;
            }
            if k.starts_with("volatile.") && k.ends_with(".hwaddr") {
                known.ips.push(v.into());
            }
            if k == "volatile.uuid"
                || k == "volatile.cloud-init.instance-id"
                || k.ends_with(".uuid")
            {
                known.machine_ids.push(v.into());
            }
        }
    }
    for p in inst
        .get("profiles")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(p) = p.as_str().filter(|p| *p != "default") {
            known.hostnames.push(p.into());
        }
    }
    if let Some(devs) = inst.get("expanded_devices").and_then(|x| x.as_object()) {
        for d in devs.values() {
            if let Some(p) = d
                .get("pool")
                .and_then(|x| x.as_str())
                .filter(|p| *p != "default")
            {
                known.hostnames.push(p.into());
            }
        }
    }
    for n in ["location", "project"] {
        if let Some(v) = inst
            .get(n)
            .and_then(|x| x.as_str())
            .filter(|v| !v.is_empty() && *v != "none" && *v != "default")
        {
            known.hostnames.push(v.into());
        }
    }
    if let Some(nets) = state.get("network").and_then(|x| x.as_object()) {
        for n in nets.values() {
            if let Some(h) = n
                .get("hwaddr")
                .and_then(|x| x.as_str())
                .filter(|h| !h.is_empty())
            {
                known.ips.push(h.into());
            }
            for a in n
                .get("addresses")
                .and_then(|x| x.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(ip) = a.get("address").and_then(|x| x.as_str()) {
                    if ip != "127.0.0.1" && ip != "::1" {
                        known.ips.push(ip.into());
                    }
                }
            }
        }
    }
    f.init_pid = state
        .get("pid")
        .and_then(|x| x.as_u64())
        .filter(|&p| p > 0)
        .map(|p| p as u32);
    f.started = parse_rfc3339(&s(&inst, "/last_used_at")).filter(|&t| t > 0);
    f.cg_names = vec![format!("lxc.payload.{name}"), format!("lxc.payload/{name}")];
    f.apparmor = Some(format!(
        "{}-{name}_",
        if rt == Runtime::Incus { "incus" } else { "lxd" }
    ));

    // user.*, cloud-init.* and environment.* values are the owner's own text
    for key in ["config", "expanded_config"] {
        if let Some(m) = inst.get_mut(key).and_then(|x| x.as_object_mut()) {
            for (k, v) in m.iter_mut() {
                if k.starts_with("user.")
                    || k.starts_with("cloud-init.")
                    || k.starts_with("environment.")
                {
                    *v = serde_json::Value::String("(left out by diag)".into());
                }
            }
        }
    }
    if let Some(d) = inst.get_mut("description") {
        *d = serde_json::Value::String("(left out by diag)".into());
    }
    files.push((
        format!("host/{cli}-instance.json"),
        format!(
            "# {cli} query (the instance): {}\n{}\n",
            q.status_line(),
            serde_json::to_string_pretty(&inst).unwrap_or_default()
        ),
    ));
    files.push((
        format!("host/{cli}-state.json"),
        format!(
            "# {cli} query (the instance state): {}\n{}\n",
            st.status_line(),
            serde_json::to_string_pretty(&state).unwrap_or_default()
        ),
    ));
    let info = util::run_cmd(cli, &["info", name, "--show-log"], T, CAP);
    files.push((
        format!("host/{cli}-info.txt"),
        format!(
            "# {cli} info <name> --show-log: {}\n{}",
            info.status_line(),
            info.text()
        ),
    ));

    // the node's runs.log, read through the runtime (it works on a stopped container)
    let homes = util::run_cmd(
        cli,
        &["query", &format!("/1.0/instances/{name}/files?path=/home")],
        T,
        64 << 10,
    );
    let homes: Vec<String> =
        serde_json::from_slice::<Vec<String>>(&homes.stdout).unwrap_or_default();
    for p in runs_paths(o, &homes) {
        let r = util::run_cmd(cli, &["file", "pull", &format!("{name}{p}"), "-"], T, CAP);
        if r.ok() && !r.stdout.is_empty() {
            f.runs_log = Some((
                format!("{cli} file pull <name>{p}"),
                String::from_utf8_lossy(&r.stdout).into_owned(),
            ));
            break;
        }
    }
    f
}

fn collect_lxc(
    name: &str,
    o: &Options,
    known: &mut Known,
    files: &mut Vec<(String, String)>,
) -> Facts {
    let mut f = Facts::default();
    let cfg_path = lxc_config(name);
    let text = cfg_path
        .as_deref()
        .and_then(|p| util::read_small(p, 1 << 20))
        .unwrap_or_default();
    let kv = parse_lxc_conf(&text);
    let get = |k: &str| {
        kv.iter()
            .rev()
            .find(|(a, _)| a == k)
            .map(|(_, b)| b.clone())
    };
    for (k, v) in &kv {
        if k == "lxc.uts.name" {
            known.hostnames.push(v.clone());
        }
        if k.starts_with("lxc.net.")
            && (k.ends_with(".hwaddr") || k.contains(".ipv4.") || k.contains(".ipv6."))
        {
            known.ips.push(v.split('/').next().unwrap_or(v).to_string());
        }
    }
    f.mem_limit =
        match get("lxc.cgroup2.memory.max").or_else(|| get("lxc.cgroup.memory.limit_in_bytes")) {
            Some(m) => format!("memory.max {m}"),
            None => "no memory limit in the config: the host's memory".into(),
        };
    files.push((
        "host/lxc-config.txt".into(),
        format!(
            "# {}\n{}",
            cfg_path
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "no config file found".into()),
            text
        ),
    ));
    let info = util::run_cmd("lxc-info", &["-n", name], T, 64 << 10);
    let it = info.text();
    for l in it.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        match k.trim() {
            "State" => f.status = v.trim().to_string(),
            "PID" => f.init_pid = v.trim().parse().ok(),
            "IP" => known.ips.push(v.trim().to_string()),
            _ => {}
        }
    }
    f.running = f.status.eq_ignore_ascii_case("running");
    files.push((
        "host/lxc-info.txt".into(),
        format!("# lxc-info -n <name>: {}\n{}", info.status_line(), it),
    ));
    let log = [PathBuf::from(format!("/var/log/lxc/{name}.log"))]
        .into_iter()
        .chain(lxc_config(name).and_then(|p| p.parent().map(|d| d.join(format!("{name}.log")))))
        .find(|p| p.is_file());
    if let Some(p) = log {
        let t = util::read_small(&p, CAP).unwrap_or_default();
        let tail: Vec<&str> = t.lines().rev().take(300).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        files.push((
            "host/lxc-log.txt".into(),
            format!(
                "# {} (last {} lines)\n{}\n",
                p.display(),
                tail.len(),
                tail.join("\n")
            ),
        ));
    }
    f.started = f
        .init_pid
        .and_then(|p| std::fs::metadata(format!("/proc/{p}")).ok())
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.mtime()
        });
    f.cg_names = vec![
        format!("lxc.payload.{name}"),
        format!("lxc.payload/{name}"),
        format!("lxc/{name}"),
    ];
    // the container's root: through its init while running, else the rootfs
    let rootfs = get("lxc.rootfs.path")
        .or_else(|| get("lxc.rootfs"))
        .map(|r| {
            let r = r.strip_prefix("dir:").unwrap_or(&r).to_string();
            r
        });
    let root = match (f.running, f.init_pid) {
        (true, Some(p)) => Some(PathBuf::from(format!("/proc/{p}/root"))),
        _ => rootfs.map(PathBuf::from).filter(|p| p.is_dir()),
    };
    if let Some(root) = root {
        let homes: Vec<String> = std::fs::read_dir(root.join("home"))
            .map(|d| {
                d.flatten()
                    .filter_map(|e| e.file_name().to_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for p in runs_paths(o, &homes) {
            if let Some(t) = util::read_small(&root.join(p.trim_start_matches('/')), CAP) {
                f.runs_log = Some((format!("<container root>{p}"), t));
                break;
            }
        }
    }
    f
}

fn collect_pct(
    id: &str,
    o: &Options,
    known: &mut Known,
    files: &mut Vec<(String, String)>,
) -> Facts {
    let mut f = Facts::default();
    let cfg = util::run_cmd("pct", &["config", id], T, CAP);
    let text = if cfg.ok() {
        cfg.text()
    } else {
        util::read_small(Path::new(&format!("/etc/pve/lxc/{id}.conf")), CAP).unwrap_or_default()
    };
    let c = parse_pct_conf(&text);
    if let Some(h) = &c.hostname {
        known.hostnames.push(h.clone());
    }
    known.ips.extend(c.macs.iter().cloned());
    known.ips.extend(c.ips.iter().cloned());
    f.mem_limit = match c.memory_mb {
        Some(m) => format!("memory {m} MB, swap {} MB", c.swap_mb.unwrap_or(0)),
        None => "memory not in the config (Proxmox's default 512 MB)".into(),
    };
    files.push((
        "host/pct-config.txt".into(),
        format!(
            "# pct config <id> (description and snapshots left out): {}\n{}",
            cfg.status_line(),
            c.kept
        ),
    ));
    let st = util::run_cmd("pct", &["status", id, "--verbose"], T, 64 << 10);
    let stt = st.text();
    f.status = stt
        .lines()
        .find_map(|l| l.strip_prefix("status:"))
        .unwrap_or("")
        .trim()
        .to_string();
    f.init_pid = stt
        .lines()
        .find_map(|l| l.strip_prefix("pid:"))
        .and_then(|p| p.trim().parse().ok());
    f.running = f.status == "running";
    files.push((
        "host/pct-status.txt".into(),
        format!("# pct status <id> --verbose: {}\n{stt}", st.status_line()),
    ));

    // the task index: Proxmox's record of starts and stops
    let mut tasks = Vec::new();
    for p in ["/var/log/pve/tasks/index", "/var/log/pve/tasks/active"] {
        for l in util::read_small(Path::new(p), 16 << 20)
            .unwrap_or_default()
            .lines()
        {
            if let Some(t) = parse_upid_line(l).filter(|t| t.id == id && t.kind.starts_with("vz")) {
                tasks.push((t, l.to_string()));
            }
        }
    }
    tasks.sort_by_key(|(t, _)| t.start);
    for (t, _) in &tasks {
        known.hostnames.push(t.node.clone());
        if let Some(u) = t.user.split('@').next().filter(|u| *u != "root") {
            known.users.push(u.to_string());
        }
    }
    let shown: Vec<String> = tasks
        .iter()
        .rev()
        .take(50)
        .rev()
        .map(|(t, _)| {
            format!(
                "{} {} end={} {}",
                util::rfc3339(t.start),
                t.kind,
                t.end.map(util::rfc3339).unwrap_or_else(|| "-".into()),
                if t.status.is_empty() {
                    "running"
                } else {
                    &t.status
                }
            )
        })
        .collect();
    files.push((
        "host/pct-tasks.txt".into(),
        format!(
            "# Proxmox tasks for the container (/var/log/pve/tasks)\n{}\n",
            shown.join("\n")
        ),
    ));
    f.started = tasks
        .iter()
        .rev()
        .find(|(t, _)| t.kind == "vzstart")
        .map(|(t, _)| t.start);
    f.stop_task = tasks
        .iter()
        .rev()
        .find(|(t, _)| matches!(t.kind.as_str(), "vzstop" | "vzshutdown" | "vzreboot"))
        .map(|(t, _)| t.clone());
    f.cg_names = vec![format!("lxc/{id}"), format!("lxc.payload.{id}")];
    f.apparmor = Some(format!("lxc-{id}_"));
    if f.running {
        let homes = util::run_cmd("pct", &["exec", id, "--", "ls", "/home"], T, 64 << 10).text();
        let homes: Vec<String> = homes.lines().map(str::to_string).collect();
        for p in runs_paths(o, &homes) {
            let r = util::run_cmd("pct", &["exec", id, "--", "cat", &p], T, CAP);
            if r.ok() && !r.stdout.is_empty() {
                f.runs_log = Some((
                    format!("pct exec <id> -- cat {p}"),
                    String::from_utf8_lossy(&r.stdout).into_owned(),
                ));
                break;
            }
        }
    }
    f
}

/// Is an irondivid process in the cgroup? Its host pid.
fn node_in(dir: &Path) -> Option<u32> {
    let procs = util::read_small(&dir.join("cgroup.procs"), 1 << 20).unwrap_or_default();
    for p in procs.lines() {
        let comm = util::read_small(Path::new(&format!("/proc/{}/comm", p.trim())), 256)
            .unwrap_or_default();
        if comm.trim() == "irondivid" {
            return p.trim().parse().ok();
        }
    }
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            if let Some(p) = node_in(&e.path()) {
                return Some(p);
            }
        }
    }
    None
}

fn host_btime() -> i64 {
    util::read_small(Path::new("/proc/stat"), 1 << 20)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0)
}

pub fn lxc_main(rt: Runtime, name: &str, o: &Options) -> i32 {
    if util::is_tty() && o.submit != Some(false) && !super::ask_consent(name) {
        println!("Nothing was collected.");
        return 0;
    }
    let mut known = crate::discovery::known_values();
    let mut files = Vec::new();
    let now = util::now_secs();
    let f = match rt {
        Runtime::Lxd | Runtime::Incus => {
            known.hostnames.push(name.into());
            collect_lxd(rt, name, o, &mut known, &mut files)
        }
        Runtime::Lxc => {
            known.hostnames.push(name.into());
            collect_lxc(name, o, &mut known, &mut files)
        }
        Runtime::Proxmox => {
            let Some(id) = pct_id(name) else {
                eprintln!("irondivi-cli diag --host: no Proxmox container {name}");
                return 1;
            };
            if id != name {
                known.hostnames.push(name.into());
            }
            collect_pct(&id, o, &mut known, &mut files)
        }
    };

    // the cgroup's dotted name (`cpuset=lxc.payload.<name>`) carries the container's name
    for c in &f.cg_names {
        if !c.contains('/') {
            known.hostnames.push(c.clone());
        }
    }

    // the container cgroup, while it exists
    let base = Path::new("/sys/fs/cgroup");
    let found = f
        .cg_names
        .iter()
        .find(|c| base.join(c).join("cgroup.procs").exists())
        .cloned();
    let cg = format!(
        "/{}",
        found
            .clone()
            .or_else(|| f.cg_names.first().cloned())
            .unwrap_or_default()
    );
    let mut cg_txt = String::new();
    let mut oom_kill = None;
    let mut pids_hit = None;
    let mut node_pid = None;
    match &found {
        Some(c) => {
            let dir = base.join(c);
            cg_txt.push_str(&format!("# /sys/fs/cgroup{cg}\n"));
            for n in [
                "memory.events",
                "memory.max",
                "memory.peak",
                "memory.current",
                "memory.swap.max",
                "memory.swap.events",
                "pids.max",
                "pids.events",
                "pids.current",
            ] {
                match util::read_small(&dir.join(n), 64 << 10) {
                    Some(t) => cg_txt.push_str(&format!("== {n}\n{t}")),
                    None => cg_txt.push_str(&format!("== {n}: not present\n")),
                }
            }
            let ev = util::read_small(&dir.join("memory.events"), 64 << 10).unwrap_or_default();
            oom_kill = events_count(&ev, "oom_kill");
            let pmax = util::read_small(&dir.join("pids.max"), 256)
                .unwrap_or_default()
                .trim()
                .to_string();
            let pev = util::read_small(&dir.join("pids.events"), 256).unwrap_or_default();
            pids_hit = events_count(&pev, "max").map(|n| (pmax, n));
            node_pid = node_in(&dir);
        }
        None => {
            // cgroup v1, then: no cgroup (the container is stopped)
            let v1 = base.join("memory").join(cg.trim_start_matches('/'));
            match util::read_small(&v1.join("memory.oom_control"), 64 << 10) {
                Some(t) => {
                    cg_txt.push_str(&format!("# /sys/fs/cgroup/memory{cg} (cgroup v1)\n== memory.oom_control\n{t}"));
                    oom_kill = events_count(&t, "oom_kill");
                    if let Some(l) = util::read_small(&v1.join("memory.limit_in_bytes"), 256) {
                        cg_txt.push_str(&format!("== memory.limit_in_bytes\n{l}"));
                    }
                    node_pid = node_in(&v1);
                }
                None => cg_txt.push_str(&format!("# no cgroup at /sys/fs/cgroup{cg}: the container is not running, and its counters went with the cgroup\n")),
            }
        }
    }

    // the host kernel log since the container started
    let since_t = f.started.map(|s| s - 60).unwrap_or(now - 7 * 86400);
    let since = util::rfc3339(since_t);
    let (klog, ksrc) = kernel_log(since_t);
    let klog_ok = klog.ok() && !klog.text().trim().is_empty();
    let (klines, ooms) = kernel_lines(&klog.text(), &cg, f.apparmor.as_deref());
    let seccomp = klines.iter().rev().find_map(|l| parse_audit(l));
    let apparmor_denials = klines
        .iter()
        .filter(|l| l.contains("apparmor=\"DENIED\""))
        .count();
    let mut k_txt = format!(
        "# host kernel log lines about cgroup {cg} since {since} ({ksrc}: {}; {} lines kept)\n",
        klog.status_line(),
        klines.len()
    );
    if !klog.ok() {
        k_txt.push_str(&format!(
            "# {}\n",
            String::from_utf8_lossy(&klog.stderr).trim()
        ));
    }
    for l in &klines {
        k_txt.push_str(l);
        k_txt.push('\n');
    }

    // the node's own record
    let last = f.runs_log.as_ref().and_then(|(_, t)| last_run(t));
    let runs_txt = match &f.runs_log {
        Some((src, t)) => {
            let tail: Vec<&str> = t.lines().filter(|l| !l.contains(" phase ")).collect();
            let tail = &tail[tail.len().saturating_sub(200)..];
            format!(
                "# the node's runs.log, last {} records without phases ({src})\n{}\n",
                tail.len(),
                tail.join("\n")
            )
        }
        None => "# the node's runs.log was not found in the container\n".into(),
    };

    let btime = host_btime();
    let ev = Ev {
        rt,
        running: f.running,
        oom_kill,
        mem_limit: &f.mem_limit,
        ooms: &ooms,
        seccomp: seccomp.as_ref(),
        apparmor_denials,
        pids_hit: pids_hit.clone(),
        klog_ok,
        since: &since,
        node_pid,
        last: last.as_ref(),
        btime,
        stop_task: f.stop_task.as_ref(),
    };
    let v = verdict(&ev);

    let mem = util::read_small(Path::new("/proc/meminfo"), 64 << 10)
        .unwrap_or_else(|| "not readable\n".into());
    let mut head = format!("Container: {name} ({})\n", rt.name());
    head.push_str(&format!(
        "State: {} memory={} started={}\n",
        if f.status.is_empty() {
            "unknown"
        } else {
            f.status.as_str()
        },
        f.mem_limit,
        f.started.map(util::rfc3339).unwrap_or_else(|| "-".into())
    ));
    head.push_str(&format!(
        "cgroup {cg}: {}\n",
        match (&found, oom_kill) {
            (Some(_), k) => format!(
                "present, oom_kill {}",
                k.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
            ),
            (None, Some(k)) => format!("cgroup v1, oom_kill {k}"),
            (None, None) => "gone (the container is not running)".into(),
        }
    ));
    head.push_str(&format!(
        "Node: {}\n",
        match (node_pid, &last) {
            (Some(p), _) => format!("irondivid alive, host pid {p}"),
            (None, Some(l)) => format!(
                "not running; last run started {} ended {}",
                l.start,
                if l.end.is_empty() {
                    "with no exit record"
                } else {
                    l.end.as_str()
                }
            ),
            (None, None) => "not running; runs.log not found".into(),
        }
    ));
    head.push_str(&format!(
        "Kernel log: {ksrc} since {since}, {} OOM kills for the cgroup\n",
        ooms.len()
    ));

    files.push(("host/cgroup.txt".into(), cg_txt));
    files.push(("host/kernel-log.txt".into(), k_txt));
    files.push(("host/runs-log.txt".into(), runs_txt));
    files.push(("host/meminfo.txt".into(), mem));
    let not_built = match rt {
        Runtime::Proxmox => "WSL and Docker Desktop hosts; this Proxmox path is tested only on hand-written fixtures in the real `pct` formats",
        _ => "WSL and Docker Desktop hosts; LXD, Incus and LXC keep no record of how a container stopped, so the stop is read from the node's runs.log",
    };
    finish(
        Pack {
            runtime: rt.name(),
            head,
            verdict: v,
            files,
            not_built: not_built.into(),
            known,
            now,
        },
        o,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // recorded on an Ubuntu 22.04 LXD host (kernel 5.15), limits.memory=10MiB
    const OOM1: &str = "2026-10-31T10:41:07+0000 hp3 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=lxc.payload.dl-oom,mems_allowed=0-1,oom_memcg=/lxc.payload.dl-oom,task_memcg=/lxc.payload.dl-oom,task=irondivid,pid=915504,uid=1000000";
    const OOM2: &str = "2026-10-31T10:41:07+0000 hp3 kernel: Memory cgroup out of memory: Killed process 915504 (irondivid) total-vm:3034896kB, anon-rss:7240kB, file-rss:17592kB, shmem-rss:0kB, UID:1000000 pgtables:484kB oom_score_adj:0";
    const OTHER: &str = "2026-10-31T10:42:00+0000 hp3 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=lxc.payload.dl-oom2,mems_allowed=0-1,oom_memcg=/lxc.payload.dl-oom2,task_memcg=/lxc.payload.dl-oom2,task=sh,pid=11,uid=1000000";
    const AA: &str = "2026-10-31T10:43:00+0000 hp3 kernel: audit: type=1400 audit(1793260000.1:99): apparmor=\"DENIED\" operation=\"mount\" profile=\"lxd-dl-oom_</var/snap/lxd/common/lxd>\" name=\"/\" pid=5 comm=\"mount\"";
    const AA_STATUS: &str = "2026-10-31T10:40:00+0000 hp3 kernel: audit: type=1400 audit(1793259000.1:98): apparmor=\"STATUS\" operation=\"profile_load\" profile=\"unconfined\" name=\"lxd-dl-oom_</var/snap/lxd/common/lxd>\" pid=4";

    const CLEAN: &str = "\
2026-10-31T10:52:04.959580Z mono=204351.466372 start run=1 pid=24 ppid=1 parent=\"init\" version=0.1.0 how=container kernel=\"5.15.0-198-generic\"
2026-10-31T10:52:05.100000Z mono=204351.6 phase phase=ready
2026-10-31T10:52:17.000000Z mono=204363.5 signal signo=TERM code=SI_USER pid=1 uid=0 comm=\"init\" action=stop
2026-10-31T10:52:17.000100Z mono=204363.5 stop-requested by=signal=TERM
2026-10-31T10:52:17.400000Z mono=204363.9 exit code=0 uptime_s=12 reason=\"stopped\"
";
    const FORCE: &str = "\
2026-10-31T10:52:04.959580Z mono=204351.466372 start run=1 pid=24 ppid=1 parent=\"init\" version=0.1.0 how=container kernel=\"5.15.0-198-generic\"
2026-10-31T10:52:05.100000Z mono=204351.6 phase phase=ready
";

    // real-format Proxmox VE 8 fixtures (values invented)
    const PCT: &str = "\
# a description line with the owner's notes
arch: amd64
cores: 2
features: nesting=1
hostname: divi
memory: 4096
net0: name=eth0,bridge=vmbr0,firewall=1,gw=192.168.50.1,hwaddr=BC:24:11:5E:7A:01,ip=192.168.50.20/24,type=veth
ostype: debian
rootfs: local-lvm:vm-101-disk-0,size=64G
swap: 512
unprivileged: 1

[snap1]
hostname: old
memory: 1024
";
    const UPID: &str = "\
UPID:pve1:00001A2B:0012F00D:6720A1B2:vzstart:101:root@pam: 6720A1B5 OK
UPID:pve1:00001A40:0012F100:6720B000:vzstop:101:alice@pve: 6720B002 OK
UPID:pve1:00001A41:0012F101:6720B100:vzstart:102:root@pam: 6720B101 OK
";

    fn ev<'a>(rt: Runtime, ooms: &'a [OomKill], last: Option<&'a LastRun>) -> Ev<'a> {
        Ev {
            rt,
            running: false,
            oom_kill: None,
            mem_limit: "limits.memory 10MiB",
            ooms,
            seccomp: None,
            apparmor_denials: 0,
            pids_hit: None,
            klog_ok: true,
            since: "2026-10-31T10:40:00Z",
            node_pid: None,
            last,
            btime: 1793239573,
            stop_task: None,
        }
    }

    #[test]
    fn names() {
        assert!(valid_name("dl-oom") && valid_name("101") && valid_name("a_b.c"));
        assert!(
            !valid_name("")
                && !valid_name("../x")
                && !valid_name("a/b")
                && !valid_name("-f")
                && !valid_name("a b")
        );
    }

    #[test]
    fn oom_lines() {
        let k = parse_oom_kill(OOM1).unwrap();
        assert_eq!(k.constraint, "CONSTRAINT_MEMCG");
        assert_eq!(k.task_memcg, "/lxc.payload.dl-oom");
        assert_eq!((k.task.as_str(), k.pid), ("irondivid", 915504));
        assert!(in_cgroup(
            "/lxc.payload.dl-oom",
            "/lxc.payload.dl-oom/init.scope"
        ));
        assert!(!in_cgroup("/lxc.payload.dl-oom", "/lxc.payload.dl-oom2"));
        let log = [AA_STATUS, OOM1, OOM2, OTHER, AA].join("\n");
        let (lines, ooms) = kernel_lines(&log, "/lxc.payload.dl-oom", Some("lxd-dl-oom_"));
        assert_eq!(ooms.len(), 1);
        assert_eq!(
            lines,
            vec![OOM1.to_string(), OOM2.to_string(), AA.to_string()]
        );
    }

    #[test]
    fn counts() {
        assert_eq!(
            events_count("low 0\nhigh 0\nmax 25\noom 1\noom_kill 1\n", "oom_kill"),
            Some(1)
        );
        assert_eq!(events_count("max 0\n", "max"), Some(0));
        assert_eq!(events_count("oom 1\n", "oom_kill"), None);
    }

    #[test]
    fn pct_parsers() {
        let c = parse_pct_conf(PCT);
        assert_eq!((c.memory_mb, c.swap_mb), (Some(4096), Some(512)));
        assert_eq!(c.hostname.as_deref(), Some("divi"));
        assert_eq!(c.macs, vec!["BC:24:11:5E:7A:01"]);
        assert_eq!(c.ips, vec!["192.168.50.1", "192.168.50.20"]);
        assert!(
            !c.kept.contains("description") && !c.kept.contains("owner") && !c.kept.contains("old")
        );
        let t: Vec<Task> = UPID.lines().filter_map(parse_upid_line).collect();
        assert_eq!(t.len(), 3);
        assert_eq!(
            (t[1].kind.as_str(), t[1].id.as_str(), t[1].user.as_str()),
            ("vzstop", "101", "alice@pve")
        );
        assert_eq!(t[1].start, 0x6720B000);
        assert_eq!(t[1].end, Some(0x6720B002));
        assert_eq!(t[1].status, "OK");
        assert!(parse_upid_line("garbage").is_none());
    }

    #[test]
    fn lxc_conf() {
        let kv = parse_lxc_conf("# c\nlxc.uts.name = divi\nlxc.cgroup2.memory.max = 4G\nlxc.rootfs.path = dir:/var/lib/lxc/divi/rootfs\n");
        assert!(kv.contains(&("lxc.cgroup2.memory.max".into(), "4G".into())));
        assert_eq!(kv.len(), 3);
    }

    #[test]
    fn runs_log_ends() {
        let c = last_run(CLEAN).unwrap();
        assert!(c.term_from_init && c.end.starts_with("exit 0"));
        let f = last_run(FORCE).unwrap();
        assert!(!f.term_from_init && f.end.is_empty());
        assert_eq!(f.last_time, "2026-10-31T10:52:05.100000Z");
    }

    #[test]
    fn verdicts() {
        let k = vec![parse_oom_kill(OOM1).unwrap()];
        let mut e = ev(Runtime::Lxd, &k, None);
        e.running = true;
        e.oom_kill = Some(1);
        let v = verdict(&e);
        assert!(v.starts_with("the node (irondivid, host pid 915504) was killed at the container's memory limit (limits.memory 10MiB"), "{v}");
        assert!(
            v.contains("oom_kill 1") && v.contains("still running"),
            "{v}"
        );

        let c = last_run(CLEAN).unwrap();
        let v = verdict(&ev(Runtime::Lxd, &[], Some(&c)));
        assert!(
            v.starts_with("stopped cleanly") && !v.contains("memory-limit kill"),
            "{v}"
        );

        let f = last_run(FORCE).unwrap();
        let v = verdict(&ev(Runtime::Lxd, &[], Some(&f)));
        assert!(
            v.starts_with("stopped without the node shutting down")
                && v.contains("`lxc stop --force`"),
            "{v}"
        );
        assert!(
            v.contains("not a memory-limit kill (no OOM line for the container's cgroup"),
            "{v}"
        );
        // no OOM claim without evidence, and no "not OOM" without a kernel log
        let mut e = ev(Runtime::Lxd, &[], Some(&f));
        e.klog_ok = false;
        let v = verdict(&e);
        assert!(
            v.contains("OOM not ruled out") && !v.contains("not a memory-limit kill"),
            "{v}"
        );
        // a count rise with no kernel line still says OOM, and why
        let mut e = ev(Runtime::Lxd, &[], None);
        e.running = true;
        e.oom_kill = Some(2);
        assert!(verdict(&e).starts_with("memory.events counts oom_kill 2"));
        // oom_kill 0 and the node alive
        let mut e = ev(Runtime::Lxd, &[], None);
        e.running = true;
        e.oom_kill = Some(0);
        e.node_pid = Some(42);
        assert!(verdict(&e).contains("is alive: it has not ended"));
        // a host reboot after the node's last record
        let mut e = ev(Runtime::Lxd, &[], Some(&f));
        e.btime = parse_rfc3339("2026-10-31T11:00:00Z").unwrap();
        assert!(verdict(&e).starts_with("the host rebooted"));
        // Proxmox: pct stop after the last record
        let t = parse_upid_line(
            "UPID:pve1:00001A40:0012F100:6AE5CA30:vzstop:101:root@pam: 6AE5CA32 OK",
        )
        .unwrap();
        let mut e = ev(Runtime::Proxmox, &[], Some(&f));
        e.stop_task = Some(&t);
        let v = verdict(&e);
        assert!(v.starts_with("stopped by `pct stop`"), "{v}");
        // a host-wide OOM
        let g = vec![parse_oom_kill(&OOM1.replace("CONSTRAINT_MEMCG", "CONSTRAINT_NONE")).unwrap()];
        assert!(verdict(&ev(Runtime::Lxd, &g, None)).contains("host kernel's OOM killer"));
        // seccomp first
        let a = Audit {
            syscall: 75,
            arch: "c000003e".into(),
            sig: 31,
        };
        let mut e = ev(Runtime::Incus, &k, None);
        e.seccomp = Some(&a);
        assert!(verdict(&e).contains("seccomp (SIGSYS): system call 75 (fdatasync)"));
    }
}
