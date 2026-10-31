// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B3 observed start: with consent, start `irondivid` once on one data dir
//! and watch it start, so a failure at start-up is seen with full detail.
//!
//! The parent asks (R2) and spawns this collector as a child, like any
//! other, with `DIVI_DIAG_OBSERVED_DATADIR` naming the data dir. This child
//! runs the B3.1 safety checks, then starts the node through the
//! single-threaded `irondivi-cli diag --exec-as` helper ([`exec_as`]),
//! follows `runs.log` to the `running` phase, and stops it by the B3.2
//! ladder ([`ladder`]). `observed/summary.txt` is what the parent puts at
//! the top of 00-SUMMARY.

use crate::ctx::{Ctx, DataDir, Node};
use crate::frame::Out;
use crate::outln;
use crate::util;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The env var the parent uses to name the data dir (its `n`)
pub const DATADIR_ENV: &str = "DIVI_DIAG_OBSERVED_DATADIR";
/// B3.1: free space needed on the chain's filesystem
const MIN_FREE: u64 = 1 << 30;
/// Bound on each captured stream of the node
const STREAM_CAP: usize = 256 * 1024;
/// irondivid's default `-checkblocks` (crates/divi-node/src/config.rs)
const DEFAULT_CHECK_BLOCKS: u64 = 100;
/// Conf keys B3.2 removes whatever their value
const REMOVED_KEYS: &[&str] = &[
    "reindex",
    "reindex-chainstate",
    "rescan",
    "salvagewallet",
    "upgradewallet",
    "stopafterblockimport",
    "loadblock",
    "checklevel",
];

// ---------------------------------------------------------- pure parts

/// B3.2: the conf copy with the start-changing keys removed; each removal
/// as (key, value). `checkblocks` goes only above the default (0 = all).
pub fn strip_conf(text: &str) -> (String, Vec<(String, String)>) {
    let mut out = String::new();
    let mut removed = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let body = t.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = body.split_once('=') {
            let k = k.trim().trim_start_matches('-').to_ascii_lowercase();
            let v = v.trim().to_string();
            let drop = REMOVED_KEYS.contains(&k.as_str())
                || (k == "checkblocks"
                    && v.trim_matches('"').parse::<u64>().map(|n| n == 0 || n > DEFAULT_CHECK_BLOCKS).unwrap_or(true));
            if drop {
                removed.push((k, v));
                continue;
            }
        } else if !body.is_empty() && !body.starts_with('[') {
            // a bare key means key=1
            let k = body.trim_start_matches('-').to_ascii_lowercase();
            if REMOVED_KEYS.contains(&k.as_str()) {
                removed.push((k, "1".into()));
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, removed)
}

/// Whether `irondivid -help` lists `-<flag>`
pub fn help_has(help: &str, flag: &str) -> bool {
    let pat = format!("-{flag}");
    help.match_indices(&pat).any(|(i, _)| {
        let before = help[..i].chars().last();
        let after = help[i + pat.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '-')
            && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// R3: what an irondivid exit code means
pub fn exit_meaning(code: i32) -> &'static str {
    match code {
        0 => "clean exit",
        1 => "error (exit 1)",
        2 => "usage error",
        3 => "configuration error",
        4 => "data dir error",
        5 => "database error",
        6 => "wallet error",
        7 => "could not bind a port",
        9 => "disk full or disk error",
        10 => "a task failed or the start-up bound passed",
        11 => "daemon error",
        101 => "panic",
        c if c > 128 => "ended by a signal (128+N)",
        _ => "not an R3 code",
    }
}

/// Whether runs.log text holds the `running` phase record
pub fn reached_running(text: &str) -> bool {
    text.lines().any(|l| l.contains(" phase name=running"))
}

/// The node's argv after the binary (B3.2)
pub fn node_args(d: &DataDir, conf: &Path, supported: &dyn Fn(&str) -> bool) -> (Vec<String>, Vec<String>) {
    let mut a = vec![format!("-datadir={}", d.path.display())];
    let net = d.network.trim_start_matches("privatedivi ");
    match net {
        "testnet" => a.push("-testnet".into()),
        "regtest" => a.push("-regtest".into()),
        _ => {}
    }
    if d.network.starts_with("privatedivi") {
        a.push("-mode=privatedivi".into());
    }
    a.push(format!("-conf={}", conf.display()));
    let mut left_out = Vec::new();
    for f in ["daemon=0", "printtoconsole=0", "staking=0", "debug=1", "disablewallet"] {
        let name = f.split('=').next().unwrap_or(f);
        if supported(name) {
            a.push(format!("-{f}"));
        } else {
            left_out.push(format!("-{f}"));
        }
    }
    (a, left_out)
}

// ------------------------------------------------------------ the ladder

/// B3.2 timings; tests shrink them
pub struct Timing {
    /// diag's own start-up bound (no `-startuptimeout` in irondivid, A18 fallback)
    pub start_bound: Duration,
    /// how long the node runs after the `running` phase
    pub after_running: Duration,
    /// RPC `stop` (or the snapshot) to SIGTERM
    pub to_term: Duration,
    /// SIGTERM to SIGKILL
    pub to_kill: Duration,
    pub tick: Duration,
    pub sample: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            start_bound: Duration::from_secs(300),
            after_running: Duration::from_secs(120),
            to_term: Duration::from_secs(60),
            to_kill: Duration::from_secs(60),
            tick: Duration::from_millis(250),
            sample: Duration::from_secs(5),
        }
    }
}

/// What the ladder does to the outside world
pub trait Hooks {
    /// RPC `stop`; the result in words
    fn rpc_stop(&mut self) -> String;
    /// the A17 snapshot request; true when an incident appeared
    fn snapshot(&mut self, pid: u32) -> bool;
    /// Ctrl+C or a signal reached diag
    fn stopped(&self) -> bool;
    /// the 5 s sample of the node
    fn sample(&mut self, pid: u32);
}

#[derive(Default)]
pub struct Ladder {
    pub events: Vec<String>,
    pub running_after: Option<f64>,
    pub status: Option<ExitStatus>,
    pub abandoned: Option<String>,
    pub incident: bool,
}

fn new_bytes(p: &Path, from: u64) -> String {
    let Ok(mut f) = std::fs::File::open(p) else { return String::new() };
    if f.seek(SeekFrom::Start(from)).is_err() {
        return String::new();
    }
    let mut b = Vec::new();
    let _ = f.take(4 << 20).read_to_end(&mut b);
    String::from_utf8_lossy(&b).into_owned()
}

/// Watch a started node and stop it by the B3.2 ladder
pub fn ladder(child: &mut Child, runs_log: &Path, from: u64, t: &Timing, h: &mut dyn Hooks) -> Ladder {
    let pid = child.id();
    let t0 = Instant::now();
    let mut l = Ladder::default();
    let mut running_at: Option<Instant> = None;
    let mut last_sample = Instant::now();
    let ev = |l: &mut Ladder, s: String| l.events.push(format!("+{:.1} s {s}", t0.elapsed().as_secs_f64()));
    // wait up to `d` for the node to exit; true when it did
    let wait = |child: &mut Child, l: &mut Ladder, d: Duration, h: &mut dyn Hooks, last: &mut Instant| -> bool {
        let end = Instant::now() + d;
        loop {
            if let Ok(Some(s)) = child.try_wait() {
                l.status = Some(s);
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            if last.elapsed() >= t.sample {
                *last = Instant::now();
                h.sample(pid);
            }
            std::thread::sleep(t.tick);
        }
    };
    let reached = loop {
        if let Ok(Some(s)) = child.try_wait() {
            l.status = Some(s);
            ev(&mut l, "the node exited by itself".into());
            return l;
        }
        if running_at.is_none() && reached_running(&new_bytes(runs_log, from)) {
            running_at = Some(Instant::now());
            l.running_after = Some(t0.elapsed().as_secs_f64());
            ev(&mut l, format!("phase running reached; watching {} s more", t.after_running.as_secs()));
        }
        if last_sample.elapsed() >= t.sample {
            last_sample = Instant::now();
            h.sample(pid);
        }
        if h.stopped() {
            ev(&mut l, "Ctrl+C or a signal reached diag: stopping the node now".into());
            break running_at.is_some();
        }
        if running_at.is_some_and(|r| r.elapsed() >= t.after_running) {
            break true;
        }
        if running_at.is_none() && t0.elapsed() >= t.start_bound {
            ev(&mut l, format!("start-up overran diag's {} s bound (no -startuptimeout in this binary)", t.start_bound.as_secs()));
            break false;
        }
        std::thread::sleep(t.tick);
    };
    if reached {
        let r = h.rpc_stop();
        ev(&mut l, format!("RPC stop: {r}"));
    } else {
        // F1: a stack before any signal
        l.incident = h.snapshot(pid);
        let m = if l.incident { "incident written" } else { "no incident" };
        ev(&mut l, format!("snapshot request before SIGTERM: {m}"));
    }
    if wait(child, &mut l, t.to_term, h, &mut last_sample) {
        ev(&mut l, "the node exited".into());
        return l;
    }
    ev(&mut l, "SIGTERM".into());
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if wait(child, &mut l, t.to_kill, h, &mut last_sample) {
        ev(&mut l, "the node exited after SIGTERM".into());
        return l;
    }
    if !l.incident {
        l.incident = h.snapshot(pid);
        let m = if l.incident { "incident written" } else { "no incident" };
        ev(&mut l, format!("snapshot request before SIGKILL: {m}"));
    }
    ev(&mut l, "SIGKILL".into());
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    if wait(child, &mut l, Duration::from_secs(5), h, &mut last_sample) {
        ev(&mut l, "the node exited after SIGKILL".into());
        return l;
    }
    let a = crate::runner::abandoned_record(pid);
    ev(&mut l, a.clone());
    l.abandoned = Some(a);
    l
}

// -------------------------------------------------------- the --exec-as helper

/// `irondivi-cli diag --exec-as <uid> <gid> <user> -- <prog> <args…>`:
/// single-threaded from its first instruction (irondivi-cli's main calls
/// diag before it starts anything), sets groups, gid, uid when they differ,
/// a new session, then `execvp`s. Never returns on success.
pub fn exec_as(args: &[String]) -> i32 {
    let usage = || {
        eprintln!("usage: irondivi-cli diag --exec-as <uid> <gid> <user> -- <program> [args]");
        crate::EX_USAGE
    };
    if args.len() < 5 || args[3] != "--" {
        return usage();
    }
    let (Ok(uid), Ok(gid)) = (args[0].parse::<u32>(), args[1].parse::<u32>()) else { return usage() };
    #[cfg(target_os = "linux")]
    {
        let n = std::fs::read_dir("/proc/self/task").map(|r| r.count()).unwrap_or(0);
        if n != 1 {
            eprintln!("--exec-as: {n} threads; refusing to change ids in a threaded process");
            return 126;
        }
    }
    use std::ffi::CString;
    let Ok(user) = CString::new(args[2].as_str()) else { return usage() };
    unsafe {
        if libc::geteuid() != uid {
            if libc::geteuid() != 0 {
                eprintln!("--exec-as: not root, cannot become uid {uid}");
                return 126;
            }
            if libc::initgroups(user.as_ptr(), gid as _) != 0
                || libc::setgid(gid as libc::gid_t) != 0
                || libc::setuid(uid as libc::uid_t) != 0
            {
                eprintln!("--exec-as: changing ids failed: {}", std::io::Error::last_os_error());
                return 126;
            }
            if libc::getuid() != uid || libc::geteuid() != uid || libc::getegid() != gid as libc::gid_t || libc::setuid(0) == 0 {
                eprintln!("--exec-as: the id change did not hold");
                return 126;
            }
        }
        libc::setsid();
    }
    let Ok(prog) = CString::new(args[4].as_str()) else { return usage() };
    let mut cargs: Vec<CString> = Vec::new();
    for a in &args[4..] {
        match CString::new(a.as_str()) {
            Ok(c) => cargs.push(c),
            Err(_) => return usage(),
        }
    }
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };
    eprintln!("--exec-as: exec failed: {}", std::io::Error::last_os_error());
    127
}

// ----------------------------------------------------------- B3.1 checks

struct Proc {
    pid: u32,
    comm: String,
    args: String,
}

fn all_procs() -> Vec<Proc> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default().trim().to_string();
            let args = std::fs::read(e.path().join("cmdline"))
                .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
                .unwrap_or_default();
            v.push(Proc { pid, comm, args });
        }
        if !v.is_empty() {
            return v;
        }
    }
    let r = util::run_cmd("ps", &["-axo", "pid=,comm=,args="], Duration::from_secs(5), 4 << 20);
    for l in r.text().lines() {
        let mut w = l.split_whitespace();
        let (Some(p), Some(c)) = (w.next(), w.next()) else { continue };
        if let Ok(pid) = p.parse() {
            let comm = crate::discovery::basename(c);
            v.push(Proc { pid, comm, args: w.collect::<Vec<_>>().join(" ") });
        }
    }
    v
}

/// (what, the command that removes the obstacle)
type Refusal = (String, String);

fn systemd_units(user: bool) -> Vec<String> {
    let mut a = vec!["list-units", "--all", "--type=service", "--plain", "--no-legend", "--no-pager"];
    if user {
        a.insert(0, "--user");
    }
    let r = util::run_cmd("systemctl", &a, Duration::from_secs(5), 1 << 20);
    r.text()
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| u.to_ascii_lowercase().contains("irondivi"))
        .map(String::from)
        .collect()
}

fn unit_props(unit: &str, user: bool) -> BTreeMap<String, String> {
    let mut a = vec!["show", "-p", "ActiveState", "-p", "Restart", "-p", "NRestarts", unit];
    if user {
        a.insert(0, "--user");
    }
    util::run_cmd("systemctl", &a, Duration::from_secs(5), 64 * 1024)
        .text()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

/// B3.1: every supervisor that names irondivi
fn supervisors(procs: &[Proc], o: &mut Out) -> Vec<Refusal> {
    let mut refuse = Vec::new();
    if util::which("systemctl").is_some() {
        let mut watch: Vec<(String, bool, String)> = Vec::new();
        for user in [false, true] {
            for u in systemd_units(user) {
                let p = unit_props(&u, user);
                let st = p.get("ActiveState").cloned().unwrap_or_default();
                let rs = p.get("Restart").cloned().unwrap_or_default();
                let n = p.get("NRestarts").cloned().unwrap_or_default();
                let cmd = format!("systemctl {}stop {u}", if user { "--user " } else { "" });
                outln!(o, "  systemd unit {u}{}: ActiveState={st} Restart={rs} NRestarts={n}", if user { " (user)" } else { "" });
                if matches!(st.as_str(), "active" | "activating" | "reloading" | "deactivating") {
                    refuse.push((format!("systemd unit {u} is {st}"), cmd));
                } else if !rs.is_empty() && rs != "no" {
                    watch.push((u, user, n));
                }
            }
        }
        if !watch.is_empty() {
            std::thread::sleep(Duration::from_secs(10));
            for (u, user, n0) in watch {
                let n1 = unit_props(&u, user).get("NRestarts").cloned().unwrap_or_default();
                outln!(o, "  systemd unit {u}: NRestarts {n0} -> {n1} over 10 s");
                if n1 != n0 {
                    refuse.push((format!("systemd unit {u} is restarting (NRestarts rising)"), format!("systemctl {}stop {u}", if user { "--user " } else { "" })));
                }
            }
        }
    }
    for p in procs {
        let names = p.args.to_ascii_lowercase().contains("irondivi");
        match p.comm.as_str() {
            "supervise-daemon" | "runsv" | "s6-supervise" if names => refuse.push((
                format!("{} (pid {}) supervises irondivi", p.comm, p.pid),
                match p.comm.as_str() {
                    "supervise-daemon" => "rc-service <service> stop".to_string(),
                    "runsv" => "sv down <service>".to_string(),
                    _ => "s6-svc -d <service dir>".to_string(),
                },
            )),
            "supervisord" => {
                let r = util::run_cmd("supervisorctl", &["status"], Duration::from_secs(5), 256 * 1024);
                for l in r.text().lines().filter(|l| l.to_ascii_lowercase().contains("irondivi")) {
                    let name = l.split_whitespace().next().unwrap_or("?");
                    refuse.push((format!("supervisord program {name}"), format!("supervisorctl stop {name}")));
                }
            }
            c if c.starts_with("PM2") || c == "pm2" => {
                let r = util::run_cmd("pm2", &["jlist"], Duration::from_secs(5), 1 << 20);
                if r.text().to_ascii_lowercase().contains("irondivi") {
                    refuse.push(("a pm2 process names irondivi".into(), "pm2 stop <name>".into()));
                }
            }
            _ => {}
        }
    }
    if cfg!(target_os = "macos") {
        let r = util::run_cmd("launchctl", &["list"], Duration::from_secs(5), 1 << 20);
        for l in r.text().lines().filter(|l| l.to_ascii_lowercase().contains("irondivi")) {
            let label = l.split_whitespace().last().unwrap_or("?");
            refuse.push((
                format!("launchd job {label} (KeepAlive not read: any loaded job naming irondivi refuses)"),
                format!("launchctl bootout gui/{}/{label}", util::uid()),
            ));
        }
    }
    // cron and @reboot entries naming irondivi
    let mut tabs: Vec<PathBuf> = vec!["/etc/crontab".into()];
    for dir in ["/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron", "/usr/lib/cron/tabs", "/var/at/tabs"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            tabs.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_file()));
        }
    }
    let mut lines: Vec<(String, String)> = Vec::new();
    for t in &tabs {
        if let Some(s) = util::read_small(t, 1 << 20) {
            lines.extend(s.lines().map(|l| (t.display().to_string(), l.to_string())));
        }
    }
    let r = util::run_cmd("crontab", &["-l"], Duration::from_secs(5), 1 << 20);
    lines.extend(r.text().lines().map(|l| ("crontab -l".to_string(), l.to_string())));
    for (src, l) in lines {
        let t = l.trim();
        if !t.starts_with('#') && t.to_ascii_lowercase().contains("irondivi") {
            refuse.push((
                format!("cron entry in {src}: {}", super::procs::cron_line(t)),
                format!("comment out that line ({})", if src == "crontab -l" { "crontab -e".to_string() } else { format!("in {src}") }),
            ));
        }
    }
    refuse
}

fn masternode(d: &DataDir) -> Option<String> {
    let s = super::live::read_settings(d, None);
    if s.get("masternode").map(|v| v.trim_matches('"')).is_some_and(|v| v != "0" && !v.is_empty()) {
        return Some("masternode=1 in the config".into());
    }
    for dir in [&d.chain, &d.path] {
        if let Some(t) = util::read_small(&dir.join("masternode.conf"), 1 << 20) {
            if t.lines().any(|l| !l.trim().is_empty() && !l.trim().starts_with('#')) {
                return Some("masternode.conf has an entry".into());
            }
        }
    }
    None
}

/// R2 ii from the B2.8 read: None = nothing pending
fn pending(ctx: &Ctx, d: &DataDir) -> Option<String> {
    let mut c = Out::capture();
    let opened = super::chain::one(ctx, d, &mut c);
    let t = c.captured();
    if !opened {
        if t.contains("no chainstate folder") {
            return None;
        }
        return Some("the chain database could not be read, so a pending migration cannot be ruled out".into());
    }
    let p: Vec<&str> = t.lines().filter(|l| l.contains("PENDING") && !l.contains("network marker")).collect();
    if p.is_empty() {
        None
    } else {
        Some(format!("pending: {}", p.join("; ")))
    }
}

/// None = the lock is free (or there is no lock file)
fn lock_held(chain: &Path) -> Option<String> {
    use std::os::unix::io::AsRawFd;
    let f = match std::fs::File::open(chain.join(".lock")) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(format!("the lock file could not be opened: {}", util::io_err(&e))),
    };
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    if r == 0 {
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        None
    } else {
        Some("the data dir lock is held".into())
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

fn pw_gid(uid: u32) -> Option<u32> {
    unsafe {
        let p = libc::getpwuid(uid as libc::uid_t);
        if p.is_null() {
            None
        } else {
            Some((*p).pw_gid as u32)
        }
    }
}

/// The irondivid to start, and how it was chosen
fn pick_binary(ctx: &Ctx) -> Option<(PathBuf, String)> {
    if let Ok(me) = std::env::current_exe() {
        if let Some(dir) = me.parent() {
            let p = dir.join("irondivid");
            if p.is_file() {
                return Some((p, "next to this irondivi-cli".into()));
            }
        }
    }
    super::files::copies(ctx)
        .into_iter()
        .find(|(p, _)| p.file_name().is_some_and(|n| n == "irondivid"))
        .map(|(p, how)| (p, format!("first copy found ({how})")))
}

// --------------------------------------------------------------- capture

fn hash_backups(d: &DataDir) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut seen = Vec::new();
    for base in [&d.chain, &d.path] {
        for sub in ["backups", "monthlyBackups"] {
            let dir = base.join(sub);
            if seen.iter().any(|s: &PathBuf| same_dir(s, &dir)) || !dir.is_dir() {
                continue;
            }
            seen.push(dir.clone());
            let mut files = Vec::new();
            walk(&dir, &mut files, 5000);
            for f in files {
                let h = util::sha256_file(&f).unwrap_or_else(|e| format!("unreadable: {}", util::io_err(&e)));
                m.insert(f.display().to_string(), h);
            }
        }
    }
    m
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, cap: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if out.len() >= cap {
            return;
        }
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, out, cap),
            Ok(_) => out.push(p),
            Err(_) => {}
        }
    }
}

fn owners(root: &Path) -> BTreeMap<PathBuf, u32> {
    use std::os::unix::fs::MetadataExt;
    let mut files = Vec::new();
    walk(root, &mut files, 500_000);
    files.into_iter().filter_map(|p| std::fs::symlink_metadata(&p).ok().map(|m| (p, m.uid()))).collect()
}

fn cgroup_counters() -> Vec<String> {
    let mut v = Vec::new();
    let Some(cg) = util::read_small(Path::new("/proc/self/cgroup"), 64 * 1024) else { return v };
    let Some(path) = cg.lines().find_map(|l| l.strip_prefix("0::")) else {
        v.push("cgroup v1 or no cgroup: counters not read".into());
        return v;
    };
    let dir = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    for f in ["memory.events", "memory.peak", "pids.peak", "pids.events"] {
        if let Some(t) = util::read_small(&dir.join(f), 64 * 1024) {
            v.push(format!("{f}: {}", t.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
    }
    v
}

fn size_of(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

struct Live<'a> {
    ctx: &'a Ctx,
    d: &'a DataDir,
    node: Node,
    o: &'a mut Out,
    samples: Vec<String>,
    t0: Instant,
    side: Option<Vec<String>>,
}

impl Hooks for Live<'_> {
    fn rpc_stop(&mut self) -> String {
        match super::live::rpc_for(self.d, None) {
            Ok(rpc) => match super::live::call(&rpc, "stop", serde_json::json!([]), Duration::from_secs(10)) {
                Ok(_) => format!("sent ({})", rpc.auth_kind),
                Err(e) => format!("failed: {e}"),
            },
            Err(e) => format!("not sent: {e}"),
        }
    }
    fn snapshot(&mut self, _pid: u32) -> bool {
        // incidents land in observed/incidents/, the lines in observed/live-node.txt
        self.o.file("observed/live-node.txt");
        let found = super::live::snapshot(self.o, self.ctx, self.d, &self.node, "observed");
        self.o.file("observed/run.txt");
        found
    }
    fn stopped(&self) -> bool {
        crate::runner::stopped()
    }
    fn sample(&mut self, pid: u32) {
        let t = self.t0.elapsed().as_secs();
        if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            let mut by: BTreeMap<String, usize> = BTreeMap::new();
            for e in rd.flatten() {
                let c = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default();
                *by.entry(c.trim().to_string()).or_default() += 1;
            }
            let n: usize = by.values().sum();
            let st = crate::discovery::proc_stat(pid).map(|(s, _, _)| s).unwrap_or('?');
            let parts: Vec<String> = by.iter().map(|(k, v)| format!("{k}×{v}")).collect();
            self.samples.push(format!("+{t} s state {st} threads {n}: {}", parts.join(" ")));
        } else {
            self.samples.push(format!("+{t} s /proc/{pid}/task not readable (not Linux, or the node is gone)"));
        }
        if self.side.is_none() {
            let r = self.ctx.redactor();
            let lim = |p: &str| util::read_small(Path::new(p), 64 * 1024).unwrap_or_else(|| "unreadable".into());
            let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).map(|p| r.path_of(&p)).unwrap_or_else(|_| "unreadable (a non-dumpable node hides it from its own user)".into());
            let me = std::env::current_dir().map(|p| r.path_of(&p)).unwrap_or_default();
            let mut v = vec![format!("cwd: node {cwd} | diag {me}")];
            let (a, b) = (lim(&format!("/proc/{pid}/limits")), lim("/proc/self/limits"));
            for (x, y) in a.lines().zip(b.lines()) {
                v.push(if x == y { format!("limit same: {x}") } else { format!("limit node: {x}\n      diag: {y}") });
            }
            self.side = Some(v);
        }
    }
}

// ------------------------------------------------------------ the collector

pub fn observed(ctx: &Ctx, o: &mut Out) {
    crate::runner::install_signal_handlers();
    let mut summary: Vec<String> = Vec::new();
    run(ctx, o, &mut summary);
    o.file("observed/summary.txt");
    for l in summary {
        o.line(&l);
    }
}

fn run(ctx: &Ctx, o: &mut Out, summary: &mut Vec<String>) {
    let r = ctx.redactor();
    o.file("observed/checks.txt");
    let want: Option<usize> = std::env::var(DATADIR_ENV).ok().and_then(|v| v.parse().ok());
    let Some(d) = ctx.datadirs.iter().find(|d| Some(d.n) == want) else {
        outln!(o, "no data dir named by the parent: nothing started");
        summary.push("Not started: no data dir was chosen".into());
        return;
    };
    outln!(o, "data dir {} ({}): {}", d.n, d.network, r.path_of(&d.chain));
    let mut refuse: Vec<Refusal> = Vec::new();
    let mut check = |o: &mut Out, name: &str, res: Vec<Refusal>| {
        if res.is_empty() {
            outln!(o, "check {name}: ok");
        }
        for (what, cmd) in &res {
            outln!(o, "check {name}: REFUSED: {what} — to fix: {cmd}");
        }
        refuse.extend(res);
    };

    // R2 i
    let mn = masternode(d).map(|w| (w, "a masternode is never started by diag (R2 i)".to_string()));
    check(o, "masternode (R2 i)", mn.into_iter().collect());
    // R2 ii
    let pend = pending(ctx, d).map(|w| (w, "start irondivid yourself and let the migration finish, then re-run diag".to_string()));
    check(o, "pending migration (R2 ii, B2.8)", pend.into_iter().collect());
    // R2 iii: running already
    let procs = all_procs();
    let mut run_refs = Vec::new();
    for p in &procs {
        if !p.comm.starts_with("irondivid") {
            continue;
        }
        let argv: Vec<String> = p.args.split_whitespace().map(String::from).collect();
        let named = crate::discovery::arg_value(&argv, "datadir").map(PathBuf::from);
        let ours = match &named {
            Some(n) => same_dir(n, &d.path) || same_dir(n, &d.chain),
            None => same_dir(&crate::discovery::default_base(&util::user_home(util::uid()).unwrap_or_default()), &d.path),
        };
        if ours {
            run_refs.push((format!("irondivid pid {} runs on this data dir", p.pid), format!("stop it first (kill -TERM {})", p.pid)));
        }
    }
    if let Some(w) = lock_held(&d.chain) {
        run_refs.push((w, "stop the irondivid that holds it".into()));
    }
    check(o, "not running (R2 iii)", run_refs);
    outln!(o, "supervisors naming irondivi:");
    let sup = supervisors(&procs, o);
    check(o, "no supervisor (R2 iii)", sup);
    // R2 iv
    let me = util::euid();
    let owner = d.owner;
    let mut own = Vec::new();
    match owner {
        None => own.push(("the data dir owner is not known".into(), crate::discovery::sudo_hint(None, &d.path))),
        Some(u) if u == me => outln!(o, "owner: diag runs as the data dir owner; the node runs as diag's user"),
        Some(_) if me == 0 => outln!(o, "owner: diag runs as root; the --exec-as helper switches to the data dir owner"),
        Some(u) => own.push((format!("the data dir belongs to another user (diag runs as uid {me})"), crate::discovery::sudo_hint(Some(u), &d.path))),
    }
    check(o, "owner (R2 iv)", own);
    let space = match util::statvfs(&d.chain) {
        Some((free, ..)) if free >= MIN_FREE => {
            outln!(o, "free space: {}", util::human(free));
            vec![]
        }
        Some((free, ..)) => vec![(format!("free space {} is under 1 GB", util::human(free)), "free space on the data dir's filesystem".into())],
        None => vec![("free space could not be read".into(), "check the data dir's filesystem".into())],
    };
    check(o, "free space (B3.1)", space);
    let swaps: Vec<Refusal> = procs
        .iter()
        .filter(|p| p.comm.starts_with("divi-swap"))
        .map(|p| (format!("{} pid {} is running", p.comm, p.pid), format!("stop it first (kill -TERM {})", p.pid)))
        .collect();
    check(o, "no divi-swapd (B3.1)", swaps);
    let bin = pick_binary(ctx);
    let help = match &bin {
        Some((p, how)) => {
            outln!(o, "binary: {} ({how})", r.path_of(p));
            match util::sha256_file(p) {
                Ok(h) => outln!(o, "binary sha256: {h}"),
                Err(e) => outln!(o, "binary sha256: {}", util::io_err(&e)),
            }
            let h = util::run_cmd(&p.display().to_string(), &["-help"], Duration::from_secs(10), 1 << 20);
            let t = format!("{}{}", String::from_utf8_lossy(&h.stdout), String::from_utf8_lossy(&h.stderr));
            if t.trim().is_empty() {
                check(o, "binary runs", vec![(format!("irondivid -help printed nothing ({})", h.status_line()), "reinstall irondivid".into())]);
            }
            t
        }
        None => {
            check(o, "binary", vec![("no irondivid found next to irondivi-cli or on PATH".into(), "install irondivid next to irondivi-cli".into())]);
            String::new()
        }
    };
    let a18 = help_has(&help, "walletbroadcast") && help_has(&help, "createwalletbackups");
    outln!(
        o,
        "A18 flags (-walletbroadcast, -createwalletbackups): {}",
        if a18 { "listed by -help, but this diag uses the A18 fallback anyway (-disablewallet)" } else { "not supported: A18 fallback, -disablewallet" }
    );
    let startup = help_has(&help, "startuptimeout");
    outln!(o, "-startuptimeout: {}", if startup { "listed, not used by this diag; diag's own 300 s bound applies" } else { "not supported: diag's own 300 s bound applies" });

    if !refuse.is_empty() {
        summary.push(format!("Not started: {} check(s) refused (R2/B3.1). To run the observed start, first:", refuse.len()));
        for (what, cmd) in &refuse {
            summary.push(format!("  - {what}: {cmd}"));
        }
        return;
    }
    let Some((bin, _)) = bin else { return };
    let owner = owner.unwrap_or(me);

    // R1 (d): the temporary conf copy
    let tmp = std::env::temp_dir().join(format!("irondivi-diag-observed-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir(&tmp) {
        outln!(o, "temporary conf folder: {}", util::io_err(&e));
        summary.push("Not started: the temporary conf folder could not be created".into());
        return;
    }
    let gid = pw_gid(owner).unwrap_or(0);
    let cleanup = |tmp: &Path| {
        let _ = std::fs::remove_dir_all(tmp);
    };
    let conf_tmp = tmp.join("divi.conf");
    let src = d.conf.clone().unwrap_or_else(|| d.path.join("divi.conf"));
    let text = std::fs::read_to_string(&src).unwrap_or_default();
    let (copy, removed) = strip_conf(&text);
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700));
        let w = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&conf_tmp)
            .and_then(|mut f| std::io::Write::write_all(&mut f, copy.as_bytes()));
        if let Err(e) = w {
            outln!(o, "temporary conf copy: {}", util::io_err(&e));
            cleanup(&tmp);
            summary.push("Not started: the temporary conf copy could not be written".into());
            return;
        }
        if me == 0 && owner != 0 {
            for p in [&tmp, &conf_tmp] {
                let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap_or_default();
                unsafe { libc::chown(c.as_ptr(), owner as libc::uid_t, gid as libc::gid_t) };
            }
        }
    }
    o.file("observed/run.txt");
    outln!(o, "conf: copy of {} in a 0700 temporary folder, removed afterwards", r.path_of(&src));
    if text.lines().any(|l| l.trim_start().starts_with("includeconf")) {
        outln!(o, "conf: includeconf lines are kept; the included files are not filtered");
    }
    for (k, v) in &removed {
        outln!(o, "removed from the conf copy: {k}={}", r.scrub(v));
    }
    let (args, left_out) = node_args(d, &conf_tmp, &|f| help_has(&help, f));
    for f in &left_out {
        outln!(o, "not passed (not listed by -help): {f}");
    }
    outln!(o, "command: irondivid {}", args.iter().map(|a| r.scrub(a)).collect::<Vec<_>>().join(" "));
    outln!(o, "run as: {}", if owner == me { "diag's own user" } else { "the data dir owner, through --exec-as" });
    outln!(o, "context: same cgroup as diag (systemd-run --scope is not used in this version); no pty; environment is diag's minus LC_ALL/LANG/MALLOC_ARENA_MAX, with the owner's HOME/USER/LOGNAME");

    let backups0 = hash_backups(d);
    let owners0 = owners(&d.path);
    let runs_log = d.chain.join("diag/runs.log");
    let debug_log = d.chain.join("debug.log");
    let (runs0, debug0) = (size_of(&runs_log), size_of(&debug_log));
    let cg0 = cgroup_counters();

    let Ok(me_exe) = std::env::current_exe() else {
        cleanup(&tmp);
        summary.push("Not started: current_exe failed".into());
        return;
    };
    let uname = util::user_name(owner).unwrap_or_else(|| owner.to_string());
    let mut cmd = Command::new(me_exe);
    cmd.args(["diag", "--exec-as", &owner.to_string(), &gid.to_string(), &uname, "--"])
        .arg(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("LC_ALL")
        .env_remove("LANG")
        .env_remove("MALLOC_ARENA_MAX")
        .env_remove(DATADIR_ENV)
        .env_remove("DIVI_DIAG_RLIMIT_DATA")
        .env("USER", &uname)
        .env("LOGNAME", &uname);
    if let Some(h) = util::user_home(owner) {
        cmd.env("HOME", h);
    }
    let t_start = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            outln!(o, "start failed: {}", util::io_err(&e));
            cleanup(&tmp);
            summary.push(format!("Not started: {}", util::io_err(&e)));
            return;
        }
    };
    let pid = child.id();
    outln!(o, "started: pid {pid}");
    let reader = |s: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(mut s) = s {
                let mut chunk = [0u8; 8192];
                while let Ok(n) = s.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if b.len() < STREAM_CAP {
                        b.extend_from_slice(&chunk[..n.min(STREAM_CAP - b.len())]);
                    }
                }
            }
            b
        })
    };
    let so = reader(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let se = reader(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let node = Node {
        pid,
        uid: Some(owner),
        datadir: Some(d.path.clone()),
        argv: std::iter::once(bin.display().to_string()).chain(args.iter().cloned()).collect(),
        ..Default::default()
    };
    let mut live = Live { ctx, d, node, o, samples: Vec::new(), t0: Instant::now(), side: None };
    let l = ladder(&mut child, &runs_log, runs0, &Timing::default(), &mut live);
    let (samples, side) = (std::mem::take(&mut live.samples), live.side.take());
    let o = live.o;
    let secs = t_start.elapsed().as_secs_f64();
    cleanup(&tmp);

    o.file("observed/run.txt");
    for e in &l.events {
        outln!(o, "{e}");
    }
    use std::os::unix::process::ExitStatusExt;
    let ended = match (&l.abandoned, l.status) {
        (Some(a), _) => a.clone(),
        (None, Some(s)) => match (s.code(), s.signal()) {
            (Some(c), _) => format!("exit {c}: {}", exit_meaning(c)),
            (None, Some(sg)) => format!("signal {sg}"),
            _ => "unknown".into(),
        },
        _ => "unknown".into(),
    };
    outln!(o, "ended: {ended} after {secs:.1} s");
    outln!(o, "temporary conf folder removed: {}", !tmp.exists());
    outln!(o, "\n-- the node beside diag (B3.2) --");
    for s in side.unwrap_or_else(|| vec!["not sampled (the node ended within 5 s)".into()]) {
        outln!(o, "{s}");
    }
    outln!(o, "\n-- cgroup counters (diag's cgroup, which the node shared) --");
    for (n, v) in [("before", cg0), ("after", cgroup_counters())] {
        for x in v {
            outln!(o, "{n}: {x}");
        }
    }
    o.file("observed/tasks.txt");
    for s in &samples {
        outln!(o, "{s}");
    }
    let so = so.join().unwrap_or_default();
    let se = se.join().unwrap_or_default();
    for (name, b) in [("stdout", so), ("stderr", se)] {
        o.file(&format!("observed/{name}.txt"));
        o.write(crate::oldlog::filter(&util::escape_bytes(&b), &r).render().as_bytes());
        o.line("");
    }
    o.file("observed/runs.log");
    o.write(new_bytes(&runs_log, runs0).as_bytes());
    o.file("observed/debug.log");
    o.write(crate::oldlog::filter(&new_bytes(&debug_log, debug0), &r).render().as_bytes());
    o.line("");

    // after: backups and owners
    let backups1 = hash_backups(d);
    let mut diffs: Vec<String> = Vec::new();
    for (k, v) in &backups0 {
        match backups1.get(k) {
            None => diffs.push(format!("removed: {}", r.path(k))),
            Some(w) if w != v => diffs.push(format!("changed: {}", r.path(k))),
            _ => {}
        }
    }
    for k in backups1.keys().filter(|k| !backups0.contains_key(*k)) {
        diffs.push(format!("new: {}", r.path(k)));
    }
    if diffs.is_empty() {
        summary.push(format!("Wallet backups: byte-identical before and after ({} files in backups/ and monthlyBackups/)", backups0.len()));
    } else {
        summary.push(format!("WALLET BACKUPS DIFFER after the observed start ({}):", diffs.len()));
        summary.extend(diffs.iter().map(|x| format!("  - {x}")));
    }
    let owners1 = owners(&d.path);
    let moved: Vec<String> = owners1
        .iter()
        .filter(|(p, u)| **u != owner && owners0.get(*p).is_none_or(|u0| u0 != *u))
        .map(|(p, _)| r.path_of(p))
        .collect();
    if moved.is_empty() {
        summary.push("Owners: no file in the data dir changed owner".into());
    } else {
        summary.push(format!("OWNERS CHANGED on {} file(s) in the data dir:", moved.len()));
        summary.extend(moved.iter().take(20).map(|x| format!("  - {x}")));
    }
    summary.push(format!(
        "Started irondivid on data dir {} ({}): {}; ended: {ended} after {secs:.0} s",
        d.n,
        d.network,
        match l.running_after {
            Some(s) => format!("reached running after {s:.1} s"),
            None => "did not reach running".into(),
        }
    ));
    if l.abandoned.is_some() {
        summary.push("The node is STILL THERE and holds the data dir lock; it could not be reaped.".into());
    }
    summary.push("Wallet: the run used -disablewallet (A18 fallback), so wallet-load failures were not exercised; upgrading irondivid and re-running diag covers them.".into());
    summary.push("Details: observed/run.txt, observed/checks.txt, observed/stderr.txt, observed/runs.log, observed/debug.log".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_strip() {
        let (c, r) = strip_conf("rpcuser=u\nreindex=1\n# rescan=1\n checklevel = 4\ncheckblocks=50\ncheckblocks=500\n-loadblock=/x\n[test]\nsalvagewallet\nlisten=1\n");
        assert_eq!(c, "rpcuser=u\n# rescan=1\ncheckblocks=50\n[test]\nlisten=1\n");
        let keys: Vec<&str> = r.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["reindex", "checklevel", "checkblocks", "loadblock", "salvagewallet"]);
        assert_eq!(r[2].1, "500");
        assert_eq!(strip_conf("checkblocks=0\n").1.len(), 1);
    }

    #[test]
    fn help_flags() {
        let h = "  -daemon  Run\n  -debug=<cat>\n  -disablewallet\n  -walletbroadcast-x\n";
        assert!(help_has(h, "daemon"));
        assert!(help_has(h, "debug"));
        assert!(help_has(h, "disablewallet"));
        assert!(!help_has(h, "wallet"));
        assert!(!help_has(h, "walletbroadcast"));
    }

    #[test]
    fn args_and_meanings() {
        let d = DataDir { path: "/b".into(), chain: "/b/regtest".into(), network: "privatedivi regtest".into(), ..Default::default() };
        let (a, left) = node_args(&d, Path::new("/t/c"), &|f| f != "debug");
        assert_eq!(a, ["-datadir=/b", "-regtest", "-mode=privatedivi", "-conf=/t/c", "-daemon=0", "-printtoconsole=0", "-staking=0", "-disablewallet"]);
        assert_eq!(left, ["-debug=1"]);
        assert_eq!(exit_meaning(10), "a task failed or the start-up bound passed");
        assert!(reached_running("t mono=1 phase name=running prev=rpc prev_ms=3\n"));
        assert!(!reached_running("t mono=1 phase name=rpc prev=staking\n"));
    }

    struct Stub {
        stops: usize,
        snaps: usize,
    }
    impl Hooks for Stub {
        fn rpc_stop(&mut self) -> String {
            self.stops += 1;
            "stub".into()
        }
        fn snapshot(&mut self, _: u32) -> bool {
            self.snaps += 1;
            false
        }
        fn stopped(&self) -> bool {
            false
        }
        fn sample(&mut self, _: u32) {}
    }

    fn quick() -> Timing {
        Timing {
            start_bound: Duration::from_secs(2),
            after_running: Duration::from_secs(1),
            to_term: Duration::from_secs(1),
            to_kill: Duration::from_secs(1),
            tick: Duration::from_millis(50),
            sample: Duration::from_secs(1),
        }
    }

    fn stub(script: &str, log: &Path) -> Child {
        Command::new("sh").arg("-c").arg(script).arg("sh").arg(log).spawn().unwrap()
    }

    #[test]
    fn ladder_running_then_term() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("runs.log");
        std::fs::write(&log, "old line\n").unwrap();
        let mut c = stub("echo 't mono=1 phase name=running prev=rpc' >> \"$1\"; trap 'exit 0' TERM; while :; do sleep 0.1; done", &log);
        let mut h = Stub { stops: 0, snaps: 0 };
        let l = ladder(&mut c, &log, 9, &quick(), &mut h);
        assert!(l.running_after.is_some(), "{:?}", l.events);
        assert_eq!((h.stops, h.snaps), (1, 0));
        assert_eq!(l.status.and_then(|s| s.code()), Some(0), "{:?}", l.events);
        assert!(l.events.iter().any(|e| e.ends_with("SIGTERM")));
    }

    #[test]
    fn ladder_overrun_then_kill() {
        use std::os::unix::process::ExitStatusExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("runs.log");
        let mut c = stub("trap '' TERM; while :; do sleep 0.1; done", &log);
        let mut h = Stub { stops: 0, snaps: 0 };
        let l = ladder(&mut c, &log, 0, &quick(), &mut h);
        assert!(l.running_after.is_none());
        assert_eq!((h.stops, h.snaps), (0, 2), "{:?}", l.events);
        assert_eq!(l.status.and_then(|s| s.signal()), Some(9), "{:?}", l.events);
        assert!(l.abandoned.is_none());
    }
}
