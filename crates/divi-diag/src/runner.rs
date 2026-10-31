// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The parent: B1.1 discovery, the R1 (a) output folder, one child process
//! per collector with its B5 time budget and B2 memory cap, the B2.20
//! `diag.log`, `00-SUMMARY.txt` and `02-manifest.txt`.

use crate::collectors::{self, Spec};
use crate::ctx::Ctx;
use crate::discovery;
use crate::frame::{read_frame, Frame, Out};
use crate::redact::Redactor;
use crate::scanner;
use crate::util;
use crate::Options;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// B5: the whole collection, without the observed start
const TOTAL_BUDGET: Duration = Duration::from_secs(600);
const GB: u64 = 1 << 30;
const MB: u64 = 1 << 20;

static STOP: AtomicBool = AtomicBool::new(false);
static STOP_SIG: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    STOP_SIG.store(sig, Ordering::SeqCst);
    STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// The memory cap of B2: 1 GB, 512 MB on a 32-bit build
pub fn mem_cap() -> u64 {
    if cfg!(target_pointer_width = "32") {
        512 * MB
    } else {
        GB
    }
}

/// Which memory-cap mechanism applies here (B2 "Memory cap"). The cgroup
/// scopes are not implemented yet, so Linux uses RLIMIT_DATA from 4.7 on
/// and a statm poll before it; macOS polls the collector's RSS.
pub fn cap_mechanism() -> &'static str {
    if cfg!(target_os = "linux") {
        if kernel_at_least(4, 7) {
            "RLIMIT_DATA"
        } else {
            "statm poll"
        }
    } else {
        "rss poll"
    }
}

fn kernel_at_least(maj: u32, min: u32) -> bool {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return false;
    }
    let rel = unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().into_owned();
    let mut it = rel.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty());
    let a: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let b: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (a, b) >= (maj, min)
}

/// Resident memory of a child, for the poll mechanisms
fn rss_of(pid: u32) -> Option<u64> {
    if cfg!(target_os = "linux") {
        let s = fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
        let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64)
    } else {
        let o = util::run_cmd("ps", &["-o", "rss=", "-p", &pid.to_string()], Duration::from_secs(2), 256);
        o.text().trim().parse::<u64>().ok().map(|k| k * 1024)
    }
}

// ---------------------------------------------------------------- child

/// `irondivi-cli diag --collector <name>`: read the context from stdin,
/// cap our own memory, run one collector
pub fn child_main(name: &str) -> i32 {
    if let Ok(v) = std::env::var("DIVI_DIAG_RLIMIT_DATA") {
        if let Ok(n) = v.parse::<u64>() {
            let r = libc::rlimit { rlim_cur: n as libc::rlim_t, rlim_max: n as libc::rlim_t };
            unsafe { libc::setrlimit(libc::RLIMIT_DATA, &r) };
        }
    }
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return 2;
    }
    let ctx: Ctx = match serde_json::from_str(&input) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bad context: {e}");
            return 2;
        }
    };
    let mut out = Out::new();
    if collectors::run(name, &ctx, &mut out) {
        out.flush();
        0
    } else {
        eprintln!("unknown collector {name}");
        2
    }
}

// --------------------------------------------------------------- parent

/// A file in the package, append-only, mode 0600
fn open_in(root: &Path, rel: &str) -> std::io::Result<File> {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    }
    OpenOptions::new().create(true).append(true).mode(0o600).open(p)
}

/// A collector may only name a plain relative path inside the package
fn safe_rel(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && rel.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// B2.20: written synchronously, line by line, scrubbed like everything else
struct DiagLog {
    f: Option<File>,
    red: Arc<Redactor>,
}

impl DiagLog {
    fn log(&mut self, msg: &str) {
        let line = format!("{} {}\n", util::rfc3339(util::now_secs()), self.red.scrub(msg));
        if let Some(f) = self.f.as_mut() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.sync_data();
        }
    }
}

#[derive(Clone)]
struct Done {
    spec: &'static Spec,
    status: String,
    secs: f64,
    bytes: u64,
}

struct Parent {
    ctx: Ctx,
    red: Arc<Redactor>,
    out: PathBuf,
    id: String,
    log: DiagLog,
    done: Vec<Done>,
    /// file → collector, for the manifest
    owners: Arc<Mutex<BTreeMap<String, String>>>,
    notes: Vec<String>,
    started: i64,
    state: &'static str,
    /// §6.3: (file, reason) for every file the final scan left out
    left_out: Vec<(String, String)>,
    scanned: bool,
}

/// R1 (a): the space a filesystem must keep free once diag writes to it
fn reserve(out_dev: u64, total: u64, ctx: &Ctx) -> u64 {
    let on_datadir_fs = ctx
        .datadirs
        .iter()
        .any(|d| fs::metadata(&d.path).map(|m| m.dev() == out_dev).unwrap_or(false));
    if on_datadir_fs {
        GB.max(total / 20)
    } else {
        50 * MB
    }
}

/// Is there room to keep writing to `dir` under the free-space rule?
fn room(dir: &Path, ctx: &Ctx) -> Result<(), String> {
    let dev = fs::metadata(dir).map(|m| m.dev()).map_err(|e| util::io_err(&e))?;
    let (free, total, _, _) = util::statvfs(dir).ok_or("statvfs failed")?;
    let need = reserve(dev, total, ctx);
    if free < need {
        Err(format!("{} free, the rule keeps {} free", util::human(free), util::human(need)))
    } else {
        Ok(())
    }
}

fn tmp_base() -> PathBuf {
    std::env::var_os("TMPDIR").map(PathBuf::from).filter(|p| p.is_dir()).unwrap_or_else(|| "/tmp".into())
}

/// The local id names the folder. The real ticket is issued by the receiver
/// at send time (§8.4); this is a stand-in drawn from the same alphabet.
fn local_id() -> String {
    use rand::Rng;
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut r = rand::thread_rng();
    (0..8).map(|_| A[r.gen_range(0..32)] as char).collect()
}

fn create_out(o: &Options, id: &str, ctx: &Ctx) -> Result<(PathBuf, Vec<String>), String> {
    let name = format!("irondivi-diag-{id}");
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Some(p) = &o.out {
        cands.push(p.clone());
    } else {
        cands.push(PathBuf::from(".").join(&name));
        cands.push(tmp_base().join(&name));
        cands.push(PathBuf::from("/tmp").join(&name));
    }
    let mut tried = Vec::new();
    for c in cands {
        let parent = c.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        if let Err(e) = room(parent, ctx) {
            tried.push(format!("{}: {e}", c.display()));
            continue;
        }
        let created = fs::DirBuilder::new().mode(0o700).create(&c);
        match created {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && o.out.is_some() => {
                let empty = fs::read_dir(&c).map(|mut d| d.next().is_none()).unwrap_or(false);
                if !empty {
                    return Err(format!("{} exists and is not empty", c.display()));
                }
                let _ = fs::set_permissions(&c, std::os::unix::fs::PermissionsExt::from_mode(0o700));
            }
            Err(e) => {
                tried.push(format!("{}: {}", c.display(), util::io_err(&e)));
                continue;
            }
        }
        let abs = fs::canonicalize(&c).unwrap_or(c);
        return Ok((abs, tried));
    }
    Err(format!("no place for the output folder: {}", tried.join("; ")))
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(to)?;
    for e in fs::read_dir(from)? {
        let e = e?;
        let t = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_tree(&e.path(), &t)?;
        } else {
            fs::copy(e.path(), &t)?;
        }
    }
    Ok(())
}

pub fn parent_main(o: Options) -> i32 {
    unsafe { libc::umask(0o077) };
    install_signal_handlers();
    let t0 = Instant::now();

    // B1.1 discovery
    let known = discovery::known_values();
    let mirrors = discovery::mirror_roots();
    let (live, stale, unreadable) = discovery::path_records(&mirrors);
    let nodes = discovery::find_nodes(&live);
    let found = discovery::discover(o.datadir.as_deref(), o.conf.as_deref(), &nodes, stale, unreadable);
    let salt = Redactor::new_salt();
    let mut ctx = Ctx {
        salt: hex::encode(salt),
        known,
        datadirs: found.dirs,
        nodes,
        mirror_roots: mirrors,
        looked_at: found.looked_at,
        offline: o.offline,
        allow_fsync: o.fsync_test != Some(false),
        cap_sys_ptrace: discovery::root_gets_ptrace(),
        invoked_as: "irondivi-cli diag".into(),
        ..Default::default()
    };
    let red = Arc::new(ctx.redactor());
    let id = local_id();
    let (out, tried) = match create_out(&o, &id, &ctx) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("irondivi-cli diag: {e}");
            return 73; // EX_CANTCREAT
        }
    };
    ctx.out_dir = out.clone();
    let mut p = Parent {
        ctx,
        red: red.clone(),
        out: out.clone(),
        id,
        log: DiagLog { f: None, red: red.clone() },
        done: Vec::new(),
        owners: Arc::new(Mutex::new(BTreeMap::new())),
        notes: Vec::new(),
        started: util::now_secs(),
        state: "in progress",
        left_out: Vec::new(),
        scanned: false,
    };
    for t in &tried {
        p.notes.push(format!("output folder not used: {t}"));
    }
    if o.run == Some(true) {
        p.notes.push("--run: the observed start (B3) is not in this version of diag; nothing was started.".into());
    }
    if o.submit == Some(true) {
        p.notes.push("--submit: preview, consent and sending (§8) are not in this version of diag; nothing was sent.".into());
    } else if !util::is_tty() {
        p.notes.push("no terminal: nothing is ever sent without one (R2).".into());
    }
    if o.offline {
        p.notes.push("--offline: the network probe (B2.15) was skipped.".into());
    }
    // 00-SUMMARY first (R1 a), then diag.log
    p.write_summary();
    p.log.f = open_in(&out, "diag.log").ok();
    p.log.log(&format!("irondivi-cli diag {} local id {} pid {}", crate::VERSION, p.id, std::process::id()));
    p.log.log(&format!("memory cap {} MB per collector, mechanism {}", mem_cap() / MB, cap_mechanism()));
    p.log.log("memory cap: cgroup scopes are not implemented in this version");
    p.log_discovery();
    eprintln!("irondivi-cli diag: writing to {}", out.display());

    for spec in collectors::ALL {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        if spec.name == "probe" && p.ctx.offline {
            p.record(spec, "SKIPPED: --offline".into(), 0.0, 0);
            continue;
        }
        if t0.elapsed() >= TOTAL_BUDGET {
            p.record(spec, format!("SKIPPED: total budget of {} s spent", TOTAL_BUDGET.as_secs()), 0.0, 0);
            continue;
        }
        if let Err(why) = room(&p.out, &p.ctx) {
            if !p.relocate(&why) {
                p.notes.push(format!("collection stopped before {}: {why}", spec.name));
                p.state = "stopped (free space)";
                break;
            }
        }
        if spec.name == "storage" {
            for d in &p.ctx.datadirs {
                let name = d.path.join(format!(".irondivi-diag-fsync-{}", p.id));
                p.log.log(&format!("fsync test file for datadir-{}: {}", d.n, name.display()));
            }
        }
        let left = TOTAL_BUDGET.saturating_sub(t0.elapsed());
        p.run_one(spec, Duration::from_secs(spec.secs).min(left));
        if spec.name == "storage" {
            p.remove_fsync_files();
        }
        p.write_summary();
    }
    if STOP.load(Ordering::SeqCst) {
        p.state = "interrupted";
        p.log.log(&format!("stopped by signal {}", STOP_SIG.load(Ordering::SeqCst)));
        p.remove_fsync_files();
    } else if p.state == "in progress" {
        p.state = "complete";
    }
    // §6.3 finalize: diag.log closes first, then the scanner reads every
    // file (summary included), and the manifest is written last so its
    // hashes are those of the files that stay
    p.log.log(&format!("collection done in {:.1} s; the final scan (§6.3) follows", t0.elapsed().as_secs_f64()));
    p.log.f = None;
    // the summary says the scan ran; a summary the scan fails is left out
    p.scanned = true;
    p.write_summary();
    p.final_scan(&salt);
    p.write_manifest();
    eprintln!("irondivi-cli diag: {} — {}", p.state, p.out.display());
    eprintln!("Nothing was sent. Read 00-SUMMARY.txt in that folder first.");
    if p.state == "complete" {
        0
    } else {
        1
    }
}

impl Parent {
    /// §6.3: scan, leave out every file with a hit, rewrite the summary
    /// with the list, and scan again until nothing is found
    fn final_scan(&mut self, salt: &[u8]) {
        let confs: Vec<PathBuf> = self.ctx.datadirs.iter().filter_map(|d| d.conf.clone()).collect();
        let cookies: Vec<PathBuf> =
            self.ctx.datadirs.iter().flat_map(|d| [d.path.join(".cookie"), d.chain.join(".cookie")]).collect();
        let secrets = scanner::secrets_of(&confs, &cookies);
        let sc = scanner::Scanner::new(&self.red, &secrets, salt);
        for round in 0..4 {
            let hits = sc.scan_folder(&self.out);
            if hits.is_empty() {
                return;
            }
            for h in hits {
                let _ = fs::remove_file(self.out.join(&h.file));
                eprintln!("irondivi-cli diag: left out {} (line {}): {}", h.file, h.line, h.reason);
                self.left_out.push((h.file, format!("line {}: {}", h.line, h.reason)));
            }
            if round < 3 {
                self.write_summary();
            }
        }
    }

    fn record(&mut self, spec: &'static Spec, status: String, secs: f64, bytes: u64) {
        self.log.log(&format!("{} {} {}: {status} ({secs:.1} s, {bytes} bytes)", spec.id, spec.name, if status == "ok" { "end" } else { "end" }));
        self.done.push(Done { spec, status, secs, bytes });
    }

    fn log_discovery(&mut self) {
        let lines: Vec<String> = self.discovery_lines();
        for l in lines {
            self.log.log(&format!("B1.1 {l}"));
        }
    }

    fn discovery_lines(&self) -> Vec<String> {
        let r = &self.red;
        let mut v = Vec::new();
        for n in &self.ctx.nodes {
            let what = n.component.clone().unwrap_or_else(|| "irondivid".into());
            v.push(format!(
                "process {what} pid {} uid {} data dir {} ({})",
                n.pid,
                n.uid.map(|u| if u == 0 { "0".to_string() } else { r.pseudonym("uid", &u.to_string()) }).unwrap_or("?".into()),
                n.datadir.as_ref().map(|d| r.path_of(d)).unwrap_or_else(|| "unknown".into()),
                n.datadir_source
            ));
        }
        for d in &self.ctx.datadirs {
            v.push(format!(
                "datadir-{}: {} network {} chain {} found by {}{}{}",
                d.n,
                r.path_of(&d.path),
                if d.network.is_empty() { "unknown" } else { d.network.as_str() },
                r.path_of(&d.chain),
                r.scrub(&d.found_by.join(", ")),
                if d.readable { String::new() } else { format!(", NOT READABLE: {}", d.read_error.clone().unwrap_or_default()) },
                d.running_pid.map(|p| format!(", node pid {p}")).unwrap_or_default()
            ));
            if !d.readable {
                v.push(format!("  to read it: {}", r.scrub(&discovery::sudo_hint(d.owner, &d.path))));
            }
        }
        if self.ctx.datadirs.is_empty() {
            v.push("no data dir found. Looked at:".into());
            for l in &self.ctx.looked_at {
                v.push(format!("  {}", r.scrub(l)));
            }
        }
        v
    }

    /// R1 (a): the output folder's filesystem is short; move to $TMPDIR or /tmp
    fn relocate(&mut self, why: &str) -> bool {
        let name = self.out.file_name().map(|n| n.to_owned()).unwrap_or_default();
        let my_dev = fs::metadata(&self.out).map(|m| m.dev()).ok();
        for base in [tmp_base(), PathBuf::from("/tmp")] {
            if fs::metadata(&base).map(|m| Some(m.dev()) == my_dev).unwrap_or(true) {
                continue;
            }
            if room(&base, &self.ctx).is_err() {
                continue;
            }
            let to = base.join(&name);
            if copy_tree(&self.out, &to).is_ok() {
                let _ = fs::remove_dir_all(&self.out);
                self.notes.push(format!("output folder moved to {}: {why}", to.display()));
                self.out = to.clone();
                self.ctx.out_dir = to.clone();
                self.log.f = open_in(&to, "diag.log").ok();
                self.log.log(&format!("moved output folder: {why}"));
                return true;
            }
        }
        false
    }

    fn remove_fsync_files(&mut self) {
        for d in self.ctx.datadirs.clone() {
            if let Ok(rd) = fs::read_dir(&d.path) {
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().starts_with(".irondivi-diag-fsync-") {
                        match fs::remove_file(e.path()) {
                            Ok(()) => self.log.log(&format!("removed {}", e.path().display())),
                            Err(er) => self.log.log(&format!("could not remove {}: {}", e.path().display(), util::io_err(&er))),
                        }
                    }
                }
            }
        }
    }

    fn run_one(&mut self, spec: &'static Spec, budget: Duration) {
        let started = Instant::now();
        if util::is_tty() {
            eprint!("  {} {:<12}", spec.id, spec.name);
        }
        self.log.log(&format!("{} {} start, budget {} s", spec.id, spec.name, budget.as_secs()));
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => {
                let s = format!("not run: current_exe: {}", util::io_err(&e));
                self.record(spec, s, 0.0, 0);
                return;
            }
        };
        let mech = cap_mechanism();
        let mut cmd = Command::new(&exe);
        cmd.args(["diag", "--collector", spec.name])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("MALLOC_ARENA_MAX", "2")
            .env("LC_ALL", "C")
            .env("LANG", "C");
        if mech == "RLIMIT_DATA" {
            cmd.env("DIVI_DIAG_RLIMIT_DATA", mem_cap().to_string());
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let s = format!("not run: {}", util::io_err(&e));
                self.record(spec, s, 0.0, 0);
                return;
            }
        };
        let pid = child.id();
        self.log.log(&format!("{} {} pid {pid}, memory cap mechanism {mech}", spec.id, spec.name));
        // the context goes over the pipe only (it holds the salt)
        if let Some(mut si) = child.stdin.take() {
            let json = serde_json::to_vec(&self.ctx).unwrap_or_default();
            std::thread::spawn(move || {
                let _ = si.write_all(&json);
            });
        }
        let (tx, rx) = mpsc::channel::<(u64, Option<String>)>();
        let mut so = child.stdout.take().expect("piped");
        let root = self.out.clone();
        let red = self.red.clone();
        let owners = self.owners.clone();
        let cname = spec.name.to_string();
        std::thread::spawn(move || {
            let mut cur: Option<(String, File)> = None;
            let mut bytes = 0u64;
            let mut err = None;
            loop {
                match read_frame(&mut so) {
                    Ok(Some(Frame::File(rel))) => {
                        if !safe_rel(&rel) {
                            err = Some(format!("refused file name {:?}", rel));
                            cur = None;
                            continue;
                        }
                        match open_in(&root, &rel) {
                            Ok(f) => {
                                owners.lock().unwrap().entry(rel.clone()).or_insert_with(|| cname.clone());
                                cur = Some((rel, f));
                            }
                            Err(e) => err = Some(format!("{rel}: {}", util::io_err(&e))),
                        }
                    }
                    Ok(Some(Frame::Data(d))) => {
                        if let Some((_, f)) = cur.as_mut() {
                            let text = String::from_utf8_lossy(&d);
                            let clean = red.scrub(&text);
                            bytes += clean.len() as u64;
                            let _ = f.write_all(clean.as_bytes());
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        err = Some(format!("pipe: {e}"));
                        break;
                    }
                }
            }
            let _ = tx.send((bytes, err.map(|e| match &cur {
                Some((r, _)) => format!("{e} (last file {r})"),
                None => e,
            })));
        });
        let mut se = child.stderr.take().expect("piped");
        let (etx, erx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            while let Ok(n) = se.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if buf.len() < 64 * 1024 {
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
            let _ = etx.send(buf);
        });

        let deadline = started + budget;
        let poll = mech != "RLIMIT_DATA";
        let mut last_poll = Instant::now();
        let mut killed_for: Option<String> = None;
        let mut status = None;
        loop {
            match child.try_wait() {
                Ok(Some(s)) => {
                    status = Some(s);
                    break;
                }
                Ok(None) => {}
                Err(_) => break,
            }
            if STOP.load(Ordering::SeqCst) {
                killed_for = Some(format!("INTERRUPTED: {} stopped by Ctrl+C or a signal", spec.name));
            } else if Instant::now() >= deadline {
                killed_for = Some(format!("TRUNCATED: {} exceeded {} s", spec.name, budget.as_secs()));
            } else if poll && last_poll.elapsed() >= Duration::from_millis(500) {
                last_poll = Instant::now();
                if let Some(rss) = rss_of(pid) {
                    if rss > mem_cap() {
                        killed_for = Some(format!("MEMORY CAP: {} exceeded {} MB", spec.name, mem_cap() / MB));
                    }
                }
            }
            if killed_for.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut abandoned = None;
        if let Some(why) = &killed_for {
            self.log.log(why);
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            let t = Instant::now();
            loop {
                if let Ok(Some(s)) = child.try_wait() {
                    status = Some(s);
                    break;
                }
                if t.elapsed() >= Duration::from_secs(5) {
                    abandoned = Some(abandoned_record(pid));
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let wait = if abandoned.is_some() { Duration::from_millis(200) } else { Duration::from_secs(5) };
        let (bytes, perr) = rx.recv_timeout(wait).unwrap_or((0, Some("output reader did not finish".into())));
        let stderr = erx.recv_timeout(Duration::from_millis(500)).unwrap_or_default();
        let secs = started.elapsed().as_secs_f64();

        let mut st = match (&killed_for, &abandoned, status) {
            (_, Some(a), _) => a.clone(),
            (Some(w), None, _) => w.clone(),
            (None, None, Some(s)) => {
                use std::os::unix::process::ExitStatusExt;
                let oom = String::from_utf8_lossy(&stderr).contains("memory allocation of");
                match (s.code(), s.signal()) {
                    (Some(0), _) => "ok".to_string(),
                    (Some(134), _) | (None, Some(6)) if oom => {
                        format!("MEMORY CAP: {} exceeded {} MB", spec.name, mem_cap() / MB)
                    }
                    (Some(c), _) => format!("FAILED: exit {c}"),
                    (None, Some(sg)) => format!("FAILED: signal {sg}"),
                    _ => "FAILED".to_string(),
                }
            }
            _ => "FAILED: could not wait".into(),
        };
        if let Some(e) = perr {
            self.log.log(&format!("{} {}: {e}", spec.id, spec.name));
            if st == "ok" {
                st = format!("ok ({e})");
            }
        }
        if !stderr.is_empty() {
            let text = util::escape_bytes(&stderr);
            for l in text.lines().take(50) {
                self.log.log(&format!("{} {} stderr: {l}", spec.id, spec.name));
            }
        }
        if st != "ok" && !st.starts_with("ok ") {
            // mark the partial output in every file the collector wrote
            let files: Vec<String> = self
                .owners
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, c)| c.as_str() == spec.name)
                .map(|(f, _)| f.clone())
                .collect();
            for f in files {
                if let Ok(mut h) = open_in(&self.out, &f) {
                    let _ = writeln!(h, "\n{st}");
                }
            }
        }
        if util::is_tty() {
            eprintln!(" {st} ({secs:.1} s)");
        }
        self.record(spec, st, secs, bytes);
    }

    fn write_summary(&self) {
        let r = &self.red;
        let mut s = String::new();
        s.push_str(&format!("IronDivi diagnostics — irondivi-cli diag {}\n", crate::VERSION));
        s.push_str(&format!("Local id: {} (a ticket is issued only when the package is sent)\n", self.id));
        s.push_str(&format!("Started: {}   Status: {}\n\n", util::rfc3339(self.started), self.state));

        s.push_str("== Run table (B2.14) ==\n");
        let mut any = false;
        for d in &self.ctx.datadirs {
            let p = self.out.join(format!("datadir-{}/run-table.txt", d.n));
            if let Ok(t) = fs::read_to_string(&p) {
                s.push_str(&format!("-- datadir-{} ({})\n{}\n", d.n, d.network, t.trim_end()));
                any = true;
            }
        }
        if !any {
            s.push_str(if self.done.iter().any(|d| d.spec.name == "runs") {
                "no run table: no data dir with runs.log or debug.log was readable\n"
            } else {
                "not collected yet\n"
            });
        }

        s.push_str("\n== Collectors (B2.20) ==\n");
        for d in &self.done {
            s.push_str(&format!("{:<6} {:<11} {:>6.1} s {:>10} B  {}\n", d.spec.id, d.spec.name, d.secs, d.bytes, d.status));
        }
        let left: Vec<&str> = collectors::ALL
            .iter()
            .filter(|c| !self.done.iter().any(|d| d.spec.name == c.name))
            .map(|c| c.name)
            .collect();
        if !left.is_empty() {
            s.push_str(&format!("not run (yet): {}\n", left.join(" ")));
        }

        s.push_str("\n== What diag found (B1.1) ==\n");
        for l in self.discovery_lines() {
            s.push_str(&l);
            s.push('\n');
        }
        let mut notes = self.notes.clone();
        for c in collectors::NOT_YET {
            notes.push(format!("not in this version: {c}"));
        }
        s.push_str("\n== Notes ==\n");
        for n in &notes {
            s.push_str(&r.scrub(n));
            s.push('\n');
        }
        if !self.left_out.is_empty() {
            s.push_str("\n== Left out by the final scan (§6.3) ==\n");
            for (f, why) in &self.left_out {
                s.push_str(&format!("{f}: {why}\n"));
            }
        }
        if self.scanned {
            s.push_str("\nThis folder has been through diag's redaction (§6.2) and final scan (§6.3), and was not sent anywhere.\n");
        } else {
            s.push_str("\nThis folder has been through diag's redaction (§6.2) and was not sent anywhere.\n");
        }
        // write-then-rename so a reader never sees half a summary
        let tmp = self.out.join(".00-SUMMARY.tmp");
        if let Ok(mut f) = OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp) {
            let _ = f.write_all(s.as_bytes());
            let _ = f.sync_data();
            let _ = fs::rename(&tmp, self.out.join("00-SUMMARY.txt"));
        }
    }

    fn write_manifest(&self) {
        let mut files = Vec::new();
        walk(&self.out, &self.out, &mut files);
        files.sort();
        let owners = self.owners.lock().unwrap();
        let mut m = String::from("# path\tsize\tsha256\tcollector\n");
        m.push_str("# every file written by a collector went through the §6.2 step 1 scrub\n");
        for (f, why) in &self.left_out {
            m.push_str(&format!("# left out: {f} — {why}\n"));
        }
        for rel in files {
            if rel == "02-manifest.txt" || rel.starts_with('.') {
                continue;
            }
            let p = self.out.join(&rel);
            let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let h = util::sha256_file(&p).unwrap_or_else(|e| util::io_err(&e));
            let who = owners.get(&rel).map(String::as_str).unwrap_or("diag");
            m.push_str(&format!("{rel}\t{size}\t{h}\t{who}\n"));
        }
        if let Ok(mut f) = open_in(&self.out, "02-manifest.txt") {
            let _ = f.write_all(m.as_bytes());
        }
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else if let Ok(rel) = p.strip_prefix(root) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
}

/// B2: a collector that survived SIGKILL for 5 s is left behind, and its
/// state is itself evidence (a hung disk)
fn abandoned_record(pid: u32) -> String {
    let state = discovery::proc_stat(pid).map(|(s, _, _)| s).unwrap_or('?');
    let wchan = fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
    let wchan = match wchan.trim() {
        "" | "0" if state == 'R' => "running".to_string(),
        "" | "0" => "hidden".to_string(),
        w => w.to_string(),
    };
    let stack = fs::read_to_string(format!("/proc/{pid}/stack"))
        .map(|s| s.lines().take(8).collect::<Vec<_>>().join(" | "))
        .unwrap_or_else(|_| "unreadable".into());
    format!("ABANDONED (uninterruptible): pid {pid} state {state} wchan {wchan} stack {stack}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_paths() {
        assert!(safe_rel("datadir-1/logs/debug.log"));
        assert!(!safe_rel("../x"));
        assert!(!safe_rel("/etc/passwd"));
        assert!(!safe_rel("a//b"));
    }

    #[test]
    fn id_alphabet() {
        let id = local_id();
        assert_eq!(id.len(), 8);
        assert!(id.bytes().all(|b| b"abcdefghijklmnopqrstuvwxyz234567".contains(&b)));
    }
}
