// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Signals (diag.md A3): every signal irondivid acts on is recorded in
//! runs.log with who sent it, then acted on.
//!
//! The handler (installed first thing in `main`, before the -daemon forks)
//! only does what is async-signal-safe: it counts, reads the sender's
//! `/proc` entries into a fixed slot with open/read/close, and writes the
//! slot's number to a pipe. The `signals` thread, started after the forks,
//! masks the sender's command line, writes the record and acts. A third
//! stop signal is handled in the handler itself, so it works when the rest
//! of the process does not: it writes its own records straight to runs.log
//! and ends the process with code 10.
//!
//! Interim (not built yet): A6's health record and incident (USR1), A17's
//! dump (QUIT), A11's counters in the third-signal record, and an argv
//! allowlist for an irondivid sender; on other systems than Linux the
//! sender is not read.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use tokio::sync::broadcast;

/// Stop signals, counted together: the first stops, the second is ignored,
/// the third ends the process
const STOP_SIGNALS: [i32; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT];

/// Recorded, then the default action (or `_exit(128+N)` as PID 1)
#[cfg(any(target_os = "linux", target_os = "android"))]
const DEFAULT_ACTION: &[i32] = &[
    libc::SIGXCPU,
    libc::SIGXFSZ,
    libc::SIGPWR,
    libc::SIGALRM,
    libc::SIGVTALRM,
    libc::SIGPROF,
    #[cfg(not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "sparc",
        target_arch = "sparc64"
    )))]
    libc::SIGSTKFLT,
    libc::SIGIO,
];
/// (SIGIO's default action is to ignore it outside Linux; there is no SIGPWR
/// or SIGSTKFLT)
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const DEFAULT_ACTION: &[i32] = &[
    libc::SIGXCPU,
    libc::SIGXFSZ,
    libc::SIGALRM,
    libc::SIGVTALRM,
    libc::SIGPROF,
];

const SLOTS: usize = 16;
const NAME: usize = 16;
const CMDLINE: usize = 256;
const CHAIN: usize = 4;

/// What the handler learned of the sender
const SENDER_NOT_READ: u8 = 0;
const SENDER_READ: u8 = 1;
const SENDER_GONE: u8 = 2;
const SENDER_HIDDEN: u8 = 3;
const SENDER_OUTSIDE: u8 = 4;
const SENDER_KERNEL: u8 = 5;

#[derive(Clone, Copy)]
struct Raw {
    signo: i32,
    code: i32,
    pid: i32,
    uid: u32,
    mono_ns: u64,
    /// The stop signals counted so far, this one included (TERM, INT, QUIT)
    count: u32,
    sender: u8,
    comm: [u8; NAME],
    comm_len: usize,
    cmdline: [u8; CMDLINE],
    cmdline_len: usize,
    chain: [(i32, [u8; NAME], usize); CHAIN],
    chain_len: usize,
}

impl Raw {
    const fn new() -> Raw {
        Raw {
            signo: 0,
            code: 0,
            pid: 0,
            uid: 0,
            mono_ns: 0,
            count: 0,
            sender: SENDER_NOT_READ,
            comm: [0; NAME],
            comm_len: 0,
            cmdline: [0; CMDLINE],
            cmdline_len: 0,
            chain: [(0, [0; NAME], 0); CHAIN],
            chain_len: 0,
        }
    }
}

const FREE: u8 = 0;
const FILLING: u8 = 1;
const READY: u8 = 2;

struct Slot {
    state: AtomicU8,
    raw: UnsafeCell<Raw>,
}

// A slot's `raw` is written only by the handler that moved it FREE ->
// FILLING, and read only by the thread that sees it READY
unsafe impl Sync for Slot {}

static SLOT: [Slot; SLOTS] = [const {
    Slot {
        state: AtomicU8::new(FREE),
        raw: UnsafeCell::new(Raw::new()),
    }
}; SLOTS];

/// The pipe from the handler to the `signals` thread: a slot's index, or
/// `0x80 | signo` when every slot was taken
static PIPE_READ: AtomicI32 = AtomicI32::new(-1);
static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);
/// Stop signals (TERM, INT) in this run
static STOPS: AtomicU32 = AtomicU32::new(0);
/// SIGPIPEs received, and console writes that failed with EPIPE
static SIGPIPES: AtomicU64 = AtomicU64::new(0);
static EPIPES: AtomicU64 = AtomicU64::new(0);
/// The monotonic time of the TSTP that stopped the process (0: none)
static STOPPED_AT: AtomicU64 = AtomicU64::new(0);

/// Where a stop goes, and whether the console gets a line for it
static SINK: OnceLock<(broadcast::Sender<()>, bool)> = OnceLock::new();
/// A one-shot command (snapshot, export): a stop signal ends it at once
static ONE_SHOT: AtomicBool = AtomicBool::new(false);
/// A stop signal not delivered yet (its number; 0: none)
static PENDING: AtomicI32 = AtomicI32::new(0);

fn handled() -> Vec<i32> {
    let mut all = vec![
        libc::SIGTERM,
        libc::SIGINT,
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGCONT,
        libc::SIGPIPE,
    ];
    all.extend_from_slice(DEFAULT_ACTION);
    all
}

/// Install the handlers. Called first in `main`, once fds 0-2 are open (the
/// pipe must not take one of them); it starts no thread.
pub fn install() {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        crate::console_line(
            false,
            format_args!(
                "Warning: signals are not recorded: {}",
                std::io::Error::last_os_error()
            ),
        );
        return;
    }
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
        // The handler must never block on a full pipe
        let flags = libc::fcntl(fds[1], libc::F_GETFL);
        libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    PIPE_READ.store(fds[0], Ordering::Relaxed);
    PIPE_WRITE.store(fds[1], Ordering::Relaxed);
    for signo in handled() {
        if let Err(e) = unsafe { signal_hook_registry::register_sigaction(signo, on_signal) } {
            crate::console_line(
                false,
                format_args!("Warning: no handler for SIG{}: {}", name(signo), e),
            );
        }
    }
}

/// The handler: async-signal-safe only (no allocation, no lock)
fn on_signal(info: &libc::siginfo_t) {
    let signo = info.si_signo;
    if signo == libc::SIGPIPE {
        SIGPIPES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let (pid, uid) = unsafe { (info.si_pid(), info.si_uid()) };
    let count = if STOP_SIGNALS.contains(&signo) {
        let n = STOPS.fetch_add(1, Ordering::SeqCst) + 1;
        if n >= 3 {
            third_stop(signo, info.si_code, pid, uid, n);
        }
        n
    } else {
        0
    };
    let fd = PIPE_WRITE.load(Ordering::Relaxed);
    let Some(i) = SLOT.iter().position(|s| {
        s.state
            .compare_exchange(FREE, FILLING, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }) else {
        let byte = 0x80 | signo as u8;
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
        return;
    };
    let raw = unsafe { &mut *SLOT[i].raw.get() };
    *raw = Raw::new();
    raw.signo = signo;
    raw.code = info.si_code;
    raw.pid = pid;
    raw.uid = uid;
    raw.count = count;
    raw.mono_ns = mono_ns();
    read_sender(raw);
    SLOT[i].state.store(READY, Ordering::Release);
    let byte = i as u8;
    unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
}

/// The third stop signal: the records go straight to runs.log's descriptor
/// and the process ends with code 10, whatever the rest of it is doing
fn third_stop(signo: i32, code: i32, pid: i32, uid: u32, count: u32) -> ! {
    let mut line = crate::runs_log::RawLine::new("signal");
    line.text(" signo=")
        .text(name(signo))
        .text(" code=")
        .text(code_name(code))
        .text(" pid=")
        .num(i64::from(pid))
        .text(" uid=")
        .num(i64::from(uid))
        .text(" action=exit count=")
        .num(i64::from(count));
    line.write();
    let (sigpipes, epipes) = counts();
    crate::runs_log::raw_exit(10, "a third stop signal", sigpipes, epipes);
    unsafe { libc::_exit(10) }
}

fn mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Whether `code` says a process sent the signal (kill, tgkill, sigqueue)
fn from_process(code: i32) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        code == libc::SI_USER || code == libc::SI_TKILL || code == libc::SI_QUEUE
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SI_USER and SI_QUEUE (sys/signal.h)
        code == 0x10001 || code == 0x10002
    }
}

/// The sender's comm, command line and parents, from /proc (Linux)
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_sender(raw: &mut Raw) {
    if !from_process(raw.code) {
        raw.sender = SENDER_KERNEL;
        return;
    }
    if raw.pid == 0 {
        raw.sender = SENDER_OUTSIDE;
        return;
    }
    let mut buf = [0u8; 512];
    let ppid = match read_proc(raw.pid, b"stat\0", &mut buf) {
        Ok(n) => {
            let (comm, ppid) = parse_stat(&buf[..n]);
            raw.comm_len = copy(comm, &mut raw.comm);
            ppid
        }
        Err(e) if e == libc::ENOENT || e == libc::ESRCH => {
            raw.sender = SENDER_GONE;
            return;
        }
        Err(_) => {
            raw.sender = SENDER_HIDDEN;
            return;
        }
    };
    raw.sender = SENDER_READ;
    if let Ok(n) = read_proc(raw.pid, b"cmdline\0", &mut raw.cmdline) {
        raw.cmdline_len = n;
    }
    let mut next = ppid;
    while raw.chain_len < CHAIN && next > 0 {
        let Ok(n) = read_proc(next, b"stat\0", &mut buf) else {
            break;
        };
        let (comm, ppid) = parse_stat(&buf[..n]);
        let entry = &mut raw.chain[raw.chain_len];
        entry.0 = next;
        entry.2 = copy(comm, &mut entry.1);
        raw.chain_len += 1;
        next = ppid;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_sender(raw: &mut Raw) {
    raw.sender = if !from_process(raw.code) {
        SENDER_KERNEL
    } else if raw.pid == 0 {
        SENDER_OUTSIDE
    } else {
        SENDER_NOT_READ
    };
}

fn copy(from: &[u8], to: &mut [u8]) -> usize {
    let n = from.len().min(to.len());
    to[..n].copy_from_slice(&from[..n]);
    n
}

/// `/proc/<pid>/<leaf>` into `buf` with open/read/close; the errno on failure
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_proc(pid: i32, leaf: &[u8], buf: &mut [u8]) -> Result<usize, i32> {
    let mut path = [0u8; 48];
    let mut n = copy(b"/proc/", &mut path);
    let mut digits = [0u8; 12];
    let mut d = digits.len();
    let mut v = pid.unsigned_abs();
    loop {
        d -= 1;
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    n += copy(&digits[d..], &mut path[n..]);
    path[n] = b'/';
    n += 1;
    copy(leaf, &mut path[n..]);
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(errno());
    }
    let mut len = 0;
    while len < buf.len() {
        let r = unsafe { libc::read(fd, buf[len..].as_mut_ptr().cast(), buf.len() - len) };
        if r < 0 {
            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(e);
        }
        if r == 0 {
            break;
        }
        len += r as usize;
    }
    unsafe { libc::close(fd) };
    Ok(len)
}

/// `pid (comm) state ppid ...`: the comm and the ppid (comm may hold `)`)
fn parse_stat(stat: &[u8]) -> (&[u8], i32) {
    let open = stat.iter().position(|&b| b == b'(');
    let close = stat.iter().rposition(|&b| b == b')');
    let (Some(open), Some(close)) = (open, close) else {
        return (&[], 0);
    };
    if close < open {
        return (&[], 0);
    }
    let mut ppid = 0i32;
    // ") S 1234 "
    let rest = &stat[close + 1..];
    let mut fields = rest.split(|&b| b == b' ').filter(|f| !f.is_empty());
    let _state = fields.next();
    if let Some(p) = fields.next() {
        for &b in p {
            if !b.is_ascii_digit() {
                break;
            }
            ppid = ppid.saturating_mul(10).saturating_add(i32::from(b - b'0'));
        }
    }
    (&stat[open + 1..close], ppid)
}

/// SIGPIPEs received and console writes that failed with EPIPE
pub fn counts() -> (u64, u64) {
    (
        SIGPIPES.load(Ordering::Relaxed),
        EPIPES.load(Ordering::Relaxed),
    )
}

/// A console write failed with EPIPE
pub fn note_epipe() {
    EPIPES.fetch_add(1, Ordering::Relaxed);
}

/// Start the `signals` thread; after the -daemon forks, which a thread
/// would not survive. Signals before it wait in the pipe.
pub fn start_writer() {
    let fd = PIPE_READ.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || loop {
            let mut byte = 0u8;
            let r = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if r != 1 {
                return;
            }
            if byte & 0x80 != 0 {
                let mut raw = Raw::new();
                raw.signo = i32::from(byte & 0x7f);
                raw.mono_ns = mono_ns();
                raw.count = if STOP_SIGNALS.contains(&raw.signo) {
                    STOPS.load(Ordering::SeqCst)
                } else {
                    0
                };
                act(&raw, " detail=lost");
                continue;
            }
            let Some(slot) = SLOT.get(usize::from(byte)) else {
                continue;
            };
            if slot.state.load(Ordering::Acquire) != READY {
                continue;
            }
            let raw = unsafe { *slot.raw.get() };
            slot.state.store(FREE, Ordering::Release);
            act(&raw, "");
        });
    if let Err(e) = spawned {
        crate::console_line(
            false,
            format_args!("Warning: signals are not recorded: {}", e),
        );
    }
}

/// Record the signal, then do what diag.md A3 says for it
fn act(raw: &Raw, detail: &str) {
    let signo = raw.signo;
    let record = |action: &str| {
        crate::runs_log::record(
            "signal",
            &format!("{} action={}{}", describe(raw), action, detail),
        )
    };
    match signo {
        libc::SIGTERM | libc::SIGINT | libc::SIGQUIT => {
            if raw.count >= 2 {
                record(&format!("ignored count={}", raw.count));
                tracing::warn!(
                    "Received SIG{} again while stopping; a third stop signal ends the process",
                    name(signo)
                );
            } else if signo == libc::SIGQUIT {
                record("stop count=1 dump=not-implemented");
                request_stop(signo);
            } else {
                record("stop count=1");
                request_stop(signo);
            }
        }
        libc::SIGHUP | libc::SIGUSR2 => {
            record("reopen-log");
            crate::REOPEN_LOG.store(true, Ordering::Relaxed);
            tracing::info!("Received SIG{}, reopening debug.log", name(signo));
        }
        libc::SIGUSR1 => record("none health=not-implemented incident=not-implemented"),
        libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => {
            let ppid = unsafe { libc::getppid() };
            if ppid != 1 && has_terminal() {
                record("stop");
                STOPPED_AT.store(raw.mono_ns, Ordering::Relaxed);
                unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
            } else {
                record(if ppid == 1 {
                    "ignored why=ppid-1"
                } else {
                    "ignored why=no-terminal"
                });
            }
        }
        libc::SIGCONT => {
            let at = STOPPED_AT.swap(0, Ordering::Relaxed);
            if at == 0 || raw.mono_ns < at {
                record("resume stopped_s=-");
            } else {
                let ms = (raw.mono_ns - at) / 1_000_000;
                record(&format!("resume stopped_s={}.{:03}", ms / 1000, ms % 1000));
            }
        }
        _ if DEFAULT_ACTION.contains(&signo) => {
            record("default");
            let code = 128 + signo;
            crate::runs_log::exit(code, &format!("SIG{}: its default action", name(signo)));
            tracing::error!(
                "Received SIG{}, ending with its default action",
                name(signo)
            );
            crate::flush_log();
            if unsafe { libc::getpid() } == 1 {
                // PID 1 is not ended by a signal it has no handler for
                unsafe { libc::_exit(code) }
            }
            unsafe {
                libc::signal(signo, libc::SIG_DFL);
                libc::raise(signo);
                libc::_exit(code)
            }
        }
        _ => record("none"),
    }
}

/// Whether the process has a controlling terminal
fn has_terminal() -> bool {
    let fd = unsafe {
        libc::open(
            c"/dev/tty".as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    unsafe { libc::close(fd) };
    true
}

/// `signo=TERM code=SI_USER pid=.. uid=.. sender=.. comm=".." cmd=".." chain=".."`
fn describe(raw: &Raw) -> String {
    let mut s = format!(
        "signo={} code={}",
        name(raw.signo),
        if raw.signo == 0 {
            "-"
        } else {
            code_name(raw.code)
        }
    );
    if !from_process(raw.code) || raw.signo == 0 {
        s.push_str(" pid=- uid=-");
    } else {
        s.push_str(&format!(" pid={} uid={}", raw.pid, raw.uid));
    }
    let sender = match raw.sender {
        SENDER_READ => "read",
        SENDER_GONE => "gone",
        SENDER_HIDDEN => "hidden",
        SENDER_OUTSIDE => "outside-pid-namespace",
        SENDER_KERNEL => "kernel",
        _ => "not-read",
    };
    if raw.signo == 0 {
        return s;
    }
    s.push_str(" sender=");
    s.push_str(sender);
    if raw.sender == SENDER_READ {
        let chain: Vec<String> = raw.chain[..raw.chain_len]
            .iter()
            .map(|(pid, comm, len)| format!("{}:{}", pid, String::from_utf8_lossy(&comm[..*len])))
            .collect();
        s.push_str(&format!(
            " comm={} cmd={} chain={}",
            crate::runs_log::quote(&String::from_utf8_lossy(&raw.comm[..raw.comm_len])),
            crate::runs_log::quote(&mask_cmdline(&raw.cmdline[..raw.cmdline_len])),
            crate::runs_log::quote(&chain.join(" ")),
        ));
    }
    s
}

/// A sender's command line with no argument's text: the basename of argv[0],
/// then `<arg>` for each argument. An `irondivi-cli` sender keeps its option
/// names (cut at `=`) and its method name; an irondivid sender is masked
/// like any other until an argv allowlist exists.
fn mask_cmdline(cmdline: &[u8]) -> String {
    let mut args = cmdline
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned());
    let Some(first) = args.next() else {
        return "-".into();
    };
    let base = first.rsplit('/').next().unwrap_or("").to_string();
    let cli = base == "irondivi-cli";
    let mut out = vec![base];
    let mut method = false;
    for a in args {
        let word = |s: &str, ok: fn(char) -> bool| !s.is_empty() && s.chars().all(ok);
        if cli && !method && a.starts_with('-') {
            let opt = a.split('=').next().unwrap_or("");
            if word(opt, |c| c.is_ascii_alphanumeric() || c == '-') {
                out.push(opt.to_string());
            } else {
                out.push("<arg>".into());
            }
        } else if cli && !method {
            method = true;
            if word(&a, |c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
                out.push(a);
            } else {
                out.push("<arg>".into());
            }
        } else {
            out.push("<arg>".into());
        }
    }
    out.join(" ")
}

/// A stop signal (TERM, INT, QUIT): to the node once it can take one; a
/// one-shot command ends at once, as before (the default action)
fn request_stop(signo: i32) {
    PENDING.store(signo, Ordering::SeqCst);
    deliver();
}

fn deliver() {
    if ONE_SHOT.load(Ordering::SeqCst) {
        let signo = PENDING.swap(0, Ordering::SeqCst);
        if signo != 0 {
            unsafe {
                libc::signal(signo, libc::SIG_DFL);
                libc::raise(signo);
            }
        }
        return;
    }
    let Some((tx, console)) = SINK.get() else {
        return;
    };
    let signo = PENDING.swap(0, Ordering::SeqCst);
    if signo == 0 {
        return;
    }
    // The stop goes out before anything is written to the console: the
    // terminal may be gone, and the stop must not depend on it (D1)
    let _ = tx.send(());
    crate::runs_log::stop_requested(match signo {
        libc::SIGINT => "signal=INT",
        libc::SIGQUIT => "signal=QUIT",
        _ => "signal=TERM",
    });
    let what = match signo {
        libc::SIGINT => "Ctrl+C",
        libc::SIGQUIT => "SIGQUIT",
        _ => "SIGTERM",
    };
    tracing::info!("Received {}, initiating shutdown...", what);
    if *console {
        crate::console_line(false, format_args!("Received {}, stopping...", what));
    }
}

/// The node's stop channel: a stop signal received before now is delivered
/// here; `console`: a line on the console for each stop
pub fn set_stop_sink(tx: broadcast::Sender<()>, console: bool) {
    let _ = SINK.set((tx, console));
    deliver();
}

/// A one-shot command: a stop signal ends it with its default action
pub fn one_shot() {
    ONE_SHOT.store(true, Ordering::SeqCst);
    deliver();
}

/// A signal's name without `SIG`
pub(crate) fn name(signo: i32) -> &'static str {
    match signo {
        libc::SIGTERM => "TERM",
        libc::SIGINT => "INT",
        libc::SIGHUP => "HUP",
        libc::SIGQUIT => "QUIT",
        libc::SIGUSR1 => "USR1",
        libc::SIGUSR2 => "USR2",
        libc::SIGTSTP => "TSTP",
        libc::SIGTTIN => "TTIN",
        libc::SIGTTOU => "TTOU",
        libc::SIGCONT => "CONT",
        libc::SIGPIPE => "PIPE",
        libc::SIGXCPU => "XCPU",
        libc::SIGXFSZ => "XFSZ",
        libc::SIGALRM => "ALRM",
        libc::SIGVTALRM => "VTALRM",
        libc::SIGPROF => "PROF",
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::SIGPWR => "PWR",
        #[cfg(all(
            any(target_os = "linux", target_os = "android"),
            not(any(
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "sparc",
                target_arch = "sparc64"
            ))
        ))]
        libc::SIGSTKFLT => "STKFLT",
        libc::SIGIO => "IO",
        _ => "other",
    }
}

fn code_name(code: i32) -> &'static str {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    match code {
        libc::SI_USER => "SI_USER",
        libc::SI_TKILL => "SI_TKILL",
        libc::SI_QUEUE => "SI_QUEUE",
        libc::SI_KERNEL => "SI_KERNEL",
        _ => "other",
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    match code {
        0x10001 => "SI_USER",
        0x10002 => "SI_QUEUE",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_senders_arguments_are_masked() {
        assert_eq!(
            mask_cmdline(b"/usr/bin/kill\0-TERM\x001234\0"),
            "kill <arg> <arg>"
        );
        assert_eq!(
            mask_cmdline(b"/home/u/bin/irondivi-cli\0-rpcpassword=zq7x\0-regtest\0sendtoaddress\0DAddr\x001\0"),
            "irondivi-cli -rpcpassword -regtest sendtoaddress <arg> <arg>"
        );
        // A method name that is not one is masked too
        assert_eq!(
            mask_cmdline(b"irondivi-cli\0Some/Path\0x\0"),
            "irondivi-cli <arg> <arg>"
        );
        // An irondivid sender: no allowlist yet, every argument masked
        assert_eq!(
            mask_cmdline(b"/opt/irondivid\0-datadir=/home/u/.divi\0"),
            "irondivid <arg>"
        );
        assert_eq!(mask_cmdline(b""), "-");
    }

    #[test]
    fn stat_lines_give_the_comm_and_the_parent() {
        assert_eq!(
            parse_stat(b"1234 (bash) S 1000 1234 1234"),
            (&b"bash"[..], 1000)
        );
        // A comm with `) ` in it
        assert_eq!(parse_stat(b"7 (a) b) R 1 7 7"), (&b"a) b"[..], 1));
        assert_eq!(parse_stat(b"garbage"), (&b""[..], 0));
    }
}
