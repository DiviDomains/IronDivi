// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A5: fatal signals (SEGV, BUS, ILL, FPE, ABRT, TRAP, SYS) to
//! `diag/crash.log`.
//!
//! The handler writes, with `write(2)` from fixed buffers and nothing that
//! allocates or locks: a `fatal-signal` record (signal, `si_code`,
//! `si_addr`, thread id and name, PC/SP/FP, and for a signal another
//! process sent, `sent=yes` with its pid, uid and comm), a frame-pointer
//! walk bounded by the thread's stack range, the saved `/proc/self/maps`
//! copy and the debug ring (A8). Then it chains to the handler that was
//! there before (std's, so a stack overflow still prints its message),
//! restores the default action and re-raises, so the exit status is the
//! signal's (`_exit(128 + signo)` as PID 1, A3).
//!
//! Each thread the node starts (tasks::thread, the tokio runtime's, main)
//! is entered in a table with its name and stack range; on Linux it gets a
//! 64 KB alternate stack, freed when the thread ends (main's never is).
//!
//! The node is non-dumpable (D5): nothing here reads a refused
//! `/proc/self` file; `maps` and `task/<tid>/comm` are readable.
//!
//! Not done (Revision 16): no `pthread_create` interposition, so threads
//! the node does not start (RocksDB's) have no alternate stack and no
//! range; no filtered stack dump (item 3) and no 32-bit `crash-stack.bin`;
//! no A11 counters; the sender's command line and parents are not read;
//! registers and the walk only on Linux x86_64 and aarch64.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU8, AtomicUsize, Ordering};

use crate::runs_log::RawLine;

const FATAL: [i32; 7] = [
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
    libc::SIGABRT,
    libc::SIGTRAP,
    libc::SIGSYS,
];

/// The pre-opened crash.log (-1: not yet)
static FD: AtomicI32 = AtomicI32::new(-1);
/// The thread now writing a record (0: none)
static CRASHING: AtomicI64 = AtomicI64::new(0);
/// That record is written
static DONE: AtomicBool = AtomicBool::new(false);

/// The handlers that were there before ours, one per FATAL entry
struct Saved(std::cell::UnsafeCell<[std::mem::MaybeUninit<libc::sigaction>; 7]>);
// Written once by install() before the handlers are set, then only read
unsafe impl Sync for Saved {}
static SAVED: Saved = Saved(std::cell::UnsafeCell::new(
    [const { std::mem::MaybeUninit::uninit() }; 7],
));
static INSTALLED: AtomicBool = AtomicBool::new(false);

const THREADS: usize = 512;
const NAME: usize = 16;

/// One thread the node started; slot 0 is main
struct Entry {
    tid: AtomicI64,
    lo: AtomicUsize,
    hi: AtomicUsize,
    name: [AtomicU8; NAME],
}

impl Entry {
    const fn new() -> Entry {
        Entry {
            tid: AtomicI64::new(0),
            lo: AtomicUsize::new(0),
            hi: AtomicUsize::new(0),
            name: [const { AtomicU8::new(0) }; NAME],
        }
    }
}

static TABLE: [Entry; THREADS] = [const { Entry::new() }; THREADS];

/// The alternate stack's size (A5 "Alternate stacks")
#[cfg(any(target_os = "linux", target_os = "android"))]
const ALT_STACK: usize = 64 * 1024;

fn tid() -> i64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        unsafe { libc::syscall(libc::SYS_gettid) as i64 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        unsafe { libc::pthread_self() as usize as i64 }
    }
}

/// First thing in main: the main thread's entry and alternate stack, then
/// the handlers (std's are already installed, and are kept to chain to)
pub fn install() {
    let slot = &TABLE[0];
    fill(slot, tid(), b"main");
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // Never freed: main ends through _exit or std's clean-up, which
        // unmaps only its own stack (A5 "The main thread")
        if let Some((stack, _)) = alt_stack() {
            std::mem::forget(stack);
        }
    }
    for (i, &signo) in FATAL.iter().enumerate() {
        unsafe {
            let mut new: libc::sigaction = std::mem::zeroed();
            new.sa_sigaction = on_fatal as *const () as usize;
            new.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            libc::sigemptyset(&mut new.sa_mask);
            let saved = (*SAVED.0.get())[i].as_mut_ptr();
            if libc::sigaction(signo, &new, saved) != 0 {
                std::ptr::write(saved, std::mem::zeroed());
            }
        }
    }
    INSTALLED.store(true, Ordering::Release);
}

/// Open `<data_dir>/diag/crash.log` for the handler (diag/ exists: runs.log
/// made it)
pub fn open(data_dir: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let path = data_dir.join("diag").join("crash.log");
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd >= 0 {
        let old = FD.swap(fd, Ordering::AcqRel);
        if old >= 0 {
            unsafe { libc::close(old) };
        }
    }
}

fn fill(slot: &Entry, tid: i64, name: &[u8]) {
    for (i, b) in slot.name.iter().enumerate() {
        b.store(name.get(i).copied().unwrap_or(0), Ordering::Relaxed);
    }
    let (lo, hi) = stack_range();
    slot.lo.store(lo, Ordering::Relaxed);
    slot.hi.store(hi, Ordering::Relaxed);
    slot.tid.store(tid, Ordering::Release);
}

/// This thread's stack, from pthread (0, 0 where it is not read)
fn stack_range() -> (usize, usize) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &mut attr) != 0 {
            return (0, 0);
        }
        let mut addr: *mut libc::c_void = std::ptr::null_mut();
        let mut size: libc::size_t = 0;
        let ok = libc::pthread_attr_getstack(&attr, &mut addr, &mut size) == 0;
        libc::pthread_attr_destroy(&mut attr);
        if ok {
            return (addr as usize, addr as usize + size);
        }
    }
    (0, 0)
}

/// A thread's entry and alternate stack, until it is dropped
pub struct Entered {
    slot: Option<usize>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    stack: Option<(AltStack, libc::stack_t)>,
}

/// Enter the calling thread under `name`; keep the result until it ends
pub fn enter_thread(name: &str) -> Entered {
    let me = tid();
    let slot = (1..THREADS).find(|&i| {
        TABLE[i]
            .tid
            .compare_exchange(0, -1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    });
    if let Some(i) = slot {
        fill(&TABLE[i], me, name.as_bytes());
    }
    Entered {
        slot,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        stack: alt_stack(),
    }
}

impl Drop for Entered {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some((stack, previous)) = self.stack.take() {
            // Back to std's stack, then ours goes
            unsafe { libc::sigaltstack(&previous, std::ptr::null_mut()) };
            drop(stack);
        }
        if let Some(i) = self.slot {
            TABLE[i].tid.store(0, Ordering::Release);
        }
    }
}

/// A mapped alternate stack with a guard page below it
#[cfg(any(target_os = "linux", target_os = "android"))]
struct AltStack {
    base: *mut libc::c_void,
    len: usize,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for AltStack {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base, self.len) };
    }
}

/// Map a 64 KB alternate stack and install it; the one it replaced is
/// returned for the drop to put back
#[cfg(any(target_os = "linux", target_os = "android"))]
fn alt_stack() -> Option<(AltStack, libc::stack_t)> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let len = ALT_STACK + page;
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return None;
    }
    let stack = AltStack { base, len };
    unsafe { libc::mprotect(base, page, libc::PROT_NONE) };
    let new = libc::stack_t {
        ss_sp: unsafe { base.cast::<u8>().add(page) }.cast(),
        ss_flags: 0,
        ss_size: ALT_STACK,
    };
    let mut previous: libc::stack_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaltstack(&new, &mut previous) } != 0 {
        return None;
    }
    Some((stack, previous))
}

// The /proc/self/maps copy (Linux): two buffers, the published one named by
// MAPS_AT; refreshed at start and by the health tick
#[cfg(any(target_os = "linux", target_os = "android"))]
mod maps {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const BYTES: usize = 256 * 1024;
    struct Buf(std::cell::UnsafeCell<[[u8; BYTES]; 2]>);
    // The writer holds WRITER and fills the unpublished buffer only
    unsafe impl Sync for Buf {}
    static BUF: Buf = Buf(std::cell::UnsafeCell::new([[0; BYTES]; 2]));
    /// Published buffer index in bit 0, its length above
    static AT: AtomicUsize = AtomicUsize::new(0);
    static WRITER: Mutex<()> = Mutex::new(());

    pub fn refresh() {
        let Ok(_guard) = WRITER.lock() else {
            return;
        };
        let next = (AT.load(Ordering::Acquire) & 1) ^ 1;
        let buf = unsafe { &mut (*BUF.0.get())[next] };
        let me = unsafe { libc::getpid() };
        let len = crate::signals::read_proc(me, b"maps\0", buf).unwrap_or(0);
        AT.store(len << 1 | next, Ordering::Release);
    }

    /// The published copy; signal-safe
    pub fn get() -> &'static [u8] {
        let at = AT.load(Ordering::Acquire);
        let buf = unsafe { &(*BUF.0.get())[at & 1] };
        &buf[..(at >> 1).min(BYTES)]
    }
}

/// Refresh the `/proc/self/maps` copy the handler writes (start, health tick)
pub fn refresh_maps() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    maps::refresh();
}

fn write_all(fd: i32, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
        bytes = &bytes[n as usize..];
    }
}

fn signal_name(signo: i32) -> &'static str {
    match signo {
        libc::SIGSEGV => "SEGV",
        libc::SIGBUS => "BUS",
        libc::SIGILL => "ILL",
        libc::SIGFPE => "FPE",
        libc::SIGABRT => "ABRT",
        libc::SIGTRAP => "TRAP",
        libc::SIGSYS => "SYS",
        _ => "other",
    }
}

/// Printable ASCII of a name, `?` for the rest, up to its NUL or newline
fn text_of(bytes: &[u8], out: &mut [u8; NAME]) -> usize {
    let mut n = 0;
    for &b in bytes.iter().take(NAME) {
        if b == 0 || b == b'\n' {
            break;
        }
        out[n] = if b.is_ascii_graphic() { b } else { b'?' };
        n += 1;
    }
    n
}

/// The calling thread's table entry
fn entry_of(me: i64) -> Option<&'static Entry> {
    // Main's tid is the pid; after the daemon forks it is not the one entered
    if me == i64::from(unsafe { libc::getpid() }) {
        return Some(&TABLE[0]);
    }
    TABLE
        .iter()
        .skip(1)
        .find(|e| e.tid.load(Ordering::Acquire) == me)
}

/// PC, SP and FP from the signal's context
#[allow(unused_variables)]
fn registers(ctx: *mut libc::c_void) -> Option<(u64, u64, u64)> {
    if ctx.is_null() {
        return None;
    }
    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
    unsafe {
        let uc = &*(ctx as *const libc::ucontext_t);
        let g = &uc.uc_mcontext.gregs;
        return Some((
            g[libc::REG_RIP as usize] as u64,
            g[libc::REG_RSP as usize] as u64,
            g[libc::REG_RBP as usize] as u64,
        ));
    }
    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
    unsafe {
        let uc = &*(ctx as *const libc::ucontext_t);
        let m = &uc.uc_mcontext;
        return Some((m.pc as u64, m.sp as u64, m.regs[29] as u64));
    }
    #[allow(unreachable_code)]
    None
}

/// The handler. Async-signal-safe: fixed buffers, write(2), atomics.
extern "C" fn on_fatal(signo: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let me = tid();
    match CRASHING.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            write_record(signo, info, ctx, me);
            DONE.store(true, Ordering::Release);
            chain(signo, info, ctx);
        }
        // The handler itself faulted, or std's handler aborted: straight on
        Err(t) if t == me => {}
        Err(_) => {
            // Another thread is writing its record: 2 s at most
            for _ in 0..200 {
                if DONE.load(Ordering::Acquire) {
                    break;
                }
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 10_000_000,
                };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            }
        }
    }
    unsafe {
        libc::signal(signo, libc::SIG_DFL);
        if libc::getpid() == 1 {
            // PID 1 is not ended by a signal it has no handler for (A3)
            libc::_exit(128 + signo);
        }
        let sent = info.is_null() || (*info).si_code <= 0;
        if sent {
            // Pending until the handler returns; a fault instead repeats
            // on return and meets the default action
            libc::raise(signo);
        }
    }
}

/// Call the handler that was installed before ours (std's)
fn chain(signo: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    if !INSTALLED.load(Ordering::Acquire) {
        return;
    }
    let Some(i) = FATAL.iter().position(|&s| s == signo) else {
        return;
    };
    let prev = unsafe { (*SAVED.0.get())[i].assume_init_ref() };
    let h = prev.sa_sigaction;
    if h == libc::SIG_DFL || h == libc::SIG_IGN || h == on_fatal as *const () as usize {
        return;
    }
    unsafe {
        if prev.sa_flags & libc::SA_SIGINFO != 0 {
            let f: extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) =
                std::mem::transmute(h);
            f(signo, info, ctx);
        } else {
            let f: extern "C" fn(i32) = std::mem::transmute(h);
            f(signo);
        }
    }
}

fn write_record(signo: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void, me: i64) {
    let fd = FD.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    let mut line = RawLine::new("fatal-signal");
    line.text(" run=")
        .num(crate::runs_log::run_number() as i64)
        .text(" pid=")
        .num(i64::from(unsafe { libc::getpid() }))
        .text(" signal=")
        .text(signal_name(signo));
    let (code, addr, pid, uid) = if info.is_null() {
        (0, 0, 0, 0)
    } else {
        unsafe {
            let i = &*info;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let addr = i.si_addr() as usize as u64;
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let addr = i.si_addr as usize as u64;
            (i.si_code, addr, i.si_pid(), i.si_uid())
        }
    };
    line.text(" code=").num(i64::from(code)).text(" addr=").hex(addr);
    line.text(" tid=").num(me).text(" thread=\"");
    let entry = entry_of(me);
    let mut name = [0u8; NAME];
    let n = match entry {
        Some(e) => {
            let mut raw = [0u8; NAME];
            for (i, b) in e.name.iter().enumerate() {
                raw[i] = b.load(Ordering::Relaxed);
            }
            text_of(&raw, &mut name)
        }
        None => foreign_name(me, &mut name),
    };
    line.text(std::str::from_utf8(&name[..n]).unwrap_or("?"))
        .text(if entry.is_some() { "\"" } else { "\" foreign=yes" });
    let regs = registers(ctx);
    match regs {
        Some((pc, sp, fp)) => {
            line.text(" pc=").hex(pc).text(" sp=").hex(sp).text(" fp=").hex(fp);
        }
        None => {
            line.text(" pc=- sp=- fp=-");
        }
    }
    let me_pid = unsafe { libc::getpid() };
    if crate::signals::from_process(code) && pid != me_pid {
        line.text(" sent=yes si_pid=")
            .num(i64::from(pid))
            .text(" si_uid=")
            .num(i64::from(uid))
            .text(" comm=\"");
        let n = sender_comm(pid, &mut name);
        line.text(std::str::from_utf8(&name[..n]).unwrap_or("?"))
            .text("\"");
    } else {
        line.text(" sent=no");
    }
    line.write_to(fd);

    // The frame walk, inside the stack range recorded at thread start
    if let (Some((pc, _, fp)), Some(e)) = (regs, entry) {
        let lo = e.lo.load(Ordering::Relaxed);
        let hi = e.hi.load(Ordering::Relaxed);
        let mut l = RawLine::new("frames");
        l.text(" lo=").hex(lo as u64).text(" hi=").hex(hi as u64);
        l.write_to(fd);
        let mut frame = RawLine::new("frame");
        frame.text(" #0 ").hex(pc);
        frame.write_to(fd);
        let mut fp = fp as usize;
        for i in 1..128 {
            if lo == 0 || fp < lo || fp + 16 > hi || !fp.is_multiple_of(8) {
                break;
            }
            let (next, ret) = unsafe { (*(fp as *const usize), *((fp + 8) as *const usize)) };
            if ret == 0 {
                break;
            }
            let mut frame = RawLine::new("frame");
            frame.text(" #").num(i).text(" ").hex(ret as u64);
            frame.write_to(fd);
            if next <= fp {
                break;
            }
            fp = next;
        }
    } else {
        let mut l = RawLine::new("frames");
        l.text(" none why=")
            .text(if entry.is_none() { "unknown-thread" } else { "no-registers" });
        l.write_to(fd);
    }

    write_all(fd, b"maps:\n");
    #[cfg(any(target_os = "linux", target_os = "android"))]
    write_all(fd, maps::get());
    write_all(fd, b"debug ring (A8, oldest first):\n");
    crate::log_delivery::RING.for_each(|l| {
        write_all(fd, l);
        if l.last() != Some(&b'\n') {
            write_all(fd, b"\n");
        }
    });
    let mut end = RawLine::new("fatal-signal-end");
    end.text(" run=").num(crate::runs_log::run_number() as i64);
    end.write_to(fd);
}

/// A thread the node did not start: its comm (Linux)
#[allow(unused_variables)]
fn foreign_name(me: i64, out: &mut [u8; NAME]) -> usize {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut leaf = [0u8; 40];
        let mut n = 0;
        for &b in b"task/" {
            leaf[n] = b;
            n += 1;
        }
        let mut digits = [0u8; 20];
        let mut d = digits.len();
        let mut v = me.unsigned_abs();
        loop {
            d -= 1;
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for &b in &digits[d..] {
            leaf[n] = b;
            n += 1;
        }
        for &b in b"/comm\0" {
            leaf[n] = b;
            n += 1;
        }
        let mut buf = [0u8; 64];
        if let Ok(len) = crate::signals::read_proc(unsafe { libc::getpid() }, &leaf[..n], &mut buf)
        {
            return text_of(&buf[..len], out);
        }
    }
    out[0] = b'-';
    1
}

/// The sender's comm (Linux); `-` when it is gone or hidden
#[allow(unused_variables)]
fn sender_comm(pid: i32, out: &mut [u8; NAME]) -> usize {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut buf = [0u8; 64];
        if pid > 0 {
            if let Ok(len) = crate::signals::read_proc(pid, b"comm\0", &mut buf) {
                let n = text_of(&buf[..len], out);
                if n > 0 {
                    return n;
                }
            }
        }
    }
    out[0] = b'-';
    1
}

/// The global allocator: System, with a line in crash.log when it fails
/// (the abort that follows is then recorded by the handler)
pub struct Alloc;

fn alloc_null(size: usize) {
    let mut line = RawLine::new("alloc-null");
    line.text(" size=").num(size as i64);
    line.write_to(FD.load(Ordering::Acquire));
}

unsafe impl std::alloc::GlobalAlloc for Alloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let p = unsafe { std::alloc::System.alloc(layout) };
        if p.is_null() {
            alloc_null(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        let p = unsafe { std::alloc::System.alloc_zeroed(layout) };
        if p.is_null() {
            alloc_null(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new: usize) -> *mut u8 {
        let p = unsafe { std::alloc::System.realloc(ptr, layout, new) };
        if p.is_null() {
            alloc_null(new);
        }
        p
    }
}

/// Debug builds on regtest only: `IRONDIVI_TEST_CRASH` asks for a SEGV
/// (`segv`), an abort (`abort`) or a Rust thread's stack overflow
/// (`overflow`) once the node runs. (The plan's `crashtest` build feature;
/// Revision 16)
pub fn start_test_crash(regtest: bool) {
    if !cfg!(debug_assertions) || !regtest {
        return;
    }
    let Ok(what) = std::env::var("IRONDIVI_TEST_CRASH") else {
        return;
    };
    let wait = std::time::Duration::from_secs(2);
    let _ = crate::tasks::thread("test-crash", crate::tasks::Kind::Supervised, move || {
        std::thread::sleep(wait);
        match what.as_str() {
            "segv" => unsafe {
                std::ptr::null_mut::<u64>().write_volatile(1);
            },
            "abort" => std::process::abort(),
            "overflow" => {
                std::hint::black_box(recurse(0));
            }
            _ => {}
        }
    });
}

#[allow(unconditional_recursion)]
fn recurse(n: u64) -> u64 {
    let a = std::hint::black_box([n; 64]);
    recurse(n + 1).wrapping_add(a[3])
}

/// The verdict a `fatal-signal` record in crash.log gives a run that left
/// its marker: `crash signal=<S>`, or `sent-by comm=<c>`
pub fn verdict_for(crash_log: &std::path::Path, run: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(crash_log).ok()?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(4 << 20)));
    let mut bytes = Vec::new();
    let _ = f.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes);
    let tag = format!(" fatal-signal run={} ", run);
    let line = text.lines().rev().find(|l| l.contains(&tag))?;
    let field = |k: &str| {
        line.split(' ')
            .find_map(|f| f.strip_prefix(k))
            .map(|v| v.trim_matches('"').to_string())
    };
    let signal = field("signal=").unwrap_or_else(|| "-".into());
    Some(if line.contains(" sent=yes ") {
        format!(
            "sent-by comm={} signal={}",
            field("comm=").unwrap_or_else(|| "-".into()),
            signal
        )
    } else {
        format!("crash signal={}", signal)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_crash_record_gives_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crash.log");
        std::fs::write(
            &path,
            "2026-10-31T00:00:00.000000Z mono=1.0 fatal-signal run=3 pid=9 signal=SEGV code=1 \
             addr=0x0 tid=9 thread=\"main\" pc=0x1 sp=0x2 fp=0x3 sent=no\n\
             2026-10-31T00:00:00.000000Z mono=1.0 fatal-signal run=4 pid=9 signal=ABRT code=0 \
             addr=0x0 tid=9 thread=\"main\" pc=0x1 sp=0x2 fp=0x3 sent=yes si_pid=7 si_uid=0 \
             comm=\"kill\"\n",
        )
        .unwrap();
        assert_eq!(verdict_for(&path, 3).as_deref(), Some("crash signal=SEGV"));
        assert_eq!(
            verdict_for(&path, 4).as_deref(),
            Some("sent-by comm=kill signal=ABRT")
        );
        assert_eq!(verdict_for(&path, 5), None);
    }

    #[test]
    fn names_are_printable() {
        let mut out = [0u8; NAME];
        let n = text_of(b"a b\x01c\n", &mut out);
        assert_eq!(&out[..n], b"a?b?c");
    }
}
