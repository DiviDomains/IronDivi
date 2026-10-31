// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Small helpers every collector uses: byte escaping, bounded external
//! commands, bounded file reads and hashing.

use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bytes as text: valid UTF-8 is kept, every byte of an invalid sequence is
/// written `\xNN` (B2: output is bytes, never dropped)
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let good = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..good]).unwrap_or(""));
                let bad = e.error_len().unwrap_or(rest.len() - good);
                for b in &rest[good..good + bad] {
                    out.push_str(&format!("\\x{:02x}", b));
                }
                rest = &rest[good + bad..];
            }
        }
    }
}

/// The result of one external command
pub struct CmdOut {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Exit code, or `None` when killed by a signal or never started
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    /// The spawn error, verbatim (`No such file or directory`, `Exec format
    /// error`, …), when the command never ran
    pub spawn_error: Option<String>,
}

impl CmdOut {
    pub fn ok(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
    pub fn text(&self) -> String {
        escape_bytes(&self.stdout)
    }
    /// One line saying how the command ended, for the output files
    pub fn status_line(&self) -> String {
        if let Some(e) = &self.spawn_error {
            return format!("not run: {}", e);
        }
        if self.timed_out {
            return "TIMEOUT (killed)".to_string();
        }
        match (self.code, self.signal) {
            (Some(c), _) => format!("exit {}", c),
            (None, Some(s)) => format!("killed by signal {}", s),
            _ => "unknown end".to_string(),
        }
    }
}

/// Is `name` an executable on PATH (or an absolute path that exists)?
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/sbin:/usr/bin:/sbin:/bin".into());
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    for extra in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin", "/opt/homebrew/bin"] {
        dirs.push(PathBuf::from(extra));
    }
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

/// Run an external command with a closed stdin, `LC_ALL=C` and a timeout;
/// output is capped at `cap` bytes per stream
pub fn run_cmd(prog: &str, args: &[&str], timeout: Duration, cap: usize) -> CmdOut {
    let mut cmd = Command::new(prog);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("SYSTEMD_PAGER", "")
        .env("PAGER", "cat")
        .env("SYSTEMD_COLORS", "0");
    run_command(cmd, timeout, cap)
}

pub fn run_command(mut cmd: Command, timeout: Duration, cap: usize) -> CmdOut {
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return CmdOut {
                stdout: vec![],
                stderr: vec![],
                code: None,
                signal: None,
                timed_out: false,
                spawn_error: Some(e.to_string()),
            }
        }
    };
    let reader = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let mut chunk = [0u8; 65536];
                loop {
                    match r.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if buf.len() < cap {
                                let take = n.min(cap - buf.len());
                                buf.extend_from_slice(&chunk[..take]);
                            }
                        }
                    }
                }
            }
            buf
        })
    };
    let out_t = reader(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err_t = reader(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(_) => break None,
        }
        if start.elapsed() > timeout {
            timed_out = true;
            let _ = child.kill();
            // Bounded reap: a child in D state may never go
            let t = Instant::now();
            let mut st = None;
            while t.elapsed() < Duration::from_secs(5) {
                if let Ok(Some(s)) = child.try_wait() {
                    st = Some(s);
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            break st;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // A killed child's grandchildren may hold the pipes open; do not wait
    // for ever on them
    let join = |t: std::thread::JoinHandle<Vec<u8>>| {
        let s = Instant::now();
        while !t.is_finished() && s.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if t.is_finished() {
            t.join().unwrap_or_default()
        } else {
            b"[output reader abandoned]".to_vec()
        }
    };
    let stdout = join(out_t);
    let stderr = join(err_t);
    use std::os::unix::process::ExitStatusExt;
    CmdOut {
        stdout,
        stderr,
        code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()),
        timed_out,
        spawn_error: None,
    }
}

/// Short form: run with a 10 s timeout and a 4 MB cap
pub fn cmd(prog: &str, args: &[&str]) -> CmdOut {
    run_cmd(prog, args, Duration::from_secs(10), 4 << 20)
}

/// Read a whole small file (capped), as escaped text; `None` when unreadable
pub fn read_small(path: &Path, cap: usize) -> Option<String> {
    read_bytes_capped(path, cap).ok().map(|b| escape_bytes(&b))
}

pub fn read_bytes_capped(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(cap as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// The last `n` bytes of a file, starting at a line boundary when cut
pub fn read_tail(path: &Path, n: u64) -> std::io::Result<(Vec<u8>, bool)> {
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let cut = len > n;
    if cut {
        f.seek(SeekFrom::Start(len - n))?;
    }
    let mut buf = Vec::new();
    f.take(n).read_to_end(&mut buf)?;
    if cut {
        if let Some(p) = buf.iter().position(|&b| b == b'\n') {
            buf.drain(..=p);
        }
    }
    Ok((buf, cut))
}

/// The error of an I/O call as the OS words it (kept verbatim in the output)
pub fn io_err(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("{} (errno {})", e, code),
        None => e.to_string(),
    }
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Seconds since the epoch as RFC3339 UTC
pub fn rfc3339(secs: i64) -> String {
    // civil-from-days (Howard Hinnant)
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn mtime_secs(md: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    md.mtime()
}

pub fn uid() -> u32 {
    unsafe { libc::getuid() }
}
pub fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// User name for a uid from the password database, if any
pub fn user_name(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; 16384];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut res,
        )
    };
    if rc != 0 || res.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

/// Home directory for a uid from the password database, if any
pub fn user_home(uid: u32) -> Option<PathBuf> {
    let mut buf = vec![0u8; 16384];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut res,
        )
    };
    if rc != 0 || res.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Some(PathBuf::from(dir.to_string_lossy().into_owned()))
}

/// Human-readable byte count
pub fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", n)
    } else {
        format!("{:.1} {}", v, U[i])
    }
}

/// Free and total bytes, free and total inodes of the filesystem holding `p`
pub fn statvfs(p: &Path) -> Option<(u64, u64, u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let f = s.f_frsize as u64;
    Some((
        s.f_bavail as u64 * f,
        s.f_blocks as u64 * f,
        s.f_favail as u64,
        s.f_files as u64,
    ))
}

pub fn is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_invalid_utf8_only() {
        assert_eq!(escape_bytes(b"ok \xff\xfe end"), "ok \\xff\\xfe end");
        assert_eq!(escape_bytes("é".as_bytes()), "é");
    }

    #[test]
    fn rfc3339_epoch() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn cmd_times_out() {
        let o = run_cmd("sleep", &["5"], Duration::from_millis(200), 1024);
        assert!(o.timed_out);
        let o = run_cmd("/nonexistent-diag-test", &[], Duration::from_secs(1), 1024);
        assert!(o.spawn_error.is_some());
    }
}
