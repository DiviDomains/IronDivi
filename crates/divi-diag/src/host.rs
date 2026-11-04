// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B6.2 `irondivi-cli diag --host <container>`: the host's half of a
//! container's story, run on the container host.
//!
//! Built for Docker and for the LXC family (LXD, Incus, plain LXC and
//! Proxmox `pct`, in `host/lxc.rs`); the runtime is found by asking each in
//! turn. The WSL and Docker Desktop hosts are not built; the summary inside
//! the container still prints their commands (§7.2 L3).
//!
//! What it collects for Docker: `docker inspect` of the container, the runtime's
//! events for it since it started (kill signals, die, stop, oom), the host
//! kernel log lines about it (OOM kills, seccomp audit records), the host's
//! memory and the storage under Docker's root. From these it names how the
//! container ended, the one thing the node inside cannot see when the end
//! was a SIGKILL or a seccomp kill: docker stop (SIGTERM, then SIGKILL after
//! the timeout), docker kill, the memory limit, a seccomp profile, or a kill
//! from outside the runtime.
//!
//! The container's names, ids, host name, addresses and network names are
//! added to §6.2's known values before anything is collected. The package is
//! scanned (§6.3) and reviewed (§8.3) like any other. Not yet: the shared
//! ticket that pairs it with the container's own package.

use crate::redact::{Known, Redactor};
use crate::scanner::{self, Scanner};
use crate::util;
use crate::{runner, Options};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

mod lxc;

const CAP: usize = 4 << 20;

/// The container's end as `docker inspect` reports it
#[derive(Debug, Default, Clone)]
pub struct State {
    pub status: String,
    pub exit_code: i64,
    pub oom_killed: bool,
    /// HostConfig.Memory, bytes; 0 = no limit
    pub memory_limit: u64,
}

/// One runtime event for the container
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub action: String,
    pub signal: Option<i32>,
    pub exit_code: Option<i64>,
    pub time_ns: i64,
}

/// A kernel seccomp audit record (type=1326): the call and its arch
#[derive(Debug, Clone, PartialEq)]
pub struct Audit {
    pub syscall: u32,
    pub arch: String,
    pub sig: i32,
}

pub fn signal_name(n: i32) -> String {
    let s = match n {
        1 => "HUP",
        2 => "INT",
        3 => "QUIT",
        4 => "ILL",
        6 => "ABRT",
        7 => "BUS",
        8 => "FPE",
        9 => "KILL",
        10 => "USR1",
        11 => "SEGV",
        12 => "USR2",
        13 => "PIPE",
        14 => "ALRM",
        15 => "TERM",
        31 => "SYS",
        _ => return format!("signal {n}"),
    };
    format!("SIG{s}")
}

fn parse_signal(s: &str) -> Option<i32> {
    if let Ok(n) = s.parse() {
        return Some(n);
    }
    let name = s.trim_start_matches("SIG");
    (1..=31).find(|&n| signal_name(n) == format!("SIG{name}"))
}

/// The system calls a node makes that a seccomp profile could forbid
pub fn syscall_name(arch: &str, n: u32) -> Option<&'static str> {
    let x86_64: &[(u32, &str)] = &[
        (0, "read"),
        (1, "write"),
        (3, "close"),
        (8, "lseek"),
        (9, "mmap"),
        (10, "mprotect"),
        (11, "munmap"),
        (12, "brk"),
        (16, "ioctl"),
        (17, "pread64"),
        (18, "pwrite64"),
        (35, "nanosleep"),
        (39, "getpid"),
        (41, "socket"),
        (42, "connect"),
        (49, "bind"),
        (50, "listen"),
        (56, "clone"),
        (62, "kill"),
        (72, "fcntl"),
        (73, "flock"),
        (74, "fsync"),
        (75, "fdatasync"),
        (82, "rename"),
        (87, "unlink"),
        (158, "arch_prctl"),
        (200, "tkill"),
        (202, "futex"),
        (228, "clock_gettime"),
        (230, "clock_nanosleep"),
        (232, "epoll_wait"),
        (234, "tgkill"),
        (257, "openat"),
        (262, "newfstatat"),
        (263, "unlinkat"),
        (281, "epoll_pwait"),
        (285, "fallocate"),
        (288, "accept4"),
        (302, "prlimit64"),
        (306, "syncfs"),
        (316, "renameat2"),
        (318, "getrandom"),
        (326, "copy_file_range"),
        (334, "rseq"),
        (425, "io_uring_setup"),
        (426, "io_uring_enter"),
        (435, "clone3"),
    ];
    let aarch64: &[(u32, &str)] = &[
        (25, "fcntl"),
        (29, "ioctl"),
        (32, "flock"),
        (35, "unlinkat"),
        (38, "renameat"),
        (47, "fallocate"),
        (56, "openat"),
        (57, "close"),
        (62, "lseek"),
        (63, "read"),
        (64, "write"),
        (67, "pread64"),
        (68, "pwrite64"),
        (82, "fsync"),
        (83, "fdatasync"),
        (98, "futex"),
        (113, "clock_gettime"),
        (115, "clock_nanosleep"),
        (129, "kill"),
        (131, "tgkill"),
        (198, "socket"),
        (203, "connect"),
        (214, "brk"),
        (215, "munmap"),
        (220, "clone"),
        (222, "mmap"),
        (226, "mprotect"),
        (261, "prlimit64"),
        (276, "renameat2"),
        (278, "getrandom"),
        (293, "rseq"),
        (435, "clone3"),
    ];
    let table = match arch {
        "c000003e" => x86_64,
        "c00000b7" => aarch64,
        _ => return None,
    };
    table.iter().find(|(k, _)| *k == n).map(|(_, v)| *v)
}

/// `type=1326 ... sig=31 arch=c000003e syscall=75 ...`
pub fn parse_audit(line: &str) -> Option<Audit> {
    if !line.contains("type=1326") {
        return None;
    }
    let field = |k: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(k).map(str::to_string))
    };
    Some(Audit {
        syscall: field("syscall=")?.parse().ok()?,
        arch: field("arch=").unwrap_or_default(),
        sig: field("sig=").and_then(|s| s.parse().ok()).unwrap_or(0),
    })
}

/// One `docker events --format '{{json .}}'` line
pub fn parse_event(line: &str) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let action = v
        .get("Action")
        .or_else(|| v.get("status"))?
        .as_str()?
        .to_string();
    let attrs = v.pointer("/Actor/Attributes");
    let attr = |k: &str| attrs.and_then(|a| a.get(k)).and_then(|s| s.as_str());
    let time_ns = v
        .get("timeNano")
        .and_then(|t| t.as_i64())
        .or_else(|| {
            v.get("time")
                .and_then(|t| t.as_i64())
                .map(|t| t * 1_000_000_000)
        })
        .unwrap_or(0);
    Some(Event {
        // "exec_start: sh -c …" carries a command line: the action word only
        action: action.split(':').next().unwrap_or("").trim().to_string(),
        signal: attr("signal").and_then(parse_signal),
        exit_code: attr("exitCode").and_then(|s| s.parse().ok()),
        time_ns,
    })
}

/// The syscall names a seccomp profile (HostConfig.SecurityOpt
/// `seccomp=<json>`) kills or traps on
pub fn profile_kills(security_opt: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for o in security_opt {
        let Some(js) = o.strip_prefix("seccomp=") else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(js) else {
            continue;
        };
        for rule in v
            .get("syscalls")
            .and_then(|s| s.as_array())
            .into_iter()
            .flatten()
        {
            let action = rule.get("action").and_then(|a| a.as_str()).unwrap_or("");
            if !matches!(
                action,
                "SCMP_ACT_KILL"
                    | "SCMP_ACT_KILL_PROCESS"
                    | "SCMP_ACT_KILL_THREAD"
                    | "SCMP_ACT_TRAP"
            ) {
                continue;
            }
            for n in rule
                .get("names")
                .and_then(|n| n.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(n) = n.as_str() {
                    out.push(n.to_string());
                }
            }
        }
    }
    out
}

/// How the container ended, in one line (B6.2)
pub fn verdict(
    st: &State,
    events: &[Event],
    audit: Option<&Audit>,
    profile: &[String],
    host_oom_kill: bool,
) -> String {
    if st.status == "running" || st.status == "restarting" || st.status == "paused" {
        return format!("the container is {}: it has not ended", st.status);
    }
    if st.status == "created" {
        return "the container was created and never started".into();
    }
    let code = st.exit_code;
    let oom = if st.oom_killed {
        "OOMKilled=true"
    } else {
        "OOMKilled=false"
    };
    // a seccomp kill: SIGSYS, exit 128+31, or the kernel's audit record
    if code == 159 || audit.is_some_and(|a| a.sig == 31) {
        let mut v = format!("killed by seccomp (SIGSYS, exit {code})");
        match audit {
            Some(a) => {
                let name = syscall_name(&a.arch, a.syscall).unwrap_or("not in diag's table");
                v.push_str(&format!(
                    ": system call {} ({name}) is forbidden by the container's seccomp profile (kernel audit record)",
                    a.syscall
                ));
            }
            None if !profile.is_empty() => v.push_str(&format!(
                ": the container's seccomp profile kills on {}; no kernel audit record names the call",
                profile.join(", ")
            )),
            None => v.push_str(": a system call the container's seccomp profile forbids; no kernel audit record names it"),
        }
        v.push_str(&format!("; not a memory-limit kill ({oom})"));
        return v;
    }
    if st.oom_killed || events.iter().any(|e| e.action == "oom") {
        let lim = if st.memory_limit > 0 {
            format!(", memory limit {} MB", st.memory_limit >> 20)
        } else {
            String::new()
        };
        return format!("killed at the container's memory limit (exit {code}, {oom}{lim})");
    }
    let kills: Vec<&Event> = events.iter().filter(|e| e.action == "kill").collect();
    let stopped = events.iter().any(|e| e.action == "stop");
    let first_soft = kills.iter().find(|e| e.signal.is_some_and(|s| s != 9));
    let hard = kills.iter().find(|e| e.signal == Some(9));
    let how = if stopped {
        "docker stop"
    } else {
        "docker kill"
    };
    match (first_soft, hard) {
        (Some(s), Some(k)) if k.time_ns >= s.time_ns => {
            let secs = (k.time_ns - s.time_ns + 500_000_000) / 1_000_000_000;
            return format!(
                "stopped by the container runtime ({how}: {}, then SIGKILL after {secs} s); exit {code}; not a memory-limit kill ({oom})",
                signal_name(s.signal.unwrap_or(15))
            );
        }
        (Some(s), _) => {
            let how_end = if code == 0 {
                "the node stopped cleanly, exit 0".to_string()
            } else {
                format!("exit {code}")
            };
            return format!(
                "stopped by the container runtime ({how}: {}); {how_end}",
                signal_name(s.signal.unwrap_or(15))
            );
        }
        (None, Some(_)) => {
            return format!(
                "killed by the container runtime ({how}: SIGKILL with no time to stop); exit {code}; not a memory-limit kill ({oom})"
            );
        }
        (None, None) => {}
    }
    if code == 137 {
        return if host_oom_kill {
            format!("SIGKILL from the host kernel's OOM killer (exit 137, kernel log; {oom}: the host ran out of memory, not the container's limit)")
        } else {
            format!("SIGKILL from outside the container runtime (exit 137, no runtime kill event, {oom}): kill -9 on the host, or the host's OOM killer with its log gone")
        };
    }
    if code > 128 && code < 160 {
        return format!(
            "ended by {} (exit {code}); the container runtime sent no signal",
            signal_name((code - 128) as i32)
        );
    }
    if code == 0 {
        return "the node exited by itself with code 0".into();
    }
    format!("the node exited by itself with code {code}")
}

/// `2026-10-31T09:00:00.123Z` as seconds since the epoch (UTC only)
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    if s.len() < 19 || !s.is_char_boundary(19) {
        return None;
    }
    let n = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, m, d) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    let (hh, mm, ss) = (n(11, 13)?, n(14, 16)?, n(17, 19)?);
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

fn strings(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The container's own values, for §6.2's known values
fn container_known(c: &serde_json::Value, k: &mut Known) {
    let s = |p: &str| {
        c.pointer(p)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let name = s("/Name").trim_start_matches('/').to_string();
    for h in [name, s("/Config/Hostname"), s("/Config/Domainname")] {
        if !h.is_empty() {
            k.hostnames.push(h);
        }
    }
    let id = s("/Id");
    if id.len() >= 12 {
        k.machine_ids.push(id[..12].to_string());
        k.machine_ids.push(id);
    }
    if let Some(nets) = c
        .pointer("/NetworkSettings/Networks")
        .and_then(|n| n.as_object())
    {
        for (net, v) in nets {
            if !matches!(net.as_str(), "bridge" | "host" | "none" | "default") {
                k.hostnames.push(net.clone());
            }
            for f in ["IPAddress", "GlobalIPv6Address", "Gateway", "MacAddress"] {
                if let Some(ip) = v.get(f).and_then(|x| x.as_str()).filter(|x| !x.is_empty()) {
                    k.ips.push(ip.to_string());
                }
            }
            for a in strings(v.get("Aliases")) {
                k.hostnames.push(a);
            }
        }
    }
    for m in c
        .get("Mounts")
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(n) = m.get("Name").and_then(|x| x.as_str()) {
            k.hostnames.push(n.to_string());
        }
    }
}

fn ask_consent(name: &str) -> bool {
    print!(
        "Include the host's view of container `{name}`? It shows the host's memory, storage and \
         container configuration (names pseudonymised). [y/N] "
    );
    let _ = std::io::stdout().flush();
    let mut l = String::new();
    match std::io::stdin().lock().read_line(&mut l) {
        Ok(0) | Err(_) => false,
        Ok(_) => matches!(l.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
    }
}

/// The host's kernel log since `since` (epoch seconds): `journalctl -k`,
/// or `dmesg` when the journal has none
pub(crate) fn kernel_log(since: i64) -> (util::CmdOut, &'static str) {
    let t = Duration::from_secs(30);
    let since_k = format!("@{since}");
    let klog = util::run_cmd(
        "journalctl",
        &["-k", "-o", "short-iso", "--no-pager", "--since", &since_k],
        t,
        CAP,
    );
    if !klog.ok() || klog.text().trim().is_empty() || klog.text().contains("No journal files") {
        return (util::run_cmd("dmesg", &[], t, CAP), "dmesg");
    }
    (klog, "journalctl -k")
}

/// What one runtime collected, for the shared package writer
pub(crate) struct Pack {
    /// "Docker", "LXD", "Incus", "LXC", "Proxmox"
    pub runtime: &'static str,
    /// The summary lines between "Collected:" and the verdict
    pub head: String,
    pub verdict: String,
    /// (path in the package, text); every text goes through the redactor
    pub files: Vec<(String, String)>,
    pub not_built: String,
    pub known: Known,
    pub now: i64,
}

/// `irondivi-cli diag --host <container>`: finds the container's runtime
/// (Docker, then Proxmox `pct`, Incus, LXD, plain LXC) and collects its
/// side of the story
pub fn host_main(container: &str, o: &Options) -> i32 {
    unsafe { libc::umask(0o077) };
    let t = Duration::from_secs(30);
    let mut tried = Vec::new();
    if util::which("docker").is_some() {
        let ins = util::run_cmd(
            "docker",
            &["inspect", "--type", "container", container],
            t,
            CAP,
        );
        if ins.ok() {
            return docker_main(container, &ins.stdout, o);
        }
        let err = String::from_utf8_lossy(&ins.stderr);
        tried.push(format!(
            "docker inspect: {} {}",
            ins.status_line(),
            err.lines().next().unwrap_or("").trim()
        ));
    } else {
        tried.push("docker: not on PATH".into());
    }
    if !lxc::valid_name(container) {
        eprintln!("irondivi-cli diag --host: `{container}` is not a container name diag looks up in LXC, LXD, Incus or Proxmox");
        return 1;
    }
    match lxc::detect(container, &mut tried) {
        Some(rt) => lxc::lxc_main(rt, container, o),
        None => {
            eprintln!("irondivi-cli diag --host: no container `{container}` found on this host. Tried: {}", tried.join("; "));
            eprintln!(
                "For WSL and Docker Desktop hosts (not built) save what the host shows about the container and \
                 attach it with `irondivi-cli diag --attach <file>`"
            );
            1
        }
    }
}

fn docker_main(container: &str, inspect: &[u8], o: &Options) -> i32 {
    let t = Duration::from_secs(30);
    let parsed: serde_json::Value = match serde_json::from_slice(inspect) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("irondivi-cli diag --host: docker inspect gave no JSON: {e}");
            return 1;
        }
    };
    let Some(c) = parsed.get(0).cloned() else {
        eprintln!("irondivi-cli diag --host: no container {container}");
        return 1;
    };
    if util::is_tty() && o.submit != Some(false) && !ask_consent(container) {
        println!("Nothing was collected.");
        return 0;
    }

    // §6.2 step 1: this host's values, then the container's
    let mut known = crate::discovery::known_values();
    container_known(&c, &mut known);
    known.hostnames.push(container.to_string());

    let st = State {
        status: c
            .pointer("/State/Status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        exit_code: c
            .pointer("/State/ExitCode")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        oom_killed: c
            .pointer("/State/OOMKilled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        memory_limit: c
            .pointer("/HostConfig/Memory")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    };
    let started = c
        .pointer("/State/StartedAt")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let since = parse_rfc3339(started)
        .filter(|&s| s > 0)
        .unwrap_or(util::now_secs() - 7 * 86400);
    let now = util::now_secs();
    let id = c
        .get("Id")
        .and_then(|v| v.as_str())
        .unwrap_or(container)
        .to_string();

    // the runtime's events for this container since it started
    let since_a = since.to_string();
    let until_a = now.to_string();
    let filt = format!("container={id}");
    let ev = util::run_cmd(
        "docker",
        &[
            "events",
            "--since",
            &since_a,
            "--until",
            &until_a,
            "--filter",
            &filt,
            "--format",
            "{{json .}}",
        ],
        t,
        CAP,
    );
    let events: Vec<Event> = ev.text().lines().filter_map(parse_event).collect();
    let mut ev_txt = format!(
        "# docker events since the container started: {}\n",
        ev.status_line()
    );
    for e in &events {
        ev_txt.push_str(&format!(
            "{} {}{}{}\n",
            util::rfc3339(e.time_ns / 1_000_000_000),
            e.action,
            e.signal
                .map(|s| format!(" signal={}", signal_name(s)))
                .unwrap_or_default(),
            e.exit_code
                .map(|c| format!(" exitCode={c}"))
                .unwrap_or_default()
        ));
    }

    // host kernel log lines about it: OOM kills and seccomp audit records
    let comm: String = c
        .get("Path")
        .and_then(|v| v.as_str())
        .and_then(|p| p.rsplit('/').next())
        .unwrap_or("irondivid")
        .chars()
        .take(15)
        .collect();
    let (klog, ksrc) = kernel_log(since - 60);
    let short = &id[..id.len().min(12)];
    let want = |l: &str| {
        let ours = l.contains(&id)
            || l.contains(short)
            || l.contains(&format!("comm=\"{comm}\""))
            || l.contains(&format!("({comm})"));
        ours && (l.contains("type=1326")
            || l.contains("oom")
            || l.contains("Killed process")
            || l.contains("Out of memory"))
    };
    let klines: Vec<String> = klog
        .text()
        .lines()
        .filter(|l| want(l))
        .map(str::to_string)
        .collect();
    let audit = klines.iter().rev().find_map(|l| parse_audit(l));
    let host_oom = klines
        .iter()
        .any(|l| l.contains("Killed process") || l.contains("oom-kill"));
    let mut k_txt = format!(
        "# host kernel log lines about the container since it started ({ksrc}: {}; {} lines kept of the log)\n",
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

    let profile = profile_kills(&strings(c.pointer("/HostConfig/SecurityOpt")));
    let v = verdict(&st, &events, audit.as_ref(), &profile, host_oom);

    // host memory and the storage under Docker's root
    let mem = util::read_small(Path::new("/proc/meminfo"), 64 << 10)
        .unwrap_or_else(|| "not readable\n".into());
    let root = util::run_cmd(
        "docker",
        &["info", "--format", "{{.DockerRootDir}} {{.Driver}}"],
        t,
        4096,
    )
    .text();
    let root_dir = root
        .split_whitespace()
        .next()
        .unwrap_or("/var/lib/docker")
        .to_string();
    let df = util::run_cmd("df", &["-P", "-k", &root_dir], t, 64 << 10);
    let mut storage = format!(
        "# docker root and storage driver: {}\n# df -P -k: {}\n{}",
        root.trim(),
        df.status_line(),
        df.text()
    );
    if let Some((total, free, _, _)) = util::statvfs(Path::new(&root_dir)) {
        storage.push_str(&format!(
            "# statvfs: total {} free {}\n",
            util::human(total),
            util::human(free)
        ));
    }

    let mut head = format!(
        "Container: {} (image {})\n",
        container,
        c.pointer("/Config/Image")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    );
    head.push_str(&format!(
        "State: {} exit={} OOMKilled={} started={} finished={}\n",
        st.status,
        st.exit_code,
        st.oom_killed,
        started,
        c.pointer("/State/FinishedAt")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    ));
    let inspect_txt = serde_json::to_string_pretty(&c).unwrap_or_default();
    finish(
        Pack {
            runtime: "Docker",
            head,
            verdict: v,
            files: vec![
                ("host/docker-inspect.json".into(), inspect_txt),
                ("host/docker-events.txt".into(), ev_txt),
                ("host/kernel-log.txt".into(), k_txt),
                ("host/meminfo.txt".into(), mem),
                ("host/storage.txt".into(), storage),
            ],
            not_built: "WSL and Docker Desktop hosts; the cgroup files of a container that has ended are gone".into(),
            known,
            now,
        },
        o,
    )
}

/// Writes the package: the files through the redactor, the summary, the
/// §6.3 final scan, the manifest, then the §8.3 review
pub(crate) fn finish(p: Pack, o: &Options) -> i32 {
    let salt = Redactor::new_salt();
    let red = Redactor::new(salt, &p.known);
    let id8 = runner::local_id();
    let (out, _) = match runner::create_out(o, &id8, &crate::ctx::Ctx::default()) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("irondivi-cli diag --host: {e}");
            return 1;
        }
    };
    for (rel, text) in &p.files {
        crate::import::write_file(&out, rel, red.scrub(text).as_bytes());
    }
    let names: Vec<&str> = p.files.iter().map(|(r, _)| r.as_str()).collect();
    let v = &p.verdict;

    let summary = |left_out: &[(String, String)]| {
        let mut s = String::new();
        s.push_str(&format!(
            "IronDivi diagnostics — irondivi-cli diag {} --host (B6.2, {})\n",
            crate::VERSION,
            p.runtime
        ));
        s.push_str(&format!(
            "Local id: {id8} (a ticket is issued only when the package is sent)\n"
        ));
        s.push_str(&format!("Collected: {}\n", util::rfc3339(p.now)));
        s.push_str(&p.head);
        s.push_str(&format!("\n== Verdict ==\nHow the container ended: {v}\n"));
        s.push_str(&format!("\n== Files ==\n{}\n", names.join("  ")));
        if !left_out.is_empty() {
            s.push_str("\n== Left out by the final scan (§6.3) ==\n");
            for (f, why) in left_out {
                s.push_str(&format!("{f}: {why}\n"));
            }
        }
        s.push_str(&format!("\nNot built here: {}.\n", p.not_built));
        s.push_str("This folder has been through diag's redaction (§6.2) and final scan (§6.3), and was not sent anywhere.\n");
        let tmp = out.join(".00-SUMMARY.tmp");
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
        {
            let _ = f.write_all(red.scrub(&s).as_bytes());
            let _ = f.sync_data();
            let _ = fs::rename(&tmp, out.join("00-SUMMARY.txt"));
        }
    };
    summary(&[]);

    // §6.3 final scan
    let secrets = crate::consent::current_secrets(o);
    let sc = Scanner::new(&red, &secrets, &salt);
    let mut left_out = Vec::new();
    for _ in 0..4 {
        let hits = sc.scan_folder(&out);
        if hits.is_empty() {
            break;
        }
        for hit in hits {
            let _ = fs::remove_file(out.join(&hit.file));
            eprintln!(
                "irondivi-cli diag: left out {} (line {}): {}",
                hit.file, hit.line, hit.reason
            );
            left_out.push((hit.file, format!("line {}: {}", hit.line, hit.reason)));
        }
        summary(&left_out);
    }

    let mut files = Vec::new();
    scanner::walk(&out, &out, &mut files);
    files.sort();
    let mut m = String::from("# path\tsize\tsha256\tcollector\n");
    for (f, why) in &left_out {
        m.push_str(&format!("# left out: {f} — {why}\n"));
    }
    for rel in files {
        if rel == "02-manifest.txt" || rel.starts_with('.') {
            continue;
        }
        let path = out.join(&rel);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let h = util::sha256_file(&path).unwrap_or_else(|e| util::io_err(&e));
        m.push_str(&format!("{rel}\t{size}\t{h}\thost\n"));
    }
    crate::import::write_file(&out, "02-manifest.txt", m.as_bytes());

    println!(
        "irondivi-cli diag --host: {}",
        red.scrub(&format!("How the container ended: {v}"))
    );
    println!(
        "irondivi-cli diag --host: wrote {} (mode 0700). Start with 00-SUMMARY.txt.",
        out.display()
    );
    let red2 = Redactor::new(Redactor::new_salt(), &p.known);
    let scan = crate::consent::ScanCtx {
        red: &red2,
        secrets,
        salt: Vec::new(),
    };
    crate::consent::after_collect(&out, o, scan);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(action: &str, signal: Option<i32>, t: i64) -> Event {
        Event {
            action: action.into(),
            signal,
            exit_code: None,
            time_ns: t * 1_000_000_000,
        }
    }

    fn exited(code: i64, oom: bool) -> State {
        State {
            status: "exited".into(),
            exit_code: code,
            oom_killed: oom,
            memory_limit: 0,
        }
    }

    #[test]
    fn docker_stop_after_the_timeout_is_never_oom() {
        let e = [
            ev("kill", Some(15), 10),
            ev("kill", Some(9), 13),
            ev("die", None, 13),
            ev("stop", None, 13),
        ];
        assert_eq!(
            verdict(&exited(137, false), &e, None, &[], false),
            "stopped by the container runtime (docker stop: SIGTERM, then SIGKILL after 3 s); exit 137; not a memory-limit kill (OOMKilled=false)"
        );
        let e = [
            ev("kill", Some(15), 10),
            ev("die", None, 11),
            ev("stop", None, 11),
        ];
        assert_eq!(
            verdict(&exited(0, false), &e, None, &[], false),
            "stopped by the container runtime (docker stop: SIGTERM); the node stopped cleanly, exit 0"
        );
        let e = [ev("kill", Some(9), 10), ev("die", None, 10)];
        assert!(verdict(&exited(137, false), &e, None, &[], false)
            .starts_with("killed by the container runtime (docker kill: SIGKILL"));
    }

    #[test]
    fn seccomp_names_the_call() {
        let line = "2026-10-31T09:00:00+0000 hp1 kernel: audit: type=1326 audit(1.2:3): auid=4294967295 uid=1000 gid=1000 ses=4294967295 subj=unconfined pid=7 comm=\"irondivid\" exe=\"/opt/bin/irondivid\" sig=31 arch=c000003e syscall=75 compat=0 ip=0x1 code=0x80000000";
        let a = parse_audit(line).unwrap();
        assert_eq!(
            a,
            Audit {
                syscall: 75,
                arch: "c000003e".into(),
                sig: 31
            }
        );
        assert_eq!(
            verdict(&exited(159, false), &[], Some(&a), &[], false),
            "killed by seccomp (SIGSYS, exit 159): system call 75 (fdatasync) is forbidden by the container's seccomp profile (kernel audit record); not a memory-limit kill (OOMKilled=false)"
        );
        let prof = profile_kills(&["seccomp={\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"names\":[\"fdatasync\"],\"action\":\"SCMP_ACT_KILL_PROCESS\"},{\"names\":[\"ptrace\"],\"action\":\"SCMP_ACT_ERRNO\"}]}".into()]);
        assert_eq!(prof, vec!["fdatasync".to_string()]);
        assert_eq!(
            verdict(&exited(159, false), &[], None, &prof, false),
            "killed by seccomp (SIGSYS, exit 159): the container's seccomp profile kills on fdatasync; no kernel audit record names the call; not a memory-limit kill (OOMKilled=false)"
        );
    }

    #[test]
    fn oom_and_other_ends() {
        let mut st = exited(137, true);
        st.memory_limit = 512 << 20;
        assert_eq!(verdict(&st, &[], None, &[], false), "killed at the container's memory limit (exit 137, OOMKilled=true, memory limit 512 MB)");
        assert!(verdict(&exited(137, false), &[], None, &[], false)
            .starts_with("SIGKILL from outside the container runtime"));
        assert!(verdict(&exited(137, false), &[], None, &[], true)
            .starts_with("SIGKILL from the host kernel's OOM killer"));
        assert_eq!(
            verdict(&exited(139, false), &[], None, &[], false),
            "ended by SIGSEGV (exit 139); the container runtime sent no signal"
        );
        assert_eq!(
            verdict(&exited(0, false), &[], None, &[], false),
            "the node exited by itself with code 0"
        );
        assert_eq!(
            verdict(&exited(10, false), &[], None, &[], false),
            "the node exited by itself with code 10"
        );
        let run = State {
            status: "running".into(),
            ..Default::default()
        };
        assert_eq!(
            verdict(&run, &[], None, &[], false),
            "the container is running: it has not ended"
        );
    }

    #[test]
    fn events_and_times_parse() {
        let l = r#"{"status":"kill","id":"abc","Type":"container","Action":"kill","Actor":{"ID":"abc","Attributes":{"name":"dc","signal":"15"}},"time":1761900000,"timeNano":1761900000123456789}"#;
        assert_eq!(
            parse_event(l).unwrap(),
            Event {
                action: "kill".into(),
                signal: Some(15),
                exit_code: None,
                time_ns: 1761900000123456789
            }
        );
        let l = r#"{"Action":"die","Actor":{"Attributes":{"exitCode":"137"}},"time":1761900003}"#;
        let e = parse_event(l).unwrap();
        assert_eq!(
            (e.exit_code, e.time_ns),
            (Some(137), 1_761_900_003_000_000_000)
        );
        let l = r#"{"Action":"exec_start: sh -c secret","Actor":{"Attributes":{}},"time":1}"#;
        assert_eq!(parse_event(l).unwrap().action, "exec_start");
        assert_eq!(parse_signal("SIGTERM"), Some(15));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339("2026-10-31T09:00:00.123456789Z").map(util::rfc3339),
            Some("2026-10-31T09:00:00Z".into())
        );
        assert!(parse_rfc3339("0001-01-01T00:00:00Z").unwrap() < 0);
    }

    #[test]
    fn container_values_become_known() {
        let c: serde_json::Value = serde_json::from_str(
            r#"{"Id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","Name":"/mynode",
                "Config":{"Hostname":"0123456789ab","Domainname":""},
                "NetworkSettings":{"Networks":{"divinet":{"IPAddress":"172.18.0.2","MacAddress":"02:42:ac:12:00:02","Aliases":["dnode"]}}},
                "Mounts":[{"Name":"divivol","Source":"/var/lib/docker/volumes/divivol/_data"}]}"#,
        )
        .unwrap();
        let mut k = Known::default();
        container_known(&c, &mut k);
        for h in ["mynode", "0123456789ab", "divinet", "dnode", "divivol"] {
            assert!(
                k.hostnames.iter().any(|x| x == h) || k.machine_ids.iter().any(|x| x == h),
                "{h}"
            );
        }
        assert!(k.ips.contains(&"172.18.0.2".to_string()));
        let red = Redactor::new([3; 32], &k);
        let s = red.scrub("container mynode on divinet as 0123456789ab");
        assert!(
            !s.contains("mynode") && !s.contains("divinet") && !s.contains("0123456789ab"),
            "{s}"
        );
    }
}
