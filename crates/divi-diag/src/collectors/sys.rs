// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.0 locks, B2.1 identity, B2.2 host, B2.3 container, B2.13 network,
//! B2.18 seccomp

use super::{cmd_block, file_block, head, one, status_fields, LINUX};
use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use crate::util;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

// ------------------------------------------------------------------ B2.0

/// The lock files a node holds in a data dir
fn lock_files(ctx: &Ctx) -> Vec<(usize, PathBuf)> {
    let mut v = Vec::new();
    for d in &ctx.datadirs {
        for base in [&d.path, &d.chain] {
            for p in [base.join(".lock"), base.join("LOCK")] {
                if p.exists() {
                    v.push((d.n, p));
                }
            }
            if let Ok(rd) = std::fs::read_dir(base) {
                for e in rd.flatten() {
                    let l = e.path().join("LOCK");
                    // the wallet store is never touched (§6.1), not even its LOCK
                    if e.file_name() != "wallet" && l.exists() {
                        v.push((d.n, l));
                    }
                }
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

fn comm(pid: &str) -> String {
    one(&format!("/proc/{pid}/comm"))
}

pub fn locks(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("host/locks.txt");
    outln!(o, "B2.0 lock holders");
    let files = lock_files(ctx);
    if files.is_empty() {
        outln!(o, "no data dir lock files found");
    }
    if LINUX {
        let locks = util::read_small(Path::new("/proc/locks"), 4 << 20).unwrap_or_default();
        for (n, f) in &files {
            let rel = f.strip_prefix(&ctx.datadirs[n - 1].path).map(|p| p.display().to_string()).unwrap_or_default();
            let Ok(md) = std::fs::metadata(f) else { continue };
            let (maj, min) = (libc::major(md.dev() as _), libc::minor(md.dev() as _));
            let key = format!("{:02x}:{:02x}:{}", maj, min, md.ino());
            let holders: Vec<String> = locks
                .lines()
                .filter(|l| l.split_whitespace().any(|w| w == key))
                .map(|l| {
                    let w: Vec<&str> = l.split_whitespace().collect();
                    let pid = w.get(4).copied().unwrap_or("?");
                    format!("{} {} {} pid {pid} ({})", w.get(1).unwrap_or(&""), w.get(2).unwrap_or(&""), w.get(3).unwrap_or(&""), comm(pid))
                })
                .collect();
            outln!(o, "datadir-{n}/{rel}: {}", if holders.is_empty() { "not held".into() } else { holders.join("; ") });
        }
        let total = locks.lines().count();
        outln!(o, "/proc/locks: {total} locks in all{}", if locks.is_empty() { " (unreadable or empty)" } else { "" });
    } else {
        for (n, f) in &files {
            let rel = f.strip_prefix(&ctx.datadirs[n - 1].path).map(|p| p.display().to_string()).unwrap_or_default();
            let fs = f.to_string_lossy().into_owned();
            let c = util::run_cmd("lsof", &["-F", "pc", "--", &fs], std::time::Duration::from_secs(8), 1 << 20);
            let mut holders = Vec::new();
            let mut pid = String::new();
            for l in c.text().lines() {
                if let Some(p) = l.strip_prefix('p') {
                    pid = p.to_string();
                } else if let Some(cm) = l.strip_prefix('c') {
                    holders.push(format!("pid {pid} ({cm})"));
                }
            }
            outln!(o, "datadir-{n}/{rel}: {}", if holders.is_empty() { "no process has it open (lsof)".into() } else { holders.join("; ") });
        }
    }
    let _ = r;
}

// ------------------------------------------------------------------ B2.1

pub fn identity(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("host/identity.txt");
    outln!(o, "diag version: irondivi-cli {}", crate::VERSION);
    outln!(o, "invoked as: {}", ctx.invoked_as);
    let now = util::now_secs();
    outln!(o, "run time (UTC): {}", util::rfc3339(now));
    let tz = std::fs::read_link("/etc/localtime")
        .ok()
        .and_then(|p| p.to_string_lossy().split("zoneinfo/").nth(1).map(String::from))
        .unwrap_or_else(|| "unknown".into());
    outln!(o, "timezone: {tz}{}", parent_env("TZ").map(|v| format!(" (TZ={v})")).unwrap_or_default());
    let (u, e) = (util::uid(), util::euid());
    let who = |id: u32| -> String {
        if id == 0 {
            "0 (root)".into()
        } else {
            let name = util::user_name(id).map(|n| r.user(&n)).unwrap_or_else(|| "?".into());
            format!("{id} ({name})")
        }
    };
    outln!(o, "uid: {}  euid: {}", who(u), who(e));
    outln!(o, "run through sudo: {}", if parent_env("SUDO_UID").is_some() { "yes" } else { "no" });
    outln!(o, "terminal: {}", if parent_tty() { "yes" } else { "no" });
    for k in ["LANG", "LC_ALL", "LC_CTYPE"] {
        outln!(o, "{k}: {}", parent_env(k).unwrap_or_else(|| "(unset)".into()));
    }
    outln!(o, "CAP_SYS_PTRACE for diag: {}", if ctx.cap_sys_ptrace { "yes" } else { "no" });
}

/// The child runs with `LC_ALL=C`; the user's own values are in the parent's
/// environment (Linux: `/proc/<ppid>/environ`, same user)
fn parent_env(key: &str) -> Option<String> {
    let ppid = unsafe { libc::getppid() };
    if LINUX {
        let b = std::fs::read(format!("/proc/{ppid}/environ")).ok()?;
        b.split(|&c| c == 0).find_map(|kv| {
            let s = String::from_utf8_lossy(kv);
            s.strip_prefix(&format!("{key}=")).map(String::from)
        })
    } else {
        // macOS: not readable from here; our own environment minus what the
        // parent set for us
        match key {
            "LC_ALL" | "LANG" => None,
            _ => std::env::var(key).ok(),
        }
    }
}

fn parent_tty() -> bool {
    if LINUX {
        let ppid = unsafe { libc::getppid() };
        std::fs::read_link(format!("/proc/{ppid}/fd/2")).map(|p| p.to_string_lossy().starts_with("/dev/pts") || p.to_string_lossy().starts_with("/dev/tty")).unwrap_or(false)
    } else {
        util::is_tty()
    }
}

// ------------------------------------------------------------------ B2.2

pub fn host(_ctx: &Ctx, o: &mut Out) {
    o.file("host/host.txt");
    if !LINUX {
        return host_macos(o);
    }
    head(o, "OS");
    file_block(o, "/etc/os-release");
    // `uname -a` carries the node name; -srvmo leaves it out
    cmd_block(o, "uname", &["-srvmo"]);
    head(o, "CPU");
    let cpu = util::read_small(Path::new("/proc/cpuinfo"), 4 << 20).unwrap_or_default();
    let n = cpu.lines().filter(|l| l.starts_with("processor")).count();
    outln!(o, "logical CPUs in /proc/cpuinfo: {n}");
    let mut seen = BTreeSet::new();
    for l in cpu.lines() {
        let k = l.split(':').next().unwrap_or("").trim();
        if ["model name", "Hardware", "Model", "CPU implementer", "CPU part", "flags", "Features", "BogoMIPS"].contains(&k) && seen.insert(k.to_string()) {
            outln!(o, "{}", l.replace('\t', ""));
        }
    }
    cmd_block(o, "nproc", &[]);
    outln!(o, "online: {}", one("/sys/devices/system/cpu/online"));
    let cg = self_cgroup();
    outln!(o, "cgroup cpu.max: {}", one(&format!("/sys/fs/cgroup{cg}/cpu.max")));
    outln!(o, "cgroup cpuset.cpus.effective: {}", one(&format!("/sys/fs/cgroup{cg}/cpuset.cpus.effective")));
    head(o, "Memory");
    file_block(o, "/proc/meminfo");
    file_block(o, "/proc/swaps");
    for k in ["vm/overcommit_memory", "vm/overcommit_ratio", "vm/swappiness", "vm/min_free_kbytes", "kernel/pid_max", "kernel/threads-max", "fs/file-nr"] {
        outln!(o, "{k}: {}", one(&format!("/proc/sys/{k}")));
    }
    outln!(o, "THP enabled: {}", one("/sys/kernel/mm/transparent_hugepage/enabled"));
    outln!(o, "THP defrag: {}", one("/sys/kernel/mm/transparent_hugepage/defrag"));
    outln!(o, "page size: {}", unsafe { libc::sysconf(libc::_SC_PAGESIZE) });
    head(o, "Load and time");
    outln!(o, "uptime: {}", one("/proc/uptime"));
    outln!(o, "boot id: {}", one("/proc/sys/kernel/random/boot_id"));
    outln!(o, "loadavg: {}", one("/proc/loadavg"));
    for p in ["cpu", "memory", "io"] {
        file_block(o, &format!("/proc/pressure/{p}"));
    }
    outln!(o, "entropy_avail: {}", one("/proc/sys/kernel/random/entropy_avail"));
    cmd_block(o, "timedatectl", &["show", "--property=NTP", "--property=NTPSynchronized", "--property=TimeUSec", "--property=Timezone"]);
    // `chronyc tracking` names the time server; only the sync figures are kept
    outln!(o, "$ chronyc tracking (server line dropped)");
    if util::which("chronyc").is_some() {
        let c = util::cmd("chronyc", &["tracking"]);
        for l in c.text().lines().filter(|l| !l.starts_with("Reference ID")) {
            outln!(o, "{l}");
        }
        if !c.ok() {
            outln!(o, "  [{}]", c.status_line());
        }
    } else {
        outln!(o, "  (not installed)");
    }
    head(o, "Limits (diag's own, a proxy for the node's)");
    cmd_block(o, "sh", &["-c", "ulimit -a"]);
}

fn host_macos(o: &mut Out) {
    head(o, "OS");
    cmd_block(o, "sw_vers", &[]);
    cmd_block(o, "uname", &["-srvm"]);
    head(o, "CPU and memory");
    cmd_block(o, "sysctl", &["hw.model", "hw.machine", "hw.ncpu", "hw.activecpu", "hw.memsize", "machdep.cpu.brand_string", "vm.swapusage", "kern.boottime", "kern.bootsessionuuid", "kern.maxfiles", "kern.maxproc"]);
    cmd_block(o, "vm_stat", &[]);
    cmd_block(o, "memory_pressure", &["-Q"]);
    head(o, "Load and time");
    cmd_block(o, "uptime", &[]);
    cmd_block(o, "sntp", &["-t", "2", "-d", "time.apple.com"]).ok();
    head(o, "Limits (diag's own, a proxy for the node's)");
    cmd_block(o, "sh", &["-c", "ulimit -a"]);
    cmd_block(o, "launchctl", &["limit"]);
}

/// The v2 path of our own cgroup ("" when unknown or v1)
fn self_cgroup() -> String {
    cgroup_of("self")
}

pub(crate) fn cgroup_of(pid: &str) -> String {
    let s = util::read_small(Path::new(&format!("/proc/{pid}/cgroup")), 64 << 10).unwrap_or_default();
    s.lines().find_map(|l| l.strip_prefix("0::")).unwrap_or("").trim().to_string()
}

// ------------------------------------------------------------------ B2.3

pub fn container(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("container/container.txt");
    if !LINUX {
        outln!(o, "macOS: no container layer to inspect.");
        cmd_block(o, "sysctl", &["kern.hv_vmm_present"]);
        return;
    }
    let mut why: Vec<String> = Vec::new();
    head(o, "Detection");
    let v = cmd_block(o, "systemd-detect-virt", &[]).text().trim().to_string();
    let c = cmd_block(o, "systemd-detect-virt", &["-c"]).text().trim().to_string();
    let env1 = std::fs::read("/proc/1/environ").ok();
    let container_env = env1.as_ref().and_then(|b| {
        b.split(|&x| x == 0).find_map(|kv| String::from_utf8_lossy(kv).strip_prefix("container=").map(String::from))
    });
    outln!(o, "/proc/1/environ container=: {}", match (&env1, &container_env) {
        (None, _) => "(unreadable)".to_string(),
        (Some(_), None) => "(not set)".to_string(),
        (Some(_), Some(v)) => v.clone(),
    });
    let ce = Path::new("/run/.containerenv").exists();
    let de = Path::new("/.dockerenv").exists();
    outln!(o, "/run/.containerenv: {}  /.dockerenv: {}", if ce { "present" } else { "absent" }, if de { "present" } else { "absent" });
    if let Some(v) = &container_env {
        why.push(format!("PID 1 environment says container={v}"));
    }
    if de {
        why.push("/.dockerenv exists".into());
    }
    if ce {
        why.push("/run/.containerenv exists".into());
    }
    if !c.is_empty() && c != "none" {
        why.push(format!("systemd-detect-virt -c says {c}"));
    }
    let ub = Path::new("/proc/user_beancounters").exists();
    if ub {
        why.push("/proc/user_beancounters exists (OpenVZ)".into());
    }
    head(o, "Conclusion");
    if why.is_empty() {
        outln!(o, "no container (virtualisation: {})", if v.is_empty() { "unknown" } else { &v });
    } else {
        outln!(o, "in a container, because: {}", why.join("; "));
        outln!(o, "host-side command (§7.2 L3): run `irondivi-cli diag` on the host, or `docker inspect <container>` there");
    }
    head(o, "Cgroups");
    file_block(o, "/proc/self/cgroup");
    file_block(o, "/proc/1/cgroup");
    let mut paths: Vec<(String, String)> = vec![("diag".into(), self_cgroup())];
    for n in &ctx.nodes {
        paths.push((format!("node pid {}", n.pid), cgroup_of(&n.pid.to_string())));
    }
    for (who, cg) in paths {
        outln!(o, "-- {who}: cgroup {}", if cg.is_empty() { "(v1 or unknown)" } else { &cg });
        if cg.is_empty() {
            continue;
        }
        let mut p = PathBuf::from(&cg);
        loop {
            let dir = Path::new("/sys/fs/cgroup").join(p.strip_prefix("/").unwrap_or(&p));
            let mut vals = Vec::new();
            for f in ["memory.max", "memory.high", "memory.current", "memory.peak", "memory.swap.max", "pids.max", "pids.current", "cpu.max"] {
                if let Some(s) = util::read_small(&dir.join(f), 4096) {
                    vals.push(format!("{f}={}", s.trim()));
                }
            }
            for f in ["memory.events", "pids.events"] {
                if let Some(s) = util::read_small(&dir.join(f), 4096) {
                    vals.push(format!("{f}: {}", s.split_whitespace().collect::<Vec<_>>().join(" ")));
                }
            }
            outln!(o, "  {}: {}", p.display(), if vals.is_empty() { "(nothing readable)".into() } else { vals.join("  ") });
            if !p.pop() || p.as_os_str().is_empty() {
                break;
            }
        }
    }
    if ub {
        file_block(o, "/proc/user_beancounters");
    }
    head(o, "Mounts (paths pseudonymised)");
    let mi = util::read_small(Path::new("/proc/self/mountinfo"), 4 << 20).unwrap_or_default();
    for l in mi.lines() {
        let w: Vec<&str> = l.split_whitespace().collect();
        if w.len() < 10 {
            continue;
        }
        let dash = w.iter().position(|x| *x == "-").unwrap_or(w.len());
        let fstype = w.get(dash + 1).copied().unwrap_or("?");
        if ["proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "securityfs", "debugfs", "tracefs", "pstore", "bpf", "configfs", "fusectl", "hugetlbfs", "autofs", "binfmt_misc", "nsfs"].contains(&fstype) {
            continue;
        }
        outln!(o, "{} root={} {} {}", r.path(w[4]), r.path(w[3]), fstype, w[5]);
    }
    head(o, "Security (diag itself, and the node when readable)");
    for l in status_fields("self", &["CapBnd", "CapEff", "Seccomp", "Seccomp_filters", "NoNewPrivs"]) {
        outln!(o, "diag {l}");
    }
    for n in &ctx.nodes {
        let pid = n.pid.to_string();
        for l in status_fields(&pid, &["CapBnd", "CapEff", "Seccomp", "NoNewPrivs"]) {
            outln!(o, "node {pid} {l}");
        }
        outln!(o, "node {pid} label: {}", one(&format!("/proc/{pid}/attr/current")));
    }
    for k in ["pid_max", "threads-max", "seccomp/actions_avail"] {
        outln!(o, "kernel/{k}: {}", one(&format!("/proc/sys/kernel/{k}")));
    }
    head(o, "PID 1");
    let p1 = one("/proc/1/comm");
    outln!(o, "PID 1 comm: {p1}, start (stat field 22): {}", crate::discovery::proc_stat(1).map(|s| s.1.to_string()).unwrap_or_else(|| "?".into()));
    for n in &ctx.nodes {
        if n.pid == 1 {
            outln!(o, "node is PID 1, no --init: zombies are not reaped and signals take A3's _exit path");
        }
    }
    if ["tini", "dumb-init", "docker-init", "catatonit"].contains(&p1.as_str()) {
        outln!(o, "PID 1 is an init ({p1})");
    }
}

// ----------------------------------------------------------------- B2.13

/// The class of an address, never the address
pub fn ip_class(a: &str) -> &'static str {
    use std::net::IpAddr;
    let a = a.split('%').next().unwrap_or(a);
    match a.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => {
            let o = v.octets();
            if v.is_loopback() {
                "loopback"
            } else if v.is_private() {
                "private"
            } else if v.is_link_local() {
                "link-local"
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                "CGNAT"
            } else if v.is_unspecified() {
                "any"
            } else if v.is_multicast() || v.is_broadcast() {
                "multicast"
            } else {
                "public"
            }
        }
        Ok(IpAddr::V6(v)) => {
            let s = v.segments();
            if v.is_loopback() {
                "loopback"
            } else if v.is_unspecified() {
                "any"
            } else if s[0] & 0xffc0 == 0xfe80 {
                "link-local"
            } else if s[0] & 0xfe00 == 0xfc00 {
                "private (ULA)"
            } else if s[0] & 0xff00 == 0xff00 {
                "multicast"
            } else if let Some(v4) = v.to_ipv4_mapped() {
                ip_class(&v4.to_string())
            } else {
                "public"
            }
        }
        Err(_) => "unknown",
    }
}

/// Replace every address in a line with its class
fn classify_line(l: &str) -> String {
    l.split_whitespace()
        .map(|w| {
            let (addr, pfx) = match w.split_once('/') {
                Some((a, p)) if p.chars().all(|c| c.is_ascii_digit()) => (a, Some(p)),
                _ => (w, None),
            };
            let bare = addr.trim_start_matches('[').trim_end_matches(']');
            if bare.parse::<std::net::IpAddr>().is_ok() {
                match pfx {
                    Some(p) => format!("<{}>/{p}", ip_class(bare)),
                    None => format!("<{}>", ip_class(bare)),
                }
            } else if looks_mac(w) {
                "<mac>".into()
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_mac(w: &str) -> bool {
    let p: Vec<&str> = w.split(':').collect();
    p.len() == 6 && p.iter().all(|x| x.len() == 2 && x.chars().all(|c| c.is_ascii_hexdigit()))
}

const NODE_PORTS: &[&str] = &["51472", "51473", "51474", "51475", "51476", "52471", "52472"];

pub fn network(ctx: &Ctx, o: &mut Out) {
    o.file("host/network.txt");
    outln!(o, "Addresses are shown by class only; no MACs, no hostnames.");
    head(o, "Interfaces");
    if LINUX {
        let a = util::cmd("ip", &["-o", "addr", "show"]);
        if a.ok() {
            for l in a.text().lines() {
                let w: Vec<&str> = l.split_whitespace().collect();
                if w.len() >= 4 {
                    outln!(o, "{} {} {}", w[1], w[2], classify_line(w[3]));
                }
            }
        } else {
            outln!(o, "ip: {}", a.status_line());
        }
        head(o, "Routes");
        for fam in ["-4", "-6"] {
            let rt = util::cmd("ip", &[fam, "route", "show"]);
            for l in rt.text().lines() {
                outln!(o, "{}", classify_line(l));
            }
        }
    } else {
        let a = util::cmd("ifconfig", &[]);
        let mut iface = String::new();
        for l in a.text().lines() {
            if !l.starts_with(['\t', ' ']) {
                iface = l.split(':').next().unwrap_or("").to_string();
            } else {
                let w: Vec<&str> = l.split_whitespace().collect();
                if matches!(w.first(), Some(&"inet") | Some(&"inet6")) && w.len() > 1 {
                    let pfx = w.iter().position(|x| *x == "prefixlen").and_then(|i| w.get(i + 1)).map(|p| format!("/{p}")).unwrap_or_else(|| {
                        w.iter().position(|x| *x == "netmask").and_then(|i| w.get(i + 1)).map(|m| format!(" mask {m}")).unwrap_or_default()
                    });
                    outln!(o, "{iface} {} <{}>{pfx}", w[0], ip_class(w[1]));
                }
            }
        }
        head(o, "Routes");
        let rt = util::cmd("netstat", &["-rn"]);
        for l in rt.text().lines().filter(|l| l.starts_with("default")) {
            outln!(o, "{}", classify_line(l));
        }
    }
    head(o, "DNS resolver");
    let rc = util::read_small(Path::new("/etc/resolv.conf"), 64 << 10).unwrap_or_default();
    let ns: Vec<String> = rc.lines().filter_map(|l| l.strip_prefix("nameserver")).map(|a| a.trim().to_string()).collect();
    for a in &ns {
        let kind = match a.as_str() {
            "127.0.0.53" => "systemd-resolved stub",
            "127.0.0.11" => "Docker embedded DNS",
            _ => ip_class(a),
        };
        outln!(o, "nameserver: {kind}");
    }
    if ns.is_empty() {
        outln!(o, "no nameserver in /etc/resolv.conf");
    }
    if Path::new("/run/systemd/resolve/stub-resolv.conf").exists() {
        outln!(o, "systemd-resolved: present");
    }
    head(o, "Listening sockets of the node");
    let pids = ctx.node_pids();
    if pids.is_empty() {
        outln!(o, "no node running");
    }
    if LINUX {
        if !pids.is_empty() {
            let s = util::cmd("ss", &["-ltnupH"]);
            let mut any = false;
            for l in s.text().lines() {
                if pids.iter().any(|p| l.contains(&format!("pid={p},"))) {
                    any = true;
                    let w: Vec<&str> = l.split_whitespace().collect();
                    let local = w.get(4).copied().unwrap_or("");
                    let (addr, port) = local.rsplit_once(':').unwrap_or((local, "?"));
                    outln!(o, "{} {} <{}> port {port}", w.first().unwrap_or(&""), w.get(1).unwrap_or(&""), ip_class(addr.trim_matches(['[', ']'])));
                }
            }
            if !any {
                outln!(o, "ss shows no socket for the node's pids ({}; another user's sockets need root)", s.status_line());
            }
        }
    } else {
        for p in &pids {
            let s = util::cmd("lsof", &["-nP", "-a", "-p", &p.to_string(), "-iTCP", "-sTCP:LISTEN"]);
            for l in s.text().lines().skip(1) {
                let name = l.split_whitespace().nth(8).unwrap_or("");
                let (addr, port) = name.rsplit_once(':').unwrap_or((name, "?"));
                outln!(o, "TCP <{}> port {port}", if addr == "*" { "any" } else { ip_class(addr.trim_matches(['[', ']'])) });
            }
        }
    }
    head(o, "Firewall rules mentioning the node's ports");
    if LINUX {
        for (prog, args) in [("nft", vec!["list", "ruleset"]), ("iptables", vec!["-S"]), ("ip6tables", vec!["-S"])] {
            if util::which(prog).is_none() {
                outln!(o, "{prog}: not installed");
                continue;
            }
            let c = util::cmd(prog, &args);
            if !c.ok() {
                outln!(o, "{prog}: {} (rules need root)", c.status_line());
                continue;
            }
            let hits: Vec<String> = c.text().lines().filter(|l| NODE_PORTS.iter().any(|p| l.contains(p))).map(|l| classify_line(l.trim())).collect();
            outln!(o, "{prog}: {} rules, {} mention a node port", c.text().lines().count(), hits.len());
            for h in hits {
                outln!(o, "  {h}");
            }
        }
    } else {
        cmd_block(o, "/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"]);
    }
    head(o, "Proxy and IPv6");
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
        if parent_env(k).is_some() || std::env::var_os(k).is_some() {
            outln!(o, "{k}: set");
        }
    }
    outln!(o, "proxy variables: checked (only the set ones are listed)");
    if LINUX {
        outln!(o, "ipv6 disable_ipv6 (all): {}", one("/proc/sys/net/ipv6/conf/all/disable_ipv6"));
    }
}

// ----------------------------------------------------------------- B2.18

pub fn seccomp(ctx: &Ctx, o: &mut Out) {
    o.file("host/seccomp.txt");
    if !LINUX {
        outln!(o, "macOS: no seccomp; sandbox state of the node:");
        for p in ctx.node_pids() {
            cmd_block(o, "ps", &["-o", "pid=,flags=", "-p", &p.to_string()]);
        }
        return;
    }
    for l in status_fields("self", &["Seccomp", "Seccomp_filters", "NoNewPrivs"]) {
        outln!(o, "diag {l}");
    }
    for p in ctx.node_pids() {
        for l in status_fields(&p.to_string(), &["Seccomp", "Seccomp_filters", "NoNewPrivs"]) {
            outln!(o, "node {p} {l}");
        }
    }
    outln!(o, "actions_avail: {}", one("/proc/sys/kernel/seccomp/actions_avail"));
    outln!(o, "actions_logged: {}", one("/proc/sys/kernel/seccomp/actions_logged"));
    outln!(o, "AppArmor: {}", one("/sys/module/apparmor/parameters/enabled"));
    outln!(o, "SELinux enforce: {}", one("/sys/fs/selinux/enforce"));
    // whether a node binary runs at all under this sandbox
    for n in &ctx.nodes {
        if let Some(exe) = &n.exe {
            if n.component.is_none() && exe.is_file() {
                let c = util::run_cmd(&exe.to_string_lossy(), &["--version"], std::time::Duration::from_secs(10), 4096);
                outln!(o, "irondivid --version under diag's sandbox: {}", c.status_line());
                break;
            }
        }
    }
    outln!(o, "denied-syscall audit lines: see kernel/kernel.txt (B2.11)");
}
