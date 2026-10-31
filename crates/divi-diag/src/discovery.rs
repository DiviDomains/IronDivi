// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B1.1: the data dirs and running nodes, plus the private values (§6.2
//! step 1) the redactor masks.

use crate::ctx::{DataDir, Node};
use crate::redact::Known;
use crate::util::*;
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const NODE_NAMES: &[&str] = &["irondivid"];
pub const COMPONENTS: &[&str] = &["irondivi-cli", "divi-swapd", "divi-swap", "irondivi-electrum", "irondivi-webui"];

// ---------------------------------------------------------------- known values

pub fn known_values() -> Known {
    let mut k = Known::default();
    let mut hn = vec![0u8; 256];
    if unsafe { libc::gethostname(hn.as_mut_ptr() as *mut libc::c_char, hn.len()) } == 0 {
        let end = hn.iter().position(|&b| b == 0).unwrap_or(0);
        let h = String::from_utf8_lossy(&hn[..end]).into_owned();
        if !h.is_empty() {
            if let Some(short) = h.split('.').next() {
                k.hostnames.push(short.to_string());
            }
            k.hostnames.push(h);
        }
    }
    for args in [&["-f"][..], &["-A"][..]] {
        let o = run_cmd("hostname", args, std::time::Duration::from_secs(3), 4096);
        if o.ok() {
            for w in o.text().split_whitespace() {
                k.hostnames.push(w.to_string());
                if let Some(short) = w.split('.').next() {
                    k.hostnames.push(short.to_string());
                }
            }
        }
    }
    if cfg!(target_os = "macos") {
        for key in ["ComputerName", "LocalHostName", "HostName"] {
            let o = cmd("scutil", &["--get", key]);
            if o.ok() {
                let t = o.text().trim().to_string();
                if !t.is_empty() {
                    k.hostnames.push(t);
                }
            }
        }
    }
    if let Some(hosts) = read_small(Path::new("/etc/hosts"), 1 << 20) {
        for line in hosts.lines() {
            let line = line.split('#').next().unwrap_or("");
            for name in line.split_whitespace().skip(1) {
                if !name.starts_with("localhost") && !name.starts_with("ip6-") && name != "broadcasthost" {
                    k.hostnames.push(name.to_string());
                }
            }
        }
    }
    if let Some(pw) = read_small(Path::new("/etc/passwd"), 4 << 20) {
        for line in pw.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 6 {
                let uid: u32 = f[2].parse().unwrap_or(0);
                if (1000..65534).contains(&uid) || f[5].starts_with("/home/") || f[5].starts_with("/Users/") {
                    k.users.push(f[0].to_string());
                    if let Some(b) = Path::new(f[5]).file_name() {
                        k.users.push(b.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    for base in ["/home", "/Users"] {
        if let Ok(rd) = std::fs::read_dir(base) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n != "Shared" && !n.starts_with('.') {
                    k.users.push(n);
                }
            }
        }
    }
    if let Some(n) = user_name(uid()) {
        if n != "root" {
            k.users.push(n);
        }
    }
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id", "/proc/sys/kernel/random/boot_id"] {
        if let Some(s) = read_small(Path::new(p), 256) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                k.machine_ids.push(s.replace('-', ""));
                k.machine_ids.push(s);
            }
        }
    }
    if cfg!(target_os = "macos") {
        let o = cmd("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
        for line in o.text().lines() {
            if line.contains("IOPlatformUUID") || line.contains("IOPlatformSerialNumber") {
                if let Some(v) = line.split('"').nth(3) {
                    k.machine_ids.push(v.to_string());
                }
            }
        }
    }
    k.ips = interface_ips();
    k.hostnames.sort();
    k.hostnames.dedup();
    k.users.sort();
    k.users.dedup();
    k
}

pub fn interface_ips() -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(a as *const libc::sockaddr_in);
                        let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        out.push(ip.to_string());
                    }
                    libc::AF_INET6 => {
                        let sin = &*(a as *const libc::sockaddr_in6);
                        out.push(std::net::Ipv6Addr::from(sin.sin6_addr.s6_addr).to_string());
                    }
                    _ => {}
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

// ---------------------------------------------------------------- processes

/// `/proc/<pid>/stat` field 22 and the state letter
pub fn proc_stat(pid: u32) -> Option<(char, u64, Vec<String>)> {
    let s = read_small(Path::new(&format!("/proc/{pid}/stat")), 4096)?;
    let close = s.rfind(')')?;
    let rest: Vec<String> = s[close + 2..].split_whitespace().map(String::from).collect();
    let state = rest.first()?.chars().next()?;
    let start = rest.get(19)?.parse().ok()?;
    Some((state, start, rest))
}

fn proc_uid(pid: u32) -> Option<u32> {
    let s = read_small(Path::new(&format!("/proc/{pid}/status")), 16384)?;
    s.lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// The A5 readability check: open and first read of `io`, else `environ`
pub fn proc_readable(pid: u32) -> bool {
    use std::io::Read;
    for f in ["io", "environ"] {
        match std::fs::File::open(format!("/proc/{pid}/{f}")) {
            Ok(mut fh) => {
                let mut b = [0u8; 64];
                match fh.read(&mut b) {
                    Ok(_) => return true,
                    Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)) => return false,
                    Err(_) => continue,
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)) => return false,
            Err(_) => continue,
        }
    }
    false
}

/// Every running irondivi process: (pid, name, argv)
pub fn list_irondivi_processes() -> Vec<(u32, String, Vec<String>)> {
    let mut out = Vec::new();
    if Path::new("/proc/self/stat").exists() {
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
                if pid == std::process::id() {
                    continue;
                }
                let comm = read_small(&e.path().join("comm"), 64).unwrap_or_default().trim().to_string();
                let argv: Vec<String> = std::fs::read(e.path().join("cmdline"))
                    .unwrap_or_default()
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(escape_bytes)
                    .collect();
                let base0 = argv.first().map(|a| basename(a)).unwrap_or_default();
                let name = [comm.as_str(), base0.as_str()]
                    .into_iter()
                    .find(|n| NODE_NAMES.contains(n) || COMPONENTS.contains(n))
                    .map(String::from);
                if let Some(name) = name {
                    if name == "irondivi-cli" && argv.iter().any(|a| a == "diag") {
                        continue; // diag itself
                    }
                    out.push((pid, name, argv));
                }
            }
        }
    } else {
        // macOS: ps shows every user's argv
        let o = run_cmd("ps", &["-axww", "-o", "pid=,command="], std::time::Duration::from_secs(10), 16 << 20);
        for line in o.text().lines() {
            let line = line.trim_start();
            let Some((pid, cmdl)) = line.split_once(' ') else { continue };
            let Ok(pid) = pid.parse::<u32>() else { continue };
            let argv: Vec<String> = cmdl.split_whitespace().map(String::from).collect();
            let base0 = argv.first().map(|a| basename(a)).unwrap_or_default();
            if (NODE_NAMES.contains(&base0.as_str()) || COMPONENTS.contains(&base0.as_str()))
                && pid != std::process::id()
                && !(base0 == "irondivi-cli" && argv.iter().any(|a| a == "diag"))
            {
                out.push((pid, base0, argv));
            }
        }
    }
    out
}

pub fn basename(p: &str) -> String {
    Path::new(p).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.to_string())
}

/// `-datadir=`/`-conf=` from an argv (both `-x=v` and `--x v` forms)
pub fn arg_value(argv: &[String], key: &str) -> Option<String> {
    let mut it = argv.iter().skip(1);
    while let Some(a) = it.next() {
        let body = a.trim_start_matches('-');
        if body.len() == a.len() {
            continue;
        }
        if let Some(v) = body.strip_prefix(key) {
            if let Some(v) = v.strip_prefix('=') {
                return Some(v.to_string());
            }
            if v.is_empty() {
                return it.next().cloned();
            }
        }
    }
    None
}

pub fn arg_flag(argv: &[String], key: &str) -> bool {
    argv.iter().skip(1).any(|a| {
        let b = a.trim_start_matches('-');
        b == key || b.strip_prefix(key).map(|v| v.starts_with('=') && v != "=0").unwrap_or(false)
    })
}

/// The network a node or config names, and the subdir compute_data_dir adds
pub fn network_of(argv: &[String], conf: Option<&crate::settings::Settings>) -> (String, &'static str, bool) {
    let get = |k: &str| arg_flag(argv, k) || conf.map(|c| c.get_bool(k, false)).unwrap_or(false);
    let pd = get("privatedivi") || arg_value(argv, "chain").map(|c| c == "privatedivi").unwrap_or(false);
    if get("testnet") {
        ("testnet".into(), "testnet", pd)
    } else if get("regtest") {
        ("regtest".into(), "regtest", pd)
    } else {
        ("main".into(), "", pd)
    }
}

// ---------------------------------------------------------------- A14 records

/// The A14 mirror roots that may exist on this machine
pub fn mirror_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(x) = std::env::var("XDG_STATE_HOME") {
        v.push(PathBuf::from(x).join("irondivi"));
    }
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Some(h) = user_home(uid()) {
        homes.push(h);
    }
    homes.push(PathBuf::from("/root"));
    for base in ["/home", "/Users"] {
        if let Ok(rd) = std::fs::read_dir(base) {
            homes.extend(rd.flatten().map(|e| e.path()));
        }
    }
    for h in homes {
        v.push(h.join(".local/state/irondivi"));
        v.push(h.join("Library/Logs/IronDivi"));
    }
    v.push(PathBuf::from("/var/log/irondivi"));
    if let Ok(rd) = std::fs::read_dir("/var/tmp") {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("irondivi-") {
                v.push(e.path());
            }
        }
    }
    let mut seen = HashSet::new();
    v.retain(|p| p.is_dir() && seen.insert(p.clone()));
    v
}

/// One A14 path record. The plan lists the fields but not the format; diag
/// reads `key=value` (or `key: value`) lines with the keys datadir, conf,
/// cwd, exe, sha256, pid, start, uid.
#[derive(Debug, Default, Clone)]
pub struct PathRecord {
    pub file: PathBuf,
    pub datadir: Option<PathBuf>,
    pub conf: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub exe: Option<PathBuf>,
    pub sha256: Option<String>,
    pub pid: Option<u32>,
    pub start: Option<u64>,
}

pub fn parse_record(file: &Path, text: &str) -> PathRecord {
    let mut r = PathRecord { file: file.to_path_buf(), ..Default::default() };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=').or_else(|| line.split_once(':')) else { continue };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "datadir" | "data_dir" => r.datadir = Some(v.into()),
            "conf" => r.conf = Some(v.into()),
            "cwd" => r.cwd = Some(v.into()),
            "exe" | "binary" => r.exe = Some(v.into()),
            "sha256" | "binary_sha256" => r.sha256 = Some(v),
            "pid" => r.pid = v.parse().ok(),
            "start" | "starttime" | "start_time" => r.start = v.parse().ok(),
            _ => {}
        }
    }
    r
}

/// Every readable `running/<pid>` record; (live, stale, unreadable dirs)
pub fn path_records(roots: &[PathBuf]) -> (Vec<PathRecord>, Vec<PathRecord>, Vec<PathBuf>) {
    let (mut live, mut stale, mut unreadable) = (Vec::new(), Vec::new(), Vec::new());
    for root in roots {
        let Ok(ids) = std::fs::read_dir(root) else {
            unreadable.push(root.clone());
            continue;
        };
        for id in ids.flatten() {
            let run = id.path().join("running");
            let rd = match std::fs::read_dir(&run) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    unreadable.push(run);
                    continue;
                }
                Err(_) => continue,
            };
            for f in rd.flatten() {
                let Some(text) = read_small(&f.path(), 64 * 1024) else {
                    unreadable.push(f.path());
                    continue;
                };
                let mut r = parse_record(&f.path(), &text);
                if r.pid.is_none() {
                    r.pid = f.file_name().to_string_lossy().parse().ok();
                }
                let ok = match (r.pid, r.start) {
                    (Some(pid), Some(st)) => proc_stat(pid).map(|(_, s, _)| s == st).unwrap_or(false)
                        || (cfg!(target_os = "macos") && pid_alive(pid)),
                    _ => false,
                };
                if ok {
                    live.push(r)
                } else {
                    stale.push(r)
                }
            }
        }
    }
    (live, stale, unreadable)
}

pub fn pid_alive(pid: u32) -> bool {
    let r = unsafe { libc::kill(pid as i32, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

// ---------------------------------------------------------------- nodes

pub fn find_nodes(records: &[PathRecord]) -> Vec<Node> {
    let mut out = Vec::new();
    for (pid, name, argv) in list_irondivi_processes() {
        let mut n = Node { pid, argv: argv.clone(), ..Default::default() };
        if name != "irondivid" {
            n.component = Some(name);
        }
        n.uid = proc_uid(pid);
        n.start = proc_stat(pid).map(|(_, s, _)| s);
        let is_linux = Path::new("/proc/self/stat").exists();
        n.readable = if is_linux { proc_readable(pid) } else { uid() == 0 || n.uid == Some(uid()) };
        if is_linux && n.readable {
            n.cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).ok();
            n.exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        } else if !is_linux {
            n.cwd = macos_cwd(pid);
            n.exe = argv.first().map(PathBuf::from).filter(|p| p.is_absolute());
        }
        let rec = records.iter().find(|r| r.pid == Some(pid));
        let arg_dd = arg_value(&argv, "datadir");
        let arg_conf = arg_value(&argv, "conf");
        if let Some(r) = rec {
            n.datadir = r.datadir.clone();
            n.conf = r.conf.clone();
            if n.cwd.is_none() {
                n.cwd = r.cwd.clone();
            }
            if n.exe.is_none() {
                n.exe = r.exe.clone();
            }
            n.binary_sha256_record = r.sha256.clone();
            n.datadir_source = "path record".into();
        } else if let Some(dd) = &arg_dd {
            let p = PathBuf::from(dd);
            if p.is_absolute() {
                n.datadir = Some(p);
                n.datadir_source = "argv absolute".into();
            } else if let Some(cwd) = &n.cwd {
                n.datadir = Some(cwd.join(p));
                n.datadir_source = "argv relative + cwd".into();
            } else {
                n.datadir_source = format!(
                    "running node {pid} uses a relative data dir ({}) and its working directory is unreadable (D5)",
                    dd
                );
            }
        } else if n.component.is_none() {
            n.datadir_source = format!(
                "running node {pid} has no -datadir and no path record, so its data dir is unknown"
            );
        }
        if n.conf.is_none() {
            if let Some(c) = arg_conf {
                let p = PathBuf::from(&c);
                n.conf = if p.is_absolute() {
                    Some(p)
                } else {
                    n.datadir.as_ref().map(|d| d.join(p))
                };
            }
        }
        out.push(n);
    }
    out
}

#[cfg(target_os = "macos")]
fn macos_cwd(pid: u32) -> Option<PathBuf> {
    let o = run_cmd("lsof", &["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"], std::time::Duration::from_secs(5), 65536);
    o.text().lines().find_map(|l| l.strip_prefix('n')).map(PathBuf::from)
}
#[cfg(not(target_os = "macos"))]
fn macos_cwd(_pid: u32) -> Option<PathBuf> {
    None
}

// ---------------------------------------------------------------- data dirs

pub fn default_base(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/IronDivi")
    } else {
        home.join(".irondivi")
    }
}

fn is_datadir(p: &Path) -> bool {
    ["irondivi.conf", "blocks", "chainstate", "wallet.dat", "wallet", "diag/runs.log"]
        .iter()
        .any(|f| p.join(f).exists())
}

pub struct Found {
    pub dirs: Vec<DataDir>,
    pub looked_at: Vec<String>,
    pub stale_records: Vec<PathRecord>,
    pub unreadable_records: Vec<PathBuf>,
}

pub fn discover(
    cli_datadir: Option<&Path>,
    cli_conf: Option<&Path>,
    nodes: &[Node],
    stale: Vec<PathRecord>,
    unreadable_records: Vec<PathBuf>,
) -> Found {
    let mut cands: Vec<(PathBuf, String)> = Vec::new();
    if let Some(d) = cli_datadir {
        cands.push((d.to_path_buf(), "--datadir".into()));
    }
    if let Some(c) = cli_conf {
        let c = if c.is_relative() {
            cli_datadir.map(|d| d.join(c)).unwrap_or_else(|| c.to_path_buf())
        } else {
            c.to_path_buf()
        };
        if let Some(text) = read_small(&c, 1 << 20) {
            let mut s = crate::settings::Settings::default();
            let _ = s.read_config(&text);
            if let Some(dd) = s.get("datadir") {
                cands.push((PathBuf::from(dd), "datadir= in --conf".into()));
            }
        }
    }
    for n in nodes.iter().filter(|n| n.component.is_none()) {
        if let Some(d) = &n.datadir {
            cands.push((d.clone(), format!("running node ({})", n.datadir_source)));
        }
    }
    for (p, why) in service_datadirs() {
        cands.push((p, why));
    }
    let mut homes: Vec<(PathBuf, String)> = Vec::new();
    if let Some(h) = user_home(uid()) {
        homes.push((h, "default for the current user".into()));
    }
    homes.push((PathBuf::from("/root"), "/root default".into()));
    for base in ["/home", "/Users"] {
        if let Ok(rd) = std::fs::read_dir(base) {
            for e in rd.flatten() {
                homes.push((e.path(), format!("{base}/* default")));
            }
        }
    }
    for (h, why) in homes {
        cands.push((h.join(".irondivi"), why.clone()));
        if cfg!(target_os = "macos") {
            cands.push((h.join("Library/Application Support/IronDivi"), why));
        }
    }
    // the current user's home is often also /root or a /home/* entry
    let mut uniq: Vec<PathBuf> = Vec::new();
    cands.retain(|(p, _)| {
        if uniq.contains(p) {
            false
        } else {
            uniq.push(p.clone());
            true
        }
    });
    cands.push(("/etc/irondivi".into(), "/etc/irondivi".into()));
    cands.push(("/var/lib/irondivi".into(), "/var/lib/irondivi".into()));

    let mut looked_at = Vec::new();
    let mut dirs: Vec<DataDir> = Vec::new();
    let mut seen: Vec<((u64, u64), usize)> = Vec::new();
    for (base, why) in cands {
        // the base and the subdirs compute_data_dir adds
        let mut chains = vec![base.clone()];
        for sub in ["testnet", "regtest", "privatedivi", "privatedivi/testnet", "privatedivi/regtest"] {
            chains.push(base.join(sub));
        }
        for chain in chains {
            let md = match std::fs::metadata(&chain) {
                Ok(m) => m,
                Err(e) => {
                    // EACCES from stat means a parent cannot be searched, so
                    // whether the folder exists is unknown: say so, but do
                    // not report it as a data dir
                    if chain == base && e.kind() == std::io::ErrorKind::PermissionDenied {
                        looked_at.push(format!(
                            "{}  cannot check: a parent folder is not searchable as this user (sudo irondivi-cli diag can)",
                            chain.display()
                        ));
                    } else if chain == base {
                        looked_at.push(format!("{}  {}", chain.display(), io_err(&e)));
                    }
                    continue;
                }
            };
            if !md.is_dir() {
                continue;
            }
            let readable = std::fs::read_dir(&chain);
            if let Err(e) = &readable {
                if chain == base {
                    looked_at.push(format!("{}  {}", chain.display(), io_err(e)));
                    if !dirs.iter().any(|d| d.path == base) {
                        dirs.push(DataDir {
                            path: base.clone(),
                            chain: base.clone(),
                            owner: Some(md.uid()),
                            readable: false,
                            read_error: Some(io_err(e)),
                            found_by: vec![why.clone()],
                            ..Default::default()
                        });
                    }
                }
                continue;
            }
            if chain == base {
                looked_at.push(format!("{}  exists", chain.display()));
            }
            if !is_datadir(&chain) {
                continue;
            }
            let key = (md.dev(), md.ino());
            if let Some((_, i)) = seen.iter().find(|(k, _)| *k == key) {
                if !dirs[*i].found_by.contains(&why) {
                    dirs[*i].found_by.push(why.clone());
                }
                continue;
            }
            let network = match chain.strip_prefix(&base).ok().and_then(|r| r.to_str()) {
                Some("") | None => "main",
                Some(r) if r.ends_with("testnet") => "testnet",
                Some(r) if r.ends_with("regtest") => "regtest",
                Some(_) => "main",
            };
            let pd = chain.components().any(|c| c.as_os_str() == "privatedivi");
            let conf = [base.join("irondivi.conf"), chain.join("irondivi.conf")]
                .into_iter()
                .find(|p| p.exists());
            seen.push((key, dirs.len()));
            dirs.push(DataDir {
                path: base.clone(),
                chain: chain.clone(),
                network: format!("{}{}", if pd { "privatedivi " } else { "" }, network),
                conf,
                owner: Some(md.uid()),
                readable: true,
                found_by: vec![why.clone()],
                ..Default::default()
            });
        }
    }
    // a running node's own data dir, matched by device and inode
    for n in nodes.iter().filter(|n| n.component.is_none()) {
        let Some(d) = &n.datadir else { continue };
        let Ok(md) = std::fs::metadata(d) else { continue };
        for dd in dirs.iter_mut() {
            if let Ok(m2) = std::fs::metadata(&dd.chain) {
                if (m2.dev(), m2.ino()) == (md.dev(), md.ino()) {
                    dd.running_pid = Some(n.pid);
                }
            }
        }
    }
    for (i, d) in dirs.iter_mut().enumerate() {
        d.n = i + 1;
    }
    Found { dirs, looked_at, stale_records: stale, unreadable_records }
}

/// `-datadir` from systemd units, OpenRC scripts and launchd plists that
/// run irondivid
fn service_datadirs() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for d in [
        "/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/init.d",
        "/Library/LaunchDaemons", "/Library/LaunchAgents",
    ] {
        if let Ok(rd) = std::fs::read_dir(d) {
            files.extend(rd.flatten().map(|e| e.path()));
        }
    }
    if let Some(h) = user_home(uid()) {
        for d in [".config/systemd/user", "Library/LaunchAgents"] {
            if let Ok(rd) = std::fs::read_dir(h.join(d)) {
                files.extend(rd.flatten().map(|e| e.path()));
            }
        }
    }
    for f in files {
        let Some(text) = read_small(&f, 256 * 1024) else { continue };
        if !text.contains("irondivid") {
            continue;
        }
        let words: Vec<String> = text
            .split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '"')
            .filter(|w| !w.is_empty())
            .map(String::from)
            .collect();
        let mut argv = vec!["irondivid".to_string()];
        argv.extend(words);
        if let Some(dd) = arg_value(&argv, "datadir") {
            out.push((PathBuf::from(dd), format!("service definition {}", f.display())));
        }
        for line in text.lines() {
            if let Some(h) = line.trim().strip_prefix("WorkingDirectory=") {
                out.push((PathBuf::from(h).join(".irondivi"), format!("service definition {}", f.display())));
            }
            if let Some(u) = line.trim().strip_prefix("User=") {
                if let Some(home) = home_of_user(u.trim()) {
                    out.push((default_base(&home), format!("User= of {}", f.display())));
                }
            }
        }
    }
    // Docker/Podman: volumes of containers whose command names irondivid
    for rt in ["docker", "podman"] {
        if which(rt).is_none() {
            continue;
        }
        let ps = run_cmd(rt, &["ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Command}}"], std::time::Duration::from_secs(10), 1 << 20);
        for line in ps.text().lines() {
            if !line.contains("irondivid") {
                continue;
            }
            let id = line.split_whitespace().next().unwrap_or("");
            let ins = run_cmd(rt, &["inspect", "--format", "{{range .Mounts}}{{.Source}}\n{{end}}", id], std::time::Duration::from_secs(10), 1 << 20);
            for src in ins.text().lines().filter(|l| !l.is_empty()) {
                out.push((PathBuf::from(src), format!("{rt} container volume")));
            }
        }
    }
    out
}

pub fn home_of_user(name: &str) -> Option<PathBuf> {
    let pw = read_small(Path::new("/etc/passwd"), 4 << 20)?;
    pw.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[0] == name).then(|| PathBuf::from(f[5]))
    })
}

/// Does root get CAP_SYS_PTRACE here (bit 19 of CapBnd)?
pub fn root_gets_ptrace() -> bool {
    if !Path::new("/proc/self/status").exists() {
        return true;
    }
    cap_bit("CapBnd", 19)
}

pub fn cap_bit(field: &str, bit: u32) -> bool {
    read_small(Path::new("/proc/self/status"), 16384)
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(&format!("{field}:")))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| u64::from_str_radix(v, 16).ok())
        })
        .map(|v| v & (1u64 << bit) != 0)
        .unwrap_or(false)
}

/// The hint for a data dir diag cannot read (B1.1)
pub fn sudo_hint(owner: Option<u32>, path: &Path) -> String {
    let who = owner
        .map(|u| user_name(u).unwrap_or_else(|| format!("#{u}")))
        .unwrap_or_else(|| "<owner>".into());
    let mut s = format!("sudo -u '{}' irondivi-cli diag --datadir '{}'", who, path.display());
    if root_gets_ptrace() {
        s.push_str("   (or: sudo irondivi-cli diag)");
    }
    s
}
