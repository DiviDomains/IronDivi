// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A7: `<datadir>/diag/startup/<run>.txt`, the environment a run started
//! in. One file per run, the last 20 kept, at most 64 KB each, mode 0600.
//!
//! What it holds: the masked argv; every configuration key with its source
//! (`argument`, `file`, `default`) and a value only for keys whose values
//! are numbers, switches or words (anything else is `<set>`); unknown keys
//! by name only; every environment variable's name, and the value of an
//! allowlist; rlimits; seccomp, `NoNewPrivs` and capabilities from
//! `/proc/self/status`; the dumpable flag; CPU model and features; page
//! size; the data dir's filesystem type and mount options; build facts;
//! the time zone; the working directory from before the `-daemon` chdir.
//!
//! Never read: `/proc/self/environ` (D5); the environment comes from the
//! process's own copy.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::OnceLock;

const KEEP: usize = 20;
const CAP: usize = 64 * 1024;

/// The working directory at start, before `-daemon` moves it
static START_CWD: OnceLock<String> = OnceLock::new();

/// Keys whose values are numbers, switches or plain words: written as they
/// are. Every other value (secrets, addresses, paths, commands) is `<set>`.
const SHOWN: &[&str] = &[
    "addressindex",
    "banscore",
    "bantime",
    "blockmaxsize",
    "blockminsize",
    "blockprioritysize",
    "checkblocks",
    "daemon",
    "debug",
    "disablewallet",
    "discover",
    "electrum",
    "electrumtls",
    "electrumws",
    "electrumwss",
    "expire",
    "listen",
    "loglevel",
    "maxconnections",
    "maxlogfiles",
    "maxlogsize",
    "maxorphantx",
    "maxreorg",
    "maxtxfee",
    "minrelaytxfee",
    "mode",
    "port",
    "printtoconsole",
    "regtest",
    "reindex",
    "rescan",
    "rpcport",
    "server",
    "spentindex",
    "stakeonstaletip",
    "stakesplitthreshold",
    "staking",
    "testnet",
    "timeout",
    "txindex",
    "utxocachesize",
    "vault",
    "webui",
    "webuiport",
];

/// Environment variables whose values are written (`MALLOC_*` by prefix;
/// `LD_*` as basenames)
const ENV_SHOWN: &[&str] = &[
    "RUST_LOG",
    "RUST_BACKTRACE",
    "TZ",
    "LANG",
    "IRONDIVI_EXPIRE",
    "IRONDIVI_TEST_CRASH",
    "IRONDIVI_TEST_PANIC",
];

/// Note the working directory; called before the `-daemon` chdir
pub fn capture() {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|e| format!("unreadable: {}", e));
    let _ = START_CWD.set(cwd);
}

/// The configuration as the record needs it
pub struct Options<'a> {
    /// The command line alone
    pub cli: &'a divi_settings::Settings,
    /// The command line, then the config file
    pub all: &'a divi_settings::Settings,
    /// Every key irondivid knows, for the defaults
    pub known_keys: &'a [&'a [&'a str]],
}

/// Write this run's record; nothing when runs.log is not kept
pub fn write(data_dir: &Path, options: &Options) {
    let run = crate::runs_log::run_number();
    if run == 0 {
        return;
    }
    let dir = data_dir.join("diag").join("startup");
    if crate::private_files::ensure_private_dir(&dir, true).is_err() {
        return;
    }
    let argv: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let mut text = record(run, &argv, options, data_dir);
    cap(&mut text);
    let mut open = std::fs::OpenOptions::new();
    open.create(true).write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
    if let Ok(mut file) = open.open(dir.join(format!("{}.txt", run))) {
        let _ = std::io::Write::write_all(&mut file, text.as_bytes());
    }
    for n in to_remove(&numbered(&dir)) {
        let _ = std::fs::remove_file(dir.join(format!("{}.txt", n)));
    }
}

fn record(run: u64, argv: &[String], options: &Options, data_dir: &Path) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "startup run={} time={} version={}",
        run,
        crate::runs_log::utc_now(),
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(s, "\n[argv]\n{}", mask_argv(argv));
    s.push_str("\n[config]\n");
    config(&mut s, options);
    s.push_str("\n[env]\n");
    environment(&mut s, std::env::vars_os());
    s.push_str("\n[rlimits]\n");
    rlimits(&mut s);
    s.push_str("\n[process]\n");
    process(&mut s);
    s.push_str("\n[cpu]\n");
    cpu(&mut s);
    s.push_str("\n[datadir]\n");
    filesystem(&mut s, data_dir);
    let _ = writeln!(
        s,
        "\n[build]\ntarget={} profile={} rustc={} git={} features={} frame_pointers={}",
        env!("IRONDIVID_TARGET"),
        env!("IRONDIVID_PROFILE"),
        crate::runs_log::quote(env!("IRONDIVID_RUSTC")),
        env!("IRONDIVID_GIT"),
        if cfg!(feature = "fault-injection") {
            "fault-injection"
        } else {
            "-"
        },
        env!("IRONDIVID_FRAME_POINTERS"),
    );
    s.push_str("\n[time]\n");
    time_zone(&mut s);
    let _ = writeln!(
        s,
        "\n[cwd]\ncwd={}",
        crate::runs_log::quote(START_CWD.get().map_or("-", |c| c.as_str()))
    );
    s
}

/// A value fit to write as it is: short, and only word characters
fn plain(value: &str) -> bool {
    value.len() <= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ',' | '_' | '-' | ':' | '+'))
}

/// argv with no value the record may not hold: the basename of argv[0],
/// option names as written, the values of [`SHOWN`] options when plain,
/// `<v>` for any other option value and `<arg>` for any other word
fn mask_argv(argv: &[String]) -> String {
    let mut out = Vec::new();
    let mut words = argv.iter();
    if let Some(first) = words.next() {
        out.push(first.rsplit('/').next().unwrap_or("").to_string());
    }
    for a in words {
        let body = a.trim_start_matches('-');
        if body.len() == a.len() || body.is_empty() {
            out.push("<arg>".into());
            continue;
        }
        let dashes = &a[..a.len() - body.len()];
        let (name, value) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (body, None),
        };
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '?'))
        {
            out.push("<arg>".into());
            continue;
        }
        let key = name.to_ascii_lowercase();
        let key = key.strip_prefix("no").filter(|k| SHOWN.contains(k)).unwrap_or(&key);
        match value {
            None => out.push(a.clone()),
            Some(v) if SHOWN.contains(&key) && plain(v) => out.push(a.clone()),
            Some(_) => out.push(format!("{}{}=<v>", dashes, name)),
        }
    }
    out.join(" ")
}

fn config(s: &mut String, o: &Options) {
    let mut set: Vec<&String> = o.all.keys().collect();
    set.sort();
    for key in &set {
        let k = key.as_str();
        let source = if o.cli.is_set(k) { "argument" } else { "file" };
        if !o.known_keys.iter().any(|l| l.contains(&k)) {
            let _ = writeln!(s, "unknown name={} source={}", sanitize_name(k), source);
            continue;
        }
        let values = o.all.get_multi(k);
        let value = if values.len() > 1 {
            if SHOWN.contains(&k) && values.iter().all(|v| plain(v)) {
                values.join(",")
            } else {
                format!("<set x{}>", values.len())
            }
        } else {
            match o.all.get(k) {
                Some("") => "<empty>".into(),
                Some(v) if SHOWN.contains(&k) && plain(v) => v.to_string(),
                Some(_) => "<set>".into(),
                None => "<unset>".into(),
            }
        };
        let _ = writeln!(s, "{} source={} value={}", k, source, value);
    }
    let mut defaults: Vec<&str> = o
        .known_keys
        .iter()
        .flat_map(|l| l.iter().copied())
        .filter(|k| !o.all.is_set(k) && *k != "?")
        .collect();
    defaults.sort();
    defaults.dedup();
    let _ = writeln!(s, "defaults={}", defaults.join(","));
}

/// A key or variable name as written, with nothing but name characters
fn sanitize_name(name: &str) -> String {
    name.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn environment(
    s: &mut String,
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) {
    let mut all: Vec<(String, String)> = vars
        .map(|(n, v)| {
            (
                n.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    all.sort();
    for (name, value) in all {
        let shown = if ENV_SHOWN.contains(&name.as_str()) || name.starts_with("MALLOC_") {
            Some(crate::runs_log::quote(&value))
        } else if name == "LD_PRELOAD" || name == "LD_LIBRARY_PATH" {
            let parts: Vec<&str> = value
                .split([':', ' '])
                .filter(|p| !p.is_empty())
                .map(|p| p.rsplit('/').next().unwrap_or(""))
                .collect();
            Some(crate::runs_log::quote(&parts.join(":")))
        } else {
            None
        };
        match shown {
            Some(v) => {
                let _ = writeln!(s, "{}={}", sanitize_name(&name), v);
            }
            None => {
                let _ = writeln!(s, "{}", sanitize_name(&name));
            }
        }
    }
}

#[cfg(unix)]
fn rlimits(s: &mut String) {
    let limits = [
        ("core", libc::RLIMIT_CORE),
        ("nofile", libc::RLIMIT_NOFILE),
        ("nproc", libc::RLIMIT_NPROC),
        ("as", libc::RLIMIT_AS),
        ("data", libc::RLIMIT_DATA),
        ("stack", libc::RLIMIT_STACK),
        ("memlock", libc::RLIMIT_MEMLOCK),
        ("fsize", libc::RLIMIT_FSIZE),
    ];
    let show = |v: libc::rlim_t| {
        if v == libc::RLIM_INFINITY {
            "unlimited".to_string()
        } else {
            v.to_string()
        }
    };
    for (name, resource) in limits {
        let mut l = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(resource, &mut l) } == 0 {
            let _ = writeln!(
                s,
                "{} soft={} hard={}",
                name,
                show(l.rlim_cur),
                show(l.rlim_max)
            );
        } else {
            let _ = writeln!(s, "{} unreadable", name);
        }
    }
}

#[cfg(not(unix))]
fn rlimits(s: &mut String) {
    s.push_str("n/a\n");
}

fn process(s: &mut String) {
    #[cfg(target_os = "linux")]
    {
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        let _ = writeln!(s, "dumpable={}", dumpable);
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => {
                for line in status.lines() {
                    let Some((key, value)) = line.split_once(':') else {
                        continue;
                    };
                    if matches!(
                        key,
                        "Seccomp"
                            | "Seccomp_filters"
                            | "NoNewPrivs"
                            | "CapInh"
                            | "CapPrm"
                            | "CapEff"
                            | "CapBnd"
                            | "CapAmb"
                    ) {
                        let _ = writeln!(s, "{}={}", key, value.trim());
                    }
                }
            }
            Err(e) => {
                let _ = writeln!(s, "status unreadable: {}", e);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    s.push_str("dumpable=n/a\nstatus n/a\n");
}

fn cpu(s: &mut String) {
    #[cfg(unix)]
    {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let _ = writeln!(s, "page_size={}", page);
    }
    let _ = writeln!(
        s,
        "cpus={}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(info) => {
            let first = |keys: &[&str]| {
                info.lines().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    keys.contains(&k.trim()).then(|| v.trim().to_string())
                })
            };
            let model = first(&["model name", "Model", "CPU part"]).unwrap_or_else(|| "-".into());
            let _ = writeln!(s, "model={}", crate::runs_log::quote(&model));
            let features = first(&["flags", "Features"]).unwrap_or_else(|| "-".into());
            let _ = writeln!(s, "features={}", features);
        }
        Err(_) => s.push_str("model=n/a\nfeatures=n/a\n"),
    }
}

/// The mount holding `data_dir`, from `/proc/self/mountinfo`: its type and
/// options, not its path
fn filesystem(s: &mut String, data_dir: &Path) {
    let dir = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(info) => match mount_of(&info, &dir) {
            Some((fs_type, options)) => {
                let _ = writeln!(s, "fs_type={} mount_options={}", fs_type, options);
            }
            None => s.push_str("fs_type=- mount_options=-\n"),
        },
        Err(_) => s.push_str("fs_type=n/a mount_options=n/a\n"),
    }
}

fn mount_of(info: &str, dir: &Path) -> Option<(String, String)> {
    let mut best: Option<(usize, String, String)> = None;
    for line in info.lines() {
        let Some((head, tail)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<&str> = head.split(' ').collect();
        let (Some(point), Some(options)) = (fields.get(4), fields.get(5)) else {
            continue;
        };
        let point = point.replace("\\040", " ").replace("\\011", "\t");
        if !dir.starts_with(&point) {
            continue;
        }
        let fs_type = tail.split(' ').next().unwrap_or("-").to_string();
        if best.as_ref().is_none_or(|b| point.len() >= b.0) {
            best = Some((point.len(), fs_type, options.to_string()));
        }
    }
    best.map(|(_, t, o)| (t, o))
}

fn time_zone(s: &mut String) {
    let tz = std::env::var("TZ").unwrap_or_else(|_| "-".into());
    let zone = std::fs::read_link("/etc/localtime")
        .ok()
        .and_then(|p| {
            let p = p.display().to_string();
            p.split_once("zoneinfo/").map(|(_, z)| z.to_string())
        })
        .unwrap_or_else(|| "-".into());
    #[cfg(unix)]
    let offset = {
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() {
            "-".to_string()
        } else {
            let off = tm.tm_gmtoff;
            format!(
                "{}{:02}{:02}",
                if off < 0 { '-' } else { '+' },
                off.abs() / 3600,
                off.abs() % 3600 / 60
            )
        }
    };
    #[cfg(not(unix))]
    let offset = "-".to_string();
    let _ = writeln!(
        s,
        "tz={} localtime={} utc_offset={}",
        crate::runs_log::quote(&tz),
        crate::runs_log::quote(&zone),
        offset
    );
}

/// Cut a record over [`CAP`] at a line end, and say so
fn cap(text: &mut String) {
    if text.len() <= CAP {
        return;
    }
    let mut end = CAP - 32;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let end = text[..end].rfind('\n').map_or(end, |n| n + 1);
    text.truncate(end);
    text.push_str("truncated=yes\n");
}

fn numbered(dir: &Path) -> Vec<u64> {
    let mut out: Vec<u64> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.strip_suffix(".txt")?.parse().ok())
        .collect();
    out.sort();
    out
}

/// The oldest records past [`KEEP`]
fn to_remove(runs: &[u64]) -> Vec<u64> {
    runs[..runs.len().saturating_sub(KEEP)].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_keeps_names_and_plain_values_only() {
        let argv: Vec<String> = [
            "/opt/bin/irondivid",
            "-regtest",
            "-datadir=/home/alice/.divi",
            "-rpcpassword=hunter2",
            "-rpcport=19999",
            "--wallet",
            "/home/alice/w.dat",
            "-nolisten",
            "-staking=0",
            "-port=$(rm)",
            "-bad name=x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            mask_argv(&argv),
            "irondivid -regtest -datadir=<v> -rpcpassword=<v> -rpcport=19999 --wallet <arg> \
             -nolisten -staking=0 -port=<v> <arg>"
        );
    }

    #[test]
    fn only_allowlisted_variables_keep_their_values() {
        let vars = [
            ("RUST_LOG", "info"),
            ("SECRET_TOKEN", "abc123"),
            ("LD_PRELOAD", "/usr/lib/libjemalloc.so /opt/x/libtrace.so"),
            ("MALLOC_ARENA_MAX", "2"),
            ("HOME", "/home/alice"),
        ]
        .into_iter()
        .map(|(n, v)| (n.into(), v.into()));
        let mut s = String::new();
        environment(&mut s, vars);
        assert!(s.contains("RUST_LOG=\"info\"\n"), "{s}");
        assert!(s.contains("SECRET_TOKEN\n"), "{s}");
        assert!(!s.contains("abc123"), "{s}");
        assert!(s.contains("LD_PRELOAD=\"libjemalloc.so:libtrace.so\""), "{s}");
        assert!(s.contains("MALLOC_ARENA_MAX=\"2\""), "{s}");
        assert!(s.contains("HOME\n") && !s.contains("alice"), "{s}");
    }

    #[test]
    fn the_longest_mount_holding_the_dir_is_used() {
        let info = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                    40 22 8:2 / /data\\040x rw,noatime shared:2 - xfs /dev/sdb1 rw\n\
                    41 22 0:5 / /dat rw - tmpfs tmpfs rw\n";
        assert_eq!(
            mount_of(info, Path::new("/data x/divi")),
            Some(("xfs".into(), "rw,noatime".into()))
        );
        assert_eq!(
            mount_of(info, Path::new("/home/alice")),
            Some(("ext4".into(), "rw,relatime".into()))
        );
    }

    #[test]
    fn a_long_record_is_cut_at_a_line_and_the_last_twenty_kept() {
        let mut text = ("x".repeat(100) + "\n").repeat(1000);
        cap(&mut text);
        assert!(text.len() <= CAP);
        assert!(text.ends_with("\ntruncated=yes\n"));
        let runs: Vec<u64> = (1..=23).collect();
        assert_eq!(to_remove(&runs), vec![1, 2, 3]);
        assert!(to_remove(&runs[..20]).is_empty());
    }
}
