// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The B2 collectors (and B1.2/B1.3). Each runs in its own child process
//! (`irondivi-cli diag --collector <name>`) and writes through [`Out`]; the
//! parent scrubs everything before it reaches the package.
//!
//! A collector writes what it finds and, for anything it could not read,
//! one line saying what and why. Part A files that do not exist yet (the
//! node side is being built at the same time) are reported as absent.

use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use crate::util::{self, CmdOut};
use std::path::Path;
use std::time::Duration;

pub mod chain;
pub mod components;
pub mod files;
pub mod live;
pub mod logs;
pub mod observed;
pub mod platform;
pub mod probe;
pub mod rpc;
pub mod procs;
pub mod storage;
pub mod sys;

/// One collector: its §5/B2 id, the name used on the command line, its B5
/// budget and what it does
pub struct Spec {
    pub id: &'static str,
    pub name: &'static str,
    pub secs: u64,
    pub what: &'static str,
}

/// In run order. B2.0 runs first (B2.0), the run table second so the
/// summary can show it early (R1 a).
pub static ALL: &[Spec] = &[
    Spec { id: "B2.0", name: "locks", secs: 10, what: "lock holders" },
    Spec { id: "B2.14", name: "runs", secs: 30, what: "run table" },
    Spec { id: "B2.1", name: "identity", secs: 30, what: "who and when" },
    Spec { id: "B2.2", name: "host", secs: 30, what: "host" },
    Spec { id: "B2.3", name: "container", secs: 30, what: "container and virtualisation" },
    Spec { id: "B4", name: "platform", secs: 30, what: "platform backend" },
    Spec { id: "B2.4", name: "processes", secs: 30, what: "processes" },
    Spec { id: "B2.5", name: "services", secs: 30, what: "service managers" },
    Spec { id: "B2.6", name: "storage", secs: 60, what: "storage and fsync test" },
    Spec { id: "B2.7", name: "inventory", secs: 30, what: "data dir inventory" },
    Spec { id: "B2.8", name: "chaindb", secs: 120, what: "chain database, read-only secondary open" },
    Spec { id: "B1.2", name: "binaries", secs: 30, what: "binaries" },
    Spec { id: "B1.3", name: "config", secs: 30, what: "configuration" },
    Spec { id: "B2.9", name: "wallet", secs: 60, what: "wallet, from the config" },
    Spec { id: "B2.10", name: "logs", secs: 60, what: "node logs" },
    Spec { id: "B2.11", name: "kernel", secs: 30, what: "kernel and system log" },
    Spec { id: "B2.12", name: "crashes", secs: 30, what: "core dumps and crash stores" },
    Spec { id: "B2.13", name: "network", secs: 30, what: "network" },
    Spec { id: "B2.15", name: "probe", secs: 30, what: "network probe of the compiled-in seeds" },
    Spec { id: "B2.16", name: "live", secs: 60, what: "live node: RPC, process state, thread sample" },
    Spec { id: "B2.17", name: "components", secs: 60, what: "Electrum, web UI, ZMQ and the swap daemons" },
    Spec { id: "B2.18", name: "seccomp", secs: 30, what: "seccomp and sandbox" },
    Spec { id: "B2.19", name: "install", secs: 30, what: "package and install" },
];

/// B3 observed start: not in [`ALL`]; run last, only with consent (R2),
/// with its own budget on top of the collection's (B5: +5 min; the ladder
/// can take 300 + 120 + 120 + 5 s, so the parent allows 660)
pub static OBSERVED: Spec = Spec { id: "B3", name: "observed", secs: 660, what: "observed start of irondivid" };

/// B6.5 `--rpc`: not in [`ALL`]; run after the collection, only for the
/// calls the user named; every call has 2 s, all of them 60 s together
pub static RPC: Spec = Spec { id: "B6.5", name: "rpc", secs: 75, what: "RPC calls you named" };

/// B2 items this version does not collect; listed in the summary
pub static NOT_YET: &[&str] = &[];

/// Run one collector in this (child) process; false for an unknown name
pub fn run(name: &str, ctx: &Ctx, o: &mut Out) -> bool {
    match name {
        "locks" => sys::locks(ctx, o),
        "runs" => logs::runs(ctx, o),
        "identity" => sys::identity(ctx, o),
        "host" => sys::host(ctx, o),
        "container" => sys::container(ctx, o),
        "platform" => platform::platform(ctx, o),
        "processes" => procs::processes(ctx, o),
        "services" => procs::services(ctx, o),
        "storage" => storage::storage(ctx, o),
        "inventory" => storage::inventory(ctx, o),
        "chaindb" => chain::chaindb(ctx, o),
        "binaries" => files::binaries(ctx, o),
        "config" => files::config(ctx, o),
        "wallet" => files::wallet(ctx, o),
        "logs" => logs::logs(ctx, o),
        "kernel" => logs::kernel(ctx, o),
        "crashes" => logs::crashes(ctx, o),
        "network" => sys::network(ctx, o),
        "probe" => probe::probe(ctx, o),
        "live" => live::live(ctx, o),
        "components" => components::components(ctx, o),
        "seccomp" => sys::seccomp(ctx, o),
        "install" => files::install(ctx, o),
        "observed" => observed::observed(ctx, o),
        "rpc" => rpc::rpc(ctx, o),
        _ => return false,
    }
    true
}

pub(crate) const LINUX: bool = cfg!(target_os = "linux");

/// `== title ==`
pub(crate) fn head(o: &mut Out, title: &str) {
    outln!(o);
    outln!(o, "== {title} ==");
}

/// Run a command and write it, its end state when not 0, and its output
pub(crate) fn cmd_block(o: &mut Out, prog: &str, args: &[&str]) -> CmdOut {
    cmd_block_t(o, prog, args, 10, 2 << 20)
}

pub(crate) fn cmd_block_t(o: &mut Out, prog: &str, args: &[&str], secs: u64, cap: usize) -> CmdOut {
    outln!(o, "$ {} {}", prog, args.join(" "));
    if util::which(prog).is_none() {
        outln!(o, "  (not installed)");
        return CmdOut { stdout: vec![], stderr: vec![], code: None, signal: None, timed_out: false, spawn_error: Some("not installed".into()) };
    }
    let r = util::run_cmd(prog, args, Duration::from_secs(secs), cap);
    if !r.ok() {
        outln!(o, "  [{}]", r.status_line());
    }
    let t = r.text();
    o.write(t.as_bytes());
    if !t.is_empty() && !t.ends_with('\n') {
        outln!(o);
    }
    if !r.ok() && !r.stderr.is_empty() {
        for l in util::escape_bytes(&r.stderr).lines().take(10) {
            outln!(o, "  stderr: {l}");
        }
    }
    r
}

/// A small file in full, or why not
pub(crate) fn file_block(o: &mut Out, path: &str) {
    match util::read_bytes_capped(Path::new(path), 1 << 20) {
        Ok(b) => {
            outln!(o, "--- {path}");
            let t = util::escape_bytes(&b);
            o.write(t.as_bytes());
            if !t.is_empty() && !t.ends_with('\n') {
                outln!(o);
            }
        }
        Err(e) => outln!(o, "--- {path}: {}", util::io_err(&e)),
    }
}

/// One line from a small file, trimmed
pub(crate) fn one(path: &str) -> String {
    match util::read_bytes_capped(Path::new(path), 64 << 10) {
        Ok(b) => util::escape_bytes(&b).trim().to_string(),
        Err(e) => format!("({})", util::io_err(&e)),
    }
}

/// `Name:\tvalue` fields of `/proc/<pid>/status`
pub(crate) fn status_fields(pid: &str, keys: &[&str]) -> Vec<String> {
    let s = util::read_small(Path::new(&format!("/proc/{pid}/status")), 16384).unwrap_or_default();
    s.lines()
        .filter(|l| keys.iter().any(|k| l.split(':').next() == Some(k)))
        .map(|l| l.replace('\t', " "))
        .collect()
}
