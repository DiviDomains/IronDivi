// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.4 processes and B2.5 service managers.

use super::{cmd_block_t, head, LINUX};
use crate::ctx::Ctx;
use crate::discovery::basename;
use crate::frame::Out;
use crate::outln;
use crate::util;
use std::path::Path;
use std::time::Duration;

/// §6.2 option keys whose values are not private; every other value is masked
pub const ARGV_ALLOW: &[&str] = &[
    "testnet", "regtest", "daemon", "staking", "loglevel", "debug", "printtoconsole", "listen",
    "maxconnections", "dbcache", "par", "txindex", "spentindex", "addressindex", "server", "rest",
    "disablewallet", "walletbroadcast", "createwalletbackups", "upnp", "discover", "dns", "dnsseed",
    "maxmempool", "mempoolexpiry", "checkblocks", "checklevel", "reindex", "reindex-chainstate",
    "prune", "logtimestamps", "logips", "shrinkdebugfile", "rpcthreads", "rpcworkqueue", "timeout",
    "banscore", "bantime", "maxuploadtarget", "blocksonly", "masternode", "litemode", "mocktime",
    "help", "version", "diag", "no-run", "run", "no-submit", "submit", "stdin", "rpcwait",
];

/// The RPC methods irondivi knows (crates/divi-rpc/src/server.rs)
pub const RPC_METHODS: &[&str] = &["addmultisigaddress", "addnode", "addvault", "allocatefunds", "backupwallet", "ban", "broadcaststartmasternode", "clearbanned", "createmultisig", "createrawtransaction", "debitvaultbyname", "decoderawtransaction", "decodescript", "disconnectnode", "dumphdinfo", "dumpprivkey", "encryptwallet", "estimatefee", "estimatepriority", "estimatesmartfee", "fundvault", "generateblock", "getaccount", "getaccountaddress", "getaddednodeinfo", "getaddressbalance", "getaddressdeltas", "getaddressesbyaccount", "getaddressesbylabel", "getaddresshistory", "getaddressinfo", "getaddresstxids", "getaddressutxos", "getbalance", "getbestblockhash", "getblock", "getblockchaininfo", "getblockcount", "getblockhash", "getblockheader", "getchaintips", "getcoinavailability", "getconnectioncount", "getdifficulty", "getimmaturebalance", "getinfo", "getinvalid", "getkeypoolsize", "getlitewalletinfo", "getlogconfig", "getlotteryblockwinners", "getmasternodecount", "getmasternodestatus", "getmasternodewinners", "getmempoolinfo", "getmininginfo", "getmintinginfo", "getnettotals", "getnetworkinfo", "getnewaddress", "getpeerinfo", "getpeerscores", "getrawchangeaddress", "getrawmempool", "getrawtransaction", "getreceivedbyaccount", "getreceivedbyaddress", "getspentinfo", "getstakesplitthreshold", "getstakingstatus", "gettransaction", "gettxindex", "gettxout", "gettxoutsetinfo", "getunconfirmedbalance", "getwalletinfo", "help", "importaddress", "importmnbroadcast", "importprivkey", "invalidateblock", "keypoolrefill", "listaccounts", "listbanned", "listlockunspent", "listmasternodes", "listmnbroadcasts", "listreceivedbyaccount", "listreceivedbyaddress", "listsinceblock", "listtransactions", "listunspent", "loadwallet", "lockunspent", "mnsync", "ping", "prioritisetransaction", "reclaimvaultfunds", "reconsiderblock", "removevault", "rescanblockchain", "reservebalance", "reverseblocktransactions", "sendfrom", "sendmany", "sendrawtransaction", "sendtoaddress", "setaccount", "setban", "setgenerate", "setlogconfig", "setmocktime", "setstakesplitthreshold", "setstaking", "setupmasternode", "signmessage", "signmnbroadcast", "signrawtransaction", "signrawtransactionwithwallet", "signtransactionwithaddresskey", "spork", "startmasternode", "stop", "validateaddress", "validateaddresses", "verifychain", "verifymasternodesetup", "verifymessage", "walletlock", "walletpassphrase", "walletpassphrasechange"];

fn opt_key(a: &str) -> String {
    let k = a.trim_start_matches('-').split('=').next().unwrap_or("").to_ascii_lowercase();
    k.strip_prefix("no").filter(|r| ARGV_ALLOW.contains(r)).map(str::to_string).unwrap_or(k)
}

/// §6.2 command-line rendering. irondivid and the other irondivi programs:
/// options with values outside [`ARGV_ALLOW`] masked, other positionals
/// `<arg>`; irondivi-cli: the options, then the method name if it is a known
/// one, then `<arg>` for everything after; anything else: the basename of
/// argv[0] and `<arg>` per argument.
pub fn mask_argv(argv: &[String]) -> String {
    let Some(a0) = argv.first() else { return String::new() };
    let base = crate::discovery::basename(a0);
    let mut out = vec![base.clone()];
    if !(base.starts_with("irondivi") || base.starts_with("divi-swap")) {
        out.extend(argv[1..].iter().map(|_| "<arg>".to_string()));
        return out.join(" ");
    }
    let cli = base.starts_with("irondivi-cli");
    let mut method_seen = false;
    for a in &argv[1..] {
        if a.starts_with('-') && a.len() > 1 && !method_seen {
            let k = opt_key(a);
            match a.split_once('=') {
                Some((key, _)) if !ARGV_ALLOW.contains(&k.as_str()) => out.push(format!("{key}=<set>")),
                _ => out.push(a.clone()),
            }
        } else if cli && !method_seen {
            method_seen = true;
            out.push(if RPC_METHODS.contains(&a.as_str()) || a == "diag" { a.clone() } else { "<arg>".into() });
        } else {
            out.push("<arg>".into());
        }
    }
    out.join(" ")
}

/// A cron line (§6.2): the schedule (and, in system crontabs, a user
/// field that the caller's scrub handles) as written; each command word
/// that names an irondivi program rendered by [`mask_argv`] up to the next
/// shell operator; the first word of any other command as its basename;
/// every other word `<arg>`
pub fn cron_line(l: &str) -> String {
    const REDIRS: &[&str] = &[">", ">>", "2>", "<"];
    let w: Vec<&str> = l.split_whitespace().collect();
    let sched = if w.first().is_some_and(|x| x.starts_with('@')) { 1 } else { 5.min(w.len()) };
    let mut out: Vec<String> = w[..sched].iter().map(|s| s.to_string()).collect();
    let ops = ["&&", "||", ";", "|", ">", ">>", "2>&1", "2>", "<"];
    let mut i = sched;
    while i < w.len() {
        let word = w[i];
        if ops.contains(&word) {
            out.push(word.to_string());
            i += 1;
        } else if crate::discovery::basename(word).starts_with("irondivi") {
            let mut j = i;
            while j < w.len() && !ops.contains(&w[j]) {
                j += 1;
            }
            let argv: Vec<String> = w[i..j].iter().map(|s| s.to_string()).collect();
            out.push(mask_argv(&argv));
            i = j;
        } else if i > sched && REDIRS.contains(&w[i - 1]) {
            // a redirection target is a path
            out.push("<arg>".into());
            i += 1;
        } else if i == sched || ops.contains(&w[i - 1]) {
            out.push(crate::discovery::basename(word));
            i += 1;
        } else {
            out.push("<arg>".into());
            i += 1;
        }
    }
    out.join(" ")
}

fn is_irondivi(name: &str) -> bool {
    name.starts_with("irondivi") || name.starts_with("divi-swap")
}

struct P {
    pid: u32,
    ppid: u32,
    uid: u32,
    start: String,
    rss_kb: u64,
    state: char,
    comm: String,
    exe: String,
    argv: Vec<String>,
}

fn boot_time() -> i64 {
    util::read_small(Path::new("/proc/stat"), 1 << 20)
        .and_then(|s| s.lines().find(|l| l.starts_with("btime ")).and_then(|l| l[6..].trim().parse().ok()))
        .unwrap_or(0)
}

fn linux_procs() -> Vec<P> {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as i64;
    let page_kb = (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) / 1024) as u64;
    let bt = boot_time();
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return v };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Some(stat) = util::read_small(&e.path().join("stat"), 4096) else { continue };
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else { continue };
        let comm = stat[open + 1..close].to_string();
        let rest: Vec<&str> = stat[close + 2..].split_whitespace().collect();
        let state = rest.first().and_then(|s| s.chars().next()).unwrap_or('?');
        let ppid = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let start_ticks: i64 = rest.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);
        let rss_pages: u64 = rest.get(21).and_then(|s| s.parse().ok()).unwrap_or(0);
        let uid = std::fs::metadata(e.path()).map(|m| std::os::unix::fs::MetadataExt::uid(&m)).unwrap_or(0);
        let exe = std::fs::read_link(e.path().join("exe")).map(|p| basename(&p.to_string_lossy())).unwrap_or_default();
        let argv = if is_irondivi(&comm) || is_irondivi(&exe) {
            std::fs::read(e.path().join("cmdline"))
                .unwrap_or_default()
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(util::escape_bytes)
                .collect()
        } else {
            vec![]
        };
        v.push(P {
            pid,
            ppid,
            uid,
            start: if bt > 0 { util::rfc3339(bt + start_ticks / hz) } else { String::new() },
            rss_kb: rss_pages * page_kb,
            state,
            comm,
            exe,
            argv,
        });
    }
    v.sort_by_key(|p| p.pid);
    v
}

fn mac_procs() -> Vec<P> {
    let r = util::run_cmd("ps", &["-axww", "-o", "pid=,ppid=,uid=,rss=,state=,lstart=,comm="], Duration::from_secs(10), 16 << 20);
    let mut v = Vec::new();
    for l in r.text().lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.len() < 11 {
            continue;
        }
        let comm_path = t[10..].join(" ");
        let comm = basename(&comm_path);
        v.push(P {
            pid: t[0].parse().unwrap_or(0),
            ppid: t[1].parse().unwrap_or(0),
            uid: t[2].parse().unwrap_or(0),
            rss_kb: t[3].parse().unwrap_or(0),
            state: t[4].chars().next().unwrap_or('?'),
            start: t[5..10].join(" "),
            exe: comm.clone(),
            comm,
            argv: vec![],
        });
    }
    // full argv for irondivi processes only
    let full = util::run_cmd("ps", &["-axww", "-o", "pid=,command="], Duration::from_secs(10), 16 << 20);
    for l in full.text().lines() {
        let l = l.trim_start();
        let Some((pid, cmd)) = l.split_once(' ') else { continue };
        let Ok(pid) = pid.parse::<u32>() else { continue };
        if let Some(p) = v.iter_mut().find(|p| p.pid == pid && is_irondivi(&p.comm)) {
            p.argv = cmd.split_whitespace().map(String::from).collect();
        }
    }
    v
}

fn user_col(r: &crate::redact::Redactor, uid: u32, node_uids: &[u32]) -> String {
    if uid == 0 {
        return "root".into();
    }
    let name = util::user_name(uid).unwrap_or_else(|| uid.to_string());
    if node_uids.contains(&uid) {
        format!("{} (node user)", r.user(&name))
    } else {
        r.user(&name)
    }
}

/// B2.4
pub fn processes(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("processes/processes.txt");
    let procs = if LINUX { linux_procs() } else { mac_procs() };
    let node_uids: Vec<u32> = ctx.nodes.iter().filter_map(|n| n.uid).collect();
    let me = std::process::id();
    outln!(o, "Every process: comm and executable name only, except irondivi processes (masked argv).");
    outln!(o, "{:>7} {:>7} {:<22} {:<24} {:>9} {} {:<16} {}", "pid", "ppid", "user", "start", "rss", "s", "comm", "exe / argv");
    for p in &procs {
        let tail = if !p.argv.is_empty() && p.pid != me {
            mask_argv(&p.argv)
        } else if p.exe != p.comm && !p.exe.is_empty() {
            p.exe.clone()
        } else {
            String::new()
        };
        outln!(
            o,
            "{:>7} {:>7} {:<22} {:<24} {:>9} {} {:<16} {}",
            p.pid,
            p.ppid,
            user_col(&r, p.uid, &node_uids),
            p.start,
            util::human(p.rss_kb * 1024),
            p.state,
            p.comm,
            tail
        );
    }

    head(o, "supervisors and process managers present");
    let names: Vec<&str> = procs.iter().map(|p| p.comm.as_str()).collect();
    for (what, comms) in [
        ("systemd", &["systemd"][..]),
        ("OpenRC", &["openrc", "openrc-init", "supervise-daemon"]),
        ("supervisord", &["supervisord"]),
        ("runit", &["runsvdir", "runsv"]),
        ("s6", &["s6-svscan", "s6-supervise"]),
        ("pm2", &["PM2", "pm2"]),
        ("docker", &["dockerd", "containerd"]),
        ("podman", &["podman", "conmon"]),
        ("launchd", &["launchd"]),
        ("cron", &["cron", "crond", "busybox-crond"]),
        ("earlyoom", &["earlyoom"]),
        ("systemd-oomd", &["systemd-oomd"]),
        ("watchdog", &["watchdog", "monit"]),
    ] {
        let n = names.iter().filter(|c| comms.iter().any(|x| c.starts_with(x))).count();
        if n > 0 {
            outln!(o, "{what}: {n} process{}", if n == 1 { "" } else { "es" });
        }
    }

    head(o, "the node's ancestors (comm only)");
    for n in &ctx.nodes {
        let mut chain = Vec::new();
        let mut cur = n.pid;
        for _ in 0..16 {
            let Some(p) = procs.iter().find(|p| p.pid == cur) else { break };
            chain.push(format!("{}({})", p.comm, p.pid));
            if p.ppid == 0 || p.ppid == cur {
                break;
            }
            cur = p.ppid;
        }
        outln!(o, "{}", chain.join(" <- "));
        let held = chain.iter().any(|c| ["screen", "SCREEN", "tmux", "nohup", "setsid"].iter().any(|x| c.starts_with(x)));
        if held {
            outln!(o, "  held by a terminal multiplexer or nohup/setsid");
        }
        if LINUX {
            outln!(o, "  oom_score_adj {}", super::one(&format!("/proc/{}/oom_score_adj", n.pid)));
        }
    }
    if ctx.nodes.is_empty() {
        outln!(o, "no node running");
    }

    head(o, "cron entries naming irondivi");
    let mut files: Vec<String> = vec!["/etc/crontab".into()];
    for d in ["/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron", "/etc/crontabs", "/usr/lib/cron/tabs"] {
        if let Ok(rd) = std::fs::read_dir(d) {
            files.extend(rd.flatten().map(|e| e.path().to_string_lossy().into_owned()));
        }
    }
    let mut any = false;
    for f in &files {
        match std::fs::read_to_string(f) {
            Ok(t) => {
                for l in t.lines().filter(|l| l.to_ascii_lowercase().contains("irondivi") && !l.trim_start().starts_with('#')) {
                    any = true;
                    outln!(o, "{}: {}", r.path(f), cron_line(l));
                }
            }
            Err(_) => continue,
        }
    }
    // our own user's crontab (no root needed)
    if util::which("crontab").is_some() {
        let c = util::run_cmd("crontab", &["-l"], Duration::from_secs(5), 1 << 20);
        for l in c.text().lines().filter(|l| l.to_ascii_lowercase().contains("irondivi") && !l.trim_start().starts_with('#')) {
            any = true;
            outln!(o, "crontab -l: {}", cron_line(l));
        }
    }
    if !any {
        outln!(o, "none found (other users' crontabs need root)");
    }

    if LINUX && procs.iter().any(|p| p.comm == "systemd-oomd") {
        head(o, "systemd-oomd");
        cmd_block_t(o, "oomctl", &[], 5, 256 << 10);
    }
}

/// The systemd unit running a pid, from its cgroup (`.../foo.service`)
pub(crate) fn unit_of(pid: u32) -> Option<(String, bool)> {
    let cg = super::sys::cgroup_of(&pid.to_string());
    let user = cg.contains("/user@");
    cg.split('/').rev().find(|s| s.ends_with(".service") && !s.starts_with("user@")).map(|s| (s.to_string(), user))
}

const SHOW_PROPS: &str = "Id,LoadState,ActiveState,SubState,Result,NRestarts,ExecMainStatus,ExecMainCode,ExecMainStartTimestamp,ExecMainExitTimestamp,ActiveEnterTimestamp,InactiveEnterTimestamp,Restart,RestartUSec,TimeoutStopUSec,KillMode,MemoryMax,MemoryHigh,TasksMax,LimitNOFILE,User,ManagedOOMSwap,ManagedOOMMemoryPressure,OOMPolicy,WatchdogUSec";

fn systemd_unit(o: &mut Out, r: &crate::redact::Redactor, unit: &str, user: bool) {
    let u: &[&str] = if user { &["--user"] } else { &[] };
    head(o, &format!("systemd unit {unit}{}", if user { " (user)" } else { "" }));
    let mut a: Vec<&str> = u.to_vec();
    a.extend(["cat", "--no-pager", unit]);
    let c = util::run_cmd("systemctl", &a, Duration::from_secs(10), 1 << 20);
    outln!(o, "$ systemctl {}cat {unit}   (Environment lines dropped)", if user { "--user " } else { "" });
    for l in c.text().lines() {
        let t = l.trim_start();
        if t.starts_with("Environment") || t.starts_with("PassEnvironment") {
            outln!(o, "{}=<dropped>", t.split('=').next().unwrap_or("Environment"));
        } else {
            outln!(o, "{l}");
        }
    }
    let mut a: Vec<&str> = u.to_vec();
    let p = format!("--property={SHOW_PROPS}");
    a.extend(["show", "--no-pager", &p, unit]);
    cmd_block_t(o, "systemctl", &a, 10, 256 << 10);
    let mut a: Vec<&str> = if user { vec!["--user-unit", unit] } else { vec!["-u", unit] };
    a.extend(["-n", "200", "-o", "short-iso", "--no-pager", "-q"]);
    let j = util::run_cmd("journalctl", &a, Duration::from_secs(15), 4 << 20);
    outln!(o, "$ journalctl {} {unit} -n 200   (hostname left out)", if user { "--user-unit" } else { "-u" });
    if !j.ok() {
        outln!(o, "  [{}]", j.status_line());
    }
    let mut kept = String::new();
    for l in j.text().lines() {
        let mut it = l.splitn(3, ' ');
        match (it.next(), it.next(), it.next()) {
            (Some(t), Some(_host), Some(rest)) if t.len() > 18 && t.as_bytes()[0].is_ascii_digit() => kept.push_str(&format!("{t} {rest}\n")),
            _ => kept.push_str(&format!("{l}\n")),
        }
    }
    o.write(crate::oldlog::filter(&kept, r).render().as_bytes());
}

/// B2.5
pub fn services(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("container/services.txt");
    let mut units: Vec<(String, bool)> = Vec::new();
    if LINUX && util::which("systemctl").is_some() {
        for n in &ctx.nodes {
            if let Some(u) = unit_of(n.pid) {
                if !units.contains(&u) {
                    units.push(u);
                }
            }
        }
        // units not running now (crashed, stopped) that name irondivi
        for user in [false, true] {
            let mut a = if user { vec!["--user"] } else { vec![] };
            a.extend(["list-units", "--all", "--no-legend", "--plain", "--no-pager", "--type=service"]);
            let l = util::run_cmd("systemctl", &a, Duration::from_secs(10), 1 << 20);
            for line in l.text().lines() {
                let name = line.split_whitespace().next().unwrap_or("");
                if name.to_ascii_lowercase().contains("irondivi") || name.to_ascii_lowercase().contains("divi-swap") {
                    let u = (name.to_string(), user);
                    if !units.contains(&u) {
                        units.push(u);
                    }
                }
            }
        }
        if units.is_empty() {
            head(o, "systemd");
            outln!(o, "no unit runs irondivid and none is named for it");
        }
        for (u, user) in &units {
            systemd_unit(o, &r, u, *user);
        }
    }
    if LINUX && util::which("rc-service").is_some() {
        head(o, "OpenRC");
        let l = util::run_cmd("rc-status", &["-a"], Duration::from_secs(10), 256 << 10);
        let svc: Vec<String> = l
            .text()
            .lines()
            .filter(|x| x.to_ascii_lowercase().contains("irondivi"))
            .filter_map(|x| x.split_whitespace().next().map(String::from))
            .collect();
        if svc.is_empty() {
            outln!(o, "no irondivi service");
        }
        for s in svc {
            cmd_block_t(o, "rc-service", &[&s, "status"], 10, 64 << 10);
            for f in [format!("/var/log/{s}.log"), format!("/var/log/{s}/{s}.log")] {
                if let Ok((b, _)) = util::read_tail(Path::new(&f), 64 << 10) {
                    outln!(o, "--- {f} (last 64 KB)");
                    o.write(util::escape_bytes(&b).as_bytes());
                }
            }
        }
    }
    if !LINUX {
        head(o, "launchd");
        let l = util::run_cmd("launchctl", &["list"], Duration::from_secs(10), 1 << 20);
        let jobs: Vec<String> = l
            .text()
            .lines()
            .filter(|x| x.to_ascii_lowercase().contains("irondivi"))
            .filter_map(|x| x.split_whitespace().nth(2).map(String::from))
            .collect();
        if jobs.is_empty() {
            outln!(o, "no launchd job names irondivi");
        }
        let uid = util::uid().to_string();
        for j in jobs {
            let target = format!("gui/{uid}/{j}");
            let p = util::run_cmd("launchctl", &["print", &target], Duration::from_secs(10), 256 << 10);
            outln!(o, "$ launchctl print gui/<uid>/{j}   (environment dropped)");
            let mut in_env = false;
            for l in p.text().lines() {
                let t = l.trim();
                if t.ends_with("environment = {") {
                    in_env = true;
                    outln!(o, "{l} <dropped> }}");
                    continue;
                }
                if in_env {
                    if t == "}" {
                        in_env = false;
                    }
                    continue;
                }
                outln!(o, "{l}");
            }
        }
    }

    // Docker
    let sock = Path::new("/var/run/docker.sock");
    if util::which("docker").is_some() && sock.exists() {
        head(o, "Docker");
        let ps = util::run_cmd("docker", &["ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Image}} {{.Names}}"], Duration::from_secs(10), 1 << 20);
        if !ps.ok() {
            outln!(o, "docker ps: [{}] {}", ps.status_line(), util::escape_bytes(&ps.stderr).lines().next().unwrap_or(""));
        }
        let mut n = 0;
        for l in ps.text().lines() {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() < 3 || !(t[1].to_ascii_lowercase().contains("irondivi") || t[2].to_ascii_lowercase().contains("irondivi")) {
                continue;
            }
            n += 1;
            let name = r.pseudonym("container", t[2]);
            outln!(o, "-- container {name} image {}", t[1]);
            let fmt = "State={{json .State}} RestartCount={{.RestartCount}} RestartPolicy={{json .HostConfig.RestartPolicy}} Memory={{.HostConfig.Memory}} MemorySwap={{.HostConfig.MemorySwap}} PidsLimit={{json .HostConfig.PidsLimit}} NanoCpus={{.HostConfig.NanoCpus}} CpuQuota={{.HostConfig.CpuQuota}} Mounts={{range .Mounts}}{{.Type}}:{{.Destination}}:rw={{.RW}} {{end}}";
            let i = util::run_cmd("docker", &["inspect", "--format", fmt, t[0]], Duration::from_secs(10), 256 << 10);
            o.write(i.text().as_bytes());
            let lg = util::run_cmd("docker", &["logs", "--tail", "200", "--timestamps", t[0]], Duration::from_secs(15), 4 << 20);
            outln!(o, "$ docker logs --tail 200 {name}");
            o.write(crate::oldlog::filter(&lg.text(), &r).render().as_bytes());
            o.write(crate::oldlog::filter(&util::escape_bytes(&lg.stderr), &r).render().as_bytes());
        }
        if n == 0 {
            outln!(o, "no irondivi container");
        }
    } else {
        head(o, "Docker");
        outln!(o, "{}", if sock.exists() { "docker CLI not installed" } else { "no Docker socket" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_masking() {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        let m = mask_argv(&v(&["/opt/x/irondivid", "-rpcpassword=hunter2", "-datadir=/d", "--rpcauth", "x:y", "-daemon", "-dbcache=400"]));
        assert_eq!(m, "irondivid -rpcpassword=<set> -datadir=<set> --rpcauth <arg> -daemon -dbcache=400");
        let m = mask_argv(&v(&["irondivi-cli", "-testnet", "walletpassphrase", "hunter2", "60"]));
        assert_eq!(m, "irondivi-cli -testnet walletpassphrase <arg> <arg>");
        assert_eq!(mask_argv(&v(&["irondivi-cli", "Dsecret"])), "irondivi-cli <arg>");
        assert_eq!(mask_argv(&v(&["/usr/bin/python3", "x.py", "-k"])), "python3 <arg> <arg>");
        assert_eq!(
            cron_line("*/5 * * * * /home/al/bin/irondivi-cli -conf=/x sendtoaddress Dabc 5 >> /tmp/log 2>&1"),
            "*/5 * * * * irondivi-cli -conf=<set> sendtoaddress <arg> <arg> >> <arg> 2>&1"
        );
    }
}
