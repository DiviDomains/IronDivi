// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.17: Electrum, web UI, ZMQ (served by `irondivid` itself) and the swap
//! daemons (`divi-swapd`, `divi-swap`, separate binaries).
//!
//! The CLI name is `components`: `services` is B2.5's. Per data dir the
//! output goes to `datadir-<n>/services/` (§7 layout); the swap daemons are
//! host-wide and go to `swaps/`.
//!
//! - Config through §6.2 (B1.3's `render_value`).
//! - Listener state: a TCP connect and close, no byte sent; a wildcard
//!   bind is checked on loopback.
//! - The TLS certificate through `openssl x509 -text` (subject, expiry, key
//!   type, names); the key file is never opened, only whether it exists.
//! - The last 1 MB of each component's log target from the newest
//!   debug.log, through the §6.2 old-log filter.
//! - Swaps: version, process state, `/healthz`, and from `GET /swaps` only
//!   counts by state and age plus the error strings (masked as §6.2 (b));
//!   no swap id, amount, counterparty data or secret. The swap database is
//!   never opened.

use super::files::{host_value, render_value};
use super::{head, LINUX};
use crate::ctx::{Ctx, DataDir, Node};
use crate::frame::Out;
use crate::oldlog;
use crate::outln;
use crate::redact::Redactor;
use crate::settings::Settings;
use crate::util;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

const LOG_TAIL: usize = 1 << 20;
const SCAN: u64 = 64 << 20;

/// (file, what, does the target belong)
type LogGroup = (&'static str, &'static str, fn(&str) -> bool);
const LOG_GROUPS: &[LogGroup] = &[
    ("electrum.log", "Electrum", |t| t.starts_with("divi_electrum")),
    ("webui.log", "web UI", |t| t.starts_with("divi_webui")),
    ("zmq.log", "ZMQ", |t| t == "zmq" || t.starts_with("zmq::") || t.ends_with("::zmq") || t.contains("::zmq::")),
    ("swap.log", "swaps", |t| t.starts_with("divi_swap") || t.starts_with("swap_")),
];

/// A TCP connect and close; nothing is sent
pub fn listener(addr: SocketAddr) -> &'static str {
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(s) => {
            let _ = s.shutdown(std::net::Shutdown::Both);
            "accepting connections"
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => "refused (nothing listening)",
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => "no answer within 2 s",
        Err(_) => "connect failed",
    }
}

/// The address to test for a bound address: loopback for a wildcard
fn check_addr(bound: &str, default_port: Option<u16>) -> Option<SocketAddr> {
    let b = bound.trim().trim_matches('"').trim_start_matches("tcp://");
    let mut a: SocketAddr = match b.parse() {
        Ok(a) => a,
        Err(_) => match (b.parse::<std::net::IpAddr>(), default_port) {
            (Ok(ip), Some(p)) => SocketAddr::new(ip, p),
            _ => b.to_socket_addrs().ok()?.next()?,
        },
    };
    if a.ip().is_unspecified() {
        a.set_ip(if a.is_ipv4() { [127, 0, 0, 1].into() } else { std::net::Ipv6Addr::LOCALHOST.into() });
    }
    Some(a)
}

fn shown(r: &Redactor, k: &str, v: &str) -> String {
    render_value(r, k, v).unwrap_or_else(|| "<set>".into())
}

fn net_flags(d: &DataDir, node: Option<&Node>, s: &Settings) -> (bool, bool, bool) {
    let argv = node.map(|n| n.argv.as_slice()).unwrap_or(&[]);
    let (mut net, _, mut pd) = crate::discovery::network_of(argv, Some(s));
    if net == "main" && !pd {
        pd = d.network.starts_with("privatedivi");
        net = d.network.trim_start_matches("privatedivi ").to_string();
    }
    (pd, net == "testnet", net == "regtest")
}

fn yes(s: &Settings, k: &str) -> &'static str {
    if s.get_bool(k, false) {
        "yes"
    } else {
        "no"
    }
}

// ---------------------------------------------------------------- cert

/// Subject, expiry, key type and names of a PEM certificate, from
/// `openssl x509 -text`; names other than IPs and localhost pseudonymised
pub fn cert_summary(r: &Redactor, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim).peekable();
    let name = |n: &str| -> String {
        let n = n.trim();
        if n.eq_ignore_ascii_case("localhost") || n.parse::<std::net::IpAddr>().is_ok() {
            r.scrub(n)
        } else {
            r.pseudonym("host", n)
        }
    };
    while let Some(l) = lines.next() {
        if let Some(v) = l.strip_prefix("Subject:") {
            let cn = v.split(',').filter_map(|p| p.trim().strip_prefix("CN").map(|x| x.trim_start_matches([' ', '=']).to_string())).next();
            let others = v.split(',').filter(|p| !p.trim().starts_with("CN")).count();
            out.push(format!("subject: CN={}{}", cn.as_deref().map(name).unwrap_or_else(|| "-".into()), if others > 0 { format!(" (+{others} other fields not kept)") } else { String::new() }));
        } else if l.starts_with("Issuer:") {
            out.push(format!("issuer: {}", if Some(l.trim_start_matches("Issuer:").trim()) == text.lines().find_map(|x| x.trim().strip_prefix("Subject:")).map(str::trim) { "self-signed (same as subject)" } else { "another (not kept)" }));
        } else if let Some(v) = l.strip_prefix("Not After :").or_else(|| l.strip_prefix("Not After:")) {
            out.push(format!("expires: {}", v.trim()));
        } else if let Some(v) = l.strip_prefix("Not Before:") {
            out.push(format!("valid from: {}", v.trim()));
        } else if let Some(v) = l.strip_prefix("Public Key Algorithm:") {
            out.push(format!("key type: {}", v.trim()));
        } else if l.contains("Public-Key:") {
            out.push(format!("key size: {}", l.split_once("Public-Key:").map(|x| x.1.trim()).unwrap_or("")));
        } else if l.starts_with("X509v3 Subject Alternative Name") {
            if let Some(n) = lines.next() {
                let names: Vec<String> = n
                    .split(',')
                    .map(|x| {
                        let x = x.trim();
                        match x.split_once(':') {
                            Some((k, v)) => format!("{k}:{}", name(v)),
                            None => name(x),
                        }
                    })
                    .collect();
                out.push(format!("names: {}", names.join(", ")));
            }
        }
    }
    out
}

fn cert(o: &mut Out, r: &Redactor, base_dir: &Path, cert: Option<&str>, key: Option<&str>) {
    let join = |v: &str| {
        let p = PathBuf::from(v.trim_matches('"'));
        if p.is_absolute() {
            p
        } else {
            base_dir.join(p)
        }
    };
    match key {
        Some(k) => outln!(o, "electrumkey: <set>, {} (never opened)", if join(k).exists() { "the file exists" } else { "the file does not exist" }),
        None => outln!(o, "electrumkey: <unset>"),
    }
    let Some(c) = cert else {
        outln!(o, "electrumcert: <unset>");
        return;
    };
    let p = join(c);
    outln!(o, "electrumcert: {}", r.path_of(&p));
    if !p.exists() {
        outln!(o, "  the file does not exist");
        return;
    }
    if util::which("openssl").is_none() {
        outln!(o, "  openssl not installed: certificate not read");
        return;
    }
    let ps = p.to_string_lossy().to_string();
    let x = util::run_cmd("openssl", &["x509", "-in", &ps, "-noout", "-text"], Duration::from_secs(10), 256 << 10);
    if !x.ok() {
        outln!(o, "  openssl x509 could not read it ({})", x.status_line());
        return;
    }
    for l in cert_summary(r, &x.text()) {
        outln!(o, "  {l}");
    }
}

// ---------------------------------------------------------------- logs

/// The lines of the newest debug.log whose module belongs to each group,
/// the last 1 MB of each, through the §6.2 filter
fn component_logs(o: &mut Out, r: &Redactor, d: &DataDir, base: &str) {
    let Some(p) = super::logs::debug_logs(d).into_iter().rev().find(|p| p.file_name().map(|n| n == "debug.log").unwrap_or(false)) else {
        o.file(&format!("{base}/services.txt"));
        outln!(o, "component logs: no debug.log in the data dir");
        return;
    };
    let (bytes, cut) = match util::read_tail(&p, SCAN) {
        Ok(x) => x,
        Err(e) => {
            o.file(&format!("{base}/services.txt"));
            outln!(o, "component logs: debug.log {}", util::io_err(&e));
            return;
        }
    };
    let text = util::escape_bytes(&bytes);
    let mut groups: Vec<Vec<&str>> = vec![Vec::new(); LOG_GROUPS.len()];
    for l in text.lines() {
        if let Some(t) = oldlog::target_of(l) {
            if let Some(i) = LOG_GROUPS.iter().position(|g| (g.2)(t)) {
                groups[i].push(l);
            }
        }
    }
    o.file(&format!("{base}/services.txt"));
    head(o, "Component logs");
    outln!(o, "from the newest debug.log{}: the last {} of each component's lines, through the §6.2 old-log filter", if cut { format!(" (its last {})", util::human(SCAN)) } else { String::new() }, util::human(LOG_TAIL as u64));
    for (i, (file, what, _)) in LOG_GROUPS.iter().enumerate() {
        let lines = &groups[i];
        outln!(o, "{what}: {} lines", lines.len());
        if lines.is_empty() {
            continue;
        }
        let mut size = 0usize;
        let mut start = lines.len();
        while start > 0 && size + lines[start - 1].len() < LOG_TAIL {
            start -= 1;
            size += lines[start].len() + 1;
        }
        let kept = lines[start..].join("\n");
        o.file(&format!("{base}/{file}"));
        if start > 0 {
            outln!(o, "[the first {start} lines cut: kept the last {}]", util::human(LOG_TAIL as u64));
        }
        o.write(oldlog::filter(&kept, r).render().as_bytes());
        o.file(&format!("{base}/services.txt"));
    }
}

// --------------------------------------------------------------- driver

fn per_datadir(o: &mut Out, r: &Redactor, ctx: &Ctx, d: &DataDir) {
    let base = format!("datadir-{}/services", d.n);
    let node = ctx.node_for(d);
    let s = super::live::read_settings(d, node);
    let (pd, testnet, regtest) = net_flags(d, node, &s);
    o.file(&format!("{base}/services.txt"));
    outln!(o, "data dir {} ({}), node {}", d.n, d.network, match node {
        Some(n) => format!("running (pid {})", n.pid),
        None => "not running: listener checks below test the configured addresses anyway".into(),
    });
    outln!(o, "A10 per-component counters: not collected (getdiaginfo is not available from this diag)");

    head(o, "Electrum");
    let mut any = false;
    for k in ["electrum", "electrumws", "electrumtls", "electrumwss"] {
        if let Some(v) = s.get(k) {
            any = true;
            let state = check_addr(v, None).map(listener).unwrap_or("address not understood");
            outln!(o, "{k}: {}  listener: {state}", host_value(r, v.trim_matches('"')));
        }
    }
    if any {
        outln!(o, "needs txindex=1: {}, addressindex=1: {}, RPC (server): {}", yes(&s, "txindex"), yes(&s, "addressindex"), if s.is_set("server") { yes(&s, "server") } else { "default" });
        cert(o, r, &d.path, s.get("electrumcert"), s.get("electrumkey"));
    } else {
        outln!(o, "not configured (no -electrum, -electrumws, -electrumtls or -electrumwss)");
    }

    head(o, "Web UI");
    if s.get_bool("webui", false) {
        let port = s.get("webuiport").and_then(|p| p.trim_matches('"').parse().ok()).unwrap_or_else(|| {
            let base = if pd { 52480 } else { 51480 };
            base + if regtest { 2 } else if testnet { 1 } else { 0 }
        });
        let bind = s.get("webuibind").map(|b| b.trim_matches('"').to_string()).unwrap_or_else(|| "127.0.0.1".into());
        outln!(o, "webui: on, bind {} port {port}{}", shown(r, "webuibind", &bind), if s.is_set("webuiport") { "" } else { " (default)" });
        outln!(o, "webuiallowremote: {}, webuiallowhost: {} entries", yes(&s, "webuiallowremote"), s.get_multi("webuiallowhost").len());
        let state = check_addr(&bind, Some(port)).map(listener).unwrap_or("address not understood");
        outln!(o, "listener: {state}");
    } else {
        outln!(o, "webui: off{}", if s.is_set("webui") { "" } else { " (default)" });
    }

    head(o, "ZMQ");
    let mut any = false;
    for k in ["zmqpubhashblock", "zmqpubhashtx", "zmqpubrawblock", "zmqpubrawtx"] {
        for v in s.get_multi(k) {
            any = true;
            let v = v.trim_matches('"');
            let state = check_addr(v, None).map(listener).unwrap_or("address not understood");
            outln!(o, "{k}: {}  listener: {state}", host_value(r, v.trim_start_matches("tcp://")));
        }
    }
    if !any {
        outln!(o, "not configured");
    }
    component_logs(o, r, d, &base);
}

// ---------------------------------------------------------------- swaps

/// A plain HTTP/1.0 GET; the status and body
pub fn http_get(addr: SocketAddr, path: &str, timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("{}", e.kind()))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let req = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("{}", e.kind()))?;
    let mut buf = Vec::new();
    s.take(16 << 20).read_to_end(&mut buf).map_err(|e| format!("{}", e.kind()))?;
    let i = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no HTTP header")?;
    let head = String::from_utf8_lossy(&buf[..i]).to_string();
    let code = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("no HTTP status")?;
    let mut body = buf[i + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    Ok((code, body))
}

fn dechunk(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let Some(e) = b[i..].windows(2).position(|w| w == b"\r\n") else { break };
        let n = usize::from_str_radix(String::from_utf8_lossy(&b[i..i + e]).split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        let s = i + e + 2;
        out.extend_from_slice(&b[s..(s + n).min(b.len())]);
        i = s + n + 2;
    }
    out
}

fn age_bucket(expires_at: u64, now: u64) -> &'static str {
    // a quote lives minutes: its expiry is the swap's age to within that
    let age = now.saturating_sub(expires_at);
    match age {
        0..=3_599 => "under 1 h",
        3_600..=86_399 => "1 h to 1 day",
        86_400..=604_799 => "1 to 7 days",
        _ => "over 7 days",
    }
}

/// Counts by state and age and the error strings from `GET /swaps`;
/// nothing else of a swap is kept
pub fn swap_report(o: &mut Out, r: &Redactor, body: &[u8], now: u64) {
    let v: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            outln!(o, "GET /swaps: not JSON");
            return;
        }
    };
    let Some(list) = v.as_array() else {
        outln!(o, "GET /swaps: not a list");
        return;
    };
    let mut by: BTreeMap<(String, &str), u64> = BTreeMap::new();
    let mut errors: BTreeMap<String, u64> = BTreeMap::new();
    for s in list {
        let st = s.get("state").and_then(|x| x.as_str()).filter(|x| x.chars().all(|c| c.is_ascii_alphabetic() || c == '_')).unwrap_or("<other>");
        let age = s.get("quote").and_then(|q| q.get("expires_at")).and_then(|x| x.as_u64()).map(|e| age_bucket(e, now)).unwrap_or("age unknown");
        *by.entry((st.to_string(), age)).or_default() += 1;
        if let Some(e) = s.get("last_error").and_then(|x| x.as_str()).filter(|e| !e.is_empty()) {
            *errors.entry(oldlog::mask_wallet_msg(e, r)).or_default() += 1;
        }
    }
    outln!(o, "GET /swaps: {} swaps (counts by state and age; ids, amounts, legs and preimages not kept)", list.len());
    for ((st, age), n) in &by {
        outln!(o, "  {st:<24} {age:<14} {n}");
    }
    if !errors.is_empty() {
        outln!(o, "last errors (arguments masked as §6.2 (b)):");
        for (e, n) in &errors {
            outln!(o, "  {n} x {e}");
        }
    }
}

fn arg_value<'a>(argv: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().map(String::as_str);
        }
        if let Some(v) = a.strip_prefix(name).and_then(|v| v.strip_prefix('=')) {
            return Some(v);
        }
    }
    None
}

fn swap_listen(n: &Node) -> (SocketAddr, &'static str) {
    let default: SocketAddr = "127.0.0.1:8480".parse().unwrap();
    let Some(c) = arg_value(&n.argv, "--config").or_else(|| arg_value(&n.argv, "-c")) else {
        return (default, "default (no --config)");
    };
    let p = Path::new(c);
    let p = if p.is_absolute() { p.to_path_buf() } else { n.cwd.clone().unwrap_or_default().join(p) };
    match util::read_small(&p, 1 << 20) {
        Some(t) => match t.parse::<toml::Table>() {
            Ok(tab) => match tab.get("listen").and_then(|v| v.as_str()) {
                Some(l) => check_addr(l, None).map(|a| (a, "from its config")).unwrap_or((default, "config listen not understood; default")),
                None => (default, "default (config has no listen)"),
            },
            Err(_) => (default, "config is not TOML; default"),
        },
        None => (default, "config not readable; default"),
    }
}

fn swap_journal(o: &mut Out, r: &Redactor, pid: u32) {
    if !LINUX {
        outln!(o, "log: divi-swapd logs to its stdout; no service manager log read on this OS");
        return;
    }
    let Some((unit, user)) = super::procs::unit_of(pid) else {
        outln!(o, "log: not a systemd unit; divi-swapd logs to its stdout, which diag cannot read");
        return;
    };
    let mut a: Vec<&str> = if user { vec!["--user-unit", &unit] } else { vec!["-u", &unit] };
    a.extend(["-n", "5000", "-o", "short-iso", "--no-pager", "-q"]);
    let j = util::run_cmd("journalctl", &a, Duration::from_secs(15), 8 << 20);
    let mut kept: Vec<String> = Vec::new();
    for l in j.text().lines() {
        let mut it = l.splitn(3, ' ');
        match (it.next(), it.next(), it.next()) {
            // the swap daemon writes tracing JSON after the journal prefix
            (Some(t), Some(_host), Some(rest)) if t.len() > 18 && t.as_bytes()[0].is_ascii_digit() => {
                let msg = rest.split_once(": ").map(|x| x.1).unwrap_or(rest);
                kept.push(if msg.trim_start().starts_with('{') { msg.to_string() } else { format!("{t} {rest}") })
            }
            _ => kept.push(l.to_string()),
        }
    }
    let mut size = 0;
    let mut start = kept.len();
    while start > 0 && size + kept[start - 1].len() < LOG_TAIL {
        start -= 1;
        size += kept[start].len() + 1;
    }
    outln!(o, "log: journal of unit {unit}, {} lines, the last {} kept in swaps/swapd.log", kept.len(), kept.len() - start);
    o.file("swaps/swapd.log");
    o.write(oldlog::filter(&kept[start..].join("\n"), r).render().as_bytes());
    o.file("swaps/swaps.txt");
}

fn swaps(o: &mut Out, r: &Redactor, ctx: &Ctx) {
    o.file("swaps/swaps.txt");
    head(o, "Swap daemons (divi-swapd, divi-swap)");
    let procs: Vec<&Node> = ctx.nodes.iter().filter(|n| matches!(n.component.as_deref(), Some("divi-swapd") | Some("divi-swap"))).collect();
    if procs.is_empty() {
        outln!(o, "no divi-swapd or divi-swap process running");
        let a: SocketAddr = "127.0.0.1:8480".parse().unwrap();
        outln!(o, "default divi-swapd address 127.0.0.1:8480: {}", listener(a));
        return;
    }
    for n in procs {
        let comp = n.component.as_deref().unwrap_or("");
        outln!(o, "-- {comp} pid {}", n.pid);
        if LINUX {
            if let Some(st) = util::read_small(Path::new(&format!("/proc/{}/stat", n.pid)), 4096) {
                let state = st.rsplit(')').next().and_then(|x| x.split_whitespace().next()).unwrap_or("?");
                outln!(o, "process state: {state}");
            }
        }
        match &n.exe {
            Some(exe) => {
                outln!(o, "binary: {}", r.path_of(exe));
                let v = util::run_cmd(&exe.to_string_lossy(), &["--version"], Duration::from_secs(5), 4096);
                outln!(o, "version: {}", if v.ok() { v.text().trim().to_string() } else { format!("[{}]", v.status_line()) });
            }
            None => outln!(o, "binary: not readable"),
        }
        if comp == "divi-swapd" {
            let (addr, from) = swap_listen(n);
            outln!(o, "listen: {} ({from}): {}", r.scrub(&addr.to_string()), listener(addr));
            match http_get(addr, "/healthz", Duration::from_secs(5)) {
                Ok((code, _)) => outln!(o, "GET /healthz: HTTP {code} (body not kept)"),
                Err(e) => outln!(o, "GET /healthz: {e}"),
            }
            match http_get(addr, "/swaps", Duration::from_secs(10)) {
                Ok((200, b)) => swap_report(o, r, &b, util::now_secs().max(0) as u64),
                Ok((code, _)) => outln!(o, "GET /swaps: HTTP {code}"),
                Err(e) => outln!(o, "GET /swaps: {e}"),
            }
            outln!(o, "swap database: not opened (§6.1)");
        }
        swap_journal(o, r, n.pid);
    }
}

/// B2.17
pub fn components(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    for d in &ctx.datadirs {
        per_datadir(o, &r, ctx, d);
    }
    if ctx.datadirs.is_empty() {
        o.file("swaps/swaps.txt");
        outln!(o, "no data dir: Electrum, web UI and ZMQ not checked");
    }
    swaps(o, &r, ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Known;

    fn r() -> Redactor {
        Redactor::new([5; 32], &Known::default())
    }

    #[test]
    fn wildcard_binds_are_checked_on_loopback() {
        assert_eq!(check_addr("0.0.0.0:50001", None), Some("127.0.0.1:50001".parse().unwrap()));
        assert_eq!(check_addr("[::]:50002", None), Some("[::1]:50002".parse().unwrap()));
        assert_eq!(check_addr("tcp://127.0.0.1:28332", None), Some("127.0.0.1:28332".parse().unwrap()));
        assert_eq!(check_addr("0.0.0.0", Some(51480)), Some("127.0.0.1:51480".parse().unwrap()));
    }

    #[test]
    fn cert_names_are_pseudonymised() {
        let text = "Certificate:\n    Data:\n        Issuer: CN = electrum.example.org, O = Alice Ltd\n        Validity\n            Not Before: Oct 30 00:00:00 2026 GMT\n            Not After : Oct 30 00:00:00 2027 GMT\n        Subject: CN = electrum.example.org, O = Alice Ltd\n        Subject Public Key Info:\n            Public Key Algorithm: id-ecPublicKey\n                Public-Key: (256 bit)\n        X509v3 extensions:\n            X509v3 Subject Alternative Name: \n                DNS:electrum.example.org, IP Address:127.0.0.1\n";
        let s = cert_summary(&r(), text).join("\n");
        assert!(!s.contains("example") && !s.contains("Alice"), "{s}");
        assert!(s.contains("subject: CN=host-") && s.contains("(+1 other fields not kept)"), "{s}");
        assert!(s.contains("issuer: self-signed"), "{s}");
        assert!(s.contains("expires: Oct 30 00:00:00 2027 GMT"), "{s}");
        assert!(s.contains("key type: id-ecPublicKey") && s.contains("key size: (256 bit)"), "{s}");
        assert!(s.contains("IP Address:"), "{s}");
    }

    #[test]
    fn swaps_keep_counts_and_masked_errors_only() {
        let body = br#"[
          {"id":"swap-secret-id-1","state":"maker_locked","quote":{"id":"q1","btc_amount":150000,"divi_amount":99000000,"expires_at":1000},"taker_leg":{"txid":"aa"},"maker_leg":null,"preimage":"cafebabe","last_error":"broadcast failed for DHfrxHzGWW1fLVZ7RCeN1W2V8RANW3TUxr amount 99000000"},
          {"id":"swap-secret-id-2","state":"maker_locked","quote":{"expires_at":1000},"preimage":null,"last_error":null},
          {"id":"swap-secret-id-3","state":"taker_claimed","quote":{"expires_at":999999}}
        ]"#;
        let mut o = Out::capture();
        swap_report(&mut o, &r(), body, 1_000_000);
        let s = o.captured();
        for bad in ["swap-secret-id", "150000", "99000000", "cafebabe", "DHfrxHz", "q1"] {
            assert!(!s.contains(bad), "{bad} in {s}");
        }
        assert!(s.contains("3 swaps"), "{s}");
        assert!(s.contains("maker_locked") && s.contains("over 7 days") && s.contains(" 2"), "{s}");
        assert!(s.contains("taker_claimed") && s.contains("under 1 h"), "{s}");
        assert!(s.contains("1 x broadcast failed for <addr> amount <num>"), "{s}");
    }

    #[test]
    fn http_get_reads_a_mock_server() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut req = Vec::new();
                let mut b = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
                if !req.starts_with(b"GET /swaps HTTP/1.0") {
                    continue; // the listener check: a connect with nothing sent
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n");
            }
        });
        let (code, body) = http_get(a, "/swaps", Duration::from_secs(3)).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, b"[]");
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert_eq!(listener(closed), "refused (nothing listening)");
        assert_eq!(listener(a), "accepting connections");
    }

    #[test]
    fn targets_of_plain_and_json_lines() {
        assert_eq!(oldlog::target_of("2026-10-30T01:02:03.000Z  INFO divi_electrum::server: listening"), Some("divi_electrum::server"));
        assert_eq!(oldlog::target_of(r#"{"timestamp":"x","level":"INFO","fields":{"message":"m"},"target":"divi_swapd::engine"}"#), Some("divi_swapd::engine"));
        assert_eq!(oldlog::target_of("garbage"), None);
    }

    #[test]
    fn component_targets() {
        let zmq = LOG_GROUPS[2].2;
        assert!(zmq("divi_node::zmq") && zmq("zmq") && !zmq("divi_network::sync"));
        assert!((LOG_GROUPS[3].2)("divi_swapd::engine") && (LOG_GROUPS[0].2)("divi_electrum::server"));
    }
}
