// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.16 live node: the A5 readability check and the `/proc` visibility
//! matrix, the process state (stopped, traced, frozen) before any RPC, the
//! safe RPC methods the plan lists over loopback with each method's fields
//! kept by name, the per-thread `wchan` sample, and the A17 snapshot
//! request when RPC does not answer. No signal is ever sent to the node.

use super::{head, one};
use crate::ctx::{Ctx, DataDir, Node};
use crate::frame::Out;
use crate::outln;
use crate::redact::Redactor;
use crate::util;
use serde_json::{Map, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// B2.16: RPC that has not answered in this long gets the snapshot request
pub const FIRST_CALL_SECS: u64 = 10;
/// Later calls, once the node has answered once
const CALL_SECS: u64 = 5;
/// No new RPC call starts after this much of the 60 s budget
const RPC_PHASE_SECS: u64 = 25;

// ------------------------------------------------------------------ RPC

/// How to reach the node's RPC: the address and the `user:password` pair.
/// Never printed.
pub struct Rpc {
    pub addr: SocketAddr,
    auth: String,
    /// "cookie" or "rpcuser/rpcpassword": what is printed instead
    pub auth_kind: &'static str,
}

impl Rpc {
    pub fn new(addr: SocketAddr, user: &str, pass: &str, auth_kind: &'static str) -> Self {
        Rpc { addr, auth: format!("{user}:{pass}"), auth_kind }
    }
}

/// Why a call did not give a result
#[derive(Debug, PartialEq)]
pub enum CallError {
    /// no answer in time (connect, write or read): the A17 case
    Timeout,
    /// nothing listens (connection refused)
    Refused,
    /// HTTP 401/403
    Auth,
    /// the node answered with a JSON-RPC error: (code, message)
    Rpc(i64, String),
    Other(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Timeout => write!(f, "no answer in time"),
            CallError::Refused => write!(f, "connection refused (RPC not listening)"),
            CallError::Auth => write!(f, "credentials refused"),
            CallError::Rpc(-32601, _) => write!(f, "not available on this node (method not found)"),
            CallError::Rpc(c, m) => write!(f, "RPC error {c}: {m}"),
            CallError::Other(s) => write!(f, "{s}"),
        }
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

fn io_class(e: &std::io::Error) -> CallError {
    use std::io::ErrorKind::*;
    match e.kind() {
        TimedOut | WouldBlock => CallError::Timeout,
        ConnectionRefused => CallError::Refused,
        _ => CallError::Other(super::probe::class(e).to_string()),
    }
}

/// Decode a `Transfer-Encoding: chunked` body
fn unchunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let nl = b.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(&b[..nl]).ok()?.split(';').next()?.trim();
        let n = usize::from_str_radix(size, 16).ok()?;
        b = &b[nl + 2..];
        if n == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..n)?);
        b = b.get(n + 2..)?;
    }
}

/// One JSON-RPC 1.0 call over a hand-written HTTP/1.1 POST
pub fn call(rpc: &Rpc, method: &str, params: Value, timeout: Duration) -> Result<Value, CallError> {
    let deadline = Instant::now() + timeout;
    let mut s = TcpStream::connect_timeout(&rpc.addr, timeout).map_err(|e| io_class(&e))?;
    let left = || deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let _ = s.set_write_timeout(Some(left()));
    let body = serde_json::json!({"jsonrpc": "1.0", "id": "diag", "method": method, "params": params}).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        rpc.addr,
        b64(rpc.auth.as_bytes()),
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).map_err(|e| io_class(&e))?;
    let mut resp = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let _ = s.set_read_timeout(Some(left()));
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&buf[..n]);
                if resp.len() > 32 << 20 {
                    return Err(CallError::Other("answer over 32 MB".into()));
                }
                // stop at Content-Length when the server keeps the socket
                if let Some(end) = complete_len(&resp) {
                    resp.truncate(end);
                    break;
                }
            }
            Err(e) => return Err(io_class(&e)),
        }
    }
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or(CallError::Other("no HTTP header".into()))?;
    let header = String::from_utf8_lossy(&resp[..split]).to_ascii_lowercase();
    let mut body = resp[split + 4..].to_vec();
    let status: u16 = header.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if status == 401 || status == 403 {
        return Err(CallError::Auth);
    }
    if header.contains("transfer-encoding: chunked") {
        body = unchunk(&body).ok_or(CallError::Other("bad chunked body".into()))?;
    }
    let v: Value = serde_json::from_slice(&body).map_err(|_| CallError::Other(format!("HTTP {status}, not JSON")))?;
    match v.get("error") {
        Some(e) if !e.is_null() => {
            let code = e.get("code").and_then(Value::as_i64).unwrap_or(0);
            let msg = e.get("message").and_then(Value::as_str).unwrap_or("").to_string();
            Err(CallError::Rpc(code, msg))
        }
        _ => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
    }
}

fn complete_len(resp: &[u8]) -> Option<usize> {
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header = String::from_utf8_lossy(&resp[..split]).to_ascii_lowercase();
    let len: usize = header.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok())?;
    (resp.len() >= split + 4 + len).then_some(split + 4 + len)
}

// ---------------------------------------------------------- field filters

/// The methods B2.16 may call, in order, with their parameters
pub const METHODS: &[(&str, &str)] = &[
    ("getblockchaininfo", "[]"),
    ("getdiaginfo", "[]"),
    ("getnetworkinfo", "[]"),
    ("getpeerinfo", "[]"),
    ("getmempoolinfo", "[]"),
    ("getstakingstatus", "[]"),
    ("mnsync", "[\"status\"]"),
    ("getmasternodestatus", "[]"),
    ("getwalletinfo", "[]"),
    ("getlogconfig", "[]"),
];

/// Fields kept by name; everything else is dropped and only its name listed
fn keep(method: &str) -> &'static [&'static str] {
    match method {
        "getblockchaininfo" => &[
            "chain", "blocks", "headers", "bestblockhash", "difficulty", "chainwork", "mediantime",
            "verificationprogress", "initialblockdownload", "size_on_disk", "pruned", "pruneheight", "warnings",
        ],
        "getnetworkinfo" => &[
            "version", "subversion", "protocolversion", "localservices", "timeoffset", "connections", "networks",
            "relayfee", "localrelay", "warnings",
        ],
        "getpeerinfo" => &[
            "id", "addr", "services", "lastsend", "lastrecv", "bytessent", "bytesrecv", "conntime", "pingtime",
            "pingwait", "version", "subver", "inbound", "startingheight", "banscore", "synced_headers",
            "synced_blocks", "inflight",
        ],
        "getmempoolinfo" => &["size", "bytes", "usage", "maxmempool", "mempoolminfee"],
        "getmasternodestatus" => &["txhash", "outputidx", "netaddr", "status", "message"],
        "getwalletinfo" => &[
            "walletversion", "balance", "unconfirmed_balance", "immature_balance", "txcount", "keypoolsize",
            "unlocked_until", "encryption_status",
        ],
        "getlogconfig" => &["max_file_size", "max_file_size_mb", "max_files", "debug", "levels", "print_to_console"],
        // every field is a status flag or a count
        "getstakingstatus" | "mnsync" => &[],
        _ => &[],
    }
}

/// `host:port` (or `[v6]:port`) to its address part
fn host_of(a: &str) -> &str {
    if let Some(r) = a.strip_prefix('[') {
        return r.split(']').next().unwrap_or(r);
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => a,
    }
}

/// An address as its class and a per-run pseudonym, never the address
pub fn addr_class(r: &Redactor, a: &str) -> String {
    let h = host_of(a);
    let class = if h.ends_with(".onion") { "onion" } else { super::sys::ip_class(h) };
    format!("{class} {}", r.pseudonym("peer", h))
}

/// A scalar for the package: numbers and flags as they are, strings scrubbed
fn scalar(r: &Redactor, v: &Value) -> String {
    match v {
        Value::String(s) => r.scrub(s),
        Value::Array(a) => format!("[{}]", a.iter().map(|x| scalar(r, x)).collect::<Vec<_>>().join(", ")),
        Value::Object(_) => "{…}".into(),
        other => other.to_string(),
    }
}

/// Write one method's result with only the kept fields
pub fn write_result(o: &mut Out, r: &Redactor, method: &str, v: &Value) {
    match (method, v) {
        ("getpeerinfo", Value::Array(peers)) => {
            outln!(o, "  {} peers", peers.len());
            for p in peers {
                if let Value::Object(m) = p {
                    let mut parts = Vec::new();
                    for k in keep(method) {
                        if let Some(x) = m.get(*k) {
                            match *k {
                                "addr" => parts.push(format!("addr={}", x.as_str().map(|a| addr_class(r, a)).unwrap_or_default())),
                                _ => parts.push(format!("{k}={}", scalar(r, x))),
                            }
                        }
                    }
                    outln!(o, "  peer: {}", parts.join(" "));
                }
            }
            dropped(o, peers.iter().filter_map(Value::as_object), keep(method));
        }
        ("getstakingstatus", Value::Object(m)) | ("mnsync", Value::Object(m)) => {
            for (k, x) in m {
                if sensitive(k) == Some("amount") || k.contains("threshold") {
                    // staking_balance, stake split threshold: never the amount
                    let v = x.as_f64().map(|f| if f > 0.0 { "more than 0 (amount withheld)" } else { "0" });
                    outln!(o, "  {k}: {}", v.unwrap_or("(removed)"));
                } else if x.is_boolean() || x.is_number() {
                    outln!(o, "  {k}: {x}");
                } else if let Some(s) = x.as_str() {
                    // MASTERNODE_SYNC_* names and the like; scrubbed anyway
                    outln!(o, "  {k}: {}", r.scrub(s));
                }
            }
        }
        ("getwalletinfo", Value::Object(m)) => wallet(o, r, m),
        ("getmasternodestatus", Value::Object(m)) => {
            for k in keep(method) {
                let Some(x) = m.get(*k) else { continue };
                match *k {
                    // own outpoint pseudonymised; the index alone says nothing
                    "txhash" => {
                        let idx = m.get("outputidx").map(|i| i.to_string()).unwrap_or_default();
                        outln!(o, "  outpoint: {}", r.pseudonym("outpoint", &format!("{}:{idx}", x.as_str().unwrap_or(""))));
                    }
                    "outputidx" => {}
                    "netaddr" => outln!(o, "  netaddr: {}", x.as_str().map(|a| addr_class(r, a)).unwrap_or_default()),
                    _ => outln!(o, "  {k}: {}", scalar(r, x)),
                }
            }
            dropped(o, std::iter::once(m), keep(method));
        }
        ("getnetworkinfo", Value::Object(m)) => {
            for k in keep(method) {
                let Some(x) = m.get(*k) else { continue };
                if *k == "networks" {
                    for n in x.as_array().into_iter().flatten() {
                        let name = n.get("name").and_then(Value::as_str).unwrap_or("?");
                        let f = |key: &str| n.get(key).map(|b| b.to_string()).unwrap_or_else(|| "-".into());
                        let proxy = n.get("proxy").and_then(Value::as_str).map(|p| if p.is_empty() { "none" } else { "set" }).unwrap_or("-");
                        outln!(o, "  network {name}: limited={} reachable={} proxy={proxy}", f("limited"), f("reachable"));
                    }
                } else {
                    outln!(o, "  {k}: {}", scalar(r, x));
                }
            }
            if let Some(l) = m.get("localaddresses").and_then(Value::as_array) {
                outln!(o, "  localaddresses: {} entries (removed)", l.len());
            }
            dropped(o, std::iter::once(m), keep(method));
        }
        ("getdiaginfo", _) => {
            // its fields are Part A's own (A10), already reduced by the node;
            // address-, key- and amount-named fields are reduced here again
            generic(o, r, v, 1);
        }
        (_, Value::Object(m)) => {
            for k in keep(method) {
                if let Some(x) = m.get(*k) {
                    let s = if *k == "bestblockhash" {
                        x.as_str().map(|h| format!("blk:{h}")).unwrap_or_default()
                    } else {
                        scalar(r, x)
                    };
                    outln!(o, "  {k}: {s}");
                }
            }
            dropped(o, std::iter::once(m), keep(method));
        }
        (_, other) => outln!(o, "  (unexpected shape: {})", kind(other)),
    }
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn dropped<'a>(o: &mut Out, objs: impl Iterator<Item = &'a Map<String, Value>>, keep: &[&str]) {
    let mut names: Vec<&str> = Vec::new();
    for m in objs {
        for k in m.keys() {
            if !keep.contains(&k.as_str()) && k != "localaddresses" && !names.contains(&k.as_str()) {
                names.push(k);
            }
        }
    }
    if !names.is_empty() {
        names.sort();
        outln!(o, "  fields not kept: {}", names.join(", "));
    }
}

/// Balances as shares of their total, never amounts
fn wallet(o: &mut Out, r: &Redactor, m: &Map<String, Value>) {
    let bal: Vec<(&str, f64)> = ["balance", "unconfirmed_balance", "immature_balance"]
        .iter()
        .filter_map(|k| m.get(*k).and_then(Value::as_f64).map(|v| (*k, v)))
        .collect();
    let total: f64 = bal.iter().map(|b| b.1).sum();
    for (k, v) in &bal {
        let share = if total > 0.0 { format!("{:.0} % of the total", v / total * 100.0) } else { "0".into() };
        outln!(o, "  {k}: {share}{}", if *v > 0.0 && bal.len() == 1 { " (amount withheld)" } else { "" });
    }
    for k in keep("getwalletinfo") {
        if k.ends_with("balance") {
            continue;
        }
        if let Some(x) = m.get(*k) {
            if *k == "unlocked_until" {
                let t = x.as_i64().unwrap_or(0);
                outln!(o, "  unlocked_until: {}", if t == 0 { "locked (0)" } else { "set" });
            } else {
                outln!(o, "  {k}: {}", scalar(r, x));
            }
        }
    }
    dropped(o, std::iter::once(m), keep("getwalletinfo"));
}

/// Fields whose values are reduced in any answer whose shape is not fixed
fn sensitive(k: &str) -> Option<&'static str> {
    let k = k.to_ascii_lowercase();
    if ["addr", "address", "netaddr", "ip", "host", "addrlocal", "addrbind", "proxy", "localaddresses"]
        .contains(&k.as_str())
        || k.ends_with("_addr")
        || k.ends_with("address")
    {
        Some("address")
    } else if ["diag_key", "known_values", "hmac", "privkey", "seed", "wif", "mnemonic", "passphrase", "password", "cookie"]
        .iter()
        .any(|s| k.contains(s))
    {
        Some("secret")
    } else if ["balance", "amount", "value", "fee_paid", "reward"].iter().any(|s| k.contains(s)) {
        Some("amount")
    } else if ["txid", "txhash", "outpoint", "payee", "label", "pubkey"].iter().any(|s| k.contains(s)) {
        Some("id")
    } else {
        None
    }
}

fn generic(o: &mut Out, r: &Redactor, v: &Value, depth: usize) {
    let pad = "  ".repeat(depth);
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match sensitive(k) {
                    Some("address") => {
                        let s = match x {
                            Value::String(a) if !a.is_empty() => addr_class(r, a),
                            Value::Array(a) => format!("{} entries (removed)", a.len()),
                            _ => "(removed)".into(),
                        };
                        outln!(o, "{pad}{k}: {s}");
                    }
                    Some("secret") | Some("amount") => outln!(o, "{pad}{k}: (removed)"),
                    Some(_) => outln!(o, "{pad}{k}: {}", x.as_str().map(|s| r.pseudonym("id", s)).unwrap_or_else(|| "(removed)".into())),
                    None if x.is_object() || x.is_array() => {
                        outln!(o, "{pad}{k}:");
                        generic(o, r, x, depth + 1);
                    }
                    None => outln!(o, "{pad}{k}: {}", scalar(r, x)),
                }
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate().take(500) {
                if x.is_object() || x.is_array() {
                    outln!(o, "{pad}[{i}]");
                    generic(o, r, x, depth + 1);
                } else {
                    outln!(o, "{pad}[{i}] {}", scalar(r, x));
                }
            }
            if a.len() > 500 {
                outln!(o, "{pad}… {} more", a.len() - 500);
            }
        }
        other => outln!(o, "{pad}{}", scalar(r, other)),
    }
}

/// Every safe method in turn. `Err(Timeout)` when the first call got no
/// answer in `first` (the A17 case); later failures are written and skipped.
pub fn rpc_report(o: &mut Out, r: &Redactor, rpc: &Rpc, first: Duration) -> Result<(), CallError> {
    let start = Instant::now();
    for (i, (m, p)) in METHODS.iter().enumerate() {
        if i > 0 && start.elapsed() > Duration::from_secs(RPC_PHASE_SECS) {
            outln!(o, "{m}: not called (the RPC phase is over its {RPC_PHASE_SECS} s)");
            continue;
        }
        let t = Instant::now();
        let params: Value = serde_json::from_str(p).unwrap_or(Value::Array(vec![]));
        let res = call(rpc, m, params, if i == 0 { first } else { Duration::from_secs(CALL_SECS) });
        let ms = t.elapsed().as_millis();
        match res {
            Ok(v) => {
                outln!(o, "{m}: answered in {ms} ms");
                write_result(o, r, m, &v);
            }
            Err(e) => {
                outln!(o, "{m}: {e} (after {ms} ms)");
                if i == 0 && matches!(e, CallError::Timeout | CallError::Refused | CallError::Auth) {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

// --------------------------------------------------------- credentials

pub(crate) fn read_settings(d: &DataDir, node: Option<&Node>) -> crate::settings::Settings {
    let mut s = node.map(|n| crate::settings::Settings::from_command_line(&n.argv)).unwrap_or_default();
    if let Some(c) = d.conf.as_ref().or(node.and_then(|n| n.conf.as_ref())) {
        if let Some(t) = util::read_small(c, 1 << 20) {
            let _ = s.read_config(&t);
        }
    }
    s
}

/// divi-network's RPC defaults for each chain
pub fn default_port(network: &str, privatedivi: bool) -> u16 {
    match (network, privatedivi) {
        ("testnet" | "regtest", false) => 51475,
        ("testnet", true) => 52473,
        ("regtest", true) => 52475,
        (_, true) => 52471,
        _ => 51473,
    }
}

/// Where and how to call the node; Err says why not (never the value)
pub fn rpc_for(d: &DataDir, node: Option<&Node>) -> Result<Rpc, String> {
    let s = read_settings(d, node);
    let port = s.get("rpcport").and_then(|p| p.trim_matches('"').parse().ok()).unwrap_or_else(|| {
        // the node's own flags and config first; the data dir's chain
        // subfolder when they name no network
        let argv = node.map(|n| n.argv.as_slice()).unwrap_or(&[]);
        let (net, _, pd) = crate::discovery::network_of(argv, Some(&s));
        if net == "main" && !pd {
            let dn = d.network.trim_start_matches("privatedivi ");
            default_port(dn, d.network.starts_with("privatedivi"))
        } else {
            default_port(&net, pd)
        }
    });
    // loopback first; the bound address only when it is not a wildcard (W2)
    let mut host = std::net::IpAddr::from([127, 0, 0, 1]);
    let binds = s.get_multi("rpcbind");
    if !binds.is_empty() && !binds.iter().any(|b| {
        let h = host_of(b.trim_matches('"'));
        h == "127.0.0.1" || h == "::1" || h == "localhost" || h == "0.0.0.0" || h == "::"
    }) {
        if let Ok(ip) = host_of(binds[0].trim_matches('"')).parse() {
            host = ip;
        }
    }
    let addr = SocketAddr::new(host, port);
    let user = s.get("rpcuser").map(|v| v.trim_matches('"').to_string());
    let pass = s.get("rpcpassword").map(|v| v.trim_matches('"').to_string());
    if let (Some(u), Some(p)) = (user, pass) {
        if !u.is_empty() && !p.is_empty() {
            return Ok(Rpc::new(addr, &u, &p, "rpcuser/rpcpassword in the config"));
        }
    }
    for dir in [&d.chain, &d.path] {
        let f = dir.join(".cookie");
        match std::fs::read_to_string(&f) {
            Ok(t) => {
                let t = t.trim();
                if let Some((u, p)) = t.split_once(':') {
                    return Ok(Rpc::new(addr, u, p, "cookie"));
                }
                return Err("the cookie file is not user:password".into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("cookie file: {}", util::io_err(&e))),
        }
    }
    Err("no rpcuser/rpcpassword pair in the config and no cookie file".into())
}

// --------------------------------------------------------- /proc

fn errno_of(e: &std::io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => "hidden by kernel",
        Some(libc::ENOENT) => "absent",
        _ => "error",
    }
}

/// One `/proc/<pid>` entry: read / hidden by kernel / absent
fn visible(pid: u32, entry: &str, state: char) -> String {
    let p = PathBuf::from(format!("/proc/{pid}/{entry}"));
    let r = if entry.ends_with('/') {
        std::fs::read_dir(&p).map(|mut d| d.next().is_some() || true).map(|_| String::new())
    } else if ["cwd", "exe", "root"].contains(&entry) {
        std::fs::read_link(&p).map(|_| String::new())
    } else {
        std::fs::File::open(&p).and_then(|mut f| {
            let mut b = vec![0u8; 4096];
            let n = f.read(&mut b)?;
            Ok(String::from_utf8_lossy(&b[..n]).into_owned())
        })
    };
    match r {
        Ok(text) => {
            if entry == "wchan" && text.trim() == "0" && state != 'R' {
                return "hidden by kernel (reads 0)".into();
            }
            "read".into()
        }
        Err(e) => errno_of(&e).into(),
    }
}

const MATRIX: &[&str] = &[
    "stat", "wchan", "stack", "syscall", "io", "maps", "smaps_rollup", "fd/", "fdinfo/", "environ", "cwd", "exe",
    "root", "ns/",
];

fn tracer_pid(pid: u32) -> Option<u32> {
    let s = util::read_small(Path::new(&format!("/proc/{pid}/status")), 16384)?;
    s.lines().find_map(|l| l.strip_prefix("TracerPid:")).and_then(|v| v.trim().parse().ok())
}

/// The cgroup freezer: v2 `cgroup.freeze`/`cgroup.events`, v1 `freezer.state`
fn frozen(pid: u32) -> Option<String> {
    let cg = util::read_small(Path::new(&format!("/proc/{pid}/cgroup")), 16384)?;
    for l in cg.lines() {
        let mut it = l.splitn(3, ':');
        let (_, ctrl, path) = (it.next()?, it.next()?, it.next()?);
        if ctrl.is_empty() {
            let base = PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/'));
            let ev = util::read_small(&base.join("cgroup.events"), 4096).unwrap_or_default();
            if ev.lines().any(|l| l.trim() == "frozen 1") || one(&base.join("cgroup.freeze").to_string_lossy()) == "1" {
                return Some("frozen by its cgroup (cgroup.freeze)".into());
            }
        } else if ctrl.split(',').any(|c| c == "freezer") {
            let f = PathBuf::from("/sys/fs/cgroup/freezer").join(path.trim_start_matches('/')).join("freezer.state");
            let st = one(&f.to_string_lossy());
            if st == "FROZEN" || st == "FREEZING" {
                return Some(format!("frozen by its cgroup (v1 freezer.state {st})"));
            }
        }
    }
    None
}

/// Stopped, traced or frozen: why RPC is not tried
fn stopped(pid: u32) -> Option<String> {
    if cfg!(target_os = "macos") {
        let r = util::run_cmd("ps", &["-o", "state=", "-p", &pid.to_string()], Duration::from_secs(5), 4096);
        let st = r.text().trim().to_string();
        return st.starts_with('T').then(|| format!("node is stopped (ps state {st})"));
    }
    let (state, _, _) = crate::discovery::proc_stat(pid)?;
    if state == 'T' || state == 't' {
        return Some(match tracer_pid(pid) {
            Some(t) if t != 0 => format!("node is traced by pid {t} (state {state})"),
            _ => format!("node is stopped by SIGSTOP or a job-control signal (state {state})"),
        });
    }
    frozen(pid)
}

fn wchan_word(w: &str, state: &str) -> String {
    match w.trim() {
        "0" | "" if state == "R" => "running".into(),
        "0" | "" => "hidden".into(),
        x => x.to_string(),
    }
}

/// Per thread, 10 samples one second apart: `state wchan` runs
fn thread_sample(o: &mut Out, pid: u32) {
    use std::collections::BTreeMap;
    let mut seen: BTreeMap<u32, (String, Vec<String>)> = BTreeMap::new();
    for i in 0..10 {
        if i > 0 {
            std::thread::sleep(Duration::from_secs(1));
        }
        let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            outln!(o, "task/: not readable");
            return;
        };
        for t in rd.flatten() {
            let Ok(tid) = t.file_name().to_string_lossy().parse::<u32>() else { continue };
            let stat = util::read_small(&t.path().join("stat"), 4096).unwrap_or_default();
            let comm = stat.split_once('(').and_then(|(_, r)| r.rsplit_once(')')).map(|(c, _)| c.to_string()).unwrap_or_default();
            let state = stat.rsplit(')').next().unwrap_or("").split_whitespace().next().unwrap_or("?").to_string();
            let w = util::read_small(&t.path().join("wchan"), 256).unwrap_or_else(|| "?".into());
            let e = seen.entry(tid).or_insert_with(|| (comm, Vec::new()));
            while e.1.len() < i {
                e.1.push("-".into());
            }
            e.1.push(format!("{state} {}", wchan_word(&w, &state)));
        }
    }
    outln!(o, "{} threads; per thread its 10 samples, runs collapsed (a hang shows as 10x the same wchan)", seen.len());
    for (tid, (comm, s)) in seen {
        let mut runs: Vec<(String, usize)> = Vec::new();
        for x in s {
            match runs.last_mut() {
                Some((v, n)) if *v == x => *n += 1,
                _ => runs.push((x, 1)),
            }
        }
        let txt: Vec<String> = runs.iter().map(|(v, n)| if *n > 1 { format!("{v} x{n}") } else { v.clone() }).collect();
        outln!(o, "  {tid:>7} {comm:<16} {}", txt.join(", "));
    }
}

/// Open fds by type: socket, pipe, anon_inode:…, file
fn fd_types(o: &mut Out, pid: u32, types: bool) {
    let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        outln!(o, "open fds: not readable");
        return;
    };
    let mut n = 0;
    let mut by: std::collections::BTreeMap<String, usize> = Default::default();
    for e in rd.flatten() {
        n += 1;
        if types {
            let t = match std::fs::read_link(e.path()) {
                Ok(l) => {
                    let s = l.to_string_lossy().to_string();
                    if let Some(x) = s.strip_prefix("anon_inode:") {
                        format!("anon_inode:{}", x.trim_matches(['[', ']']))
                    } else if let Some((k, _)) = s.split_once(':').filter(|_| !s.starts_with('/')) {
                        k.to_string()
                    } else {
                        "file".into()
                    }
                }
                Err(_) => "(type hidden)".into(),
            };
            *by.entry(t).or_default() += 1;
        }
    }
    outln!(o, "open fds: {n}");
    for (k, v) in by {
        outln!(o, "  {k}: {v}");
    }
}

// ------------------------------------------------------- A17 snapshot

/// The A14 mirror folder of a data dir (`<mirror>/<datadir id>`): the one
/// whose `running/<pid>` path record names it. The plan does not define
/// "datadir id", so diag finds it through the record.
pub fn mirror_dir(ctx: &Ctx, d: &DataDir) -> Option<PathBuf> {
    let (live, stale, _) = crate::discovery::path_records(&ctx.mirror_roots);
    live.iter()
        .chain(stale.iter())
        .find(|r| r.datadir.as_deref() == Some(d.path.as_path()) || r.datadir.as_deref() == Some(d.chain.as_path()))
        .and_then(|r| r.file.parent()?.parent().map(Path::to_path_buf))
}

/// Run `f` on a detached thread; None when it did not return in `secs`
fn bounded<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

fn create_request(p: &Path) -> std::io::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(p).map(|_| ())
}

/// Incident files newer than `since` in the places A17 writes them
fn new_incidents(dirs: &[PathBuf], since: SystemTime) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let newer = e.metadata().and_then(|m| m.modified()).map(|t| t >= since).unwrap_or(false);
                if newer && e.path().is_file() {
                    v.push(e.path());
                }
            }
        }
    }
    v
}

fn len_of(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// The A17 snapshot request, in the V7 order, and the wait for its incident
/// true when an incident appeared
pub fn snapshot(o: &mut Out, ctx: &Ctx, d: &DataDir, node: &Node, base: &str) -> bool {
    let me = util::euid();
    if me != 0 && Some(me) != node.uid {
        outln!(o, "snapshot request: not written (diag runs as another user than the node; {})",
            crate::discovery::sudo_hint(node.uid, &d.path));
        return false;
    }
    let mirror = mirror_dir(ctx, d);
    let since = SystemTime::now() - Duration::from_secs(1);
    let mut events: Vec<(PathBuf, u64)> = Vec::new();
    match &mirror {
        Some(m) => {
            let req = m.join("diag/snapshot-request");
            for ev in [m.join("events.log"), m.join("diag/events.log")] {
                events.push((ev.clone(), len_of(&ev)));
            }
            match create_request(&req) {
                Ok(()) => outln!(o, "snapshot request: mirror copy written"),
                Err(e) => outln!(o, "snapshot request: mirror copy failed: {}", util::io_err(&e)),
            }
        }
        None => outln!(o, "snapshot request: no A14 mirror folder names this data dir (no path record); data-dir copy only"),
    }
    let dreq = d.chain.join("diag/snapshot-request");
    match bounded(1, move || create_request(&dreq)) {
        Some(Ok(())) => outln!(o, "snapshot request: data-dir copy written"),
        Some(Err(e)) => outln!(o, "snapshot request: data-dir copy failed: {}", util::io_err(&e)),
        None => outln!(o, "snapshot request: data-dir copy did not return in 1 s (left to its thread; the data-dir disk may be hung)"),
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(m) = &mirror {
        dirs.push(m.join("incidents"));
        dirs.push(m.join("diag/incidents"));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found: Vec<PathBuf> = Vec::new();
    let dd_inc = d.chain.join("diag/incidents");
    let ev_dd = d.chain.join("diag/events.log");
    let ev_dd_len = bounded(1, {
        let p = ev_dd.clone();
        move || len_of(&p)
    })
    .unwrap_or(0);
    while Instant::now() < deadline && found.is_empty() {
        std::thread::sleep(Duration::from_millis(250));
        found = new_incidents(&dirs, since);
        if found.is_empty() {
            let dd = dd_inc.clone();
            found = bounded(1, move || new_incidents(&[dd], since)).unwrap_or_default();
        }
    }
    events.push((ev_dd, ev_dd_len));
    let refused = events.iter().any(|(p, from)| {
        let p = p.clone();
        let from = *from;
        bounded(1, move || {
            let mut f = std::fs::File::open(&p).ok()?;
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Start(from)).ok()?;
            let mut s = String::new();
            f.take(1 << 20).read_to_string(&mut s).ok()?;
            Some(s.contains("incident budget exhausted"))
        })
        .flatten()
        .unwrap_or(false)
    });
    if refused {
        outln!(o, "snapshot refused: budget (A17 \"incident budget exhausted\")");
    }
    if found.is_empty() {
        outln!(o, "snapshot incident: none within 5 s{}", if refused { "" } else { " (a node from before A17, or its watchdog is stuck too)" });
        return false;
    }
    for f in found.iter().take(4) {
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        outln!(o, "snapshot incident: {name} (copied to {base}/incidents/)");
        match util::read_bytes_capped(f, 4 << 20) {
            Ok(b) => {
                o.file(&format!("{base}/incidents/{name}"));
                o.write(crate::oldlog::filter(&util::escape_bytes(&b), &ctx.redactor()).render().as_bytes());
                o.line("");
                o.file(&format!("{base}/live-node.txt"));
            }
            Err(e) => outln!(o, "  not readable: {}", util::io_err(&e)),
        }
    }
    true
}

// --------------------------------------------------------------- driver

pub fn live(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    if ctx.datadirs.is_empty() {
        o.file("live-node.txt");
        outln!(o, "no data dir found: no live node to ask");
        return;
    }
    for d in &ctx.datadirs {
        let base = format!("datadir-{}", d.n);
        o.file(&format!("{base}/live-node.txt"));
        head(o, "B2.16 live node");
        let Some(node) = ctx.node_for(d) else {
            outln!(o, "no node is running on this data dir: nothing to ask");
            continue;
        };
        one_node(o, ctx, &r, d, node, &base);
    }
}

fn one_node(o: &mut Out, ctx: &Ctx, r: &Redactor, d: &DataDir, node: &Node, base: &str) {
    let pid = node.pid;
    let mac = cfg!(target_os = "macos");
    let readable = !mac && crate::discovery::proc_readable(pid);
    if mac {
        outln!(o, "A5 readability check: n/a (macOS)");
    } else {
        let cap = crate::util::read_small(Path::new("/proc/self/status"), 16384)
            .and_then(|s| s.lines().find(|l| l.starts_with("CapEff:")).map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string()))
            .unwrap_or_else(|| "?".into());
        outln!(o, "A5 readability check (io/environ): {}", if readable { "readable" } else { "refused (non-dumpable node, D5, or another user)" });
        outln!(o, "diag: euid {} ({}), CapEff {cap}, CAP_SYS_PTRACE {}", util::euid(),
            if util::euid() == 0 { "root" } else if Some(util::euid()) == node.uid { "the node's user" } else { "another user" },
            if crate::discovery::cap_bit("CapEff", 19) { "yes" } else { "no" });
    }

    // the process state, before any RPC; no signal is ever sent
    if let Some(why) = stopped(pid) {
        outln!(o, "process state: {why}");
        outln!(o, "RPC: not tried (the node cannot answer); no signal sent");
        matrix(o, pid, readable, "none", mac);
        return;
    }
    let state = crate::discovery::proc_stat(pid).map(|s| s.0).unwrap_or('?');
    if !mac {
        outln!(o, "process state: {state}");
    }

    // RPC
    outln!(o);
    let mut source = "none";
    match rpc_for(d, Some(node)) {
        Err(why) => outln!(o, "RPC: not tried: {why}"),
        Ok(rpc) => {
            outln!(o, "RPC: {} port {}, credentials: {}", super::sys::ip_class(&rpc.addr.ip().to_string()), rpc.addr.port(), rpc.auth_kind);
            match rpc_report(o, r, &rpc, Duration::from_secs(FIRST_CALL_SECS)) {
                Ok(()) => source = "getdiaginfo",
                Err(CallError::Timeout) => {
                    outln!(o, "RPC did not answer within {FIRST_CALL_SECS} s");
                    snapshot(o, ctx, d, node, base);
                    source = "A17 incident";
                }
                Err(_) => {}
            }
        }
    }

    // /proc reads
    outln!(o);
    if mac {
        outln!(o, "status, limits, io, smaps_rollup, wchan: n/a (macOS)");
        outln!(o, "--- sample {pid} 1 (reads stacks, sends no signal)");
        super::cmd_block_t(o, "sample", &[&pid.to_string(), "1"], 15, 4 << 20);
        let l = util::run_cmd("lsof", &["-n", "-P", "-p", &pid.to_string()], Duration::from_secs(10), 8 << 20);
        let mut by: std::collections::BTreeMap<String, usize> = Default::default();
        for line in l.text().lines().skip(1) {
            if let Some(t) = line.split_whitespace().nth(4) {
                *by.entry(t.to_string()).or_default() += 1;
            }
        }
        outln!(o, "open files by type (lsof): {}", by.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "));
    } else {
        for k in super::status_fields(&pid.to_string(), &[
            "State", "TracerPid", "Threads", "VmPeak", "VmSize", "VmHWM", "VmRSS", "VmSwap", "SigBlk", "SigIgn",
            "SigCgt", "CapEff", "NoNewPrivs", "Seccomp", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
        ]) {
            outln!(o, "status {k}");
        }
        super::file_block(o, &format!("/proc/{pid}/limits"));
        if readable {
            super::file_block(o, &format!("/proc/{pid}/io"));
            super::file_block(o, &format!("/proc/{pid}/smaps_rollup"));
            fd_types(o, pid, true);
            outln!(o);
            thread_sample(o, pid);
        } else {
            outln!(o, "io, smaps_rollup, fd types, wchan sample: unreadable: node is non-dumpable (D5); from {source} instead");
            if util::euid() == 0 {
                // root without CAP_SYS_PTRACE keeps the count (N4)
                fd_types(o, pid, false);
            }
        }
    }
    outln!(o);
    matrix(o, pid, readable, source, mac);
}

fn matrix(o: &mut Out, pid: u32, readable: bool, source: &str, mac: bool) {
    outln!(o, "visibility matrix (entry of the node's /proc folder: result; source used instead):");
    let state = crate::discovery::proc_stat(pid).map(|s| s.0).unwrap_or('?');
    for e in MATRIX {
        if mac {
            outln!(o, "  {e:<13} n/a (macOS)");
            continue;
        }
        let v = visible(pid, e, state);
        let instead = if v == "read" || v.starts_with("read ") {
            String::new()
        } else if ["cwd", "exe", "root"].contains(e) {
            "; instead: A14 path record".into()
        } else if *e == "environ" {
            "; instead: none (getdiaginfo known-value pages, A10)".into()
        } else {
            format!("; instead: {source}")
        };
        outln!(o, "  {e:<13} {v}{instead}");
    }
    let _ = readable;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"__cookie__:ab"), "X19jb29raWVfXzphYg==");
    }

    #[test]
    fn hosts() {
        assert_eq!(host_of("1.2.3.4:51472"), "1.2.3.4");
        assert_eq!(host_of("[2001:db8::1]:51472"), "2001:db8::1");
        assert_eq!(host_of("abc.onion:51472"), "abc.onion");
        assert_eq!(wchan_word("0", "R"), "running");
        assert_eq!(wchan_word("0\n", "S"), "hidden");
        assert_eq!(wchan_word("futex_wait_queue", "S"), "futex_wait_queue");
    }

    #[test]
    fn chunked() {
        assert_eq!(unchunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap(), b"abcde");
    }
}
