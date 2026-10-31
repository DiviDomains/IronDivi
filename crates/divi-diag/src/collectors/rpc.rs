// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B6.5 `diag --rpc <method> [args…]`: one allowlisted call to the running
//! node, its answer through the RPC JSON layer ([`crate::rpcjson`]).
//!
//! The parent checks every request before anything runs ([`check`]): the
//! allowlist, the refused methods, `getdiaginfo` without parameters, and
//! the clamps that need no node (`listtransactions` count, `getblock`
//! verbosity, `getmasternodewinners` blocks). This collector does the
//! checks that need the node: free memory, `listunspent` against the
//! wallet's transaction count, verbose `getrawmempool` against the
//! mempool size and `listsinceblock` against the tip. Every call has 2 s
//! ("slow: stopped waiting") and all of them share 60 s.

use super::live::{self, CallError, Rpc};
use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use crate::redact::Redactor;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// The B6.5 allowlist (every name checked against divi-rpc's server.rs);
/// `mnsync` only as `mnsync status`
pub const ALLOW: &[&str] = &[
    "getblockchaininfo", "getblockcount", "getbestblockhash", "getblockhash", "getblockheader", "getblock",
    "getchaintips", "getdifficulty", "getrawmempool", "getmempoolinfo", "getnetworkinfo", "getpeerinfo",
    "getconnectioncount", "getnettotals", "getinfo", "getstakingstatus", "getmintinginfo", "getmasternodecount",
    "listmasternodes", "getmasternodestatus", "getmasternodewinners", "getlotteryblockwinners", "mnsync", "gettxout",
    "getinvalid", "getwalletinfo", "getbalance", "getcoinavailability", "listtransactions", "listsinceblock",
    "listunspent", "listlockunspent", "gettransaction", "getreceivedbyaddress", "getdiaginfo",
];

/// Removed in revision 6: no argument bounds them (B6.5)
const RUN_IT_YOURSELF: &[&str] = &["gettxoutsetinfo", "getaddressbalance", "getaddressutxos"];

/// Public lists: every 64-hex value or key and every address field is
/// pseudonymised under the public-record salt, never the wallet-side one
/// (B6.5 "Public lists"). `getblock` is a public list in the plan, but
/// every block answer is reduced here (own staked block undecided).
const PUBLIC_LISTS: &[&str] = &["listmasternodes", "getrawmempool", "getmasternodewinners", "getlotteryblockwinners"];

/// The fields that hold an address in the public lists
const ADDR_KEYS: &[&str] = &["addr", "address", "addresses", "payee", "payees", "winner"];

/// Whose argument names a block that may be an own staked one: dropped
/// from the call line (R1); diag cannot tell here, so always
const BLOCK_ARG: &[&str] = &["getblock", "getblockheader", "getblockhash"];

pub const CALL_SECS: u64 = 2;
pub const TOTAL_SECS: u64 = 60;
const MIN_FREE: u64 = 512 << 20;
const MAX_TXCOUNT: u64 = 10_000;
const MAX_MEMPOOL_VERBOSE: u64 = 5_000;
const MAX_SINCE_DEPTH: i64 = 1_000;

/// One checked request, handed to the child in the context
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Req {
    pub method: String,
    pub params: Vec<Value>,
    /// the clamps the parent applied, one line each
    pub clamps: Vec<String>,
}

/// `--rpc` arguments as the node takes them: JSON when it parses, else a
/// string (the irondivi-cli convention)
pub fn params_of(args: &[String]) -> Vec<Value> {
    args.iter()
        .map(|a| match serde_json::from_str::<Value>(a) {
            Ok(v @ (Value::Number(_) | Value::Bool(_) | Value::Array(_) | Value::Object(_) | Value::Null)) => v,
            _ => Value::String(a.clone()),
        })
        .collect()
}

fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

/// The checks that need no node. `Err` is the refusal reason.
pub fn check(method: &str, mut params: Vec<Value>) -> Result<Req, String> {
    let mut clamps = Vec::new();
    if RUN_IT_YOURSELF.contains(&method) {
        return Err(format!(
            "no argument bounds its cost on the node; run it yourself and attach the output: \
             irondivi-cli {method} > {method}.json, then irondivi-cli diag --attach {method}.json --attach-method {method}"
        ));
    }
    if !ALLOW.contains(&method) {
        let l = method.to_ascii_lowercase();
        let why = if l.starts_with("dump") || l.starts_with("sign") || l.starts_with("backup") {
            "it reads or uses private keys or wallet files"
        } else if l.ends_with("privkey") || l.ends_with("genkey") {
            "it handles private keys"
        } else {
            "it is not on the B6.5 allowlist (diag never calls a method that changes state)"
        };
        return Err(why.into());
    }
    match method {
        "getdiaginfo" if !params.is_empty() => {
            return Err("getdiaginfo takes no parameters here: diag_key and known_values are refused (A10)".into())
        }
        "mnsync" if params.len() != 1 || params[0].as_str() != Some("status") => {
            return Err("only `mnsync status` is allowed (`mnsync reset` changes state)".into())
        }
        "listtransactions" => {
            if let Some(c) = params.get(1).and_then(as_i64) {
                if c > 1000 {
                    params[1] = Value::from(1000);
                    clamps.push(format!("clamped: count {c} → 1000"));
                }
            }
        }
        "getblock" => match params.get(1) {
            None => {}
            Some(v) => {
                let n = as_i64(v).unwrap_or(1);
                if n != 1 {
                    params[1] = Value::from(1);
                    clamps.push(format!(
                        "clamped: verbosity {} → 1{}",
                        n,
                        if n == 0 { " (a raw block is not sent)" } else { "" }
                    ));
                }
            }
        },
        "getblockheader" => {
            if params.get(1).and_then(Value::as_bool) == Some(false) {
                params[1] = Value::Bool(true);
                clamps.push("clamped: verbose false → true (a raw header is not sent)".into());
            }
        }
        // the node reads `blocks` as a string (C `atoi`, masternode.rs), so
        // a number is sent as its string; `irondivi-cli` itself sends 100
        // as a number and the node refuses it
        "getmasternodewinners" => {
            if let Some(n) = params.first().and_then(as_i64) {
                if n > 100 {
                    clamps.push(format!("clamped: blocks {n} → 100"));
                }
                params[0] = Value::from(n.min(100).to_string());
            }
        }
        "listsinceblock" if params.first().and_then(Value::as_str).is_none_or(str::is_empty) => {
            return Err("listsinceblock without a block hash lists the whole wallet; name a block at most 1000 \
                        blocks below the tip"
                .into())
        }
        _ => {}
    }
    Ok(Req { method: method.to_string(), params, clamps })
}

/// The call as it is shown, logged and sent: a block argument is dropped
/// (R1), every other argument through the hex backstop and §6.2
pub fn call_line(red: &Redactor, method: &str, params: &[Value]) -> String {
    let mut s = method.to_string();
    for (i, p) in params.iter().enumerate() {
        s.push(' ');
        if i == 0 && BLOCK_ARG.contains(&method) {
            s.push_str("<block argument dropped>");
            continue;
        }
        let t = match p {
            Value::String(x) => x.clone(),
            other => other.to_string(),
        };
        s.push_str(&red.scrub(&crate::rpcjson::backstop(&t)));
    }
    s
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The public-record pseudonym: a different salt from the wallet side's,
/// so a public pseudonym never equals the wallet-side one of the same
/// value and the user's own entry cannot be picked out
fn pseudonym(salt: &[u8], s: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"irondivi-diag public record");
    h.update(salt);
    h.update(s.as_bytes());
    format!("pub-{}", &hex::encode(h.finalize())[..12])
}

/// Every 64-hex value and key, and every string in an address field, of
/// a public list, for every entry alike
fn public_pseudonyms(v: Value, salt: &[u8]) -> (Value, usize) {
    fn walk(v: Value, salt: &[u8], n: &mut usize, addr: bool) -> Value {
        match v {
            Value::String(s) if is_hex64(&s) => {
                *n += 1;
                Value::from(pseudonym(salt, &s.to_ascii_lowercase()))
            }
            Value::String(s) if addr && !s.is_empty() => {
                *n += 1;
                Value::from(pseudonym(salt, &s))
            }
            Value::Array(a) => Value::Array(a.into_iter().map(|x| walk(x, salt, n, addr)).collect()),
            Value::Object(m) => Value::Object(
                m.into_iter()
                    .map(|(k, x)| {
                        let a = ADDR_KEYS.contains(&k.as_str());
                        let k = if is_hex64(&k) {
                            *n += 1;
                            pseudonym(salt, &k.to_ascii_lowercase())
                        } else {
                            k
                        };
                        (k, walk(x, salt, n, a))
                    })
                    .collect(),
            ),
            other => other,
        }
    }
    let mut n = 0;
    let v = walk(v, salt, &mut n, false);
    (v, n)
}

/// The collector: run each request against the chosen data dir's node
pub fn rpc(ctx: &Ctx, o: &mut Out) {
    let red = ctx.redactor();
    o.file("rpc/summary.txt");
    for l in &ctx.rpc_refused {
        outln!(o, "{l}");
    }
    if ctx.rpc.is_empty() {
        return;
    }
    let Some(d) = ctx.rpc_datadir.and_then(|n| ctx.datadirs.iter().find(|d| d.n == n)) else {
        outln!(o, "no data dir chosen: no call made");
        return;
    };
    let Some(node) = ctx.node_for(d) else {
        outln!(o, "no node is running on datadir-{}: no call made", d.n);
        return;
    };
    let rpc = match live::rpc_for(d, Some(node)) {
        Ok(r) => r,
        Err(why) => {
            outln!(o, "no call made: {why}");
            return;
        }
    };
    outln!(o, "node: datadir-{} pid {}, credentials from the {}", d.n, node.pid, rpc.auth_kind);
    let start = Instant::now();
    let salt = hex::decode(&ctx.salt).unwrap_or_default();
    for (i, req) in ctx.rpc.iter().enumerate() {
        let n = i + 1;
        let line = call_line(&red, &req.method, &req.params);
        outln!(o, "");
        outln!(o, "call {n}: {line}");
        for c in &req.clamps {
            outln!(o, "    {c}");
        }
        if start.elapsed() >= Duration::from_secs(TOTAL_SECS) {
            outln!(o, "    not called: the {TOTAL_SECS} s shared by every --rpc call are spent");
            continue;
        }
        let free = crate::mem::free_memory(Some(node.pid));
        if let Some(b) = free.bytes {
            if b < MIN_FREE {
                outln!(o, "    refused: free memory {} MB is under 512 MB", b >> 20);
                continue;
            }
        }
        let mut params = req.params.clone();
        match gate(&rpc, &req.method, &mut params) {
            Gate::Go(notes) => {
                for l in notes {
                    outln!(o, "    {l}");
                }
            }
            Gate::Refuse(why) => {
                outln!(o, "    refused: {why}");
                continue;
            }
        }
        let t = Instant::now();
        let res = live::call(&rpc, &req.method, Value::Array(params), Duration::from_secs(CALL_SECS));
        let ms = t.elapsed().as_millis();
        let v = match res {
            Ok(v) => v,
            Err(CallError::Timeout) => {
                outln!(o, "    slow: stopped waiting after {CALL_SECS} s (the node may still be working on it)");
                continue;
            }
            Err(e) => {
                outln!(o, "    {e} (after {ms} ms)");
                continue;
            }
        };
        let (v, pubn) = if PUBLIC_LISTS.contains(&req.method.as_str()) {
            public_pseudonyms(v, &salt)
        } else {
            (v, 0)
        };
        let t = crate::rpcjson::treat_call(v, &req.method);
        let rel = format!("rpc/{n}-{}.json", req.method);
        outln!(o, "    answered in {ms} ms: {rel}");
        outln!(o, "    treatment: {}", t.treatment);
        if pubn > 0 {
            outln!(o, "    pseudonymised under the public-record salt, for every entry: {pubn} values");
        }
        for a in t.action_lines() {
            outln!(o, "    {a}");
        }
        let text = serde_json::to_string_pretty(&t.json).unwrap_or_default();
        o.file(&rel);
        o.write(red.scrub(&text).as_bytes());
        o.write(b"\n");
        o.file("rpc/summary.txt");
    }
}

enum Gate {
    Go(Vec<String>),
    Refuse(String),
}

/// The checks that need the node (B6.5 argument caps); every look-up has
/// the same 2 s
fn gate(rpc: &Rpc, method: &str, params: &mut [Value]) -> Gate {
    let ask = |m: &str, p: Value| live::call(rpc, m, p, Duration::from_secs(CALL_SECS));
    match method {
        "listunspent" => match ask("getwalletinfo", Value::Array(vec![])) {
            Ok(w) => match w.get("txcount").and_then(Value::as_u64) {
                Some(c) if c > MAX_TXCOUNT => Gate::Refuse(format!(
                    "the wallet has more than {MAX_TXCOUNT} transactions; run it yourself and attach the output: \
                     irondivi-cli listunspent > unspent.json, then irondivi-cli diag --attach unspent.json \
                     --attach-method listunspent"
                )),
                Some(_) => Gate::Go(vec![]),
                None => Gate::Refuse("getwalletinfo gave no txcount, so the size of the wallet is unknown".into()),
            },
            Err(e) => Gate::Refuse(format!("getwalletinfo, needed to size the wallet first: {e}")),
        },
        "getrawmempool" if params.first().and_then(Value::as_bool) == Some(true) => {
            match ask("getmempoolinfo", Value::Array(vec![])).ok().and_then(|m| m.get("size").and_then(Value::as_u64)) {
                Some(s) if s < MAX_MEMPOOL_VERBOSE => Gate::Go(vec![]),
                got => {
                    params[0] = Value::Bool(false);
                    Gate::Go(vec![match got {
                        Some(s) => format!("clamped: verbose true → false (the mempool holds {s} entries, 5000 or more)"),
                        None => "clamped: verbose true → false (the mempool size is unknown)".into(),
                    }])
                }
            }
        }
        "listsinceblock" => {
            let hash = params.first().and_then(Value::as_str).unwrap_or("").to_string();
            let h = ask("getblockheader", Value::Array(vec![Value::from(hash)]))
                .ok()
                .and_then(|v| v.get("height").and_then(Value::as_i64));
            let tip = ask("getblockcount", Value::Array(vec![])).ok().and_then(|v| v.as_i64());
            match (h, tip) {
                (Some(h), Some(t)) if t - h <= MAX_SINCE_DEPTH => Gate::Go(vec![]),
                (Some(h), Some(t)) => Gate::Refuse(format!(
                    "the block is {} blocks below the tip, more than {MAX_SINCE_DEPTH}",
                    t - h
                )),
                _ => Gate::Refuse("the block's height or the tip is unknown, so the depth cannot be checked".into()),
            }
        }
        _ => Gate::Go(vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Vec<Value> {
        params_of(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn params_parse_like_the_cli() {
        assert_eq!(p(&["1", "true", "abc", "[\"x\"]"]), vec![Value::from(1), Value::Bool(true), Value::from("abc"), serde_json::json!(["x"])]);
        // a quoted word stays a string, not a JSON string with quotes
        assert_eq!(p(&["\"*\""]), vec![Value::from("\"*\"")]);
    }

    #[test]
    fn refusals() {
        for m in ["dumpprivkey", "dumpwallet", "signmessage", "backupwallet", "importprivkey", "sendtoaddress", "stop"] {
            assert!(check(m, vec![]).is_err(), "{m}");
        }
        let e = check("gettxoutsetinfo", vec![]).unwrap_err();
        assert!(e.contains("--attach gettxoutsetinfo.json --attach-method gettxoutsetinfo"));
        assert!(check("getdiaginfo", p(&["diag_key"])).is_err());
        assert!(check("getdiaginfo", vec![]).is_ok());
        assert!(check("mnsync", p(&["reset"])).is_err());
        assert!(check("mnsync", vec![]).is_err());
        assert!(check("mnsync", p(&["status"])).is_ok());
        assert!(check("listsinceblock", vec![]).is_err());
    }

    #[test]
    fn clamps() {
        let r = check("listtransactions", p(&["*", "1000000"])).unwrap();
        assert_eq!(r.params[1], Value::from(1000));
        assert_eq!(r.clamps, vec!["clamped: count 1000000 → 1000"]);
        let r = check("getblock", p(&["00ab", "2"])).unwrap();
        assert_eq!(r.params[1], Value::from(1));
        let r = check("getblock", p(&["00ab", "false"])).unwrap();
        assert_eq!(r.params[1], Value::from(1));
        let r = check("getmasternodewinners", p(&["5000"])).unwrap();
        assert_eq!(r.params[0], Value::from("100"));
        let r = check("getmasternodewinners", p(&["20"])).unwrap();
        assert_eq!(r.params[0], Value::from("20"));
        assert!(r.clamps.is_empty());
        let r = check("getblockheader", p(&["00ab", "false"])).unwrap();
        assert_eq!(r.params[1], Value::Bool(true));
        assert!(check("listtransactions", p(&["*", "50"])).unwrap().clamps.is_empty());
    }

    #[test]
    fn call_line_drops_block_args_and_masks_hex() {
        let red = Redactor::new([7u8; 32], &Default::default());
        let h = "aa".repeat(32);
        let l = call_line(&red, "getblock", &[Value::from(h.clone()), Value::from(1)]);
        assert_eq!(l, "getblock <block argument dropped> 1");
        let l = call_line(&red, "gettransaction", &[Value::from(h.clone())]);
        assert!(!l.contains(&h), "{l}");
        let l = call_line(&red, "gettxout", &[Value::from("ab".repeat(30))]);
        assert!(l.contains("<hex:60>"), "{l}");
    }

    #[test]
    fn public_lists_use_their_own_salt() {
        let h = "cd".repeat(32);
        let (v, n) = public_pseudonyms(serde_json::json!([{"txhash": h, "outidx": 0}]), b"s");
        assert_eq!(n, 1);
        let s = v[0]["txhash"].as_str().unwrap();
        assert!(s.starts_with("pub-") && !s.contains(&h));
        let (w, _) = public_pseudonyms(serde_json::json!([h]), b"t");
        assert_ne!(w[0], v[0]["txhash"]);
        // mempool keys and address fields too
        let (m, n) = public_pseudonyms(serde_json::json!({h.clone(): {"size": 1}, "x": {"addr": "DXyz", "status": "ENABLED"}}), b"s");
        assert_eq!(n, 2);
        assert!(!m.to_string().contains(&h) && !m.to_string().contains("DXyz"), "{m}");
        assert_eq!(m["x"]["status"], "ENABLED");
    }
}
