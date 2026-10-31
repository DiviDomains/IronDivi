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
use crate::rpcjson::BlockDecision;
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
/// (B6.5 "Public lists"). The block methods are public records too, once
/// their block is decided not own ([`decide`], [`crate::rpcjson::treat_block`]).
const PUBLIC_LISTS: &[&str] = &["listmasternodes", "getrawmempool", "getmasternodewinners", "getlotteryblockwinners"];

/// The fields that hold an address in the public lists
const ADDR_KEYS: &[&str] = &["addr", "address", "addresses", "payee", "payees", "winner"];

/// Whose argument names a block that may be an own staked one: dropped
/// from the call line (R1) unless the block is decided not own
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

/// The call as it is shown, logged and sent. The block argument of
/// `getblock`, `getblockheader` and `getblockhash` is dropped (R1) unless
/// the block was decided not own (`public`), when a hash shows as
/// `blk:<hash>` and a height as itself. Every address gets its own
/// pseudonym (the same one it has in the answer), every other argument
/// goes through the hex backstop and §6.2.
pub fn call_line(red: &Redactor, method: &str, params: &[Value], public: bool) -> String {
    let mut s = method.to_string();
    for (i, p) in params.iter().enumerate() {
        s.push(' ');
        let t = match p {
            Value::String(x) => x.clone(),
            other => other.to_string(),
        };
        if i == 0 && BLOCK_ARG.contains(&method) {
            if !public {
                s.push_str("<block argument dropped>");
            } else if is_hex64(&t) {
                s.push_str(&format!("blk:{}", t.to_ascii_lowercase()));
            } else if t.bytes().all(|b| b.is_ascii_digit()) {
                s.push_str(&t);
            } else {
                s.push_str("<block argument dropped>");
            }
            continue;
        }
        s.push_str(&red.scrub(&red.addresses(&crate::rpcjson::backstop(&t))));
    }
    s
}

/// Every string in an answer with its addresses replaced by their own
/// pseudonyms, before the walk and the scrub
fn own_addresses(red: &Redactor, v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(red.addresses(&s)),
        Value::Array(a) => Value::Array(a.into_iter().map(|x| own_addresses(red, x)).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, x)| (k, own_addresses(red, x))).collect()),
        other => other,
    }
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

/// One block lookup has 10 s, all of them 60 s, apart from the 60 s the
/// calls themselves share (B6.5 "Undecided is reduced")
pub const LOOKUP_SECS: u64 = 10;
pub const LOOKUPS_SECS: u64 = 60;

/// What a block lookup asks of the node: a trait so the tests answer from
/// fixtures
pub trait Ask {
    fn ask(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, String>;
    /// free memory is known and under 512 MB (step 1's rule)
    fn low_memory(&mut self) -> bool;
}

struct NodeAsk<'a> {
    rpc: &'a Rpc,
    pid: u32,
}

impl Ask for NodeAsk<'_> {
    fn ask(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        live::call(self.rpc, method, params, timeout).map_err(|e| match e {
            CallError::Timeout => "no answer in time".to_string(),
            e => e.to_string(),
        })
    }
    fn low_memory(&mut self) -> bool {
        crate::mem::free_memory(Some(self.pid)).bytes.is_some_and(|b| b < MIN_FREE)
    }
}

/// A coinstake as `getblock <hash> 2` shows it: a first input that spends
/// an output (not a coinbase), at least two outputs, the first one empty
/// (`is_coinstake`, divi-primitives transaction.rs)
fn is_coinstake(tx: &Value) -> bool {
    let vin0 = &tx["vin"][0];
    let vout = tx["vout"].as_array();
    let empty0 = vout.and_then(|v| v.first()).is_some_and(|o| {
        let zero = o["valueSat"].as_i64() == Some(0) || o["value"].as_f64() == Some(0.0);
        let spk = &o["scriptPubKey"];
        let no_script = spk["hex"].as_str().is_some_and(str::is_empty) || spk["asm"].as_str().is_some_and(str::is_empty);
        zero && no_script
    });
    vin0.get("txid").and_then(Value::as_str).is_some()
        && vin0.get("coinbase").is_none()
        && vout.is_some_and(|v| v.len() >= 2)
        && empty0
}

/// Whose block is `hash`: from the staked input only (Y1, N2), the script
/// of the output the coinstake's first input spends, tested against the
/// wallet with `validateaddress` (`ismine` or `iswatchonly`). Nothing the
/// lookup reads is written anywhere.
pub fn decide(a: &mut dyn Ask, hash: &str, run_left: Duration) -> BlockDecision {
    use BlockDecision::*;
    let budget = run_left.min(Duration::from_secs(LOOKUP_SECS));
    if budget.is_zero() {
        return Undecided(format!("the {LOOKUPS_SECS} s for block lookups are spent"));
    }
    let end = Instant::now() + budget;
    let call = |a: &mut dyn Ask, m: &str, p: Value| -> Result<Value, String> {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("the lookup went over its {} s", budget.as_secs()));
        }
        if a.low_memory() {
            return Err("free memory is under 512 MB".into());
        }
        a.ask(m, p, left).map_err(|e| format!("{m}: {e}"))
    };
    let block = match call(a, "getblock", serde_json::json!([hash, 2])) {
        Ok(b) => b,
        Err(e) => return Undecided(e),
    };
    let Some(cs) = block["tx"].as_array().and_then(|t| t.get(1)).filter(|t| is_coinstake(t)) else {
        // a proof-of-work block has no coinstake: nobody staked it
        return NotOwn;
    };
    let (Some(txid), Some(n)) = (cs["vin"][0]["txid"].as_str(), cs["vin"][0]["vout"].as_u64()) else {
        return Undecided("the coinstake's input could not be read".into());
    };
    let prev = match call(a, "getrawtransaction", serde_json::json!([txid, 1])) {
        Ok(p) => p,
        Err(e) => return Undecided(e),
    };
    let out = prev["vout"]
        .as_array()
        .and_then(|v| v.iter().find(|o| o["n"].as_u64() == Some(n)).or_else(|| v.get(n as usize)));
    let Some(spk) = out.map(|o| &o["scriptPubKey"]) else {
        return Undecided("the staked output could not be read".into());
    };
    let typ = spk["type"].as_str().unwrap_or("");
    let addrs: Vec<String> = spk["addresses"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();
    if !matches!(typ, "pubkeyhash" | "scripthash" | "pubkey" | "vault") || addrs.is_empty() {
        let typ = if typ.is_empty() { "unknown" } else { typ };
        return Undecided(format!("its staked script ({typ}) cannot be decoded"));
    }
    for addr in addrs {
        match call(a, "validateaddress", serde_json::json!([addr])) {
            Ok(v) if v["ismine"].as_bool() == Some(true) || v["iswatchonly"].as_bool() == Some(true) => return Own,
            Ok(v) if v["isvalid"].as_bool() == Some(false) => {
                return Undecided("an address of its staked script is not valid here".into())
            }
            Ok(_) => {}
            Err(e) => return Undecided(e),
        }
    }
    if typ == "vault" {
        // the wallet's vault hashes are not shown to be in its key set
        return Undecided("a vault stake, and the wallet's vault hashes may be missing from the own set".into());
    }
    NotOwn
}

/// The hash and height a block answer is about
fn block_of(method: &str, params: &[Value], v: &Value) -> Option<(String, Option<i64>)> {
    match method {
        "getblock" | "getblockheader" => {
            let h = v["hash"].as_str().filter(|h| is_hex64(h))?;
            Some((h.to_ascii_lowercase(), v["height"].as_i64()))
        }
        "getblockhash" => {
            let h = v.as_str().filter(|h| is_hex64(h))?;
            Some((h.to_ascii_lowercase(), params.first().and_then(as_i64)))
        }
        _ => None,
    }
}

/// Y4: in a run of consecutive heights, one block that is not decided
/// "not own" reduces every block of the run (a clear neighbour gives the
/// reduced block's height away). `calls` holds (height, decision) per call.
pub fn neighbours(calls: &mut [(Option<i64>, Option<BlockDecision>)]) {
    let mut hs: Vec<i64> = calls.iter().filter(|(_, d)| d.is_some()).filter_map(|(h, _)| *h).collect();
    hs.sort_unstable();
    hs.dedup();
    let mut runs: Vec<Vec<i64>> = Vec::new();
    for h in hs {
        match runs.last_mut() {
            Some(r) if r.last().is_some_and(|l| l + 1 == h) => r.push(h),
            _ => runs.push(vec![h]),
        }
    }
    for r in runs.iter().filter(|r| r.len() > 1) {
        let in_run = |h: Option<i64>| h.is_some_and(|h| r.contains(&h));
        let reduced = calls
            .iter()
            .any(|(h, d)| in_run(*h) && d.as_ref().is_some_and(|d| *d != BlockDecision::NotOwn));
        if reduced {
            for (h, d) in calls.iter_mut() {
                if in_run(*h) && *d == Some(BlockDecision::NotOwn) {
                    *d = Some(BlockDecision::Undecided("reduced with its neighbours (Y4)".into()));
                }
            }
        }
    }
}

/// One call as made, before anything is written
struct Made {
    notes: Vec<String>,
    answer: Option<(Value, u128)>,
    height: Option<i64>,
    decision: Option<BlockDecision>,
}

/// The collector: run each request against the chosen data dir's node.
/// Every call is made first, then the block answers are decided (and Y4
/// applied over all of them), then the summary and the answers are
/// written, so a call line shows a block argument only once its block is
/// known not to be own.
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
    let mut looked = Duration::ZERO;
    let mut cache: std::collections::HashMap<String, BlockDecision> = Default::default();
    let mut made: Vec<Made> = Vec::new();
    for req in &ctx.rpc {
        let mut m = Made { notes: req.clamps.clone(), answer: None, height: None, decision: None };
        if start.elapsed().saturating_sub(looked) >= Duration::from_secs(TOTAL_SECS) {
            m.notes.push(format!("not called: the {TOTAL_SECS} s shared by every --rpc call are spent"));
            made.push(m);
            continue;
        }
        if let Some(b) = crate::mem::free_memory(Some(node.pid)).bytes {
            if b < MIN_FREE {
                m.notes.push(format!("refused: free memory {} MB is under 512 MB", b >> 20));
                made.push(m);
                continue;
            }
        }
        let mut params = req.params.clone();
        match gate(&rpc, &req.method, &mut params) {
            Gate::Go(notes) => m.notes.extend(notes),
            Gate::Refuse(why) => {
                m.notes.push(format!("refused: {why}"));
                made.push(m);
                continue;
            }
        }
        let t = Instant::now();
        let res = live::call(&rpc, &req.method, Value::Array(params.clone()), Duration::from_secs(CALL_SECS));
        let ms = t.elapsed().as_millis();
        match res {
            Ok(v) => {
                if let Some((hash, height)) = block_of(&req.method, &params, &v) {
                    let lt = Instant::now();
                    let left = Duration::from_secs(LOOKUPS_SECS).saturating_sub(looked);
                    let dec = cache
                        .entry(hash)
                        .or_insert_with_key(|h| decide(&mut NodeAsk { rpc: &rpc, pid: node.pid }, h, left));
                    m.decision = Some(dec.clone());
                    m.height = height;
                    looked += lt.elapsed();
                }
                m.answer = Some((v, ms));
            }
            Err(CallError::Timeout) => {
                m.notes.push(format!("slow: stopped waiting after {CALL_SECS} s (the node may still be working on it)"))
            }
            Err(e) => m.notes.push(format!("{e} (after {ms} ms)")),
        }
        made.push(m);
    }
    // Y4 over every block answer in the package
    let mut hd: Vec<(Option<i64>, Option<BlockDecision>)> = made.iter().map(|m| (m.height, m.decision.clone())).collect();
    neighbours(&mut hd);
    for (m, (_, d)) in made.iter_mut().zip(hd) {
        m.decision = d;
    }
    let salt = hex::decode(&ctx.salt).unwrap_or_default();
    let blocks = made.iter().filter(|m| m.decision.is_some()).count();
    let reduced = made.iter().filter(|m| m.decision.as_ref().is_some_and(|d| *d != BlockDecision::NotOwn)).count();
    for (i, (req, m)) in ctx.rpc.iter().zip(made).enumerate() {
        let n = i + 1;
        let public = m.decision == Some(BlockDecision::NotOwn);
        outln!(o, "");
        outln!(o, "call {n}: {}", call_line(&red, &req.method, &req.params, public));
        for l in &m.notes {
            outln!(o, "    {l}");
        }
        let Some((v, ms)) = m.answer else { continue };
        let mut pubn = 0;
        let t = match &m.decision {
            Some(d) => {
                match d {
                    BlockDecision::Own => outln!(
                        o,
                        "    this block was staked by your wallet; only its version, size class and transaction count \
                         are sent"
                    ),
                    BlockDecision::Undecided(why) => outln!(
                        o,
                        "    this block could not be checked against your wallet ({why}); only its version, size \
                         class and transaction count are sent"
                    ),
                    BlockDecision::NotOwn => outln!(o, "    not staked by your wallet: a public record"),
                }
                crate::rpcjson::treat_block(v, &req.method, d, &|s| pseudonym(&salt, s))
            }
            None => {
                let v = if PUBLIC_LISTS.contains(&req.method.as_str()) {
                    let (v, k) = public_pseudonyms(v, &salt);
                    pubn = k;
                    v
                } else {
                    own_addresses(&red, v)
                };
                crate::rpcjson::treat_call(v, &req.method)
            }
        };
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
    if blocks > 0 && reduced == blocks {
        outln!(o, "");
        outln!(
            o,
            "every block answer was reduced (Y5): the masternode-payment evidence that remains is \
             `irondivi-cli diag --rpc getmasternodewinners`, the payment lines in the logs, and \
             `irondivi-cli diag --tx <txid>`, which shows one transaction (such as a coinstake) in clear with its \
             own consent"
        );
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
        let l = call_line(&red, "getblock", &[Value::from(h.clone()), Value::from(1)], false);
        assert_eq!(l, "getblock <block argument dropped> 1");
        let l = call_line(&red, "getblock", &[Value::from(h.to_uppercase()), Value::from(1)], true);
        assert_eq!(l, format!("getblock blk:{h} 1"));
        let l = call_line(&red, "getblockhash", &[Value::from(1234)], true);
        assert_eq!(l, "getblockhash 1234");
        let l = call_line(&red, "getblockhash", &[Value::from(1234)], false);
        assert_eq!(l, "getblockhash <block argument dropped>");
        let l = call_line(&red, "gettransaction", &[Value::from(h.clone())], false);
        assert!(!l.contains(&h), "{l}");
        let l = call_line(&red, "gettxout", &[Value::from("ab".repeat(30))], false);
        assert!(l.contains("<hex:60>"), "{l}");
        let a = "DLhq6dWyzzoLu1WGRKp7SxA7NGLMbeVjWN";
        let l = call_line(&red, "getreceivedbyaddress", &[Value::from(a)], false);
        assert_eq!(l, format!("getreceivedbyaddress {}", red.addresses(a)));
        assert!(l.contains("addr-"), "{l}");
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

    /// A node answering the lookup from fixtures
    struct Fake {
        block: Value,
        prev: Result<Value, String>,
        mine: Vec<&'static str>,
        watch: Vec<&'static str>,
        low: bool,
        asked: Vec<String>,
    }

    impl Ask for Fake {
        fn ask(&mut self, method: &str, params: Value, _t: Duration) -> Result<Value, String> {
            self.asked.push(method.to_string());
            match method {
                "getblock" => {
                    assert_eq!(params[1], 2);
                    Ok(self.block.clone())
                }
                "getrawtransaction" => self.prev.clone(),
                "validateaddress" => {
                    let a = params[0].as_str().unwrap();
                    Ok(serde_json::json!({"isvalid": true, "ismine": self.mine.contains(&a),
                        "iswatchonly": self.watch.contains(&a)}))
                }
                m => panic!("unexpected {m}"),
            }
        }
        fn low_memory(&mut self) -> bool {
            self.low
        }
    }

    const STAKER: &str = "DLhq6dWyzzoLu1WGRKp7SxA7NGLMbeVjWN";
    const OWNER: &str = "DPhJsztbZafDc1YeyrRqSjmKjkmLJpQpUn";

    fn pos_block() -> Value {
        serde_json::json!({"hash": "11".repeat(32), "height": 100, "tx": [
            {"txid": "22".repeat(32), "vin": [{"coinbase": "0164", "sequence": 0}],
             "vout": [{"value": 0.0, "valueSat": 0, "n": 0, "scriptPubKey": {"asm": "", "hex": "", "type": "nonstandard"}}]},
            {"txid": "33".repeat(32), "vin": [{"txid": "44".repeat(32), "vout": 1, "scriptSig": {"asm": "", "hex": ""}, "sequence": 0}],
             "vout": [{"value": 0.0, "valueSat": 0, "n": 0, "scriptPubKey": {"asm": "", "hex": "", "type": "nonstandard"}},
                      {"value": 1000.0, "valueSat": 100000000000i64, "n": 1, "scriptPubKey": {"type": "pubkeyhash", "addresses": [STAKER]}}]}
        ]})
    }

    fn prev(typ: &str, addrs: &[&str]) -> Value {
        serde_json::json!({"vout": [
            {"n": 0, "scriptPubKey": {"type": "pubkeyhash", "addresses": [OWNER]}},
            {"n": 1, "scriptPubKey": {"type": typ, "addresses": addrs}}
        ]})
    }

    fn fake(prev: Result<Value, String>) -> Fake {
        Fake { block: pos_block(), prev, mine: vec![], watch: vec![], low: false, asked: vec![] }
    }

    fn run(f: &mut Fake) -> BlockDecision {
        decide(f, &"11".repeat(32), Duration::from_secs(60))
    }

    #[test]
    fn lookup_decides_from_the_staked_input_only() {
        use BlockDecision::*;
        // own: the spent output's address is in the wallet (not output 0's)
        let mut f = fake(Ok(prev("pubkeyhash", &[STAKER])));
        f.mine = vec![STAKER];
        assert_eq!(run(&mut f), Own);
        assert_eq!(f.asked, ["getblock", "getrawtransaction", "validateaddress"]);
        // a watched address counts as own
        let mut f = fake(Ok(prev("pubkeyhash", &[STAKER])));
        f.watch = vec![STAKER];
        assert_eq!(run(&mut f), Own);
        // only output 0 (not the staked one) is the wallet's: not own
        let mut f = fake(Ok(prev("pubkeyhash", &[STAKER])));
        f.mine = vec![OWNER];
        assert_eq!(run(&mut f), NotOwn);
        // a vault with either address the wallet's is own; with none, undecided
        let mut f = fake(Ok(prev("vault", &[OWNER, STAKER])));
        f.mine = vec![STAKER];
        assert_eq!(run(&mut f), Own);
        let mut f = fake(Ok(prev("vault", &[OWNER, STAKER])));
        assert!(matches!(run(&mut f), Undecided(w) if w.contains("vault")));
        // nonstandard script, a failed getrawtransaction, low memory: undecided
        let mut f = fake(Ok(prev("nonstandard", &[])));
        assert!(matches!(run(&mut f), Undecided(w) if w.contains("nonstandard")));
        let mut f = fake(Err("No such mempool or blockchain transaction".into()));
        assert!(matches!(run(&mut f), Undecided(w) if w.starts_with("getrawtransaction:")));
        let mut f = fake(Ok(prev("pubkeyhash", &[STAKER])));
        f.low = true;
        assert!(matches!(run(&mut f), Undecided(w) if w.contains("512 MB")));
        assert!(f.asked.is_empty());
        // the run's budget spent: undecided, nothing asked
        let mut f = fake(Ok(prev("pubkeyhash", &[STAKER])));
        f.mine = vec![STAKER];
        assert!(matches!(decide(&mut f, &"11".repeat(32), Duration::ZERO), Undecided(_)));
        assert!(f.asked.is_empty());
    }

    #[test]
    fn a_block_without_a_coinstake_is_not_own() {
        let mut f = fake(Ok(prev("pubkeyhash", &[STAKER])));
        f.mine = vec![STAKER];
        f.block = serde_json::json!({"hash": "11".repeat(32), "tx": [
            {"vin": [{"coinbase": "01"}], "vout": [{"value": 50.0, "n": 0, "scriptPubKey": {"hex": "76a9", "type": "pubkeyhash", "addresses": [STAKER]}}]}]});
        assert_eq!(run(&mut f), BlockDecision::NotOwn);
        assert_eq!(f.asked, ["getblock"]);
    }

    #[test]
    fn y4_reduces_the_whole_run() {
        use BlockDecision::*;
        let mut c = vec![
            (Some(10), Some(NotOwn)),
            (Some(11), Some(Own)),
            (Some(12), Some(NotOwn)),
            (Some(20), Some(NotOwn)),
            (None, None),
            (Some(12), Some(NotOwn)),
        ];
        neighbours(&mut c);
        assert!(matches!(&c[0].1, Some(Undecided(w)) if w.contains("Y4")));
        assert_eq!(c[1].1, Some(Own));
        assert!(matches!(&c[2].1, Some(Undecided(_))));
        assert_eq!(c[3].1, Some(NotOwn));
        assert_eq!(c[4].1, None);
        assert!(matches!(&c[5].1, Some(Undecided(_))));
        // a clear run stays clear
        let mut c = vec![(Some(1), Some(NotOwn)), (Some(2), Some(NotOwn))];
        neighbours(&mut c);
        assert_eq!(c[1].1, Some(NotOwn));
    }

    #[test]
    fn block_answers_by_decision() {
        use crate::rpcjson::treat_block;
        let pubt = |s: &str| pseudonym(b"salt", s);
        let h = "ab".repeat(32);
        let blk = serde_json::json!({"hash": h, "height": 7, "version": 4, "size": 900,
            "previousblockhash": "cd".repeat(32), "nextblockhash": "ef".repeat(32),
            "tx": ["12".repeat(32), {"txid": "34".repeat(32), "vin": []}]});
        let t = treat_block(blk.clone(), "getblock", &BlockDecision::NotOwn, &pubt);
        let s = t.json.to_string();
        assert!(!s.contains(&"cd".repeat(32)) && !s.contains(&"ef".repeat(32)), "{s}");
        assert!(!s.contains(&"12".repeat(32)) && !s.contains(&"34".repeat(32)), "{s}");
        assert_eq!(t.json["tx"][0], pubt(&"12".repeat(32)));
        assert_eq!(t.json["tx"][1], pubt(&"34".repeat(32)));
        assert_eq!(t.json["height"], 7);
        for d in [BlockDecision::Own, BlockDecision::Undecided("x".into())] {
            let t = treat_block(blk.clone(), "getblock", &d, &pubt);
            let s = t.json.to_string();
            assert!(!s.contains(&h) && !s.contains("\"height\""), "{s}");
            assert!(s.contains("\"version\""), "{s}");
        }
        let t = treat_block(Value::from(h.clone()), "getblockhash", &BlockDecision::NotOwn, &pubt);
        assert_eq!(t.json, Value::from(format!("blk:{h}")));
        let t = treat_block(Value::from(h.clone()), "getblockhash", &BlockDecision::Own, &pubt);
        assert_eq!(t.json, Value::Null);
    }
}
