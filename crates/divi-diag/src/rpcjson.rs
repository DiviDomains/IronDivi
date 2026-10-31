// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The JSON layer for RPC answers (docs/plans/diag.md B6.5 "Redaction",
//! "Scripts and raw transactions", "Timing fields, by class"; B6.6
//! "Attached RPC answers"). It runs on the parsed answer, before §6.2
//! ([`crate::redact::Redactor::scrub`]) runs on the text it gives back:
//!
//! - keys dropped in every case: `label`, `account`, `comment`, `to`,
//!   `hdmasterkeyid`, `hdchainid`, and the script and raw-transaction keys
//!   `hex`, `asm`, `redeemScript`, `script`, `scriptSig`, a string
//!   `scriptPubKey` (an object one keeps `type` and `reqSigs`);
//! - the backstop: a run of 40 or more hex characters becomes `<hex:N>`,
//!   except a lone 64-hex run (a txid or hash: §6.2 pseudonymises it) and a
//!   public block hash, which is marked `blk:` so §6.2 keeps it;
//! - the wallet rules, on every object of a wallet or address-scoped
//!   answer and on every **wallet-shaped** object anywhere (`txid` with an
//!   amount key, a timing key or `address`): A11 amount buckets, the
//!   confirmation buckets, heights, times and block references dropped;
//! - the key-name rule on every other object: a number under an amount key
//!   (matched by `_` token) is bucketed, `confirmations` is bucketed, and
//!   `height`, `blockheight`, `time`, `blocktime` and `timereceived` are
//!   dropped; the fields of a shape-confirmed public answer and the `time`
//!   and `timeNano` of a `docker events` line are left alone;
//! - `stakeweight` and `netstakeweight` become one ratio bucket,
//!   `expectedtime` and `txcount` are bucketed;
//! - every block answer (`merkleroot` with `hash`) is reduced to its
//!   version, its size rounded up to a power of two and its transaction
//!   count: diag cannot tell an own staked block from another one here, so
//!   every block is undecided (B6.5 "Undecided is reduced").
//!
//! Every drop and bucket is counted by key path, for the preview.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Dropped in every answer, whatever the label (B6.5, P1)
const ALWAYS_DROP: &[&str] = &[
    "label", "account", "comment", "to", "hdmasterkeyid", "hdchainid", "hex", "asm", "redeemScript", "script",
    "scriptSig",
];
/// Amount tokens of the key-name rule (S1)
const AMOUNT_TOKENS: &[&str] = &[
    "amount", "value", "balance", "fee", "satoshis", "received", "sent", "credit", "debit", "reward", "total", "stake",
];
/// The amount keys that make an object with `txid` wallet-shaped
const WALLET_AMOUNT: &[&str] = &["amount", "value", "fee", "balance", "satoshis", "received"];
const CONF_KEYS: &[&str] = &["confirmations", "bcconfirmations"];
const TIME_KEYS: &[&str] = &["height", "blockheight", "time", "blocktime", "timereceived"];
/// Dropped from wallet-rule objects on top of [`TIME_KEYS`]
const BLOCK_REFS: &[&str] = &["blockhash", "blockindex", "spentHeight", "previousblockhash", "nextblockhash"];

/// Wallet and address-scoped methods: the wallet rules apply to every object
pub const WALLET_METHODS: &[&str] = &[
    "listunspent", "listtransactions", "listsinceblock", "gettransaction", "getwalletinfo", "getbalance",
    "getunconfirmedbalance", "getmintinginfo", "getstakingstatus", "getreceivedbyaddress", "listreceivedbyaddress",
    "getaddressbalance", "getaddressutxos", "listlockunspent", "getstakesplitthreshold",
];

/// A public method diag knows the shape of: (method, keys always there,
/// keys it may add). A label naming it is honoured only on a strict match.
const PUBLIC_SHAPES: &[(&str, &[&str], &[&str])] = &[
    (
        "gettxoutsetinfo",
        &["height", "bestblock", "transactions", "txouts", "bogosize", "bytes_serialized", "hash_serialized", "total_amount"],
        &[],
    ),
    (
        "getblockchaininfo",
        &["chain", "blocks", "headers", "bestblockhash", "difficulty", "mediantime", "chainwork"],
        &[
            "pruned", "pruneheight", "winnersstripheight", "fullhistorypeers", "lastblockfetch", "snapshotbase", "warnings",
            "verificationprogress", "initialblockdownload", "size_on_disk", "softforks", "bip9_softforks",
        ],
    ),
];
/// Public block hashes in a shape-confirmed public answer (kept, `blk:`)
const PUBLIC_BLOCK_HASH_KEYS: &[&str] = &["bestblock", "bestblockhash", "hash"];

/// Public methods known by name only (no shape check is possible): the label
/// is not honoured as public, the file is treated as of unknown origin
const PUBLIC_NAMES: &[&str] = &[
    "getblock", "getblockheader", "getblockhash", "getblockcount", "getbestblockhash", "getdifficulty",
    "getnetworkinfo", "getpeerinfo", "getconnectioncount", "getnettotals", "getmempoolinfo", "getrawmempool",
    "getchaintips", "getinfo", "mnsync", "getmasternodecount", "getmasternodewinners", "getspork", "gettxout",
    "getrawtransaction", "getdiaginfo", "uptime",
];

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Treated {
    pub json: Value,
    /// the preview line: "treated as RPC output: <method>" or the unknown-origin line
    pub treatment: String,
    /// key path -> what happened ("dropped", "bucketed", ...) -> count
    pub actions: BTreeMap<String, usize>,
}

impl Treated {
    /// One line per key path, for the preview
    pub fn action_lines(&self) -> Vec<String> {
        self.actions.iter().map(|(k, n)| if *n > 1 { format!("{k} (x{n})") } else { k.clone() }).collect()
    }
}

/// The JSON-RPC envelope `{"result": …, "error": …, "id": …}` is removed
pub fn unwrap_envelope(v: Value) -> Value {
    if let Value::Object(m) = &v {
        if m.contains_key("result") && m.keys().all(|k| matches!(k.as_str(), "result" | "error" | "id" | "jsonrpc")) {
            if let Value::Object(mut m) = v {
                return m.remove("result").unwrap_or(Value::Null);
            }
        }
    }
    v
}

fn has_all(m: &Map<String, Value>, ks: &[&str]) -> bool {
    ks.iter().all(|k| m.contains_key(*k))
}

/// The method an answer's shape names, if any (B6.6)
pub fn shape(v: &Value) -> Option<&'static str> {
    for (name, always, may) in PUBLIC_SHAPES {
        if let Some(m) = v.as_object() {
            if has_all(m, always) && m.keys().all(|k| always.contains(&k.as_str()) || may.contains(&k.as_str())) {
                return Some(name);
            }
        }
    }
    let utxo = |e: &Value| e.as_object().is_some_and(|m| has_all(m, &["address", "txid", "outputIndex", "satoshis", "height"]));
    match v {
        Value::Object(m) => {
            if has_all(m, &["balance", "received"]) && m.len() <= 4 {
                return Some("getaddressbalance");
            }
            if m.get("utxos").and_then(Value::as_array).is_some_and(|a| a.iter().all(utxo)) && has_all(m, &["hash", "height"]) {
                return Some("getaddressutxos");
            }
            if has_all(m, &["transactions", "lastblock"]) {
                return Some("listsinceblock");
            }
            if has_all(m, &["txid", "details"]) {
                return Some("gettransaction");
            }
            if has_all(m, &["walletversion", "balance", "txcount"]) {
                return Some("getwalletinfo");
            }
            if has_all(m, &["currentblocksize", "pooledtx", "stakeweight", "netstakeweight"]) {
                return Some("getmintinginfo");
            }
            None
        }
        Value::Array(a) if !a.is_empty() => {
            if a.iter().all(utxo) {
                return Some("getaddressutxos");
            }
            let all = |ks: &[&str]| a.iter().all(|e| e.as_object().is_some_and(|m| has_all(m, ks)));
            if all(&["txid", "vout", "amount", "confirmations", "spendable"]) {
                return Some("listunspent");
            }
            if all(&["txid", "category", "amount", "confirmations"]) {
                return Some("listtransactions");
            }
            None
        }
        _ => None,
    }
}

fn is_public_shape(m: &str) -> bool {
    PUBLIC_SHAPES.iter().any(|(n, _, _)| *n == m)
}

/// `docker events` / `podman events` JSON line (P4)
pub fn is_docker_event(v: &Value) -> bool {
    v.as_object().is_some_and(|m| has_all(m, &["Type", "Action", "Actor"]) || has_all(m, &["status", "id", "from"]))
}

/// A11 magnitude of an amount in satoshis
pub fn amount_bucket(sats: i64) -> String {
    if sats == 0 {
        return "amt-0".into();
    }
    let sign = if sats < 0 { "-" } else { "" };
    format!("amt-{sign}1e{}", sats.unsigned_abs().ilog10())
}

/// A11 magnitude of a count
fn count_bucket(n: u64) -> String {
    if n == 0 {
        "count-0".into()
    } else {
        format!("count-1e{}", n.ilog10())
    }
}

/// B6.5 confirmation classes; -1 is never folded into 0 (E1)
pub fn conf_bucket(n: i64) -> &'static str {
    match n {
        i64::MIN..=-1 => "conf--1",
        0 => "conf-0",
        1..=5 => "conf-1-5",
        6..=100 => "conf-6-100",
        _ => "conf->100",
    }
}

fn ratio_bucket(r: f64) -> &'static str {
    if r < 0.0001 {
        "stake-share-<0.01%"
    } else if r < 0.001 {
        "stake-share-0.01-0.1%"
    } else if r < 0.01 {
        "stake-share-0.1-1%"
    } else {
        "stake-share->1%"
    }
}

fn expected_bucket(secs: f64) -> &'static str {
    let d = secs / 86400.0;
    if d < 1.0 {
        "expected-<1d"
    } else if d < 7.0 {
        "expected-1-7d"
    } else if d < 30.0 {
        "expected-7-30d"
    } else {
        "expected->30d"
    }
}

fn is_amount_key(k: &str) -> bool {
    k.split('_').any(|t| AMOUNT_TOKENS.iter().any(|a| t.eq_ignore_ascii_case(a)))
}

/// `satoshis` holds satoshis; every other amount key holds DIVI
fn to_sats(k: &str, n: f64) -> i64 {
    if k.eq_ignore_ascii_case("satoshis") {
        n as i64
    } else {
        (n * 1e8).round() as i64
    }
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// The ≥40-hex backstop on one string (keys and values)
pub fn backstop(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if is_hex(b[i]) {
            let start = i;
            while i < b.len() && is_hex(b[i]) {
                i += 1;
            }
            let n = i - start;
            if n >= 40 && n != 64 {
                out.push_str(&format!("<hex:{n}>"));
            } else {
                out.push_str(&s[start..i]);
            }
        } else {
            let c = s[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(is_hex)
}

struct Walk {
    actions: BTreeMap<String, usize>,
}

impl Walk {
    fn note(&mut self, path: &str, what: &str) {
        let path = if path.is_empty() { "(answer)" } else { path };
        *self.actions.entry(format!("{what}: {path}")).or_default() += 1;
    }

    fn wallet_shaped(m: &Map<String, Value>) -> bool {
        m.contains_key("txid")
            && (WALLET_AMOUNT.iter().any(|k| m.contains_key(*k))
                || CONF_KEYS.iter().chain(TIME_KEYS).any(|k| m.contains_key(*k))
                || m.contains_key("address"))
    }

    fn is_block(m: &Map<String, Value>) -> bool {
        m.contains_key("merkleroot") && m.contains_key("hash")
    }

    /// B6.5 "Undecided is reduced": version, size to the next power of two, nTx
    fn reduce_block(&mut self, m: &Map<String, Value>, path: &str) -> Value {
        self.reduce_block_why(m, path, "own staked block undecided")
    }

    fn reduce_block_why(&mut self, m: &Map<String, Value>, path: &str, why: &str) -> Value {
        let mut out = Map::new();
        if let Some(v) = m.get("version") {
            out.insert("version".into(), v.clone());
        }
        if let Some(s) = m.get("size").and_then(Value::as_u64) {
            out.insert("size_at_most".into(), Value::from(s.max(1).next_power_of_two()));
        }
        let ntx = m.get("nTx").and_then(Value::as_u64).or_else(|| m.get("tx").and_then(Value::as_array).map(|a| a.len() as u64));
        if let Some(n) = ntx {
            out.insert("nTx".into(), Value::from(n));
        }
        self.note(path, &format!("block answer reduced to version, size and nTx ({why})"));
        Value::Object(out)
    }

    /// `wallet`: the wallet rules apply (wallet method or wallet-shaped
    /// ancestor); `public`: inside a shape-confirmed public answer;
    /// `docker`: the top level of a docker events line
    fn value(&mut self, v: Value, path: &str, wallet: bool, public: bool, docker: bool) -> Value {
        match v {
            Value::Object(m) => self.object(m, path, wallet, public, docker),
            Value::Array(a) => {
                let p = format!("{path}[]");
                Value::Array(a.into_iter().map(|e| self.value(e, &p, wallet, public, false)).collect())
            }
            Value::String(s) => Value::String(backstop(&s)),
            other => other,
        }
    }

    fn object(&mut self, m: Map<String, Value>, path: &str, wallet: bool, public: bool, docker: bool) -> Value {
        if Self::is_block(&m) && !public {
            return self.reduce_block(&m, path);
        }
        let wallet = wallet || Self::wallet_shaped(&m);
        // getmintinginfo: one ratio bucket from both weights, or neither
        let ratio = match (m.get("stakeweight"), m.get("netstakeweight").and_then(Value::as_f64)) {
            (Some(sw), Some(net)) if net > 0.0 => {
                let own = sw.as_f64().or_else(|| sw.get("combined").and_then(Value::as_f64));
                own.map(|o| ratio_bucket(o / net))
            }
            _ => None,
        };
        let mut out = Map::new();
        for (k, v) in m {
            let kp = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
            if ALWAYS_DROP.contains(&k.as_str()) {
                self.note(&kp, "dropped");
                continue;
            }
            if k == "scriptPubKey" {
                match v {
                    Value::Object(sm) => {
                        let mut keep = Map::new();
                        for t in ["type", "reqSigs"] {
                            if let Some(x) = sm.get(t) {
                                keep.insert(t.into(), x.clone());
                            }
                        }
                        self.note(&kp, "reduced to type and reqSigs");
                        out.insert(k, Value::Object(keep));
                    }
                    _ => self.note(&kp, "dropped"),
                }
                continue;
            }
            if public {
                let v = match v {
                    Value::String(s) if PUBLIC_BLOCK_HASH_KEYS.contains(&k.as_str()) && is_hex64(&s) => {
                        Value::String(format!("blk:{s}"))
                    }
                    Value::String(s) if k == "hash_serialized" && is_hex64(&s) => Value::String(format!("sha256:{s}")),
                    other => self.value(other, &kp, false, true, false),
                };
                out.insert(backstop(&k), v);
                continue;
            }
            if k == "stakeweight" || k == "netstakeweight" {
                match ratio {
                    Some(b) if k == "stakeweight" => {
                        self.note(&kp, "with netstakeweight: one ratio bucket");
                        out.insert("stake_share".into(), Value::from(b));
                    }
                    Some(_) => {}
                    None => self.note(&kp, "dropped (no ratio)"),
                }
                continue;
            }
            if k == "expectedtime" {
                if let Some(n) = v.as_f64() {
                    self.note(&kp, "bucketed");
                    out.insert(k, Value::from(expected_bucket(n)));
                } else {
                    self.note(&kp, "dropped");
                }
                continue;
            }
            if k == "txcount" {
                if let Some(n) = v.as_u64() {
                    self.note(&kp, "bucketed");
                    out.insert(k, Value::from(count_bucket(n)));
                    continue;
                }
            }
            // an address is masked here too, not only by §6.2's address check
            if k == "address" || k == "addresses" {
                let nv = match v {
                    Value::String(s) if s.starts_with("pub-") || is_addr_pseudonym(&s) => Value::String(s),
                    Value::String(_) => {
                        self.note(&kp, "masked");
                        Value::from("<addr>")
                    }
                    Value::Array(a)
                        if a.iter().all(|x| x.as_str().is_some_and(|s| s.starts_with("pub-") || is_addr_pseudonym(s))) =>
                    {
                        Value::Array(a)
                    }
                    Value::Array(a) if a.iter().all(Value::is_string) => {
                        self.note(&kp, "masked");
                        Value::Array(a.iter().map(|_| Value::from("<addr>")).collect())
                    }
                    other => self.value(other, &kp, wallet, false, false),
                };
                out.insert(k, nv);
                continue;
            }
            let docker_time = docker && (k == "time" || k == "timeNano");
            if !docker_time && (TIME_KEYS.contains(&k.as_str()) || (wallet && BLOCK_REFS.contains(&k.as_str()))) {
                self.note(&kp, "dropped");
                continue;
            }
            if CONF_KEYS.contains(&k.as_str()) {
                if let Some(n) = v.as_i64() {
                    self.note(&kp, "bucketed");
                    out.insert(k, Value::from(conf_bucket(n)));
                    continue;
                }
            }
            if is_amount_key(&k) {
                if let Some(n) = v.as_f64() {
                    self.note(&kp, "bucketed (A11)");
                    out.insert(k.clone(), Value::from(amount_bucket(to_sats(&k, n))));
                    continue;
                }
            }
            let nv = self.value(v, &kp, wallet, false, false);
            out.insert(backstop(&k), nv);
        }
        Value::Object(out)
    }
}

/// The treatment of one parsed answer. `label` is `--attach-method`.
pub fn treat(v: Value, label: Option<&str>) -> Treated {
    let v = unwrap_envelope(v);
    let found = shape(&v);
    let mut lead = String::new();
    let method: Option<String> = match label {
        Some(l) if WALLET_METHODS.contains(&l) => Some(l.to_string()),
        Some(l) if is_public_shape(l) && found == Some(l) => Some(l.to_string()),
        Some(l) => {
            if is_public_shape(l) || PUBLIC_NAMES.contains(&l) {
                lead = format!("label `{l}` does not match the file's shape; ");
            } else {
                lead = format!("label `{l}` is not a method diag knows; ");
            }
            found.map(str::to_string)
        }
        None => found.map(str::to_string),
    };
    let mut w = Walk { actions: BTreeMap::new() };
    let (json, treatment) = match method.as_deref() {
        Some(m) if is_public_shape(m) => (w.value(v, "", false, true, false), format!("{lead}treated as RPC output: {m}")),
        Some(m) => {
            // a bare number (getbalance) is an amount
            let v = match v {
                Value::Number(n) => {
                    w.note("(answer)", "bucketed (A11)");
                    Value::from(amount_bucket(to_sats("amount", n.as_f64().unwrap_or(0.0))))
                }
                other => w.value(other, "", true, false, false),
            };
            (v, format!("{lead}treated as RPC output: {m}"))
        }
        None => {
            let docker = is_docker_event(&v);
            let v = w.value(v, "", false, false, docker);
            let t = if docker {
                "docker events line; script keys and hash backstop applied".to_string()
            } else {
                format!(
                    "{lead}JSON of unknown origin; script keys and hash backstop applied (if it is an RPC answer: \
                     irondivi-cli diag --attach <file> --attach-method <method>)"
                )
            };
            (v, t)
        }
    };
    Treated { json, treatment, actions: w.actions }
}

/// The treatment of the node's own answer to a `--rpc` call (B6.5): the
/// method is known, so there is no label to distrust. Wallet methods get
/// the wallet rules (a bare number is an A11 bucket), a public shape the
/// public rules when the answer has that shape, everything else the
/// key-name rule, where a block answer is reduced (every block is
/// undecided here). The `getblockhash` answer, the hash itself, is
/// dropped whole.
pub fn treat_call(v: Value, method: &str) -> Treated {
    let mut w = Walk { actions: BTreeMap::new() };
    let treatment = format!("RPC answer: {method}");
    if method == "getblockhash" {
        w.note("(answer)", "dropped (the block hash names the block; own staked block undecided)");
        return Treated { json: Value::Null, treatment, actions: w.actions };
    }
    let wallet = WALLET_METHODS.contains(&method) || method == "getcoinavailability";
    let json = if wallet {
        match v {
            Value::Number(n) => {
                w.note("(answer)", "bucketed (A11)");
                Value::from(amount_bucket(to_sats("amount", n.as_f64().unwrap_or(0.0))))
            }
            other => w.value(other, "", true, false, false),
        }
    } else if is_public_shape(method) && shape(&v) == Some(method) {
        w.value(v, "", false, true, false)
    } else {
        w.value(v, "", false, false, false)
    };
    Treated { json, treatment, actions: w.actions }
}

/// `addr-<4 hex>`: an address the --rpc collector already replaced by its
/// own pseudonym ([`crate::redact::Redactor::addresses`])
fn is_addr_pseudonym(s: &str) -> bool {
    s.strip_prefix("addr-").is_some_and(|h| h.len() == 4 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Whose block a block answer is about (B6.5 "Own staked blocks")
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockDecision {
    /// the coinstake's staked input pays an address of this wallet
    Own,
    /// decided not this wallet's: a public record
    NotOwn,
    /// could not be decided (the reason); reduced like an own block
    Undecided(String),
}

/// The treatment of a block answer (`getblock`, `getblockheader`,
/// `getblockhash`) once the block is decided. Own and undecided: only
/// version, size class and nTx, and the getblockhash answer dropped whole.
/// Not own: a public record, except `previousblockhash` and
/// `nextblockhash`, dropped from every block (S4), and each txid replaced
/// by `public_txid` (its public-record pseudonym; at verbosity 2 a
/// transaction entry is reduced to that pseudonym).
pub fn treat_block(v: Value, method: &str, d: &BlockDecision, public_txid: &dyn Fn(&str) -> String) -> Treated {
    let mut w = Walk { actions: BTreeMap::new() };
    let treatment = format!("RPC answer: {method}");
    let why = match d {
        BlockDecision::Own => "staked by this wallet".to_string(),
        BlockDecision::Undecided(r) => format!("could not be checked against the wallet: {r}"),
        BlockDecision::NotOwn => String::new(),
    };
    if method == "getblockhash" {
        let json = match (d, v) {
            (BlockDecision::NotOwn, Value::String(h)) if is_hex64(&h) => Value::String(format!("blk:{h}")),
            _ => {
                let why = if why.is_empty() { "not a block hash".to_string() } else { why };
                w.note("(answer)", &format!("dropped (the block hash names the block; {why})"));
                Value::Null
            }
        };
        return Treated { json, treatment, actions: w.actions };
    }
    let json = match (d, v) {
        (BlockDecision::NotOwn, Value::Object(mut m)) => {
            for k in ["previousblockhash", "nextblockhash"] {
                if m.remove(k).is_some() {
                    w.note(k, "dropped from every block (S4)");
                }
            }
            let tx = m.remove("tx");
            let mut out = w.object(m, "", false, true, false);
            if let (Some(Value::Array(a)), Value::Object(o)) = (tx, &mut out) {
                let n = a.len();
                let ids: Vec<Value> = a
                    .into_iter()
                    .map(|t| {
                        let id = match &t {
                            Value::String(s) => Some(s.clone()),
                            Value::Object(e) => e.get("txid").and_then(Value::as_str).map(str::to_string),
                            _ => None,
                        };
                        match id {
                            Some(s) if is_hex64(&s) => Value::from(public_txid(&s.to_ascii_lowercase())),
                            _ => Value::from("<dropped>"),
                        }
                    })
                    .collect();
                for _ in 0..n {
                    w.note("tx[]", "each txid pseudonymised under the public-record salt");
                }
                o.insert("tx".into(), Value::Array(ids));
            }
            out
        }
        (_, Value::Object(m)) if !matches!(d, BlockDecision::NotOwn) => w.reduce_block_why(&m, "", &why),
        (_, other) => w.value(other, "", false, false, false),
    };
    Treated { json, treatment, actions: w.actions }
}

/// Parse an attached file as JSON: one document, or JSON lines (every
/// non-empty line an object or array). `None` when it is not JSON.
pub fn parse(data: &[u8]) -> Option<Vec<Value>> {
    let text = std::str::from_utf8(data).ok()?;
    if text.trim().is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return match v {
            Value::Object(_) | Value::Array(_) | Value::Number(_) => Some(vec![v]),
            _ => None,
        };
    }
    let mut out = Vec::new();
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<Value>(l) {
            Ok(v @ (Value::Object(_) | Value::Array(_))) => out.push(v),
            _ => return None,
        }
    }
    Some(out)
}

/// Treat a parsed file (one document or JSON lines); returns the text to
/// scrub, the preview line and the actions
pub fn treat_file(docs: Vec<Value>, label: Option<&str>) -> (String, String, Vec<String>) {
    let lines = docs.len() > 1;
    let mut text = String::new();
    let mut treatment = String::new();
    let mut actions: BTreeMap<String, usize> = BTreeMap::new();
    for d in docs {
        let t = treat(d, label);
        if lines {
            text.push_str(&serde_json::to_string(&t.json).unwrap_or_default());
        } else {
            text.push_str(&serde_json::to_string_pretty(&t.json).unwrap_or_default());
        }
        text.push('\n');
        if treatment.is_empty() {
            treatment = t.treatment;
        }
        for (k, n) in t.actions {
            *actions.entry(k).or_default() += n;
        }
    }
    let t = Treated { actions, ..Default::default() };
    (text, treatment, t.action_lines())
}

#[cfg(test)]
mod treat_call_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn call_answers() {
        let t = treat_call(json!(1234.5), "getbalance");
        assert!(t.json.is_string() || t.json.is_number());
        assert_ne!(t.json, json!(1234.5));
        let t = treat_call(json!("ab".repeat(32)), "getblockhash");
        assert_eq!(t.json, Value::Null);
        let h = "cd".repeat(32);
        let blk = json!({"hash": h, "merkleroot": h, "version": 4, "size": 300, "tx": [h, h], "height": 5});
        let t = treat_call(blk, "getblock");
        assert_eq!(t.json, json!({"version": 4, "size_at_most": 512, "nTx": 2}));
        let t = treat_call(json!([{"address": "pub-0123456789ab", "x": 1}]), "getmasternodewinners");
        assert_eq!(t.json[0]["address"], "pub-0123456789ab");
        assert_eq!(t.treatment, "RPC answer: getmasternodewinners");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TXID: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
    const BLK: &str = "00000bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb2";

    #[test]
    fn buckets() {
        assert_eq!(amount_bucket(0), "amt-0");
        assert_eq!(amount_bucket(123_456_789), "amt-1e8");
        assert_eq!(amount_bucket(-5), "amt--1e0");
        assert_eq!(conf_bucket(-1), "conf--1");
        assert_eq!(conf_bucket(0), "conf-0");
        assert_eq!(conf_bucket(101), "conf->100");
        assert!(is_amount_key("unconfirmed_balance") && is_amount_key("total_amount") && is_amount_key("Stake_count"));
        assert!(!is_amount_key("stakeweight") && !is_amount_key("pid"));
    }

    #[test]
    fn backstop_masks_long_hex_but_not_64() {
        let h160 = "76a914".to_string() + &"ab".repeat(20) + "88ac";
        assert_eq!(backstop(&h160), "<hex:50>");
        assert_eq!(backstop(TXID), TXID);
        assert_eq!(backstop(&format!("x {} y", "c".repeat(40))), "x <hex:40> y");
        assert_eq!(backstop(&"d".repeat(39)), "d".repeat(39));
    }

    #[test]
    fn listunspent_is_recognised_and_reduced() {
        let v = json!([{"txid": TXID, "vout": 1, "address": "DPx", "account": "savings", "scriptPubKey": "76a914abab",
            "redeemScript": "5221", "amount": 12.5, "confirmations": 3, "spendable": true, "solvable": true, "ischange": false}]);
        let t = treat(v, None);
        assert_eq!(t.treatment, "treated as RPC output: listunspent");
        let e = &t.json[0];
        assert!(e.get("account").is_none() && e.get("scriptPubKey").is_none() && e.get("redeemScript").is_none());
        assert_eq!(e["amount"], "amt-1e9");
        assert_eq!(e["confirmations"], "conf-1-5");
        assert_eq!(e["txid"], TXID);
        assert_eq!(e["address"], "<addr>");
    }

    #[test]
    fn wallet_shaped_object_in_unknown_json_and_key_name_rule() {
        let v = json!({"pid": 77, "time": 1_700_000_000, "port": 51472, "unconfirmed_balance": 1.0,
            "inner": {"txid": TXID, "blockhash": BLK, "blockindex": 2, "value": 0.5, "comment": "rent"}});
        let t = treat(v, None);
        assert!(t.treatment.starts_with("JSON of unknown origin; script keys and hash backstop applied"));
        assert_eq!(t.json["pid"], 77);
        assert_eq!(t.json["port"], 51472);
        assert!(t.json.get("time").is_none());
        assert_eq!(t.json["unconfirmed_balance"], "amt-1e8");
        let i = &t.json["inner"];
        assert!(i.get("blockhash").is_none() && i.get("blockindex").is_none() && i.get("comment").is_none());
        assert_eq!(i["value"], "amt-1e7");
        assert!(t.action_lines().iter().any(|l| l == "dropped: time"));
    }

    #[test]
    fn gettxoutsetinfo_stays_clear_only_on_its_shape() {
        let v = json!({"height": 900, "bestblock": BLK, "transactions": 5, "txouts": 9, "bogosize": 1,
            "bytes_serialized": 2, "hash_serialized": TXID, "total_amount": 1000.0});
        let t = treat(v.clone(), Some("gettxoutsetinfo"));
        assert_eq!(t.treatment, "treated as RPC output: gettxoutsetinfo");
        assert_eq!(t.json["height"], 900);
        assert_eq!(t.json["total_amount"], 1000.0);
        assert_eq!(t.json["bestblock"], format!("blk:{BLK}"));
        // one key more: the label is ignored and the key-name rule applies
        let mut w = v;
        w["extra"] = json!(1);
        let t = treat(w, Some("gettxoutsetinfo"));
        assert!(t.treatment.starts_with("label `gettxoutsetinfo` does not match the file's shape; JSON of unknown origin"));
        assert!(t.json.get("height").is_none());
        assert_eq!(t.json["total_amount"], "amt-1e11");
    }

    #[test]
    fn wallet_label_always_adds_rules() {
        let t = treat(json!({"walletversion": 1, "balance": 3.0, "unconfirmed_balance": 0, "immature_balance": 0,
            "txcount": 1234, "keypoolsize": 1000, "hdmasterkeyid": "ab"}), Some("getwalletinfo"));
        assert_eq!(t.json["balance"], "amt-1e8");
        assert_eq!(t.json["txcount"], "count-1e3");
        assert!(t.json.get("hdmasterkeyid").is_none());
        let t = treat(json!(42.5), Some("getbalance"));
        assert_eq!(t.json, json!("amt-1e9"));
    }

    #[test]
    fn mintinginfo_ratio_and_expected_time() {
        let t = treat(json!({"blocks": 5, "currentblocksize": 0, "currentblocktx": 0, "pooledtx": 0,
            "stakeweight": {"minimum": 1, "maximum": 2, "combined": 50}, "netstakeweight": 10000, "expectedtime": 200000}), None);
        assert_eq!(t.treatment, "treated as RPC output: getmintinginfo");
        assert_eq!(t.json["stake_share"], "stake-share-0.1-1%");
        assert!(t.json.get("stakeweight").is_none() && t.json.get("netstakeweight").is_none());
        assert_eq!(t.json["expectedtime"], "expected-1-7d");
    }

    #[test]
    fn blocks_are_reduced_and_envelopes_removed() {
        let t = treat(json!({"result": {"hash": BLK, "merkleroot": TXID, "height": 7, "version": 4, "size": 300,
            "tx": [TXID, TXID], "time": 1}, "error": null, "id": 1}), Some("getblock"));
        assert!(t.treatment.starts_with("label `getblock` does not match"));
        assert_eq!(t.json, json!({"version": 4, "size_at_most": 512, "nTx": 2}));
    }

    #[test]
    fn docker_events_keep_time() {
        let docs = parse(b"{\"Type\":\"container\",\"Action\":\"die\",\"Actor\":{\"ID\":\"x\"},\"time\":5,\"timeNano\":6}\n{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{},\"time\":7}\n").unwrap();
        assert_eq!(docs.len(), 2);
        let (text, treatment, _) = treat_file(docs, None);
        assert!(treatment.starts_with("docker events line"));
        assert!(text.contains("\"time\":5") && text.contains("\"timeNano\":6"));
        assert!(parse(b"not json\n").is_none());
    }
}
