// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! §6.2 step 2 "Old-log lines": the one filter every copy of node or
//! component log output goes through before it is packaged, whatever the
//! node's version.
//!
//! - (a) a 64-hex string that is not a public block hash is pseudonymised
//!   (here and again by the parent's scrub);
//! - (b) a line from a wallet-bearing module keeps its timestamp, level,
//!   module and the plain words of its message; every argument is masked by
//!   kind. The code's format strings are not available to diag, so the
//!   words are told from the arguments by their shape (a word of letters is
//!   kept, anything else is masked);
//! - every `divi_node::staker` line is removed and counted (the A11 staker
//!   allowlist does not exist yet: removing all of them is the safe reading);
//! - (c) an amount (`… sats`, `… sat`, `… DIVI`) is masked in every other
//!   line, (d) everything after `=` in `Invalid -k=v` is dropped;
//! - (e) per-block lines are removed and counted, weekly, bucketed 0, 1–3,
//!   4–20, >20; failure-only lines daily. Every log is treated as an older
//!   log (the §6.2 default).
//!
//! Lines in the JSON form (divi-swapd logs tracing JSON to stdout) keep
//! their timestamp, level, target and message only, then go through the
//! same rules.

use crate::redact::Redactor;
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The modules whose lines carry wallet data (§6.2 (b), from the A11 edit
/// sites)
const WALLET_MODULES: &[&str] =
    &["divi_wallet", "divi_node::staker", "divi_node::mempool", "divi_rpc", "divi_electrum", "divi_swap", "irondivid::core_files"];

/// §6.2 (e): per-block formats, matched on their fixed start
const PER_BLOCK: &[&str] = &[
    "Received block",
    "Ignoring block",
    "Block message received",
    "Connected block",
    "Connected orphan block",
    "Chain reorganized!",
    "Accepted block",
    "Broadcast block inv",
    "Relayed block inv",
    "Activating stored block",
    "try_activate_block: Successfully activated block",
    "Self-accepted block",
    "Block sync complete",
    "Sync progress",
    "Sync stalled",
    "runCommand error",
];

/// Matched anywhere in the message (the hash or height comes first)
const PER_BLOCK_INNER: &[(&str, &str, &str)] = &[
    ("Block ", " reorganised the chain", "Block … reorganised the chain"),
    ("Block ", " processed", "Block … at height … processed"),
];

/// Failure-only lines: counted per day (§6.2 (e))
const FAILURE_ONLY: &[&str] = &[
    "Dropped invalid block",
    "Staking error",
    "Failed to compute next difficulty",
    "Failed to create stake block",
    "Failed to sign",
];

#[derive(Default, Debug)]
pub struct Filtered {
    /// The lines kept, each ending in a newline
    pub text: String,
    /// (period, what) → count; period is "week of D" or "day D"
    pub counts: BTreeMap<(String, String), u64>,
    pub removed: u64,
    pub masked: u64,
}

impl Filtered {
    /// The kept text followed by the bucketed counts of the removed lines
    pub fn render(&self) -> String {
        let mut s = self.text.clone();
        if !self.counts.is_empty() {
            s.push_str(&format!(
                "[§6.2 old-log lines: {} per-block, staker and failure-only lines removed from this copy; counts per period, bucketed 0, 1-3, 4-20, >20]\n",
                self.removed
            ));
            for ((period, what), n) in &self.counts {
                s.push_str(&format!("[{period}: {what}: {}]\n", bucket(*n)));
            }
        }
        s
    }
}

pub fn bucket(n: u64) -> &'static str {
    match n {
        0 => "0",
        1..=3 => "1-3",
        4..=20 => "4-20",
        _ => ">20",
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn date_of(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = ts.get(0..4)?.parse().ok()?;
    let m: i64 = ts.get(5..7)?.parse().ok()?;
    let d: i64 = ts.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

fn fmt_day(z: i64) -> String {
    let (y, m, d) = civil_from_days(z);
    format!("{y:04}-{m:02}-{d:02}")
}

/// "week of <Monday>" / "day <date>"; "undated" when the line has no date
pub fn period(ts: &str, daily: bool) -> String {
    match date_of(ts) {
        None => "undated".into(),
        Some(z) if daily => format!("day {}", fmt_day(z)),
        Some(z) => {
            // 1970-01-01 was a Thursday (weekday 3 counting Monday as 0)
            let wd = (z + 3).rem_euclid(7);
            format!("week of {}", fmt_day(z - wd))
        }
    }
}

/// One parsed line: timestamp, level, target, message
struct Line<'a> {
    ts: &'a str,
    level: &'a str,
    target: &'a str,
    msg: &'a str,
}

const LEVELS: &[&str] = &["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];

fn strip_ansi(l: &str) -> std::borrow::Cow<'_, str> {
    if !l.contains('\x1b') {
        return l.into();
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").unwrap()).replace_all(l, "")
}

/// `TIMESTAMP  LEVEL target: message` (tracing's default format; spans
/// such as `irondivid{…}:` may sit before the target)
fn parse(l: &str) -> Option<Line<'_>> {
    let l = l.trim_start();
    let (ts, rest) = l.split_once(char::is_whitespace)?;
    date_of(ts)?;
    let rest = rest.trim_start();
    let (level, rest) = rest.split_once(char::is_whitespace)?;
    if !LEVELS.contains(&level) {
        return None;
    }
    let rest = rest.trim_start();
    // the target is the last `word:` before the message that looks like a
    // module path
    let mut off = 0;
    let mut found: Option<(usize, usize)> = None;
    for w in rest.split_inclusive(' ') {
        let t = w.trim_end();
        if let Some(name) = t.strip_suffix(':') {
            let name = name.rsplit(':').next().filter(|_| !name.contains('{')).map(|_| name).unwrap_or(name);
            let clean = name.rsplit_once("}:").map(|x| x.1).unwrap_or(name);
            if !clean.is_empty() && clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') {
                found = Some((off + (name.len() - clean.len()), off + t.len()));
                break;
            }
        }
        if !(t.contains('{') || t.ends_with(':')) {
            break;
        }
        off += w.len();
    }
    let (a, b) = found?;
    Some(Line { ts, level, target: &rest[a..b - 1], msg: rest[b..].trim_start() })
}

/// The module target of a log line, plain or tracing-JSON
pub fn target_of(l: &str) -> Option<&str> {
    if let Some(p) = parse(l) {
        return Some(p.target);
    }
    let t = l.trim();
    if t.starts_with('{') {
        // `"target":"x"` without a full parse: the line borrows from `l`
        let i = t.find("\"target\":\"")? + 10;
        let e = t[i..].find('"')?;
        return Some(&t[i..i + e]);
    }
    None
}

/// A tracing-JSON line: `{"timestamp":…,"level":…,"fields":{"message":…},"target":…}`
fn parse_json(l: &str) -> Option<(String, String)> {
    let t = l.trim();
    if !t.starts_with('{') {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(t).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    let msg = v.get("fields").and_then(|f| f.get("message")).and_then(|m| m.as_str()).or_else(|| v.get("message").and_then(|m| m.as_str()))?;
    let others = v.get("fields").and_then(|f| f.as_object()).map(|o| o.len().saturating_sub(1)).unwrap_or(0);
    let extra = if others > 0 { format!(" [{others} structured fields not kept]") } else { String::new() };
    Some((format!("{}  {} {}: {}", s("timestamp"), s("level"), s("target"), msg), extra))
}

fn wallet_target(target: &str) -> bool {
    WALLET_MODULES.iter().any(|m| target == *m || target.starts_with(&format!("{m}::")) || (*m == "divi_swap" && target.starts_with("divi_swap")))
        || target.starts_with("swap_")
}

/// The irondivid crate-root lines on the A11 edit-site list
fn wallet_root_line(target: &str, msg: &str) -> bool {
    (target == "irondivid" || target.starts_with("irondivid::") && !target.starts_with("irondivid::core_files"))
        && (msg.contains("Unconfirmed wallet tx") || (msg.starts_with("Transaction ") && msg.contains("submitted to mempool")))
}

fn per_block(msg: &str) -> Option<&'static str> {
    if msg.starts_with("Failed to save wallet after") && !msg.starts_with("Failed to save wallet after chain sync") {
        return Some("Failed to save wallet after");
    }
    if let Some(f) = PER_BLOCK.iter().find(|f| msg.starts_with(**f)) {
        return Some(f);
    }
    if let Some((_, _, name)) = PER_BLOCK_INNER.iter().find(|(a, b, _)| msg.starts_with(a) && msg.contains(b)) {
        return Some(name);
    }
    // A11 counted list: the wallet lines written on the connect path
    if msg.starts_with("Received ") && msg.contains(" in tx ") {
        return Some("Received … in tx …");
    }
    None
}

fn failure_only(msg: &str) -> Option<&'static str> {
    FAILURE_ONLY.iter().find(|f| msg.starts_with(**f)).copied()
}

fn is_word(core: &str) -> bool {
    !core.is_empty()
        && core.chars().all(|c| c.is_ascii_alphabetic() || c == '_' || c == '-' || c == '\'' || c == '!' || c == '?')
        && core.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        // a base58 string of letters only is still an argument
        && !(core.len() >= 25 && core.chars().any(|c| c.is_ascii_uppercase()) && core.chars().any(|c| c.is_ascii_lowercase()))
}

fn is_num(core: &str) -> bool {
    let c = core.trim_start_matches(['-', '+']);
    !c.is_empty() && c.chars().any(|ch| ch.is_ascii_digit()) && c.chars().all(|ch| ch.is_ascii_digit() || ch == '.' || ch == ',' || ch == '_')
}

fn kind(core: &str, r: &Redactor) -> String {
    if is_num(core) {
        return "<num>".into();
    }
    if (core.starts_with('"') && core.ends_with('"') && core.len() >= 2) || (core.starts_with('\'') && core.ends_with('\'') && core.len() >= 2) {
        return "<str>".into();
    }
    if let Ok(sa) = core.parse::<std::net::SocketAddr>() {
        // the port after an address reduced to its class is kept
        return format!("{}:{}", r.scrub(&sa.ip().to_string()), sa.port());
    }
    if core.parse::<std::net::IpAddr>().is_ok() {
        return r.scrub(core);
    }
    let b58 = core.len() >= 25 && core.len() <= 62 && core.chars().all(|c| c.is_ascii_alphanumeric());
    if b58 && core.chars().any(|c| c.is_ascii_digit()) {
        return "<addr>".into();
    }
    "<arg>".into()
}

/// §6.2 (b): mask every argument of a wallet-module message
pub fn mask_wallet_msg(msg: &str, r: &Redactor) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut prev = String::new();
    let mut after_named = false;
    let mut quoted = false;
    for tok in msg.split_whitespace() {
        // a quoted argument with spaces: masked as one
        if quoted {
            if tok.ends_with('"') || tok.ends_with("\",") {
                quoted = false;
            }
            continue;
        }
        let lead: String = tok.chars().take_while(|c| "([{<".contains(*c)).collect();
        let rest = &tok[lead.len()..];
        let core_end = rest.trim_end_matches([',', ';', ':', '.', ')', ']', '}', '>']).len();
        let (core, trail) = rest.split_at(core_end);
        let lower = prev.to_ascii_lowercase();
        let masked = if core.is_empty() {
            tok.to_string()
        } else if core.starts_with('"') && !(core.len() >= 2 && core.ends_with('"')) {
            quoted = true;
            format!("{lead}<str>")
        } else if after_named {
            format!("{lead}{}{trail}", if core.starts_with('"') { "<str>" } else { "<arg>" })
        } else if let Some((k, _)) = core.split_once('=') {
            let k = if k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') { k } else { "<arg>" };
            format!("{lead}{k}=<arg>{trail}")
        } else if (is_num(core) && (lower == "port" || (lower == "code" && core.starts_with('-')))) || is_word(core) {
            tok.to_string()
        } else {
            format!("{lead}{}{trail}", kind(core, r))
        };
        after_named = matches!(core.to_ascii_lowercase().as_str(), "label" | "name");
        prev = core.to_string();
        out.push(masked);
    }
    out.join(" ")
}

fn re_amount() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b-?\d[\d,_]*(?:\.\d+)?\s*(sats|sat|DIVI)\b(\.[A-Za-z])?").unwrap())
}

fn re_invalid() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(Invalid -[A-Za-z0-9_.-]+=)\S.*$").unwrap())
}

fn re_hex64() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(blk:|sha256:)?\b([0-9a-fA-F]{64})\b").unwrap())
}

/// (a), (c) and (d) on a line that is kept
fn plain_rules(l: &str, r: &Redactor) -> String {
    let t = re_hex64().replace_all(l, |c: &regex::Captures| {
        if c.get(1).is_some() {
            c[0].to_string()
        } else {
            r.pseudonym("h64", &c[2].to_ascii_lowercase())
        }
    });
    // `29 divi.conf` (an `ls -l` time before a file name) is not an amount
    let t = re_amount().replace_all(&t, |c: &regex::Captures| match c.get(2) {
        Some(_) => c[0].to_string(),
        None => format!("<num> {}", &c[1]),
    });
    let t = re_invalid().replace_all(&t, "$1");
    t.into_owned()
}

fn peer_of(msg: &str) -> Option<&str> {
    let i = msg.find(" from peer ")?;
    msg[i + 11..].split_whitespace().next().map(|p| p.trim_end_matches([',', ':', ')']))
}

/// §6.3: would the filter remove this line (a per-block, failure-only or
/// staker line)? The filter's own count lines (`[week of …: …]`) are not.
pub fn would_remove(raw: &str) -> Option<&'static str> {
    let t = raw.trim();
    if t.starts_with('[') && t.ends_with(']') {
        return None;
    }
    let l = strip_ansi(raw);
    let json = parse_json(&l);
    let l: &str = json.as_ref().map(|j| j.0.as_str()).unwrap_or(&l);
    let parsed = parse(l);
    let msg = parsed.as_ref().map(|p| p.msg).unwrap_or(l).trim_start();
    if let Some(w) = failure_only(msg).or_else(|| per_block(msg)) {
        return Some(w);
    }
    if parsed.is_none() {
        if let Some(w) = PER_BLOCK.iter().find(|p| l.contains(**p)) {
            return Some(w);
        }
    }
    let target = parsed.as_ref().map(|p| p.target).unwrap_or("");
    if target.starts_with("divi_node::staker") || (parsed.is_none() && l.contains("divi_node::staker")) {
        return Some("staker line");
    }
    None
}

/// The one filter (§6.2 "Old-log lines")
pub fn filter(text: &str, r: &Redactor) -> Filtered {
    let mut f = Filtered::default();
    for raw in text.lines() {
        let l = strip_ansi(raw);
        let json = parse_json(&l);
        let l: &str = json.as_ref().map(|j| j.0.as_str()).unwrap_or(&l);
        let extra = json.as_ref().map(|j| j.1.as_str()).unwrap_or("");
        let parsed = parse(l);
        let (ts, msg) = match &parsed {
            Some(p) => (p.ts, p.msg),
            None => (l.split_whitespace().next().unwrap_or(""), l),
        };
        let target = parsed.as_ref().map(|p| p.target).unwrap_or("");

        // (e) per-block lines, any module
        let msg_for_match = msg.trim_start();
        if let Some(what) = failure_only(msg_for_match) {
            f.removed += 1;
            *f.counts.entry((period(ts, true), what.to_string())).or_default() += 1;
            continue;
        }
        if let Some(what) = per_block(msg_for_match).or_else(|| {
            // an unparsed line (a journal prefix, a ring copy): matched anywhere
            if parsed.is_none() {
                PER_BLOCK.iter().find(|p| l.contains(**p)).copied()
            } else {
                None
            }
        }) {
            f.removed += 1;
            *f.counts.entry((period(ts, false), what.to_string())).or_default() += 1;
            if what == "Received block" {
                if let Some(p) = peer_of(l) {
                    *f.counts.entry((period(ts, false), format!("Received block from {}", r.pseudonym("peer", p)))).or_default() += 1;
                }
            }
            continue;
        }
        // staker lines: none is on an allowlist yet
        if target.starts_with("divi_node::staker") || (parsed.is_none() && l.contains("divi_node::staker")) {
            f.removed += 1;
            *f.counts.entry((period(ts, false), "staker line".into())).or_default() += 1;
            continue;
        }
        // (b) wallet-bearing modules
        if let Some(p) = &parsed {
            if wallet_target(p.target) || wallet_root_line(p.target, p.msg) {
                f.masked += 1;
                f.text.push_str(&format!("{}  {} {}: {}{extra}\n", p.ts, p.level, p.target, mask_wallet_msg(p.msg, r)));
                continue;
            }
        } else if WALLET_MODULES.iter().any(|m| l.contains(&format!("{m}:")) || l.contains(&format!("{m}::"))) {
            // a wallet line in a form not parsed (journal prefix): keep the
            // part before the module, mask the rest
            let m = WALLET_MODULES.iter().find(|m| l.contains(&format!("{m}:")) || l.contains(&format!("{m}::"))).unwrap();
            let i = l.find(m).unwrap();
            let (head, tail) = l.split_at(i);
            let (module, msg) = tail.split_once(": ").unwrap_or((tail, ""));
            f.masked += 1;
            f.text.push_str(&format!("{}{}: {}\n", plain_rules(head, r), module, mask_wallet_msg(msg, r)));
            continue;
        }
        f.text.push_str(&plain_rules(l, r));
        f.text.push_str(extra);
        f.text.push('\n');
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Known;

    fn r() -> Redactor {
        Redactor::new([3; 32], &Known::default())
    }

    #[test]
    fn weeks_start_on_monday() {
        assert_eq!(period("2026-10-30T10:00:00Z", false), "week of 2026-10-26");
        assert_eq!(period("2026-10-26T00:00:00Z", false), "week of 2026-10-26");
        assert_eq!(period("2026-11-01T23:59:59Z", false), "week of 2026-10-26");
        assert_eq!(period("2024-03-01T00:00:00Z", false), "week of 2024-02-26");
        assert_eq!(period("2026-10-30T10:00:00Z", true), "day 2026-10-30");
        assert_eq!(period("garbage", false), "undated");
        assert_eq!(civil_from_days(days_from_civil(2000, 2, 29)), (2000, 2, 29));
    }

    #[test]
    fn per_block_lines_are_counted_not_kept() {
        let log = "\
2026-10-27T01:00:00.000Z DEBUG divi_network::sync: Received block 00000000000000000000000000000000000000000000000000000000000000ab from peer 7
2026-10-27T01:00:01.000Z DEBUG divi_network::sync: Connected block abc at height 1234567
2026-10-28T01:00:01.000Z  WARN divi_network::sync: Dropped invalid block abc: bad
2026-10-28T01:00:02.000Z  INFO divi_node::staker: Staked block abc at height 1234567 (reward: 456 DIVI)
2026-10-28T01:00:03.000Z  INFO divi_node::node: Block 00ab at height 9 processed
2026-10-28T01:00:04.000Z  INFO irondivid: Listening on port 51472
";
        let f = filter(log, &r());
        assert_eq!(f.text.lines().count(), 1, "{}", f.text);
        assert!(f.text.contains("Listening on port 51472"));
        let out = f.render();
        assert!(!out.contains("1234567"), "{out}");
        assert!(!out.contains("456"), "{out}");
        assert!(out.contains("[week of 2026-10-26: Connected block: 1-3]"), "{out}");
        assert!(out.contains("[day 2026-10-28: Dropped invalid block: 1-3]"), "{out}");
        assert!(out.contains("[week of 2026-10-26: staker line: 1-3]"), "{out}");
        assert!(out.contains("Received block from peer-"), "{out}");
    }

    #[test]
    fn wallet_lines_keep_only_words() {
        let log = "\
2026-10-27T01:00:00.000Z  INFO divi_wallet::wallet_db: Balance now 1.23456789 for label Savings at height 4242
2026-10-27T01:00:00.000Z  WARN divi_rpc::server: RPC error code -32601 on port 51473 from 192.168.1.9:51472
2026-10-27T01:00:00.000Z  INFO divi_wallet: Sent 123456789 to DHfrxHzGWW1fLVZ7RCeN1W2V8RANW3TUxr name=\"my coins\"
2026-10-27T01:00:00.000Z  INFO irondivid: Unconfirmed wallet tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b cannot be resubmitted
";
        let f = filter(log, &r());
        let t = &f.text;
        for bad in ["1.23456789", "Savings", "4242", "123456789", "DHfrxHzGWW1fLVZ7RCeN1W2V8RANW3TUxr", "my coins", "192.168.1.9", "4a5e1e4b"] {
            assert!(!t.contains(bad), "{bad} in {t}");
        }
        assert!(t.contains("Balance now <num> for label <arg> at height <num>"), "{t}");
        assert!(t.contains("code -32601 on port 51473"), "{t}");
        assert!(t.contains(":51472"), "{t}");
        assert!(t.contains("Unconfirmed wallet tx <arg> cannot be resubmitted"), "{t}");
    }

    #[test]
    fn amounts_and_invalid_values_elsewhere() {
        let log = "\
2026-10-27T01:00:00.000Z  INFO divi_network::fees: fee 1.23456789 DIVI and 5000 sats
2026-10-27T01:00:00.000Z  WARN irondivid: Invalid -rpcpassword=CANARYcanary123 ignored
2026-10-27T01:00:00.000Z  INFO divi_storage: hash 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b and blk:4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
";
        let t = filter(log, &r()).text;
        assert!(!t.contains("1.23456789") && !t.contains("5000"), "{t}");
        assert!(t.contains("<num> DIVI") && t.contains("<num> sats"), "{t}");
        let r2 = Redactor::new([0; 32], &Known::default());
        assert_eq!(plain_rules("Oct 31 04:29 divi.conf; sent 5 DIVI.", &r2), "Oct 31 04:29 divi.conf; sent <num> DIVI.");
        assert!(!t.contains("CANARY"), "{t}");
        assert!(t.contains("Invalid -rpcpassword="), "{t}");
        assert!(t.contains("hash h64-"), "{t}");
        assert!(t.contains("blk:4a5e1e4b"), "{t}");
    }

    #[test]
    fn json_lines_keep_message_only() {
        let log = r#"{"timestamp":"2026-10-27T01:00:00.000Z","level":"INFO","fields":{"message":"swap 7 claimed 1500 sats","preimage":"deadbeef"},"target":"divi_swapd::engine"}"#;
        let t = filter(log, &r()).text;
        assert!(!t.contains("deadbeef") && !t.contains("1500") && !t.contains(" 7 "), "{t}");
        assert!(t.contains("divi_swapd::engine: swap <num> claimed <num> sats [1 structured fields not kept]"), "{t}");
    }

    #[test]
    fn spans_before_the_target() {
        let p = parse("2026-10-27T01:00:00Z  INFO irondivid{run=3}: divi_wallet::db: Sent 5 to x").unwrap();
        assert_eq!(p.target, "divi_wallet::db");
        assert_eq!(p.msg, "Sent 5 to x");
    }
}
