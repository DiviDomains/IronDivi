//! B6.3 `diag --tx <txid>`: one transaction the user names, in clear,
//! after the §8.2 question. It is made, asked about and written here in
//! the parent, never by a collector (every collector frame goes through
//! the redaction pass): the decoded transaction, its inputs' prevouts, its
//! mempool state, the wallet record and its conflicts. Scripts and raw
//! transaction data never go; the wallet's labels go as a pseudonym only;
//! no other wallet transaction is included.

use crate::collectors::live;
use crate::ctx::Ctx;
use crate::redact::Redactor;
use serde_json::{json, Map, Value};
use std::time::{Duration, Instant};

/// Inputs whose prevout is looked up; past this they are named by txid
/// and index only
const MAX_INPUTS: usize = 200;
/// Outputs checked for being this wallet's change
const MAX_OUTPUTS: usize = 50;
/// Conflicting wallet transactions named
const MAX_CONFLICTS: usize = 20;
/// The whole gathering, at most 2 s a call
const TOTAL_SECS: u64 = 60;
/// Mempool entries above which the verbose mempool is not asked for
const MAX_MEMPOOL_VERBOSE: u64 = 5_000;
/// Lines shown before the question; the rest is in the file
const PREVIEW_LINES: usize = 200;
/// Funding transactions named in the question
const NAMED_FUNDING: usize = 5;

/// One node call: method, params → answer or the error's text
pub type Call<'a> = dyn FnMut(&str, Value) -> Result<Value, String> + 'a;

/// What [`gather`] made
pub struct Gathered {
    /// the package file, after the clear drop
    pub v: Value,
    /// how many script, raw data and label fields were dropped
    pub dropped: usize,
    /// this wallet's change: output index and address
    pub change: Vec<(u64, String)>,
    /// every output is this wallet's: no change can be named
    pub to_self: bool,
    /// the transactions whose outputs it spends
    pub funding: Vec<String>,
    /// what could not be found, one line each
    pub notes: Vec<String>,
}

/// Is `s` a transaction id (64 hex digits)
pub fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Every non-empty `label` or `account` gets a `label_pseudonym` beside
/// it; the clear drop then removes the label itself (B6.3: "the wallet's
/// labels on any of these are pseudonymised")
fn pseudonymise_labels(v: &mut Value, red: &Redactor) {
    match v {
        Value::Object(m) => {
            let label = ["label", "account"].iter().find_map(|k| {
                m.get(*k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            });
            if let Some(l) = label {
                m.insert(
                    "label_pseudonym".into(),
                    Value::from(red.pseudonym("label", &l)),
                );
            }
            m.values_mut().for_each(|x| pseudonymise_labels(x, red));
        }
        Value::Array(a) => a.iter_mut().for_each(|x| pseudonymise_labels(x, red)),
        _ => {}
    }
}

/// A coinbase input's `coinbase` field is its raw script: only the fact
/// that it is one goes
fn drop_coinbase_script(tx: &mut Value) {
    if let Some(vin) = tx.get_mut("vin").and_then(Value::as_array_mut) {
        for i in vin {
            if let Some(c) = i.get_mut("coinbase") {
                *c = Value::Bool(true);
            }
        }
    }
}

/// Output `n` of a decoded transaction
fn output(tx: &Value, n: u64) -> Option<Value> {
    tx.get("vout")?
        .as_array()?
        .iter()
        .find(|o| o.get("n").and_then(Value::as_u64) == Some(n))
        .cloned()
}

/// The addresses of a decoded output
fn addresses(o: &Value) -> Vec<String> {
    o.pointer("/scriptPubKey/addresses")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Output `n` of transaction `txid`: from the wallet's record, else from
/// the node (getrawtransaction: mempool, transaction index or unspent coins)
fn prevout(call: &mut Call, txid: &str, n: u64) -> Option<(Value, &'static str)> {
    let hex = call("gettransaction", json!([txid]))
        .ok()
        .and_then(|w| w.get("hex").and_then(Value::as_str).map(String::from));
    if let Some(h) = hex {
        if let Some(o) = call("decoderawtransaction", json!([h]))
            .ok()
            .and_then(|t| output(&t, n))
        {
            return Some((o, "the wallet"));
        }
    }
    call("getrawtransaction", json!([txid, 1]))
        .ok()
        .and_then(|t| output(&t, n))
        .map(|o| (o, "the node (getrawtransaction)"))
}

/// Ask the node for everything B6.3 sends about `txid`, then apply the
/// clear drop. Err when the node knows no such transaction.
pub fn gather(
    call: &mut Call,
    red: &Redactor,
    txid: &str,
    budget: Duration,
) -> Result<Gathered, String> {
    let start = Instant::now();
    let mut notes = Vec::new();
    let mut wallet = match call("gettransaction", json!([txid])) {
        Ok(w) => Some(w),
        Err(e) => {
            notes.push(format!("no wallet record: {e}"));
            None
        }
    };
    let (mut tx, decoded_from) = match call("getrawtransaction", json!([txid, 1])) {
        Ok(t) => (
            t,
            "the node (getrawtransaction: mempool, transaction index or unspent coins)",
        ),
        Err(e1) => match wallet
            .as_ref()
            .and_then(|w| w.get("hex"))
            .and_then(Value::as_str)
            .map(String::from)
        {
            Some(h) => (
                call("decoderawtransaction", json!([h]))
                    .map_err(|e| format!("its wallet record could not be decoded: {e}"))?,
                "the wallet record (the node could not return it)",
            ),
            None => return Err(format!("the node knows no transaction {txid}: {e1}")),
        },
    };
    drop_coinbase_script(&mut tx);

    // the inputs' prevouts: which earlier transactions paid for it
    let mut prevouts = Vec::new();
    let mut funding = Vec::new();
    let vin = tx
        .get("vin")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (i, input) in vin.iter().enumerate() {
        if input.get("coinbase").is_some() {
            prevouts.push(json!({"input": i, "coinbase": true}));
            continue;
        }
        let (Some(pt), Some(n)) = (
            input.get("txid").and_then(Value::as_str),
            input.get("vout").and_then(Value::as_u64),
        ) else {
            continue;
        };
        if !funding.iter().any(|f| f == pt) {
            funding.push(pt.to_string());
        }
        if i >= MAX_INPUTS || start.elapsed() > budget {
            prevouts.push(json!({"input": i, "txid": pt, "vout": n, "not_looked_up": "past the input or time cap"}));
            continue;
        }
        match prevout(call, pt, n) {
            Some((o, src)) => prevouts.push(json!({
                "input": i, "txid": pt, "vout": n,
                "value": o.get("value").cloned().unwrap_or(Value::Null),
                "scriptPubKey": o.get("scriptPubKey").cloned().unwrap_or(Value::Null),
                "found_in": src,
            })),
            None => {
                notes.push(format!(
                    "input {i}: its prevout is in neither the wallet nor the node"
                ));
                prevouts.push(json!({"input": i, "txid": pt, "vout": n, "not_found": true}));
            }
        }
    }

    // the change: on a send, the outputs paying an address of this
    // wallet, less those the wallet lists as where the send went; when
    // every output is this wallet's, it is a send to yourself and which
    // one is change cannot be told from the node's answers
    let sent_to: Vec<String> = wallet
        .as_ref()
        .and_then(|w| w.get("details"))
        .and_then(Value::as_array)
        .map(|d| {
            d.iter()
                .filter(|e| e.get("category").and_then(Value::as_str) == Some("send"))
                .flat_map(|e| {
                    // Divi lists either one `address` or `addresses: [{address}]`
                    let one = e.get("address").and_then(Value::as_str).map(String::from);
                    let many = e
                        .get("addresses")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|a| {
                            a.get("address")
                                .and_then(Value::as_str)
                                .or_else(|| a.as_str())
                                .map(String::from)
                        });
                    one.into_iter().chain(many).collect::<Vec<_>>()
                })
                .collect()
        })
        .unwrap_or_default();
    let is_send = wallet.as_ref().is_some_and(|w| {
        w.get("fee").is_some_and(Value::is_number)
            || w.get("details").and_then(Value::as_array).is_some_and(|d| {
                d.iter()
                    .any(|e| e.get("category").and_then(Value::as_str) == Some("send"))
            })
    });
    let mut change = Vec::new();
    let mut to_self = false;
    if is_send {
        let outs = tx
            .get("vout")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut checked = 0;
        for o in outs.iter().take(MAX_OUTPUTS) {
            checked += 1;
            let Some(n) = o.get("n").and_then(Value::as_u64) else {
                continue;
            };
            for a in addresses(o) {
                if start.elapsed() > budget {
                    break;
                }
                let mine = call("validateaddress", json!([a]))
                    .ok()
                    .and_then(|v| v.get("ismine").and_then(Value::as_bool));
                if mine == Some(true) {
                    if !sent_to.contains(&a) {
                        change.push((n, a));
                    }
                    break;
                }
            }
        }
        if checked > 0 && checked == outs.len() && change.len() == outs.len() && sent_to.is_empty()
        {
            to_self = true;
            change.clear();
            notes.push(
                "every output pays this wallet (a send to yourself): which one is change cannot be told".into(),
            );
        }
    }

    // mempool state
    let pool: Option<Vec<String>> = call("getrawmempool", json!([false])).ok().and_then(|v| {
        v.as_array().map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
    });
    let in_pool = pool
        .as_ref()
        .map(|p| p.iter().any(|t| t.eq_ignore_ascii_case(txid)));
    let mut mempool = Map::new();
    mempool.insert(
        "in_mempool".into(),
        in_pool.map_or(Value::Null, Value::Bool),
    );
    let info = call("getmempoolinfo", json!([])).ok();
    if in_pool == Some(true) {
        match info
            .as_ref()
            .and_then(|i| i.get("size"))
            .and_then(Value::as_u64)
        {
            Some(s) if s < MAX_MEMPOOL_VERBOSE => {
                if let Some(e) = call("getrawmempool", json!([true]))
                    .ok()
                    .and_then(|v| v.get(txid).cloned())
                {
                    mempool.insert("entry".into(), e);
                }
            }
            _ => notes.push(
                "the mempool entry was not asked for: the mempool size is unknown or 5000 or more"
                    .into(),
            ),
        }
    }
    if let Some(i) = info {
        mempool.insert("info".into(), i);
    }
    let confirmations = wallet
        .as_ref()
        .and_then(|w| w.get("confirmations"))
        .or_else(|| tx.get("confirmations"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let rejection = if in_pool == Some(false) && confirmations <= 0 {
        Value::from(
            "not in the mempool and not confirmed; this node version keeps no rejection reason for the \
             wallet's own transactions (A13 own-invalid is not built)",
        )
    } else {
        Value::Null
    };

    // conflicts: their ids, depth and mempool state, nothing more
    let mut conflicts = Vec::new();
    let ids: Vec<String> = wallet
        .as_ref()
        .and_then(|w| w.get("walletconflicts"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    for c in ids.iter().take(MAX_CONFLICTS) {
        let conf = call("gettransaction", json!([c]))
            .ok()
            .and_then(|w| w.get("confirmations").and_then(Value::as_i64));
        conflicts.push(json!({
            "txid": c,
            "confirmations": conf,
            "in_mempool": pool.as_ref().map(|p| p.iter().any(|t| t.eq_ignore_ascii_case(c))),
        }));
    }
    if ids.len() > MAX_CONFLICTS {
        notes.push(format!(
            "{} more conflicting transactions not named",
            ids.len() - MAX_CONFLICTS
        ));
    }

    if let Some(w) = wallet.as_mut() {
        pseudonymise_labels(w, red);
    }
    let v = json!({
        "txid": txid,
        "decoded_from": decoded_from,
        "transaction": tx,
        "prevouts": prevouts,
        "your_change": change.iter().map(|(n, a)| json!({"output": n, "address": a})).collect::<Vec<_>>(),
        "to_yourself": to_self,
        "mempool": Value::Object(mempool),
        "rejection": rejection,
        "wallet": wallet,
        "conflicts": conflicts,
        "notes": notes,
    });
    let (v, dropped) = crate::rpcjson::clear(v);
    Ok(Gathered {
        v,
        dropped,
        change,
        to_self,
        funding,
        notes,
    })
}

/// The §8.2 question, naming the change output and the funding
/// transactions (§10)
pub fn question(txid: &str, g: &Gathered) -> String {
    let change = if g.to_self {
        "none can be told: every output pays this wallet".to_string()
    } else if g.change.is_empty() {
        "no output is your change".to_string()
    } else {
        g.change
            .iter()
            .map(|(n, a)| format!("output {n}, {a}"))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let mut funding = g
        .funding
        .iter()
        .take(NAMED_FUNDING)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if g.funding.len() > NAMED_FUNDING {
        funding.push_str(&format!(" and {} more", g.funding.len() - NAMED_FUNDING));
    }
    if funding.is_empty() {
        funding = "none: it spends no earlier output".into();
    }
    format!(
        "Include transaction `{txid}` in clear? It shows its amount, inputs and outputs, which of the outputs \
         is your change and its address ({change}), and which earlier transactions paid for it ({funding}). \
         Your labels stay hidden. [yes/no] "
    )
}

/// B6.3 on a live node: gather, show, ask, write `tx/transaction.json`.
/// `datadir` is the data dir chosen for the call (or why none is).
/// Returns the lines for the summary and the file written, if any.
pub fn ask(
    ctx: &Ctx,
    datadir: Result<usize, String>,
    red: &Redactor,
    root: &std::path::Path,
    txid: &str,
    inp: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
) -> (Vec<String>, Option<String>) {
    let not = |out: &mut dyn std::io::Write, why: String| {
        let _ = writeln!(out, "--tx {txid}: not included: {why}");
        (vec![format!("--tx: not included: {why}")], None)
    };
    let d = match datadir {
        Ok(n) => match ctx.datadirs.iter().find(|d| d.n == n) {
            Some(d) => d,
            None => return not(out, "the data dir was not found".into()),
        },
        Err(why) => return not(out, why),
    };
    let Some(node) = ctx.node_for(d) else {
        return not(out, "the node is not running".into());
    };
    let rpc = match live::rpc_for(d, Some(node)) {
        Ok(r) => r,
        Err(why) => return not(out, why),
    };
    if let Some(b) = crate::mem::free_memory(Some(node.pid)).bytes {
        if b < crate::collectors::rpc::MIN_FREE {
            return not(out, format!("free memory {} MB is under 512 MB", b >> 20));
        }
    }
    let secs = Duration::from_secs(crate::collectors::rpc::CALL_SECS);
    let mut call = |m: &str, p: Value| live::call(&rpc, m, p, secs).map_err(|e| e.to_string());
    let g = match gather(&mut call, red, txid, Duration::from_secs(TOTAL_SECS)) {
        Ok(g) => g,
        Err(why) => return not(out, why),
    };
    let text = red.scrub_clear(&serde_json::to_string_pretty(&g.v).unwrap_or_default());
    let _ = writeln!(
        out,
        "\n---- transaction {txid} in clear (B6.3), as it would be sent"
    );
    let lines = text.lines().count();
    for l in text.lines().take(PREVIEW_LINES) {
        let _ = writeln!(out, "  | {l}");
    }
    if lines > PREVIEW_LINES {
        let _ = writeln!(out, "  | ... {} more lines", lines - PREVIEW_LINES);
    }
    let _ = write!(out, "{}", question(txid, &g));
    let _ = out.flush();
    let mut a = String::new();
    if !(matches!(inp.read_line(&mut a), Ok(k) if k > 0) && crate::consent::is_yes(&a)) {
        return (
            vec!["--tx: not included: you did not answer yes (§8.2)".into()],
            None,
        );
    }
    let rel = "tx/transaction.json".to_string();
    let path = root.join(&rel);
    let wrote = (|| -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap_or(root))?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")
    })();
    match wrote {
        Ok(()) => {
            let mut l = vec![format!(
                "--tx: {rel}, you answered yes; change: {}; {} funding transactions; {} script, raw data and label \
                 fields dropped; the node was asked at consent time",
                if g.change.is_empty() { "none".into() } else { g.change.iter().map(|(n, _)| format!("output {n}")).collect::<Vec<_>>().join(", ") },
                g.funding.len(),
                g.dropped
            )];
            l.extend(g.notes.iter().map(|n| format!("--tx: {n}")));
            (l, Some(rel))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            (
                vec![format!(
                    "--tx: not included: could not be written ({})",
                    e.kind()
                )],
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const T: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const F1: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const F2: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const C: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const OTHER: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const PAY: &str = "DFvLxvYDRB3X6ZqXrkLBkMxSvp7SkYBTGe";
    const MINE: &str = "DRLvrm8Pn6Y4Ce8RFcXWPkYbyXn8zj5Z3H";

    fn spk(a: &str) -> Value {
        json!({"asm": "OP_DUP OP_HASH160 ab OP_EQUALVERIFY OP_CHECKSIG", "hex": "76a914ab88ac", "type": "pubkeyhash", "reqSigs": 1, "addresses": [a]})
    }

    /// a node without a transaction index: getrawtransaction fails for
    /// anything not in the mempool
    fn node() -> impl FnMut(&str, Value) -> Result<Value, String> {
        let decoded: HashMap<&str, Value> = HashMap::from([
            (
                "hexT",
                json!({"txid": T, "hex": "hexT", "vin": [
                {"txid": F1, "vout": 0, "scriptSig": {"asm": "x", "hex": "y"}},
                {"txid": F2, "vout": 1, "scriptSig": {"asm": "x", "hex": "y"}}],
                "vout": [{"n": 0, "value": 3.0, "scriptPubKey": spk(PAY)}, {"n": 1, "value": 1.9, "scriptPubKey": spk(MINE)}]}),
            ),
            (
                "hexF1",
                json!({"txid": F1, "vin": [{"coinbase": "03abcdef"}], "vout": [{"n": 0, "value": 2.0, "scriptPubKey": spk(MINE)}]}),
            ),
            (
                "hexF2",
                json!({"txid": F2, "vin": [], "vout": [{"n": 0, "value": 9.0, "scriptPubKey": spk(PAY)}, {"n": 1, "value": 3.0, "scriptPubKey": spk(MINE)}]}),
            ),
        ]);
        move |m: &str, p: Value| {
            let a0 = p.get(0).and_then(Value::as_str).unwrap_or("").to_string();
            match (m, a0.as_str()) {
                ("gettransaction", x) if x == T => Ok(json!({
                    "amount": -3.0, "fee": -0.1, "confirmations": 0, "txid": T, "hex": "hexT",
                    "walletconflicts": [C], "comment": "rent",
                    "details": [{"account": "landlord", "address": PAY, "category": "send", "amount": -3.0, "label": "landlord", "vout": 0}]})),
                ("gettransaction", x) if x == F1 => Ok(json!({"hex": "hexF1", "confirmations": 9})),
                ("gettransaction", x) if x == F2 => Ok(json!({"hex": "hexF2", "confirmations": 7})),
                ("gettransaction", x) if x == C => {
                    Ok(json!({"hex": "hexC", "confirmations": -1, "amount": -8.0}))
                }
                ("decoderawtransaction", h) => {
                    decoded.get(h).cloned().ok_or_else(|| "bad hex".into())
                }
                ("getrawtransaction", _) => {
                    Err("No information available about transaction".into())
                }
                ("validateaddress", a) => Ok(json!({"ismine": a == MINE})),
                ("getrawmempool", _) => Ok(json!([OTHER])),
                ("getmempoolinfo", _) => Ok(json!({"size": 1})),
                _ => Err(format!("unexpected {m}")),
            }
        }
    }

    #[test]
    fn one_send_with_change_names_exactly_its_parts() {
        let red = Redactor::new([7u8; 32], &Default::default());
        let mut n = node();
        let g = gather(&mut n, &red, T, Duration::from_secs(60)).unwrap();
        assert_eq!(g.change, vec![(1, MINE.to_string())]);
        assert_eq!(g.funding, vec![F1.to_string(), F2.to_string()]);
        let s = g.v.to_string();
        // scripts, raw data, labels and comments are gone; a pseudonym stays
        for k in [
            "\"hex\"",
            "\"asm\"",
            "scriptSig",
            "\"label\"",
            "\"account\"",
            "\"comment\"",
            "landlord",
            "rent",
            "76a914",
        ] {
            assert!(!s.contains(k), "{k} in {s}");
        }
        assert_eq!(
            g.v["wallet"]["details"][0]["label_pseudonym"],
            red.pseudonym("label", "landlord")
        );
        // prevouts from the wallet, with their value and address
        assert_eq!(g.v["prevouts"][1]["value"], 3.0);
        assert_eq!(g.v["prevouts"][1]["scriptPubKey"]["addresses"][0], MINE);
        assert_eq!(g.v["prevouts"][0]["found_in"], "the wallet");
        assert_eq!(
            g.v["decoded_from"],
            "the wallet record (the node could not return it)"
        );
        // the conflict by id and depth only
        assert_eq!(
            g.v["conflicts"][0],
            json!({"txid": C, "confirmations": -1, "in_mempool": false})
        );
        assert!(!s.contains("-8.0") && !s.contains(OTHER), "{s}");
        assert_eq!(g.v["mempool"]["in_mempool"], false);
        assert!(g.v["rejection"]
            .as_str()
            .unwrap()
            .contains("not in the mempool"));
        // the clear rule the scanner applies finds nothing left to drop
        assert_eq!(crate::rpcjson::clear(g.v.clone()).1, 0);
        let q = question(T, &g);
        assert!(
            q.contains(&format!("output 1, {MINE}")) && q.contains(F1) && q.contains(F2),
            "{q}"
        );
        assert!(q.contains("Your labels stay hidden"));
    }

    #[test]
    fn a_send_to_yourself_names_no_change() {
        let red = Redactor::new([7u8; 32], &Default::default());
        let tx = json!({"txid": T, "vin": [{"txid": F1, "vout": 0}],
            "vout": [{"n": 0, "value": 7.25, "scriptPubKey": spk(MINE)}, {"n": 1, "value": 1.0, "scriptPubKey": spk(PAY)}]});
        let mut n = |m: &str, p: Value| -> Result<Value, String> {
            match m {
                "gettransaction" if p[0] == T => Ok(
                    json!({"fee": 0.1, "confirmations": 3, "walletconflicts": [],
                    "details": [{"category": "move", "addresses": [{"address": MINE}, {"address": PAY}]}]}),
                ),
                "getrawtransaction" if p[0] == T => Ok(tx.clone()),
                "validateaddress" => Ok(json!({"ismine": true})),
                "getrawmempool" => Ok(json!([])),
                _ => Err("no".into()),
            }
        };
        let g = gather(&mut n, &red, T, Duration::from_secs(60)).unwrap();
        assert!(g.to_self && g.change.is_empty());
        assert!(question(T, &g).contains("none can be told"));
        assert!(g.v["rejection"].is_null(), "confirmed");
        // a send whose detail names the payee: that output is not change
        let mut n2 = |m: &str, p: Value| -> Result<Value, String> {
            match m {
                "gettransaction" if p[0] == T => Ok(json!({"fee": 0.1, "confirmations": 3,
                    "details": [{"category": "send", "addresses": [{"address": MINE}]}]})),
                "getrawtransaction" if p[0] == T => Ok(tx.clone()),
                "validateaddress" => Ok(json!({"ismine": true})),
                _ => Err("no".into()),
            }
        };
        let g = gather(&mut n2, &red, T, Duration::from_secs(60)).unwrap();
        assert_eq!(g.change, vec![(1, PAY.to_string())]);
        assert!(!g.to_self);
    }

    #[test]
    fn a_coinbase_input_carries_no_script() {
        let mut tx = json!({"vin": [{"coinbase": "03abcdef", "sequence": 1}]});
        drop_coinbase_script(&mut tx);
        assert_eq!(tx["vin"][0]["coinbase"], true);
    }

    #[test]
    fn an_unknown_transaction_is_an_error() {
        let red = Redactor::new([7u8; 32], &Default::default());
        let mut n = node();
        assert!(gather(&mut n, &red, OTHER, Duration::from_secs(60)).is_err());
        assert!(is_txid(T) && !is_txid("12") && !is_txid(&"g".repeat(64)));
    }
}
