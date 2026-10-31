// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `--attach <file>` (docs/plans/diag.md B6.6): a file the user names goes
//! into the package under `host/attached/`, through the same redaction as
//! everything else. Its names (host column, home paths, `rpcpassword`)
//! are harvested before the redactor is built, so they are masked in every
//! file, not only in the attached one. A JSON file goes through the JSON
//! layer ([`crate::rpcjson`]) first; any other file is redacted as an
//! imported log (the B6.4 rules, the syslog host column included).

use crate::import::{self, Raw, Rules};
use crate::redact::{Known, Redactor};
use crate::rpcjson;
use crate::scanner::Secret;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub struct Item {
    pub name: String,
    pub label: Option<String>,
    pub data: Vec<u8>,
    pub json: Option<Vec<serde_json::Value>>,
    pub truncated: bool,
}

#[derive(Default)]
pub struct Prepared {
    pub items: Vec<Item>,
    /// values §6.3 must not find (an `rpcpassword` in an attached file)
    pub secrets: Vec<Secret>,
    pub notes: Vec<String>,
}

/// What one attached file became, for the summary
pub struct Written {
    pub rel: String,
    pub treatment: String,
    pub actions: Vec<String>,
}

/// Read every file (B6.4 caps) and harvest its names into `known`
pub fn prepare(list: &[(PathBuf, Option<String>)], known: &mut Known) -> Prepared {
    let mut p = Prepared::default();
    let mut total = 0u64;
    for (path, label) in list {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "attached".into());
        if total >= import::TOTAL {
            p.notes.push(format!("--attach {}: not read, the {} MB total is reached", path.display(), import::TOTAL >> 20));
            continue;
        }
        let cap = import::PER_FILE.min(import::TOTAL - total);
        let mut data = Vec::new();
        let read = File::open(path).and_then(|f| f.take(cap + 1).read_to_end(&mut data));
        if let Err(e) = read {
            p.notes.push(format!("--attach {}: could not be read: {}", path.display(), crate::util::io_err(&e)));
            continue;
        }
        let truncated = data.len() as u64 > cap;
        data.truncate(cap as usize);
        total += data.len() as u64;
        let json = if truncated { None } else { rpcjson::parse(&data) };
        p.items.push(Item { name, label: label.clone(), data, json, truncated });
    }
    if p.items.is_empty() {
        return p;
    }
    let rules = Rules::new();
    // a text file is read as a log, so its syslog host column is harvested
    let raw = Raw {
        files: p
            .items
            .iter()
            .map(|i| {
                let dir = if i.json.is_some() { "attached" } else { "kernel" };
                (format!("{dir}/{}", i.name), i.data.clone())
            })
            .collect(),
        skipped: Vec::new(),
    };
    let h = import::harvest(&raw, &rules);
    let add = |into: &mut Vec<String>, from: Vec<String>| {
        for v in from {
            if !into.contains(&v) {
                into.push(v);
            }
        }
    };
    add(&mut known.hostnames, h.known.hostnames);
    add(&mut known.users, h.known.users);
    // docker events: container names are the user's names
    let mut names = Vec::new();
    for i in &p.items {
        for d in i.json.iter().flatten() {
            if let Some(n) = d.pointer("/Actor/Attributes/name").and_then(|v| v.as_str()) {
                if n.len() >= 2 {
                    names.push(n.to_string());
                }
            }
        }
    }
    add(&mut known.hostnames, names);
    p.secrets = h.secrets.into_iter().map(|s| Secret { label: s.label.replace("an imported", "an attached"), ..s }).collect();
    p
}

/// The redacted text of every attached file: (package path, text, record)
pub fn render(p: &Prepared, red: &Redactor) -> Vec<(String, String, Written)> {
    let rules = Rules::new();
    let mut out = Vec::new();
    for (n, i) in p.items.iter().enumerate() {
        let rel = format!("host/attached/{}-{}", n + 1, red.path(&i.name));
        let (text, mut treatment, actions) = match &i.json {
            Some(docs) => {
                let (t, tr, a) = rpcjson::treat_file(docs.clone(), i.label.as_deref());
                (red.scrub(&t), tr, a)
            }
            None => {
                let mut tr = "text; redacted as a log (B6.4 rules)".to_string();
                if let Some(l) = &i.label {
                    tr = format!("label `{l}` ignored: the file is not JSON; {tr}");
                }
                (import::render(&format!("kernel/{}", i.name), &i.data, red, &rules), tr, Vec::new())
            }
        };
        if i.truncated {
            treatment.push_str(&format!("; cut at {} MB", import::PER_FILE >> 20));
        }
        out.push((rel.clone(), text, Written { rel, treatment, actions }));
    }
    out
}
