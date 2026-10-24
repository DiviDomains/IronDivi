// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Start-up options as Divi Core's divid reads them (Settings.cpp): from the
//! command line, `-name=value` or `-name` (`--name` the same, `-noname` its
//! negation, the last value winning, unknown names ignored), then from the
//! config file, which only fills names the command line left unset (its
//! first value winning). Options that may repeat (`addnode`, `connect`, …)
//! keep every value, the command line's first; every option keeps its list of
//! values that way.

use std::collections::HashMap;

/// Options irondivid takes a value for. Written `--name value` (irondivid's own
/// form) the next argument is the value; divid's form is `-name=value`.
const VALUE_OPTIONS: &[&str] = &[
    "conf",
    "datadir",
    "mode",
    "rpcuser",
    "rpcpassword",
    "rpcport",
    "rpcbind",
    "rpcallowip",
    "port",
    "bind",
    "addnode",
    "fullnode",
    "connect",
    "seednode",
    "checkblocks",
    "maxreorg",
    "proxy",
    "wallet",
    "banscore",
    "bantime",
    "stakesplitthreshold",
    "utxocachesize",
    "expire",
    "maxlogsize",
    "maxlogfiles",
    "maxconnections",
    "maxorphantx",
    "minrelaytxfee",
    "timeout",
    "pid",
    "blocknotify",
    "walletnotify",
    "export-start",
    "export-end",
    "export-output",
    "export-snapshot",
    "import-snapshot",
    "snapshot-root",
    "sign-snapshot",
    "verify-snapshot",
    "snapshot-signer",
];

/// Short options irondivid has always had (`-c file`, `-d dir`)
const SHORT_OPTIONS: &[(&str, &str)] = &[("c", "conf"), ("d", "datadir")];

/// Options with a value of their own, never just "1"
const BOOL_WITH_VALUE: &[&str] = &["staking", "txindex", "spentindex", "addressindex"];

/// The options read from the command line and the config file
#[derive(Debug, Default, Clone)]
pub struct Settings {
    single: HashMap<String, String>,
    multi: HashMap<String, Vec<String>>,
    /// Words that are not options (divid ignores them too)
    pub stray: Vec<String>,
}

/// Divi Core's InterpretBool: empty is true, else atoi(value) != 0, so
/// "true" or "yes" are false as for divid
pub fn interpret_bool(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    atoi(value) != 0
}

/// C atoi: leading spaces, an optional sign, then digits up to the first
/// other character; 0 when there are none
pub fn atoi(value: &str) -> i64 {
    let v = value.trim_start();
    let (negative, digits) = match v.as_bytes().first() {
        Some(b'-') => (true, &v[1..]),
        Some(b'+') => (false, &v[1..]),
        _ => (false, v),
    };
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    let n = digits[..end].parse::<i64>().unwrap_or(0);
    if negative {
        -n
    } else {
        n
    }
}

impl Settings {
    /// Settings::SetParameter: `-noname=v` is `-name=!v`; a single value is
    /// replaced unless `once` (the config file) and already set; every value
    /// is kept for options that repeat
    pub fn set(&mut self, key: &str, value: &str, once: bool) {
        let (key, value) = match key.strip_prefix("no") {
            Some(rest) if key.len() > 2 && !is_known_no_word(key) => (
                rest.to_string(),
                if interpret_bool(value) { "0" } else { "1" }.to_string(),
            ),
            _ => (key.to_string(), value.to_string()),
        };
        if !once || !self.single.contains_key(&key) {
            self.single.insert(key.clone(), value.clone());
        }
        self.multi.entry(key).or_default().push(value);
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.single.get(key).map(String::as_str)
    }

    pub fn is_set(&self, key: &str) -> bool {
        self.single.contains_key(key)
    }

    /// GetBoolArg
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        self.get(key).map_or(default, interpret_bool)
    }

    /// Every value of an option, the command line's first
    pub fn get_multi(&self, key: &str) -> &[String] {
        self.multi.get(key).map_or(&[], Vec::as_slice)
    }

    /// SoftSetBoolArg: set only if unset; true if it was set now
    pub fn soft_set_bool(&mut self, key: &str, value: bool) -> bool {
        if self.is_set(key) {
            return false;
        }
        self.set(key, if value { "1" } else { "0" }, false);
        true
    }

    /// Every option name that has a value
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.single.keys()
    }

    /// Read the command line (without the program name). Both divid's
    /// `-name=value` / `-name` and irondivid's `--name value` are read.
    pub fn from_command_line(argv: &[String]) -> Settings {
        let mut settings = Settings::default();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            let Some(body) = arg.strip_prefix('-') else {
                settings.stray.push(arg.clone());
                i += 1;
                continue;
            };
            let double = body.starts_with('-');
            if body.starts_with("--") {
                // ---name is ignored (Settings.cpp:103-109)
                i += 1;
                continue;
            }
            let body = body.strip_prefix('-').unwrap_or(body);
            let (name, value) = match body.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (body.to_string(), None),
            };
            let short = SHORT_OPTIONS
                .iter()
                .find(|(s, _)| *s == name)
                .map(|(_, l)| *l);
            let name = short.map(str::to_string).unwrap_or(name);
            let takes_next = value.is_none()
                && (double || short.is_some())
                && (VALUE_OPTIONS.contains(&name.as_str())
                    || (BOOL_WITH_VALUE.contains(&name.as_str())
                        && argv.get(i + 1).is_some_and(|v| is_bool_word(v))));
            let value = match value {
                Some(v) => v,
                None if takes_next && i + 1 < argv.len() => {
                    i += 1;
                    argv[i].clone()
                }
                None => String::new(),
            };
            // irondivid's `--name` for a value option it may give alone
            let value = match (value.as_str(), name.as_str()) {
                ("true", n) | ("false", n) if BOOL_WITH_VALUE.contains(&n) => {
                    if value == "true" { "1" } else { "0" }.to_string()
                }
                _ => value,
            };
            settings.set(&name, &value, false);
            i += 1;
        }
        settings
    }

    /// Fill the options the command line left unset from a config file in
    /// divid's format (Settings::ReadConfigFile with boost's parser): one
    /// `name=value` per line, `#` starting a comment, a bare `name` meaning
    /// an empty value. A `[section]` header and a `net.name` prefix do not
    /// keep a setting from applying: Divi Core 3.0.0 applies them on every
    /// network (ParseNetworkSpecificFlag tests "testnet" without its dash).
    pub fn read_config(&mut self, content: &str) {
        let mut section: Option<String> = None;
        for raw in content.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = Some(line[1..line.len() - 1].trim().to_string());
                continue;
            }
            let (key, value) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (line, ""),
            };
            if key.is_empty() {
                continue;
            }
            let full = match &section {
                Some(s) if !s.is_empty() => format!("{}.{}", s, key),
                _ => key.to_string(),
            };
            let key = match full.split_once('.') {
                Some((net, rest)) if !net.is_empty() => rest.to_string(),
                _ => full,
            };
            self.set(&key, value.trim_matches('"'), true);
        }
    }

    /// Fill the options the command line left unset from irondivid's TOML
    /// config: a list is a repeated option, a boolean is 1 or 0
    pub fn read_toml(&mut self, table: &toml::Table) {
        for (key, value) in table {
            let values: Vec<&toml::Value> = match value {
                toml::Value::Array(list) => list.iter().collect(),
                v => vec![v],
            };
            for v in values {
                let text = match v {
                    toml::Value::String(s) => s.clone(),
                    toml::Value::Integer(i) => i.to_string(),
                    toml::Value::Float(f) => f.to_string(),
                    toml::Value::Boolean(b) => if *b { "1" } else { "0" }.to_string(),
                    _ => continue,
                };
                self.set(key, &text, true);
            }
        }
    }
}

/// Names that start with "no" but are not a negation in Divi Core's sense are
/// none: InterpretNegativeSetting strips "no" from any name. Kept as a hook.
fn is_known_no_word(_key: &str) -> bool {
    false
}

fn is_bool_word(v: &str) -> bool {
    matches!(v, "true" | "false" | "1" | "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Settings {
        Settings::from_command_line(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn command_line_reads_both_forms() {
        let s = cli(&[
            "-datadir=/d",
            "--rpcport",
            "1",
            "-rpcport=2",
            "-daemon",
            "-nolisten",
            "-foo=bar",
            "--txindex",
            "--staking",
            "false",
            "-c",
            "/c.conf",
        ]);
        assert_eq!(s.get("datadir"), Some("/d"));
        assert_eq!(
            s.get("rpcport"),
            Some("2"),
            "the last command-line value wins"
        );
        assert!(s.get_bool("daemon", false));
        assert!(!s.get_bool("listen", true));
        assert_eq!(s.get("foo"), Some("bar"));
        assert!(s.get_bool("txindex", false));
        assert!(!s.get_bool("staking", true));
        assert_eq!(s.get("conf"), Some("/c.conf"));
        // divid's -name takes no value from the next argument
        let s = cli(&["-datadir", "/d"]);
        assert_eq!(s.get("datadir"), Some(""));
        assert_eq!(s.stray, vec!["/d".to_string()]);
    }

    #[test]
    fn config_file_fills_what_the_command_line_left_unset() {
        let mut s = cli(&["-port=1", "-addnode=a"]);
        s.read_config(
            "port=2\nrpcport=3 # comment\nrpcport=4\naddnode=b\naddnode=c\nnolisten=1\n\
             regtest.timeout=7\n[test]\nmaxconnections=9\nbare\nstaking=true\n",
        );
        assert_eq!(s.get("port"), Some("1"));
        assert_eq!(s.get("rpcport"), Some("3"), "the file's first value wins");
        assert_eq!(s.get_multi("addnode"), ["a", "b", "c"]);
        assert!(!s.get_bool("listen", true));
        assert_eq!(s.get("maxconnections"), Some("9"));
        assert_eq!(s.get("timeout"), Some("7"));
        assert!(s.get_bool("bare", false));
        assert!(!s.get_bool("staking", true), "atoi(\"true\") is 0");
    }

    #[test]
    fn atoi_is_c_s() {
        assert_eq!(atoi("12abc"), 12);
        assert_eq!(atoi(" -3"), -3);
        assert_eq!(atoi("true"), 0);
        assert_eq!(atoi(""), 0);
    }
}
