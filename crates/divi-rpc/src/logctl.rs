// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The log filter while the daemon runs: the overall level (`-loglevel`) and
//! divid's debug categories (`-debug=<category>`) both change live, through
//! `setlogconfig` and the web interface. The daemon installs the control
//! once with its reloadable filter; the last lines logged are kept in memory
//! for the web interface's log view.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::OnceLock;

use parking_lot::Mutex;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::{EnvFilter, Layer};

/// The levels `-loglevel` takes, quietest first
pub const LEVELS: &[&str] = &["off", "error", "warn", "info", "debug", "trace"];

/// divid's and irondivid's debug categories and the code each one turns to
/// debug. "1" and "all" are every category; "0" is none.
pub const CATEGORIES: &[(&str, &[&str])] = &[
    ("net", &["divi_network"]),
    ("sync", &["divi_network::sync"]),
    ("peers", &["divi_network::peer"]),
    (
        "addrman",
        &["divi_network::addrman", "divi_network::peer_manager"],
    ),
    ("node", &["divi_node"]),
    ("mempool", &["divi_node::mempool", "divi_node::orphans"]),
    ("estimatefee", &["divi_node::fee_estimator"]),
    (
        "staking",
        &[
            "divi_node::staker",
            "divi_rpc::staking",
            "divi_wallet::coinstake",
        ],
    ),
    ("chain", &["divi_storage", "divi_consensus"]),
    ("wallet", &["divi_wallet", "divi_rpc::wallet"]),
    ("selectcoins", &["divi_wallet::coin_selection"]),
    ("rpc", &["divi_rpc"]),
    ("http", &["divi_rpc::http", "divi_rpc::rest"]),
    ("zmq", &["divi_node::zmq"]),
    ("db", &["divi_storage"]),
    ("reindex", &["divi_node::block_import", "divi_storage"]),
    ("validation", &["divi_consensus", "divi_node::node"]),
    (
        "masternode",
        &[
            "divi_masternode",
            "divi_rpc::masternode",
            "divi_rpc::mn_list",
            "divi_rpc::mn_votes",
            "divi_rpc::mn_broadcast",
        ],
    ),
    ("spork", &["divi_network::spork", "divi_rpc::spork"]),
    ("electrum", &["divi_electrum"]),
    ("webui", &["divi_webui"]),
    (
        "swap",
        &[
            "divi_swap",
            "swap_adaptor",
            "swap_keys",
            "swap_chain_divi",
            "swap_chain_btc",
            "swap_chain_ltc",
            "swap_chain_zec",
            "swap_chain_evm",
            "swap_chain_xmr",
        ],
    ),
    ("daemon", &["irondivid"]),
];

/// The filter now in force
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LogState {
    /// The overall level
    pub level: String,
    /// The debug categories on; "all" alone when every one is
    pub categories: Vec<String>,
    /// RUST_LOG was set at start: it wins, and nothing here changes it
    pub env_override: bool,
}

impl LogState {
    /// The `loglevel` spec string corresponding to this state
    pub fn spec(&self) -> String {
        if self.categories.iter().any(|c| c == "all") {
            return "debug".to_string();
        }
        let mut out = self.level.clone();
        for c in &self.categories {
            let _ = write!(out, ",{c}:debug");
        }
        out
    }
}

type Reload = Box<dyn Fn(&str, &LogState) -> Result<(), String> + Send + Sync>;

/// The installed control: how to swap the filter and what it is now
pub struct LogControl {
    reload: Reload,
    state: Mutex<LogState>,
    ring: Mutex<Ring>,
}

static CONTROL: OnceLock<LogControl> = OnceLock::new();

/// Lines kept for the log view
const RING_LINES: usize = 2000;

#[derive(Default)]
struct Ring {
    next: u64,
    lines: VecDeque<LogLine>,
}

/// One logged line, numbered so a reader can ask for what came after
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub seq: u64,
    /// Unix time in milliseconds
    pub time: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// The filter directives for an overall level and a set of categories
pub fn directives(level: &str, categories: &[String]) -> Result<String, String> {
    let level = level.trim().to_lowercase();
    if !LEVELS.contains(&level.as_str()) {
        return Err(format!(
            "unknown log level '{level}' (one of {})",
            LEVELS.join(", ")
        ));
    }
    let mut out = level.clone();
    let debug_idx = LEVELS.iter().position(|x| *x == "debug").unwrap_or(4);
    let quieter = |l: &str| LEVELS.iter().position(|x| *x == l) < Some(debug_idx);
    for c in categories {
        let c = c.trim().to_lowercase();
        if c == "1" || c == "all" {
            // Every category, on top of whatever level is quieter than debug
            if quieter(&level) {
                out = "debug".into();
            }
            continue;
        }
        let Some((_, targets)) = CATEGORIES.iter().find(|(name, _)| *name == c) else {
            return Err(format!("unknown debug category '{c}'"));
        };
        if quieter(&level) {
            for t in *targets {
                let _ = write!(out, ",{t}=debug");
            }
        }
    }
    Ok(out)
}

/// The categories as `-debug` gives them: none for "0", "all" for "1"
pub fn normalize(categories: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in categories {
        let c = c.trim().to_lowercase();
        if c.is_empty() {
            continue;
        }
        if c == "0" || c == "none" {
            return Vec::new();
        }
        let c = if c == "1" { "all".to_string() } else { c };
        if !out.contains(&c) {
            out.push(c);
        }
    }
    if out.iter().any(|c| c == "all") {
        return vec!["all".into()];
    }
    out
}

/// Install the control (once; later calls are ignored)
pub fn install(
    reload: impl Fn(&str, &LogState) -> Result<(), String> + Send + Sync + 'static,
    state: LogState,
) {
    let _ = CONTROL.set(LogControl {
        reload: Box::new(reload),
        state: Mutex::new(state),
        ring: Mutex::new(Ring::default()),
    });
}

/// The control, once the daemon has installed it
pub fn control() -> Option<&'static LogControl> {
    CONTROL.get()
}

impl LogControl {
    pub fn state(&self) -> LogState {
        self.state.lock().clone()
    }

    /// Record new state after `setlogconfig` updated the filter directly
    pub fn sync_state(&self, level: &str, categories: Vec<String>) {
        let mut state = self.state.lock();
        state.level = level.to_string();
        state.categories = categories;
    }

    /// Change the level, the categories or both, at once
    pub fn set(
        &self,
        level: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<LogState, String> {
        let mut state = self.state.lock();
        if state.env_override {
            return Err(
                "RUST_LOG is set; it decides what is logged until a restart without it".into(),
            );
        }
        let level = level.unwrap_or(&state.level).trim().to_lowercase();
        let categories = match categories {
            Some(c) => normalize(c),
            None => state.categories.clone(),
        };
        let filter = directives(&level, &categories)?;
        EnvFilter::try_new(&filter).map_err(|e| e.to_string())?;
        let next = LogState {
            level,
            categories,
            env_override: false,
        };
        (self.reload)(&filter, &next)?;
        *state = next.clone();
        Ok(next)
    }

    /// The kept lines after `after`, at most `limit`, oldest first
    pub fn lines_after(&self, after: u64, limit: usize) -> (Vec<LogLine>, u64) {
        let ring = self.ring.lock();
        let lines: Vec<LogLine> = ring
            .lines
            .iter()
            .filter(|l| l.seq > after)
            .take(limit)
            .cloned()
            .collect();
        (lines, ring.next)
    }

    fn push(&self, mut line: LogLine) {
        let mut ring = self.ring.lock();
        ring.next += 1;
        line.seq = ring.next;
        if ring.lines.len() >= RING_LINES {
            ring.lines.pop_front();
        }
        ring.lines.push_back(line);
    }
}

/// The layer that copies each line the filter lets through into memory
pub struct RingLayer;

impl<S: Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(control) = control() else { return };
        let mut text = Text::default();
        event.record(&mut text);
        let meta = event.metadata();
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        control.push(LogLine {
            seq: 0,
            time,
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message: text.0,
        });
    }
}

#[derive(Default)]
struct Text(String);

impl Visit for Text {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, "{}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(value);
        } else {
            self.record_debug(field, &value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn categories_become_targets() {
        assert_eq!(directives("off", &[]).unwrap(), "off");
        assert_eq!(directives("info", &[]).unwrap(), "info");
        assert_eq!(
            directives("info", &v(&["wallet"])).unwrap(),
            "info,divi_wallet=debug,divi_rpc::wallet=debug"
        );
        assert_eq!(directives("warn", &v(&["all"])).unwrap(), "debug");
        // At debug or trace the categories add nothing
        assert_eq!(directives("trace", &v(&["net"])).unwrap(), "trace");
        assert!(directives("loud", &[]).is_err());
        assert!(directives("info", &v(&["nosuch"])).is_err());
        for (_, targets) in CATEGORIES {
            for t in *targets {
                EnvFilter::try_new(format!("info,{t}=debug")).unwrap();
            }
        }
    }

    #[test]
    fn normalize_follows_divid() {
        assert_eq!(normalize(&v(&["net", "0"])), Vec::<String>::new());
        assert_eq!(normalize(&v(&["1"])), v(&["all"]));
        assert_eq!(normalize(&v(&["net", "all"])), v(&["all"]));
        assert_eq!(normalize(&v(&["Net", "net", "rpc"])), v(&["net", "rpc"]));
    }
}
