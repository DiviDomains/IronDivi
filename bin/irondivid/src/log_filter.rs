//! Which log lines are written: a level for IronDivi as a whole, and a level
//! per category, from `-loglevel=` and `-debug=` (command line or config file)
//! or the `setlogconfig` RPC. RUST_LOG, when set, replaces all of it.
//!
//! - `loglevel=<level>`: every IronDivi category at that level
//! - `loglevel=<category>:<level>`: one category (repeat, or separate by commas)
//! - `debug=<category>`: that category at debug; `debug`, `debug=1` and
//!   `debug=all` are every category; `debug=0` none
//!
//! Levels are off, error, warn, info, debug, trace. With nothing set the
//! node writes info for its own code and warn for the libraries it uses.

use std::collections::BTreeMap;

/// The log categories and the code (tracing targets) each one covers
pub const CATEGORIES: &[(&str, &[&str])] = &[
    ("net", &["divi_network"]),
    ("sync", &["divi_network::sync"]),
    (
        "peers",
        &[
            "divi_network::peer_manager",
            "divi_network::connection",
            "divi_network::addrbook",
        ],
    ),
    ("node", &["divi_node"]),
    ("mempool", &["divi_node::mempool"]),
    (
        "staking",
        &["divi_node::staker", "divi_storage::stake_modifier"],
    ),
    (
        "chain",
        &["divi_storage", "divi_consensus", "divi_node::block_import"],
    ),
    ("wallet", &["divi_wallet"]),
    (
        "masternode",
        &["divi_masternode", "divi_network::masternode_handler"],
    ),
    ("spork", &["divi_network::spork", "divi_storage::spork"]),
    ("rpc", &["divi_rpc"]),
    ("electrum", &["divi_electrum"]),
    ("webui", &["divi_webui"]),
    ("swap", &["divi_swap", "swap_"]),
    ("zmq", &["zmq", "divi_node::zmq"]),
    ("daemon", &["irondivid"]),
];

/// Every target of IronDivi's own code (`swap_` covers the swap-* crates)
const OUR_TARGETS: &[&str] = &["divi_", "swap_", "zmq", "irondivid"];

/// The level of everything that is not IronDivi's own code
const LIBRARY_LEVEL: &str = "warn";

/// The level of IronDivi's own code when nothing else is set
pub const DEFAULT_LEVEL: &str = "info";

const LEVELS: &[&str] = &["off", "error", "warn", "info", "debug", "trace"];

/// What `-loglevel` and `-debug` asked for
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLevels {
    /// The level of all of IronDivi's code
    pub base: String,
    /// Categories at a level other than `base`, by name
    pub categories: BTreeMap<String, String>,
    /// Category names that are not known (still accepted, they match nothing)
    pub unknown: Vec<String>,
}

impl Default for LogLevels {
    fn default() -> Self {
        LogLevels {
            base: DEFAULT_LEVEL.to_string(),
            categories: BTreeMap::new(),
            unknown: Vec::new(),
        }
    }
}

fn level(value: &str, what: &str) -> Result<String, String> {
    let v = value.trim().to_ascii_lowercase();
    if LEVELS.contains(&v.as_str()) {
        Ok(v)
    } else {
        Err(format!(
            "invalid log level '{}' in {} (use one of {})",
            value.trim(),
            what,
            LEVELS.join(", ")
        ))
    }
}

impl LogLevels {
    /// Read `-debug` and `-loglevel` values, as the command line and config
    /// file give them (each may repeat and hold commas)
    pub fn parse(debug: &[String], loglevel: &[String]) -> Result<LogLevels, String> {
        let mut out = LogLevels::default();
        // -debug=0 anywhere turns -debug off, as in divid
        if !debug.iter().any(|d| d.trim() == "0") {
            for item in debug.iter().flat_map(|d| d.split(',')) {
                let item = item.trim().to_ascii_lowercase();
                match item.as_str() {
                    "" | "1" | "all" => out.base = "debug".to_string(),
                    _ => out.set_category(&item, "debug"),
                }
            }
        }
        for item in loglevel.iter().flat_map(|l| l.split(',')) {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            match item.split_once(':') {
                Some((cat, lvl)) => {
                    let lvl = level(lvl, &format!("-loglevel={}", item))?;
                    out.set_category(&cat.trim().to_ascii_lowercase(), &lvl);
                }
                None => out.base = level(item, &format!("-loglevel={}", item))?,
            }
        }
        Ok(out)
    }

    /// Read the argument of `setlogconfig`: the same `loglevel` syntax, with
    /// `debug` for every category at debug and `default` for the start-up
    /// default
    pub fn parse_spec(spec: &str) -> Result<LogLevels, String> {
        match spec.trim().to_ascii_lowercase().as_str() {
            "" | "default" => Ok(LogLevels::default()),
            _ => LogLevels::parse(&[], &[spec.to_string()]),
        }
    }

    fn set_category(&mut self, cat: &str, lvl: &str) {
        if !CATEGORIES.iter().any(|(name, _)| *name == cat)
            && !self.unknown.iter().any(|u| u == cat)
        {
            self.unknown.push(cat.to_string());
        }
        self.categories.insert(cat.to_string(), lvl.to_string());
    }

    /// Whether any of IronDivi's code writes debug or trace lines
    pub fn is_debug(&self) -> bool {
        let verbose = |l: &str| l == "debug" || l == "trace";
        verbose(&self.base) || self.categories.values().any(|l| verbose(l))
    }

    /// The `loglevel` value that means these levels (shown by getlogconfig)
    pub fn spec(&self) -> String {
        let mut parts = vec![self.base.clone()];
        parts.extend(self.categories.iter().map(|(c, l)| format!("{}:{}", c, l)));
        parts.join(",")
    }

    /// The tracing filter directives for these levels
    pub fn directives(&self) -> String {
        // A longer target wins over a shorter one, so a category beats the
        // base level and `sync` beats `net`, whatever order they were given
        let mut targets: BTreeMap<&str, &str> = BTreeMap::new();
        for t in OUR_TARGETS {
            targets.insert(t, &self.base);
        }
        for (cat, lvl) in &self.categories {
            if let Some((_, ts)) = CATEGORIES.iter().find(|(name, _)| name == cat) {
                for t in *ts {
                    targets.insert(t, lvl);
                }
            }
        }
        let mut out = vec![LIBRARY_LEVEL.to_string()];
        out.extend(targets.iter().map(|(t, l)| format!("{}={}", t, l)));
        out.join(",")
    }
}

/// The category names, for help text and errors
pub fn category_names() -> String {
    CATEGORIES
        .iter()
        .map(|(n, _)| *n)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn nothing_set_is_info_for_ours_and_warn_for_libraries() {
        let l = LogLevels::parse(&[], &[]).unwrap();
        assert!(!l.is_debug());
        assert_eq!(l.spec(), "info");
        assert_eq!(
            l.directives(),
            "warn,divi_=info,irondivid=info,swap_=info,zmq=info"
        );
    }

    #[test]
    fn debug_with_no_category_is_everything() {
        for v in ["", "1", "all"] {
            let l = LogLevels::parse(&s(&[v]), &[]).unwrap();
            assert_eq!(l.base, "debug", "-debug={}", v);
        }
    }

    #[test]
    fn debug_zero_turns_it_off() {
        let l = LogLevels::parse(&s(&["net", "0"]), &[]).unwrap();
        assert_eq!(l, LogLevels::default());
    }

    #[test]
    fn debug_category_is_that_category_only() {
        let l = LogLevels::parse(&s(&["sync", "rpc,wallet"]), &[]).unwrap();
        assert_eq!(l.base, "info");
        assert_eq!(l.spec(), "info,rpc:debug,sync:debug,wallet:debug");
        let d = l.directives();
        assert!(d.contains("divi_network::sync=debug"), "{}", d);
        assert!(d.contains("divi_rpc=debug"), "{}", d);
        assert!(d.contains("divi_wallet=debug"), "{}", d);
        assert!(d.contains("divi_=info"), "{}", d);
    }

    #[test]
    fn loglevel_sets_the_base_and_categories() {
        let l = LogLevels::parse(&[], &s(&["warn", "sync:trace,peers:off"])).unwrap();
        assert_eq!(l.base, "warn");
        let d = l.directives();
        assert!(d.contains("divi_=warn"), "{}", d);
        assert!(d.contains("divi_network::sync=trace"), "{}", d);
        assert!(d.contains("divi_network::connection=off"), "{}", d);
        assert!(l.is_debug());
    }

    #[test]
    fn the_last_value_for_a_category_wins() {
        let l = LogLevels::parse(&s(&["net"]), &s(&["net:error"])).unwrap();
        assert_eq!(l.categories["net"], "error");
    }

    #[test]
    fn an_invalid_level_is_an_error() {
        assert!(LogLevels::parse(&[], &s(&["sync:verbose"])).is_err());
        assert!(LogLevels::parse(&[], &s(&["loud"])).is_err());
    }

    #[test]
    fn an_unknown_category_is_kept_and_reported() {
        let l = LogLevels::parse(&s(&["nosuch"]), &[]).unwrap();
        assert_eq!(l.unknown, ["nosuch"]);
        assert!(!l.directives().contains("nosuch"));
    }

    #[test]
    fn every_directive_string_is_accepted_by_tracing() {
        let mut all = vec![];
        for (cat, _) in CATEGORIES {
            all.push(format!("{}:trace", cat));
        }
        let l = LogLevels::parse(&[], &all).unwrap();
        tracing_subscriber::EnvFilter::try_new(l.directives()).unwrap();
        tracing_subscriber::EnvFilter::try_new(LogLevels::default().directives()).unwrap();
    }

    #[test]
    fn a_spec_reads_back_to_the_same_levels() {
        let l = LogLevels::parse(&s(&["staking"]), &s(&["warn", "rpc:error"])).unwrap();
        assert_eq!(LogLevels::parse_spec(&l.spec()).unwrap(), l);
        assert_eq!(
            LogLevels::parse_spec("default").unwrap(),
            LogLevels::default()
        );
        assert_eq!(LogLevels::parse_spec("debug").unwrap().base, "debug");
    }
}
