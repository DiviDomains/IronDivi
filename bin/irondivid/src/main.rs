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

//! IronDivi Daemon
//!
//! The main daemon process for IronDivi - a Rust implementation of the Divi node.
//!
//! Usage:
//!   irondivid [OPTIONS]
//!
//! Examples:
//!   irondivid --regtest --printtoconsole
//!   irondivid --testnet --datadir=/path/to/data
//!   irondivid --rpcuser=user --rpcpassword=pass

mod private_files;
mod snapshot_sig;

use anyhow::{Context, Result};
use clap::builder::BoolishValueParser;
use clap::Parser;
use divi_crypto::compute_block_hash;
use divi_node::config::{LogConfig, NetworkType, NodeConfig};
use divi_node::{Node, Staker, StakingConfig};
use divi_primitives::amount::Amount;
use divi_primitives::transaction::Transaction;
use divi_primitives::ChainMode;
use divi_rpc::{start_server_with_wallet_peer_and_staker, RpcConfig};
use divi_wallet::{HdWallet, Network as WalletNetwork, WalletDb};
use std::error::Error as StdError;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// IronDivi Daemon - Rust implementation of Divi node
#[derive(Parser, Debug, Clone)]
#[command(name = "irondivid")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "IronDivi daemon - Rust implementation of Divi full node")]
#[command(long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long = "conf")]
    conf: Option<PathBuf>,

    /// Data directory
    #[arg(short = 'd', long = "datadir")]
    datadir: Option<PathBuf>,

    /// Use testnet
    #[arg(long)]
    testnet: bool,

    /// Use regtest (regression test mode)
    #[arg(long)]
    regtest: bool,

    /// Chain mode: divi (default) or privatedivi
    #[arg(long, value_parser = ["divi", "privatedivi"])]
    mode: Option<String>,

    /// Run in background as daemon
    #[arg(long)]
    daemon: bool,

    /// Print to console instead of log file
    #[arg(long)]
    printtoconsole: bool,

    /// RPC username
    #[arg(long)]
    rpcuser: Option<String>,

    /// RPC password
    #[arg(long)]
    rpcpassword: Option<String>,

    /// RPC port
    #[arg(long)]
    rpcport: Option<u16>,

    /// RPC bind address
    #[arg(long)]
    rpcbind: Option<String>,

    /// RPC credentials as `user:salt$hash` (see share/rpcauth); repeatable
    #[arg(long = "rpcauth")]
    rpcauth: Vec<String>,

    /// Methods a user may call, as `user:method,method`; repeatable
    #[arg(long = "rpcwhitelist")]
    rpcwhitelist: Vec<String>,

    /// Whether users without an rpcwhitelist entry are refused (default: true once
    /// any rpcwhitelist is set)
    #[arg(long)]
    rpcwhitelistdefault: Option<bool>,

    /// Non-loopback address or range (CIDR) allowed to connect to RPC; repeatable
    #[arg(long = "rpcallowip")]
    rpcallowip: Vec<String>,

    /// Browser origin (e.g. `https://wallet.example`) allowed to call RPC; repeatable
    #[arg(long = "rpcalloworigin")]
    rpcalloworigin: Vec<String>,

    /// Host name accepted in the HTTP `Host` header of RPC requests; repeatable
    #[arg(long = "rpcallowhost")]
    rpcallowhost: Vec<String>,

    /// P2P port
    #[arg(long)]
    port: Option<u16>,

    /// P2P bind address
    #[arg(long)]
    bind: Option<String>,

    /// Add a node to connect to
    #[arg(long = "addnode")]
    addnode: Vec<String>,

    /// Keep a connection to a full-history node (a pruned node fetches old blocks from it)
    #[arg(long = "fullnode")]
    fullnode: Vec<String>,

    /// Connect only to specified node(s)
    #[arg(long = "connect")]
    connect: Vec<String>,

    /// How many of the newest blocks to check at start (default 100; 0 = all blocks)
    #[arg(long, value_name = "N")]
    checkblocks: Option<u32>,

    /// Make outbound P2P connections through this SOCKS5 proxy (ip:port, port 9050 if
    /// omitted). DNS seeds are then not resolved locally.
    #[arg(long, value_name = "IP:PORT")]
    proxy: Option<String>,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Wallet directory (default: datadir/wallet)
    #[arg(long)]
    wallet: Option<PathBuf>,

    /// Disable wallet (run without wallet support)
    #[arg(long)]
    disablewallet: bool,

    /// Enable transaction index (required for PoS validation and getrawtransaction RPC;
    /// default on). Unset keeps the config-file value.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", value_parser = BoolishValueParser::new())]
    txindex: Option<bool>,

    /// Start the staker at boot (`--staking=false` = C++ `-staking=0`; RPC setstaking can still start it)
    #[arg(long)]
    staking: Option<bool>,

    /// Stake even when the chain tip is older than 24h (restart a stalled network).
    /// Off by default: staking on a stale tip mints a private fork.
    #[arg(long)]
    stakeonstaletip: bool,

    /// Stake split threshold in DIVI, reported by getstakingstatus (C++ -stakesplitthreshold, default 20000)
    #[arg(long)]
    stakesplitthreshold: Option<f64>,

    /// Enable spent index for gettxout RPC. Unset keeps the config-file value.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", value_parser = BoolishValueParser::new())]
    spentindex: Option<bool>,

    /// Enable address index for address-based queries. Unset keeps the config-file value.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", value_parser = BoolishValueParser::new())]
    addressindex: Option<bool>,

    /// Export blockchain to JSON format (requires start and end height, and output directory)
    #[arg(long)]
    export_chain: bool,

    /// Start height for chain export
    #[arg(long, requires = "export_chain")]
    export_start: Option<u32>,

    /// End height for chain export
    #[arg(long, requires = "export_chain")]
    export_end: Option<u32>,

    /// Output directory for chain export
    #[arg(long, requires = "export_chain")]
    export_output: Option<PathBuf>,

    /// Write a thin chain-state snapshot of this node's chainstate into DIR (node must be stopped).
    #[arg(long, value_name = "DIR", conflicts_with = "import_snapshot")]
    export_snapshot: Option<PathBuf>,

    /// Install the snapshot in DIR as this node's chainstate (must be empty or missing), then exit.
    #[arg(long, value_name = "DIR")]
    import_snapshot: Option<PathBuf>,

    /// With --import-snapshot: refuse unless the snapshot's root hash equals this value.
    #[arg(long, value_name = "HEX", requires = "import_snapshot")]
    snapshot_root: Option<String>,

    /// Sign the root hash of the snapshot in DIR and write DIR/ROOT.sig. The 32-byte signing key
    /// is read from stdin as 64 hex characters (never as an argument), then the node exits.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["export_snapshot", "import_snapshot"])]
    sign_snapshot: Option<PathBuf>,

    /// Check DIR/ROOT.sig against --snapshot-signer, then exit.
    #[arg(long, value_name = "DIR", requires = "snapshot_signer", conflicts_with_all = ["export_snapshot", "import_snapshot", "sign_snapshot"])]
    verify_snapshot: Option<PathBuf>,

    /// Divi address whose key must have signed the snapshot's root hash. With --import-snapshot
    /// the import is refused unless DIR/ROOT.sig verifies against this address.
    #[arg(long, value_name = "ADDRESS")]
    snapshot_signer: Option<String>,

    /// UTXO cache size in number of entries (0 = disabled, default).
    /// Use 10000000 (~500MB) for memory-constrained systems.
    #[arg(long)]
    utxocachesize: Option<u64>,

    /// Discard block data older than this age so the node can stake without the full chain.
    /// Units: s, m (minutes), h, d, w, mo (months = 30d), y (years = 365d), e.g. 30d.
    /// -1 = never expire (default); 0 = keep only the minimum needed to stake and validate.
    /// Also settable via IRONDIVI_EXPIRE or `expire` in irondivi.conf (flag > env > conf).
    #[arg(long, allow_hyphen_values = true)]
    expire: Option<String>,

    /// Maximum log file size in MB (default: 1)
    #[arg(long)]
    maxlogsize: Option<u32>,

    /// Number of log files to keep (default: 5)
    #[arg(long)]
    maxlogfiles: Option<u32>,
}

impl Args {
    fn chain_mode(&self) -> ChainMode {
        parse_chain_mode(self.mode.as_deref().unwrap_or("divi"))
    }
}

fn parse_chain_mode(mode: &str) -> ChainMode {
    match mode {
        "privatedivi" => ChainMode::PrivateDivi,
        _ => ChainMode::Divi,
    }
}

/// Get the default data directory for the current platform
fn default_data_dir() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        #[cfg(target_os = "macos")]
        {
            home.join("Library")
                .join("Application Support")
                .join("IronDivi")
        }
        #[cfg(target_os = "windows")]
        {
            dirs::data_dir().unwrap_or(home.clone()).join("IronDivi")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            home.join(".irondivi")
        }
    } else {
        PathBuf::from(".irondivi")
    }
}

/// Load configuration from file if it exists.
///
/// Both formats are read: TOML (`rpcuser = "foo"`, what IronDivi documented) and the
/// Divi Core / Bitcoin `key=value` format (`rpcuser=foo`, `addnode=` repeated). A file
/// that parses as TOML is read as TOML, so existing files keep their meaning.
fn load_config_file(path: &PathBuf) -> Result<Option<toml::Table>> {
    if path.exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        let table = match content.parse::<toml::Table>() {
            Ok(table) => table,
            Err(_) => parse_divi_config(&content),
        };
        Ok(Some(normalize_config(table)))
    } else {
        Ok(None)
    }
}

/// Parse a Divi Core style config file: one `key=value` per line, `#` starts a comment,
/// surrounding whitespace is ignored, a bare `key` means `key=1`, a repeated key becomes
/// a list, and settings under a `[section]` header are ignored (C++ ReadConfigFile with
/// boost's config parser).
fn parse_divi_config(content: &str) -> toml::Table {
    let mut table = toml::Table::new();
    let mut section: Option<String> = None;
    for (n, raw) in content.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            warn!(
                "config file line {}: section {} is not supported; its settings are ignored",
                n + 1,
                line
            );
            section = Some(line.to_string());
            continue;
        }
        // Divi Core 3.0 ignores settings under a section header too
        if section.is_some() {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (line, "1"),
        };
        if key.is_empty() {
            warn!("config file line {}: no key, ignored", n + 1);
            continue;
        }
        let value = toml::Value::String(value.trim_matches('"').to_string());
        match table.get_mut(key) {
            Some(toml::Value::Array(list)) => list.push(value),
            Some(first) => {
                let first = first.clone();
                table.insert(key.to_string(), toml::Value::Array(vec![first, value]));
            }
            None => {
                table.insert(key.to_string(), value);
            }
        }
    }
    table
}

#[derive(Clone, Copy)]
enum ConfKind {
    Str,
    Int,
    Bool,
    List,
}

fn conf_kind(key: &str) -> Option<ConfKind> {
    use ConfKind::*;
    Some(match key {
        "rpcuser" | "rpcpassword" | "rpcbind" | "bind" | "proxy" | "mode" | "expire" => Str,
        "rpcport" | "port" | "checkblocks" | "maxlogsize" | "maxlogfiles" | "utxocachesize" => Int,
        "listen"
        | "testnet"
        | "regtest"
        | "daemon"
        | "printtoconsole"
        | "staking"
        | "stakeonstaletip"
        | "txindex"
        | "spentindex"
        | "addressindex"
        | "disablewallet"
        | "rpcwhitelistdefault" => Bool,
        "addnode" | "fullnode" | "connect" | "rpcauth" | "rpcwhitelist" | "rpcallowip"
        | "rpcalloworigin" | "rpcallowhost" => List,
        _ => return None,
    })
}

/// Give every known key the value type `apply_config_file` expects, whichever format the
/// file was in: `txindex=1` / `"1"` / `true` all become a boolean, `rpcport="51473"` an
/// integer, `rpcpassword = 12345` a string. A repeated single-value key keeps its last
/// value, as in C++. Values that do not convert are left for `apply_config_file` to warn about.
fn normalize_config(table: toml::Table) -> toml::Table {
    use toml::Value;
    let scalar_text = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Integer(i) => Some(i.to_string()),
        Value::Boolean(b) => Some(if *b { "1" } else { "0" }.to_string()),
        Value::Float(f) => Some(f.to_string()),
        _ => None,
    };
    table
        .into_iter()
        .map(|(key, value)| {
            let Some(kind) = conf_kind(&key) else {
                return (key, value);
            };
            let value = match (kind, value) {
                (ConfKind::List, v) => v,
                (_, Value::Array(list)) if !list.is_empty() => list.last().cloned().unwrap(),
                (_, v) => v,
            };
            let converted = match kind {
                ConfKind::List => None,
                ConfKind::Str => match &value {
                    Value::String(_) => None,
                    v => scalar_text(v).map(Value::String),
                },
                ConfKind::Int => match &value {
                    Value::String(s) => s.trim().parse::<i64>().ok().map(Value::Integer),
                    _ => None,
                },
                ConfKind::Bool => match &value {
                    Value::Integer(i) => Some(Value::Boolean(*i != 0)),
                    Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                        "1" | "true" | "yes" | "on" => Some(Value::Boolean(true)),
                        "0" | "false" | "no" | "off" => Some(Value::Boolean(false)),
                        other => other.parse::<i64>().ok().map(|i| Value::Boolean(i != 0)),
                    },
                    _ => None,
                },
            };
            (key, converted.unwrap_or(value))
        })
        .collect()
}

/// Where the config file is: `--conf`, else `irondivi.conf` in the data directory
fn config_path(args: &Args) -> PathBuf {
    args.conf
        .clone()
        .unwrap_or_else(|| compute_data_dir(args).join("irondivi.conf"))
}

/// Fill the options that are needed before the node config exists (network, chain mode,
/// daemon, console and log-file settings) from the config file when the command line does
/// not set them; the command line always wins. Pins `conf` to the file read, so a network
/// chosen by the file does not make the node look for a different file.
fn resolve_args(mut args: Args) -> Result<Args> {
    let path = config_path(&args);
    let Some(table) = load_config_file(&path)? else {
        return Ok(args);
    };
    let flag = |key: &str| table.get(key).and_then(|v| v.as_bool()).unwrap_or(false);
    if !args.testnet && !args.regtest {
        args.testnet = flag("testnet");
        args.regtest = flag("regtest");
    }
    if args.mode.is_none() {
        args.mode = table
            .get("mode")
            .and_then(|v| v.as_str())
            .filter(|m| matches!(*m, "divi" | "privatedivi"))
            .map(String::from);
    }
    args.daemon |= flag("daemon");
    args.printtoconsole |= flag("printtoconsole");
    args.disablewallet |= flag("disablewallet");
    // C++ debug= takes a category (debug=1, debug=net); anything but 0 turns debug logging on
    args.debug |= table
        .get("debug")
        .and_then(|v| match v {
            toml::Value::String(s) => Some(!matches!(s.trim(), "" | "0")),
            toml::Value::Integer(i) => Some(*i != 0),
            toml::Value::Boolean(b) => Some(*b),
            toml::Value::Array(list) => Some(!list.is_empty()),
            _ => None,
        })
        .unwrap_or(false);
    let positive = |key: &str| {
        table
            .get(key)
            .and_then(|v| v.as_integer())
            .filter(|i| *i > 0 && *i <= u32::MAX as i64)
            .map(|i| i as u32)
    };
    if args.maxlogsize.is_none() {
        args.maxlogsize = positive("maxlogsize");
    }
    if args.maxlogfiles.is_none() {
        args.maxlogfiles = positive("maxlogfiles").filter(|n| *n <= 100);
    }
    args.conf = Some(path);
    Ok(args)
}

/// Apply configuration values from TOML table to NodeConfig
/// The strings of a config value that may be given once or repeated
fn conf_strings(key: &str, value: &toml::Value) -> Vec<String> {
    let items = match value.as_array() {
        Some(arr) => arr.iter().collect(),
        None => vec![value],
    };
    items
        .into_iter()
        .filter_map(|v| {
            let s = v.as_str().map(String::from);
            if s.is_none() {
                warn!("Invalid {key} value in config file, expected string");
            }
            s
        })
        .collect()
}

/// Warn when a config file holding RPC credentials can be read by other users
fn warn_if_conf_exposed(path: &std::path::Path, file_config: &toml::Table) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let has_secret = ["rpcpassword", "rpcauth"]
            .iter()
            .any(|k| file_config.contains_key(*k));
        if let Ok(meta) = std::fs::metadata(path) {
            if has_secret && meta.permissions().mode() & 0o077 != 0 {
                warn!(
                    "{:?} holds RPC credentials and is readable by other users; run chmod 600 on it",
                    path
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, file_config);
}

fn apply_config_file(config: &mut NodeConfig, file_config: &toml::Table) {
    for (key, value) in file_config {
        match key.as_str() {
            // RPC settings
            "rpcuser" => {
                if let Some(s) = value.as_str() {
                    config.rpc.username = Some(s.to_string());
                } else {
                    warn!("Invalid rpcuser value in config file, expected string");
                }
            }
            "rpcpassword" => {
                if let Some(s) = value.as_str() {
                    config.rpc.password = Some(s.to_string());
                } else {
                    warn!("Invalid rpcpassword value in config file, expected string");
                }
            }
            "rpcport" => {
                if let Some(i) = value.as_integer() {
                    if i > 0 && i <= 65535 {
                        config.rpc.port = i as u16;
                    } else {
                        warn!("Invalid rpcport value in config file, must be 1-65535");
                    }
                } else {
                    warn!("Invalid rpcport value in config file, expected integer");
                }
            }
            "rpcbind" => {
                if let Some(s) = value.as_str() {
                    config.rpc.listen_addr = s.to_string();
                } else {
                    warn!("Invalid rpcbind value in config file, expected string");
                }
            }
            // P2P settings
            "port" => {
                if let Some(i) = value.as_integer() {
                    if i > 0 && i <= 65535 {
                        config.p2p.port = i as u16;
                    } else {
                        warn!("Invalid port value in config file, must be 1-65535");
                    }
                } else {
                    warn!("Invalid port value in config file, expected integer");
                }
            }
            "bind" => {
                if let Some(s) = value.as_str() {
                    config.p2p.listen_addr = s.to_string();
                } else {
                    warn!("Invalid bind value in config file, expected string");
                }
            }
            "checkblocks" => {
                if let Some(i) = value
                    .as_integer()
                    .filter(|i| (0..=u32::MAX as i64).contains(i))
                {
                    config.check_blocks = i as u32;
                } else {
                    warn!(
                        "Invalid checkblocks value in config file, expected a non-negative integer"
                    );
                }
            }
            "proxy" => {
                if let Some(s) = value.as_str() {
                    config.p2p.proxy = Some(s.to_string());
                } else {
                    warn!("Invalid proxy value in config file, expected string");
                }
            }
            "listen" => {
                if let Some(b) = value.as_bool() {
                    config.p2p.listen = Some(b);
                } else if let Some(i) = value.as_integer() {
                    config.p2p.listen = Some(i != 0);
                } else {
                    warn!("Invalid listen value in config file, expected boolean or integer");
                }
            }
            // Network type settings (only applied if not overridden by CLI)
            "testnet" => {
                if let Some(b) = value.as_bool() {
                    if b {
                        debug!("testnet=1 in config file (CLI flags take precedence)");
                    }
                } else if let Some(i) = value.as_integer() {
                    if i != 0 {
                        debug!("testnet=1 in config file (CLI flags take precedence)");
                    }
                }
            }
            "regtest" => {
                if let Some(b) = value.as_bool() {
                    if b {
                        debug!("regtest=1 in config file (CLI flags take precedence)");
                    }
                } else if let Some(i) = value.as_integer() {
                    if i != 0 {
                        debug!("regtest=1 in config file (CLI flags take precedence)");
                    }
                }
            }
            // Daemon mode (informational only, handled by CLI)
            "daemon" => {
                if let Some(b) = value.as_bool() {
                    if b {
                        debug!("daemon=1 in config file (use --daemon flag)");
                    }
                } else if let Some(i) = value.as_integer() {
                    if i != 0 {
                        debug!("daemon=1 in config file (use --daemon flag)");
                    }
                }
            }
            // Read before the node config is built (resolve_args)
            "disablewallet" | "debug" => {}
            "printtoconsole" => {
                if let Some(b) = value.as_bool() {
                    if b {
                        debug!("printtoconsole=1 in config file (use --printtoconsole flag)");
                    }
                } else if let Some(i) = value.as_integer() {
                    if i != 0 {
                        debug!("printtoconsole=1 in config file (use --printtoconsole flag)");
                    }
                }
            }
            "staking" => {
                if let Some(b) = value.as_bool() {
                    config.staking.enabled = b;
                } else if let Some(i) = value.as_integer() {
                    config.staking.enabled = i != 0;
                } else {
                    warn!("Invalid staking value in config file, expected boolean or integer");
                }
            }
            "stakeonstaletip" => {
                if let Some(b) = value.as_bool() {
                    config.staking.stake_on_stale_tip = b;
                } else if let Some(i) = value.as_integer() {
                    config.staking.stake_on_stale_tip = i != 0;
                } else {
                    warn!(
                        "Invalid stakeonstaletip value in config file, expected boolean or integer"
                    );
                }
            }
            "stakesplitthreshold" => {
                let divi = value
                    .as_float()
                    .or_else(|| value.as_integer().map(|i| i as f64))
                    .or_else(|| value.as_str().and_then(|s| s.parse().ok()));
                match divi {
                    Some(d) if d >= 0.0 => {
                        config.staking.split_threshold = (d * 100_000_000.0).round() as i64
                    }
                    _ => warn!("Invalid stakesplitthreshold value in config file, expected DIVI"),
                }
            }
            // Index settings
            "txindex" => {
                if let Some(b) = value.as_bool() {
                    config.index.txindex = b;
                } else if let Some(i) = value.as_integer() {
                    config.index.txindex = i != 0;
                } else {
                    warn!("Invalid txindex value in config file, expected boolean or integer");
                }
            }
            "spentindex" => {
                if let Some(b) = value.as_bool() {
                    config.index.spentindex = b;
                } else if let Some(i) = value.as_integer() {
                    config.index.spentindex = i != 0;
                } else {
                    warn!("Invalid spentindex value in config file, expected boolean or integer");
                }
            }
            "addressindex" => {
                if let Some(b) = value.as_bool() {
                    config.index.addressindex = b;
                } else if let Some(i) = value.as_integer() {
                    config.index.addressindex = i != 0;
                } else {
                    warn!("Invalid addressindex value in config file, expected boolean or integer");
                }
            }
            "rpcauth" => config.rpc.rpcauth.extend(conf_strings(key, value)),
            "rpcwhitelist" => config.rpc.whitelist.extend(conf_strings(key, value)),
            "rpcallowip" => config.rpc.allow_ips.extend(conf_strings(key, value)),
            "rpcalloworigin" => config.rpc.allow_origins.extend(conf_strings(key, value)),
            "rpcallowhost" => config.rpc.allow_hosts.extend(conf_strings(key, value)),
            "rpcwhitelistdefault" => {
                if let Some(b) = value.as_bool() {
                    config.rpc.whitelist_default = Some(b);
                } else {
                    warn!("Invalid rpcwhitelistdefault value in config file, expected boolean");
                }
            }
            // Peer settings
            "addnode" => {
                if let Some(s) = value.as_str() {
                    config.network.static_peers.push(s.to_string());
                } else if let Some(arr) = value.as_array() {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            config.network.static_peers.push(s.to_string());
                        } else {
                            warn!("Invalid addnode array element, expected string");
                        }
                    }
                } else {
                    warn!("Invalid addnode value in config file, expected string or array");
                }
            }
            "fullnode" => {
                if let Some(s) = value.as_str() {
                    config.network.static_peers.push(s.to_string());
                } else if let Some(arr) = value.as_array() {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            config.network.static_peers.push(s.to_string());
                        } else {
                            warn!("Invalid fullnode array element, expected string");
                        }
                    }
                } else {
                    warn!("Invalid fullnode value in config file, expected string or array");
                }
            }
            "connect" => {
                if let Some(s) = value.as_str() {
                    config.p2p.connect.push(s.to_string());
                    config.p2p.enable_discovery = false;
                } else if let Some(arr) = value.as_array() {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            config.p2p.connect.push(s.to_string());
                        } else {
                            warn!("Invalid connect array element, expected string");
                        }
                    }
                    config.p2p.enable_discovery = false;
                } else {
                    warn!("Invalid connect value in config file, expected string or array");
                }
            }
            // Logging settings
            "maxlogsize" => {
                if let Some(i) = value.as_integer() {
                    if i > 0 {
                        config.log.max_file_size = i as u64 * 1_048_576; // Convert MB to bytes
                    } else {
                        warn!("Invalid maxlogsize value in config file, must be positive");
                    }
                } else {
                    warn!("Invalid maxlogsize value in config file, expected integer");
                }
            }
            "maxlogfiles" => {
                if let Some(i) = value.as_integer() {
                    if i > 0 && i <= 100 {
                        config.log.max_files = i as u32;
                    } else {
                        warn!("Invalid maxlogfiles value in config file, must be 1-100");
                    }
                } else {
                    warn!("Invalid maxlogfiles value in config file, expected integer");
                }
            }
            "mode" => {
                if let Some(s) = value.as_str() {
                    match s {
                        "divi" | "privatedivi" => {
                            debug!("mode={} in config file (CLI flags take precedence)", s);
                        }
                        _ => {
                            warn!("Invalid mode value in config file, expected 'divi' or 'privatedivi'");
                        }
                    }
                } else {
                    warn!("Invalid mode value in config file, expected string");
                }
            }
            // UTXO cache
            "utxocachesize" => {
                if let Some(i) = value.as_integer() {
                    if i >= 0 {
                        config.utxo_cache_size = i as u64;
                    } else {
                        warn!("Invalid utxocachesize, must be >= 0");
                    }
                } else {
                    warn!("Invalid utxocachesize, expected integer");
                }
            }
            // Block-expiry pruning: "30d", "-1", "0" (a bare TOML integer -1 / 0 also works)
            "expire" => {
                let text = match (value.as_str(), value.as_integer()) {
                    (Some(s), _) => s.to_string(),
                    (None, Some(i)) => i.to_string(),
                    _ => {
                        eprintln!("Invalid expire in config file, expected string like \"30d\"");
                        std::process::exit(1);
                    }
                };
                match divi_storage::prune::Expire::parse(&text) {
                    Ok(e) => config.expire = e,
                    Err(e) => {
                        eprintln!("config file: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            // Unknown key - log warning
            _ => {
                warn!("Unknown configuration key in config file: {}", key);
            }
        }
    }
}

/// Build node configuration from CLI args and config file
fn build_config(args: &Args) -> Result<NodeConfig> {
    build_config_with_env(args, std::env::var("IRONDIVI_EXPIRE").ok())
}

/// `env_expire` is the value of `IRONDIVI_EXPIRE`; passed in so tests never mutate process env.
fn build_config_with_env(args: &Args, env_expire: Option<String>) -> Result<NodeConfig> {
    let args = &resolve_args(args.clone())?;
    let chain_mode = args.chain_mode();

    // Start with network-specific defaults
    let mut config = if args.regtest {
        NodeConfig::regtest(chain_mode)
    } else if args.testnet {
        NodeConfig::testnet(chain_mode)
    } else {
        NodeConfig::mainnet(chain_mode)
    };

    // Set data directory
    let data_dir = args.datadir.clone().unwrap_or_else(|| {
        let mut dir = default_data_dir();
        if args.chain_mode() == ChainMode::PrivateDivi {
            dir = dir.join("privatedivi");
        }
        if args.testnet {
            dir = dir.join("testnet");
        } else if args.regtest {
            dir = dir.join("regtest");
        }
        dir
    });
    config.data_dir = data_dir;

    // Try to load config file and apply its settings
    let conf_path = args
        .conf
        .clone()
        .unwrap_or_else(|| config.data_dir.join("irondivi.conf"));

    if let Some(file_config) = load_config_file(&conf_path)? {
        info!("Loaded config from {:?}", conf_path);
        warn_if_conf_exposed(&conf_path, &file_config);
        apply_config_file(&mut config, &file_config);
    }

    // Environment overrides the config file (and is itself overridden by the CLI below)
    if let Some(v) = env_expire {
        if !v.trim().is_empty() {
            config.expire = divi_storage::prune::Expire::parse(&v)
                .map_err(|e| anyhow::anyhow!("IRONDIVI_EXPIRE: {}", e))?;
        }
    }

    // Apply CLI overrides (these take precedence over config file)
    if let Some(rpcuser) = &args.rpcuser {
        config.rpc.username = Some(rpcuser.clone());
    }
    if let Some(rpcpassword) = &args.rpcpassword {
        warn!(
            "--rpcpassword on the command line is visible to every user of this machine \
             (ps, /proc); put it in the config file or use rpcauth instead"
        );
        config.rpc.password = Some(rpcpassword.clone());
    }
    config.rpc.rpcauth.extend(args.rpcauth.iter().cloned());
    config
        .rpc
        .whitelist
        .extend(args.rpcwhitelist.iter().cloned());
    if args.rpcwhitelistdefault.is_some() {
        config.rpc.whitelist_default = args.rpcwhitelistdefault;
    }
    config.rpc.allow_ips.extend(args.rpcallowip.iter().cloned());
    config
        .rpc
        .allow_origins
        .extend(args.rpcalloworigin.iter().cloned());
    config
        .rpc
        .allow_hosts
        .extend(args.rpcallowhost.iter().cloned());
    if let Some(rpcport) = args.rpcport {
        config.rpc.port = rpcport;
    }
    if let Some(rpcbind) = &args.rpcbind {
        config.rpc.listen_addr = rpcbind.clone();
    }
    if let Some(port) = args.port {
        config.p2p.port = port;
    }
    if let Some(bind) = &args.bind {
        config.p2p.listen_addr = bind.clone();
    }
    if let Some(n) = args.checkblocks {
        config.check_blocks = n;
    }
    if let Some(proxy) = &args.proxy {
        config.p2p.proxy = Some(proxy.clone());
    }
    if args.debug {
        config.debug.debug_logging = true;
        config.debug.log_rpc = true;
    }

    if let Some(staking) = args.staking {
        config.staking.enabled = staking;
    }
    if args.stakeonstaletip {
        config.staking.stake_on_stale_tip = true;
    }
    if let Some(divi) = args.stakesplitthreshold {
        config.staking.split_threshold = (divi * 100_000_000.0).round() as i64;
    }
    // Only flags given on the command line override the config file
    if let Some(b) = args.txindex {
        config.index.txindex = b;
    }
    if let Some(b) = args.spentindex {
        config.index.spentindex = b;
    }
    if let Some(b) = args.addressindex {
        config.index.addressindex = b;
    }

    if let Some(cache_size) = args.utxocachesize {
        config.utxo_cache_size = cache_size;
    }
    if let Some(v) = &args.expire {
        config.expire = divi_storage::prune::Expire::parse(v)
            .map_err(|e| anyhow::anyhow!("--expire: {}", e))?;
    }

    // Add static peers from CLI (append to any from config file)
    if !args.connect.is_empty() {
        // Connect-only: resolved by NodeConfig::peer_sources().
        config.p2p.connect.extend(args.connect.clone());
        config.p2p.enable_discovery = false; // Don't discover when using -connect
    } else {
        config.network.static_peers.extend(args.addnode.clone());
        config.network.static_peers.extend(args.fullnode.clone());
    }

    Ok(config)
}

/// Compute data directory from args (used before config is built)
fn compute_data_dir(args: &Args) -> PathBuf {
    args.datadir.clone().unwrap_or_else(|| {
        let mut dir = default_data_dir();
        if args.chain_mode() == ChainMode::PrivateDivi {
            dir = dir.join("privatedivi");
        }
        if args.testnet {
            dir = dir.join("testnet");
        } else if args.regtest {
            dir = dir.join("regtest");
        }
        dir
    })
}

/// Check if log file exceeds max size and rotate if needed
fn maybe_rotate_logs(log_dir: &std::path::Path, max_size: u64, max_files: u32) {
    let log_path = log_dir.join("debug.log");

    // Check current size
    if let Ok(metadata) = std::fs::metadata(&log_path) {
        if metadata.len() >= max_size {
            rotate_logs(log_dir, max_files);
        }
    }
}

/// Rotate log files: debug.log -> debug.log.1, .1 -> .2, etc.
fn rotate_logs(log_dir: &std::path::Path, max_files: u32) {
    // Delete oldest if it would exceed max_files
    let oldest = log_dir.join(format!("debug.log.{}", max_files - 1));
    let _ = std::fs::remove_file(&oldest);

    // Shift existing rotated files
    for i in (1..max_files - 1).rev() {
        let from = log_dir.join(format!("debug.log.{}", i));
        let to = log_dir.join(format!("debug.log.{}", i + 1));
        let _ = std::fs::rename(&from, &to);
    }

    // Rotate current log
    let current = log_dir.join("debug.log");
    let rotated = log_dir.join("debug.log.1");
    let _ = std::fs::rename(&current, &rotated);
}

/// Spawn background task to periodically check and rotate logs
fn spawn_log_rotation_task(data_dir: PathBuf, max_size: u64, max_files: u32) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60)); // Check every minute
            maybe_rotate_logs(&data_dir, max_size, max_files);
        }
    });
}

/// Initialize logging
fn init_logging(log_config: &LogConfig, data_dir: &PathBuf) {
    // Use RUST_LOG if set, otherwise use default based on debug config
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if log_config.debug {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    if log_config.print_to_console {
        // Log to console only
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(filter)
            .init();
    } else {
        // Log to file (debug.log in data directory) like C++ divid
        // Create data directory if it doesn't exist
        if let Err(e) = private_files::ensure_private_dir(data_dir, false) {
            eprintln!(
                "Warning: Could not create data directory {:?}: {}",
                data_dir, e
            );
            // Fall back to console logging
            tracing_subscriber::registry()
                .with(fmt::layer())
                .with(filter)
                .init();
            return;
        }

        // Check for rotation before starting (in case log is already too big)
        maybe_rotate_logs(data_dir, log_config.max_file_size, log_config.max_files);

        // Logs written before the umask was set may be readable by others (NODE-4)
        private_files::restrict_file(&data_dir.join("debug.log"));
        for i in 1..log_config.max_files {
            private_files::restrict_file(&data_dir.join(format!("debug.log.{}", i)));
        }

        // Create file appender - no rotation, just debug.log like C++ divid
        let file_appender = RollingFileAppender::new(Rotation::NEVER, data_dir, "debug.log");

        // Create a non-blocking writer to avoid blocking the async runtime
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // Store the guard in a static to keep the writer alive
        // This is safe because we only initialize logging once
        static GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
            std::sync::OnceLock::new();
        let _ = GUARD.set(_guard);

        // Set up file logging with timestamps
        tracing_subscriber::registry()
            .with(
                fmt::layer().with_writer(non_blocking).with_ansi(false), // No ANSI colors in file
            )
            .with(filter)
            .init();

        // Start background rotation task
        spawn_log_rotation_task(
            data_dir.clone(),
            log_config.max_file_size,
            log_config.max_files,
        );

        eprintln!("Logging to {:?}", data_dir.join("debug.log"));
        eprintln!(
            "Log rotation: max {} bytes per file, {} files kept",
            log_config.max_file_size, log_config.max_files
        );
    }
}

/// Print startup banner
fn print_banner(config: &NodeConfig) {
    let network = match config.network.network_type {
        NetworkType::Mainnet => "mainnet",
        NetworkType::Testnet => "testnet",
        NetworkType::Regtest => "regtest",
    };
    let chain = match config.network.chain_mode {
        ChainMode::Divi => "Divi",
        ChainMode::PrivateDivi => "PrivateDivi",
    };

    info!("========================================");
    info!("  IronDivi v{}", env!("CARGO_PKG_VERSION"));
    info!("  Rust implementation of Divi node");
    info!("========================================");
    info!("Chain: {} ({})", chain, network);
    info!("Data dir: {:?}", config.data_dir);
    info!("RPC: {}:{}", config.rpc.listen_addr, config.rpc.port);
    info!("P2P: {}:{}", config.p2p.listen_addr, config.p2p.port);
    info!("========================================");
}

/// Load or create wallet
fn load_or_create_wallet(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
) -> Result<Arc<WalletDb>> {
    let restoring = std::env::var("WALLET_MNEMONIC").ok();
    load_or_create_wallet_from(wallet_path, network, chain_mode, restoring)
}

/// Load the wallet at `wallet_path`, or create it: restored from `restoring`
/// when a mnemonic is given, otherwise from a fresh random seed.
fn load_or_create_wallet_from(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
    restoring: Option<String>,
) -> Result<Arc<WalletDb>> {
    // Try to open existing wallet
    if wallet_path.exists() {
        info!("Loading wallet from {:?}", wallet_path);
        // Only this user may read the wallet (NODE-3)
        if let Err(e) = private_files::ensure_private_dir(wallet_path, true) {
            warn!("Could not check the wallet directory permissions: {}", e);
        }
        let wallet = WalletDb::open(wallet_path, network)
            .with_context(|| format!("Failed to open wallet at {:?}", wallet_path))?;

        // Migrate chain_mode if needed (fixes wallets created before ChainMode was configurable)
        wallet
            .migrate_chain_mode(chain_mode)
            .with_context(|| "Failed to migrate wallet chain_mode")?;

        // As Divi Core at start: fill the keypool while the seed is in memory
        // (an encrypted wallet starts locked and is topped up on unlock)
        if !wallet.is_locked() {
            if let Err(e) = wallet.top_up_keypool() {
                warn!("Could not top up the keypool: {}", e);
            }
        }

        warn_if_unencrypted(&wallet);
        info!("Wallet loaded successfully");
        return Ok(Arc::new(wallet));
    }

    // Create new wallet (from WALLET_MNEMONIC env var if set, otherwise random)
    info!("Creating new wallet at {:?}", wallet_path);
    private_files::ensure_private_dir(wallet_path, true)
        .with_context(|| format!("Failed to create wallet directory: {:?}", wallet_path))?;

    let hd_wallet = if let Some(ref mnemonic) = restoring {
        // Use WALLET_CHAIN_MODE env var to override chain mode for mnemonic restore.
        // Falls back to the --mode flag value so PrivateDivi nodes derive correct addresses.
        let restore_chain_mode = std::env::var("WALLET_CHAIN_MODE")
            .ok()
            .map(|v| match v.to_lowercase().as_str() {
                "privatedivi" => ChainMode::PrivateDivi,
                "divi" => ChainMode::Divi,
                _ => chain_mode,
            })
            .unwrap_or(chain_mode);
        info!(
            "Restoring wallet from WALLET_MNEMONIC environment variable (chain_mode={:?})",
            restore_chain_mode
        );
        HdWallet::from_mnemonic(mnemonic, None, restore_chain_mode)
            .with_context(|| "Failed to restore HD wallet from mnemonic")?
    } else {
        HdWallet::new(chain_mode).with_context(|| "Failed to generate HD wallet")?
    };

    // Never log the mnemonic: logs go to journald and log files, which are
    // neither encrypted nor access-controlled like the wallet. Point the
    // operator at the RPC that returns it on demand instead.
    warn!("new wallet created; retrieve the seed with the dumphdinfo RPC");

    let wallet = WalletDb::create_persistent(wallet_path, network, hd_wallet)
        .with_context(|| "Failed to create wallet")?;

    // When restoring from mnemonic, pre-generate keys so the catch-up scan can find
    // UTXOs. They go into the keypool, as in Core, so the receiving and change
    // indices stay at 0: issuing them instead would put the next getnewaddress at
    // /0/{lookahead} and the next change output at /1/{lookahead}, past the gap
    // limit of other wallets restoring the same seed.
    if restoring.is_some() {
        let lookahead: u32 = std::env::var("WALLET_LOOKAHEAD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);
        info!(
            "Pre-generating {} receiving and {} change addresses for wallet recovery",
            lookahead, lookahead
        );
        let generated = wallet
            .refill_keypool(Some(lookahead * 2))
            .with_context(|| "Failed to pre-generate recovery keys")?;
        info!("Pre-generated {} addresses", generated);
    }

    // A new wallet starts with a full keypool, as in Divi Core
    if restoring.is_none() {
        wallet
            .top_up_keypool()
            .with_context(|| "Failed to fill the keypool")?;
    }

    // Save immediately
    wallet.save().with_context(|| "Failed to save wallet")?;

    warn_if_unencrypted(&wallet);
    info!("New wallet created successfully");
    Ok(Arc::new(wallet))
}

/// Say loudly that the seed and keys are stored in the clear (NODE-3). Staking keeps working
/// on an encrypted wallet: `walletpassphrase <passphrase> 0 true` unlocks it for staking only.
fn warn_if_unencrypted(wallet: &WalletDb) {
    if !wallet.is_encrypted() {
        warn!(
            "The wallet is NOT encrypted: its seed and private keys are stored in the clear. \
             Run encryptwallet, then walletpassphrase <passphrase> 0 true to keep staking."
        );
        eprintln!(
            "WARNING: the wallet is not encrypted; anyone who can read its files can spend \
             its coins. Run the encryptwallet RPC."
        );
    }
}

/// Put the wallet's unconfirmed transactions back into the mempool after a
/// restart (Core's ReacceptWalletTransactions), so a send made before the
/// node stopped can still confirm. Runs after the catch-up scan, which has
/// already dropped the ones mined meanwhile. A transaction whose inputs are
/// neither unspent on chain nor outputs of a transaction in the mempool can
/// never confirm (spent by another transaction while we were down): the
/// wallet forgets it, as it does when the mempool evicts one.
fn resubmit_wallet_txs(node: &Node, wallet: &Arc<WalletDb>) {
    let txs = wallet.unconfirmed_transactions();
    if txs.is_empty() {
        return;
    }
    let chain = node.chain();
    let mempool = node.mempool();
    let mut resubmitted = 0;
    for tx in txs {
        let txid = tx.txid();
        let inputs_available = tx.vin.iter().all(|input| {
            mempool.contains(&input.prevout.txid)
                || matches!(chain.get_utxo(&input.prevout), Ok(Some(_)))
        });
        // Same generous fee as a local RPC send (see set_tx_submit below)
        let fee = Amount::from_sat((tx.size() as i64) * 10_000);
        let result = if inputs_available {
            mempool.add(tx, fee).map_err(|e| e.to_string())
        } else {
            Err("inputs no longer available".to_string())
        };
        match result {
            Ok(_) => {
                resubmitted += 1;
                let relay = node.tx_relay().clone();
                tokio::spawn(async move {
                    relay.announce_tx(txid).await;
                });
            }
            Err(e) => {
                warn!(
                    "Unconfirmed wallet tx {} cannot be resubmitted ({}); forgetting it",
                    txid, e
                );
                wallet.remove_mempool_tx(&txid);
            }
        }
    }
    info!(
        "Resubmitted {} unconfirmed wallet transaction(s) to the mempool",
        resubmitted
    );
}

/// Run the daemon
async fn run_daemon(
    config: NodeConfig,
    wallet_path: Option<PathBuf>,
    disable_wallet: bool,
    shutdown_tx: broadcast::Sender<()>,
    shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    // Create data directory if it doesn't exist
    private_files::ensure_private_dir(&config.data_dir, false)
        .with_context(|| format!("Failed to create data directory: {:?}", config.data_dir))?;

    // Initialize the node
    info!("Initializing node...");
    let node = Node::new(config.clone()).with_context(|| "Failed to initialize node")?;

    // Start the node
    node.start().await.with_context(|| "Failed to start node")?;

    info!("Node started, chain height: {}", node.chain().height());

    // Get chain and peer manager references for RPC server
    let chain = node.chain().clone();
    let peer_manager = node.peer_manager().clone();

    // Load or create wallet (unless disabled)
    let wallet = if disable_wallet {
        info!("Wallet disabled");

        // Still need mempool cleanup + fee estimation callback even without wallet
        let block_sync = node.block_sync();
        let mempool_for_callback = node.mempool().clone();
        let fee_estimator_for_callback = node.fee_estimator().clone();
        let tx_relay_for_callback = node.tx_relay().clone();
        let chain_for_callback = node.chain().clone();
        block_sync.set_block_connected_callback(Arc::new(move |block, height| {
            let mut total_fees = divi_primitives::amount::Amount::from_sat(0);
            for tx in block.transactions.iter().skip(1) {
                if let Some(mempool_entry) = mempool_for_callback.get(&tx.txid()) {
                    total_fees += mempool_entry.fee;
                }
            }
            let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
            mempool_for_callback.remove_for_block(&txids);
            evict_block_conflicts(&mempool_for_callback, &chain_for_callback, block);
            for txid in &txids {
                tx_relay_for_callback.mark_seen(*txid);
            }
            fee_estimator_for_callback.add_block(height, block, total_fees);
        }));

        None
    } else {
        let wallet_dir = wallet_path.unwrap_or_else(|| config.data_dir.join("wallet"));
        let wallet_network = match config.network.network_type {
            NetworkType::Mainnet => WalletNetwork::Mainnet,
            NetworkType::Testnet => WalletNetwork::Testnet,
            NetworkType::Regtest => WalletNetwork::Regtest,
        };
        let wallet = Some(load_or_create_wallet(
            &wallet_dir,
            wallet_network,
            config.network.chain_mode,
        )?);

        // Register unified block-connected callback (mempool cleanup + fee estimation + wallet scan)
        if let Some(ref wallet_arc) = wallet {
            let wallet_for_scan = Arc::clone(wallet_arc);
            let block_sync = node.block_sync();
            let mempool_for_callback = node.mempool().clone();
            let fee_estimator_for_callback = node.fee_estimator().clone();
            let tx_relay_for_callback = node.tx_relay().clone();
            let chain_for_scan = node.chain().clone();
            block_sync.set_block_connected_callback(Arc::new(move |block, height| {
                let block_hash = compute_block_hash(&block.header);

                // 1. Bring the wallet up to the active tip (adds new UTXOs, removes spent
                // ones). The block handed in may be one of several connected by a reorg,
                // or a side-chain block, so scan the active chain itself, in order.
                // This runs before the mempool cleanup below so the wallet's mempool
                // entries for this block are replaced by confirmed records in one step;
                // otherwise a send would briefly show its inputs as unspent again.
                sync_wallet_to_tip(&wallet_for_scan, &chain_for_scan);

                // 2. Calculate fees from mempool entries and clean mempool
                let mut total_fees = divi_primitives::amount::Amount::from_sat(0);
                for tx in block.transactions.iter().skip(1) {
                    if let Some(mempool_entry) = mempool_for_callback.get(&tx.txid()) {
                        total_fees += mempool_entry.fee;
                    }
                }
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
                mempool_for_callback.remove_for_block(&txids);
                evict_block_conflicts(&mempool_for_callback, &chain_for_scan, block);
                for txid in &txids {
                    tx_relay_for_callback.mark_seen(*txid);
                }
                fee_estimator_for_callback.add_block(height, block, total_fees);

                // 3. Persist dirty wallet changes to database (incremental, not full rewrite)
                if let Err(e) = wallet_for_scan.save_incremental() {
                    error!("Failed to save wallet after block {}: {}", height, e);
                }

                debug!(
                    "Block {} at height {} processed (fees: {}, mempool cleaned, wallet scanned)",
                    block_hash,
                    height,
                    total_fees.as_sat()
                );
            }));
            info!("Unified block callback registered (mempool + fees + wallet)");

            // Mirror wallet-relevant mempool transactions into the wallet so
            // unconfirmed sends and receives show up immediately (0 confirmations).
            // The listeners fire for every path into and out of the mempool: P2P
            // relay, local RPC sends, confirmation, eviction and clearing.
            {
                let wallet_for_added = Arc::clone(wallet_arc);
                node.mempool()
                    .set_added_listener(Arc::new(move |tx: &Transaction| {
                        if wallet_for_added.add_mempool_tx(tx) {
                            info!("Wallet sees unconfirmed tx {}", tx.txid());
                        }
                    }));
                let wallet_for_removed = Arc::clone(wallet_arc);
                node.mempool()
                    .set_removed_listener(Arc::new(move |tx: &Transaction| {
                        wallet_for_removed.remove_mempool_tx(&tx.txid());
                    }));

                // P2P is already running, so pick up anything relayed before the
                // listener was in place. Oldest first so parents precede children;
                // duplicates from the listener racing this loop are ignored.
                let mempool = node.mempool();
                let mut pending: Vec<_> = mempool
                    .get_txids()
                    .iter()
                    .filter_map(|txid| mempool.get(txid))
                    .collect();
                pending.sort_by_key(|entry| std::cmp::Reverse(entry.age()));
                let seen = pending
                    .iter()
                    .filter(|entry| wallet_arc.add_mempool_tx(&entry.tx))
                    .count();
                if seen > 0 {
                    info!(
                        "Wallet picked up {} unconfirmed tx(s) already in the mempool",
                        seen
                    );
                }
            }

            // Register wallet reorg callback for chain reorganizations
            {
                let wallet_for_reorg = Arc::clone(wallet_arc);
                block_sync.set_reorg_callback(Arc::new(move |fork_height| {
                    info!(
                        "Chain reorg detected at fork height {} - updating wallet",
                        fork_height
                    );
                    wallet_for_reorg.handle_reorg(fork_height);
                    if let Err(e) = wallet_for_reorg.save() {
                        error!("Failed to save wallet after reorg: {}", e);
                    }
                }));
            }
            info!("Wallet reorg callback registered");

            // Register orphaned transaction callback: re-add txs from disconnected blocks
            // to the mempool so they can be re-mined on the new chain.
            {
                let mempool_for_orphans = node.mempool().clone();
                let chain_for_orphans = node.chain().clone();
                block_sync.set_orphaned_tx_callback(Arc::new(
                    move |orphaned_txs: Vec<Transaction>| {
                        info!(
                            "Reorg: re-adding {} orphaned transaction(s) to mempool",
                            orphaned_txs.len()
                        );
                        for tx in orphaned_txs {
                            let txid = tx.txid();
                            // Calculate fee by summing inputs minus outputs using the UTXO set
                            let fee = {
                                let mut input_total = Amount::from_sat(0);
                                let mut ok = true;
                                for input in &tx.vin {
                                    match chain_for_orphans.get_utxo(&input.prevout) {
                                        Ok(Some(utxo)) => {
                                            input_total += utxo.value;
                                        }
                                        _ => {
                                            // UTXO not found — tx may depend on another orphaned tx
                                            // that is also being re-added; skip fee check and use 0.
                                            ok = false;
                                            break;
                                        }
                                    }
                                }
                                if ok {
                                    let output_total: Amount = tx
                                        .vout
                                        .iter()
                                        .map(|o| o.value)
                                        .fold(Amount::from_sat(0), |a, b| a + b);
                                    if input_total >= output_total {
                                        input_total - output_total
                                    } else {
                                        Amount::from_sat(0)
                                    }
                                } else {
                                    Amount::from_sat(0)
                                }
                            };
                            match mempool_for_orphans.add(tx, fee) {
                                Ok(_) => {
                                    debug!(
                                        "Re-added orphaned tx {} to mempool (fee: {} sat)",
                                        txid,
                                        fee.as_sat()
                                    );
                                }
                                Err(e) => {
                                    debug!(
                                        "Could not re-add orphaned tx {} to mempool: {}",
                                        txid, e
                                    );
                                }
                            }
                        }
                        // The tip may now be lower: drop what can no longer be mined
                        mempool_for_orphans.remove_non_final();
                    },
                ));
            }
            info!("Orphaned transaction callback registered");

            // Catch-up scan: process blocks between last_scan_height and current chain tip.
            // Block notifications may already be arriving; they share the wallet's scan
            // lock and its scan height, so neither side skips or reorders a block.
            let last_scan = wallet_arc.last_scan_height();
            let chain_height = node.chain().height();
            if last_scan < chain_height {
                info!(
                    "Wallet catch-up scan: blocks {} to {}",
                    last_scan + 1,
                    chain_height
                );
                sync_wallet_to_tip(wallet_arc, node.chain());
                if let Err(e) = wallet_arc.save() {
                    error!("Failed to save wallet after catch-up scan: {}", e);
                }
                info!(
                    "Wallet catch-up scan complete (scan height {})",
                    wallet_arc.last_scan_height()
                );
            }

            // Reconcile wallet UTXOs against the chain UTXO set.
            // Removes phantom UTXOs left from orphaned staked blocks whose
            // spent_utxo_data was lost before it was persisted to disk.
            let chain_for_reconcile = node.chain().clone();
            let removed = wallet_arc.reconcile_utxos(|outpoint| {
                chain_for_reconcile
                    .get_utxo(outpoint)
                    .ok()
                    .flatten()
                    .is_some()
            });
            if removed > 0 {
                if let Err(e) = wallet_arc.save_incremental() {
                    error!("Failed to save wallet after UTXO reconciliation: {}", e);
                }
            }

            resubmit_wallet_txs(&node, wallet_arc);
        }

        wallet
    };

    // Block-expiry pruning: runs after the wallet catch-up scan above, then periodically.
    // Bodies within MIN_BLOCKS_TO_KEEP of the tip (and above the wallet's scan height)
    // are never touched, so a racing reorg cannot need pruned data.
    if node.config().expire.is_enabled() {
        let expire = node.config().expire;
        let chain_for_prune = node.chain().clone();
        let wallet_for_prune = wallet.clone();
        info!("Block-expiry pruning enabled: expire={:?}", expire);
        tokio::spawn(async move {
            loop {
                let floor = wallet_for_prune.as_ref().map(|w| w.last_scan_height());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let chain = chain_for_prune.clone();
                let res =
                    tokio::task::spawn_blocking(move || chain.prune_expired(expire, floor, now))
                        .await;
                match res {
                    Ok(Ok(0)) => {}
                    Ok(Ok(n)) => info!(
                        "Pruned {} blocks (prune height now {})",
                        n,
                        chain_for_prune.prune_height()
                    ),
                    Ok(Err(e)) => error!("Block pruning failed: {}", e),
                    Err(e) => error!("Block pruning task panicked: {}", e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }

    // Start staker if wallet is available
    let staker = if let Some(ref wallet_opt) = wallet {
        let wallet_arc = wallet_opt.clone();
        let mempool = node.mempool().clone();
        let staker_chain = node.chain().clone();
        let staker_peer_manager = node.peer_manager().clone();

        // Use regtest-friendly staking config
        let mut staking_config = StakingConfig {
            allow_stale_tip: config.staking.stake_on_stale_tip,
            stake_split_threshold: config.staking.split_threshold,
            ..StakingConfig::default()
        };
        if staking_config.allow_stale_tip {
            warn!(
                "-stakeonstaletip set: staking is allowed on a tip older than {}s",
                staking_config.max_tip_age_secs
            );
        }
        if config.network.network_type == NetworkType::Regtest {
            // Reduce minimum requirements for regtest
            staking_config.min_stake_amount = 1_000_000_000; // 10 DIVI (instead of 10,000)
            staking_config.min_coin_age = 60; // 1 minute (instead of 1 hour)
                                              // Regtest chains start from an old genesis; never apply the stale-tip guard.
            staking_config.allow_stale_tip = true;
        }

        let staker = Arc::new(Staker::new(
            wallet_arc.clone(),
            staker_chain,
            mempool,
            staker_peer_manager,
            staking_config,
        ));

        // Give the staker the same block-connected callback used by BlockSync
        // so that self-accepted staked blocks trigger wallet scanning, mempool
        // cleanup, and fee estimation without waiting for the P2P round-trip.
        {
            let wallet_for_staker = Arc::clone(&wallet_arc);
            let mempool_for_staker = node.mempool().clone();
            let fee_estimator_for_staker = node.fee_estimator().clone();
            let tx_relay_for_staker = node.tx_relay().clone();
            let chain_for_staker_scan = node.chain().clone();
            staker.set_block_connected_callback(Arc::new(move |block, height| {
                let block_hash = compute_block_hash(&block.header);

                // 1. Bring the wallet up to the active tip, before the mempool cleanup
                // (see the block-connected callback for why)
                sync_wallet_to_tip(&wallet_for_staker, &chain_for_staker_scan);

                // 2. Calculate fees from mempool entries and clean mempool
                let mut total_fees = divi_primitives::amount::Amount::from_sat(0);
                for tx in block.transactions.iter().skip(1) {
                    if let Some(mempool_entry) = mempool_for_staker.get(&tx.txid()) {
                        total_fees += mempool_entry.fee;
                    }
                }
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
                mempool_for_staker.remove_for_block(&txids);
                evict_block_conflicts(&mempool_for_staker, &chain_for_staker_scan, block);
                for txid in &txids {
                    tx_relay_for_staker.mark_seen(*txid);
                }
                fee_estimator_for_staker.add_block(height, block, total_fees);

                // 3. Persist wallet changes
                if let Err(e) = wallet_for_staker.save_incremental() {
                    error!(
                        "Failed to save wallet after self-accepted block {}: {}",
                        height, e
                    );
                }

                debug!(
                    "Self-accepted block {} at height {} processed (wallet + mempool + fees)",
                    block_hash, height
                );
            }));
            info!("Staker block callback registered (for self-accepted blocks)");
        }

        // Start the staking loop unless disabled (-staking=0)
        if config.staking.enabled {
            info!("Starting staker...");
            staker.clone().start().await;
        } else {
            warn!(
                "Staking disabled at startup (staking=false); use RPC setstaking true to start it"
            );
        }

        Some(staker)
    } else {
        None
    };

    // Start RPC server. RPC always requires authentication: without a complete
    // rpcuser/rpcpassword pair a random cookie is written to <datadir>/.cookie
    // (mode 0600) for local clients; `_rpc_cookie` removes it when we return.
    let (rpc_user, rpc_password, _rpc_cookie) = divi_rpc::resolve_rpc_auth(
        config.rpc.username.as_deref(),
        config.rpc.password.as_deref(),
        &config.data_dir,
    )
    .with_context(|| format!("Failed to write RPC cookie in {:?}", config.data_dir))?;
    match &_rpc_cookie {
        Some(cookie) => {
            if config.rpc.username.is_some() || config.rpc.password.is_some() {
                warn!("Only one of rpcuser/rpcpassword is set; using cookie authentication");
            }
            info!("RPC cookie authentication: {:?}", cookie.path());
        }
        None => info!("RPC authentication: rpcuser/rpcpassword"),
    }
    let rpc_config = RpcConfig {
        bind_address: config.rpc.socket_addr(),
        username: Some(rpc_user),
        password: Some(rpc_password),
        access: config.rpc.access(),
    };
    // Fail at startup, not on the first request, on a bad rpcauth/rpcwhitelist/
    // rpcallowip entry or a non-loopback bind without rpcallowip.
    divi_rpc::rpc_access(&rpc_config)
        .map_err(anyhow::Error::from)
        .and_then(|a| {
            a.check_bind(rpc_config.bind_address)
                .map_err(|e| anyhow::anyhow!(e))
        })
        .context("Invalid RPC configuration")?;

    info!("Starting RPC server on {}...", rpc_config.bind_address);

    // Run RPC server with shutdown handling
    let mut shutdown_rx = shutdown_rx;

    // RPC `stop` takes the same path as SIGTERM. The short delay lets the
    // "Divi server stopping" reply reach the client before the server is dropped.
    let rpc_stop: divi_rpc::ShutdownCallback = Arc::new(move || {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = tx.send(());
        });
    });
    let wallet_for_shutdown = wallet.clone();

    if let Some(wallet) = wallet {
        // Setup staker callbacks if enabled
        let staker_ref = staker.clone();
        let wallet_for_staking_status = Arc::clone(&wallet);
        let chain_for_staking_status = Arc::clone(&chain);
        let peers_for_staking_status = Arc::clone(&peer_manager);
        let split_threshold_divi = config.staking.split_threshold as f64 / 100_000_000.0;
        let mempool_for_rpc = node.mempool().clone();
        let spork_for_rpc = node.spork_manager().clone();
        let history_for_rpc = node.history_fetcher();
        let mempool_for_tx = node.mempool().clone();
        let tx_relay_for_tx = node.tx_relay().clone();
        let datadir_for_mn = config.data_dir.clone();
        let pm_for_mn = node.peer_manager().clone();
        let log_config_for_rpc = divi_rpc::LogConfigInfo {
            max_file_size: config.log.max_file_size,
            max_files: config.log.max_files,
            debug: config.log.debug,
            print_to_console: config.log.print_to_console,
        };

        tokio::select! {
            result = start_server_with_wallet_peer_and_staker(
                rpc_config,
                chain,
                wallet,
                peer_manager,
                move |rpc_server| {
                    rpc_server.set_shutdown_callback(rpc_stop);
                    rpc_server.set_mempool(mempool_for_rpc);
                    rpc_server.set_block_fetcher(history_for_rpc);
                    rpc_server.set_spork_manager(spork_for_rpc);
                    rpc_server.set_log_config(log_config_for_rpc);

                    // Initialize masternode manager
                    let mn_manager = divi_masternode::MasternodeManager::new();
                    rpc_server.set_masternode_manager(mn_manager);
                    rpc_server.set_masternode_datadir(datadir_for_mn);
                    rpc_server.set_masternode_relay(Arc::new(move |bytes: Vec<u8>| {
                        pm_for_mn.broadcast_masternode_broadcast(bytes);
                    }));
                    info!("Masternode manager initialized");

                    // Wire up transaction submission (mempool + relay)
                    let mempool_for_submit = mempool_for_tx.clone();
                    let tx_relay_for_submit = tx_relay_for_tx.clone();
                    let chain_for_submit = Arc::clone(&chain_for_staking_status);
                    rpc_server.wallet().set_tx_submit(Arc::new(move |tx: Transaction| {
                        let txid = tx.txid();

                        // The real fee (inputs - outputs), so the mempool's relay
                        // fee check sees what peers will see
                        let fee = Node::calculate_transaction_fee(
                            &tx,
                            &chain_for_submit,
                            &mempool_for_submit,
                        )
                        .map_err(submit_error)?;
                        // The mempool checks inputs and scripts (Node's validator)
                        mempool_for_submit.add(tx, fee).map_err(submit_error)?;

                        // Announce to peers (async, fire-and-forget)
                        let relay = tx_relay_for_submit.clone();
                        let txid_copy = txid;
                        tokio::spawn(async move {
                            relay.announce_tx(txid_copy).await;
                        });

                        info!("Transaction {} submitted to mempool and announced to peers", txid);
                        Ok(txid)
                    }));
                    info!("Transaction submission callback configured");

                    if let Some(ref staker_arc) = staker_ref {
                        let staker_for_status = Arc::clone(staker_arc);
                        let staker_for_control = Arc::clone(staker_arc);
                        let wallet_for_status = Arc::clone(&wallet_for_staking_status);
                        let chain_for_status = Arc::clone(&chain_for_staking_status);
                        let peers_for_status = Arc::clone(&peers_for_staking_status);

                        // Register status callback
                        rpc_server.staking().set_status_callback(Arc::new(move || {
                            let tip_time = chain_for_status.tip().map(|t| t.time).unwrap_or(0);
                            staking_info(
                                &staker_for_status.get_status(),
                                wallet_for_status.is_locked(),
                                peers_for_status.peer_count(),
                                tip_time,
                                blockchain_synced(&chain_for_status),
                                split_threshold_divi,
                            )
                        }));

                        // Register control callback
                        rpc_server.staking().set_staking_control(Arc::new(move |enable| {
                            if enable {
                                let staker = Arc::clone(&staker_for_control);
                                tokio::spawn(async move {
                                    staker.start().await;
                                });
                            } else {
                                staker_for_control.stop();
                            }
                            Ok(())
                        }));

                        // set/getstakesplitthreshold
                        let staker_for_split = Arc::clone(staker_arc);
                        rpc_server
                            .staking()
                            .set_split_threshold_control(Arc::new(move |new| {
                                if let Some(threshold) = new {
                                    staker_for_split.set_stake_split_threshold(threshold);
                                }
                                staker_for_split.stake_split_threshold()
                            }));

                        info!("Staking RPC callbacks registered");
                    }
                }
            ) => {
                if let Err(e) = result {
                    error!("RPC server error: {}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
        }
    } else {
        let mempool_for_rpc = node.mempool().clone();
        let spork_for_rpc = node.spork_manager().clone();
        let history_for_rpc = node.history_fetcher();
        let datadir_for_mn = config.data_dir.clone();
        let pm_for_mn = node.peer_manager().clone();
        let log_config_for_rpc = divi_rpc::LogConfigInfo {
            max_file_size: config.log.max_file_size,
            max_files: config.log.max_files,
            debug: config.log.debug,
            print_to_console: config.log.print_to_console,
        };

        tokio::select! {
            result = divi_rpc::start_server_with_peer_manager_and_setup(
                rpc_config,
                chain,
                peer_manager,
                move |rpc_server| {
                    rpc_server.set_shutdown_callback(rpc_stop);
                    rpc_server.set_mempool(mempool_for_rpc);
                    rpc_server.set_block_fetcher(history_for_rpc);
                    rpc_server.set_spork_manager(spork_for_rpc);
                    rpc_server.set_log_config(log_config_for_rpc);

                    // Initialize masternode manager
                    let mn_manager = divi_masternode::MasternodeManager::new();
                    rpc_server.set_masternode_manager(mn_manager);
                    rpc_server.set_masternode_datadir(datadir_for_mn);
                    rpc_server.set_masternode_relay(Arc::new(move |bytes: Vec<u8>| {
                        pm_for_mn.broadcast_masternode_broadcast(bytes);
                    }));
                    info!("Masternode manager initialized");
                }
            ) => {
                if let Err(e) = result {
                    error!("RPC server error: {}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
        }
    }

    // Stop the node
    info!("Stopping node...");
    node.stop().await.with_context(|| "Failed to stop node")?;

    if let Some(wallet) = wallet_for_shutdown {
        match wallet.save() {
            Ok(()) => info!("Wallet saved"),
            Err(e) => error!("Failed to save wallet on shutdown: {}", e),
        }
    }

    info!("Node stopped");
    Ok(())
}

/// How a mempool refusal of a locally submitted transaction reaches the RPC
fn submit_error(e: divi_node::NodeError) -> divi_rpc::TxSubmitError {
    use divi_node::NodeError;
    use divi_rpc::TxSubmitError;
    match e {
        NodeError::TxRejected { code, reason } => TxSubmitError::Rejected { code, reason },
        NodeError::MissingInputs => TxSubmitError::UnknownInputs,
        NodeError::NonFinal => TxSubmitError::Rejected {
            code: divi_node::error::reject::NONSTANDARD,
            reason: "non-final".to_string(),
        },
        other => TxSubmitError::Failed(other.to_string()),
    }
}

/// getstakingstatus/getmintinginfo data. Each field has the meaning Divi Core's
/// getstakingstatus gives it (rpcmisc.cpp).
fn staking_info(
    status: &divi_node::StakingStatus,
    wallet_locked: bool,
    peer_count: usize,
    tip_time: u32,
    synced: bool,
    split_threshold_divi: f64,
) -> divi_rpc::StakingInfo {
    divi_rpc::StakingInfo {
        enabled: status.enabled,
        staking: status.staking,
        errors: None,
        current_block_size: 0,
        current_block_tx: 0,
        pooled_tx: 0,
        difficulty: 0.000244140625,
        search_interval: 500,
        weight: status.stake_weight,
        netstakeweight: status.stake_weight,
        expected_time: status.expected_time,
        staking_balance: status.stake_weight as f64 / 100_000_000.0,
        // !IsLocked(): also true when unlocked for staking only
        wallet_unlocked: !wallet_locked,
        have_connections: peer_count > 0,
        // Tip time after the PoS start, 2016-08-18 (1471482000)
        valid_time: tip_time > 1_471_482_000,
        mintable_coins: status.mintable_coins,
        enough_coins: status.stake_weight > 0,
        // IronDivi keeps no masternode list sync of its own; Divi Core's
        // starts once the chain is synced
        mnsync: synced,
        blocks: status.blocks,
        stake_split_threshold: split_threshold_divi,
    }
}

/// Divi Core `IsBlockchainSynced`, which its masternode sync waits for: not in
/// initial block download and the tip is at most ten minutes old. IronDivi has no
/// masternode list sync of its own, so getstakingstatus `mnsync` reports this.
fn blockchain_synced(chain: &divi_storage::Chain) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    !chain.is_ibd()
        && chain
            .tip()
            .is_some_and(|t| now.saturating_sub(t.time as u64) <= 600)
}

/// Drop mempool txs that double-spend an input of `block`, if the block is on
/// the active chain (the callbacks are also handed side-chain blocks).
fn evict_block_conflicts(
    mempool: &divi_node::Mempool,
    chain: &divi_storage::Chain,
    block: &divi_primitives::block::Block,
) {
    let hash = compute_block_hash(&block.header);
    let active = chain
        .get_block_index(&hash)
        .ok()
        .flatten()
        .and_then(|index| chain.get_block_index_by_height(index.height).ok().flatten())
        .is_some_and(|index| index.hash == hash);
    if active {
        mempool.remove_conflicts(&block.transactions);
    }
}

/// Scan the active chain into the wallet, in order, from its last scanned
/// height up to the tip. Blocks that cannot be read (pruned) are skipped and
/// reported.
fn sync_wallet_to_tip(wallet: &WalletDb, chain: &divi_storage::Chain) {
    let missing = divi_rpc::wallet::sync_wallet_with_chain(wallet, chain);
    if let (Some(first), Some(last)) = (missing.first(), missing.last()) {
        error!(
            "Wallet scan could not read {} block(s) in {}..={} (pruned: prune height {}). \
             Wallet history in that range is NOT scanned. Restore the blocks (resync) or accept the gap.",
            missing.len(),
            first,
            last,
            chain.prune_height()
        );
    }
}

fn storage_params(config: &NodeConfig) -> divi_storage::ChainParams {
    let network_type = match config.network.network_type {
        NetworkType::Mainnet => divi_storage::NetworkType::Mainnet,
        NetworkType::Testnet => divi_storage::NetworkType::Testnet,
        NetworkType::Regtest => divi_storage::NetworkType::Regtest,
    };
    divi_storage::ChainParams::for_network(network_type, config.network.chain_mode)
}

fn snapshot_command(config: &NodeConfig, args: &Args) -> Result<()> {
    if let Some(dir) = &args.sign_snapshot {
        use std::io::Read;
        let mut key = String::new();
        std::io::stdin()
            .read_to_string(&mut key)
            .context("reading the signing key from stdin")?;
        let m = divi_storage::snapshot::SnapshotManifest::read(dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let sig = snapshot_sig::sign_root(&m, &key)?;
        snapshot_sig::write_sig(dir, &sig)?;
        println!(
            "signed root_hash {} ({}) as {}\nwrote {}",
            m.root_hash,
            m.network,
            sig.signer,
            dir.join(snapshot_sig::SIG_NAME).display()
        );
        return Ok(());
    }
    if let Some(dir) = &args.verify_snapshot {
        let signer = args.snapshot_signer.as_deref().unwrap_or_default();
        let m = snapshot_sig::verify_dir(dir, signer)?;
        println!(
            "OK: root_hash {} ({}, tip {}) is signed by {}",
            m.root_hash, m.network, m.tip_height, signer
        );
        return Ok(());
    }
    if let Some(out) = &args.export_snapshot {
        let m = divi_storage::snapshot::export_snapshot(
            &config.chainstate_path(),
            out,
            storage_params(config),
        )
        .context("snapshot export failed")?;
        println!(
            "snapshot written to {:?}\nnetwork {} tip {} {}\nroot_hash {}",
            out, m.network, m.tip_height, m.tip_hash, m.root_hash
        );
    } else if let Some(dir) = &args.import_snapshot {
        if let Some(signer) = &args.snapshot_signer {
            let signed = snapshot_sig::verify_dir(dir, signer)?;
            println!(
                "signature OK: root_hash {} signed by {}",
                signed.root_hash, signer
            );
        }
        let m = divi_storage::snapshot::import_snapshot(
            dir,
            &config.chainstate_path(),
            storage_params(config),
            args.snapshot_root.as_deref(),
        )
        .context("snapshot import failed")?;
        println!(
            "snapshot installed at {:?}\nnetwork {} tip {} {}\nroot_hash {}\nstart the node with --expire so it stays thin; blocks after the tip are fully validated",
            config.chainstate_path(), m.network, m.tip_height, m.tip_hash, m.root_hash
        );
    }
    Ok(())
}

async fn export_chain_command(config: NodeConfig, args: &Args) -> Result<()> {
    use divi_storage::{Chain, ChainDatabase, ChainParams};

    let start_height = args.export_start.context("Missing --export-start")?;
    let end_height = args.export_end.context("Missing --export-end")?;
    let output_dir = args
        .export_output
        .as_ref()
        .context("Missing --export-output")?;

    private_files::ensure_private_dir(&config.data_dir, false)
        .with_context(|| format!("Failed to create data directory: {:?}", config.data_dir))?;

    info!("Opening blockchain database...");
    let db_path = config.data_dir.join("blocks");
    let db = Arc::new(ChainDatabase::open(&db_path).with_context(|| "Failed to open database")?);

    info!("Loading chain...");
    let network_type = match config.network.network_type {
        NetworkType::Mainnet => divi_storage::NetworkType::Mainnet,
        NetworkType::Testnet => divi_storage::NetworkType::Testnet,
        NetworkType::Regtest => divi_storage::NetworkType::Regtest,
    };
    let params = ChainParams::for_network(network_type, config.network.chain_mode);
    let chain = Chain::new(db, params).with_context(|| "Failed to load chain")?;

    info!("Current chain height: {}", chain.height());
    info!(
        "Exporting blocks {} to {} to {:?}",
        start_height, end_height, output_dir
    );

    chain
        .export_chain(start_height, end_height, output_dir)
        .with_context(|| "Failed to export chain")?;

    info!("Export complete!");
    Ok(())
}

fn main() -> Result<()> {
    // Before anything is written: the datadir holds the wallet and the RPC cookie (NODE-3)
    private_files::restrict_umask();

    // Parse CLI arguments, completed from the config file where they are unset
    let args = match resolve_args(Args::parse()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            std::process::exit(1);
        }
    };

    // Compute data directory early (needed for daemonization and logging)
    let data_dir = compute_data_dir(&args);

    // Handle daemonization BEFORE initializing tokio runtime (Unix only)
    #[cfg(unix)]
    if args.daemon {
        use std::os::unix::io::AsRawFd;

        // Ensure data directory exists before daemonizing
        if let Err(e) = private_files::ensure_private_dir(&data_dir, false) {
            eprintln!("Failed to create data directory {:?}: {}", data_dir, e);
            std::process::exit(1);
        }

        let pid_file = data_dir.join("irondivid.pid");
        let log_file = data_dir.join("debug.log");

        eprintln!("Logging to {:?}", log_file);

        // First fork
        match unsafe { libc::fork() } {
            -1 => {
                eprintln!("Failed to fork: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            pid if pid > 0 => std::process::exit(0), // Parent exits
            _ => {}                                  // Child continues
        }

        // Create new session
        if unsafe { libc::setsid() } == -1 {
            eprintln!("Failed to setsid: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }

        // Second fork (prevent reacquiring a controlling terminal)
        match unsafe { libc::fork() } {
            -1 => {
                eprintln!("Failed to fork: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            pid if pid > 0 => std::process::exit(0), // Intermediate parent exits
            _ => {}                                  // Grandchild continues
        }

        // Set working directory
        let _ = std::env::set_current_dir(&data_dir);

        // Redirect stdout/stderr to log file
        use std::os::unix::fs::OpenOptionsExt;
        private_files::restrict_file(&log_file);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_file)
            .unwrap_or_else(|e| {
                eprintln!("Failed to open log file: {}", e);
                std::process::exit(1);
            });
        let log_fd = log.as_raw_fd();
        unsafe {
            libc::dup2(log_fd, libc::STDOUT_FILENO);
            libc::dup2(log_fd, libc::STDERR_FILENO);
            // Close stdin
            libc::close(libc::STDIN_FILENO);
        }

        // Write PID file: all at once, so a reader never sees a partial pid (NODE-23)
        let pid = std::process::id().to_string();
        if let Err(e) = private_files::write_private_atomic(&pid_file, pid.as_bytes()) {
            eprintln!("Failed to write PID file {:?}: {}", pid_file, e);
        }
    }

    #[cfg(not(unix))]
    if args.daemon {
        eprintln!("Warning: Daemon mode is only supported on Unix systems, running in foreground");
    }

    // Now enter the tokio runtime (after daemonization)
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build tokio runtime")?
        .block_on(async_main(args, data_dir))
}

async fn async_main(args: Args, data_dir: PathBuf) -> Result<()> {
    // Build log config from CLI args
    let log_config = LogConfig {
        max_file_size: args.maxlogsize.unwrap_or(1) as u64 * 1_048_576, // Convert MB to bytes
        max_files: args.maxlogfiles.unwrap_or(5),
        debug: args.debug,
        print_to_console: args.printtoconsole,
    };

    // Initialize logging (writes to debug.log in data_dir by default)
    init_logging(&log_config, &data_dir);

    // Build configuration
    let mut config = build_config(&args)?;
    config.log = log_config;

    // Print banner
    print_banner(&config);

    // Check for conflicting network options
    if args.testnet && args.regtest {
        error!("Cannot use both --testnet and --regtest");
        std::process::exit(1);
    }

    if args.export_snapshot.is_some()
        || args.import_snapshot.is_some()
        || args.sign_snapshot.is_some()
        || args.verify_snapshot.is_some()
    {
        return snapshot_command(&config, &args);
    }

    if args.export_chain {
        return export_chain_command(config, &args).await;
    }

    // Set up shutdown channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    // Set up signal handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C, initiating shutdown...");
            }
            _ = terminate => {
                info!("Received SIGTERM, initiating shutdown...");
            }
        }

        let _ = shutdown_tx_clone.send(());
    });

    // Run the daemon
    if let Err(e) = run_daemon(
        config,
        args.wallet,
        args.disablewallet,
        shutdown_tx,
        shutdown_rx,
    )
    .await
    {
        error!("Daemon error: {:#}", e);
        // Print the full error chain
        let mut source: Option<&(dyn StdError + 'static)> = e.source();
        while let Some(err) = source {
            error!("  Caused by: {}", err);
            source = err.source();
        }
        std::process::exit(1);
    }

    info!("IronDivi shutdown complete");
    Ok(())
}

#[cfg(test)]
mod connect_tests {
    use super::*;

    fn cfg(extra: &[&str]) -> NodeConfig {
        let dir = std::env::temp_dir().join(format!("irondivid-connect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut argv = vec![
            "irondivid".to_string(),
            "--mode".to_string(),
            "privatedivi".to_string(),
            "--testnet".to_string(),
            format!("--datadir={}", dir.display()),
        ];
        argv.extend(extra.iter().map(|s| s.to_string()));
        build_config(&Args::parse_from(argv)).unwrap()
    }

    #[test]
    fn cli_connect_is_connect_only() {
        // Regression: --connect appended to the built-in testnet peers
        // (vps1.divi.domains:52581..52585) and DNS seeds stayed on.
        let src = cfg(&["--connect=127.0.0.1:52581"]).peer_sources();
        assert_eq!(src.static_peers, vec!["127.0.0.1:52581".to_string()]);
        assert!(src.dns_seeds.is_empty());
        assert!(!src.listen);
    }

    #[test]
    fn cli_addnode_keeps_builtin_peers() {
        let config = cfg(&["--addnode=127.0.0.1:52581"]);
        let src = config.peer_sources();
        assert!(src.static_peers.contains(&"127.0.0.1:52581".to_string()));
        assert!(src.static_peers.len() > 1);
        assert!(!src.dns_seeds.is_empty());
        assert!(src.listen);
    }

    #[test]
    fn proxy_from_cli_and_config_file() {
        assert_eq!(cfg(&[]).p2p.proxy, None);
        assert_eq!(
            cfg(&["--proxy=127.0.0.1:9050"]).p2p.proxy_addr(),
            Ok(Some("127.0.0.1:9050".parse().unwrap()))
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("irondivi.conf"),
            "proxy = \"127.0.0.1:9150\"\n",
        )
        .unwrap();
        let argv = |extra: &[&str]| {
            let mut v = vec![
                "irondivid".to_string(),
                "--regtest".to_string(),
                format!("--datadir={}", dir.path().display()),
            ];
            v.extend(extra.iter().map(|s| s.to_string()));
            Args::parse_from(v)
        };
        let from_file = build_config(&argv(&[])).unwrap();
        assert_eq!(from_file.p2p.proxy.as_deref(), Some("127.0.0.1:9150"));
        // The command line wins over the file
        let both = build_config(&argv(&["--proxy=127.0.0.1:9050"])).unwrap();
        assert_eq!(both.p2p.proxy.as_deref(), Some("127.0.0.1:9050"));
    }

    #[test]
    fn checkblocks_default_cli_and_config_file() {
        assert_eq!(cfg(&[]).check_blocks, 100);
        assert_eq!(cfg(&["--checkblocks=0"]).check_blocks, 0);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("irondivi.conf"), "checkblocks = 500\n").unwrap();
        let args = Args::parse_from([
            "irondivid".to_string(),
            "--regtest".to_string(),
            format!("--datadir={}", dir.path().display()),
        ]);
        assert_eq!(build_config(&args).unwrap().check_blocks, 500);
    }

    #[test]
    fn cli_fullnode_is_a_kept_static_peer() {
        let src = cfg(&["--fullnode=10.0.0.9:52496"]).peer_sources();
        assert!(src.static_peers.contains(&"10.0.0.9:52496".to_string()));
        assert!(!src.dns_seeds.is_empty());
    }
}

#[cfg(test)]
mod config_format_tests {
    use super::*;

    fn cfg(conf: &str, extra: &[&str]) -> Result<NodeConfig> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("irondivi.conf"), conf).unwrap();
        let mut argv = vec![
            "irondivid".to_string(),
            format!("--datadir={}", dir.path().display()),
        ];
        argv.extend(extra.iter().map(|s| s.to_string()));
        build_config(&Args::parse_from(argv))
    }

    #[test]
    fn node12_rpc_access_keys_from_file_and_cli() {
        let c = cfg(
            "rpcauth=bob:00ff$abcd\nrpcauth=carol:11ee$beef\nrpcwhitelist=bob:getinfo\n\
             rpcwhitelistdefault=0\nrpcallowip=10.0.0.0/8\nrpcalloworigin=https://w.example\n\
             rpcallowhost=node.lan\n",
            &[
                "--rpcallowip=192.168.1.5",
                "--rpcwhitelist=carol:getblockcount",
            ],
        )
        .unwrap();
        assert_eq!(c.rpc.rpcauth, ["bob:00ff$abcd", "carol:11ee$beef"]);
        assert_eq!(c.rpc.whitelist, ["bob:getinfo", "carol:getblockcount"]);
        assert_eq!(c.rpc.whitelist_default, Some(false));
        assert_eq!(c.rpc.allow_ips, ["10.0.0.0/8", "192.168.1.5"]);
        assert_eq!(c.rpc.allow_origins, ["https://w.example"]);
        assert_eq!(c.rpc.allow_hosts, ["node.lan"]);
        let access = c.rpc.access();
        assert_eq!(access.allow_ips, c.rpc.allow_ips);
    }

    /// A Divi Core divi.conf used to stop irondivid ("Failed to parse config file"):
    /// the file was read only as TOML.
    #[test]
    fn divi_format_config_file_is_read() {
        let c = cfg(
            "# Divi Core style\n\
             rpcuser=foo\n\
             rpcpassword=12345abc   # inline comment\n\
             rpcport=19999\n\
             regtest=1\n\
             listen=0\n\
             addnode=10.0.0.1:51476\n\
             addnode=10.0.0.2:51476\n\
             spentindex=1\n\
             server=1\n",
            &[],
        )
        .expect("Divi-format file must load");
        assert_eq!(c.rpc.username.as_deref(), Some("foo"));
        assert_eq!(c.rpc.password.as_deref(), Some("12345abc"));
        assert_eq!(c.rpc.port, 19999);
        assert_eq!(c.p2p.port, 51476, "regtest=1 in the file selects regtest");
        assert_eq!(c.p2p.listen, Some(false));
        assert!(c.index.spentindex);
        for peer in ["10.0.0.1:51476", "10.0.0.2:51476"] {
            assert!(c.network.static_peers.contains(&peer.to_string()), "{peer}");
        }
    }

    /// Files in the TOML format IronDivi documented keep working unchanged.
    #[test]
    fn toml_config_file_still_read() {
        let c = cfg(
            "rpcuser = \"foo\"\nrpcport = 19998\naddnode = [\"10.0.0.1:1\", \"10.0.0.2:2\"]\n\
             txindex = false\nrpcpassword = 12345\n",
            &[],
        )
        .unwrap();
        assert_eq!(c.rpc.username.as_deref(), Some("foo"));
        assert_eq!(c.rpc.port, 19998);
        assert!(c.network.static_peers.contains(&"10.0.0.2:2".to_string()));
        assert!(!c.index.txindex);
        assert_eq!(c.rpc.password.as_deref(), Some("12345"));
    }

    /// The index flags in the file used to be overwritten by the command-line defaults
    /// (txindex true, spentindex/addressindex false), set or not.
    #[test]
    fn unset_index_flags_keep_the_config_file_value() {
        let c = cfg("txindex=0\nspentindex=1\naddressindex=1\n", &[]).unwrap();
        assert!(!c.index.txindex);
        assert!(c.index.spentindex);
        assert!(c.index.addressindex);
        // Given on the command line, they win
        let c = cfg(
            "txindex=0\nspentindex=1\n",
            &["--txindex", "--spentindex=0", "--addressindex=true"],
        )
        .unwrap();
        assert!(c.index.txindex);
        assert!(!c.index.spentindex);
        assert!(c.index.addressindex);
        // No file and no flag: defaults
        let c = cfg("", &[]).unwrap();
        assert!(c.index.txindex && !c.index.spentindex && !c.index.addressindex);
    }

    /// testnet=1 in the file was logged and ignored, so the node ran mainnet on that datadir.
    #[test]
    fn network_from_config_file_unless_given_on_the_command_line() {
        assert_eq!(cfg("testnet=1\n", &[]).unwrap().p2p.port, 51474);
        assert_eq!(cfg("testnet = true\n", &[]).unwrap().p2p.port, 51474);
        assert_eq!(cfg("testnet=1\n", &["--regtest"]).unwrap().p2p.port, 51476);
        assert_eq!(cfg("", &[]).unwrap().p2p.port, 51472);
    }

    /// Divi Core 3.0 does not read [section] settings; they must not leak into the main ones.
    #[test]
    fn section_settings_are_not_applied() {
        let c = cfg("rpcuser=foo\n[test]\nrpcport=1\nrpcuser=bar\n", &[]).unwrap();
        assert_eq!(c.rpc.username.as_deref(), Some("foo"));
        assert_eq!(c.rpc.port, 51471);
    }

    /// Log-file and console settings in the file reach the logger (they were overwritten
    /// by the command-line defaults before the file was read).
    #[test]
    fn early_options_come_from_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("irondivi.conf"),
            "maxlogsize=7\nmaxlogfiles=9\nprinttoconsole=1\nmode=privatedivi\n\
             disablewallet=1\ndebug=net\n",
        )
        .unwrap();
        let dd = format!("--datadir={}", dir.path().display());
        let a = resolve_args(Args::parse_from(["irondivid", dd.as_str()])).unwrap();
        assert_eq!((a.maxlogsize, a.maxlogfiles), (Some(7), Some(9)));
        assert!(a.printtoconsole && a.disablewallet && a.debug);
        assert_eq!(a.chain_mode(), ChainMode::PrivateDivi);
        let a = resolve_args(Args::parse_from([
            "irondivid",
            dd.as_str(),
            "--maxlogsize=2",
            "--mode=divi",
        ]))
        .unwrap();
        assert_eq!(a.maxlogsize, Some(2));
        assert_eq!(a.chain_mode(), ChainMode::Divi);
    }
}

#[cfg(test)]
mod wallet_log_tests {
    use super::*;

    /// Run `f` under a subscriber that records every event at every level, and
    /// return its result with the formatted log text.
    fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
        use std::io::Write;
        use std::sync::Mutex;

        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (out, logs)
    }

    /// Fail if the log text holds the phrase, or any run of three of its words.
    fn assert_mnemonic_not_logged(logs: &str, mnemonic: &str) {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert!(words.len() >= 12, "expected a full mnemonic");
        assert!(!logs.contains(mnemonic), "the mnemonic was logged");
        for run in words.windows(3) {
            let run = run.join(" ");
            assert!(!logs.contains(&run), "mnemonic words were logged: {run:?}");
        }
        assert!(
            logs.contains("dumphdinfo"),
            "wallet creation should point the operator at dumphdinfo"
        );
    }

    #[test]
    fn test_new_wallet_does_not_log_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let (wallet, logs) = capture_logs(|| {
            load_or_create_wallet_from(&path, WalletNetwork::Regtest, ChainMode::Divi, None)
        });
        let wallet = wallet.expect("wallet creation");
        let mnemonic = wallet.mnemonic().expect("new wallet has a mnemonic");
        assert_mnemonic_not_logged(&logs, &mnemonic);
    }

    #[test]
    fn test_restored_wallet_does_not_log_mnemonic() {
        // BIP39 test vector: public, holds nothing.
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let mnemonic = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let (wallet, logs) = capture_logs(|| {
            load_or_create_wallet_from(
                &path,
                WalletNetwork::Regtest,
                ChainMode::Divi,
                Some(mnemonic.clone()),
            )
        });
        let wallet = wallet.expect("wallet restore");
        assert_eq!(wallet.mnemonic().as_deref(), Some(mnemonic.as_str()));
        assert_mnemonic_not_logged(&logs, &mnemonic);
    }
    #[test]
    fn test_restored_wallet_issues_from_index_zero() {
        // Core's keypool hands out its oldest key, so a restored wallet's first
        // change output goes to /1/0 even though the lookahead derived /1/0..199.
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let mnemonic = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let wallet = load_or_create_wallet_from(
            &path,
            WalletNetwork::Regtest,
            ChainMode::Divi,
            Some(mnemonic.clone()),
        )
        .expect("wallet restore");

        assert_eq!(wallet.keystore().get_indices(), (0, 0));
        assert_eq!(wallet.keypool_size(), 400);

        let hd = divi_wallet::HdWallet::from_mnemonic(&mnemonic, None, ChainMode::Divi).unwrap();
        let addr_at = |change: bool, i: u32| {
            let key = if change {
                hd.derive_change(0, i).unwrap()
            } else {
                hd.derive_receiving(0, i).unwrap()
            };
            divi_wallet::KeyEntry::with_hd_path(key.secret_key().unwrap(), String::new())
                .address(WalletNetwork::Regtest)
        };
        // The whole lookahead is still recognised for the catch-up scan.
        assert!(wallet.is_mine(&addr_at(false, 199)));
        assert!(wallet.is_mine(&addr_at(true, 199)));

        assert_eq!(wallet.new_change_address().unwrap(), addr_at(true, 0));
        assert_eq!(wallet.new_receiving_address().unwrap(), addr_at(false, 0));
    }
}

#[cfg(test)]
mod mode_tests {
    use super::*;
    use divi_primitives::ChainMode;

    fn cfg(argv: &[&str]) -> NodeConfig {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vec![
            "irondivid".to_string(),
            format!("--datadir={}", dir.path().display()),
        ];
        v.extend(argv.iter().map(|s| s.to_string()));
        build_config(&Args::parse_from(v)).unwrap()
    }

    #[test]
    fn unknown_mode_is_a_startup_error_listing_valid_values() {
        let err = Args::try_parse_from(["irondivid", "--mode", "irondivi"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid value 'irondivi'"), "{err}");
        assert!(
            err.contains("[possible values: divi, privatedivi]"),
            "{err}"
        );
    }

    #[test]
    fn mode_defaults_to_divi() {
        assert_eq!(
            Args::parse_from(["irondivid"]).chain_mode(),
            ChainMode::Divi
        );
        assert_eq!(parse_chain_mode("privatedivi"), ChainMode::PrivateDivi);
    }

    /// `--mode privatedivi --testnet` must select PrivateDivi testnet
    /// end to end: magic, ports and genesis, not Divi testnet.
    #[test]
    fn mode_and_network_select_chain() {
        use divi_node::config::NetworkType as N;
        // (argv, mode, network, magic, p2p port, rpc port)
        type Case = (&'static [&'static str], ChainMode, N, [u8; 4], u16, u16);
        let cases: [Case; 6] = [
            (
                &[],
                ChainMode::Divi,
                N::Mainnet,
                [0xdf, 0xa0, 0x8d, 0x8f],
                51472,
                51471,
            ),
            (
                &["--testnet"],
                ChainMode::Divi,
                N::Testnet,
                [0xdf, 0xa0, 0x8d, 0x78],
                51474,
                51473,
            ),
            (
                &["--regtest"],
                ChainMode::Divi,
                N::Regtest,
                [0xa1, 0xcf, 0x7e, 0xac],
                51476,
                51475,
            ),
            (
                &["--mode", "privatedivi"],
                ChainMode::PrivateDivi,
                N::Mainnet,
                [0x70, 0xd2, 0x76, 0x11],
                52472,
                52471,
            ),
            (
                &["--mode", "privatedivi", "--testnet"],
                ChainMode::PrivateDivi,
                N::Testnet,
                [0x70, 0xd1, 0x76, 0x12],
                52474,
                52473,
            ),
            (
                &["--mode", "privatedivi", "--regtest"],
                ChainMode::PrivateDivi,
                N::Regtest,
                [0x70, 0xd1, 0x76, 0x13],
                52476,
                52475,
            ),
        ];
        for (argv, mode, net, magic, p2p, rpc) in cases {
            let c = cfg(argv);
            assert_eq!(c.network.chain_mode, mode, "{argv:?}");
            assert_eq!(c.network.network_type, net, "{argv:?}");
            assert_eq!(c.network.magic, magic, "{argv:?}");
            assert_eq!(c.p2p.port, p2p, "{argv:?}");
            assert_eq!(c.rpc.port, rpc, "{argv:?}");
        }
    }
}

#[cfg(test)]
mod expire_tests {
    use super::*;
    use divi_storage::prune::Expire;

    /// Env is process-global, so every precedence case runs inside this one test.
    #[test]
    fn expire_precedence_cli_over_env_over_conf() {
        fn cfg(conf: Option<&str>, argv: &[&str]) -> Result<NodeConfig> {
            cfg_env(conf, None, argv)
        }
        fn cfg_env(conf: Option<&str>, env: Option<&str>, argv: &[&str]) -> Result<NodeConfig> {
            let dir = tempfile::tempdir().unwrap();
            if let Some(c) = conf {
                std::fs::write(dir.path().join("irondivi.conf"), c).unwrap();
            }
            let mut v = vec![
                "irondivid".to_string(),
                format!("--datadir={}", dir.path().display()),
            ];
            v.extend(argv.iter().map(|s| s.to_string()));
            build_config_with_env(&Args::parse_from(v), env.map(String::from))
        }

        // Default: disabled.
        assert_eq!(cfg(None, &[]).unwrap().expire, Expire::Never);
        // Conf only (string and bare integers).
        assert_eq!(
            cfg(Some("expire = \"30d\"\n"), &[]).unwrap().expire,
            Expire::Window(30 * 86_400)
        );
        assert_eq!(
            cfg(Some("expire = 0\n"), &[]).unwrap().expire,
            Expire::Minimum
        );
        assert_eq!(
            cfg(Some("expire = -1\n"), &[]).unwrap().expire,
            Expire::Never
        );
        // Env beats conf.
        assert_eq!(
            cfg_env(Some("expire = \"30d\"\n"), Some("1w"), &[])
                .unwrap()
                .expire,
            Expire::Window(7 * 86_400)
        );
        // CLI beats env and conf, including negative values in both spellings.
        assert_eq!(
            cfg_env(Some("expire = \"30d\"\n"), Some("1w"), &["--expire", "2h"])
                .unwrap()
                .expire,
            Expire::Window(7200)
        );
        assert_eq!(
            cfg(None, &["--expire", "-1"]).unwrap().expire,
            Expire::Never
        );
        assert_eq!(cfg(None, &["--expire=-1"]).unwrap().expire, Expire::Never);
        assert_eq!(cfg(None, &["--expire=0"]).unwrap().expire, Expire::Minimum);
        // Invalid value on any surface is an error, not a warning.
        assert!(cfg(None, &["--expire=30"]).is_err());
        assert!(cfg_env(None, Some("bogus"), &[]).is_err());
    }
}

#[cfg(test)]
mod staking_status_tests {
    use super::*;

    /// getstakingstatus used to hardcode walletunlocked, haveconnections,
    /// validtime, mnsync, mintablecoins and the split threshold
    #[test]
    fn staking_info_reports_real_state() {
        let status = divi_node::StakingStatus {
            enabled: true,
            staking: true,
            mintable_coins: false,
            utxo_count: 1,
            stake_weight: 12_000 * 100_000_000,
            expected_time: None,
            last_stake_time: 0,
            blocks: 100,
        };
        let info = staking_info(&status, true, 0, 0, false, 5000.0);
        assert!(!info.wallet_unlocked, "locked wallet reported unlocked");
        assert!(!info.have_connections, "no peers reported as connections");
        assert!(!info.valid_time);
        assert!(
            !info.mintable_coins,
            "mintablecoins copied the staking flag"
        );
        assert!(!info.mnsync);
        assert_eq!(info.stake_split_threshold, 5000.0);
        assert!(info.enough_coins);

        let info = staking_info(&status, false, 3, 1_761_000_000, true, 20000.0);
        assert!(info.wallet_unlocked && info.have_connections && info.valid_time && info.mnsync);
    }
}
