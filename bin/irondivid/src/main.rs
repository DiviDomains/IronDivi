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

use anyhow::{Context, Result};
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
#[derive(Parser, Debug)]
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
    #[arg(long, default_value = "divi", value_parser = ["divi", "privatedivi"])]
    mode: String,

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

    /// P2P port
    #[arg(long)]
    port: Option<u16>,

    /// P2P bind address
    #[arg(long)]
    bind: Option<String>,

    /// Add a node to connect to
    #[arg(long = "addnode")]
    addnode: Vec<String>,

    /// Connect only to specified node(s)
    #[arg(long = "connect")]
    connect: Vec<String>,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Wallet directory (default: datadir/wallet)
    #[arg(long)]
    wallet: Option<PathBuf>,

    /// Disable wallet (run without wallet support)
    #[arg(long)]
    disablewallet: bool,

    /// Enable transaction index (required for PoS validation and getrawtransaction RPC)
    #[arg(long, default_value = "true")]
    txindex: bool,

    /// Start the staker at boot (`--staking=false` = C++ `-staking=0`; RPC setstaking can still start it)
    #[arg(long)]
    staking: Option<bool>,

    /// Stake even when the chain tip is older than 24h (restart a stalled network).
    /// Off by default: staking on a stale tip mints a private fork.
    #[arg(long)]
    stakeonstaletip: bool,

    /// Enable spent index for gettxout RPC
    #[arg(long)]
    spentindex: bool,

    /// Enable address index for address-based queries
    #[arg(long)]
    addressindex: bool,

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

    /// UTXO cache size in number of entries (0 = disabled, default).
    /// Use 10000000 (~500MB) for memory-constrained systems.
    #[arg(long)]
    utxocachesize: Option<u64>,

    /// Maximum log file size in MB (default: 1)
    #[arg(long, default_value = "1")]
    maxlogsize: u32,

    /// Number of log files to keep (default: 5)
    #[arg(long, default_value = "5")]
    maxlogfiles: u32,
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

/// Load configuration from file if it exists
fn load_config_file(path: &PathBuf) -> Result<Option<toml::Table>> {
    if path.exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        let table: toml::Table = content
            .parse()
            .with_context(|| format!("Failed to parse config file: {:?}", path))?;
        Ok(Some(table))
    } else {
        Ok(None)
    }
}

/// Apply configuration values from TOML table to NodeConfig
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
            // Unknown key - log warning
            _ => {
                warn!("Unknown configuration key in config file: {}", key);
            }
        }
    }
}

/// Build node configuration from CLI args and config file
fn build_config(args: &Args) -> Result<NodeConfig> {
    let chain_mode = parse_chain_mode(&args.mode);

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
        if parse_chain_mode(&args.mode) == ChainMode::PrivateDivi {
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
        apply_config_file(&mut config, &file_config);
    }

    // Apply CLI overrides (these take precedence over config file)
    if let Some(rpcuser) = &args.rpcuser {
        config.rpc.username = Some(rpcuser.clone());
    }
    if let Some(rpcpassword) = &args.rpcpassword {
        config.rpc.password = Some(rpcpassword.clone());
    }
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
    config.index.txindex = args.txindex;
    config.index.spentindex = args.spentindex;
    config.index.addressindex = args.addressindex;

    if let Some(cache_size) = args.utxocachesize {
        config.utxo_cache_size = cache_size;
    }

    // Add static peers from CLI (append to any from config file)
    if !args.connect.is_empty() {
        // Connect-only: resolved by NodeConfig::peer_sources().
        config.p2p.connect.extend(args.connect.clone());
        config.p2p.enable_discovery = false; // Don't discover when using -connect
    } else if !args.addnode.is_empty() {
        config.network.static_peers.extend(args.addnode.clone());
    }

    Ok(config)
}

/// Compute data directory from args (used before config is built)
fn compute_data_dir(args: &Args) -> PathBuf {
    args.datadir.clone().unwrap_or_else(|| {
        let mut dir = default_data_dir();
        if parse_chain_mode(&args.mode) == ChainMode::PrivateDivi {
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
        if let Err(e) = std::fs::create_dir_all(data_dir) {
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
        let wallet = WalletDb::open(wallet_path, network)
            .with_context(|| format!("Failed to open wallet at {:?}", wallet_path))?;

        // Migrate chain_mode if needed (fixes wallets created before ChainMode was configurable)
        wallet
            .migrate_chain_mode(chain_mode)
            .with_context(|| "Failed to migrate wallet chain_mode")?;

        info!("Wallet loaded successfully");
        return Ok(Arc::new(wallet));
    }

    // Create new wallet (from WALLET_MNEMONIC env var if set, otherwise random)
    info!("Creating new wallet at {:?}", wallet_path);
    std::fs::create_dir_all(wallet_path)
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

    // When restoring from mnemonic, pre-generate addresses so catch-up scan can find UTXOs
    if restoring.is_some() {
        let lookahead: u32 = std::env::var("WALLET_LOOKAHEAD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);
        info!(
            "Pre-generating {} receiving and {} change addresses for wallet recovery",
            lookahead, lookahead
        );
        for _ in 0..lookahead {
            wallet
                .new_receiving_address()
                .with_context(|| "Failed to derive receiving address")?;
            wallet
                .new_change_address()
                .with_context(|| "Failed to derive change address")?;
        }
        info!("Pre-generated {} addresses", lookahead * 2);
    }

    // Save immediately
    wallet.save().with_context(|| "Failed to save wallet")?;

    info!("New wallet created successfully");
    Ok(Arc::new(wallet))
}

/// Run the daemon
async fn run_daemon(
    config: NodeConfig,
    wallet_path: Option<PathBuf>,
    disable_wallet: bool,
    shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&config.data_dir)
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
        block_sync.set_block_connected_callback(Arc::new(move |block, height| {
            let mut total_fees = divi_primitives::amount::Amount::from_sat(0);
            for tx in block.transactions.iter().skip(1) {
                if let Some(mempool_entry) = mempool_for_callback.get(&tx.txid()) {
                    total_fees += mempool_entry.fee;
                }
            }
            let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
            mempool_for_callback.remove_for_block(&txids);
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
            block_sync.set_block_connected_callback(Arc::new(move |block, height| {
                let block_hash = compute_block_hash(&block.header);

                // 1. Calculate fees from mempool entries and clean mempool
                let mut total_fees = divi_primitives::amount::Amount::from_sat(0);
                for tx in block.transactions.iter().skip(1) {
                    if let Some(mempool_entry) = mempool_for_callback.get(&tx.txid()) {
                        total_fees += mempool_entry.fee;
                    }
                }
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
                mempool_for_callback.remove_for_block(&txids);
                for txid in &txids {
                    tx_relay_for_callback.mark_seen(*txid);
                }
                fee_estimator_for_callback.add_block(height, block, total_fees);

                // 2. Scan block for wallet transactions (adds new UTXOs, removes spent ones)
                wallet_for_scan.scan_block(
                    block_hash,
                    height,
                    block.header.time,
                    &block.transactions,
                );
                wallet_for_scan.set_last_scan_height(height);

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
                    },
                ));
            }
            info!("Orphaned transaction callback registered");

            // Catch-up scan: process blocks between last_scan_height and current chain tip
            let last_scan = wallet_arc.last_scan_height();
            let chain_height = node.chain().height();
            if last_scan < chain_height {
                info!(
                    "Wallet catch-up scan: blocks {} to {}",
                    last_scan + 1,
                    chain_height
                );
                let chain_for_scan = node.chain().clone();
                let wallet_for_catchup = Arc::clone(wallet_arc);
                let mut scanned = 0u32;
                for height in (last_scan + 1)..=chain_height {
                    let index = match chain_for_scan.get_block_index_by_height(height) {
                        Ok(Some(idx)) => idx,
                        _ => continue,
                    };
                    let block = match chain_for_scan.get_block(&index.hash) {
                        Ok(Some(blk)) => blk,
                        _ => continue,
                    };
                    wallet_for_catchup.scan_block(
                        index.hash,
                        height,
                        block.header.time,
                        &block.transactions,
                    );
                    scanned += 1;
                    if scanned.is_multiple_of(1000) {
                        info!(
                            "Catch-up scan progress: {}/{} blocks",
                            scanned,
                            chain_height - last_scan
                        );
                    }
                }
                wallet_for_catchup.set_last_scan_height(chain_height);
                if let Err(e) = wallet_for_catchup.save() {
                    error!("Failed to save wallet after catch-up scan: {}", e);
                }
                info!("Wallet catch-up scan complete ({} blocks scanned)", scanned);
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
        }

        wallet
    };

    // Start staker if wallet is available
    let staker = if let Some(ref wallet_opt) = wallet {
        let wallet_arc = wallet_opt.clone();
        let mempool = node.mempool().clone();
        let staker_chain = node.chain().clone();
        let staker_peer_manager = node.peer_manager().clone();

        // Use regtest-friendly staking config
        let mut staking_config = StakingConfig {
            allow_stale_tip: config.staking.stake_on_stale_tip,
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
            staker.set_block_connected_callback(Arc::new(move |block, height| {
                let block_hash = compute_block_hash(&block.header);

                // 1. Calculate fees from mempool entries and clean mempool
                let mut total_fees = divi_primitives::amount::Amount::from_sat(0);
                for tx in block.transactions.iter().skip(1) {
                    if let Some(mempool_entry) = mempool_for_staker.get(&tx.txid()) {
                        total_fees += mempool_entry.fee;
                    }
                }
                let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
                mempool_for_staker.remove_for_block(&txids);
                for txid in &txids {
                    tx_relay_for_staker.mark_seen(*txid);
                }
                fee_estimator_for_staker.add_block(height, block, total_fees);

                // 2. Scan block for wallet transactions
                wallet_for_staker.scan_block(
                    block_hash,
                    height,
                    block.header.time,
                    &block.transactions,
                );
                wallet_for_staker.set_last_scan_height(height);

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

    // Start RPC server
    let rpc_config = RpcConfig {
        bind_address: config.rpc.socket_addr(),
        username: config.rpc.username.clone(),
        password: config.rpc.password.clone(),
    };

    info!("Starting RPC server on {}...", rpc_config.bind_address);

    // Run RPC server with shutdown handling
    let mut shutdown_rx = shutdown_rx;

    if let Some(wallet) = wallet {
        // Setup staker callbacks if enabled
        let staker_ref = staker.clone();
        let mempool_for_rpc = node.mempool().clone();
        let mempool_for_tx = node.mempool().clone();
        let tx_relay_for_tx = node.tx_relay().clone();
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
                    rpc_server.set_mempool(mempool_for_rpc);
                    rpc_server.set_log_config(log_config_for_rpc);

                    // Initialize masternode manager
                    let mn_manager = divi_masternode::MasternodeManager::new();
                    rpc_server.set_masternode_manager(mn_manager);
                    info!("Masternode manager initialized");

                    // Wire up transaction submission (mempool + relay)
                    let mempool_for_submit = mempool_for_tx.clone();
                    let tx_relay_for_submit = tx_relay_for_tx.clone();
                    rpc_server.wallet().set_tx_submit(Arc::new(move |tx: Transaction| {
                        let txid = tx.txid();

                        // For locally submitted transactions, calculate fee generously
                        // to pass mempool relay fee check. The actual fee is embedded
                        // in the tx (inputs - outputs) and was set by the wallet.
                        let fee = Amount::from_sat(
                            (tx.size() as i64) * 10_000
                        );
                        mempool_for_submit.add(tx, fee).map_err(|e| format!("Mempool rejected: {}", e))?;

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

                        // Register status callback
                        rpc_server.staking().set_status_callback(Arc::new(move || {
                            let status = staker_for_status.get_status();
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
                                wallet_unlocked: true,
                                have_connections: true,
                                valid_time: true,
                                mintable_coins: status.staking,
                                enough_coins: status.stake_weight > 0,
                                mnsync: true,
                                blocks: status.blocks,
                            }
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
                    rpc_server.set_mempool(mempool_for_rpc);
                    rpc_server.set_log_config(log_config_for_rpc);

                    // Initialize masternode manager
                    let mn_manager = divi_masternode::MasternodeManager::new();
                    rpc_server.set_masternode_manager(mn_manager);
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

    info!("Node stopped");
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

    std::fs::create_dir_all(&config.data_dir)
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
    // Parse CLI arguments
    let args = Args::parse();

    // Compute data directory early (needed for daemonization and logging)
    let data_dir = compute_data_dir(&args);

    // Handle daemonization BEFORE initializing tokio runtime (Unix only)
    #[cfg(unix)]
    if args.daemon {
        use std::os::unix::io::AsRawFd;

        // Ensure data directory exists before daemonizing
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
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
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
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

        // Write PID file
        let _ = std::fs::write(&pid_file, format!("{}", std::process::id()));
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
        max_file_size: args.maxlogsize as u64 * 1_048_576, // Convert MB to bytes
        max_files: args.maxlogfiles,
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
    if let Err(e) = run_daemon(config, args.wallet, args.disablewallet, shutdown_rx).await {
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
            parse_chain_mode(&Args::parse_from(["irondivid"]).mode),
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
