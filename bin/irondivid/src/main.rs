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

mod core_files;
mod interfaces;
mod log_filter;
mod private_files;
mod settings;
mod snapshot_sig;

use anyhow::{Context, Result};
use divi_crypto::compute_block_hash;
use divi_node::config::{LogConfig, NetworkType, NodeConfig};
use divi_node::{shutdown_stage, Node, Staker, StakingConfig};
use divi_primitives::amount::Amount;
use divi_primitives::transaction::Transaction;
use divi_primitives::ChainMode;
use divi_rpc::{start_server_with_wallet_peer_and_staker, RpcConfig};
use divi_wallet::{HdWallet, Network as WalletNetwork, WalletDb};
use settings::{atoi, Settings};
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// irondivid's start-up options. They are read as Divi Core's divid reads
/// its own (settings.rs): `-name=value` or `--name value` on the command line,
/// then the config file, which fills only what the command line left unset.
#[derive(Debug, Clone, Default)]
struct Args {
    conf: Option<PathBuf>,
    datadir: Option<PathBuf>,
    testnet: bool,
    regtest: bool,
    mode: Option<String>,
    daemon: bool,
    printtoconsole: bool,
    debug: bool,
    /// -loglevel and -debug: what is written to debug.log
    log_levels: log_filter::LogLevels,
    wallet: Option<PathBuf>,
    disablewallet: bool,
    pid: Option<PathBuf>,
    export_chain: bool,
    export_start: Option<u32>,
    export_end: Option<u32>,
    export_output: Option<PathBuf>,
    export_snapshot: Option<PathBuf>,
    import_snapshot: Option<PathBuf>,
    snapshot_root: Option<String>,
    sign_snapshot: Option<PathBuf>,
    verify_snapshot: Option<PathBuf>,
    snapshot_signer: Option<String>,
    /// `--expire` from the command line (flag > IRONDIVI_EXPIRE > file)
    expire: Option<String>,
    maxlogsize: Option<u32>,
    maxlogfiles: Option<u32>,
    help: bool,
    version: bool,
    /// The command line alone
    cli: Settings,
    /// The command line, then the config file once it is read
    settings: Settings,
    conf_loaded: bool,
}

const USAGE: &str = "Usage:\n  irondivid [options]                     Start IronDivi Daemon\n\n\
Options are read as divid reads them: -name=value (or --name value), -noname\n\
to turn an option off, then the config file (irondivi.conf, else divi.conf, in\n\
the data directory) for whatever the command line left unset. Among them:\n  \
-conf=<file> -datadir=<dir> -testnet -regtest -mode=<divi|privatedivi>\n  \
-daemon -pid=<file> -printtoconsole -disablewallet -wallet=<name>\n  \
-debug[=<category>] -loglevel=<level> -loglevel=<category>:<level>\n  \
(levels: off error warn info debug trace; categories: net sync peers node\n  \
mempool staking chain wallet masternode spork rpc electrum webui swap zmq\n  \
daemon; the default is info; see docs/logging.md)\n  \
-port=<port> -bind=<addr> -listen -connect=<ip> -addnode=<ip> -dnsseed\n  \
-maxconnections=<n> -proxy=<ip:port> -banscore=<n> -bantime=<n> -timeout=<ms>\n  \
-server -rpcbind=<addr> -rpcallowip=<ip> -rpcport=<port> -rpcuser=<user>\n  \
-rpcpassword=<pw> -rpcauth=<user:salt$hash> -rpcwhitelist=<user:methods>\n  \
-rpcwhitelistdefault -rpcalloworigin=<origin> -rpcallowhost=<host>\n  \
-txindex -addressindex -spentindex -checkblocks=<n>\n  \
-maxreorg=<n> -maxorphantx=<n> -minrelaytxfee=<amt> -staking\n  \
-blockmaxsize=<n> -blockprioritysize=<n> -blockminsize=<n>\n  \
-blocknotify=<cmd> -walletnotify=<cmd>\n  \
-zmqpubhashblock=<address> -zmqpubhashtx=<address>\n  \
-zmqpubrawblock=<address> -zmqpubrawtx=<address>\n\
IronDivi's own: -fullnode=<ip> -stakeonstaletip -stakesplitthreshold=<n>\n  \
-utxocachesize=<n> -expire=<age> -maxlogsize=<MB> -maxlogfiles=<n>\n  \
-webui -webuiport=<port> -webuibind=<addr> -webuiallowhost=<host>\n  \
-webuiallowremote (the web interface, off unless -webui is given)\n  \
-electrum=<addr:port> -electrumtls=<addr:port> -electrumcert=<pem>\n  \
-electrumkey=<pem> -electrumws=<addr:port> -electrumwss=<addr:port>\n  \
(an Electrum server, TCP/TLS/WebSocket; needs -txindex -addressindex)\n  \
--export-chain --export-start N --export-end N --export-output DIR\n  \
--export-snapshot DIR --import-snapshot DIR [--snapshot-root HEX]\n  \
--sign-snapshot DIR --verify-snapshot DIR --snapshot-signer ADDRESS\n";

impl Args {
    fn chain_mode(&self) -> ChainMode {
        parse_chain_mode(self.mode.as_deref().unwrap_or("divi"))
    }

    /// Read the command line (the first item is the program name)
    fn try_parse_from<I, T>(argv: I) -> Result<Args>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let argv: Vec<String> = argv.into_iter().skip(1).map(Into::into).collect();
        let cli = Settings::from_command_line(&argv);
        let mut args = Args {
            cli: cli.clone(),
            settings: cli,
            ..Args::default()
        };
        args.refresh()?;
        Ok(args)
    }

    #[cfg(test)]
    fn parse_from<I, T>(argv: I) -> Args
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Args::try_parse_from(argv).unwrap_or_else(|e| {
            eprintln!("Error: {:#}", e);
            std::process::exit(1)
        })
    }

    /// Take the option values from the settings read so far
    fn refresh(&mut self) -> Result<()> {
        let s = &self.settings;
        let path = |key: &str| s.get(key).map(PathBuf::from);
        let cli_path = |key: &str| self.cli.get(key).map(PathBuf::from);
        let number = |key: &str| -> Result<Option<u32>> {
            self.cli
                .get(key)
                .map(|v| {
                    v.trim()
                        .parse::<u32>()
                        .with_context(|| format!("invalid value '{}' for --{}", v, key))
                })
                .transpose()
        };
        if let Some(mode) = s.get("mode") {
            if !matches!(mode, "divi" | "privatedivi") {
                anyhow::bail!(
                    "invalid value '{}' for '--mode <MODE>' [possible values: divi, privatedivi]",
                    mode
                );
            }
        }
        self.conf = path("conf");
        self.datadir = path("datadir");
        self.testnet = s.get_bool("testnet", false);
        self.regtest = s.get_bool("regtest", false);
        self.mode = s.get("mode").map(String::from);
        self.daemon = s.get_bool("daemon", false);
        self.printtoconsole = s.get_bool("printtoconsole", false);
        // -debug=<category> and -loglevel=<[category:]level> may repeat;
        // -debug=0 is no debugging
        self.log_levels =
            log_filter::LogLevels::parse(s.get_multi("debug"), s.get_multi("loglevel"))
                .map_err(anyhow::Error::msg)?;
        self.debug = self.log_levels.is_debug();
        self.wallet = path("wallet");
        self.disablewallet = s.get_bool("disablewallet", false);
        self.pid = path("pid");
        self.export_chain = self.cli.get_bool("export-chain", false);
        self.export_start = number("export-start")?;
        self.export_end = number("export-end")?;
        self.export_output = cli_path("export-output");
        self.export_snapshot = cli_path("export-snapshot");
        self.import_snapshot = cli_path("import-snapshot");
        self.snapshot_root = self.cli.get("snapshot-root").map(String::from);
        self.sign_snapshot = cli_path("sign-snapshot");
        self.verify_snapshot = cli_path("verify-snapshot");
        self.snapshot_signer = self.cli.get("snapshot-signer").map(String::from);
        self.expire = self.cli.get("expire").map(String::from);
        let positive = |key: &str| {
            s.get(key)
                .map(settings::atoi)
                .filter(|i| *i > 0 && *i <= u32::MAX as i64)
                .map(|i| i as u32)
        };
        self.maxlogsize = positive("maxlogsize");
        self.maxlogfiles = positive("maxlogfiles").filter(|n| *n <= 100);
        // divid's AppInit takes -? and -help, and -version (divid.cpp:70-85);
        // -h and -V are not its options
        self.help = ["?", "help"].iter().any(|k| self.cli.is_set(k));
        self.version = self.cli.is_set("version");
        if self.export_chain && (self.export_start.is_none() && self.cli.is_set("export-start")) {
            anyhow::bail!("invalid --export-start");
        }
        Ok(())
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

/// The config file, as divid finds its own (Settings::GetConfigFile): `-conf`,
/// relative to the data directory, else `irondivi.conf` there, else divid's
/// `divi.conf`
fn config_path(args: &Args) -> PathBuf {
    let dir = compute_data_dir(args);
    match &args.conf {
        Some(conf) if conf.is_relative() => dir.join(conf),
        Some(conf) => conf.clone(),
        None if dir.join("irondivi.conf").exists() => dir.join("irondivi.conf"),
        None => dir.join("divi.conf"),
    }
}

/// A config file divid's parser refuses, with boost's text
#[derive(Debug)]
struct ConfigFileError(String);

impl std::fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigFileError {}

/// Read the config file into the settings: irondivid's TOML when the file is
/// its own (`irondivi.conf` or `*.toml`) and parses as TOML, else divid's
/// `name=value` format. Values the command line set are kept. Pins `conf` to
/// the file read, so a network chosen by the file does not move it.
fn resolve_args(mut args: Args) -> Result<Args> {
    if args.conf_loaded {
        return Ok(args);
    }
    let path = config_path(&args);
    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Error reading configuration file: {:?}", path))?;
        // Only irondivid's own file may be TOML: a divi.conf that happens to
        // parse as TOML still means what it means to divid
        let own = path.file_name().is_some_and(|n| n == "irondivi.conf")
            || path.extension().is_some_and(|e| e == "toml");
        match content.parse::<toml::Table>() {
            Ok(table) if own => args.settings.read_toml(&table),
            _ => args
                .settings
                .read_config(&content)
                .map_err(ConfigFileError)?,
        }
    }
    args.refresh()?;
    args.conf = Some(path);
    args.conf_loaded = true;
    Ok(args)
}

/// Options divid takes that irondivid has nothing for: accepted, with a warning
const UNSUPPORTED_OPTIONS: &[&str] = &[
    "alertnotify",
    "alerts",
    "budgetvotemode",
    "checklevel",
    "createwalletbackups",
    "datacarrier",
    "datacarriersize",
    "dbcache",
    "disablesystemnotifications",
    "dns",
    "forcednsseed",
    "forcestart",
    "genproclimit",
    "listenonion",
    "litemode",
    "logips",
    "logtimestamps",
    "masternode",
    "masternodeaddr",
    "masternodeprivkey",
    "maxreceivebuffer",
    "maxsendbuffer",
    "mining",
    "mnconf",
    "mnconflock",
    "monthlybackups",
    "onion",
    "onlynet",
    "par",
    "peerbloomfilters",
    "permitbaremultisig",
    "proxyrandomize",
    "resync",
    "rpcthreads",
    "seednode",
    "sendfreetransactions",
    "shrinkdebugfile",
    "sysperms",
    "torcontrol",
    "torpassword",
    "txconfirmtarget",
    "upnp",
    "vault_min",
];

/// Options read elsewhere (before the node config is built, or by a command)
const READ_ELSEWHERE: &[&str] = &[
    "webui",
    "webuiport",
    "webuibind",
    "webuiallowremote",
    "webuiallowhost",
    "electrum",
    "electrumtls",
    "electrumws",
    "electrumwss",
    "electrumcert",
    "electrumkey",
    "conf",
    "hdseed",
    "mnemonic",
    "mnemonicpassphrase",
    "datadir",
    "testnet",
    "regtest",
    "mode",
    "daemon",
    "printtoconsole",
    "debug",
    "loglevel",
    "wallet",
    "disablewallet",
    "pid",
    "export-chain",
    "export-start",
    "export-end",
    "export-output",
    "export-snapshot",
    "import-snapshot",
    "snapshot-root",
    "sign-snapshot",
    "verify-snapshot",
    "snapshot-signer",
    "maxlogsize",
    "maxlogfiles",
    "?",
    "help",
    "h",
    "version",
    "V",
];

/// The value of a numeric option as divid reads it (atoi64), or None and a
/// warning when it is not a number in `range`
fn number_option(s: &Settings, key: &str, range: std::ops::RangeInclusive<i64>) -> Option<i64> {
    let text = s.get(key)?;
    let n = settings::atoi(text);
    if text.trim().is_empty() || !range.contains(&n) {
        warn!("Invalid -{}={}: ignored", key, text);
        return None;
    }
    Some(n)
}

/// An address with an optional port, as -bind and -rpcbind give it
fn host_and_port(value: &str) -> (String, Option<u16>) {
    if let Ok(sa) = value.parse::<std::net::SocketAddr>() {
        let host = match sa.ip() {
            std::net::IpAddr::V6(v6) => format!("[{}]", v6),
            v4 => v4.to_string(),
        };
        return (host, Some(sa.port()));
    }
    if let Ok(ip) = value.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V6(v6) => (format!("[{}]", v6), None),
            v4 => (v4.to_string(), None),
        };
    }
    match value.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().ok()),
        _ => (value.to_string(), None),
    }
}

/// Apply the settings to the node config, with divid's interactions between
/// options (init.cpp, net.cpp SetNetworkingParameters, rpcserver.cpp)
fn apply_settings(config: &mut NodeConfig, settings: &Settings) -> Result<()> {
    let mut s = settings.clone();
    let regtest = config.network.network_type == NetworkType::Regtest;
    // -bind or -whitebind means listening; -connect means no DNS seeds and
    // no listening; -proxy means no listening (net.cpp:1672-1700)
    if s.is_set("bind") || s.is_set("whitebind") {
        s.soft_set_bool("listen", true);
    }
    if !s.get_multi("connect").is_empty() {
        s.soft_set_bool("dnsseed", false);
        s.soft_set_bool("listen", false);
    }
    if s.is_set("proxy") {
        s.soft_set_bool("listen", false);
    }
    // -proxy, -listen=0 and -externalip each turn -discover off unless it is
    // given (net.cpp:1690-1716)
    if s.is_set("proxy") || !s.get_bool("listen", true) || s.is_set("externalip") {
        s.soft_set_bool("discover", false);
    }
    // Regtest does not stake unless asked (init.cpp:242); no wallet, no staking
    if regtest && !s.is_set("staking") {
        s.set("staking", "0", false);
    }
    if s.get_bool("disablewallet", false) {
        s.soft_set_bool("staking", false);
    }

    let port = |key: &str| number_option(&s, key, 1..=65535).map(|p| p as u16);

    if let Some(user) = s.get("rpcuser") {
        config.rpc.username = Some(user.to_string());
    }
    if let Some(password) = s.get("rpcpassword") {
        config.rpc.password = Some(password.to_string());
    }
    if let Some(p) = port("rpcport") {
        config.rpc.port = p;
    }
    // divid serves RPC unless -server=0 (divid.cpp:139)
    config.rpc.enabled = s.get_bool("server", true);
    // The REST interface, off unless asked for (Divi Core -rest, rpcserver.cpp:1025)
    config.rpc.rest = s.get_bool("rest", false);
    // The RPC server listens on the loopback unless -rpcallowip lets others
    // in; then on -rpcbind, else on every interface (rpcserver.cpp:633-706)
    let allowed = s.get_multi("rpcallowip").to_vec();
    for subnet in &allowed {
        if divi_rpc::Subnet::parse(subnet).is_none() {
            anyhow::bail!(
                "Invalid -rpcallowip subnet specification: {}. Valid are a single IP (e.g. 1.2.3.4), \
                 a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).",
                subnet
            );
        }
    }
    let rpcbind = s.get_multi("rpcbind");
    if allowed.is_empty() {
        config.rpc.listen_addr = "127.0.0.1".to_string();
        if !rpcbind.is_empty() {
            warn!("option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect");
        }
    } else if let Some(first) = rpcbind.first() {
        // Each must be a numeric address, with a port or not (ParseEndpoint,
        // rpcserver.cpp:623-629, :693-703)
        for addr in rpcbind {
            let (host, _) = host_and_port(addr);
            if host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_err()
            {
                anyhow::bail!("Could not parse -rpcbind value {} as network address", addr);
            }
        }
        let (host, p) = host_and_port(first);
        config.rpc.listen_addr = host;
        if let Some(p) = p {
            config.rpc.port = p;
        }
        if rpcbind.len() > 1 {
            warn!(
                "irondivid listens on one -rpcbind address: {} (the others are ignored)",
                first
            );
        }
    } else {
        config.rpc.listen_addr = "[::]".to_string();
    }
    config.rpc.allow_ips = allowed;
    // -rpckeepalive=0: each RPC connection is closed after its reply
    // (rpcserver.cpp:1014-1017)
    config.rpc.keep_alive = s.get_bool("rpckeepalive", true);
    // RPC access control, each repeatable but -rpcwhitelistdefault: hashed
    // credentials (`user:salt$hash`), the methods a user may call
    // (`user:method,method`), browser origins and Host names to accept
    config.rpc.rpcauth = s.get_multi("rpcauth").to_vec();
    config.rpc.whitelist = s.get_multi("rpcwhitelist").to_vec();
    if s.is_set("rpcwhitelistdefault") {
        config.rpc.whitelist_default = Some(s.get_bool("rpcwhitelistdefault", true));
    }
    config.rpc.allow_origins = s.get_multi("rpcalloworigin").to_vec();
    config.rpc.allow_hosts = s.get_multi("rpcallowhost").to_vec();

    if let Some(p) = port("port") {
        config.p2p.port = p;
    }
    if let Some(first) = s.get_multi("bind").first() {
        let (host, p) = host_and_port(first);
        config.p2p.listen_addr = host;
        if let Some(p) = p {
            config.p2p.port = p;
        }
    }
    if s.is_set("listen") {
        config.p2p.listen = Some(s.get_bool("listen", true));
    }
    // -whitelist networks; one that is not a network stops the start
    // (net.cpp:1749-1755)
    for net in s.get_multi("whitelist") {
        if divi_network::Subnet::parse(net).is_none() {
            anyhow::bail!("Invalid netmask specified in -whitelist: '{}'", net);
        }
        config.p2p.whitelist.push(net.clone());
    }
    // -whitebind: a numeric address with its port; with -whitebind and no
    // -bind, only the -whitebind addresses are listened on (net.cpp:1808-1823)
    for raw in s.get_multi("whitebind") {
        config.p2p.white_bind.push(white_bind_address(raw)?);
    }
    if s.is_set("whitebind") && !s.is_set("bind") {
        config.p2p.listen_on_addr = false;
    }
    let connect = s.get_multi("connect");
    if !connect.is_empty() {
        config.p2p.connect.extend(connect.iter().cloned());
        config.p2p.enable_discovery = false;
    }
    config.p2p.addnode = s.get_multi("addnode").to_vec();
    config
        .network
        .static_peers
        .extend(s.get_multi("addnode").iter().cloned());
    config
        .network
        .static_peers
        .extend(s.get_multi("fullnode").iter().cloned());
    if !s.get_bool("dnsseed", true) {
        config.network.dns_seeds.clear();
    }
    // -maxconnections counts inbound and outbound; at most 16 are outbound
    // (net.cpp:106, :757, :1727)
    if let Some(n) = number_option(&s, "maxconnections", 0..=i64::from(u32::MAX)) {
        let n = n as usize;
        config.p2p.max_outbound = n.min(16);
        config.p2p.max_inbound = n.saturating_sub(16);
    }
    if let Some(ms) = s.get("timeout") {
        // net.cpp: a timeout of 0 or less is the default
        let ms = settings::atoi(ms);
        config.p2p.connect_timeout_ms = if ms > 0 { ms as u64 } else { 5000 };
    }
    if let Some(proxy) = s.get("proxy") {
        config.p2p.proxy = Some(proxy.to_string());
    }
    config.p2p.discover = s.get_bool("discover", true);
    // -externalip=<ip>[:port], the listen port when none is given; one that
    // does not resolve to a valid address stops the start (net.cpp:1834-1839)
    for raw in s.get_multi("externalip") {
        let addr = resolve_service(raw, config.p2p.port)
            .filter(|a| divi_network::local::is_valid(&a.ip()))
            .ok_or_else(|| anyhow::anyhow!("Cannot resolve -externalip address: '{}'", raw))?;
        config.p2p.external_ips.push(addr);
    }
    // Divi Core SetProtocolVersion (init.cpp:1450-1452)
    if let Some(n) = number_option(&s, "protocolversion", 0..=i64::from(i32::MAX)) {
        config.network.protocol_version = n as u32;
    }
    if let Some(n) = number_option(&s, "banscore", 0..=i64::from(u32::MAX)) {
        config.p2p.ban_score = n as u32;
    }
    if let Some(n) = number_option(&s, "bantime", 0..=i64::MAX) {
        config.p2p.ban_time = n as u64;
    }
    // -loadblock files as given, relative to the working directory as in divid
    config.load_block = s.get_multi("loadblock").iter().map(PathBuf::from).collect();
    config.stop_after_block_import = s.get_bool("stopafterblockimport", false);
    if let Some(n) = number_option(&s, "checkblocks", 0..=i64::from(u32::MAX)) {
        config.check_blocks = n as u32;
    }
    if let Some(n) = number_option(&s, "maxreorg", 0..=i64::from(u32::MAX)) {
        config.max_reorg = Some(n as u32);
    }
    if let Some(n) = number_option(&s, "maxorphantx", 0..=i64::MAX) {
        config.mempool.max_orphan_txs = n as usize;
    }
    if let Some(text) = s.get("minrelaytxfee") {
        // ParseMoney; refused unless it is an amount above zero, and kept in
        // satoshis per kB (init.cpp:823-829, FeeRate.cpp)
        let sat = parse_money(text).filter(|&sat| sat > 0).ok_or_else(|| {
            anyhow::anyhow!("Invalid amount for -minrelaytxfee=<amount>: '{}'", text)
        })?;
        config.mempool.min_relay_fee_per_kb = sat;
    }
    // -maxtxfee: an amount ParseMoney reads, at least the relay fee for 1 kB;
    // above 10 DIVI a warning (init.cpp:831-845)
    if let Some(text) = s.get("maxtxfee") {
        let invalid = || anyhow::anyhow!("Invalid amount for -maxtxfee=<amount>: '{}'", text);
        let max_fee = parse_money(text).ok_or_else(invalid)?;
        if max_fee > 10 * 100_000_000 {
            warn!("Warning: -maxtxfee is set very high! Fees this large could be paid on a single transaction.");
        }
        let relay = config.mempool.min_relay_fee_per_kb;
        if max_fee < relay {
            anyhow::bail!(
                "Invalid amount for -maxtxfee=<amount>: '{}' (must be at least the minrelay fee of {}.{:08} DIV/kB to prevent stuck transactions)",
                text,
                relay / 100_000_000,
                relay % 100_000_000
            );
        }
        config.mempool.max_tx_fee = max_fee;
    }
    // -onlynet: each one of Divi Core's network names (ParseNetwork,
    // netbase.cpp:70-77; init.cpp:1734-1740)
    for net in s.get_multi("onlynet") {
        if !matches!(
            net.to_lowercase().as_str(),
            "ipv4" | "ipv6" | "tor" | "onion"
        ) {
            anyhow::bail!("Unknown network specified in -onlynet: '{}'", net);
        }
    }
    if let Some(wif) = s.get("sporkkey") {
        // Divi Core's SetSporkKey (init.cpp:968-975): a key that is not this
        // network's spork key stops the start
        let mainnet = config.network.magic == divi_network::constants::MAINNET_MAGIC;
        let spork = divi_network::spork::spork_key(&config.network.magic);
        if !spork.is_some_and(|spork| is_spork_key(wif, mainnet, &spork)) {
            anyhow::bail!("Unable to sign spork message, wrong key?");
        }
        warn!(
            "-sporkkey is this network's spork key, but irondivid does not sign sporks; not used"
        );
    }
    config.staking.enabled = s.get_bool("staking", true);
    if s.is_set("stakeonstaletip") {
        config.staking.stake_on_stale_tip = s.get_bool("stakeonstaletip", false);
    }
    if let Some(text) = s.get("stakesplitthreshold") {
        match text.trim().parse::<f64>() {
            Ok(d) if d >= 0.0 => {
                config.staking.split_threshold = (d * 100_000_000.0).round() as i64
            }
            _ => warn!("Invalid stakesplitthreshold value, expected DIVI"),
        }
    }
    // Divi Core reads these as unsigned int (BlockMemoryPoolTransactionCollector.cpp:18-42)
    for (key, slot) in [
        ("blockmaxsize", &mut config.staking.block_max_size),
        ("blockprioritysize", &mut config.staking.block_priority_size),
        ("blockminsize", &mut config.staking.block_min_size),
    ] {
        if let Some(n) = number_option(&s, key, 0..=i64::from(u32::MAX)) {
            *slot = n as usize;
        }
    }
    for (key, slot) in [
        ("txindex", &mut config.index.txindex),
        ("spentindex", &mut config.index.spentindex),
        ("addressindex", &mut config.index.addressindex),
    ] {
        if s.is_set(key) {
            *slot = s.get_bool(key, false);
        }
    }
    config.index.reindex = s.get_bool("reindex", false);
    if let Some(n) = number_option(&s, "maxlogsize", 1..=i64::from(u32::MAX)) {
        config.log.max_file_size = n as u64 * 1_048_576;
    }
    if let Some(n) = number_option(&s, "maxlogfiles", 1..=100) {
        config.log.max_files = n as u32;
    }
    if let Some(n) = number_option(&s, "utxocachesize", 0..=i64::MAX) {
        config.utxo_cache_size = n as u64;
    }
    if let Some(text) = s.get("expire") {
        config.expire = divi_storage::prune::Expire::parse(text)
            .map_err(|e| anyhow::anyhow!("config file: {}", e))?;
    }
    config.blocknotify = s
        .get("blocknotify")
        .filter(|c| !c.is_empty())
        .map(String::from);
    config.walletnotify = s
        .get("walletnotify")
        .filter(|c| !c.is_empty())
        .map(String::from);
    // Divi Core takes each -zmqpub* that is set, even empty (its bind then
    // fails), as given (zmqnotificationinterface.cpp:38-50)
    let zmq_address = |key: &str| s.get(key).map(String::from);
    config.zmq = divi_node::zmq::ZmqConfig {
        hashblock: zmq_address("zmqpubhashblock"),
        hashtx: zmq_address("zmqpubhashtx"),
        rawblock: zmq_address("zmqpubrawblock"),
        rawtx: zmq_address("zmqpubrawtx"),
    };
    config.vault = s.get_bool("vault", false);

    const APPLIED: &[&str] = &[
        "vault",
        "rescan",
        "salvagewallet",
        "spendzeroconfchange",
        "keypool",
        "upgradewallet",
        "rpcuser",
        "rpcpassword",
        "rpcport",
        "server",
        "rest",
        "rpcallowip",
        "rpcbind",
        "rpckeepalive",
        "rpcauth",
        "rpcwhitelist",
        "rpcwhitelistdefault",
        "rpcalloworigin",
        "rpcallowhost",
        "port",
        "bind",
        "listen",
        "connect",
        "addnode",
        "fullnode",
        "dnsseed",
        "maxconnections",
        "timeout",
        "proxy",
        "discover",
        "externalip",
        "protocolversion",
        "banscore",
        "bantime",
        "checkblocks",
        "loadblock",
        "stopafterblockimport",
        "maxreorg",
        "maxorphantx",
        "minrelaytxfee",
        "maxtxfee",
        "sporkkey",
        "staking",
        "stakeonstaletip",
        "stakesplitthreshold",
        "blockmaxsize",
        "blockprioritysize",
        "blockminsize",
        "txindex",
        "spentindex",
        "addressindex",
        "reindex",
        "utxocachesize",
        "expire",
        "blocknotify",
        "walletnotify",
        "zmqpubhashblock",
        "zmqpubhashtx",
        "zmqpubrawblock",
        "zmqpubrawtx",
        "whitelist",
        "whitebind",
    ];
    let mut keys: Vec<&String> = settings.keys().collect();
    keys.sort();
    for key in keys {
        let k = key.as_str();
        if APPLIED.contains(&k) || READ_ELSEWHERE.contains(&k) {
            continue;
        }
        if UNSUPPORTED_OPTIONS.contains(&k) {
            if k == "masternode" {
                // divid reads -masternode=<alias> as "run as the masternode
                // <alias> of masternode.conf" and refuses to start without it
                // (MasternodeModule.cpp:163-190); irondivid cannot run as one
                anyhow::bail!(
                    "-masternode={}: irondivid does not run as a masternode; remove the masternode= line to start it",
                    settings.get("masternode").unwrap_or("")
                );
            } else if k == "checklevel" {
                // divid refuses any -checklevel: it always checks at level 4
                // (init.cpp:782-784)
                anyhow::bail!(
                    "Error: Unsupported argument -checklevel found. Checklevel must be level 4."
                );
            } else {
                warn!(
                    "Option -{} is not supported by irondivid; ignored",
                    settings.written_name(k)
                );
            }
        } else {
            warn!("Unknown option -{}; ignored", settings.written_name(k));
        }
    }
    Ok(())
}

/// A -whitebind value as Divi Core's Lookup reads it without name lookup:
/// `ip:port` or `[ipv6]:port`; the port must be given (net.cpp:1815-1821)
fn white_bind_address(text: &str) -> Result<std::net::SocketAddr> {
    let text = text.trim();
    let addr = text.parse::<std::net::SocketAddr>().ok().or_else(|| {
        text.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| std::net::SocketAddr::new(ip, 0))
    });
    match addr {
        None => anyhow::bail!("Cannot resolve -whitebind address: '{}'", text),
        Some(a) if a.port() == 0 => {
            anyhow::bail!("Need to specify a port with -whitebind: '{}'", text)
        }
        Some(a) => Ok(a),
    }
}

/// A start the node refuses for a stated reason gives that reason alone, as
/// Divi Core's InitError prints its text after "Error: " (noui.cpp:38-40), e.g.
/// the -txindex change of init.cpp:1104-1105; other errors keep the step that
/// failed
fn start_error(e: divi_node::NodeError) -> anyhow::Error {
    match e {
        divi_node::NodeError::Init(reason) => anyhow::Error::msg(reason),
        e => anyhow::Error::new(e).context("Failed to initialize node"),
    }
}

/// Whether `wif` is a private key of this network (mainnet or not) whose public
/// key is `spork`, as Divi Core's CSporkManager::SetPrivKey checks it: the
/// secret is read as this network's (CBitcoinSecret) and its key id compared
/// with the spork key's (spork.cpp:461-475)
fn is_spork_key(wif: &str, mainnet: bool, spork: &[u8]) -> bool {
    let Ok(key) = divi_wallet::decode_wif(wif) else {
        return false;
    };
    if (key.network == WalletNetwork::Mainnet) != mainnet {
        return false;
    }
    let Ok(secret) = divi_crypto::keys::SecretKey::from_bytes(&key.key_bytes) else {
        return false;
    };
    let public = secret.public_key();
    if key.compressed {
        public.serialize_compressed()[..] == *spork
    } else {
        public.serialize_uncompressed()[..] == *spork
    }
}

/// A host with an optional port, as Divi Core's CService reads it: `ip`,
/// `ip:port`, `[ipv6]:port`, or a name, with `default_port` when none is given
fn resolve_service(text: &str, default_port: u16) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    let text = text.trim();
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = text.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse().ok()?),
        _ => (text, default_port),
    };
    (host, port).to_socket_addrs().ok()?.next()
}

/// Divi Core's ParseMoney: up to 8 decimals, no sign, no exponent. In satoshis.
fn parse_money(text: &str) -> Option<i64> {
    let t = text.trim();
    let (whole, frac) = t.split_once('.').unwrap_or((t, ""));
    if whole.is_empty() && frac.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
        || frac.len() > 8
        || whole.len() > 10
    {
        return None;
    }
    let whole: i64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let frac: i64 = format!("{:0<8}", frac).parse().ok()?;
    Some(whole * 100_000_000 + frac)
}

/// Warn when a config file holding RPC credentials can be read by other users
fn warn_if_conf_exposed(path: &std::path::Path, has_secret: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
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
    let _ = (path, has_secret);
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
    config.data_dir = compute_data_dir(args);
    config.bootstrap_dir = Some(core_network_dir(args));
    if let Some(conf) = &args.conf {
        if conf.exists() {
            info!("Loaded config from {:?}", conf);
            // The file holds RPC credentials when it sets what the command
            // line did not
            let from_file =
                |key: &str| args.settings.get_multi(key).len() > args.cli.get_multi(key).len();
            warn_if_conf_exposed(conf, from_file("rpcpassword") || from_file("rpcauth"));
        }
    }
    if args.cli.is_set("rpcpassword") {
        warn!(
            "-rpcpassword on the command line is visible to every user of this machine \
             (ps, /proc); put it in the config file or use rpcauth instead"
        );
    }

    // Everything from the command line and the file, the command line first;
    // IRONDIVI_EXPIRE then --expire override the file's expire
    let mut settings = args.settings.clone();
    if let Some(v) = env_expire.filter(|v| !v.trim().is_empty()) {
        divi_storage::prune::Expire::parse(&v)
            .map_err(|e| anyhow::anyhow!("IRONDIVI_EXPIRE: {}", e))?;
        if !args.cli.is_set("expire") {
            settings.set("expire", &v, false);
        }
    }
    if let Some(v) = &args.expire {
        divi_storage::prune::Expire::parse(v).map_err(|e| anyhow::anyhow!("--expire: {}", e))?;
    }
    apply_settings(&mut config, &settings)?;

    Ok(config)
}

/// Divi Core's network data directory, GetDataDir(): the data directory, with
/// testnet3/ or regtest/ for those networks (chainparamsbase.cpp:54, :68).
/// bootstrap.dat is read there, as divid reads it (init.cpp:698-699).
fn core_network_dir(args: &Args) -> PathBuf {
    let base = args.datadir.clone().unwrap_or_else(|| {
        let mut dir = default_data_dir();
        if args.chain_mode() == ChainMode::PrivateDivi {
            dir = dir.join("privatedivi");
        }
        dir
    });
    if args.testnet {
        base.join("testnet3")
    } else if args.regtest {
        base.join("regtest")
    } else {
        base
    }
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

/// Rotate log files: debug.log -> debug.log.1, .1 -> .2, etc., keeping
/// `max_files` files in all (debug.log included)
fn rotate_logs(log_dir: &std::path::Path, max_files: u32) {
    let current = log_dir.join("debug.log");
    if max_files <= 1 {
        let _ = std::fs::remove_file(&current);
        return;
    }

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
    let rotated = log_dir.join("debug.log.1");
    let _ = std::fs::rename(&current, &rotated);
}

/// The debug.log writer. Before a write would take the file past
/// `max_size`, the file is closed and rotated, and a new debug.log is
/// opened, so the node never keeps writing to a rotated file. A file only
/// goes over `max_size` if a single record is larger than that. When
/// stdout and stderr go to debug.log (daemon mode), they follow the new
/// file too.
struct RotatingLog {
    dir: PathBuf,
    max_size: u64,
    max_files: u32,
    redirect_std: bool,
    file: Option<std::fs::File>,
    size: u64,
}

impl RotatingLog {
    fn open(
        dir: &std::path::Path,
        max_size: u64,
        max_files: u32,
        redirect_std: bool,
    ) -> std::io::Result<Self> {
        let mut log = RotatingLog {
            dir: dir.to_path_buf(),
            max_size,
            max_files,
            redirect_std,
            file: None,
            size: 0,
        };
        log.reopen()?;
        // The log may already be too big from an earlier run
        if log.size >= max_size {
            log.rotate()?;
        }
        Ok(log)
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("debug.log"))?;
        self.size = file.metadata()?.len();
        #[cfg(unix)]
        if self.redirect_std {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO);
                libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
            }
        }
        self.file = Some(file);
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.file = None;
        rotate_logs(&self.dir, self.max_files);
        self.reopen()
    }
}

/// Set by SIGHUP: the next log write reopens debug.log (it may have been
/// moved away by logrotate)
static REOPEN_LOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl std::io::Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if REOPEN_LOG.swap(false, std::sync::atomic::Ordering::Relaxed) {
            self.file = None;
            self.reopen()?;
        }
        if self.size > 0 && self.size + buf.len() as u64 > self.max_size {
            self.rotate()?;
        }
        if self.file.is_none() {
            // A failed rotation left no file open; try again
            self.reopen()?;
        }
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("debug.log is not open"));
        };
        let n = file.write(buf)?;
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// Whether stderr is the file at `path` (stdout and stderr were sent to
/// debug.log in daemon mode)
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn stderr_is_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(libc::STDERR_FILENO, &mut st) } != 0 {
        return false;
    }
    st.st_dev as u64 == meta.dev() && st.st_ino as u64 == meta.ino()
}

#[cfg(not(unix))]
fn stderr_is_file(_path: &std::path::Path) -> bool {
    false
}

/// The filter of the running logger, which `setlogconfig` replaces
static LOG_FILTER: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>,
> = std::sync::OnceLock::new();

/// Change the log levels of the running node (the `setlogconfig` RPC);
/// returns the levels now in force
fn set_log_levels(spec: &str) -> std::result::Result<String, String> {
    let levels = log_filter::LogLevels::parse_spec(spec)?;
    let handle = LOG_FILTER
        .get()
        .ok_or_else(|| "logging is not set up".to_string())?;
    let filter = EnvFilter::try_new(levels.directives()).map_err(|e| e.to_string())?;
    handle.reload(filter).map_err(|e| e.to_string())?;
    if !levels.unknown.is_empty() {
        warn!(
            "Unknown log categories {:?} (known: {})",
            levels.unknown,
            log_filter::category_names()
        );
    }
    info!("Log levels set to {}", levels.spec());
    Ok(levels.spec())
}

/// Initialize logging
fn init_logging(log_config: &LogConfig, levels: &log_filter::LogLevels, data_dir: &PathBuf) {
    // RUST_LOG, when set, replaces -loglevel and -debug
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(levels.directives()));
    // First on the registry, so the handle's type does not depend on the
    // writer chosen below
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    let _ = LOG_FILTER.set(handle);

    // In daemon mode the console is debug.log itself, so it rotates like it
    let std_is_log = stderr_is_file(&data_dir.join("debug.log"));

    if log_config.print_to_console && !std_is_log {
        // Log to console only
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
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
                .with(filter)
                .with(fmt::layer())
                .init();
            return;
        }

        // Logs written before the umask was set may be readable by others (NODE-4)
        private_files::restrict_file(&data_dir.join("debug.log"));
        for i in 1..log_config.max_files {
            private_files::restrict_file(&data_dir.join(format!("debug.log.{}", i)));
        }

        // debug.log, rotated by size like C++ divid
        let file_appender = match RotatingLog::open(
            data_dir,
            log_config.max_file_size,
            log_config.max_files,
            std_is_log,
        ) {
            Ok(log) => log,
            Err(e) => {
                eprintln!(
                    "Warning: Could not open {:?}: {}",
                    data_dir.join("debug.log"),
                    e
                );
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer())
                    .init();
                return;
            }
        };

        // Create a non-blocking writer to avoid blocking the async runtime
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // Kept until the process exits, when `flush_log` writes out what it
        // still holds
        *LOG_GUARD.lock().unwrap_or_else(|e| e.into_inner()) = Some(_guard);

        // Set up file logging with timestamps
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer().with_writer(non_blocking).with_ansi(false), // No ANSI colors in file
            )
            .init();

        eprintln!("Logging to {:?}", data_dir.join("debug.log"));
        eprintln!(
            "Log rotation: max {} bytes per file, {} files kept",
            log_config.max_file_size, log_config.max_files
        );
        // In the foreground the console stays quiet once started, which read as
        // a hang or an exit to new users
        if !std_is_log {
            eprintln!(
                "Running in the foreground; Ctrl+C stops the node. Follow it with: tail -f {:?}",
                data_dir.join("debug.log")
            );
        }
    }
}

/// The writer thread of debug.log (non-blocking): dropping its guard writes
/// out the lines it still holds
static LOG_GUARD: std::sync::Mutex<Option<tracing_appender::non_blocking::WorkerGuard>> =
    std::sync::Mutex::new(None);

/// Write out the log lines not yet in debug.log (waits a second at most)
fn flush_log() {
    let guard = LOG_GUARD.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(guard);
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
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

/// What a new wallet is made from: Divi Core's -mnemonic, -mnemonicpassphrase
/// and -hdseed, from the command line or divi.conf (wallet.cpp:2286-2304),
/// else the WALLET_MNEMONIC, WALLET_MNEMONIC_PASSPHRASE and WALLET_HDSEED
/// environment variables. Never logged.
#[derive(Default)]
struct WalletSeed {
    mnemonic: Option<String>,
    passphrase: Option<String>,
    hdseed: Option<String>,
}

impl WalletSeed {
    fn from_settings(settings: &Settings) -> Self {
        let get = |key: &str| settings.get(key).map(str::to_string);
        WalletSeed {
            mnemonic: get("mnemonic"),
            passphrase: get("mnemonicpassphrase"),
            hdseed: get("hdseed"),
        }
    }
}

/// Wallet start options
#[derive(Debug, Clone, Copy, Default)]
struct WalletOptions {
    /// -rescan: scan the whole chain at the start; -salvagewallet sets it
    /// unless it is given (init.cpp:763-766, :1242)
    rescan: bool,
    /// -spendzeroconfchange: sends may use unconfirmed outputs of our own
    /// transactions (wallet.cpp:1848)
    spend_zero_conf_change: bool,
    /// -keypool: keys of each chain the keypool is topped up to, read as a
    /// number and at least one (wallet.cpp:2071-2080)
    keypool: Option<u32>,
    /// -upgradewallet, read as a number: the highest wallet version a new
    /// wallet may have (wallet.cpp:1963-1971)
    upgrade_wallet: Option<i64>,
}

impl WalletOptions {
    fn from_settings(settings: &Settings) -> Self {
        WalletOptions {
            rescan: settings.get_bool("rescan", settings.get_bool("salvagewallet", false)),
            spend_zero_conf_change: settings.get_bool("spendzeroconfchange", false),
            keypool: settings
                .get("keypool")
                .map(|v| atoi(v).clamp(1, u32::MAX as i64) as u32),
            upgrade_wallet: settings.get("upgradewallet").map(atoi),
        }
    }

    /// Divi Core gives a new wallet the latest version only when
    /// -upgradewallet is absent or is its client version; otherwise the
    /// wallet keeps the base version, and a limit below that stops the load
    /// (wallet.cpp:183, :1963-1971; init.cpp:1175)
    fn refuses_new_wallet(&self) -> bool {
        const CLIENT_VERSION: i64 = 3_000_000;
        const FEATURE_BASE: i64 = 10_500;
        matches!(self.upgrade_wallet, Some(v) if v != CLIENT_VERSION && v < FEATURE_BASE)
    }
}

/// Load or create wallet
fn load_or_create_wallet(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
    seed: WalletSeed,
    options: &WalletOptions,
) -> Result<Arc<WalletDb>> {
    let env = |name: &str| std::env::var(name).ok();
    // An empty mnemonic asks for a new one, as in Core
    let mnemonic = seed
        .mnemonic
        .or_else(|| env("WALLET_MNEMONIC"))
        .filter(|m| !m.trim().is_empty());
    let passphrase = seed
        .passphrase
        .or_else(|| env("WALLET_MNEMONIC_PASSPHRASE"));
    // -hdseed is preferred over a mnemonic (init.cpp:947-951)
    let hdseed = seed.hdseed.or_else(|| env("WALLET_HDSEED"));
    load_or_restore_wallet_with_seed(
        wallet_path,
        network,
        chain_mode,
        mnemonic,
        passphrase,
        hdseed,
        options,
    )
}

/// `load_or_restore_wallet` with no mnemonic passphrase
#[cfg(test)]
fn load_or_create_wallet_from(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
    restoring: Option<String>,
) -> Result<Arc<WalletDb>> {
    load_or_restore_wallet(wallet_path, network, chain_mode, restoring, None)
}

/// Load the wallet at `wallet_path`, or create it: restored from `restoring`
/// when a mnemonic is given (with its BIP39 `passphrase`), otherwise from a
/// fresh random seed.
#[cfg(test)]
fn load_or_restore_wallet(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
    restoring: Option<String>,
    passphrase: Option<String>,
) -> Result<Arc<WalletDb>> {
    load_or_restore_wallet_with_seed(
        wallet_path,
        network,
        chain_mode,
        restoring,
        passphrase,
        None,
        &WalletOptions::default(),
    )
}

/// `load_or_restore_wallet`, where a new wallet may instead come from a hex
/// `seed` (Divi Core's -hdseed, taken over a mnemonic)
fn load_or_restore_wallet_with_seed(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
    restoring: Option<String>,
    passphrase: Option<String>,
    seed: Option<String>,
    options: &WalletOptions,
) -> Result<Arc<WalletDb>> {
    // Try to open existing wallet
    if wallet_path.exists() {
        // Divi Core copies the wallet into backups/ (and monthlyBackups/) at
        // every start, before it opens it (init.cpp:1479)
        if let Some(data_dir) = wallet_path.parent() {
            if let Err(e) = divi_wallet::backup::backup_at_start(wallet_path, data_dir) {
                warn!("Failed to create backup: {}", e);
            }
        }
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

        if let Some(size) = options.keypool {
            wallet.keystore().set_keypool_target(size);
        }
        // Divi Core does not refill the keypool when it loads a wallet: it tops
        // up only before it takes a key (wallet.cpp:2122-2131), so a pool may
        // sit one key short per chain, or below a -keypool raised since. Only
        // an empty pool, which divid never has (a wallet stored before its
        // keypool was), is filled here, so payments to its next keys are
        // still found. A locked wallet is topped up on unlock.
        if !wallet.is_locked() && wallet.keypool_size() == 0 {
            if let Err(e) = wallet.top_up_keypool() {
                warn!("Could not top up the keypool: {}", e);
            }
        }

        warn_if_unencrypted(&wallet);
        info!("Wallet loaded successfully");
        return Ok(Arc::new(wallet));
    }

    // Create a new wallet: from -hdseed, else from -mnemonic or new words,
    // with -mnemonicpassphrase (Divi Core GenerateNewHDChain, wallet.cpp:2282-2316)

    // Divi Core takes -hdseed when it is hex and logs anything else, then
    // goes on with the mnemonic or a new seed (wallet.cpp:2286-2297)
    let seed = match seed {
        Some(hex_seed) => match hex::decode(hex_seed.trim()) {
            Ok(bytes) if !bytes.is_empty() => Some(bytes),
            _ => {
                warn!("-hdseed is not a hex seed; not using it");
                None
            }
        },
        None => None,
    };
    if seed.is_some() && (restoring.is_some() || passphrase.is_some()) {
        warn!("-hdseed and -mnemonic/-mnemonicpassphrase together: using the seed");
    }
    let restoring = if seed.is_some() { None } else { restoring };
    let passphrase = if seed.is_some() { None } else { passphrase };
    // The version limit is checked before the seed is made
    // (wallet.cpp:1963-1979), and before anything is written
    if options.refuses_new_wallet() {
        anyhow::bail!("Error loading wallet.dat: database load failure");
    }
    // Checked only when words make the wallet, before anything is written
    // (wallet.cpp:2302-2305, reported by init.cpp:1203-1209)
    if passphrase.as_ref().is_some_and(|p| p.len() > 256) {
        anyhow::bail!(
            "Error loading or creating wallet.dat, GenerateNewHDChain: Mnemonic passphrase is too long, must be at most 256 characters"
        );
    }

    info!("Creating new wallet at {:?}", wallet_path);
    private_files::ensure_private_dir(wallet_path, true)
        .with_context(|| format!("Failed to create wallet directory: {:?}", wallet_path))?;
    let hd_wallet = if let Some(ref seed) = seed {
        info!("Restoring wallet from -hdseed");
        HdWallet::from_seed(seed, chain_mode)
            .with_context(|| "Failed to restore HD wallet from seed")?
    } else if let Some(ref mnemonic) = restoring {
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
            "Restoring wallet from -mnemonic (chain_mode={:?})",
            restore_chain_mode
        );
        HdWallet::from_mnemonic(mnemonic, passphrase.as_deref(), restore_chain_mode)
            .with_context(|| "Failed to restore HD wallet from mnemonic")?
    } else {
        // No mnemonic: new words, with the passphrase if one is given
        // (hdchain.cpp:56-67)
        HdWallet::generate(passphrase.as_deref(), chain_mode)
            .with_context(|| "Failed to generate HD wallet")?
    };

    // Never log the mnemonic: logs go to journald and log files, which are
    // neither encrypted nor access-controlled like the wallet. Point the
    // operator at the RPC that returns it on demand instead.
    warn!("new wallet created; retrieve the seed with the dumphdinfo RPC");

    let wallet = WalletDb::create_persistent(wallet_path, network, hd_wallet)
        .with_context(|| "Failed to create wallet")?;
    if let Some(size) = options.keypool {
        wallet.keystore().set_keypool_target(size);
    }

    // A new or restored wallet starts with a full keypool, as in Divi Core,
    // whose restore finds the coins of exactly these keys: the catch-up scan
    // from genesis recognises every keypool key. WALLET_LOOKAHEAD sets how many
    // keys of each chain a restore pre-generates (default: the keypool size).
    // They stay in the keypool, so the receiving and change indices stay low.
    let lookahead = (restoring.is_some() || seed.is_some())
        .then(|| std::env::var("WALLET_LOOKAHEAD").ok()?.parse::<u32>().ok())
        .flatten();
    let generated = wallet
        .refill_keypool(lookahead)
        .with_context(|| "Failed to fill the keypool")?;
    info!("Keypool filled with {} keys", generated);
    // Divi Core's default key: the first receiving key, taken from the
    // keypool with an empty label (wallet.cpp:342-356)
    let default_key = wallet
        .new_receiving_address()
        .with_context(|| "Failed to take the default key")?;
    wallet
        .set_label(&default_key, "")
        .with_context(|| "Failed to label the default key")?;

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

/// Put one wallet transaction back in the mempool with its real fee (inputs -
/// outputs), as a local RPC send does, so the relay fee check applies to it.
fn resubmit_tx(
    tx: Transaction,
    chain: &Arc<divi_storage::Chain>,
    mempool: &Arc<divi_node::Mempool>,
) -> std::result::Result<divi_primitives::hash::Hash256, String> {
    let inputs_available = tx.vin.iter().all(|input| {
        mempool.contains(&input.prevout.txid)
            || matches!(chain.get_utxo(&input.prevout), Ok(Some(_)))
    });
    if !inputs_available {
        return Err("inputs no longer available".to_string());
    }
    let fee = Node::calculate_transaction_fee(&tx, chain, mempool).map_err(|e| e.to_string())?;
    mempool.add(tx, fee).map_err(|e| e.to_string())
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
    let mut resubmitted = 0;
    for tx in txs {
        let txid = tx.txid();
        match resubmit_tx(tx, node.chain(), node.mempool()) {
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

/// Lock `<datadir>/.lock` as Divi Core does; a data directory another process
/// holds stops the start with Divi Core's error
fn lock_data_dir(dir: &std::path::Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(".lock"))
        .with_context(|| format!("Failed to open {:?}", dir.join(".lock")))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "Cannot obtain a lock on data directory {}. Divi Core or irondivid is probably already running.",
            dir.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("Failed to lock {:?}", dir.join(".lock")))
        }
    }
}

/// Run the daemon
#[allow(clippy::too_many_arguments)]
async fn run_daemon(
    mut config: NodeConfig,
    wallet_path: Option<PathBuf>,
    wallet_seed: WalletSeed,
    disable_wallet: bool,
    wallet_options: WalletOptions,
    shutdown_tx: broadcast::Sender<()>,
    shutdown_rx: broadcast::Receiver<()>,
    webui: Option<divi_webui::WebUiConfig>,
    electrum: Option<divi_electrum::ElectrumConfig>,
) -> Result<()> {
    // Create data directory if it doesn't exist
    private_files::ensure_private_dir(&config.data_dir, false)
        .with_context(|| format!("Failed to create data directory: {:?}", config.data_dir))?;
    // One process per data directory, held until this one exits
    // (TryLockDataDirectory, init.cpp:850-862)
    let _datadir_lock = lock_data_dir(&config.data_dir)?;
    // divid reads masternode.conf at every start and makes it when missing
    core_files::ensure_masternode_conf(&config.data_dir);

    // -webui: take its port now, so a port in use stops the start at once
    let webui = webui.map(divi_webui::prepare).transpose()?;
    let webui_shutdown = shutdown_tx.subscribe();
    // -electrum: the same, for the Electrum server's ports and certificate
    let electrum = electrum.map(divi_electrum::prepare).transpose()?;
    let electrum_shutdown = shutdown_tx.subscribe();

    // Divi Core Discover: the interfaces' addresses (net.cpp:1385-1425)
    if config.p2p.discover {
        config.p2p.interface_ips = interfaces::addresses();
    }

    // Initialize the node
    info!("Initializing node...");
    // Never dropped: the process ends without running the destructors of the
    // node's state (databases, caches, mempool), see `exit_after_stop`
    let node = std::mem::ManuallyDrop::new(Node::new(config.clone()).map_err(start_error)?);

    // -blocknotify, before any block comes in (init.cpp:1563-1564)
    if let Some(cmd) = config.blocknotify.clone() {
        spawn_block_notify(node.chain().clone(), cmd);
    }

    // The ZMQ notifiers, before the chain takes blocks (init.cpp:1495-1500).
    // Kept for the life of the node; none if an address cannot be bound.
    let _zmq = divi_node::zmq::ZmqNotifier::start(&config.zmq, node.chain(), node.mempool());

    // Start the node
    node.start().await.with_context(|| "Failed to start node")?;

    // Divi Core's -stopafterblockimport: the import thread asks for shutdown
    // once it is done (init.cpp:724-727)
    if config.stop_after_block_import {
        let chain = node.chain().clone();
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            while chain.is_importing() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            info!("Stopping after block import");
            let _ = tx.send(());
        });
    }

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
            mempool_block_connected(
                &mempool_for_callback,
                &chain_for_callback,
                |txid| tx_relay_for_callback.mark_seen(txid),
                &fee_estimator_for_callback,
                block,
                height,
            );
        }));

        None
    } else {
        let wallet_dir = core_files::wallet_dir(&config.data_dir, wallet_path.as_deref());
        let wallet_network = match config.network.network_type {
            NetworkType::Mainnet => WalletNetwork::Mainnet,
            NetworkType::Testnet => WalletNetwork::Testnet,
            NetworkType::Regtest => WalletNetwork::Regtest,
        };
        let wallet = Some(load_or_create_wallet(
            &wallet_dir,
            wallet_network,
            config.network.chain_mode,
            wallet_seed,
            &wallet_options,
        )?);
        if let Some(ref w) = wallet {
            // Timed unlocks drop their keys when they run out (NODE-6)
            WalletDb::start_auto_lock(w);
            core_files::lock_masternode_collateral(w, &config.data_dir);
            w.set_vault_mode(config.vault);
            w.set_spend_zero_conf_change(wallet_options.spend_zero_conf_change);
            w.set_relay_fee_per_kb(config.mempool.min_relay_fee_per_kb);
            w.set_max_tx_fee(config.mempool.max_tx_fee);
            // -walletnotify, before the wallet catches up with the chain
            // (init.cpp:1199, before the rescan at :1242)
            if let Some(cmd) = config.walletnotify.clone() {
                w.set_tx_listener(Arc::new(move |txid| run_notify(&cmd, &txid.to_string())));
            }
        }

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
                let total_fees = mempool_block_connected(
                    &mempool_for_callback,
                    &chain_for_scan,
                    |txid| tx_relay_for_callback.mark_seen(txid),
                    &fee_estimator_for_callback,
                    block,
                    height,
                );

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
            debug!("Unified block callback registered (mempool + fees + wallet)");

            // Mirror wallet-relevant mempool transactions into the wallet so
            // unconfirmed sends and receives show up immediately (0 confirmations).
            // The listeners fire for every path into and out of the mempool: P2P
            // relay, local RPC sends, confirmation, eviction and clearing.
            {
                let wallet_for_added = Arc::clone(wallet_arc);
                node.mempool()
                    .add_added_listener(Arc::new(move |tx: &Transaction| {
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
            debug!("Wallet reorg callback registered");

            // Catch-up scan: process blocks between last_scan_height and current chain tip.
            // Block notifications may already be arriving; they share the wallet's scan
            // lock and its scan height, so neither side skips or reorders a block.
            // A chain lower than the scan height (rebuilt or reindexed) rolls the
            // wallet back to the tip; the sync that follows scans those blocks again.
            // -rescan: scan the whole active chain again, keeping what the
            // wallet holds, as Divi Core's verifySyncToActiveChain from the
            // genesis block (init.cpp:1242, wallet.cpp:279-313)
            let chain_height = node.chain().height();
            if wallet_options.rescan {
                info!("Rescanning... from height 0 to {}", chain_height);
                wallet_arc.set_last_scan_height(0);
            }
            let last_scan = wallet_arc.last_scan_height();
            if last_scan > chain_height {
                info!(
                    "Wallet scanned to height {} but the chain is at {}; rescanning above it as the chain syncs",
                    last_scan, chain_height
                );
            } else if last_scan < chain_height {
                info!(
                    "Wallet catch-up scan: blocks {} to {}",
                    last_scan + 1,
                    chain_height
                );
            }
            if last_scan != chain_height {
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
            let removed = wallet_arc.reconcile_utxos(chain_for_reconcile.height(), |outpoint| {
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

            // Divi Core checks once a day whether a monthly backup is due
            // (LegacyWalletDatabaseEndpointFactory.cpp:111-121; on regtest
            // that loop runs on mock time)
            if config.network.network_type != NetworkType::Regtest {
                let wallet_for_backup = Arc::clone(wallet_arc);
                let backup_root = wallet_dir.parent().map(|p| p.to_path_buf());
                tokio::spawn(async move {
                    let Some(root) = backup_root else { return };
                    let mut daily =
                        tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
                    daily.tick().await;
                    loop {
                        daily.tick().await;
                        let wallet = Arc::clone(&wallet_for_backup);
                        let root = root.clone();
                        let made = tokio::task::spawn_blocking(move || {
                            divi_wallet::backup::monthly_backup(&wallet, &root)
                        })
                        .await;
                        match made {
                            Ok(Ok(Some(path))) => info!("Monthly wallet backup {}", path.display()),
                            Ok(Ok(None)) => {}
                            Ok(Err(e)) => warn!("Monthly wallet backup failed: {}", e),
                            Err(e) => warn!("Monthly wallet backup failed: {}", e),
                        }
                    }
                });
            }
        }

        wallet
    };

    // After every chain reorganization, return the transactions of the
    // disconnected blocks to the mempool and drop what the new chain confirmed
    // or made unspendable, as Divi Core's disconnectTip and connectTip do. This
    // does not depend on the wallet.
    {
        let mempool_for_reorg = node.mempool().clone();
        let chain_for_reorg = node.chain().clone();
        node.block_sync().set_orphaned_tx_callback(Arc::new(
            move |orphaned_txs: Vec<Transaction>| {
                divi_node::update_mempool_after_reorg(
                    &chain_for_reorg,
                    &mempool_for_reorg,
                    orphaned_txs,
                );
            },
        ));
    }

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

        let staking_config = staking_config(&config, node.chain().params());
        if staking_config.allow_stale_tip && config.network.network_type != NetworkType::Regtest {
            warn!(
                "-stakeonstaletip set: staking is allowed on a tip older than {}s",
                staking_config.max_tip_age_secs
            );
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

                // 2. Clean the mempool and feed the fee estimator
                mempool_block_connected(
                    &mempool_for_staker,
                    &chain_for_staker_scan,
                    |txid| tx_relay_for_staker.mark_seen(txid),
                    &fee_estimator_for_staker,
                    block,
                    height,
                );

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
            debug!("Staker block callback registered (for self-accepted blocks)");
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
        keep_alive: config.rpc.keep_alive,
        rest: config.rpc.rest,
        access: config.rpc.access(),
        max_request_size: config.rpc.max_request_size,
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
    // An RPC server that cannot run (its port taken) stops the node, which
    // then exits with failure, as divid's InitError does
    let mut rpc_error = None;

    // RPC `stop` takes the same path as SIGTERM. The short delay lets the
    // "DIVI server stopping" reply reach the client before the server is dropped.
    let rpc_stop: divi_rpc::ShutdownCallback = Arc::new(move || {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = tx.send(());
        });
    });
    let wallet_for_shutdown = wallet.clone();

    if !config.rpc.enabled {
        // -server=0: no RPC server, the node runs until it is told to stop
        info!("RPC server disabled (-server=0)");
        let _ = shutdown_rx.recv().await;
        info!("Shutdown signal received");
    } else if let Some(wallet) = wallet {
        // Setup staker callbacks if enabled
        let staker_ref = staker.clone();
        let wallet_for_staking_status = Arc::clone(&wallet);
        let chain_for_staking_status = Arc::clone(&chain);
        let peers_for_staking_status = Arc::clone(&peer_manager);
        let split_threshold_divi = config.staking.split_threshold as f64 / 100_000_000.0;
        let mempool_for_rpc = node.mempool().clone();
        let mempool_for_electrum = node.mempool().clone();
        let chain_for_electrum = Arc::clone(&chain);
        let reorg_hook_for_rpc = mempool_reorg_hook(&node, Some(Arc::clone(&wallet)));
        let spork_for_rpc = node.spork_manager().clone();
        let history_for_rpc = node.history_fetcher();
        let block_sync_for_rpc = node.block_sync().clone();
        let mempool_for_tx = node.mempool().clone();
        let tx_relay_for_tx = node.tx_relay().clone();
        let datadir_for_mn = config.data_dir.clone();
        let pm_for_mn = node.peer_manager().clone();
        // The node's own masternode list, which the network fills from mnb/mnp
        let mn_for_rpc = node.masternode_manager().as_ref().clone();
        let mn_list_for_rpc = Arc::clone(node.masternode_list());
        let log_config_for_rpc = divi_rpc::LogConfigInfo {
            max_file_size: config.log.max_file_size,
            max_files: config.log.max_files,
            debug: config.log.debug,
            levels: config.log.levels.clone(),
            print_to_console: config.log.print_to_console,
        };

        tokio::select! {
            result = start_server_with_wallet_peer_and_staker(
                rpc_config,
                chain,
                wallet,
                peer_manager,
                move |rpc_server| {
                    if let Some(webui) = webui {
                        webui.spawn(Arc::clone(rpc_server), webui_shutdown);
                    }
                    if let Some(electrum) = electrum {
                        electrum.spawn(
                            chain_for_electrum,
                            mempool_for_electrum,
                            Arc::clone(rpc_server),
                            electrum_shutdown,
                        );
                    }
                    rpc_server.set_shutdown_callback(rpc_stop);
                    rpc_server.set_mempool(mempool_for_rpc);
                    rpc_server.set_reorg_hook(reorg_hook_for_rpc);
                    rpc_server.set_block_fetcher(history_for_rpc);
                    rpc_server.set_block_sync(block_sync_for_rpc);
                    rpc_server.set_spork_manager(spork_for_rpc);
                    rpc_server.set_log_config(log_config_for_rpc);
                    rpc_server.set_log_levels_callback(Arc::new(set_log_levels));

                    // The masternode RPCs read the node's masternode list
                    rpc_server.set_masternode_manager(mn_for_rpc);
                    rpc_server.set_masternode_list(mn_list_for_rpc);
                    rpc_server.set_masternode_datadir(datadir_for_mn);
                    rpc_server.set_masternode_relay(Arc::new(move |bytes: Vec<u8>| {
                        pm_for_mn.broadcast_masternode_broadcast(bytes);
                    }));
                    info!("Masternode manager initialized");

                    // Wire up transaction submission (mempool + relay)
                    let mempool_for_submit = mempool_for_tx.clone();
                    let tx_relay_for_submit = tx_relay_for_tx.clone();
                    rpc_server.wallet().set_tx_submit(Arc::new(move |tx: Transaction| {
                        let txid = tx.txid();

                        // The mempool runs every check and works out the fee
                        // (Node's validator)
                        mempool_for_submit
                            .add(tx, Amount::ZERO)
                            .map_err(submit_error)?;

                        // Announce to peers (async, fire-and-forget)
                        let relay = tx_relay_for_submit.clone();
                        let txid_copy = txid;
                        tokio::spawn(async move {
                            relay.announce_tx(txid_copy).await;
                        });

                        info!("Transaction {} submitted to mempool and announced to peers", txid);
                        Ok(txid)
                    }));
                    debug!("Transaction submission callback configured");

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

                        // setgenerate (regtest): mine blocks to the wallet now
                        let staker_for_generate = Arc::clone(staker_arc);
                        rpc_server
                            .staking()
                            .set_generate_control(Arc::new(move |n| {
                                staker_for_generate
                                    .generate_blocks(n)
                                    .map(|hashes| hashes.iter().map(|h| h.to_string()).collect())
                            }));
                        let staker_for_block = Arc::clone(staker_arc);
                        rpc_server
                            .staking()
                            .set_generate_block_control(Arc::new(move |o| {
                                use divi_node::staker::{BlockOverrides, GenerateBlockError};
                                use divi_rpc::staking::GenerateBlockFailure;
                                staker_for_block
                                    .generate_block_with(&BlockOverrides {
                                        extra_txs: o.extra_txs,
                                        coinstake: o.coinstake,
                                        ignore_mempool: o.ignore_mempool,
                                        bits_shift: o.bits_shift,
                                    })
                                    .map(|hash| hash.to_string())
                                    .map_err(|e| match e {
                                        GenerateBlockError::Refused(m) => {
                                            GenerateBlockFailure::Refused(m)
                                        }
                                        GenerateBlockError::Failed(m) => {
                                            GenerateBlockFailure::Failed(m)
                                        }
                                    })
                            }));

                        debug!("Staking RPC callbacks registered");
                    }
                }
            ) => {
                if let Err(e) = result {
                    error!("RPC server error: {}", e);
                    rpc_error = Some(e.to_string());
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
        }
    } else {
        let mempool_for_rpc = node.mempool().clone();
        let mempool_for_electrum = node.mempool().clone();
        let chain_for_electrum = Arc::clone(&chain);
        let reorg_hook_for_rpc = mempool_reorg_hook(&node, None);
        let spork_for_rpc = node.spork_manager().clone();
        let history_for_rpc = node.history_fetcher();
        let block_sync_for_rpc = node.block_sync().clone();
        let datadir_for_mn = config.data_dir.clone();
        let pm_for_mn = node.peer_manager().clone();
        // The node's own masternode list, which the network fills from mnb/mnp
        let mn_for_rpc = node.masternode_manager().as_ref().clone();
        let mn_list_for_rpc = Arc::clone(node.masternode_list());
        let log_config_for_rpc = divi_rpc::LogConfigInfo {
            max_file_size: config.log.max_file_size,
            max_files: config.log.max_files,
            debug: config.log.debug,
            levels: config.log.levels.clone(),
            print_to_console: config.log.print_to_console,
        };

        tokio::select! {
            result = divi_rpc::start_server_with_peer_manager_and_setup(
                rpc_config,
                chain,
                peer_manager,
                move |rpc_server| {
                    if let Some(webui) = webui {
                        webui.spawn(Arc::clone(rpc_server), webui_shutdown);
                    }
                    if let Some(electrum) = electrum {
                        electrum.spawn(
                            chain_for_electrum,
                            mempool_for_electrum,
                            Arc::clone(rpc_server),
                            electrum_shutdown,
                        );
                    }
                    rpc_server.set_shutdown_callback(rpc_stop);
                    rpc_server.set_mempool(mempool_for_rpc);
                    rpc_server.set_reorg_hook(reorg_hook_for_rpc);
                    rpc_server.set_block_fetcher(history_for_rpc);
                    rpc_server.set_block_sync(block_sync_for_rpc);
                    rpc_server.set_spork_manager(spork_for_rpc);
                    rpc_server.set_log_config(log_config_for_rpc);
                    rpc_server.set_log_levels_callback(Arc::new(set_log_levels));

                    // The masternode RPCs read the node's masternode list
                    rpc_server.set_masternode_manager(mn_for_rpc);
                    rpc_server.set_masternode_list(mn_list_for_rpc);
                    rpc_server.set_masternode_datadir(datadir_for_mn);
                    rpc_server.set_masternode_relay(Arc::new(move |bytes: Vec<u8>| {
                        pm_for_mn.broadcast_masternode_broadcast(bytes);
                    }));
                    info!("Masternode manager initialized");
                }
            ) => {
                if let Err(e) = result {
                    error!("RPC server error: {}", e);
                    rpc_error = Some(e.to_string());
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
        }
    }

    // Stop the node
    info!("Stopping node...");
    let started = std::time::Instant::now();
    node.stop().await.with_context(|| "Failed to stop node")?;
    shutdown_stage("node stopped", started);

    let mut clean = true;
    if let Some(wallet) = wallet_for_shutdown {
        let started = std::time::Instant::now();
        match wallet.save() {
            Ok(()) => info!("Wallet saved"),
            Err(e) => {
                error!("Failed to save wallet on shutdown: {}", e);
                clean = false;
            }
        }
        shutdown_stage("wallet saved", started);
    }
    if clean {
        let started = std::time::Instant::now();
        if let Err(e) = node.chain().end_run() {
            error!("Failed to record the clean stop: {}", e);
        }
        shutdown_stage("databases synced and the clean stop recorded", started);
    }

    info!("Node stopped");
    match rpc_error {
        Some(e) => Err(anyhow::anyhow!("RPC server error: {}", e)),
        None => Ok(()),
    }
}

/// `-electrum`, `-electrumtls`, `-electrumws` and `-electrumwss`: the Electrum server's settings; None when
/// it is off
fn electrum_config(
    args: &Args,
    config: &NodeConfig,
) -> Result<Option<divi_electrum::ElectrumConfig>> {
    let s = &args.settings;
    let addr = |name: &str| -> Result<Option<SocketAddr>> {
        match s.get(name).map(str::trim) {
            None | Some("") => Ok(None),
            Some(a) => a
                .parse()
                .map(Some)
                .with_context(|| format!("Invalid -{name}: '{a}' (an address:port)")),
        }
    };
    let tcp = addr("electrum")?;
    let ws = addr("electrumws")?;
    // -electrumtls and -electrumwss share -electrumcert and -electrumkey
    let tls_for = |flag: &str| -> Result<Option<divi_electrum::TlsConfig>> {
        let Some(bind) = addr(flag)? else {
            return Ok(None);
        };
        let file = |name: &str| -> Result<PathBuf> {
            match s.get(name).map(str::trim) {
                Some(p) if !p.is_empty() => Ok(config.data_dir.join(p)),
                _ => anyhow::bail!("-{flag} needs -{name}=<file.pem>"),
            }
        };
        Ok(Some(divi_electrum::TlsConfig {
            bind,
            cert: file("electrumcert")?,
            key: file("electrumkey")?,
        }))
    };
    let tls = tls_for("electrumtls")?;
    let wss = tls_for("electrumwss")?;
    if tcp.is_none() && tls.is_none() && ws.is_none() && wss.is_none() {
        return Ok(None);
    }
    if !config.index.txindex || !config.index.addressindex {
        anyhow::bail!("-electrum needs -txindex=1 and -addressindex=1");
    }
    if !config.rpc.enabled {
        anyhow::bail!(
            "-electrum calls the daemon through its RPC server; it cannot run with -server=0"
        );
    }
    Ok(Some(divi_electrum::ElectrumConfig {
        tcp,
        tls,
        ws,
        wss,
        banner: format!("IronDivi {} Electrum server", env!("CARGO_PKG_VERSION")),
    }))
}

/// `-webui`: the web interface's settings; None when it is off
fn webui_config(args: &Args, config: &NodeConfig) -> Result<Option<divi_webui::WebUiConfig>> {
    let s = &args.settings;
    if !s.get_bool("webui", false) {
        return Ok(None);
    }
    if !config.rpc.enabled {
        anyhow::bail!(
            "-webui calls the daemon through its RPC server; it cannot run with -server=0"
        );
    }
    let private = config.network.chain_mode == ChainMode::PrivateDivi;
    let net = config.network.network_type;
    let port = match s.get("webuiport") {
        Some(p) => p
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .with_context(|| format!("Invalid -webuiport: '{p}'"))?,
        None => divi_webui::default_port(
            private,
            net == NetworkType::Testnet,
            net == NetworkType::Regtest,
        ),
    };
    let ip: std::net::IpAddr = match s.get("webuibind").map(str::trim) {
        Some(b) if !b.is_empty() => b
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .with_context(|| format!("Invalid -webuibind: '{b}' (an IP address)"))?,
        _ => std::net::Ipv4Addr::LOCALHOST.into(),
    };
    let cli = args
        .cli
        .keys()
        .map(|k| {
            let all = args.cli.get_multi(k);
            let values = if all.is_empty() {
                args.cli.get(k).map(str::to_string).into_iter().collect()
            } else {
                all.to_vec()
            };
            (k.clone(), values)
        })
        .collect();
    Ok(Some(divi_webui::WebUiConfig {
        bind: SocketAddr::new(ip, port),
        allow_remote: s.get_bool("webuiallowremote", false),
        allow_hosts: s.get_multi("webuiallowhost").to_vec(),
        data_dir: config.data_dir.clone(),
        conf_path: config_path(args),
        network: match net {
            NetworkType::Mainnet => "main",
            NetworkType::Testnet => "test",
            NetworkType::Regtest => "regtest",
        }
        .into(),
        chain_mode: if private { "privatedivi" } else { "divi" }.into(),
        cli,
    }))
}

/// Run a notify command as divid's runCommand: through the shell, `%s`
/// replaced, not waited for
fn run_notify(cmd: &str, value: &str) {
    let cmd = cmd.replace("%s", value);
    std::thread::spawn(move || {
        match std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status()
        {
            Ok(status) if !status.success() => warn!("runCommand error: {} ({})", cmd, status),
            Ok(_) => {}
            Err(e) => warn!("runCommand error: {} ({})", cmd, e),
        }
    });
}

/// -blocknotify: run the command each time the best block changes, with the
/// new tip's hash (divid's UpdatedBlockTip, init.cpp:113-117, :518-523)
fn spawn_block_notify(chain: Arc<divi_storage::Chain>, cmd: String) {
    chain.add_tip_listener(Arc::new(move |tip| run_notify(&cmd, &tip.hash.to_string())));
}

/// The staker's settings. The minimum coin age is the network's (Divi Core
/// nMinCoinAgeForStaking, chainparams.cpp:195, :498: one hour, none on
/// regtest), the age block validation requires; there is no minimum coin
/// value, as in Core.
fn staking_config(config: &NodeConfig, chain: &divi_storage::ChainParams) -> StakingConfig {
    StakingConfig {
        // Regtest chains start from an old genesis; never apply the stale-tip guard.
        allow_stale_tip: config.staking.stake_on_stale_tip
            || config.network.network_type == NetworkType::Regtest,
        stake_split_threshold: config.staking.split_threshold,
        min_coin_age: chain.min_stake_age,
        max_block_size: config.staking.block_max_size,
        block_priority_size: config.staking.block_priority_size,
        block_min_size: config.staking.block_min_size,
        ..StakingConfig::default()
    }
}

/// How a mempool refusal of a locally submitted transaction reaches the RPC
fn submit_error(e: divi_node::NodeError) -> divi_rpc::TxSubmitError {
    use divi_node::NodeError;
    use divi_rpc::TxSubmitError;
    match e {
        // AreInputsStandard fails without a reject state in Divi Core
        // (MempoolConsensus.cpp:363-364), so sendrawtransaction answers -25
        // with its empty reject reason (rpcrawtransaction.cpp:880-883)
        NodeError::TxRejected { reason, .. } if reason == "bad-txns-nonstandard-inputs" => {
            TxSubmitError::Failed(String::new())
        }
        // A coin a mempool transaction already spends: AcceptToMemoryPool returns
        // false without a reject state (MempoolConsensus.cpp:303-313), so -25 ""
        NodeError::MempoolConflict(_) => TxSubmitError::Failed(String::new()),
        NodeError::TxRejected { code, reason, .. } => TxSubmitError::Rejected { code, reason },
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
        recently_attempted: status.recently_attempted,
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

/// Whether `block` is on the active chain (the sync layer also hands over
/// blocks it stored on a side chain)
fn block_is_active(chain: &divi_storage::Chain, block: &divi_primitives::block::Block) -> bool {
    let hash = compute_block_hash(&block.header);
    chain
        .get_block_index(&hash)
        .ok()
        .flatten()
        .and_then(|index| chain.get_block_index_by_height(index.height).ok().flatten())
        .is_some_and(|index| index.hash == hash)
}

/// The mempool side of invalidateblock and its family: the disconnected
/// blocks' transactions go back to the mempool and what the chain now spends
/// leaves it, as after any reorganization. The wallet is brought to the tip
/// first, as Divi Core's disconnectTip and connectTip tell it of every block
/// that leaves or joins the chain (SyncTransactions, ChainTipManager.cpp:189,
/// :150): blocks that left are rolled back, blocks that joined are scanned.
/// Before the mempool, so a returned transaction reaches a wallet that no
/// longer holds it as confirmed.
fn mempool_reorg_hook(
    node: &Node,
    wallet: Option<Arc<WalletDb>>,
) -> divi_rpc::blockchain::ReorgHook {
    let chain = node.chain().clone();
    let mempool = node.mempool().clone();
    Arc::new(move |disconnected| {
        if let Some(wallet) = &wallet {
            sync_wallet_to_tip(wallet, &chain);
            if let Err(e) = wallet.save_incremental() {
                error!("Failed to save the wallet after the chain moved: {}", e);
            }
        }
        divi_node::update_mempool_after_reorg(&chain, &mempool, disconnected)
    })
}

/// The mempool side of a block handed over by the sync layer or the staker.
/// A block on the active chain removes the transactions it confirms and those
/// that conflict with it, and goes to the fee estimator, as Divi Core's
/// connectTip does (removeConfirmedTransactions, ChainTipManager.cpp:139-141).
/// A block stored on a side chain confirms nothing and leaves the mempool as it
/// is. Blocks a reorganisation connected below the new tip are covered by
/// `update_mempool_after_reorg`. Returns the fees of the block's transactions
/// that were in the mempool.
fn mempool_block_connected(
    mempool: &divi_node::Mempool,
    chain: &divi_storage::Chain,
    mark_seen: impl Fn(divi_primitives::hash::Hash256),
    fee_estimator: &divi_node::FeeEstimator,
    block: &divi_primitives::block::Block,
    height: u32,
) -> divi_primitives::amount::Amount {
    let txids: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
    for txid in &txids {
        mark_seen(*txid);
    }
    let mut total_fees = divi_primitives::amount::Amount::from_sat(0);
    if !block_is_active(chain, block) {
        return total_fees;
    }
    for txid in txids.iter().skip(1) {
        if let Some(mempool_entry) = mempool.get(txid) {
            total_fees += mempool_entry.fee;
        }
    }
    mempool.remove_for_block(&txids);
    mempool.remove_conflicts(&block.transactions);
    fee_estimator.add_block(height, block, total_fees);
    total_fees
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
        let (m, state_hash) = divi_storage::snapshot::export_snapshot_with_state(
            &config.chainstate_path(),
            out,
            storage_params(config),
        )
        .context("snapshot export failed")?;
        println!(
            "snapshot written to {:?}\nnetwork {} tip {} {}\nroot_hash {}\nstate_hash {}\n\
             Other nodes import it only once a release lists this state. If this node validated \
             the chain from genesis, the entry for divi_storage::snapshot::KNOWN_STATES is:\n  \
             KnownState {{ chain_mode: ChainMode::{:?}, network: NetworkType::{:?}, height: {}, \
             block_hash: \"{}\", state_hash: \"{}\" }},",
            out,
            m.network,
            m.tip_height,
            m.tip_hash,
            m.root_hash,
            state_hash,
            config.network.chain_mode,
            storage_params(config).network_type,
            m.tip_height,
            m.tip_hash,
            state_hash
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
            "snapshot installed at {:?}\nnetwork {} tip {} {}\nroot_hash {}\nthe chain state at the tip matches the one this release knows; history below it was not validated by this node\nstart the node with --expire so it stays thin; blocks after the tip are fully validated",
            config.chainstate_path(), m.network, m.tip_height, m.tip_hash, m.root_hash
        );
    }
    Ok(())
}

async fn export_chain_command(config: NodeConfig, args: &Args) -> Result<()> {
    use divi_storage::{Chain, ChainDatabase, StorageError};

    let start_height = args.export_start.context("Missing --export-start")?;
    let end_height = args.export_end.context("Missing --export-end")?;
    let output_dir = args
        .export_output
        .as_ref()
        .context("Missing --export-output")?;

    // The node's own chain database, opened only if it is there: nothing is
    // created, and another network's database is refused as at start
    let db_path = config.chainstate_path();
    info!("Opening chain database {}", db_path.display());
    let no_chain = |e: StorageError| match e {
        StorageError::NotFound(_) => anyhow::anyhow!(
            "No chain database in {}; nothing to export (start irondivid on this data \
             directory to sync it first)",
            db_path.display()
        ),
        StorageError::ChainState(_) => anyhow::anyhow!(
            "Chain database {} holds no blocks; nothing to export",
            db_path.display()
        ),
        e => anyhow::anyhow!("Chain database {}: {}", db_path.display(), e),
    };
    let db = Arc::new(ChainDatabase::open_existing(&db_path).map_err(no_chain)?);
    let chain = Chain::open_existing(db, storage_params(&config)).map_err(no_chain)?;

    info!("Current chain height: {}", chain.height());
    info!(
        "Exporting blocks {} to {} to {:?}",
        start_height, end_height, output_dir
    );

    chain
        .export_chain(start_height, end_height, output_dir)
        .map_err(|e| anyhow::anyhow!("Failed to export chain: {}", e))?;
    // The same blocks as a block file divid and irondivid read with -loadblock
    let block_file = output_dir.join("bootstrap.dat");
    let written = chain
        .export_block_file(start_height, end_height, config.network.magic, &block_file)
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {}", block_file.display(), e))?;
    info!("Wrote {} blocks to {}", written, block_file.display());

    info!("Export complete!");
    Ok(())
}

/// -pid, default divid.pid, relative to the data directory (util.cpp:115-119)
fn pid_file_path(args: &Args, data_dir: &std::path::Path) -> PathBuf {
    match &args.pid {
        Some(p) if p.is_absolute() => p.clone(),
        Some(p) => data_dir.join(p),
        None => data_dir.join("divid.pid"),
    }
}

/// Divi Core removes its pid file in Shutdown, which also runs after a failed
/// start (init.cpp:396); only a file this process wrote is removed
fn remove_pid_file(pid_file: &std::path::Path) {
    if std::fs::read_to_string(pid_file).is_ok_and(|p| p.trim() == std::process::id().to_string()) {
        let _ = std::fs::remove_file(pid_file);
    }
}

fn main() -> Result<()> {
    // Before anything is written: the datadir holds the wallet and the RPC cookie (NODE-3)
    private_files::restrict_umask();
    // A core dump would hold unlocked wallet keys (NODE-10)
    if let Err(e) = private_files::disable_core_dumps() {
        eprintln!("Warning: could not disable core dumps: {}", e);
    }

    // Parse CLI arguments, completed from the config file where they are unset
    let args = match Args::try_parse_from(std::env::args()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            std::process::exit(1);
        }
    };
    // divid's AppInit: -?, -help and -version print and exit 1 (divid.cpp)
    if args.help || args.version {
        print!(
            "IronDivi Daemon version v{}\n{}",
            env!("CARGO_PKG_VERSION"),
            if args.help { USAGE } else { "" }
        );
        std::process::exit(1);
    }
    // ... a -datadir that is not a directory is refused (divid.cpp)
    if let Some(dir) = &args.datadir {
        if !dir.is_dir() {
            eprintln!(
                "Error: Specified data directory \"{}\" does not exist.",
                dir.display()
            );
            std::process::exit(1);
        }
    }
    let args = match resolve_args(args) {
        Ok(args) => args,
        Err(e) => {
            // divid prints its config file errors under their own heading (divid.cpp:97-98)
            match e.downcast_ref::<ConfigFileError>() {
                Some(c) => eprintln!("Error reading configuration file: {}", c),
                None => eprintln!("Error: {:#}", e),
            }
            std::process::exit(1);
        }
    };
    // ... and so are -testnet and -regtest together
    if args.testnet && args.regtest {
        eprintln!("Error: Invalid combination of -regtest and -testnet.");
        std::process::exit(1);
    }

    // Compute data directory early (needed for daemonization and logging)
    let data_dir = compute_data_dir(&args);
    if let Err(e) =
        core_files::refuse_at_start(&data_dir, args.wallet.as_deref(), args.disablewallet)
    {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }

    // Handle daemonization BEFORE initializing tokio runtime (Unix only)
    #[cfg(unix)]
    if args.daemon {
        use std::os::unix::io::AsRawFd;

        // Ensure data directory exists before daemonizing
        if let Err(e) = private_files::ensure_private_dir(&data_dir, false) {
            eprintln!("Failed to create data directory {:?}: {}", data_dir, e);
            std::process::exit(1);
        }

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
    }

    #[cfg(not(unix))]
    if args.daemon {
        eprintln!("Warning: Daemon mode is only supported on Unix systems, running in foreground");
    }

    // Now enter the tokio runtime (after daemonization)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build tokio runtime")?;
    let result = runtime.block_on(async_main(args, data_dir));
    exit_after_stop(runtime, result)
}

/// End the process once `async_main` has stopped the node and recorded the
/// clean stop. The runtime is not dropped: that would wait, with no deadline,
/// for every worker and blocking thread, and run the destructors of all the
/// node's state still held by its tasks, among them the databases' close and
/// the freeing of its caches, which reads back every page of them that is in
/// swap. The next start needs none of it: `end_run` has synced the databases'
/// logs. Divi Core likewise exits once its Shutdown() steps are done
/// (init.cpp).
fn exit_after_stop(runtime: tokio::runtime::Runtime, result: Result<()>) -> ! {
    let started = std::time::Instant::now();
    let code = match &result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            1
        }
    };
    // Let the runtime's threads go without waiting for them
    std::mem::forget(runtime);
    shutdown_stage("exit", started);
    flush_log();
    // _exit: no atexit handlers or C++ static destructors either (RocksDB's
    // thread pools would be joined there)
    unsafe { libc::_exit(code) }
}

async fn async_main(args: Args, data_dir: PathBuf) -> Result<()> {
    // Removed at a clean stop, after `args` has been taken apart
    let pid_file = pid_file_path(&args, &data_dir);

    // Build log config from CLI args
    let log_config = LogConfig {
        max_file_size: args.maxlogsize.unwrap_or(1) as u64 * 1_048_576, // Convert MB to bytes
        max_files: args.maxlogfiles.unwrap_or(5),
        debug: args.debug,
        levels: args.log_levels.spec(),
        // An export only reads the data directory: it logs to the console
        print_to_console: args.printtoconsole || args.export_chain,
    };

    // Initialize logging (writes to debug.log in data_dir by default)
    init_logging(&log_config, &args.log_levels, &data_dir);
    if !args.log_levels.unknown.is_empty() {
        warn!(
            "Unknown log categories {:?} in -debug/-loglevel (known: {})",
            args.log_levels.unknown,
            log_filter::category_names()
        );
    }
    info!("Log levels: {}", args.log_levels.spec());

    // Build configuration
    let mut config = build_config(&args)?;
    config.log = log_config;

    // Print banner
    print_banner(&config);
    core_files::warn_core_wallet(&config.data_dir);

    // Check for conflicting network options
    if args.testnet && args.regtest {
        error!("Cannot use both --testnet and --regtest");
        flush_log();
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
    // Divi Core writes its pid file with or without -daemon (init.cpp:1470)
    // All at once, so a reader never sees a partial pid (NODE-23)
    #[cfg(unix)]
    if let Err(e) =
        private_files::write_private_atomic(&pid_file, std::process::id().to_string().as_bytes())
    {
        warn!("Failed to write PID file {:?}: {}", pid_file, e);
    }

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    // SIGHUP reopens debug.log and the node keeps running, as Divi Core does
    // (init.cpp:513-516), so a logrotate postrotate line does not stop it
    #[cfg(unix)]
    {
        let mut hangup = signal::unix::signal(signal::unix::SignalKind::hangup())
            .context("Failed to install SIGHUP handler")?;
        tokio::spawn(async move {
            while hangup.recv().await.is_some() {
                REOPEN_LOG.store(true, std::sync::atomic::Ordering::Relaxed);
                info!("Received SIGHUP, reopening debug.log");
            }
        });
    }

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

    let wallet_seed = WalletSeed::from_settings(&args.settings);
    let wallet_options = WalletOptions::from_settings(&args.settings);
    let webui = webui_config(&args, &config)?;
    let electrum = electrum_config(&args, &config)?;

    // Run the daemon
    if let Err(e) = run_daemon(
        config,
        args.wallet,
        wallet_seed,
        args.disablewallet,
        wallet_options,
        shutdown_tx,
        shutdown_rx,
        webui,
        electrum,
    )
    .await
    {
        error!("Daemon error: {:#}", e);
        // Also on stderr, as Divi Core's InitError (noui.cpp:38-40): the log
        // writer may not get to write the line before the process exits
        {
            use std::io::Write as _;
            let _ = writeln!(std::io::stderr(), "Error: {:#}", e);
        }
        // Print the full error chain
        let mut source: Option<&(dyn StdError + 'static)> = e.source();
        while let Some(err) = source {
            error!("  Caused by: {}", err);
            source = err.source();
        }
        remove_pid_file(&pid_file);
        flush_log();
        std::process::exit(1);
    }

    remove_pid_file(&pid_file);

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
                "-rpcwhitelist=carol:getblockcount",
            ],
        )
        .unwrap();
        // Repeated options keep every value, the command line's first
        assert_eq!(c.rpc.rpcauth, ["bob:00ff$abcd", "carol:11ee$beef"]);
        assert_eq!(c.rpc.whitelist, ["carol:getblockcount", "bob:getinfo"]);
        assert_eq!(c.rpc.whitelist_default, Some(false));
        assert_eq!(c.rpc.allow_ips, ["192.168.1.5", "10.0.0.0/8"]);
        assert_eq!(c.rpc.allow_origins, ["https://w.example"]);
        assert_eq!(c.rpc.allow_hosts, ["node.lan"]);
        let access = c.rpc.access();
        assert_eq!(access.allow_ips, c.rpc.allow_ips);

        // Each in divid's -name=value form alone, and -rpcwhitelistdefault
        // as a bare flag; none of them set means the defaults
        let c = cfg(
            "",
            &[
                "-rpcauth=dave:22dd$cafe",
                "-rpcwhitelist=dave:getinfo",
                "-rpcwhitelistdefault",
                "-rpcalloworigin=https://x.example",
                "-rpcallowhost=box.lan",
            ],
        )
        .unwrap();
        assert_eq!(c.rpc.rpcauth, ["dave:22dd$cafe"]);
        assert_eq!(c.rpc.whitelist, ["dave:getinfo"]);
        assert_eq!(c.rpc.whitelist_default, Some(true));
        assert_eq!(c.rpc.allow_origins, ["https://x.example"]);
        assert_eq!(c.rpc.allow_hosts, ["box.lan"]);
        let c = cfg("rpcuser=u\nrpcpassword=p\n", &[]).unwrap();
        assert!(c.rpc.rpcauth.is_empty() && c.rpc.whitelist.is_empty());
        assert_eq!(c.rpc.whitelist_default, None);
        assert!(c.rpc.allow_ips.is_empty() && c.rpc.allow_hosts.is_empty());
        assert_eq!(c.rpc.listen_addr, "127.0.0.1");
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

    /// Divi Core 3.0 applies [section] settings on every network
    /// (ParseNetworkSpecificFlag); the first value of a name still wins
    #[test]
    fn section_settings_apply_first_value_wins() {
        let c = cfg("rpcuser=foo\n[test]\nrpcport=1\nrpcuser=bar\n", &[]).unwrap();
        assert_eq!(c.rpc.username.as_deref(), Some("foo"));
        assert_eq!(c.rpc.port, 1);
    }

    /// -debug and -loglevel, from the command line or the file, set the log
    /// levels; nothing set is info, and a bad level stops the start
    #[test]
    fn log_levels_come_from_debug_and_loglevel() {
        let dir = tempfile::tempdir().unwrap();
        let dd = format!("--datadir={}", dir.path().display());
        let levels = |extra: &[&str]| {
            let mut argv = vec!["irondivid", dd.as_str()];
            argv.extend(extra);
            resolve_args(Args::parse_from(argv)).map(|a| (a.debug, a.log_levels.spec()))
        };
        assert_eq!(levels(&[]).unwrap(), (false, "info".to_string()));
        assert_eq!(levels(&["-debug"]).unwrap(), (true, "debug".to_string()));
        assert_eq!(
            levels(&["-debug", "-nodebug"]).unwrap(),
            (false, "info".to_string())
        );
        assert_eq!(
            levels(&["-debug=sync", "-debug=rpc"]).unwrap(),
            (true, "info,rpc:debug,sync:debug".to_string())
        );
        assert_eq!(
            levels(&["-loglevel=warn", "-loglevel=peers:error"]).unwrap(),
            (false, "warn,peers:error".to_string())
        );
        assert!(levels(&["-loglevel=sync:loud"]).is_err());

        std::fs::write(
            dir.path().join("irondivi.conf"),
            "loglevel=warn\nloglevel=staking:trace\n",
        )
        .unwrap();
        assert_eq!(
            levels(&[]).unwrap(),
            (true, "warn,staking:trace".to_string())
        );
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

    /// -rpckeepalive is read, on by default (rpcserver.cpp:1014-1017)
    #[test]
    fn rpckeepalive_is_read() {
        assert!(cfg("regtest=1\n", &[]).unwrap().rpc.keep_alive);
        assert!(
            !cfg("regtest=1\nrpckeepalive=0\n", &[])
                .unwrap()
                .rpc
                .keep_alive
        );
        assert!(
            !cfg("regtest=1\n", &["--rpckeepalive=0"])
                .unwrap()
                .rpc
                .keep_alive
        );
    }

    /// -whitelist and -whitebind as divid reads them: a bad network or a
    /// -whitebind without a port stops the start, and -whitebind alone means
    /// listening only there (net.cpp:1749-1755, :1808-1823)
    #[test]
    fn whitelist_and_whitebind_are_divid_s() {
        let c = cfg(
            "regtest=1\nwhitelist=10.0.0.0/8\nwhitelist=192.168.1.5\n",
            &[],
        )
        .unwrap();
        assert_eq!(c.p2p.whitelist, ["10.0.0.0/8", "192.168.1.5"]);
        assert!(c.p2p.listen_on_addr && c.p2p.white_bind.is_empty());

        let err = cfg("regtest=1\nwhitelist=not-a-net\n", &[]).unwrap_err();
        assert_eq!(
            format!("{:#}", err),
            "Invalid netmask specified in -whitelist: 'not-a-net'"
        );

        let c = cfg(
            "regtest=1\nconnect=127.0.0.1:1\nwhitebind=127.0.0.1:53999\n",
            &[],
        )
        .unwrap();
        assert_eq!(c.p2p.white_bind, ["127.0.0.1:53999".parse().unwrap()]);
        assert!(
            !c.p2p.listen_on_addr,
            "-whitebind alone also listens elsewhere"
        );
        assert_eq!(c.p2p.listen, Some(true), "-whitebind turns listening on");
        let c = cfg(
            "regtest=1\nbind=127.0.0.1\nwhitebind=127.0.0.1:53999\n",
            &[],
        )
        .unwrap();
        assert!(c.p2p.listen_on_addr);

        for (bad, why) in [
            (
                "127.0.0.1",
                "Need to specify a port with -whitebind: '127.0.0.1'",
            ),
            (
                "localhost:53999",
                "Cannot resolve -whitebind address: 'localhost:53999'",
            ),
        ] {
            let err = cfg(&format!("regtest=1\nwhitebind={bad}\n"), &[]).unwrap_err();
            assert_eq!(format!("{:#}", err), why);
        }
    }
}

#[cfg(test)]
mod wallet_log_tests {
    use super::*;

    thread_local! {
        /// Where the test subscriber writes this thread's events while a
        /// capture runs on it
        static CAPTURED: std::cell::RefCell<Option<Vec<u8>>> =
            const { std::cell::RefCell::new(None) };
    }

    struct ThreadBuf;
    impl std::io::Write for ThreadBuf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            CAPTURED.with(|c| {
                if let Some(buf) = c.borrow_mut().as_mut() {
                    buf.extend_from_slice(bytes);
                }
            });
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `f` and return its result with the formatted text of every event it
    /// logged on this thread, at every level. One subscriber is installed for
    /// the whole test process, so tests running at the same time cannot change
    /// which events are enabled (a scoped subscriber per test could: tracing
    /// caches whether an event is wanted across threads).
    fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(|| ThreadBuf)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other global subscriber in the test process");
        });
        CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
        let out = f();
        let bytes = CAPTURED.with(|c| c.borrow_mut().take()).unwrap_or_default();
        (out, String::from_utf8(bytes).unwrap())
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
        // change output goes to /1/0 even though the keypool derived /1/0..999;
        // receiving key /0/0 is the default key, so getnewaddress starts at /0/1.
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

        assert_eq!(wallet.keystore().get_indices(), (1, 0));
        assert_eq!(wallet.keypool_size(), 1999);

        // Divi Core derives m/44'/1'/0'/change/i on regtest; the seed of
        // this BIP39 test vector
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();
        let account = divi_wallet::ExtendedPrivateKey::from_seed(&seed)
            .unwrap()
            .derive_hardened(44)
            .unwrap()
            .derive_hardened(1)
            .unwrap()
            .derive_hardened(0)
            .unwrap();
        let addr_at = |change: bool, i: u32| {
            let key = account
                .derive_normal(u32::from(change))
                .unwrap()
                .derive_normal(i)
                .unwrap();
            divi_wallet::KeyEntry::with_hd_path(key.secret_key().unwrap(), String::new())
                .address(WalletNetwork::Regtest)
        };
        // The whole keypool is still recognised for the catch-up scan.
        assert!(wallet.is_mine(&addr_at(false, 999)));
        assert!(wallet.is_mine(&addr_at(true, 999)));
        assert!(wallet.is_mine(&addr_at(false, 0)));

        assert_eq!(wallet.new_change_address().unwrap(), addr_at(true, 0));
        assert_eq!(wallet.new_receiving_address().unwrap(), addr_at(false, 1));
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
                51473,
            ),
            (
                &["--testnet"],
                ChainMode::Divi,
                N::Testnet,
                [0xdf, 0xa0, 0x8d, 0x78],
                51474,
                51475,
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
            recently_attempted: false,
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

#[cfg(test)]
mod log_rotation_tests {
    use super::*;
    use std::io::Write;

    /// Names and sizes of the log files in `dir`
    fn log_files(dir: &std::path::Path) -> Vec<(String, u64)> {
        let mut files: Vec<(String, u64)> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_name().to_string_lossy().starts_with("debug.log"))
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    e.metadata().unwrap().len(),
                )
            })
            .collect();
        files.sort();
        files
    }

    /// Write `lines` records of 50 bytes, checking the files after each
    fn write_and_check(max_size: u64, max_files: u32, lines: usize) -> Vec<(String, u64)> {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::open(dir.path(), max_size, max_files, false).unwrap();
        for i in 0..lines {
            let line = format!("{:049}\n", i);
            log.write_all(line.as_bytes()).unwrap();
            log.flush().unwrap();
            let files = log_files(dir.path());
            assert!(
                files.iter().any(|(n, _)| n == "debug.log"),
                "debug.log missing after line {i}: {files:?}"
            );
            assert!(
                files.iter().all(|(_, len)| *len <= max_size),
                "file over {max_size} bytes after line {i}: {files:?}"
            );
            assert!(
                files.len() <= max_files as usize,
                "more than {max_files} files after line {i}: {files:?}"
            );
        }
        // The newest record is in debug.log
        let last = std::fs::read_to_string(dir.path().join("debug.log")).unwrap();
        assert!(last.ends_with(&format!("{:049}\n", lines - 1)));
        log_files(dir.path())
    }

    #[test]
    fn log_rotation_writes_new_debug_log_within_limits() {
        // 1000 bytes per file, 20 records each: rotates 9 times
        let files = write_and_check(1000, 5, 200);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "debug.log",
                "debug.log.1",
                "debug.log.2",
                "debug.log.3",
                "debug.log.4"
            ]
        );
        assert!(files.iter().all(|(_, len)| *len == 1000));
    }

    #[test]
    fn log_rotation_with_one_file_keeps_only_debug_log() {
        let files = write_and_check(1000, 1, 50);
        assert_eq!(files, [("debug.log".to_string(), 500)]);
    }

    #[test]
    fn log_rotation_rotates_oversized_log_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("debug.log"), vec![b'x'; 2000]).unwrap();
        let mut log = RotatingLog::open(dir.path(), 1000, 3, false).unwrap();
        log.write_all(b"new\n").unwrap();
        assert_eq!(
            log_files(dir.path()),
            [
                ("debug.log".to_string(), 4),
                ("debug.log.1".to_string(), 2000)
            ]
        );
    }
}

#[cfg(test)]
mod mempool_block_tests {
    use super::*;
    use divi_primitives::amount::Amount;
    use divi_primitives::block::Block;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{OutPoint, TxIn, TxOut};

    const COIN: i64 = 100_000_000;

    fn block_on(
        chain: &divi_storage::Chain,
        parent: Hash256,
        tag: u8,
        txs: &[Transaction],
    ) -> Block {
        let parent = chain.get_block_index(&parent).unwrap().unwrap();
        let mut sig = divi_storage::bip34_height_script(parent.height + 1);
        sig.push(tag);
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = parent.hash;
        block.header.time = parent.time + 60 + u32::from(tag);
        block.header.bits = 0x207fffff;
        block.transactions = vec![Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * COIN),
                Script::from_bytes(vec![0x51]),
            )],
            lock_time: 0,
        }];
        block.transactions.extend_from_slice(txs);
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        block
    }

    /// A block the sync layer stored on a side chain confirms nothing: the
    /// mempool keeps its transactions and the fee estimator does not see it.
    /// Its sibling on the active chain removes them.
    #[test]
    fn only_a_block_on_the_active_chain_cleans_the_mempool() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::regtest(divi_primitives::ChainMode::Divi);
        config.data_dir = dir.path().to_path_buf();
        let node = divi_node::Node::new(config).unwrap();
        let chain = node.chain();
        let mut coin = None;
        for _ in 0..21 {
            let block = block_on(chain, chain.tip().unwrap().hash, 0, &[]);
            coin.get_or_insert(OutPoint::new(block.transactions[0].txid(), 0));
            chain.accept_block(block).unwrap();
        }
        let pending = Transaction {
            version: 1,
            vin: vec![TxIn::new(coin.unwrap(), Script::new(), 0xffffffff)],
            vout: vec![TxOut::new(
                Amount::from_sat(1249 * COIN),
                Script::from_bytes(vec![0x51]),
            )],
            lock_time: 0,
        };
        // A mempool without the chain checks: this is about which blocks clean
        // it, not about what it admits
        let mempool = divi_node::Mempool::new(divi_node::config::MempoolConfig::default());
        mempool
            .add(pending.clone(), Amount::from_sat(COIN))
            .unwrap();

        let parent = chain.tip().unwrap().hash;
        let side = block_on(
            chain,
            chain.tip().unwrap().prev_hash,
            1,
            std::slice::from_ref(&pending),
        );
        chain.accept_block(side.clone()).unwrap();
        assert_ne!(chain.tip().unwrap().hash, compute_block_hash(&side.header));
        let fees = mempool_block_connected(
            &mempool,
            chain,
            |_| {},
            node.fee_estimator(),
            &side,
            chain.height(),
        );
        assert!(mempool.contains(&pending.txid()));
        assert_eq!(fees, Amount::from_sat(0));

        let active = block_on(chain, parent, 0, std::slice::from_ref(&pending));
        chain.accept_block(active.clone()).unwrap();
        let fees = mempool_block_connected(
            &mempool,
            chain,
            |_| {},
            node.fee_estimator(),
            &active,
            chain.height(),
        );
        assert!(!mempool.contains(&pending.txid()));
        assert_eq!(fees, Amount::from_sat(COIN));
    }
}

#[cfg(test)]
mod staking_config_tests {
    use super::*;

    /// The staker uses the network's minimum coin age and no minimum coin
    /// value, as Divi Core's staker does
    #[test]
    fn staking_config_follows_the_network() {
        for (network, config, age) in [
            (
                divi_storage::NetworkType::Regtest,
                NodeConfig::regtest(divi_primitives::ChainMode::Divi),
                0,
            ),
            (
                divi_storage::NetworkType::Testnet,
                NodeConfig::testnet(divi_primitives::ChainMode::Divi),
                3600,
            ),
            (
                divi_storage::NetworkType::Mainnet,
                NodeConfig::mainnet(divi_primitives::ChainMode::Divi),
                3600,
            ),
        ] {
            let params =
                divi_storage::ChainParams::for_network(network, divi_primitives::ChainMode::Divi);
            let staking = staking_config(&config, &params);
            assert_eq!(staking.min_coin_age, age, "{network:?}");
            assert_eq!(staking.min_stake_amount, 0, "{network:?}");
        }
    }
}

#[cfg(test)]
mod submit_error_tests {
    use super::*;

    /// sendrawtransaction of a spend of a coin a mempool transaction spends:
    /// Divi Core's AcceptToMemoryPool keeps no reject state for it
    /// (MempoolConsensus.cpp:303-313), so the reply is -25 with an empty message
    /// (rpcrawtransaction.cpp:883-886)
    #[test]
    fn mempool_conflict_answers_like_core() {
        use divi_primitives::hash::Hash256;
        match submit_error(divi_node::NodeError::MempoolConflict(Hash256::from_bytes(
            [3; 32],
        ))) {
            divi_rpc::TxSubmitError::Failed(message) => assert_eq!(message, ""),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// A refusal Divi Core makes without a reject state reaches the RPC as
    /// -25 with an empty message; refusals with a state keep code and reason
    #[test]
    fn nonstandard_inputs_answer_like_core() {
        use divi_node::{error::reject, NodeError};
        match submit_error(NodeError::rejected(
            reject::NONSTANDARD,
            "bad-txns-nonstandard-inputs",
        )) {
            divi_rpc::TxSubmitError::Failed(message) => assert_eq!(message, ""),
            other => panic!("expected Failed, got {other:?}"),
        }
        match submit_error(NodeError::rejected(reject::NONSTANDARD, "dust")) {
            divi_rpc::TxSubmitError::Rejected { code, reason } => {
                assert_eq!((code, reason.as_str()), (reject::NONSTANDARD, "dust"))
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod wallet_move_tests {
    use super::*;

    /// Divi Core 3.0.0 regtest with -hdseed=000102030405060708090a0b0c0d0e0f
    /// gives this address at m/44'/1'/0'/0/0
    const CORE_FIRST_ADDRESS: &str = "y7VQ7R3SDRxzNuUsUuFzuq2FT1uVtW8iBz";

    /// WALLET_HDSEED restores a wallet from a hex seed, as Core's -hdseed, and
    /// is taken over WALLET_MNEMONIC (the only test here that sets them)
    #[test]
    fn hex_seed_restores_cores_first_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        std::env::set_var("WALLET_HDSEED", "000102030405060708090a0b0c0d0e0f");
        std::env::set_var(
            "WALLET_MNEMONIC",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        let wallet = load_or_create_wallet(
            &path,
            WalletNetwork::Regtest,
            ChainMode::Divi,
            WalletSeed::default(),
            &WalletOptions::default(),
        );
        std::env::remove_var("WALLET_HDSEED");
        std::env::remove_var("WALLET_MNEMONIC");
        let wallet = wallet.unwrap();
        let addresses: Vec<String> = wallet
            .get_addresses()
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert!(
            addresses.iter().any(|a| a == CORE_FIRST_ADDRESS),
            "first address differs from Core's for the same seed"
        );
        assert!(wallet.mnemonic().is_none());
    }

    /// Opening an existing wallet first copies it into backups/ and
    /// monthlyBackups/ next to it, as Divi Core does at every start
    #[test]
    fn start_makes_wallet_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        drop(
            load_or_create_wallet_from(&path, WalletNetwork::Regtest, ChainMode::Divi, None)
                .unwrap(),
        );
        let wallet =
            load_or_create_wallet_from(&path, WalletNetwork::Regtest, ChainMode::Divi, None)
                .unwrap();
        for sub in ["backups", "monthlyBackups"] {
            let entries: Vec<_> = std::fs::read_dir(dir.path().join(sub))
                .map(|r| r.flatten().map(|e| e.path()).collect())
                .unwrap_or_default();
            assert_eq!(entries.len(), 1, "{sub}: {entries:?}");
            let copy = WalletDb::open(&entries[0], WalletNetwork::Regtest).unwrap();
            assert_eq!(copy.mnemonic(), wallet.mnemonic());
        }
    }
}

/// The same divi.conf lines and command line give the node divid's values
/// (Settings.cpp, init.cpp, net.cpp, rpcserver.cpp)
#[cfg(test)]
mod divid_option_tests {
    use super::*;

    fn cfg_in(file: &str, conf: &str, extra: &[&str]) -> Result<NodeConfig> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(file), conf).unwrap();
        let mut argv = vec![
            "irondivid".to_string(),
            format!("--datadir={}", dir.path().display()),
        ];
        argv.extend(extra.iter().map(|s| s.to_string()));
        build_config(&Args::parse_from(argv))
    }

    fn cfg(conf: &str) -> NodeConfig {
        cfg_in("irondivi.conf", conf, &[]).unwrap()
    }

    /// divid reads divi.conf in its data directory
    #[test]
    fn divi_conf_in_the_data_directory_is_read() {
        let c = cfg_in("divi.conf", "rpcuser=u\nrpcpassword=p\nrpcport=1234\n", &[]).unwrap();
        assert_eq!(c.rpc.port, 1234);
        assert_eq!(c.rpc.username.as_deref(), Some("u"));
    }

    /// A divi.conf that happens to be valid TOML still means what it means to
    /// divid: a [section] line does not hide the keys after it
    /// (Settings.cpp:159-184) and quotes stay in the value. Only irondivid's
    /// own file, irondivi.conf or a .toml file, is read as TOML.
    #[test]
    fn divi_conf_is_read_as_divid_reads_it_even_when_it_is_toml() {
        let conf = "rpcuser=1\nrpcpassword=2\nrpcport=1234\n[test]\nrpcport=5\ntimeout=7\n";
        for file in ["divi.conf", "other.conf"] {
            let extra = format!("--conf={file}");
            let c = cfg_in(file, conf, &[&extra]).unwrap();
            assert_eq!(c.rpc.port, 1234, "{file}: the first value wins");
            assert_eq!(c.p2p.connect_timeout_ms, 7, "{file}: [test] keys apply");
        }
        let c = cfg_in("divi.conf", "rpcuser=\"u\"\nrpcpassword=2\n", &[]).unwrap();
        assert_eq!(c.rpc.username.as_deref(), Some("\"u\""));

        for file in ["irondivi.conf", "node.toml"] {
            let extra = format!("--conf={file}");
            let c = cfg_in(file, "rpcuser = \"u\"\nrpcport = 1236\n", &[&extra]).unwrap();
            assert_eq!(c.rpc.username.as_deref(), Some("u"), "{file}");
            assert_eq!(c.rpc.port, 1236, "{file}");
        }
    }

    /// -addnode keeps every value, the command line's first, for the added
    /// node list as well as the peers dialled
    #[test]
    fn addnode_values_in_order_command_line_first() {
        let c = cfg_in(
            "divi.conf",
            "rpcuser=u\naddnode=127.0.0.2:11\naddnode=127.0.0.2:12\n",
            &["-addnode=127.0.0.2:10"],
        )
        .unwrap();
        assert_eq!(
            c.p2p.addnode,
            ["127.0.0.2:10", "127.0.0.2:11", "127.0.0.2:12"]
        );
    }

    /// -conf is relative to the data directory (Settings::GetConfigFile)
    #[test]
    fn conf_is_relative_to_the_data_directory() {
        let c = cfg_in(
            "alt.conf",
            "rpcuser=u\nrpcport=1235\n",
            &["--conf=alt.conf"],
        )
        .unwrap();
        assert_eq!(c.rpc.port, 1235);
    }

    /// The file's first value of an option wins; the command line wins over it
    #[test]
    fn first_value_in_the_file_wins() {
        assert_eq!(cfg("rpcuser=x\nrpcport=1\nrpcport=2\n").rpc.port, 1);
        let c = cfg_in("irondivi.conf", "rpcuser=x\nrpcport=1\n", &["--rpcport=3"]).unwrap();
        assert_eq!(c.rpc.port, 3);
    }

    /// `nolisten=1` is `listen=0`, and divid reads `listen=true` as 0 (atoi)
    #[test]
    fn negation_and_divid_booleans() {
        assert_eq!(cfg("rpcuser=x\nnolisten=1\n").p2p.listen, Some(false));
        assert_eq!(cfg("rpcuser=x\nlisten=true\n").p2p.listen, Some(false));
        assert_eq!(cfg("rpcuser=x\nlisten=1\n").p2p.listen, Some(true));
    }

    /// -bind means listening even with -connect; -proxy means no listening
    #[test]
    fn bind_and_proxy_change_listening_as_in_divid() {
        let c = cfg("rpcuser=x\nconnect=127.0.0.1:1\nbind=127.0.0.1\n");
        assert!(c.peer_sources().listen);
        let c = cfg("rpcuser=x\nproxy=127.0.0.1:9050\n");
        assert!(!c.peer_sources().listen);
    }

    /// -dnsseed=0, -maxconnections, -server=0, -maxorphantx, -minrelaytxfee
    #[test]
    fn network_and_relay_options_are_applied() {
        assert!(cfg("rpcuser=x\ndnsseed=0\n").network.dns_seeds.is_empty());
        let c = cfg("rpcuser=x\nmaxconnections=20\n");
        assert_eq!((c.p2p.max_inbound, c.p2p.max_outbound), (4, 16));
        let c = NodeConfig::mainnet(ChainMode::Divi);
        assert_eq!((c.p2p.max_inbound, c.p2p.max_outbound), (109, 16));
        assert!(!cfg("rpcuser=x\nserver=0\n").rpc.enabled);
        assert_eq!(cfg("rpcuser=x\nmaxorphantx=7\n").mempool.max_orphan_txs, 7);
        assert_eq!(
            cfg("rpcuser=x\nminrelaytxfee=0.0002\n")
                .mempool
                .min_relay_fee_per_kb,
            20_000
        );
        assert!(cfg_in("irondivi.conf", "rpcuser=x\nminrelaytxfee=abc\n", &[]).is_err());
    }

    /// Divi Core keeps -minrelaytxfee in satoshis per kB (FeeRate.cpp) and
    /// refuses an amount that is not above zero (init.cpp:823-829)
    #[test]
    fn minrelaytxfee_keeps_satoshis_per_kb_as_core() {
        let floor = |text: &str| {
            let c = cfg(&format!("rpcuser=x\nminrelaytxfee={text}\n"));
            let mempool = divi_node::Mempool::new(c.mempool);
            (
                mempool.min_relay_fee_per_kb(),
                mempool.min_relay_fee_for(250),
            )
        };
        assert_eq!(floor("0.000015"), (1500, 375));
        assert_eq!(floor("0.000005"), (500, 125));
        assert_eq!(floor("0.0001"), (10_000, 2500));
        for zero in ["0", "0.0"] {
            let err = cfg_in(
                "irondivi.conf",
                &format!("rpcuser=x\nminrelaytxfee={zero}\n"),
                &[],
            )
            .err()
            .map(|e| e.to_string());
            assert_eq!(
                err.as_deref(),
                Some(format!("Invalid amount for -minrelaytxfee=<amount>: '{zero}'").as_str())
            );
        }
    }

    /// divid refuses to start with a -sporkkey that is not the network's spork
    /// key (init.cpp:971-974), whatever is wrong with it
    #[test]
    fn sporkkey_that_is_not_the_spork_key_stops_the_start() {
        let other = divi_crypto::keys::SecretKey::new_random();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(other.as_bytes());
        for wif in [
            divi_wallet::encode_wif(&bytes, true, WalletNetwork::Testnet),
            divi_wallet::encode_wif(&bytes, true, WalletNetwork::Mainnet),
            "not a key".to_string(),
            String::new(),
        ] {
            let err = cfg_in(
                "irondivi.conf",
                &format!("rpcuser=x\nregtest=1\nsporkkey={wif}\n"),
                &[],
            )
            .err()
            .map(|e| e.to_string());
            assert_eq!(
                err.as_deref(),
                Some("Unable to sign spork message, wrong key?")
            );
        }
    }

    /// The spork key check: this network's secret of that public key, in the
    /// compressed or uncompressed form the key was given in
    #[test]
    fn spork_key_check_matches_the_public_key_and_network() {
        let secret = divi_crypto::keys::SecretKey::new_random();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret.as_bytes());
        let public = secret.public_key();
        let compressed = public.serialize_compressed();
        let uncompressed = public.serialize_uncompressed();
        let testnet = divi_wallet::encode_wif(&bytes, true, WalletNetwork::Testnet);
        let mainnet = divi_wallet::encode_wif(&bytes, true, WalletNetwork::Mainnet);
        let testnet_long = divi_wallet::encode_wif(&bytes, false, WalletNetwork::Testnet);
        assert!(is_spork_key(&testnet, false, &compressed));
        assert!(is_spork_key(&mainnet, true, &compressed));
        assert!(is_spork_key(&testnet_long, false, &uncompressed));
        assert!(!is_spork_key(&testnet, true, &compressed), "other network");
        assert!(!is_spork_key(&mainnet, false, &compressed), "other network");
        assert!(
            !is_spork_key(&testnet_long, false, &compressed),
            "other key id"
        );
        let other = divi_crypto::keys::SecretKey::new_random().public_key();
        assert!(!is_spork_key(
            &testnet,
            false,
            &other.serialize_compressed()
        ));
    }

    /// Without -rpcallowip divid listens on the loopback and ignores -rpcbind
    #[test]
    fn rpcbind_needs_rpcallowip() {
        assert_eq!(
            cfg("rpcuser=x\nrpcbind=0.0.0.0\n").rpc.listen_addr,
            "127.0.0.1"
        );
    }

    /// Regtest does not stake unless asked; nor does a node without a wallet
    #[test]
    fn regtest_and_disablewallet_do_not_stake() {
        let c = cfg_in("irondivi.conf", "rpcuser=x\n", &["--regtest"]).unwrap();
        assert!(!c.staking.enabled);
        let c = cfg_in("irondivi.conf", "rpcuser=x\nstaking=1\n", &["--regtest"]).unwrap();
        assert!(c.staking.enabled);
        assert!(!cfg("rpcuser=x\ndisablewallet=1\n").staking.enabled);
        assert!(cfg("rpcuser=x\n").staking.enabled);
    }

    /// divid reads any masternode=<alias> as running as that masternode and
    /// refuses to start when it cannot; irondivid cannot run as one at all.
    /// masternodeprivkey and masternodeaddr alone do nothing in either.
    #[test]
    fn a_masternode_line_is_refused() {
        for value in ["1", "0", "mn1"] {
            let conf = format!("rpcuser=x\nmasternode={}\n", value);
            assert!(cfg_in("irondivi.conf", &conf, &[]).is_err(), "{value}");
        }
        let c = cfg_in(
            "irondivi.conf",
            "rpcuser=x\nmasternodeprivkey=abc\nmasternodeaddr=1.2.3.4:51472\n",
            &[],
        );
        assert!(c.is_ok());
    }

    /// divid's default RPC ports (chainparamsbase.cpp:25, 53)
    #[test]
    fn default_rpc_ports_are_divid_s() {
        assert_eq!(NodeConfig::mainnet(ChainMode::Divi).rpc.port, 51473);
        assert_eq!(NodeConfig::testnet(ChainMode::Divi).rpc.port, 51475);
        assert_eq!(NodeConfig::regtest(ChainMode::Divi).rpc.port, 51475);
    }
}

/// Starts divid refuses, refused with its text (init.cpp, divid.cpp, rpcserver.cpp)
#[cfg(test)]
mod start_errors {
    use super::*;

    fn start(conf: &str, argv: &[&str]) -> Result<NodeConfig> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("divi.conf"), conf).unwrap();
        let mut v = vec![
            "irondivid".to_string(),
            format!("-datadir={}", dir.path().display()),
        ];
        v.extend(argv.iter().map(|s| s.to_string()));
        build_config(&Args::parse_from(v))
    }

    fn refused(conf: &str, argv: &[&str]) -> String {
        format!(
            "{:#}",
            start(conf, argv).expect_err("the start must be refused")
        )
    }

    const CONF: &str = "regtest=1\nrpcuser=u\nrpcpassword=p\n";

    /// -maxtxfee as init.cpp:831-845: ParseMoney, then at least the relay fee
    #[test]
    fn maxtxfee_is_refused_as_divid_refuses_it() {
        for bad in ["abc", "-1", "99999999999", "1e3"] {
            assert_eq!(
                refused(CONF, &[&format!("-maxtxfee={bad}")]),
                format!("Invalid amount for -maxtxfee=<amount>: '{bad}'")
            );
        }
        assert_eq!(
            refused(CONF, &["-maxtxfee=0.00001", "-minrelaytxfee=0.0001"]),
            "Invalid amount for -maxtxfee=<amount>: '0.00001' (must be at least the minrelay \
             fee of 0.00010000 DIV/kB to prevent stuck transactions)"
        );
        assert_eq!(
            start(CONF, &["-maxtxfee=0.5"]).unwrap().mempool.max_tx_fee,
            50_000_000
        );
        assert_eq!(
            start(CONF, &[]).unwrap().mempool.max_tx_fee,
            100 * 100_000_000
        );
        assert!(
            start(CONF, &["-maxtxfee=100"]).is_ok(),
            "very high is a warning only"
        );
    }

    /// -onlynet takes ipv4, ipv6, tor or onion (netbase.cpp:70-77, init.cpp:1734-1740)
    #[test]
    fn onlynet_names_a_network_divid_knows() {
        assert_eq!(
            refused(CONF, &["-onlynet=bogus"]),
            "Unknown network specified in -onlynet: 'bogus'"
        );
        for good in ["ipv4", "IPv6", "tor", "onion"] {
            assert!(
                start(CONF, &[&format!("-onlynet={good}")]).is_ok(),
                "{good}"
            );
        }
    }

    /// -rpcbind is a numeric address, read only with -rpcallowip
    /// (rpcserver.cpp:623-629, :685-703)
    #[test]
    fn rpcbind_must_be_a_numeric_address() {
        assert_eq!(
            refused(CONF, &["-rpcallowip=127.0.0.1", "-rpcbind=garbage"]),
            "Could not parse -rpcbind value garbage as network address"
        );
        assert_eq!(
            refused(
                CONF,
                &[
                    "-rpcallowip=127.0.0.1",
                    "-rpcbind=127.0.0.1",
                    "-rpcbind=localhost"
                ]
            ),
            "Could not parse -rpcbind value localhost as network address"
        );
        assert!(
            start(CONF, &["-rpcbind=garbage"]).is_ok(),
            "ignored without -rpcallowip"
        );
        assert!(start(CONF, &["-rpcallowip=127.0.0.1", "-rpcbind=127.0.0.1:1234"]).is_ok());
        assert!(start(CONF, &["-rpcallowip=::1", "-rpcbind=[::1]:1234"]).is_ok());
    }

    /// A divi.conf line with no "=" is boost's error (divid.cpp:95-99)
    #[test]
    fn config_line_without_a_value_stops_the_start() {
        assert_eq!(
            refused(&format!("{CONF}listen\n"), &[]),
            "the options configuration file contains an invalid line 'listen'"
        );
    }

    /// divid takes -? and -help, and -version; -h and -V are not its options
    /// (divid.cpp:70-85)
    #[test]
    fn help_and_version_are_divid_s_options() {
        let parse = |a: &str| Args::parse_from(["irondivid", a]);
        assert!(parse("-?").help && parse("-help").help && parse("--help").help);
        assert!(parse("-version").version);
        assert!(!parse("-h").help && !parse("-h").version);
        assert!(!parse("-V").version);
    }

    /// One process per data directory, with divid's text (init.cpp:850-862)
    #[test]
    fn a_held_data_directory_stops_a_second_start() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_data_dir(dir.path()).unwrap();
        let e = format!("{:#}", lock_data_dir(dir.path()).unwrap_err());
        assert_eq!(
            e,
            format!(
                "Cannot obtain a lock on data directory {}. Divi Core or irondivid is probably already running.",
                dir.path().display()
            )
        );
        drop(first);
        assert!(
            lock_data_dir(dir.path()).is_ok(),
            "free again once the first exits"
        );
    }
}

#[cfg(test)]
mod resubmit_tests {
    use super::*;
    use divi_primitives::hash::Hash256;
    use divi_primitives::script::Script;
    use divi_primitives::transaction::{OutPoint, TxIn, TxOut};
    use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType as StorageNetwork};

    fn spend(prev: Hash256, value: i64) -> Transaction {
        let mut tx = Transaction::new();
        tx.vin.push(TxIn::new(
            OutPoint::new(prev, 0),
            Script::from_bytes(vec![0x51]),
            0xffff_ffff,
        ));
        tx.vout.push(TxOut::new(
            Amount::from_sat(value),
            Script::new_p2pkh(&[9u8; 20]),
        ));
        tx
    }

    /// A wallet transaction put back after a restart used to be charged a
    /// made-up fee of 10,000 sat per byte, so one paying less than the relay
    /// fee got past the mempool's fee check. It now pays what it really pays.
    #[test]
    fn node21_resubmit_uses_the_real_fee() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
        let params = ChainParams::for_network(StorageNetwork::Regtest, ChainMode::Divi);
        let chain = Arc::new(Chain::new(db, params).unwrap());
        let mempool = Arc::new(divi_node::Mempool::new(Default::default()));

        let parent = spend(Hash256::from_bytes([7u8; 32]), 5_000_000);
        let parent_id = parent.txid();
        mempool.add(parent, Amount::from_sat(1_000_000)).unwrap();

        // 100 sat for a ~85 byte transaction is under 10 sat/byte
        let cheap = spend(parent_id, 5_000_000 - 100);
        let cheap_id = cheap.txid();
        assert!(resubmit_tx(cheap, &chain, &mempool).is_err());
        assert!(!mempool.contains(&cheap_id));

        let paid = spend(parent_id, 5_000_000 - 100_000);
        let paid_id = paid.txid();
        assert_eq!(resubmit_tx(paid, &chain, &mempool), Ok(paid_id));

        // Inputs that exist nowhere are reported, not added
        let orphan = spend(Hash256::from_bytes([8u8; 32]), 1_000);
        assert_eq!(
            resubmit_tx(orphan, &chain, &mempool),
            Err("inputs no longer available".to_string())
        );
    }
}
