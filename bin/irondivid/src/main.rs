// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
mod counts;
#[cfg(unix)]
mod crash;
mod events;
mod health;
mod incidents;
mod interfaces;
mod log_delivery;
mod log_filter;
mod masternode_options;
mod private_files;
mod running_marker;
mod runs_log;
mod settings;
#[cfg(unix)]
mod signals;
mod snapshot_sig;
mod startup;
mod tasks;

/// System's, with a crash.log line when an allocation fails (A5)
#[cfg(unix)]
#[global_allocator]
static ALLOC: crash::Alloc = crash::Alloc;

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
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(not(unix))]
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Set once a console write has failed (terminal gone after an SSH drop, or
/// stdout/stderr closed): noted in debug.log the first time only
static CONSOLE_LOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Write one line to stderr (or stdout). `eprintln!` and `println!` panic when
/// the write fails (EPIPE, EIO after the terminal is gone), which killed the
/// task that made the call; a console line is never worth that (D1, D2)
fn console_line(to_stdout: bool, line: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let written = if to_stdout {
        writeln!(std::io::stdout(), "{}", line)
    } else {
        writeln!(std::io::stderr(), "{}", line)
    };
    if let Err(e) = written {
        #[cfg(unix)]
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            signals::note_epipe();
        }
        if !CONSOLE_LOST.swap(true, std::sync::atomic::Ordering::Relaxed) {
            // The log line's own timestamp says when
            warn!(
                "{} lost: {}; console lines are dropped from now on",
                if to_stdout { "stdout" } else { "stderr" },
                e
            );
        }
    }
}

/// `eprintln!` that never panics
macro_rules! console {
    ($($arg:tt)*) => { console_line(false, format_args!($($arg)*)) };
}

/// `println!` that never panics
macro_rules! console_out {
    ($($arg:tt)*) => { console_line(true, format_args!($($arg)*)) };
}

/// irondivid's exit codes (diag.md R3). 0 is a clean stop and 101 a panic on
/// the main thread; 8 is unused.
mod exit_code {
    /// -help, -version (divid's AppInit)
    pub const HELP: i32 = 1;
    /// A start divid's AppInit2 ends with false and no InitError: a stop
    /// asked for before the start was done, or -dbloadfailexit (divid.cpp:180)
    pub const QUIET: i32 = 1;
    /// An option's value; the reason names the option
    pub const USAGE: i32 = 2;
    /// The config file; the reason names the file and the line, never its text
    pub const CONFIG: i32 = 3;
    /// The data directory (create, lock, permissions) and the daemon's log file
    pub const DATADIR: i32 = 4;
    pub const DATABASE: i32 = 5;
    pub const WALLET: i32 = 6;
    pub const BIND: i32 = 7;
    /// No space left (ENOSPC) or a read-only file system (EROFS)
    pub const DISK: i32 = 9;
    /// A critical task failed, a third signal, a start-up timeout, and any
    /// start-up error R3 has no row for
    pub const FAILED: i32 = 10;
    /// The -daemon fork or setsid failed
    pub const DAEMON: i32 = 11;
}

/// End the process with `code`: the reason (when not empty) goes to
/// debug.log and the console, the log writer is flushed, and the process
/// ends with `_exit`, which runs no destructors: RocksDB's would join its
/// thread pools. The only way irondivid exits with a code other than 0
/// or 101 (A9, R3), apart from signals.rs: a third stop signal (10) and a
/// signal whose default action ends the process (128+N), which write their
/// own exit records. The panic hook in tasks.rs calls it too: 10 for a
/// critical task or thread, 101 for a main-thread panic before main's
/// `catch_unwind`. A test refuses any other exit call in this crate.
fn die(code: i32, reason: std::fmt::Arguments<'_>) -> ! {
    let reason = reason.to_string();
    // The open hour's counts, raw, ahead of the exit record (A11); like it,
    // a no-op before runs.log is open
    counts::raw_copy(|l| l.write());
    // Durable before anything else that could stall (A1); a no-op before
    // runs.log is open
    runs_log::exit(code, &reason);
    if !reason.is_empty() {
        // Before init_logging this goes nowhere; the console line is enough then
        error!("{} (exit code {})", reason, code);
        console!("{}", reason);
    }
    flush_log();
    unsafe { libc::_exit(code) }
}

/// `die(code, format_args!(...))`
macro_rules! die {
    ($code:expr) => { die($code, format_args!("")) };
    ($code:expr, $($arg:tt)*) => { die($code, format_args!($($arg)*)) };
}

/// An error that carries its exit code. Its text and its causes are the
/// inner error's, so the line printed for it is the line printed before.
#[derive(Debug)]
struct Coded {
    code: i32,
    inner: anyhow::Error,
}

impl std::fmt::Display for Coded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl StdError for Coded {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner.source()
    }
}

impl Coded {
    fn error(code: i32, inner: impl Into<anyhow::Error>) -> anyhow::Error {
        anyhow::Error::new(Coded {
            code,
            inner: inner.into(),
        })
    }
}

trait OrExit<T> {
    /// Fail with exit code `code`, unless the cause is a full or read-only disk (9)
    fn or_exit(self, code: i32) -> Result<T>;
    /// Fail with 7 when the cause is an address in use or not available, else `code`
    fn bind_or_exit(self, code: i32) -> Result<T>;
}

impl<T, E: Into<anyhow::Error>> OrExit<T> for std::result::Result<T, E> {
    fn or_exit(self, code: i32) -> Result<T> {
        self.map_err(|e| Coded::error(code, e))
    }
    fn bind_or_exit(self, code: i32) -> Result<T> {
        self.map_err(|e| {
            let e: anyhow::Error = e.into();
            let code = if causes(as_dyn(&e)).into_iter().any(is_bind_error) {
                exit_code::BIND
            } else {
                code
            };
            Coded::error(code, e)
        })
    }
}

/// `e` and every cause under it, a `Coded`'s inner error included
fn causes<'a>(e: &'a (dyn StdError + 'static)) -> Vec<&'a (dyn StdError + 'static)> {
    let mut all = Vec::new();
    let mut next = Some(e);
    while let Some(err) = next {
        all.push(err);
        next = match err.downcast_ref::<Coded>() {
            Some(coded) => Some(as_dyn(&coded.inner)),
            None => err.source(),
        };
    }
    all
}

fn as_dyn(e: &anyhow::Error) -> &(dyn StdError + 'static) {
    e.as_ref()
}

fn io_kind(e: &(dyn StdError + 'static)) -> Option<std::io::ErrorKind> {
    e.downcast_ref::<std::io::Error>().map(|io| io.kind())
}

fn is_bind_error(e: &(dyn StdError + 'static)) -> bool {
    matches!(
        io_kind(e),
        Some(std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable)
    )
}

/// ENOSPC or EROFS. RocksDB's errors reach us as text, with the OS's own
/// words for the two in it.
fn is_disk_error(e: &(dyn StdError + 'static)) -> bool {
    use std::io::ErrorKind::{ReadOnlyFilesystem, StorageFull};
    match io_kind(e) {
        Some(kind) => matches!(kind, StorageFull | ReadOnlyFilesystem),
        None => {
            let text = e.to_string();
            text.contains("No space left on device") || text.contains("Read-only file system")
        }
    }
}

/// The exit code for an error that stops irondivid (R3): a full or read-only
/// disk first, wherever it is in the causes; else the outermost cause that
/// names a code: a `Coded`, the config file, the wallet, the database, an
/// address in use; else 10.
fn exit_code_of(e: &anyhow::Error) -> i32 {
    error_exit_code(as_dyn(e))
}

fn error_exit_code(e: &(dyn StdError + 'static)) -> i32 {
    let all = causes(e);
    if all.iter().any(|e| is_disk_error(*e)) {
        return exit_code::DISK;
    }
    for err in all {
        if let Some(coded) = err.downcast_ref::<Coded>() {
            return coded.code;
        }
        if err.is::<ConfigFileError>() {
            return exit_code::CONFIG;
        }
        if err.is::<divi_wallet::WalletError>() {
            return exit_code::WALLET;
        }
        if err.is::<divi_storage::StorageError>() {
            return exit_code::DATABASE;
        }
        if is_bind_error(err) {
            return exit_code::BIND;
        }
    }
    exit_code::FAILED
}

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
    logips: bool,
    logtimestamps: bool,
    shrinkdebugfile: bool,
    /// -logwalletdetail: wallet values in clear in the logs (A11), start only
    logwalletdetail: bool,
    /// -loglevel and -debug: what is written to debug.log
    log_levels: log_filter::LogLevels,
    wallet: Option<PathBuf>,
    disablewallet: bool,
    sysperms: bool,
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
-blocknotify=<cmd> -walletnotify=<cmd> -alertnotify=<cmd>\n  \
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
        Args::try_parse_from(argv).unwrap_or_else(|e| panic!("{e:#}"))
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
                        .with_context(|| format!("invalid value for --{}", key))
                })
                .transpose()
        };
        if let Some(mode) = s.get("mode") {
            if !matches!(mode, "divi" | "privatedivi") {
                anyhow::bail!(
                    "invalid value for '--mode <MODE>' [possible values: divi, privatedivi]"
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
        self.logwalletdetail = s.get_bool("logwalletdetail", false);
        // -debug=<category> and -loglevel=<[category:]level> may repeat;
        // -debug=0 is no debugging
        self.log_levels =
            log_filter::LogLevels::parse(s.get_multi("debug"), s.get_multi("loglevel"))
                .map_err(anyhow::Error::msg)?;
        self.debug = self.log_levels.is_debug();
        self.logips = s.get_bool("logips", false);
        self.logtimestamps = s.get_bool("logtimestamps", true);
        // Default: shrink unless debugging (Logging.cpp:204)
        self.shrinkdebugfile = s.get_bool("shrinkdebugfile", !self.debug);
        self.wallet = path("wallet");
        self.disablewallet = s.get_bool("disablewallet", false);
        self.sysperms = s.get_bool("sysperms", false);
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
    // divid opens a directory as a stream that is good() and yields no line,
    // so it runs without a config file (Settings.cpp:186-205)
    if path.exists() && !path.is_dir() {
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
                .map_err(|e| ConfigFileError(format!("{}: {}", path.display(), e)))?,
        }
    }
    args.refresh()?;
    args.conf = Some(path);
    args.conf_loaded = true;
    Ok(args)
}

/// Options divid takes that irondivid has nothing for: accepted, with a warning.
/// Among them divid's test aids for parts irondivid has but does not let an
/// option change: -accountlabels (the default account's coins in every send,
/// rpcwallet.cpp:445-467, :715), -activeversion (the masternode protocol,
/// version.cpp:11-17), -manual_fork (two fork times, ForkActivation.cpp:50-55),
/// -override_mnpayee (BlockIncentivesPopulator.cpp:224) and -stakeupdatetime
/// (PoSTransactionCreator.cpp:116)
const UNSUPPORTED_OPTIONS: &[&str] = &[
    "accountlabels",
    "activeversion",
    "manual_fork",
    "override_mnpayee",
    "stakeupdatetime",
    "checklevel",
];

/// Options divid takes and does nothing with, only naming them in its help:
/// accepted without a word, as divid does (LicenseAndInfo.cpp:135, :143;
/// -disablesystemnotifications :142, -mining and -genproclimit :186-187, :205;
/// -checkpoints :165, -printpriority :201; -windowtitle :150,
/// -printstakemodifier and -printcoinstake :215-216)
const UNUSED_BY_DIVID: &[&str] = &[
    "sendfreetransactions",
    "txconfirmtarget",
    "disablesystemnotifications",
    "mining",
    "genproclimit",
    "checkpoints",
    "printpriority",
    "windowtitle",
    "printstakemodifier",
    "printcoinstake",
];

/// Options divid reads for checks and test aids of its own that irondivid has
/// no counterpart for, taken without a word as divid takes them: consistency
/// checks of its block index and mempool (BlockCheckingHelpers.cpp:162,
/// init.cpp:795), its wallet flush thread (init.cpp:1281) and signature cache
/// size (script/sigcache.cpp:51), none of which shows outside, and its message
/// fault injection (-dropmessagestest main.cpp:473, Node.cpp:479;
/// -fuzzmessagestest Node.cpp:484-485), which irondivid does not do; its
/// Berkeley DB wallet environment (-dblogsize db.cpp:101, -privdb
/// dbenv.cpp:68); the debug section of its -help (-help-debug
/// LicenseAndInfo.cpp:140-231); and the shutdown flag of its block index with
/// the recovery after a stop that was not prepared (-safe_shutdown, -recoverblockdb
/// BlockIndexLoading.cpp:258-283), a check irondivid does not make (see
/// -forcestart)
const NO_COUNTERPART: &[&str] = &[
    "checkblockindex",
    "checkmempool",
    "flushwallet",
    "maxsigcachesize",
    "dropmessagestest",
    "fuzzmessagestest",
    "dblogsize",
    "privdb",
    "help-debug",
    "safe_shutdown",
    "recoverblockdb",
];

/// Options apply_settings reads
const APPLIED: &[&str] = &[
    // read by apply_settings and the RPC access settings
    "logwalletdetail",
    "rpcauth",
    "rpcwhitelist",
    "rpcwhitelistdefault",
    "rpcalloworigin",
    "rpcallowhost",
    // divid's -forcestart skips the checks it makes after a stop that was
    // not prepared: its best block in the block index, its coin database
    // at that block (BlockIndexLoading.cpp:267-285). irondivid writes each
    // block's chain state in one batch, so after a kill it is at its last
    // whole block and has no such check to skip: the option is taken as is
    "forcestart",
    "rpcthreads",
    "alerts",
    "vault",
    // read by masternode_options
    "masternode",
    "masternodeaddr",
    "masternodeprivkey",
    "mnconf",
    "mnconflock",
    // only in divid's help: no code of divid reads them, and it says
    // nothing about them (LicenseAndInfo.cpp:209, :226)
    "litemode",
    "budgetvotemode",
    "rescan",
    "force_rescan",
    "salvagewallet",
    "dbloadfailexit",
    "allowunencryptedwallet",
    "spendzeroconfchange",
    "keypool",
    "upgradewallet",
    "createwalletbackups",
    "monthlybackups",
    "vault_min",
    "whitelisted_vault",
    "prunewalletconfs",
    "rpcuser",
    "rpcpassword",
    "rpcport",
    "server",
    "rest",
    "rpcallowip",
    "rpcbind",
    "rpckeepalive",
    "port",
    "bind",
    "listen",
    "connect",
    "addnode",
    "seednode",
    "fullnode",
    "dnsseed",
    "maxconnections",
    "timeout",
    "proxy",
    "proxyrandomize",
    "onion",
    "dns",
    "listenonion",
    "torcontrol",
    "torpassword",
    "upnp",
    // read by retired_options
    "socks",
    "tor",
    "debugnet",
    "benchmark",
    "discover",
    "externalip",
    "onlynet",
    "maxreceivebuffer",
    "maxsendbuffer",
    "logips",
    "logtimestamps",
    "shrinkdebugfile",
    "protocolversion",
    "banscore",
    "bantime",
    "checkblocks",
    "resync",
    "loadblock",
    "stopafterblockimport",
    "maxreorg",
    "maxorphantx",
    "minrelaytxfee",
    "peerbloomfilters",
    "acceptnonstandard",
    "permitbaremultisig",
    "datacarrier",
    "datacarriersize",
    "relaypriority",
    "limitfreerelay",
    "maxtxfee",
    "sporkkey",
    "staking",
    "stakeonstaletip",
    "stakesplitthreshold",
    "blockversion",
    "blockmaxsize",
    "blockprioritysize",
    "blockminsize",
    "txindex",
    "spentindex",
    "addressindex",
    "reindex",
    "utxocachesize",
    "dbcache",
    "par",
    "forcednsseed",
    "expire",
    "blocknotify",
    "alertnotify",
    "walletnotify",
    "zmqpubhashblock",
    "zmqpubhashtx",
    "zmqpubrawblock",
    "zmqpubrawtx",
    "whitelist",
    "whitebind",
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
    "sysperms",
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
    // read by main before the runtime starts
    "mocktime",
    "testsafemode",
    "disablesafemode",
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
    // divid's parameter interactions, each logged as divid logs it when it
    // sets an option not given (net.cpp:1672-1716). -bind or -whitebind means
    // listening; -connect means no DNS seeds and no listening
    let interaction = |set: bool, text: &str| {
        if set {
            info!("{}", text);
        }
    };
    if s.is_set("bind") || s.is_set("whitebind") {
        let set = s.soft_set_bool("listen", true);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -bind or -whitebind set -> setting -listen=1",
        );
    }
    if !s.get_multi("connect").is_empty() {
        let set = s.soft_set_bool("dnsseed", false);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -connect set -> setting -dnsseed=0",
        );
        let set = s.soft_set_bool("listen", false);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -connect set -> setting -listen=0",
        );
    }
    // -proxy means no listening, no UPnP and no discovery
    if s.is_set("proxy") {
        let set = s.soft_set_bool("listen", false);
        interaction(
            set,
            "SetNetworkingParameters: parameter interaction: -proxy set -> setting -listen=0",
        );
        let set = s.soft_set_bool("upnp", false);
        interaction(
            set,
            "SetNetworkingParameters: parameter interaction: -proxy set -> setting -upnp=0",
        );
        let set = s.soft_set_bool("discover", false);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -proxy set -> setting -discover=0",
        );
    }
    // -listen=0 turns -upnp, -discover and -listenonion off unless given
    if !s.get_bool("listen", true) {
        let set = s.soft_set_bool("upnp", false);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -listen=0 -> setting -upnp=0",
        );
        let set = s.soft_set_bool("discover", false);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -listen=0 -> setting -discover=0",
        );
        let set = s.soft_set_bool("listenonion", false);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -listen=0 -> setting -listenonion=0",
        );
    }
    // -externalip turns -discover off unless given
    if s.is_set("externalip") {
        let set = s.soft_set_bool("discover", false);
        interaction(
            set,
            "InitializeDivi : parameter interaction: -externalip set -> setting -discover=0",
        );
    }
    // -salvagewallet rewrites nothing in Divi Core 3.0.0: it sets -rescan
    // (EnableWalletFeatures, init.cpp:763-766), after the network ones
    // (init.cpp:1416-1418)
    if s.get_bool("salvagewallet", false) && s.soft_set_bool("rescan", true) {
        info!("InitializeDivi : parameter interaction: -salvagewallet=1 -> setting -rescan=1");
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
    // Off regtest divid will not serve RPC with the user name as the
    // password: it stops at start (rpcserver.cpp:655-678). Without a password
    // irondivid writes a cookie instead (auth_cookie.rs).
    if config.rpc.enabled && !regtest {
        if let (Some(user), Some(password)) = (&config.rpc.username, &config.rpc.password) {
            if !password.is_empty() && user == password {
                anyhow::bail!(
                    "To use irondivid you must set an rpcpassword in the configuration file.\n\
                     The username and password MUST NOT be the same."
                );
            }
        }
    }
    // The REST interface, off unless asked for (Divi Core -rest, rpcserver.cpp:1025)
    config.rpc.rest = s.get_bool("rest", false);
    // The RPC server listens on the loopback unless -rpcallowip lets others
    // in; then on -rpcbind, else on every interface (rpcserver.cpp:633-706)
    let allowed = s.get_multi("rpcallowip").to_vec();
    for (i, subnet) in allowed.iter().enumerate() {
        if divi_rpc::Subnet::parse(subnet).is_none() {
            anyhow::bail!(
                "Invalid -rpcallowip subnet specification{}. Valid are a single IP (e.g. 1.2.3.4), \
                 a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).",
                which(i, allowed.len())
            );
        }
    }
    let rpcbind = s.get_multi("rpcbind");
    if allowed.is_empty() {
        // divid binds ::1 and 127.0.0.1, and runs on either alone
        config.rpc.listen_addr = "127.0.0.1".to_string();
        config.rpc.also_listen = vec![std::net::SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            config.rpc.port,
        ))];
        if !rpcbind.is_empty() {
            warn!("option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect");
        }
    } else if let Some(first) = rpcbind.first() {
        // Each must be a numeric address, with a port or not (ParseEndpoint,
        // rpcserver.cpp:623-629, :693-703)
        for (i, addr) in rpcbind.iter().enumerate() {
            let (host, _) = host_and_port(addr);
            if host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_err()
            {
                anyhow::bail!(
                    "Could not parse -rpcbind value{} as network address",
                    which(i, rpcbind.len())
                );
            }
        }
        // Every -rpcbind is listened on, each without a port on -rpcport
        // (rpcserver.cpp:694-695)
        let default_port = config.rpc.port;
        config.rpc.also_listen = rpcbind[1..]
            .iter()
            .map(|addr| {
                let (host, p) = host_and_port(addr);
                let ip = host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .expect("checked above");
                std::net::SocketAddr::new(ip, p.unwrap_or(default_port))
            })
            .collect();
        let (host, p) = host_and_port(first);
        config.rpc.listen_addr = host;
        if let Some(p) = p {
            config.rpc.port = p;
        }
    } else {
        config.rpc.listen_addr = "[::]".to_string();
        config.rpc.also_listen = Vec::new();
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
    // GetListenPort: -port, else the network's (net.cpp)
    let listen_port = config.p2p.port;
    let binds = s.get_multi("bind");
    if let Some(first) = binds.first() {
        // A node that listens resolves every -bind, this one too, and one
        // that is no address stops the start (net.cpp:1806-1811)
        if s.get_bool("listen", true) {
            bind_address(first, listen_port)?;
        }
        let (host, p) = host_and_port(first);
        config.p2p.listen_addr = host;
        if let Some(p) = p {
            config.p2p.port = p;
        }
    }
    // Every further -bind is listened on too, on its own port or the listen
    // port (net.cpp:1809-1814)
    for raw in binds.iter().skip(1) {
        config.p2p.more_bind.push(bind_address(raw, listen_port)?);
    }
    if s.is_set("listen") {
        config.p2p.listen = Some(s.get_bool("listen", true));
    }
    // -whitelist networks; one that is not a network stops the start
    // (net.cpp:1749-1755)
    let whitelist = s.get_multi("whitelist");
    for (i, net) in whitelist.iter().enumerate() {
        if divi_network::Subnet::parse(net).is_none() {
            anyhow::bail!(
                "Invalid netmask specified in -whitelist{}",
                which(i, whitelist.len())
            );
        }
        config.p2p.whitelist.push(net.clone());
    }
    // -whitebind: a numeric address with its port; with -whitebind and no
    // -bind, only the -whitebind addresses are listened on (net.cpp:1808-1823)
    let whitebind = s.get_multi("whitebind");
    for (i, raw) in whitebind.iter().enumerate() {
        config
            .p2p
            .white_bind
            .push(white_bind_address(raw, &which(i, whitebind.len()))?);
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
    config.p2p.seednode = s.get_multi("seednode").to_vec();
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
    if s.is_set("dnsseed") {
        config.p2p.dns_seed = Some(s.get_bool("dnsseed", true));
    }
    config.p2p.force_dns_seed = s.get_bool("forcednsseed", false);
    // -maxconnections as divid reads it: atoi64, at most FD_SETSIZE (1024) less
    // one for -bind and one for -whitebind (at least one) less 150 kept for
    // files, at least 0, with no warning (net.cpp:1726-1728). Inbound peers
    // may use it less 16 (net.cpp:757); at most 16 learnt addresses are dialled
    if s.is_set("maxconnections") {
        let binds = (i64::from(s.is_set("bind")) + i64::from(s.is_set("whitebind"))).max(1);
        let n = settings::atoi(s.get("maxconnections").unwrap_or(""))
            .min(1024 - binds - 150)
            .max(0) as usize;
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
    // GetBoolArg("-proxyrandomize", true) (net.cpp:1761)
    config.p2p.proxy_randomize = s.get_bool("proxyrandomize", true);
    // -onion=<ip:port>, -onion=0 / -noonion (net.cpp:1785-1800)
    config.p2p.onion = s.get("onion").map(str::to_string);
    // GetBoolArg("-dns", DEFAULT_NAME_LOOKUP): host names are looked up only
    // with it (net.cpp:1759)
    config.p2p.name_lookup = s.get_bool("dns", true);
    // The Tor controller (init.cpp:1621, torcontrol.cpp:640, :744)
    config.p2p.listen_onion = s.get_bool("listenonion", true);
    config.p2p.tor_control = s
        .get("torcontrol")
        .unwrap_or(divi_network::torcontrol::DEFAULT_TOR_CONTROL)
        .to_string();
    config.p2p.tor_password = s.get("torpassword").unwrap_or("").to_string();
    config.p2p.upnp = s.get_bool("upnp", divi_network::upnp::DEFAULT_UPNP);
    config.p2p.discover = s.get_bool("discover", true);
    config.p2p.peer_bloom_filters = s.get_bool("peerbloomfilters", true);
    // -externalip=<ip>[:port], the listen port when none is given; one that
    // does not resolve to a valid address stops the start (net.cpp:1834-1839)
    let externalip = s.get_multi("externalip");
    for (i, raw) in externalip.iter().enumerate() {
        let addr = resolve_service(raw, config.p2p.port, config.p2p.name_lookup)
            .filter(|a| divi_network::local::is_valid(&a.ip()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot resolve -externalip address{}",
                    which(i, externalip.len())
                )
            })?;
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
    // -resync: the chain's folders are removed before it loads (init.cpp:1480-1483)
    config.resync = s.get_bool("resync", false);
    // -checkblocks: atoi64; 0 or below checks every block (verifyDb.cpp:73-74)
    if let Some(text) = s.get("checkblocks") {
        config.check_blocks = settings::atoi(text).clamp(0, i64::from(u32::MAX)) as u32;
    }
    if let Some(n) = number_option(&s, "maxreorg", 0..=i64::from(u32::MAX)) {
        config.max_reorg = Some(n as u32);
    }
    // -maxorphantx: atoi64, below 0 read as 0, then kept as an unsigned int
    // (main.cpp:790): a negative value, a text or an empty one keeps no orphan
    if let Some(text) = s.get("maxorphantx") {
        config.mempool.max_orphan_txs = settings::atoi(text).max(0) as u32 as usize;
    }
    if let Some(text) = s.get("minrelaytxfee") {
        // ParseMoney; refused unless it is an amount above zero, and kept in
        // satoshis per kB (init.cpp:823-829, FeeRate.cpp)
        let sat = parse_money(text).filter(|&sat| sat > 0).ok_or_else(|| {
            anyhow::anyhow!("Invalid amount for -minrelaytxfee=<amount> (an amount above zero)")
        })?;
        config.mempool.min_relay_fee_per_kb = sat;
    }
    config.mempool.accept_nonstandard = s.get_bool("acceptnonstandard", false);
    // GetBoolArg("-permitbaremultisig", true), read once (MempoolConsensus.cpp:31)
    config.mempool.permit_bare_multisig = s.get_bool("permitbaremultisig", true);
    // -datacarrier ? GetArg("-datacarriersize", MAX_OP_META_RELAY) : 0, kept as
    // an unsigned int, read once (MempoolConsensus.cpp:32-33)
    // GetBoolArg("-relaypriority", true), read for each transaction in Core;
    // the options do not change while a node runs (MempoolConsensus.cpp:255)
    config.mempool.relay_priority = s.get_bool("relaypriority", true);
    // GetArg("-limitfreerelay", 30), thousands of bytes per minute, read for
    // each free transaction from a peer (MempoolConsensus.cpp:228)
    config.mempool.limit_free_relay = s.get("limitfreerelay").map_or(30, settings::atoi);
    config.mempool.max_datacarrier_bytes = if s.get_bool("datacarrier", true) {
        s.get("datacarriersize")
            .map_or(603, |text| settings::atoi(text) as u32)
    } else {
        0
    };
    // -maxtxfee: an amount ParseMoney reads, at least the relay fee for 1 kB;
    // above 10 DIVI a warning (init.cpp:831-845)
    if let Some(text) = s.get("maxtxfee") {
        let invalid = || anyhow::anyhow!("Invalid amount for -maxtxfee=<amount>");
        let max_fee = parse_money(text).ok_or_else(invalid)?;
        if max_fee > 10 * 100_000_000 {
            warn!("Warning: -maxtxfee is set very high! Fees this large could be paid on a single transaction.");
        }
        let relay = config.mempool.min_relay_fee_per_kb;
        if max_fee < relay {
            anyhow::bail!(
                "Invalid amount for -maxtxfee=<amount> (must be at least the minrelay fee of {}.{:08} DIV/kB to prevent stuck transactions)",
                relay / 100_000_000,
                relay % 100_000_000
            );
        }
        config.mempool.max_tx_fee = max_fee;
    }
    // -onlynet: each one of Divi Core's network names (ParseNetwork,
    // netbase.cpp:70-77; init.cpp:1734-1740)
    let onlynet = s.get_multi("onlynet");
    for (i, net) in onlynet.iter().enumerate() {
        if divi_network::local::Network::parse(net).is_none() {
            anyhow::bail!(
                "Unknown network specified in -onlynet{} (use ipv4, ipv6, onion or tor)",
                which(i, onlynet.len())
            );
        }
        config.p2p.only_nets.push(net.to_lowercase());
    }
    // -maxreceivebuffer: thousands of bytes, read as divid's GetArg
    if let Some(v) = s.get("maxreceivebuffer") {
        config.p2p.max_receive_buffer = settings::atoi(v);
    }
    // -maxsendbuffer: thousands of bytes, read as divid's GetArg
    if let Some(v) = s.get("maxsendbuffer") {
        config.p2p.max_send_buffer = settings::atoi(v);
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
    // -blockversion: the version of the blocks made, on regtest only, read
    // as a number into the header's int (BlockFactory.cpp:90-95)
    if regtest {
        if let Some(text) = s.get("blockversion") {
            config.staking.block_version = Some(atoi(text) as i32);
        }
    }
    // Divi Core reads these with atoi64 into an unsigned int, never refusing
    // one: a word or nothing is 0, a negative one wraps; the staker clamps
    // them (BlockMemoryPoolTransactionCollector.cpp:18-42)
    for (key, slot) in [
        ("blockmaxsize", &mut config.staking.block_max_size),
        ("blockprioritysize", &mut config.staking.block_priority_size),
        ("blockminsize", &mut config.staking.block_min_size),
    ] {
        if let Some(text) = s.get(key) {
            *slot = atoi(text) as u32 as usize;
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
    // -dbcache in MiB, read as divid reads a number (atoi: 0 for a word) and
    // split as divid splits it (init.cpp:1030, :1046-1056): the block tree and
    // coin database caches make the chain database's block cache, the coins
    // in memory the UTXO cache (unless -utxocachesize gives that)
    if let Some(text) = s.get("dbcache") {
        let sizes = divi_node::config::db_cache_sizes(settings::atoi(text), config.index.txindex);
        config.block_cache_size = Some(sizes.block_tree + sizes.coin_db);
        config.utxo_cache_size = sizes.coin_cache_entries;
    }
    // -par, read as divid reads a number (atoi: 0 for a word), against the
    // machine's cores (init.cpp:801, TransactionInputChecker.cpp:16-26)
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get() as i64);
    config.script_check_threads =
        divi_storage::script_check::threads_for(settings::atoi(s.get("par").unwrap_or("0")), cores);
    if let Some(n) = number_option(&s, "utxocachesize", 0..=i64::MAX) {
        config.utxo_cache_size = n as u64;
    }
    if let Some(text) = s.get("expire") {
        config.expire = divi_storage::prune::Expire::parse(text)
            .map_err(|e| anyhow::anyhow!("-expire: {}", e))?;
    }
    config.blocknotify = s
        .get("blocknotify")
        .filter(|c| !c.is_empty())
        .map(String::from);
    config.alertnotify = s
        .get("alertnotify")
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
    // GetArg("-rpcthreads", 4), an atoi64 of the text (rpcserver.cpp:756)
    if let Some(n) = s.get("rpcthreads") {
        config.rpc.threads = settings::atoi(n);
    }
    config.p2p.alerts = s.get_bool("alerts", true);

    retired_options(settings)?;
    let mut keys: Vec<&String> = settings.keys().collect();
    keys.sort();
    for key in keys {
        let k = key.as_str();
        if let Some(text) = option_warning(settings, k) {
            warn!("{}", text);
        }
    }
    Ok(())
}

/// divid's check of the options it no longer takes, in its order
/// (CheckCriticalUnsupportedFeaturesAreNotUsed, init.cpp:770-790): a true
/// -debugnet or -benchmark draws a warning; -socks given at all and a true
/// -tor stop the start, as any -checklevel does (it always checks at level 4)
fn retired_options(s: &Settings) -> Result<()> {
    if s.get_bool("debugnet", false) {
        init_warning("Warning: Unsupported argument -debugnet ignored, use -debug=net.");
    }
    if s.is_set("socks") {
        anyhow::bail!("Error: Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported.");
    }
    if s.get_bool("tor", false) {
        anyhow::bail!("Error: Unsupported argument -tor found, use -onion.");
    }
    if s.is_set("checklevel") {
        anyhow::bail!("Error: Unsupported argument -checklevel found. Checklevel must be level 4.");
    }
    if s.get_bool("benchmark", false) {
        init_warning("Warning: Unsupported argument -benchmark ignored, use -debug=bench.");
    }
    Ok(())
}

/// divid's InitWarning: "Warning: " and the text, in debug.log and on stderr
/// (init.cpp:303-307, noui.cpp:38-40)
fn init_warning(text: &str) {
    info!("Warning: {}", text);
    eprintln!("Warning: {}", text);
}

/// The warning an option read nowhere gets: one divid takes and irondivid
/// has nothing for, or one neither knows; none for an option that is read
fn option_warning(settings: &Settings, k: &str) -> Option<String> {
    if APPLIED.contains(&k)
        || READ_ELSEWHERE.contains(&k)
        || UNUSED_BY_DIVID.contains(&k)
        || NO_COUNTERPART.contains(&k)
    {
        return None;
    }
    Some(if UNSUPPORTED_OPTIONS.contains(&k) {
        format!(
            "Option -{} is not supported by irondivid; ignored",
            settings.written_name(k)
        )
    } else {
        format!("Unknown option -{}; ignored", settings.written_name(k))
    })
}

/// A -bind value as Divi Core's Lookup reads it without name lookup: `ip`,
/// `ip:port` or `[ipv6]:port`, `port` when none is given; else the start stops
/// with "Cannot resolve -bind address" (net.cpp:1809-1813)
fn bind_address(text: &str, port: u16) -> Result<std::net::SocketAddr> {
    let text = text.trim();
    text.parse::<std::net::SocketAddr>()
        .ok()
        .or_else(|| {
            text.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| std::net::SocketAddr::new(ip, port))
        })
        .ok_or_else(|| anyhow::anyhow!("Cannot resolve -bind address: '{}'", text))
}

/// Which of a repeated option's values a refusal is about, as " (value 2
/// of 3)", or nothing when there is one: an R3 code 2 reason names the
/// option and the place, never the value (a value can be a password or an
/// address the owner keeps to themselves)
fn which(index: usize, count: usize) -> String {
    if count > 1 {
        format!(" (value {} of {})", index + 1, count)
    } else {
        String::new()
    }
}

/// A -whitebind value as Divi Core's Lookup reads it without name lookup:
/// `ip:port` or `[ipv6]:port`; the port must be given (net.cpp:1815-1821)
fn white_bind_address(text: &str, which: &str) -> Result<std::net::SocketAddr> {
    let text = text.trim();
    let addr = text.parse::<std::net::SocketAddr>().ok().or_else(|| {
        text.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| std::net::SocketAddr::new(ip, 0))
    });
    match addr {
        None => anyhow::bail!("Cannot resolve -whitebind address{}", which),
        Some(a) if a.port() == 0 => {
            anyhow::bail!("Need to specify a port with -whitebind{}", which)
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
        // The database and index checks of the start (node.rs)
        divi_node::NodeError::Init(reason) => {
            Coded::error(exit_code::DATABASE, anyhow::Error::msg(reason))
        }
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
fn resolve_service(
    text: &str,
    default_port: u16,
    name_lookup: bool,
) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    let text = text.trim();
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = text.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    // A host name only with -dns (CService(strAddr, port, fNameLookup))
    if !name_lookup {
        return None;
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
    /// -shrinkdebugfile, and when the size was last checked for it
    shrink: bool,
    shrink_checked: std::time::Instant,
}

/// Over this size debug.log is shrunk (Logging.cpp:99)
const SHRINK_ABOVE: u64 = 10 * 1_000_000;
/// What a shrink keeps of the end of debug.log (Logging.cpp:105)
const SHRINK_KEEP: u64 = 200_000;
/// How often a running node checks whether to shrink (Logging.cpp:186)
const SHRINK_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Divi Core ShrinkDebugFile (Logging.cpp:94-118): a debug.log over 10 MB is
/// cut to its last 200 000 bytes
fn shrink_debug_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let size = std::fs::metadata(path)?.len();
    if size <= SHRINK_ABOVE {
        return Ok(());
    }
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::End(-(SHRINK_KEEP as i64)))?;
    let mut tail = Vec::with_capacity(SHRINK_KEEP as usize);
    file.read_to_end(&mut tail)?;
    drop(file);
    std::fs::write(path, tail)
}

impl RotatingLog {
    fn open(
        dir: &std::path::Path,
        max_size: u64,
        max_files: u32,
        redirect_std: bool,
        shrink: bool,
    ) -> std::io::Result<Self> {
        let mut log = RotatingLog {
            dir: dir.to_path_buf(),
            max_size,
            max_files,
            redirect_std,
            file: None,
            size: 0,
            shrink,
            shrink_checked: std::time::Instant::now(),
        };
        // Shrunk at start as divid does (Logging.cpp:205); a file that is
        // still over the size limit after that is rotated
        if shrink {
            let _ = shrink_debug_file(&dir.join("debug.log"));
        }
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
        // And every five minutes while running (Logging.cpp:186-191)
        if self.shrink && self.shrink_checked.elapsed() > SHRINK_EVERY {
            self.shrink_checked = std::time::Instant::now();
            if self.size > SHRINK_ABOVE {
                self.file = None;
                let _ = shrink_debug_file(&self.dir.join("debug.log"));
                self.reopen()?;
            }
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
    // Start only, so a run's A7 record is the whole truth about it (A11)
    if spec.to_ascii_lowercase().contains("logwalletdetail") {
        events::event("setlogconfig-refused", "option=logwalletdetail");
        return Err("logwalletdetail can be set only at start".to_string());
    }
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

/// One layer of the logger, as the registry takes it
type BoxLayer = Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>;

/// Initialize logging. Every layer has its own filter (A8): the configured
/// levels govern debug.log and the console, the debug ring takes debug of
/// our own code whatever they are and leaves counted lines out.
fn init_logging(log_config: &LogConfig, levels: &log_filter::LogLevels, data_dir: &PathBuf) {
    use tracing_subscriber::Layer as _;
    // -logips: whether log lines name peers by address too (Logging.cpp:202)
    divi_network::peer_log::set_log_ips(log_config.log_ips);
    // RUST_LOG, when set, replaces -loglevel and -debug
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(levels.directives()));
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    let _ = LOG_FILTER.set(handle);
    let ring: BoxLayer = log_delivery::ring_layer(&log_delivery::RING).boxed();
    let console = |filter: tracing_subscriber::reload::Layer<
        EnvFilter,
        tracing_subscriber::Registry,
    >|
     -> BoxLayer {
        fmt::layer()
            .fmt_fields(log_delivery::Fields)
            .with_filter(filter)
            .boxed()
    };

    // In daemon mode the console is debug.log itself, so it rotates like it
    let std_is_log = stderr_is_file(&data_dir.join("debug.log"));

    if log_config.print_to_console && !std_is_log {
        // Log to console only
        tracing_subscriber::registry()
            .with(vec![console(filter), ring])
            .init();
    } else {
        // Log to file (debug.log in data directory) like C++ divid
        // Create data directory if it doesn't exist
        if let Err(e) = private_files::ensure_private_dir(data_dir, false) {
            console!(
                "Warning: Could not create data directory {:?}: {}",
                data_dir,
                e
            );
            // Fall back to console logging
            tracing_subscriber::registry()
                .with(vec![console(filter), ring])
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
            log_config.shrink,
        ) {
            Ok(log) => log,
            Err(e) => {
                console!(
                    "Warning: Could not open {:?}: {}",
                    data_dir.join("debug.log"),
                    e
                );
                tracing_subscriber::registry()
                    .with(vec![console(filter), ring])
                    .init();
                return;
            }
        };

        // Written on the caller's thread until the node runs, then by the
        // writer thread with a 2 s bound (A8); lines as divid writes them
        log_delivery::set_sink(Box::new(file_appender));
        let file: BoxLayer = fmt::layer()
            .fmt_fields(log_delivery::Fields)
            .event_format(DividLogFormat {
                timestamps: log_config.timestamps,
            })
            .with_writer(log_delivery::DebugLog)
            .with_ansi(false) // No ANSI colors in file
            .with_filter(filter)
            .boxed();
        tracing_subscriber::registry().with(vec![file, ring]).init();

        // Nothing more on stderr: divid writes there only its warnings and
        // errors (InitWarning, InitError, noui.cpp:38-40), and a -daemon child
        // keeps the stderr of the terminal it was started from
    }
}

/// A debug.log line as Divi Core writes it (Logging.cpp:179-184): with
/// -logtimestamps (default 1) the time, `%Y-%m-%d %H:%M:%S` in UTC, and a
/// space; then the message. Warnings and errors begin `WARNING: ` and
/// `ERROR: ` (divid's error() writes `ERROR: `); no level or module name.
struct DividLogFormat {
    timestamps: bool,
}

impl<S, N> fmt::FormatEvent<S, N> for DividLogFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        if self.timestamps {
            write!(
                writer,
                "{} ",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
            )?;
        }
        match *event.metadata().level() {
            tracing::Level::ERROR => write!(writer, "ERROR: ")?,
            tracing::Level::WARN => write!(writer, "WARNING: ")?,
            _ => {}
        }
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Write out the log lines not yet in debug.log (waits 2 s at most, A8).
/// Neither a direct exit nor the end of `main` drops a static, so every
/// way out of the process after logging starts calls this first: otherwise the
/// last lines, a start-up error among them, are lost whenever the writer
/// thread has not run yet (a loaded host).
fn flush_log() {
    log_delivery::flush(log_delivery::BOUND);
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
    // divid's line (init.cpp:965)
    info!(
        "Using {} threads for script verification",
        config.script_check_threads
    );
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
    /// -hdseed or -mnemonic is set, even empty: a wallet already there is
    /// moved out of the way for the restore (init.cpp:864-888)
    restore: bool,
}

impl WalletSeed {
    fn from_settings(settings: &Settings) -> Self {
        let get = |key: &str| settings.get(key).map(str::to_string);
        WalletSeed {
            mnemonic: get("mnemonic"),
            passphrase: get("mnemonicpassphrase"),
            hdseed: get("hdseed"),
            restore: settings.is_set("hdseed") || settings.is_set("mnemonic"),
        }
    }
}

/// A start that stops with exit code 1 and no error line, as Divi Core's
/// AppInit2 returning false without an InitError (-dbloadfailexit, or a stop
/// asked for before the start was done)
#[derive(Debug)]
struct QuietExit;

/// Whether `e` is a [`QuietExit`], bare or carried by a [`Coded`]
fn is_quiet_exit(e: &anyhow::Error) -> bool {
    e.downcast_ref::<QuietExit>().is_some()
        || e.downcast_ref::<Coded>()
            .is_some_and(|c| c.inner.downcast_ref::<QuietExit>().is_some())
}

impl std::fmt::Display for QuietExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the start ended before it was done")
    }
}

impl std::error::Error for QuietExit {}

/// Divi Core's CheckWalletFileExists (init.cpp:864-888): with -hdseed or
/// -mnemonic set, a wallet already there is renamed to `<wallet><time>.moved`
/// beside it, so a new one is made from the seed
fn move_wallet_for_restore(wallet_path: &Path) -> Result<()> {
    if !wallet_path.exists() {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut moved = wallet_path.as_os_str().to_os_string();
    moved.push(format!("{now}.moved"));
    std::fs::rename(wallet_path, &moved).map_err(|_| {
        anyhow::anyhow!(
            "Unable to move wallet out of the way for seed restore: {}",
            wallet_path.display()
        )
    })
}

/// Divi Core copies the wallet into backups/ (and monthlyBackups/) at every
/// start, in step 5: after the pid file, before the network and the chain
/// (BackupWallet, init.cpp:1479, :933-943). A wallet not there yet has none,
/// and the log says so.
fn backup_wallet_at_start(wallet_path: &Path, options: &WalletOptions) {
    if let Some(data_dir) = wallet_path.parent() {
        if let Err(e) =
            divi_wallet::backup::backup_at_start(wallet_path, data_dir, options.wallet_backups)
        {
            warn!("Failed to create backup: {}", e);
        }
    }
}

/// Wallet start options
#[derive(Debug, Clone)]
struct WalletOptions {
    /// -rescan: scan the whole chain at the start; -salvagewallet sets it
    /// unless it is given (init.cpp:763-766, :1242)
    rescan: bool,
    /// Whether -rescan is given: a transaction record that cannot be read
    /// asks for a rescan only when it is not (SoftSetBoolArg, walletdb.cpp:508)
    rescan_given: bool,
    /// -force_rescan: the start's scan from the genesis block, as divid's
    /// seed restore asks for it (wallet.cpp:261, :2327)
    force_rescan: bool,
    /// -dbloadfailexit, read as a number: a wallet that loads with a warning
    /// stops the start (init.cpp:1307-1309)
    db_load_fail_exit: bool,
    /// -allowunencryptedwallet: no warning at start about an unencrypted
    /// wallet (init.cpp:1228-1231)
    allow_unencrypted: bool,
    /// -spendzeroconfchange: sends may use unconfirmed outputs of our own
    /// transactions (wallet.cpp:1848)
    spend_zero_conf_change: bool,
    /// -keypool: keys of each chain the keypool is topped up to, read as a
    /// number and at least one (wallet.cpp:2071-2080)
    keypool: Option<u32>,
    /// -upgradewallet, read as a number: the highest wallet version a new
    /// wallet may have (wallet.cpp:1963-1971)
    upgrade_wallet: Option<i64>,
    /// -createwalletbackups: backups kept in backups/ and monthlyBackups/ by
    /// the backup at start, 20 by default, a negative count as 0
    /// (init.cpp:124, :938; WalletBackupCreator.cpp:21)
    wallet_backups: usize,
    /// -monthlybackups: backups kept in monthlyBackups/ by the daily check,
    /// 12 by default; 0 or less leaves the check off (init.cpp:1284,
    /// LegacyWalletDatabaseEndpointFactory.cpp:77)
    monthly_backups: usize,
    /// -vault_min, whole DIVI read as a number: managed vault coins below it
    /// are not staked (AvailableUtxoCollector.cpp:22)
    vault_min: Amount,
    /// -whitelisted_vault, each read with ParseHex: vault scripts registered
    /// at every load (init.cpp:1182-1191, :1201)
    whitelisted_vaults: Vec<Vec<u8>>,
    /// -prunewalletconfs, read as a number: wallet transactions spent that
    /// deep are left out of memory at the start (init.cpp:1574-1577)
    prune_wallet_confs: Option<i64>,
}

/// Divi Core's LoadWallet lines (walletdb.cpp:529-537): the file version a
/// 3.0.0 wallet has, and the key counts
fn log_load_counts(plaintext: usize, encrypted: usize, with_metadata: usize) {
    info!("nFileVersion = 3000000");
    info!(
        "Keys: {} plaintext, {} encrypted, {} w/ metadata, {} total",
        plaintext,
        encrypted,
        with_metadata,
        plaintext + encrypted
    );
    if plaintext + encrypted != with_metadata {
        info!("Some keys lack metadata. Wallet may require a rescan");
    }
}

/// Divi Core's IsHex (utilstrencodings.cpp:64-71): an even number of hex
/// digits, at least two, and nothing else
fn core_is_hex(text: &str) -> bool {
    !text.is_empty() && text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Divi Core's ParseHex (utilstrencodings.cpp:73-91): pairs of hex digits,
/// spaces skipped before each pair, up to the first pair that is not one
fn parse_hex_prefix(text: &str) -> Vec<u8> {
    let mut bytes = text.bytes().peekable();
    let nibble = |b: Option<u8>| b.and_then(|b| (b as char).to_digit(16));
    let mut out = Vec::new();
    loop {
        while bytes
            .next_if(|b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
            .is_some()
        {}
        let Some(high) = nibble(bytes.next()) else {
            return out;
        };
        let Some(low) = nibble(bytes.next()) else {
            return out;
        };
        out.push((high << 4 | low) as u8);
    }
}

/// divid's defaults: the options as when none is given
impl Default for WalletOptions {
    fn default() -> Self {
        WalletOptions::from_settings(&Settings::default())
    }
}

impl WalletOptions {
    fn from_settings(settings: &Settings) -> Self {
        WalletOptions {
            rescan: settings.get_bool("rescan", settings.get_bool("salvagewallet", false)),
            rescan_given: settings.get("rescan").is_some(),
            force_rescan: settings.get_bool("force_rescan", false),
            db_load_fail_exit: settings.get("dbloadfailexit").is_some_and(|v| atoi(v) != 0),
            allow_unencrypted: settings.get_bool("allowunencryptedwallet", false),
            spend_zero_conf_change: settings.get_bool("spendzeroconfchange", false),
            keypool: settings
                .get("keypool")
                .map(|v| atoi(v).clamp(1, u32::MAX as i64) as u32),
            upgrade_wallet: settings.get("upgradewallet").map(atoi),
            wallet_backups: settings
                .get("createwalletbackups")
                .map_or(divi_wallet::backup::STARTUP_BACKUPS, |v| {
                    atoi(v).max(0) as usize
                }),
            monthly_backups: settings
                .get("monthlybackups")
                .map_or(divi_wallet::backup::MONTHLY_BACKUPS, |v| {
                    atoi(v).max(0) as usize
                }),
            vault_min: Amount::from_sat(
                settings
                    .get("vault_min")
                    .map_or(0, |v| atoi(v).saturating_mul(100_000_000)),
            ),
            whitelisted_vaults: settings
                .get_multi("whitelisted_vault")
                .iter()
                .map(|v| parse_hex_prefix(v))
                .collect(),
            prune_wallet_confs: settings.get("prunewalletconfs").map(atoi),
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

/// The WALLET_MNEMONIC, WALLET_MNEMONIC_PASSPHRASE and WALLET_HDSEED
/// environment variables, each taken when its option is not set (see
/// `WalletSeed`), and WALLET_CHAIN_MODE and WALLET_LOOKAHEAD, read by a
/// restore
#[derive(Default)]
struct WalletEnv {
    mnemonic: Option<String>,
    passphrase: Option<String>,
    hdseed: Option<String>,
    chain_mode: Option<String>,
    lookahead: Option<String>,
}

impl WalletEnv {
    fn from_process() -> Self {
        let env = |name: &str| std::env::var(name).ok();
        WalletEnv {
            mnemonic: env("WALLET_MNEMONIC"),
            passphrase: env("WALLET_MNEMONIC_PASSPHRASE"),
            hdseed: env("WALLET_HDSEED"),
            chain_mode: env("WALLET_CHAIN_MODE"),
            lookahead: env("WALLET_LOOKAHEAD"),
        }
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
    load_or_create_wallet_with_env(
        wallet_path,
        network,
        chain_mode,
        seed,
        options,
        WalletEnv::from_process(),
    )
}

/// `env` is the WALLET_* variables; passed in so tests never touch the
/// process environment
fn load_or_create_wallet_with_env(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
    seed: WalletSeed,
    options: &WalletOptions,
    env: WalletEnv,
) -> Result<Arc<WalletDb>> {
    // A hex -hdseed is preferred over -mnemonic and -mnemonicpassphrase,
    // logged at every start, a wallet there or not (init.cpp:945-951)
    if seed.hdseed.as_deref().is_some_and(core_is_hex)
        && (seed.mnemonic.is_some() || seed.passphrase.is_some())
    {
        info!("PruneHDSeedParameterInteraction: parameter interaction: can't use -hdseed and -mnemonic/-mnemonicpassphrase together, will prefer -seed");
    }
    // An empty mnemonic asks for a new one, as in Core
    let mnemonic = seed
        .mnemonic
        .or_else(|| env.mnemonic.clone())
        .filter(|m| !m.trim().is_empty());
    let passphrase = seed.passphrase.or_else(|| env.passphrase.clone());
    let hdseed = seed.hdseed.or_else(|| env.hdseed.clone());
    load_or_restore_wallet_with_seed(
        wallet_path,
        network,
        chain_mode,
        mnemonic,
        passphrase,
        hdseed,
        options,
        &env,
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
        &WalletEnv::default(),
    )
}

/// `load_or_restore_wallet`, where a new wallet may instead come from a hex
/// `seed` (Divi Core's -hdseed, taken over a mnemonic); a restore takes
/// WALLET_CHAIN_MODE and WALLET_LOOKAHEAD from `env`
#[allow(clippy::too_many_arguments)]
fn load_or_restore_wallet_with_seed(
    wallet_path: &PathBuf,
    network: WalletNetwork,
    chain_mode: ChainMode,
    restoring: Option<String>,
    passphrase: Option<String>,
    seed: Option<String>,
    options: &WalletOptions,
    env: &WalletEnv,
) -> Result<Arc<WalletDb>> {
    // Try to open existing wallet (backed up by `backup_wallet_at_start`)
    if wallet_path.exists() {
        info!("Loading wallet from {:?}", wallet_path);
        // Only this user may read the wallet (NODE-3)
        if let Err(e) = private_files::ensure_private_dir(wallet_path, true) {
            warn!("Could not check the wallet directory permissions: {}", e);
        }
        let wallet = match WalletDb::open(wallet_path, network) {
            // A key record that cannot be read: Divi Core's DB_CORRUPT, an
            // InitError (init.cpp:1153-1156, :1299-1305)
            Err(divi_wallet::WalletError::Corrupt) => {
                let message = divi_wallet::WalletError::Corrupt.to_string();
                error!("Errors detected during wallet loading\n{}", message);
                return Err(anyhow::Error::msg(message));
            }
            other => {
                other.with_context(|| format!("Failed to open wallet at {:?}", wallet_path))?
            }
        };
        // Other records that cannot be read: a warning, and the start goes
        // on unless -dbloadfailexit (DB_NONCRITICAL_ERROR, init.cpp:1157-1162,
        // :1299-1310)
        let problems = wallet.load_problems();
        if problems.transactions + problems.others > 0 {
            let message = "Warning: error reading wallet.dat! All keys read correctly, but transaction data or address book entries might be missing or incorrect.";
            info!("Errors detected during wallet loading\n{}", message);
            // InitWarning: "Warning: " and the message, logged and on stderr
            // (noui.cpp:38-40)
            warn!("Warning: {}", message);
            eprintln!("Warning: {}", message);
            if options.db_load_fail_exit {
                return Err(anyhow::Error::new(QuietExit));
            }
        }

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

        let (plaintext, encrypted, with_metadata) = wallet.load_counts();
        log_load_counts(plaintext, encrypted, with_metadata);
        warn_if_unencrypted(&wallet);
        info!("Wallet loaded successfully");
        return Ok(Arc::new(wallet));
    }

    // Create a new wallet: from -hdseed, else from -mnemonic or new words,
    // with -mnemonicpassphrase (Divi Core GenerateNewHDChain, wallet.cpp:2282-2316)

    // Divi Core takes -hdseed when it is hex and logs anything else, then
    // goes on with the mnemonic or a new seed (wallet.cpp:2286-2297)
    let seed = match seed {
        Some(hex_seed) if core_is_hex(&hex_seed) => hex::decode(&hex_seed).ok(),
        Some(_) => {
            info!("CWallet::GenerateNewHDChain -- Incorrect seed, generating random one instead");
            None
        }
        None => None,
    };
    let restoring = if seed.is_some() { None } else { restoring };
    let passphrase = if seed.is_some() { None } else { passphrase };
    // The version limit is checked before the seed is made
    // (wallet.cpp:1963-1979), and before anything is written
    if options.refuses_new_wallet() {
        // As Divi Core logs it (wallet.cpp:1969, init.cpp:1303)
        info!("Unable to downgrade wallet version. -upgradewallet=<custom_version> might be incorrectly set");
        let message = "Error loading wallet.dat: database load failure";
        error!("Errors detected during wallet loading\n{}", message);
        anyhow::bail!(message);
    }
    // Checked only when words make the wallet, before anything is written
    // (wallet.cpp:2302-2305, reported by init.cpp:1203-1209)
    if passphrase.as_ref().is_some_and(|p| p.len() > 256) {
        anyhow::bail!(
            "Error loading or creating wallet.dat, GenerateNewHDChain: Mnemonic passphrase is too long, must be at most 256 characters"
        );
    }

    let hd_wallet = if let Some(ref seed) = seed {
        info!("Restoring wallet from -hdseed");
        HdWallet::from_seed(seed, chain_mode)
            .with_context(|| "Failed to restore HD wallet from seed")?
    } else if let Some(ref mnemonic) = restoring {
        // Use WALLET_CHAIN_MODE env var to override chain mode for mnemonic restore.
        // Falls back to the --mode flag value so PrivateDivi nodes derive correct addresses.
        let restore_chain_mode = env
            .chain_mode
            .as_deref()
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
        // Words of an unknown count, outside the word list or failing their
        // checksum: CMnemonic::Check refuses them, before the wallet is made
        // (hdchain.cpp:63-65, init.cpp:1203-1209)
        HdWallet::from_mnemonic(mnemonic, passphrase.as_deref(), restore_chain_mode).map_err(
            |_| {
                anyhow::anyhow!(
                    "Error loading or creating wallet.dat, SetMnemonic: invalid mnemonic: please check your words`"
                )
            },
        )?
    } else {
        // No mnemonic: new words, with the passphrase if one is given
        // (hdchain.cpp:56-67)
        HdWallet::generate(passphrase.as_deref(), chain_mode)
            .with_context(|| "Failed to generate HD wallet")?
    };

    // Divi Core loads the empty wallet file before it makes the keys
    log_load_counts(0, 0, 0);
    info!("Creating new wallet at {:?}", wallet_path);
    // Only this user may read the wallet (NODE-3)
    private_files::ensure_private_dir(wallet_path, true)
        .with_context(|| format!("Failed to create wallet directory: {:?}", wallet_path))?;

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
        .then(|| env.lookahead.as_deref()?.parse::<u32>().ok())
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
        console!(
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
/// restart (Core's SubmitUnconfirmedWalletTransactionsToMempool,
/// init.cpp:1262-1275), so a send made before the node stopped can still
/// confirm. Those the mempool dropped earlier (detached, at depth -1) are
/// offered too, as Core offers every wallet transaction with fewer than 0
/// confirmations. Runs after the catch-up scan, which has
/// already dropped the ones mined meanwhile. A transaction whose inputs are
/// neither unspent on chain nor outputs of a transaction in the mempool can
/// never confirm (spent by another transaction while we were down): the
/// wallet forgets it, as it does when the mempool evicts one. Nothing is
/// announced to peers, as Core announces none of them then.
fn resubmit_wallet_txs(node: &Node, wallet: &Arc<WalletDb>) {
    let txs = wallet.transactions_to_resubmit();
    if txs.is_empty() {
        return;
    }
    let mut resubmitted = 0;
    for (tx, detached) in txs {
        let txid = tx.txid();
        match resubmit_tx(tx, node.chain(), node.mempool()) {
            // Added to the mempool only, not announced: Divi Core's
            // SubmitTransactionToMempool runs AcceptToMemoryPool alone
            // (init.cpp:1272, txmempool.cpp:408-415); peers hear of the
            // transaction from the periodic mempool rebroadcast
            Ok(_) => {
                resubmitted += 1;
            }
            // A detached transaction the mempool refuses stays as it is, at
            // depth -1, as Divi Core's wallet keeps it
            Err(e) if detached => {
                debug!(
                    "Detached wallet tx {} not resubmitted: {}",
                    divi_primitives::redact::WalletTxid::of(txid),
                    e
                );
            }
            Err(e) => {
                warn!(
                    "Unconfirmed wallet tx {} cannot be resubmitted ({}); forgetting it",
                    divi_primitives::redact::WalletTxid::of(txid),
                    e
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
    // Divi Core waits up to 10 seconds for the lock, for a node still on its
    // way out (init.cpp:858-860)
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
                "Cannot obtain a lock on data directory {}. Divi Core or irondivid is probably already running.",
                dir.display()
            ),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).with_context(|| format!("Failed to lock {:?}", dir.join(".lock")))
            }
        }
    }
}

/// How long a start waits for the data directory lock (init.cpp:858-860)
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Run the daemon
#[allow(clippy::too_many_arguments)]
async fn run_daemon(
    mut config: NodeConfig,
    wallet_path: Option<PathBuf>,
    wallet_seed: WalletSeed,
    disable_wallet: bool,
    wallet_options: WalletOptions,
    mn_options: masternode_options::MasternodeOptions,
    shutdown_tx: broadcast::Sender<()>,
    shutdown_rx: broadcast::Receiver<()>,
    pid_file: PathBuf,
    webui: Option<divi_webui::WebUiConfig>,
    electrum: Option<divi_electrum::ElectrumConfig>,
) -> Result<()> {
    runs_log::phase("datadir");
    // Create data directory if it doesn't exist
    private_files::ensure_private_dir(&config.data_dir, false)
        .with_context(|| format!("Failed to create data directory: {:?}", config.data_dir))
        .or_exit(exit_code::DATADIR)?;
    // One process per data directory, held until this one exits
    // (TryLockDataDirectory, init.cpp:850-862)
    runs_log::phase("lock");
    let _datadir_lock = lock_data_dir(&config.data_dir).or_exit(exit_code::DATADIR)?;
    // Only the holder of the lock may read or replace the marker (A2)
    runs_log::marker_create();
    // With -hdseed or -mnemonic the wallet there is moved out of the way once
    // the lock is held, before the pid file and before anything is opened, as
    // Divi Core's CheckWalletFileExists (init.cpp:1460-1467, :864-888)
    let wallet_dir = core_files::wallet_dir(&config.data_dir, wallet_path.as_deref());
    if !disable_wallet && wallet_seed.restore {
        move_wallet_for_restore(&wallet_dir)?;
    }
    // Divi Core writes its pid file once it holds the lock, with or without
    // -daemon (init.cpp:1470), so a second start leaves a running node's alone
    #[cfg(unix)]
    write_pid_file(&pid_file);
    if !disable_wallet {
        backup_wallet_at_start(&wallet_dir, &wallet_options);
    }
    // The clock warning of the network time offset goes where Divi Core's
    // Warnings::setMiscWarning puts it: getinfo's and getmininginfo's "errors"
    // (timedata.cpp:96-97)
    divi_network::timedata::on_clock_warning(divi_rpc::warnings::set_misc_warning);

    // -webui: take its port now, so a port in use stops the start at once
    let webui = webui
        .map(divi_webui::prepare)
        .transpose()
        .bind_or_exit(exit_code::USAGE)?;
    let webui_shutdown = shutdown_tx.subscribe();
    // -electrum: the same, for the Electrum server's ports and certificate
    let electrum = electrum
        .map(divi_electrum::prepare)
        .transpose()
        .bind_or_exit(exit_code::USAGE)?;
    let electrum_shutdown = shutdown_tx.subscribe();

    // Divi Core Discover: the interfaces' addresses (net.cpp:1385-1425)
    if config.p2p.discover {
        config.p2p.interface_ips = interfaces::addresses();
    }

    // Initialize the node
    info!("Initializing node...");
    // The databases open and the chain loads in Node::new (db-open and
    // chain-load are one phase until divi-node reports the boundary)
    runs_log::phase("db-open");
    // Never dropped: the process ends without running the destructors of the
    // node's state (databases, caches, mempool), see `exit_after_stop`
    let node = std::mem::ManuallyDrop::new(Node::new(config.clone()).map_err(start_error)?);
    // Divi Core's import thread (-reindex, bootstrap.dat, -loadblock) starts
    // once the wallet is loaded (init.cpp:1580); here the wallet is loaded
    // after the node starts, so the thread waits until then (below)
    node.hold_import();

    // -blocknotify, before any block comes in (init.cpp:1563-1564)
    if let Some(cmd) = config.blocknotify.clone() {
        spawn_block_notify(node.chain().clone(), cmd);
    }
    spawn_version_warning(node.chain().clone(), config.alertnotify.clone());
    // The chain's fork warning check sets what Divi Core's
    // Warnings::setLargeWorkInvalidChainFound does: getinfo's and
    // getmininginfo's "errors", and safe mode (Warnings.cpp:41-47)
    node.chain().add_fork_warning_listener(Arc::new(
        divi_rpc::warnings::set_large_work_invalid_chain_found,
    ));
    divi_rpc::warnings::set_large_work_invalid_chain_found(
        node.chain().large_work_invalid_chain_found(),
    );

    // The ZMQ notifiers, before the chain takes blocks (init.cpp:1495-1500).
    // Kept for the life of the node; none if an address cannot be bound.
    let _zmq = divi_node::zmq::ZmqNotifier::start(&config.zmq, node.chain(), node.mempool());

    // Divi Core's last check before it starts the node: 50 MB free on the
    // data directory's filesystem (init.cpp:1604-1605)
    if !divi_storage::disk_space::check_disk_space(&config.data_dir, 0) {
        divi_storage::abort::abort_node("Disk space is low!");
        anyhow::bail!("Disk space is low!");
    }

    // Start the node
    runs_log::phase("network");
    node.start().await.map_err(|e| match e {
        // start()'s only Init: no P2P listener could be bound
        // (bind_listeners); its io error is text by then (R3)
        divi_node::NodeError::Init(_) => Coded::error(
            exit_code::BIND,
            anyhow::Error::new(e).context("Failed to start node"),
        ),
        e => anyhow::Error::new(e).context("Failed to start node"),
    })?;

    // Divi Core's -stopafterblockimport: the import thread asks for shutdown
    // once it is done (init.cpp:724-727). divid starts that thread once its
    // chain and wallet are loaded and scanned (init.cpp:1578), so its stop
    // comes after its init has returned, and it exits 0 (divid.cpp:146-180).
    // irondivid's import goes on once its wallet is loaded (`release_import`),
    // still before the end of its start, and a short one can end there: the
    // stop is asked for once the start is done (`start_done`), so that only a
    // signal or `stop` counts as a stop during the start (exit 1, below)
    let start_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if config.stop_after_block_import {
        let chain = node.chain().clone();
        let tx = shutdown_tx.clone();
        let start_done = Arc::clone(&start_done);
        tasks::spawn_supervised("stop-after-import", async move {
            while chain.is_importing() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            info!("Stopping after block import");
            while !start_done.load(std::sync::atomic::Ordering::Acquire) {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let _ = tx.send(());
            runs_log::stop_requested("stopafterblockimport");
        });
    }

    info!("Node started, chain height: {}", node.chain().height());
    // The hourly count lines of the counted sites (A11)
    counts::init();
    tasks::spawn_supervised("counts", counts::run());
    health::start(health::Handles {
        chain: node.chain().clone(),
        block_sync: node.block_sync().clone(),
        peers: node.peer_manager().clone(),
        mempool: node.mempool().clone(),
        data_dir: config.data_dir.clone(),
    });

    // Get chain and peer manager references for RPC server
    let chain = node.chain().clone();
    let peer_manager = node.peer_manager().clone();

    // Load or create wallet (unless disabled)
    runs_log::phase("wallet-load");
    let wallet = if disable_wallet {
        info!("Wallet disabled!");

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
        let wallet_network = match config.network.network_type {
            NetworkType::Mainnet => WalletNetwork::Mainnet,
            NetworkType::Testnet => WalletNetwork::Testnet,
            NetworkType::Regtest => WalletNetwork::Regtest,
        };
        let wallet = Some(
            load_or_create_wallet(
                &wallet_dir,
                wallet_network,
                config.network.chain_mode,
                wallet_seed,
                &wallet_options,
            )
            .or_exit(exit_code::WALLET)?,
        );
        if let Some(ref w) = wallet {
            // Divi Core warns at every start of a wallet that is not locked,
            // unless -allowunencryptedwallet; not after the load's own warning,
            // which returns first (init.cpp:1220-1231)
            let problems = w.load_problems();
            if !wallet_options.allow_unencrypted
                && !w.is_locked()
                && problems.transactions + problems.others == 0
            {
                let message = "Make sure to encrypt your wallet and delete all non-encrypted backups after you verified that wallet works!";
                warn!("Warning: {}", message);
                eprintln!("Warning: {}", message);
            }
            // Timed unlocks drop their keys when they run out (NODE-6)
            WalletDb::start_auto_lock(w);
            w.set_vault_mode(config.vault);
            // Before the wallet catches up with the chain, as divid loads
            // them with the wallet (init.cpp:1201, :1242)
            for script in &wallet_options.whitelisted_vaults {
                if w.whitelist_vault(script) {
                    info!("Whitelisted vault {} registered", hex::encode(script));
                }
            }
            w.set_spend_zero_conf_change(wallet_options.spend_zero_conf_change);
            w.set_vault_min(wallet_options.vault_min);
            w.set_relay_fee_per_kb(config.mempool.min_relay_fee_per_kb);
            w.set_max_tx_fee(config.mempool.max_tx_fee);
            // A spork 14 entry sets the fees the wallet's sends pay and may pay
            {
                let (w, chain) = (Arc::clone(w), node.chain().clone());
                node.spork_manager().on_tx_fee_spork(Arc::new(move || {
                    if let Some(fee) = chain.tx_fee_spork_at_tip() {
                        w.set_relay_fee_per_kb(fee.min_fee_per_kb as i64);
                        w.set_max_tx_fee(fee.max_fee as i64);
                    }
                }));
            }
            // -walletnotify, before the wallet catches up with the chain
            // (init.cpp:1199, before the rescan at :1242)
            if let Some(cmd) = config.walletnotify.clone() {
                w.set_tx_listener(Arc::new(move |txid| {
                    run_notify("walletnotify", &cmd, &txid.to_string())
                }));
            }
        }

        // Register unified block-connected callback (mempool cleanup + fee estimation + wallet scan)
        if let Some(ref wallet_arc) = wallet {
            let block_sync = node.block_sync();
            block_sync.set_block_connected_callback(wallet_block_callback(
                Arc::clone(wallet_arc),
                node.mempool().clone(),
                node.fee_estimator().clone(),
                node.tx_relay().clone(),
                node.chain().clone(),
            ));
            debug!("Unified block callback registered (mempool + fees + wallet)");

            // Mirror wallet-relevant mempool transactions into the wallet so
            // unconfirmed sends and receives show up immediately (0 confirmations).
            // The listeners fire for every path into and out of the mempool: P2P
            // relay, local RPC sends, confirmation, eviction and clearing.
            {
                let wallet_for_added = Arc::clone(wallet_arc);
                node.mempool()
                    .add_added_listener(Arc::new(move |tx: &Transaction| {
                        // No log line: its time beside the relay lines would
                        // pick out the wallet's own transactions in debug.log
                        wallet_for_added.add_mempool_tx(tx);
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
            // A transaction record that could not be read asks for a rescan,
            // unless -rescan is given (walletdb.cpp:505-508)
            let rescan = wallet_options.rescan
                || (!wallet_options.rescan_given && wallet_arc.load_problems().transactions > 0);
            if rescan {
                info!("Rescanning... from height 0 to {}", chain_height);
                wallet_arc.set_last_scan_height(0);
            } else if wallet_options.force_rescan {
                // -force_rescan scans from the genesis block too, under the
                // word for a scan that was not asked for (wallet.cpp:261-262, :292)
                info!("Scanning... from height 0 to {}", chain_height);
                wallet_arc.set_last_scan_height(0);
            } else {
                // Divi Core scans from the wallet's stored best block, itself
                // included (wallet.cpp:258-269, :279-313): the last block is
                // scanned again at every start. A wallet that never scanned
                // starts at the genesis block. Its line names both ends
                // (wallet.cpp:292-294)
                let scanned = wallet_arc.last_scan_height();
                divi_rpc::wallet::resume_wallet_scan(wallet_arc, node.chain());
                let from = if scanned == 0 {
                    0
                } else {
                    wallet_arc.last_scan_height() + 1
                };
                info!("Scanning... from height {} to {}", from, chain_height);
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

            // -prunewalletconfs, at least 20, once the wallet has caught up
            // with the chain (wallet.cpp:1162-1240, init.cpp:1574-1577)
            if let Some(confs) = wallet_options.prune_wallet_confs {
                let chain = node.chain();
                let (original, kept) =
                    wallet_arc.prune_transactions(confs.max(20), chain.height(), |t| {
                        let block = chain.get_block(t.block_hash.as_ref()?).ok()??;
                        let index = block
                            .transactions
                            .iter()
                            .position(|tx| tx.txid() == t.txid)?;
                        Some((block.transactions[index].clone(), index))
                    });
                info!(
                    "Pruned wallet transactions loaded to memory: Original {} vs. Current {}",
                    original, kept
                );
            }

            // Divi Core checks a day after start, and a day after each check,
            // whether a monthly backup is due; on regtest the day is counted
            // on mock time (LegacyWalletDatabaseEndpointFactory.cpp:111-121,
            // MockMilliSleep in utiltime.cpp:54-60)
            if wallet_options.monthly_backups > 0 {
                let wallet_for_backup = Arc::clone(wallet_arc);
                let backup_root = wallet_dir.parent().map(|p| p.to_path_buf());
                let keep = wallet_options.monthly_backups;
                let clock: fn() -> i64 = if config.network.network_type == NetworkType::Regtest {
                    divi_primitives::clock::now
                } else {
                    divi_primitives::clock::system_now
                };
                tasks::spawn_supervised("wallet-backup", async move {
                    let Some(root) = backup_root else { return };
                    const DAY: i64 = 24 * 3600;
                    let mut since = clock();
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        if clock() - since <= DAY {
                            continue;
                        }
                        let wallet = Arc::clone(&wallet_for_backup);
                        let root = root.clone();
                        let made = tasks::spawn_blocking("wallet-backup", move || {
                            divi_wallet::backup::monthly_backup(&wallet, &root, keep)
                        })
                        .await;
                        match made {
                            Ok(Ok(Some(path))) => info!("Monthly wallet backup {}", path.display()),
                            Ok(Ok(None)) => {}
                            Ok(Err(e)) => warn!("Monthly wallet backup failed: {}", e),
                            Err(e) => warn!("Monthly wallet backup failed: {}", e),
                        }
                        since = clock();
                    }
                });
            }
        }

        // Divi Core's debug print at the end of the start, 0 without a
        // wallet (init.cpp:1613-1618)
        let (pool, book) = wallet
            .as_ref()
            .map_or((0, 0), |w| (w.keypool_size(), w.address_book().len()));
        info!("Key Pool size = {}", pool);
        info!("Address Book size = {}", book);

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
        tasks::spawn_supervised("block-expiry", async move {
            loop {
                let floor = wallet_for_prune.as_ref().map(|w| w.last_scan_height());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let chain = chain_for_prune.clone();
                let res = tasks::spawn_blocking("block-expiry", move || {
                    chain.prune_expired(expire, floor, now)
                })
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

    // Divi Core's step 10, once the chain and the wallet are loaded: it reads
    // masternode.conf (-mnconf), makes it when missing, with -masternode checks
    // the masternode's settings, then locks the collaterals masternode.conf
    // names (-mnconflock, default on), all before staking starts in step 11
    // (init.cpp:1594-1598, MasternodeModule.cpp:210-240, :454-466)
    // masternode.conf is a config file (R3: 3); -masternode and the options
    // it checks are option values (R3: 2)
    let mn_entries = mn_options
        .read_conf()
        .map_err(|e| Coded::error(exit_code::CONFIG, anyhow::anyhow!(e)))?;
    let mn_network = match config.network.network_type {
        NetworkType::Mainnet => WalletNetwork::Mainnet,
        NetworkType::Testnet => WalletNetwork::Testnet,
        NetworkType::Regtest => WalletNetwork::Regtest,
    };
    mn_options
        .check_start(&mn_entries, config.index.txindex, mn_network)
        .map_err(|e| Coded::error(exit_code::USAGE, anyhow::anyhow!(e)))?;
    if let (Some(w), true) = (wallet.as_ref(), mn_options.lock) {
        core_files::lock_masternode_collateral(w, &mn_options.conf_path);
    }

    // Start staker if wallet is available
    runs_log::phase("staking");
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
            // The same callback, so an own block writes the lines a peer's
            // does (A11 "Own blocks log like peer blocks" item 4)
            staker.set_block_connected_callback(wallet_block_callback(
                Arc::clone(&wallet_arc),
                node.mempool().clone(),
                node.fee_estimator().clone(),
                node.tx_relay().clone(),
                node.chain().clone(),
            ));
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

    // The wallet is loaded: the import thread goes on, a -reindex with it,
    // while RPC answers, as Divi Core's (init.cpp:686-728, :1580, :1639)
    node.release_import();

    runs_log::phase("rpc");
    // Start RPC server. RPC always requires authentication: without an
    // rpcpassword a random cookie is written to <datadir>/.cookie
    // (mode 0600) for local clients; `_rpc_cookie` removes it when we return.
    let (rpc_user, rpc_password, _rpc_cookie) = divi_rpc::resolve_rpc_auth(
        config.rpc.username.as_deref(),
        config.rpc.password.as_deref(),
        &config.data_dir,
    )
    .with_context(|| format!("Failed to write RPC cookie in {:?}", config.data_dir))
    .or_exit(exit_code::DATADIR)?;
    match &_rpc_cookie {
        Some(cookie) => {
            if config.rpc.username.is_some() || config.rpc.password.is_some() {
                warn!("rpcuser is set without an rpcpassword; using cookie authentication");
            }
            info!("RPC cookie authentication: {:?}", cookie.path());
        }
        None => info!("RPC authentication: rpcuser/rpcpassword"),
    }
    let rpc_config = RpcConfig {
        bind_address: config.rpc.socket_addr(),
        also_bind: config.rpc.also_listen.clone(),
        username: Some(rpc_user),
        password: Some(rpc_password),
        keep_alive: config.rpc.keep_alive,
        rest: config.rpc.rest,
        threads: config.rpc.threads,
        // -rpcallowip as Divi Core's CSubNet reads it, checked by build_config
        allowed: config
            .rpc
            .allow_ips
            .iter()
            .filter_map(|a| divi_rpc::Subnet::parse(a))
            .collect(),
        access: divi_rpc::AccessConfig {
            allow_ips: Vec::new(),
            ..config.rpc.access()
        },
        max_request_size: config.rpc.max_request_size,
    };
    // Fail at startup, not on the first request, on a bad rpcauth/rpcwhitelist
    // entry or a non-loopback bind without rpcallowip.
    divi_rpc::rpc_access(&rpc_config)
        .map_err(anyhow::Error::from)
        .and_then(|a| {
            std::iter::once(rpc_config.bind_address)
                .chain(rpc_config.also_bind.iter().copied())
                .try_for_each(|addr| a.check_bind(addr))
                .map_err(|e| anyhow::anyhow!(e))
        })
        .context("Invalid RPC configuration")
        .or_exit(exit_code::USAGE)?;

    info!("Starting RPC server on {}...", rpc_config.bind_address);
    // Start-up is done: say so, or a slow start and a running node look alike
    runs_log::phase("running");
    // From here a slow disk holds the writer thread, not the node (A8)
    log_delivery::start_writer();
    tasks::start_test_panics(config.network.network_type == NetworkType::Regtest);
    #[cfg(unix)]
    crash::start_test_crash(config.network.network_type == NetworkType::Regtest);
    if !config.log.print_to_console {
        console!("IronDivi is running (chain height {}).", chain.height());
    }

    // Run RPC server with shutdown handling
    let mut shutdown_rx = shutdown_rx;
    // An RPC server that cannot run (its port taken) stops the node, which
    // then exits with failure, as divid's InitError does
    let mut rpc_error = None;

    // RPC `stop` takes the same path as SIGTERM. The short delay lets the
    // "DIVI server stopping" reply reach the client before the server is dropped.
    let rpc_stop: divi_rpc::ShutdownCallback = Arc::new(move || {
        runs_log::stop_requested("rpc");
        let tx = shutdown_tx.clone();
        tasks::spawn_supervised("rpc-stop", async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = tx.send(());
        });
    });
    let wallet_for_shutdown = wallet.clone();

    // Divi Core's init returns !fRequestShutdown (init.cpp:1536-1539, :1661):
    // a SIGTERM or SIGINT that came while the node was starting stops it here,
    // with exit code 1 (divid.cpp:180)
    let stopped_during_start = !matches!(
        shutdown_rx.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    );
    start_done.store(true, std::sync::atomic::Ordering::Release);
    if stopped_during_start {
        info!("Shutdown requested. Exiting.");
    } else if !config.rpc.enabled {
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
        let mnconf_for_rpc = mn_options.conf_path.clone();
        let pm_for_mn = node.peer_manager().clone();
        // The node's own masternode list, which the network fills from mnb/mnp
        let mn_for_rpc = node.masternode_manager().as_ref().clone();
        let mn_list_for_rpc = Arc::clone(node.masternode_list());
        let mn_votes_for_rpc = Arc::clone(node.masternode_votes());
        let mn_sync_for_rpc = Arc::clone(node.masternode_sync());
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
                    rpc_server.set_masternode_list(Arc::clone(&mn_list_for_rpc));
                    rpc_server.set_masternode_votes(mn_votes_for_rpc);
                    rpc_server.set_masternode_sync(Arc::clone(&mn_sync_for_rpc));
                    rpc_server.set_masternode_datadir(datadir_for_mn);
                    rpc_server.set_masternode_conf(mnconf_for_rpc);
                    // broadcaststartmasternode: the list took the broadcast and
                    // left its inv to announce (RelayParsedMasternodeBroadcast,
                    // RpcMasternodeFeatures.cpp:80-121)
                    let mn_list_for_relay = Arc::clone(&mn_list_for_rpc);
                    rpc_server.set_masternode_relay(Arc::new(move |_bytes: Vec<u8>| {
                        for item in mn_list_for_relay.take_relays() {
                            pm_for_mn.broadcast(masternode_inv(item));
                        }
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
                        tasks::spawn_supervised("tx-announce", async move {
                            relay.announce_tx(txid_copy).await;
                        });

                        Ok(txid)
                    }));
                    debug!("Transaction submission callback configured");

                    if let Some(ref staker_arc) = staker_ref {
                        let staker_for_status = Arc::clone(staker_arc);
                        let staker_for_control = Arc::clone(staker_arc);
                        let wallet_for_status = Arc::clone(&wallet_for_staking_status);
                        let staker_for_health = Arc::clone(staker_arc);
                        let wallet_for_health = Arc::clone(&wallet_for_staking_status);
                        health::set_staking(Box::new(move || {
                            let status = staker_for_health.get_status();
                            health::Staking {
                                enabled: status.enabled,
                                mintable_coins: status.mintable_coins,
                                wallet_locked: wallet_for_health.is_locked(),
                                last_stake_time: status.last_stake_time,
                            }
                        }));
                        let chain_for_status = Arc::clone(&chain_for_staking_status);
                        let peers_for_status = Arc::clone(&peers_for_staking_status);
                        let sync_for_status = Arc::clone(&mn_sync_for_rpc);

                        // Register status callback
                        rpc_server.staking().set_status_callback(Arc::new(move || {
                            let tip_time = chain_for_status.tip().map(|t| t.time).unwrap_or(0);
                            staking_info(
                                &staker_for_status.get_status(),
                                wallet_for_status.is_locked(),
                                peers_for_status.peer_count(),
                                tip_time,
                                sync_for_status.lock().sync.is_synced(),
                                split_threshold_divi,
                            )
                        }));

                        // Register control callback
                        rpc_server.staking().set_staking_control(Arc::new(move |enable| {
                            if enable {
                                let staker = Arc::clone(&staker_for_control);
                                tasks::spawn_critical("staker", async move {
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
                                use divi_node::staker::GenerateBlockError;
                                use divi_rpc::staking::GenerateBlockFailure;
                                staker_for_generate
                                    .generate_blocks(n)
                                    .map(|hashes| hashes.iter().map(|h| h.to_string()).collect())
                                    .map_err(|e| match e {
                                        GenerateBlockError::Refused(m) => {
                                            GenerateBlockFailure::Refused(m)
                                        }
                                        GenerateBlockError::Failed(m) => {
                                            GenerateBlockFailure::Failed(m)
                                        }
                                    })
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
                match result {
                    Err(e) => {
                        error!("RPC server error: {}", e);
                        rpc_error = Some((e.to_string(), rpc_exit_code(&e)));
                    }
                    // The server ends after an RPC stop, whose signal follows
                    Ok(()) => {
                        let _ = shutdown_rx.recv().await;
                        info!("Shutdown signal received");
                    }
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
        let mnconf_for_rpc = mn_options.conf_path.clone();
        let pm_for_mn = node.peer_manager().clone();
        // The node's own masternode list, which the network fills from mnb/mnp
        let mn_for_rpc = node.masternode_manager().as_ref().clone();
        let mn_list_for_rpc = Arc::clone(node.masternode_list());
        let mn_votes_for_rpc = Arc::clone(node.masternode_votes());
        let mn_sync_for_rpc = Arc::clone(node.masternode_sync());
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
                    rpc_server.set_masternode_list(Arc::clone(&mn_list_for_rpc));
                    rpc_server.set_masternode_votes(mn_votes_for_rpc);
                    rpc_server.set_masternode_sync(mn_sync_for_rpc);
                    rpc_server.set_masternode_datadir(datadir_for_mn);
                    rpc_server.set_masternode_conf(mnconf_for_rpc);
                    // broadcaststartmasternode: the list took the broadcast and
                    // left its inv to announce (RelayParsedMasternodeBroadcast,
                    // RpcMasternodeFeatures.cpp:80-121)
                    let mn_list_for_relay = Arc::clone(&mn_list_for_rpc);
                    rpc_server.set_masternode_relay(Arc::new(move |_bytes: Vec<u8>| {
                        for item in mn_list_for_relay.take_relays() {
                            pm_for_mn.broadcast(masternode_inv(item));
                        }
                    }));
                    info!("Masternode manager initialized");
                }
            ) => {
                match result {
                    Err(e) => {
                        error!("RPC server error: {}", e);
                        rpc_error = Some((e.to_string(), rpc_exit_code(&e)));
                    }
                    // The server ends after an RPC stop, whose signal follows
                    Ok(()) => {
                        let _ = shutdown_rx.recv().await;
                        info!("Shutdown signal received");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
        }
    }

    // Divi Core's first line of its stop (PrepareShutdown, init.cpp:360)
    info!("PrepareShutdown: In progress...");

    // Divi Core stops minting before it flushes the chain state and the wallet
    // (init.cpp:372-373, :381, :386): no block is staked while they are written
    if let Some(staker) = staker.clone() {
        let started = std::time::Instant::now();
        let _ = tasks::spawn_blocking("staker-stop", move || staker.stop_and_wait()).await;
        shutdown_stage("staking stopped", started);
    }

    // Stop the node
    info!("Stopping node...");
    if tasks::test_panic(config.network.network_type == NetworkType::Regtest, "main") {
        panic!("test panic: this text stays in crash.log");
    }
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
        Some((e, code)) => Err(Coded::error(
            code,
            anyhow::anyhow!("RPC server error: {}", e),
        )),
        None if stopped_during_start => Err(anyhow::Error::new(QuietExit)),
        None => Ok(()),
    }
}

/// The exit code for the RPC server's error: its bind refused (7), its
/// address refused by the access settings (2, an InvalidInput io error from
/// serve), else as any other error
fn rpc_exit_code(e: &(dyn StdError + 'static)) -> i32 {
    let all = causes(e);
    if all.iter().any(|e| is_disk_error(*e)) {
        return exit_code::DISK;
    }
    for err in all {
        match io_kind(err) {
            Some(
                std::io::ErrorKind::AddrInUse
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::PermissionDenied,
            ) => return exit_code::BIND,
            Some(std::io::ErrorKind::InvalidInput) => return exit_code::USAGE,
            _ => {}
        }
    }
    error_exit_code(e)
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
                .with_context(|| format!("Invalid -{name} (an address:port)")),
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
            .with_context(|| "Invalid -webuiport (a port from 1 to 65535)")?,
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
fn run_notify(kind: &'static str, cmd: &str, value: &str) {
    let cmd = cmd.replace("%s", value);
    let started = tasks::thread("notify", tasks::Kind::Supervised, move || {
        let ran = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status();
        match ran {
            Ok(status) if !status.success() => warn!("{}", notify_failed(kind, status)),
            Ok(_) => {}
            Err(e) => warn!("{}", notify_failed(kind, e.kind())),
        }
    });
    if let Err(e) = started {
        warn!("runCommand not started: {} ({})", kind, e.kind());
    }
}

/// A failed notify command's line: its kind and the exit status or the
/// error kind, never the command or the txid or hash it was given (A11
/// "Notify commands"), so an own transaction's line is a peer block's
fn notify_failed(kind: &str, why: impl std::fmt::Display) -> String {
    format!("runCommand error: {} ({})", kind, why)
}

/// -alertnotify: run the command with the warning's text, kept to Divi Core's
/// safe characters and put in single quotes (CAlert::Notify, alert.cpp:218-235)
fn alert_notify(cmd: &str, message: &str) {
    const SAFE: &str =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890 .,;_-/:?@()";
    let safe: String = message.chars().filter(|c| SAFE.contains(*c)).collect();
    run_notify("alertnotify", cmd, &format!("'{safe}'"));
}

/// Divi Core's warning when most of the last 100 blocks are of a newer
/// version than it makes (ChainTipManager.cpp:43-60): once out of initial
/// download, with more than 50 of them above version 4 (block.h:26), the
/// miscellaneous warning is set and -alertnotify run, once. Initial download
/// is the chain's IsInitialBlockDownload (ChainSyncHelpers.cpp:33-50)
fn spawn_version_warning(chain: Arc<divi_storage::Chain>, alertnotify: Option<String>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    const CURRENT_VERSION: i32 = 4;
    let warned = AtomicBool::new(false);
    let blocks = chain.clone();
    chain.add_tip_listener(Arc::new(move |tip| {
        if warned.load(Ordering::SeqCst) || blocks.is_initial_block_download() {
            return;
        }
        let upgraded = (0..100u32)
            .map_while(|back| tip.height.checked_sub(back))
            .filter_map(|height| blocks.get_block_index_by_height(height).ok().flatten())
            .filter(|index| index.version > CURRENT_VERSION)
            .count();
        if upgraded > 100 / 2 {
            let message = "Warning: This version is obsolete, upgrade required!";
            warn!(
                "{} of last 100 blocks above version {}",
                upgraded, CURRENT_VERSION
            );
            divi_rpc::warnings::set_misc_warning(message);
            if let Some(cmd) = &alertnotify {
                alert_notify(cmd, message);
            }
            warned.store(true, Ordering::SeqCst);
        }
    }));
}

/// -blocknotify: run the command each time the best block changes, with the
/// new tip's hash (divid's UpdatedBlockTip, init.cpp:113-117, :518-523).
/// Divi Core signals a new tip only out of the initial block download
/// (ChainExtensionService.cpp:556-565), so the tip that ends it is the first
/// one run
fn spawn_block_notify(chain: Arc<divi_storage::Chain>, cmd: String) {
    let blocks = Arc::downgrade(&chain);
    chain.add_tip_listener(Arc::new(move |tip| {
        if blocks
            .upgrade()
            .is_some_and(|c| !c.is_initial_block_download())
        {
            run_notify("blocknotify", &cmd, &tip.hash.to_string());
        }
    }));
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
        block_version: config.staking.block_version,
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
    masternode_synced: bool,
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
        // The masternode sync has finished (IsSynced, rpcmisc.cpp:1069)
        mnsync: masternode_synced,
        recently_attempted: status.recently_attempted,
        blocks: status.blocks,
        stake_split_threshold: split_threshold_divi,
    }
}

/// An inv for a masternode item the list left to relay
fn masternode_inv((kind, hash): (u32, [u8; 32])) -> divi_network::NetworkMessage {
    let inv_type = match kind {
        divi_rpc::mn_list::INV_WINNER => divi_network::InvType::MasternodeWinner,
        divi_rpc::mn_list::INV_BROADCAST => divi_network::InvType::MasternodeAnnounce,
        _ => divi_network::InvType::MasternodePing,
    };
    divi_network::NetworkMessage::Inv(vec![divi_network::InvItem::new(
        inv_type,
        divi_primitives::hash::Hash256(hash),
    )])
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
/// The block-connected callback of a node with a wallet. BlockSync runs it
/// for peer blocks and the staker for own staked blocks, so both write the
/// same lines (A11 "Own blocks log like peer blocks" item 4).
fn wallet_block_callback(
    wallet: Arc<WalletDb>,
    mempool: Arc<divi_node::Mempool>,
    fee_estimator: Arc<divi_node::FeeEstimator>,
    tx_relay: Arc<divi_network::TxRelay>,
    chain: Arc<divi_storage::Chain>,
) -> divi_network::BlockConnectedCallback {
    Arc::new(move |block, height| {
        let block_hash = compute_block_hash(&block.header);

        // 1. Bring the wallet up to the active tip (adds new UTXOs, removes spent
        // ones). The block handed in may be one of several connected by a reorg,
        // or a side-chain block, so scan the active chain itself, in order.
        // This runs before the mempool cleanup below so the wallet's mempool
        // entries for this block are replaced by confirmed records in one step;
        // otherwise a send would briefly show its inputs as unspent again.
        sync_wallet_to_tip(&wallet, &chain);

        // 2. Calculate fees from mempool entries and clean mempool
        let total_fees = mempool_block_connected(
            &mempool,
            &chain,
            |txid| tx_relay.mark_seen(txid),
            &fee_estimator,
            block,
            height,
        );

        // 3. Persist dirty wallet changes to database (incremental, not full rewrite)
        if let Err(e) = wallet.save_incremental() {
            error!("Failed to save wallet after block {}: {}", height, e);
        }

        debug!(
            "Block {} at height {} processed (fees: {}, mempool cleaned, wallet scanned)",
            block_hash,
            height,
            total_fees.as_sat()
        );
    })
}

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
        console_out!(
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
        console_out!(
            "OK: root_hash {} ({}, tip {}) is signed by {}",
            m.root_hash,
            m.network,
            m.tip_height,
            signer
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
        console_out!(
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
            console_out!(
                "signature OK: root_hash {} signed by {}",
                signed.root_hash,
                signer
            );
        }
        let m = divi_storage::snapshot::import_snapshot(
            dir,
            &config.chainstate_path(),
            storage_params(config),
            args.snapshot_root.as_deref(),
        )
        .context("snapshot import failed")?;
        console_out!(
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

/// CreatePidFile: the process id and a newline (util.cpp:122-128)
/// All at once and private, so a reader never sees a partial pid (NODE-23)
fn write_pid_file(pid_file: &std::path::Path) {
    if let Err(e) = private_files::write_private_atomic(
        pid_file,
        format!("{}\n", std::process::id()).as_bytes(),
    ) {
        warn!("Failed to write PID file {:?}: {}", pid_file, e);
    }
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

#[cfg(unix)]
thread_local! {
    /// A runtime thread's entry in the crash handler's table (A5)
    static CRASH_ENTRY: std::cell::RefCell<Option<crash::Entered>> =
        const { std::cell::RefCell::new(None) };
}

/// A runtime thread starts: enter it in the crash handler's table
fn crash_enter() {
    #[cfg(unix)]
    {
        let name = std::thread::current().name().unwrap_or("tokio").to_string();
        let entered = crash::enter_thread(name.as_str());
        let _ = CRASH_ENTRY.try_with(|e| *e.borrow_mut() = Some(entered));
    }
}

/// A runtime thread ends: its entry and alternate stack go
fn crash_leave() {
    #[cfg(unix)]
    let _ = CRASH_ENTRY.try_with(|e| e.borrow_mut().take());
}

fn main() {
    // Every panic is recorded from here on (A4)
    // Fatal signals to crash.log, before anything else can fault (A5)
    #[cfg(unix)]
    crash::install();
    tasks::install_hook();
    // A closed stdin, stdout or stderr is reopened on /dev/null before any
    // file is opened: the next open() would take that number, and console
    // lines would be written into a database or the wallet (D2)
    #[cfg(unix)]
    for fd in 0..=2 {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
            let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
            if null >= 0 && null != fd {
                unsafe {
                    libc::dup2(null, fd);
                    libc::close(null);
                }
            }
        }
    }
    // Before the -daemon forks hide the parent and the terminal (A1)
    runs_log::note_launch();
    // The working directory, before -daemon moves it (A7)
    startup::capture();
    // Every signal is recorded from here on (A3); fds 0-2 are open, so the
    // handler's pipe does not take one. Its thread starts after the forks.
    #[cfg(unix)]
    signals::install();
    // Before anything is written: the datadir holds the wallet and the RPC cookie (NODE-3)
    private_files::restrict_umask();
    // A core dump would hold unlocked wallet keys (NODE-10)
    if let Err(e) = private_files::disable_core_dumps() {
        console!("Warning: could not disable core dumps: {}", e);
    }

    // Parse CLI arguments, completed from the config file where they are unset
    let args = match Args::try_parse_from(std::env::args()) {
        Ok(args) => args,
        Err(e) => die!(exit_code::USAGE, "Error: {:#}", e),
    };
    // divid's AppInit: -?, -help and -version print and exit 1 (divid.cpp)
    if args.help || args.version {
        // Through console_out!: print! panics on EPIPE, and the exit code
        // would be 101 (D2). Byte for byte what print! wrote.
        if args.help {
            console_out!(
                "IronDivi Daemon version v{}\n{}",
                env!("CARGO_PKG_VERSION"),
                USAGE.strip_suffix('\n').unwrap_or(USAGE)
            );
        } else {
            console_out!("IronDivi Daemon version v{}", env!("CARGO_PKG_VERSION"));
        }
        die!(exit_code::HELP);
    }
    // ... a -datadir that is not a directory is refused (divid.cpp)
    if let Some(dir) = &args.datadir {
        if !dir.is_dir() {
            die!(
                exit_code::DATADIR,
                "Error: Specified data directory \"{}\" does not exist.",
                dir.display()
            );
        }
    }
    let args = match resolve_args(args) {
        Ok(args) => args,
        Err(e) => {
            // divid prints its config file errors under their own heading (divid.cpp:97-98)
            // The file could not be read: 3, or 9 for a full or read-only disk
            let code = match exit_code_of(&e) {
                exit_code::FAILED if e.chain().any(|c| c.is::<std::io::Error>()) => {
                    exit_code::CONFIG
                }
                exit_code::FAILED => exit_code::USAGE,
                code => code,
            };
            match e.downcast_ref::<ConfigFileError>() {
                Some(c) => die!(code, "Error reading configuration file: {}", c),
                None => die!(code, "Error: {:#}", e),
            }
        }
    };
    // ... and so are -testnet and -regtest together
    if args.testnet && args.regtest {
        die!(
            exit_code::USAGE,
            "Error: Invalid combination of -regtest and -testnet."
        );
    }

    // divid creates its files 0600 and its directories 0700 (umask 077), or
    // with the system's umask under -sysperms, which it refuses with the
    // wallet on (init.cpp:1378-1385)
    #[cfg(unix)]
    if !args.sysperms {
        // SAFETY: umask(2) only sets this process's file-creation mask
        unsafe { libc::umask(0o077) };
    } else if !args.disablewallet {
        die!(
            exit_code::USAGE,
            "Error: Error: -sysperms is not allowed in combination with enabled wallet functionality"
        );
    }

    // Compute data directory early (needed for daemonization and logging)
    let data_dir = compute_data_dir(&args);
    if let Err(e) =
        core_files::refuse_at_start(&data_dir, args.wallet.as_deref(), args.disablewallet)
    {
        die!(exit_code::DATADIR, "Error: {:#}", e);
    }

    // -daemon as Divi Core's AppInit does it, before the tokio runtime: the
    // line on stdout, one fork, the parent exits 0 and the child calls setsid,
    // keeping its working directory and its standard streams (divid.cpp:122-140)
    #[cfg(unix)]
    if args.daemon {
        println!("DIVI server starting");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        // No thread may exist before the fork (diag.md §3)
        runs_log::note_first_fork();
        match unsafe { libc::fork() } {
            -1 => die!(
                exit_code::DAEMON,
                "Error: fork() returned -1 errno {}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            ),
            // The parent exits and writes nothing more
            pid if pid > 0 => unsafe { libc::_exit(0) },
            _ => {} // the child goes on
        }
        if unsafe { libc::setsid() } == -1 {
            die!(
                exit_code::DAEMON,
                "Error: setsid() returned -1 errno {}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
        }
    }

    #[cfg(not(unix))]
    if args.daemon {
        console!("Warning: Daemon mode is only supported on Unix systems, running in foreground");
    }

    // The thread that records signals and acts on them (A3); those received
    // before now wait in its pipe
    #[cfg(unix)]
    signals::start_writer();

    // A credential change would make the process dumpable again, and a pipe core handler
    // would then store a core holding wallet keys (NODE-10). A plain thread, started after
    // the forks and before the wallet opens, so a stalled runtime cannot stop it. Its own
    // thread at the health tick's rate (10 s for the first 10 minutes, then 60 s); health.log
    // carries the value it read, and a reset is an events.log record.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Err(e) = tasks::thread("dumpable-check", tasks::Kind::Supervised, || loop {
        use std::sync::atomic::Ordering;
        match private_files::restore_non_dumpable() {
            Some((was, reset)) => {
                health::DUMPABLE.store(was, Ordering::Relaxed);
                health::DUMPABLE_RESETS.fetch_add(1, Ordering::Relaxed);
                let result = if reset.is_ok() { "ok" } else { "error" };
                events::event("dumpable-reset", &format!("was={} result={}", was, result));
                match reset {
                    Ok(()) => warn!("dumpable restored (was {})", was),
                    Err(e) => error!("dumpable is {} and could not be reset: {}", was, e),
                }
            }
            None => health::DUMPABLE.store(0, Ordering::Relaxed),
        }
        // The maps copy a crash record carries (A5)
        crash::refresh_maps();
        std::thread::sleep(health::interval());
    }) {
        console!("Warning: could not start the core dump check: {}", e);
    }

    // -mocktime: the node's clock from here on, set as divid sets it after
    // daemonizing (divid.cpp:140-143); read as a number, 0 is the real clock
    if let Some(text) = args.settings.get("mocktime") {
        divi_primitives::clock::set_mock_time(atoi(text));
    }
    // -testsafemode puts the RPC server in safe mode, -disablesafemode lets
    // it run every call all the same (rpcserver.cpp:185, :1052)
    divi_rpc::warnings::set_safe_mode(
        args.settings.get_bool("testsafemode", false),
        args.settings.get_bool("disablesafemode", false),
    );

    // Now enter the tokio runtime (after daemonization)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Each runtime thread in the crash handler's table, with its own
        // alternate stack (A5)
        .on_thread_start(crash_enter)
        .on_thread_stop(crash_leave)
        .build()
        .unwrap_or_else(|e| {
            die!(
                exit_code::FAILED,
                "Error: Failed to build tokio runtime: {}",
                e
            )
        });
    // A panic on this thread would otherwise unwind through the runtime's drop,
    // which waits with no deadline, and then exit through the C++ destructors,
    // which join RocksDB's thread pools: the node could hang until the service
    // manager killed it. The panic message is already written by then.
    // The only catch_unwind in the node (A4; a test keeps it so)
    tasks::main_caught();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async_main(args, data_dir))
    }));
    match result {
        Ok(result) => exit_after_stop(runtime, result),
        Err(_) => {
            std::mem::forget(runtime);
            runs_log::exit(101, "Error: the node's main task panicked");
            error!("Error: the node's main task panicked");
            flush_log();
            unsafe { libc::_exit(101) }
        }
    }
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
    // Let the runtime's threads go without waiting for them
    std::mem::forget(runtime);
    shutdown_stage("exit", started);
    match result {
        // _exit: no atexit handlers or C++ static destructors either (RocksDB's
        // thread pools would be joined there)
        Ok(()) => {
            // The partial hour's count lines (A11)
            counts::flush();
            runs_log::exit(0, "stopped");
            flush_log();
            unsafe { libc::_exit(0) }
        }
        // In debug.log as well: on a -daemon node the console is that file,
        // but a foreground node's only record would be a lost terminal (D3)
        Err(e) => die!(exit_code_of(&e), "Error: {:#}", e),
    }
}

async fn async_main(args: Args, data_dir: PathBuf) -> Result<()> {
    // Removed at a clean stop, after `args` has been taken apart
    let pid_file = pid_file_path(&args, &data_dir);

    // Build log config from CLI args
    let log_config = LogConfig {
        max_file_size: args.maxlogsize.unwrap_or(1) as u64 * 1_048_576, // Convert MB to bytes
        max_files: args.maxlogfiles.unwrap_or(5),
        debug: args.debug,
        log_ips: args.logips,
        timestamps: args.logtimestamps,
        shrink: args.shrinkdebugfile,
        levels: args.log_levels.spec(),
        // An export only reads the data directory: it logs to the console
        print_to_console: args.printtoconsole || args.export_chain,
    };

    // Wallet values print as per-run pseudonyms unless -logwalletdetail=1
    // (A11); set before the first line
    divi_primitives::redact::set_wallet_detail(args.logwalletdetail);

    // Initialize logging (writes to debug.log in data_dir by default)
    init_logging(&log_config, &args.log_levels, &data_dir);
    if args.logwalletdetail {
        warn!(
            "-logwalletdetail=1: wallet txids, addresses, amounts and labels are written \
             in clear to the logs of this run; diag treats every file of this run as unredacted"
        );
    }
    if !args.log_levels.unknown.is_empty() {
        warn!(
            "Unknown log categories {:?} in -debug/-loglevel (known: {})",
            args.log_levels.unknown,
            log_filter::category_names()
        );
    }
    info!("Log levels: {}", args.log_levels.spec());

    // diag/runs.log (A1); not for the snapshot and export commands, which
    // only read the data directory
    let one_shot = args.export_snapshot.is_some()
        || args.import_snapshot.is_some()
        || args.sign_snapshot.is_some()
        || args.verify_snapshot.is_some()
        || args.export_chain;
    // A stop signal ends a one-shot command at once, as before A3
    #[cfg(unix)]
    if one_shot {
        signals::one_shot();
    }
    if !one_shot {
        let network = if args.regtest {
            "regtest"
        } else if args.testnet {
            "testnet"
        } else {
            "main"
        };
        let network = format!("{}/{:?}", network, args.chain_mode()).to_lowercase();
        runs_log::open(&data_dir, &network, cfg!(unix) && args.daemon);
        tasks::set_data_dir(&data_dir);
        events::set_data_dir(&data_dir);
        incidents::set_data_dir(&data_dir);
        #[cfg(unix)]
        {
            crash::open(&data_dir);
            crash::refresh_maps();
        }
        startup::write(
            &data_dir,
            &startup::Options {
                cli: &args.cli,
                all: &args.settings,
                known_keys: &[APPLIED, READ_ELSEWHERE, UNSUPPORTED_OPTIONS],
            },
        );
        runs_log::phase("config");
    }

    // Build configuration
    let mut config = build_config(&args).or_exit(exit_code::USAGE)?;
    let log_config_console = log_config.print_to_console;
    config.log = log_config;

    // Print banner
    print_banner(&config);
    core_files::warn_core_wallet(&config.data_dir);

    // Check for conflicting network options
    if args.testnet && args.regtest {
        die!(exit_code::USAGE, "Cannot use both --testnet and --regtest");
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

    // Divi Core AbortNode (ValidationState.cpp:17-27): a write the node cannot
    // make tells the user to look at debug.log and starts the shutdown
    let abort_tx = shutdown_tx.clone();
    divi_storage::abort::set_handler(Box::new(move |_| {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "Error: Error: A fatal internal error occured, see debug.log for details"
        );
        let _ = abort_tx.send(());
    }));

    // Stop signals (TERM, INT, QUIT) reach the node from here; one received
    // earlier is delivered now. SIGHUP reopens debug.log and the node keeps
    // running, as Divi Core does (init.cpp:513-516). See signals.rs (A3).
    #[cfg(unix)]
    signals::set_stop_sink(shutdown_tx.clone(), !log_config_console);
    #[cfg(not(unix))]
    {
        let shutdown_tx_clone = shutdown_tx.clone();
        let console = !log_config_console;
        tasks::spawn_supervised("ctrl-c", async move {
            if let Err(e) = signal::ctrl_c().await {
                error!("Ctrl+C handler failed: {}", e);
                return;
            }
            // The stop goes out before anything is written to the console (D1)
            let _ = shutdown_tx_clone.send(());
            runs_log::stop_requested("signal=INT");
            info!("Received Ctrl+C, initiating shutdown...");
            if console {
                console!("Received Ctrl+C, stopping...");
            }
        });
    }

    let wallet_seed = WalletSeed::from_settings(&args.settings);
    let wallet_options = WalletOptions::from_settings(&args.settings);
    let mn_options =
        masternode_options::MasternodeOptions::from_settings(&args.settings, &config.data_dir);
    let webui = webui_config(&args, &config).or_exit(exit_code::USAGE)?;
    let electrum = electrum_config(&args, &config).or_exit(exit_code::USAGE)?;

    // Run the daemon
    if let Err(e) = run_daemon(
        config,
        args.wallet,
        wallet_seed,
        args.disablewallet,
        wallet_options,
        mn_options,
        shutdown_tx,
        shutdown_rx,
        pid_file.clone(),
        webui,
        electrum,
    )
    .await
    {
        // A start stopped without an InitError (-dbloadfailexit) prints nothing
        // more (init.cpp:1307-1309)
        if is_quiet_exit(&e) {
            remove_pid_file(&pid_file);
            die!(exit_code::QUIET);
        }
        remove_pid_file(&pid_file);
        // On stderr as well, as Divi Core's InitError (noui.cpp:38-40); {:#}
        // carries every cause
        die!(exit_code_of(&e), "Error: {:#}", e);
    }

    remove_pid_file(&pid_file);

    // Divi Core's last line, once its pid file is gone (MainShutdown, init.cpp:418)
    info!("MainShutdown: done");
    info!("IronDivi shutdown complete");
    if !log_config_console {
        console!("IronDivi stopped.");
    }
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
        // Below 0, as divid's VerifyDB reads it: every block (verifyDb.cpp:73-74)
        assert_eq!(cfg(&["--checkblocks=-1"]).check_blocks, 0);
        assert_eq!(cfg(&["--checkblocks=abc"]).check_blocks, 0);
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
            // try_parse_from: parse_from exits the test process on a bad level
            Args::try_parse_from(argv)
                .and_then(resolve_args)
                .map(|a| (a.debug, a.log_levels.spec()))
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

    /// Off regtest divid stops at start when rpcuser is rpcpassword
    /// (rpcserver.cpp:655-678); irondivid served that login
    #[test]
    fn rpcuser_equal_to_rpcpassword_is_refused_off_regtest() {
        for net in ["", "testnet=1\n"] {
            let err = cfg(&format!("{net}rpcuser=same\nrpcpassword=same\n"), &[])
                .err()
                .unwrap_or_else(|| panic!("{net:?}: started"));
            assert!(
                err.to_string().contains("MUST NOT be the same"),
                "{net:?}: {err}"
            );
            // without the RPC server there is no login to refuse
            assert!(cfg(
                &format!("{net}server=0\nrpcuser=same\nrpcpassword=same\n"),
                &[]
            )
            .is_ok());
            assert!(cfg(&format!("{net}rpcuser=a\nrpcpassword=b\n"), &[]).is_ok());
        }
        // regtest does not need the password (chainparams.cpp:513)
        assert!(cfg("regtest=1\nrpcuser=same\nrpcpassword=same\n", &[]).is_ok());
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
            "Invalid netmask specified in -whitelist"
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
            ("127.0.0.1", "Need to specify a port with -whitebind"),
            ("localhost:53999", "Cannot resolve -whitebind address"),
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
    /// The names in `dir` that end in ".moved"
    fn moved_wallets(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".moved"))
            .collect()
    }

    /// As init.cpp:864-888: -mnemonic with a wallet already there moves it to
    /// `<wallet><time>.moved` (run_daemon's `move_wallet_for_restore`, before
    /// the load) and restores a new one from the words; without -mnemonic or
    /// -hdseed the wallet there is loaded
    #[test]
    fn a_mnemonic_moves_a_wallet_already_there() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let mnemonic = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let old = load_or_create_wallet_from(&path, WalletNetwork::Regtest, ChainMode::Divi, None)
            .unwrap()
            .mnemonic();
        let open = |seed: WalletSeed| {
            load_or_create_wallet_with_env(
                &path,
                WalletNetwork::Regtest,
                ChainMode::Divi,
                seed,
                &WalletOptions::default(),
                WalletEnv::default(),
            )
            .unwrap()
            .mnemonic()
        };
        // Compared without printing: the words are never shown
        assert!(
            open(WalletSeed::default()) == old,
            "the wallet there was not loaded"
        );
        assert!(moved_wallets(dir.path()).is_empty());

        move_wallet_for_restore(&path).unwrap();
        let restored = open(WalletSeed {
            mnemonic: Some(mnemonic.clone()),
            restore: true,
            ..WalletSeed::default()
        });
        assert!(
            restored.as_deref() == Some(mnemonic.as_str()),
            "the wallet was not restored from -mnemonic"
        );
        let moved = moved_wallets(dir.path());
        assert_eq!(moved.len(), 1, "{moved:?}");
        let time = moved[0]
            .strip_prefix("wallet")
            .and_then(|n| n.strip_suffix(".moved"))
            .unwrap();
        assert!(time.parse::<u64>().unwrap() > 1_600_000_000, "{moved:?}");
        // The moved wallet is the old one, whole
        let back = WalletDb::open(&dir.path().join(&moved[0]), WalletNetwork::Regtest).unwrap();
        assert!(
            back.mnemonic() == old,
            "the moved wallet is not the old one"
        );
    }

    /// As hdchain.cpp:63-65 and init.cpp:1203-1209: words that fail their
    /// checksum stop the start with divid's text, after the wallet there was
    /// moved, and leave no new wallet
    #[test]
    fn invalid_mnemonic_words_stop_the_start() {
        // "abandon" twelve times: every word is in the list, the checksum fails
        let words = ["abandon"; 12].join(" ");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        drop(
            load_or_create_wallet_from(&path, WalletNetwork::Regtest, ChainMode::Divi, None)
                .unwrap(),
        );
        move_wallet_for_restore(&path).unwrap();
        let refused = load_or_create_wallet_with_env(
            &path,
            WalletNetwork::Regtest,
            ChainMode::Divi,
            WalletSeed {
                mnemonic: Some(words),
                restore: true,
                ..WalletSeed::default()
            },
            &WalletOptions::default(),
            WalletEnv::default(),
        )
        .map(|_| ())
        .unwrap_err();
        assert_eq!(
            format!("{refused:#}"),
            "Error loading or creating wallet.dat, SetMnemonic: invalid mnemonic: please check your words`"
        );
        assert_eq!(moved_wallets(dir.path()).len(), 1);
        assert!(!path.exists(), "a wallet was left at {path:?}");
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
        assert!(err.contains("invalid value for '--mode"), "{err}");
        assert!(
            !err.contains("irondivi'"),
            "the value is never echoed: {err}"
        );
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
        let mut log = RotatingLog::open(dir.path(), max_size, max_files, false, false).unwrap();
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
        let mut log = RotatingLog::open(dir.path(), 1000, 3, false, false).unwrap();
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
    /// is taken over WALLET_MNEMONIC
    #[test]
    fn hex_seed_restores_cores_first_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let wallet = load_or_create_wallet_with_env(
            &path,
            WalletNetwork::Regtest,
            ChainMode::Divi,
            WalletSeed::default(),
            &WalletOptions::default(),
            WalletEnv {
                hdseed: Some("000102030405060708090a0b0c0d0e0f".into()),
                mnemonic: Some(
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                        .into(),
                ),
                ..WalletEnv::default()
            },
        )
        .unwrap();
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

    /// A start first copies the wallet there into backups/ and
    /// monthlyBackups/ next to it, as Divi Core does at every start
    #[test]
    fn start_makes_wallet_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        drop(
            load_or_create_wallet_from(&path, WalletNetwork::Regtest, ChainMode::Divi, None)
                .unwrap(),
        );
        backup_wallet_at_start(&path, &WalletOptions::default());
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

    /// -conf naming a directory: divid reads no line from it and runs with
    /// no config file (Settings.cpp:186-205)
    #[test]
    fn a_conf_that_is_a_directory_is_read_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        let argv = [
            "irondivid".to_string(),
            format!("--datadir={}", dir.path().display()),
            "-conf=conf.d".to_string(),
        ];
        let c = build_config(&Args::parse_from(argv)).unwrap();
        assert_eq!(c.rpc.port, NodeConfig::default().rpc.port);
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

    /// -seednode is applied (Divi Core AddOneShot, net.cpp:1842-1843), every
    /// value, the command line's first, and not dialled as a lasting peer
    #[test]
    fn seednode_values_are_applied() {
        let c = cfg_in(
            "divi.conf",
            "rpcuser=u\nseednode=127.0.0.2:11\nseednode=127.0.0.3\n",
            &["-seednode=127.0.0.2:10"],
        )
        .unwrap();
        assert_eq!(
            c.p2p.seednode,
            ["127.0.0.2:10", "127.0.0.2:11", "127.0.0.3"]
        );
        assert!(!c
            .peer_sources()
            .static_peers
            .contains(&"127.0.0.2:10".to_string()));
        assert!(!UNSUPPORTED_OPTIONS.contains(&"seednode"));
    }

    /// -blockmaxsize, -blockprioritysize and -blockminsize are read as divid
    /// reads them, into an unsigned int with no warning: nothing or a word is
    /// 0, a negative value wraps (BlockMemoryPoolTransactionCollector.cpp:18-42)
    #[test]
    fn block_sizes_are_read_as_divid_reads_them() {
        let c = cfg_in(
            "divi.conf",
            "rpcuser=u\n",
            &[
                "-blockmaxsize",
                "-blockminsize=-1",
                "-blockprioritysize=abc",
            ],
        )
        .unwrap();
        assert_eq!(c.staking.block_max_size, 0);
        assert_eq!(c.staking.block_min_size, u32::MAX as usize);
        assert_eq!(c.staking.block_priority_size, 0);
    }

    /// -dbcache is applied as divid splits it (init.cpp:1030, :1046-1056):
    /// read with atoi, clamped, the coins in memory unless -utxocachesize
    #[test]
    fn dbcache_sets_the_caches() {
        const MIB: usize = 1 << 20;
        let c = cfg_in("divi.conf", "rpcuser=u\ndbcache=100\n", &[]).unwrap();
        let d = divi_node::config::db_cache_sizes(100, c.index.txindex);
        assert_eq!(c.block_cache_size, Some(d.block_tree + d.coin_db));
        assert_eq!(c.utxo_cache_size, d.coin_cache_entries);
        let word = cfg_in("divi.conf", "rpcuser=u\n", &["-dbcache=abc"]).unwrap();
        assert_eq!(word.block_cache_size.map(|b| b < 4 * MIB), Some(true));
        let big = cfg_in("divi.conf", "rpcuser=u\n", &["-dbcache=99999999"]).unwrap();
        // Clamped to 4096 MiB: 512 to the block tree, 1792 to the coin database
        assert_eq!(big.block_cache_size, Some(2304 * MIB));
        let both = cfg_in(
            "divi.conf",
            "rpcuser=u\n",
            &["-dbcache=100", "-utxocachesize=7"],
        )
        .unwrap();
        assert_eq!(both.utxo_cache_size, 7);
        // Not given: irondivid's own sizes
        let none = cfg_in("divi.conf", "rpcuser=u\n", &[]).unwrap();
        assert_eq!(none.block_cache_size, None);
        assert_eq!(none.utxo_cache_size, 10_000_000);
        assert!(!UNSUPPORTED_OPTIONS.contains(&"dbcache"));
    }

    /// -dnsseed and -forcednsseed, and -connect turning -dnsseed off unless it
    /// is given (net.cpp:1015-1030, :1683-1685)
    #[test]
    fn dnsseed_and_forcednsseed_are_applied() {
        let c = cfg_in("divi.conf", "rpcuser=u\n", &["-forcednsseed=1"]).unwrap();
        assert!(c.p2p.force_dns_seed);
        assert_eq!(c.p2p.dns_seed, None);
        let c = cfg_in("divi.conf", "rpcuser=u\nforcednsseed=0\ndnsseed=0\n", &[]).unwrap();
        assert!(!c.p2p.force_dns_seed);
        assert_eq!(c.p2p.dns_seed, Some(false));
        let c = cfg_in("divi.conf", "rpcuser=u\n", &["-connect=127.0.0.2:1"]).unwrap();
        assert_eq!(c.p2p.dns_seed, Some(false), "-connect sets -dnsseed=0");
        let c = cfg_in(
            "divi.conf",
            "rpcuser=u\n",
            &["-connect=127.0.0.2:1", "-dnsseed=1"],
        )
        .unwrap();
        assert_eq!(c.p2p.dns_seed, Some(true));
        assert!(!UNSUPPORTED_OPTIONS.contains(&"forcednsseed"));
    }

    /// -mining, -genproclimit and -disablesystemnotifications: divid lists them
    /// in its help only (LicenseAndInfo.cpp:142, :186-187), so they are taken
    /// without a warning
    #[test]
    fn help_only_options_are_taken_without_a_warning() {
        let s = Settings::default();
        for o in ["mining", "genproclimit", "disablesystemnotifications"] {
            assert!(!UNSUPPORTED_OPTIONS.contains(&o), "{o}");
            assert_eq!(option_warning(&s, o), None, "{o}");
        }
        assert!(cfg_in(
            "divi.conf",
            "rpcuser=u\nmining=1\ngenproclimit=-1\ndisablesystemnotifications=1\n",
            &["-genproclimit=4"],
        )
        .is_ok());
    }

    /// Each option is in one list only: read by apply_settings, read
    /// elsewhere, one divid does not use, or one irondivid does not support
    #[test]
    fn every_option_is_in_one_list() {
        let lists: [(&str, &[&str]); 4] = [
            ("APPLIED", APPLIED),
            ("READ_ELSEWHERE", READ_ELSEWHERE),
            ("UNUSED_BY_DIVID", UNUSED_BY_DIVID),
            ("UNSUPPORTED_OPTIONS", UNSUPPORTED_OPTIONS),
        ];
        let mut seen = std::collections::HashMap::new();
        for (name, list) in lists {
            for key in list {
                if let Some(first) = seen.insert(*key, name) {
                    panic!("-{key} is in {first} and in {name}");
                }
            }
        }
        for key in ["forcestart", "rpcthreads", "alerts", "alertnotify"] {
            assert_eq!(seen.get(key), Some(&"APPLIED"), "-{key}");
        }
        assert_eq!(seen.get("sysperms"), Some(&"READ_ELSEWHERE"));
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
        // Below 0, a text or nothing keeps no orphan (main.cpp:790)
        for none in ["-5", "abc", ""] {
            let conf = format!("rpcuser=x\nmaxorphantx={none}\n");
            assert_eq!(cfg(&conf).mempool.max_orphan_txs, 0, "-maxorphantx={none}");
        }
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
                Some("Invalid amount for -minrelaytxfee=<amount> (an amount above zero)")
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

    /// divid listens on ::1 and 127.0.0.1 by default, and on every -rpcbind
    /// (one without a port on -rpcport) when -rpcallowip is given
    /// (rpcserver.cpp:683-750); irondivid took 127.0.0.1 or the first -rpcbind
    #[test]
    fn rpc_listens_on_every_address_divid_binds() {
        let addrs = |c: NodeConfig| {
            let mut all = vec![c.rpc.socket_addr()];
            all.extend(c.rpc.also_listen);
            all.iter().map(|a| a.to_string()).collect::<Vec<_>>()
        };
        assert_eq!(
            addrs(cfg("rpcuser=x\nrpcport=4000\n")),
            ["127.0.0.1:4000", "[::1]:4000"]
        );
        assert_eq!(
            addrs(cfg(
                "rpcuser=x\nrpcport=4000\nrpcallowip=10.0.0.0/8\n\
                 rpcbind=127.0.0.2:4001\nrpcbind=127.0.0.3\nrpcbind=[::1]:4002\n"
            )),
            ["127.0.0.2:4001", "127.0.0.3:4000", "[::1]:4002"]
        );
        assert_eq!(
            addrs(cfg("rpcuser=x\nrpcport=4000\nrpcallowip=10.0.0.0/8\n")),
            ["[::]:4000"]
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

    /// -litemode and -budgetvotemode appear only in divid's help
    /// (LicenseAndInfo.cpp:209, :226): no code of divid reads them and it says
    /// nothing about them, so irondivid does not call them unsupported; an
    /// option of divid that irondivid has nothing for still gets the warning
    #[test]
    fn help_only_options_draw_no_warning() {
        let s = Settings::default();
        assert_eq!(option_warning(&s, "checkpoints"), None);
        assert_eq!(option_warning(&s, "printpriority"), None);
        assert_eq!(option_warning(&s, "litemode"), None);
        assert_eq!(option_warning(&s, "budgetvotemode"), None);
        assert_eq!(option_warning(&s, "masternode"), None);
        // applied as divid applies it
        assert_eq!(option_warning(&s, "dbcache"), None);
        assert_eq!(option_warning(&s, "par"), None);
        assert_eq!(option_warning(&s, "peerbloomfilters"), None);
        assert!(option_warning(&s, "accountlabels")
            .unwrap()
            .contains("not supported"));
        assert!(option_warning(&s, "nosuchoption")
            .unwrap()
            .starts_with("Unknown option"));
    }

    /// divid's own check and test-aid options are taken without a warning
    /// (BlockCheckingHelpers.cpp:162, init.cpp:795, :1281, script/sigcache.cpp:51,
    /// main.cpp:473, Node.cpp:479-485)
    #[test]
    fn divids_check_and_test_options_draw_no_warning() {
        let s = Settings::default();
        for k in [
            "checkblockindex",
            "checkmempool",
            "flushwallet",
            "maxsigcachesize",
            "dropmessagestest",
            "fuzzmessagestest",
        ] {
            assert_eq!(option_warning(&s, k), None, "{k}");
        }
    }

    /// The masternode options are read when the node starts, after
    /// masternode.conf, in divid's order (masternode_options); building the
    /// configuration takes them without a word
    #[test]
    fn masternode_lines_are_checked_at_the_start() {
        for value in ["1", "0", "mn1"] {
            let conf = format!("rpcuser=x\nmasternode={}\n", value);
            assert!(cfg_in("irondivi.conf", &conf, &[]).is_ok(), "{value}");
        }
        let c = cfg_in(
            "irondivi.conf",
            "rpcuser=x\nmasternodeprivkey=abc\nmasternodeaddr=1.2.3.4:51472\nmnconf=x.conf\nmnconflock=0\n",
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
                "Invalid amount for -maxtxfee=<amount>"
            );
        }
        assert_eq!(
            refused(CONF, &["-maxtxfee=0.00001", "-minrelaytxfee=0.0001"]),
            "Invalid amount for -maxtxfee=<amount> (must be at least the minrelay \
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
            "Unknown network specified in -onlynet (use ipv4, ipv6, onion or tor)"
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
            "Could not parse -rpcbind value as network address"
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
            "Could not parse -rpcbind value (value 2 of 2) as network address"
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
        let refusal = refused(&format!("{CONF}listen\n"), &[]);
        assert!(
            refusal.ends_with(
                "divi.conf: the options configuration file contains an invalid line (line 4)"
            ),
            "{refusal}"
        );
        // The line itself is never shown: it may hold a password (R3, code 3)
        assert!(!refused(&format!("{CONF}rpcpassword secret\n"), &[]).contains("secret"));
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

    /// A lock let go within 10 seconds is taken: Divi Core waits that long for
    /// a node still on its way out (init.cpp:858-860)
    #[test]
    fn the_data_directory_lock_is_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_data_dir(dir.path()).unwrap();
        std::thread::scope(|s| {
            s.spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(1));
                drop(first);
            });
            let started = std::time::Instant::now();
            assert!(lock_data_dir(dir.path()).is_ok());
            assert!(started.elapsed() >= std::time::Duration::from_millis(900));
        });
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
mod proxy_tor_settings_tests {
    use super::*;

    fn p2p(argv: &[&str]) -> divi_node::config::P2pConfig {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vec![
            "irondivid".to_string(),
            "--regtest".to_string(),
            format!("--datadir={}", dir.path().display()),
        ];
        v.extend(argv.iter().map(|s| s.to_string()));
        build_config(&Args::parse_from(v)).unwrap().p2p
    }

    /// -maxconnections as divid reads it: a number below 0, a text or nothing
    /// is 0, and at most FD_SETSIZE less the binds less 150 (net.cpp:1726-1728);
    /// inbound peers get it less 16 (net.cpp:757)
    #[test]
    fn maxconnections_is_read_as_divid_reads_it() {
        let slots = |argv: &[&str]| {
            let c = p2p(argv);
            (c.max_inbound, c.max_outbound)
        };
        for none in [
            "-maxconnections=-1",
            "-maxconnections=",
            "-maxconnections=abc",
        ] {
            assert_eq!(slots(&[none]), (0, 0), "{none}");
        }
        assert_eq!(slots(&["-maxconnections=17"]), (1, 16));
        assert_eq!(slots(&["-maxconnections=5"]), (0, 5));
        assert_eq!(slots(&["-maxconnections=2000"]), (857, 16));
        assert_eq!(
            slots(&[
                "-maxconnections=2000",
                "-bind=127.0.0.1",
                "-whitebind=127.0.0.1:1"
            ]),
            (856, 16)
        );
    }

    /// -upnp: off by default; -proxy and -listen=0 turn it off unless it is
    /// given (DEFAULT_UPNP, net.cpp:1690-1706)
    #[test]
    fn upnp_default_and_soft_sets() {
        assert!(!p2p(&[]).upnp);
        assert!(p2p(&["-upnp=1"]).upnp);
        assert!(p2p(&["-upnp"]).upnp);
        assert!(!p2p(&["-upnp=0"]).upnp);
        assert!(p2p(&["-upnp=1", "-listen=0"]).upnp);
        assert!(p2p(&["-upnp=1", "-proxy=127.0.0.1:9050"]).upnp);
    }

    /// -listenonion: on by default, off under -listen=0 (also by -connect or
    /// -proxy) unless given; -torcontrol and -torpassword as given
    #[test]
    fn tor_settings_default_and_soft_sets() {
        let d = p2p(&[]);
        assert!(d.listen_onion);
        assert_eq!(d.tor_control, "127.0.0.1:9051");
        assert_eq!(d.tor_password, "");
        assert!(!p2p(&["-listen=0"]).listen_onion);
        assert!(!p2p(&["-connect=127.0.0.1:1"]).listen_onion);
        assert!(!p2p(&["-proxy=127.0.0.1:9050"]).listen_onion);
        assert!(p2p(&["-listen=0", "-listenonion=1"]).listen_onion);
        assert!(p2p(&["-bind=127.0.0.1", "-connect=127.0.0.1:1"]).listen_onion);
        let t = p2p(&[
            "-torcontrol=127.0.0.1:9999",
            "-torpassword=dummy-not-a-password",
        ]);
        assert_eq!(t.tor_control, "127.0.0.1:9999");
        assert_eq!(t.tor_password, "dummy-not-a-password");
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

#[cfg(test)]
mod notify_tests {
    use super::notify_failed;

    #[test]
    fn a_failed_notify_line_holds_its_kind_and_status_only() {
        assert_eq!(
            notify_failed("walletnotify", "exit status: 1"),
            "runCommand error: walletnotify (exit status: 1)"
        );
        assert_eq!(
            notify_failed("blocknotify", std::io::ErrorKind::NotFound),
            "runCommand error: blocknotify (entity not found)"
        );
    }
}
