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

//! IronDivi CLI
//!
//! Command-line interface for interacting with the IronDivi daemon.
//!
//! It reads its options, parses arguments, waits, prints and exits as Divi
//! Core's divi-cli does (src/divi-cli.cpp, rpcclient.cpp), so scripts written
//! for divi-cli run unchanged. IronDivi additions (`--name value` options,
//! cookie authentication, irondivi.conf, `--stdin*`, `--named`, `--rpcwallet`,
//! `-getinfo`, `-netinfo`, `-generate`) do not change what a divi-cli command
//! line does.
//!
//! Usage:
//!   irondivi-cli [options] <command> [params]
//!
//! Examples:
//!   irondivi-cli getblockcount
//!   irondivi-cli -regtest getblockchaininfo
//!   irondivi-cli -rpcwait getblock 0000000000000000000...
//!   irondivi-cli -getinfo

mod json_spirit;

use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

/// A failure, printed and turned into an exit code as divi-cli does
#[derive(Debug)]
enum CliError {
    /// An error reply from the node: `error: {"code":…,"message":…}` on
    /// stderr, exit code the absolute value of the code (divi-cli.cpp:166-172)
    Rpc { code: i64, error: Vec<u8> },
    /// `error: <message>` on stderr, exit 1 (divi-cli.cpp:194-196)
    Message(String),
    /// A message printed as it is on stderr, exit 1 (AppInitRPC's errors)
    Plain(String),
    /// Text on stdout, exit 1 (-help, -version, no arguments)
    Usage(String),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            // exit() keeps the low 8 bits, as for divi-cli's `abs(code)`
            CliError::Rpc { code, .. } => (code.unsigned_abs() % 256) as i32,
            _ => 1,
        }
    }

    fn print(&self) {
        match self {
            CliError::Rpc { error, .. } => {
                let mut line = b"error: ".to_vec();
                line.extend_from_slice(error);
                line.push(b'\n');
                let _ = io::stderr().write_all(&line);
            }
            CliError::Message(msg) => eprintln!("error: {}", msg),
            CliError::Plain(msg) => eprintln!("{}", msg),
            CliError::Usage(text) => print!("{}", text),
        }
    }
}

/// The special commands IronDivi adds; divi-cli would read them as options
const SPECIAL_COMMANDS: [&str; 3] = ["-getinfo", "-netinfo", "-generate"];

/// Options that take a value. Written `--name value` (IronDivi's form), the
/// next argument is the value; divi-cli's form is `-name=value`.
const VALUE_OPTIONS: [&str; 8] = [
    "conf",
    "datadir",
    "rpcconnect",
    "rpcport",
    "rpcuser",
    "rpcpassword",
    "mode",
    "rpcwallet",
];

/// The command line, read as divi-cli reads it (Settings::ParseParameters):
/// options come before the method, `-name=value` or `-name`, `--name` the
/// same as `-name`, `-noname` its negation; unknown options are ignored.
#[derive(Debug, Default)]
struct Args {
    conf: Option<PathBuf>,
    rpcconnect: Option<String>,
    rpcport: Option<String>,
    rpcuser: Option<String>,
    rpcpassword: Option<String>,
    testnet: Option<bool>,
    regtest: Option<bool>,
    mode: String,
    rpcwallet: Option<String>,
    datadir: Option<PathBuf>,
    rpcwait: Option<bool>,
    stdin: bool,
    stdinrpcpass: bool,
    stdinwalletpassphrase: bool,
    named: bool,
    help: bool,
    version: bool,
    /// The method and its parameters
    args: Vec<String>,
}

/// Settings' InterpretBool: empty is true, else the leading integer is not
/// zero; IronDivi's irondivi.conf also writes `true`
fn interpret_bool(value: &str) -> bool {
    if value.is_empty() || value.trim() == "true" {
        return true;
    }
    // atoi: optional sign, then digits up to the first other character
    let v = value.trim_start();
    let digits = v.strip_prefix(['-', '+']).unwrap_or(v);
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    digits[..end].bytes().any(|b| b != b'0')
}

impl Args {
    /// Read the arguments after the program name
    fn parse(argv: &[String]) -> Result<Args, CliError> {
        let mut args = Args {
            mode: "divi".to_string(),
            ..Args::default()
        };
        let mut settings: Vec<(String, String)> = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            let option = arg.starts_with('-') && !SPECIAL_COMMANDS.contains(&arg.as_str());
            if !args.args.is_empty() || !option {
                // divi-cli also reads options among the parameters as settings
                if option && !args.args.is_empty() {
                    if let Some(setting) = split_option(arg) {
                        settings.push((setting.0, setting.1.unwrap_or_default()));
                    }
                }
                args.args.push(arg.clone());
                i += 1;
                continue;
            }
            if let Some((key, value)) = split_option(arg) {
                let value = match value {
                    Some(v) => v,
                    // IronDivi's `--name value` and `-c path`
                    None if (arg.starts_with("--") && VALUE_OPTIONS.contains(&key.as_str()))
                        || key == "c" =>
                    {
                        i += 1;
                        argv.get(i).cloned().unwrap_or_default()
                    }
                    None => String::new(),
                };
                settings.push((key, value));
            }
            i += 1;
        }
        for (key, value) in settings {
            args.set(&key, &value)?;
        }
        Ok(args)
    }

    /// Apply one setting; a later one wins, as on divi-cli's command line
    fn set(&mut self, key: &str, value: &str) -> Result<(), CliError> {
        // -noname=v is -name=!v
        let (key, value) = match key.strip_prefix("no") {
            Some(rest) if !rest.is_empty() && !matches!(key, "named") => (
                rest,
                if interpret_bool(value) { "0" } else { "1" }.to_string(),
            ),
            _ => (key, value.to_string()),
        };
        let flag = interpret_bool(&value);
        match key {
            "conf" | "c" => self.conf = Some(PathBuf::from(value)),
            "datadir" => self.datadir = Some(PathBuf::from(value)),
            "rpcconnect" => self.rpcconnect = Some(value),
            "rpcport" => self.rpcport = Some(value),
            "rpcuser" => self.rpcuser = Some(value),
            "rpcpassword" => self.rpcpassword = Some(value),
            "rpcwallet" => self.rpcwallet = Some(value),
            "mode" => {
                if value != "divi" && value != "privatedivi" {
                    return Err(CliError::Message(format!(
                        "invalid value '{}' for -mode: expected divi or privatedivi",
                        value
                    )));
                }
                self.mode = value;
            }
            "testnet" => self.testnet = Some(flag),
            "regtest" => self.regtest = Some(flag),
            "rpcwait" => self.rpcwait = Some(flag),
            "stdin" => self.stdin = flag,
            "stdinrpcpass" => self.stdinrpcpass = flag,
            "stdinwalletpassphrase" => self.stdinwalletpassphrase = flag,
            "named" | "n" => self.named = flag,
            "?" | "help" | "h" => self.help = true,
            "version" | "V" => self.version = true,
            _ => {}
        }
        Ok(())
    }
}

/// An option's name and value: `--x` is `-x`, `---x` is ignored
fn split_option(arg: &str) -> Option<(String, Option<String>)> {
    if arg.starts_with("---") {
        return None;
    }
    let body = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-'))?;
    Some(match body.split_once('=') {
        Some((k, v)) => (k.to_string(), Some(v.to_string())),
        None => (body.to_string(), None),
    })
}

/// divi-cli's -help / -? line, also printed with no arguments
fn version_line() -> String {
    format!(
        "IronDivi RPC client version v{}\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// divi-cli's -version text: the version line, usage and options
fn version_text() -> String {
    version_line()
        + "\nUsage:\n  irondivi-cli [options] <command> [params]  Send command to IronDivi\n  irondivi-cli [options] help                List commands\n  irondivi-cli [options] help <command>      Get help for a command\n"
        + "\nOptions:\n  -?                     This help message\n  -conf=<file>           Configuration file (default: irondivi.conf, else divi.conf, in the data directory)\n  -datadir=<dir>         Data directory\n  -testnet               Use the test network\n  -regtest               Use the regression test network\n  -mode=<divi|privatedivi>  Chain mode (default: divi)\n  -rpcconnect=<ip>       Send commands to node running on <ip> (default: 127.0.0.1)\n  -rpcport=<port>        Connect to JSON-RPC on <port> (default: irondivid's: 51471, testnet 51473, regtest 51475)\n  -rpcwait               Wait for RPC server to start\n  -rpcuser=<user>        Username for JSON-RPC connections\n  -rpcpassword=<pw>      Password for JSON-RPC connections (without either, the node's .cookie)\n  -rpcwallet=<name>      Wallet of a multi-wallet node\n  -named                 Pass named arguments (name=value) instead of positional ones\n  -stdin                 Read extra arguments from standard input, one per line\n  -stdinrpcpass          Read the RPC password from standard input\n  -stdinwalletpassphrase Read the wallet passphrase(s) from standard input\n  -getinfo, -netinfo [level], -generate <n>  Summary commands\n  Options may also be written --name value.\n"
}

/// Get default RPC port based on network
fn default_rpc_port(testnet: bool, regtest: bool, privatedivi: bool) -> u16 {
    match (privatedivi, regtest, testnet) {
        (true, true, _) => 52475,
        (true, _, true) => 52473,
        (true, _, _) => 52471,
        (_, true, _) => 51475,
        (_, _, true) => 51473,
        _ => 51471,
    }
}

/// Configuration values read from the config file
#[derive(Default)]
struct Config {
    rpcuser: Option<String>,
    rpcpassword: Option<String>,
    rpcport: Option<String>,
    rpcconnect: Option<String>,
    testnet: Option<bool>,
    regtest: Option<bool>,
    rpcwait: Option<bool>,
    mode: Option<String>,
}

/// Read the configuration file. As divi-cli (Settings::ReadConfigFile), the
/// first value of a key wins and command-line values are not overridden;
/// IronDivi also reads TOML quoting and `[test]` / `[regtest]` sections.
fn read_config(path: &Path, network: &str) -> Config {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Config::default(),
    };

    let mut config = Config::default();
    let mut current_section = "main".to_string();
    let target_section = match network {
        "testnet" => "test",
        "regtest" => "regtest",
        _ => "main",
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle section headers like [regtest], [test]
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_lowercase();
            continue;
        }

        // Only apply settings from main (no header) or matching network section
        if current_section != "main" && current_section != target_section {
            continue;
        }

        // Strip inline comments (value # comment)
        let line = line.split('#').next().unwrap_or(line).trim();

        if let Some((key, value)) = line.split_once('=') {
            // irondivid reads the same file as TOML, where strings are quoted.
            let value = unquote(value).trim().to_string();
            let first = |slot: &mut Option<String>| {
                slot.get_or_insert(value.clone());
            };
            match key.trim() {
                "rpcuser" => first(&mut config.rpcuser),
                "rpcpassword" => first(&mut config.rpcpassword),
                "rpcport" => first(&mut config.rpcport),
                "rpcconnect" => first(&mut config.rpcconnect),
                "mode" => first(&mut config.mode),
                "testnet" => {
                    config.testnet.get_or_insert(interpret_bool(&value));
                }
                "regtest" => {
                    config.regtest.get_or_insert(interpret_bool(&value));
                }
                "rpcwait" => {
                    config.rpcwait.get_or_insert(interpret_bool(&value));
                }
                _ => {}
            }
        }
    }
    config
}

/// The Core data directory for the chain mode: `~/.divi` for Divi and
/// `~/.privatedivi` for PrivateDivi, matching divid and privatedivid.
fn chain_home(home: &Path, privatedivi: bool) -> PathBuf {
    home.join(if privatedivi { ".privatedivi" } else { ".divi" })
}

/// The default config file for the chain mode. PrivateDivi must not read
/// `~/.divi/divi.conf`: that file belongs to a Divi node, and its `rpcport`
/// would send a `--mode privatedivi` call to a node on another chain.
fn default_conf_path(home: &Path, privatedivi: bool) -> PathBuf {
    chain_home(home, privatedivi).join(if privatedivi {
        "privatedivi.conf"
    } else {
        "divi.conf"
    })
}

/// irondivid's default data directory, mirroring `default_data_dir()` and the
/// subdirectories irondivid adds: `/privatedivi` for PrivateDivi, then
/// `/testnet` or `/regtest`.
fn irondivi_data_dir(home: &Path, privatedivi: bool, network: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    let mut dir = home
        .join("Library")
        .join("Application Support")
        .join("IronDivi");
    #[cfg(target_os = "windows")]
    let mut dir = dirs::data_dir()
        .unwrap_or_else(|| home.to_path_buf())
        .join("IronDivi");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut dir = home.join(".irondivi");
    if privatedivi {
        dir = dir.join("privatedivi");
    }
    match network {
        "testnet" => dir.join("testnet"),
        "regtest" => dir.join("regtest"),
        _ => dir,
    }
}

/// The config file to read when `--conf` is not given: irondivid's
/// `irondivi.conf` (in `--datadir`, or irondivid's default data dir), else the
/// Divi Core file. Without this an irondivid with RPC auth is unreachable,
/// since its credentials live only in `irondivi.conf`.
fn find_conf_path(
    home: &Path,
    datadir: Option<&Path>,
    privatedivi: bool,
    network: &str,
) -> PathBuf {
    let irondivi = match datadir {
        Some(dir) => dir.join("irondivi.conf"),
        None => irondivi_data_dir(home, privatedivi, network).join("irondivi.conf"),
    };
    if irondivi.exists() {
        irondivi
    } else {
        default_conf_path(home, privatedivi)
    }
}

/// Strip one pair of matching surrounding quotes, as TOML string values carry.
fn unquote(value: &str) -> &str {
    let v = value.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

/// The cookie irondivid writes in its own data directory (`--datadir`, or
/// its default per mode and network).
fn irondivi_cookie_path(
    home: &Path,
    datadir: Option<&Path>,
    privatedivi: bool,
    network: &str,
) -> PathBuf {
    match datadir {
        Some(dir) => dir.join(".cookie"),
        None => irondivi_data_dir(home, privatedivi, network).join(".cookie"),
    }
}

/// The cookie of a Divi Core-style node: a network subdirectory of
/// `--datadir`, or of the Core directory.
fn core_cookie_path(
    home: &Path,
    datadir: Option<&Path>,
    privatedivi: bool,
    network: &str,
) -> PathBuf {
    let base = datadir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| chain_home(home, privatedivi));
    match network {
        "testnet" => base.join("testnet3").join(".cookie"),
        "regtest" => base.join("regtest").join(".cookie"),
        _ => base.join(".cookie"),
    }
}

/// Read cookie file for authentication
fn read_cookie(path: &Path) -> Option<(String, String)> {
    let contents = std::fs::read_to_string(path).ok()?;
    let (user, pass) = contents.trim().split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Read what `--stdinrpcpass`, `--stdinwalletpassphrase` and `--stdin` ask
/// for (the RPC password first). Returns the wallet passphrases, which go in
/// as the method's first parameters, always as strings.
fn handle_stdin(args: &mut Args) -> Result<Vec<String>, CliError> {
    if args.stdinrpcpass {
        let mut pass = String::new();
        io::stdin()
            .lock()
            .read_line(&mut pass)
            .map_err(|e| CliError::Message(e.to_string()))?;
        args.rpcpassword = Some(pass.trim().to_string());
    }

    let mut passphrases = Vec::new();
    if args.stdinwalletpassphrase {
        let method = args.args.first().map(String::as_str).unwrap_or("");
        let stdin = io::stdin();
        let terminal = io::IsTerminal::is_terminal(&stdin);
        passphrases = read_wallet_passphrases(method, &mut stdin.lock(), terminal)?;
    }

    if args.stdin {
        let mut extra_input = String::new();
        io::stdin()
            .lock()
            .read_to_string(&mut extra_input)
            .map_err(|e| CliError::Message(e.to_string()))?;
        for line in extra_input.lines() {
            if !line.is_empty() {
                args.args.push(line.to_string());
            }
        }
    }

    Ok(passphrases)
}

/// Wallet passphrases `method` takes as its first arguments
fn wallet_passphrase_count(method: &str) -> Option<usize> {
    match method {
        "walletpassphrase" | "encryptwallet" => Some(1),
        "walletpassphrasechange" => Some(2),
        _ => None,
    }
}

/// `--stdinwalletpassphrase` (bitcoin-cli `-stdinwalletpassphrase`): read one
/// passphrase per line, prompting on stderr with echo off when `terminal`.
fn read_wallet_passphrases(
    method: &str,
    input: &mut impl BufRead,
    terminal: bool,
) -> Result<Vec<String>, CliError> {
    let count = wallet_passphrase_count(method).ok_or_else(|| {
        CliError::Message(
            "--stdinwalletpassphrase is only applicable for walletpassphrase, \
             walletpassphrasechange and encryptwallet"
                .to_string(),
        )
    })?;
    let prompts = if count == 2 {
        ["Old wallet passphrase> ", "New wallet passphrase> "].as_slice()
    } else {
        ["Wallet passphrase> "].as_slice()
    };
    let mut passphrases = Vec::with_capacity(count);
    for prompt in prompts {
        if terminal {
            eprint!("{}", prompt);
            set_terminal_echo(false);
        }
        let mut line = String::new();
        let read = input.read_line(&mut line);
        if terminal {
            set_terminal_echo(true);
            eprintln!();
        }
        let n = read.map_err(|e| CliError::Message(e.to_string()))?;
        if n == 0 {
            return Err(CliError::Message(
                "--stdinwalletpassphrase specified but failed to read from standard input"
                    .to_string(),
            ));
        }
        // Only the line ending is removed: spaces belong to the passphrase
        let len = line.trim_end_matches(['\n', '\r']).len();
        line.truncate(len);
        passphrases.push(line);
    }
    Ok(passphrases)
}

/// Turn terminal echo on stdin on or off (Unix `stty`)
fn set_terminal_echo(on: bool) {
    let _ = std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(std::process::Stdio::inherit())
        .status();
}

/// Handle -getinfo special command (aggregates multiple RPC calls)
fn handle_getinfo(client: &RpcClient) -> Result<(), CliError> {
    let blockchain = client.call_serde("getblockchaininfo")?;
    let network = client.call_serde("getnetworkinfo")?;
    let wallet = client.call_serde("getwalletinfo").ok();

    println!(
        "Chain: {}",
        blockchain["chain"].as_str().unwrap_or("unknown")
    );
    println!("Blocks: {}", blockchain["blocks"]);
    println!("Headers: {}", blockchain["headers"]);
    println!(
        "Verification: {:.4}%",
        blockchain["verificationprogress"].as_f64().unwrap_or(0.0) * 100.0
    );
    println!("Difficulty: {}", blockchain["difficulty"]);
    println!();
    println!("Network: {}", network["subversion"].as_str().unwrap_or(""));
    let (conn_in, conn_out) = match (
        network["connections_in"].as_u64(),
        network["connections_out"].as_u64(),
    ) {
        (Some(i), Some(o)) => (i, o),
        // Older servers do not report the split: count it from the peer list
        _ => {
            let peers = client.call_serde("getpeerinfo")?;
            connection_split(&peers)
        }
    };
    println!(
        "Connections: {} (in: {}, out: {})",
        network["connections"], conn_in, conn_out
    );

    if let Some(w) = wallet {
        println!();
        println!("Wallet: {}", w["walletname"].as_str().unwrap_or("default"));
        println!("Balance: {}", w["balance"]);
    }

    Ok(())
}

/// (inbound, outbound) connection counts from a `getpeerinfo` result
fn connection_split(peers: &Value) -> (u64, u64) {
    let peers = peers.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let inbound = peers
        .iter()
        .filter(|p| p["inbound"].as_bool().unwrap_or(false))
        .count() as u64;
    (inbound, peers.len() as u64 - inbound)
}

/// Handle -netinfo special command (shows peer connection summary)
fn handle_netinfo(client: &RpcClient, detail: u8) -> Result<(), CliError> {
    let peers = client.call_serde("getpeerinfo")?;
    let network = client.call_serde("getnetworkinfo")?;

    let empty_vec = vec![];
    let peers_arr = peers.as_array().unwrap_or(&empty_vec);
    println!("Peer connections: {}", peers_arr.len());
    println!("Protocol version: {}", network["protocolversion"]);
    println!();

    if detail > 0 {
        println!(
            "{:<45} {:>6} {:>8} {:>8}",
            "Address", "Type", "Recv", "Send"
        );
        println!("{}", "-".repeat(70));
        for peer in peers_arr {
            println!(
                "{:<45} {:>6} {:>8} {:>8}",
                peer["addr"].as_str().unwrap_or("?"),
                if peer["inbound"].as_bool().unwrap_or(false) {
                    "in"
                } else {
                    "out"
                },
                peer["bytesrecv"].as_u64().unwrap_or(0) / 1024,
                peer["bytessent"].as_u64().unwrap_or(0) / 1024,
            );
        }
    }

    Ok(())
}

/// Handle -generate special command (two-step: get address, then generate)
fn handle_generate(client: &RpcClient, nblocks: u64) -> Result<(), CliError> {
    // Step 1: Get a new address from wallet
    let address_result = client.call_serde("getnewaddress")?;
    let address = address_result
        .as_str()
        .ok_or_else(|| CliError::Message("Failed to get new address".to_string()))?;

    // Step 2: Generate blocks to that address
    let reply = client.post("generatetoaddress", &json!([nblocks, address]))?;
    rpc_error(&reply, false)?;
    let result = json_spirit::to_serde(reply.get("result"));

    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|e| CliError::Message(e.to_string()))?
    );
    Ok(())
}

/// A call failed to connect: divi-cli retries those with -rpcwait
enum CallError {
    Connect,
    Failed(CliError),
}

/// RPC Client
struct RpcClient {
    url: String,
    username: Option<String>,
    password: Option<String>,
}

impl RpcClient {
    /// Send one request and return the reply object, checked as divi-cli's
    /// CallRPC does (divi-cli.cpp:85-134). There is no time limit: divi-cli
    /// waits for the node however long a call takes.
    fn post(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<json_spirit::Value, CallError> {
        let request = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params});
        let client = reqwest::blocking::Client::builder()
            .timeout(None)
            .build()
            .map_err(|e| CallError::Failed(CliError::Message(e.to_string())))?;
        let mut req = client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(request.to_string());
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            req = req.basic_auth(user, Some(pass));
        }
        let response = match req.send() {
            Ok(r) => r,
            // divi-cli: only failing to connect is "couldn't connect"
            Err(e) if e.is_connect() || e.is_builder() => return Err(CallError::Connect),
            Err(_) => return Err(fail("no response from server")),
        };
        let status = response.status().as_u16();
        let body = response.bytes().map(|b| b.to_vec()).unwrap_or_default();

        if status == 401 {
            return Err(fail(
                "incorrect rpcuser or rpcpassword (authorization failed)",
            ));
        }
        if status > 400 && status != 404 && status != 500 {
            return Err(fail(&format!("server returned HTTP error {}", status)));
        }
        if body.is_empty() {
            return Err(fail("no response from server"));
        }
        let reply =
            json_spirit::parse(&body).ok_or_else(|| fail("couldn't parse reply from server"))?;
        match &reply {
            json_spirit::Value::Object(members) if members.is_empty() => Err(fail(
                "expected reply to have result, error and id properties",
            )),
            json_spirit::Value::Object(_) => Ok(reply),
            other => Err(fail(&format!(
                "value is type {}, expected obj",
                other.type_name()
            ))),
        }
    }

    /// One call for the summary commands: its result, or its error
    fn call_serde(&self, method: &str) -> Result<serde_json::Value, CliError> {
        let reply = match self.post(method, &json!([])) {
            Ok(reply) => reply,
            Err(CallError::Connect) => {
                return Err(CliError::Message("couldn't connect to server".into()))
            }
            Err(CallError::Failed(e)) => return Err(e),
        };
        rpc_error(&reply, false)?;
        Ok(json_spirit::to_serde(reply.get("result")))
    }
}

fn fail(message: &str) -> CallError {
    CallError::Failed(CliError::Message(message.to_string()))
}

/// The reply's error, as divi-cli reads it: an error object needs an integer
/// code; with -rpcwait a warmup error (-28) means try again
fn rpc_error(reply: &json_spirit::Value, wait: bool) -> Result<(), CallError> {
    let error = reply.get("error");
    match error {
        json_spirit::Value::Null => Ok(()),
        json_spirit::Value::Object(_) => {
            let code = match error.get("code") {
                json_spirit::Value::Int(c) => *c,
                json_spirit::Value::UInt(c) => *c as i64,
                other => {
                    return Err(fail(&format!(
                        "value is type {}, expected int",
                        other.type_name()
                    )))
                }
            };
            if wait && code == -28 {
                return Err(CallError::Connect);
            }
            Err(CallError::Failed(CliError::Rpc {
                code,
                error: json_spirit::write(error, false),
            }))
        }
        other => Err(fail(&format!(
            "value is type {}, expected obj",
            other.type_name()
        ))),
    }
}

impl From<CallError> for CliError {
    fn from(e: CallError) -> Self {
        match e {
            CallError::Connect => CliError::Message("couldn't connect to server".into()),
            CallError::Failed(e) => e,
        }
    }
}

/// Parse named arguments in key=value format
fn parse_named_args(args: &[String]) -> Result<serde_json::Value, CliError> {
    let mut obj = serde_json::Map::new();
    for arg in args {
        let (key, value) = arg.split_once('=').ok_or_else(|| {
            CliError::Message(format!(
                "Invalid named argument: {} (expected key=value)",
                arg
            ))
        })?;
        obj.insert(key.to_string(), parse_argument(value));
    }
    Ok(serde_json::Value::Object(obj))
}

/// An argument as divi-cli's RPCConvertValues sends it (rpcclient.cpp:17-36):
/// the JSON value when the whole argument is JSON, else the argument itself
fn parse_argument(arg: &str) -> serde_json::Value {
    match json_spirit::parse(arg.as_bytes()) {
        Some(value) => json_spirit::to_serde(&value),
        None => serde_json::Value::String(arg.to_string()),
    }
}

/// The result as divi-cli prints it: nothing for null, a string as it is,
/// anything else as indented JSON (divi-cli.cpp:174-180, 202-203)
fn format_result(result: &json_spirit::Value) -> Option<Vec<u8>> {
    match result {
        json_spirit::Value::Null => None,
        json_spirit::Value::Str(s) => Some(s.clone()),
        other => Some(json_spirit::write(other, true)),
    }
}

/// Where an RPC call goes and with which credentials.
#[derive(Debug)]
struct Endpoint {
    rpc_connect: String,
    rpc_port: String,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
    rpcwait: bool,
    conf_path: PathBuf,
}

/// Resolve the RPC endpoint (priority: CLI args > config file > defaults).
/// The default config file and cookie directory follow `--mode`, so a
/// PrivateDivi call never picks up a Divi node's `rpcport` or credentials.
fn resolve_endpoint(args: &Args, home: &Path) -> Result<Endpoint, CliError> {
    let privatedivi = args.mode == "privatedivi";

    // Determine network type
    let network = if args.regtest == Some(true) {
        "regtest"
    } else if args.testnet == Some(true) {
        "testnet"
    } else {
        "mainnet"
    };

    // divi-cli: -conf is relative to the data directory, divi.conf by default
    let conf_path = match (&args.conf, &args.datadir) {
        (Some(conf), Some(dir)) if conf.is_relative() => dir.join(conf),
        (Some(conf), _) => conf.clone(),
        (None, Some(dir)) if !dir.join("irondivi.conf").exists() => dir.join("divi.conf"),
        (None, _) => find_conf_path(home, args.datadir.as_deref(), privatedivi, network),
    };
    let config = read_config(&conf_path, network);

    // Apply config file values if CLI args not provided
    let testnet = args.testnet.or(config.testnet).unwrap_or(false);
    let regtest = args.regtest.or(config.regtest).unwrap_or(false);
    if testnet && regtest {
        return Err(CliError::Plain(
            "Error: Invalid combination of -regtest and -testnet.".to_string(),
        ));
    }

    // Re-determine network after config
    let network = if regtest {
        "regtest"
    } else if testnet {
        "testnet"
    } else {
        "mainnet"
    };

    let rpc_connect = args
        .rpcconnect
        .clone()
        .or(config.rpcconnect.clone())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let rpc_port = args
        .rpcport
        .clone()
        .or(config.rpcport.clone())
        .unwrap_or_else(|| default_rpc_port(testnet, regtest, privatedivi).to_string());

    // Determine credentials: CLI > irondivi.conf (or --conf) > irondivid's
    // cookie > the Divi Core fallback conf > a Core-layout cookie. irondivid's
    // own cookie beats ~/.divi/divi.conf credentials, which belong to divid.
    let datadir = args.datadir.as_deref();
    let conf_is_core_fallback = args.conf.is_none()
        && args.datadir.is_none()
        && conf_path == default_conf_path(home, privatedivi);
    let conf_creds = match (config.rpcuser.clone(), config.rpcpassword.clone()) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    };
    let (rpc_user, rpc_password) = match (&args.rpcuser, &args.rpcpassword) {
        (Some(u), Some(p)) => (Some(u.clone()), Some(p.clone())),
        _ => {
            let found = match conf_creds {
                Some(creds) if !conf_is_core_fallback => Some(creds),
                core_creds => {
                    read_cookie(&irondivi_cookie_path(home, datadir, privatedivi, network))
                        .or(core_creds)
                        .or_else(|| {
                            read_cookie(&core_cookie_path(home, datadir, privatedivi, network))
                        })
                }
            };
            match found {
                Some((u, p)) => (
                    args.rpcuser.clone().or(Some(u)),
                    args.rpcpassword.clone().or(Some(p)),
                ),
                None => (
                    args.rpcuser.clone().or(config.rpcuser),
                    args.rpcpassword.clone().or(config.rpcpassword),
                ),
            }
        }
    };

    Ok(Endpoint {
        rpc_connect,
        rpc_port,
        rpc_user,
        rpc_password,
        rpcwait: args.rpcwait.or(config.rpcwait).unwrap_or(false),
        conf_path,
    })
}

fn run(argv: &[String]) -> Result<Option<Vec<u8>>, CliError> {
    // divi-cli's AppInitRPC: help and version first, then the data directory,
    // the configuration file and the network
    let mut args = Args::parse(argv)?;
    if argv.is_empty() || args.help {
        return Err(CliError::Usage(version_line()));
    }
    if args.version {
        return Err(CliError::Usage(version_text()));
    }
    if let Some(dir) = &args.datadir {
        if !dir.is_dir() {
            return Err(CliError::Plain(format!(
                "Error: Specified data directory \"{}\" does not exist.",
                dir.display()
            )));
        }
    }

    let home = dirs::home_dir().unwrap_or_default();
    let mut endpoint = resolve_endpoint(&args, &home)?;

    let passphrases = handle_stdin(&mut args)?;
    if args.stdinrpcpass {
        endpoint.rpc_password = args.rpcpassword.clone();
    }

    // CommandLineRPC: a method is needed
    if args.args.is_empty() {
        return Err(CliError::Message("too few parameters".to_string()));
    }

    // Build URL with optional wallet
    let url = if let Some(ref wallet) = args.rpcwallet {
        format!(
            "http://{}:{}/wallet/{}",
            endpoint.rpc_connect, endpoint.rpc_port, wallet
        )
    } else {
        format!("http://{}:{}", endpoint.rpc_connect, endpoint.rpc_port)
    };

    let method = args.args[0].clone();
    let method_args = &args.args[1..];

    // Convert string args to JSON values
    let params = if args.named {
        parse_named_args(method_args)?
    } else {
        let mut params: Vec<serde_json::Value> = passphrases
            .into_iter()
            .map(serde_json::Value::String)
            .collect();
        params.extend(method_args.iter().map(|a| parse_argument(a)));
        serde_json::Value::Array(params)
    };

    // CallRPC: credentials are needed (divi-cli.cpp:87-91)
    let no_user = endpoint.rpc_user.as_deref().unwrap_or("").is_empty();
    let no_password = endpoint.rpc_password.as_deref().unwrap_or("").is_empty();
    if no_user && no_password {
        return Err(CliError::Message(format!(
            "You must set rpcpassword=<password> in the configuration file:\n{}\n\
             If the file does not exist, create it with owner-readable-only file permissions.",
            endpoint.conf_path.display()
        )));
    }

    let client = RpcClient {
        url,
        username: endpoint.rpc_user,
        password: endpoint.rpc_password,
    };

    // Handle special commands
    match method.as_str() {
        "-getinfo" => {
            handle_getinfo(&client)?;
            return Ok(None);
        }
        "-netinfo" => {
            let detail = method_args
                .first()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0u8);
            handle_netinfo(&client, detail)?;
            return Ok(None);
        }
        "-generate" => {
            let nblocks = method_args
                .first()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1u64);
            handle_generate(&client, nblocks)?;
            return Ok(None);
        }
        _ => {}
    }

    // Execute, waiting for the node with -rpcwait (divi-cli.cpp:156-191)
    loop {
        let outcome = client
            .post(&method, &params)
            .and_then(|reply| rpc_error(&reply, endpoint.rpcwait).map(|()| reply));
        match outcome {
            Ok(reply) => return Ok(format_result(reply.get("result"))),
            Err(CallError::Connect) if endpoint.rpcwait => {
                std::thread::sleep(std::time::Duration::from_millis(1000))
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let exit_code = match run(&argv) {
        Ok(output) => {
            if let Some(mut text) = output {
                text.push(b'\n');
                let _ = io::stdout().write_all(&text);
            }
            0
        }
        Err(e) => {
            e.print();
            e.exit_code()
        }
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use std::fs;

    /// The command line after the program name
    fn parse_args(argv: &[&str]) -> Args {
        let argv: Vec<String> = argv[1..].iter().map(|a| a.to_string()).collect();
        Args::parse(&argv).unwrap()
    }

    /// A home directory holding only a Divi Core testnet `divi.conf`, the
    /// layout found on vps1 where divid and irondivid share one user.
    fn home_with_divi_conf() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".divi")).unwrap();
        fs::write(
            home.path().join(".divi/divi.conf"),
            "testnet=1\nrpcport=51475\n",
        )
        .unwrap();
        home
    }

    #[test]
    fn default_conf_path_follows_mode() {
        let home = Path::new("/h");
        assert_eq!(
            default_conf_path(home, false),
            Path::new("/h/.divi/divi.conf")
        );
        assert_eq!(
            default_conf_path(home, true),
            Path::new("/h/.privatedivi/privatedivi.conf")
        );
        assert_eq!(chain_home(home, false), Path::new("/h/.divi"));
        assert_eq!(chain_home(home, true), Path::new("/h/.privatedivi"));
    }

    /// Regression: `--mode privatedivi --testnet` used to read
    /// `~/.divi/divi.conf` and query divid on 51475 (Divi testnet).
    #[test]
    fn privatedivi_ignores_divi_conf() {
        let home = home_with_divi_conf();
        let args = parse_args(&[
            "irondivi-cli",
            "--mode",
            "privatedivi",
            "--testnet",
            "getblockcount",
        ]);
        assert_eq!(
            resolve_endpoint(&args, home.path()).unwrap().rpc_port,
            "52473"
        );
    }

    #[test]
    fn divi_still_reads_divi_conf() {
        let home = home_with_divi_conf();
        let args = parse_args(&["irondivi-cli", "getblockcount"]);
        assert_eq!(
            resolve_endpoint(&args, home.path()).unwrap().rpc_port,
            "51475"
        );
    }

    #[test]
    fn privatedivi_reads_its_own_conf() {
        let home = home_with_divi_conf();
        fs::create_dir_all(home.path().join(".privatedivi")).unwrap();
        fs::write(
            home.path().join(".privatedivi/privatedivi.conf"),
            "[test]\nrpcport=52599\n",
        )
        .unwrap();
        let args = parse_args(&[
            "irondivi-cli",
            "--mode",
            "privatedivi",
            "--testnet",
            "getblockcount",
        ]);
        assert_eq!(
            resolve_endpoint(&args, home.path()).unwrap().rpc_port,
            "52599"
        );
    }

    /// Regression: irondivi-cli read only the Core `~/.divi/divi.conf`, so it
    /// got 401 from an irondivid whose credentials are in `irondivi.conf`.
    #[test]
    fn irondivi_conf_is_preferred_over_divi_conf() {
        let home = home_with_divi_conf();
        let dir = irondivi_data_dir(home.path(), false, "mainnet");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("irondivi.conf"),
            "rpcuser = \"u\"\nrpcpassword = \"p\"\nrpcport = 51471\n",
        )
        .unwrap();
        let args = parse_args(&["irondivi-cli", "getblockcount"]);
        let ep = resolve_endpoint(&args, home.path()).unwrap();
        assert_eq!(ep.rpc_port, "51471");
        assert_eq!(ep.rpc_user.as_deref(), Some("u"));
        assert_eq!(ep.rpc_password.as_deref(), Some("p"));
    }

    #[test]
    fn datadir_selects_its_irondivi_conf() {
        let home = home_with_divi_conf();
        let vault = home.path().join(".irondivi-vault");
        fs::create_dir_all(&vault).unwrap();
        fs::write(vault.join("irondivi.conf"), "rpcport = 51491\n").unwrap();
        let args = parse_args(&[
            "irondivi-cli",
            "--datadir",
            vault.to_str().unwrap(),
            "getblockcount",
        ]);
        assert_eq!(
            resolve_endpoint(&args, home.path()).unwrap().rpc_port,
            "51491"
        );
    }

    #[test]
    fn irondivi_data_dir_follows_mode_and_network() {
        let home = Path::new("/h");
        let base = irondivi_data_dir(home, false, "mainnet");
        assert_eq!(
            irondivi_data_dir(home, true, "mainnet"),
            base.join("privatedivi")
        );
        assert_eq!(
            irondivi_data_dir(home, true, "testnet"),
            base.join("privatedivi").join("testnet")
        );
        assert_eq!(
            irondivi_data_dir(home, false, "regtest"),
            base.join("regtest")
        );
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        assert_eq!(base, Path::new("/h/.irondivi"));
    }

    #[test]
    fn cookie_in_irondivid_datadir_is_used() {
        // irondivid writes <datadir>/.cookie; the CLI must find it with
        // the same --datadir and no credentials.
        let home = tempfile::tempdir().unwrap();
        let datadir = home.path().join("node");
        fs::create_dir_all(&datadir).unwrap();
        fs::write(datadir.join(".cookie"), "__cookie__:feedbeef").unwrap();
        let args = parse_args(&[
            "irondivi-cli",
            "--regtest",
            "--datadir",
            datadir.to_str().unwrap(),
            "getblockcount",
        ]);
        let ep = resolve_endpoint(&args, home.path()).unwrap();
        assert_eq!(ep.rpc_user.as_deref(), Some("__cookie__"));
        assert_eq!(ep.rpc_password.as_deref(), Some("feedbeef"));
    }

    #[test]
    fn cookie_in_default_irondivi_dir_is_used() {
        let home = tempfile::tempdir().unwrap();
        let dir = irondivi_data_dir(home.path(), false, "regtest");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".cookie"), "__cookie__:c0ffee").unwrap();
        let args = parse_args(&["irondivi-cli", "--regtest", "getblockcount"]);
        let ep = resolve_endpoint(&args, home.path()).unwrap();
        assert_eq!(ep.rpc_user.as_deref(), Some("__cookie__"));
        assert_eq!(ep.rpc_password.as_deref(), Some("c0ffee"));
    }

    #[test]
    fn core_layout_cookie_still_found() {
        let home = tempfile::tempdir().unwrap();
        let datadir = home.path().join("core");
        fs::create_dir_all(datadir.join("testnet3")).unwrap();
        fs::write(datadir.join("testnet3/.cookie"), "__cookie__:abc").unwrap();
        let args = parse_args(&[
            "irondivi-cli",
            "--testnet",
            "--datadir",
            datadir.to_str().unwrap(),
            "getblockcount",
        ]);
        let ep = resolve_endpoint(&args, home.path()).unwrap();
        assert_eq!(ep.rpc_password.as_deref(), Some("abc"));
    }

    #[test]
    fn irondivid_cookie_beats_divi_core_conf_credentials() {
        // A host that also runs divid has ~/.divi/divi.conf with rpcuser and
        // rpcpassword; they must not shadow irondivid's own cookie.
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".divi")).unwrap();
        fs::write(
            home.path().join(".divi/divi.conf"),
            "rpcuser=core\nrpcpassword=corepw\n",
        )
        .unwrap();
        let datadir = home.path().join("node");
        fs::create_dir_all(&datadir).unwrap();
        let args = parse_args(&[
            "irondivi-cli",
            "--regtest",
            "--datadir",
            datadir.to_str().unwrap(),
            "getblockcount",
        ]);
        // No cookie: with -datadir, divi-cli reads <datadir>/divi.conf only,
        // never ~/.divi/divi.conf
        let ep = resolve_endpoint(&args, home.path()).unwrap();
        assert_eq!(ep.rpc_user.as_deref(), None);

        fs::write(datadir.join(".cookie"), "__cookie__:feedbeef").unwrap();
        let ep = resolve_endpoint(&args, home.path()).unwrap();
        assert_eq!(ep.rpc_user.as_deref(), Some("__cookie__"));
        assert_eq!(ep.rpc_password.as_deref(), Some("feedbeef"));

        // Credentials in the node's own irondivi.conf still win
        fs::write(
            datadir.join("irondivi.conf"),
            "rpcuser = \"u\"\nrpcpassword = \"p\"\n",
        )
        .unwrap();
        let ep = resolve_endpoint(&args, home.path()).unwrap();
        assert_eq!(ep.rpc_user.as_deref(), Some("u"));
    }

    #[test]
    fn explicit_rpcport_wins() {
        let home = home_with_divi_conf();
        let args = parse_args(&["irondivi-cli", "--rpcport", "1234", "getblockcount"]);
        assert_eq!(
            resolve_endpoint(&args, home.path()).unwrap().rpc_port,
            "1234"
        );
    }

    #[test]
    fn unknown_mode_is_rejected_listing_valid_values() {
        let err =
            Args::parse(&["--mode".into(), "irondivi".into(), "getblockcount".into()]).unwrap_err();
        let CliError::Message(err) = err else {
            panic!("expected a message")
        };
        assert!(err.contains("irondivi"), "{err}");
        assert!(err.contains("divi") && err.contains("privatedivi"), "{err}");
    }

    #[test]
    fn config_values_accept_toml_quotes() {
        assert_eq!(unquote(" \"alice\" "), "alice");
        assert_eq!(unquote("'alice'"), "alice");
        assert_eq!(unquote("alice"), "alice");
        assert_eq!(unquote("\""), "\"");
        assert_eq!(unquote("51491"), "51491");
    }
}

#[cfg(test)]
mod stdin_passphrase_tests {
    use super::*;

    #[test]
    fn reads_one_passphrase_line_keeping_spaces() {
        let mut input = io::Cursor::new(b"  my pass phrase \r\nnext\n".to_vec());
        let got = read_wallet_passphrases("walletpassphrase", &mut input, false).unwrap();
        assert_eq!(got, vec!["  my pass phrase ".to_string()]);
        let mut input = io::Cursor::new(b"pw\n".to_vec());
        assert_eq!(
            read_wallet_passphrases("encryptwallet", &mut input, false).unwrap(),
            vec!["pw".to_string()]
        );
    }

    #[test]
    fn walletpassphrasechange_reads_old_then_new() {
        let mut input = io::Cursor::new(b"old one\nnew one\n".to_vec());
        let got = read_wallet_passphrases("walletpassphrasechange", &mut input, false).unwrap();
        assert_eq!(got, vec!["old one".to_string(), "new one".to_string()]);
    }

    #[test]
    fn refuses_other_methods_and_empty_input() {
        let mut input = io::Cursor::new(b"pw\n".to_vec());
        assert!(read_wallet_passphrases("getbalance", &mut input, false).is_err());
        let mut input = io::Cursor::new(Vec::new());
        assert!(read_wallet_passphrases("walletpassphrase", &mut input, false).is_err());
    }
}
