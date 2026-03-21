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
//! Usage:
//!   irondivi-cli [OPTIONS] <COMMAND> [ARGS...]
//!
//! Examples:
//!   irondivi-cli getblockcount
//!   irondivi-cli --regtest getblockchaininfo
//!   irondivi-cli getblock 0000000000000000000...
//!   irondivi-cli -getinfo
//!   irondivi-cli -netinfo 1
//!   irondivi-cli -generate 10

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read};
use std::path::PathBuf;

/// Exit codes matching bitcoin-cli/divi-cli
mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const GENERAL_ERROR: i32 = 1;
    pub const CONNECTION_FAILED: i32 = 2;
    pub const INVALID_RESPONSE: i32 = 5;
    pub const INVALID_PARAMS: i32 = 87;
}

/// CLI error types with appropriate exit codes
#[derive(Debug)]
enum CliError {
    Connection(String),
    InvalidResponse(String),
    InvalidParams(String),
    RpcError { code: i64, message: String },
    General(String),
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            CliError::Connection(_) => exit_codes::CONNECTION_FAILED,
            CliError::InvalidResponse(_) => exit_codes::INVALID_RESPONSE,
            CliError::InvalidParams(_) => exit_codes::INVALID_PARAMS,
            CliError::RpcError { .. } => exit_codes::GENERAL_ERROR,
            CliError::General(_) => exit_codes::GENERAL_ERROR,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Connection(msg) => write!(f, "error: couldn't connect to server: {}", msg),
            CliError::InvalidResponse(msg) => {
                write!(f, "error: invalid response from server: {}", msg)
            }
            CliError::InvalidParams(msg) => write!(f, "error: invalid parameters: {}", msg),
            CliError::RpcError { code, message } => write!(f, "error code: {}: {}", code, message),
            CliError::General(msg) => write!(f, "error: {}", msg),
        }
    }
}

impl std::error::Error for CliError {}

/// IronDivi CLI - Command-line JSON-RPC client for IronDivi daemon
///
/// This is a drop-in replacement for divi-cli with full command compatibility.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Command-line JSON-RPC client for IronDivi",
    after_help = "\
EXAMPLES:
  irondivi-cli getblockcount
  irondivi-cli getblockchaininfo
  irondivi-cli --testnet getblockchaininfo
  irondivi-cli --mode privatedivi getblockchaininfo
  irondivi-cli --named sendtoaddress address=\"addr\" amount=1.0
  irondivi-cli --rpcwallet=mywallet getbalance
  irondivi-cli -getinfo
  irondivi-cli -netinfo 1
  irondivi-cli -generate 10

SPECIAL COMMANDS:
  -getinfo              Show aggregated blockchain, network, and wallet info
  -netinfo [level]      Show network peer summary (level 0-4)
  -generate <n>         Generate n blocks to a new wallet address

CONFIGURATION:
  Config file is read from ~/.divi/divi.conf (or --conf path)
  Cookie auth from ~/.divi/.cookie is used if no rpcuser/rpcpassword

EXIT CODES:
  0   Success
  1   General error (including RPC errors)
  2   Connection failed
  5   Invalid response from server
  87  Invalid parameters
"
)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long = "conf")]
    conf: Option<PathBuf>,

    /// RPC server address
    #[arg(long = "rpcconnect", default_value = "127.0.0.1")]
    rpcconnect: String,

    /// RPC port
    #[arg(long = "rpcport")]
    rpcport: Option<u16>,

    /// RPC username
    #[arg(long = "rpcuser")]
    rpcuser: Option<String>,

    /// RPC password
    #[arg(long = "rpcpassword")]
    rpcpassword: Option<String>,

    /// Use testnet defaults
    #[arg(long)]
    testnet: bool,

    /// Use regtest defaults
    #[arg(long)]
    regtest: bool,

    /// Chain mode: divi (default) or privatedivi
    #[arg(long, default_value = "divi", value_parser = ["divi", "privatedivi"])]
    mode: String,

    /// Wallet name for multi-wallet RPC
    #[arg(long)]
    rpcwallet: Option<String>,

    /// Data directory (for cookie authentication)
    #[arg(long)]
    datadir: Option<PathBuf>,

    /// Read extra arguments from stdin
    #[arg(long)]
    stdin: bool,

    /// Read RPC password from stdin
    #[arg(long)]
    stdinrpcpass: bool,

    /// Read wallet passphrase from stdin
    #[arg(long)]
    stdinwalletpassphrase: bool,

    /// Use named arguments (key=value format)
    #[arg(long, short = 'n')]
    named: bool,

    /// RPC method and arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

/// JSON-RPC request
#[derive(Debug, Serialize)]
struct RpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Value,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[allow(dead_code)]
    id: Option<Value>,
    result: Option<Value>,
    error: Option<RpcError>,
}

/// JSON-RPC error
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RpcError {
    code: i32,
    message: String,
    #[allow(dead_code)]
    data: Option<Value>,
}

/// RPC Client
struct RpcClient {
    url: String,
    username: Option<String>,
    password: Option<String>,
}

impl RpcClient {
    fn call(&self, method: &str, params: Value) -> Result<Value, CliError> {
        let request = RpcRequest {
            jsonrpc: "1.0".to_string(),
            id: 1,
            method: method.to_string(),
            params,
        };

        let client = reqwest::blocking::Client::new();
        let mut req = client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&request).map_err(|e| CliError::General(e.to_string()))?);

        // Add basic auth if credentials provided
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            req = req.basic_auth(user, Some(pass));
        }

        let response = req.send().map_err(|e| {
            if e.is_connect() {
                CliError::Connection(e.to_string())
            } else if e.is_timeout() {
                CliError::Connection("connection timed out".to_string())
            } else {
                CliError::General(e.to_string())
            }
        })?;

        let status = response.status();
        let body = response
            .text()
            .map_err(|e| CliError::InvalidResponse(e.to_string()))?;

        if !status.is_success() {
            // Try to parse RPC error
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(error) = json.get("error") {
                    if !error.is_null() {
                        let code = error["code"].as_i64().unwrap_or(-1);
                        let message = error["message"]
                            .as_str()
                            .unwrap_or("unknown error")
                            .to_string();
                        return Err(CliError::RpcError { code, message });
                    }
                }
            }
            return Err(CliError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let json: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| CliError::InvalidResponse(e.to_string()))?;

        // Check for RPC error in response
        if let Some(error) = json.get("error") {
            if !error.is_null() {
                let code = error["code"].as_i64().unwrap_or(-1);
                let message = error["message"]
                    .as_str()
                    .unwrap_or("unknown error")
                    .to_string();
                return Err(CliError::RpcError { code, message });
            }
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| CliError::InvalidResponse("missing 'result' field".to_string()))
    }
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

/// Configuration values parsed from config file
#[derive(Default)]
struct Config {
    rpcuser: Option<String>,
    rpcpassword: Option<String>,
    rpcport: Option<u16>,
    rpcconnect: Option<String>,
    testnet: bool,
    regtest: bool,
    mode: Option<String>,
}

/// Read configuration file with section header support
fn read_config(path: Option<PathBuf>, network: &str) -> Config {
    use std::fs;

    let path = path.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".divi").join("divi.conf"))
            .unwrap_or_default()
    });

    if !path.exists() {
        return Config::default();
    }

    let contents = match fs::read_to_string(&path) {
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
            match key.trim() {
                "rpcuser" => config.rpcuser = Some(value.trim().to_string()),
                "rpcpassword" => config.rpcpassword = Some(value.trim().to_string()),
                "rpcport" => config.rpcport = value.trim().parse().ok(),
                "rpcconnect" => config.rpcconnect = Some(value.trim().to_string()),
                "testnet" if value.trim() == "1" => config.testnet = true,
                "regtest" if value.trim() == "1" => config.regtest = true,
                "mode" => config.mode = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    config
}

/// Read cookie file for authentication
fn read_cookie(datadir: Option<PathBuf>, network: &str) -> Option<(String, String)> {
    use std::fs;

    let base = datadir.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".divi"))
            .unwrap_or_default()
    });

    let path = match network {
        "testnet" => base.join("testnet3").join(".cookie"),
        "regtest" => base.join("regtest").join(".cookie"),
        _ => base.join(".cookie"),
    };

    if !path.exists() {
        return None;
    }

    let contents = fs::read_to_string(&path).ok()?;
    let (user, pass) = contents.trim().split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Handle stdin input (CRITICAL: Read password FIRST when both flags used)
fn handle_stdin(args: &mut Args) -> Result<(), CliError> {
    // CRITICAL: Read password FIRST when both flags used
    if args.stdinrpcpass {
        let mut pass = String::new();
        io::stdin()
            .lock()
            .read_line(&mut pass)
            .map_err(|e| CliError::General(e.to_string()))?;
        args.rpcpassword = Some(pass.trim().to_string());
    }

    // Then read remaining lines for command args
    if args.stdin {
        let mut extra_input = String::new();
        io::stdin()
            .lock()
            .read_to_string(&mut extra_input)
            .map_err(|e| CliError::General(e.to_string()))?;
        for line in extra_input.lines() {
            if !line.is_empty() {
                args.args.push(line.to_string());
            }
        }
    }

    Ok(())
}

/// Handle -getinfo special command (aggregates multiple RPC calls)
fn handle_getinfo(client: &RpcClient) -> Result<(), CliError> {
    let blockchain = client.call("getblockchaininfo", Value::Array(vec![]))?;
    let network = client.call("getnetworkinfo", Value::Array(vec![]))?;
    let wallet = client.call("getwalletinfo", Value::Array(vec![])).ok();

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
    println!(
        "Connections: {} (in: {}, out: {})",
        network["connections"],
        network["connections_in"].as_u64().unwrap_or(0),
        network["connections_out"].as_u64().unwrap_or(0)
    );

    if let Some(w) = wallet {
        println!();
        println!("Wallet: {}", w["walletname"].as_str().unwrap_or("default"));
        println!("Balance: {}", w["balance"]);
    }

    Ok(())
}

/// Handle -netinfo special command (shows peer connection summary)
fn handle_netinfo(client: &RpcClient, detail: u8) -> Result<(), CliError> {
    let peers = client.call("getpeerinfo", Value::Array(vec![]))?;
    let network = client.call("getnetworkinfo", Value::Array(vec![]))?;

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
    let address_result = client.call("getnewaddress", Value::Array(vec![]))?;
    let address = address_result
        .as_str()
        .ok_or_else(|| CliError::General("Failed to get new address".to_string()))?;

    // Step 2: Generate blocks to that address
    let result = client.call(
        "generatetoaddress",
        Value::Array(vec![json!(nblocks), json!(address)]),
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|e| CliError::General(e.to_string()))?
    );
    Ok(())
}

/// Format JSON output with pretty printing

/// Parse a single argument (JSON or string)
fn parse_argument_value(arg: &str) -> Value {
    // Try to parse as JSON first
    if let Ok(v) = serde_json::from_str(arg) {
        return v;
    }
    // If not JSON, try as number
    if let Ok(num) = arg.parse::<i64>() {
        return json!(num);
    }
    if let Ok(num) = arg.parse::<f64>() {
        return json!(num);
    }
    // Booleans
    if arg == "true" {
        return json!(true);
    }
    if arg == "false" {
        return json!(false);
    }
    // Otherwise string
    json!(arg)
}

/// Parse named arguments in key=value format
fn parse_named_args(args: &[String]) -> Result<Value, CliError> {
    let mut obj = serde_json::Map::new();
    for arg in args {
        let (key, value) = arg.split_once('=').ok_or_else(|| {
            CliError::InvalidParams(format!(
                "Invalid named argument: {} (expected key=value)",
                arg
            ))
        })?;
        obj.insert(key.to_string(), parse_argument_value(value));
    }
    Ok(Value::Object(obj))
}

fn format_output(value: &Value) -> String {
    if value.is_string() {
        // Print strings without quotes
        value.as_str().unwrap_or("").to_string()
    } else {
        // Pretty print JSON
        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
    }
}

fn run() -> Result<(), CliError> {
    let mut args = Args::parse();

    // Handle stdin input
    handle_stdin(&mut args)?;

    // Need at least one argument (the method name)
    if args.args.is_empty() {
        return Err(CliError::InvalidParams(
            "No method specified. Use --help for usage.".to_string(),
        ));
    }

    // Determine network type
    let network = if args.regtest {
        "regtest"
    } else if args.testnet {
        "testnet"
    } else {
        "mainnet"
    };

    // Read config file (priority: CLI args > config file > defaults)
    let config = read_config(args.conf.clone(), network);

    // Apply config file values if CLI args not provided
    let testnet = args.testnet || config.testnet;
    let regtest = args.regtest || config.regtest;

    // Re-determine network after config
    let network = if regtest {
        "regtest"
    } else if testnet {
        "testnet"
    } else {
        "mainnet"
    };

    // Determine RPC connection parameters (CLI > config > defaults)
    let rpc_connect = args.rpcconnect.clone();
    let rpc_connect = if rpc_connect == "127.0.0.1" {
        // If default, check config
        config.rpcconnect.unwrap_or_else(|| rpc_connect)
    } else {
        rpc_connect
    };

    let rpc_port = args
        .rpcport
        .or(config.rpcport)
        .unwrap_or_else(|| default_rpc_port(testnet, regtest, args.mode == "privatedivi"));

    // Determine credentials (CLI > config > cookie file)
    let (rpc_user, rpc_password) = match (&args.rpcuser, &args.rpcpassword) {
        (Some(u), Some(p)) => (Some(u.clone()), Some(p.clone())),
        _ => {
            // Try config file
            match (&config.rpcuser, &config.rpcpassword) {
                (Some(u), Some(p)) => (Some(u.clone()), Some(p.clone())),
                _ => {
                    // Fall back to cookie file
                    match read_cookie(args.datadir.clone(), network) {
                        Some((u, p)) => (Some(u), Some(p)),
                        None => (args.rpcuser.clone(), args.rpcpassword.clone()),
                    }
                }
            }
        }
    };

    // Build URL with optional wallet
    let url = if let Some(ref wallet) = args.rpcwallet {
        format!("http://{}:{}/wallet/{}", rpc_connect, rpc_port, wallet)
    } else {
        format!("http://{}:{}", rpc_connect, rpc_port)
    };

    // Create RPC client
    let client = RpcClient {
        url,
        username: rpc_user,
        password: rpc_password,
    };

    // Get method and remaining args
    let method = &args.args[0];
    let method_args = &args.args[1..];

    // Handle special commands
    match method.as_str() {
        "-getinfo" => {
            handle_getinfo(&client)?;
            return Ok(());
        }
        "-netinfo" => {
            let detail = method_args
                .first()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0u8);
            handle_netinfo(&client, detail)?;
            return Ok(());
        }
        "-generate" => {
            let nblocks = method_args
                .first()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1u64);
            handle_generate(&client, nblocks)?;
            return Ok(());
        }
        _ => {}
    }

    // Convert string args to JSON values
    let params: Value = if args.named {
        // Parse as named arguments (key=value)
        parse_named_args(method_args)?
    } else {
        // Parse as positional arguments (array)
        Value::Array(
            method_args
                .iter()
                .map(|arg| {
                    // Try to parse as JSON first (for objects/arrays)
                    serde_json::from_str(arg).unwrap_or_else(|_| {
                        // If not valid JSON, try as number
                        if let Ok(num) = arg.parse::<i64>() {
                            json!(num)
                        } else if let Ok(num) = arg.parse::<f64>() {
                            json!(num)
                        } else if arg == "true" {
                            json!(true)
                        } else if arg == "false" {
                            json!(false)
                        } else {
                            // Otherwise treat as string
                            json!(arg)
                        }
                    })
                })
                .collect(),
        )
    };

    // Execute RPC call
    let result = client.call(method, params)?;

    // Print result
    println!("{}", format_output(&result));

    Ok(())
}

fn main() {
    let exit_code = match run() {
        Ok(()) => exit_codes::SUCCESS,
        Err(e) => {
            eprintln!("{}", e);
            e.exit_code()
        }
    };
    std::process::exit(exit_code);
}
