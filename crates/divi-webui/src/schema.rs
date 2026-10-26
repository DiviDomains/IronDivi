// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Every option irondivid reads, as the settings page shows and edits it.
//! The one-shot commands (`--export-chain`, snapshots, `-help`) are not here:
//! they are not settings.

use serde_json::{json, Value};

/// What an option's value is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 1 or 0 (divid reads `true` as 0, so the file always gets 1 or 0)
    Bool,
    /// A whole number in the range
    Int(i64, i64),
    /// An amount of DIVI, as `0.0001`
    Amount,
    /// Free text on one line
    Text,
    /// One of these words
    Choice(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
pub struct Opt {
    pub key: &'static str,
    pub category: &'static str,
    pub kind: Kind,
    /// May be given more than once
    pub multi: bool,
    /// Never sent to the browser; it sees only whether one is set
    pub secret: bool,
    /// The page may change it (some are shown but kept to the command line
    /// or to the wallet's own creation)
    pub writable: bool,
    /// What irondivid does when the option is not given
    pub default: &'static str,
    pub help: &'static str,
}

const fn opt(
    key: &'static str,
    category: &'static str,
    kind: Kind,
    default: &'static str,
    help: &'static str,
) -> Opt {
    Opt {
        key,
        category,
        kind,
        multi: false,
        secret: false,
        writable: true,
        default,
        help,
    }
}

const fn multi(o: Opt) -> Opt {
    Opt { multi: true, ..o }
}

const fn secret(o: Opt) -> Opt {
    Opt { secret: true, ..o }
}

const fn fixed(o: Opt) -> Opt {
    Opt {
        writable: false,
        ..o
    }
}

const PORT: Kind = Kind::Int(1, 65535);
const COUNT: Kind = Kind::Int(0, u32::MAX as i64);
const BOOL: Kind = Kind::Bool;
const TEXT: Kind = Kind::Text;

/// The order the page shows the categories in
pub const CATEGORIES: &[&str] = &[
    "Chain",
    "Web interface",
    "Wallet",
    "Staking",
    "Network",
    "Connections",
    "RPC server",
    "Blocks and mempool",
    "Indexes and storage",
    "Notifications",
    "Logging",
];

pub const OPTIONS: &[Opt] = &[
    // Chain
    fixed(opt("conf", "Chain", TEXT, "irondivi.conf, else divi.conf, in the data directory",
        "The config file. Set on the command line only.")),
    fixed(opt("datadir", "Chain", TEXT, "the platform's IronDivi directory",
        "Where the chain, wallet and this file live. Set on the command line only.")),
    opt("mode", "Chain", Kind::Choice(&["divi", "privatedivi"]), "divi",
        "Which chain family to run: Divi or PrivateDivi."),
    opt("testnet", "Chain", BOOL, "0", "Run on the test network."),
    opt("regtest", "Chain", BOOL, "0", "Run a private regression-test chain."),
    opt("daemon", "Chain", BOOL, "0", "Run in the background."),
    opt("pid", "Chain", TEXT, "irondivid.pid", "The process-id file."),
    // Web interface
    opt("webui", "Web interface", BOOL, "0",
        "Serve this web interface. Turning it off takes effect at the next start."),
    opt("webuiport", "Web interface", PORT, "51480 mainnet, 51481 testnet, 51482 regtest (PrivateDivi 5248x)",
        "The port this interface listens on."),
    opt("webuibind", "Web interface", TEXT, "127.0.0.1",
        "The address this interface listens on. Anything but loopback also needs webuiallowremote."),
    opt("webuiallowremote", "Web interface", BOOL, "0",
        "Allow a bind address other than loopback. The interface is plain HTTP: put TLS (a reverse proxy or an SSH tunnel) in front of it."),
    multi(opt("webuiallowhost", "Web interface", TEXT, "localhost, 127.0.0.1, [::1]",
        "Extra Host names the browser may use to reach this interface (for a reverse proxy).")),
    // Wallet
    opt("wallet", "Wallet", TEXT, "wallet.dat", "The wallet file, in the data directory."),
    opt("disablewallet", "Wallet", BOOL, "0", "Run without a wallet."),
    opt("keypool", "Wallet", COUNT, "1000", "Keys made ahead of use."),
    opt("spendzeroconfchange", "Wallet", BOOL, "0", "Spend change that is not yet confirmed."),
    opt("rescan", "Wallet", BOOL, "0", "Rescan the chain for the wallet's transactions at start."),
    opt("salvagewallet", "Wallet", BOOL, "0", "Recover what can be read from a damaged wallet (rescans)."),
    opt("upgradewallet", "Wallet", TEXT, "", "Upgrade the wallet to this version (empty: the latest)."),
    opt("vault", "Wallet", BOOL, "0", "Allow vaults to be added and removed."),
    opt("walletnotify", "Wallet", TEXT, "", "Command run when a wallet transaction changes; %s is its txid."),
    fixed(secret(opt("hdseed", "Wallet", TEXT, "", "Seed for a new HD wallet. Not set here."))),
    fixed(secret(opt("mnemonic", "Wallet", TEXT, "", "Recovery words for a new HD wallet. Not set here."))),
    fixed(secret(opt("mnemonicpassphrase", "Wallet", TEXT, "", "Passphrase for the recovery words. Not set here."))),
    // Staking
    opt("staking", "Staking", BOOL, "1", "Stake the wallet's coins. Changes now and in the file."),
    opt("stakeonstaletip", "Staking", BOOL, "0", "Stake even when the chain tip is old."),
    opt("stakesplitthreshold", "Staking", Kind::Amount, "the wallet's own", "Split a stake reward above this much DIVI. Changes now and in the file."),
    opt("blockmaxsize", "Staking", COUNT, "", "Largest block this node makes, in bytes."),
    opt("blockprioritysize", "Staking", COUNT, "", "Bytes of a block kept for high-priority transactions."),
    opt("blockminsize", "Staking", COUNT, "", "Smallest block this node makes, in bytes."),
    secret(opt("sporkkey", "Staking", TEXT, "", "This network's spork key (checked, not used to sign).")),
    // Network
    opt("port", "Network", PORT, "51472 mainnet, 51474 testnet, 51476 regtest (PrivateDivi 5247x)", "The peer-to-peer port."),
    multi(opt("bind", "Network", TEXT, "every address", "Addresses to listen for peers on.")),
    opt("listen", "Network", BOOL, "1", "Accept connections from peers."),
    opt("discover", "Network", BOOL, "1", "Find this node's own addresses."),
    multi(opt("externalip", "Network", TEXT, "", "This node's public addresses, to advertise.")),
    opt("dnsseed", "Network", BOOL, "1", "Find peers through DNS seeds."),
    opt("proxy", "Network", TEXT, "", "A SOCKS5 proxy, as host:port."),
    multi(opt("onlynet", "Network", Kind::Choice(&["ipv4", "ipv6", "onion", "tor"]), "every network",
        "Connect only over these networks.")),
    opt("protocolversion", "Network", Kind::Int(0, i32::MAX as i64), "", "The protocol version to announce."),
    // Connections
    multi(opt("connect", "Connections", TEXT, "", "Connect to these peers only.")),
    multi(opt("addnode", "Connections", TEXT, "", "Peers to connect to as well as those found.")),
    multi(opt("fullnode", "Connections", TEXT, "", "Peers to fetch the whole chain from.")),
    opt("maxconnections", "Connections", COUNT, "125", "Most peers at once."),
    opt("timeout", "Connections", COUNT, "5000", "Connect timeout, in milliseconds."),
    opt("banscore", "Connections", COUNT, "100", "Misbehaviour score that bans a peer."),
    opt("bantime", "Connections", Kind::Int(0, i64::MAX), "86400", "How long a ban lasts, in seconds."),
    multi(opt("whitelist", "Connections", TEXT, "", "Peers (address or netmask) never banned.")),
    multi(opt("whitebind", "Connections", TEXT, "", "Addresses whose peers are never banned.")),
    // RPC server
    opt("server", "RPC server", BOOL, "1", "Serve JSON-RPC. This interface needs it on."),
    opt("rest", "RPC server", BOOL, "0", "Serve the REST interface."),
    multi(opt("rpcbind", "RPC server", TEXT, "127.0.0.1", "Addresses RPC listens on.")),
    opt("rpcport", "RPC server", PORT, "51473 mainnet, 51475 testnet and regtest", "The RPC port."),
    multi(opt("rpcallowip", "RPC server", TEXT, "loopback", "Addresses or netmasks allowed to call RPC.")),
    opt("rpcuser", "RPC server", TEXT, "", "The RPC user name."),
    secret(opt("rpcpassword", "RPC server", TEXT, "a cookie file", "The RPC password.")),
    multi(secret(opt("rpcauth", "RPC server", TEXT, "", "RPC users as user:salt$hash."))),
    multi(opt("rpcwhitelist", "RPC server", TEXT, "", "Methods a user may call, as user:method,method.")),
    opt("rpcwhitelistdefault", "RPC server", BOOL, "1", "Users without a whitelist may call nothing when any whitelist is set."),
    multi(opt("rpcalloworigin", "RPC server", TEXT, "", "Browser origins allowed to call RPC.")),
    multi(opt("rpcallowhost", "RPC server", TEXT, "", "Host names RPC answers to.")),
    opt("rpckeepalive", "RPC server", BOOL, "1", "Keep RPC connections open between calls."),
    // Blocks and mempool
    opt("checkblocks", "Blocks and mempool", COUNT, "", "Blocks checked at start."),
    opt("maxreorg", "Blocks and mempool", COUNT, "", "Deepest reorganisation accepted."),
    opt("maxorphantx", "Blocks and mempool", Kind::Int(0, i64::MAX), "", "Orphan transactions kept."),
    opt("minrelaytxfee", "Blocks and mempool", Kind::Amount, "", "Lowest fee per kB relayed, in DIVI."),
    opt("maxtxfee", "Blocks and mempool", Kind::Amount, "", "Highest fee the wallet pays, in DIVI."),
    multi(opt("loadblock", "Blocks and mempool", TEXT, "", "Block files to import at start.")),
    opt("stopafterblockimport", "Blocks and mempool", BOOL, "0", "Stop once the import is done."),
    opt("reindex", "Blocks and mempool", BOOL, "0", "Rebuild the chain state from the block files at start."),
    // Indexes and storage
    opt("txindex", "Indexes and storage", BOOL, "0", "Index every transaction."),
    opt("addressindex", "Indexes and storage", BOOL, "0", "Index transactions by address."),
    opt("spentindex", "Indexes and storage", BOOL, "0", "Index which transaction spent each output."),
    opt("utxocachesize", "Indexes and storage", Kind::Int(0, i64::MAX), "", "Unspent outputs kept in memory."),
    opt("expire", "Indexes and storage", TEXT, "", "Drop old block data past this age (as 30d)."),
    // Notifications
    opt("blocknotify", "Notifications", TEXT, "", "Command run when the best block changes; %s is its hash."),
    opt("zmqpubhashblock", "Notifications", TEXT, "", "ZMQ address for block hashes (tcp://host:port)."),
    opt("zmqpubhashtx", "Notifications", TEXT, "", "ZMQ address for transaction hashes."),
    opt("zmqpubrawblock", "Notifications", TEXT, "", "ZMQ address for raw blocks."),
    opt("zmqpubrawtx", "Notifications", TEXT, "", "ZMQ address for raw transactions."),
    // Logging
    opt("printtoconsole", "Logging", BOOL, "0", "Log to the console too."),
    multi(opt("debug", "Logging", TEXT, "", "Debug logging (a category, 1 for all, 0 for none).")),
    opt("maxlogsize", "Logging", Kind::Int(1, u32::MAX as i64), "", "Largest log file, in MB."),
    opt("maxlogfiles", "Logging", Kind::Int(1, 100), "", "Log files kept."),
];

/// The options the running daemon takes without a restart, and the RPC
/// method that changes each
pub const LIVE: &[(&str, &str)] = &[
    ("staking", "setstaking"),
    ("stakesplitthreshold", "setstakesplitthreshold"),
];

pub fn find(key: &str) -> Option<&'static Opt> {
    OPTIONS.iter().find(|o| o.key == key)
}

/// Check a value against the option's kind; the text the file should hold
pub fn normalize(o: &Opt, value: &str) -> Result<String, String> {
    let v = value.trim();
    if value.contains(['\n', '\r', '\0']) {
        return Err(format!("{}: a value is one line", o.key));
    }
    match o.kind {
        Kind::Bool => match v {
            "1" | "true" | "on" | "yes" => Ok("1".into()),
            "0" | "false" | "off" | "no" => Ok("0".into()),
            _ => Err(format!("{}: expected on or off", o.key)),
        },
        Kind::Int(min, max) => match v.parse::<i64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(n.to_string()),
            _ => Err(format!(
                "{}: expected a whole number from {} to {}",
                o.key, min, max
            )),
        },
        Kind::Amount => {
            let ok = !v.is_empty()
                && v.chars().all(|c| c.is_ascii_digit() || c == '.')
                && v.matches('.').count() <= 1
                && v.split('.').nth(1).map_or(true, |f| f.len() <= 8)
                && v != ".";
            if ok {
                Ok(v.into())
            } else {
                Err(format!("{}: expected an amount of DIVI, as 0.0001", o.key))
            }
        }
        Kind::Choice(words) => {
            let lower = v.to_lowercase();
            if words.contains(&lower.as_str()) {
                Ok(lower)
            } else {
                Err(format!("{}: expected one of {}", o.key, words.join(", ")))
            }
        }
        Kind::Text => Ok(v.into()),
    }
}

/// The schema as the page reads it
pub fn to_json() -> Value {
    let options: Vec<Value> = OPTIONS
        .iter()
        .map(|o| {
            let (kind, extra) = match o.kind {
                Kind::Bool => ("bool", json!(null)),
                Kind::Int(min, max) => ("int", json!({"min": min, "max": max})),
                Kind::Amount => ("amount", json!(null)),
                Kind::Text => ("text", json!(null)),
                Kind::Choice(words) => ("choice", json!(words)),
            };
            json!({
                "key": o.key,
                "category": o.category,
                "kind": kind,
                "range": extra,
                "multi": o.multi,
                "secret": o.secret,
                "writable": o.writable,
                "default": o.default,
                "help": o.help,
                "live": LIVE.iter().any(|(k, _)| *k == o.key),
            })
        })
        .collect();
    json!({ "categories": CATEGORIES, "options": options })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_categorised() {
        let mut seen = std::collections::HashSet::new();
        for o in OPTIONS {
            assert!(seen.insert(o.key), "{} twice", o.key);
            assert!(CATEGORIES.contains(&o.category), "{}", o.key);
        }
    }

    #[test]
    fn values_are_checked_by_kind() {
        let staking = find("staking").unwrap();
        assert_eq!(normalize(staking, "true").unwrap(), "1");
        assert!(normalize(staking, "maybe").is_err());
        let port = find("port").unwrap();
        assert_eq!(normalize(port, " 51472 ").unwrap(), "51472");
        assert!(normalize(port, "0").is_err());
        assert!(normalize(port, "70000").is_err());
        let fee = find("minrelaytxfee").unwrap();
        assert!(normalize(fee, "0.0001").is_ok());
        assert!(normalize(fee, "1e-4").is_err());
        assert!(normalize(fee, "0.000000001").is_err());
        let mode = find("mode").unwrap();
        assert_eq!(normalize(mode, "PrivateDivi").unwrap(), "privatedivi");
        assert!(normalize(find("rpcuser").unwrap(), "a\nb").is_err());
    }
}
