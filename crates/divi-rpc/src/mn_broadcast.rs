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

//! C++-compatible masternode broadcast handling behind `setupmasternode`, `signmnbroadcast`,
//! `broadcaststartmasternode`, `startmasternode`, `importmnbroadcast` and `listmnbroadcasts`.
//!
//! Broadcasts travel as hex of the C++ `CMasternodeBroadcast` serialization (see
//! `divi_masternode::cpp_wire`). Pre-signed broadcasts are kept in a file under the datadir.

use crate::error::{codes, Error, RpcError};
use divi_crypto::{hash160, SecretKey};
use divi_masternode::cpp_wire::{CppBroadcast, CppPing, CppTxIn};
use divi_primitives::Hash256;
use divi_storage::chain::NetworkType;
use divi_storage::Chain;
use divi_wallet::address::{encode_wif, Network};
use divi_wallet::WalletDb;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

/// Blocks of confirmation a collateral needs before the broadcast time is pinned to it
const MASTERNODE_MIN_CONFIRMATIONS: u32 = 15;
/// How far into the future the network tolerates a broadcast `sigTime`
const FUTURE_SIGTIME_SECS: i64 = 45 * 60;

/// Relay hook: hands raw broadcast bytes to the P2P layer (as an `mnb` message)
pub type BroadcastRelay = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// What a handler needs from the node
pub struct MnContext<'a> {
    pub chain: &'a Arc<Chain>,
    pub wallet: Option<Arc<WalletDb>>,
}

fn invalid_param(msg: impl Into<String>) -> Error {
    RpcError::new(codes::INVALID_PARAMETER, msg.into()).into()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `COutPoint::ToString`
fn outpoint_string(hash: &Hash256, n: u32) -> String {
    format!("COutPoint({}, {})", &hash.to_hex()[..10], n)
}

fn wallet_network(chain: &Chain) -> Network {
    match chain.network_type() {
        NetworkType::Mainnet => Network::Mainnet,
        NetworkType::Testnet => Network::Testnet,
        NetworkType::Regtest => Network::Regtest,
    }
}

/// Secret key for a public key the wallet owns
/// The wallet's secret for `pubkey`, only while fully unlocked: a staking-only
/// unlock keeps keys in memory for staking, not for signing collateral messages
fn wallet_secret(wallet: &WalletDb, pubkey: &[u8]) -> Option<SecretKey> {
    if !wallet.is_fully_unlocked() {
        return None;
    }
    let id = hash160(pubkey);
    wallet.keystore().get_key(&id).and_then(|e| e.secret)
}

/// C++ `MasternodeTier` int for a collateral amount (regtest collaterals are 1000x cheaper)
fn tier_for_collateral(chain: &Chain, amount: i64) -> Option<i32> {
    let scale = if chain.network_type() == NetworkType::Regtest {
        1000
    } else {
        1
    };
    divi_masternode::MASTERNODE_TIERS
        .iter()
        .find(|t| t.collateral_amount() / scale == amount)
        .map(|t| t.to_u8() as i32)
}

/// Collateral facts for an outpoint on the active chain
struct Collateral {
    amount: i64,
    /// Height of the block holding the collateral transaction
    height: u32,
}

fn find_collateral(chain: &Chain, hash: &Hash256, n: u32) -> Option<Collateral> {
    let (tx, loc) = chain.get_transaction_with_location(hash).ok()??;
    let out = tx.vout.get(n as usize)?;
    let bi = chain.get_block_index(&loc.block_hash).ok()??;
    let active = chain.get_block_index_by_height(bi.height).ok()??;
    if active.hash != bi.hash {
        return None;
    }
    Some(Collateral {
        amount: out.value.0,
        height: bi.height,
    })
}

fn block_at(chain: &Chain, height: u32) -> Option<divi_storage::BlockIndex> {
    chain.get_block_index_by_height(height).ok().flatten()
}

fn blockchain_synced(chain: &Chain) -> bool {
    if chain.network_type() == NetworkType::Regtest {
        return true;
    }
    chain
        .tip()
        .map(|t| now() - (t.time as i64) < 2 * 3600)
        .unwrap_or(false)
}

/// Parse `ip:port` / `[v6]:port` (a missing port gets `default_port`)
pub fn parse_service(s: &str, default_port: u16) -> Option<(IpAddr, u16)> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some((sa.ip(), sa.port()));
    }
    s.parse::<IpAddr>().ok().map(|ip| (ip, default_port))
}

/// Collateral outpoint (txid, vout) -> serialized broadcast
type BroadcastMap = BTreeMap<([u8; 32], u32), Vec<u8>>;

/// Persistent set of pre-signed broadcasts keyed by collateral outpoint
#[derive(Default)]
pub struct BroadcastStore {
    entries: Mutex<BroadcastMap>,
    path: Mutex<Option<PathBuf>>,
}

impl BroadcastStore {
    /// Use `path` for persistence and load what it holds
    pub fn set_path(&self, path: PathBuf) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(list) = serde_json::from_str::<Vec<String>>(&text) {
                let mut map = self.entries.lock();
                for h in list {
                    if let Ok(bytes) = hex::decode(&h) {
                        if let Ok(b) = CppBroadcast::decode(&bytes) {
                            map.insert((b.vin.prevout_hash, b.vin.prevout_n), bytes);
                        }
                    }
                }
            }
        }
        *self.path.lock() = Some(path);
    }

    /// Store (replace) the broadcast for its collateral; false if it cannot be persisted
    pub fn add(&self, mnb: &CppBroadcast) -> bool {
        self.entries
            .lock()
            .insert((mnb.vin.prevout_hash, mnb.vin.prevout_n), mnb.encode());
        self.save()
    }

    pub fn get(&self, hash: &[u8; 32], n: u32) -> Option<CppBroadcast> {
        let map = self.entries.lock();
        map.get(&(*hash, n))
            .and_then(|b| CppBroadcast::decode(b).ok())
    }

    pub fn list(&self) -> Vec<CppBroadcast> {
        self.entries
            .lock()
            .values()
            .filter_map(|b| CppBroadcast::decode(b).ok())
            .collect()
    }

    fn save(&self) -> bool {
        let Some(path) = self.path.lock().clone() else {
            return true;
        };
        let list: Vec<String> = self.entries.lock().values().map(hex::encode).collect();
        match serde_json::to_string(&list) {
            Ok(text) => write_private(&path, text.as_bytes()).is_ok(),
            Err(_) => false,
        }
    }
}

/// Replace `path` with `contents`, mode 0600, through a synced temporary file
/// and a rename, so a crash never leaves half a cache (NODE-22).
fn write_private(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// One `masternode.conf` line: `alias ip:port masternodePrivKey txhash outidx`
pub struct ConfEntry {
    pub alias: String,
    pub ip: String,
    pub tx_hash: String,
    pub out_idx: String,
}

pub fn read_conf(path: &std::path::Path) -> Vec<ConfEntry> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 5).then(|| ConfEntry {
                alias: f[0].to_string(),
                ip: f[1].to_string(),
                tx_hash: f[3].to_string(),
                out_idx: f[4].to_string(),
            })
        })
        .collect()
}

fn decode_hex_broadcast(hex_str: &str) -> Result<CppBroadcast, Error> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| RpcError::new(codes::DESERIALIZATION_ERROR, "Broadcast must be hex"))?;
    CppBroadcast::decode(&bytes).map_err(|e| {
        RpcError::new(
            codes::DESERIALIZATION_ERROR,
            format!("Broadcast decode failed: {}", e),
        )
        .into()
    })
}

/// `signmnbroadcast`: sign the broadcast with the collateral key held by the wallet
pub fn sign_broadcast(ctx: &MnContext, hex_in: &str) -> Result<serde_json::Value, Error> {
    let fail = || invalid_param("Unable to sign broadcast!");
    let mut mnb = decode_hex_broadcast(hex_in)?;
    let wallet = ctx.wallet.as_ref().ok_or_else(fail)?;
    let key = wallet_secret(wallet, &mnb.pubkey_collateral).ok_or_else(fail)?;
    mnb.sign(&key).map_err(|_| fail())?;
    if !mnb.signature_is_valid() {
        return Err(fail());
    }
    Ok(serde_json::json!({ "broadcast_data": hex::encode(mnb.encode()) }))
}

/// `setupmasternode`: build the unsigned-by-collateral broadcast for a funded collateral
pub fn setup_masternode(
    ctx: &MnContext,
    alias: &str,
    txhash: &str,
    out_idx: &str,
    collateral_pubkey_hex: &str,
    ip_address: &str,
    default_port: u16,
) -> Result<serde_json::Value, Error> {
    let wallet = ctx
        .wallet
        .as_ref()
        .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Wallet disabled!"))?;
    if !wallet.is_fully_unlocked() {
        return Err(RpcError::new(
            codes::WALLET_UNLOCK_NEEDED,
            "Error: Please enter the wallet passphrase with walletpassphrase first.",
        )
        .into());
    }

    // Fresh wallet key to act as the masternode key (printed as WIF in the config line)
    let addr = wallet
        .new_receiving_address()
        .map_err(|e| RpcError::new(codes::WALLET_ERROR, e.to_string()))?;
    let entry = wallet
        .keystore()
        .get_key_by_address(&addr)
        .ok_or_else(|| RpcError::new(codes::WALLET_ERROR, "Private key for new address unknown"))?;
    let mn_secret = entry.secret.clone().ok_or_else(|| {
        RpcError::new(
            codes::WALLET_ERROR,
            format!("Private key for address {} is not known", addr),
        )
    })?;
    let mn_pubkey = entry.public.to_bytes();

    let collateral_pubkey = hex::decode(collateral_pubkey_hex)
        .ok()
        .filter(|k| k.len() == 33 || k.len() == 65)
        .ok_or_else(|| invalid_param("Invalid collateral public key"))?;

    let mut ip_and_port = ip_address.to_string();
    if !ip_and_port.contains(':') {
        ip_and_port = format!("{}:{}", ip_and_port, default_port);
    }
    let (ip, port) = parse_service(&ip_and_port, default_port)
        .ok_or_else(|| invalid_param(format!("Invalid masternode address {}", ip_and_port)))?;

    let hash = Hash256::from_hex(txhash)
        .map_err(|_| invalid_param(format!("Could not parse input reference {}", txhash)))?;
    let n: u32 = out_idx
        .parse()
        .map_err(|_| invalid_param(format!("Could not parse input reference {}", out_idx)))?;

    let chain = ctx.chain;
    let outpoint = outpoint_string(&hash, n);
    let coll = find_collateral(chain, &hash, n)
        .ok_or_else(|| invalid_param(format!("Could not find txin {} for masternode", outpoint)))?;
    if !blockchain_synced(chain) {
        return Err(invalid_param(
            "Sync in progress. Must wait until sync is complete to start Masternode",
        ));
    }
    let tier = tier_for_collateral(chain, coll.amount).ok_or_else(|| {
        invalid_param(format!(
            "Invalid tier selected for masternode {}, collateral value is: {}",
            ip_and_port, coll.amount
        ))
    })?;

    // Delayed ping: block `min(input age, 12)` below the tip, time at least 45 min after it
    let tip = chain
        .tip()
        .ok_or_else(|| invalid_param("Chain has no tip"))?;
    let age = (tip.height + 1).saturating_sub(coll.height).min(12);
    let ping_block = block_at(chain, tip.height - age.min(tip.height))
        .ok_or_else(|| invalid_param("Failed to sign ping, no ping block"))?;
    let vin = CppTxIn::new(hash.0, n);
    let mut ping = CppPing {
        vin: vin.clone(),
        block_hash: ping_block.hash.0,
        sig_time: (ping_block.time as i64 + 45 * 60).max(now()),
        signature: Vec::new(),
    };
    ping.sign(&mn_secret)
        .map_err(|_| invalid_param(format!("Failed to sign ping, masternode={}", hash.to_hex())))?;

    // sigTime must be after the collateral has MASTERNODE_MIN_CONFIRMATIONS confirmations
    let conf_height = coll.height + MASTERNODE_MIN_CONFIRMATIONS - 1;
    let sig_time = match block_at(chain, conf_height) {
        Some(b) if conf_height <= tip.height => b.time as i64,
        _ => now() + FUTURE_SIGTIME_SECS,
    };

    let mut mnb = CppBroadcast {
        vin,
        ip: [0; 16],
        port,
        pubkey_collateral: collateral_pubkey,
        pubkey_masternode: mn_pubkey,
        signature: Vec::new(),
        sig_time,
        protocol_version: divi_network::constants::PROTOCOL_VERSION,
        last_ping: ping,
        tier,
    };
    mnb.set_service(ip, port);

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(mn_secret.as_bytes());
    let wif = encode_wif(&key_bytes, true, wallet_network(chain));
    Ok(serde_json::json!({
        "protocol_version": mnb.protocol_version,
        "message_to_sign": hex::encode(mnb.message_to_sign()),
        "config_line": format!("{} {} {} {} {}", alias, ip_and_port, wif, txhash, out_idx),
        "broadcast_data": hex::encode(mnb.encode()),
    }))
}

/// Validate a signed broadcast the way a receiving node would before accepting it
fn check_broadcast(ctx: &MnContext, mnb: &CppBroadcast) -> Result<(), String> {
    if !mnb.signature_is_valid() {
        return Err("Bad broadcast signature".into());
    }
    let ping = &mnb.last_ping;
    if !ping_signature_valid(mnb, ping) {
        return Err("Bad ping signature".into());
    }
    if mnb.sig_time > now() + 3600 {
        return Err("Broadcast signature time too far in the future".into());
    }
    let hash = Hash256(mnb.vin.prevout_hash);
    let coll = find_collateral(ctx.chain, &hash, mnb.vin.prevout_n)
        .ok_or("Collateral not found in the active chain")?;
    if tier_for_collateral(ctx.chain, coll.amount) != Some(mnb.tier) {
        return Err("Collateral amount does not match the tier".into());
    }
    Ok(())
}

pub(crate) fn ping_signature_valid(mnb: &CppBroadcast, ping: &CppPing) -> bool {
    divi_masternode::cpp_wire::verify_message(
        &mnb.pubkey_masternode,
        &ping.signature,
        &ping.message_to_sign(),
    )
}

/// `broadcaststartmasternode`: validate and relay a signed broadcast
pub fn relay_broadcast(
    ctx: &MnContext,
    relay: Option<&BroadcastRelay>,
    hex_in: &str,
    signature_hex: Option<&str>,
) -> Result<serde_json::Value, Error> {
    let mut mnb = decode_hex_broadcast(hex_in)?;
    if let Some(sig) = signature_hex.filter(|s| !s.is_empty()) {
        mnb.signature = hex::decode(sig)
            .map_err(|_| RpcError::new(codes::DESERIALIZATION_ERROR, "Signature must be hex"))?;
    }
    // `update_ping` only matters for a node running as this masternode; this node never is.
    match check_broadcast(ctx, &mnb) {
        Ok(()) => {
            if let Some(relay) = relay {
                relay(mnb.encode());
            }
            Ok(serde_json::json!({ "status": "success" }))
        }
        Err(e) => {
            tracing::warn!("broadcaststartmasternode: {}", e);
            Ok(serde_json::json!({ "status": "failed", "error": "Error processing broadcast" }))
        }
    }
}

/// `startmasternode`: this node is never a running masternode, so like C++ on a controller it
/// reports "Could not create MN broadcast" for a configured alias.
pub fn start_masternode(
    conf: &[ConfEntry],
    alias: &str,
    stored: &BroadcastStore,
    local_is_masternode: bool,
) -> serde_json::Value {
    let Some(entry) = conf.iter().find(|e| e.alias == alias) else {
        return serde_json::json!({
            "status": "failed",
            "error": "Invalid alias, couldn't find MN. Check your masternode.conf file",
        });
    };
    if !local_is_masternode {
        return serde_json::json!({
            "status": "failed",
            "error": "Could not create MN broadcast. Check your masternode.conf file",
        });
    }
    let hash = Hash256::from_hex(&entry.tx_hash).ok();
    let n = entry.out_idx.parse::<u32>().ok();
    match (hash, n) {
        (Some(h), Some(n)) if stored.get(&h.0, n).is_some() => {
            serde_json::json!({ "status": "success" })
        }
        (Some(_), Some(_)) => serde_json::json!({
            "status": "failed",
            "error": "No broadcast message available",
        }),
        _ => serde_json::json!({
            "status": "failed",
            "error": "Failed to parse input reference",
        }),
    }
}

/// `importmnbroadcast`
pub fn import_broadcast(store: &BroadcastStore, hex_in: &str) -> Result<serde_json::Value, Error> {
    let mnb = decode_hex_broadcast(hex_in)?;
    Ok(serde_json::json!(store.add(&mnb)))
}

/// `listmnbroadcasts`
pub fn list_broadcasts(store: &BroadcastStore) -> serde_json::Value {
    serde_json::Value::Array(
        store
            .list()
            .iter()
            .map(|b| {
                serde_json::json!({
                    "txhash": Hash256(b.vin.prevout_hash).to_hex(),
                    "outidx": b.vin.prevout_n,
                    "broadcast": hex::encode(b.encode()),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bcast(n: u32) -> CppBroadcast {
        CppBroadcast {
            vin: CppTxIn::new([n as u8; 32], n),
            ip: [0; 16],
            port: 1,
            pubkey_collateral: vec![2; 33],
            pubkey_masternode: vec![3; 33],
            signature: vec![],
            sig_time: 5,
            protocol_version: 70920,
            last_ping: CppPing {
                vin: CppTxIn::new([n as u8; 32], n),
                block_hash: [0; 32],
                sig_time: 5,
                signature: vec![],
            },
            tier: 0,
        }
    }

    /// NODE-5: the collateral key is not handed out while locked or unlocked
    /// for staking only
    #[test]
    fn node05_collateral_key_needs_full_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = WalletDb::create_persistent(
            &dir.path().join("w"),
            Network::Testnet,
            divi_wallet::HdWallet::new(divi_primitives::ChainMode::Divi).unwrap(),
        )
        .unwrap();
        let addr = wallet.new_receiving_address().unwrap();
        let pubkey = wallet.get_key_by_address(&addr).unwrap().pubkey_bytes();
        assert!(wallet_secret(&wallet, &pubkey).is_some());
        wallet.encrypt_wallet("pw").unwrap();
        wallet.lock();
        assert!(wallet_secret(&wallet, &pubkey).is_none());
        wallet.unlock_for("pw", 60, true).unwrap();
        assert!(wallet_secret(&wallet, &pubkey).is_none());
        wallet.lock();
        wallet.unlock("pw", 60).unwrap();
        assert!(wallet_secret(&wallet, &pubkey).is_some());
    }

    #[test]
    fn store_roundtrip_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnbroadcasts.json");
        let store = BroadcastStore::default();
        store.set_path(path.clone());
        assert!(store.list().is_empty());
        assert!(store.add(&bcast(1)));
        assert!(store.add(&bcast(2)));
        assert!(store.add(&bcast(1))); // replace, not duplicate
        assert_eq!(store.list().len(), 2);

        let reloaded = BroadcastStore::default();
        reloaded.set_path(path);
        assert_eq!(reloaded.list().len(), 2);
        assert_eq!(reloaded.get(&[2; 32], 2).unwrap(), bcast(2));
        let listed = list_broadcasts(&reloaded);
        assert_eq!(listed.as_array().unwrap().len(), 2);
        assert_eq!(listed[0]["outidx"], 1);
    }

    #[test]
    fn node22_cache_is_replaced_atomically_and_privately() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnbroadcasts.json");
        // A cache left readable by an older version
        std::fs::write(&path, "[]").unwrap();
        let store = BroadcastStore::default();
        store.set_path(path.clone());
        assert!(store.add(&bcast(1)));
        // A stale temporary file from a crash does not block the next save
        std::fs::write(dir.path().join("mnbroadcasts.json.tmp"), "junk").unwrap();
        assert!(store.add(&bcast(2)));

        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("mnbroadcasts.json")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let reloaded = BroadcastStore::default();
        reloaded.set_path(path);
        assert_eq!(reloaded.list().len(), 2);
    }

    #[test]
    fn import_rejects_garbage_and_accepts_wire() {
        let store = BroadcastStore::default();
        assert!(import_broadcast(&store, "zz").is_err());
        assert!(import_broadcast(&store, "00").is_err());
        let hex_b = hex::encode(bcast(3).encode());
        assert_eq!(import_broadcast(&store, &hex_b).unwrap(), true);
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn start_masternode_results_match_cpp_messages() {
        let conf = vec![ConfEntry {
            alias: "mn1".into(),
            ip: "1.2.3.4:51474".into(),
            tx_hash: "00".repeat(32),
            out_idx: "0".into(),
        }];
        let store = BroadcastStore::default();
        let r = start_masternode(&conf, "nope", &store, false);
        assert_eq!(r["status"], "failed");
        assert!(r["error"].as_str().unwrap().starts_with("Invalid alias"));
        let r = start_masternode(&conf, "mn1", &store, false);
        assert!(r["error"]
            .as_str()
            .unwrap()
            .starts_with("Could not create MN broadcast"));
        let r = start_masternode(&conf, "mn1", &store, true);
        assert_eq!(r["error"], "No broadcast message available");
    }

    #[test]
    fn service_parsing() {
        assert_eq!(
            parse_service("1.2.3.4", 51474),
            Some(("1.2.3.4".parse().unwrap(), 51474))
        );
        assert_eq!(
            parse_service("1.2.3.4:9", 51474),
            Some(("1.2.3.4".parse().unwrap(), 9))
        );
        assert_eq!(
            parse_service("[::1]:7", 1),
            Some(("::1".parse().unwrap(), 7))
        );
        assert!(parse_service("not-an-ip", 1).is_none());
    }

    #[test]
    fn conf_parsing_skips_comments() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("masternode.conf");
        std::fs::write(&p, "# c\nmn1 1.2.3.4:5 KEY aa 1\n\nshort line\n").unwrap();
        let c = read_conf(&p);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].alias, "mn1");
        assert_eq!(c[0].out_idx, "1");
    }
}
