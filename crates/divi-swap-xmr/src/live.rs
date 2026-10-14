// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Live backends: [`DiviChain`] and [`MoneroChain`] over the xmr lane's live halves,
//! `swap_chain_xmr::divi_chain::LiveDiviChain` (a DIVI JSON-RPC wallet) and
//! `swap_chain_xmr::monero_chain` (`monerod` + `monero-wallet-rpc`). Two things the traits
//! leave out are kept here:
//!
//! - **Where to scan from.** Neither live scan can start at genesis. [`LiveDivi::find_spend`]
//!   starts at the block holding the spent outpoint's own transaction (nothing can spend it
//!   earlier) and remembers how far it got; [`LiveMonero::find_lock`] starts
//!   `lookback_blocks` below the tip the first time it sees a key, then likewise resumes.
//!   Both resume a few blocks back ([`RESCAN_MARGIN`]) to ride out a short reorg. The DIVI
//!   memory is per process (a restart rescans once from the outpoint's block); the Monero
//!   cursor is also persisted per lock address in the journal directory, so a restarted
//!   maker resumes where it stopped instead of rescanning `lookback_blocks` of a remote
//!   `monerod`. A missing or unreadable cursor file only widens the scan back to
//!   `lookback_blocks`; it never narrows it.
//! - **Not repeating a send.** `MoneroChain::lock` is not idempotent and the taker engine
//!   only checks `find_lock` (blocks, not the pool) before calling it again after a crash.
//!   [`LiveMonero::lock`] keeps a journal file per lock address: written before the
//!   transfer, completed with its txid after. A journal entry with a txid answers the
//!   retry; one without (the transfer's outcome is unknown) refuses to send again until an
//!   operator checks the wallet. Sweeps are journalled by lock txid the same way.
//!
//! `swap_chain_xmr::live_rpc`'s block fetch panics on a transport error, so every Monero
//! call runs on its own task and a panic comes back as [`SwapError::Transient`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::transaction::{OutPoint, Transaction, TxOut};
use divi_swap::{Result, SwapError};
pub use monero_wallet::address::{MoneroAddress, Network};
use serde::{Deserialize, Serialize};
pub use swap_chain_xmr::divi_chain::LiveDiviChain;
use swap_chain_xmr::monero_chain::{self, MoneroChainError, XmrLockOutput};

use crate::chain::{DiviChain, MoneroChain, XmrOutput};

/// Blocks a resumed scan re-reads below where the previous one stopped.
pub const RESCAN_MARGIN: u64 = 3;

/// Monero outputs are spendable only after this many confirmations (the protocol's
/// 10-block lock); a sweep before that is premature.
pub const MONERO_SPENDABLE_CONFS: u32 = 10;

/// First block to scan for a spend of an output whose transaction has `confs`
/// confirmations at `tip`; `None` if the chain does not know that transaction.
fn first_spend_height(tip: u64, confs: Option<u32>) -> Option<u64> {
    match confs? {
        0 => Some(tip),
        c => Some((tip + 1).saturating_sub(c as u64)),
    }
}

/// Where the next scan starts after one that read up to `tip` found nothing.
fn resume_height(tip: u64, start: u64) -> u64 {
    tip.saturating_sub(RESCAN_MARGIN).max(start)
}

/// [`DiviChain`] over `LiveDiviChain`. Give each engine its own key and coin file: two
/// wallets selecting the same coins would build conflicting transactions.
pub struct LiveDivi {
    chain: LiveDiviChain,
    next_scan: Mutex<HashMap<OutPoint, u64>>,
}

impl LiveDivi {
    pub fn new(chain: LiveDiviChain) -> Self {
        LiveDivi {
            chain,
            next_scan: Mutex::new(HashMap::new()),
        }
    }

    /// The wrapped chain (e.g. to `learn_utxo` a coin sent to [`DiviChain::payout_script`]).
    pub fn inner(&self) -> &LiveDiviChain {
        &self.chain
    }
}

#[allow(clippy::double_must_use)]
#[async_trait]
impl DiviChain for LiveDivi {
    fn payout_script(&self) -> Script {
        self.chain.payout_script()
    }

    async fn tip_height(&self) -> Result<u64> {
        self.chain.tip_height().await
    }

    async fn median_time_past(&self) -> Result<u32> {
        self.chain.median_time_past().await
    }

    async fn build_funding(&self, script_pubkey: &Script, amount: u64) -> Result<Transaction> {
        self.chain.build_funding(script_pubkey, amount).await
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<()> {
        self.chain.broadcast(tx).await
    }

    async fn confirmations(&self, txid: &Hash256) -> Result<Option<u32>> {
        self.chain.confirmations(txid).await
    }

    async fn output(&self, at: &OutPoint) -> Result<Option<(TxOut, u32)>> {
        self.chain.output(at).await
    }

    async fn find_spend(&self, at: &OutPoint) -> Result<Option<Transaction>> {
        let tip = self.chain.tip_height().await?;
        let remembered = self.next_scan.lock().unwrap().get(at).copied();
        let start = match remembered {
            Some(h) => h,
            None => match first_spend_height(tip, self.chain.confirmations(&at.txid).await?) {
                Some(h) => h,
                None => return Ok(None), // an unknown transaction has no spends
            },
        };
        let found = self.chain.find_spend(at, start).await?;
        if found.is_none() {
            self.next_scan
                .lock()
                .unwrap()
                .insert(*at, resume_height(tip, start));
        }
        Ok(found)
    }
}

/// Endpoints and settings of a [`LiveMonero`].
#[derive(Clone)]
pub struct LiveMoneroConfig {
    /// `monerod` RPC (read-only use: scanning, fees, relaying the sweep).
    pub monerod_url: String,
    /// `monero-wallet-rpc` with this party's wallet open (the taker's `lock` spends from it).
    pub wallet_rpc_url: String,
    pub wallet_rpc_user: String,
    /// Held in memory only; resolved from a secret reference by the caller.
    pub wallet_rpc_password: String,
    pub network: Network,
    /// Where sweeps pay (this party's own wallet address).
    pub sweep_to: MoneroAddress,
    /// How far below the tip the first scan for a lock address starts.
    pub lookback_blocks: u64,
    /// Lock and sweep journals (public data only: keys' public halves and txids).
    pub journal_dir: PathBuf,
}

/// [`MoneroChain`] over `swap_chain_xmr::monero_chain`.
pub struct LiveMonero {
    cfg: LiveMoneroConfig,
    next_scan: Mutex<HashMap<[u8; 32], u64>>,
}

/// One journal file: the intent is written first, the txid once known.
#[derive(Debug, Serialize, Deserialize)]
struct Journal {
    txid: Option<String>,
}

fn map_err(e: MoneroChainError) -> SwapError {
    match e {
        MoneroChainError::Rpc(m) => SwapError::Transient(m),
        MoneroChainError::DecoySelection(n) => {
            SwapError::Transient(format!("decoy selection failed after {n} attempts"))
        }
        MoneroChainError::InvalidKey(k) => SwapError::InvalidParams(format!("invalid {k}")),
        other => SwapError::Other(other.to_string()),
    }
}

/// Runs `f` on its own task: a panic in it (the block fetch's `expect`s on a dropped
/// connection) comes back as a transient error instead of unwinding through the engine.
async fn contained<T, F>(f: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(f)
        .await
        .map_err(|e| SwapError::Transient(format!("monero rpc task failed: {e}")))?
}

impl LiveMonero {
    /// Creates the journal directory (mode 0700) if it is missing.
    pub fn new(cfg: LiveMoneroConfig) -> Result<Self> {
        std::fs::create_dir_all(&cfg.journal_dir)
            .map_err(|e| SwapError::Storage(format!("{}: {e}", cfg.journal_dir.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg.journal_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| SwapError::Storage(format!("{}: {e}", cfg.journal_dir.display())))?;
        }
        Ok(LiveMonero {
            cfg,
            next_scan: Mutex::new(HashMap::new()),
        })
    }

    fn lock_journal(&self, spend_pub: &[u8; 32]) -> PathBuf {
        self.cfg
            .journal_dir
            .join(format!("lock-{}.json", hex::encode(spend_pub)))
    }

    fn scan_cursor(&self, spend_pub: &[u8; 32]) -> PathBuf {
        self.cfg
            .journal_dir
            .join(format!("scan-{}.json", hex::encode(spend_pub)))
    }

    /// Where the next lock scan for `spend_pub` starts: the in-memory cursor, else the
    /// persisted one, else `lookback_blocks` below `tip`.
    fn scan_start(&self, spend_pub: &[u8; 32], tip: u64) -> u64 {
        if let Some(h) = self.next_scan.lock().unwrap().get(spend_pub).copied() {
            return h;
        }
        let path = self.scan_cursor(spend_pub);
        let persisted = match read_cursor(&path) {
            Ok(c) => c.map(|c| c.next),
            Err(e) => {
                tracing::warn!(error = %e, "ignoring an unreadable XMR scan cursor");
                None
            }
        };
        match persisted {
            // A cursor above the tip (a different chain, or a reorg past it) is not trusted.
            Some(h) if h <= tip => h,
            _ => tip.saturating_sub(self.cfg.lookback_blocks),
        }
    }

    /// Records where the next lock scan for `spend_pub` starts, in memory and on disk. A
    /// failed write is logged, not fatal: it only costs a longer scan after a restart.
    fn set_scan_start(&self, spend_pub: &[u8; 32], next: u64) {
        let changed = self.next_scan.lock().unwrap().insert(*spend_pub, next) != Some(next);
        if changed {
            if let Err(e) = write_cursor(&self.scan_cursor(spend_pub), &ScanCursor { next }) {
                tracing::warn!(error = %e, "could not persist the XMR scan cursor");
            }
        }
    }

    fn sweep_journal(&self, lock_txid: &str) -> PathBuf {
        self.cfg.journal_dir.join(format!("sweep-{lock_txid}.json"))
    }

    async fn tip(&self) -> Result<u64> {
        let url = self.cfg.monerod_url.clone();
        let info = contained(async move {
            swap_chain_xmr::live_rpc::monerod_get_info(&url)
                .await
                .map_err(|e| SwapError::Transient(format!("monerod get_info: {e}")))
        })
        .await?;
        // `height` is the block count: the top block is one below it.
        info["result"]["height"]
            .as_u64()
            .and_then(|h| h.checked_sub(1))
            .ok_or_else(|| SwapError::Transient(format!("monerod get_info: no height: {info}")))
    }
}

/// A persisted lock-scan cursor: the next block a scan for one lock address starts at.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ScanCursor {
    next: u64,
}

fn read_cursor(path: &Path) -> Result<Option<ScanCursor>> {
    read_json(path)
}

fn write_cursor(path: &Path, c: &ScanCursor) -> Result<()> {
    write_json(path, c)
}

fn read_journal(path: &Path) -> Result<Option<Journal>> {
    read_json(path)
}

/// Writes `j` to `path` durably (temp file, fsync, rename).
fn write_journal(path: &Path, j: &Journal) -> Result<()> {
    write_json(path, j)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| SwapError::Storage(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SwapError::Storage(format!("{}: {e}", path.display()))),
    }
}

/// Writes `v` to `path` durably (temp file, fsync, rename).
fn write_json<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    use std::io::Write;
    let err = |e: std::io::Error| SwapError::Storage(format!("{}: {e}", path.display()));
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(err)?;
    f.write_all(&serde_json::to_vec(v).expect("journal serializes"))
        .map_err(err)?;
    f.sync_all().map_err(err)?;
    std::fs::rename(&tmp, path).map_err(err)
}

#[allow(clippy::double_must_use)]
#[async_trait]
impl MoneroChain for LiveMonero {
    async fn lock(
        &self,
        spend_pub: &[u8; 32],
        view_secret: &[u8; 32],
        amount: u64,
    ) -> Result<String> {
        let path = self.lock_journal(spend_pub);
        match read_journal(&path)? {
            Some(Journal { txid: Some(t) }) => return Ok(t),
            Some(Journal { txid: None }) => {
                return Err(SwapError::Other(format!(
                    "an earlier XMR lock to this swap's address may have gone out without its \
                     txid being recorded: check the wallet's outgoing transfers, then write \
                     {{\"txid\":\"<txid>\"}} to {} (or delete it if nothing was sent)",
                    path.display()
                )))
            }
            None => {}
        }
        write_journal(&path, &Journal { txid: None })?;
        let c = self.cfg.clone();
        let (sp, vs) = (*spend_pub, *view_secret);
        let sent = contained(async move {
            monero_chain::lock(
                &c.wallet_rpc_url,
                &c.wallet_rpc_user,
                &c.wallet_rpc_password,
                sp,
                vs,
                amount,
                c.network,
            )
            .await
            .map_err(|e| (matches!(e, MoneroChainError::Rpc(_)), map_err(e)))
            .map_err(|(unknown, e)| {
                if unknown {
                    e
                } else {
                    // The wallet answered with an error (or the keys were bad): nothing sent.
                    SwapError::Rejected(e.to_string())
                }
            })
        })
        .await;
        match sent {
            Ok(txid) => {
                write_journal(
                    &path,
                    &Journal {
                        txid: Some(txid.clone()),
                    },
                )?;
                Ok(txid)
            }
            Err(e @ (SwapError::Rejected(_) | SwapError::InvalidParams(_))) => {
                let _ = std::fs::remove_file(&path);
                Err(e)
            }
            // Transport failure or a panic: the transfer may or may not have gone out, so
            // the journal stays and the next call refuses (see above).
            Err(e) => Err(e),
        }
    }

    async fn find_lock(
        &self,
        spend_pub: &[u8; 32],
        view_secret: &[u8; 32],
    ) -> Result<Option<XmrOutput>> {
        let tip = self.tip().await?;
        let start = self.scan_start(spend_pub, tip);
        let url = self.cfg.monerod_url.clone();
        let (sp, vs) = (*spend_pub, *view_secret);
        let found = contained(async move {
            monero_chain::find_lock(
                &url,
                sp,
                vs,
                start as usize,
                (tip + 1).saturating_sub(start) as usize,
            )
            .await
            .map_err(map_err)
        })
        .await?;
        match found {
            Some(o) => {
                // `find_lock` counts from monerod's block *count*, one more than a confirmation
                // count; take monerod's own figure for the txid (and one less as a fallback).
                let confirmations = self
                    .confirmations(&o.txid)
                    .await?
                    .unwrap_or(o.confirmations.saturating_sub(1));
                // Its block is (tip + 1 - confirmations); keep rescanning from there so the
                // confirmations stay current and a reorg that drops it is noticed.
                let height = (tip + 1).saturating_sub(confirmations.max(1) as u64);
                self.set_scan_start(spend_pub, height);
                Ok(Some(XmrOutput {
                    txid: o.txid,
                    amount: o.amount_piconero,
                    confirmations,
                }))
            }
            None => {
                self.set_scan_start(spend_pub, resume_height(tip, start));
                Ok(None)
            }
        }
    }

    async fn sweep(
        &self,
        lock: &XmrOutput,
        spend_secret: &[u8; 32],
        view_secret: &[u8; 32],
    ) -> Result<String> {
        let path = self.sweep_journal(&lock.txid);
        if let Some(Journal { txid: Some(t) }) = read_journal(&path)? {
            return Ok(t);
        }
        if lock.confirmations < MONERO_SPENDABLE_CONFS {
            return Err(SwapError::Premature(format!(
                "XMR lock {} has {} of {MONERO_SPENDABLE_CONFS} confirmations",
                lock.txid, lock.confirmations
            )));
        }
        let c = self.cfg.clone();
        let out = XmrLockOutput {
            txid: lock.txid.clone(),
            amount_piconero: lock.amount,
            confirmations: lock.confirmations,
        };
        let (ss, vs) = (*spend_secret, *view_secret);
        let txid = contained(async move {
            monero_chain::sweep(&c.monerod_url, &out, ss, vs, c.sweep_to)
                .await
                .map_err(map_err)
        })
        .await?;
        write_journal(
            &path,
            &Journal {
                txid: Some(txid.clone()),
            },
        )?;
        Ok(txid)
    }

    async fn confirmations(&self, txid: &str) -> Result<Option<u32>> {
        let url = self.cfg.monerod_url.clone();
        let txid = txid.to_string();
        contained(async move { Ok(monero_chain::confirmations(&url, &txid).await) }).await
    }
}

/// Parses a Monero address for `network` (e.g. a config's sweep address).
pub fn parse_address(network: Network, s: &str) -> Result<MoneroAddress> {
    MoneroAddress::from_str(network, s.trim())
        .map_err(|e| SwapError::InvalidParams(format!("monero address: {e}")))
}

/// `"stagenet"`, `"testnet"` or `"mainnet"`.
pub fn parse_network(s: &str) -> Result<Network> {
    match s {
        "stagenet" => Ok(Network::Stagenet),
        "testnet" => Ok(Network::Testnet),
        "mainnet" => Ok(Network::Mainnet),
        other => Err(SwapError::InvalidParams(format!(
            "monero network must be stagenet, testnet or mainnet, got {other:?}"
        ))),
    }
}

/// The engine profile for a Monero network: [`crate::XmrConfig::testnet`] on stagenet and
/// testnet, [`crate::XmrConfig::mainnet`] on mainnet. Mainnet moves real money, so it needs
/// an explicit `allow_mainnet` that every binary keeps off by default (`xmr-mainnet-plan.md`
/// phase D: only after the outside review, with Bert present).
pub fn profile_for(network: Network, allow_mainnet: bool) -> Result<crate::XmrConfig> {
    match network {
        Network::Mainnet if !allow_mainnet => Err(SwapError::InvalidParams(
            "monero mainnet moves real money: no mainnet without the explicit allow-mainnet \
             opt-in (xmr-mainnet-plan.md phase D)"
                .into(),
        )),
        Network::Mainnet => Ok(crate::XmrConfig::mainnet()),
        _ => Ok(crate::XmrConfig::testnet()),
    }
}

/// The DIVI address network matching a Monero network.
pub fn divi_network(network: Network) -> divi_wallet::address::Network {
    match network {
        Network::Mainnet => divi_wallet::address::Network::Mainnet,
        _ => divi_wallet::address::Network::Testnet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_needs_the_opt_in() {
        let e = profile_for(Network::Mainnet, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no mainnet"), "{e}");
        assert_eq!(
            profile_for(Network::Mainnet, true).unwrap(),
            crate::XmrConfig::mainnet()
        );
        for n in [Network::Stagenet, Network::Testnet] {
            for allow in [false, true] {
                assert_eq!(profile_for(n, allow).unwrap(), crate::XmrConfig::testnet());
            }
        }
        assert_eq!(
            divi_network(Network::Mainnet),
            divi_wallet::address::Network::Mainnet
        );
        assert_eq!(
            divi_network(Network::Stagenet),
            divi_wallet::address::Network::Testnet
        );
    }

    /// A stagenet address of throwaway public keys.
    fn stagenet_addr() -> String {
        let spend = curve25519_dalek_ng::constants::ED25519_BASEPOINT_POINT
            .compress()
            .to_bytes();
        monero_chain::lock_address(spend, [1; 32], Network::Stagenet)
            .unwrap()
            .to_string()
    }

    /// Endpoints that refuse connections: any RPC a test makes fails fast and visibly.
    fn chain(dir: &Path) -> LiveMonero {
        LiveMonero::new(LiveMoneroConfig {
            monerod_url: "http://127.0.0.1:9".into(),
            wallet_rpc_url: "http://127.0.0.1:9".into(),
            wallet_rpc_user: "u".into(),
            wallet_rpc_password: "p".into(),
            network: Network::Stagenet,
            sweep_to: parse_address(Network::Stagenet, &stagenet_addr()).unwrap(),
            lookback_blocks: 720,
            journal_dir: dir.join("journal"),
        })
        .unwrap()
    }

    #[test]
    fn scan_heights() {
        assert_eq!(first_spend_height(100, None), None);
        assert_eq!(first_spend_height(100, Some(0)), Some(100));
        assert_eq!(first_spend_height(100, Some(1)), Some(100));
        assert_eq!(first_spend_height(100, Some(10)), Some(91));
        assert_eq!(first_spend_height(5, Some(50)), Some(0));
        assert_eq!(resume_height(100, 10), 100 - RESCAN_MARGIN);
        assert_eq!(resume_height(100, 99), 99);
    }

    #[test]
    fn networks_and_addresses() {
        assert!(parse_network("stagenet").is_ok());
        assert!(parse_network("main").is_err());
        assert!(parse_address(Network::Stagenet, &stagenet_addr()).is_ok());
        assert!(parse_address(Network::Mainnet, &stagenet_addr()).is_err());
    }

    #[tokio::test]
    async fn recorded_lock_answers_a_retry_without_sending() {
        let dir = tempfile::tempdir().unwrap();
        let m = chain(dir.path());
        let key = [7u8; 32];
        write_journal(
            &m.lock_journal(&key),
            &Journal {
                txid: Some("ab".repeat(32)),
            },
        )
        .unwrap();
        assert_eq!(m.lock(&key, &[1; 32], 5).await.unwrap(), "ab".repeat(32));
    }

    #[tokio::test]
    async fn unrecorded_lock_refuses_to_send_again() {
        let dir = tempfile::tempdir().unwrap();
        let m = chain(dir.path());
        let key = [7u8; 32];
        write_journal(&m.lock_journal(&key), &Journal { txid: None }).unwrap();
        let e = m.lock(&key, &[1; 32], 5).await.unwrap_err();
        assert!(e.to_string().contains("may have gone out"), "{e}");
    }

    #[tokio::test]
    async fn lock_that_never_reached_the_wallet_keeps_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let m = chain(dir.path());
        // Not a valid point: rejected before any RPC, so the journal is cleared.
        let bad = [0xffu8; 32];
        assert!(m.lock(&bad, &[1; 32], 5).await.is_err());
        assert!(read_journal(&m.lock_journal(&bad)).unwrap().is_none());
        // A valid key against a dead wallet RPC: outcome unknown, so the journal stays.
        let ok = curve25519_dalek_ng::constants::ED25519_BASEPOINT_POINT
            .compress()
            .to_bytes();
        let e = m.lock(&ok, &[1; 32], 5).await.unwrap_err();
        assert!(matches!(e, SwapError::Transient(_)), "{e}");
        assert!(matches!(
            read_journal(&m.lock_journal(&ok)).unwrap(),
            Some(Journal { txid: None })
        ));
    }

    #[tokio::test]
    async fn sweep_waits_for_spendable_and_replays_its_journal() {
        let dir = tempfile::tempdir().unwrap();
        let m = chain(dir.path());
        let mut lock = XmrOutput {
            txid: "cd".repeat(32),
            amount: 1,
            confirmations: MONERO_SPENDABLE_CONFS - 1,
        };
        let e = m.sweep(&lock, &[1; 32], &[2; 32]).await.unwrap_err();
        assert!(matches!(e, SwapError::Premature(_)), "{e}");
        write_journal(
            &m.sweep_journal(&lock.txid),
            &Journal {
                txid: Some("ef".repeat(32)),
            },
        )
        .unwrap();
        lock.confirmations = MONERO_SPENDABLE_CONFS;
        assert_eq!(
            m.sweep(&lock, &[1; 32], &[2; 32]).await.unwrap(),
            "ef".repeat(32)
        );
    }

    #[test]
    fn lock_scan_cursor_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let other = [8u8; 32];
        {
            let m = chain(dir.path());
            // Nothing remembered: the configured lookback below the tip.
            assert_eq!(m.scan_start(&key, 10_000), 10_000 - 720);
            assert_eq!(m.scan_start(&key, 100), 0);
            m.set_scan_start(&key, resume_height(10_000, 10_000 - 720));
            assert_eq!(m.scan_start(&key, 10_001), 10_000 - RESCAN_MARGIN);
        }
        // A new process over the same journal directory resumes there, not 720 back.
        let m = chain(dir.path());
        assert_eq!(m.scan_start(&key, 10_005), 10_000 - RESCAN_MARGIN);
        // Cursors are per lock address.
        assert_eq!(m.scan_start(&other, 10_005), 10_005 - 720);
        assert_eq!(
            read_cursor(&m.scan_cursor(&key)).unwrap(),
            Some(ScanCursor {
                next: 10_000 - RESCAN_MARGIN
            })
        );
    }

    #[test]
    fn a_bad_lock_scan_cursor_only_widens_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let m = chain(dir.path());
        std::fs::write(m.scan_cursor(&key), b"not json").unwrap();
        assert_eq!(chain(dir.path()).scan_start(&key, 5_000), 5_000 - 720);
        // A cursor above the tip (another chain, or a deep reorg) is not trusted either.
        write_cursor(&m.scan_cursor(&key), &ScanCursor { next: 9_000 }).unwrap();
        assert_eq!(chain(dir.path()).scan_start(&key, 5_000), 5_000 - 720);
    }

    #[test]
    fn found_lock_pins_the_cursor_at_its_block() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let m = chain(dir.path());
        // find_lock pins the cursor at the lock's block so its confirmations stay current;
        // after a restart the rescan starts there (a few blocks), not at the lookback.
        m.set_scan_start(&key, 4_990);
        assert_eq!(chain(dir.path()).scan_start(&key, 5_000), 4_990);
    }

    #[tokio::test]
    async fn dead_monerod_is_transient_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let m = chain(dir.path());
        let e = m.find_lock(&[7; 32], &[1; 32]).await.unwrap_err();
        assert!(matches!(e, SwapError::Transient(_)), "{e}");
        assert_eq!(m.confirmations("00").await.unwrap(), None);
    }
}
