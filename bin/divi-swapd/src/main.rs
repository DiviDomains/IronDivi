// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! divi-swapd — atomic swap maker daemon.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use divi_swap::mock::MockChain;
use divi_swap::secrets::SecretRef;
use divi_swap::{Amount, Chain, ChainBackend, Maker, Store};
use divi_swapd::{
    router, run_scan, spawn_gated_scheduler, AppState, BackendKind, BtcSection, DaemonConfig,
    ScanStatus,
};
use divi_wallet::address::Network as DiviNetwork;
use swap_chain_btc::{BtcBackend, FeePolicy, RetryPolicy};
use swap_chain_divi::{DiviBackend, FeePolicy as DiviFeePolicy};

#[derive(Parser)]
#[command(name = "divi-swapd", version, about = "Atomic swap maker daemon")]
struct Args {
    /// Path to the TOML config file.
    #[arg(long)]
    config: PathBuf,
    /// Override the backend: `mock` runs both chains in-process (local/CI), `live` uses the
    /// public testnets.
    #[arg(long, value_parser = parse_backend)]
    backend: Option<BackendKind>,
}

fn parse_backend(s: &str) -> Result<BackendKind, String> {
    match s {
        "mock" => Ok(BackendKind::Mock),
        "live" => Ok(BackendKind::Live),
        other => Err(format!("backend must be mock or live, got {other:?}")),
    }
}

type Backends = (Arc<dyn ChainBackend>, Arc<dyn ChainBackend>);

/// DIVI wallet scan to run after the listener is bound.
struct ScanJob {
    divi: Arc<DiviBackend>,
    from: u64,
}

/// Blocks per scan step; the cursor is persisted after each.
const SCAN_CHUNK: u64 = 500;
const SCAN_RETRY: Duration = Duration::from_secs(30);

fn mock_backends() -> Backends {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1_700_000_000);
    let divi = MockChain::new(Chain::Divi, now, 60);
    let btc = MockChain::new(Chain::Btc, now, 600);
    let (d, b) = (
        divi.backend(1, Amount(1_000_000 * Amount::COIN)),
        btc.backend(2, Amount(0)),
    );
    // Nobody else mines the simulated chains, so the daemon does: one block per tick.
    for chain in [divi, btc] {
        tokio::spawn(async move {
            let mut i = tokio::time::interval(Duration::from_secs(5));
            loop {
                i.tick().await;
                chain.mine(1);
            }
        });
    }
    (Arc::new(d), Arc::new(b))
}

/// Resolve a `[…].key` reference into a secp256k1 key held only in memory.
fn resolve_key(reference: &str, what: &str) -> Result<bitcoin::secp256k1::SecretKey> {
    let r = SecretRef::parse(reference).map_err(|e| anyhow::anyhow!("{what} key: {e}"))?;
    let hex_key = r
        .resolve()
        .map_err(|e| anyhow::anyhow!("{what} key: {e}"))?;
    let mut raw = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut raw)
        .map_err(|_| anyhow::anyhow!("{what} key is not 32 bytes of hex"))?;
    let key = bitcoin::secp256k1::SecretKey::from_slice(&raw);
    raw.fill(0);
    key.map_err(|_| anyhow::anyhow!("{what} key is not a valid secp256k1 key"))
}

fn live_btc(cfg: &BtcSection) -> Result<Arc<dyn ChainBackend>> {
    // Validates the name; the endpoints themselves come from the config.
    swap_chain_btc::esplora_endpoints(&cfg.network).map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = resolve_key(&cfg.key, "btc")?;
    let mut endpoints = vec![cfg.esplora_url.clone()];
    endpoints.extend(cfg.fallback_esplora_url.clone());
    let backend = BtcBackend::new(endpoints, key, FeePolicy::default(), RetryPolicy::default())?;
    tracing::info!(address = %backend.address(), network = %cfg.network, "btc backend ready");
    Ok(Arc::new(backend))
}

async fn live_backends(cfg: &DaemonConfig) -> Result<(Backends, Option<ScanJob>)> {
    let (Some(divi_cfg), Some(btc_cfg)) = (&cfg.divi, &cfg.btc) else {
        bail!("live backend needs both [divi] and [btc] sections");
    };
    let btc = live_btc(btc_cfg)?;
    let hex_key = SecretRef::parse(&divi_cfg.key)
        .and_then(|r| r.resolve())
        .map_err(|e| anyhow::anyhow!("divi key: {e}"))?;
    let key = divi_crypto::keys::SecretKey::from_hex(hex_key.trim())
        .map_err(|_| anyhow::anyhow!("divi key is not a valid 32-byte hex key"))?;
    drop(hex_key);
    let divi = DiviBackend::new(
        &divi_cfg.rpc_url,
        key,
        DiviNetwork::Testnet,
        DiviFeePolicy::default(),
        divi_cfg.wallet_path.clone(),
    )?;
    tracing::info!(address = %divi.address(), "divi backend ready");
    let divi = Arc::new(divi);
    let job = divi_cfg.scan_from_height.map(|from| ScanJob {
        divi: divi.clone(),
        from,
    });
    Ok(((divi, btc), job))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = DaemonConfig::load(&args.config)?;
    let kind = args
        .backend
        .unwrap_or(if cfg.divi.is_some() && cfg.btc.is_some() {
            BackendKind::Live
        } else {
            BackendKind::Mock
        });
    let ((divi, btc), scan_job) = match kind {
        BackendKind::Mock => (mock_backends(), None),
        BackendKind::Live => live_backends(&cfg).await?,
    };
    let scan = if scan_job.is_some() {
        ScanStatus::scanning()
    } else {
        ScanStatus::done()
    };

    let store = Store::open(&cfg.db_path).context("opening swap database")?;
    let maker = Arc::new(Maker::new(
        cfg.swap_config()?,
        divi.clone(),
        btc.clone(),
        store,
        cfg.offers.clone(),
    )?);
    let _scheduler = spawn_gated_scheduler(
        maker.clone(),
        Duration::from_secs(cfg.tick_secs),
        scan.clone(),
    );

    let app = router(
        AppState {
            maker,
            divi,
            btc,
            scan: scan.clone(),
        },
        &cfg.prefix(),
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    tracing::info!(listen = %cfg.listen, backend = ?kind, "divi-swapd up");
    if let Some(job) = scan_job {
        tokio::spawn(async move {
            run_scan(&*job.divi, job.from, &scan, SCAN_CHUNK, SCAN_RETRY).await;
        });
    }
    axum::serve(listener, app).await?;
    Ok(())
}
