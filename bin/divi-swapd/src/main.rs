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
use divi_swap::{Amount, Chain, ChainBackend, Maker, Store, SwapConfig};
use divi_swapd::{router, spawn_scheduler, AppState, BackendKind, DaemonConfig};

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

fn live_backends(_cfg: &DaemonConfig) -> Result<Backends> {
    bail!("live backend is not wired yet: waiting on the swap-chain-divi / swap-chain-btc lanes")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = DaemonConfig::load(&args.config)?;
    let kind = args.backend.unwrap_or(if cfg.secrets.is_some() {
        BackendKind::Live
    } else {
        BackendKind::Mock
    });
    let (divi, btc) = match kind {
        BackendKind::Mock => mock_backends(),
        BackendKind::Live => live_backends(&cfg)?,
    };

    let store = Store::open(&cfg.db_path).context("opening swap database")?;
    let maker = Arc::new(Maker::new(
        SwapConfig::profile(cfg.profile),
        divi.clone(),
        btc.clone(),
        store,
        cfg.offers.clone(),
    )?);
    let _scheduler = spawn_scheduler(maker.clone(), Duration::from_secs(cfg.tick_secs));

    let app = router(AppState { maker, divi, btc }, &cfg.prefix());
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    tracing::info!(listen = %cfg.listen, backend = ?kind, "divi-swapd up");
    axum::serve(listener, app).await?;
    Ok(())
}
