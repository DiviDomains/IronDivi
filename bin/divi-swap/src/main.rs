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

//! divi-swap — atomic swap taker and operator CLI.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use divi_swap::mock::MockChain;
use divi_swap::{Amount, Chain, ChainBackend, Store, Taker};
use divi_swap_cli::{flow, ClaimGate, ClaimPolicy, MakerClient, RunOpts, Sessions};

#[derive(Parser)]
#[command(
    name = "divi-swap",
    version,
    about = "Atomic swap taker and operator CLI"
)]
struct Cli {
    /// Taker swap database.
    #[arg(long, global = true, default_value = "divi-swap.db")]
    db: PathBuf,
    /// `mock` simulates both chains in this process (no real swap possible); `live` uses
    /// the public testnets.
    #[arg(long, global = true, value_enum, default_value = "live")]
    backend: BackendArg,
    /// Secret reference (`op://…` or `credential:<name>`) for the taker's DIVI key.
    #[arg(long, global = true)]
    divi_key: Option<String>,
    /// Secret reference for the taker's BTC key.
    #[arg(long, global = true)]
    btc_key: Option<String>,
    /// BTC test network: `signet` or `testnet` (testnet3).
    #[arg(
        long,
        global = true,
        env = "SWAP_BTC_NETWORK",
        default_value = "signet"
    )]
    btc_network: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum BackendArg {
    Mock,
    Live,
}

#[derive(Args)]
struct MakerArgs {
    /// Maker base URL including any path prefix, e.g. https://host/swap
    #[arg(long)]
    maker: String,
}

#[derive(Args)]
struct DealArgs {
    #[command(flatten)]
    maker: MakerArgs,
    /// Offer id from `GET /offers`.
    #[arg(long)]
    offer: String,
    /// BTC amount, in satoshis.
    #[arg(long)]
    btc_sats: u64,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a fresh quote for an offer.
    Quote(DealArgs),
    /// Take a fresh quote and accept it; prints the local swap id.
    Accept(DealArgs),
    /// Fund the BTC HTLC for an accepted swap and notify the maker.
    Lock {
        /// Local swap id printed by `accept`.
        #[arg(long)]
        swap: String,
    },
    /// Show the maker's view of a swap.
    Status {
        /// Local swap id.
        #[arg(long)]
        swap: String,
    },
    /// Claim the DIVI once the maker's lock is confirmed (one taker step).
    Claim {
        /// Local swap id.
        #[arg(long)]
        swap: String,
    },
    /// Refund the BTC if the taker timeout has passed (one taker step).
    Refund {
        /// Local swap id.
        #[arg(long)]
        swap: String,
    },
    /// The whole taker flow: quote, accept, lock, then step until done.
    Run {
        #[command(flatten)]
        deal: DealArgs,
        /// Give up after this many seconds.
        #[arg(long, default_value_t = 8 * 3600)]
        timeout_secs: u64,
        /// Seconds between polls of the maker.
        #[arg(long, default_value_t = 10)]
        poll_secs: u64,
        /// Late claim (test scenario): hold the DIVI claim until the DIVI median time is
        /// this many seconds before the maker's refund locktime (must exceed 1800).
        #[arg(long, conflicts_with = "never_claim")]
        claim_not_before: Option<u32>,
        /// Never claim (test scenario): wait out the BTC timelock and refund.
        #[arg(long)]
        never_claim: bool,
    },
    /// Print `key=value` txids for a swap: the taker's own plus the maker's view.
    Txids {
        /// Local swap id.
        #[arg(long)]
        swap: String,
    },
}

fn backends(cli: &Cli) -> Result<(Arc<dyn ChainBackend>, Arc<dyn ChainBackend>)> {
    match cli.backend {
        BackendArg::Mock => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(1_700_000_000);
            let divi = MockChain::new(Chain::Divi, now, 60).backend(3, Amount(0));
            let btc = MockChain::new(Chain::Btc, now, 600).backend(4, Amount(10 * Amount::COIN));
            Ok((Arc::new(divi), Arc::new(btc)))
        }
        BackendArg::Live => live_backends(cli),
    }
}

fn secret_hex(
    reference: &Option<String>,
    flag: &str,
    what: &str,
) -> Result<zeroize::Zeroizing<String>> {
    let r = reference
        .as_deref()
        .with_context(|| format!("live backend needs {flag} <op://… or credential:…>"))?;
    divi_swap::secrets::SecretRef::parse(r)
        .and_then(|r| r.resolve())
        .map_err(|e| anyhow::anyhow!("{what} key: {e}"))
}

fn live_backends(cli: &Cli) -> Result<(Arc<dyn ChainBackend>, Arc<dyn ChainBackend>)> {
    let dhex = secret_hex(&cli.divi_key, "--divi-key", "divi")?;
    let dkey = divi_crypto::keys::SecretKey::from_hex(dhex.trim())
        .map_err(|_| anyhow::anyhow!("divi key is not a valid 32-byte hex key"))?;
    drop(dhex);
    let bhex = secret_hex(&cli.btc_key, "--btc-key", "btc")?;
    let mut raw = [0u8; 32];
    hex::decode_to_slice(bhex.trim(), &mut raw)
        .map_err(|_| anyhow::anyhow!("btc key is not 32 bytes of hex"))?;
    let bkey = bitcoin::secp256k1::SecretKey::from_slice(&raw);
    raw.fill(0);
    let bkey = bkey.map_err(|_| anyhow::anyhow!("btc key is not a valid secp256k1 key"))?;
    drop(bhex);
    let divi = swap_chain_divi::DiviBackend::new(
        "https://services.divi.domains/api/testnet/rpc/",
        dkey,
        divi_wallet::address::Network::Testnet,
        swap_chain_divi::FeePolicy::default(),
        None,
    )?;
    let btc = swap_chain_btc::BtcBackend::for_network(
        &cli.btc_network,
        bkey,
        swap_chain_btc::FeePolicy::default(),
    )?;
    Ok((Arc::new(divi), Arc::new(btc)))
}

fn taker(cli: &Cli) -> Result<Taker> {
    let (divi, btc) = backends(cli)?;
    Ok(Taker::new(divi, btc, Store::open(&cli.db)?))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let cli = Cli::parse();
    let sessions = Sessions::beside(&cli.db);

    match &cli.cmd {
        Cmd::Quote(d) => {
            let quote = MakerClient::new(&d.maker.maker)
                .quote(&d.offer, d.btc_sats)
                .await?;
            println!("{}", serde_json::to_string_pretty(&quote)?);
        }
        Cmd::Accept(d) => {
            let local = flow::begin(
                &taker(&cli)?,
                &MakerClient::new(&d.maker.maker),
                &sessions,
                &d.offer,
                d.btc_sats,
            )
            .await?;
            println!("{local}");
        }
        Cmd::Lock { swap } => {
            let client = MakerClient::new(&sessions.get(swap)?.maker_url);
            flow::lock(&taker(&cli)?, &client, &sessions, swap).await?;
            println!("locked");
        }
        Cmd::Status { swap } => {
            let s = sessions.get(swap)?;
            let view = MakerClient::new(&s.maker_url)
                .swap(&s.maker_swap_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        Cmd::Claim { swap } | Cmd::Refund { swap } => {
            let client = MakerClient::new(&sessions.get(swap)?.maker_url);
            let state = flow::step(&taker(&cli)?, &client, &sessions, swap).await?;
            println!("{state:?}");
        }
        Cmd::Run {
            deal,
            timeout_secs,
            poll_secs,
            claim_not_before,
            never_claim,
        } => {
            let opts = RunOpts {
                timeout: Duration::from_secs(*timeout_secs),
                poll: Duration::from_secs(*poll_secs),
            };
            let policy = match (claim_not_before, never_claim) {
                (Some(n), _) => ClaimPolicy::NotBefore {
                    secs_before_timeout: *n,
                },
                (None, true) => ClaimPolicy::Never,
                (None, false) => ClaimPolicy::Asap,
            };
            let (divi, btc) = backends(&cli)?;
            let gate = ClaimGate {
                policy,
                store: Store::open(&cli.db)?,
                divi: divi.clone(),
            };
            let taker = Taker::new(divi, btc, Store::open(&cli.db)?);
            let (local, state) = flow::run_swap_gated(
                &taker,
                &MakerClient::new(&deal.maker.maker),
                &sessions,
                &deal.offer,
                deal.btc_sats,
                &opts,
                &mut || {},
                Some(&gate),
            )
            .await?;
            println!("{local} {state:?}");
        }
        Cmd::Txids { swap } => {
            let s = sessions.get(swap)?;
            let rec = Store::open(&cli.db)?
                .get_taker_swap(swap)?
                .with_context(|| format!("no taker record {swap}"))?;
            let view = MakerClient::new(&s.maker_url)
                .swap(&s.maker_swap_id)
                .await?;
            println!("taker_state={:?}", rec.state);
            println!("maker_state={:?}", view.state);
            let line = |k: &str, v: Option<String>| {
                if let Some(v) = v {
                    println!("{k}={v}");
                }
            };
            line(
                "btc_lock",
                rec.btc_funding.as_ref().map(|f| f.tx.txid.to_string()),
            );
            line(
                "btc_claim_by_maker",
                view.taker_leg.spend_txid.map(|t| t.to_string()),
            );
            line(
                "btc_refund_by_taker",
                rec.btc_refund.as_ref().map(|t| t.txid.to_string()),
            );
            line(
                "divi_lock",
                view.maker_leg
                    .as_ref()
                    .and_then(|l| l.outpoint)
                    .map(|o| o.txid.to_string()),
            );
            line(
                "divi_claim_by_taker",
                rec.divi_claim.as_ref().map(|t| t.txid.to_string()),
            );
            line(
                "divi_spend_by_maker",
                view.maker_leg
                    .as_ref()
                    .and_then(|l| l.spend_txid)
                    .map(|t| t.to_string()),
            );
        }
    }
    Ok(())
}
