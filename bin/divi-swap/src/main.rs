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

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use divi_swap::mock::MockChain;
use divi_swap::{Amount, Chain, ChainBackend, Store, Taker};
use divi_swap_cli::{flow, ClaimGate, ClaimPolicy, MakerClient, RunOpts, Sessions};
use swap_chain_btc::BtcBackend;
use swap_chain_divi::DiviBackend;
use swap_chain_ltc::LtcBackend;
use swap_chain_zec::ZecBackend;

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
    /// Chain swapped against DIVI: `btc`, `ltc`, `usdc`, `zec` or `xmr` (the offer's
    /// `counter_chain`; `xmr` is the adaptor-signature swap, live with the `--xmr-*` flags).
    #[arg(long, global = true, default_value = "btc", value_parser = parse_counter_chain)]
    counter_chain: Chain,
    /// Secret reference (`op://…` or `credential:<name>`) for the taker's DIVI key.
    #[arg(long, global = true)]
    divi_key: Option<String>,
    /// Secret reference for the taker's BTC key (when `--counter-chain btc`).
    #[arg(long, global = true)]
    btc_key: Option<String>,
    /// Secret reference for the taker's LTC key (when `--counter-chain ltc`).
    #[arg(long, global = true)]
    ltc_key: Option<String>,
    /// Secret reference for the taker's ZEC key (when `--counter-chain zec`).
    #[arg(long, global = true)]
    zec_key: Option<String>,
    /// Taker's DIVI coin database (live backend only; created mode 0600, must be outside any
    /// git tree). Required for the reverse direction, where the taker pays DIVI.
    #[arg(long, global = true)]
    divi_wallet: Option<PathBuf>,
    /// DIVI height to start scanning for the taker's coins when the wallet has no cursor yet.
    #[arg(long, global = true)]
    divi_scan_from: Option<u64>,
    /// BTC test network: `signet` or `testnet` (testnet3).
    #[arg(
        long,
        global = true,
        env = "SWAP_BTC_NETWORK",
        default_value = "signet"
    )]
    btc_network: String,
    /// Secret reference for the taker's USDC (EVM) key. Needed when `--counter-chain usdc`.
    #[arg(long, global = true)]
    usdc_key: Option<String>,
    /// Which EVM testnet: `sepolia` (default) or `base-sepolia`. Only picks defaults for
    /// `--usdc-rpc-url`/`--usdc-token` below when they are left unset.
    #[arg(long, global = true, default_value = "sepolia")]
    usdc_network: String,
    /// EVM JSON-RPC URL. Defaults to a free public endpoint for `--usdc-network`.
    #[arg(long, global = true, env = "SWAP_EVM_RPC_URL")]
    usdc_rpc_url: Option<String>,
    /// Deployed `Erc20Htlc` contract address.
    #[arg(long, global = true)]
    usdc_htlc: Option<String>,
    /// ERC-20 (USDC) token address. Defaults to Circle's test USDC for `--usdc-network`.
    #[arg(long, global = true)]
    usdc_token: Option<String>,
    /// `monerod` RPC URL (when `--counter-chain xmr`, live).
    #[arg(long, global = true, env = "SWAP_XMR_MONEROD_URL")]
    xmr_monerod_url: Option<String>,
    /// `monero-wallet-rpc` URL with the taker's wallet open: the XMR is locked from it.
    #[arg(long, global = true, env = "SWAP_XMR_WALLET_RPC_URL")]
    xmr_wallet_rpc_url: Option<String>,
    /// `monero-wallet-rpc` user.
    #[arg(long, global = true, default_value = "")]
    xmr_wallet_rpc_user: String,
    /// Secret reference for the `monero-wallet-rpc` password.
    #[arg(long, global = true)]
    xmr_wallet_rpc_password: Option<String>,
    /// Monero network: `stagenet` (default), `testnet`, or `mainnet` (only with
    /// `--xmr-allow-mainnet`).
    #[arg(long, global = true, default_value = "stagenet")]
    xmr_network: String,
    /// Allow `--xmr-network mainnet`, which moves real money. Off by default
    /// (`xmr-mainnet-plan.md` phase D).
    #[arg(long, global = true)]
    xmr_allow_mainnet: bool,
    /// DIVI JSON-RPC proxy for the xmr taker's DIVI wallet. Defaults to the DIVI testnet
    /// proxy; required on mainnet.
    #[arg(long, global = true)]
    xmr_divi_rpc_url: Option<String>,
    /// The taker's own Monero address: where a refund sweeps her XMR back to.
    #[arg(long, global = true)]
    xmr_sweep_address: Option<String>,
    /// Blocks below the Monero tip where a scan for the swap's lock starts (each process
    /// scans once from there, then follows the tip).
    #[arg(long, global = true, default_value_t = 720)]
    xmr_lookback_blocks: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

fn parse_counter_chain(s: &str) -> Result<Chain, String> {
    match s.parse::<Chain>() {
        Ok(c) if c.is_counter() => Ok(c),
        Ok(_) => Err("the counter chain cannot be divi".into()),
        Err(e) => Err(e.to_string()),
    }
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
    /// Counter-chain amount (BTC, LTC, …), in satoshis.
    #[arg(long)]
    btc_sats: u64,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a fresh quote for an offer.
    Quote(DealArgs),
    /// Take a fresh quote and accept it; prints the local swap id.
    Accept(DealArgs),
    /// Fund the taker-leg HTLC (BTC, or DIVI in the reverse direction) and notify the maker.
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
    /// Claim the maker's lock once it is confirmed (one taker step).
    Claim {
        /// Local swap id.
        #[arg(long)]
        swap: String,
    },
    /// Refund the taker-leg lock once its timeout has passed. Unlike `claim`, this never
    /// claims the maker leg even if that would still be safe — for an operator who has
    /// decided to abandon the swap and explicitly wants to refund, not `claim`'s/`run`'s
    /// normal "claim if still safe, else refund" judgment call (see `Taker::refund`).
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
        /// Late claim (test scenario): hold the claim until the maker-leg chain's median time
        /// is this many seconds before the maker's refund locktime (must exceed 1800).
        #[arg(long, conflicts_with = "never_claim")]
        claim_not_before: Option<u32>,
        /// Never claim (test scenario): wait out the taker timelock and refund.
        #[arg(long)]
        never_claim: bool,
    },
    /// Print the taker's DIVI and BTC addresses and balances (live backend; no keys).
    Balance,
    /// Print `key=value` txids for a swap: the taker's own plus the maker's view.
    Txids {
        /// Local swap id.
        #[arg(long)]
        swap: String,
    },
}

/// Concrete counter-chain handle, live backend only (for `Balance`'s address + balance
/// lookup, which need the real type rather than `dyn ChainBackend`).
enum CounterLive {
    Btc(Arc<BtcBackend>),
    Ltc(Arc<LtcBackend>),
    Zec(Arc<ZecBackend>),
}

impl CounterLive {
    fn address(&self) -> String {
        match self {
            CounterLive::Btc(b) => b.address().to_string(),
            CounterLive::Ltc(b) => b.address().to_string(),
            CounterLive::Zec(z) => z.address().encode(),
        }
    }

    /// Confirmed plus pending balance, in the chain's smallest unit.
    async fn balance_sats(&self, btc_network: &str) -> Result<i64> {
        match self {
            CounterLive::Zec(z) => Ok(z.balance_zatoshi().await? as i64),
            CounterLive::Btc(_) | CounterLive::Ltc(_) => {
                let endpoints = match self {
                    CounterLive::Btc(_) => swap_chain_btc::esplora_endpoints(btc_network)?,
                    CounterLive::Ltc(_) => swap_chain_ltc::esplora_endpoints("testnet")?,
                    CounterLive::Zec(_) => unreachable!(),
                };
                chain_balance(&endpoints, &self.address()).await
            }
        }
    }
}

struct Backends {
    divi: Arc<dyn ChainBackend>,
    /// The `--counter-chain` backend.
    btc: Arc<dyn ChainBackend>,
    /// Concrete handles, live backend only.
    live: Option<(Arc<DiviBackend>, CounterLive)>,
}

fn backends(cli: &Cli) -> Result<Backends> {
    match cli.backend {
        BackendArg::Mock => {
            if cli.divi_wallet.is_some() {
                bail!("--divi-wallet needs --backend live");
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(1_700_000_000);
            let block_secs = match cli.counter_chain {
                Chain::Ltc => 150,
                Chain::Zec => 75,
                _ => 600,
            };
            let divi = MockChain::new(Chain::Divi, now, 60).backend(3, Amount(10 * Amount::COIN));
            let btc = MockChain::new(cli.counter_chain, now, block_secs)
                .backend(4, Amount(10 * Amount::COIN));
            Ok(Backends {
                divi: Arc::new(divi),
                btc: Arc::new(btc),
                live: None,
            })
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

/// Resolve `reference` and decode it as a 32-byte secp256k1 key (BTC, LTC and ZEC share a
/// key format: compressed pubkeys over the same curve, so one helper covers all three).
fn secp_key(
    reference: &Option<String>,
    flag: &str,
    what: &str,
) -> Result<bitcoin::secp256k1::SecretKey> {
    let hex_key = secret_hex(reference, flag, what)?;
    let mut raw = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut raw)
        .map_err(|_| anyhow::anyhow!("{what} key is not 32 bytes of hex"))?;
    let key = bitcoin::secp256k1::SecretKey::from_slice(&raw);
    raw.fill(0);
    key.map_err(|_| anyhow::anyhow!("{what} key is not a valid secp256k1 key"))
}

/// `--usdc-network`, resolved, plus `--usdc-rpc-url`/`--usdc-token` falling back to that
/// network's defaults. Split out from [`live_usdc_backend`] so it can be unit-tested
/// without a key or a network connection.
fn usdc_endpoints(cli: &Cli) -> Result<(swap_chain_evm::UsdcNetwork, String, String)> {
    let network: swap_chain_evm::UsdcNetwork = cli
        .usdc_network
        .parse()
        .map_err(|e: String| anyhow::anyhow!("--usdc-network: {e}"))?;
    let rpc_url = cli
        .usdc_rpc_url
        .clone()
        .unwrap_or_else(|| network.default_rpc_url().to_string());
    let token = cli
        .usdc_token
        .clone()
        .unwrap_or_else(|| network.usdc_token().to_string());
    Ok((network, rpc_url, token))
}

/// The `--counter-chain usdc` live backend. `Backends.live` stays `None` for it (that tuple
/// is concretely `(DiviBackend, CounterLive)`, used only by `Balance`).
fn live_usdc_backend(cli: &Cli) -> Result<Arc<dyn ChainBackend>> {
    let hex_key = secret_hex(&cli.usdc_key, "--usdc-key", "usdc")?;
    let key: swap_chain_evm::PrivateKeySigner = hex_key
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("usdc key is not a valid secp256k1 hex key"))?;
    drop(hex_key);
    let (_network, rpc_url, token) = usdc_endpoints(cli)?;
    let htlc = cli
        .usdc_htlc
        .as_deref()
        .context("live usdc backend needs --usdc-htlc")?
        .parse()
        .map_err(|e| anyhow::anyhow!("--usdc-htlc: {e}"))?;
    let token = token
        .parse()
        .map_err(|e| anyhow::anyhow!("--usdc-token: {e}"))?;
    Ok(Arc::new(swap_chain_evm::UsdcBackend::new(
        &rpc_url, key, htlc, token,
    )?))
}

fn live_backends(cli: &Cli) -> Result<Backends> {
    let dhex = secret_hex(&cli.divi_key, "--divi-key", "divi")?;
    let dkey = divi_crypto::keys::SecretKey::from_hex(dhex.trim())
        .map_err(|_| anyhow::anyhow!("divi key is not a valid 32-byte hex key"))?;
    drop(dhex);
    let wallet = cli
        .divi_wallet
        .as_deref()
        .map(divi_swap_cli::wallet::prepare_wallet_path)
        .transpose()?;
    let divi = Arc::new(DiviBackend::new(
        "https://services.divi.domains/api/testnet/rpc/",
        dkey,
        divi_wallet::address::Network::Testnet,
        swap_chain_divi::FeePolicy::default(),
        wallet,
    )?);

    if cli.counter_chain == Chain::Usdc {
        return Ok(Backends {
            divi,
            btc: live_usdc_backend(cli)?,
            live: None,
        });
    }
    let (btc, counter): (Arc<dyn ChainBackend>, CounterLive) = match cli.counter_chain {
        Chain::Btc => {
            let bkey = secp_key(&cli.btc_key, "--btc-key", "btc")?;
            let backend = Arc::new(BtcBackend::for_network(
                &cli.btc_network,
                bkey,
                swap_chain_btc::FeePolicy::default(),
            )?);
            (backend.clone(), CounterLive::Btc(backend))
        }
        Chain::Ltc => {
            let lkey = secp_key(&cli.ltc_key, "--ltc-key", "ltc")?;
            let backend = Arc::new(LtcBackend::for_network(
                "testnet",
                lkey,
                swap_chain_ltc::FeePolicy::default(),
            )?);
            (backend.clone(), CounterLive::Ltc(backend))
        }
        Chain::Zec => {
            let zkey = secp_key(&cli.zec_key, "--zec-key", "zec")?;
            let backend = Arc::new(ZecBackend::testnet(
                zkey,
                swap_chain_zec::FeePolicy::default(),
            )?);
            (backend.clone(), CounterLive::Zec(backend))
        }
        other => bail!("no live {other} backend in this build yet; use --backend mock"),
    };

    Ok(Backends {
        divi: divi.clone(),
        btc,
        live: Some((divi, counter)),
    })
}

/// Bring the DIVI wallet up to the chain tip when the taker will spend DIVI from it.
async fn sync_divi(cli: &Cli, b: &Backends) -> Result<()> {
    if let (Some((divi, _)), Some(_)) = (&b.live, &cli.divi_wallet) {
        divi_swap_cli::wallet::scan_to_tip(divi, cli.divi_scan_from).await?;
    }
    Ok(())
}

/// Confirmed plus pending sats at `address`, from the first Esplora `endpoints` entry that
/// answers (BTC and LTC serve the same Esplora JSON shape).
async fn chain_balance(endpoints: &[String], address: &str) -> Result<i64> {
    let mut last = None;
    for base in endpoints {
        let url = format!("{base}/address/{address}");
        let got = async {
            let v: serde_json::Value = reqwest::get(&url).await?.error_for_status()?.json().await?;
            anyhow::Ok(v)
        }
        .await;
        match got {
            Ok(v) => {
                let n = |s: &str, k: &str| v[s][k].as_i64().unwrap_or(0);
                return Ok(
                    n("chain_stats", "funded_txo_sum") - n("chain_stats", "spent_txo_sum")
                        + n("mempool_stats", "funded_txo_sum")
                        - n("mempool_stats", "spent_txo_sum"),
                );
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no esplora endpoint")))
}

async fn taker(cli: &Cli) -> Result<Taker> {
    let b = backends(cli)?;
    sync_divi(cli, &b).await?;
    Ok(Taker::new(b.divi, b.btc, Store::open(&cli.db)?))
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
    if cli.counter_chain == Chain::Xmr {
        return xmr_main(&cli, &sessions).await;
    }

    match &cli.cmd {
        Cmd::Quote(d) => {
            let quote = MakerClient::new(&d.maker.maker)
                .quote(&d.offer, d.btc_sats)
                .await?;
            println!("{}", serde_json::to_string_pretty(&quote)?);
        }
        Cmd::Accept(d) => {
            let local = flow::begin(
                &taker(&cli).await?,
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
            flow::lock(&taker(&cli).await?, &client, &sessions, swap).await?;
            println!("locked");
        }
        Cmd::Status { swap } => {
            let s = sessions.get(swap)?;
            let view = MakerClient::new(&s.maker_url)
                .swap(&s.maker_swap_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        Cmd::Claim { swap } => {
            let client = MakerClient::new(&sessions.get(swap)?.maker_url);
            let state = flow::step(&taker(&cli).await?, &client, &sessions, swap).await?;
            println!("{state:?}");
        }
        Cmd::Refund { swap } => {
            let state = flow::refund(&taker(&cli).await?, swap).await?;
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
            let b = backends(&cli)?;
            sync_divi(&cli, &b).await?;
            let gate = ClaimGate {
                policy,
                store: Store::open(&cli.db)?,
                divi: b.divi.clone(),
                btc: b.btc.clone(),
            };
            let taker = Taker::new(b.divi, b.btc, Store::open(&cli.db)?);
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
        Cmd::Balance => {
            let b = backends(&cli)?;
            let Some((divi, counter)) = &b.live else {
                bail!("balance needs --backend live");
            };
            sync_divi(&cli, &b).await?;
            let addr = counter.address();
            println!("divi_address={}", divi.address());
            println!("divi_balance_sats={}", divi.balance());
            println!("{}_address={addr}", cli.counter_chain);
            println!(
                "{}_balance_sats={}",
                cli.counter_chain,
                counter.balance_sats(&cli.btc_network).await?
            );
        }
        Cmd::Txids { swap } => {
            let s = sessions.get(swap)?;
            let rec = Store::open(&cli.db)?
                .get_taker_swap(swap)?
                .with_context(|| format!("no taker record {swap}"))?;
            let view = MakerClient::new(&s.maker_url)
                .swap(&s.maker_swap_id)
                .await?;
            for l in divi_swap_cli::txids::lines(&rec, &view) {
                println!("{l}");
            }
        }
    }
    Ok(())
}

/// The taker engine for `--counter-chain xmr`. Live: the DIVI wallet of `--divi-key` (it only
/// receives) and the Monero wallet behind `--xmr-wallet-rpc-url`; the lock journal sits next
/// to `--db`. Mock: a DIVI wallet that receives the DIVI, a Monero wallet holding 10 XMR.
fn xmr_taker(cli: &Cli) -> Result<divi_swap_xmr::XmrTaker> {
    use divi_swap_xmr::mock::{MockDiviChain, MockMoneroChain};
    if matches!(cli.backend, BackendArg::Live) {
        return live_xmr_taker(cli);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1_700_000_000);
    let divi = MockDiviChain::new(now, 60).wallet(8);
    let xmr = MockMoneroChain::new().wallet("taker", 10_000_000_000_000);
    Ok(divi_swap_xmr::XmrTaker::new(
        divi_swap_xmr::XmrConfig::testnet(),
        Arc::new(divi),
        Arc::new(xmr),
        Store::open(&cli.db)?,
    )?)
}

/// [`xmr_taker`]'s live engine.
fn live_xmr_taker(cli: &Cli) -> Result<divi_swap_xmr::XmrTaker> {
    use divi_swap_xmr::live::{self, LiveDivi, LiveDiviChain, LiveMonero, LiveMoneroConfig};
    let network = live::parse_network(&cli.xmr_network)?;
    let profile = live::profile_for(network, cli.xmr_allow_mainnet)
        .map_err(|e| anyhow::anyhow!("--xmr-network {}: {e}", cli.xmr_network))?;
    let divi_rpc_url = match (&cli.xmr_divi_rpc_url, network) {
        (Some(u), _) => u.clone(),
        (None, live::Network::Mainnet) => {
            bail!("--xmr-network mainnet needs --xmr-divi-rpc-url (the default is DIVI testnet)")
        }
        (None, _) => "https://services.divi.domains/api/testnet/rpc/".to_string(),
    };
    let need = |v: &Option<String>, flag: &str| {
        v.clone()
            .with_context(|| format!("live --counter-chain xmr needs {flag}"))
    };
    let sweep_to = live::parse_address(
        network,
        &need(&cli.xmr_sweep_address, "--xmr-sweep-address")?,
    )
    .map_err(|e| anyhow::anyhow!("--xmr-sweep-address: {e}"))?;
    let monerod_url = need(&cli.xmr_monerod_url, "--xmr-monerod-url")?;
    let wallet_rpc_url = need(&cli.xmr_wallet_rpc_url, "--xmr-wallet-rpc-url")?;
    let wallet_rpc_password = match &cli.xmr_wallet_rpc_password {
        Some(_) => secret_hex(
            &cli.xmr_wallet_rpc_password,
            "--xmr-wallet-rpc-password",
            "monero-wallet-rpc password",
        )?
        .trim()
        .to_string(),
        None => String::new(),
    };
    let dhex = secret_hex(&cli.divi_key, "--divi-key", "divi")?;
    let dkey = divi_crypto::keys::SecretKey::from_hex(dhex.trim())
        .map_err(|_| anyhow::anyhow!("divi key is not a valid 32-byte hex key"))?;
    drop(dhex);
    let wallet = cli
        .divi_wallet
        .as_deref()
        .map(divi_swap_cli::wallet::prepare_wallet_path)
        .transpose()?;
    let divi = LiveDiviChain::new(
        &divi_rpc_url,
        dkey,
        swap_chain_divi::FeePolicy::default(),
        wallet,
    )?;
    let xmr = LiveMonero::new(LiveMoneroConfig {
        monerod_url,
        wallet_rpc_url,
        wallet_rpc_user: cli.xmr_wallet_rpc_user.clone(),
        wallet_rpc_password,
        network,
        sweep_to,
        lookback_blocks: cli.xmr_lookback_blocks,
        journal_dir: PathBuf::from(format!("{}.xmr-journal", cli.db.display())),
    })?;
    Ok(divi_swap_xmr::XmrTaker::new(
        profile,
        Arc::new(LiveDivi::new(divi)),
        Arc::new(xmr),
        Store::open(&cli.db)?,
    )?)
}

/// `--counter-chain xmr`: the adaptor-swap taker (`divi_swap_cli::xmr_flow`).
async fn xmr_main(cli: &Cli, sessions: &Sessions) -> Result<()> {
    use divi_swap_cli::xmr_flow;
    match &cli.cmd {
        Cmd::Quote(d) => {
            let quote = MakerClient::new(&d.maker.maker)
                .quote(&d.offer, d.btc_sats)
                .await?;
            println!("{}", serde_json::to_string_pretty(&quote)?);
        }
        Cmd::Accept(d) => {
            let taker = xmr_taker(cli)?;
            let local = xmr_flow::begin(
                &taker,
                &MakerClient::new(&d.maker.maker),
                sessions,
                &d.offer,
                d.btc_sats,
            )
            .await?;
            println!("{local}");
        }
        Cmd::Status { swap } => {
            let s = sessions.get(swap)?;
            let view = MakerClient::new(&s.maker_url)
                .xmr_swap(&s.maker_swap_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        Cmd::Claim { swap } | Cmd::Refund { swap } => {
            let client = MakerClient::new(&sessions.get(swap)?.maker_url);
            let state = xmr_flow::step(&xmr_taker(cli)?, &client, sessions, swap).await?;
            println!("{state:?}");
        }
        Cmd::Run {
            deal,
            timeout_secs,
            poll_secs,
            claim_not_before,
            never_claim,
        } => {
            if claim_not_before.is_some() || *never_claim {
                bail!("--claim-not-before / --never-claim are hashlock-only");
            }
            let opts = RunOpts {
                timeout: Duration::from_secs(*timeout_secs),
                poll: Duration::from_secs(*poll_secs),
            };
            let (local, outcome) = xmr_flow::run(
                &xmr_taker(cli)?,
                &MakerClient::new(&deal.maker.maker),
                sessions,
                &deal.offer,
                deal.btc_sats,
                &opts,
                &mut || {},
            )
            .await?;
            println!("{local} {outcome}");
        }
        Cmd::Lock { .. } | Cmd::Balance | Cmd::Txids { .. } => {
            bail!("not available for xmr: `accept` sends the signatures, `claim` steps the swap (it locks XMR and redeems)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(extra: &[&str]) -> Cli {
        let mut argv = vec!["divi-swap"];
        argv.extend_from_slice(extra);
        argv.extend_from_slice(&[
            "quote",
            "--maker",
            "http://x",
            "--offer",
            "o",
            "--btc-sats",
            "1",
        ]);
        Cli::try_parse_from(argv).unwrap()
    }

    #[test]
    fn live_xmr_taker_names_what_it_is_missing_before_touching_anything() {
        let err = |extra: &[&str]| match live_xmr_taker(&cli(extra)) {
            Ok(_) => panic!("built a live xmr taker from {extra:?}"),
            Err(e) => e.to_string(),
        };
        let e = err(&["--counter-chain", "xmr"]);
        assert!(e.contains("--xmr-sweep-address"), "{e}");
        let e = err(&["--counter-chain", "xmr", "--xmr-network", "mainnet"]);
        assert!(e.contains("no mainnet"), "{e}");
        let e = err(&[
            "--counter-chain",
            "xmr",
            "--xmr-network",
            "mainnet",
            "--xmr-allow-mainnet",
        ]);
        assert!(e.contains("--xmr-divi-rpc-url"), "{e}");
        let e = err(&[
            "--counter-chain",
            "xmr",
            "--xmr-sweep-address",
            "5notanaddress",
        ]);
        assert!(e.contains("monero address"), "{e}");
    }

    #[test]
    fn usdc_network_defaults_to_sepolia() {
        let (network, rpc_url, token) = usdc_endpoints(&cli(&[])).unwrap();
        assert_eq!(network, swap_chain_evm::UsdcNetwork::Sepolia);
        assert_eq!(
            rpc_url,
            swap_chain_evm::UsdcNetwork::Sepolia.default_rpc_url()
        );
        assert_eq!(token, swap_chain_evm::SEPOLIA_USDC);
    }

    #[test]
    fn usdc_network_base_sepolia_picks_its_own_defaults() {
        let (network, rpc_url, token) =
            usdc_endpoints(&cli(&["--usdc-network", "base-sepolia"])).unwrap();
        assert_eq!(network, swap_chain_evm::UsdcNetwork::BaseSepolia);
        assert_eq!(
            rpc_url,
            swap_chain_evm::UsdcNetwork::BaseSepolia.default_rpc_url()
        );
        assert_eq!(token, swap_chain_evm::BASE_SEPOLIA_USDC);
    }

    #[test]
    fn usdc_explicit_rpc_url_and_token_override_the_network_default() {
        let (_, rpc_url, token) = usdc_endpoints(&cli(&[
            "--usdc-network",
            "base-sepolia",
            "--usdc-rpc-url",
            "http://localhost:9999",
            "--usdc-token",
            "0x1111111111111111111111111111111111111111",
        ]))
        .unwrap();
        assert_eq!(rpc_url, "http://localhost:9999");
        assert_eq!(token, "0x1111111111111111111111111111111111111111");
    }

    #[test]
    fn usdc_unknown_network_is_rejected() {
        let err = usdc_endpoints(&cli(&["--usdc-network", "mainnet"])).unwrap_err();
        assert!(err.to_string().contains("--usdc-network"), "{err}");
    }

    #[test]
    fn usdc_backend_constructs_on_either_networks_default_rpc_url_without_network_access() {
        // UsdcBackend::new only parses the RPC URL and derives a pubkey locally; it makes no
        // network calls, so this proves both networks' default_rpc_url() strings are valid
        // URLs the backend actually accepts.
        let htlc = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        for network in [
            swap_chain_evm::UsdcNetwork::Sepolia,
            swap_chain_evm::UsdcNetwork::BaseSepolia,
        ] {
            let backend = swap_chain_evm::UsdcBackend::new(
                network.default_rpc_url(),
                swap_chain_evm::PrivateKeySigner::random(),
                htlc,
                network.usdc_token().parse().unwrap(),
            )
            .unwrap();
            assert_eq!(backend.chain(), Chain::Usdc);
        }
    }
}
