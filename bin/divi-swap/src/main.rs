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
    /// A second, independent DIVI JSON-RPC endpoint. When set, the taker's DIVI reads
    /// (confirmations, HTLC output, find-spend, median time, tip, wallet scan) are made on both
    /// endpoints and a disagreement is retried, never acted on. Must differ from the default
    /// endpoint; unset = single endpoint. Not used by the xmr arm.
    #[arg(long, global = true)]
    divi_fallback_rpc_url: Option<String>,
    /// DIVI network: `testnet` (default) or `mainnet` (only with `--allow-mainnet`). Picks the
    /// DIVI RPC endpoint and address version; with `--profile` it must agree (not used by the
    /// xmr arm, whose DIVI side follows `--xmr-network`).
    #[arg(long, global = true, default_value = "testnet")]
    divi_network: String,
    /// BTC network: `signet` (default), `testnet` (testnet3) or `mainnet` (only with
    /// `--allow-mainnet`).
    #[arg(
        long,
        global = true,
        env = "SWAP_BTC_NETWORK",
        default_value = "signet"
    )]
    btc_network: String,
    /// Litecoin network: `testnet` (default) or `mainnet` (only with `--allow-mainnet`).
    #[arg(
        long,
        global = true,
        env = "SWAP_LTC_NETWORK",
        default_value = "testnet"
    )]
    ltc_network: String,
    /// Opt-in LTC mainnet tip-hash cross-check against an independent source: `blockbook`,
    /// `blockcypher` or `off` (default). Mainnet only; run before any LTC action. A
    /// disagreement refuses; an unreachable source only warns.
    #[arg(
        long,
        global = true,
        env = "SWAP_LTC_CROSSCHECK",
        default_value = "off"
    )]
    ltc_crosscheck: String,
    /// Zcash network: `testnet` (default) or `mainnet` (only with `--allow-mainnet`).
    #[arg(long, global = true, default_value = "testnet")]
    zec_network: String,
    /// Allow `--divi-network`, `--zec-network`, `--btc-network`, `--ltc-network` or
    /// `--usdc-network` mainnet
    /// (`mainnet`, or `ethereum`/`base` for usdc), which moves real money. Off by default,
    /// mirroring `--xmr-allow-mainnet` (one shared flag for the zec/btc/ltc/usdc arms; xmr
    /// keeps its own).
    #[arg(long, global = true)]
    allow_mainnet: bool,
    /// Swap timing profile the networks must agree with: `testnet` (default) or `mainnet`.
    /// The taker takes its terms from the maker, so this only gates the network flags: a
    /// `mainnet` profile with a test network, or a `testnet` profile with a mainnet one, is
    /// refused before any network call.
    #[arg(long, global = true, default_value = "testnet", value_parser = parse_profile)]
    profile: divi_swap::Profile,
    /// Secret reference for the taker's USDC (EVM) key. Needed when `--counter-chain usdc`.
    #[arg(long, global = true)]
    usdc_key: Option<String>,
    /// Which EVM network: `sepolia` (default), `base-sepolia`, or the mainnets `ethereum` and
    /// `base` (only with `--allow-mainnet`). Only picks defaults for
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

fn parse_profile(s: &str) -> Result<divi_swap::Profile, String> {
    match s {
        "testnet" => Ok(divi_swap::Profile::Testnet),
        "mainnet" => Ok(divi_swap::Profile::Mainnet),
        other => Err(format!("profile must be testnet or mainnet, got {other:?}")),
    }
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
    /// Print each chain's tip as the swap code sees it, one `chain network height hash`
    /// line per chain (read-only; the same network flags and mainnet guards as `balance`).
    Tip {
        /// `divi`, `btc`, `ltc`, `zec`, `xmr` or `all`. `xmr` needs `--xmr-monerod-url`; `all`
        /// includes it only when that URL is given.
        #[arg(long, default_value = "all")]
        chain: String,
    },
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
            CounterLive::Zec(z) => z.encoded_address(),
        }
    }

    /// Confirmed plus pending balance, in the chain's smallest unit.
    async fn balance_sats(&self, btc_network: &str, ltc_network: &str) -> Result<i64> {
        match self {
            CounterLive::Zec(z) => Ok(z.balance_zatoshi().await? as i64),
            CounterLive::Btc(_) | CounterLive::Ltc(_) => {
                let endpoints = match self {
                    CounterLive::Btc(_) => swap_chain_btc::esplora_endpoints(btc_network)?,
                    CounterLive::Ltc(_) => swap_chain_ltc::esplora_endpoints(ltc_network)?,
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
    if network.is_mainnet() && !cli.allow_mainnet {
        bail!(
            "--usdc-network {network} moves real money: no mainnet without the explicit \
             --allow-mainnet opt-in"
        );
    }
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
fn live_usdc_backend(cli: &Cli) -> Result<Arc<swap_chain_evm::UsdcBackend>> {
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

/// Refuse `mainnet` for the btc/ltc arms without `--allow-mainnet`, and an unknown network
/// name outright — before any key is resolved or any network call is made. Same wording as
/// the zec guard.
fn guard_network(flag: &str, network: &str, test_networks: &[&str], allow: bool) -> Result<()> {
    if network != "mainnet" && !test_networks.contains(&network) {
        bail!(
            "{flag} must be {} or mainnet, got {network:?}",
            test_networks.join(", ")
        );
    }
    if network == "mainnet" && !allow {
        bail!(
            "{flag} mainnet moves real money: no mainnet without the explicit \
             --allow-mainnet opt-in"
        );
    }
    Ok(())
}

/// The engine profile must agree with the network of the counter chain in use.
/// USDC has no `CounterLive` handle (it is an EVM account, not a UTXO address), so `balance`
/// takes its own path instead of the `Backends::live` one.
fn is_usdc_live(cli: &Cli) -> bool {
    cli.counter_chain == Chain::Usdc && matches!(cli.backend, BackendArg::Live)
}

fn guard_profile(cli: &Cli) -> Result<()> {
    let coin = match cli.counter_chain {
        Chain::Btc => (
            Chain::Btc,
            cli.btc_network.as_str(),
            Some(cli.allow_mainnet),
        ),
        Chain::Ltc => (
            Chain::Ltc,
            cli.ltc_network.as_str(),
            Some(cli.allow_mainnet),
        ),
        Chain::Zec => (
            Chain::Zec,
            cli.zec_network.as_str(),
            Some(cli.allow_mainnet),
        ),
        Chain::Usdc => (Chain::Usdc, cli.usdc_network.as_str(), None),
        Chain::Xmr => (
            Chain::Xmr,
            cli.xmr_network.as_str(),
            Some(cli.xmr_allow_mainnet),
        ),
        Chain::Divi => (
            Chain::Divi,
            cli.divi_network.as_str(),
            Some(cli.allow_mainnet),
        ),
    };
    let mut coins = vec![coin];
    // DIVI last, so a counter coin's disagreement is reported first. The xmr arm's DIVI side
    // follows `--xmr-network` (`live::divi_network`), not `--divi-network`.
    if !matches!(cli.counter_chain, Chain::Xmr | Chain::Divi) {
        coins.push((
            Chain::Divi,
            cli.divi_network.as_str(),
            Some(cli.allow_mainnet),
        ));
    }
    divi_swap::config::check_profile_networks(cli.profile, &coins).map_err(anyhow::Error::msg)
}

/// Apply `--divi-fallback-rpc-url` to a DIVI backend. Unset or blank leaves it untouched; the
/// same URL as the default endpoint is refused (one node asked twice is not a second source).
fn with_divi_fallback(
    cli: &Cli,
    network: divi_wallet::address::Network,
    backend: DiviBackend,
) -> Result<DiviBackend> {
    let Some(url) = cli
        .divi_fallback_rpc_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    else {
        return Ok(backend);
    };
    if url.trim_end_matches('/') == swap_chain_divi::default_rpc(network).trim_end_matches('/') {
        bail!("--divi-fallback-rpc-url must differ from the default DIVI endpoint");
    }
    Ok(backend.with_fallback_rpc(url))
}

fn live_backends(cli: &Cli) -> Result<Backends> {
    match cli.counter_chain {
        Chain::Btc => guard_network(
            "--btc-network",
            &cli.btc_network,
            &["signet", "testnet"],
            cli.allow_mainnet,
        )?,
        Chain::Ltc => {
            guard_network(
                "--ltc-network",
                &cli.ltc_network,
                &["testnet"],
                cli.allow_mainnet,
            )?;
            if ltc_crosscheck_source(cli)?.is_some() && cli.ltc_network != "mainnet" {
                bail!("--ltc-crosscheck is mainnet-only: no testnet source is verified");
            }
        }
        _ => {}
    }
    if cli.counter_chain == Chain::Zec {
        match cli.zec_network.as_str() {
            "testnet" | "mainnet" => {}
            other => bail!("--zec-network must be testnet or mainnet, got {other:?}"),
        }
        if cli.zec_network == "mainnet" && !cli.allow_mainnet {
            bail!(
                "--zec-network mainnet moves real money: no mainnet without the explicit \
                 --allow-mainnet opt-in"
            );
        }
    }
    guard_network(
        "--divi-network",
        &cli.divi_network,
        &["testnet"],
        cli.allow_mainnet,
    )?;
    guard_profile(cli)?;
    let divi_network = if cli.divi_network == "mainnet" {
        divi_wallet::address::Network::Mainnet
    } else {
        divi_wallet::address::Network::Testnet
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
    let divi = Arc::new(with_divi_fallback(
        cli,
        divi_network,
        DiviBackend::new(
            swap_chain_divi::default_rpc(divi_network),
            dkey,
            divi_network,
            swap_chain_divi::FeePolicy::default(),
            wallet,
        )?,
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
                &cli.ltc_network,
                lkey,
                swap_chain_ltc::FeePolicy::default(),
            )?);
            (backend.clone(), CounterLive::Ltc(backend))
        }
        Chain::Zec => {
            let zkey = secp_key(&cli.zec_key, "--zec-key", "zec")?;
            let backend = Arc::new(ZecBackend::for_network(
                &cli.zec_network,
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

/// Per-chain tip read deadline: a hung endpoint becomes a named error for that chain
/// instead of stalling the whole report.
const TIP_TIMEOUT: Duration = Duration::from_secs(30);

/// The chains `tip --chain <name>` reports, in print order. `all` adds XMR only when a
/// monerod URL was given (`xmr_url`); otherwise `tip_main` prints a skip note.
fn tip_chains(name: &str, xmr_url: bool) -> Result<Vec<Chain>> {
    match name.to_ascii_lowercase().as_str() {
        "all" => {
            let mut chains = vec![Chain::Divi, Chain::Btc, Chain::Ltc, Chain::Zec];
            if xmr_url {
                chains.push(Chain::Xmr);
            }
            Ok(chains)
        }
        "xmr" => Ok(vec![Chain::Xmr]),
        "divi" => Ok(vec![Chain::Divi]),
        "btc" => Ok(vec![Chain::Btc]),
        "ltc" => Ok(vec![Chain::Ltc]),
        "zec" => Ok(vec![Chain::Zec]),
        other => bail!("--chain must be divi, btc, ltc, zec, xmr or all, got {other:?}"),
    }
}

/// The network flag value `chain` runs on (`mock` for the mock backend).
fn tip_network(cli: &Cli, chain: Chain) -> &str {
    if matches!(cli.backend, BackendArg::Mock) {
        return "mock";
    }
    match chain {
        Chain::Btc => &cli.btc_network,
        Chain::Ltc => &cli.ltc_network,
        Chain::Zec => &cli.zec_network,
        Chain::Xmr => &cli.xmr_network,
        _ => &cli.divi_network,
    }
}

/// The `balance` network guards for every selected chain, plus the profile agreement, all
/// before any network call. A mainnet chain needs `--allow-mainnet` and `--profile mainnet`.
fn tip_guards(cli: &Cli, chains: &[Chain]) -> Result<()> {
    for &chain in chains {
        match chain {
            Chain::Btc => guard_network(
                "--btc-network",
                &cli.btc_network,
                &["signet", "testnet"],
                cli.allow_mainnet,
            )?,
            Chain::Ltc => guard_network(
                "--ltc-network",
                &cli.ltc_network,
                &["testnet"],
                cli.allow_mainnet,
            )?,
            Chain::Zec => guard_network(
                "--zec-network",
                &cli.zec_network,
                &["testnet"],
                cli.allow_mainnet,
            )?,
            // XMR keeps its own mainnet opt-in, as in `guard_profile`.
            Chain::Xmr => {
                guard_network(
                    "--xmr-network",
                    &cli.xmr_network,
                    &["stagenet", "testnet"],
                    cli.xmr_allow_mainnet,
                )
                .map_err(|e| anyhow::anyhow!("{e} (for xmr: --xmr-allow-mainnet)"))?;
                if cli.xmr_monerod_url.is_none() {
                    bail!("tip --chain xmr needs --xmr-monerod-url");
                }
            }
            _ => guard_network(
                "--divi-network",
                &cli.divi_network,
                &["testnet"],
                cli.allow_mainnet,
            )?,
        }
        let allow = if chain == Chain::Xmr {
            cli.xmr_allow_mainnet
        } else {
            cli.allow_mainnet
        };
        divi_swap::config::check_profile_networks(
            cli.profile,
            &[(chain, tip_network(cli, chain), Some(allow))],
        )
        .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

/// A live backend for `chain`. Reading a tip needs no key, but every backend constructor
/// takes one: a fresh in-memory key that is never saved, never funded and dropped on return.
fn tip_backend(cli: &Cli, chain: Chain) -> Result<Arc<dyn ChainBackend>> {
    let key = bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng());
    Ok(match chain {
        Chain::Btc => Arc::new(BtcBackend::for_network(
            &cli.btc_network,
            key,
            swap_chain_btc::FeePolicy::default(),
        )?),
        Chain::Ltc => Arc::new(LtcBackend::for_network(
            &cli.ltc_network,
            key,
            swap_chain_ltc::FeePolicy::default(),
        )?),
        Chain::Zec => Arc::new(ZecBackend::for_network(
            &cli.zec_network,
            key,
            swap_chain_zec::FeePolicy::default(),
        )?),
        Chain::Divi => {
            let network = if cli.divi_network == "mainnet" {
                divi_wallet::address::Network::Mainnet
            } else {
                divi_wallet::address::Network::Testnet
            };
            let dkey = divi_crypto::keys::SecretKey::from_hex(&hex::encode(key.secret_bytes()))
                .map_err(|_| anyhow::anyhow!("divi throwaway key"))?;
            Arc::new(with_divi_fallback(
                cli,
                network,
                DiviBackend::new(
                    swap_chain_divi::default_rpc(network),
                    dkey,
                    network,
                    swap_chain_divi::FeePolicy::default(),
                    None,
                )?,
            )?)
        }
        other => bail!("no tip backend for {other}"),
    })
}

/// Where a chain's tip comes from: a `ChainBackend`, or (XMR, which bypasses `ChainBackend`)
/// the height of a monerod after `ensure_monerod_network` confirmed its network.
enum TipSource {
    Backend(Result<Arc<dyn ChainBackend>>),
    Monerod { url: String, network: String },
}

/// A chain, its network label and its tip source.
type TipEntry = (Chain, String, TipSource);

/// One backend per selected chain (a mock chain per chain under `--backend mock`). A chain
/// whose backend cannot be built keeps its error so it is reported by name.
fn tip_backends(cli: &Cli, chains: &[Chain]) -> Vec<TipEntry> {
    chains
        .iter()
        .map(|&chain| {
            let backend = match cli.backend {
                _ if chain == Chain::Xmr => {
                    return (
                        chain,
                        cli.xmr_network.clone(),
                        match &cli.xmr_monerod_url {
                            Some(url) => TipSource::Monerod {
                                url: url.clone(),
                                network: cli.xmr_network.clone(),
                            },
                            None => {
                                TipSource::Backend(Err(anyhow::anyhow!("no --xmr-monerod-url")))
                            }
                        },
                    );
                }
                BackendArg::Mock => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as u32)
                        .unwrap_or(1_700_000_000);
                    let backend: Arc<dyn ChainBackend> =
                        Arc::new(MockChain::new(chain, now, 60).backend(3, Amount(0)));
                    Ok(backend)
                }
                BackendArg::Live => tip_backend(cli, chain),
            };
            (
                chain,
                tip_network(cli, chain).to_string(),
                TipSource::Backend(backend),
            )
        })
        .collect()
}

/// Read every chain's tip: `(lines, failures)`. A chain that cannot be reached prints
/// `chain network error: …` and counts as a failure; the others still print.
async fn tip_report(entries: Vec<TipEntry>, xmr_allow_mainnet: bool) -> (Vec<String>, usize) {
    let mut lines = Vec::new();
    let mut failures = 0;
    for (chain, network, backend) in entries {
        let (height, hash) = match backend {
            TipSource::Backend(Err(e)) => (Err(format!("{e:#}")), Ok(String::new())),
            TipSource::Backend(Ok(b)) => {
                let height = match tokio::time::timeout(TIP_TIMEOUT, b.tip_height()).await {
                    Ok(Ok(h)) => Ok(h),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err(format!("no answer within {}s", TIP_TIMEOUT.as_secs())),
                };
                let hash = match tokio::time::timeout(TIP_TIMEOUT, b.tip_hash()).await {
                    Ok(Ok(h)) => Ok(h),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err(format!("no answer within {}s", TIP_TIMEOUT.as_secs())),
                };
                (height, hash)
            }
            // `get_info` supplies both the nettype and the height; the network must match the
            // selected one before the height is printed.
            TipSource::Monerod { url, network } => {
                let r = divi_swap_xmr::live::ensure_monerod_network(
                    "--xmr-network",
                    &network,
                    xmr_allow_mainnet,
                    &url,
                );
                match tokio::time::timeout(TIP_TIMEOUT, r).await {
                    Ok(Ok(net)) => (
                        Ok(net.height),
                        Ok(net.top_block_hash.unwrap_or_else(|| "-".to_string())),
                    ),
                    Ok(Err(e)) => (Err(e.to_string()), Ok(String::new())),
                    Err(_) => (
                        Err(format!("no answer within {}s", TIP_TIMEOUT.as_secs())),
                        Ok(String::new()),
                    ),
                }
            }
        };
        let (line, failed) = tip_line(chain, &network, height, hash);
        failures += usize::from(failed);
        lines.push(line);
    }
    (lines, failures)
}

/// One output line, `chain network height hash`. The first three fields are the original
/// format. A height that cannot be read prints `chain network error: …`; a hash that cannot
/// be read after a good height prints `chain network height hash-error: …` so the height is
/// not lost. Returns the line and whether it counts as a failure.
fn tip_line(
    chain: Chain,
    network: &str,
    height: Result<u64, String>,
    hash: Result<String, String>,
) -> (String, bool) {
    match (height, hash) {
        (Ok(h), Ok(x)) => (format!("{chain} {network} {h} {x}"), false),
        (Ok(h), Err(e)) => (format!("{chain} {network} {h} hash-error: {e}"), true),
        (Err(e), _) => (format!("{chain} {network} error: {e}"), true),
    }
}

async fn tip_main(cli: &Cli, chain: &str) -> Result<()> {
    let chains = tip_chains(chain, cli.xmr_monerod_url.is_some())?;
    if matches!(cli.backend, BackendArg::Live) {
        tip_guards(cli, &chains)?;
    }
    let (mut lines, failures) = tip_report(tip_backends(cli, &chains), cli.xmr_allow_mainnet).await;
    let reported = lines.len();
    if chain.eq_ignore_ascii_case("all") && cli.xmr_monerod_url.is_none() {
        lines.push("xmr skipped (no --xmr-monerod-url)".to_string());
    }
    for line in &lines {
        println!("{line}");
    }
    if failures > 0 {
        bail!("{failures} of {reported} chain tips could not be read");
    }
    Ok(())
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

/// `--ltc-crosscheck` parsed; `None` is `off`.
fn ltc_crosscheck_source(cli: &Cli) -> Result<Option<swap_chain_ltc::CrossCheckSource>> {
    swap_chain_ltc::CrossCheckSource::parse_opt(&cli.ltc_crosscheck)
        .map_err(|e| anyhow::anyhow!("--ltc-crosscheck: {e}"))
}

/// Before any LTC action: the opt-in tip-hash cross-check. A disagreement is an error; an
/// unavailable source warns and continues; `off` and non-LTC runs make no request.
async fn ltc_preflight(cli: &Cli, b: &Backends) -> Result<()> {
    if let Some((_, CounterLive::Ltc(ltc))) = &b.live {
        ltc.crosscheck(ltc_crosscheck_source(cli)?).await?;
    }
    Ok(())
}

async fn taker(cli: &Cli) -> Result<Taker> {
    let b = backends(cli)?;
    ltc_preflight(cli, &b).await?;
    sync_divi(cli, &b).await?;
    Ok(Taker::new(b.divi, b.btc, Store::open(&cli.db)?).with_profile_floor(cli.profile))
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
    if let Cmd::Tip { chain } = &cli.cmd {
        return tip_main(&cli, chain).await;
    }
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
                .with_swap_token(&s.maker_swap_id, &s.swap_token)
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
            ltc_preflight(&cli, &b).await?;
            sync_divi(&cli, &b).await?;
            let gate = ClaimGate {
                policy,
                store: Store::open(&cli.db)?,
                divi: b.divi.clone(),
                btc: b.btc.clone(),
            };
            let taker =
                Taker::new(b.divi, b.btc, Store::open(&cli.db)?).with_profile_floor(cli.profile);
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
        Cmd::Tip { .. } => unreachable!("handled before the match"),
        Cmd::Balance if is_usdc_live(&cli) => {
            guard_profile(&cli)?;
            let usdc = live_usdc_backend(&cli)?;
            let (eth, units) = usdc.gas_and_token_balance().await?;
            println!("usdc_address={}", usdc.address());
            println!("usdc_eth_wei={eth}");
            println!("usdc_balance_units={units}");
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
                counter
                    .balance_sats(&cli.btc_network, &cli.ltc_network)
                    .await?
            );
        }
        Cmd::Txids { swap } => {
            let s = sessions.get(swap)?;
            let rec = Store::open(&cli.db)?
                .get_taker_swap(swap)?
                .with_context(|| format!("no taker record {swap}"))?;
            let view = MakerClient::new(&s.maker_url)
                .with_swap_token(&s.maker_swap_id, &s.swap_token)
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
async fn xmr_taker(cli: &Cli) -> Result<divi_swap_xmr::XmrTaker> {
    use divi_swap_xmr::mock::{MockDiviChain, MockMoneroChain};
    if matches!(cli.backend, BackendArg::Live) {
        return live_xmr_taker(cli).await;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1_700_000_000);
    let divi = MockDiviChain::new(now, 60).wallet(8);
    let xmr = MockMoneroChain::new().wallet("taker", 10_000_000_000_000);
    Ok(divi_swap_xmr::XmrTaker::new(
        divi_swap_xmr::XmrConfig::for_profile(cli.profile),
        Arc::new(divi),
        Arc::new(xmr),
        Store::open(&cli.db)?,
    )?
    .with_profile_floor(cli.profile))
}

/// [`xmr_taker`]'s live engine.
async fn live_xmr_taker(cli: &Cli) -> Result<divi_swap_xmr::XmrTaker> {
    use divi_swap_xmr::live::{self, LiveDivi, LiveDiviChain, LiveMonero, LiveMoneroConfig};
    let network = live::parse_network(&cli.xmr_network)?;
    let profile = live::profile_for(network, cli.xmr_allow_mainnet)
        .map_err(|e| anyhow::anyhow!("--xmr-network {}: {e}", cli.xmr_network))?;
    guard_profile(cli)?;
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
    // Before any secret or wallet work: the node must be on the network --xmr-network names.
    live::ensure_monerod_network(
        "--xmr-network",
        &cli.xmr_network,
        cli.xmr_allow_mainnet,
        &monerod_url,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
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
        wallet_rpc_url: Some(wallet_rpc_url),
        wallet_rpc_user: cli.xmr_wallet_rpc_user.clone(),
        wallet_rpc_password,
        network,
        sweep_to,
        lookback_blocks: cli.xmr_lookback_blocks,
        journal_dir: PathBuf::from(format!("{}.xmr-journal", cli.db.display())),
    })?;
    let divi = LiveDivi::new(divi);
    divi_swap_xmr::check_divi_chain(&divi, live::divi_chain_name(network))
        .await
        .map_err(|e| anyhow::anyhow!("--xmr-divi-rpc-url: {e}"))?;
    Ok(divi_swap_xmr::XmrTaker::new(
        profile,
        Arc::new(divi),
        Arc::new(xmr),
        Store::open(&cli.db)?,
    )?
    .with_profile_floor(cli.profile))
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
            let taker = xmr_taker(cli).await?;
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
                .xmr_swap(&s.maker_swap_id, &s.swap_token)
                .await?;
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        Cmd::Claim { swap } | Cmd::Refund { swap } => {
            let client = MakerClient::new(&sessions.get(swap)?.maker_url);
            let state = xmr_flow::step(&xmr_taker(cli).await?, &client, sessions, swap).await?;
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
                &xmr_taker(cli).await?,
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
        Cmd::Tip { .. } => unreachable!("handled before the xmr arm"),
        Cmd::Lock { .. } | Cmd::Balance | Cmd::Txids { .. } => {
            bail!("not available for xmr: `accept` sends the signatures, `claim` steps the swap (it locks XMR and redeems)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip_cli(extra: &[&str]) -> Cli {
        let mut argv = vec!["divi-swap"];
        argv.extend_from_slice(extra);
        argv.push("tip");
        Cli::parse_from(argv)
    }

    #[tokio::test]
    async fn tip_prints_one_line_per_chain_on_the_mock_backend() {
        let cli = tip_cli(&["--backend", "mock"]);
        let chains = tip_chains("all", false).unwrap();
        let (lines, failures) = tip_report(tip_backends(&cli, &chains), false).await;
        assert_eq!(failures, 0);
        assert_eq!(lines.len(), 4);
        for (line, chain) in lines.iter().zip(["divi", "btc", "ltc", "zec"]) {
            let f: Vec<&str> = line.split(' ').collect();
            assert_eq!(f.len(), 4, "{line}");
            assert_eq!((f[0], f[1]), (chain, "mock"));
            f[2].parse::<u64>().unwrap();
            assert_eq!(f[3].len(), 64, "{line}");
            assert!(f[3].bytes().all(|b| b.is_ascii_hexdigit()), "{line}");
        }
    }

    /// A parser written for the old `chain network height` line (first three fields) still
    /// reads every line, and the hash is the mock's own tip hash.
    #[tokio::test]
    async fn tip_height_only_parser_still_reads_the_first_three_fields() {
        let cli = tip_cli(&["--backend", "mock"]);
        let chains = tip_chains("all", false).unwrap();
        let (lines, _) = tip_report(tip_backends(&cli, &chains), false).await;
        for line in &lines {
            let mut it = line.split_whitespace();
            let (chain, network, height) = (it.next(), it.next(), it.next());
            assert!(chain.is_some() && network == Some("mock"), "{line}");
            height.unwrap().parse::<u64>().unwrap();
        }
        let want = MockChain::new(Chain::Btc, 1_700_000_000, 60)
            .backend(3, Amount(0))
            .tip_hash()
            .await
            .unwrap();
        assert_eq!(lines[1].split(' ').nth(3), Some(want.as_str()));
    }

    /// One chain whose backend is down prints a named error; the others still print a
    /// full four-field line, in `--chain all` order.
    #[tokio::test]
    async fn tip_reports_one_chain_error_while_the_others_still_print() {
        let mk = |chain: Chain, offline: bool| {
            let c = MockChain::new(chain, 1_700_000_000, 60);
            c.set_offline(offline);
            let b: Arc<dyn ChainBackend> = Arc::new(c.backend(3, Amount(0)));
            (chain, "mock".to_string(), TipSource::Backend(Ok(b)))
        };
        let entries = vec![
            mk(Chain::Divi, false),
            mk(Chain::Btc, true),
            mk(Chain::Ltc, false),
            mk(Chain::Zec, false),
        ];
        let (lines, failures) = tip_report(entries, false).await;
        assert_eq!(failures, 1);
        let order: Vec<&str> = lines.iter().map(|l| l.split(' ').next().unwrap()).collect();
        assert_eq!(order, ["divi", "btc", "ltc", "zec"]);
        assert!(lines[1].starts_with("btc mock error: "), "{}", lines[1]);
        for i in [0, 2, 3] {
            assert_eq!(lines[i].split(' ').count(), 4, "{}", lines[i]);
        }
    }

    #[test]
    fn tip_line_keeps_the_height_when_only_the_hash_fails() {
        let (line, failed) = tip_line(
            Chain::Btc,
            "mainnet",
            Ok(7),
            Err("endpoint down".to_string()),
        );
        assert!(failed);
        assert_eq!(line, "btc mainnet 7 hash-error: endpoint down");
        let (line, failed) = tip_line(Chain::Xmr, "stagenet", Ok(9), Ok("-".to_string()));
        assert!(!failed);
        assert_eq!(line, "xmr stagenet 9 -");
    }

    #[test]
    fn tip_chain_selector_names_what_it_accepts() {
        assert_eq!(tip_chains("zec", false).unwrap(), vec![Chain::Zec]);
        assert_eq!(tip_chains("xmr", false).unwrap(), vec![Chain::Xmr]);
        let e = tip_chains("doge", false).unwrap_err().to_string();
        assert!(e.contains("divi, btc, ltc, zec, xmr or all"), "{e}");
        // `all` carries XMR only with a monerod URL.
        assert!(!tip_chains("all", false).unwrap().contains(&Chain::Xmr));
        assert_eq!(tip_chains("all", true).unwrap().last(), Some(&Chain::Xmr));
    }

    #[test]
    fn tip_refuses_a_mainnet_network_without_allow_mainnet() {
        for (chain, flag) in [
            ("btc", "--btc-network"),
            ("ltc", "--ltc-network"),
            ("zec", "--zec-network"),
            ("divi", "--divi-network"),
        ] {
            let cli = tip_cli(&[flag, "mainnet", "--profile", "mainnet"]);
            let e = tip_guards(&cli, &tip_chains(chain, false).unwrap())
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("no mainnet without the explicit --allow-mainnet"),
                "{chain}: {e}"
            );
        }
    }

    #[test]
    fn tip_guards_accept_mainnet_with_both_opt_ins_and_refuse_a_profile_mismatch() {
        let ok = tip_cli(&[
            "--btc-network",
            "mainnet",
            "--allow-mainnet",
            "--profile",
            "mainnet",
        ]);
        tip_guards(&ok, &[Chain::Btc]).unwrap();
        let bad = tip_cli(&["--btc-network", "mainnet", "--allow-mainnet"]);
        let e = tip_guards(&bad, &[Chain::Btc]).unwrap_err().to_string();
        assert!(e.contains("profile"), "{e}");
    }

    #[tokio::test]
    async fn tip_names_the_unreachable_chain_and_still_prints_the_rest() {
        let cli = tip_cli(&["--backend", "mock"]);
        let mut entries = tip_backends(&cli, &[Chain::Divi, Chain::Ltc, Chain::Zec]);
        entries[1].2 = TipSource::Backend(Err(anyhow::anyhow!("esplora unreachable")));
        let (lines, failures) = tip_report(entries, false).await;
        assert_eq!(failures, 1);
        assert!(lines[0].starts_with("divi mock "), "{lines:?}");
        assert_eq!(lines[1], "ltc mock error: esplora unreachable");
        assert!(lines[2].starts_with("zec mock "), "{lines:?}");
    }

    /// A monerod answering `get_info` with `nettype`/`height`; returns its base URL.
    async fn fake_monerod(nettype: &'static str, height: u64) -> String {
        fake_monerod_with_hash(nettype, height, Some(XMR_HASH)).await
    }

    const XMR_HASH: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

    /// As [`fake_monerod`], with `get_info`'s `top_block_hash` present or absent.
    async fn fake_monerod_with_hash(
        nettype: &'static str,
        height: u64,
        hash: Option<&'static str>,
    ) -> String {
        let app = axum::Router::new().route(
            "/json_rpc",
            axum::routing::post(move || async move {
                let mut result = serde_json::json!({
                    "nettype": nettype, "mainnet": nettype == "mainnet",
                    "height": height, "status": "OK"});
                if let Some(h) = hash {
                    result["top_block_hash"] = serde_json::json!(h);
                }
                axum::Json(serde_json::json!({"id":"0","jsonrpc":"2.0","result":result}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn xmr_tip(extra: &[&str]) -> (Vec<String>, usize) {
        let cli = tip_cli(extra);
        let chains = tip_chains("xmr", true).unwrap();
        tip_report(tip_backends(&cli, &chains), cli.xmr_allow_mainnet).await
    }

    #[tokio::test]
    async fn tip_xmr_prints_the_monerod_height() {
        let url = fake_monerod("stagenet", 2_227_400).await;
        let (lines, failures) = xmr_tip(&["--xmr-monerod-url", &url]).await;
        assert_eq!(failures, 0);
        assert_eq!(lines, vec![format!("xmr stagenet 2227400 {XMR_HASH}")]);
    }

    #[tokio::test]
    async fn tip_xmr_prints_a_dash_when_monerod_sends_no_hash() {
        let url = fake_monerod_with_hash("stagenet", 2_227_400, None).await;
        let (lines, failures) = xmr_tip(&["--xmr-monerod-url", &url]).await;
        assert_eq!(failures, 0);
        assert_eq!(lines, vec!["xmr stagenet 2227400 -".to_string()]);
    }

    #[tokio::test]
    async fn tip_xmr_refuses_a_node_on_another_network() {
        let url = fake_monerod("mainnet", 3_000_000).await;
        let (lines, failures) = xmr_tip(&["--xmr-monerod-url", &url]).await;
        assert_eq!(failures, 1);
        assert!(
            lines[0].starts_with("xmr stagenet error: ") && lines[0].contains("mainnet"),
            "{lines:?}"
        );
        assert!(!lines[0].contains("3000000"), "{lines:?}");
    }

    #[test]
    fn tip_xmr_refuses_mainnet_without_the_opt_in_before_any_network_call() {
        let cli = tip_cli(&[
            "--xmr-network",
            "mainnet",
            "--xmr-monerod-url",
            "http://127.0.0.1:1",
            "--profile",
            "mainnet",
        ]);
        let e = tip_guards(&cli, &[Chain::Xmr]).unwrap_err().to_string();
        assert!(e.contains("--xmr-allow-mainnet"), "{e}");
        let ok = tip_cli(&[
            "--xmr-network",
            "mainnet",
            "--xmr-allow-mainnet",
            "--xmr-monerod-url",
            "http://127.0.0.1:1",
            "--profile",
            "mainnet",
        ]);
        tip_guards(&ok, &[Chain::Xmr]).unwrap();
        let none = tip_cli(&[]);
        let e = tip_guards(&none, &[Chain::Xmr]).unwrap_err().to_string();
        assert!(e.contains("--xmr-monerod-url"), "{e}");
    }

    #[tokio::test]
    async fn tip_all_without_a_monerod_url_skips_xmr_with_a_note() {
        let cli = tip_cli(&["--backend", "mock"]);
        assert!(cli.xmr_monerod_url.is_none());
        tip_main(&cli, "all").await.unwrap();
        // The note itself is printed by `tip_main`; `all` must not have built an XMR entry.
        assert!(!tip_chains("all", false).unwrap().contains(&Chain::Xmr));
    }

    #[tokio::test]
    async fn tip_xmr_names_an_unreachable_monerod_and_still_prints_the_rest() {
        let cli = tip_cli(&[
            "--backend",
            "mock",
            "--xmr-monerod-url",
            "http://127.0.0.1:1",
        ]);
        let chains = [Chain::Divi, Chain::Xmr, Chain::Zec];
        let (lines, failures) = tip_report(tip_backends(&cli, &chains), false).await;
        assert_eq!(failures, 1);
        assert!(lines[0].starts_with("divi mock "), "{lines:?}");
        assert!(lines[1].starts_with("xmr stagenet error: "), "{lines:?}");
        assert!(lines[1].contains("127.0.0.1:1"), "{lines:?}");
        assert!(lines[2].starts_with("zec mock "), "{lines:?}");
    }

    fn throwaway_divi() -> DiviBackend {
        let key = divi_crypto::keys::SecretKey::from_hex(&"11".repeat(32)).unwrap();
        DiviBackend::new(
            "http://127.0.0.1:1",
            key,
            divi_wallet::address::Network::Testnet,
            swap_chain_divi::FeePolicy::default(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn divi_fallback_flag_parses_and_builds_a_backend_with_a_fallback() {
        let net = divi_wallet::address::Network::Testnet;
        let c = cli(&["--divi-fallback-rpc-url", "http://127.0.0.1:2"]);
        assert_eq!(
            c.divi_fallback_rpc_url.as_deref(),
            Some("http://127.0.0.1:2")
        );
        let b = with_divi_fallback(&c, net, throwaway_divi()).unwrap();
        assert!(b.has_fallback());
    }

    #[test]
    fn divi_fallback_unset_or_blank_leaves_the_backend_single_source() {
        let net = divi_wallet::address::Network::Testnet;
        let unset = cli(&[]);
        assert_eq!(unset.divi_fallback_rpc_url, None);
        assert!(!with_divi_fallback(&unset, net, throwaway_divi())
            .unwrap()
            .has_fallback());
        let blank = cli(&["--divi-fallback-rpc-url", "  "]);
        assert!(!with_divi_fallback(&blank, net, throwaway_divi())
            .unwrap()
            .has_fallback());
    }

    #[test]
    fn divi_fallback_equal_to_the_default_endpoint_is_refused() {
        let net = divi_wallet::address::Network::Testnet;
        let same = swap_chain_divi::default_rpc(net).to_string();
        let c = cli(&["--divi-fallback-rpc-url", &same]);
        let err = with_divi_fallback(&c, net, throwaway_divi()).err().unwrap();
        assert!(err.to_string().contains("must differ"), "{err}");
    }

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
    fn zec_network_defaults_to_testnet() {
        assert_eq!(cli(&[]).zec_network, "testnet");
        assert!(!cli(&[]).allow_mainnet);
    }

    #[test]
    fn divi_network_defaults_to_testnet() {
        assert_eq!(cli(&[]).divi_network, "testnet");
    }

    #[test]
    fn divi_mainnet_without_allow_mainnet_is_rejected_before_any_network_call() {
        let e = match live_backends(&cli(&["--divi-network", "mainnet"])) {
            Ok(_) => panic!("built a live divi backend without --allow-mainnet"),
            Err(e) => e.to_string(),
        };
        assert!(
            e.contains("--divi-network mainnet moves real money") && e.contains("--allow-mainnet"),
            "{e}"
        );
    }

    #[test]
    fn divi_bad_network_is_rejected_before_any_network_call() {
        let e = match live_backends(&cli(&["--divi-network", "regtest"])) {
            Ok(_) => panic!("built a live divi backend on regtest"),
            Err(e) => e.to_string(),
        };
        assert!(
            e.contains("--divi-network must be testnet or mainnet"),
            "{e}"
        );
    }

    #[test]
    fn divi_network_must_agree_with_the_profile_in_both_directions() {
        // Mainnet profile + mainnet btc, DIVI left on testnet.
        let e = match live_backends(&cli(&[
            "--profile",
            "mainnet",
            "--btc-network",
            "mainnet",
            "--allow-mainnet",
        ])) {
            Ok(_) => panic!("built a live backend: mainnet profile, divi testnet"),
            Err(e) => e.to_string(),
        };
        assert!(
            e.contains("profile = \"mainnet\" but [divi].network = \"testnet\"")
                && e.contains("mainnet profile with a test network is refused"),
            "{e}"
        );
        // Testnet profile (default), DIVI on mainnet with the opt-in.
        let e = match live_backends(&cli(&["--divi-network", "mainnet", "--allow-mainnet"])) {
            Ok(_) => panic!("built a live backend: testnet profile, divi mainnet"),
            Err(e) => e.to_string(),
        };
        assert!(
            e.contains("profile = \"testnet\" but [divi].network = \"mainnet\"")
                && e.contains("real funds under testnet timeouts are refused"),
            "{e}"
        );
    }

    #[test]
    fn divi_mainnet_passes_every_guard_when_all_agree() {
        let c = cli(&[
            "--profile",
            "mainnet",
            "--btc-network",
            "mainnet",
            "--divi-network",
            "mainnet",
            "--allow-mainnet",
        ]);
        guard_network(
            "--divi-network",
            &c.divi_network,
            &["testnet"],
            c.allow_mainnet,
        )
        .unwrap();
        guard_profile(&c).unwrap();
    }

    #[test]
    fn zec_mainnet_without_allow_mainnet_is_rejected_before_any_network_call() {
        let e = match live_backends(&cli(&[
            "--counter-chain",
            "zec",
            "--zec-network",
            "mainnet",
        ])) {
            Ok(_) => panic!("built a live zec backend without --allow-mainnet"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("--allow-mainnet"), "{e}");
    }

    #[test]
    fn zec_bad_network_is_rejected_before_any_network_call() {
        let e = match live_backends(&cli(&[
            "--counter-chain",
            "zec",
            "--zec-network",
            "regtest",
        ])) {
            Ok(_) => panic!("built a live zec backend with an unknown network"),
            Err(e) => e,
        };
        assert!(
            e.to_string()
                .contains("--zec-network must be testnet or mainnet"),
            "{e}"
        );
    }

    #[test]
    fn ltc_crosscheck_defaults_off_and_testnet_refuses_it_before_any_network_call() {
        assert_eq!(cli(&[]).ltc_crosscheck, "off");
        for src in ["blockbook", "blockcypher"] {
            let e = match live_backends(&cli(&["--counter-chain", "ltc", "--ltc-crosscheck", src]))
            {
                Ok(_) => panic!("built a live testnet ltc backend with --ltc-crosscheck {src}"),
                Err(e) => e,
            };
            assert!(
                e.to_string().contains("--ltc-crosscheck is mainnet-only"),
                "{e}"
            );
        }
        let e = match live_backends(&cli(&["--counter-chain", "ltc", "--ltc-crosscheck", "x"])) {
            Ok(_) => panic!("accepted an unknown --ltc-crosscheck"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("--ltc-crosscheck"), "{e}");
    }

    #[test]
    fn btc_and_ltc_networks_default_to_the_test_networks() {
        assert_eq!(cli(&[]).btc_network, "signet");
        assert_eq!(cli(&[]).ltc_network, "testnet");
    }

    #[test]
    fn btc_ltc_mainnet_without_allow_mainnet_is_rejected_before_any_network_call() {
        for (chain, flag) in [("btc", "--btc-network"), ("ltc", "--ltc-network")] {
            let e = match live_backends(&cli(&["--counter-chain", chain, flag, "mainnet"])) {
                Ok(_) => panic!("built a live {chain} backend on mainnet without --allow-mainnet"),
                Err(e) => e,
            };
            assert!(e.to_string().contains("--allow-mainnet"), "{chain}: {e}");
            assert!(e.to_string().contains(flag), "{chain}: {e}");
        }
    }

    #[test]
    fn btc_ltc_bad_network_is_rejected_before_any_network_call() {
        for (chain, flag) in [("btc", "--btc-network"), ("ltc", "--ltc-network")] {
            let e = match live_backends(&cli(&["--counter-chain", chain, flag, "regtest"])) {
                Ok(_) => panic!("built a live {chain} backend on an unknown network"),
                Err(e) => e,
            };
            assert!(
                e.to_string().contains(&format!("{flag} must be")),
                "{chain}: {e}"
            );
        }
    }

    #[test]
    fn profile_defaults_to_testnet() {
        assert_eq!(cli(&[]).profile, divi_swap::Profile::Testnet);
    }

    #[test]
    fn mainnet_profile_with_a_test_network_is_rejected_before_any_network_call() {
        for (chain, extra) in [("btc", &[][..]), ("ltc", &[]), ("zec", &[]), ("usdc", &[])] {
            let mut argv = vec!["--counter-chain", chain, "--profile", "mainnet"];
            argv.extend_from_slice(extra);
            let e = match live_backends(&cli(&argv)) {
                Ok(_) => panic!("built a live {chain} backend: mainnet profile, test network"),
                Err(e) => e.to_string(),
            };
            assert!(
                e.contains(&format!("profile = \"mainnet\" but [{chain}].network"))
                    && e.contains("mainnet profile with a test network is refused"),
                "{chain}: {e}"
            );
        }
    }

    #[test]
    fn testnet_profile_with_a_mainnet_network_is_rejected_before_any_network_call() {
        for (chain, flag) in [
            ("btc", "--btc-network"),
            ("ltc", "--ltc-network"),
            ("zec", "--zec-network"),
        ] {
            let e = match live_backends(&cli(&[
                "--counter-chain",
                chain,
                flag,
                "mainnet",
                "--allow-mainnet",
            ])) {
                Ok(_) => panic!("built a live {chain} backend: testnet profile, mainnet"),
                Err(e) => e.to_string(),
            };
            assert!(
                e.contains(&format!(
                    "profile = \"testnet\" but [{chain}].network = \"mainnet\""
                )) && e.contains("real funds under testnet timeouts are refused"),
                "{chain}: {e}"
            );
        }
    }

    #[tokio::test]
    async fn xmr_profile_must_agree_with_xmr_network_before_any_network_call() {
        let mainnet_testnet = cli(&[
            "--counter-chain",
            "xmr",
            "--xmr-network",
            "mainnet",
            "--xmr-allow-mainnet",
            "--xmr-divi-rpc-url",
            "http://127.0.0.1:1",
            "--xmr-sweep-address",
            "x",
        ]);
        let e = live_xmr_taker(&mainnet_testnet)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains("profile = \"testnet\" but [xmr].network = \"mainnet\""),
            "{e}"
        );
        let stagenet_mainnet = cli(&["--counter-chain", "xmr", "--profile", "mainnet"]);
        let e = live_xmr_taker(&stagenet_mainnet)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains("profile = \"mainnet\" but [xmr].network = \"stagenet\""),
            "{e}"
        );
    }

    #[test]
    fn mainnet_guard_passes_with_allow_mainnet() {
        guard_network("--btc-network", "mainnet", &["signet", "testnet"], true).unwrap();
        guard_network("--ltc-network", "mainnet", &["testnet"], true).unwrap();
        guard_network("--btc-network", "signet", &["signet", "testnet"], false).unwrap();
    }

    #[tokio::test]
    async fn live_xmr_taker_names_what_it_is_missing_before_touching_anything() {
        // The failures asserted here all come before any network call.
        async fn err(extra: &[&str]) -> String {
            match live_xmr_taker(&cli(extra)).await {
                Ok(_) => panic!("built a live xmr taker from {extra:?}"),
                Err(e) => e.to_string(),
            }
        }
        let e = err(&["--counter-chain", "xmr"]).await;
        assert!(e.contains("--xmr-sweep-address"), "{e}");
        let e = err(&["--counter-chain", "xmr", "--xmr-network", "mainnet"]).await;
        assert!(e.contains("no mainnet"), "{e}");
        let e = err(&[
            "--counter-chain",
            "xmr",
            "--xmr-network",
            "mainnet",
            "--xmr-allow-mainnet",
            "--profile",
            "mainnet",
        ])
        .await;
        assert!(e.contains("--xmr-divi-rpc-url"), "{e}");
        let e = err(&[
            "--counter-chain",
            "xmr",
            "--xmr-sweep-address",
            "5notanaddress",
        ])
        .await;
        assert!(e.contains("monero address"), "{e}");
    }

    #[tokio::test]
    async fn live_xmr_taker_refuses_a_monerod_it_cannot_confirm_the_network_of() {
        // Valid args, monerod on a closed loopback port: refused before any wallet work.
        let sweep = "53hWE4DtPhFAvGj998ShM5D47iQ7hC6L2FhtiNiaHzX54dqQgtDemNoAdsYQHiS1C5Uqejdhe6D9bTAtcCT2jtwE6wyf2mn";
        let e = match live_xmr_taker(&cli(&[
            "--counter-chain",
            "xmr",
            "--xmr-sweep-address",
            sweep,
            "--xmr-monerod-url",
            "http://127.0.0.1:1",
            "--xmr-wallet-rpc-url",
            "http://127.0.0.1:1",
        ]))
        .await
        {
            Ok(_) => panic!("built a live xmr taker against an unreachable monerod"),
            Err(e) => e.to_string(),
        };
        assert!(e.contains("--xmr-network = \"stagenet\""), "{e}");
        assert!(e.contains("refusing to start"), "{e}");
    }

    #[test]
    fn balance_routes_usdc_live_to_its_own_path() {
        assert!(is_usdc_live(&cli(&[
            "--backend",
            "live",
            "--counter-chain",
            "usdc"
        ])));
        assert!(
            is_usdc_live(&cli(&["--counter-chain", "usdc"])),
            "live is the default"
        );
        assert!(!is_usdc_live(&cli(&[
            "--backend",
            "mock",
            "--counter-chain",
            "usdc"
        ])));
        assert!(!is_usdc_live(&cli(&[
            "--backend",
            "live",
            "--counter-chain",
            "btc"
        ])));
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
    fn usdc_mainnet_without_allow_mainnet_is_rejected_before_any_network_call() {
        for net in ["ethereum", "base"] {
            let e = usdc_endpoints(&cli(&["--usdc-network", net])).unwrap_err();
            assert!(e.to_string().contains("--allow-mainnet"), "{net}: {e}");
        }
    }

    #[test]
    fn usdc_mainnet_with_allow_mainnet_returns_mainnet_defaults() {
        for (net, want, token) in [
            (
                "ethereum",
                swap_chain_evm::UsdcNetwork::Ethereum,
                swap_chain_evm::ETHEREUM_USDC,
            ),
            (
                "base",
                swap_chain_evm::UsdcNetwork::Base,
                swap_chain_evm::BASE_USDC,
            ),
        ] {
            let (network, rpc_url, tok) =
                usdc_endpoints(&cli(&["--usdc-network", net, "--allow-mainnet"])).unwrap();
            assert_eq!(network, want);
            assert_eq!(rpc_url, want.default_rpc_url());
            assert_eq!(tok, token);
        }
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
