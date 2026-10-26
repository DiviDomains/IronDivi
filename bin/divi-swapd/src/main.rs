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

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use divi_swap::mock::MockChain;
use divi_swap::reservation::ExpiryStart;
use divi_swap::secrets::SecretRef;
use divi_swap::{Amount, Chain, ChainBackend, InputReservations, Maker, Store};
use divi_swapd::{
    mock_counter_offers, mock_xmr_offers, router_with_auth, run_scan, spawn_gated_scheduler,
    AppState, BackendKind, BtcSection, DaemonConfig, HashlockAuth, LtcSection, ScanStatus,
    XmrSection, ZecSection, MOCK_ONLY_CHAINS,
};
use swap_chain_btc::{BtcBackend, FeePolicy, RetryPolicy};
use swap_chain_divi::{DiviBackend, FeePolicy as DiviFeePolicy};
use swap_chain_ltc::LtcBackend;
use swap_chain_zec::{FeePolicy as ZecFeePolicy, RetryPolicy as ZecRetryPolicy, ZecBackend};

#[derive(Parser)]
#[command(name = "divi-swapd", version, about = "Atomic swap maker daemon")]
struct Args {
    /// Path to the TOML config file.
    #[arg(long)]
    config: PathBuf,
    /// Override the backend: `mock` runs every chain in-process (local/CI, with LTC and ZEC
    /// offers added), `live` uses the public testnets.
    #[arg(long, value_parser = parse_backend)]
    backend: Option<BackendKind>,
    /// Print the XMR swaps still in flight, read straight from the swap store, and exit.
    /// Read-only: nothing is created or written, no chain or key is touched, no HTTP.
    /// Output (stdout only): `xmr_configured yes|no`, `in_flight N`, then one `<id> <state>`
    /// per non-terminal swap. Exit 0 iff the store was readable. Run it as the service user.
    #[arg(long)]
    xmr_inflight: bool,
    /// With `--xmr-inflight`: append the taker's reported XMR lock txid to every swap line
    /// (`<id> <state> <txid>`, `-` until a lock is recorded). The `xmr_configured` and
    /// `in_flight` lines are unchanged; without this flag the output is byte-identical to before.
    #[arg(long, requires = "xmr_inflight")]
    xmr_lock_txids: bool,
    /// With `--xmr-inflight`: the alert job's form. The `xmr_configured` and `in_flight` lines
    /// are unchanged; each swap line becomes `<id>\t<state>\t<t_punish|->\t<last_error>`
    /// (tab-separated; `-` when `t_punish` is null; `last_error` last, empty when none, with
    /// backslash, tab, newline and carriage return escaped as `\\`, `\t`, `\n`, `\r`).
    /// Same swaps as plain `--xmr-inflight` (every non-terminal state, `cancelled` and
    /// `refunded` included). Without this flag the output is byte-identical to before.
    #[arg(long, requires = "xmr_inflight", conflicts_with = "xmr_lock_txids")]
    xmr_watch: bool,
    /// Print every reserved wallet input (BTC, LTC, ZEC maker locks), read straight from the
    /// swap database, and exit. Read-only: nothing is created or written, no node, key or
    /// network is touched, and it is safe next to a running daemon. Output (stdout only):
    /// `reservations N`, then one tab-separated
    /// `<chain>\t<input txid>:<vout>\t<reserving txid>\t<swap id|unknown>\t<swap state|unknown>`
    /// per input. Exit 0 iff the database was readable. Run it as the service user.
    #[arg(long, conflicts_with_all = ["xmr_inflight", "release_reservation"])]
    reservations: bool,
    /// Release the reservations of ONE lock transaction (hex txid, as `--reservations` prints
    /// it) on the chain given by `--chain`, so those coins are selectable again. WRITES the
    /// swap database. BEFORE using it you MUST check, with a node of that chain, that the
    /// txid is in no mempool and in no block: releasing the inputs of a lock that can still
    /// confirm lets the next swap double-spend it. Refused unless the swap that broadcast the
    /// txid is terminal (a maker swap `done`/`aborted`, a taker swap `done`) or no swap row names it, and refused while
    /// `divi-swapd` (or anything else) has the database open: stop the daemon first. Without
    /// `--yes` it only prints what it would release and exits 2.
    #[arg(
        long,
        value_name = "TXID",
        requires = "chain",
        conflicts_with = "xmr_inflight"
    )]
    release_reservation: Option<String>,
    /// With `--release-reservation`: the chain the reservation is on (btc, ltc, zec, divi).
    #[arg(long, requires = "release_reservation", value_parser = parse_chain)]
    chain: Option<Chain>,
    /// With `--release-reservation`: actually release.
    #[arg(long, requires = "release_reservation")]
    yes: bool,
    /// Highest feerate the maker's claim of a taker leg on CHAIN ever pays, as `CHAIN=FEERATE`
    /// (base unit per vbyte; on usdc wei per gas, the claim's `maxFeePerGas`). Repeatable,
    /// one per chain (btc, ltc, usdc; divi and zec claims cannot be bumped). Unset: the
    /// chain's builtin cap (usdc 500 gwei, `500000000000`).
    #[arg(long, value_parser = divi_swap::config::parse_chain_value)]
    claim_fee_cap: Vec<(Chain, u64)>,
    /// Replacement price bump, percent, of the node a same-nonce (usdc) taker-leg claim is
    /// sent to, as `CHAIN=PCT`: each replacement raises both fees at least this much (geth
    /// `--txpool.pricebump`). Repeatable. Unset: 10, geth's default. A node stricter than this
    /// is still outbid: every second "underpriced" refusal doubles the next step.
    #[arg(long, value_parser = divi_swap::config::parse_chain_value)]
    claim_price_bump: Vec<(Chain, u64)>,
}

/// `maker` with the escalations `--claim-fee-cap` and `--claim-price-bump` set
/// ([`divi_swap::config::claim_fee_escalations`]) for its taker-leg claims.
fn with_claim_fees(maker: Maker, args: &Args) -> Result<Maker> {
    Ok(
        divi_swap::config::claim_fee_escalations(&args.claim_fee_cap, &args.claim_price_bump)?
            .into_iter()
            .fold(maker, |m, (chain, esc)| {
                m.with_fee_escalation(chain, Some(esc))
            }),
    )
}

fn parse_chain(s: &str) -> Result<Chain, String> {
    s.parse::<Chain>().map_err(|e| e.to_string())
}

fn parse_backend(s: &str) -> Result<BackendKind, String> {
    match s {
        "mock" => Ok(BackendKind::Mock),
        "live" => Ok(BackendKind::Live),
        other => Err(format!("backend must be mock or live, got {other:?}")),
    }
}

/// DIVI, BTC, and any further counter chains.
struct Backends {
    divi: Arc<dyn ChainBackend>,
    btc: Arc<dyn ChainBackend>,
    others: Vec<Arc<dyn ChainBackend>>,
}

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
    let mut chains = vec![divi, btc];
    let mut others: Vec<Arc<dyn ChainBackend>> = Vec::new();
    for (seed, c) in (5u8..).zip(MOCK_ONLY_CHAINS) {
        let block_secs = if c == Chain::Ltc { 150 } else { 75 };
        let chain = MockChain::new(c, now, block_secs);
        others.push(Arc::new(chain.backend(seed, Amount(1_000 * Amount::COIN))));
        chains.push(chain);
    }
    // Nobody else mines the simulated chains, so the daemon does: one block per tick.
    for chain in chains {
        tokio::spawn(async move {
            let mut i = tokio::time::interval(Duration::from_secs(5));
            loop {
                i.tick().await;
                chain.mine(1);
            }
        });
    }
    Backends {
        divi: Arc::new(d),
        btc: Arc::new(b),
        others,
    }
}

/// `cfg.offers` plus the mock-only counter-chain offers whose ids are not configured (an id
/// configured with `enabled = false` stays off in mock mode too).
fn mock_offers(cfg: &DaemonConfig) -> Vec<divi_swap::api::Offer> {
    let mut offers = cfg.offers.clone();
    for o in mock_counter_offers().into_iter().chain(mock_xmr_offers()) {
        let configured =
            offers.iter().any(|have| have.id == o.id) || cfg.disabled_offers.contains(&o.id);
        if !configured {
            offers.push(o);
        }
    }
    offers
}

/// The adaptor-swap maker over in-process chains (`--backend mock`): a DIVI chain carrying
/// real transactions and a Monero chain, both mined here every 5 s like the other mocks.
fn mock_xmr_engine(
    store: Store,
    offers: Vec<divi_swap::api::Offer>,
) -> Result<Arc<divi_swap_xmr::XmrMaker>> {
    use divi_swap_xmr::mock::{MockDiviChain, MockMoneroChain};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1_700_000_000);
    let divi = MockDiviChain::new(now, 60);
    let xmr = MockMoneroChain::new();
    let wallet = divi.wallet(7);
    wallet.fund(1_000_000 * 100_000_000);
    let engine = divi_swap_xmr::XmrMaker::new(
        divi_swap_xmr::XmrConfig::testnet(),
        Arc::new(wallet),
        Arc::new(xmr.wallet("maker", 0)),
        store,
        offers,
    )?;
    tokio::spawn(async move {
        let mut i = tokio::time::interval(Duration::from_secs(5));
        loop {
            i.tick().await;
            divi.mine(1);
            xmr.mine(1);
        }
    });
    Ok(Arc::new(engine))
}

/// Resolve a DIVI key reference into a key held only in memory.
fn resolve_divi_key(reference: &str, what: &str) -> Result<divi_crypto::keys::SecretKey> {
    let hex_key = SecretRef::parse(reference)
        .and_then(|r| r.resolve())
        .map_err(|e| anyhow::anyhow!("{what} key: {e}"))?;
    let key = divi_crypto::keys::SecretKey::from_hex(hex_key.trim())
        .map_err(|_| anyhow::anyhow!("{what} key is not a valid 32-byte hex key"));
    drop(hex_key);
    key
}

/// The adaptor-swap maker over the live chains of `[xmr]`: its own DIVI wallet (never the
/// `[divi]` one) and the maker's Monero wallet.
async fn live_xmr_engine(
    cfg: &DaemonConfig,
    xs: &XmrSection,
    store: Store,
    offers: Vec<divi_swap::api::Offer>,
) -> Result<Arc<divi_swap_xmr::XmrMaker>> {
    use divi_swap_xmr::live::{self, LiveDivi, LiveMonero, LiveMoneroConfig};
    let network = live::parse_network(&xs.network)?;
    let profile = live::profile_for(network, xs.allow_mainnet)
        .map_err(|e| anyhow::anyhow!("[xmr].network = {:?}: {e}", xs.network))?;
    if network == live::Network::Mainnet
        && xs.divi_rpc_url == divi_swapd::config::default_divi_rpc()
    {
        bail!("[xmr].divi_rpc_url: the default is the DIVI testnet RPC; set a mainnet one");
    }
    // Before anything that touches a wallet: the node must be on the configured network.
    live::ensure_monerod_network(
        "[xmr].network",
        &xs.network,
        xs.allow_mainnet,
        &xs.monerod_url,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sweep_to = live::parse_address(network, &xs.sweep_address)
        .map_err(|e| anyhow::anyhow!("[xmr].sweep_address: {e}"))?;
    let key = resolve_divi_key(&xs.divi_key, "xmr divi")?;
    if let Some(d) = &cfg.divi {
        if resolve_divi_key(&d.key, "divi")?.public_key() == key.public_key() {
            bail!("[xmr].divi_key is the [divi] key: give the xmr engine its own DIVI key");
        }
    }
    let address =
        divi_wallet::address::Address::p2pkh(&key.public_key(), live::divi_network(network))
            .to_string();
    let wallet_rpc_password = match &xs.wallet_rpc_password {
        Some(r) => SecretRef::parse(r)
            .and_then(|r| r.resolve())
            .map_err(|e| anyhow::anyhow!("[xmr].wallet_rpc_password: {e}"))?
            .trim()
            .to_string(),
        None => String::new(),
    };
    let divi = live::LiveDiviChain::new(
        &xs.divi_rpc_url,
        key,
        DiviFeePolicy::default(),
        xs.divi_wallet_path.clone(),
    )?;
    for txid in &xs.divi_fund_txids {
        let n = divi
            .learn_utxo(txid)
            .await
            .with_context(|| format!("[xmr].divi_fund_txids: {txid}"))?;
        tracing::info!(%txid, coins = n, "xmr divi wallet: learned coins");
    }
    let journal_dir = xs
        .journal_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.xmr-journal", cfg.db_path.display())));
    let xmr = LiveMonero::new(LiveMoneroConfig {
        monerod_url: xs.monerod_url.clone(),
        wallet_rpc_url: xs.wallet_rpc_url.clone(),
        wallet_rpc_user: xs.wallet_rpc_user.clone(),
        wallet_rpc_password,
        network,
        sweep_to,
        lookback_blocks: xs.lookback_blocks,
        journal_dir,
    })?;
    let divi = LiveDivi::new(divi);
    divi_swap_xmr::check_divi_chain(&divi, live::divi_chain_name(network))
        .await
        .map_err(|e| anyhow::anyhow!("[xmr].divi_rpc_url: {e}"))?;
    tracing::info!(
        divi_address = %address, network = %xs.network, monerod = %xs.monerod_url,
        "xmr engine ready (live)"
    );
    let engine =
        divi_swap_xmr::XmrMaker::new(profile, Arc::new(divi), Arc::new(xmr), store, offers)?;
    Ok(Arc::new(engine))
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

fn live_btc(cfg: &BtcSection, reservations: &InputReservations) -> Result<Arc<dyn ChainBackend>> {
    // Network name and the mainnet opt-in are validated at config load; the network also
    // picks the address format (`bc1` vs `tb1`).
    let endpoints = cfg.endpoints()?;
    let key = resolve_key(&cfg.key, "btc")?;
    let backend = BtcBackend::new_on(
        &cfg.network,
        endpoints,
        key,
        FeePolicy::default(),
        RetryPolicy::default(),
    )?
    .with_input_reservations(reservations.clone());
    tracing::info!(address = %backend.address(), network = %cfg.network, "btc backend ready");
    Ok(Arc::new(backend))
}

async fn live_ltc(
    cfg: &LtcSection,
    reservations: &InputReservations,
) -> Result<Arc<dyn ChainBackend>> {
    // Network name and the mainnet opt-in are validated at config load; the network also
    // picks the address HRP (`ltc` vs `tltc`).
    let endpoints = cfg.endpoints()?;
    let key = resolve_key(&cfg.key, "ltc")?;
    let backend = LtcBackend::new_on(
        &cfg.network,
        endpoints,
        key,
        swap_chain_ltc::FeePolicy::default(),
        swap_chain_ltc::RetryPolicy::default(),
    )?
    .with_input_reservations(reservations.clone());
    tracing::info!(address = %backend.address(), network = %cfg.network, "ltc backend ready");
    // Opt-in (`[ltc].crosscheck`): a primary that disagrees with the independent source
    // refuses to start; an unreachable source only warns.
    backend.crosscheck(cfg.crosscheck_source()?).await?;
    Ok(Arc::new(backend))
}

/// Floor the maker's own balance must meet before an *enabled* usdc offer is actually
/// served — independent of, and in addition to, the config's `enabled` flag. Checked once
/// at startup against the live balance; a maker that drops under the floor after it was
/// funded keeps serving until the next restart (same as every other config change here).
const MIN_MAKER_ETH_WEI: u128 = 10_000_000_000_000_000; // 0.01 ETH
const MIN_MAKER_USDC_UNITS: u64 = 10_000_000; // 10 USDC, 6 decimals

/// Builds the live `UsdcBackend` and checks its balance against every enabled usdc offer
/// in `offers`, returning the ids of any that are enabled but underfunded — the caller
/// drops those from what it actually serves.
async fn live_usdc(
    cfg: &divi_swapd::UsdcSection,
    offers: &[divi_swap::api::Offer],
) -> Result<(Arc<dyn ChainBackend>, Vec<String>)> {
    let hex_key = divi_swap::secrets::SecretRef::parse(&cfg.key)
        .and_then(|r| r.resolve())
        .map_err(|e| anyhow::anyhow!("usdc key: {e}"))?;
    let key: swap_chain_evm::PrivateKeySigner = hex_key
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("usdc key is not a valid secp256k1 hex key"))?;
    drop(hex_key);
    let htlc = cfg
        .htlc
        .parse()
        .map_err(|e| anyhow::anyhow!("usdc htlc address: {e}"))?;
    let rpc_url = cfg.rpc_url()?;
    let token_str = cfg.token()?;
    let token = token_str
        .parse()
        .map_err(|e| anyhow::anyhow!("usdc token address: {e}"))?;
    let address = key.address();
    let backend = swap_chain_evm::UsdcBackend::new(&rpc_url, key, htlc, token)?
        .with_min_lock_gas_wei(MIN_MAKER_ETH_WEI);
    let (eth_wei, usdc_units) = backend
        .gas_and_token_balance()
        .await
        .map_err(|e| anyhow::anyhow!("usdc balance check: {e}"))?;
    tracing::info!(
        %address, network = %cfg.network, mainnet = cfg.network()?.is_mainnet(), htlc = %cfg.htlc, token = %token_str,
        %eth_wei, %usdc_units, "usdc backend ready"
    );
    let mut underfunded = Vec::new();
    for o in offers.iter().filter(|o| o.counter_chain == Chain::Usdc) {
        if !swap_chain_evm::usdc_offer_is_fundable(
            o.direction,
            eth_wei,
            usdc_units,
            MIN_MAKER_ETH_WEI,
            MIN_MAKER_USDC_UNITS,
        ) {
            tracing::warn!(
                offer = %o.id, %eth_wei, %usdc_units,
                "usdc offer is enabled but the maker's balance is below the floor \
                 (need >= 0.01 ETH, and >= 10 USDC to sell USDC); not serving it until funded"
            );
            underfunded.push(o.id.clone());
        }
    }
    Ok((Arc::new(backend), underfunded))
}

fn live_zec(cfg: &ZecSection, reservations: &InputReservations) -> Result<Arc<dyn ChainBackend>> {
    let key = resolve_key(&cfg.key, "zec")?;
    let endpoints = cfg.endpoints()?;
    let backend = ZecBackend::new(
        endpoints,
        key,
        ZecFeePolicy::default(),
        ZecRetryPolicy::default(),
    )?
    .with_network(&cfg.network)?
    .with_input_reservations(reservations.clone());
    tracing::info!(
        address = %backend.encoded_address(), network = %cfg.network, "zec backend ready"
    );
    Ok(Arc::new(backend))
}

async fn live_backends(
    cfg: &DaemonConfig,
    in_flight: &BTreeSet<Chain>,
) -> Result<(Backends, Option<ScanJob>, Vec<divi_swap::api::Offer>)> {
    let (Some(divi_cfg), Some(btc_cfg)) = (&cfg.divi, &cfg.btc) else {
        bail!("live backend needs both [divi] and [btc] sections");
    };
    // BTC, LTC and ZEC select coins from a live address query, and the DIVI wallet file
    // tombstones a lock's inputs only in the process that broadcast it; this table keeps the
    // inputs of a broadcast lock out of the next swap's selection, in every process on this
    // database, until the lock confirms.
    let reservations =
        InputReservations::open(&cfg.db_path).context("opening input reservations")?;
    let mut others: Vec<Arc<dyn ChainBackend>> = Vec::new();
    let mut underfunded_offers: Vec<String> = Vec::new();
    for c in cfg.counter_backends_to_start(in_flight)? {
        others.push(match c {
            Chain::Ltc => {
                live_ltc(cfg.ltc.as_ref().expect("checked by config"), &reservations).await?
            }
            Chain::Usdc => {
                let (backend, underfunded) =
                    live_usdc(cfg.usdc.as_ref().expect("checked by config"), &cfg.offers).await?;
                underfunded_offers.extend(underfunded);
                backend
            }
            Chain::Zec => live_zec(cfg.zec.as_ref().expect("checked by config"), &reservations)?,
            other => bail!("no live {other} backend in this build"),
        });
    }
    for (c, present) in [
        (Chain::Ltc, cfg.ltc.is_some()),
        (Chain::Usdc, cfg.usdc.is_some()),
        (Chain::Zec, cfg.zec.is_some()),
    ] {
        if present && !others.iter().any(|b| b.chain() == c) {
            tracing::info!(%c, "no enabled {c} offer and no {c} swap in flight; not starting the [{c}] backend");
        }
    }
    if !cfg.disabled_offers.is_empty() {
        tracing::info!(offers = ?cfg.disabled_offers, "offers disabled in config");
    }
    // Adaptor-swap offers run on their own engine (`live_xmr_engine`), not a ChainBackend.
    let known: Vec<Chain> = std::iter::once(Chain::Btc)
        .chain(others.iter().map(|b| b.chain()))
        .collect();
    if let Some(o) = cfg
        .offers
        .iter()
        .find(|o| !o.counter_chain.is_adaptor() && !known.contains(&o.counter_chain))
    {
        bail!(
            "offer {}: no live {} backend in this build yet (add a [{}] section, or use --backend mock)",
            o.id,
            o.counter_chain,
            o.counter_chain
        );
    }
    let btc = live_btc(btc_cfg, &reservations)?;
    let key = resolve_divi_key(&divi_cfg.key, "divi")?;
    let divi = Arc::new(live_divi(divi_cfg, key, &reservations)?);
    let job = divi_cfg.scan_from_height.map(|from| ScanJob {
        divi: divi.clone(),
        from,
    });
    let backends = Backends { divi, btc, others };
    let offers = cfg
        .offers
        .iter()
        .filter(|o| !underfunded_offers.contains(&o.id))
        .cloned()
        .collect();
    Ok((backends, job, offers))
}

/// The live DIVI backend of `[divi]` for `key`, reserving the inputs of its locks in
/// `reservations` so a second daemon on the same wallet file and database never funds from
/// them.
fn live_divi(
    cfg: &divi_swapd::config::DiviSection,
    key: divi_crypto::keys::SecretKey,
    reservations: &InputReservations,
) -> Result<DiviBackend> {
    let network = cfg.network()?;
    let mut divi = DiviBackend::new(
        &cfg.rpc_url()?,
        key,
        network,
        DiviFeePolicy::default(),
        cfg.wallet_path.clone(),
    )?
    .with_input_reservations(reservations.clone());
    if let Some(fallback) = cfg.fallback_rpc_url()? {
        divi = divi.with_fallback_rpc(&fallback);
        tracing::info!(
            "divi second source enabled: swap reads on two endpoints, disagreement is transient"
        );
    }
    tracing::info!(address = %divi.address(), network = ?network, "divi backend ready");
    Ok(divi)
}

/// One pass of the lock-expiry sweep over `counters` and the DIVI backend `divi` at
/// wall-clock `now` (unix seconds): a maker lock past its deadline that a fresh backend has
/// found in no mempool and no block on two checks [`divi_swap::reservation::EXPIRY_ABSENT_BLOCKS`]
/// blocks apart gives its inputs back to the wallet ([`InputReservations::release_expired`];
/// on DIVI the wallet file gets them back too, on the backend's own proof, through
/// [`InputReservations::release_expired_swaps_and_bookings`]). A DIVI lock of a finished swap
/// is released first ([`InputReservations::release_finished_swaps`]). `divi_start` is
/// `[divi].expiry_start`: with `"mtp"` every DIVI count waits for the node's median time past
/// ([`InputReservations::release_expired_from`]); the counter chains always use the default.
/// A chain that cannot be
/// asked, or whose backend is stale or went backwards, keeps its reservations this pass
/// (`--release-reservation` stays the manual override). Returns how many inputs were released.
async fn expiry_sweep_once(
    res: &InputReservations,
    store: &Store,
    divi: &dyn ChainBackend,
    counters: &[Arc<dyn ChainBackend>],
    now: u32,
    divi_start: ExpiryStart,
) -> usize {
    let mut expired = 0;
    for b in counters {
        match res.release_expired_swaps(store, b.as_ref(), now).await {
            Ok(n) => expired += n,
            Err(e) => {
                tracing::warn!(chain = %b.chain(), error = %e, "could not check locks for expiry")
            }
        }
    }
    let finished = match res.release_finished_swaps(store, Chain::Divi) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "could not release finished DIVI lock inputs");
            0
        }
    };
    if finished > 0 {
        tracing::info!(finished, "released the DIVI lock inputs of finished swaps");
    }
    match res
        .release_expired_swaps_and_bookings(store, divi, now, divi_start)
        .await
    {
        Ok(n) => expired += n,
        Err(e) => {
            tracing::warn!(chain = %Chain::Divi, error = %e, "could not check locks for expiry")
        }
    }
    if expired > 0 {
        tracing::info!(
            released = expired,
            "released the inputs of dropped locks past their deadline"
        );
    }
    finished + expired
}

/// The live daemon's lock-expiry sweep: [`expiry_sweep_once`] every `every`.
fn spawn_expiry_sweep(
    cfg: &DaemonConfig,
    store: Store,
    divi: Arc<dyn ChainBackend>,
    counters: Vec<Arc<dyn ChainBackend>>,
    every: Duration,
) -> Result<tokio::task::JoinHandle<()>> {
    let res = InputReservations::open(&cfg.db_path).context("opening input reservations")?;
    let divi_start = cfg.divi_expiry_start()?;
    Ok(tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs().min(u32::MAX as u64) as u32);
            expiry_sweep_once(&res, &store, divi.as_ref(), &counters, now, divi_start).await;
        }
    }))
}

/// `--xmr-inflight`: the in-flight XMR swaps in `db_path`, as the lines documented on `Args`.
/// The store must already exist: a wrong path is an error, never an empty store.
/// With `lock_txids`, each swap line gets a third field: the reported XMR lock txid, or `-`.
fn xmr_inflight_report(cfg: &DaemonConfig, lock_txids: bool) -> Result<String> {
    let store = Store::open_read_only(&cfg.db_path)
        .with_context(|| format!("opening swap database {}", cfg.db_path.display()))?;
    let open = divi_swap_xmr::XmrMaker::in_flight_locks(&store)?;
    let mut out = format!(
        "xmr_configured {}\nin_flight {}\n",
        if cfg.xmr.is_some() { "yes" } else { "no" },
        open.len()
    );
    for (id, state, txid) in open {
        let state = serde_json::to_value(state)?;
        out.push_str(&format!("{id} {}", state.as_str().unwrap_or("?")));
        if lock_txids {
            out.push_str(&format!(" {}", txid.as_deref().unwrap_or("-")));
        }
        out.push('\n');
    }
    Ok(out)
}

/// The swap in `store` that broadcast `txid` on `chain`: `(id, state, terminal)`. Maker swaps
/// are matched on their maker-leg funding tx, taker swaps on their taker-leg funding tx;
/// `terminal` is the swap state's own `is_terminal`.
fn swap_for_txid(
    store: &Store,
    chain: Chain,
    txid: &divi_swap::Txid,
) -> Result<Option<(String, String, bool)>> {
    // Every swap has a leg on DIVI and one on its counter chain; a txid names one lock.
    let on = |q: &divi_swap::api::Quote| chain == Chain::Divi || q.counter_chain == chain;
    for s in store.list_maker_swaps()? {
        if on(&s.quote) && s.maker_leg_funding.as_ref().map(|f| f.tx.txid) == Some(*txid) {
            let state = serde_json::to_value(s.state)?;
            return Ok(Some((
                s.id,
                state.as_str().unwrap_or("?").to_string(),
                s.state.is_terminal(),
            )));
        }
    }
    for s in store.list_taker_swaps()? {
        if on(&s.quote) && s.taker_leg_funding.as_ref().map(|f| f.tx.txid) == Some(*txid) {
            let state = serde_json::to_value(s.state)?;
            return Ok(Some((
                s.id,
                state.as_str().unwrap_or("?").to_string(),
                s.state.is_terminal(),
            )));
        }
    }
    Ok(None)
}

/// `--reservations`: every reserved input, as the lines documented on `Args`. Read-only.
fn reservations_report(cfg: &DaemonConfig) -> Result<String> {
    let store = Store::open_read_only(&cfg.db_path)
        .with_context(|| format!("opening swap database {}", cfg.db_path.display()))?;
    let rows = InputReservations::open_read_only(&cfg.db_path)
        .context("opening input reservations")?
        .list_all()?;
    let mut out = format!("reservations {}\n", rows.len());
    for r in rows {
        let (id, state) = match swap_for_txid(&store, r.chain, &r.reserved_by)? {
            Some((id, state, _)) => (id, state),
            None => ("unknown".to_string(), "unknown".to_string()),
        };
        out.push_str(&format!(
            "{}\t{}:{}\t{}\t{}\t{}\n",
            r.chain,
            r.input.txid.to_rpc_hex(),
            r.input.vout,
            r.reserved_by.to_rpc_hex(),
            tsv_escape(&id),
            state
        ));
    }
    Ok(out)
}

/// Result of `--release-reservation`: what to print, and whether anything was released.
struct ReleaseOutcome {
    text: String,
    released: bool,
}

/// `--release-reservation <txid> --chain <c> [--yes]`. Refuses (an error) when the swap that
/// broadcast `txid` is not terminal, when nothing is reserved for it, or (with `yes`) when
/// another connection has the database open. Without `yes` it writes nothing. The swap state
/// is read before the exclusive lock is taken (the lock cannot coexist with a reader); with
/// the lock held no daemon can run, and a terminal swap never leaves its state.
fn release_reservation(
    cfg: &DaemonConfig,
    chain: Chain,
    txid_hex: &str,
    yes: bool,
) -> Result<ReleaseOutcome> {
    let txid = divi_swap::Txid::from_rpc_hex(txid_hex)
        .map_err(|e| anyhow::anyhow!("not a txid ({txid_hex:?}): {e}"))?;
    let (held, swap) = {
        let store = Store::open_read_only(&cfg.db_path)
            .with_context(|| format!("opening swap database {}", cfg.db_path.display()))?;
        let rows = InputReservations::open_read_only(&cfg.db_path)
            .context("opening input reservations")?
            .list_all()?;
        let held = rows
            .iter()
            .filter(|r| r.chain == chain && r.reserved_by == txid)
            .count();
        (held, swap_for_txid(&store, chain, &txid)?)
    };
    if held == 0 {
        bail!("no {chain} input is reserved by {txid}: nothing to release");
    }
    let who = match &swap {
        Some((id, state, terminal)) => {
            if !*terminal {
                bail!(
                    "refusing: swap {id} that broadcast {txid} is {state}, not terminal; its lock \
                     may still confirm or be rebroadcast"
                );
            }
            format!("swap {id} ({state}, terminal)")
        }
        None => "no swap row names it (orphan)".to_string(),
    };
    if !yes {
        return Ok(ReleaseOutcome {
            text: format!(
                "would release {held} {chain} input(s) reserved by {txid}: {who}\n\
                 first check that {txid} is in no mempool and no block; re-run with --yes to release\n"
            ),
            released: false,
        });
    }
    let res = InputReservations::open_exclusive(&cfg.db_path).context("taking the database")?;
    let n = res.release_tx(chain, &txid)?;
    Ok(ReleaseOutcome {
        text: format!("released {n} {chain} input(s) reserved by {txid}: {who}\n"),
        released: true,
    })
}

/// Escape a field of an `--xmr-watch` line so it cannot add a column or a line.
fn tsv_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

/// `--xmr-inflight --xmr-watch`: the header lines of `xmr_inflight_report`, then one
/// `<id>\t<state>\t<t_punish|->\t<last_error>` line per non-terminal swap. Opens the store
/// read-only, like `xmr_inflight_report`.
fn xmr_watch_report(cfg: &DaemonConfig) -> Result<String> {
    let store = Store::open_read_only(&cfg.db_path)
        .with_context(|| format!("opening swap database {}", cfg.db_path.display()))?;
    let open = divi_swap_xmr::XmrMaker::in_flight_watch(&store)?;
    let mut out = format!(
        "xmr_configured {}\nin_flight {}\n",
        if cfg.xmr.is_some() { "yes" } else { "no" },
        open.len()
    );
    for w in open {
        let state = serde_json::to_value(w.state)?;
        let t_punish = w
            .t_punish
            .map_or_else(|| "-".to_string(), |t| t.to_string());
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            tsv_escape(&w.id),
            state.as_str().unwrap_or("?"),
            t_punish,
            tsv_escape(w.last_error.as_deref().unwrap_or(""))
        ));
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.xmr_inflight {
        // Before the log subscriber: its default writer is stdout, which scripts parse.
        let cfg = DaemonConfig::load(&args.config)?;
        print!(
            "{}",
            if args.xmr_watch {
                xmr_watch_report(&cfg)?
            } else {
                xmr_inflight_report(&cfg, args.xmr_lock_txids)?
            }
        );
        return Ok(());
    }
    if args.reservations {
        let cfg = DaemonConfig::load(&args.config)?;
        print!("{}", reservations_report(&cfg)?);
        return Ok(());
    }
    if let (Some(txid), Some(chain)) = (&args.release_reservation, args.chain) {
        let cfg = DaemonConfig::load(&args.config)?;
        let out = release_reservation(&cfg, chain, txid, args.yes)?;
        print!("{}", out.text);
        if !out.released {
            std::process::exit(2);
        }
        return Ok(());
    }
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
    let store = Store::open(&cfg.db_path).context("opening swap database")?;
    // Counter chains of swaps still under way: their backends start even if every offer on
    // that chain has since been switched off.
    let in_flight: BTreeSet<Chain> = store
        .list_maker_swaps()?
        .iter()
        .filter(|s| !s.state.is_terminal())
        .map(|s| s.quote.counter_chain)
        .collect();
    let (backends, scan_job, offers) = match kind {
        BackendKind::Mock => (mock_backends(), None, mock_offers(&cfg)),
        BackendKind::Live => live_backends(&cfg, &in_flight).await?,
    };
    let Backends { divi, btc, others } = backends;
    let scan = if scan_job.is_some() {
        ScanStatus::scanning()
    } else {
        ScanStatus::done()
    };

    // XMR offers run on the adaptor engine; the rest on the hashlock maker.
    let (xmr_offers, offers): (Vec<_>, Vec<_>) = offers
        .into_iter()
        .partition(|o| o.counter_chain.is_adaptor());
    let xmr = match kind {
        BackendKind::Mock => (!xmr_offers.is_empty())
            .then(|| mock_xmr_engine(store.clone(), xmr_offers))
            .transpose()?,
        BackendKind::Live => {
            let open = divi_swap_xmr::XmrMaker::open_swaps(&store)?;
            if cfg.xmr_engine_needed(open)? {
                let xs = cfg.xmr.as_ref().expect("checked by xmr_engine_needed");
                Some(live_xmr_engine(&cfg, xs, store.clone(), xmr_offers).await?)
            } else {
                if cfg.xmr.is_some() {
                    tracing::info!("no enabled xmr offer and no xmr swap in flight; not starting the [xmr] engine");
                }
                None
            }
        }
    };
    let hashlock_auth = HashlockAuth::new(store.clone())
        .with_operator_token(cfg.operator_token()?)
        .allow_tokenless(cfg.allow_tokenless_swaps);
    let counters: Vec<Arc<dyn ChainBackend>> = std::iter::once(btc.clone()).chain(others).collect();
    let _expiry = match kind {
        BackendKind::Mock => None,
        BackendKind::Live => Some(spawn_expiry_sweep(
            &cfg,
            store.clone(),
            divi.clone(),
            counters.clone(),
            Duration::from_secs(cfg.tick_secs),
        )?),
    };
    let mut maker =
        Maker::with_counters(cfg.swap_config()?, divi.clone(), counters, store, offers)?;
    maker = with_claim_fees(maker, &args)?;
    if let Some(x) = &xmr {
        maker = maker.with_engine(x.clone())?;
    }
    let maker = Arc::new(maker);
    let _scheduler = spawn_gated_scheduler(
        maker.clone(),
        Duration::from_secs(cfg.tick_secs),
        scan.clone(),
    );

    let app = router_with_auth(
        AppState {
            maker,
            divi,
            btc,
            scan: scan.clone(),
        },
        xmr,
        &cfg.prefix(),
        cfg.trust_proxy_headers,
        hashlock_auth,
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    tracing::info!(
        listen = %cfg.listen, backend = ?kind,
        swap_listing = cfg.operator_token_file.is_some(),
        tokenless_swaps = cfg.allow_tokenless_swaps,
        "divi-swapd up"
    );
    if let Some(job) = scan_job {
        tokio::spawn(async move {
            run_scan(&*job.divi, job.from, &scan, SCAN_CHUNK, SCAN_RETRY).await;
        });
    }
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::network::TransactionBuilder;
    use alloy::primitives::U256;
    use alloy::providers::Provider;
    use alloy::rpc::types::TransactionRequest;
    use divi_swap::api::{Direction, Offer};

    /// A maker on mock backends for every counter chain, with `flags` applied.
    fn maker_with_flags(flags: &[&str]) -> Result<Maker> {
        let argv = ["divi-swapd", "--config", "c"].iter().chain(flags);
        let args = Args::try_parse_from(argv)?;
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("swaps.db"))?;
        let divi = MockChain::new(Chain::Divi, 1_700_000_000, 60);
        let counters = [Chain::Btc, Chain::Ltc, Chain::Zec, Chain::Usdc]
            .into_iter()
            .zip(2u8..)
            .map(|(c, seed)| {
                Arc::new(MockChain::new(c, 1_700_000_000, 600).backend(seed, Amount(0)))
                    as Arc<dyn ChainBackend>
            })
            .collect();
        let maker = Maker::with_counters(
            divi_swap::SwapConfig::profile(divi_swap::Profile::Testnet),
            Arc::new(divi.backend(1, Amount(0))),
            counters,
            store,
            Vec::new(),
        )?;
        with_claim_fees(maker, &args)
    }

    #[test]
    fn claim_fee_flags_reach_the_makers_taker_leg_claims() {
        let builtin = |c| divi_swap::FeeEscalation::builtin(c).unwrap();
        let plain = maker_with_flags(&[]).unwrap();
        for c in [Chain::Btc, Chain::Ltc, Chain::Usdc] {
            assert_eq!(plain.fee_escalation(c), Some(builtin(c)), "{c}");
        }
        let maker = maker_with_flags(&[
            "--claim-fee-cap",
            "btc=77",
            "--claim-fee-cap",
            "usdc=900000000000",
            "--claim-price-bump",
            "usdc=25",
        ])
        .unwrap();
        let btc = maker.fee_escalation(Chain::Btc).unwrap();
        assert_eq!(btc.cap_feerate, 77);
        assert_eq!(btc, builtin(Chain::Btc).with_cap_feerate(77));
        let usdc = maker.fee_escalation(Chain::Usdc).unwrap();
        assert_eq!(usdc.cap_feerate, 900_000_000_000);
        assert_eq!(usdc.price_bump_pct, 25);
        // Unnamed chains keep their builtin.
        assert_eq!(maker.fee_escalation(Chain::Ltc), Some(builtin(Chain::Ltc)));
        assert_eq!(maker.fee_escalation(Chain::Zec), None);
        // A chain whose claims cannot be bumped is refused, not ignored.
        let err = maker_with_flags(&["--claim-fee-cap", "zec=5"])
            .err()
            .expect("zec refused");
        assert!(err.to_string().contains("zec"), "{err}");
        assert!(maker_with_flags(&["--claim-price-bump", "btc"]).is_err());
    }

    fn offer(id: &str, direction: Direction) -> Offer {
        Offer {
            id: id.into(),
            direction,
            counter_chain: Chain::Usdc,
            divi_sats_per_btc: 1,
            min_btc_sats: 1,
            max_btc_sats: 2,
        }
    }

    /// `live_usdc` end to end against anvil: builds the real backend from a `[usdc]`
    /// section (RPC URL, HTLC address, token — read exactly the way a deployed config
    /// would supply them) and confirms it serves an enabled offer that only needs gas
    /// (`divi-usdc-sepolia`, the maker sells DIVI it already holds) while refusing one
    /// that also needs USDC collateral the maker does not hold (`usdc-divi-sepolia`).
    #[tokio::test]
    async fn live_usdc_excludes_an_enabled_but_underfunded_offer() {
        if !swap_chain_evm::foundry_available() {
            eprintln!("skipping: forge/anvil not found on PATH");
            return;
        }
        let anvil = alloy::node_bindings::Anvil::new().spawn();
        let endpoint = anvil.endpoint();

        let deployer = swap_chain_evm::PrivateKeySigner::from(&anvil.keys()[0]);
        let maker_key = swap_chain_evm::PrivateKeySigner::random();
        let maker_hex = hex::encode(maker_key.to_bytes());
        let maker_addr = maker_key.address();

        let deploy_provider =
            swap_chain_evm::connect_provider(&endpoint, deployer).expect("deploy provider");
        let htlc = swap_chain_evm::deploy_contract(
            &deploy_provider,
            swap_chain_evm::erc20_htlc_bytecode(),
        )
        .await
        .expect("deploy htlc");
        let token = swap_chain_evm::deploy_contract(
            &deploy_provider,
            swap_chain_evm::bytecode("MockErc20").expect("build MockErc20"),
        )
        .await
        .expect("deploy token");

        // Enough gas to meet MIN_MAKER_ETH_WEI, but no USDC at all: forward must still be
        // servable, reverse must not.
        deploy_provider
            .send_transaction(
                TransactionRequest::default()
                    .with_to(maker_addr)
                    .with_value(U256::from(MIN_MAKER_ETH_WEI)),
            )
            .await
            .expect("fund maker gas")
            .get_receipt()
            .await
            .expect("fund maker gas receipt");

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test-maker-usdc"), &maker_hex).unwrap();
        // SAFETY: this is the only test in this binary that reads or sets
        // CREDENTIALS_DIRECTORY, so there is no cross-test race on the process environment.
        unsafe {
            std::env::set_var("CREDENTIALS_DIRECTORY", dir.path());
        }

        let cfg = divi_swapd::UsdcSection {
            network: "sepolia".into(),
            allow_mainnet: false,
            rpc_url: Some(endpoint.clone()),
            htlc: format!("{htlc}"),
            token: Some(format!("{token}")),
            key: "credential:test-maker-usdc".into(),
        };
        let offers = vec![
            offer("divi-usdc-sepolia", Direction::TakerPaysBtc),
            offer("usdc-divi-sepolia", Direction::TakerPaysDivi),
        ];

        let (_backend, underfunded) = live_usdc(&cfg, &offers).await.expect("live_usdc");
        unsafe {
            std::env::remove_var("CREDENTIALS_DIRECTORY");
        }
        assert_eq!(underfunded, vec!["usdc-divi-sepolia".to_string()]);
    }

    fn inflight_cfg(db: &std::path::Path, xmr: bool) -> DaemonConfig {
        let mut text = format!("db_path = \"{}\"\n", db.display());
        if xmr {
            text.push_str(
                "[xmr]\nmonerod_url = \"http://127.0.0.1:38081\"\n\
                 wallet_rpc_url = \"http://127.0.0.1:38088\"\nwallet_rpc_user = \"swap\"\n\
                 wallet_rpc_password = \"credential:maker-xmr-wallet-rpc\"\n\
                 sweep_address = \"5Aaaa\"\ndivi_key = \"credential:maker-divi-xmr\"\n\
                 divi_fund_txids = [\"ab\"]\n",
            );
        }
        DaemonConfig::parse(&text).unwrap()
    }

    fn put_xmr(store: &Store, id: &str, state: &str) {
        let doc = serde_json::json!({ "id": id, "state": state, "extra": "ignored" });
        store.put_doc(divi_swap_xmr::maker::KIND, id, &doc).unwrap();
    }

    #[test]
    fn xmr_inflight_lists_only_non_terminal_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        put_xmr(&store, "d", "done");
        put_xmr(&store, "a", "aborted");
        put_xmr(&store, "p", "punished");
        put_xmr(&store, "l", "locked");
        put_xmr(&store, "c", "cancelled");
        let out = xmr_inflight_report(&inflight_cfg(&db, true), false).unwrap();
        let mut lines: Vec<&str> = out.lines().collect();
        assert_eq!(&lines[..2], ["xmr_configured yes", "in_flight 2"]);
        lines.drain(..2);
        lines.sort();
        assert_eq!(lines, ["c cancelled", "l locked"]);
    }

    #[test]
    fn xmr_inflight_lock_txids_appends_a_third_field_and_changes_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        put_xmr(&store, "a", "accepted");
        let doc = serde_json::json!({ "id": "x", "state": "xmr_reported", "xmr_txid": "ab12" });
        store
            .put_doc(divi_swap_xmr::maker::KIND, "x", &doc)
            .unwrap();
        put_xmr(&store, "d", "done");
        let plain = xmr_inflight_report(&inflight_cfg(&db, true), false).unwrap();
        let with = xmr_inflight_report(&inflight_cfg(&db, true), true).unwrap();
        let mut plain_lines: Vec<&str> = plain.lines().collect();
        let mut with_lines: Vec<&str> = with.lines().collect();
        assert_eq!(&with_lines[..2], &plain_lines[..2]);
        plain_lines.drain(..2);
        with_lines.drain(..2);
        plain_lines.sort();
        with_lines.sort();
        assert_eq!(plain_lines, ["a accepted", "x xmr_reported"]);
        assert_eq!(with_lines, ["a accepted -", "x xmr_reported ab12"]);
    }

    fn put_xmr_watch(
        store: &Store,
        id: &str,
        state: &str,
        t_punish: Option<u32>,
        err: Option<&str>,
    ) {
        let doc = serde_json::json!({
            "id": id, "state": state, "t_punish": t_punish, "last_error": err, "extra": "ignored"
        });
        store.put_doc(divi_swap_xmr::maker::KIND, id, &doc).unwrap();
    }

    #[test]
    fn xmr_watch_prints_four_fields_for_every_non_terminal_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        put_xmr_watch(&store, "d", "done", Some(1), None);
        put_xmr_watch(&store, "a", "aborted", Some(1), None);
        put_xmr_watch(&store, "p", "punished", Some(1), None);
        put_xmr_watch(&store, "c", "cancelled", Some(1_700_000_000), None);
        put_xmr_watch(&store, "r", "refunded", Some(1_700_000_500), Some("boom"));
        put_xmr_watch(&store, "n", "locked", None, None);
        let out = xmr_watch_report(&inflight_cfg(&db, true)).unwrap();
        let mut lines: Vec<&str> = out.lines().collect();
        assert_eq!(&lines[..2], ["xmr_configured yes", "in_flight 3"]);
        lines.drain(..2);
        lines.sort();
        assert_eq!(
            lines,
            [
                "c\tcancelled\t1700000000\t",
                "n\tlocked\t-\t",
                "r\trefunded\t1700000500\tboom"
            ]
        );
    }

    #[test]
    fn xmr_watch_escapes_tabs_and_newlines_in_last_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        put_xmr_watch(&store, "e", "locked", Some(5), Some("a\tb\nc\r\\d"));
        let out = xmr_watch_report(&inflight_cfg(&db, true)).unwrap();
        assert_eq!(
            out,
            "xmr_configured yes\nin_flight 1\ne\tlocked\t5\ta\\tb\\nc\\r\\\\d\n"
        );
        assert_eq!(out.lines().count(), 3, "an error never adds a line");
    }

    #[test]
    fn xmr_watch_leaves_default_output_unchanged_and_needs_xmr_inflight() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        put_xmr_watch(&store, "c", "cancelled", Some(9), Some("x"));
        let cfg = inflight_cfg(&db, true);
        assert_eq!(
            xmr_inflight_report(&cfg, false).unwrap(),
            "xmr_configured yes\nin_flight 1\nc cancelled\n"
        );
        assert_eq!(
            xmr_inflight_report(&cfg, true).unwrap(),
            "xmr_configured yes\nin_flight 1\nc cancelled -\n"
        );
        assert!(Args::try_parse_from(["divi-swapd", "--config", "c", "--xmr-watch"]).is_err());
        assert!(Args::try_parse_from([
            "divi-swapd",
            "--config",
            "c",
            "--xmr-inflight",
            "--xmr-watch",
            "--xmr-lock-txids"
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "divi-swapd",
            "--config",
            "c",
            "--xmr-inflight",
            "--xmr-watch"
        ])
        .is_ok());
    }

    #[test]
    fn xmr_watch_missing_store_is_an_error_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("typo.db");
        assert!(xmr_watch_report(&inflight_cfg(&db, true)).is_err());
        assert!(!db.exists());
    }

    #[test]
    fn xmr_lock_txids_requires_xmr_inflight() {
        assert!(Args::try_parse_from(["divi-swapd", "--config", "c", "--xmr-lock-txids"]).is_err());
        assert!(Args::try_parse_from([
            "divi-swapd",
            "--config",
            "c",
            "--xmr-inflight",
            "--xmr-lock-txids"
        ])
        .is_ok());
    }

    #[test]
    fn xmr_inflight_all_terminal_and_empty_store_report_zero() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        assert_eq!(
            xmr_inflight_report(&inflight_cfg(&db, true), false).unwrap(),
            "xmr_configured yes\nin_flight 0\n"
        );
        put_xmr(&store, "d", "done");
        put_xmr(&store, "p", "punished");
        assert_eq!(
            xmr_inflight_report(&inflight_cfg(&db, true), false).unwrap(),
            "xmr_configured yes\nin_flight 0\n"
        );
    }

    #[test]
    fn xmr_inflight_without_xmr_config_still_reads_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        assert_eq!(
            xmr_inflight_report(&inflight_cfg(&db, false), false).unwrap(),
            "xmr_configured no\nin_flight 0\n"
        );
        // A leftover swap with the section removed is still reported (the daemon refuses to
        // start in that state; the redeploy gate must not call it clean).
        put_xmr(&store, "x", "xmr_reported");
        assert_eq!(
            xmr_inflight_report(&inflight_cfg(&db, false), false).unwrap(),
            "xmr_configured no\nin_flight 1\nx xmr_reported\n"
        );
    }

    #[test]
    fn xmr_inflight_missing_store_is_an_error_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("typo.db");
        assert!(xmr_inflight_report(&inflight_cfg(&db, true), false).is_err());
        assert!(!db.exists(), "a read must never create the store");
    }

    #[test]
    fn xmr_inflight_does_not_write_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        put_xmr(&store, "l", "locked");
        let ro = Store::open_read_only(&db).unwrap();
        assert!(ro.put_doc("k", "i", &1u8).is_err(), "read-only handle");
        assert_eq!(divi_swap_xmr::XmrMaker::in_flight(&ro).unwrap().len(), 1);
    }

    // ---- --reservations / --release-reservation ----

    fn op(n: u8, vout: u32) -> divi_swap::Outpoint {
        divi_swap::Outpoint {
            txid: divi_swap::Txid([n; 32]),
            vout,
        }
    }

    /// A maker swap in `state` whose maker-leg lock on BTC is the tx `lock`.
    fn lock_swap(id: &str, state: divi_swap::SwapState, lock: u8) -> divi_swap::store::MakerRecord {
        let htlc = divi_swap::HtlcParams {
            hash: [1; 32],
            claim_pubkey: [2; 33],
            refund_pubkey: [3; 33],
            locktime: 1_800_000_000,
            script_version: Default::default(),
        };
        divi_swap::store::MakerRecord {
            id: id.into(),
            created_at: 10,
            state,
            quote: divi_swap::api::Quote {
                id: format!("q-{id}"),
                offer_id: "o".into(),
                direction: Direction::TakerPaysDivi,
                counter_chain: Chain::Btc,
                btc_amount: Amount(1),
                divi_amount: Amount(2),
                expires_at: 3,
                maker_btc_pubkey: [2; 33],
                maker_divi_pubkey: [3; 33],
                taker_timeout_secs: 4,
                maker_timeout_secs: 5,
                btc_confirmations: 1,
                divi_confirmations: 1,
            },
            hash: [lock; 32],
            taker_maker_leg_pubkey: [2; 33],
            taker_leg_htlc: htlc,
            taker_leg_outpoint: None,
            taker_leg_locked: None,
            maker_leg_htlc: Some(htlc),
            maker_leg_funding: Some(divi_swap::Funding {
                tx: divi_swap::SignedTx {
                    txid: divi_swap::Txid([lock; 32]),
                    raw: vec![],
                },
                outpoint: op(lock, 0),
                amount: Amount(1),
            }),
            maker_leg_scan_from: 0,
            maker_mtp_at_lock: None,
            maker_leg_refund: None,
            preimage: None,
            taker_leg_claim: None,
            last_error: None,
            maker_lock_dropped: false,
            claim_fees: Default::default(),
        }
    }

    /// A database with: swap `done` (lock 0x11, input 1:0 and 2:1), swap `live` (lock 0x22,
    /// input 3:0), and an orphan lock 0x33 (input 4:0) that no swap row names. All BTC.
    fn reserved_db(dir: &std::path::Path) -> std::path::PathBuf {
        let db = dir.join("swaps.db");
        let store = Store::open(&db).unwrap();
        store
            .put_maker_swap(&lock_swap("done", divi_swap::SwapState::Done, 0x11))
            .unwrap();
        store
            .put_maker_swap(&lock_swap("live", divi_swap::SwapState::MakerLocked, 0x22))
            .unwrap();
        let res = InputReservations::open(&db).unwrap();
        let t = |n: u8| divi_swap::Txid([n; 32]);
        res.reserve(Chain::Btc, &t(0x11), &[op(1, 0), op(2, 1)])
            .unwrap();
        res.reserve(Chain::Btc, &t(0x22), &[op(3, 0)]).unwrap();
        res.reserve(Chain::Btc, &t(0x33), &[op(4, 0)]).unwrap();
        db
    }

    fn hex_of(n: u8) -> String {
        divi_swap::Txid([n; 32]).to_rpc_hex()
    }

    #[tokio::test]
    async fn the_expiry_sweep_releases_a_dropped_lock_past_its_deadline_only() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        let deadline = lock_swap("x", divi_swap::SwapState::MakerLocked, 0)
            .maker_leg_htlc
            .unwrap()
            .locktime;
        let chain = MockChain::new(Chain::Btc, deadline - 1, 600);
        let wallet = chain.backend(9, Amount(Amount::COIN));
        // `dropped`'s lock (0x11) is in no mempool and no block; `pending`'s is broadcast.
        let dropped = lock_swap("dropped", divi_swap::SwapState::MakerLocked, 0x11);
        let mut pending = lock_swap("pending", divi_swap::SwapState::MakerLocked, 0x22);
        let f = wallet
            .build_funding(pending.maker_leg_htlc.as_ref().unwrap(), Amount(5_000))
            .await
            .unwrap();
        wallet.broadcast(&f.tx).await.unwrap();
        let pending_lock = f.tx.txid;
        pending.maker_leg_funding = Some(f);
        store.put_maker_swap(&dropped).unwrap();
        store.put_maker_swap(&pending).unwrap();
        let res = InputReservations::open(&db).unwrap();
        res.reserve(Chain::Btc, &divi_swap::Txid([0x11; 32]), &[op(1, 0)])
            .unwrap();
        res.reserve(Chain::Btc, &pending_lock, &[op(2, 0)]).unwrap();
        let held = || {
            let mut by: Vec<_> = res
                .list_all()
                .unwrap()
                .into_iter()
                .map(|r| r.reserved_by)
                .collect();
            by.sort_by_key(|t| t.0);
            by
        };
        let mut both = vec![divi_swap::Txid([0x11; 32]), pending_lock];
        both.sort_by_key(|t| t.0);
        let counters: Vec<Arc<dyn ChainBackend>> = vec![Arc::new(wallet)];
        // The wall clock at the chain's own: a fresh backend unless a test says otherwise.
        let divi = MockChain::new(Chain::Divi, deadline - 1, 60).backend(8, Amount(Amount::COIN));
        let sweep = |now: u32| {
            expiry_sweep_once(&res, &store, &divi, &counters, now, ExpiryStart::default())
        };

        assert_eq!(sweep(chain.mtp()).await, 0);
        assert_eq!(held(), both, "one second before the deadline");
        chain.set_offline(true);
        chain.advance_time(1);
        assert_eq!(sweep(chain.mtp()).await, 0);
        assert_eq!(
            held(),
            both,
            "a chain that cannot be asked keeps everything"
        );
        chain.set_offline(false);
        let first = chain.height();
        assert_eq!(sweep(chain.mtp()).await, 0, "the first absent check");
        assert_eq!(
            res.first_absent_height(Chain::Btc, &divi_swap::Txid([0x11; 32]))
                .unwrap(),
            Some(first)
        );
        assert_eq!(
            sweep(chain.mtp()).await,
            0,
            "a second tick at the same height"
        );
        chain.mine(divi_swap::reservation::EXPIRY_ABSENT_BLOCKS);
        assert_eq!(
            sweep(chain.mtp() + divi_swap::reservation::EXPIRY_MAX_TIP_AGE_SECS + 1).await,
            0,
            "a stale backend releases nothing"
        );
        assert_eq!(held(), both);
        assert_eq!(sweep(chain.mtp()).await, 1);
        assert_eq!(
            held(),
            vec![pending_lock],
            "the pending lock keeps its input"
        );
        assert_eq!(sweep(chain.mtp()).await, 0);
    }

    #[test]
    fn reservations_list_is_empty_on_a_store_with_and_without_the_table() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        Store::open(&db).unwrap();
        let cfg = inflight_cfg(&db, false);
        assert_eq!(reservations_report(&cfg).unwrap(), "reservations 0\n");
        InputReservations::open(&db).unwrap();
        assert_eq!(reservations_report(&cfg).unwrap(), "reservations 0\n");
        assert!(reservations_report(&inflight_cfg(&dir.path().join("nope.db"), false)).is_err());
    }

    #[test]
    fn reservations_list_names_the_swap_and_state_or_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        let out = reservations_report(&inflight_cfg(&db, false)).unwrap();
        let line = |input: u8, vout: u32, by: u8, id: &str, state: &str| {
            format!(
                "btc\t{}:{vout}\t{}\t{id}\t{state}\n",
                hex_of(input),
                hex_of(by)
            )
        };
        let mut want = String::from("reservations 4\n");
        for l in [
            line(1, 0, 0x11, "done", "Done"),
            line(2, 1, 0x11, "done", "Done"),
            line(3, 0, 0x22, "live", "MakerLocked"),
            line(4, 0, 0x33, "unknown", "unknown"),
        ] {
            want.push_str(&l);
        }
        // Rows come back ordered by reserving txid (internal-byte hex), then input.
        let mut got: Vec<&str> = out.lines().collect();
        let mut exp: Vec<&str> = want.lines().collect();
        got[1..].sort_unstable();
        exp[1..].sort_unstable();
        assert_eq!(got, exp, "{out}");
    }

    #[test]
    fn reservations_list_leaves_the_file_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        // Close the writers so the WAL is checkpointed into the main file first.
        let before = std::fs::read(&db).unwrap();
        let cfg = inflight_cfg(&db, false);
        reservations_report(&cfg).unwrap();
        reservations_report(&cfg).unwrap();
        assert_eq!(std::fs::read(&db).unwrap(), before);
    }

    #[test]
    fn release_is_refused_for_a_non_terminal_swap_even_with_yes() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        for yes in [false, true] {
            let err =
                release_reservation(&inflight_cfg(&db, false), Chain::Btc, &hex_of(0x22), yes)
                    .err()
                    .expect("must refuse");
            assert!(err.to_string().contains("not terminal"), "{err}");
        }
        assert_eq!(
            InputReservations::open(&db)
                .unwrap()
                .reserved(Chain::Btc)
                .unwrap()
                .len(),
            4
        );
    }

    /// A taker swap in `state` whose taker-leg funding on BTC is the tx `lock`.
    fn taker_lock_swap(
        id: &str,
        state: divi_swap::TakerState,
        lock: u8,
    ) -> divi_swap::store::TakerRecord {
        let m = lock_swap(id, divi_swap::SwapState::Done, lock);
        divi_swap::store::TakerRecord {
            id: id.into(),
            state,
            quote: m.quote,
            preimage: [9; 32],
            hash: m.hash,
            maker_swap_id: None,
            taker_leg_htlc: Some(m.taker_leg_htlc),
            taker_leg_funding: m.maker_leg_funding,
            maker_leg_htlc: None,
            maker_leg_outpoint: None,
            maker_leg_amount: None,
            maker_leg_claim: None,
            taker_leg_refund: None,
            claim_declined: None,
            claim_base_feerate: None,
            claim_feerate: None,
            claim_replaced: Vec::new(),
            claim_children: Vec::new(),
            claim_child_replaced: None,
            claim_underpriced: 0,
            last_error: None,
        }
    }

    /// A database with a finished taker swap (lock 0x51, input 5:0) and a refunded-but-not-done
    /// one (lock 0x52, input 6:0). All BTC.
    fn taker_reserved_db(dir: &std::path::Path) -> std::path::PathBuf {
        let db = dir.join("swaps.db");
        let store = Store::open(&db).unwrap();
        store
            .put_taker_swap(&taker_lock_swap("tdone", divi_swap::TakerState::Done, 0x51))
            .unwrap();
        store
            .put_taker_swap(&taker_lock_swap(
                "trefunded",
                divi_swap::TakerState::Refunded,
                0x52,
            ))
            .unwrap();
        let res = InputReservations::open(&db).unwrap();
        let t = |n: u8| divi_swap::Txid([n; 32]);
        res.reserve(Chain::Btc, &t(0x51), &[op(5, 0)]).unwrap();
        res.reserve(Chain::Btc, &t(0x52), &[op(6, 0)]).unwrap();
        db
    }

    #[test]
    fn release_is_refused_for_a_non_terminal_taker_swap_even_with_yes() {
        let dir = tempfile::tempdir().unwrap();
        let db = taker_reserved_db(dir.path());
        for yes in [false, true] {
            let err =
                release_reservation(&inflight_cfg(&db, false), Chain::Btc, &hex_of(0x52), yes)
                    .err()
                    .expect("must refuse");
            assert!(err.to_string().contains("not terminal"), "{err}");
        }
        assert_eq!(
            InputReservations::open(&db)
                .unwrap()
                .reserved(Chain::Btc)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_divi_leg_taker_lock_is_named_by_its_swap_and_refused_until_it_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        // `TakerPaysDivi` against BTC: the taker's lock is on DIVI.
        let mut s = taker_lock_swap("tdivi", divi_swap::TakerState::Locked, 0x55);
        assert_eq!(s.quote.taker_chain(), Chain::Divi);
        store.put_taker_swap(&s).unwrap();
        InputReservations::open(&db)
            .unwrap()
            .reserve(Chain::Divi, &divi_swap::Txid([0x55; 32]), &[op(9, 0)])
            .unwrap();
        let cfg = inflight_cfg(&db, false);
        let out = reservations_report(&cfg).unwrap();
        assert!(out.contains("\ttdivi\t"), "{out}");
        for yes in [false, true] {
            let err = release_reservation(&cfg, Chain::Divi, &hex_of(0x55), yes)
                .err()
                .expect("a live DIVI lock is not an orphan");
            assert!(err.to_string().contains("not terminal"), "{err}");
        }
        s.state = divi_swap::TakerState::Done;
        store.put_taker_swap(&s).unwrap();
        drop(store); // `--yes` needs the database to itself
        let out = release_reservation(&cfg, Chain::Divi, &hex_of(0x55), true).unwrap();
        assert!(out.released);
        assert!(
            out.text.contains("swap tdivi (done, terminal)"),
            "{}",
            out.text
        );
    }

    #[test]
    fn release_is_accepted_for_a_terminal_taker_swap() {
        let dir = tempfile::tempdir().unwrap();
        let db = taker_reserved_db(dir.path());
        let out = release_reservation(&inflight_cfg(&db, false), Chain::Btc, &hex_of(0x51), true)
            .unwrap();
        assert!(out.released);
        assert!(
            out.text.contains("swap tdone (done, terminal)"),
            "{}",
            out.text
        );
        let held = InputReservations::open(&db)
            .unwrap()
            .reserved(Chain::Btc)
            .unwrap();
        assert!(!held.contains(&op(5, 0)) && held.contains(&op(6, 0)));
    }

    #[test]
    fn a_lost_taker_swap_is_terminal_listed_as_lost_and_releasable() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        Store::open(&db)
            .unwrap()
            .put_taker_swap(&taker_lock_swap("tlost", divi_swap::TakerState::Lost, 0x53))
            .unwrap();
        InputReservations::open(&db)
            .unwrap()
            .reserve(Chain::Btc, &divi_swap::Txid([0x53; 32]), &[op(7, 0)])
            .unwrap();
        let cfg = inflight_cfg(&db, false);
        let out = reservations_report(&cfg).unwrap();
        assert!(out.contains("\ttlost\tlost\n"), "{out}");
        let out = release_reservation(&cfg, Chain::Btc, &hex_of(0x53), true).unwrap();
        assert!(out.released);
        assert!(
            out.text.contains("swap tlost (lost, terminal)"),
            "{}",
            out.text
        );
    }

    #[test]
    fn a_lost_maker_swap_is_terminal_listed_as_lost_and_releasable() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        Store::open(&db)
            .unwrap()
            .put_maker_swap(&lock_swap("mlost", divi_swap::SwapState::Lost, 0x54))
            .unwrap();
        InputReservations::open(&db)
            .unwrap()
            .reserve(Chain::Btc, &divi_swap::Txid([0x54; 32]), &[op(8, 0)])
            .unwrap();
        let cfg = inflight_cfg(&db, false);
        let out = reservations_report(&cfg).unwrap();
        assert!(out.contains("\tmlost\tLost\n"), "{out}");
        let out = release_reservation(&cfg, Chain::Btc, &hex_of(0x54), true).unwrap();
        assert!(out.released);
        assert!(
            out.text.contains("swap mlost (Lost, terminal)"),
            "{}",
            out.text
        );
    }

    #[test]
    fn reservations_list_shows_the_real_taker_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = taker_reserved_db(dir.path());
        let out = reservations_report(&inflight_cfg(&db, false)).unwrap();
        assert!(out.contains("\ttdone\tdone\n"), "{out}");
        assert!(out.contains("\ttrefunded\trefunded\n"), "{out}");
    }

    #[test]
    fn release_without_yes_prints_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        let out = release_reservation(&inflight_cfg(&db, false), Chain::Btc, &hex_of(0x11), false)
            .unwrap();
        assert!(!out.released);
        assert!(
            out.text.starts_with("would release 2 btc input(s)"),
            "{}",
            out.text
        );
        assert_eq!(
            InputReservations::open(&db)
                .unwrap()
                .reserved(Chain::Btc)
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn release_is_accepted_for_a_terminal_swap_and_the_inputs_are_selectable_again() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        let out = release_reservation(&inflight_cfg(&db, false), Chain::Btc, &hex_of(0x11), true)
            .unwrap();
        assert!(out.released);
        assert!(
            out.text.starts_with("released 2 btc input(s)"),
            "{}",
            out.text
        );
        let res = InputReservations::open(&db).unwrap();
        let held = res.reserved(Chain::Btc).unwrap();
        assert!(!held.contains(&op(1, 0)) && !held.contains(&op(2, 1)));
        assert_eq!(held.len(), 2, "the other locks keep theirs");
        // Another transaction can now take the released input.
        res.reserve(Chain::Btc, &divi_swap::Txid([0x44; 32]), &[op(1, 0)])
            .unwrap();
    }

    #[test]
    fn release_is_accepted_for_an_orphan_txid_and_scoped_to_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        // Same txid reserved on LTC too: a BTC release must leave it.
        InputReservations::open(&db)
            .unwrap()
            .reserve(Chain::Ltc, &divi_swap::Txid([0x33; 32]), &[op(9, 0)])
            .unwrap();
        let out = release_reservation(&inflight_cfg(&db, false), Chain::Btc, &hex_of(0x33), true)
            .unwrap();
        assert!(out.text.contains("no swap row names it"), "{}", out.text);
        let res = InputReservations::open(&db).unwrap();
        assert_eq!(res.reserved(Chain::Ltc).unwrap().len(), 1);
        assert_eq!(res.reserved(Chain::Btc).unwrap().len(), 3);
    }

    #[test]
    fn release_refuses_an_unreserved_or_malformed_txid() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        let cfg = inflight_cfg(&db, false);
        assert!(release_reservation(&cfg, Chain::Btc, &hex_of(0x99), true).is_err());
        assert!(release_reservation(&cfg, Chain::Ltc, &hex_of(0x11), true).is_err());
        assert!(release_reservation(&cfg, Chain::Btc, "zz", true).is_err());
    }

    #[test]
    fn release_refuses_while_another_connection_holds_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = reserved_db(dir.path());
        // What the daemon holds for its lifetime.
        let _daemon = (
            Store::open(&db).unwrap(),
            InputReservations::open(&db).unwrap(),
        );
        let err = release_reservation(&inflight_cfg(&db, false), Chain::Btc, &hex_of(0x11), true)
            .err()
            .expect("must refuse");
        assert!(format!("{err:#}").contains("in use"), "{err:#}");
        assert_eq!(_daemon.1.reserved(Chain::Btc).unwrap().len(), 4);
    }

    #[test]
    fn release_flags_need_each_other() {
        assert!(Args::try_parse_from(["divi-swapd", "--config", "c", "--yes"]).is_err());
        assert!(Args::try_parse_from([
            "divi-swapd",
            "--config",
            "c",
            "--release-reservation",
            "ab"
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "divi-swapd",
            "--config",
            "c",
            "--release-reservation",
            "ab",
            "--chain",
            "btc"
        ])
        .is_ok());
        assert!(Args::try_parse_from(["divi-swapd", "--config", "c", "--reservations"]).is_ok());
    }

    // ---- the maker's DIVI leg in the shared reservation table ----

    /// [`lock_swap`] with the maker's leg on DIVI (`TakerPaysBtc` against BTC).
    fn divi_lock_swap(
        id: &str,
        state: divi_swap::SwapState,
        lock: u8,
    ) -> divi_swap::store::MakerRecord {
        let mut s = lock_swap(id, state, lock);
        s.quote.direction = Direction::TakerPaysBtc;
        assert_eq!(s.quote.maker_chain(), Chain::Divi);
        s
    }

    /// The maker's DIVI key in these tests.
    fn maker_divi_key() -> divi_crypto::keys::SecretKey {
        divi_crypto::keys::SecretKey::from_bytes(&[0x44; 32]).unwrap()
    }

    /// A lock of [`MAKER_DIVI_LOCK`] from either coin of [`MAKER_DIVI_COINS`] leaves change
    /// under the dust limit, so no lock makes a coin a later lock could spend.
    const MAKER_DIVI_LOCK: Amount = Amount(500_000_000);
    const MAKER_DIVI_COINS: [(u8, u64); 2] = [(1, 500_226_000), (2, 500_230_000)];

    /// A `[divi]` wallet file holding [`MAKER_DIVI_COINS`], as a scan leaves it.
    fn maker_divi_wallet(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("divi-wallet.json");
        let utxos: Vec<_> = MAKER_DIVI_COINS
            .iter()
            .map(|(n, value)| {
                serde_json::json!({
                    "outpoint": {"txid": divi_swap::Txid([*n; 32]).to_rpc_hex(), "vout": 0},
                    "value": value,
                })
            })
            .collect();
        let wallet = serde_json::json!({
            "utxos": utxos, "reserved": [], "spent": [], "excluded": [], "scanned_height": 1,
        });
        std::fs::write(&path, wallet.to_string()).unwrap();
        path
    }

    /// A DIVI node: counts `sendrawtransaction`, answers `getrawtransaction` with the
    /// confirmations set in `confs` (no entry: unknown tx), refuses everything else.
    #[derive(Clone, Default)]
    struct MakerDiviNode {
        sent: Arc<std::sync::atomic::AtomicUsize>,
        confs: Arc<parking_lot::Mutex<std::collections::HashMap<String, u32>>>,
    }

    impl wiremock::Respond for MakerDiviNode {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let reply = |result: serde_json::Value, error: serde_json::Value| {
                wiremock::ResponseTemplate::new(if error.is_null() { 200 } else { 500 })
                    .set_body_json(serde_json::json!({"result": result, "error": error, "id": 1}))
            };
            match body["method"].as_str().unwrap_or_default() {
                "sendrawtransaction" => {
                    self.sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    reply(serde_json::json!("00"), serde_json::Value::Null)
                }
                "getrawtransaction" => {
                    let txid = body["params"][0].as_str().unwrap_or_default().to_string();
                    match self.confs.lock().get(&txid) {
                        Some(c) => reply(
                            serde_json::json!({"txid": txid, "confirmations": c}),
                            serde_json::Value::Null,
                        ),
                        None => reply(
                            serde_json::Value::Null,
                            serde_json::json!({"code": -5, "message": "No such mempool or blockchain transaction"}),
                        ),
                    }
                }
                _ => reply(
                    serde_json::Value::Null,
                    serde_json::json!({"code": -32601, "message": "Method not found"}),
                ),
            }
        }
    }

    impl MakerDiviNode {
        async fn start() -> (wiremock::MockServer, Self) {
            let server = wiremock::MockServer::start().await;
            let node = Self::default();
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .respond_with(node.clone())
                .mount(&server)
                .await;
            (server, node)
        }

        fn sent(&self) -> usize {
            self.sent.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn set_confs(&self, txid: &divi_swap::Txid, confs: u32) {
            self.confs.lock().insert(txid.to_rpc_hex(), confs);
        }
    }

    /// The `[divi]` section of a daemon on `url` with its wallet file at `wallet`.
    fn divi_section(url: &str, wallet: &std::path::Path) -> divi_swapd::config::DiviSection {
        divi_swapd::config::DiviSection {
            network: "testnet".into(),
            allow_mainnet: false,
            rpc_url: Some(url.into()),
            fallback_rpc_url: None,
            key: "credential:unused".into(),
            wallet_path: Some(wallet.to_path_buf()),
            scan_from_height: None,
            expiry_start: None,
        }
    }

    /// A daemon's live DIVI backend on `url`, `wallet` and the swap database `db`, as
    /// `live_backends` builds it: its own connection to the reservation table, as a separate
    /// process has.
    fn maker_divi(url: &str, wallet: &std::path::Path, db: &std::path::Path) -> Arc<DiviBackend> {
        let res = InputReservations::open(db).unwrap();
        Arc::new(live_divi(&divi_section(url, wallet), maker_divi_key(), &res).unwrap())
    }

    /// A maker-leg DIVI HTLC for hash `[n; 32]` refunding to `b`.
    fn maker_divi_htlc(b: &DiviBackend, n: u8) -> divi_swap::HtlcParams {
        divi_swap::HtlcParams {
            hash: [n; 32],
            claim_pubkey: [2; 33],
            refund_pubkey: b.pubkey(),
            locktime: 1_800_000_000,
            script_version: Default::default(),
        }
    }

    /// Build and broadcast the maker's DIVI lock for swap `n`, as `on_taker_lock_confirmed`
    /// then `on_maker_locked` do; a broadcast refused because another daemon reserved the
    /// coin first is retried once with a fresh selection.
    async fn maker_divi_lock(b: &DiviBackend, n: u8) -> Result<divi_swap::Funding> {
        let h = maker_divi_htlc(b, n);
        let mut last = None;
        for _ in 0..2 {
            let f = b.build_funding(&h, MAKER_DIVI_LOCK).await?;
            match b.broadcast(&f.tx).await {
                Ok(_) => return Ok(f),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap().into())
    }

    /// The coins a legacy-format DIVI funding tx spends (fewer than 253 inputs, each
    /// scriptSig shorter than 253 bytes).
    fn divi_inputs(f: &divi_swap::Funding) -> Vec<divi_swap::Outpoint> {
        let raw = &f.tx.raw;
        let mut at = 5;
        (0..raw[4])
            .map(|_| {
                let txid = divi_swap::Txid(raw[at..at + 32].try_into().unwrap());
                let vout = u32::from_le_bytes(raw[at + 32..at + 36].try_into().unwrap());
                at += 36;
                at += 1 + raw[at] as usize + 4;
                divi_swap::Outpoint { txid, vout }
            })
            .collect()
    }

    /// Every DIVI reservation in `db`, as (input, reserving tx).
    fn divi_rows(db: &std::path::Path) -> Vec<(divi_swap::Outpoint, divi_swap::Txid)> {
        InputReservations::open_read_only(db)
            .unwrap()
            .list_all()
            .unwrap()
            .into_iter()
            .filter(|r| r.chain == Chain::Divi)
            .map(|r| (r.input, r.reserved_by))
            .collect()
    }

    #[tokio::test]
    async fn two_maker_divi_locks_from_one_daemon_never_share_an_input() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let wallet = maker_divi_wallet(dir.path());
        let (server, node) = MakerDiviNode::start().await;
        let daemon = maker_divi(&server.uri(), &wallet, &db);

        let a = maker_divi_lock(&daemon, 1).await.unwrap();
        let b = maker_divi_lock(&daemon, 2).await.unwrap();
        let (ia, ib) = (divi_inputs(&a), divi_inputs(&b));
        assert!(ia.iter().all(|i| !ib.contains(i)), "{ia:?} / {ib:?}");
        assert_eq!(node.sent(), 2);
        let mut rows = divi_rows(&db);
        rows.sort_by_key(|(i, _)| i.txid.0);
        let mut want: Vec<_> = ia
            .iter()
            .map(|i| (*i, a.tx.txid))
            .chain(ib.iter().map(|i| (*i, b.tx.txid)))
            .collect();
        want.sort_by_key(|(i, _)| i.txid.0);
        assert_eq!(rows, want, "each lock reserves its inputs in the table");
        // A third swap finds nothing left and sends nothing.
        assert!(maker_divi_lock(&daemon, 3).await.is_err());
        assert_eq!(node.sent(), 2);
    }

    #[tokio::test]
    async fn two_maker_daemons_on_one_db_and_wallet_never_share_a_divi_input() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let wallet = maker_divi_wallet(dir.path());
        let (server, node) = MakerDiviNode::start().await;
        let (one, two) = (
            maker_divi(&server.uri(), &wallet, &db),
            maker_divi(&server.uri(), &wallet, &db),
        );
        let (a, b) = tokio::join!(maker_divi_lock(&one, 1), maker_divi_lock(&two, 2));
        let (a, b) = (a.unwrap(), b.unwrap());
        let (ia, ib) = (divi_inputs(&a), divi_inputs(&b));
        assert!(
            ia.iter().all(|i| !ib.contains(i)),
            "both locks spend {ia:?} / {ib:?}"
        );
        assert_eq!(node.sent(), 2);
        assert_eq!(divi_rows(&db).len(), 2, "{:?}", divi_rows(&db));
        // A third daemon on the same files: nothing unreserved left, nothing sent.
        let three = maker_divi(&server.uri(), &wallet, &db);
        assert!(maker_divi_lock(&three, 3).await.is_err());
        assert_eq!(node.sent(), 2);
        assert_eq!(divi_rows(&db).len(), 2);
    }

    /// The coin race the maker engine re-selects on (`Maker::on_maker_locked`): both daemons
    /// build from the same coin, the second to broadcast is refused by the table as
    /// `InputsHeld` with nothing sent, its wallet file gives the coin back, and its next
    /// build takes the other coin.
    #[tokio::test]
    async fn a_maker_divi_lock_that_loses_the_coin_race_is_refused_unsent_and_rebuilt_from_another_coin(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let wallet = maker_divi_wallet(dir.path());
        let (server, node) = MakerDiviNode::start().await;
        let (one, two) = (
            maker_divi(&server.uri(), &wallet, &db),
            maker_divi(&server.uri(), &wallet, &db),
        );
        let lost = one
            .build_funding(&maker_divi_htlc(&one, 1), MAKER_DIVI_LOCK)
            .await
            .unwrap();
        let won = two
            .build_funding(&maker_divi_htlc(&two, 2), MAKER_DIVI_LOCK)
            .await
            .unwrap();
        assert_eq!(divi_inputs(&lost), divi_inputs(&won), "both took one coin");
        two.broadcast(&won.tx).await.unwrap();
        assert_eq!(node.sent(), 1);

        let err = one.broadcast(&lost.tx).await.unwrap_err();
        assert!(
            matches!(err, divi_swap::SwapError::InputsHeld(_)),
            "{err:?}"
        );
        assert_eq!(node.sent(), 1, "the refused lock was never sent");
        let rows = divi_rows(&db);
        assert!(rows.iter().all(|(_, by)| *by == won.tx.txid), "{rows:?}");

        let again = one
            .build_funding(&maker_divi_htlc(&one, 1), MAKER_DIVI_LOCK)
            .await
            .unwrap();
        let (ia, iw) = (divi_inputs(&again), divi_inputs(&won));
        assert!(ia.iter().all(|i| !iw.contains(i)), "{ia:?} / {iw:?}");
        one.broadcast(&again.tx).await.unwrap();
        assert_eq!(node.sent(), 2);
        assert_eq!(divi_rows(&db).len(), 2);
    }

    #[tokio::test]
    async fn a_maker_divi_lock_row_is_kept_in_the_mempool_and_released_on_its_first_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let wallet = maker_divi_wallet(dir.path());
        let (server, node) = MakerDiviNode::start().await;
        let daemon = maker_divi(&server.uri(), &wallet, &db);
        let f = maker_divi_lock(&daemon, 1).await.unwrap();
        assert_eq!(divi_rows(&db).len(), 1, "broadcast: reserved");
        // Not yet seen, then in the mempool: kept.
        assert_eq!(daemon.confirmations(&f.tx.txid).await.unwrap(), None);
        assert_eq!(divi_rows(&db).len(), 1, "not seen: kept");
        node.set_confs(&f.tx.txid, 0);
        assert_eq!(daemon.confirmations(&f.tx.txid).await.unwrap(), Some(0));
        assert_eq!(divi_rows(&db).len(), 1, "mempool: kept");
        node.set_confs(&f.tx.txid, 1);
        assert_eq!(daemon.confirmations(&f.tx.txid).await.unwrap(), Some(1));
        assert!(divi_rows(&db).is_empty(), "confirmed: released");
    }

    /// The sweep, run on a DIVI mock chain at `chain`'s wall clock with an idle BTC counter.
    async fn divi_sweep(
        res: &InputReservations,
        store: &Store,
        divi: &divi_swap::mock::MockBackend,
        now: u32,
    ) -> usize {
        let btc: Vec<Arc<dyn ChainBackend>> = vec![Arc::new(
            MockChain::new(Chain::Btc, now, 600).backend(9, Amount(Amount::COIN)),
        )];
        expiry_sweep_once(res, store, divi, &btc, now, ExpiryStart::default()).await
    }

    #[tokio::test]
    async fn the_divi_expiry_sweep_starts_each_count_where_the_config_says() {
        let dir = tempfile::tempdir().unwrap();
        let deadline = divi_lock_swap("x", divi_swap::SwapState::MakerLocked, 0)
            .maker_leg_htlc
            .unwrap()
            .locktime;
        let mut released_at = Vec::new();
        for (i, line) in ["", "expiry_start = \"tip\"\n", "expiry_start = \"mtp\"\n"]
            .into_iter()
            .enumerate()
        {
            let db = dir.path().join(format!("swaps{i}.db"));
            let cfg = DaemonConfig::parse(&format!(
                "db_path = \"{}\"\n[divi]\nkey = \"credential:maker-divi\"\n{line}",
                db.display()
            ))
            .unwrap();
            let store = Store::open(&db).unwrap();
            store
                .put_maker_swap(&divi_lock_swap(
                    "dropped",
                    divi_swap::SwapState::MakerLocked,
                    0x11,
                ))
                .unwrap();
            let res = InputReservations::open(&db).unwrap();
            res.reserve(Chain::Divi, &divi_swap::Txid([0x11; 32]), &[op(1, 0)])
                .unwrap();
            // A dense DIVI chain past the deadline whose tips look fresh (swept at the tip's
            // own time) while MTP trails them by five blocks.
            let chain = MockChain::new(Chain::Divi, deadline, 60);
            let divi = chain.backend(8, Amount(Amount::COIN));
            divi.set_tip_lead(5 * 60);
            let first = chain.height();
            let start = cfg.divi_expiry_start().unwrap();
            loop {
                let now = chain.mtp() + 5 * 60;
                if expiry_sweep_once(&res, &store, &divi, &[], now, start).await > 0 {
                    break;
                }
                assert!(chain.height() < first + 20, "{line:?}: never released");
                chain.mine(1);
            }
            released_at.push(chain.height() - first);
        }
        let n = divi_swap::reservation::EXPIRY_ABSENT_BLOCKS;
        assert_eq!(released_at, [n, n, n + 4]);
    }

    #[tokio::test]
    async fn a_finished_maker_divi_swap_releases_its_lock_row_and_btc_rows_are_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        let res = InputReservations::open(&db).unwrap();
        let t = |n: u8| divi_swap::Txid([n; 32]);
        for s in [
            divi_lock_swap("done", divi_swap::SwapState::Done, 0x11),
            divi_lock_swap("lost", divi_swap::SwapState::Lost, 0x12),
            divi_lock_swap("live", divi_swap::SwapState::MakerLockConfirmed, 0x21),
            divi_lock_swap("refundable", divi_swap::SwapState::MakerRefundable, 0x22),
            lock_swap("btc-done", divi_swap::SwapState::Done, 0x31),
        ] {
            store.put_maker_swap(&s).unwrap();
        }
        for (chain, lock, input) in [
            (Chain::Divi, 0x11, 1),
            (Chain::Divi, 0x12, 2),
            (Chain::Divi, 0x21, 3),
            (Chain::Divi, 0x22, 4),
            (Chain::Btc, 0x31, 5),
        ] {
            res.reserve(chain, &t(lock), &[op(input, 0)]).unwrap();
        }
        // Well before every deadline, on a fresh chain: only finishing can release.
        let chain = MockChain::new(Chain::Divi, 1_700_000_000, 60);
        let divi = chain.backend(8, Amount(Amount::COIN));
        let by = |res: &InputReservations| -> BTreeSet<(Chain, u8)> {
            res.list_all()
                .unwrap()
                .into_iter()
                .map(|r| (r.chain, r.reserved_by.0[0]))
                .collect()
        };
        divi_sweep(&res, &store, &divi, chain.mtp()).await;
        assert_eq!(
            by(&res),
            BTreeSet::from([(Chain::Btc, 0x31), (Chain::Divi, 0x21), (Chain::Divi, 0x22)]),
            "finished DIVI locks released; live ones and BTC kept as before"
        );
        assert!(
            divi.released_locks().is_empty(),
            "the wallet file is not touched"
        );
        // Again, and after a restart: nothing twice.
        divi_sweep(&res, &store, &divi, chain.mtp()).await;
        let res = InputReservations::open(&db).unwrap();
        divi_sweep(&res, &store, &divi, chain.mtp()).await;
        assert_eq!(by(&res).len(), 3);
        // A swap that finishes later is released then.
        let mut s = store.get_maker_swap("refundable").unwrap().unwrap();
        s.state = divi_swap::SwapState::Done;
        store.put_maker_swap(&s).unwrap();
        divi_sweep(&res, &store, &divi, chain.mtp()).await;
        assert_eq!(
            by(&res),
            BTreeSet::from([(Chain::Btc, 0x31), (Chain::Divi, 0x21)])
        );
    }

    #[tokio::test]
    async fn the_expiry_sweep_releases_a_dropped_maker_divi_lock_past_its_deadline_only() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        let deadline = divi_lock_swap("x", divi_swap::SwapState::MakerLocked, 0)
            .maker_leg_htlc
            .unwrap()
            .locktime;
        let chain = MockChain::new(Chain::Divi, deadline - 1, 60);
        let divi = chain.backend(8, Amount(Amount::COIN));
        // `dropped`'s lock (0x11) is in no mempool and no block; `pending`'s is broadcast.
        let dropped = divi_lock_swap("dropped", divi_swap::SwapState::MakerLocked, 0x11);
        let mut pending = divi_lock_swap("pending", divi_swap::SwapState::MakerLocked, 0x22);
        let f = divi
            .build_funding(pending.maker_leg_htlc.as_ref().unwrap(), Amount(5_000))
            .await
            .unwrap();
        divi.broadcast(&f.tx).await.unwrap();
        let pending_lock = f.tx.txid;
        pending.maker_leg_funding = Some(f);
        store.put_maker_swap(&dropped).unwrap();
        store.put_maker_swap(&pending).unwrap();
        let res = InputReservations::open(&db).unwrap();
        let dropped_lock = divi_swap::Txid([0x11; 32]);
        res.reserve(Chain::Divi, &dropped_lock, &[op(1, 0)])
            .unwrap();
        res.reserve(Chain::Divi, &pending_lock, &[op(2, 0)])
            .unwrap();
        let held = || {
            let mut by: Vec<_> = divi_rows(&db).into_iter().map(|(_, t)| t).collect();
            by.sort_by_key(|t| t.0);
            by
        };
        let mut both = vec![dropped_lock, pending_lock];
        both.sort_by_key(|t| t.0);

        assert_eq!(divi_sweep(&res, &store, &divi, chain.mtp()).await, 0);
        assert_eq!(held(), both, "one second before the deadline");
        chain.set_offline(true);
        chain.advance_time(1);
        assert_eq!(divi_sweep(&res, &store, &divi, chain.mtp()).await, 0);
        assert_eq!(
            held(),
            both,
            "a chain that cannot be asked keeps everything"
        );
        chain.set_offline(false);
        let first = chain.height();
        assert_eq!(
            divi_sweep(&res, &store, &divi, chain.mtp()).await,
            0,
            "the first absent check"
        );
        assert_eq!(
            res.first_absent_height(Chain::Divi, &dropped_lock).unwrap(),
            Some(first)
        );
        chain.mine(divi_swap::reservation::EXPIRY_ABSENT_BLOCKS - 1);
        assert_eq!(
            divi_sweep(&res, &store, &divi, chain.mtp()).await,
            0,
            "one block short"
        );
        chain.mine(1);
        assert_eq!(
            divi_sweep(
                &res,
                &store,
                &divi,
                chain.mtp() + divi_swap::reservation::EXPIRY_MAX_TIP_AGE_SECS + 1
            )
            .await,
            0,
            "a stale backend releases nothing"
        );
        assert_eq!(held(), both);
        assert!(divi.released_locks().is_empty(), "never released early");
        assert_eq!(divi_sweep(&res, &store, &divi, chain.mtp()).await, 1);
        assert_eq!(
            held(),
            vec![pending_lock],
            "the pending lock keeps its input"
        );
        assert_eq!(
            divi.released_locks(),
            vec![dropped_lock],
            "the wallet file gets the dropped lock's inputs back, on the backend's own proof"
        );
        assert_eq!(divi_sweep(&res, &store, &divi, chain.mtp()).await, 0);
        assert_eq!(divi.released_locks().len(), 1);
    }

    #[test]
    fn a_maker_divi_lock_is_named_by_its_swap_and_refused_until_it_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let store = Store::open(&db).unwrap();
        let mut s = divi_lock_swap("mdivi", divi_swap::SwapState::MakerLocked, 0x56);
        store.put_maker_swap(&s).unwrap();
        InputReservations::open(&db)
            .unwrap()
            .reserve(Chain::Divi, &divi_swap::Txid([0x56; 32]), &[op(9, 0)])
            .unwrap();
        let cfg = inflight_cfg(&db, false);
        let out = reservations_report(&cfg).unwrap();
        assert!(out.contains("\tmdivi\tMakerLocked\n"), "{out}");
        assert!(!out.contains("unknown"), "not an orphan: {out}");
        for yes in [false, true] {
            let err = release_reservation(&cfg, Chain::Divi, &hex_of(0x56), yes)
                .err()
                .expect("a live maker DIVI lock is not an orphan");
            assert!(err.to_string().contains("not terminal"), "{err}");
        }
        assert_eq!(divi_rows(&db).len(), 1);
        s.state = divi_swap::SwapState::Done;
        store.put_maker_swap(&s).unwrap();
        drop(store);
        let out = release_reservation(&cfg, Chain::Divi, &hex_of(0x56), true).unwrap();
        assert!(out.released);
        assert!(
            out.text.contains("swap mdivi (Done, terminal)"),
            "{}",
            out.text
        );
        assert!(divi_rows(&db).is_empty());
    }

    #[tokio::test]
    async fn maker_divi_claims_and_refunds_reserve_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let wallet = maker_divi_wallet(dir.path());
        InputReservations::open(&db).unwrap();
        let (server, node) = MakerDiviNode::start().await;
        // Read-only: a reservation attempt would fail the broadcast.
        let ro = InputReservations::open_read_only(&db).unwrap();
        let daemon =
            live_divi(&divi_section(&server.uri(), &wallet), maker_divi_key(), &ro).unwrap();
        let (pre, hash) = divi_swap::htlc::new_preimage();
        let mut h = maker_divi_htlc(&daemon, 0);
        h.hash = hash;
        h.claim_pubkey = daemon.pubkey();
        let at = |n: u8| op(n, 0);
        // The maker's claim of a DIVI taker leg, and its refund of its own DIVI lock.
        let claim = daemon
            .build_claim(&h, &at(7), MAKER_DIVI_LOCK, &pre)
            .await
            .unwrap();
        let refund = daemon
            .build_refund(&h, &at(8), MAKER_DIVI_LOCK)
            .await
            .unwrap();
        daemon.broadcast(&claim).await.unwrap();
        daemon.broadcast(&refund).await.unwrap();
        assert_eq!(node.sent(), 2);
        assert!(divi_rows(&db).is_empty());
        // The same read-only table does refuse a lock funding: the claim and refund were
        // left alone, not let through by a failed write.
        let lock = daemon
            .build_funding(&maker_divi_htlc(&daemon, 2), MAKER_DIVI_LOCK)
            .await
            .unwrap();
        assert!(daemon.broadcast(&lock.tx).await.is_err());
        assert_eq!(node.sent(), 2);
    }

    #[tokio::test]
    async fn a_maker_divi_lock_from_before_the_table_stays_protected_by_the_wallet_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        let wallet = maker_divi_wallet(dir.path());
        let (server, node) = MakerDiviNode::start().await;
        // The daemon before this change: `[divi]` funds without the table.
        let old = DiviBackend::new(
            &server.uri(),
            maker_divi_key(),
            divi_wallet::address::Network::Testnet,
            DiviFeePolicy::default(),
            Some(wallet.clone()),
        )
        .unwrap();
        let before = maker_divi_lock(&old, 1).await.unwrap();
        drop(old);
        let mut s = divi_lock_swap("old", divi_swap::SwapState::MakerLockConfirmed, 0);
        s.maker_leg_funding = Some(before.clone());
        let store = Store::open(&db).unwrap();
        store.put_maker_swap(&s).unwrap();

        // Restarted on this build: the old lock has no row, and the wallet file still
        // keeps its input out of every selection.
        let daemon = maker_divi(&server.uri(), &wallet, &db);
        assert!(divi_rows(&db).is_empty());
        let res = InputReservations::open(&db).unwrap();
        let idle = MockChain::new(Chain::Divi, 1_700_000_000, 60).backend(8, Amount(0));
        divi_sweep(&res, &store, &idle, 1_700_000_000).await;
        let new = maker_divi_lock(&daemon, 2).await.unwrap();
        let (io, inew) = (divi_inputs(&before), divi_inputs(&new));
        assert!(io.iter().all(|i| !inew.contains(i)), "{io:?} / {inew:?}");
        assert!(
            maker_divi_lock(&daemon, 3).await.is_err(),
            "the old lock's coin is not free"
        );
        assert!(maker_divi_lock(&maker_divi(&server.uri(), &wallet, &db), 4)
            .await
            .is_err());
        assert_eq!(divi_rows(&db).len(), 1, "only the new lock has a row");
        // The maker's F2 re-send of the old bytes (a lock not yet deep) gives it a row.
        daemon.broadcast(&before.tx).await.unwrap();
        assert_eq!(divi_rows(&db).len(), 2);
        assert_eq!(node.sent(), 3);
        // Its swap finishing releases that row, and leaves the wallet file as it was.
        s.state = divi_swap::SwapState::Done;
        store.put_maker_swap(&s).unwrap();
        divi_sweep(&res, &store, &idle, 1_700_000_000).await;
        assert!(idle.released_locks().is_empty());
        assert_eq!(
            divi_rows(&db),
            inew.iter().map(|i| (*i, new.tx.txid)).collect::<Vec<_>>()
        );
        assert!(maker_divi_lock(&daemon, 5).await.is_err(), "still spent");
    }
}
