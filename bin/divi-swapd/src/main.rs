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
    /// With `--release-reservation`: the chain the reservation is on (btc, ltc, zec).
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
    // BTC, LTC and ZEC select coins from a live address query; this table keeps the inputs of
    // a broadcast lock out of the next swap's selection until the lock confirms.
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
    let divi_network = divi_cfg.network()?;
    let mut divi = DiviBackend::new(
        &divi_cfg.rpc_url()?,
        key,
        divi_network,
        DiviFeePolicy::default(),
        divi_cfg.wallet_path.clone(),
    )?;
    if let Some(fallback) = divi_cfg.fallback_rpc_url()? {
        divi = divi.with_fallback_rpc(&fallback);
        tracing::info!(
            "divi second source enabled: swap reads on two endpoints, disagreement is transient"
        );
    }
    tracing::info!(address = %divi.address(), network = ?divi_network, "divi backend ready");
    let divi = Arc::new(divi);
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
    for s in store.list_maker_swaps()? {
        if s.quote.counter_chain == chain
            && s.maker_leg_funding.as_ref().map(|f| f.tx.txid) == Some(*txid)
        {
            let state = serde_json::to_value(s.state)?;
            return Ok(Some((
                s.id,
                state.as_str().unwrap_or("?").to_string(),
                s.state.is_terminal(),
            )));
        }
    }
    for s in store.list_taker_swaps()? {
        if s.quote.counter_chain == chain
            && s.taker_leg_funding.as_ref().map(|f| f.tx.txid) == Some(*txid)
        {
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
    let counters = std::iter::once(btc.clone()).chain(others).collect();
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
}
