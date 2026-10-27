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

//! TOML configuration. Keys are never accepted by value: only `op://…` or
//! `credential:<name>` references, resolved at runtime by `divi_swap::secrets`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use divi_swap::api::{Direction, Offer};
use divi_swap::{Chain, Profile};
use serde::Deserialize;

use crate::proxy::{default_trusted_proxies, IpCidr, ProxyTrust};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// Every chain simulated in-process.
    Mock,
    /// Real DIVI RPC (testnet unless `[divi].network = "mainnet"`) + BTC Esplora.
    Live,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiviSection {
    /// `testnet` (default) or `mainnet`, mirroring `[zec].network`.
    #[serde(default = "default_divi_network")]
    pub network: String,
    /// Must be `true` for `network = "mainnet"`, which moves real money. Off by default,
    /// mirroring `[zec].allow_mainnet`.
    #[serde(default)]
    pub allow_mainnet: bool,
    /// DIVI JSON-RPC proxy URL. When absent, [`DiviSection::rpc_url`] falls back to
    /// `swap_chain_divi::default_rpc(network)`.
    pub rpc_url: Option<String>,
    /// Second, independent DIVI JSON-RPC endpoint (ideally the operator's own node).
    /// When set, every swap-relevant read is made on both endpoints and a disagreement is
    /// `Transient` (retried later), never a decision; a broadcast goes to both. Optional on
    /// testnet; required on a mainnet profile unless `allow_single_source = true`.
    #[serde(default)]
    pub fallback_rpc_url: Option<String>,
    /// Let a mainnet profile start without `fallback_rpc_url`, trusting one endpoint for every
    /// swap read. Off by default; when it is used, a warning is logged at every start.
    #[serde(default)]
    pub allow_single_source: bool,
    /// Reference (`op://…` or `credential:<name>`) to the maker's DIVI key.
    pub key: String,
    /// Known-UTXO file (public data only).
    pub wallet_path: Option<PathBuf>,
    /// First block height to scan for wallet UTXOs.
    pub scan_from_height: Option<u64>,
}

fn default_divi_network() -> String {
    "testnet".into()
}

impl DiviSection {
    /// The configured DIVI network (`testnet` or `mainnet`).
    pub fn network(&self) -> Result<divi_wallet::address::Network> {
        match self.network.as_str() {
            "testnet" => Ok(divi_wallet::address::Network::Testnet),
            "mainnet" => Ok(divi_wallet::address::Network::Mainnet),
            other => bail!("[divi].network must be testnet or mainnet, got {other:?}"),
        }
    }

    /// `rpc_url`, or `network`'s default public endpoint if unset.
    pub fn rpc_url(&self) -> Result<String> {
        Ok(match &self.rpc_url {
            Some(u) => u.clone(),
            None => swap_chain_divi::default_rpc(self.network()?).to_string(),
        })
    }

    /// `fallback_rpc_url` when set and non-blank; an identical URL to `rpc_url` is refused
    /// because it would make the "second" source a copy of the first.
    pub fn fallback_rpc_url(&self) -> Result<Option<String>> {
        let Some(f) = self.fallback_rpc_url.as_deref().map(str::trim) else {
            return Ok(None);
        };
        if f.is_empty() {
            return Ok(None);
        }
        if f == self.rpc_url()?.trim() {
            bail!("[divi].fallback_rpc_url must differ from [divi].rpc_url");
        }
        Ok(Some(f.to_string()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BtcSection {
    /// `signet` (default), `testnet` or `mainnet`.
    #[serde(default = "default_network")]
    pub network: String,
    /// Must be `true` for `network = "mainnet"`, which moves real money. Off by default,
    /// mirroring `[zec].allow_mainnet`.
    #[serde(default)]
    pub allow_mainnet: bool,
    /// Primary Esplora API base. When absent, [`BtcSection::endpoints`] falls back to
    /// `swap_chain_btc::esplora_endpoints(network)` and `fallback_esplora_url` is not consulted.
    pub esplora_url: Option<String>,
    /// Fallback Esplora API base.
    pub fallback_esplora_url: Option<String>,
    /// Read `find_spend`, `htlc_output` and `confirmations` (what a claim or refund rests
    /// on) from the primary and the secondary endpoint, and treat any disagreement, or either
    /// endpoint failing, as transient (retried, never acted on). Off by default: the secondary
    /// is then only a failover. Needs two different endpoints (see [`BtcSection::endpoints`]).
    #[serde(default)]
    pub quorum_reads: bool,
    /// Reference (`op://…` or `credential:<name>`) to the maker's BTC key.
    pub key: String,
}

impl BtcSection {
    /// Esplora endpoints, primary first: `esplora_url` (then `fallback_esplora_url`) when
    /// set, else `network`'s defaults (`swap_chain_btc::esplora_endpoints`).
    pub fn endpoints(&self) -> Result<Vec<String>> {
        Ok(match &self.esplora_url {
            Some(primary) => {
                let mut eps = vec![primary.clone()];
                eps.extend(self.fallback_esplora_url.clone());
                eps
            }
            None => swap_chain_btc::esplora_endpoints(&self.network)
                .map_err(|e| anyhow::anyhow!("[btc].network: {e}"))?,
        })
    }

    /// With `quorum_reads` on, the endpoints must be a primary and a different secondary.
    fn validate_quorum_reads(&self) -> Result<()> {
        if !self.quorum_reads {
            return Ok(());
        }
        let eps = self.endpoints()?;
        let norm = |u: &String| u.trim().trim_end_matches('/').to_string();
        if eps.len() < 2 || norm(&eps[0]) == norm(&eps[1]) {
            bail!(
                "[btc].quorum_reads = true needs a second, different Esplora endpoint: set \
                 [btc].fallback_esplora_url next to [btc].esplora_url (or leave both unset \
                 for the network's two defaults)"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LtcSection {
    /// `testnet` (default) or `mainnet`.
    #[serde(default = "default_ltc_network")]
    pub network: String,
    /// Must be `true` for `network = "mainnet"`, which moves real money. Off by default,
    /// mirroring `[zec].allow_mainnet`.
    #[serde(default)]
    pub allow_mainnet: bool,
    /// Primary Esplora API base. When absent, [`LtcSection::endpoints`] falls back to
    /// `swap_chain_ltc::esplora_endpoints(network)` and `fallback_esplora_url` is not consulted.
    pub esplora_url: Option<String>,
    /// Fallback Esplora API base, if one exists (none known as of 2026-10-11 — see
    /// `swap-chain-ltc`'s lane status).
    pub fallback_esplora_url: Option<String>,
    /// Reference (`op://…` or `credential:<name>`) to the maker's LTC key.
    pub key: String,
    /// Tip-hash cross-check of the primary Esplora against an independent source:
    /// `"blockbook"`, `"blockcypher"` or `"off"` (default). Mainnet only; refused at config
    /// load on testnet, required on a mainnet profile unless `allow_single_source = true`.
    /// Run once at startup, before any LTC action.
    #[serde(default = "default_ltc_crosscheck")]
    pub crosscheck: String,
    /// Let a mainnet profile start with `crosscheck = "off"`, trusting the one Esplora source.
    /// Off by default; when it is used, a warning is logged at every start.
    #[serde(default)]
    pub allow_single_source: bool,
}

impl LtcSection {
    /// Parsed `crosscheck`; `None` is `off`.
    pub fn crosscheck_source(&self) -> Result<Option<swap_chain_ltc::CrossCheckSource>> {
        swap_chain_ltc::CrossCheckSource::parse_opt(&self.crosscheck)
            .map_err(|e| anyhow::anyhow!("[ltc].crosscheck: {e}"))
    }

    /// Esplora endpoints, primary first: `esplora_url` (then `fallback_esplora_url`) when
    /// set, else `network`'s defaults (`swap_chain_ltc::esplora_endpoints`).
    pub fn endpoints(&self) -> Result<Vec<String>> {
        Ok(match &self.esplora_url {
            Some(primary) => {
                let mut eps = vec![primary.clone()];
                eps.extend(self.fallback_esplora_url.clone());
                eps
            }
            None => swap_chain_ltc::esplora_endpoints(&self.network)
                .map_err(|e| anyhow::anyhow!("[ltc].network: {e}"))?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsdcSection {
    /// Which EVM network this backend runs on: `"sepolia"` (default), `"base-sepolia"`,
    /// `"ethereum"` or `"base"` (`swap_chain_evm::UsdcNetwork`; the last two are mainnets and
    /// need `allow_mainnet` below). Only a label plus a source of defaults for
    /// `rpc_url`/`token` below when they are left unset — the backend itself is
    /// network-agnostic, so setting both explicitly works on any EVM chain regardless of
    /// `network`. A single `[usdc]` section (and so a single `Chain::Usdc` backend) serves
    /// one network at a time; running both concurrently needs a second counter chain.
    #[serde(default = "default_usdc_network")]
    pub network: String,
    /// Must be `true` for a mainnet `network` (`"ethereum"`, `"base"`), which moves real
    /// money. Off by default, mirroring `[zec].allow_mainnet`.
    #[serde(default)]
    pub allow_mainnet: bool,
    /// EVM JSON-RPC URL. Defaults to a free public endpoint for `network`.
    pub rpc_url: Option<String>,
    /// Second, independent EVM JSON-RPC node (ideally the operator's own). When set, the
    /// reads a claim or refund rests on (`htlc_output`, `find_spend`, `confirmations`,
    /// `median_time_past`) are asked of both nodes and a disagreement, or this node not
    /// answering, is `Transient` (retried later), never a decision
    /// (`swap_chain_evm::UsdcBackend::with_quorum_rpc`). Off by default; optional on every
    /// profile.
    #[serde(default)]
    pub fallback_rpc_url: Option<String>,
    /// Deployed `Erc20Htlc` contract address.
    pub htlc: String,
    /// ERC-20 (USDC) token address. Defaults to Circle's test USDC for `network`.
    pub token: Option<String>,
    /// Reference (`op://…` or `credential:<name>`) to the maker's EVM key.
    pub key: String,
}

fn default_usdc_network() -> String {
    swap_chain_evm::UsdcNetwork::Sepolia.as_str().into()
}

impl UsdcSection {
    /// Parsed `network`, validated at config-load time by [`DaemonConfig::validate`].
    pub fn network(&self) -> Result<swap_chain_evm::UsdcNetwork> {
        self.network
            .parse()
            .map_err(|e| anyhow::anyhow!("[usdc].network: {e}"))
    }

    /// `rpc_url`, or `network`'s default public endpoint if unset.
    pub fn rpc_url(&self) -> Result<String> {
        Ok(match &self.rpc_url {
            Some(u) => u.clone(),
            None => self.network()?.default_rpc_url().to_string(),
        })
    }

    /// `fallback_rpc_url` when set and non-blank; an identical URL to `rpc_url` is refused
    /// because it would make the "second" node a copy of the first.
    pub fn fallback_rpc_url(&self) -> Result<Option<String>> {
        let Some(f) = self.fallback_rpc_url.as_deref().map(str::trim) else {
            return Ok(None);
        };
        if f.is_empty() {
            return Ok(None);
        }
        let norm = |u: &str| u.trim().trim_end_matches('/').to_string();
        if norm(f) == norm(&self.rpc_url()?) {
            bail!("[usdc].fallback_rpc_url must differ from [usdc].rpc_url");
        }
        Ok(Some(f.to_string()))
    }

    /// `token`, or `network`'s USDC token address if unset.
    pub fn token(&self) -> Result<String> {
        Ok(match &self.token {
            Some(t) => t.clone(),
            None => self.network()?.usdc_token().to_string(),
        })
    }
}

/// The live adaptor-swap engine (`divi_swap_xmr`) behind `counter_chain = "xmr"` offers:
/// a Monero wallet (`monero-wallet-rpc`) and its own DIVI wallet. Ignored by the mock backend.
#[derive(Debug, Clone, Deserialize)]
pub struct XmrSection {
    /// `stagenet` (default), `testnet` or `mainnet`.
    #[serde(default = "default_xmr_network")]
    pub network: String,
    /// Must be `true` for `network = "mainnet"`, which moves real money. Off by default;
    /// set only at phase D of `xmr-mainnet-plan.md` (after the outside review, Bert present).
    #[serde(default)]
    pub allow_mainnet: bool,
    /// `monerod` RPC: scanning for the taker's lock, fees, relaying the sweep.
    pub monerod_url: String,
    /// `monero-wallet-rpc` URL. Taker-only: the maker never sends XMR from a wallet (it
    /// sweeps with the recovered key), so a maker leaves the three `wallet_rpc_*` keys out.
    #[serde(default)]
    pub wallet_rpc_url: Option<String>,
    #[serde(default)]
    pub wallet_rpc_user: String,
    /// Reference (`op://…` or `credential:<name>`) to the wallet RPC password.
    pub wallet_rpc_password: Option<String>,
    /// The maker's own Monero address: where the swept XMR goes.
    pub sweep_address: String,
    /// Reference to the DIVI key funding `Tx_lock`. Must not be the `[divi]` key: two coin
    /// sets over one key would select the same coins.
    pub divi_key: String,
    /// DIVI JSON-RPC proxy URL for that wallet.
    #[serde(default = "default_divi_rpc")]
    pub divi_rpc_url: String,
    /// Known-UTXO file of that wallet (public data only).
    pub divi_wallet_path: Option<PathBuf>,
    /// Blocks below the Monero tip where the first scan for a swap's lock starts.
    #[serde(default = "default_xmr_lookback")]
    pub lookback_blocks: u64,
    /// Lock/sweep journals (public data); default `<db_path>.xmr-journal`.
    pub journal_dir: Option<PathBuf>,
    /// Transactions paying that wallet (funding, earlier refunds) to learn its coins from at
    /// startup; its own change is tracked as it broadcasts.
    #[serde(default)]
    pub divi_fund_txids: Vec<String>,
}

fn default_xmr_network() -> String {
    "stagenet".into()
}
fn default_xmr_lookback() -> u64 {
    720 // ~1 day of 2-minute blocks
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZecSection {
    /// `testnet` (default) or `mainnet`, mirroring `[xmr].network`.
    #[serde(default = "default_zec_network")]
    pub network: String,
    /// Must be `true` for `network = "mainnet"`, which moves real money. Off by default,
    /// mirroring `[xmr].allow_mainnet`.
    #[serde(default)]
    pub allow_mainnet: bool,
    /// Primary lightwalletd gRPC endpoint. When absent, [`ZecSection::endpoints`] falls back
    /// to `swap_chain_zec::lightwalletd_endpoints(network)` (the probed defaults for
    /// `network`, plus whatever `SWAP_ZEC_LIGHTWALLETD_EXTRA` adds) and
    /// `fallback_lightwalletd_url` is not consulted.
    pub lightwalletd_url: Option<String>,
    /// Fallback lightwalletd gRPC endpoint, used only when `lightwalletd_url` is set (comes
    /// after it).
    pub fallback_lightwalletd_url: Option<String>,
    /// Reference (`op://…` or `credential:<name>`) to the maker's ZEC key.
    pub key: String,
}

fn default_zec_network() -> String {
    "testnet".into()
}

impl ZecSection {
    /// Lightwalletd endpoints, primary first: `lightwalletd_url` (then
    /// `fallback_lightwalletd_url` if also set) when present, else `network`'s probed
    /// defaults (`swap_chain_zec::lightwalletd_endpoints`).
    pub fn endpoints(&self) -> Result<Vec<String>> {
        Ok(match &self.lightwalletd_url {
            Some(primary) => {
                let mut eps = vec![primary.clone()];
                eps.extend(self.fallback_lightwalletd_url.clone());
                eps
            }
            None => swap_chain_zec::lightwalletd_endpoints(&self.network)
                .map_err(|e| anyhow::anyhow!("[zec].network: {e}"))?,
        })
    }
}

/// The DIVI testnet RPC proxy: the default `[divi]` and `[xmr]` DIVI endpoint.
pub fn default_divi_rpc() -> String {
    "https://services.divi.domains/api/testnet/rpc/".into()
}
fn default_network() -> String {
    "signet".into()
}
fn default_ltc_crosscheck() -> String {
    "off".into()
}
fn default_ltc_network() -> String {
    "testnet".into()
}
fn default_listen() -> SocketAddr {
    "127.0.0.1:8480".parse().expect("static address")
}
fn default_profile() -> Profile {
    Profile::Testnet
}
/// One `[[offers]]` table: the wire [`Offer`] plus daemon-only switches.
#[derive(Debug, Clone, Deserialize)]
pub struct OfferEntry {
    #[serde(flatten)]
    pub offer: Offer,
    /// `false` keeps the offer in the file but off `/offers` (and unquotable). A counter
    /// chain whose offers are all disabled gets no backend, so its `[<chain>]` section can
    /// stay in place without its API being needed. Defaults to `true`.
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

fn default_offer_entries() -> Vec<OfferEntry> {
    default_offers()
        .into_iter()
        .map(|offer| OfferEntry {
            offer,
            enabled: true,
        })
        .collect()
}

fn default_offers() -> Vec<Offer> {
    [
        ("divi-btc-testnet", Direction::TakerPaysBtc),
        ("btc-divi-testnet", Direction::TakerPaysDivi),
    ]
    .into_iter()
    .map(|(id, direction)| Offer {
        id: id.into(),
        direction,
        counter_chain: Chain::Btc,
        divi_sats_per_btc: mock_divi_per_coin(Chain::Btc),
        min_btc_sats: 5_000,
        max_btc_sats: 50_000,
    })
    .collect()
}

/// Counter chains `--backend mock` simulates besides BTC, via a generic in-process
/// `MockChain` rather than a dedicated mock. (LTC and ZEC also have live backends — see
/// [`LtcSection`] / [`ZecSection`] — but mock mode always simulates every chain the same
/// way, for fast hermetic local/CI coverage.)
pub const MOCK_ONLY_CHAINS: [Chain; 2] = [Chain::Ltc, Chain::Zec];

/// Placeholder DIVI-per-coin price (in DIVI base units) for every chain, as an exhaustive
/// match: a new [`Chain`] variant fails to compile here until it is priced, so no coin
/// silently inherits another coin's rate.
pub const fn mock_divi_per_coin(chain: Chain) -> u64 {
    const DIVI: u64 = 100_000_000;
    match chain {
        Chain::Divi => DIVI,            // 1 DIVI per DIVI
        Chain::Btc => 3_000_000 * DIVI, // 3,000,000 DIVI per BTC (the `mock_offers` price)
        Chain::Ltc => 10_000 * DIVI,    // 10,000 DIVI per LTC
        Chain::Zec => 5_000 * DIVI,     // 5,000 DIVI per ZEC
        Chain::Usdc => 100 * DIVI,      // 100 DIVI per USDC
        Chain::Xmr => 5_000 * DIVI,     // 5,000 DIVI per XMR
    }
}

/// The offers `--backend mock` adds for each of [`MOCK_ONLY_CHAINS`]: `divi-<c>-testnet`
/// (maker sells DIVI) and `<c>-divi-testnet` (maker buys DIVI). Prices are placeholders.
pub fn mock_counter_offers() -> Vec<Offer> {
    MOCK_ONLY_CHAINS
        .into_iter()
        .flat_map(|c| {
            let price = mock_divi_per_coin(c);
            [
                (format!("divi-{c}-testnet"), Direction::TakerPaysBtc),
                (format!("{c}-divi-testnet"), Direction::TakerPaysDivi),
            ]
            .map(|(id, direction)| Offer {
                id,
                direction,
                counter_chain: c,
                divi_sats_per_btc: price,
                min_btc_sats: 100_000,
                max_btc_sats: 10_000_000,
            })
        })
        .collect()
}

/// The adaptor-swap offer `--backend mock` adds (`divi_swap_xmr`): `divi-xmr-stagenet`, the
/// maker sells DIVI for XMR (the adaptor protocol has the maker hold DIVI, so there is no
/// reverse offer). Amounts are 1e-8 XMR units, like every counter chain; price placeholder.
pub fn mock_xmr_offers() -> Vec<Offer> {
    vec![Offer {
        id: "divi-xmr-stagenet".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Xmr,
        divi_sats_per_btc: mock_divi_per_coin(Chain::Xmr),
        min_btc_sats: 100_000,     // 0.001 XMR
        max_btc_sats: 100_000_000, // 1 XMR
    }]
}
fn default_tick() -> u64 {
    5
}

/// Optional overrides of the profile's timing, for tests that cannot wait hours
/// (`SwapConfig::validate` still enforces the timeout-gap invariant).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SwapOverrides {
    pub taker_timeout_secs: Option<u32>,
    pub maker_timeout_secs: Option<u32>,
    pub btc_confirmations: Option<u32>,
    pub divi_confirmations: Option<u32>,
    /// `[swap.chains.<ticker>]` for counter chains other than BTC (BTC and DIVI use the
    /// fields above).
    #[serde(default)]
    pub chains: BTreeMap<Chain, ChainOverrides>,
}

/// Per-chain overrides of the profile's [`divi_swap::ChainParams`].
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct ChainOverrides {
    pub confirmations: Option<u32>,
    pub mtp_lag_secs: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// SQLite database path.
    pub db_path: PathBuf,
    #[serde(default = "default_profile")]
    pub profile: Profile,
    /// Key the per-IP rate limit on the last `X-Forwarded-For` entry (else `X-Real-IP`) instead
    /// of the socket peer, for requests whose peer is in [`Self::trusted_proxies`]. Off by
    /// default: set it only behind a reverse proxy you control that sets those headers (the
    /// shipped nginx snippet does). On with an empty `trusted_proxies` is refused at start.
    #[serde(default)]
    pub trust_proxy_headers: bool,
    /// Socket peers (addresses or networks, `"a.b.c.d/n"`, `"x::y/n"`) whose proxy headers are
    /// believed when [`Self::trust_proxy_headers`] is on; any other peer is keyed on its own
    /// address, so a client that reaches the daemon directly cannot pick its bucket. Default
    /// `["127.0.0.1/32", "::1/128"]`: a proxy on the same host.
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<IpCidr>,
    /// File holding the operator token (one line) that `GET /swaps`, the full swap listing,
    /// requires in `X-Operator-Token`. Unset: the listing answers 404 to everyone. Keep the
    /// file out of git, mode 0600; the daemon reads it once at start.
    #[serde(default)]
    pub operator_token_file: Option<PathBuf>,
    /// Let a taker that cannot send swap tokens (built before them) open a swap anyway. That
    /// swap has no token, so anyone who learns its id can read it and call `lock` on it.
    /// Off by default: such a taker is refused at accept with a message to upgrade.
    #[serde(default)]
    pub allow_tokenless_swaps: bool,
    /// Optional path prefix. Empty by default: nginx strips `/swap/` before proxying.
    #[serde(default)]
    pub path_prefix: String,
    /// Seconds between scheduler ticks.
    #[serde(default = "default_tick")]
    pub tick_secs: u64,
    /// `[[offers]]` as written, including disabled ones; a built-in BTC pair is used when
    /// none are configured.
    #[serde(rename = "offers", default = "default_offer_entries")]
    pub offer_entries: Vec<OfferEntry>,
    /// The enabled offers — what the maker serves. Filled by [`DaemonConfig::parse`].
    #[serde(skip)]
    pub offers: Vec<Offer>,
    /// Ids of offers present but `enabled = false`. Filled by [`DaemonConfig::parse`].
    #[serde(skip)]
    pub disabled_offers: Vec<String>,
    /// `[divi]` and `[btc]` are required by the live backend, ignored by the mock one.
    pub divi: Option<DiviSection>,
    pub btc: Option<BtcSection>,
    /// Enables a live LTC counter backend; needed only for offers with `counter_chain =
    /// "ltc"`. Ignored by the mock backend (which always simulates LTC).
    pub ltc: Option<LtcSection>,
    /// Required only if an offer's `counter_chain` is `usdc`.
    pub usdc: Option<UsdcSection>,
    /// Enables a live ZEC counter backend; needed only for offers with `counter_chain =
    /// "zec"`. Ignored by the mock backend (which always simulates ZEC).
    pub zec: Option<ZecSection>,
    /// Enables the live adaptor-swap engine; needed only for offers with `counter_chain =
    /// "xmr"` (or xmr swaps still in flight). Ignored by the mock backend.
    pub xmr: Option<XmrSection>,
    /// Overrides on top of `profile`.
    #[serde(default)]
    pub swap: SwapOverrides,
}

impl DaemonConfig {
    /// The operator token from [`DaemonConfig::operator_token_file`], trimmed; `None` when no
    /// file is configured. A configured file that is unreadable or empty is an error (the
    /// listing would silently stay closed).
    pub fn operator_token(&self) -> Result<Option<String>> {
        let Some(p) = &self.operator_token_file else {
            return Ok(None);
        };
        let t = std::fs::read_to_string(p)
            .with_context(|| format!("reading operator_token_file {}", p.display()))?;
        let t = t.trim();
        if t.is_empty() {
            bail!("operator_token_file {} is empty", p.display());
        }
        Ok(Some(t.to_string()))
    }

    /// The peers the rate limits take the client address from: [`Self::trusted_proxies`] with
    /// [`Self::trust_proxy_headers`] on, none with it off.
    pub fn proxy_trust(&self) -> ProxyTrust {
        if self.trust_proxy_headers {
            ProxyTrust::proxies(self.trusted_proxies.iter().copied())
        } else {
            ProxyTrust::off()
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg: DaemonConfig = toml::from_str(text).context("parsing config")?;
        for e in &cfg.offer_entries {
            if e.enabled {
                cfg.offers.push(e.offer.clone());
            } else {
                cfg.disabled_offers.push(e.offer.id.clone());
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Whether an enabled offer trades against `chain` (so its live backend is needed).
    pub fn serves(&self, chain: Chain) -> bool {
        self.offers.iter().any(|o| o.counter_chain == chain)
    }

    /// Whether the config has a `[<chain>]` section for this non-BTC counter chain.
    fn has_section(&self, chain: Chain) -> bool {
        match chain {
            Chain::Ltc => self.ltc.is_some(),
            Chain::Usdc => self.usdc.is_some(),
            Chain::Zec => self.zec.is_some(),
            Chain::Xmr => self.xmr.is_some(),
            Chain::Btc => self.btc.is_some(),
            Chain::Divi => self.divi.is_some(),
        }
    }

    /// Non-BTC counter chains whose live backend to start: those an enabled offer serves or a
    /// non-terminal swap (`in_flight`) still runs on. A section whose offers are all disabled
    /// and that no swap needs is skipped (no API calls, nothing in `/healthz`); disabling an
    /// offer therefore never strands a swap already under way on that chain.
    pub fn counter_backends_to_start(&self, in_flight: &BTreeSet<Chain>) -> Result<Vec<Chain>> {
        let mut start = Vec::new();
        for c in Chain::ALL
            .into_iter()
            .filter(|c| c.is_counter() && *c != Chain::Btc && !c.is_adaptor())
        {
            let swaps = in_flight.contains(&c);
            let wanted = self.serves(c) || swaps;
            match (wanted, self.has_section(c)) {
                (true, true) => start.push(c),
                (true, false) if swaps => bail!(
                    "swaps in flight on {c} need the [{c}] section (restore it, or the maker \
                     cannot claim or refund them)"
                ),
                (true, false) => bail!(
                    "offer on {c} is enabled but there is no [{c}] section (add one, or set \
                     enabled = false)"
                ),
                (false, _) => {}
            }
        }
        Ok(start)
    }

    /// Whether to start the live adaptor-swap engine: an enabled xmr offer or `open_swaps`
    /// unfinished xmr swaps need it, and then it needs the `[xmr]` section (same rule as
    /// [`DaemonConfig::counter_backends_to_start`]).
    pub fn xmr_engine_needed(&self, open_swaps: usize) -> Result<bool> {
        let wanted = self.serves(Chain::Xmr) || open_swaps > 0;
        match (wanted, self.xmr.is_some()) {
            (true, true) => Ok(true),
            (true, false) if open_swaps > 0 => bail!(
                "{open_swaps} xmr swap(s) in flight need the [xmr] section (restore it, or the \
                 maker cannot redeem or refund them)"
            ),
            (true, false) => bail!(
                "offer on xmr is enabled but there is no [xmr] section (add one, or set \
                 enabled = false)"
            ),
            (false, _) => Ok(false),
        }
    }

    /// The profile's timing with `[swap]` overrides applied and validated.
    pub fn swap_config(&self) -> Result<divi_swap::SwapConfig> {
        let mut c = divi_swap::SwapConfig::profile(self.profile);
        let o = &self.swap;
        c.taker_timeout_secs = o.taker_timeout_secs.unwrap_or(c.taker_timeout_secs);
        c.maker_timeout_secs = o.maker_timeout_secs.unwrap_or(c.maker_timeout_secs);
        c.btc_confirmations = o.btc_confirmations.unwrap_or(c.btc_confirmations);
        c.divi_confirmations = o.divi_confirmations.unwrap_or(c.divi_confirmations);
        for (&chain, ov) in &o.chains {
            if matches!(chain, Chain::Btc | Chain::Divi) {
                bail!("[swap.chains.{chain}]: use btc_confirmations / divi_confirmations");
            }
            let mut p = c.chain_params(chain);
            p.confirmations = ov.confirmations.unwrap_or(p.confirmations);
            p.mtp_lag_secs = ov.mtp_lag_secs.unwrap_or(p.mtp_lag_secs);
            c.chains.insert(chain, p);
        }
        c.validate().map_err(|e| anyhow::anyhow!("[swap]: {e}"))?;
        Ok(c)
    }

    /// Normalised prefix: empty, or `/seg` with no trailing slash.
    pub fn prefix(&self) -> String {
        let p = self.path_prefix.trim_matches('/');
        if p.is_empty() {
            String::new()
        } else {
            format!("/{p}")
        }
    }

    /// The `[btc]`/`[ltc]` network gate, same rules and wording as `[zec]`: a known network
    /// name, `mainnet` only with `allow_mainnet = true`, and the network must agree with the
    /// swap timing `profile`.
    fn validate_mainnet_gate(
        &self,
        section: &str,
        network: &str,
        allow_mainnet: bool,
        test_networks: &[&str],
    ) -> Result<()> {
        if network != "mainnet" && !test_networks.contains(&network) {
            bail!(
                "[{section}].network must be {} or mainnet, got {network:?}",
                test_networks.join(", ")
            );
        }
        if network == "mainnet" && !allow_mainnet {
            bail!(
                "[{section}].network = \"mainnet\": {section} mainnet moves real money: no mainnet \
                 without the explicit allow_mainnet opt-in (mainnet-readiness.md §{})",
                section.to_uppercase()
            );
        }
        if (network == "mainnet") != (self.profile == Profile::Mainnet) {
            bail!(
                "[{section}].network = {network:?} disagrees with profile = {:?}: the swap timing \
                 profile and the {section} backend must run on the same network",
                self.profile
            );
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.tick_secs == 0 {
            bail!("tick_secs must be > 0");
        }
        if self.trust_proxy_headers && self.trusted_proxies.is_empty() {
            bail!(
                "trust_proxy_headers = true with an empty trusted_proxies: no peer's headers \
                 would be believed; list the proxy's address (default [\"127.0.0.1/32\", \"::1/128\"])"
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for o in self.offer_entries.iter().map(|e| &e.offer) {
            if !seen.insert(&o.id) {
                bail!("offer {}: duplicate id", o.id);
            }
            if o.min_btc_sats > o.max_btc_sats {
                bail!("offer {}: min_btc_sats > max_btc_sats", o.id);
            }
            if !o.counter_chain.is_counter() {
                bail!("offer {}: counter_chain cannot be divi", o.id);
            }
        }
        let refs = self
            .divi
            .iter()
            .map(|d| &d.key)
            .chain(self.btc.iter().map(|b| &b.key))
            .chain(self.ltc.iter().map(|l| &l.key))
            .chain(self.usdc.iter().map(|u| &u.key))
            .chain(self.zec.iter().map(|z| &z.key))
            .chain(self.xmr.iter().map(|x| &x.divi_key))
            .chain(
                self.xmr
                    .iter()
                    .filter_map(|x| x.wallet_rpc_password.as_ref()),
            );
        for r in refs {
            divi_swap::secrets::SecretRef::parse(r)
                .map_err(|e| anyhow::anyhow!("bad secret reference: {e}"))?;
        }
        if let Some(u) = &self.usdc {
            let network = u.network()?;
            u.fallback_rpc_url()?;
            if network.is_mainnet() && !u.allow_mainnet {
                bail!(
                    "[usdc].network = {:?}: usdc mainnet moves real money: no mainnet \
                     without the explicit allow_mainnet opt-in (mainnet-readiness.md §USDC/EVM)",
                    u.network
                );
            }
            if network.is_mainnet() && self.profile != Profile::Mainnet {
                bail!(
                    "[usdc].network = {:?} disagrees with profile = {:?}: the swap timing \
                     profile and the usdc backend must run on the same network",
                    u.network,
                    self.profile
                );
            }
        }
        if let Some(b) = &self.btc {
            self.validate_mainnet_gate("btc", &b.network, b.allow_mainnet, &["signet", "testnet"])?;
            b.validate_quorum_reads()?;
        }
        if let Some(l) = &self.ltc {
            self.validate_mainnet_gate("ltc", &l.network, l.allow_mainnet, &["testnet"])?;
            if l.crosscheck_source()?.is_some() && l.network != "mainnet" {
                bail!("[ltc].crosscheck is mainnet-only: no testnet source is verified");
            }
            if self.profile == Profile::Mainnet && l.crosscheck_source()?.is_none() {
                require_second_source("ltc", "[ltc].crosscheck is \"off\"", l.allow_single_source)?;
            }
        }
        if let Some(z) = &self.zec {
            match z.network.as_str() {
                "testnet" | "mainnet" => {}
                other => bail!("[zec].network must be testnet or mainnet, got {other:?}"),
            }
            if z.network == "mainnet" && !z.allow_mainnet {
                bail!(
                    "[zec].network = \"mainnet\": zec mainnet moves real money: no mainnet \
                     without the explicit allow_mainnet opt-in (mainnet-readiness.md §ZEC)"
                );
            }
            let zec_mainnet = z.network == "mainnet";
            let profile_mainnet = self.profile == Profile::Mainnet;
            if zec_mainnet != profile_mainnet {
                bail!(
                    "[zec].network = {:?} disagrees with profile = {:?}: the swap timing \
                     profile and the zec backend must run on the same network",
                    z.network,
                    self.profile
                );
            }
        }
        // One rule for every section (xmr and usdc have no gate of their own above). DIVI
        // is checked after the counter coins, so their errors are reported first.
        let mut coins: Vec<divi_swap::config::ConfiguredNetwork<'_>> = Vec::new();
        if let Some(b) = &self.btc {
            coins.push((Chain::Btc, &b.network, Some(b.allow_mainnet)));
        }
        if let Some(l) = &self.ltc {
            coins.push((Chain::Ltc, &l.network, Some(l.allow_mainnet)));
        }
        if let Some(z) = &self.zec {
            coins.push((Chain::Zec, &z.network, Some(z.allow_mainnet)));
        }
        if let Some(x) = &self.xmr {
            coins.push((Chain::Xmr, &x.network, Some(x.allow_mainnet)));
        }
        if let Some(u) = &self.usdc {
            coins.push((Chain::Usdc, &u.network, None));
        }
        divi_swap::config::check_profile_networks(self.profile, &coins)
            .map_err(anyhow::Error::msg)?;
        if let Some(d) = &self.divi {
            d.network()?;
            if d.network == "mainnet" && !d.allow_mainnet {
                bail!(
                    "[divi].network = \"mainnet\": divi mainnet moves real money: no mainnet \
                     without the explicit allow_mainnet opt-in (mainnet-readiness.md §DIVI)"
                );
            }
            if (d.network == "mainnet") != (self.profile == Profile::Mainnet) {
                bail!(
                    "[divi].network = {:?} disagrees with profile = {:?}: the swap timing \
                     profile and the divi backend must run on the same network",
                    d.network,
                    self.profile
                );
            }
            if self.profile == Profile::Mainnet && d.fallback_rpc_url()?.is_none() {
                require_second_source(
                    "divi",
                    "[divi].fallback_rpc_url is not set",
                    d.allow_single_source,
                )?;
            }
        }
        Ok(())
    }
}

/// A mainnet `[section]` without its second source (`missing` says which key): refused, unless
/// `[section].allow_single_source = true` waives it, which logs a warning. Config load runs at
/// every start, so the warning does too.
fn require_second_source(section: &str, missing: &str, waived: bool) -> Result<()> {
    if !waived {
        bail!(
            "{missing}: a mainnet [{section}] needs a second, independent source; set it, or set \
             [{section}].allow_single_source = true to run on one source deliberately"
        );
    }
    tracing::warn!(
        "{missing}: mainnet [{section}] runs on a single source ([{section}].allow_single_source \
         = true); one lying or broken endpoint is trusted for HTLC, confirmation and spend reads"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_chain_has_its_own_mock_rate() {
        assert_eq!(mock_divi_per_coin(Chain::Btc), 300_000_000_000_000);
        assert_eq!(mock_divi_per_coin(Chain::Ltc), 10_000 * 100_000_000);
        assert_eq!(mock_divi_per_coin(Chain::Zec), 5_000 * 100_000_000);
        assert_eq!(mock_divi_per_coin(Chain::Xmr), 5_000 * 100_000_000);
        for c in Chain::ALL {
            assert!(mock_divi_per_coin(c) > 0, "{c} has no rate");
        }
        assert_eq!(
            mock_xmr_offers()[0].divi_sats_per_btc,
            mock_divi_per_coin(Chain::Xmr)
        );
    }

    use super::*;

    const GOOD: &str = r#"
db_path = "/tmp/x.db"
path_prefix = "swap/"
[[offers]]
id = "o1"
divi_sats_per_btc = 100
min_btc_sats = 1
max_btc_sats = 10
[divi]
key = "op://v/i/f"
[btc]
key = "credential:btc"
"#;

    /// `GOOD` with its `[btc]` section on mainnet (allowed), for tests that set
    /// `profile = "mainnet"`: every live section must agree with the profile.
    fn good_mainnet_btc_only() -> String {
        GOOD.replace(
            "[btc]\nkey",
            "[btc]\nnetwork = \"mainnet\"\nallow_mainnet = true\nkey",
        )
    }

    /// As [`good_mainnet_btc_only`], with `[divi]` on mainnet (allowed) too, and the second
    /// DIVI endpoint a mainnet config needs.
    fn good_mainnet_btc() -> String {
        good_mainnet_btc_only().replace(
            "[divi]\nkey",
            "[divi]\nnetwork = \"mainnet\"\nallow_mainnet = true\n\
             fallback_rpc_url = \"http://127.0.0.1:51473\"\nkey",
        )
    }

    #[test]
    fn btc_quorum_reads_are_off_by_default_and_need_two_endpoints() {
        let b = DaemonConfig::parse(GOOD).unwrap().btc.unwrap();
        assert!(!b.quorum_reads);
        let with = |extra: &str| {
            DaemonConfig::parse(&GOOD.replace("[btc]\n", &format!("[btc]\n{extra}\n")))
        };
        // The network's two defaults are a quorum.
        assert!(
            with("quorum_reads = true")
                .unwrap()
                .btc
                .unwrap()
                .quorum_reads
        );
        let two = "esplora_url = \"http://a:1\"\nfallback_esplora_url = \"http://b:2\"";
        assert!(with(&format!("{two}\nquorum_reads = true")).is_ok());
        // One endpoint, or the same one twice, is refused at load, naming both keys.
        for one in [
            "esplora_url = \"http://a:1\"",
            "esplora_url = \"http://a:1\"\nfallback_esplora_url = \"http://a:1/\"",
        ] {
            let err = with(&format!("{one}\nquorum_reads = true"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("[btc].quorum_reads") && err.contains("[btc].fallback_esplora_url"),
                "{err}"
            );
            // Off, the same single endpoint is fine (failover only, as before).
            assert!(with(one).is_ok());
        }
    }

    #[test]
    fn divi_fallback_rpc_url_is_off_by_default_and_must_differ_from_the_primary() {
        let d = DaemonConfig::parse(GOOD).unwrap().divi.unwrap();
        assert_eq!(d.fallback_rpc_url().unwrap(), None);
        let with = |extra: &str| {
            DaemonConfig::parse(&GOOD.replace("[divi]\n", &format!("[divi]\n{extra}\n")))
                .unwrap()
                .divi
                .unwrap()
        };
        let d = with("rpc_url = \"http://a:1\"\nfallback_rpc_url = \" http://b:2 \"");
        assert_eq!(d.fallback_rpc_url().unwrap().as_deref(), Some("http://b:2"));
        let d = with("fallback_rpc_url = \"  \"");
        assert_eq!(d.fallback_rpc_url().unwrap(), None);
        let d = with("rpc_url = \"http://a:1\"\nfallback_rpc_url = \"http://a:1\"");
        assert!(d.fallback_rpc_url().is_err());
    }

    #[test]
    fn usdc_fallback_rpc_url_is_off_by_default_and_must_differ_from_the_primary() {
        let usdc = |extra: &str| {
            DaemonConfig::parse(&format!(
                "{GOOD}\n[usdc]\n{extra}\nhtlc = \"0x00\"\nkey = \"credential:usdc\"\n"
            ))
        };
        let u = usdc("").unwrap().usdc.unwrap();
        assert_eq!(u.fallback_rpc_url, None);
        assert_eq!(u.fallback_rpc_url().unwrap(), None);
        let u = usdc("fallback_rpc_url = \"  \"").unwrap().usdc.unwrap();
        assert_eq!(u.fallback_rpc_url().unwrap(), None);
        let u = usdc("rpc_url = \"http://a:1\"\nfallback_rpc_url = \" http://b:2 \"")
            .unwrap()
            .usdc
            .unwrap();
        assert_eq!(u.fallback_rpc_url().unwrap().as_deref(), Some("http://b:2"));
        // The same node twice is refused at load, naming both keys: an explicit primary, and
        // the network's default primary when `rpc_url` is unset.
        let default = swap_chain_evm::UsdcNetwork::Sepolia.default_rpc_url();
        for same in [
            "rpc_url = \"http://a:1\"\nfallback_rpc_url = \" http://a:1/ \"".to_string(),
            format!("fallback_rpc_url = \"{default}\""),
        ] {
            let err = usdc(&same).unwrap_err().to_string();
            assert!(
                err.contains("[usdc].fallback_rpc_url") && err.contains("[usdc].rpc_url"),
                "{err}"
            );
        }
    }

    #[test]
    fn divi_section_defaults_to_testnet_and_its_rpc() {
        let d = DaemonConfig::parse(GOOD).unwrap().divi.unwrap();
        assert_eq!(d.network, "testnet");
        assert!(!d.allow_mainnet);
        assert_eq!(d.rpc_url().unwrap(), swap_chain_divi::TESTNET_RPC);
        assert_eq!(d.rpc_url().unwrap(), default_divi_rpc());
    }

    #[test]
    fn divi_mainnet_with_allow_and_matching_profile_is_ok_with_the_mainnet_default_rpc() {
        let text = format!("profile = \"mainnet\"\n{}", good_mainnet_btc());
        let d = DaemonConfig::parse(&text).unwrap().divi.unwrap();
        assert!(d.allow_mainnet);
        assert_eq!(d.network().unwrap(), divi_wallet::address::Network::Mainnet);
        assert_eq!(d.rpc_url().unwrap(), swap_chain_divi::MAINNET_RPC);
        // An explicit rpc_url wins over the network default.
        let text = text.replace("[divi]\n", "[divi]\nrpc_url = \"http://localhost:9\"\n");
        let d = DaemonConfig::parse(&text).unwrap().divi.unwrap();
        assert_eq!(d.rpc_url().unwrap(), "http://localhost:9");
    }

    #[test]
    fn divi_mainnet_without_allow_mainnet_is_rejected() {
        let text = format!(
            "profile = \"mainnet\"\n{}",
            good_mainnet_btc().replace(
                "[divi]\nnetwork = \"mainnet\"\nallow_mainnet = true\n",
                "[divi]\nnetwork = \"mainnet\"\n"
            )
        );
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(
            e.contains("[divi].network = \"mainnet\": divi mainnet moves real money")
                && e.contains("no mainnet without the explicit allow_mainnet"),
            "{e}"
        );
    }

    #[test]
    fn divi_bad_network_is_rejected() {
        let text = GOOD.replace("[divi]\nkey", "[divi]\nnetwork = \"regtest\"\nkey");
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(
            e.contains("[divi].network must be testnet or mainnet"),
            "{e}"
        );
    }

    #[test]
    fn divi_mainnet_under_a_testnet_profile_is_rejected_even_with_allow() {
        // btc on signet so the btc check passes first; the default profile is testnet.
        let text = GOOD.replace(
            "[divi]\nkey",
            "[divi]\nnetwork = \"mainnet\"\nallow_mainnet = true\nkey",
        );
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(
            e.contains("[divi].network = \"mainnet\" disagrees with profile = Testnet")
                && e.contains("must run on the same network"),
            "{e}"
        );
    }

    #[test]
    fn divi_testnet_under_a_mainnet_profile_is_rejected() {
        // The dangerous direction before this lane: real BTC, DIVI silently on testnet.
        let text = format!("profile = \"mainnet\"\n{}", good_mainnet_btc_only());
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(
            e.contains("[divi].network = \"testnet\" disagrees with profile = Mainnet"),
            "{e}"
        );
    }

    #[test]
    fn parses_and_normalises_prefix() {
        let c = DaemonConfig::parse(GOOD).unwrap();
        assert_eq!(c.prefix(), "/swap");
        assert_eq!(c.profile, Profile::Testnet);
    }

    /// A config from before `trusted_proxies` loads, with the loopback default and the flag
    /// off (so no peer's headers are read).
    #[test]
    fn an_old_config_without_trusted_proxies_loads() {
        let c = DaemonConfig::parse(GOOD).unwrap();
        assert!(!c.trust_proxy_headers);
        assert_eq!(c.trusted_proxies, crate::proxy::default_trusted_proxies());
        assert!(!c.proxy_trust().trusts("127.0.0.1".parse().unwrap()));
        let on = DaemonConfig::parse(&format!("trust_proxy_headers = true\n{GOOD}")).unwrap();
        let t = on.proxy_trust();
        assert!(t.trusts("127.0.0.1".parse().unwrap()) && t.trusts("::1".parse().unwrap()));
        assert!(!t.trusts("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn trusted_proxies_take_addresses_and_networks() {
        let c = DaemonConfig::parse(&format!(
            "trust_proxy_headers = true\ntrusted_proxies = [\"10.0.0.0/8\", \"192.0.2.7\", \"fd00::/8\"]\n{GOOD}"
        ))
        .unwrap();
        let t = c.proxy_trust();
        for (ip, trusted) in [
            ("10.9.8.7", true),
            ("192.0.2.7", true),
            ("192.0.2.8", false),
            ("fd12::1", true),
            ("127.0.0.1", false),
        ] {
            assert_eq!(t.trusts(ip.parse().unwrap()), trusted, "{ip}");
        }
        for bad in ["\"10.0.0.1/8\"", "\"10.0.0.0/33\"", "\"nonsense\"", "8"] {
            let err = DaemonConfig::parse(&format!("trusted_proxies = [{bad}]\n{GOOD}"));
            assert!(err.is_err(), "{bad} accepted");
        }
    }

    /// The example's commented proxy lines, uncommented, parse to the documented defaults.
    #[test]
    fn deploy_example_proxy_lines_parse_uncommented() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/divi-swapd/divi-swapd.toml.example");
        let text = std::fs::read_to_string(path).unwrap();
        let on = text
            .replace("# trust_proxy_headers = true", "trust_proxy_headers = true")
            .replace("# trusted_proxies = ", "trusted_proxies = ");
        assert_ne!(on, text);
        let c = DaemonConfig::parse(&on).unwrap();
        assert!(c.trust_proxy_headers);
        assert_eq!(c.trusted_proxies, crate::proxy::default_trusted_proxies());
    }

    /// Fails on 75c9b7c, which had no `trusted_proxies` (the key was ignored and the flag
    /// alone trusted every peer).
    #[test]
    fn trust_proxy_headers_with_no_trusted_proxies_is_refused() {
        let err = DaemonConfig::parse(&format!(
            "trust_proxy_headers = true\ntrusted_proxies = []\n{GOOD}"
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("trusted_proxies"), "{err}");
        // With the flag off an empty list is harmless: the headers are never read.
        DaemonConfig::parse(&format!("trusted_proxies = []\n{GOOD}")).unwrap();
    }

    #[test]
    fn parses_deploy_example() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/divi-swapd/divi-swapd.toml.example");
        let c = DaemonConfig::load(&path).unwrap();
        assert_eq!(c.listen.port(), 18480);
        assert!(!c.trust_proxy_headers, "shipped commented out");
        assert_eq!(c.trusted_proxies, crate::proxy::default_trusted_proxies());
        assert_eq!(c.prefix(), "");
        assert_eq!(c.offers[0].id, "divi-btc-testnet");
        let d = c.divi.unwrap();
        assert_eq!(d.key, "credential:maker-divi");
        assert_eq!(d.scan_from_height, Some(339800));
        assert!(d.wallet_path.is_some());
        let b = c.btc.unwrap();
        assert_eq!(b.network, "signet");
        assert!(b.fallback_esplora_url.is_some());
        let l = c.ltc.unwrap();
        assert_eq!(l.network, "testnet");
        assert_eq!(
            l.endpoints().unwrap()[0],
            swap_chain_ltc::LITECOINSPACE_TESTNET
        );
        // Reuses the BTC swap key (funding.md decision 64ae2a0); no maker-ltc item exists.
        assert_eq!(l.key, "credential:maker-btc");
        let ltc_ids: Vec<_> = c
            .offer_entries
            .iter()
            .filter(|e| e.offer.counter_chain == Chain::Ltc)
            .map(|e| e.offer.id.as_str())
            .collect();
        assert_eq!(ltc_ids, ["divi-ltc-testnet", "ltc-divi-testnet"]);
        // Served: BTC both ways and LTC forward. The reverse LTC offer (maker pays LTC), USDC
        // (placeholder contract) and ZEC (no TAZ yet) are off.
        let served: Vec<_> = c.offers.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(
            served,
            ["divi-btc-testnet", "btc-divi-testnet", "divi-ltc-testnet"]
        );
        assert!(c
            .offers
            .iter()
            .all(|o| !matches!(o.counter_chain, Chain::Usdc | Chain::Zec)));
        assert!(c.zec.is_some() && c.usdc.is_some());
    }

    #[test]
    fn swap_overrides_apply_and_are_validated() {
        let ok = format!("{GOOD}\n[swap]\nmaker_timeout_secs = 1800\ntaker_timeout_secs = 20000\n");
        let c = DaemonConfig::parse(&ok).unwrap().swap_config().unwrap();
        assert_eq!((c.maker_timeout_secs, c.taker_timeout_secs), (1800, 20000));
        let bad = format!("{GOOD}\n[swap]\nmaker_timeout_secs = 1800\ntaker_timeout_secs = 3600\n");
        assert!(DaemonConfig::parse(&bad).unwrap().swap_config().is_err());
    }

    #[test]
    fn old_config_without_direction_parses() {
        let c = DaemonConfig::parse(GOOD).unwrap();
        assert_eq!(c.offers[0].direction, Direction::TakerPaysBtc);
        let reverse = GOOD.replace(
            "id = \"o1\"",
            "id = \"o1\"\ndirection = \"taker_pays_divi\"",
        );
        let c = DaemonConfig::parse(&reverse).unwrap();
        assert_eq!(c.offers[0].direction, Direction::TakerPaysDivi);
    }

    #[test]
    fn default_offers_cover_both_directions() {
        let text = "db_path = \"/tmp/x.db\"";
        let c = DaemonConfig::parse(text).unwrap();
        let ids: Vec<_> = c
            .offers
            .iter()
            .map(|o| (o.id.as_str(), o.direction))
            .collect();
        assert_eq!(
            ids,
            [
                ("divi-btc-testnet", Direction::TakerPaysBtc),
                ("btc-divi-testnet", Direction::TakerPaysDivi)
            ]
        );
        assert_eq!(c.offers[0].divi_sats_per_btc, c.offers[1].divi_sats_per_btc);
    }

    #[test]
    fn counter_chain_offers_and_overrides_parse() {
        let text = format!(
            "{GOOD}\n[[offers]]\nid = \"ltc-divi-testnet\"\ndirection = \"taker_pays_divi\"\n\
             counter_chain = \"ltc\"\ndivi_sats_per_btc = 1\nmin_btc_sats = 1\nmax_btc_sats = 2\n\
             [swap.chains.ltc]\nconfirmations = 4\n[swap.chains.zec]\nmtp_lag_secs = 900\n"
        );
        let c = DaemonConfig::parse(&text).unwrap();
        assert_eq!(c.offers[0].counter_chain, Chain::Btc);
        assert_eq!(c.offers[1].counter_chain, Chain::Ltc);
        let s = c.swap_config().unwrap();
        assert_eq!(s.confirmations(Chain::Ltc), 4);
        assert_eq!(s.chain_params(Chain::Ltc).mtp_lag_secs, 1800);
        assert_eq!(s.chain_params(Chain::Zec).mtp_lag_secs, 900);
        // Unset in [swap.chains.zec]: the testnet profile's own value.
        assert_eq!(
            s.confirmations(Chain::Zec),
            divi_swap::SwapConfig::profile(Profile::Testnet).confirmations(Chain::Zec)
        );
        assert_eq!(s.confirmations(Chain::Btc), 1);

        let bad = format!("{GOOD}\n[swap.chains.btc]\nconfirmations = 4\n");
        assert!(DaemonConfig::parse(&bad).unwrap().swap_config().is_err());
        let divi = GOOD.replace("id = \"o1\"", "id = \"o1\"\ncounter_chain = \"divi\"");
        assert!(DaemonConfig::parse(&divi).is_err());
    }

    #[test]
    fn disabled_offers_parse_but_are_not_served() {
        let text = format!(
            "{GOOD}\n[[offers]]\nid = \"divi-zec-testnet\"\ncounter_chain = \"zec\"\n\
             enabled = false\ndivi_sats_per_btc = 1\nmin_btc_sats = 1\nmax_btc_sats = 2\n\
             [[offers]]\nid = \"divi-ltc-testnet\"\ncounter_chain = \"ltc\"\nenabled = true\n\
             divi_sats_per_btc = 1\nmin_btc_sats = 1\nmax_btc_sats = 2\n\
             [zec]\nkey = \"credential:maker-btc\"\n"
        );
        let c = DaemonConfig::parse(&text).unwrap();
        let ids: Vec<_> = c.offers.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["o1", "divi-ltc-testnet"]);
        assert_eq!(c.disabled_offers, ["divi-zec-testnet"]);
        assert_eq!(c.offer_entries.len(), 3);
        assert!(c.serves(Chain::Ltc) && c.serves(Chain::Btc));
        assert!(
            !c.serves(Chain::Zec),
            "[zec] present but every zec offer is off"
        );
        // Disabled offers are still validated, and ids must be unique across both.
        let bad = text.replace(
            "min_btc_sats = 1\nmax_btc_sats = 2\n[[offers]]",
            "min_btc_sats = 3\nmax_btc_sats = 2\n[[offers]]",
        );
        assert!(DaemonConfig::parse(&bad).is_err());
        let dup = text.replace("divi-zec-testnet", "o1");
        assert!(DaemonConfig::parse(&dup).is_err());
    }

    #[test]
    fn counter_backends_follow_offers_and_in_flight_swaps() {
        let with = |extra: &str| {
            DaemonConfig::parse(&format!(
                "{GOOD}\n[[offers]]\nid = \"divi-ltc-testnet\"\ncounter_chain = \"ltc\"\n\
                 {extra}divi_sats_per_btc = 1\nmin_btc_sats = 1\nmax_btc_sats = 2\n\
                 [ltc]\nkey = \"credential:maker-btc\"\n[zec]\nkey = \"credential:maker-btc\"\n"
            ))
            .unwrap()
        };
        let none = BTreeSet::new();
        let ltc_swap = BTreeSet::from([Chain::Ltc]);
        // Served → started; [zec] present but unused → skipped.
        assert_eq!(
            with("").counter_backends_to_start(&none).unwrap(),
            [Chain::Ltc]
        );
        // Offer switched off: skipped, unless a swap still runs on LTC.
        let off = with("enabled = false\n");
        assert!(off.counter_backends_to_start(&none).unwrap().is_empty());
        assert_eq!(
            off.counter_backends_to_start(&ltc_swap).unwrap(),
            [Chain::Ltc]
        );
        // ZEC swap in flight with its section present: started even with no zec offer.
        let zec_swap = BTreeSet::from([Chain::Zec]);
        assert_eq!(
            off.counter_backends_to_start(&zec_swap).unwrap(),
            [Chain::Zec]
        );
        // Section removed while a swap needs it, or an enabled offer without a section: refuse.
        let no_section = DaemonConfig::parse(GOOD).unwrap();
        let err = no_section.counter_backends_to_start(&ltc_swap).unwrap_err();
        assert!(err.to_string().contains("swaps in flight on ltc"), "{err}");
        let bare = DaemonConfig::parse(&format!(
            "{GOOD}\n[[offers]]\nid = \"z\"\ncounter_chain = \"zec\"\n\
             divi_sats_per_btc = 1\nmin_btc_sats = 1\nmax_btc_sats = 2\n"
        ))
        .unwrap();
        assert!(bare.counter_backends_to_start(&none).is_err());
    }

    const XMR: &str = r#"
[[offers]]
id = "divi-xmr-stagenet"
counter_chain = "xmr"
divi_sats_per_btc = 500000000000
min_btc_sats = 100000
max_btc_sats = 100000000
"#;
    const XMR_SECTION: &str = r#"
[xmr]
monerod_url = "http://127.0.0.1:38081"
wallet_rpc_url = "http://127.0.0.1:38088"
wallet_rpc_user = "swap"
wallet_rpc_password = "credential:maker-xmr-wallet-rpc"
sweep_address = "5Aaaa"
divi_key = "credential:maker-divi-xmr"
divi_fund_txids = ["ab"]
"#;

    #[test]
    fn xmr_section_without_wallet_rpc_keys_loads() {
        let section = XMR_SECTION
            .lines()
            .filter(|l| !l.starts_with("wallet_rpc_"))
            .collect::<Vec<_>>()
            .join("\n");
        let c = DaemonConfig::parse(&format!("{GOOD}{XMR}{section}")).unwrap();
        let x = c.xmr.as_ref().unwrap();
        assert!(x.wallet_rpc_url.is_none() && x.wallet_rpc_password.is_none());
        assert!(x.wallet_rpc_user.is_empty());
        // Keys that are present are still parsed and checked as before.
        let c = DaemonConfig::parse(&format!("{GOOD}{XMR}{XMR_SECTION}")).unwrap();
        let x = c.xmr.as_ref().unwrap();
        assert_eq!(x.wallet_rpc_url.as_deref(), Some("http://127.0.0.1:38088"));
        assert_eq!(x.wallet_rpc_user, "swap");
    }

    #[test]
    fn xmr_section_parses_with_defaults_and_rejects_raw_secrets() {
        let c = DaemonConfig::parse(&format!("{GOOD}{XMR}{XMR_SECTION}")).unwrap();
        let x = c.xmr.as_ref().unwrap();
        assert_eq!(x.network, "stagenet");
        assert!(
            !x.allow_mainnet,
            "mainnet must stay off unless the config says so"
        );
        assert_eq!(x.lookback_blocks, 720);
        assert_eq!(x.divi_rpc_url, default_divi_rpc());
        assert!(x.journal_dir.is_none() && x.divi_wallet_path.is_none());
        assert_eq!(x.divi_fund_txids, ["ab"]);
        assert!(c.serves(Chain::Xmr));
        // xmr never gets a ChainBackend.
        assert!(c
            .counter_backends_to_start(&BTreeSet::from([Chain::Xmr]))
            .unwrap()
            .is_empty());
        for raw in [
            XMR_SECTION.replace("credential:maker-divi-xmr", "deadbeefdeadbeef"),
            XMR_SECTION.replace("credential:maker-xmr-wallet-rpc", "hunter2"),
        ] {
            assert!(DaemonConfig::parse(&format!("{GOOD}{XMR}{raw}")).is_err());
        }
    }

    #[test]
    fn xmr_engine_follows_offers_and_open_swaps() {
        let parse = |t: String| DaemonConfig::parse(&t).unwrap();
        let both = parse(format!("{GOOD}{XMR}{XMR_SECTION}"));
        assert!(both.xmr_engine_needed(0).unwrap());
        let off = parse(format!(
            "{GOOD}{}{XMR_SECTION}",
            XMR.replace("counter_chain", "enabled = false\ncounter_chain")
        ));
        assert!(!off.xmr_engine_needed(0).unwrap());
        assert!(off.xmr_engine_needed(1).unwrap());
        let no_section = parse(format!("{GOOD}{XMR}"));
        let e = no_section.xmr_engine_needed(0).unwrap_err();
        assert!(e.to_string().contains("no [xmr] section"), "{e}");
        let plain = parse(GOOD.to_string());
        assert!(!plain.xmr_engine_needed(0).unwrap());
        let e = plain.xmr_engine_needed(2).unwrap_err();
        assert!(e.to_string().contains("2 xmr swap(s) in flight"), "{e}");
    }

    #[test]
    fn btc_ltc_sections_default_to_test_networks_without_mainnet() {
        let c = DaemonConfig::parse(&format!("{GOOD}\n[ltc]\nkey = \"credential:btc\"\n")).unwrap();
        let b = c.btc.unwrap();
        assert_eq!(b.network, "signet");
        assert!(
            !b.allow_mainnet,
            "mainnet must stay off unless the config says so"
        );
        let l = c.ltc.unwrap();
        assert_eq!(l.network, "testnet");
        assert!(!l.allow_mainnet);
    }

    #[test]
    fn btc_ltc_mainnet_without_allow_is_rejected() {
        for section in ["btc", "ltc"] {
            let text = if section == "btc" {
                "[btc]\nnetwork = \"mainnet\"\nkey = \"credential:btc\"\n".to_string()
            } else {
                format!("{GOOD}\n[ltc]\nnetwork = \"mainnet\"\nkey = \"credential:btc\"\n")
            };
            let text = if section == "btc" {
                GOOD.replace("[btc]\nkey = \"credential:btc\"\n", &text)
            } else {
                text
            };
            let e = DaemonConfig::parse(&text).unwrap_err();
            assert!(
                e.to_string()
                    .contains("no mainnet without the explicit allow_mainnet"),
                "{section}: {e}"
            );
        }
    }

    #[test]
    fn btc_ltc_mainnet_with_allow_and_matching_profile_is_ok_with_crate_default_endpoints() {
        let text = format!(
            "profile = \"mainnet\"\n{}\n[ltc]\nnetwork = \"mainnet\"\nallow_mainnet = true\n\
             key = \"credential:btc\"\ncrosscheck = \"blockbook\"\n",
            good_mainnet_btc()
        );
        let c = DaemonConfig::parse(&text).unwrap();
        let b = c.btc.unwrap();
        assert!(b.allow_mainnet);
        assert_eq!(b.endpoints().unwrap()[0], "https://mempool.space/api");
        let l = c.ltc.unwrap();
        assert_eq!(
            l.endpoints().unwrap(),
            vec!["https://litecoinspace.org/api"]
        );
    }

    #[test]
    fn ltc_crosscheck_defaults_off_and_is_mainnet_only() {
        let c = DaemonConfig::parse(&format!("{GOOD}\n[ltc]\nkey = \"credential:btc\"\n")).unwrap();
        assert_eq!(c.ltc.unwrap().crosscheck_source().unwrap(), None);
        // Testnet refuses any source at config load (no testnet source is verified).
        for src in ["blockbook", "blockcypher"] {
            let text = format!("{GOOD}\n[ltc]\nkey = \"credential:btc\"\ncrosscheck = \"{src}\"\n");
            let e = DaemonConfig::parse(&text).unwrap_err();
            assert!(
                e.to_string().contains("[ltc].crosscheck is mainnet-only"),
                "{e}"
            );
        }
        // `off` is fine on testnet; an unknown value is refused anywhere.
        let ok = format!("{GOOD}\n[ltc]\nkey = \"credential:btc\"\ncrosscheck = \"off\"\n");
        DaemonConfig::parse(&ok).unwrap();
        let bad = format!("{GOOD}\n[ltc]\nkey = \"credential:btc\"\ncrosscheck = \"esplora\"\n");
        let e = DaemonConfig::parse(&bad).unwrap_err();
        assert!(e.to_string().contains("[ltc].crosscheck"), "{e}");
    }

    #[test]
    fn ltc_crosscheck_is_accepted_on_mainnet() {
        for (src, want) in [
            ("blockbook", swap_chain_ltc::CrossCheckSource::Blockbook),
            ("blockcypher", swap_chain_ltc::CrossCheckSource::BlockCypher),
        ] {
            let text = format!(
                "profile = \"mainnet\"\n{}\n[ltc]\nnetwork = \"mainnet\"\nallow_mainnet = true\n\
                 key = \"credential:btc\"\ncrosscheck = \"{src}\"\n",
                good_mainnet_btc()
            );
            let c = DaemonConfig::parse(&text).unwrap();
            assert_eq!(c.ltc.unwrap().crosscheck_source().unwrap(), Some(want));
        }
    }

    #[test]
    fn btc_ltc_network_disagreeing_with_profile_is_rejected() {
        // Default profile is testnet; an allowed mainnet section still disagrees.
        let text = GOOD.replace(
            "[btc]\nkey",
            "[btc]\nnetwork = \"mainnet\"\nallow_mainnet = true\nkey",
        );
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(e.to_string().contains("disagrees with profile"), "{e}");
        // Reverse: mainnet profile with a test-network [ltc] section.
        let text = format!("profile = \"mainnet\"\n{GOOD}\n[ltc]\nkey = \"credential:btc\"\n");
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(
            e.to_string()
                .contains("[btc].network = \"signet\" disagrees with profile"),
            "{e}"
        );
    }

    #[test]
    fn btc_ltc_bad_network_is_rejected() {
        let text = GOOD.replace("[btc]\nkey", "[btc]\nnetwork = \"regtest\"\nkey");
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(
            e.to_string()
                .contains("[btc].network must be signet, testnet or mainnet"),
            "{e}"
        );
        let text = format!("{GOOD}\n[ltc]\nnetwork = \"signet\"\nkey = \"credential:btc\"\n");
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(
            e.to_string()
                .contains("[ltc].network must be testnet or mainnet"),
            "{e}"
        );
    }

    #[test]
    fn zec_section_defaults_to_testnet() {
        let text = format!("{GOOD}\n[zec]\nkey = \"credential:maker-btc\"\n");
        let c = DaemonConfig::parse(&text).unwrap();
        let z = c.zec.unwrap();
        assert_eq!(z.network, "testnet");
        assert!(
            !z.allow_mainnet,
            "mainnet must stay off unless the config says so"
        );
        assert!(z.lightwalletd_url.is_none());
    }

    #[test]
    fn zec_mainnet_without_allow_is_rejected() {
        let text =
            format!("{GOOD}\n[zec]\nnetwork = \"mainnet\"\nkey = \"credential:maker-btc\"\n");
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(
            e.to_string()
                .contains("no mainnet without the explicit allow_mainnet"),
            "{e}"
        );
    }

    #[test]
    fn zec_mainnet_with_allow_and_matching_profile_is_ok() {
        // `profile` is a bare top-level key: it must come before GOOD's first `[table]`
        // header, or TOML scopes it into GOOD's last section ([btc]) instead.
        let text = format!(
            "profile = \"mainnet\"\n{}\n[zec]\nnetwork = \"mainnet\"\nallow_mainnet = true\n\
             key = \"credential:maker-btc\"\n",
            good_mainnet_btc()
        );
        let c = DaemonConfig::parse(&text).unwrap();
        let z = c.zec.unwrap();
        assert_eq!(z.network, "mainnet");
        assert!(z.allow_mainnet);
    }

    const USDC_KEY: &str =
        "key = \"credential:maker-usdc\"\nhtlc = \"0x1111111111111111111111111111111111111111\"\n";

    #[test]
    fn usdc_section_defaults_to_sepolia_with_mainnet_off() {
        let c = DaemonConfig::parse(&format!("{GOOD}\n[usdc]\n{USDC_KEY}")).unwrap();
        let u = c.usdc.unwrap();
        assert_eq!(u.network, "sepolia");
        assert!(
            !u.allow_mainnet,
            "mainnet must stay off unless the config says so"
        );
        assert!(!u.network().unwrap().is_mainnet());
    }

    #[test]
    fn usdc_mainnet_without_allow_is_rejected() {
        for net in ["ethereum", "base"] {
            // Even with the matching profile: the opt-in is a separate gate.
            let text = format!(
                "profile = \"mainnet\"\n{}\n[usdc]\nnetwork = \"{net}\"\n{USDC_KEY}",
                good_mainnet_btc()
            );
            let e = DaemonConfig::parse(&text).unwrap_err();
            assert!(
                e.to_string()
                    .contains("no mainnet without the explicit allow_mainnet"),
                "{net}: {e}"
            );
        }
    }

    #[test]
    fn usdc_mainnet_with_allow_and_matching_profile_is_ok() {
        for net in ["ethereum", "base"] {
            let text = format!(
                "profile = \"mainnet\"\n{}\n[usdc]\nnetwork = \"{net}\"\n\
                 allow_mainnet = true\n{USDC_KEY}",
                good_mainnet_btc()
            );
            let u = DaemonConfig::parse(&text).unwrap().usdc.unwrap();
            assert_eq!(u.network, net);
            assert!(u.allow_mainnet && u.network().unwrap().is_mainnet());
        }
    }

    #[test]
    fn usdc_mainnet_disagreeing_with_profile_is_rejected() {
        for net in ["ethereum", "base"] {
            // Default profile is testnet; an allowed mainnet [usdc] section disagrees.
            let text =
                format!("{GOOD}\n[usdc]\nnetwork = \"{net}\"\nallow_mainnet = true\n{USDC_KEY}");
            let e = DaemonConfig::parse(&text).unwrap_err();
            assert!(
                e.to_string().contains("disagrees with profile"),
                "{net}: {e}"
            );
        }
    }

    #[test]
    fn zec_bad_network_is_rejected() {
        let text =
            format!("{GOOD}\n[zec]\nnetwork = \"regtest\"\nkey = \"credential:maker-btc\"\n");
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(
            e.to_string()
                .contains("[zec].network must be testnet or mainnet"),
            "{e}"
        );
    }

    #[test]
    fn zec_network_disagreeing_with_profile_is_rejected() {
        // Default profile is testnet; a mainnet [zec] section (even allowed) disagrees.
        let text = format!(
            "{GOOD}\n[zec]\nnetwork = \"mainnet\"\nallow_mainnet = true\n\
             key = \"credential:maker-btc\"\n"
        );
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(e.to_string().contains("disagrees with profile"), "{e}");
        // And the reverse: mainnet profile with a testnet [zec] section.
        let text =
            format!("profile = \"mainnet\"\n{GOOD}\n[zec]\nkey = \"credential:maker-btc\"\n");
        let e = DaemonConfig::parse(&text).unwrap_err();
        assert!(e.to_string().contains("disagrees with profile"), "{e}");
    }

    #[test]
    fn zec_absent_lightwalletd_url_resolves_networks_probed_defaults() {
        let text = format!(
            "profile = \"mainnet\"\n{}\n[zec]\nnetwork = \"mainnet\"\nallow_mainnet = true\n\
             key = \"credential:maker-btc\"\n",
            good_mainnet_btc()
        );
        let c = DaemonConfig::parse(&text).unwrap();
        let eps = c.zec.unwrap().endpoints().unwrap();
        assert!(!eps.is_empty());
        assert_eq!(eps[0], "https://zec.rocks:443");

        let t = DaemonConfig::parse(&format!("{GOOD}\n[zec]\nkey = \"credential:maker-btc\"\n"))
            .unwrap();
        let eps = t.zec.unwrap().endpoints().unwrap();
        assert_eq!(eps, vec![swap_chain_zec::TESTNET_LIGHTWALLETD.to_string()]);
    }

    #[test]
    fn zec_explicit_lightwalletd_url_stays_primary_with_fallback_after() {
        let text = format!(
            "{GOOD}\n[zec]\nlightwalletd_url = \"https://primary:443\"\n\
             fallback_lightwalletd_url = \"https://fallback:443\"\nkey = \"credential:maker-btc\"\n"
        );
        let c = DaemonConfig::parse(&text).unwrap();
        let eps = c.zec.unwrap().endpoints().unwrap();
        assert_eq!(eps, vec!["https://primary:443", "https://fallback:443"]);
    }

    #[test]
    fn wave4_snippet_on_the_deployed_config() {
        // What dnsdivi runs today (pre-counter-chain BTC pair) + the wave-4 append.
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/divi-swapd");
        let deployed = "db_path = \"/var/lib/divi-swapd/swaps.db\"\n\
            [divi]\nkey = \"credential:maker-divi\"\n[btc]\nkey = \"credential:maker-btc\"\n\
            [[offers]]\nid = \"divi-btc-testnet\"\ndivi_sats_per_btc = 300000000000000\n\
            min_btc_sats = 5000\nmax_btc_sats = 50000\n\
            [[offers]]\nid = \"btc-divi-testnet\"\ndirection = \"taker_pays_divi\"\n\
            divi_sats_per_btc = 300000000000000\nmin_btc_sats = 5000\nmax_btc_sats = 50000\n";
        let snippet = std::fs::read_to_string(base.join("wave4-offers.toml")).unwrap();
        let c = DaemonConfig::parse(&format!("{deployed}\n{snippet}")).unwrap();
        let served: Vec<_> = c
            .offers
            .iter()
            .map(|o| (o.id.as_str(), o.counter_chain))
            .collect();
        assert_eq!(
            served,
            [
                ("divi-btc-testnet", Chain::Btc),
                ("btc-divi-testnet", Chain::Btc),
                ("divi-ltc-testnet", Chain::Ltc),
                ("ltc-divi-testnet", Chain::Ltc),
            ]
        );
        assert_eq!(c.disabled_offers, ["divi-zec-testnet", "zec-divi-testnet"]);
        let l = c.ltc.as_ref().unwrap();
        assert_eq!(
            l.endpoints().unwrap()[0],
            swap_chain_ltc::LITECOINSPACE_TESTNET
        );
        assert_eq!(l.key, "credential:maker-btc");
        assert!(c.zec.is_some() && !c.serves(Chain::Zec));
        assert!(c.usdc.is_none(), "wave 4 does not touch usdc");
        // The appended offers match the mock ones, so local mock runs mirror dnsdivi —
        // except ltc-divi-testnet's max_btc_sats, deliberately capped to the maker's live
        // tLTC balance (wave4-offers.toml) rather than the mock's generic ceiling: that cap
        // must only ever be tighter, never looser.
        for o in mock_counter_offers() {
            let e = c.offer_entries.iter().find(|e| e.offer.id == o.id).unwrap();
            if o.id == "ltc-divi-testnet" {
                assert!(
                    e.offer.max_btc_sats <= o.max_btc_sats,
                    "{}: live cap {} exceeds the mock ceiling {}",
                    o.id,
                    e.offer.max_btc_sats,
                    o.max_btc_sats
                );
                assert_eq!(
                    Offer {
                        max_btc_sats: o.max_btc_sats,
                        ..e.offer.clone()
                    },
                    o,
                    "{}",
                    o.id
                );
            } else {
                assert_eq!(e.offer, o, "{}", o.id);
            }
        }
        c.swap_config().unwrap();
    }

    #[test]
    fn usdc_offers_snippet_on_top_of_the_wave4_deployed_config() {
        // What dnsdivi runs after wave 4 (BTC + LTC, ZEC gated off) + the usdc append
        // (tools/swap-poc/usdc-deploy.md), while the Erc20Htlc contract is still undeployed.
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/divi-swapd");
        let deployed = "db_path = \"/var/lib/divi-swapd/swaps.db\"\n\
            [divi]\nkey = \"credential:maker-divi\"\n[btc]\nkey = \"credential:maker-btc\"\n\
            [[offers]]\nid = \"divi-btc-testnet\"\ndivi_sats_per_btc = 300000000000000\n\
            min_btc_sats = 5000\nmax_btc_sats = 50000\n\
            [[offers]]\nid = \"btc-divi-testnet\"\ndirection = \"taker_pays_divi\"\n\
            divi_sats_per_btc = 300000000000000\nmin_btc_sats = 5000\nmax_btc_sats = 50000\n";
        let wave4 = std::fs::read_to_string(base.join("wave4-offers.toml")).unwrap();
        let usdc = std::fs::read_to_string(base.join("usdc-offers.toml")).unwrap();
        let c = DaemonConfig::parse(&format!("{deployed}\n{wave4}\n{usdc}")).unwrap();
        let served: Vec<_> = c
            .offers
            .iter()
            .map(|o| (o.id.as_str(), o.counter_chain))
            .collect();
        assert_eq!(
            served,
            [
                ("divi-btc-testnet", Chain::Btc),
                ("btc-divi-testnet", Chain::Btc),
                ("divi-ltc-testnet", Chain::Ltc),
                ("ltc-divi-testnet", Chain::Ltc),
            ],
            "both usdc offers start disabled, same as zec's"
        );
        assert!(c.disabled_offers.contains(&"divi-usdc-sepolia".to_string()));
        assert!(c.disabled_offers.contains(&"usdc-divi-sepolia".to_string()));
        let u = c.usdc.clone().unwrap();
        assert_eq!(u.network, "sepolia");
        assert_eq!(u.htlc, "0x0000000000000000000000000000000000000000");
        assert_eq!(u.key, "credential:maker-btc");
        assert!(!c.serves(Chain::Usdc), "both usdc offers are disabled");
        // counter_backends_to_start must not try to start [usdc] with no swap in flight and
        // no enabled offer — the whole point of landing this file before the contract exists
        // (ltc still starts: both ltc offers above are enabled).
        let start = c.counter_backends_to_start(&BTreeSet::new()).unwrap();
        assert_eq!(start, [Chain::Ltc]);
        c.swap_config().unwrap();
    }

    #[test]
    fn mock_counter_offer_ids() {
        let ids: Vec<_> = mock_counter_offers().into_iter().map(|o| o.id).collect();
        assert_eq!(
            ids,
            [
                "divi-ltc-testnet",
                "ltc-divi-testnet",
                "divi-zec-testnet",
                "zec-divi-testnet"
            ]
        );
        for o in mock_counter_offers() {
            let (head, _) = o.id.split_once('-').unwrap();
            let maker_sells_divi = head == "divi";
            assert_eq!(maker_sells_divi, o.direction == Direction::TakerPaysBtc);
        }
    }

    #[test]
    fn rejects_raw_key_values() {
        let bad = GOOD.replace("op://v/i/f", "deadbeefdeadbeef");
        assert!(DaemonConfig::parse(&bad).is_err());
    }

    #[test]
    fn xmr_testnet_profile_with_mainnet_network_is_rejected() {
        // The dangerous direction: real XMR under testnet timeouts, even with the opt-in.
        let section = XMR_SECTION.replace(
            "[xmr]\n",
            "[xmr]\nnetwork = \"mainnet\"\nallow_mainnet = true\n",
        );
        let e = DaemonConfig::parse(&format!("{GOOD}{XMR}{section}")).unwrap_err();
        let e = e.to_string();
        assert!(
            e.contains("profile = \"testnet\" but [xmr].network = \"mainnet\"")
                && e.contains("real funds under testnet timeouts are refused"),
            "{e}"
        );
    }

    #[test]
    fn xmr_mainnet_profile_with_stagenet_or_without_allow_is_rejected() {
        let text = format!(
            "profile = \"mainnet\"\n{}{XMR}{XMR_SECTION}",
            good_mainnet_btc()
        );
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(
            e.contains("profile = \"mainnet\" but [xmr].network = \"stagenet\"")
                && e.contains("mainnet profile with a test network is refused"),
            "{e}"
        );
        let section = XMR_SECTION.replace("[xmr]\n", "[xmr]\nnetwork = \"mainnet\"\n");
        let text = format!(
            "profile = \"mainnet\"\n{}{XMR}{section}",
            good_mainnet_btc()
        );
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(e.contains("[xmr].allow_mainnet is not set"), "{e}");
        // All agree: accepted.
        let section = XMR_SECTION.replace(
            "[xmr]\n",
            "[xmr]\nnetwork = \"mainnet\"\nallow_mainnet = true\n",
        );
        let text = format!(
            "profile = \"mainnet\"\n{}{XMR}{section}",
            good_mainnet_btc()
        );
        DaemonConfig::parse(&text).unwrap();
    }

    #[test]
    fn usdc_test_network_under_mainnet_profile_is_rejected() {
        let text = format!(
            "profile = \"mainnet\"\n{}\n[usdc]\nhtlc = \"0x00\"\nkey = \"credential:usdc\"\n",
            good_mainnet_btc()
        );
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(
            e.contains("profile = \"mainnet\" but [usdc].network = \"sepolia\""),
            "{e}"
        );
    }

    #[test]
    fn usdc_network_defaults_to_sepolia_and_picks_its_rpc_and_token() {
        let text = format!("{GOOD}\n[usdc]\nhtlc = \"0x00\"\nkey = \"credential:usdc\"\n");
        let c = DaemonConfig::parse(&text).unwrap();
        let u = c.usdc.unwrap();
        assert_eq!(u.network, "sepolia");
        assert_eq!(u.network().unwrap(), swap_chain_evm::UsdcNetwork::Sepolia);
        assert_eq!(
            u.rpc_url().unwrap(),
            swap_chain_evm::UsdcNetwork::Sepolia.default_rpc_url()
        );
        assert_eq!(u.token().unwrap(), swap_chain_evm::SEPOLIA_USDC);
    }

    #[test]
    fn usdc_network_base_sepolia_picks_its_own_rpc_and_token() {
        let text = format!(
            "{GOOD}\n[usdc]\nnetwork = \"base-sepolia\"\nhtlc = \"0x00\"\nkey = \"credential:usdc\"\n"
        );
        let c = DaemonConfig::parse(&text).unwrap();
        let u = c.usdc.unwrap();
        assert_eq!(
            u.rpc_url().unwrap(),
            swap_chain_evm::UsdcNetwork::BaseSepolia.default_rpc_url()
        );
        assert_eq!(u.token().unwrap(), swap_chain_evm::BASE_SEPOLIA_USDC);
    }

    #[test]
    fn usdc_explicit_rpc_url_and_token_override_the_network_default() {
        let text = format!(
            "{GOOD}\n[usdc]\nnetwork = \"base-sepolia\"\nrpc_url = \"http://localhost:9999\"\n\
             token = \"0x1111111111111111111111111111111111111111\"\nhtlc = \"0x00\"\n\
             key = \"credential:usdc\"\n"
        );
        let c = DaemonConfig::parse(&text).unwrap();
        let u = c.usdc.unwrap();
        assert_eq!(u.rpc_url().unwrap(), "http://localhost:9999");
        assert_eq!(
            u.token().unwrap(),
            "0x1111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn usdc_unknown_network_is_rejected_at_load_time() {
        let text = format!(
            "{GOOD}\n[usdc]\nnetwork = \"mainnet\"\nhtlc = \"0x00\"\nkey = \"credential:usdc\"\n"
        );
        let err = DaemonConfig::parse(&text).unwrap_err();
        assert!(err.to_string().contains("[usdc].network"), "{err}");
    }

    /// The exact `[usdc]`/`[[offers]]` shape `tools/swap-poc/usdc-live.sh`'s `run_scenario`
    /// generates for its "happy" scenario (placeholder `network`/`htlc`/`rpc_url`/secret
    /// refs — the script fills in real ones). Catches drift between the two without needing
    /// secrets, a daemon, or a network: a mock/unit-level check of a script this lane cannot
    /// otherwise exercise on hp2 (no 1Password, no live Sepolia).
    fn usdc_live_toml(timing: &str) -> String {
        format!(
            "listen = \"127.0.0.1:18494\"\n\
             db_path = \"/tmp/usdc-live-test/maker.db\"\n\
             tick_secs = 5\n\
             {timing}\n\
             [divi]\n\
             key = \"op://v/maker-divi/f\"\n\
             wallet_path = \"/tmp/usdc-live-test/maker-wallet.json\"\n\
             scan_from_height = 339800\n\
             \n\
             [btc]\n\
             network = \"testnet\"\n\
             esplora_url = \"https://mempool.space/testnet/api\"\n\
             key = \"op://v/maker-btc/f\"\n\
             \n\
             [usdc]\n\
             network = \"sepolia\"\n\
             rpc_url = \"https://ethereum-sepolia-rpc.publicnode.com\"\n\
             htlc = \"0x1111111111111111111111111111111111111111\"\n\
             key = \"op://v/maker-btc/f\"\n\
             \n\
             [[offers]]\n\
             id = \"divi-usdc-sepolia\"\n\
             direction = \"taker_pays_btc\"\n\
             counter_chain = \"usdc\"\n\
             divi_sats_per_btc = 10000000000\n\
             min_btc_sats = 1000000\n\
             max_btc_sats = 1000000000\n\
             \n\
             [[offers]]\n\
             id = \"usdc-divi-sepolia\"\n\
             direction = \"taker_pays_divi\"\n\
             counter_chain = \"usdc\"\n\
             divi_sats_per_btc = 10000000000\n\
             min_btc_sats = 1000000\n\
             max_btc_sats = 1000000000\n"
        )
    }

    #[test]
    fn usdc_live_happy_scenario_toml_parses_and_serves_both_directions() {
        let c = DaemonConfig::parse(&usdc_live_toml("")).unwrap();
        let served: Vec<_> = c
            .offers
            .iter()
            .map(|o| (o.id.as_str(), o.counter_chain, o.direction))
            .collect();
        assert_eq!(
            served,
            [
                ("divi-usdc-sepolia", Chain::Usdc, Direction::TakerPaysBtc),
                ("usdc-divi-sepolia", Chain::Usdc, Direction::TakerPaysDivi),
            ]
        );
        let u = c.usdc.clone().unwrap();
        assert_eq!(u.network, "sepolia");
        assert_eq!(u.htlc, "0x1111111111111111111111111111111111111111");
        // The daemon's own default timeouts (happy scenario passes no [swap] override).
        let s = c.swap_config().unwrap();
        assert_eq!(s.taker_timeout_secs, 6 * 3600);
        assert_eq!(s.maker_timeout_secs, 3 * 3600);
    }

    #[test]
    fn usdc_live_case_c_scenario_toml_parses_with_its_swap_overrides() {
        let timing = "[swap]\nmaker_timeout_secs = 3600\ntaker_timeout_secs = 14410\n";
        let c = DaemonConfig::parse(&usdc_live_toml(timing)).unwrap();
        assert!(c.serves(Chain::Usdc));
        let s = c.swap_config().unwrap();
        assert_eq!(s.taker_timeout_secs, 14410);
        assert_eq!(s.maker_timeout_secs, 3600);
    }

    /// A mainnet config with `[ltc]` on mainnet and the given extra `[ltc]` lines.
    fn mainnet_with_ltc(divi: &str, ltc_extra: &str) -> String {
        format!(
            "profile = \"mainnet\"\n{divi}\n[ltc]\nnetwork = \"mainnet\"\nallow_mainnet = true\n\
             key = \"credential:btc\"\n{ltc_extra}"
        )
    }

    /// Parses `text` with a capturing log subscriber; returns the result and the log text.
    fn parse_logged(text: &str) -> (Result<DaemonConfig>, String) {
        #[derive(Clone)]
        struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf(Default::default());
        let w = buf.clone();
        let sub = tracing_subscriber::fmt()
            .with_writer(move || w.clone())
            .with_ansi(false)
            .finish();
        let r = tracing::subscriber::with_default(sub, || DaemonConfig::parse(text));
        let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (r, log)
    }

    #[test]
    fn mainnet_ltc_with_crosscheck_off_or_absent_is_refused_naming_the_key() {
        for extra in ["", "crosscheck = \"off\"\n"] {
            let text = mainnet_with_ltc(&good_mainnet_btc(), extra);
            let e = DaemonConfig::parse(&text).unwrap_err().to_string();
            assert!(
                e.contains("[ltc].crosscheck") && e.contains("allow_single_source"),
                "{extra:?}: {e}"
            );
        }
    }

    #[test]
    fn mainnet_divi_without_a_fallback_is_refused_naming_the_key() {
        let no_fallback =
            good_mainnet_btc().replace("fallback_rpc_url = \"http://127.0.0.1:51473\"\n", "");
        let blank = good_mainnet_btc().replace("\"http://127.0.0.1:51473\"", "\"  \"");
        for divi in [no_fallback, blank] {
            let text = format!("profile = \"mainnet\"\n{divi}");
            let e = DaemonConfig::parse(&text).unwrap_err().to_string();
            assert!(
                e.contains("[divi].fallback_rpc_url") && e.contains("allow_single_source"),
                "{e}"
            );
        }
    }

    #[test]
    fn allow_single_source_lets_a_mainnet_config_start_and_warns() {
        // DIVI without a fallback, waived in [divi].
        let divi = good_mainnet_btc().replace(
            "fallback_rpc_url = \"http://127.0.0.1:51473\"\n",
            "allow_single_source = true\n",
        );
        let (r, log) = parse_logged(&format!("profile = \"mainnet\"\n{divi}"));
        r.unwrap();
        assert!(
            log.contains("WARN")
                && log.contains("[divi].fallback_rpc_url")
                && log.contains("allow_single_source"),
            "{log}"
        );
        // LTC crosscheck off, waived in [ltc]; the DIVI fallback is set, so only LTC warns.
        let (r, log) = parse_logged(&mainnet_with_ltc(
            &good_mainnet_btc(),
            "allow_single_source = true\n",
        ));
        r.unwrap();
        assert!(
            log.contains("WARN") && log.contains("[ltc].crosscheck"),
            "{log}"
        );
        assert!(!log.contains("[divi].fallback_rpc_url"), "{log}");
        // A waiver in one section does not cover the other.
        let text = mainnet_with_ltc(&divi, "");
        let e = DaemonConfig::parse(&text).unwrap_err().to_string();
        assert!(e.contains("[ltc].crosscheck"), "{e}");
        // Both sources present: no warning, waiver or not.
        let (r, log) = parse_logged(&mainnet_with_ltc(
            &good_mainnet_btc(),
            "crosscheck = \"blockcypher\"\nallow_single_source = true\n",
        ));
        r.unwrap();
        assert!(!log.contains("allow_single_source"), "{log}");
    }

    #[test]
    fn testnet_configs_without_either_source_still_load_without_a_warning() {
        let (r, log) = parse_logged(&format!("{GOOD}\n[ltc]\nkey = \"credential:btc\"\n"));
        let c = r.unwrap();
        assert_eq!(c.profile, Profile::Testnet);
        assert_eq!(c.divi.unwrap().fallback_rpc_url().unwrap(), None);
        assert_eq!(c.ltc.unwrap().crosscheck_source().unwrap(), None);
        assert!(!log.contains("allow_single_source"), "{log}");
    }

    #[test]
    fn deploy_example_documents_the_mainnet_two_source_keys() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/divi-swapd/divi-swapd.toml.example");
        let text = std::fs::read_to_string(&path).unwrap();
        DaemonConfig::parse(&text).unwrap();
        // Both sections name the mainnet requirement and the waiver.
        for section in ["[divi]", "[ltc]"] {
            let body = text.split(&format!("\n{section}\n")).nth(1).unwrap();
            let body = body.split("\n[").next().unwrap();
            assert!(
                body.contains("allow_single_source") && body.contains("required on mainnet"),
                "{section}: {body}"
            );
        }
    }
}
