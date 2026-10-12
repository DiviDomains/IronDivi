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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// Every chain simulated in-process.
    Mock,
    /// Real DIVI testnet RPC + BTC Esplora.
    Live,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiviSection {
    /// DIVI JSON-RPC proxy URL.
    #[serde(default = "default_divi_rpc")]
    pub rpc_url: String,
    /// Reference (`op://…` or `credential:<name>`) to the maker's DIVI key.
    pub key: String,
    /// Known-UTXO file (public data only).
    pub wallet_path: Option<PathBuf>,
    /// First block height to scan for wallet UTXOs.
    pub scan_from_height: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BtcSection {
    #[serde(default = "default_network")]
    pub network: String,
    /// Primary Esplora API base.
    #[serde(default = "default_esplora")]
    pub esplora_url: String,
    /// Fallback Esplora API base.
    pub fallback_esplora_url: Option<String>,
    /// Reference (`op://…` or `credential:<name>`) to the maker's BTC key.
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LtcSection {
    #[serde(default = "default_ltc_network")]
    pub network: String,
    /// Primary Esplora API base.
    #[serde(default = "default_ltc_esplora")]
    pub esplora_url: String,
    /// Fallback Esplora API base, if one exists (none known as of 2026-10-11 — see
    /// `swap-chain-ltc`'s lane status).
    pub fallback_esplora_url: Option<String>,
    /// Reference (`op://…` or `credential:<name>`) to the maker's LTC key.
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsdcSection {
    /// Which EVM testnet this backend runs on: `"sepolia"` (default) or `"base-sepolia"`
    /// (`swap_chain_evm::UsdcNetwork`). Only a label plus a source of defaults for
    /// `rpc_url`/`token` below when they are left unset — the backend itself is
    /// network-agnostic, so setting both explicitly works on any EVM chain regardless of
    /// `network`. A single `[usdc]` section (and so a single `Chain::Usdc` backend) serves
    /// one network at a time; running both concurrently needs a second counter chain.
    #[serde(default = "default_usdc_network")]
    pub network: String,
    /// EVM JSON-RPC URL. Defaults to a free public endpoint for `network`.
    pub rpc_url: Option<String>,
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

    /// `token`, or `network`'s USDC token address if unset.
    pub fn token(&self) -> Result<String> {
        Ok(match &self.token {
            Some(t) => t.clone(),
            None => self.network()?.usdc_token().to_string(),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZecSection {
    /// Primary lightwalletd gRPC endpoint.
    #[serde(default = "default_lightwalletd")]
    pub lightwalletd_url: String,
    /// Fallback lightwalletd gRPC endpoint.
    pub fallback_lightwalletd_url: Option<String>,
    /// Reference (`op://…` or `credential:<name>`) to the maker's ZEC key.
    pub key: String,
}

fn default_divi_rpc() -> String {
    "https://services.divi.domains/api/testnet/rpc/".into()
}
fn default_esplora() -> String {
    "https://mempool.space/signet/api".into()
}
fn default_lightwalletd() -> String {
    swap_chain_zec::TESTNET_LIGHTWALLETD.to_string()
}
fn default_network() -> String {
    "signet".into()
}
fn default_ltc_network() -> String {
    "testnet".into()
}
fn default_ltc_esplora() -> String {
    swap_chain_ltc::LITECOINSPACE_TESTNET.into()
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
        divi_sats_per_btc: 300_000_000_000_000,
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

/// The offers `--backend mock` adds for each of [`MOCK_ONLY_CHAINS`]: `divi-<c>-testnet`
/// (maker sells DIVI) and `<c>-divi-testnet` (maker buys DIVI). Prices are placeholders.
pub fn mock_counter_offers() -> Vec<Offer> {
    MOCK_ONLY_CHAINS
        .into_iter()
        .flat_map(|c| {
            let price = match c {
                Chain::Ltc => 10_000 * 100_000_000, // 10,000 DIVI per LTC
                _ => 5_000 * 100_000_000,           // 5,000 DIVI per ZEC
            };
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
    /// Overrides on top of `profile`.
    #[serde(default)]
    pub swap: SwapOverrides,
}

impl DaemonConfig {
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
            .filter(|c| c.is_counter() && *c != Chain::Btc)
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

    fn validate(&self) -> Result<()> {
        if self.tick_secs == 0 {
            bail!("tick_secs must be > 0");
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
            .chain(self.zec.iter().map(|z| &z.key));
        for r in refs {
            divi_swap::secrets::SecretRef::parse(r)
                .map_err(|e| anyhow::anyhow!("bad secret reference: {e}"))?;
        }
        if let Some(u) = &self.usdc {
            u.network()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn parses_and_normalises_prefix() {
        let c = DaemonConfig::parse(GOOD).unwrap();
        assert_eq!(c.prefix(), "/swap");
        assert_eq!(c.profile, Profile::Testnet);
    }

    #[test]
    fn parses_deploy_example() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/divi-swapd/divi-swapd.toml.example");
        let c = DaemonConfig::load(&path).unwrap();
        assert_eq!(c.listen.port(), 18480);
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
        assert_eq!(l.esplora_url, swap_chain_ltc::LITECOINSPACE_TESTNET);
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
        assert_eq!(s.confirmations(Chain::Zec), 3); // testnet profile
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
        assert_eq!(l.esplora_url, swap_chain_ltc::LITECOINSPACE_TESTNET);
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
}
