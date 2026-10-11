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

use std::collections::BTreeMap;
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

fn default_divi_rpc() -> String {
    "https://services.divi.domains/api/testnet/rpc/".into()
}
fn default_esplora() -> String {
    "https://mempool.space/signet/api".into()
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
/// `MockChain` rather than a dedicated mock. (LTC also has a live backend — see
/// [`LtcSection`] — but mock mode always simulates every chain the same way, for fast
/// hermetic local/CI coverage; ZEC has no live backend yet.)
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
    /// Standing offers; a built-in testnet offer is used when none are configured.
    #[serde(default = "default_offers")]
    pub offers: Vec<Offer>,
    /// `[divi]` and `[btc]` are required by the live backend, ignored by the mock one.
    pub divi: Option<DiviSection>,
    pub btc: Option<BtcSection>,
    /// Enables a live LTC counter backend; needed only for offers with `counter_chain =
    /// "ltc"`. Ignored by the mock backend (which always simulates LTC).
    pub ltc: Option<LtcSection>,
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
        let cfg: DaemonConfig = toml::from_str(text).context("parsing config")?;
        cfg.validate()?;
        Ok(cfg)
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
        for o in &self.offers {
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
            .chain(self.ltc.iter().map(|l| &l.key));
        for r in refs {
            divi_swap::secrets::SecretRef::parse(r)
                .map_err(|e| anyhow::anyhow!("bad secret reference: {e}"))?;
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
        assert_eq!(l.key, "credential:maker-ltc");
        let ltc_ids: Vec<_> = c
            .offers
            .iter()
            .filter(|o| o.counter_chain == Chain::Ltc)
            .map(|o| o.id.as_str())
            .collect();
        assert_eq!(ltc_ids, ["divi-ltc-testnet", "ltc-divi-testnet"]);
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
}
