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

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use divi_swap::api::Offer;
use divi_swap::Profile;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// Both chains simulated in-process.
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

fn default_divi_rpc() -> String {
    "https://services.divi.domains/api/testnet/rpc/".into()
}
fn default_esplora() -> String {
    "https://mempool.space/signet/api".into()
}
fn default_network() -> String {
    "signet".into()
}
fn default_listen() -> SocketAddr {
    "127.0.0.1:8480".parse().expect("static address")
}
fn default_profile() -> Profile {
    Profile::Testnet
}
fn default_offers() -> Vec<Offer> {
    vec![Offer {
        id: "divi-btc-testnet".into(),
        divi_sats_per_btc: 300_000_000_000_000,
        min_btc_sats: 5_000,
        max_btc_sats: 50_000,
    }]
}
fn default_tick() -> u64 {
    5
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
        }
        let refs = self
            .divi
            .iter()
            .map(|d| &d.key)
            .chain(self.btc.iter().map(|b| &b.key));
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
    }

    #[test]
    fn rejects_raw_key_values() {
        let bad = GOOD.replace("op://v/i/f", "deadbeefdeadbeef");
        assert!(DaemonConfig::parse(&bad).is_err());
    }
}
