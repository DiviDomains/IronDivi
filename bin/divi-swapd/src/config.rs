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
pub struct SecretRefs {
    /// Reference to the maker's DIVI private key.
    pub divi_key: String,
    /// Reference to the maker's BTC private key.
    pub btc_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Endpoints {
    /// DIVI JSON-RPC proxy URL.
    #[serde(default = "default_divi_rpc")]
    pub divi_rpc: String,
    /// Primary Esplora API base.
    #[serde(default = "default_esplora")]
    pub btc_esplora: String,
    /// Fallback Esplora API base.
    pub btc_esplora_fallback: Option<String>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            divi_rpc: default_divi_rpc(),
            btc_esplora: default_esplora(),
            btc_esplora_fallback: None,
        }
    }
}

fn default_divi_rpc() -> String {
    "https://services.divi.domains/api/testnet/rpc/".into()
}
fn default_esplora() -> String {
    "https://mempool.space/signet/api".into()
}
fn default_listen() -> SocketAddr {
    "127.0.0.1:8480".parse().expect("static address")
}
fn default_profile() -> Profile {
    Profile::Testnet
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
    /// Optional path prefix, e.g. `/swap` behind nginx.
    #[serde(default)]
    pub path_prefix: String,
    /// Seconds between scheduler ticks.
    #[serde(default = "default_tick")]
    pub tick_secs: u64,
    #[serde(default)]
    pub offers: Vec<Offer>,
    /// Required for the live backend; ignored by the mock backend.
    pub secrets: Option<SecretRefs>,
    #[serde(default)]
    pub endpoints: Endpoints,
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
        if self.offers.is_empty() {
            bail!("config needs at least one [[offers]] entry");
        }
        for o in &self.offers {
            if o.min_btc_sats > o.max_btc_sats {
                bail!("offer {}: min_btc_sats > max_btc_sats", o.id);
            }
        }
        for r in self.secrets.iter().flat_map(|s| [&s.divi_key, &s.btc_key]) {
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
[secrets]
divi_key = "op://v/i/f"
btc_key = "credential:btc"
"#;

    #[test]
    fn parses_and_normalises_prefix() {
        let c = DaemonConfig::parse(GOOD).unwrap();
        assert_eq!(c.prefix(), "/swap");
        assert_eq!(c.profile, Profile::Testnet);
    }

    #[test]
    fn rejects_raw_key_values() {
        let bad = GOOD.replace("op://v/i/f", "deadbeefdeadbeef");
        assert!(DaemonConfig::parse(&bad).is_err());
    }
}
