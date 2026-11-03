// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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

//! Which maker swap a local taker swap id belongs to. The engine `Store` keeps the taker's
//! own state; this sidecar only remembers where the maker lives so separate CLI invocations
//! (`accept`, then `lock`, then `status`) can find it. It holds the xmr maker's per-swap bearer
//! token, so it is written mode 0600 like the database beside it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub maker_url: String,
    pub maker_swap_id: String,
    /// The xmr maker's per-swap token (`X-Swap-Token`); empty for hashlock sessions.
    #[serde(default)]
    pub swap_token: String,
}

// Hand-written so a stray `{:?}` never prints the bearer token.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("maker_url", &self.maker_url)
            .field("maker_swap_id", &self.maker_swap_id)
            .field(
                "swap_token",
                &if self.swap_token.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .finish()
    }
}

pub struct Sessions {
    path: PathBuf,
}

impl Sessions {
    /// Sidecar next to the taker database: `<db>.sessions.json`.
    pub fn beside(db: &Path) -> Self {
        let mut name = db.as_os_str().to_owned();
        name.push(".sessions.json");
        Sessions { path: name.into() }
    }

    fn load(&self) -> Result<BTreeMap<String, Session>> {
        match std::fs::read_to_string(&self.path) {
            Ok(s) => {
                serde_json::from_str(&s).with_context(|| format!("parsing {}", self.path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    pub fn put(&self, local_id: &str, s: Session) -> Result<()> {
        let mut all = self.load()?;
        all.insert(local_id.to_string(), s);
        let tmp = self.path.with_extension("tmp");
        write_private(&tmp, &serde_json::to_vec_pretty(&all)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, local_id: &str) -> Result<Session> {
        self.load()?
            .remove(local_id)
            .ok_or_else(|| anyhow!("unknown local swap id {local_id}"))
    }
}

/// Write `bytes` to `path` with mode 0600, whatever the umask or a stale file already there.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `mode` applies only when the file is created; tighten a leftover before any byte lands.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = Sessions::beside(&dir.path().join("t.db"));
        assert!(s.get("a").is_err());
        let v = Session {
            maker_url: "http://m".into(),
            maker_swap_id: "x".into(),
            swap_token: String::new(),
        };
        s.put("a", v.clone()).unwrap();
        assert_eq!(s.get("a").unwrap(), v);
    }
}
