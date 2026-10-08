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

//! Which maker swap a local taker swap id belongs to. The engine `Store` keeps the taker's
//! own state; this sidecar (no secrets) only remembers where the maker lives so separate
//! CLI invocations (`accept`, then `lock`, then `status`) can find it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub maker_url: String,
    pub maker_swap_id: String,
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
        std::fs::write(&tmp, serde_json::to_vec_pretty(&all)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, local_id: &str) -> Result<Session> {
        self.load()?
            .remove(local_id)
            .ok_or_else(|| anyhow!("unknown local swap id {local_id}"))
    }
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
        };
        s.put("a", v.clone()).unwrap();
        assert_eq!(s.get("a").unwrap(), v);
    }
}
