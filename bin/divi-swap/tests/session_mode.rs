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

//! The taker's `<db>.sessions.json` sidecar holds the xmr maker's per-swap bearer token
//! (`X-Swap-Token`), so it must be created mode 0600, like the database beside it, whatever
//! the umask, and a looser file left by an older build must be tightened on the next write.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use divi_swap_cli::session::{Session, Sessions};

fn session() -> Session {
    Session {
        maker_url: "http://m".into(),
        maker_swap_id: "x".into(),
        swap_token: "bearer-token".into(),
    }
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn sessions_file_is_created_0600() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let s = Sessions::beside(&db);
    // The default umask (022) gives 0644 to a plain `fs::write`; that is the case this pins.
    s.put("a", session()).unwrap();
    let file = dir.path().join("t.db.sessions.json");
    assert_eq!(mode(&file), 0o600, "{file:?}");
    assert_eq!(s.get("a").unwrap(), session());
}

#[test]
fn a_loose_sessions_file_from_an_older_build_is_tightened_on_the_next_put() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let file = dir.path().join("t.db.sessions.json");
    std::fs::write(&file, "{}").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    // A stale temp file with a loose mode must not leak its mode into the replacement.
    let tmp = dir.path().join("t.db.sessions.tmp");
    std::fs::write(&tmp, "x").unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();
    let s = Sessions::beside(&db);
    s.put("a", session()).unwrap();
    assert_eq!(mode(&file), 0o600, "{file:?}");
}
