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

//! The taker's DIVI wallet file (public data: known coins and a scan cursor) and block scan.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use swap_chain_divi::DiviBackend;

/// Blocks per scan step; the wallet persists its cursor after each.
const SCAN_CHUNK: u64 = 500;

/// Validate `--divi-wallet`: it must not live inside a git working tree, and is kept mode 0600.
/// Returns the absolute path.
pub fn prepare_wallet_path(path: &Path) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = abs
        .parent()
        .with_context(|| format!("{} has no parent directory", abs.display()))?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("wallet directory {} does not exist", parent.display()))?;
    if let Some(root) = parent.ancestors().find(|a| a.join(".git").exists()) {
        bail!(
            "refusing --divi-wallet {}: inside the git working tree {}; keep it outside the repo",
            abs.display(),
            root.display()
        );
    }
    let file = parent.join(abs.file_name().context("wallet path has no file name")?);
    restrict_umask();
    if file.exists() {
        set_private(&file)?;
    }
    Ok(file)
}

/// New files (including the wallet's temp-then-rename writes) are created owner-only.
#[cfg(unix)]
fn restrict_umask() {
    extern "C" {
        fn umask(mask: u32) -> u32;
    }
    // SAFETY: umask(2) only sets this process's file-creation mask; it cannot fail.
    unsafe {
        umask(0o077);
    }
}

#[cfg(not(unix))]
fn restrict_umask() {}

#[cfg(unix)]
fn set_private(file: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", file.display()))
}

#[cfg(not(unix))]
fn set_private(_file: &Path) -> Result<()> {
    Ok(())
}

/// Scan the DIVI chain into the wallet, resuming from `max(scan_from, saved cursor)`.
/// Errors if there is neither a cursor nor `--divi-scan-from`.
pub async fn scan_to_tip(divi: &DiviBackend, scan_from: Option<u64>) -> Result<()> {
    let Some(mut next) = scan_from.into_iter().chain(divi.scanned_height()).max() else {
        bail!("first use of this DIVI wallet needs --divi-scan-from <height> (a block before it was funded)");
    };
    use divi_swap::ChainBackend;
    loop {
        let tip = divi.tip_height().await?;
        if next > tip {
            return Ok(());
        }
        while next <= tip {
            let to = (next + SCAN_CHUNK - 1).min(tip);
            next = divi.scan_range(next, to).await?;
            eprintln!("divi wallet scanned to {to} of {tip}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_path_inside_a_git_tree() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join(".git")).unwrap();
        std::fs::create_dir(repo.path().join("sub")).unwrap();
        let err = prepare_wallet_path(&repo.path().join("sub/w.json")).unwrap_err();
        assert!(err.to_string().contains("git working tree"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn existing_wallet_is_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let w = dir.path().join("w.json");
        std::fs::write(&w, "{}").unwrap();
        std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o644)).unwrap();
        let got = prepare_wallet_path(&w).unwrap();
        let mode = std::fs::metadata(&got).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
