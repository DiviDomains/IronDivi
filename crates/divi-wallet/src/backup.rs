// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Wallet backups as Divi Core makes them: a copy at every start in
//! `backups/` and a monthly one in `monthlyBackups/` (init.cpp:933-943,
//! WalletBackupCreator.cpp, MonthlyWalletBackupCreator.cpp), each named after
//! the wallet with the time appended (`wallet.2026-10-24-01-50`), the oldest
//! removed past the count kept. The wallet is a folder, so a backup is a
//! folder too.

use crate::error::WalletError;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

/// Backups kept in `backups/` unless -createwalletbackups says otherwise
/// (Divi Core nWalletBackups, init.cpp:124, read at init.cpp:938)
pub const STARTUP_BACKUPS: usize = 20;
/// Backups kept in `monthlyBackups/` by the daily check unless
/// -monthlybackups says otherwise (LegacyWalletDatabaseEndpointFactory.cpp:77)
pub const MONTHLY_BACKUPS: usize = 12;
/// Age of the newest monthly backup that calls for a new one
/// (timeIntervalConstants.h: 30 days)
pub const MONTH: Duration = Duration::from_secs(30 * 24 * 3600);

/// Copy a folder and everything in it
pub fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// `.%Y-%m-%d-%H-%M` in UTC, the suffix Divi Core gives a backup
/// (WalletBackupCreator.cpp:68)
pub fn time_suffix(at: SystemTime) -> String {
    let secs = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Days to civil date (proleptic Gregorian)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        ".{year:04}-{month:02}-{day:02}-{:02}-{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// The backups of the wallet named `wallet` in a folder, oldest first by
/// modification time: the entries whose name less its last extension is the
/// wallet's (`wallet.2026-10-24-01-50`). Anything else in the folder is not
/// counted and never removed, as Divi Core lists only `<wallet file>.*`
/// (FilteredBoostFileSystem.cpp:35-56).
fn by_age(dir: &Path, wallet: &str) -> Vec<(SystemTime, PathBuf)> {
    let mut entries: Vec<(SystemTime, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| Path::new(&e.file_name()).file_stem() == Some(std::ffi::OsStr::new(wallet)))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    entries.sort();
    entries
}

/// The name backups of the wallet at `wallet` start with
fn wallet_name(wallet: &Path) -> String {
    wallet
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wallet".into())
}

/// Keep the `keep` newest backups of `wallet` in `dir` (Divi Core
/// PruneOldBackups)
fn prune(dir: &Path, wallet: &str, keep: usize) {
    let entries = by_age(dir, wallet);
    let excess = entries.len().saturating_sub(keep);
    for (_, path) in entries.into_iter().take(excess) {
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => info!("Old backup deleted: {}", path.display()),
            Err(e) => warn!("Failed to delete backup {}: {}", path.display(), e),
        }
    }
}

/// Where a backup of `wallet` made at `now` goes in `dir`
fn backup_path(dir: &Path, wallet: &Path, now: SystemTime) -> PathBuf {
    dir.join(format!("{}{}", wallet_name(wallet), time_suffix(now)))
}

/// Copy the closed wallet folder into `dir` and prune it to `keep`
/// (Divi Core WalletBackupCreator::BackupWallet). The folder is made even
/// when nothing is copied, as Core makes it, and with `keep` above 0 it is
/// pruned even when no copy was made (no wallet yet, or a backup of that
/// minute already there), as Core prunes after a failed copy
/// (WalletBackupCreator.cpp:103-121).
fn backup_closed(
    wallet: &Path,
    dir: &Path,
    keep: usize,
    now: SystemTime,
) -> Result<Option<PathBuf>, WalletError> {
    std::fs::create_dir_all(dir).map_err(|e| WalletError::Storage(e.to_string()))?;
    if keep == 0 {
        return Ok(None);
    }
    let target = backup_path(dir, wallet, now);
    let made = if !wallet.is_dir() {
        None
    } else if target.exists() {
        warn!("Backup {} already exists; not made again", target.display());
        None
    } else {
        copy_dir(wallet, &target).map_err(|e| {
            let _ = std::fs::remove_dir_all(&target);
            WalletError::Storage(format!("Failed to create backup: {e}"))
        })?;
        info!(
            "Creating backup of {} -> {}",
            wallet.display(),
            target.display()
        );
        Some(target)
    };
    prune(dir, &wallet_name(wallet), keep);
    Ok(made)
}

/// Whether the newest backup of `wallet` in `dir` is a month old or there is
/// none (Divi Core MonthlyWalletBackupCreator::BackupWallet)
fn monthly_due(dir: &Path, wallet: &str, now: SystemTime) -> bool {
    match by_age(dir, wallet).last() {
        Some((newest, _)) => now.duration_since(*newest).unwrap_or_default() >= MONTH,
        None => true,
    }
}

/// The backups Divi Core makes before it opens the wallet at start: one in
/// `<data_dir>/backups`, and one in `<data_dir>/monthlyBackups` when the
/// newest there is a month old; `keep` kept in each, Core's start using one
/// count, -createwalletbackups, for both (init.cpp:933-941). With `keep` 0 no
/// backup is made and none removed (WalletBackupCreator.cpp:103-121).
/// `wallet` must not be open.
pub fn backup_at_start(wallet: &Path, data_dir: &Path, keep: usize) -> Result<(), WalletError> {
    let now = SystemTime::now();
    info!("backing up wallet");
    // No wallet yet (a first start): each of the two backups says so and
    // makes nothing, not even its folder (WalletBackupFeatureContainer.cpp:24-33,
    // :57-70)
    if !wallet.exists() {
        for _ in 0..2 {
            info!(
                "Wallet file not found at {}. Skipping backup...",
                wallet.display()
            );
        }
        return Ok(());
    }
    backup_closed(wallet, &data_dir.join("backups"), keep, now)?;
    let monthly = data_dir.join("monthlyBackups");
    std::fs::create_dir_all(&monthly).map_err(|e| WalletError::Storage(e.to_string()))?;
    if monthly_due(&monthly, &wallet_name(wallet), now) {
        backup_closed(wallet, &monthly, keep, now)?;
    }
    Ok(())
}

/// The daily check of a running node: a backup of the open wallet in
/// `<data_dir>/monthlyBackups` when the newest there is a month old by the
/// node's clock, `keep` kept (Divi Core MonthlyWalletBackupThread with
/// -monthlybackups, LegacyWalletDatabaseEndpointFactory.cpp:75-88; the age
/// and the name come from GetTime, which setmocktime sets)
pub fn monthly_backup(
    wallet: &crate::WalletDb,
    data_dir: &Path,
    keep: usize,
) -> Result<Option<PathBuf>, WalletError> {
    let now = node_now();
    let dir = data_dir.join("monthlyBackups");
    std::fs::create_dir_all(&dir).map_err(|e| WalletError::Storage(e.to_string()))?;
    let path = wallet.database_path();
    let name = wallet_name(&path);
    if keep == 0 || !monthly_due(&dir, &name, now) {
        return Ok(None);
    }
    let target = backup_path(&dir, &path, now);
    if target.exists() {
        warn!("Backup {} already exists; not made again", target.display());
        return Ok(None);
    }
    wallet.backup_to(&target)?;
    prune(&dir, &name, keep);
    Ok(Some(target))
}

/// The node's clock as a SystemTime (the mocked time when one is set)
fn node_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(divi_primitives::clock::now().max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_is_cores_utc_time_format() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_806_600);
        assert_eq!(time_suffix(t), ".2026-10-24-01-50");
        assert_eq!(time_suffix(SystemTime::UNIX_EPOCH), ".1970-01-01-00-00");
        let leap = SystemTime::UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(time_suffix(leap), ".2000-02-29-00-00");
    }

    #[test]
    fn start_up_backups_are_pruned_to_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet");
        std::fs::create_dir_all(&wallet).unwrap();
        std::fs::write(wallet.join("CURRENT"), b"x").unwrap();
        let backups = dir.path().join("backups");
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_806_600);
        for i in 0..(STARTUP_BACKUPS as u64 + 3) {
            let at = start + Duration::from_secs(60 * i);
            backup_closed(&wallet, &backups, STARTUP_BACKUPS, at)
                .unwrap()
                .unwrap();
        }
        let left = by_age(&backups, "wallet");
        assert_eq!(left.len(), STARTUP_BACKUPS);
        assert!(
            left[0].1.to_string_lossy().ends_with("-01-53"),
            "{:?}",
            left[0].1
        );
        assert!(left.iter().all(|(_, p)| p.join("CURRENT").exists()));
    }

    #[test]
    fn pruned_even_when_no_copy_is_made() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet");
        std::fs::create_dir_all(&wallet).unwrap();
        let backups = dir.path().join("backups");
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_806_600);
        for i in 0..3 {
            backup_closed(&wallet, &backups, 5, at + Duration::from_secs(60 * i))
                .unwrap()
                .unwrap();
        }
        // The same minute again: no copy, and still pruned to the count
        assert!(backup_closed(&wallet, &backups, 2, at).unwrap().is_none());
        assert_eq!(by_age(&backups, "wallet").len(), 2);
        // No wallet: no copy, pruned
        std::fs::remove_dir_all(&wallet).unwrap();
        let later = at + Duration::from_secs(240);
        assert!(backup_closed(&wallet, &backups, 1, later)
            .unwrap()
            .is_none());
        assert_eq!(by_age(&backups, "wallet").len(), 1);
        std::fs::create_dir_all(&wallet).unwrap();
        // Only the wallet's own backups are counted and removed
        for other in [
            "notes.txt",
            "wallet.2026-10-24-01-50.old",
            "other.2026-10-24-01-50",
        ] {
            std::fs::write(backups.join(other), b"x").unwrap();
        }
        backup_closed(&wallet, &backups, 1, at + Duration::from_secs(300))
            .unwrap()
            .unwrap();
        assert_eq!(by_age(&backups, "wallet").len(), 1);
        assert_eq!(std::fs::read_dir(&backups).unwrap().count(), 4);
        // 0: nothing made, nothing removed
        assert!(
            backup_closed(&wallet, &backups, 0, at + Duration::from_secs(600))
                .unwrap()
                .is_none()
        );
        assert_eq!(by_age(&backups, "wallet").len(), 1);
    }

    #[test]
    fn monthly_backup_only_when_newest_is_a_month_old() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        assert!(monthly_due(dir.path(), "wallet", now));
        let b = dir.path().join("wallet.x");
        std::fs::create_dir_all(&b).unwrap();
        assert!(!monthly_due(dir.path(), "wallet", now));
        std::fs::File::open(&b)
            .unwrap()
            .set_modified(now - MONTH - Duration::from_secs(1))
            .unwrap();
        assert!(monthly_due(dir.path(), "wallet", now));
    }
}
