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

/// Backups kept in `backups/` (Divi Core -createwalletbackups default,
/// init.cpp:124)
pub const STARTUP_BACKUPS: usize = 20;
/// Backups kept in `monthlyBackups/` by the daily check (Divi Core
/// -monthlybackups default, LegacyWalletDatabaseEndpointFactory.cpp:77)
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

/// The entries of a backup folder, oldest first by modification time
fn by_age(dir: &Path) -> Vec<(SystemTime, PathBuf)> {
    let mut entries: Vec<(SystemTime, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    entries.sort();
    entries
}

/// Keep the `keep` newest entries of `dir` (Divi Core PruneOldBackups)
fn prune(dir: &Path, keep: usize) {
    let entries = by_age(dir);
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
    let name = wallet
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wallet".into());
    dir.join(format!("{name}{}", time_suffix(now)))
}

/// Copy the closed wallet folder into `dir` and prune it to `keep`
/// (Divi Core WalletBackupCreator::BackupWallet). The folder is made even
/// when nothing is copied, as Core makes it.
fn backup_closed(
    wallet: &Path,
    dir: &Path,
    keep: usize,
    now: SystemTime,
) -> Result<Option<PathBuf>, WalletError> {
    std::fs::create_dir_all(dir).map_err(|e| WalletError::Storage(e.to_string()))?;
    if keep == 0 || !wallet.is_dir() {
        return Ok(None);
    }
    let target = backup_path(dir, wallet, now);
    if target.exists() {
        warn!("Backup {} already exists; not made again", target.display());
        return Ok(None);
    }
    copy_dir(wallet, &target).map_err(|e| {
        let _ = std::fs::remove_dir_all(&target);
        WalletError::Storage(format!("Failed to create backup: {e}"))
    })?;
    info!(
        "Creating backup of {} -> {}",
        wallet.display(),
        target.display()
    );
    prune(dir, keep);
    Ok(Some(target))
}

/// Whether the newest entry of `dir` is a month old or there is none
/// (Divi Core MonthlyWalletBackupCreator::BackupWallet)
fn monthly_due(dir: &Path, now: SystemTime) -> bool {
    match by_age(dir).last() {
        Some((newest, _)) => now.duration_since(*newest).unwrap_or_default() >= MONTH,
        None => true,
    }
}

/// The backups Divi Core makes before it opens the wallet at start: one in
/// `<data_dir>/backups`, and one in `<data_dir>/monthlyBackups` when the
/// newest there is a month old; `STARTUP_BACKUPS` kept in each (Core's start
/// uses one count for both). `wallet` must not be open.
pub fn backup_at_start(wallet: &Path, data_dir: &Path) -> Result<(), WalletError> {
    let now = SystemTime::now();
    info!("backing up wallet");
    backup_closed(wallet, &data_dir.join("backups"), STARTUP_BACKUPS, now)?;
    let monthly = data_dir.join("monthlyBackups");
    std::fs::create_dir_all(&monthly).map_err(|e| WalletError::Storage(e.to_string()))?;
    if monthly_due(&monthly, now) {
        backup_closed(wallet, &monthly, STARTUP_BACKUPS, now)?;
    }
    Ok(())
}

/// The daily check of a running node: a backup of the open wallet in
/// `<data_dir>/monthlyBackups` when the newest there is a month old,
/// `MONTHLY_BACKUPS` kept
pub fn monthly_backup(
    wallet: &crate::WalletDb,
    data_dir: &Path,
) -> Result<Option<PathBuf>, WalletError> {
    let now = SystemTime::now();
    let dir = data_dir.join("monthlyBackups");
    std::fs::create_dir_all(&dir).map_err(|e| WalletError::Storage(e.to_string()))?;
    if !monthly_due(&dir, now) {
        return Ok(None);
    }
    let target = backup_path(&dir, &wallet.database_path(), now);
    wallet.backup_to(&target)?;
    prune(&dir, MONTHLY_BACKUPS);
    Ok(Some(target))
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
        let left = by_age(&backups);
        assert_eq!(left.len(), STARTUP_BACKUPS);
        assert!(
            left[0].1.to_string_lossy().ends_with("-01-53"),
            "{:?}",
            left[0].1
        );
        assert!(left.iter().all(|(_, p)| p.join("CURRENT").exists()));
    }

    #[test]
    fn monthly_backup_only_when_newest_is_a_month_old() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        assert!(monthly_due(dir.path(), now));
        let b = dir.path().join("wallet.x");
        std::fs::create_dir_all(&b).unwrap();
        assert!(!monthly_due(dir.path(), now));
        std::fs::File::open(&b)
            .unwrap()
            .set_modified(now - MONTH - Duration::from_secs(1))
            .unwrap();
        assert!(monthly_due(dir.path(), now));
    }
}
