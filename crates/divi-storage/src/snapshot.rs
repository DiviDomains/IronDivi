// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Chain-state snapshots for starting a thin node without syncing from genesis.
//!
//! A snapshot is a directory: `MANIFEST.json` plus `chainstate/`, a RocksDB checkpoint that
//! has already been pruned with the same `Expire::Minimum` rules a thin node applies to
//! itself (old block bodies and undo data gone, old lottery-winner lists stripped). The
//! manifest lists every file with its SHA-256 and carries a `root_hash` over the manifest
//! fields and file list, which is the one value operators compare or publish.
//!
//! Divi block headers commit to no UTXO set, so the UTXO set inside a snapshot is trusted,
//! not proven: only the tip's place on the chain can be checked against other nodes. The
//! import therefore records the snapshot tip and every later block is fully validated.
//! Import only ever writes into an empty chainstate directory; deleting that directory
//! undoes it.

use crate::chain::{Chain, ChainParams};
use crate::database::ChainDatabase;
use crate::error::StorageError;
use crate::prune::Expire;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// Current snapshot layout version.
pub const SNAPSHOT_FORMAT: u32 = 1;
/// Manifest file name inside a snapshot directory.
pub const MANIFEST_NAME: &str = "MANIFEST.json";
/// Name of the database directory inside a snapshot directory.
pub const DATA_DIR: &str = "chainstate";

/// One file of the snapshot database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Describes a snapshot; `root_hash` is the value operators compare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub format: u32,
    pub network: String,
    pub tip_height: u32,
    pub tip_hash: String,
    pub prune_height: u32,
    pub winners_strip_height: u32,
    pub files: Vec<SnapshotFile>,
    pub root_hash: String,
}

fn err(msg: impl Into<String>) -> StorageError {
    StorageError::Snapshot(msg.into())
}

fn network_name(params: &ChainParams) -> &'static str {
    use crate::chain::NetworkType::*;
    match params.network_type {
        Mainnet => "mainnet",
        Testnet => "testnet",
        Regtest => "regtest",
    }
}

fn hash_file(path: &Path) -> Result<(u64, String), StorageError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size += n as u64;
    }
    Ok((size, hex::encode(h.finalize())))
}

impl SnapshotManifest {
    /// SHA-256 over the format, network, tip, watermarks and the sorted file list.
    pub fn compute_root_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(format!(
            "irondivi-snapshot\nformat={}\nnetwork={}\ntip={}:{}\nprune={}\nstrip={}\n",
            self.format,
            self.network,
            self.tip_height,
            self.tip_hash,
            self.prune_height,
            self.winners_strip_height
        ));
        let mut files: Vec<&SnapshotFile> = self.files.iter().collect();
        files.sort_by(|a, b| a.name.cmp(&b.name));
        for f in files {
            h.update(format!("{}:{}:{}\n", f.name, f.size, f.sha256));
        }
        hex::encode(h.finalize())
    }

    /// Read `MANIFEST.json` from a snapshot directory and check its root hash is consistent.
    pub fn read(snapshot_dir: &Path) -> Result<Self, StorageError> {
        let raw = std::fs::read(snapshot_dir.join(MANIFEST_NAME))?;
        let m: SnapshotManifest =
            serde_json::from_slice(&raw).map_err(|e| err(format!("bad manifest: {e}")))?;
        if m.format != SNAPSHOT_FORMAT {
            return Err(err(format!("unsupported snapshot format {}", m.format)));
        }
        if m.compute_root_hash() != m.root_hash {
            return Err(err("manifest root_hash does not match its contents"));
        }
        Ok(m)
    }
}

/// Files RocksDB keeps only for itself; they are not part of the data and change on every open.
fn is_ignored(name: &str) -> bool {
    name == "LOCK" || name.starts_with("LOG")
}

/// Build a snapshot of the chainstate at `src` into the new directory `out`.
/// `src` must not be open in another process. The source is never modified.
pub fn export_snapshot(
    src: &Path,
    out: &Path,
    params: ChainParams,
) -> Result<SnapshotManifest, StorageError> {
    if out.exists() {
        return Err(err(format!("{} already exists", out.display())));
    }
    std::fs::create_dir_all(out)?;
    let data = out.join(DATA_DIR);

    // 1. Checkpoint: hard-links the immutable files, so the source stays byte-for-byte as is.
    {
        let db = ChainDatabase::open(src)?;
        db.create_checkpoint(&data)?;
    }

    // 2. Thin the copy the same way a running thin node thins itself, then close it.
    let (tip_height, tip_hash, prune_height, strip_height);
    {
        let db = Arc::new(ChainDatabase::open(&data)?);
        let chain = Chain::new(db.clone(), params.clone())?;
        let tip = chain
            .tip()
            .ok_or_else(|| err("source chainstate has no tip"))?;
        chain.prune_expired(Expire::Minimum, None, 0)?;
        db.flush()?;
        tip_height = tip.height;
        tip_hash = tip.hash;
        prune_height = chain.prune_height();
        strip_height = chain.winners_strip_height();
    }

    // 3. Hash every file of the closed copy.
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&data)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_ignored(&name) || !entry.file_type()?.is_file() {
            continue;
        }
        let (size, sha256) = hash_file(&entry.path())?;
        files.push(SnapshotFile { name, size, sha256 });
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    for name in std::fs::read_dir(&data)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_ignored(n))
    {
        let _ = std::fs::remove_file(data.join(name));
    }

    let mut manifest = SnapshotManifest {
        format: SNAPSHOT_FORMAT,
        network: network_name(&params).to_string(),
        tip_height,
        tip_hash: tip_hash.to_string(),
        prune_height,
        winners_strip_height: strip_height,
        files,
        root_hash: String::new(),
    };
    manifest.root_hash = manifest.compute_root_hash();
    std::fs::write(
        out.join(MANIFEST_NAME),
        serde_json::to_vec_pretty(&manifest).map_err(|e| err(e.to_string()))?,
    )?;
    Ok(manifest)
}

/// Install the snapshot in `snapshot_dir` as the chainstate at `dest`.
///
/// Refuses unless `dest` is missing or empty, every file matches its manifest hash, the
/// network matches `params`, and (when given) the root hash equals `expect_root`. Files are
/// copied to a sibling temporary directory and renamed into place only after the opened
/// database reports exactly the manifest's tip, so a failed import leaves nothing behind.
pub fn import_snapshot(
    snapshot_dir: &Path,
    dest: &Path,
    params: ChainParams,
    expect_root: Option<&str>,
) -> Result<SnapshotManifest, StorageError> {
    let manifest = SnapshotManifest::read(snapshot_dir)?;
    if let Some(want) = expect_root {
        if !want.eq_ignore_ascii_case(&manifest.root_hash) {
            return Err(err(format!(
                "root hash {} does not match the expected {}",
                manifest.root_hash, want
            )));
        }
    }
    if manifest.network != network_name(&params) {
        return Err(err(format!(
            "snapshot is for {}, this node runs {}",
            manifest.network,
            network_name(&params)
        )));
    }
    if dest.exists() && std::fs::read_dir(dest)?.next().is_some() {
        return Err(err(format!(
            "{} is not empty; a snapshot only starts a fresh node",
            dest.display()
        )));
    }

    let mut tmp_name = dest
        .file_name()
        .ok_or_else(|| err("destination has no name"))?
        .to_os_string();
    tmp_name.push(".importing");
    let tmp = dest.with_file_name(tmp_name);
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp)?;
    }
    std::fs::create_dir_all(&tmp)?;

    let result = (|| -> Result<(), StorageError> {
        let src_data = snapshot_dir.join(DATA_DIR);
        for f in &manifest.files {
            if f.name.contains('/') || f.name.contains('\\') || f.name == ".." {
                return Err(err(format!("unsafe file name {}", f.name)));
            }
            let from = src_data.join(&f.name);
            let (size, sha) = hash_file(&from)?;
            if size != f.size || sha != f.sha256 {
                return Err(err(format!("{} does not match the manifest", f.name)));
            }
            std::fs::copy(&from, tmp.join(&f.name))?;
        }
        let db = Arc::new(ChainDatabase::open(&tmp)?);
        let chain = Chain::new(db.clone(), params)?;
        let tip = chain
            .tip()
            .ok_or_else(|| err("snapshot chainstate has no tip"))?;
        if tip.height != manifest.tip_height || tip.hash.to_string() != manifest.tip_hash {
            return Err(err("database tip does not match the manifest"));
        }
        db.set_snapshot_base(tip.height, &tip.hash)?;
        db.flush()?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            if dest.exists() {
                std::fs::remove_dir(dest)?;
            }
            std::fs::rename(&tmp, dest)?;
            Ok(manifest)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::NetworkType;
    use divi_primitives::ChainMode;
    use tempfile::tempdir;

    fn params() -> ChainParams {
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi)
    }

    fn make_source(dir: &Path) {
        let db = Arc::new(ChainDatabase::open(dir).unwrap());
        let _chain = Chain::new(db, params()).unwrap();
    }

    #[test]
    fn export_then_import_roundtrip() {
        let work = tempdir().unwrap();
        let src = work.path().join("src");
        let snap = work.path().join("snap");
        let dest = work.path().join("dest");
        make_source(&src);

        let m = export_snapshot(&src, &snap, params()).unwrap();
        assert_eq!(m.network, "regtest");
        assert_eq!(m.root_hash, m.compute_root_hash());
        assert!(!m.files.is_empty());

        let imported = import_snapshot(&snap, &dest, params(), Some(&m.root_hash)).unwrap();
        assert_eq!(imported, m);

        let db = Arc::new(ChainDatabase::open(&dest).unwrap());
        let (h, hash) = db.snapshot_base().expect("snapshot base recorded");
        assert_eq!(h, m.tip_height);
        assert_eq!(hash.to_string(), m.tip_hash);
        assert!(!work.path().join("dest.importing").exists());
    }

    #[test]
    fn export_refuses_existing_output() {
        let work = tempdir().unwrap();
        let src = work.path().join("src");
        make_source(&src);
        assert!(export_snapshot(&src, work.path(), params()).is_err());
    }

    #[test]
    fn import_refuses_wrong_root_hash_and_nonempty_dest() {
        let work = tempdir().unwrap();
        let src = work.path().join("src");
        let snap = work.path().join("snap");
        make_source(&src);
        export_snapshot(&src, &snap, params()).unwrap();

        let dest = work.path().join("dest");
        assert!(import_snapshot(&snap, &dest, params(), Some(&"00".repeat(32))).is_err());
        assert!(!dest.exists());

        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("x"), b"x").unwrap();
        assert!(import_snapshot(&snap, &dest, params(), None).is_err());
        assert!(dest.join("x").exists());
    }

    #[test]
    fn import_refuses_tampered_file_and_leaves_nothing() {
        let work = tempdir().unwrap();
        let src = work.path().join("src");
        let snap = work.path().join("snap");
        let dest = work.path().join("dest");
        make_source(&src);
        let m = export_snapshot(&src, &snap, params()).unwrap();

        let victim = &m.files.iter().find(|f| f.size > 0).unwrap().name;
        let p = snap.join(DATA_DIR).join(victim);
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&p, bytes).unwrap();

        assert!(import_snapshot(&snap, &dest, params(), None).is_err());
        assert!(!dest.exists());
        assert!(!work.path().join("dest.importing").exists());
    }

    #[test]
    fn import_refuses_other_network() {
        let work = tempdir().unwrap();
        let src = work.path().join("src");
        let snap = work.path().join("snap");
        make_source(&src);
        export_snapshot(&src, &snap, params()).unwrap();
        let other = ChainParams::for_network(NetworkType::Testnet, ChainMode::Divi);
        assert!(import_snapshot(&snap, &work.path().join("d"), other, None).is_err());
    }
}
