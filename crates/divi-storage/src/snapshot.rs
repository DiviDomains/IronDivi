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
//! Divi block headers commit to no UTXO set, so the manifest and its signature only say who
//! made a snapshot, not that its contents match the chain. Import therefore recomputes a
//! state hash from the installed database itself — every UTXO entry, the consensus fields of
//! every active-chain block index entry from genesis to the tip, and the lottery-winner lists
//! consensus reads after the tip — re-hashes every stored header, and accepts the snapshot
//! only if the tip and the state hash equal a [`KnownState`] compiled into this release
//! (the approach of Bitcoin Core's assumeutxo). A known state is taken from a node that
//! validated the chain from genesis; `--export-snapshot` prints the line to add.
//!
//! History below the tip is not re-validated by the importing node; the tip is recorded as
//! the snapshot base, and every later block is fully validated. Import only ever writes into
//! an empty chainstate directory; deleting that directory undoes it.

use crate::chain::{Chain, ChainParams, NetworkType};
use crate::database::ChainDatabase;
use crate::error::StorageError;
use crate::prune::Expire;
use divi_primitives::ChainMode;
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

/// A chain state this release accepts as a snapshot base: the block at `height` and the
/// state hash ([`compute_state_hash`]) a node that validated the chain from genesis computed
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownState {
    pub chain_mode: ChainMode,
    pub network: NetworkType,
    pub height: u32,
    pub block_hash: &'static str,
    pub state_hash: &'static str,
}

/// Snapshot bases this release accepts.
pub const KNOWN_STATES: &[KnownState] = &[
    // Divi mainnet at 4,271,533, from a node synced from genesis on 2026-10-23; the block hash
    // matches Divi Core 3.0.0's getblockhash 4271533, and Core's gettxoutsetinfo hash_serialized
    // (bc93a4f9...f26b) recomputed from this node's UTXO set equals Core's at that height.
    KnownState {
        chain_mode: ChainMode::Divi,
        network: NetworkType::Mainnet,
        height: 4_271_533,
        block_hash: "d96e72872e0517c38250f4fcf0a18124c591676f54ab608f6ce22ad3b7dfe860",
        state_hash: "94530069ad50bd93db3e04bbdab5d3db937cf37b2dc3dc972408ec393731fcbf",
    },
    // Divi testnet at 361,452, from a node synced from genesis on 2026-10-22; the block hash
    // matches Divi Core 3.0.0's getblockhash 361452.
    KnownState {
        chain_mode: ChainMode::Divi,
        network: NetworkType::Testnet,
        height: 361_452,
        block_hash: "13f1f99be9822b935e14e697353f850378861d98fc5df587bb15aca8095932c5",
        state_hash: "f01617c4716191c69888d5cde70b9337d5b2d83195786de5c4813f199a8402d9",
    },
    // Regtest genesis: lets a fresh regtest chainstate round-trip through export/import.
    KnownState {
        chain_mode: ChainMode::Divi,
        network: NetworkType::Regtest,
        height: 0,
        block_hash: REGTEST_GENESIS_HASH,
        state_hash: REGTEST_GENESIS_STATE,
    },
];

const REGTEST_GENESIS_HASH: &str =
    "0000000b3f9980dcf71f5f52d69e30d3b02f807e0a77b91b6091701e4ae51a6f";
const REGTEST_GENESIS_STATE: &str =
    "4264a74d764d8bcd0e78c52e47293b4862e2811d229ac582315c668dea761a18";

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

/// Hash of the chain state at the database tip, `height` must be the tip height.
///
/// Covers, in order: every active-chain block index entry from genesis to `height` (block
/// hash, header fields, chain work, stake modifier and whether it was generated, proof-of-stake
/// flag, money supply), the lottery-winner lists at the heights consensus reads after the tip
/// (the tip and every block just before a lottery block), and every UTXO entry byte for byte
/// in key order, each in the layout of a version-1 transaction's record. Local bookkeeping (file positions, status flags, side branches) is left out,
/// so two nodes on the same chain get the same hash whatever they pruned. On the way it checks
/// that every stored header hashes to its entry and links to the one below.
pub fn compute_state_hash(
    db: &ChainDatabase,
    chain: &Chain,
    height: u32,
) -> Result<String, StorageError> {
    use divi_primitives::block::BlockHeader;
    use divi_primitives::serialize::serialize;

    let params = chain.params();
    let mut index_hash = Sha256::new();
    let mut prev: Option<crate::block_index::BlockIndex> = None;
    for h in 0..=height {
        let hash = db
            .get_height_mapping(h)?
            .ok_or_else(|| err(format!("no block at height {h}")))?;
        let idx = db
            .get_block_index(&hash)?
            .ok_or_else(|| err(format!("no index entry for block {hash} at height {h}")))?;
        if idx.height != h || idx.hash != hash {
            return Err(err(format!("index entry at height {h} is inconsistent")));
        }
        if let Some(p) = &prev {
            if idx.prev_hash != p.hash {
                return Err(err(format!(
                    "block at height {h} does not link to height {}",
                    h - 1
                )));
            }
        }
        let header = BlockHeader {
            version: idx.version,
            prev_block: idx.prev_hash,
            merkle_root: idx.merkle_root,
            time: idx.time,
            bits: idx.bits,
            nonce: idx.nonce,
            accumulator_checkpoint: idx.accumulator.unwrap_or_default(),
        };
        if divi_crypto::compute_block_hash(&header) != hash {
            return Err(err(format!(
                "stored header at height {h} does not hash to {hash}"
            )));
        }
        index_hash.update(hash.as_bytes());
        index_hash.update(idx.version.to_le_bytes());
        index_hash.update(idx.merkle_root.as_bytes());
        index_hash.update(idx.time.to_le_bytes());
        index_hash.update(idx.bits.to_le_bytes());
        index_hash.update(idx.nonce.to_le_bytes());
        index_hash.update(idx.accumulator.unwrap_or_default().as_bytes());
        index_hash.update(idx.chain_work);
        index_hash.update(idx.stake_modifier.to_le_bytes());
        index_hash.update([
            idx.generated_stake_modifier as u8,
            idx.is_proof_of_stake as u8,
        ]);
        match idx.money_supply {
            Some(m) => {
                index_hash.update([1]);
                index_hash.update(m.to_le_bytes());
            }
            None => index_hash.update([0]),
        }
        if h == height || chain.is_winners_terminal_height(h) {
            let winners = serialize(&idx.lottery_winners);
            index_hash.update((winners.len() as u64).to_le_bytes());
            index_hash.update(&winners);
        }
        prev = Some(idx);
    }

    let raw = db.inner_db();
    let cf = raw
        .cf_handle("utxo")
        .ok_or_else(|| err("database has no utxo column"))?;
    let mut utxo_hash = Sha256::new();
    let mut utxos = 0u64;
    for item in raw.iterator_cf(cf, rocksdb::IteratorMode::Start) {
        let (key, value) = item?;
        // Each record as it was written before records kept their transaction's
        // version, so nodes with and without versions agree on the known states
        let record = crate::utxo::Utxo::from_bytes(&value)?;
        let value = if record.version == 1 {
            value
        } else {
            record.with_version(1).to_bytes().into_boxed_slice()
        };
        utxo_hash.update((key.len() as u64).to_le_bytes());
        utxo_hash.update(&key);
        utxo_hash.update((value.len() as u64).to_le_bytes());
        utxo_hash.update(&value);
        utxos += 1;
    }

    let mut h = Sha256::new();
    h.update(format!(
        "irondivi-chain-state\nversion=1\nmode={:?}\nnetwork={}\nheight={}\n",
        params.chain_mode,
        network_name(params),
        height
    ));
    h.update(index_hash.finalize());
    h.update(utxos.to_le_bytes());
    h.update(utxo_hash.finalize());
    Ok(hex::encode(h.finalize()))
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
    export_snapshot_with_state(src, out, params).map(|(m, _)| m)
}

/// [`export_snapshot`], also returning the state hash at the snapshot tip (the value a
/// [`KnownState`] entry pins).
pub fn export_snapshot_with_state(
    src: &Path,
    out: &Path,
    params: ChainParams,
) -> Result<(SnapshotManifest, String), StorageError> {
    let state_hash;
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
        state_hash = compute_state_hash(&db, &chain, tip.height)?;
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
    Ok((manifest, state_hash))
}

/// Install the snapshot in `snapshot_dir` as the chainstate at `dest`, accepting only the
/// bases in [`KNOWN_STATES`].
///
/// Refuses unless `dest` is missing or empty, every file matches its manifest hash, the
/// network matches `params`, (when given) the root hash equals `expect_root`, and the
/// installed database's tip and recomputed state hash equal a known state. Files are copied
/// to a sibling temporary directory and renamed into place only after all of that holds, so
/// a failed import leaves nothing behind.
pub fn import_snapshot(
    snapshot_dir: &Path,
    dest: &Path,
    params: ChainParams,
    expect_root: Option<&str>,
) -> Result<SnapshotManifest, StorageError> {
    import_snapshot_with(snapshot_dir, dest, params, expect_root, KNOWN_STATES)
}

/// [`import_snapshot`] against an explicit list of known states.
pub fn import_snapshot_with(
    snapshot_dir: &Path,
    dest: &Path,
    params: ChainParams,
    expect_root: Option<&str>,
    known: &[KnownState],
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
        let chain = Chain::new(db.clone(), params.clone())?;
        let tip = chain
            .tip()
            .ok_or_else(|| err("snapshot chainstate has no tip"))?;
        if tip.height != manifest.tip_height || tip.hash.to_string() != manifest.tip_hash {
            return Err(err("database tip does not match the manifest"));
        }
        let candidates: Vec<&KnownState> = known
            .iter()
            .filter(|k| k.chain_mode == params.chain_mode && k.network == params.network_type)
            .collect();
        let base = candidates
            .iter()
            .find(|k| k.height == tip.height)
            .ok_or_else(|| {
                let heights: Vec<String> =
                    candidates.iter().map(|k| k.height.to_string()).collect();
                err(format!(
                    "this release knows no {} chain state at height {}; it accepts snapshots taken at: {}",
                    network_name(&params),
                    tip.height,
                    if heights.is_empty() { "none".to_string() } else { heights.join(", ") }
                ))
            })?;
        if !base.block_hash.eq_ignore_ascii_case(&tip.hash.to_string()) {
            return Err(err(format!(
                "snapshot tip {} at height {} is not the known block {}",
                tip.hash, tip.height, base.block_hash
            )));
        }
        let state = compute_state_hash(&db, &chain, tip.height)?;
        if !base.state_hash.eq_ignore_ascii_case(&state) {
            return Err(err(format!(
                "snapshot chain state {state} at height {} does not match the known state {}",
                tip.height, base.state_hash
            )));
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

    /// The compiled regtest-genesis entry must equal what a fresh regtest chain computes.
    #[test]
    fn regtest_genesis_known_state_is_current() {
        let work = tempdir().unwrap();
        let db = Arc::new(ChainDatabase::open(work.path()).unwrap());
        let chain = Chain::new(db.clone(), params()).unwrap();
        let tip = chain.tip().unwrap();
        let state = compute_state_hash(&db, &chain, 0).unwrap();
        assert_eq!(
            (tip.hash.to_string(), state),
            (
                REGTEST_GENESIS_HASH.to_string(),
                REGTEST_GENESIS_STATE.to_string()
            )
        );
    }

    /// A record that keeps its transaction's version hashes as the same coin
    /// written without it, so the known states hold for nodes with either
    #[test]
    fn state_hash_leaves_out_the_transaction_version() {
        use divi_primitives::{amount::Amount, script::Script, transaction::OutPoint, Hash256};
        let states: Vec<String> = [1, 2]
            .into_iter()
            .map(|version| {
                let work = tempdir().unwrap();
                let db = Arc::new(ChainDatabase::open(work.path()).unwrap());
                let chain = Chain::new(db.clone(), params()).unwrap();
                let coin = crate::utxo::Utxo::new(
                    Amount::from_sat(5),
                    Script::new_p2pkh(&[0x42; 20]),
                    0,
                    false,
                    false,
                )
                .with_version(version);
                db.add_utxo(&OutPoint::new(Hash256::from_bytes([7; 32]), 0), &coin)
                    .unwrap();
                compute_state_hash(&db, &chain, 0).unwrap()
            })
            .collect();
        assert_eq!(states[0], states[1]);
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

    /// Rewrite a snapshot's manifest so it matches whatever its files now hold: a
    /// self-consistent manifest proves nothing about the chain.
    fn reseal(snap: &Path) {
        let data = snap.join(DATA_DIR);
        for e in std::fs::read_dir(&data).unwrap() {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            if is_ignored(&name) {
                std::fs::remove_file(data.join(name)).unwrap();
            }
        }
        let mut m = SnapshotManifest::read(snap).unwrap();
        m.files = std::fs::read_dir(&data)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let (size, sha256) = hash_file(&e.path()).unwrap();
                SnapshotFile {
                    name: e.file_name().to_string_lossy().into_owned(),
                    size,
                    sha256,
                }
            })
            .collect();
        m.files.sort_by(|a, b| a.name.cmp(&b.name));
        m.root_hash = m.compute_root_hash();
        std::fs::write(snap.join(MANIFEST_NAME), serde_json::to_vec(&m).unwrap()).unwrap();
    }

    /// An extra coin written into the snapshot database, with the manifest rebuilt to match,
    /// used to install as long as the manifest was self-consistent.
    #[test]
    fn import_refuses_changed_utxo_set_even_with_matching_manifest() {
        use divi_primitives::{amount::Amount, script::Script, transaction::OutPoint, Hash256};
        let work = tempdir().unwrap();
        let src = work.path().join("src");
        let snap = work.path().join("snap");
        let dest = work.path().join("dest");
        make_source(&src);
        export_snapshot(&src, &snap, params()).unwrap();
        {
            let db = ChainDatabase::open(snap.join(DATA_DIR)).unwrap();
            let coin = crate::utxo::Utxo::new(
                Amount::from_sat(1_000_000 * 100_000_000),
                Script::new_p2pkh(&[0x42; 20]),
                0,
                false,
                false,
            );
            db.add_utxo(&OutPoint::new(Hash256::from_bytes([7; 32]), 0), &coin)
                .unwrap();
            db.flush().unwrap();
        }
        reseal(&snap);
        assert!(
            SnapshotManifest::read(&snap).is_ok(),
            "manifest is consistent"
        );

        let e = import_snapshot(&snap, &dest, params(), None);
        assert!(e.is_err(), "changed UTXO set was installed");
        let e = e.unwrap_err().to_string();
        assert!(e.contains("does not match the known state"), "{e}");
        assert!(!dest.exists());
        assert!(!work.path().join("dest.importing").exists());
    }

    fn regtest_block(parent: &crate::block_index::BlockIndex, n: u8) -> divi_primitives::Block {
        use divi_primitives::transaction::{Transaction, TxIn, TxOut};
        use divi_primitives::{amount::Amount, script::Script};
        let mut block = divi_primitives::Block::default();
        block.header.version = 4;
        block.header.prev_block = parent.hash;
        block.header.time = parent.time + 60;
        block.header.bits = 0x207fffff;
        let mut sig = crate::chain::bip34_height_script(parent.height + 1);
        sig.extend_from_slice(&[0x01, n]);
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250_00000000),
                Script::new_p2pkh(&[n; 20]),
            )],
            lock_time: 0,
        });
        block.header.merkle_root = divi_crypto::compute_merkle_root(&block.transactions);
        let target = divi_primitives::hash::Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        block
    }

    /// A 12-block regtest source, its snapshot, and the known state taken from it.
    fn chain_snapshot(work: &Path) -> (std::path::PathBuf, KnownState) {
        let src = work.join("src");
        {
            let db = Arc::new(ChainDatabase::open(&src).unwrap());
            let chain = Chain::new(db, params()).unwrap();
            for n in 1..=12u8 {
                let tip = chain.tip().unwrap();
                chain.accept_block(regtest_block(&tip, n)).unwrap();
            }
            assert_eq!(chain.height(), 12);
        }
        let snap = work.join("snap");
        let (m, state) = export_snapshot_with_state(&src, &snap, params()).unwrap();
        let known = KnownState {
            chain_mode: ChainMode::Divi,
            network: NetworkType::Regtest,
            height: m.tip_height,
            block_hash: Box::leak(m.tip_hash.into_boxed_str()),
            state_hash: Box::leak(state.into_boxed_str()),
        };
        (snap, known)
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                copy_dir(&e.path(), &to.join(e.file_name()));
            } else {
                std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
            }
        }
    }

    /// Change one block index entry in a copy of the snapshot, reseal it, and try to import.
    fn import_with_changed_index(
        work: &Path,
        snap: &Path,
        known: KnownState,
        height: u32,
        change: impl FnOnce(&mut crate::block_index::BlockIndex),
    ) -> Result<SnapshotManifest, StorageError> {
        let copy = work.join(format!("snap-{height}"));
        copy_dir(snap, &copy);
        {
            let db = ChainDatabase::open(copy.join(DATA_DIR)).unwrap();
            let hash = db.get_height_mapping(height).unwrap().unwrap();
            let mut idx = db.get_block_index(&hash).unwrap().unwrap();
            change(&mut idx);
            db.store_block_index(&idx).unwrap();
            db.flush().unwrap();
        }
        reseal(&copy);
        import_snapshot_with(
            &copy,
            &work.join(format!("dest-{height}")),
            params(),
            None,
            &[known],
        )
    }

    #[test]
    fn import_checks_tip_and_state_against_known_states() {
        let work = tempdir().unwrap();
        let (snap, known) = chain_snapshot(work.path());

        // The untouched snapshot installs against its own known state...
        let ok = work.path().join("ok");
        let m = import_snapshot_with(&snap, &ok, params(), None, &[known]).unwrap();
        assert_eq!(m.tip_height, 12);
        assert_eq!(
            ChainDatabase::open(&ok).unwrap().snapshot_base().unwrap().0,
            12
        );

        // ...but not when this release knows no state at that height,
        let e = import_snapshot(&snap, &work.path().join("d1"), params(), None).unwrap_err();
        assert!(
            e.to_string()
                .contains("knows no regtest chain state at height 12"),
            "{e}"
        );
        // nor against a different block or state at that height.
        let other_block = KnownState {
            block_hash: "00".repeat(32).leak(),
            ..known
        };
        let e = import_snapshot_with(
            &snap,
            &work.path().join("d2"),
            params(),
            None,
            &[other_block],
        )
        .unwrap_err();
        assert!(e.to_string().contains("is not the known block"), "{e}");
        let other_state = KnownState {
            state_hash: "11".repeat(32).leak(),
            ..known
        };
        let e = import_snapshot_with(
            &snap,
            &work.path().join("d3"),
            params(),
            None,
            &[other_state],
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("does not match the known state"),
            "{e}"
        );
        for d in ["d1", "d2", "d3"] {
            assert!(!work.path().join(d).exists());
        }
    }

    #[test]
    fn import_refuses_changed_block_index() {
        let work = tempdir().unwrap();
        let (snap, known) = chain_snapshot(work.path());
        // Derived consensus data that no header commits to
        let e = import_with_changed_index(work.path(), &snap, known, 7, |i| i.stake_modifier ^= 1)
            .unwrap_err();
        assert!(
            e.to_string().contains("does not match the known state"),
            "{e}"
        );
        let e = import_with_changed_index(work.path(), &snap, known, 12, |i| {
            i.lottery_winners.height += 1
        })
        .unwrap_err();
        assert!(
            e.to_string().contains("does not match the known state"),
            "{e}"
        );
        // A header field: the stored header no longer hashes to its block
        let e =
            import_with_changed_index(work.path(), &snap, known, 3, |i| i.time += 1).unwrap_err();
        assert!(e.to_string().contains("does not hash to"), "{e}");
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
