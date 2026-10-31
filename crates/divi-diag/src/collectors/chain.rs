// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.8: the chain database, opened read-only as a RocksDB secondary into a
//! temporary folder under `$TMPDIR` (never the output folder), removed after.
//! The primary is never written and never opened with repair; the wallet
//! database is never opened at all.
//!
//! Block hashes are written as `blk:<hex>` so the redactor keeps them.
// Without the `chaindb` feature the open path is compiled out.
#![cfg_attr(not(feature = "chaindb"), allow(dead_code, unused_imports))]

use super::head;
use crate::ctx::{Ctx, DataDir};
use crate::frame::Out;
use crate::mem;
use crate::outln;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Skip the open below this much free memory (B2.8)
pub const MIN_FREE: u64 = 512 << 20;
/// The block-index scan stops after this many entries or this long
const SCAN_MAX: u64 = 5_000_000;
const SCAN_SECS: u64 = 25;
/// How many failed entries and verify problems are listed by hash
const LIST_MAX: usize = 20;

/// The fixed prefix of a `BlockIndex` record (divi-storage `to_bytes`)
#[derive(Debug, Clone, PartialEq)]
pub struct IndexHead {
    pub hash: [u8; 32],
    pub prev: [u8; 32],
    pub height: u32,
    pub status: u32,
}

pub const VALID_HEADER: u32 = 1;
pub const HAVE_DATA: u32 = 16;
pub const FAILED: u32 = 32;
pub const ON_MAIN_CHAIN: u32 = 64;

/// Parse the part of a `BlockIndex` record diag needs: hash, prev, height,
/// and the status that follows the optional accumulator, n_tx and chain work
pub fn parse_index(b: &[u8]) -> Option<IndexHead> {
    // hash 32, prev 32, height 4, version 4, merkle 32, time 4, bits 4, nonce 4
    let mut p = 32 + 32 + 4 + 4 + 32 + 4 + 4 + 4;
    if b.len() < p + 1 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&b[..32]);
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&b[32..64]);
    let height = u32::from_le_bytes(b[64..68].try_into().ok()?);
    p += 1 + if b[p] == 1 { 32 } else { 0 };
    p += 4 + 32; // n_tx, chain work
    let status = u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?);
    Some(IndexHead { hash, prev, height, status })
}

/// A public block hash as the redactor keeps it
pub fn blk(internal: &[u8]) -> String {
    let mut r = internal.to_vec();
    r.reverse();
    format!("blk:{}", hex::encode(r))
}

fn status_names(s: u32) -> String {
    let names = [
        (1, "header"),
        (2, "txs"),
        (4, "chain"),
        (8, "scripts"),
        (HAVE_DATA, "data"),
        (FAILED, "FAILED"),
        (ON_MAIN_CHAIN, "main"),
    ];
    let v: Vec<&str> = names.iter().filter(|(b, _)| s & b != 0).map(|(_, n)| *n).collect();
    format!("{s} ({})", v.join(","))
}

/// The temporary secondary folder; removed when dropped, whatever happened
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> std::io::Result<TmpDir> {
        let p = std::env::temp_dir().join(format!(
            "irondivi-diag-secondary-{}-{}-{}",
            std::process::id(),
            tag,
            crate::util::now_secs()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&p)?;
        Ok(TmpDir(p))
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The prefix every secondary folder starts with; §6.3 refuses paths under it
pub fn secondary_prefix() -> PathBuf {
    std::env::temp_dir().join("irondivi-diag-secondary-")
}

/// Remove the secondary folders a killed collector process `pid` left in
/// `tmp` (its Drop never ran); returns how many were removed (R1 b, B5)
pub fn remove_leftover_secondary(tmp: &Path, pid: u32) -> usize {
    let prefix = format!("irondivi-diag-secondary-{pid}-");
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(tmp) {
        for e in rd.flatten() {
            let name = e.file_name();
            let is_dir = e.file_type().map(|t| t.is_dir() && !t.is_symlink()).unwrap_or(false);
            if is_dir && name.to_string_lossy().starts_with(&prefix) && std::fs::remove_dir_all(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

pub fn chaindb(ctx: &Ctx, o: &mut Out) {
    o.file("chaindb.txt");
    head(o, "B2.8 chain database (read-only secondary open)");
    if ctx.datadirs.is_empty() {
        outln!(o, "no data dir found; nothing opened");
        outln!(o, "block hash set: unavailable; §6.2 pseudonymises every 64-hex string in this package");
        return;
    }
    let mut any_open = false;
    for d in &ctx.datadirs {
        any_open |= one(ctx, d, o);
    }
    if !any_open {
        outln!(o);
        outln!(o, "block hash set: unavailable (no chain database opened); §6.2 pseudonymises every 64-hex string in this package");
    }
}

/// Is this a LevelDB (divid, C++) folder rather than a RocksDB one?
fn is_leveldb(p: &Path) -> bool {
    if !p.join("CURRENT").exists() {
        return false;
    }
    let rocks = std::fs::read_dir(p)
        .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with("OPTIONS-")))
        .unwrap_or(false);
    !rocks
}

pub(crate) fn one(ctx: &Ctx, d: &DataDir, o: &mut Out) -> bool {
    let r = ctx.redactor();
    head(o, &format!("data dir {} ({}): {}", d.n, d.network, r.path_of(&d.chain)));
    let cs = d.chain.join("chainstate");
    if !cs.is_dir() {
        outln!(o, "no chainstate folder");
        return false;
    }
    if is_leveldb(&cs) {
        outln!(o, "chainstate is a LevelDB database (the C++ divid's), not irondivid's; not opened");
        return false;
    }
    if !cs.join("CURRENT").exists() {
        let why = match std::fs::metadata(cs.join("CURRENT")) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => "not readable by diag".to_string(),
            _ => "no CURRENT file (empty or not a database)".to_string(),
        };
        outln!(o, "chainstate not opened: {why}");
        return false;
    }
    let free = mem::free_memory(d.running_pid);
    for n in &free.notes {
        outln!(o, "memory: {n}");
    }
    match free.bytes {
        Some(b) if b < MIN_FREE => {
            outln!(o, "SKIPPED: free memory {} MB is under 512 MB; the chain database is not opened", b >> 20);
            outln!(o, "block hash set: unavailable for this data dir (§6.2 fallback)");
            return false;
        }
        None => outln!(o, "memory: free memory unknown; opening anyway with the 8 MB cache"),
        _ => {}
    }
    match open_and_report(&cs, &d.chain.join("txindex"), o) {
        Ok(()) => true,
        Err(e) => {
            outln!(o, "OPEN FAILED (recorded verbatim): {e}");
            outln!(o, "block hash set: unavailable for this data dir; §6.2 pseudonymises every 64-hex string in this package");
            false
        }
    }
}

#[cfg(feature = "chaindb")]
fn options() -> rocksdb::Options {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.set_max_open_files(64);
    let mut bb = rocksdb::BlockBasedOptions::default();
    bb.set_block_cache(&rocksdb::Cache::new_lru_cache(8 << 20));
    opts.set_block_based_table_factory(&bb);
    opts
}

#[cfg(feature = "chaindb")]
fn open_secondary(primary: &Path, tmp: &TmpDir) -> Result<(rocksdb::DB, Vec<String>), String> {
    let opts = options();
    let cfs = rocksdb::DB::list_cf(&opts, primary).map_err(|e| format!("list column families: {e}"))?;
    let db = rocksdb::DB::open_cf_as_secondary(&opts, primary, &tmp.0, cfs.iter()).map_err(|e| e.to_string())?;
    let _ = db.try_catch_up_with_primary();
    Ok((db, cfs))
}

#[cfg(not(feature = "chaindb"))]
pub fn open_and_report(_cs: &Path, _tx: &Path, _o: &mut Out) -> Result<(), String> {
    Err("this build of diag has no RocksDB (built without the chaindb feature)".into())
}

#[cfg(feature = "chaindb")]
pub fn open_and_report(cs: &Path, txpath: &Path, o: &mut Out) -> Result<(), String> {
    let tmp = TmpDir::new("chainstate").map_err(|e| format!("cannot make the secondary folder: {e}"))?;
    let (db, cfs) = open_secondary(cs, &tmp)?;
    outln!(o, "opened as secondary (8 MB block cache, max_open_files=64)");

    outln!(o);
    outln!(o, "column families (estimated keys, live data, SST files):");
    for cf in &cfs {
        let Some(h) = db.cf_handle(cf) else { continue };
        let p = |name: &str| db.property_int_value_cf(h, name).ok().flatten();
        outln!(
            o,
            "  {cf:<20} {:>12}  {:>10}  {:>10}",
            p("rocksdb.estimate-num-keys").map(|v| v.to_string()).unwrap_or("?".into()),
            p("rocksdb.estimate-live-data-size").map(crate::util::human).unwrap_or("?".into()),
            p("rocksdb.total-sst-files-size").map(crate::util::human).unwrap_or("?".into()),
        );
    }

    // metadata
    let meta = db.cf_handle("metadata");
    let get = |k: &[u8]| -> Option<Vec<u8>> { meta.and_then(|m| db.get_cf(m, k).ok().flatten()) };
    let u32_of = |v: Option<Vec<u8>>| v.and_then(|b| b.get(..4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes));
    outln!(o);
    outln!(o, "metadata:");
    let network = get(b"network").map(|v| String::from_utf8_lossy(&v).into_owned());
    outln!(o, "  chain mode / network recorded: {}", network.as_deref().unwrap_or("(none recorded; checked by genesis at start)"));
    let height = u32_of(get(b"chain_height"));
    outln!(o, "  tip height: {}", height.map(|h| h.to_string()).unwrap_or("(none)".into()));
    let best = get(b"best_block");
    outln!(o, "  tip hash: {}", best.as_deref().filter(|b| b.len() == 32).map(blk).unwrap_or("(none)".into()));
    outln!(o, "  prune height: {}", u32_of(get(b"prune_height")).map(|h| h.to_string()).unwrap_or("0 (not pruned)".into()));
    match get(b"snapshot_base") {
        Some(v) if v.len() == 36 => outln!(
            o,
            "  snapshot base: height {} {}",
            u32::from_le_bytes(v[..4].try_into().unwrap_or([0; 4])),
            blk(&v[4..])
        ),
        Some(v) => outln!(o, "  snapshot base: malformed ({} bytes)", v.len()),
        None => outln!(o, "  snapshot base: none (synced, not imported)"),
    }
    match get(b"clean_stop") {
        Some(v) if v == b"1" => outln!(o, "  clean_stop: 1 (last stop was clean)"),
        Some(v) if v == b"0" => outln!(o, "  clean_stop: 0 (running now, or the last run did not stop cleanly)"),
        Some(_) => outln!(o, "  clean_stop: unexpected value"),
        None => outln!(o, "  clean_stop: none recorded"),
    }
    match get(b"reorg_target") {
        Some(v) if v.len() == 32 => outln!(o, "  reorg_target: {} (a reorganisation was in progress)", blk(&v)),
        Some(_) => outln!(o, "  reorg_target: malformed"),
        None => outln!(o, "  reorg_target: none"),
    }
    outln!(o);
    outln!(o, "schema: the database records no schema version; migration markers:");
    outln!(
        o,
        "  height_index_repair_v1: {}",
        if get(b"height_index_repair_v1").is_some() { "applied" } else { "PENDING (runs at next start)" }
    );
    match u32_of(get(b"winners_strip_height")) {
        Some(h) => outln!(
            o,
            "  lottery-winner strip: through height {h}{}",
            match height {
                Some(t) if h < t => " (PENDING above it)",
                _ => "",
            }
        ),
        None => outln!(o, "  lottery-winner strip: not started"),
    }
    outln!(
        o,
        "  network marker: {}",
        if network.is_some() { "applied" } else { "PENDING (recorded at next start)" }
    );

    // indexes
    outln!(o);
    outln!(o, "indexes:");
    for (name, cf) in [
        ("addressindex (address_delta)", "address_delta"),
        ("addressindex (address_unspent)", "address_unspent"),
        ("addressindex (scripthash)", "scripthash"),
        ("spentindex", "spent_index"),
        ("address_utxo", "address_utxo"),
        ("address_history", "address_history"),
        ("tx_index", "tx_index"),
    ] {
        let st = match db.cf_handle(cf) {
            None => "absent".to_string(),
            Some(h) => {
                let mut it = db.raw_iterator_cf(h);
                it.seek_to_first();
                if it.valid() {
                    "present, has entries".into()
                } else {
                    "present, empty".into()
                }
            }
        };
        outln!(o, "  {name}: {st}");
    }
    txindex(txpath, height, o);

    // block index
    let Some(bi) = db.cf_handle("block_index") else {
        outln!(o, "block_index column family absent");
        return Ok(());
    };
    outln!(o);
    outln!(o, "block index scan (bounded at {SCAN_MAX} entries / {SCAN_SECS} s):");
    let t0 = Instant::now();
    let mut it = db.raw_iterator_cf(bi);
    it.seek(b"b");
    let (mut n, mut failed, mut bad, mut header_tip) = (0u64, Vec::new(), 0u64, (0u32, Vec::new()));
    let mut complete = true;
    while it.valid() {
        let Some(k) = it.key() else { break };
        if k.first() != Some(&b'b') {
            break;
        }
        n += 1;
        match it.value().and_then(parse_index) {
            Some(h) => {
                if h.status & FAILED != 0 {
                    failed.push(h.clone());
                }
                if h.status & VALID_HEADER != 0 && h.status & FAILED == 0 && h.height >= header_tip.0 {
                    header_tip = (h.height, h.hash.to_vec());
                }
            }
            None => bad += 1,
        }
        if n >= SCAN_MAX || (n % 4096 == 0 && t0.elapsed() > Duration::from_secs(SCAN_SECS)) {
            complete = false;
            break;
        }
        it.next();
    }
    outln!(
        o,
        "  scanned {n} entries in {:.1} s{}",
        t0.elapsed().as_secs_f64(),
        if complete { " (complete)" } else { " (STOPPED at the bound; counts below are partial)" }
    );
    outln!(o, "  header tip: height {} {}", header_tip.0, if header_tip.1.is_empty() { "(none)".into() } else { blk(&header_tip.1) });
    if bad > 0 {
        outln!(o, "  unparsable records: {bad}");
    }
    outln!(o, "  failed-block entries: {}", failed.len());
    failed.sort_by_key(|f| std::cmp::Reverse(f.height));
    for f in failed.iter().take(LIST_MAX) {
        outln!(o, "    height {} {} status {}", f.height, blk(&f.hash), status_names(f.status));
    }

    // verify the last 288 blocks' records
    if let Some(tip) = height {
        verify(&db, bi, tip, u32_of(get(b"prune_height")).unwrap_or(0), o);
    }
    Ok(())
}

#[cfg(feature = "chaindb")]
fn txindex(path: &Path, tip: Option<u32>, o: &mut Out) {
    if !path.is_dir() {
        outln!(o, "  txindex: no txindex database");
        return;
    }
    let tmp = match TmpDir::new("txindex") {
        Ok(t) => t,
        Err(e) => {
            outln!(o, "  txindex: cannot make the secondary folder: {e}");
            return;
        }
    };
    match open_secondary(path, &tmp) {
        Err(e) => outln!(o, "  txindex: open failed (verbatim): {e}"),
        Ok((db, _)) => {
            let v = db.cf_handle("txindex").and_then(|h| db.get_cf(h, b"tip").ok().flatten());
            match v {
                Some(v) if v.len() == 36 => {
                    let h = u32::from_le_bytes(v[..4].try_into().unwrap_or([0; 4]));
                    let behind = tip.map(|t| t.saturating_sub(h));
                    outln!(
                        o,
                        "  txindex: indexed through height {h} {}{}",
                        blk(&v[4..]),
                        behind.map(|b| format!(", {b} behind the tip")).unwrap_or_default()
                    );
                }
                Some(_) => outln!(o, "  txindex: tip record malformed"),
                None => outln!(o, "  txindex: present, no tip recorded"),
            }
        }
    }
}

#[cfg(feature = "chaindb")]
fn verify(db: &rocksdb::DB, bi: &rocksdb::ColumnFamily, tip: u32, prune: u32, o: &mut Out) {
    let from = tip.saturating_sub(287);
    outln!(o);
    outln!(o, "verify of the index records of heights {from}..={tip} (read-only):");
    let mut problems: Vec<String> = Vec::new();
    let mut count = 0usize;
    let mut prev_hash: Option<[u8; 32]> = None;
    for h in from..=tip {
        let mut hk = vec![b'h'];
        hk.extend_from_slice(&h.to_le_bytes());
        let hash = match db.get_cf(bi, &hk) {
            Ok(Some(v)) if v.len() == 32 => v,
            Ok(Some(_)) => {
                problems.push(format!("height {h}: height record malformed"));
                prev_hash = None;
                continue;
            }
            Ok(None) => {
                problems.push(format!("height {h}: no height record"));
                prev_hash = None;
                continue;
            }
            Err(e) => {
                problems.push(format!("height {h}: read error: {e}"));
                prev_hash = None;
                continue;
            }
        };
        count += 1;
        let mut bk = vec![b'b'];
        bk.extend_from_slice(&hash);
        let rec = match db.get_cf(bi, &bk) {
            Ok(Some(v)) => v,
            _ => {
                problems.push(format!("height {h} {}: no index record", blk(&hash)));
                prev_hash = None;
                continue;
            }
        };
        let Some(ix) = parse_index(&rec) else {
            problems.push(format!("height {h} {}: index record unparsable", blk(&hash)));
            prev_hash = None;
            continue;
        };
        if ix.height != h {
            problems.push(format!("height {h} {}: record says height {}", blk(&hash), ix.height));
        }
        if ix.hash[..] != hash[..] {
            problems.push(format!("height {h} {}: record holds another hash", blk(&hash)));
        }
        if ix.status & ON_MAIN_CHAIN == 0 {
            problems.push(format!("height {h} {}: not marked on the main chain ({})", blk(&hash), status_names(ix.status)));
        }
        if ix.status & FAILED != 0 {
            problems.push(format!("height {h} {}: marked FAILED", blk(&hash)));
        }
        if ix.status & HAVE_DATA == 0 && h > prune {
            problems.push(format!("height {h} {}: no block data and not pruned", blk(&hash)));
        }
        if let Some(p) = prev_hash {
            if ix.prev != p {
                problems.push(format!("height {h} {}: prev hash does not link to height {}", blk(&hash), h - 1));
            }
        }
        let mut cur = [0u8; 32];
        cur.copy_from_slice(&hash);
        prev_hash = Some(cur);
    }
    outln!(o, "  {count} height records read, {} problems", problems.len());
    for p in problems.iter().take(LIST_MAX) {
        outln!(o, "    {p}");
    }
    if problems.len() > LIST_MAX {
        outln!(o, "    ... {} more", problems.len() - LIST_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leftover_secondary_only_for_that_pid() {
        let t = tempfile::tempdir().unwrap();
        let mine = t.path().join("irondivi-diag-secondary-4242-chainstate-1");
        std::fs::create_dir_all(mine.join("sub")).unwrap();
        std::fs::write(mine.join("sub/LOG"), "x").unwrap();
        let other = t.path().join("irondivi-diag-secondary-42421-chainstate-1");
        std::fs::create_dir(&other).unwrap();
        let file = t.path().join("irondivi-diag-secondary-4242-file");
        std::fs::write(&file, "").unwrap();
        assert_eq!(remove_leftover_secondary(t.path(), 4242), 1);
        assert!(!mine.exists());
        assert!(other.exists());
        assert!(file.exists());
        assert_eq!(remove_leftover_secondary(t.path(), 4242), 0);
    }

    #[test]
    fn leveldb_is_told_apart() {
        let t = tempfile::tempdir().unwrap();
        assert!(!is_leveldb(t.path()));
        std::fs::write(t.path().join("CURRENT"), "MANIFEST-000001\n").unwrap();
        assert!(is_leveldb(t.path()));
        std::fs::write(t.path().join("OPTIONS-000005"), "").unwrap();
        assert!(!is_leveldb(t.path()));
    }

    #[test]
    fn index_layout() {
        let mut b = Vec::new();
        b.extend_from_slice(&[1u8; 32]);
        b.extend_from_slice(&[2u8; 32]);
        b.extend_from_slice(&7u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 4 + 32 + 12]);
        b.push(1);
        b.extend_from_slice(&[9u8; 32]);
        b.extend_from_slice(&[0u8; 4 + 32]);
        b.extend_from_slice(&(ON_MAIN_CHAIN | HAVE_DATA).to_le_bytes());
        let h = parse_index(&b).unwrap();
        assert_eq!(h.height, 7);
        assert_eq!(h.hash, [1u8; 32]);
        assert_eq!(h.status, ON_MAIN_CHAIN | HAVE_DATA);
    }

    #[test]
    fn blk_is_display_order() {
        let mut v = [0u8; 32];
        v[0] = 0xab;
        assert!(blk(&v).ends_with("ab"));
        assert!(blk(&v).starts_with("blk:00"));
    }
}
