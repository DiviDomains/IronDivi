// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! C3: deterministic interleavings of `ChainDatabase` UTXO readers, writers,
//! flushes and eviction against the UTXO cache.
//!
//! Each test forces one schedule with the cache's test-only scheduling points
//! (`"utxo fill"`: after a cache-miss database read, before the value is
//! cached; `"utxo flush"`: after a flush built its batch, before it writes it)
//! and then checks three things: what the cache answers, what the database
//! holds after a flush, and what a restart (a reopen with and without the
//! cache) sees. Before C3 a reader could cache a value a writer had already
//! replaced or spent, and a flush could write such a value back to disk.

use crate::block_index::{BlockIndex, BlockStatus};
use crate::database::{BatchedUtxoWriter, ChainDatabase};
use crate::utxo::{outpoint_from_key, Utxo};
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::lottery::LotteryWinners;
use divi_primitives::script::Script;
use divi_primitives::transaction::OutPoint;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Weak};
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn op(n: u8) -> OutPoint {
    OutPoint::new(Hash256::from_bytes([n; 32]), u32::from(n))
}

fn coin(sat: i64) -> Utxo {
    Utxo::new(
        Amount::from_sat(sat),
        Script::new_p2pkh(&[0u8; 20]),
        100,
        false,
        false,
    )
}

fn index(hash_byte: u8, height: u32) -> BlockIndex {
    BlockIndex {
        hash: Hash256::from_bytes([hash_byte; 32]),
        prev_hash: Hash256::zero(),
        height,
        version: 4,
        merkle_root: Hash256::zero(),
        time: 1_700_000_000 + height,
        bits: 0x1e0fffff,
        nonce: 0,
        accumulator: None,
        n_tx: 1,
        chain_work: [0u8; 32],
        status: BlockStatus::empty(),
        file_num: -1,
        data_pos: 0,
        stake_modifier: 0,
        generated_stake_modifier: false,
        lottery_winners: LotteryWinners::new(height),
        is_proof_of_stake: false,
        money_supply: None,
    }
}

fn value(u: Option<Utxo>) -> Option<i64> {
    u.map(|u| u.value.as_sat())
}

/// Every path that writes the UTXO set
#[derive(Clone, Copy, Debug)]
enum Writer {
    RemoveUtxo,
    AddUtxoNewValue,
    BatchSpend,
    AtomicConnectSpend,
    AtomicDisconnectUndo,
}

const WRITERS: [Writer; 5] = [
    Writer::RemoveUtxo,
    Writer::AddUtxoNewValue,
    Writer::BatchSpend,
    Writer::AtomicConnectSpend,
    Writer::AtomicDisconnectUndo,
];

/// Run `w` on `target` (which holds a coin); returns the coin's value after it
fn run_writer(db: &ChainDatabase, w: Writer, target: OutPoint, height: u32) -> Option<i64> {
    match w {
        Writer::RemoveUtxo => {
            db.remove_utxo(&target).unwrap();
            None
        }
        Writer::AddUtxoNewValue => {
            let v = 2_000 + i64::from(height);
            db.add_utxo(&target, &coin(v)).unwrap();
            Some(v)
        }
        Writer::BatchSpend => {
            let mut b = BatchedUtxoWriter::new();
            b.remove(target);
            db.flush_utxo_batch(&b).unwrap();
            None
        }
        Writer::AtomicConnectSpend => {
            let mut b = BatchedUtxoWriter::new();
            b.remove(target);
            let idx = index(0x40 + (height % 64) as u8, height);
            db.atomic_connect_block(&b, b"undo", &idx.hash, &idx, &|_| Ok(()))
                .unwrap();
            None
        }
        Writer::AtomicDisconnectUndo => {
            let mut b = BatchedUtxoWriter::new();
            b.remove(target);
            let idx = index(0x80 + (height % 64) as u8, height + 1);
            let parent = index(0x80 + ((height + 63) % 64) as u8, height);
            db.atomic_disconnect_block(&b, &idx, &parent, &|_| Ok(()))
                .unwrap();
            None
        }
    }
}

/// A database at `path` holding `coins`, reopened with a UTXO cache of
/// `entries` so nothing is cached yet
fn seeded(path: &Path, coins: &[(OutPoint, i64)], entries: u64) -> Arc<ChainDatabase> {
    {
        let plain = ChainDatabase::open(path).unwrap();
        for (o, v) in coins {
            plain.add_utxo(o, &coin(*v)).unwrap();
        }
    }
    Arc::new(ChainDatabase::open_with_utxo_cache(path, entries).unwrap())
}

fn set_hook(db: &ChainDatabase, point: &'static str, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
    db.utxo_cache_ref()
        .expect("cache enabled")
        .set_sched_hook(point, hook);
}

/// After a flush and a restart, `target` must hold `want`, with and without
/// the cache
fn assert_durable(path: &Path, db: Arc<ChainDatabase>, target: OutPoint, want: Option<i64>) {
    db.flush_utxo_cache().unwrap();
    assert_eq!(
        value(db.get_utxo(&target).unwrap()),
        want,
        "cache view after flush"
    );
    set_hook(&db, "utxo fill", None);
    set_hook(&db, "utxo flush", None);
    drop(db);
    let plain = ChainDatabase::open(path).unwrap();
    assert_eq!(
        value(plain.get_utxo(&target).unwrap()),
        want,
        "database after restart (no cache)"
    );
    drop(plain);
    let cached = ChainDatabase::open_with_utxo_cache(path, 1000).unwrap();
    assert_eq!(
        value(cached.get_utxo(&target).unwrap()),
        want,
        "database after restart (cache)"
    );
}

/// The reader misses, reads the coin from the database, and before it caches
/// what it read, `w` writes the coin (database and cache). The cache must
/// answer with `w`'s result, and so must the database after a flush and a
/// restart.
fn stale_fill_case(w: Writer, via_has_utxo: bool) {
    let dir = tempdir().unwrap();
    let target = op(1);
    let db = seeded(dir.path(), &[(target, 1_000)], 1000);

    let after = Arc::new(Mutex::new(None));
    {
        let weak: Weak<ChainDatabase> = Arc::downgrade(&db);
        let fired = AtomicBool::new(false);
        let after = after.clone();
        set_hook(
            &db,
            "utxo fill",
            Some(Arc::new(move || {
                if !fired.swap(true, Ordering::SeqCst) {
                    let db = weak.upgrade().unwrap();
                    *after.lock() = Some(run_writer(&db, w, target, 7));
                }
            })),
        );
    }

    // The read itself linearizes before the write: it may report the old coin
    if via_has_utxo {
        assert!(db.has_utxo(&target).unwrap());
    } else {
        assert_eq!(value(db.get_utxo(&target).unwrap()), Some(1_000));
    }
    let want = after.lock().take().expect("the writer ran inside the read");

    assert_eq!(
        value(db.get_utxo(&target).unwrap()),
        want,
        "{w:?}: the cache kept the value the reader read before the write"
    );
    assert_eq!(db.has_utxo(&target).unwrap(), want.is_some(), "{w:?}");
    assert_durable(dir.path(), db, target, want);
}

/// One test per (read path, writer) so each schedule passes or fails alone
macro_rules! stale_fill_tests {
    ($($name:ident: $w:expr, $has:expr;)*) => {$(
        #[test]
        fn $name() {
            stale_fill_case($w, $has);
        }
    )*};
}

stale_fill_tests! {
    stale_get_fill_vs_remove_utxo: Writer::RemoveUtxo, false;
    stale_get_fill_vs_add_utxo_new_value: Writer::AddUtxoNewValue, false;
    stale_get_fill_vs_batch_spend: Writer::BatchSpend, false;
    stale_get_fill_vs_atomic_connect_spend: Writer::AtomicConnectSpend, false;
    stale_get_fill_vs_atomic_disconnect_undo: Writer::AtomicDisconnectUndo, false;
    stale_has_fill_vs_remove_utxo: Writer::RemoveUtxo, true;
    stale_has_fill_vs_add_utxo_new_value: Writer::AddUtxoNewValue, true;
    stale_has_fill_vs_batch_spend: Writer::BatchSpend, true;
    stale_has_fill_vs_atomic_connect_spend: Writer::AtomicConnectSpend, true;
    stale_has_fill_vs_atomic_disconnect_undo: Writer::AtomicDisconnectUndo, true;
}

/// Pause the database cache's flush after it built its batch
fn pause_flush(db: &ChainDatabase) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (reached_tx, reached_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let reached_tx = Mutex::new(Some(reached_tx));
    let release_rx = Mutex::new(Some(release_rx));
    set_hook(
        db,
        "utxo flush",
        Some(Arc::new(move || {
            if let Some(tx) = reached_tx.lock().take() {
                tx.send(()).unwrap();
                release_rx.lock().take().unwrap().recv().unwrap();
            }
        })),
    );
    (reached_rx, release_tx)
}

/// A flush races `w`, which spends a coin the cache saw written: the flush is
/// held after it built its batch, `w` runs on another thread, then the flush
/// is let go. The spend must survive the flush and a restart, and the durable
/// UTXO digest and tip must equal a clean replay with no cache.
fn stale_flush_case(w: Writer, cache_entries: u64) {
    let dir = tempdir().unwrap();
    let target = op(2);
    let db = Arc::new(ChainDatabase::open_with_utxo_cache(dir.path(), cache_entries).unwrap());
    db.add_utxo(&target, &coin(3_000)).unwrap();
    // With a one-entry cache these push the coin out of the LRU first
    for i in 0..20u8 {
        db.add_utxo(&op(100 + i), &coin(i64::from(i))).unwrap();
    }
    db.utxo_cache_ref().unwrap().run_pending_tasks();

    let (reached, release) = pause_flush(&db);
    let flusher = {
        let db = db.clone();
        std::thread::spawn(move || db.flush_utxo_cache().unwrap())
    };
    // Either the flush is now held with its batch, or it had nothing to write
    let mut paused = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if reached.try_recv().is_ok() {
            paused = true;
            break;
        }
        if flusher.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    let writer_done = Arc::new(AtomicBool::new(false));
    let writer = {
        let (db, done) = (db.clone(), writer_done.clone());
        std::thread::spawn(move || {
            let r = run_writer(&db, w, target, 9);
            done.store(true, Ordering::SeqCst);
            r
        })
    };
    // Give the writer the chance to land while the flush is held
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline && !writer_done.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(2));
    }
    if paused {
        release.send(()).unwrap();
    }
    flusher.join().unwrap();
    let want = writer.join().unwrap();
    assert_eq!(want, None);

    let stats = db.get_utxo_stats().unwrap();
    assert_eq!(
        value(db.get_utxo(&target).unwrap()),
        want,
        "{w:?}: the spent coin is back"
    );

    // Clean replay with no cache
    let clean_dir = tempdir().unwrap();
    let clean = ChainDatabase::open(clean_dir.path()).unwrap();
    clean.add_utxo(&target, &coin(3_000)).unwrap();
    for i in 0..20u8 {
        clean.add_utxo(&op(100 + i), &coin(i64::from(i))).unwrap();
    }
    run_writer(&clean, w, target, 9);
    let clean_stats = clean.get_utxo_stats().unwrap();
    assert_eq!(
        stats.hash_serialized, clean_stats.hash_serialized,
        "{w:?}: digest"
    );
    assert_eq!(stats.best_block, clean_stats.best_block, "{w:?}: tip");
    assert_eq!(stats.height, clean_stats.height, "{w:?}: height");
    assert_eq!(stats.txouts, clean_stats.txouts, "{w:?}: coin count");

    assert_durable(dir.path(), db, target, want);
}

macro_rules! stale_flush_tests {
    ($($name:ident: $w:expr, $entries:expr;)*) => {$(
        #[test]
        fn $name() {
            stale_flush_case($w, $entries);
        }
    )*};
}

stale_flush_tests! {
    stale_flush_vs_remove_utxo: Writer::RemoveUtxo, 1000;
    stale_flush_vs_batch_spend: Writer::BatchSpend, 1000;
    stale_flush_vs_atomic_connect_spend: Writer::AtomicConnectSpend, 1000;
    stale_flush_vs_atomic_disconnect_undo: Writer::AtomicDisconnectUndo, 1000;
    stale_flush_of_evicted_entry_vs_remove_utxo: Writer::RemoveUtxo, 1;
    stale_flush_of_evicted_entry_vs_atomic_connect_spend: Writer::AtomicConnectSpend, 1;
}

/// A model check with a tiny (eviction-heavy) cache: a deterministic mix of
/// every writer, reads through both read paths, flushes, and writers forced
/// into the gap between a reader's database read and its fill. After every
/// step the cache must agree with the model; after a restart, so must the
/// database.
#[test]
fn model_check_interleaved_fills_writers_flushes_eviction() {
    let dir = tempdir().unwrap();
    let ops: Vec<OutPoint> = (0..16u8).map(op).collect();
    let initial: Vec<(OutPoint, i64)> = ops.iter().map(|o| (*o, 1)).collect();
    let db = seeded(dir.path(), &initial, 3);
    let model: Arc<Mutex<HashMap<OutPoint, Option<i64>>>> = Arc::new(Mutex::new(
        initial.iter().map(|(o, v)| (*o, Some(*v))).collect(),
    ));

    // A pending writer the next fill runs in its gap
    let pending: Arc<Mutex<Option<(Writer, OutPoint, u32)>>> = Arc::new(Mutex::new(None));
    {
        let weak = Arc::downgrade(&db);
        let (pending, model) = (pending.clone(), model.clone());
        set_hook(
            &db,
            "utxo fill",
            Some(Arc::new(move || {
                let job = pending.lock().take();
                if let Some((w, target, h)) = job {
                    let db = weak.upgrade().unwrap();
                    let v = run_writer(&db, w, target, h);
                    model.lock().insert(target, v);
                }
            })),
        );
    }

    let mut seed: u64 = 0x5eed_c3c3;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as u32
    };
    let height = AtomicU32::new(10);
    for step in 0..3000u32 {
        let target = ops[(next() % 16) as usize];
        let h = height.fetch_add(1, Ordering::SeqCst);
        match next() % 8 {
            0 | 1 => {
                // Restore or rewrite the coin
                let v = i64::from(step) + 10;
                db.add_utxo(&target, &coin(v)).unwrap();
                model.lock().insert(target, Some(v));
            }
            2 => {
                let w = WRITERS[(next() % 5) as usize];
                let v = run_writer(&db, w, target, h);
                model.lock().insert(target, v);
            }
            3 => {
                // Force a writer into the next fill's gap
                let w = WRITERS[(next() % 5) as usize];
                let other = ops[(next() % 16) as usize];
                *pending.lock() = Some((w, other, h));
                let _ = db.get_utxo(&target).unwrap();
                *pending.lock() = None;
            }
            4 => {
                let w = WRITERS[(next() % 5) as usize];
                *pending.lock() = Some((w, target, h));
                let _ = db.has_utxo(&target).unwrap();
                *pending.lock() = None;
            }
            5 => {
                db.flush_utxo_cache().unwrap();
            }
            _ => {
                let _ = db.get_utxo(&target).unwrap();
            }
        }
        if step % 64 == 0 {
            db.utxo_cache_ref().unwrap().run_pending_tasks();
        }
        let m = model.lock().clone();
        for o in &ops {
            assert_eq!(
                value(db.get_utxo(o).unwrap()),
                m[o],
                "step {step}: cache disagrees with the model for {o:?}"
            );
        }
    }

    db.flush_utxo_cache().unwrap();
    set_hook(&db, "utxo fill", None);
    let m = model.lock().clone();
    drop(db);
    let plain = ChainDatabase::open(dir.path()).unwrap();
    for o in &ops {
        assert_eq!(
            value(plain.get_utxo(o).unwrap()),
            m[o],
            "after restart: {o:?}"
        );
    }
}

/// Real threads, no forced schedule: readers hammer both read paths while a
/// writer runs every write path and flushes. Afterwards every cached answer
/// equals the database, and a restart equals the writer's model.
#[test]
fn threaded_readers_writers_flushes_stay_coherent() {
    let dir = tempdir().unwrap();
    let ops: Vec<OutPoint> = (0..12u8).map(op).collect();
    let initial: Vec<(OutPoint, i64)> = ops.iter().map(|o| (*o, 1)).collect();
    let db = seeded(dir.path(), &initial, 4);
    let mut model: HashMap<OutPoint, Option<i64>> =
        initial.iter().map(|(o, v)| (*o, Some(*v))).collect();
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..3)
        .map(|r| {
            let (db, ops, stop) = (db.clone(), ops.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    for o in &ops {
                        if r % 2 == 0 {
                            let _ = db.get_utxo(o).unwrap();
                        } else {
                            let _ = db.has_utxo(o).unwrap();
                        }
                    }
                }
            })
        })
        .collect();
    for step in 0..1500u32 {
        let target = ops[(step as usize * 7) % ops.len()];
        if step % 3 == 0 {
            let v = i64::from(step) + 10;
            db.add_utxo(&target, &coin(v)).unwrap();
            model.insert(target, Some(v));
        } else {
            let w = WRITERS[(step as usize) % WRITERS.len()];
            let v = run_writer(&db, w, target, step + 10);
            model.insert(target, v);
        }
        if step % 50 == 0 {
            db.flush_utxo_cache().unwrap();
        }
    }
    stop.store(true, Ordering::SeqCst);
    for r in readers {
        r.join().unwrap();
    }
    for o in &ops {
        assert_eq!(
            value(db.get_utxo(o).unwrap()),
            model[o],
            "cached view {o:?}"
        );
    }
    db.flush_utxo_cache().unwrap();
    drop(db);
    let plain = ChainDatabase::open(dir.path()).unwrap();
    let raw = plain.inner_db();
    let cf = raw.cf_handle("utxo").unwrap();
    let mut on_disk = 0;
    for item in raw.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
        let (k, _) = item.unwrap();
        let o = outpoint_from_key(&k).unwrap();
        assert!(model[&o].is_some(), "{o:?} on disk but spent");
        on_disk += 1;
    }
    assert_eq!(on_disk, model.values().filter(|v| v.is_some()).count());
    for o in &ops {
        assert_eq!(
            value(plain.get_utxo(o).unwrap()),
            model[o],
            "after restart {o:?}"
        );
    }
}
