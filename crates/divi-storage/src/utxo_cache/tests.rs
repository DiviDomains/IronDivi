// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

use super::*;
use crate::database::ChainDatabase;
use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::time::Duration;
use tempfile::tempdir;

fn test_outpoint(n: u8) -> OutPoint {
    OutPoint::new(Hash256::from_bytes([n; 32]), n as u32)
}

fn test_utxo(value: i64) -> Utxo {
    Utxo::new(
        Amount::from_sat(value),
        Script::new_p2pkh(&[0u8; 20]),
        100,
        false,
        false,
    )
}

fn sat(u: Option<Option<Utxo>>) -> Option<Option<i64>> {
    u.map(|o| o.map(|u| u.value.as_sat()))
}

fn db_put(db: &DB, op: &OutPoint, u: &Utxo) -> Result<(), StorageError> {
    db.put_cf(&db.cf_handle(CF_UTXO).unwrap(), utxo_key(op), u.to_bytes())?;
    Ok(())
}

fn db_delete(db: &DB, op: &OutPoint) -> Result<(), StorageError> {
    db.delete_cf(&db.cf_handle(CF_UTXO).unwrap(), utxo_key(op))?;
    Ok(())
}

fn db_get(db: &DB, op: &OutPoint) -> Option<i64> {
    db.get_cf(&db.cf_handle(CF_UTXO).unwrap(), utxo_key(op))
        .unwrap()
        .map(|b| Utxo::from_bytes(&b).unwrap().value.as_sat())
}

// ---------------------------------------------------------------------------
// Behaviour kept from before C3
// ---------------------------------------------------------------------------

#[test]
fn test_cache_insert_and_get() {
    let cache = UtxoCache::new(1000);
    let outpoint = test_outpoint(1);
    let utxo = test_utxo(50000);
    cache.insert(outpoint, utxo.clone());
    assert_eq!(cache.get(&outpoint).unwrap().unwrap().value, utxo.value);
    assert_eq!(cache.dirty_count(), 1);
}

#[test]
fn test_cache_remove_tombstone() {
    let cache = UtxoCache::new(1000);
    let outpoint = test_outpoint(2);
    cache.insert(outpoint, test_utxo(100000));
    cache.remove(outpoint);
    assert!(cache.get(&outpoint).unwrap().is_none());
    assert_eq!(cache.contains(&outpoint), Some(false));
}

#[test]
fn test_cache_miss() {
    let cache = UtxoCache::new(1000);
    assert!(cache.get(&test_outpoint(3)).is_none());
    assert!(cache.contains(&test_outpoint(3)).is_none());
}

#[test]
fn test_cache_contains() {
    let cache = UtxoCache::new(1000);
    cache.insert(test_outpoint(4), test_utxo(1000));
    cache.remove(test_outpoint(5));
    assert_eq!(cache.contains(&test_outpoint(4)), Some(true));
    assert_eq!(cache.contains(&test_outpoint(5)), Some(false));
    assert!(cache.contains(&test_outpoint(99)).is_none());
}

#[test]
fn test_cache_stats() {
    let cache = UtxoCache::new(1000);
    let stats = cache.stats();
    assert_eq!(stats.entry_count, 0);
    assert_eq!(stats.dirty_count, 0);
    assert_eq!(stats.max_entries, 1000);
    cache.insert(test_outpoint(1), test_utxo(100));
    cache.insert(test_outpoint(2), test_utxo(200));
    cache.remove(test_outpoint(3));
    cache.run_pending_tasks();
    let stats = cache.stats();
    assert_eq!(stats.entry_count, 3);
    assert_eq!(stats.dirty_count, 3);
}

#[test]
fn test_cache_clear() {
    let cache = UtxoCache::new(1000);
    cache.insert(test_outpoint(1), test_utxo(100));
    cache.insert(test_outpoint(2), test_utxo(200));
    cache.run_pending_tasks();
    assert_eq!(cache.entry_count(), 2);
    assert_eq!(cache.dirty_count(), 2);
    cache.clear();
    cache.run_pending_tasks();
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.dirty_count(), 0);
}

#[test]
fn test_fill_from_db() {
    let cache = UtxoCache::new(1000);
    let outpoint = test_outpoint(10);
    let utxo = test_utxo(999999);
    let ticket = cache.fill_ticket();
    assert!(cache.fill(ticket, outpoint, Some(utxo.clone())));
    cache.run_pending_tasks();
    // Cached but NOT dirty: it equals the database
    assert_eq!(cache.entry_count(), 1);
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.get(&outpoint).unwrap().unwrap().value, utxo.value);
}

#[test]
fn test_cache_lru_eviction() {
    let cache = UtxoCache::new(5);
    for i in 0..10u8 {
        let t = cache.fill_ticket();
        cache.fill(t, test_outpoint(i), Some(test_utxo(i as i64 * 100)));
    }
    cache.run_pending_tasks();
    assert!(cache.entry_count() <= 5);
}

#[test]
fn test_max_entries() {
    assert_eq!(UtxoCache::new(12345).max_entries(), 12345);
}

#[test]
fn test_evicted_count_initially_zero() {
    assert_eq!(UtxoCache::new(1000).evicted_count(), 0);
}

#[test]
fn test_fill_none_does_not_cache() {
    let cache = UtxoCache::new(1000);
    let outpoint = test_outpoint(20);
    let t = cache.fill_ticket();
    assert!(!cache.fill(t, outpoint, None));
    cache.run_pending_tasks();
    assert!(cache.get(&outpoint).is_none());
    assert_eq!(cache.dirty_count(), 0);
}

#[test]
fn test_insert_overrides_fill() {
    let cache = UtxoCache::new(1000);
    let outpoint = test_outpoint(30);
    let t = cache.fill_ticket();
    assert!(cache.fill(t, outpoint, Some(test_utxo(99999))));
    assert_eq!(cache.dirty_count(), 0);
    cache.insert(outpoint, test_utxo(12345));
    assert_eq!(cache.get(&outpoint).unwrap().unwrap().value.as_sat(), 12345);
    assert_eq!(cache.dirty_count(), 1);
}

#[test]
fn test_remove_after_fill_marks_dirty() {
    let cache = UtxoCache::new(1000);
    let outpoint = test_outpoint(40);
    let t = cache.fill_ticket();
    assert!(cache.fill(t, outpoint, Some(test_utxo(5000))));
    assert_eq!(cache.dirty_count(), 0);
    cache.remove(outpoint);
    assert_eq!(cache.dirty_count(), 1);
    assert!(cache.get(&outpoint).unwrap().is_none());
}

#[test]
fn test_cache_multiple_inserts_same_outpoint() {
    let cache = UtxoCache::new(1000);
    let outpoint = test_outpoint(50);
    cache.insert(outpoint, test_utxo(100));
    cache.insert(outpoint, test_utxo(200));
    cache.insert(outpoint, test_utxo(300));
    cache.run_pending_tasks();
    assert_eq!(cache.get(&outpoint).unwrap().unwrap().value.as_sat(), 300);
    assert_eq!(cache.dirty_count(), 1);
}

#[test]
fn test_dirty_count_after_clear_includes_evicted() {
    // Kept from before C3; with a small cache some dirty entries are evicted
    // from the LRU, and clear() must discard those too
    let cache = UtxoCache::new(2);
    for i in 0..10u8 {
        cache.insert(test_outpoint(i), test_utxo(i64::from(i) * 100));
    }
    cache.run_pending_tasks();
    assert_eq!(cache.dirty_count(), 10);
    assert!(cache.evicted_count() > 0);
    cache.clear();
    cache.run_pending_tasks();
    assert_eq!(cache.dirty_count(), 0);
    assert_eq!(cache.evicted_count(), 0);
    assert_eq!(cache.entry_count(), 0);
}

#[test]
fn test_stats_display() {
    let cache = UtxoCache::new(500);
    cache.insert(test_outpoint(1), test_utxo(100));
    cache.run_pending_tasks();
    let display = format!("{}", cache.stats());
    assert!(display.contains("500"));
    assert!(display.contains("dirty"));
}

// ---------------------------------------------------------------------------
// C3: validated fills
// ---------------------------------------------------------------------------

/// The stale-fill interleaving, step by step: a reader takes its ticket and
/// reads V from the database, a writer then spends the coin (database and
/// cache), and only then does the reader try to cache V. The fill must be
/// refused; the tombstone stays.
#[test]
fn fill_refused_after_write_through_between_read_and_fill() {
    let dir = tempdir().unwrap();
    let chain_db = ChainDatabase::open(dir.path()).unwrap();
    let db = chain_db.inner_db();
    let cache = UtxoCache::new(1000);
    let op = test_outpoint(60);
    db_put(db, &op, &test_utxo(600)).unwrap();

    // Reader: miss, ticket, database read
    assert!(cache.get(&op).is_none());
    let ticket = cache.fill_ticket();
    let read = Some(test_utxo(db_get(db, &op).unwrap()));

    // Writer spends it in between
    cache
        .write_through(vec![(op, None)], || db_delete(db, &op))
        .unwrap();

    // Reader's fill of the value it read must be refused
    assert!(!cache.fill(ticket, op, read));
    assert_eq!(sat(cache.get(&op)), Some(None));
    assert_eq!(db_get(db, &op), None);
}

/// A ticket taken while a mutation is in flight (its database write may or
/// may not be visible to the read) is never accepted, even after the
/// mutation has finished.
#[test]
fn fill_refused_when_ticket_taken_during_mutation() {
    let dir = tempdir().unwrap();
    let chain_db = ChainDatabase::open(dir.path()).unwrap();
    let db = chain_db.inner_db();
    let cache = UtxoCache::new(1000);
    let op = test_outpoint(61);
    db_put(db, &op, &test_utxo(610)).unwrap();

    let mut inside = None;
    cache
        .write_through(vec![(op, None)], || {
            // The reader runs entirely while the writer's database write is
            // in flight (before it is applied to the cache)
            let t = cache.fill_ticket();
            let v = db_get(db, &op).map(test_utxo);
            inside = Some((t, v));
            db_delete(db, &op)
        })
        .unwrap();
    let (t, v) = inside.unwrap();
    assert!(!cache.fill(t, op, v));
    assert_eq!(sat(cache.get(&op)), Some(None));
}

/// A fill with no concurrent mutation is accepted and later mutations still
/// win over it.
#[test]
fn fill_accepted_when_quiescent_and_superseded_by_later_write() {
    let dir = tempdir().unwrap();
    let chain_db = ChainDatabase::open(dir.path()).unwrap();
    let db = chain_db.inner_db();
    let cache = UtxoCache::new(1000);
    let op = test_outpoint(62);
    db_put(db, &op, &test_utxo(620)).unwrap();
    let t = cache.fill_ticket();
    assert!(cache.fill(t, op, Some(test_utxo(620))));
    cache
        .write_through(vec![(op, Some(test_utxo(621)))], || {
            db_put(db, &op, &test_utxo(621))
        })
        .unwrap();
    assert_eq!(sat(cache.get(&op)), Some(Some(621)));
    // The old ticket is now stale
    assert!(!cache.fill(t, op, Some(test_utxo(620))));
    assert_eq!(sat(cache.get(&op)), Some(Some(621)));
}

/// A refused fill does not corrupt anything: a stale reader racing many
/// writers on real threads never leaves the cache disagreeing with the
/// database once everything has finished.
#[test]
fn threaded_fills_never_leave_cache_ahead_or_behind_database() {
    let dir = tempdir().unwrap();
    let chain_db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let cache = Arc::new(UtxoCache::new(4));
    let ops: Vec<OutPoint> = (0..8u8).map(test_outpoint).collect();
    let stop = Arc::new(AtomicBool::new(false));

    let mut readers = Vec::new();
    for _ in 0..3 {
        let (db, cache, ops, stop) = (chain_db.clone(), cache.clone(), ops.clone(), stop.clone());
        readers.push(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for op in &ops {
                    if cache.get(op).is_none() {
                        let t = cache.fill_ticket();
                        let v = db_get(db.inner_db(), op).map(test_utxo);
                        cache.fill(t, *op, v);
                    }
                }
            }
        }));
    }
    for round in 0..400i64 {
        let op = ops[(round % 8) as usize];
        let db = chain_db.inner_db();
        if round % 3 == 0 {
            cache
                .write_through(vec![(op, None)], || db_delete(db, &op))
                .unwrap();
        } else {
            let u = test_utxo(1000 + round);
            cache
                .write_through(vec![(op, Some(u.clone()))], || db_put(db, &op, &u))
                .unwrap();
        }
    }
    stop.store(true, Ordering::SeqCst);
    for r in readers {
        r.join().unwrap();
    }
    for op in &ops {
        let db_val = db_get(chain_db.inner_db(), op);
        if let Some(cached) = cache.get(op) {
            assert_eq!(
                cached.map(|u| u.value.as_sat()),
                db_val,
                "cache disagrees with database"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// C3: write-through failure and unwinding
// ---------------------------------------------------------------------------

#[test]
fn failed_write_through_leaves_cache_unchanged_and_fills_resume() {
    let cache = UtxoCache::new(1000);
    let op = test_outpoint(70);
    cache
        .write_through(vec![(op, Some(test_utxo(700)))], || Ok(()))
        .unwrap();
    let err = cache.write_through(vec![(op, None)], || {
        Err::<(), _>(StorageError::ChainState("write failed".into()))
    });
    assert!(err.is_err());
    // The database did not change, so neither did the cache
    assert_eq!(sat(cache.get(&op)), Some(Some(700)));
    // No mutation is left in flight
    let t = cache.fill_ticket();
    assert!(cache.fill(t, test_outpoint(71), Some(test_utxo(710))));
}

#[test]
fn panicking_write_through_drops_touched_entries() {
    let cache = UtxoCache::new(1000);
    let op = test_outpoint(72);
    cache
        .write_through(vec![(op, Some(test_utxo(720)))], || Ok(()))
        .unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cache.write_through(vec![(op, None)], || -> Result<(), StorageError> {
            panic!("process dies mid-write")
        });
    }));
    assert!(r.is_err());
    // Unknown database state: the entry is dropped so the database is read
    cache.run_pending_tasks();
    assert!(cache.get(&op).is_none());
    // The sequence is even again and the gate is free
    let t = cache.fill_ticket();
    assert!(cache.fill(t, test_outpoint(73), Some(test_utxo(730))));
    cache
        .write_through(vec![(op, Some(test_utxo(721)))], || Ok(()))
        .unwrap();
}

// ---------------------------------------------------------------------------
// C3: flush ordering (write-back use)
// ---------------------------------------------------------------------------

/// Pause `cache`'s flush between its snapshot and its database write; returns
/// (reached, release).
fn pause_flush(cache: &UtxoCache) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (reached_tx, reached_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let reached_tx = Mutex::new(Some(reached_tx));
    let release_rx = Mutex::new(Some(release_rx));
    cache.set_sched_hook(
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

/// The stale-flush interleaving: a flush snapshots dirty value V1 and is about
/// to write it, while a writer writes V2 through. The writer must wait for the
/// flush, so V1 can never land over V2.
#[test]
fn flush_cannot_overwrite_a_newer_write_through() {
    let dir = tempdir().unwrap();
    let chain_db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let cache = Arc::new(UtxoCache::new(1000));
    let op = test_outpoint(80);
    cache.insert(op, test_utxo(800)); // dirty V1

    let (reached, release) = pause_flush(&cache);
    let flusher = {
        let (db, cache) = (chain_db.clone(), cache.clone());
        std::thread::spawn(move || cache.flush(db.inner_db()).unwrap())
    };
    reached.recv().unwrap(); // flush holds its snapshot of V1

    let writer_done = Arc::new(AtomicBool::new(false));
    let writer = {
        let (db, cache, done) = (chain_db.clone(), cache.clone(), writer_done.clone());
        std::thread::spawn(move || {
            let u = test_utxo(801);
            cache
                .write_through(vec![(op, Some(u.clone()))], || {
                    db_put(db.inner_db(), &op, &u)
                })
                .unwrap();
            done.store(true, Ordering::SeqCst);
        })
    };
    std::thread::sleep(Duration::from_millis(150));
    // Blocked on the gate for as long as the flush is paused
    assert!(!writer_done.load(Ordering::SeqCst));
    release.send(()).unwrap();
    assert_eq!(flusher.join().unwrap(), 1);
    writer.join().unwrap();

    assert_eq!(db_get(chain_db.inner_db(), &op), Some(801));
    assert_eq!(sat(cache.get(&op)), Some(Some(801)));
    assert_eq!(cache.dirty_count(), 0);
}

/// A write-back made while a flush is paused must stay dirty afterwards
/// (before C3 the flush cleared dirty markers it never wrote).
#[test]
fn flush_keeps_entries_dirtied_after_its_snapshot() {
    let dir = tempdir().unwrap();
    let chain_db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let cache = Arc::new(UtxoCache::new(1000));
    let a = test_outpoint(81);
    let b = test_outpoint(82);
    cache.insert(a, test_utxo(810));

    let (reached, release) = pause_flush(&cache);
    let flusher = {
        let (db, cache) = (chain_db.clone(), cache.clone());
        std::thread::spawn(move || cache.flush(db.inner_db()).unwrap())
    };
    reached.recv().unwrap();
    let writer = {
        let cache = cache.clone();
        std::thread::spawn(move || {
            cache.insert(a, test_utxo(811));
            cache.insert(b, test_utxo(820));
        })
    };
    std::thread::sleep(Duration::from_millis(50));
    release.send(()).unwrap();
    assert_eq!(flusher.join().unwrap(), 1);
    writer.join().unwrap();

    assert_eq!(cache.dirty_count(), 2, "post-snapshot writes stay dirty");
    assert_eq!(sat(cache.get(&a)), Some(Some(811)));
    cache.set_sched_hook("utxo flush", None);
    assert_eq!(cache.flush(chain_db.inner_db()).unwrap(), 2);
    assert_eq!(db_get(chain_db.inner_db(), &a), Some(811));
    assert_eq!(db_get(chain_db.inner_db(), &b), Some(820));
    assert_eq!(cache.dirty_count(), 0);
}

/// A failed flush keeps everything dirty and the database untouched; the
/// retry writes the newest values.
#[test]
fn failed_flush_keeps_entries_dirty_for_retry() {
    let dir = tempdir().unwrap();
    let chain_db = ChainDatabase::open(dir.path()).unwrap();
    let cache = UtxoCache::new(1000);
    let op = test_outpoint(83);
    cache.insert(op, test_utxo(830));
    crate::fault::arm("utxo flush", 0);
    assert!(cache.flush(chain_db.inner_db()).is_err());
    crate::fault::disarm();
    assert_eq!(cache.dirty_count(), 1);
    assert_eq!(db_get(chain_db.inner_db(), &op), None);
    // Fills still work after the failed flush (no mutation left in flight)
    let t = cache.fill_ticket();
    assert!(cache.fill(t, test_outpoint(84), Some(test_utxo(840))));
    assert_eq!(cache.flush(chain_db.inner_db()).unwrap(), 1);
    assert_eq!(db_get(chain_db.inner_db(), &op), Some(830));
    assert_eq!(cache.dirty_count(), 0);
}

// ---------------------------------------------------------------------------
// C3: eviction
// ---------------------------------------------------------------------------

/// Dirty entries live outside the LRU: evicting them loses nothing, reads keep
/// returning the newest value, and the flush writes all of them.
#[test]
fn eviction_never_drops_or_reorders_dirty_entries() {
    let dir = tempdir().unwrap();
    let chain_db = ChainDatabase::open(dir.path()).unwrap();
    let cache = UtxoCache::new(2);
    for i in 0..50u8 {
        cache.insert(test_outpoint(i), test_utxo(i as i64));
    }
    // Overwrite some after they were evicted
    for i in 0..10u8 {
        cache.insert(test_outpoint(i), test_utxo(1000 + i as i64));
    }
    cache.remove(test_outpoint(20));
    cache.run_pending_tasks();
    assert!(cache.entry_count() <= 2);
    assert!(cache.evicted_count() >= 45);
    for i in 0..50u8 {
        let want = match i {
            0..=9 => Some(1000 + i as i64),
            20 => None,
            _ => Some(i as i64),
        };
        assert_eq!(
            sat(cache.get(&test_outpoint(i))),
            Some(want),
            "outpoint {i}"
        );
    }
    assert_eq!(cache.flush(chain_db.inner_db()).unwrap(), 50);
    for i in 0..50u8 {
        let want = match i {
            0..=9 => Some(1000 + i as i64),
            20 => None,
            _ => Some(i as i64),
        };
        assert_eq!(db_get(chain_db.inner_db(), &test_outpoint(i)), want);
    }
}

/// A fill can never resurrect an evicted tombstone: once the tombstone is
/// evicted the read goes to the database (which has the delete), and a value
/// read before the delete is refused.
#[test]
fn stale_fill_after_tombstone_eviction_is_refused() {
    let dir = tempdir().unwrap();
    let chain_db = ChainDatabase::open(dir.path()).unwrap();
    let db = chain_db.inner_db();
    let cache = UtxoCache::new(1);
    let op = test_outpoint(90);
    db_put(db, &op, &test_utxo(900)).unwrap();
    let ticket = cache.fill_ticket();
    let stale = db_get(db, &op).map(test_utxo);
    cache
        .write_through(vec![(op, None)], || db_delete(db, &op))
        .unwrap();
    // Push the tombstone out of the one-entry LRU
    for i in 0..20u8 {
        let t = cache.fill_ticket();
        cache.fill(t, test_outpoint(100 + i), Some(test_utxo(i as i64)));
    }
    cache.run_pending_tasks();
    assert!(!cache.fill(ticket, op, stale));
    assert_ne!(sat(cache.get(&op)), Some(Some(900)));
    assert_eq!(db_get(db, &op), None);
}

#[test]
fn dirty_tombstone_rejects_write_through_before_closure_and_survives_flush() {
    let dir = tempdir().unwrap();
    let chain_db = ChainDatabase::open(dir.path()).unwrap();
    let db = chain_db.inner_db();
    let cache = UtxoCache::new(8);
    let op = test_outpoint(99);
    db_put(db, &op, &test_utxo(99)).unwrap();
    cache.remove(op);
    let result = cache.write_through(vec![(op, None)], || -> Result<(), StorageError> {
        panic!("must reject before invoking an ambiguous writer")
    });
    assert!(result.is_err());
    assert_eq!(cache.dirty_count(), 1);
    assert_eq!(cache.contains(&op), Some(false));
    assert_eq!(cache.flush(db).unwrap(), 1);
    let cf = db.cf_handle("utxo").unwrap();
    assert!(db.get_cf(cf, utxo_key(&op)).unwrap().is_none());
}
