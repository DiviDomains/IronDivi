// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! P7 / I3: the DIVI spend scan reads a bounded window per pass and says how far it read, so
//! the engine's persisted spend cursor (H2, `divi_swap` `spend_cursor.rs`) resumes from it
//! instead of reading every block from the lock on every tick; and the median time past is
//! kept per best block.
//!
//! No network: wiremock "nodes" over a scripted chain that can fork, counting every call.
//! The engine's cursor module is private to `divi_swap`, so [`read`] drives a backend exactly
//! as `spend_cursor::find_spend` does (resume at the saved mark with the mark to check; a
//! `Reorged` answer drops the mark and reads again from the floor in the same call; the mark
//! is kept in the swap store's `docs` table), and is the only engine logic restated here.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use divi_crypto::keys::SecretKey;
use divi_swap::{ChainBackend, Outpoint, ScanMark, SpendInfo, SpendScan, Store, SwapError, Txid};
use divi_wallet::address::Network;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use swap_chain_divi::{DiviBackend, FeePolicy, RetryPolicy, RpcClient, MAX_SCAN_BLOCKS};
use wiremock::{matchers::method, Mock, MockServer, Request, Respond, ResponseTemplate};

const BASE_TIME: u64 = 1_800_000_000;
/// The lock's height: the floor every read starts from.
const FLOOR: u64 = 10;
/// Unrelated transactions per block besides the coinbase.
const FILL: usize = 3;

// ---- a scripted chain -------------------------------------------------------------------

/// What one endpoint believes. Blocks are kept by hash, so blocks of a replaced branch are
/// still served by hash (as a real node serves stale blocks) but not by height.
#[derive(Default)]
struct Chain {
    /// The best chain: `best[h]` is the hash of the block at height `h`.
    best: Vec<String>,
    blocks: HashMap<String, Block>,
    txs: HashMap<String, Value>,
    mempool: Vec<String>,
    calls: HashMap<String, u64>,
    /// `getblock` answers name another block than the one asked for.
    wrong_hash: bool,
    /// `getblock` of the block at this height has no `time` (still indexing).
    no_time: Option<u64>,
    /// `getblock` of the block at this height has no parent (an index cut short).
    no_parent: Option<u64>,
    /// After this many `getblockhash` calls at this height, answer this hash instead.
    swap_after: Option<(u64, u64, String)>,
}

struct Block {
    height: u64,
    time: u64,
    parent: Option<String>,
    txs: Vec<String>,
}

fn block_hash(branch: u8, h: u64) -> String {
    format!("{branch:02x}{h:062x}")
}

fn lock() -> Outpoint {
    Outpoint {
        txid: Txid([0xaa; 32]),
        vout: 0,
    }
}

fn claim_txid(n: u8) -> String {
    Txid([n; 32]).to_rpc_hex()
}

impl Chain {
    fn new(tip: u64) -> Self {
        let mut c = Chain::default();
        c.extend(0, tip);
        c
    }

    fn tip(&self) -> u64 {
        self.best.len() as u64 - 1
    }

    /// Mine blocks of `branch` until the tip is `tip`. A branch's blocks are earlier in time
    /// than the first branch's at the same height, so a reorg moves the median time past.
    fn extend(&mut self, branch: u8, tip: u64) {
        while self.best.len() as u64 <= tip {
            let h = self.best.len() as u64;
            let hash = block_hash(branch, h);
            let coinbase = format!("c{:01x}{h:062x}", branch);
            self.txs.insert(
                coinbase.clone(),
                json!({"txid": coinbase, "vin": [{"coinbase": "01"}], "vout": []}),
            );
            let mut txs = vec![coinbase];
            for i in 0..FILL {
                let id = format!("f{:01x}{i:02x}{h:060x}", branch);
                self.txs.insert(
                    id.clone(),
                    json!({"txid": id, "vin": [{"txid": "ee".repeat(32), "vout": i,
                        "scriptSig": {"hex": "00"}}], "vout": []}),
                );
                txs.push(id);
            }
            self.blocks.insert(
                hash.clone(),
                Block {
                    height: h,
                    time: BASE_TIME + h * 60 - u64::from(branch) * 1000,
                    parent: self.best.last().cloned(),
                    txs,
                },
            );
            self.best.push(hash);
        }
    }

    /// Replace every block from `fork` up with blocks of `branch`, up to a new tip `tip`.
    fn reorg(&mut self, fork: u64, branch: u8, tip: u64) {
        self.best.truncate(fork as usize);
        self.extend(branch, tip);
    }

    /// A claim of the lock (`n` names it) mined in the block at `h`, or in the mempool.
    fn claim(&mut self, n: u8, at: Option<u64>) {
        let id = claim_txid(n);
        self.txs.insert(
            id.clone(),
            json!({"txid": id, "vin": [{"txid": lock().txid.to_rpc_hex(), "vout": lock().vout,
                "scriptSig": {"hex": format!("aabb{n:02x}")}}], "vout": []}),
        );
        match at {
            Some(h) => {
                let hash = self.best[h as usize].clone();
                self.blocks.get_mut(&hash).unwrap().txs.push(id);
            }
            None => self.mempool.push(id),
        }
    }

    /// A claim of the lock (`n` names it) mined in the block at `h`, whose scriptSig pushes
    /// `preimage`.
    fn claim_revealing(&mut self, n: u8, h: u64, preimage: &[u8; 32]) {
        let id = claim_txid(n);
        self.txs.insert(
            id.clone(),
            json!({"txid": id, "vin": [{"txid": lock().txid.to_rpc_hex(), "vout": lock().vout,
                "scriptSig": {"hex": format!("20{}", hex::encode(preimage))}}], "vout": []}),
        );
        let hash = self.best[h as usize].clone();
        self.blocks.get_mut(&hash).unwrap().txs.push(id);
    }

    fn median_time_past(&self) -> u32 {
        let mut t: Vec<u64> = self
            .best
            .iter()
            .rev()
            .take(11)
            .map(|h| self.blocks[h].time)
            .collect();
        t.sort_unstable();
        t[t.len() / 2] as u32
    }
}

#[derive(Clone)]
struct Node(Arc<Mutex<Chain>>);

impl Respond for Node {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        let p = &body["params"];
        let m = body["method"].as_str().unwrap_or("").to_string();
        let mut c = self.0.lock();
        *c.calls.entry(m.clone()).or_default() += 1;
        let ok = |v: Value| {
            ResponseTemplate::new(200).set_body_json(json!({"result": v, "error": null, "id": 1}))
        };
        let err = |code: i64, msg: &str| {
            ResponseTemplate::new(500).set_body_json(
                json!({"result": null, "error": {"code": code, "message": msg}, "id": 1}),
            )
        };
        match m.as_str() {
            "getblockcount" => ok(json!(c.tip())),
            "getbestblockhash" => ok(json!(c.best.last().unwrap())),
            "getblockhash" => {
                let h = p[0].as_u64().unwrap();
                let Some(hash) = c.best.get(h as usize).cloned() else {
                    return err(-8, "Block height out of range");
                };
                if let Some((at, after, other)) = c.swap_after.as_mut() {
                    if *at == h {
                        if *after == 0 {
                            return ok(json!(other.clone()));
                        }
                        *after -= 1;
                    }
                }
                ok(json!(hash))
            }
            "getblock" => {
                let hash = p[0].as_str().unwrap().to_string();
                let Some(b) = c.blocks.get(&hash) else {
                    return err(-5, "Block not found");
                };
                let mut v = json!({
                    "hash": if c.wrong_hash { block_hash(9, b.height) } else { hash.clone() },
                    "height": b.height,
                    "time": b.time,
                    "tx": b.txs,
                });
                if let Some(parent) = &b.parent {
                    v["previousblockhash"] = json!(parent);
                }
                if c.no_time == Some(b.height) {
                    v.as_object_mut().unwrap().shift_remove("time");
                }
                if c.no_parent == Some(b.height) {
                    v.as_object_mut().unwrap().shift_remove("previousblockhash");
                }
                ok(v)
            }
            "getrawtransaction" => match c.txs.get(p[0].as_str().unwrap()) {
                Some(t) => ok(t.clone()),
                None => err(-5, "No such mempool or blockchain transaction"),
            },
            "getrawmempool" => ok(json!(c.mempool)),
            _ => err(-32601, "Method not found"),
        }
    }
}

async fn node(chain: Chain) -> (MockServer, Arc<Mutex<Chain>>) {
    let server = MockServer::start().await;
    let chain = Arc::new(Mutex::new(chain));
    Mock::given(method("POST"))
        .respond_with(Node(chain.clone()))
        .mount(&server)
        .await;
    (server, chain)
}

fn retry() -> RetryPolicy {
    RetryPolicy {
        attempts: 1,
        base_delay: Duration::from_millis(1),
    }
}

fn single(url: &str) -> DiviBackend {
    DiviBackend::with_retry(
        url,
        SecretKey::from_hex(&"11".repeat(32)).unwrap(),
        Network::Testnet,
        FeePolicy::default(),
        None,
        retry(),
    )
    .unwrap()
}

fn dual(primary: &str, fallback: &str) -> DiviBackend {
    single(primary).with_fallback_rpc(fallback)
}

/// Calls made since the last [`reset`], by method.
fn calls(c: &Arc<Mutex<Chain>>, m: &str) -> u64 {
    c.lock().calls.get(m).copied().unwrap_or(0)
}

fn total(c: &Arc<Mutex<Chain>>) -> u64 {
    c.lock().calls.values().sum()
}

fn reset(c: &Arc<Mutex<Chain>>) {
    c.lock().calls.clear();
}

fn mark(c: &Arc<Mutex<Chain>>, h: u64) -> ScanMark {
    ScanMark {
        height: h,
        hash: c.lock().best[h as usize].clone(),
    }
}

fn is_held<T: std::fmt::Debug>(r: &Result<T, SwapError>) -> bool {
    matches!(r, Err(SwapError::Held(m)) if m.contains("disagree"))
}

// ---- the engine's cursor, as `spend_cursor::find_spend` drives a backend -----------------

const KIND: &str = "spend_cursor";
const ID: &str = "maker/maker_leg/p7";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Cursor {
    floor: u64,
    through: ScanMark,
    complete: bool,
}

#[derive(Debug, PartialEq)]
enum Found {
    Spend(SpendInfo),
    NoneThroughTip,
    Pending,
}

fn saved(store: &Store) -> Option<Cursor> {
    store.get_doc(KIND, ID).unwrap()
}

async fn read(store: &Store, b: &dyn ChainBackend, floor: u64) -> Result<Found, SwapError> {
    read_via(store, b, floor, false).await
}

/// One pass as `hold::scan_spend` makes it for a read a refund waits on: on the backend, and,
/// once the refund deadline has passed (`past_deadline`), a held pass again on the
/// primary-only view from the same start and mark. Before the deadline a held pass stays held.
async fn scan_held(
    b: &dyn ChainBackend,
    from: u64,
    resume: Option<&ScanMark>,
    past_deadline: bool,
) -> Result<SpendScan, SwapError> {
    match b.scan_spend(&lock(), from, resume).await {
        Err(SwapError::Held(_)) if past_deadline => {
            let view = b
                .primary_only()
                .ok_or_else(|| SwapError::Transient("no primary-only view".into()))?;
            view.scan_spend(&lock(), from, resume).await
        }
        other => other,
    }
}

/// [`read`], each pass made as [`scan_held`] makes it.
async fn read_via(
    store: &Store,
    b: &dyn ChainBackend,
    floor: u64,
    past_deadline: bool,
) -> Result<Found, SwapError> {
    let saved = saved(store);
    let mut restarted = false;
    loop {
        let (from, resume) = match &saved {
            Some(c) if !restarted && c.floor <= floor && c.through.height >= floor => {
                (c.through.height, Some(c.through.clone()))
            }
            _ => (floor, None),
        };
        match scan_held(b, from, resume.as_ref(), past_deadline).await? {
            SpendScan::Spent(s) => return Ok(Found::Spend(s)),
            SpendScan::NotYet {
                through: Some(through),
                complete,
            } => {
                let floor = match (&resume, &saved) {
                    (Some(_), Some(c)) => c.floor,
                    _ => floor,
                };
                store.put_doc(
                    KIND,
                    ID,
                    &Cursor {
                        floor,
                        through,
                        complete,
                    },
                )?;
                return Ok(if complete {
                    Found::NoneThroughTip
                } else {
                    Found::Pending
                });
            }
            SpendScan::NotYet {
                through: None,
                complete,
            } => {
                return Ok(if complete {
                    Found::NoneThroughTip
                } else {
                    Found::Pending
                })
            }
            SpendScan::Reorged if resume.is_some() => restarted = true,
            SpendScan::Reorged => {
                return Err(SwapError::Transient("reorg without a mark".into()));
            }
        }
    }
}

fn spent_at(f: Result<Found, SwapError>) -> Option<u64> {
    match f.unwrap() {
        Found::Spend(s) => {
            assert_eq!(s.txid.to_rpc_hex().len(), 64);
            s.height
        }
        other => panic!("expected a spend, got {other:?}"),
    }
}

// ---- one endpoint -------------------------------------------------------------------------

/// A claim two windows past the lock: each read advances the persisted mark by one window
/// (the mark's block is re-read for its hash only), a restart resumes from the saved mark,
/// and the third read finds the claim. Short passes are `Pending` and never read the mempool.
#[tokio::test]
async fn a_claim_two_windows_past_the_lock_is_found_by_reads_that_advance_across_a_restart() {
    assert_eq!(MAX_SCAN_BLOCKS, 200);
    let mut chain = Chain::new(FLOOR + 449);
    chain.claim(1, Some(FLOOR + 420));
    let (s, c) = node(chain).await;
    let b = single(&s.uri());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("swaps.db");
    {
        let store = Store::open(&db).unwrap();
        assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
        let first = saved(&store).unwrap();
        assert_eq!(first.through, mark(&c, FLOOR + 199));
        assert!(!first.complete);
        assert_eq!(calls(&c, "getblock"), 200);
        reset(&c);
        assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
        assert_eq!(saved(&store).unwrap().through, mark(&c, FLOOR + 398));
        // The mark's block is checked by hash, not read again.
        assert_eq!(calls(&c, "getblock"), 199);
        assert_eq!(calls(&c, "getrawmempool"), 0);
    }
    let store = Store::open(&db).unwrap();
    reset(&c);
    assert_eq!(spent_at(read(&store, &b, FLOOR).await), Some(FLOOR + 420));
    assert_eq!(
        calls(&c, "getblock"),
        22,
        "the restarted read resumed from its mark"
    );
    // A spend leaves the mark on a block that was checked.
    assert_eq!(saved(&store).unwrap().through, mark(&c, FLOOR + 398));
}

/// No claim: `Pending` until a pass reaches the tip, then `NoneThroughTip`; from then on a
/// tick at the same tip costs five calls (no block or transaction read), and a tick one block
/// on reads that block alone, also across a restart.
#[tokio::test]
async fn an_unspent_lock_is_pending_until_the_tip_then_each_tick_reads_only_new_blocks() {
    let (s, c) = node(Chain::new(FLOOR + 449)).await;
    let b = single(&s.uri());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("swaps.db");
    let store = Store::open(&db).unwrap();
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    assert_eq!(calls(&c, "getrawmempool"), 0);
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    let done = saved(&store).unwrap();
    assert_eq!(done.through, mark(&c, FLOOR + 449));
    assert!(done.complete);
    assert_eq!(done.floor, FLOOR);
    assert_eq!(calls(&c, "getrawmempool"), 1);

    reset(&c);
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    assert_eq!(
        (
            calls(&c, "getblockcount"),
            calls(&c, "getblockhash"),
            calls(&c, "getblock"),
            calls(&c, "getrawtransaction"),
            calls(&c, "getrawmempool")
        ),
        (2, 2, 0, 0, 1)
    );
    assert_eq!(total(&c), 5);

    c.lock().extend(0, FLOOR + 450);
    reset(&c);
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    assert_eq!(saved(&store).unwrap().through, mark(&c, FLOOR + 450));
    assert_eq!(calls(&c, "getblock"), 1);
    assert_eq!(calls(&c, "getrawtransaction"), 1 + FILL as u64);
    assert_eq!(total(&c), 7 + 1 + FILL as u64);

    drop(store);
    let store = Store::open(&db).unwrap();
    reset(&c);
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    assert_eq!(
        total(&c),
        5,
        "a restarted engine resumes from the saved mark"
    );
}

/// A claim in the mempool is seen only by the pass that reaches the tip: the two short passes
/// before it are `Pending`, not "no spend".
#[tokio::test]
async fn a_mempool_claim_is_seen_once_a_pass_reaches_the_tip() {
    let mut chain = Chain::new(FLOOR + 449);
    chain.claim(2, None);
    let (s, _c) = node(chain).await;
    let b = single(&s.uri());
    let store = Store::in_memory().unwrap();
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    assert_eq!(spent_at(read(&store, &b, FLOOR).await), None);
}

/// A bounded pass short of the tip, read directly: its last block, not complete, no mempool.
#[tokio::test]
async fn a_pass_short_of_the_tip_names_its_last_block_and_is_not_complete() {
    let mut chain = Chain::new(FLOOR + 449);
    chain.claim(3, None);
    let (s, c) = node(chain).await;
    let b = single(&s.uri());
    assert_eq!(
        b.scan_spend(&lock(), FLOOR, None).await.unwrap(),
        SpendScan::NotYet {
            through: Some(mark(&c, FLOOR + 199)),
            complete: false
        }
    );
    assert_eq!(calls(&c, "getrawmempool"), 0);
    // Through the tip in one pass (a chain shorter than the window): complete.
    let (s, c) = node(Chain::new(FLOOR + 150)).await;
    assert_eq!(
        single(&s.uri())
            .scan_spend(&lock(), FLOOR, None)
            .await
            .unwrap(),
        SpendScan::NotYet {
            through: Some(mark(&c, FLOOR + 150)),
            complete: true
        }
    );
}

/// `find_spend` called directly keeps its contract: every block from the start through the
/// tip, then the mempool, however many windows that is.
#[tokio::test]
async fn a_direct_find_spend_still_reads_through_the_tip() {
    let mut chain = Chain::new(FLOOR + 449);
    chain.claim(4, Some(FLOOR + 250));
    let (s, _c) = node(chain).await;
    let found = single(&s.uri()).find_spend(&lock(), FLOOR).await.unwrap();
    assert_eq!(found.unwrap().height, Some(FLOOR + 250));

    let mut chain = Chain::new(FLOOR + 449);
    chain.claim(4, Some(FLOOR + 449));
    let (s, _c) = node(chain).await;
    let (f, _fc) = node({
        let mut c = Chain::new(FLOOR + 449);
        c.claim(4, Some(FLOOR + 449));
        c
    })
    .await;
    let found = dual(&s.uri(), &f.uri())
        .find_spend(&lock(), FLOOR)
        .await
        .unwrap();
    assert_eq!(found.unwrap().height, Some(FLOOR + 449));

    let mut chain = Chain::new(FLOOR + 449);
    chain.claim(4, None);
    let (s, _c) = node(chain).await;
    let found = single(&s.uri()).find_spend(&lock(), FLOOR).await.unwrap();
    assert_eq!(found.unwrap().height, None);

    let (s, c) = node(Chain::new(FLOOR + 449)).await;
    assert!(single(&s.uri())
        .find_spend(&lock(), FLOOR)
        .await
        .unwrap()
        .is_none());
    assert_eq!(calls(&c, "getrawmempool"), 1);
}

/// A reorg that replaces the marked tip: the resumed pass sees another block at the mark, the
/// read starts again from the floor in the same call and finds the claim on the new branch.
#[tokio::test]
async fn a_shallow_reorg_at_the_mark_reads_again_from_the_floor_and_finds_the_claim() {
    let (s, c) = node(Chain::new(FLOOR + 150)).await;
    let b = single(&s.uri());
    let store = Store::in_memory().unwrap();
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    let before = saved(&store).unwrap().through;
    {
        let mut ch = c.lock();
        ch.reorg(FLOOR + 150, 1, FLOOR + 151);
        ch.claim(5, Some(FLOOR + 150));
    }
    assert_ne!(before, mark(&c, FLOOR + 150));
    assert_eq!(
        b.scan_spend(&lock(), before.height, Some(&before))
            .await
            .unwrap(),
        SpendScan::Reorged
    );
    assert_eq!(spent_at(read(&store, &b, FLOOR).await), Some(FLOOR + 150));
}

/// A deeper reorg onto a shorter branch (the tip is now below the mark) is a reorg too, and
/// the claim mined on that branch below the old mark is found.
#[tokio::test]
async fn a_deep_reorg_below_the_mark_reads_again_and_finds_the_claim() {
    let (s, c) = node(Chain::new(FLOOR + 150)).await;
    let b = single(&s.uri());
    let store = Store::in_memory().unwrap();
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    {
        let mut ch = c.lock();
        ch.reorg(FLOOR + 90, 1, FLOOR + 120);
        ch.claim(6, Some(FLOOR + 100));
    }
    reset(&c);
    let old = saved(&store).unwrap().through;
    assert_eq!(
        b.scan_spend(&lock(), old.height, Some(&old)).await.unwrap(),
        SpendScan::Reorged
    );
    assert_eq!(
        total(&c),
        1,
        "a tip below the mark is a reorg, nothing else is read"
    );
    assert_eq!(spent_at(read(&store, &b, FLOOR).await), Some(FLOOR + 100));
}

/// A reorg under a mark several windows in, with the claim on the new branch past the old
/// mark: the reads start over from the floor and are `Pending` window by window until they
/// find it; no read in between says "no spend".
#[tokio::test]
async fn a_reorg_across_windows_never_reports_no_spend_before_the_claim() {
    let (s, c) = node(Chain::new(FLOOR + 449)).await;
    let b = single(&s.uri());
    let store = Store::in_memory().unwrap();
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    {
        let mut ch = c.lock();
        ch.reorg(FLOOR + 300, 1, FLOOR + 470);
        ch.claim(7, Some(FLOOR + 465));
    }
    let mut reads = Vec::new();
    for _ in 0..6 {
        let f = read(&store, &b, FLOOR).await.unwrap();
        assert_ne!(f, Found::NoneThroughTip);
        let done = matches!(f, Found::Spend(_));
        reads.push(f);
        if done {
            break;
        }
    }
    assert_eq!(reads.len(), 3, "{reads:?}");
    assert!(matches!(&reads[2], Found::Spend(s) if s.height == Some(FLOOR + 465)));
}

/// A mark the pass does not start at is checked on the best chain first; a mark this backend
/// could not have written proves nothing. Both void it.
#[tokio::test]
async fn a_mark_off_the_start_or_malformed_is_checked_before_anything_is_read() {
    let (s, c) = node(Chain::new(FLOOR + 150)).await;
    let b = single(&s.uri());
    let good = mark(&c, FLOOR + 100);
    let other = ScanMark {
        height: FLOOR + 100,
        hash: format!("{:064x}", 7),
    };
    assert_eq!(
        b.scan_spend(&lock(), FLOOR + 50, Some(&other))
            .await
            .unwrap(),
        SpendScan::Reorged
    );
    let malformed = ScanMark {
        height: FLOOR + 100,
        hash: "not a hash".into(),
    };
    assert_eq!(
        b.scan_spend(&lock(), FLOOR + 100, Some(&malformed))
            .await
            .unwrap(),
        SpendScan::Reorged
    );
    assert_eq!(
        b.scan_spend(&lock(), FLOOR + 50, Some(&good))
            .await
            .unwrap(),
        SpendScan::NotYet {
            through: Some(mark(&c, FLOOR + 150)),
            complete: true
        }
    );
    // An upper-case mark is the same block.
    let upper = ScanMark {
        height: good.height,
        hash: good.hash.to_uppercase(),
    };
    assert!(matches!(
        b.scan_spend(&lock(), FLOOR + 100, Some(&upper))
            .await
            .unwrap(),
        SpendScan::NotYet { complete: true, .. }
    ));
}

/// The last block of a short pass replaced while the pass ran, or a block whose parent is not
/// the block before it, is inconsistent evidence: `Transient`, never a mark.
#[tokio::test]
async fn a_change_under_a_short_pass_is_transient() {
    let (s, c) = node(Chain::new(FLOOR + 449)).await;
    c.lock().swap_after = Some((FLOOR + 199, 1, block_hash(5, FLOOR + 199)));
    let b = single(&s.uri());
    assert!(matches!(
        b.scan_spend(&lock(), FLOOR, None).await,
        Err(SwapError::Transient(_))
    ));
    let (s, c) = node(Chain::new(FLOOR + 449)).await;
    c.lock().no_parent = Some(FLOOR + 120);
    assert!(matches!(
        single(&s.uri()).scan_spend(&lock(), FLOOR, None).await,
        Err(SwapError::Transient(_))
    ));
    // A resumed pass whose next block does not build on the mark.
    let (s, c) = node(Chain::new(FLOOR + 150)).await;
    let m = mark(&c, FLOOR + 100);
    c.lock()
        .blocks
        .get_mut(&block_hash(0, FLOOR + 101))
        .unwrap()
        .parent = Some(block_hash(3, FLOOR + 100));
    assert!(matches!(
        single(&s.uri())
            .scan_spend(&lock(), FLOOR + 100, Some(&m))
            .await,
        Err(SwapError::Transient(_))
    ));
}

// ---- two endpoints ------------------------------------------------------------------------

/// Two endpoints that agree advance one cursor together; a tick at the same tip then costs
/// each endpoint five calls.
#[tokio::test]
async fn two_agreeing_endpoints_advance_one_cursor() {
    let (p, pc) = node(Chain::new(FLOOR + 449)).await;
    let (f, fc) = node(Chain::new(FLOOR + 449)).await;
    let b = dual(&p.uri(), &f.uri());
    let store = Store::in_memory().unwrap();
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    reset(&pc);
    reset(&fc);
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    assert_eq!((total(&pc), total(&fc)), (5, 5));
}

/// One endpoint a block behind: the pass reaches only the lower tip on both, so the read is
/// `Pending` with the lower mark, and `NoneThroughTip` once both name the same last block.
#[tokio::test]
async fn an_endpoint_a_block_behind_keeps_the_read_pending_until_it_catches_up() {
    for primary_behind in [true, false] {
        let (a, ac) = node(Chain::new(FLOOR + 150)).await;
        let (z, zc) = node(Chain::new(FLOOR + 151)).await;
        let b = if primary_behind {
            dual(&a.uri(), &z.uri())
        } else {
            dual(&z.uri(), &a.uri())
        };
        let store = Store::in_memory().unwrap();
        assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
        assert_eq!(saved(&store).unwrap().through, mark(&ac, FLOOR + 150));
        assert_eq!(read(&store, &b, FLOOR).await.unwrap(), Found::Pending);
        ac.lock().extend(0, FLOOR + 151);
        assert_eq!(
            read(&store, &b, FLOOR).await.unwrap(),
            Found::NoneThroughTip
        );
        assert_eq!(saved(&store).unwrap().through, mark(&zc, FLOOR + 151));
    }
}

/// Endpoints on different blocks at one height, or further apart than the tip tolerance, are
/// a disagreement (held); a reorg under the mark on one endpoint voids it for both, and the
/// read from the floor then holds as well. No read says "no spend".
#[tokio::test]
async fn endpoints_on_different_branches_or_too_far_apart_hold() {
    let (p, _pc) = node(Chain::new(FLOOR + 150)).await;
    let (f, fc) = node(Chain::new(FLOOR + 150)).await;
    let b = dual(&p.uri(), &f.uri());
    let store = Store::in_memory().unwrap();
    assert_eq!(
        read(&store, &b, FLOOR).await.unwrap(),
        Found::NoneThroughTip
    );
    fc.lock().reorg(FLOOR + 140, 1, FLOOR + 150);
    let m = saved(&store).unwrap().through;
    assert_eq!(
        b.scan_spend(&lock(), m.height, Some(&m)).await.unwrap(),
        SpendScan::Reorged
    );
    assert!(is_held(&read(&store, &b, FLOOR).await));

    for (behind, held) in [(2, false), (3, true)] {
        let (p, _) = node(Chain::new(FLOOR + 150)).await;
        let (f, _) = node(Chain::new(FLOOR + 150 + behind)).await;
        let r = dual(&p.uri(), &f.uri())
            .scan_spend(&lock(), FLOOR, None)
            .await;
        assert_eq!(is_held(&r), held, "{behind} blocks apart: {r:?}");
        if !held {
            assert!(matches!(
                r,
                Ok(SpendScan::NotYet {
                    complete: false,
                    ..
                })
            ));
        }
    }
}

/// A claim one endpoint shows and the other hides is held, as before.
#[tokio::test]
async fn a_claim_one_endpoint_hides_is_held() {
    let mut chain = Chain::new(FLOOR + 150);
    chain.claim(8, Some(FLOOR + 140));
    let (p, _) = node(chain).await;
    let (f, _) = node(Chain::new(FLOOR + 150)).await;
    let store = Store::in_memory().unwrap();
    assert!(is_held(
        &read(&store, &dual(&p.uri(), &f.uri()), FLOOR).await
    ));
    assert!(is_held(
        &read(&store, &dual(&f.uri(), &p.uri()), FLOOR).await
    ));
}

/// A read held for a fallback that is down is made, past the refund deadline, on the
/// primary-only view (`hold::scan_spend`). That view resumes from the same cursor, so a
/// claim more than one window past the lock is still found, window by window.
#[tokio::test]
async fn the_primary_only_view_resumes_a_held_read_past_one_window() {
    let mut chain = Chain::new(FLOOR + 449);
    chain.claim(9, Some(FLOOR + 420));
    let (p, pc) = node(chain).await;
    let b = dual(&p.uri(), "http://127.0.0.1:1");
    let store = Store::in_memory().unwrap();
    assert!(is_held(&read(&store, &b, FLOOR).await));
    let view = b
        .primary_only()
        .expect("a fallback has a primary-only view");
    assert_eq!(
        read(&store, view.as_ref(), FLOOR).await.unwrap(),
        Found::Pending
    );
    assert_eq!(
        read(&store, view.as_ref(), FLOOR).await.unwrap(),
        Found::Pending
    );
    assert_eq!(saved(&store).unwrap().through, mark(&pc, FLOOR + 398));
    reset(&pc);
    assert_eq!(
        spent_at(read(&store, view.as_ref(), FLOOR).await),
        Some(FLOOR + 420)
    );
    assert_eq!(calls(&pc, "getblock"), 22);
}

// ---- F1: a lower mark the higher endpoint did not read ------------------------------------
//
// A lying endpoint names the real chain `H0` through 150 but leaves the taker's claim out of
// `H0_149` (or `H0_150`). The honest endpoint is briefly on a fork,
// `H0_148 -> H1_149 -> H1_150 -> H1_151`, which has no claim. The marks are one block apart.
// Joined at the liar's `(150, H0_150)`, the mark would vouch for blocks the honest endpoint
// never read: once it moves back to `H0`, its block at 150 matches the mark, and no later pass
// reads `H0_149` or `H0_150` again.

/// The lock's height in the F1 cases.
const F1_FLOOR: u64 = 100;

/// The two endpoints while the honest one is on the fork: `(liar, honest)`.
fn f1_chains() -> (Chain, Chain) {
    let liar = Chain::new(150);
    let mut honest = Chain::new(148);
    honest.extend(1, 151);
    assert_eq!(honest.best[148], liar.best[148]);
    assert_ne!(honest.best[149], liar.best[149]);
    (liar, honest)
}

/// The fork resolves: the honest endpoint moves back to `H0`, now at 152, with the claim in
/// the block at `claim_at`. The liar follows `H0` to 152 and still leaves the claim out.
fn f1_resolve(
    liar: &Arc<Mutex<Chain>>,
    honest: &Arc<Mutex<Chain>>,
    claim_at: u64,
    preimage: &[u8; 32],
) {
    let mut h = honest.lock();
    h.reorg(149, 0, 152);
    h.claim_revealing(7, claim_at, preimage);
    liar.lock().extend(0, 152);
    assert_eq!(h.best, liar.lock().best);
}

fn revealed(f: Result<Found, SwapError>, hash: &[u8; 32]) -> (Option<u64>, Option<[u8; 32]>) {
    match f.unwrap() {
        Found::Spend(s) => (s.height, s.extract_preimage(hash)),
        other => panic!("expected a spend, got {other:?}"),
    }
}

/// F1, the first pass: the liar's mark is one block below the honest one, but the honest pass
/// read another block at 150. That is held, whichever endpoint is the fallback, and no
/// cursor is saved.
#[tokio::test]
async fn a_lower_mark_on_another_branch_is_held_and_saves_no_cursor() {
    for liar_is_primary in [true, false] {
        let (liar, honest) = f1_chains();
        let (l, _) = node(liar).await;
        let (h, _) = node(honest).await;
        let b = if liar_is_primary {
            dual(&l.uri(), &h.uri())
        } else {
            dual(&h.uri(), &l.uri())
        };
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("swaps.db")).unwrap();
        let r = b.scan_spend(&lock(), F1_FLOOR, None).await;
        assert!(is_held(&r), "liar primary {liar_is_primary}: {r:?}");
        let r = read(&store, &b, F1_FLOOR).await;
        assert!(is_held(&r), "liar primary {liar_is_primary}: {r:?}");
        assert_eq!(saved(&store), None, "liar primary {liar_is_primary}");
    }
}

/// F1, honest primary and lying fallback: after the fork resolves, the claim the fallback
/// hides is held until the refund deadline. Past it the primary-only view reads from the
/// floor (100, not 151: no cursor was saved) and finds the claim and its preimage.
#[tokio::test]
async fn a_lying_fallback_cannot_hide_a_claim_from_an_honest_primary_across_a_fork() {
    for claim_at in [149, 150] {
        let (pre, hash) = divi_swap::htlc::new_preimage();
        let (liar, honest) = f1_chains();
        let (l, lc) = node(liar).await;
        let (h, hc) = node(honest).await;
        let b = dual(&h.uri(), &l.uri());
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("swaps.db")).unwrap();
        assert!(is_held(&read(&store, &b, F1_FLOOR).await));
        assert_eq!(saved(&store), None);

        f1_resolve(&lc, &hc, claim_at, &pre);
        let r = read(&store, &b, F1_FLOOR).await;
        assert!(
            is_held(&r),
            "claim at {claim_at}, before the deadline: {r:?}"
        );
        assert_eq!(saved(&store), None);

        reset(&hc);
        assert_eq!(
            revealed(read_via(&store, &b, F1_FLOOR, true).await, &hash),
            (Some(claim_at), Some(pre)),
            "claim at {claim_at}"
        );
        // The held pass and then the primary-only pass each read the primary from the floor
        // up to the claim.
        assert_eq!(
            calls(&hc, "getblock"),
            2 * (claim_at - F1_FLOOR + 1),
            "claim at {claim_at}"
        );
        assert_eq!(saved(&store), None);
    }
}

/// F1, either order: once the fork resolves and the lying endpoint answers truthfully again
/// (a proxy glitch that clears), the dual-source read starts from the floor, both endpoints
/// see the claim, and it is found with its preimage.
#[tokio::test]
async fn once_the_glitch_clears_the_dual_read_from_the_floor_finds_the_claim() {
    for liar_is_primary in [true, false] {
        for claim_at in [149, 150] {
            let (pre, hash) = divi_swap::htlc::new_preimage();
            let (liar, honest) = f1_chains();
            let (l, lc) = node(liar).await;
            let (h, hc) = node(honest).await;
            let b = if liar_is_primary {
                dual(&l.uri(), &h.uri())
            } else {
                dual(&h.uri(), &l.uri())
            };
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(&dir.path().join("swaps.db")).unwrap();
            assert!(is_held(&read(&store, &b, F1_FLOOR).await));
            assert_eq!(saved(&store), None);

            f1_resolve(&lc, &hc, claim_at, &pre);
            lc.lock().claim_revealing(7, claim_at, &pre);
            reset(&lc);
            reset(&hc);
            assert_eq!(
                revealed(read(&store, &b, F1_FLOOR).await, &hash),
                (Some(claim_at), Some(pre)),
                "liar primary {liar_is_primary}, claim at {claim_at}"
            );
            for c in [&lc, &hc] {
                assert_eq!(calls(c, "getblock"), claim_at - F1_FLOOR + 1);
            }
        }
    }
}

// ---- median time past ---------------------------------------------------------------------

/// The cached read equals the eleven-block median on chains shorter and longer than eleven
/// blocks, and a second read at the same tip is one call.
#[tokio::test]
async fn the_cached_median_time_past_is_the_eleven_block_median() {
    for tip in [0, 1, 4, 9, 10, 11, 40] {
        let (s, c) = node(Chain::new(tip)).await;
        let b = single(&s.uri());
        let want = c.lock().median_time_past();
        assert_eq!(b.median_time_past().await.unwrap(), want, "tip {tip}");
        assert_eq!(calls(&c, "getbestblockhash"), 1);
        assert_eq!(calls(&c, "getblock"), (tip + 1).min(11));
        assert_eq!(calls(&c, "getblockcount") + calls(&c, "getblockhash"), 0);
        reset(&c);
        assert_eq!(b.median_time_past().await.unwrap(), want);
        assert_eq!(
            total(&c),
            1,
            "tip {tip}: a second read at the same tip is one call"
        );
    }
}

/// A new block, and a different block at the same height after a reorg, are read afresh.
#[tokio::test]
async fn a_new_tip_or_a_reorg_at_the_same_height_reads_the_median_again() {
    let (s, c) = node(Chain::new(100)).await;
    let b = single(&s.uri());
    let first = b.median_time_past().await.unwrap();
    c.lock().extend(0, 101);
    reset(&c);
    let next = b.median_time_past().await.unwrap();
    assert_eq!(next, c.lock().median_time_past());
    assert_ne!(next, first);
    assert_eq!(total(&c), 12);
    c.lock().reorg(101, 1, 101);
    reset(&c);
    let reorged = b.median_time_past().await.unwrap();
    assert_eq!(reorged, c.lock().median_time_past());
    assert_ne!(
        reorged, next,
        "the branch's tip is earlier: the median moved"
    );
    assert_eq!(total(&c), 12);
}

/// An error (a block still indexing) is never kept; nor is an answer whose blocks did not
/// prove themselves (a block other than the one asked for, a walk cut short above genesis).
/// Those answers are what the uncached read gave, read again next time.
#[tokio::test]
async fn errors_and_unproven_answers_are_not_kept() {
    let (s, c) = node(Chain::new(100)).await;
    let b = single(&s.uri());
    let want = c.lock().median_time_past();
    c.lock().no_time = Some(97);
    assert!(matches!(
        b.median_time_past().await,
        Err(SwapError::Transient(_))
    ));
    c.lock().no_time = None;
    reset(&c);
    assert_eq!(b.median_time_past().await.unwrap(), want);
    assert_eq!(total(&c), 12, "the error was not kept");

    for lie in [0, 1] {
        let (s, c) = node(Chain::new(100)).await;
        let b = single(&s.uri());
        if lie == 0 {
            c.lock().wrong_hash = true;
        } else {
            c.lock().no_parent = Some(95);
        }
        let got = b.median_time_past().await.unwrap();
        if lie == 0 {
            assert_eq!(got, want);
        }
        reset(&c);
        assert_eq!(b.median_time_past().await.unwrap(), got);
        assert!(total(&c) > 1, "an unproven answer was kept");
        {
            let mut ch = c.lock();
            ch.wrong_hash = false;
            ch.no_parent = None;
        }
        assert_eq!(b.median_time_past().await.unwrap(), want);
        reset(&c);
        assert_eq!(b.median_time_past().await.unwrap(), want);
        assert_eq!(total(&c), 1);
    }
}

/// With a fallback, each endpoint keeps its own answer: an unchanged tip is two calls, not
/// twenty-four; the primary-only view and clones of the client share the primary's.
#[tokio::test]
async fn two_endpoints_and_clones_keep_the_median_per_endpoint() {
    let (p, pc) = node(Chain::new(100)).await;
    let (f, fc) = node(Chain::new(100)).await;
    let b = dual(&p.uri(), &f.uri());
    let want = pc.lock().median_time_past();
    assert_eq!(b.median_time_past().await.unwrap(), want);
    assert_eq!((total(&pc), total(&fc)), (12, 12));
    reset(&pc);
    reset(&fc);
    assert_eq!(b.median_time_past().await.unwrap(), want);
    assert_eq!((total(&pc), total(&fc)), (1, 1));
    let view = b.primary_only().unwrap();
    reset(&pc);
    assert_eq!(view.median_time_past().await.unwrap(), want);
    assert_eq!((total(&pc), total(&fc)), (1, 1));

    let rpc = RpcClient::new(&p.uri(), retry());
    let clone = rpc.clone();
    assert_eq!(rpc.median_time_past().await.unwrap(), want);
    reset(&pc);
    assert_eq!(clone.median_time_past().await.unwrap(), want);
    assert_eq!(total(&pc), 1);
}
