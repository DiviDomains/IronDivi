// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The shared mempool index against the per-call scan it replaced: the same
//! results and errors for every script and pool state, a pool transaction
//! read once per state, and no stale index under churn.

use super::*;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use divi_primitives::{Amount, Block, Script, TxIn, TxOut};
use divi_rpc::blockchain::MempoolTxInfo;
use divi_storage::search_index::{collect_connect, PrevOut};
use divi_storage::{ChainDatabase, ChainParams, SearchIndex};

/// The scan `mempool_view` ran before the index, with the output limit as a
/// parameter: the reference the index must match
pub(super) fn reference_view(
    mempool: &dyn MempoolProvider,
    sh: &[u8; 32],
    confirmed: &[Unspent],
    max_outputs: usize,
    history_limit: usize,
) -> Result<MempoolView> {
    let infos = mempool.get_tx_infos();
    let mut txs: Vec<(Hash256, i64, bool, Transaction)> = Vec::new();
    for info in infos {
        if let Some(tx) = mempool.get_transaction(&info.txid) {
            txs.push((info.txid, info.fee_sat, !info.depends.is_empty(), tx));
        }
    }
    let mut values: HashMap<OutPoint, i64> = confirmed
        .iter()
        .map(|u| (OutPoint::new(u.txid, u.vout), u.value))
        .collect();
    let mut outputs = Vec::new();
    let mut paying: HashSet<Hash256> = HashSet::new();
    for (txid, _, depends, tx) in &txs {
        for (k, out) in tx.vout.iter().enumerate() {
            if script_hash(out.script_pubkey.as_bytes()) == *sh {
                if outputs.len() == max_outputs {
                    return Err(ElectrumError::bad_request("too many unspent outputs"));
                }
                let outpoint = OutPoint::new(*txid, k as u32);
                let value = out.value.as_sat();
                values.insert(outpoint, value);
                outputs.push((outpoint, value, if *depends { -1 } else { 0 }));
                paying.insert(*txid);
            }
        }
    }
    let mut spent = HashSet::new();
    let mut history = Vec::new();
    for (txid, fee, depends, tx) in &txs {
        let mut relevant = paying.contains(txid);
        for input in &tx.vin {
            if values.contains_key(&input.prevout) {
                spent.insert(input.prevout);
                relevant = true;
            }
        }
        if relevant {
            if history.len() == history_limit {
                return Err(ElectrumError::bad_request("history too large"));
            }
            history.push(HistoryEntry {
                txid: *txid,
                height: if *depends { -1 } else { 0 },
                fee: Some(*fee),
            });
        }
    }
    history.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| a.txid.to_hex().cmp(&b.txid.to_hex()))
    });
    Ok(MempoolView {
        history,
        outputs,
        spent,
    })
}

struct Listed {
    tx: Transaction,
    fee: i64,
    /// Overrides the computed dependency flag
    depends: Option<bool>,
}

#[derive(Default)]
struct PoolState {
    /// Txids in listing order
    order: Vec<Hash256>,
    txs: HashMap<Hash256, Listed>,
    /// Listed, but `get_transaction` no longer finds them
    hidden: HashSet<Hash256>,
}

/// A mempool that counts its reads and can be changed in every way the
/// index must notice
#[derive(Default)]
pub(crate) struct TestPool {
    state: Mutex<PoolState>,
    pub(crate) fetches: AtomicUsize,
}

impl TestPool {
    fn state(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap()
    }

    pub(crate) fn add(&self, tx: Transaction, fee: i64) -> Hash256 {
        self.add_as(tx, fee, false)
    }

    /// Adds `tx`, possibly already gone for reads, under one lock
    fn add_as(&self, tx: Transaction, fee: i64, hidden: bool) -> Hash256 {
        let txid = tx.txid();
        let mut state = self.state();
        if hidden {
            state.hidden.insert(txid);
        }
        let listed = Listed {
            tx,
            fee,
            depends: None,
        };
        assert!(state.txs.insert(txid, listed).is_none());
        state.order.push(txid);
        txid
    }

    pub(crate) fn remove(&self, txid: &Hash256) -> Option<Transaction> {
        let mut state = self.state();
        let listed = state.txs.remove(txid)?;
        state.order.retain(|t| t != txid);
        Some(listed.tx)
    }

    pub(crate) fn set_fee(&self, txid: &Hash256, fee: i64) {
        if let Some(listed) = self.state().txs.get_mut(txid) {
            listed.fee = fee;
        }
    }

    pub(crate) fn force_depends(&self, txid: &Hash256, depends: Option<bool>) {
        if let Some(listed) = self.state().txs.get_mut(txid) {
            listed.depends = depends;
        }
    }

    pub(crate) fn hide(&self, txid: &Hash256, hidden: bool) {
        let mut state = self.state();
        if hidden {
            state.hidden.insert(*txid);
        } else {
            state.hidden.remove(txid);
        }
    }

    pub(crate) fn rotate(&self, n: usize) {
        let mut state = self.state();
        let len = state.order.len();
        if len > 0 {
            state.order.rotate_left(n % len);
        }
    }

    fn txids(&self) -> Vec<Hash256> {
        self.state().order.clone()
    }

    fn len(&self) -> usize {
        self.state().order.len()
    }

    fn hidden(&self) -> Vec<Hash256> {
        self.state().hidden.iter().copied().collect()
    }
}

impl MempoolProvider for TestPool {
    fn get_txids(&self) -> Vec<Hash256> {
        self.txids()
    }

    fn get_tx_infos(&self) -> Vec<MempoolTxInfo> {
        let state = self.state();
        state
            .order
            .iter()
            .map(|txid| {
                let l = &state.txs[txid];
                // in-pool parents, as divi-node lists them
                let mut depends: Vec<Hash256> =
                    l.tx.vin
                        .iter()
                        .map(|i| i.prevout.txid)
                        .filter(|p| state.txs.contains_key(p))
                        .collect();
                depends.sort();
                depends.dedup();
                match l.depends {
                    Some(true) if depends.is_empty() => depends.push(Hash256::zero()),
                    Some(false) => depends.clear(),
                    _ => {}
                }
                MempoolTxInfo {
                    txid: *txid,
                    size: 0,
                    fee_sat: l.fee,
                    time: 0,
                    depends,
                    height: 0,
                    starting_priority: 0.0,
                    current_priority: 0.0,
                }
            })
            .collect()
    }

    fn get_transaction(&self, txid: &Hash256) -> Option<Transaction> {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let state = self.state();
        if state.hidden.contains(txid) {
            return None;
        }
        state.txs.get(txid).map(|l| l.tx.clone())
    }

    fn prioritise_transaction(&self, _: &Hash256, _: f64, _: i64) -> bool {
        false
    }
}

pub(crate) fn script(n: u32) -> Script {
    let mut hash = [0x5a; 20];
    hash[..4].copy_from_slice(&n.to_le_bytes());
    Script::new_p2pkh(&hash)
}

pub(crate) fn sh(n: u32) -> [u8; 32] {
    script_hash(script(n).as_bytes())
}

static SALT: AtomicU32 = AtomicU32::new(1);

/// A transaction spending `inputs` and paying `(script, value)` outputs,
/// with a txid of its own
pub(crate) fn tx(inputs: &[OutPoint], outputs: &[(u32, i64)]) -> Transaction {
    Transaction {
        version: 1,
        vin: inputs
            .iter()
            .map(|o| TxIn::new(*o, Script::new(), u32::MAX))
            .collect(),
        vout: outputs
            .iter()
            .map(|&(n, value)| TxOut::new(Amount::from_sat(value), script(n)))
            .collect(),
        lock_time: SALT.fetch_add(1, Ordering::Relaxed),
    }
}

/// A chain with the address index on, its mempool, and two backends over
/// them: the one under test and one answering from the reference scan
pub(crate) struct Fixture {
    _dir: tempfile::TempDir,
    index: Arc<SearchIndex>,
    pub(crate) pool: Arc<TestPool>,
    pub(crate) backend: Arc<Backend>,
    pub(crate) reference: Backend,
    /// Every output made so far, for confirming spends of it
    outputs: Mutex<HashMap<OutPoint, PrevOut>>,
}

pub(crate) fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path()).unwrap());
    let mut chain = Chain::new(db.clone(), ChainParams::default()).unwrap();
    let index = Arc::new(SearchIndex::new(db, true, false));
    chain.enable_search_index(index.clone());
    let chain = Arc::new(chain);
    let rpc = Arc::new(RpcServer::new(chain.clone()));
    let pool = Arc::new(TestPool::default());
    let backend = Arc::new(Backend::new(chain.clone(), pool.clone(), rpc.clone()));
    let mut reference = Backend::new(chain, pool.clone(), rpc);
    reference.reference = true;
    Fixture {
        _dir: dir,
        index,
        pool,
        backend,
        reference,
        outputs: Mutex::default(),
    }
}

impl Fixture {
    fn record(&self, tx: &Transaction) {
        let txid = tx.txid();
        let mut outputs = self.outputs.lock().unwrap();
        for (k, out) in tx.vout.iter().enumerate() {
            outputs.insert(
                OutPoint::new(txid, k as u32),
                (out.value, out.script_pubkey.clone()),
            );
        }
    }

    /// Puts `tx` in the mempool
    pub(crate) fn add(&self, tx: Transaction, fee: i64) -> Hash256 {
        self.record(&tx);
        self.pool.add(tx, fee)
    }

    /// Lists `tx` in the mempool, but gone by the time it is read
    fn add_hidden(&self, tx: Transaction, fee: i64) -> Hash256 {
        self.record(&tx);
        self.pool.add_as(tx, fee, true)
    }

    /// Writes `txs` to the address index as the block at `height`
    pub(crate) fn confirm(&self, height: u32, txs: Vec<Transaction>) {
        for tx in &txs {
            self.record(tx);
        }
        let mut block = Block::new();
        block.transactions = txs;
        let prevouts = self.outputs.lock().unwrap().clone();
        let updates = collect_connect(&block, height, &prevouts, true, false);
        self.index.apply_connect(&updates).unwrap();
    }

    /// Moves pool transaction `txid` into the block at `height`
    pub(crate) fn mine(&self, height: u32, txid: &Hash256) {
        let tx = self.pool.remove(txid).expect("in the pool");
        self.confirm(height, vec![tx]);
    }

    /// Every query answers the same from the index and from the scan
    pub(crate) fn assert_parity(&self, scripts: &[[u8; 32]]) {
        let (a, b) = (&*self.backend, &self.reference);
        for s in scripts {
            assert_eq!(a.history(s), b.history(s), "history");
            assert_eq!(a.mempool_history(s), b.mempool_history(s), "mempool");
            assert_eq!(a.status(s), b.status(s), "status");
            assert_eq!(a.balance(s), b.balance(s), "balance");
            assert_eq!(a.listunspent(s), b.listunspent(s), "listunspent");
        }
    }
}

/// xorshift64*: reproducible without a dependency
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

const SCRIPTS: u32 = 6;

fn scripts() -> Vec<[u8; 32]> {
    // and one that nothing pays
    (0..=SCRIPTS).map(sh).collect()
}

/// One random change to the pool or chain: a new transaction (possibly
/// spending pool, confirmed, unknown or the same outputs twice), a removal,
/// a confirmation, a fee or dependency change, a reorder, or a new
/// transaction that is listed but gone by the time it is read, until it is
/// readable again
fn churn(f: &Fixture, rng: &mut Rng, known: &mut Vec<OutPoint>, height: &mut u32) {
    let txids = f.pool.txids();
    match rng.below(10) {
        0..=3 => {
            let mut inputs = Vec::new();
            for _ in 0..1 + rng.below(3) {
                if !known.is_empty() && rng.chance(85) {
                    inputs.push(known[rng.below(known.len())]);
                } else {
                    inputs.push(OutPoint::new(
                        Hash256::from_bytes([0xee; 32]),
                        rng.below(9) as u32,
                    ));
                }
            }
            if rng.chance(10) {
                inputs.push(inputs[0]);
            }
            let outputs: Vec<(u32, i64)> = (0..1 + rng.below(3))
                .map(|_| {
                    (
                        rng.below(SCRIPTS as usize) as u32,
                        1 + rng.below(1_000_000) as i64,
                    )
                })
                .collect();
            let t = tx(&inputs, &outputs);
            let txid = t.txid();
            known.extend((0..outputs.len() as u32).map(|k| OutPoint::new(txid, k)));
            f.add(t, rng.below(5_000) as i64);
            // the spender sometimes listed before its parent
            if rng.chance(20) {
                f.pool.rotate(f.pool.len() - 1);
            }
        }
        _ if txids.is_empty() => {}
        4 => {
            f.pool.remove(&txids[rng.below(txids.len())]);
        }
        5 => {
            *height += 1;
            f.mine(*height, &txids[rng.below(txids.len())]);
        }
        6 => f
            .pool
            .set_fee(&txids[rng.below(txids.len())], rng.below(5_000) as i64),
        7 => {
            let depends = [None, Some(true), Some(false)][rng.below(3)];
            f.pool
                .force_depends(&txids[rng.below(txids.len())], depends);
        }
        8 => f.pool.rotate(1 + rng.below(txids.len())),
        _ => match f.pool.hidden().first() {
            Some(txid) => f.pool.hide(txid, false),
            None => {
                let input = known[rng.below(known.len())];
                let t = tx(&[input], &[(rng.below(SCRIPTS as usize) as u32, 5)]);
                known.push(OutPoint::new(t.txid(), 0));
                f.add_hidden(t, 3);
            }
        },
    }
}

fn funded(f: &Fixture, rng: &mut Rng) -> Vec<OutPoint> {
    let mut known = Vec::new();
    for height in 1..=4 {
        let outputs: Vec<(u32, i64)> = (0..4)
            .map(|_| {
                (
                    rng.below(SCRIPTS as usize) as u32,
                    1 + rng.below(1_000_000) as i64,
                )
            })
            .collect();
        let t = tx(&[], &outputs);
        let txid = t.txid();
        known.extend((0..4).map(|k| OutPoint::new(txid, k)));
        f.confirm(height, vec![t]);
    }
    known
}

#[test]
fn the_index_answers_as_the_scan_over_random_churn() {
    let f = fixture();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut known = funded(&f, &mut rng);
    let mut height = 4;
    let scripts = scripts();
    for _ in 0..400 {
        churn(&f, &mut rng, &mut known, &mut height);
        f.assert_parity(&scripts);
    }
}

#[test]
fn small_limits_fail_alike() {
    let f = fixture();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut known = funded(&f, &mut rng);
    let mut height = 4;
    for _ in 0..150 {
        churn(&f, &mut rng, &mut known, &mut height);
        let listed: Vec<PoolEntry> = f
            .pool
            .get_tx_infos()
            .into_iter()
            .map(|i| (i.txid, i.fee_sat, !i.depends.is_empty()))
            .collect();
        let index = MempoolIndex::build(listed, None, |t| f.pool.get_transaction(t));
        // confirmed outputs as a caller passes them, some spent in the pool
        let confirmed: Vec<Unspent> = known
            .iter()
            .filter(|_| rng.chance(30))
            .map(|o| Unspent {
                txid: o.txid,
                vout: o.vout,
                height: 1,
                value: 7,
            })
            .collect();
        for s in scripts() {
            for max_outputs in 0..4 {
                for history_limit in 0..5 {
                    assert_eq!(
                        index.view(&s, &confirmed, max_outputs, history_limit),
                        reference_view(&*f.pool, &s, &confirmed, max_outputs, history_limit),
                        "max_outputs={max_outputs} history_limit={history_limit}"
                    );
                }
            }
        }
    }
}

#[test]
fn limits_fail_alike_at_the_real_maximum() {
    let f = fixture();
    let (a, b) = (sh(1), sh(2));
    let over = f.add(tx(&[], &vec![(1, 1); MAX_HISTORY_ENTRIES + 1]), 1);
    assert_eq!(
        f.backend.listunspent(&a),
        Err(ElectrumError::bad_request("too many unspent outputs"))
    );
    f.assert_parity(&[a]);
    f.pool.remove(&over);
    // exactly the limit of outputs, then one pool transaction too many
    let full = f.add(tx(&[], &vec![(1, 1); MAX_HISTORY_ENTRIES]), 1);
    assert_eq!(
        f.backend.listunspent(&a).unwrap().len(),
        MAX_HISTORY_ENTRIES
    );
    f.assert_parity(&[a]);
    let mut last = Hash256::zero();
    for k in 0..MAX_HISTORY_ENTRIES as u32 {
        last = f.add(tx(&[OutPoint::new(full, k)], &[(2, 1)]), 1);
    }
    assert_eq!(
        f.backend.mempool_history(&a),
        Err(ElectrumError::bad_request("history too large"))
    );
    f.assert_parity(&[a, b]);
    f.pool.remove(&last);
    assert_eq!(
        f.backend.mempool_history(&a).unwrap().len(),
        MAX_HISTORY_ENTRIES
    );
    f.assert_parity(&[a, b]);
    // one confirmed transaction leaves room for one fewer
    f.confirm(1, vec![tx(&[], &[(1, 5)])]);
    assert_eq!(
        f.backend.history(&a),
        Err(ElectrumError::bad_request("history too large"))
    );
    assert_eq!(
        f.backend.mempool_history(&a).unwrap().len(),
        MAX_HISTORY_ENTRIES
    );
    f.assert_parity(&[a]);
}

/// The fingerprint as the base computed it: the tip and the sorted txids
fn txid_fingerprint(f: &Fixture) -> [u8; 32] {
    let mut txids = f.pool.get_txids();
    txids.sort();
    let mut data = Vec::new();
    for txid in txids {
        data.extend_from_slice(txid.as_bytes());
    }
    sha256(&data)
}

#[test]
fn a_parent_confirming_under_its_child_moves_the_child_to_height_0() {
    let f = fixture();
    let funding = tx(&[], &[(1, 50_000)]);
    let funding_id = funding.txid();
    f.confirm(5, vec![funding]);
    let parent = f.add(tx(&[OutPoint::new(funding_id, 0)], &[(2, 40_000)]), 100);
    let child = f.add(tx(&[OutPoint::new(parent, 0)], &[(3, 30_000)]), 200);
    let scripts = [sh(1), sh(2), sh(3)];
    let unconfirmed = [HistoryEntry {
        txid: child,
        height: -1,
        fee: Some(200),
    }];
    assert_eq!(f.backend.history(&sh(3)).unwrap(), unconfirmed);
    f.assert_parity(&scripts);
    let (fingerprint, status) = (f.backend.fingerprint(), f.backend.status(&sh(3)));

    f.mine(6, &parent);
    let confirmed = [HistoryEntry {
        txid: child,
        height: 0,
        fee: Some(200),
    }];
    assert_eq!(f.backend.history(&sh(3)).unwrap(), confirmed);
    assert_ne!(f.backend.status(&sh(3)), status);
    assert_ne!(f.backend.fingerprint(), fingerprint);
    // the parent's script: confirmed at 6, spent by the child in the pool
    assert_eq!(f.backend.balance(&sh(2)).unwrap(), (40_000, -40_000));
    assert!(f.backend.listunspent(&sh(2)).unwrap().is_empty());
    f.assert_parity(&scripts);
}

#[test]
fn a_dependency_or_fee_change_alone_changes_the_fingerprint() {
    let f = fixture();
    let parent = f.add(tx(&[], &[(1, 9)]), 1);
    let child = f.add(tx(&[OutPoint::new(parent, 0)], &[(2, 8)]), 1);
    let before = (f.backend.fingerprint(), txid_fingerprint(&f));
    let status = f.backend.status(&sh(2)).unwrap();
    // same txids, same tip: only the child's dependency changes
    f.pool.force_depends(&child, Some(false));
    assert_eq!(txid_fingerprint(&f), before.1, "txids alone miss it");
    assert_ne!(f.backend.fingerprint(), before.0);
    assert_ne!(f.backend.status(&sh(2)).unwrap(), status);
    f.assert_parity(&[sh(1), sh(2)]);
    // a fee change shows in get_mempool, so it changes the fingerprint too
    let fingerprint = f.backend.fingerprint();
    f.pool.set_fee(&child, 77);
    assert_ne!(f.backend.fingerprint(), fingerprint);
    assert_eq!(f.backend.mempool_history(&sh(2)).unwrap()[0].fee, Some(77));
    f.assert_parity(&[sh(1), sh(2)]);
}

#[test]
fn a_transaction_gone_while_indexing_is_read_again() {
    let f = fixture();
    let a = f.add(tx(&[], &[(1, 5)]), 1);
    f.add(tx(&[], &[(2, 5)]), 1);
    f.pool.hide(&a, true);
    assert!(f.backend.history(&sh(1)).unwrap().is_empty());
    f.assert_parity(&[sh(1), sh(2)]);
    f.pool.hide(&a, false);
    assert_eq!(f.backend.history(&sh(1)).unwrap().len(), 1);
    f.assert_parity(&[sh(1), sh(2)]);
}

/// The one difference from the scan, and only in a race: a transaction
/// leaving the pool between the listing and the read. The scan's read
/// misses it; the index, having read it before, answers as the listing
/// stood. The next listing no longer has it.
#[test]
fn an_indexed_transaction_answers_as_listed() {
    let f = fixture();
    let a = f.add(tx(&[], &[(1, 5)]), 1);
    assert_eq!(f.backend.history(&sh(1)).unwrap().len(), 1);
    f.pool.hide(&a, true);
    assert_eq!(f.backend.history(&sh(1)).unwrap().len(), 1);
    assert!(f.reference.history(&sh(1)).unwrap().is_empty());
    f.pool.remove(&a);
    assert!(f.backend.history(&sh(1)).unwrap().is_empty());
    f.assert_parity(&[sh(1)]);
}

#[test]
fn listunspent_follows_the_listing_order() {
    let f = fixture();
    for value in 1..=5 {
        f.add(tx(&[], &[(1, value)]), 1);
    }
    let first = f.backend.listunspent(&sh(1)).unwrap();
    f.pool.rotate(2);
    let fetches = f.pool.fetches.load(Ordering::Relaxed);
    let second = f.backend.listunspent(&sh(1)).unwrap();
    assert_ne!(first, second);
    assert_eq!(f.pool.fetches.load(Ordering::Relaxed), fetches, "reused");
    f.assert_parity(&[sh(1)]);
}

#[test]
fn one_pool_state_reads_each_transaction_once() {
    let f = fixture();
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let mut outputs: Vec<OutPoint> = Vec::new();
    let mut txids = Vec::new();
    for _ in 0..500 {
        let mut inputs = vec![OutPoint::new(
            Hash256::from_bytes([0xcc; 32]),
            rng.below(1000) as u32,
        )];
        if !outputs.is_empty() && rng.chance(50) {
            inputs.push(outputs[rng.below(outputs.len())]);
        }
        let pays: Vec<(u32, i64)> = (0..2 + rng.below(2))
            .map(|_| (rng.below(600) as u32, 1_000))
            .collect();
        let t = tx(&inputs, &pays);
        let txid = t.txid();
        outputs.extend((0..pays.len() as u32).map(|k| OutPoint::new(txid, k)));
        txids.push(f.add(t, 10));
    }
    let fetches = || f.pool.fetches.load(Ordering::Relaxed);
    // a notification pass over 1,000 scripts, about half of them paid
    f.backend.fingerprint();
    for n in 0..1_000 {
        f.backend.status(&sh(n)).unwrap();
    }
    assert_eq!(fetches(), 500);
    for n in 0..1_000 {
        match n % 3 {
            0 => _ = f.backend.balance(&sh(n)).unwrap(),
            1 => _ = f.backend.listunspent(&sh(n)).unwrap(),
            _ => _ = f.backend.history(&sh(n)).unwrap(),
        }
    }
    assert_eq!(fetches(), 500);
    // the scan read the whole pool for every call
    f.reference.status(&sh(0)).unwrap();
    assert_eq!(fetches(), 1_000);
    // a new transaction is the only one read
    f.add(tx(&[outputs[0]], &[(1, 5)]), 10);
    f.backend.status(&sh(1)).unwrap();
    assert_eq!(fetches(), 1_001);
    // a parent leaving flips its children's heights without a read
    f.mine(1, &txids[0]);
    f.backend.status(&sh(1)).unwrap();
    assert_eq!(fetches(), 1_001);
    let scripts: Vec<[u8; 32]> = (0..40).map(sh).collect();
    f.assert_parity(&scripts);
}

/// Runs `f` on its own thread, failing if it takes longer than `limit`
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, wait) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _ = done.send(f());
    });
    match wait.recv_timeout(limit) {
        Ok(value) => {
            thread.join().unwrap();
            value
        }
        // the thread panicked: join to pass the panic on
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(thread.join().unwrap_err())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("deadlock: not done within {limit:?}")
        }
    }
}

#[test]
fn concurrent_queries_during_churn_neither_deadlock_nor_go_stale() {
    let f = Arc::new(fixture());
    let mut rng = Rng(0x0bad_cafe_0bad_cafe);
    let mut known = funded(&f, &mut rng);
    let mut height = 4;
    for _ in 0..60 {
        churn(&f, &mut rng, &mut known, &mut height);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let readers: Vec<_> = (0..6)
        .map(|i| {
            let (f, stop, calls) = (f.clone(), stop.clone(), calls.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for s in scripts() {
                        let b = &f.backend;
                        match i % 3 {
                            0 => _ = b.status(&s).unwrap(),
                            1 => _ = b.listunspent(&s).unwrap(),
                            _ => _ = (b.balance(&s).unwrap(), b.fingerprint()),
                        }
                        b.history(&s).unwrap();
                        calls.fetch_add(2, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    let churned = f.clone();
    within(Duration::from_secs(300), move || {
        let scripts = scripts();
        for _ in 0..300 {
            churn(&churned, &mut rng, &mut known, &mut height);
            // only this thread changes the pool, so its view is exact even
            // while the readers rebuild and share the index
            churned.assert_parity(&scripts);
        }
    });
    stop.store(true, Ordering::Relaxed);
    within(Duration::from_secs(60), move || {
        for reader in readers {
            reader.join().unwrap();
        }
    });
    assert!(calls.load(Ordering::Relaxed) > 0);
    f.assert_parity(&scripts());
}
