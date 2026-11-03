// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The `chain-events.log` records the library crates report (diag plan
//! A12): invalid blocks, refused relayed transactions that are not the
//! wallet's, bans, and from the tip listener a tip record every 100 blocks
//! and one per reorg.
//!
//! Every hash here is public chain data and printed with the public types
//! (`blk:` in clear, a peer as a per-run pseudonym), whoever staked the
//! block. Each kind is capped at [`CAP`] records per ten minutes, so a peer
//! that sends a stream of bad data cannot turn it into a stream of synced
//! writes; what the cap held back is counted in a `suppressed` record.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use divi_primitives::diag_events::{self, Event};
use divi_primitives::redact::{BlockHash, PeerAddr};
use divi_primitives::{Block, Hash256, Transaction};
use divi_storage::Chain;

/// The window the caps and the ban storm are counted over
const WINDOW_S: f64 = 600.0;
/// Records of one kind per window
const CAP: u32 = 60;
/// Bans in a window above which it is a ban storm
const STORM: usize = 10;
/// A tip record every this many blocks, and while the chain is in initial
/// block download (each record is a synced write on the block path)
const TIP_EVERY: u32 = 100;
const TIP_EVERY_IBD: u32 = 10_000;
/// Blocks walked back, both branches together, to find a reorg's fork
const MAX_WALK: u32 = 2000;

/// Whether a transaction is the wallet's own (known to it, paying it, or
/// spending its outputs)
pub type WalletCheck = Box<dyn Fn(&Hash256, &Transaction) -> bool + Send + Sync>;

static WALLET: OnceLock<WalletCheck> = OnceLock::new();
static STATE: Mutex<State> = Mutex::new(State::new());

/// The node's sink: installed before the node starts, so a bad block in
/// the first sync is recorded
pub fn install() {
    diag_events::install(Box::new(|e| handle(e, now())));
}

/// Refused transactions are recorded only once this is set: before it,
/// one of them might be the wallet's. A node without a wallet sets one
/// that says no.
pub fn set_wallet_check(check: WalletCheck) {
    let _ = WALLET.set(check);
}

fn now() -> f64 {
    crate::runs_log::since_launch().as_secs_f64()
}

/// A record cap over a ten-minute window
struct Window {
    start: f64,
    n: u32,
    held: u32,
}

impl Window {
    const fn new() -> Self {
        Window {
            start: f64::NEG_INFINITY,
            n: 0,
            held: 0,
        }
    }

    /// Whether one more record fits, and the records the window that just
    /// closed held back (non-zero once, when a new window opens)
    fn admit(&mut self, now: f64) -> (bool, u32) {
        let mut held = 0;
        if now - self.start >= WINDOW_S {
            held = std::mem::take(&mut self.held);
            self.start = now;
            self.n = 0;
        }
        if self.n < CAP {
            self.n += 1;
            (true, held)
        } else {
            self.held += 1;
            (false, held)
        }
    }
}

/// Over [`STORM`] bans in ten minutes; once per storm, re-armed when the
/// count falls back
struct Storm {
    bans: VecDeque<f64>,
    armed: bool,
}

impl Storm {
    const fn new() -> Self {
        Storm {
            bans: VecDeque::new(),
            armed: true,
        }
    }

    /// Count a ban; `Some(bans in the window)` when this one starts a storm
    fn ban(&mut self, now: f64) -> Option<usize> {
        while self.bans.front().is_some_and(|t| now - t >= WINDOW_S) {
            self.bans.pop_front();
        }
        // Bounded: a storm is reported, not every ban in it remembered
        if self.bans.len() <= STORM {
            self.bans.push_back(now);
        }
        if self.bans.len() <= STORM {
            self.armed = true;
            return None;
        }
        if std::mem::replace(&mut self.armed, false) {
            Some(self.bans.len())
        } else {
            None
        }
    }
}

struct State {
    invalid: Window,
    rejected: Window,
    bans: Window,
    storm: Storm,
    /// When the last invalid-block incident was written
    invalid_incident: f64,
}

impl State {
    const fn new() -> Self {
        State {
            invalid: Window::new(),
            rejected: Window::new(),
            bans: Window::new(),
            storm: Storm::new(),
            invalid_incident: f64::NEG_INFINITY,
        }
    }
}

/// What one event asks for, decided under the lock and written after it
#[derive(Debug, Default, PartialEq)]
struct Plan {
    record: Option<(&'static str, String)>,
    suppressed: Option<String>,
    incident: Option<(&'static str, String)>,
}

fn decide(state: &mut State, e: &Event<'_>, now: f64) -> Plan {
    let mut plan = Plan::default();
    let (kind, window) = match e {
        Event::InvalidBlock { .. } => ("invalid-block", &mut state.invalid),
        Event::RejectedTx { .. } => ("rejected-tx", &mut state.rejected),
        Event::Ban { .. } => ("ban", &mut state.bans),
        // A13 bundles only: no line names them
        Event::BadMessage { .. } | Event::OwnBlockRejected { .. } | Event::OwnTxRejected { .. } => {
            return plan
        }
    };
    let (fits, held) = window.admit(now);
    if held > 0 {
        plan.suppressed = Some(format!("kind={} n={}", kind, held));
    }
    let fields = match e {
        Event::InvalidBlock {
            hash,
            height,
            reason,
            peer,
            ..
        } => format!(
            "hash={} height={} peer={} reason={}",
            BlockHash(*hash),
            height.map_or("-".to_string(), |h| h.to_string()),
            peer.map_or("-".to_string(), |p| PeerAddr(p).to_string()),
            crate::runs_log::quote(reason)
        ),
        Event::RejectedTx { txid, reason, .. } => {
            format!("txid={} reason={}", txid, crate::runs_log::quote(reason))
        }
        Event::Ban { ip, reason } => format!(
            "peer={} reason={}",
            PeerAddr(*ip),
            crate::runs_log::quote(reason)
        ),
        Event::BadMessage { .. } | Event::OwnBlockRejected { .. } | Event::OwnTxRejected { .. } => {
            return plan
        }
    };
    match e {
        Event::InvalidBlock { .. } if now - state.invalid_incident >= WINDOW_S => {
            state.invalid_incident = now;
            plan.incident = Some(("invalid-block", fields.clone()));
        }
        Event::Ban { .. } => {
            if let Some(n) = state.storm.ban(now) {
                plan.incident = Some(("ban-storm", format!("bans_10m={}", n)));
            }
        }
        _ => {}
    }
    if fits {
        plan.record = Some((kind, fields));
    }
    plan
}

/// Whether a transaction is the wallet's own; yes while the check is not
/// set (it might be)
pub(crate) fn is_own(txid: &Hash256, tx: &Transaction) -> bool {
    WALLET.get().is_none_or(|own| own(txid, tx))
}

/// Whether a block is one this wallet staked: proof of stake with its
/// coinstake the wallet's (yes while the check is not set)
fn staked_here(block: &Block) -> bool {
    block.is_proof_of_stake()
        && block
            .transactions
            .get(1)
            .is_some_and(|t| is_own(&t.txid(), t))
}

fn handle(e: &Event<'_>, now: f64) {
    // A13: the bundle first, then the line (the same line whoever staked
    // or sent it; an own transaction has none)
    match e {
        Event::BadMessage { .. } | Event::OwnBlockRejected { .. } | Event::OwnTxRejected { .. } => {
            crate::replay::note(e, true);
            return;
        }
        Event::RejectedTx { txid, tx, .. } => {
            let own = is_own(txid, tx);
            crate::replay::note(e, own);
            if own {
                return;
            }
        }
        Event::InvalidBlock { block, .. } => {
            crate::replay::note(e, block.is_some_and(staked_here));
        }
        Event::Ban { .. } => {}
    }
    let plan = decide(&mut STATE.lock().unwrap_or_else(|e| e.into_inner()), e, now);
    let log = &crate::events::CHAIN_EVENTS;
    if let Some(fields) = plan.suppressed {
        log.record("suppressed", &fields);
    }
    if let Some((kind, fields)) = plan.record {
        log.record(kind, &fields);
    }
    if let Some((kind, detail)) = plan.incident {
        if let Some(n) = crate::incidents::write(kind, &detail) {
            crate::events::event("incident", &format!("n={} kind={}", n, kind));
        }
    }
}

/// How many blocks of the old branch a new tip left behind: 0 when it
/// extends the old tip, `None` when the fork is further back than
/// [`MAX_WALK`] or a block on the way is unknown. `parent` gives a block's
/// parent hash.
fn fork_depth(
    old: (u32, Hash256),
    new: (u32, Hash256),
    parent: impl Fn(&Hash256) -> Option<Hash256>,
) -> Option<u32> {
    let (mut a, mut b) = (old, new);
    for _ in 0..MAX_WALK {
        if a.1 == b.1 {
            return Some(old.0 - a.0);
        }
        if a.0 >= b.0 {
            a = (a.0.checked_sub(1)?, parent(&a.1)?);
        } else {
            b = (b.0.checked_sub(1)?, parent(&b.1)?);
        }
    }
    None
}

/// The records a tip change asks for
fn on_tip(
    last: Option<(u32, Hash256)>,
    height: u32,
    hash: Hash256,
    prev: Hash256,
    ibd: bool,
    parent: impl Fn(&Hash256) -> Option<Hash256>,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let Some(old) = last else {
        return out;
    };
    if prev != old.1 && hash != old.1 {
        let depth = fork_depth(old, (height, hash), parent);
        if depth != Some(0) {
            out.push((
                "reorg",
                format!(
                    "depth={} old={} new={} height={}",
                    depth.map_or("unknown".to_string(), |d| d.to_string()),
                    BlockHash(old.1),
                    BlockHash(hash),
                    height
                ),
            ));
        }
    }
    let every = if ibd { TIP_EVERY_IBD } else { TIP_EVERY };
    if height / every != old.0 / every {
        out.push(("tip", format!("height={} hash={}", height, BlockHash(hash))));
    }
    out
}

/// The tip and reorg records, from the chain's tip listener (which runs
/// after the chain's lock is let go)
pub fn watch_tip(chain: &Arc<Chain>) {
    let last = Mutex::new(chain.tip().map(|t| (t.height, t.hash)));
    let weak: Weak<Chain> = Arc::downgrade(chain);
    chain.add_tip_listener(Arc::new(move |tip| {
        let Some(chain) = weak.upgrade() else {
            return;
        };
        let parent = |h: &Hash256| chain.get_block_index(h).ok().flatten().map(|i| i.prev_hash);
        let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
        for (kind, fields) in on_tip(
            *last,
            tip.height,
            tip.hash,
            tip.prev_hash,
            chain.is_ibd(),
            parent,
        ) {
            crate::events::CHAIN_EVENTS.record(kind, &fields);
        }
        *last = Some((tip.height, tip.hash));
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn h(n: u32) -> Hash256 {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        b[31] = 1;
        Hash256::from_bytes(b)
    }

    #[test]
    fn a_kind_is_capped_per_window_and_the_held_back_count_follows() {
        let mut w = Window::new();
        for i in 0..CAP {
            assert_eq!(w.admit(f64::from(i)), (true, 0));
        }
        assert_eq!(w.admit(100.0), (false, 0));
        assert_eq!(w.admit(200.0), (false, 0));
        // A new window opens: the two held back are reported once
        assert_eq!(w.admit(WINDOW_S + 1.0), (true, 2));
        assert_eq!(w.admit(WINDOW_S + 2.0), (true, 0));
    }

    #[test]
    fn a_ban_storm_is_one_incident_rearmed_when_the_bans_fall_back() {
        let mut s = Storm::new();
        for i in 0..STORM {
            assert_eq!(s.ban(i as f64), None);
        }
        assert_eq!(s.ban(20.0), Some(STORM + 1));
        assert_eq!(s.ban(21.0), None);
        assert_eq!(s.ban(22.0), None);
        // Ten minutes on, the old bans have gone: re-armed
        assert_eq!(s.ban(WINDOW_S + 30.0), None);
        for i in 0..STORM - 1 {
            assert_eq!(s.ban(WINDOW_S + 31.0 + i as f64), None);
        }
        assert_eq!(s.ban(WINDOW_S + 50.0), Some(STORM + 1));
    }

    #[test]
    fn an_invalid_block_is_public_and_its_incident_is_once_per_ten_minutes() {
        let mut st = State::new();
        let ip = "198.51.100.7".parse().unwrap();
        let e = Event::InvalidBlock {
            hash: h(9),
            height: Some(1234),
            reason: "bad \"stake\"\nproof",
            peer: Some(ip),
            block: None,
            code: "",
        };
        let p = decide(&mut st, &e, 5.0);
        let (kind, fields) = p.record.unwrap();
        assert_eq!(kind, "invalid-block");
        assert!(
            fields.starts_with(&format!("hash=blk:{} height=1234 peer=peer-", h(9))),
            "{fields}"
        );
        assert!(
            fields.ends_with(" reason=\"bad 'stake' proof\""),
            "{fields}"
        );
        assert!(!fields.contains("198.51"), "{fields}");
        assert_eq!(p.incident.unwrap().0, "invalid-block");
        assert!(decide(&mut st, &e, 100.0).incident.is_none());
        assert!(decide(&mut st, &e, 5.0 + WINDOW_S).incident.is_some());
        let none = Event::InvalidBlock {
            hash: h(9),
            height: None,
            reason: "x",
            peer: None,
            block: None,
            code: "",
        };
        let (_, fields) = decide(&mut st, &none, 700.0).record.unwrap();
        assert!(fields.contains(" height=- peer=- "), "{fields}");
    }

    #[test]
    fn a_ban_names_the_peer_by_pseudonym() {
        let mut st = State::new();
        let e = Event::Ban {
            ip: "2001:db8::5".parse().unwrap(),
            reason: "misbehaving",
        };
        let (kind, fields) = decide(&mut st, &e, 1.0).record.unwrap();
        assert_eq!(kind, "ban");
        assert!(
            fields.starts_with("peer=peer-") && !fields.contains("2001"),
            "{fields}"
        );
    }

    /// A chain as a parent map: height n's block is h(n) on the main
    /// branch, h(1000 + n) from `side_from` on (an empty range for none)
    fn chain(top: u32, side_from: u32, side_top: u32) -> HashMap<Hash256, Hash256> {
        let mut m = HashMap::new();
        for n in 1..=top {
            m.insert(h(n), h(n - 1));
        }
        for n in side_from..=side_top {
            let parent = if n == side_from {
                h(n - 1)
            } else {
                h(1000 + n - 1)
            };
            m.insert(h(1000 + n), parent);
        }
        m
    }

    #[test]
    fn a_reorg_records_its_depth_and_both_tips_in_clear() {
        let m = chain(50, 48, 51);
        let parent = |x: &Hash256| m.get(x).copied();
        // Main tip 50; the side branch forks after 47 and reaches 51
        let out = on_tip(Some((50, h(50))), 51, h(1051), h(1050), false, parent);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].0, "reorg");
        assert_eq!(
            out[0].1,
            format!("depth=3 old=blk:{} new=blk:{} height=51", h(50), h(1051))
        );
        // Extending the tip, by one or several blocks, is no reorg
        assert!(on_tip(Some((49, h(49))), 50, h(50), h(49), false, parent).is_empty());
        assert!(on_tip(Some((45, h(45))), 50, h(50), h(49), false, parent).is_empty());
        // A tip that went back (invalidated blocks) is a reorg of that depth
        let back = on_tip(Some((50, h(50))), 47, h(47), h(46), false, parent);
        assert!(back[0].1.starts_with("depth=3 "), "{back:?}");
    }

    #[test]
    fn a_fork_out_of_reach_reads_unknown() {
        let m: HashMap<Hash256, Hash256> = HashMap::new();
        let out = on_tip(Some((10, h(10))), 11, h(2011), h(2010), false, |x| {
            m.get(x).copied()
        });
        assert!(out[0].1.starts_with("depth=unknown "), "{out:?}");
    }

    #[test]
    fn a_tip_record_every_hundred_blocks_and_none_at_start() {
        let m = chain(301, 1, 0);
        let parent = |x: &Hash256| m.get(x).copied();
        assert!(on_tip(None, 200, h(200), h(199), false, parent).is_empty());
        assert!(on_tip(Some((198, h(198))), 199, h(199), h(198), false, parent).is_empty());
        let out = on_tip(Some((199, h(199))), 200, h(200), h(199), false, parent);
        assert_eq!(
            out,
            vec![("tip", format!("height=200 hash=blk:{}", h(200)))]
        );
        // Several blocks at once across a hundred: one record
        assert_eq!(
            on_tip(Some((250, h(250))), 301, h(301), h(300), false, parent).len(),
            1
        );
        // In initial block download, one per ten thousand
        assert!(on_tip(Some((199, h(199))), 200, h(200), h(199), true, parent).is_empty());
    }
}
