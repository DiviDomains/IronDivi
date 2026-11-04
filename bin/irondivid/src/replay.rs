// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A13 replay bundles under `<datadir>/diag/`:
//!
//! - `invalid/<hash>/`: a block a peer sent that was refused: `block.hex`
//!   (when the block was still held), `headers.txt` (its parent back to the
//!   fork point with the active chain), `spent.txt` (the outputs it spends,
//!   as the chain has them now), `state.txt` (reason, code path, the
//!   parent's stake modifier, difficulty, money supply and lottery winners)
//!   and `sporks.txt`. Cap 20 MB.
//! - `rejected-tx/<txid>/`: a relayed transaction that is not the
//!   wallet's: `tx.hex`, `spent.txt`, `state.txt`. Cap 5 MB.
//! - `own-invalid/<hash>/`: the same for a block this wallet staked or a
//!   transaction that is its own or was submitted here (A15 "sent from
//!   here"), and for a refused block or transaction while the wallet check
//!   is not yet set. Included in a package only on the §8.2 question.
//!   Cap 20 MB.
//! - `bad-messages/<n>.txt`: a message that did not parse (its command and
//!   first 4 KB) or that added misbehaviour score (the cause and score),
//!   the peer by pseudonym. Every 64-hex token in the text is replaced by
//!   `<hash>`. Cap 5 MB, and 60 records per ten minutes.
//!
//! The headers, blocks and outputs are public records printed with no
//! marking by ownership. Nothing here writes a log line. The event sink
//! only copies the event into a job for the `diag-replay` thread, which does
//! every chain read and file write; a job that does not fit the queue is
//! skipped and counted in the next bundle's `skipped_before`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use divi_primitives::diag_events::Event;
use divi_primitives::redact::PeerAddr;
use divi_primitives::serialize::serialize;
use divi_primitives::{Block, Hash256, Transaction};
use divi_storage::Chain;

/// Jobs waiting for the thread
const QUEUE: usize = 64;
/// Header lines in a bundle (the plan's reorg walk bound)
const MAX_HEADERS: u32 = 2000;
/// Spent-output lines in a bundle
const MAX_SPENT: usize = 5000;
/// Bad-message records per ten minutes
const MESSAGES_PER_WINDOW: u32 = 60;
const WINDOW_S: f64 = 600.0;

const INVALID: (&str, u64) = ("invalid", 20 << 20);
const REJECTED: (&str, u64) = ("rejected-tx", 5 << 20);
const OWN: (&str, u64) = ("own-invalid", 20 << 20);
const MESSAGES: (&str, u64) = ("bad-messages", 5 << 20);

/// The spork lines (`id value time signature-hex`), from the node's spork
/// manager
pub type SporkLines = Box<dyn Fn() -> Vec<String> + Send + Sync>;

struct Sources {
    chain: Weak<Chain>,
    sporks: SporkLines,
}

static QUEUE_TX: OnceLock<Mutex<SyncSender<Job>>> = OnceLock::new();
static SOURCES: OnceLock<Sources> = OnceLock::new();
static SKIPPED: AtomicU64 = AtomicU64::new(0);
/// Bad messages in the current window: (start, records)
static MESSAGE_WINDOW: Mutex<(f64, u32)> = Mutex::new((f64::NEG_INFINITY, 0));

/// Where a block or transaction bundle goes
#[derive(Debug, Clone, Copy, PartialEq)]
enum To {
    Public,
    Own,
}

#[derive(Debug)]
enum Job {
    Block {
        to: To,
        hash: Hash256,
        height: Option<u32>,
        block: Option<Block>,
        reason: String,
        code: String,
        peer: Option<IpAddr>,
    },
    Tx {
        to: To,
        txid: Hash256,
        tx: Transaction,
        reason: String,
    },
    Message {
        peer: Option<IpAddr>,
        command: String,
        head: Vec<u8>,
        error: String,
        score: u32,
    },
}

/// Start the `diag-replay` thread writing under `<data_dir>/diag/`
pub fn start(data_dir: &Path) {
    let (tx, rx) = sync_channel(QUEUE);
    if QUEUE_TX.set(Mutex::new(tx)).is_err() {
        return;
    }
    let root = data_dir.join("diag");
    if let Err(e) = crate::tasks::thread("diag-replay", crate::tasks::Kind::Supervised, move || {
        run(&root, rx)
    }) {
        tracing::warn!("diag replay bundles off: {}", e);
    }
}

/// The chain and sporks the bundles read; set once the node is built
pub fn set_sources(chain: &Arc<Chain>, sporks: SporkLines) {
    let _ = SOURCES.set(Sources {
        chain: Arc::downgrade(chain),
        sporks,
    });
}

/// Hand an event to the thread. `own`: the block or transaction is the
/// wallet's (or the wallet check is not set yet). Ban events are not
/// bundled.
pub fn note(e: &Event<'_>, own: bool) {
    let Some(job) = job_of(e, own, crate::runs_log::since_launch().as_secs_f64()) else {
        return;
    };
    let Some(tx) = QUEUE_TX.get() else {
        return;
    };
    let sent = tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .try_send(job)
        .is_ok();
    if !sent {
        SKIPPED.fetch_add(1, Ordering::Relaxed);
    }
}

fn job_of(e: &Event<'_>, own: bool, now: f64) -> Option<Job> {
    let to = if own { To::Own } else { To::Public };
    Some(match e {
        Event::InvalidBlock {
            hash,
            height,
            reason,
            peer,
            block,
            code,
        } => Job::Block {
            to,
            hash: *hash,
            height: *height,
            block: block.cloned(),
            reason: reason.to_string(),
            code: code.to_string(),
            peer: *peer,
        },
        Event::OwnBlockRejected {
            block,
            reason,
            code,
        } => Job::Block {
            to: To::Own,
            hash: block.hash(),
            height: None,
            block: Some((*block).clone()),
            reason: reason.to_string(),
            code: code.to_string(),
            peer: None,
        },
        Event::RejectedTx { txid, tx, reason } => Job::Tx {
            to,
            txid: *txid,
            tx: (*tx).clone(),
            reason: reason.to_string(),
        },
        Event::OwnTxRejected { txid, tx, reason } => Job::Tx {
            to: To::Own,
            txid: *txid,
            tx: (*tx).clone(),
            reason: reason.to_string(),
        },
        Event::BadMessage {
            peer,
            command,
            head,
            error,
            score,
        } => {
            if !admit_message(now) {
                SKIPPED.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            Job::Message {
                peer: *peer,
                command: command.to_string(),
                head: head[..head.len().min(divi_primitives::diag_events::MESSAGE_HEAD)].to_vec(),
                error: error.to_string(),
                score: *score,
            }
        }
        Event::Ban { .. } => return None,
    })
}

fn admit_message(now: f64) -> bool {
    let mut w = MESSAGE_WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    if now - w.0 >= WINDOW_S {
        *w = (now, 0);
    }
    if w.1 < MESSAGES_PER_WINDOW {
        w.1 += 1;
        true
    } else {
        false
    }
}

fn run(root: &Path, rx: Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        let chain = SOURCES.get().and_then(|s| s.chain.upgrade());
        let sporks = SOURCES.get().map(|s| (s.sporks)()).unwrap_or_default();
        write(root, &job, chain.as_deref(), &sporks);
    }
}

/// Write one job's bundle under `root` (`<datadir>/diag`)
fn write(root: &Path, job: &Job, chain: Option<&Chain>, sporks: &[String]) -> Option<PathBuf> {
    // A14: not while the low-disk pause is on
    if crate::budget::paused() {
        SKIPPED.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let skipped = SKIPPED.swap(0, Ordering::Relaxed);
    let (part, name, files) = match job {
        Job::Block {
            to,
            hash,
            height,
            block,
            reason,
            code,
            peer,
        } => {
            let part = if *to == To::Own { OWN } else { INVALID };
            let mut files = Vec::new();
            let mut state = vec![
                "kind=block".to_string(),
                format!("hash={}", hash),
                format!("height={}", opt(height)),
                format!("reason={}", one_line(reason)),
                format!("code={}", code),
                format!(
                    "peer={}",
                    peer.map_or("-".to_string(), |p| PeerAddr(p).to_string())
                ),
            ];
            if let Some(b) = block {
                files.push(("block.hex", hex::encode(serialize(b)) + "\n"));
                let parent = b.header.prev_block;
                state.push(format!("parent={}", parent));
                if let Some(chain) = chain {
                    let (headers, fork) = headers(chain, &parent);
                    files.push(("headers.txt", headers));
                    state.push(format!("fork_height={}", opt(&fork)));
                    state.extend(parent_state(chain, &parent));
                    files.push(("spent.txt", spent(chain, &b.transactions)));
                }
            }
            if let Some(chain) = chain {
                state.push(format!("network={:?}", chain.network_type()));
            }
            files.push(("sporks.txt", lines(sporks)));
            files.push(("state.txt", tail(state, skipped)));
            (part, hash.to_string(), files)
        }
        Job::Tx {
            to,
            txid,
            tx,
            reason,
        } => {
            let part = if *to == To::Own { OWN } else { REJECTED };
            let mut files = vec![("tx.hex", hex::encode(serialize(tx)) + "\n")];
            let mut state = vec![
                "kind=tx".to_string(),
                format!("txid={}", txid),
                format!("reason={}", one_line(reason)),
            ];
            if let Some(chain) = chain {
                files.push(("spent.txt", spent(chain, std::slice::from_ref(tx))));
                state.push(format!(
                    "tip={}",
                    chain
                        .tip()
                        .map_or("-".to_string(), |t| t.height.to_string())
                ));
                state.push(format!("network={:?}", chain.network_type()));
            }
            files.push(("state.txt", tail(state, skipped)));
            (part, txid.to_string(), files)
        }
        Job::Message {
            peer,
            command,
            head,
            error,
            score,
        } => {
            let n = next_number(&root.join(MESSAGES.0));
            let mut text = vec![
                format!("command={}", one_line(command)),
                format!(
                    "peer={}",
                    peer.map_or("-".to_string(), |p| PeerAddr(p).to_string())
                ),
                format!("score={}", score),
                format!("error={}", one_line(&mask_hashes(error))),
                format!("head_len={}", head.len()),
                format!("head={}", hex::encode(head)),
            ];
            text = tail(text, skipped).lines().map(str::to_string).collect();
            return put_file(root, MESSAGES, &format!("{}.txt", n), &lines(&text));
        }
    };
    let base = root.join(part.0);
    let _ = crate::private_files::ensure_private_dir(root, true);
    let _ = crate::private_files::ensure_private_dir(&base, true);
    let dir = base.join(&name);
    // The same block or transaction again: the first bundle stands
    if dir.exists() {
        return None;
    }
    crate::private_files::ensure_private_dir(&dir, true).ok()?;
    for (file, body) in files {
        put(&dir.join(file), body.as_bytes());
    }
    prune(&base, part.1);
    Some(dir)
}

fn put_file(root: &Path, part: (&str, u64), name: &str, body: &str) -> Option<PathBuf> {
    if crate::budget::paused() {
        return None;
    }
    let base = root.join(part.0);
    let _ = crate::private_files::ensure_private_dir(root, true);
    crate::private_files::ensure_private_dir(&base, true).ok()?;
    let path = base.join(name);
    put(&path, body.as_bytes());
    prune(&base, part.1);
    Some(path)
}

fn opt(v: &Option<u32>) -> String {
    v.map_or("-".to_string(), |v| v.to_string())
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn lines(v: &[String]) -> String {
    let mut s = v.join("\n");
    s.push('\n');
    s
}

/// The state lines with the time and the skipped count added
fn tail(mut state: Vec<String>, skipped: u64) -> String {
    state.push(format!("time={}", crate::runs_log::utc_now()));
    state.push(format!("run={}", crate::runs_log::run_number()));
    state.push(format!("skipped_before={}", skipped));
    lines(&state)
}

/// Every run of 64 hex digits replaced by `<hash>`: a cause that names a
/// transaction never names the wallet's own
fn mask_hashes(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let run = b[i..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
        if run >= 64 {
            out.push_str("<hash>");
            i += run;
        } else if run > 0 {
            out.push_str(&s[i..i + run]);
            i += run;
        } else {
            let c = s[i..].chars().next().unwrap_or(' ');
            out.push(c);
            i += c.len_utf8().max(1);
        }
    }
    out
}

/// The parent and its ancestors back to the first on the active chain (the
/// fork point), as index lines; and the fork height
fn headers(chain: &Chain, parent: &Hash256) -> (String, Option<u32>) {
    let mut out = Vec::new();
    let mut at = *parent;
    let mut fork = None;
    for _ in 0..MAX_HEADERS {
        let Ok(Some(i)) = chain.get_block_index(&at) else {
            out.push(format!("{} unknown", at));
            break;
        };
        out.push(format!(
            "height={} hash={} prev={} version={} merkle={} time={} bits={:08x} nonce={} pos={}",
            i.height,
            i.hash,
            i.prev_hash,
            i.version,
            i.merkle_root,
            i.time,
            i.bits,
            i.nonce,
            u8::from(i.is_proof_of_stake)
        ));
        let active = chain
            .get_block_index_by_height(i.height)
            .ok()
            .flatten()
            .is_some_and(|a| a.hash == i.hash);
        if active || i.height == 0 {
            fork = Some(i.height);
            break;
        }
        at = i.prev_hash;
    }
    (lines(&out), fork)
}

/// The parent's stake modifier, difficulty, money supply and lottery
/// winners: the inputs a block on it is checked against
fn parent_state(chain: &Chain, parent: &Hash256) -> Vec<String> {
    let Ok(Some(p)) = chain.get_block_index(parent) else {
        return vec!["parent_known=no".to_string()];
    };
    let mut v = vec![
        "parent_known=yes".to_string(),
        format!("parent_height={}", p.height),
        format!("parent_time={}", p.time),
        format!("parent_bits={:08x}", p.bits),
        format!("parent_stake_modifier={:016x}", p.stake_modifier),
        format!(
            "parent_generated_stake_modifier={}",
            u8::from(p.generated_stake_modifier)
        ),
        format!(
            "parent_money_supply={}",
            p.money_supply.map_or("-".to_string(), |m| m.to_string())
        ),
        format!("lottery_height={}", p.lottery_winners.height),
    ];
    for (n, w) in p.lottery_winners.coinstakes.iter().enumerate() {
        v.push(format!(
            "lottery_{}={} {}",
            n,
            w.tx_hash,
            w.script_pubkey.to_hex()
        ));
    }
    v
}

/// The outputs the transactions spend, as the chain's UTXO set has them
/// now (`missing`: spent, or never known)
fn spent(chain: &Chain, txs: &[Transaction]) -> String {
    let mut out = Vec::new();
    'all: for tx in txs {
        if tx.is_coinbase() {
            continue;
        }
        for input in &tx.vin {
            if out.len() >= MAX_SPENT {
                out.push("truncated".to_string());
                break 'all;
            }
            let p = &input.prevout;
            out.push(match chain.get_utxo(p) {
                Ok(Some(u)) => format!(
                    "{}:{} value={} height={} coinbase={} coinstake={} script={}",
                    p.txid,
                    p.vout,
                    u.value.as_sat(),
                    u.height,
                    u8::from(u.is_coinbase),
                    u8::from(u.is_coinstake),
                    u.script_pubkey.to_hex()
                ),
                Ok(None) => format!("{}:{} missing", p.txid, p.vout),
                Err(e) => format!("{}:{} error={}", p.txid, p.vout, one_line(&e.to_string())),
            });
        }
    }
    lines(&out)
}

fn put(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    if let Ok(mut file) = options.open(path) {
        let _ = file.write_all(bytes);
    }
}

/// The next free record number in `dir`
fn next_number(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    e.file_name()
                        .to_str()?
                        .strip_suffix(".txt")?
                        .parse::<u64>()
                        .ok()
                })
                .max()
                .map_or(1, |n| n + 1)
        })
        .unwrap_or(1)
}

fn size_of(path: &Path) -> u64 {
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if m.is_dir() {
        std::fs::read_dir(path)
            .map(|rd| rd.flatten().map(|e| size_of(&e.path())).sum())
            .unwrap_or(0)
    } else {
        m.len()
    }
}

/// Remove the oldest entries of `base` until it is within `cap` bytes; the
/// newest always stays
fn prune(base: &Path, cap: u64) {
    let Ok(rd) = std::fs::read_dir(base) else {
        return;
    };
    let mut entries: Vec<(std::time::SystemTime, PathBuf, u64)> = rd
        .flatten()
        .map(|e| {
            let p = e.path();
            let t = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            let s = size_of(&p);
            (t, p, s)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut total: u64 = entries.iter().map(|e| e.2).sum();
    let keep = entries.len().saturating_sub(1);
    for (_, p, s) in entries.into_iter().take(keep) {
        if total <= cap {
            break;
        }
        let removed = if p.is_dir() {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
        if removed.is_ok() {
            total = total.saturating_sub(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_in_a_cause_are_masked() {
        let id = "ab".repeat(32);
        let s = format!("tx {} rejected by the mempool: bad-txns ü", id);
        assert_eq!(
            mask_hashes(&s),
            "tx <hash> rejected by the mempool: bad-txns ü"
        );
        // Shorter hex runs are kept
        assert_eq!(mask_hashes("code 0x1f deadbeef"), "code 0x1f deadbeef");
    }

    #[test]
    fn a_block_bundle_without_a_chain_has_the_block_and_its_state() {
        let dir = tempfile::tempdir().unwrap();
        let block = Block::default();
        let hash = block.hash();
        let job = Job::Block {
            to: To::Public,
            hash,
            height: Some(7),
            block: Some(block.clone()),
            reason: "bad\nstake".to_string(),
            code: "InvalidBlock".to_string(),
            peer: Some("198.51.100.7".parse().unwrap()),
        };
        let out = write(dir.path(), &job, None, &["1 2 3 aa".to_string()]).unwrap();
        assert_eq!(out, dir.path().join("invalid").join(hash.to_string()));
        let hexed = std::fs::read_to_string(out.join("block.hex")).unwrap();
        assert_eq!(hexed.trim(), hex::encode(serialize(&block)));
        let state = std::fs::read_to_string(out.join("state.txt")).unwrap();
        assert!(state.contains("reason=bad stake\n"), "{state}");
        assert!(state.contains("code=InvalidBlock\n"), "{state}");
        assert!(state.contains("peer=peer-"), "{state}");
        assert!(!state.contains("198.51"), "{state}");
        assert_eq!(
            std::fs::read_to_string(out.join("sporks.txt")).unwrap(),
            "1 2 3 aa\n"
        );
        // The same block again leaves the first bundle
        assert!(write(dir.path(), &job, None, &[]).is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(out.join("state.txt"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn own_and_bad_message_records_go_to_their_own_parts() {
        let dir = tempfile::tempdir().unwrap();
        let tx = Transaction::default();
        let txid = tx.txid();
        let own = write(
            dir.path(),
            &Job::Tx {
                to: To::Own,
                txid,
                tx: tx.clone(),
                reason: "fee".to_string(),
            },
            None,
            &[],
        )
        .unwrap();
        assert_eq!(own, dir.path().join("own-invalid").join(txid.to_string()));
        assert!(!dir.path().join("rejected-tx").exists());
        let id = "cd".repeat(32);
        let m = write(
            dir.path(),
            &Job::Message {
                peer: None,
                command: "tx".to_string(),
                head: vec![1, 2, 3],
                error: format!("tx {} rejected", id),
                score: 10,
            },
            None,
            &[],
        )
        .unwrap();
        assert_eq!(m, dir.path().join("bad-messages").join("1.txt"));
        let text = std::fs::read_to_string(&m).unwrap();
        assert!(text.contains("error=tx <hash> rejected\n"), "{text}");
        assert!(text.contains("head=010203\n"), "{text}");
        assert!(!text.contains(&id));
    }

    #[test]
    fn the_oldest_entries_go_first_and_the_newest_stays() {
        let dir = tempfile::tempdir().unwrap();
        for n in 1..=4 {
            put(&dir.path().join(format!("{}.txt", n)), &[0u8; 100]);
            // Distinct modification times
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000 + n);
            let f = std::fs::File::options()
                .write(true)
                .open(dir.path().join(format!("{}.txt", n)))
                .unwrap();
            f.set_modified(t).unwrap();
        }
        prune(dir.path(), 250);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, vec!["3.txt", "4.txt"]);
        // Over the cap with one entry: it stays
        prune(dir.path(), 10);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn bad_messages_are_capped_per_window() {
        // A window far from the clock other tests use
        let base = 1.0e9;
        let mut admitted = 0;
        for i in 0..(MESSAGES_PER_WINDOW + 5) {
            if admit_message(base + f64::from(i) * 0.001) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, MESSAGES_PER_WINDOW);
        assert!(admit_message(base + WINDOW_S + 1.0));
    }
}
