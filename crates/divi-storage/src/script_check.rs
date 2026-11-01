// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Script check threads: Divi Core's -par (TransactionInputChecker.cpp:16-26).
//! With none, each input's script is checked as its block is connected; with
//! two or more, a block's script checks wait until its other checks are done
//! and then run on that many threads, as Divi Core's check queue does
//! (BlockTransactionChecker.cpp:136-141, BlockConnectionService.cpp:342).

use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::transaction::Transaction;
use divi_script::{verify_input_with_flags, ScriptError, ScriptFlags};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Divi Core MAX_SCRIPTCHECK_THREADS (defaultValues.h:76)
pub const MAX_SCRIPTCHECK_THREADS: i64 = 16;

static THREADS: AtomicUsize = AtomicUsize::new(0);

/// Divi Core SetScriptCheckingThreadCount: `par` threads, or the cores plus
/// `par` for 0 and below; 1 or fewer is none (0); at most 16
pub fn threads_for(par: i64, cores: i64) -> usize {
    let mut n = par;
    if n <= 0 {
        n += cores;
    }
    if n <= 1 {
        0
    } else {
        n.min(MAX_SCRIPTCHECK_THREADS) as usize
    }
}

/// Set the script check threads (0: check each script as its block connects)
pub fn set_threads(n: usize) {
    THREADS.store(n, Ordering::Relaxed);
}

/// The script check threads; 0 when scripts are checked inline
pub fn threads() -> usize {
    THREADS.load(Ordering::Relaxed)
}

/// One input's script check, held until the block's other checks are done
pub struct ScriptCheck {
    pub tx_index: usize,
    pub input_index: usize,
    pub script_pubkey: Script,
    pub value: Amount,
}

/// Run `checks` of `transactions` under `flags` on up to `threads` threads.
/// Returns the failing check that comes first in the block, so the outcome
/// is the same whichever thread finds it.
pub fn run(
    transactions: &[Transaction],
    checks: &[ScriptCheck],
    flags: ScriptFlags,
    threads: usize,
) -> Result<(), (usize, ScriptError)> {
    let check = |n: usize| {
        let c = &checks[n];
        verify_input_with_flags(
            &transactions[c.tx_index],
            c.input_index,
            &c.script_pubkey,
            c.value,
            flags,
        )
    };
    let workers = threads.min(checks.len());
    if workers <= 1 {
        return (0..checks.len()).try_for_each(|n| check(n).map_err(|e| (n, e)));
    }
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let errors = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut first: Option<(usize, ScriptError)> = None;
                    loop {
                        let n = next.fetch_add(1, Ordering::Relaxed);
                        // A failure earlier in the block than any check still
                        // to run is final; later checks can stop
                        if n >= checks.len() || failed.load(Ordering::Relaxed) {
                            break;
                        }
                        if let Err(e) = check(n) {
                            failed.store(true, Ordering::Relaxed);
                            first = Some((n, e));
                            break;
                        }
                    }
                    first
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().expect("script check thread"))
            .collect::<Vec<_>>()
    });
    // Checks are handed out in block order, so every check before the
    // earliest failure ran; the earliest of the failures found is the first
    // in the block
    match errors.into_iter().min_by_key(|(n, _)| *n) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::transaction::{OutPoint, TxIn};

    /// One transaction of `n` inputs, each spent by an empty script_sig
    fn spends(n: usize) -> Vec<Transaction> {
        let input = TxIn {
            prevout: OutPoint::null(),
            script_sig: Script::new(),
            sequence: u32::MAX,
        };
        vec![Transaction {
            version: 1,
            vin: vec![input; n],
            vout: vec![],
            lock_time: 0,
        }]
    }

    /// Input `i` is checked against OP_1 (passes) or OP_0 (fails)
    fn checks(n: usize, failing: &[usize]) -> Vec<ScriptCheck> {
        (0..n)
            .map(|i| ScriptCheck {
                tx_index: 0,
                input_index: i,
                script_pubkey: Script::from_bytes(vec![if failing.contains(&i) {
                    0x00
                } else {
                    0x51
                }]),
                value: Amount::ZERO,
            })
            .collect()
    }

    /// On any number of threads the failure reported is the first in the
    /// block, as checking each input in turn would find
    #[test]
    fn the_first_failure_in_the_block_is_reported() {
        let txs = spends(400);
        for threads in [0, 1, 2, 8, 16] {
            assert!(run(&txs, &checks(400, &[]), ScriptFlags::mandatory(), threads).is_ok());
            let failing = checks(400, &[137, 138, 399]);
            let got = run(&txs, &failing, ScriptFlags::mandatory(), threads);
            assert_eq!(got.err().map(|(n, _)| n), Some(137), "{threads} threads");
        }
    }

    /// TransactionInputChecker.cpp:16-26: n, or the cores plus n for 0 and
    /// below; 1 or fewer is none; capped at 16
    #[test]
    fn threads_as_divi_core_counts_them() {
        assert_eq!(threads_for(4, 8), 4);
        assert_eq!(threads_for(1, 8), 0);
        assert_eq!(threads_for(0, 8), 8);
        assert_eq!(threads_for(0, 1), 0);
        assert_eq!(threads_for(-1, 8), 7);
        assert_eq!(threads_for(-7, 8), 0);
        assert_eq!(threads_for(-100, 8), 0);
        assert_eq!(threads_for(17, 8), 16);
        assert_eq!(threads_for(0, 64), 16);
    }
}
