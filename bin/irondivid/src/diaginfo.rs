// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The content of `getdiaginfo` (diag plan A10), built in the node.
//!
//! The RPC itself is not registered: its dispatch and the `Caller` that
//! gates `known_values` live in the RPC server, which this part does not
//! change. [`build`] is what that method will return; today every A12
//! incident carries it as `getdiaginfo.json`.
//!
//! It is called from the incident writer, which runs when the node may be
//! hung and from the panic hook, so it never waits: every source is a
//! lock-free table or a `try_lock`, and a busy one reads `"busy"`.
//! Nothing behind the chain, mempool, peer, wallet or masternode locks is
//! read here.
//!
//! Every value is already redacted at its source (A11, A15): method names,
//! masked error messages, lock and task names, thread names and wchans.

use serde_json::{json, Map, Value};

/// The sections this build fills, in the plan's order
pub fn build() -> Value {
    let mut out = Map::new();
    out.insert("version".into(), json!(1));
    out.insert("run".into(), json!(crate::runs_log::run_number()));
    out.insert("time".into(), json!(crate::runs_log::utc_now()));
    let health = crate::health::last_line();
    out.insert(
        "health".into(),
        if health.is_empty() {
            json!("busy or not yet written")
        } else {
            json!(health.trim_end())
        },
    );
    out.insert("rpc_in_flight".into(), rpc_in_flight());
    out.insert(
        "rpc_recent_errors".into(),
        match crate::rpc_log::recent_errors() {
            Some(m) => json!(m),
            None => json!("busy"),
        },
    );
    out.insert("locks".into(), locks());
    let (threads, refused) = crate::watchdog::threads();
    out.insert(
        "threads".into(),
        json!({
            "sample": threads.lines().collect::<Vec<_>>(),
            "refused_by_kernel": refused,
        }),
    );
    out.insert(
        "not_included".into(),
        json!([
            "sync state, chain tips, orphan pools, peers, ban list, address book",
            "masternode, lottery and treasury state, staking kernel counters",
            "wallet section, diag_key pseudonym map, known_values pages",
        ]),
    );
    Value::Object(out)
}

fn rpc_in_flight() -> Value {
    divi_primitives::diag_rpc::in_flight()
        .into_iter()
        .map(|c| {
            json!({
                "method": c.method,
                "transport": c.transport.as_str(),
                "for_ms": c.for_ms,
            })
        })
        .collect()
}

fn locks() -> Value {
    use divi_primitives::diag_lock;
    let holders: Map<String, Value> = diag_lock::holders()
        .into_iter()
        .map(|(l, h)| (l.as_str().to_string(), json!(h)))
        .collect();
    let waits: Vec<Value> = diag_lock::waiting()
        .into_iter()
        .map(|w| {
            json!({
                "lock": w.lock.as_str(),
                "for_ms": w.for_ms,
                "waiter": w.waiter,
                "holder": w.holder,
            })
        })
        .collect();
    let counts: Map<String, Value> = diag_lock::counts()
        .into_iter()
        .map(|(l, over, longest)| {
            (
                l.as_str().to_string(),
                json!({ "over_1s": over, "longest_ms": longest }),
            )
        })
        .collect();
    json!({ "last_holder": holders, "waiting": waits, "waits": counts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::diag_lock::{self, Lock};
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;

    #[test]
    fn build_returns_while_every_diag_lock_is_held() {
        let locks: Vec<Mutex<()>> = Lock::ALL.iter().map(|_| Mutex::new(())).collect();
        let guards: Vec<_> = Lock::ALL
            .iter()
            .zip(&locks)
            .map(|(&l, m)| diag_lock::timed(l, || m.try_lock().ok(), || m.lock().unwrap()))
            .collect();
        let (tx, rx) = mpsc::channel();
        crate::tasks::thread("diaginfo-test", crate::tasks::Kind::Supervised, move || {
            let _ = tx.send(build());
        })
        .expect("thread");
        let v = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("build waited on a held lock");
        drop(guards);
        for key in [
            "health",
            "rpc_in_flight",
            "rpc_recent_errors",
            "locks",
            "threads",
        ] {
            assert!(v.get(key).is_some(), "no {} in {}", key, v);
        }
    }

    #[test]
    fn output_has_no_long_hex_and_no_ip_address() {
        let text = build().to_string();
        let bytes = text.as_bytes();
        let mut run = 0;
        for b in bytes {
            run = if b.is_ascii_hexdigit() { run + 1 } else { 0 };
            assert!(run < 64, "a 64-hex token in {}", text);
        }
        for word in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
            let parts: Vec<_> = word.split('.').collect();
            assert!(
                !(parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())),
                "an IPv4 address in {}",
                text
            );
        }
    }
}
