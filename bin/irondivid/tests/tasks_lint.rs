// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! A4: every task and thread irondivid starts goes through tasks.rs, which
//! names it and says whether its panic ends the node; main's is the only
//! `catch_unwind` in the node, so a main-thread panic always ends the run
//! with 101. The node crates still start their own tasks: their number may
//! only fall.

use std::path::{Path, PathBuf};

/// The ways to start a task or a thread (split, so this file does not match)
const SPAWNS: [&str; 4] = [
    concat!("tokio::", "spawn("),
    concat!("thread::", "spawn("),
    concat!("task::", "spawn("),
    concat!("thread::Builder", "::new()"),
];
const CATCH: &str = concat!("catch_", "unwind(");

/// The crates the node is built from, besides irondivid
const NODE_CRATES: [&str; 10] = [
    "divi-node",
    "divi-network",
    "divi-rpc",
    "divi-storage",
    "divi-primitives",
    "divi-wallet",
    "divi-crypto",
    "divi-masternode",
    "divi-webui",
    "divi-electrum",
];

/// Starts in the node crates when A4 landed; none may be added
const CRATE_SPAWNS: [(&str, usize); 14] = [
    ("divi-electrum/src/lib.rs", 3),
    ("divi-network/src/peer_manager.rs", 11),
    ("divi-network/src/socks5.rs", 3),
    ("divi-network/src/sync.rs", 1),
    ("divi-node/src/node.rs", 14),
    ("divi-node/src/staker.rs", 1),
    ("divi-node/src/zmq.rs", 5),
    ("divi-rpc/src/network.rs", 3),
    ("divi-rpc/src/rest.rs", 1),
    ("divi-rpc/src/server.rs", 3),
    ("divi-storage/src/chain.rs", 2),
    ("divi-wallet/src/keystore.rs", 1),
    ("divi-wallet/src/wallet_db.rs", 1),
    ("divi-webui/src/lib.rs", 1),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn spawns(text: &str) -> usize {
    SPAWNS.iter().map(|s| text.matches(s).count()).sum()
}

#[test]
fn irondivid_starts_tasks_only_through_tasks_rs() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut found = Vec::new();
    for file in files {
        if file.ends_with("tasks.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        if spawns(&text) > 0 {
            found.push(file.display().to_string());
        }
    }
    assert!(found.is_empty(), "start it with tasks.rs: {found:?}");
}

#[test]
fn main_has_the_only_catch_unwind() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    for name in NODE_CRATES {
        rust_files(&root().join("crates").join(name).join("src"), &mut files);
    }
    let mut found = Vec::new();
    for file in files {
        let n = std::fs::read_to_string(&file)
            .unwrap()
            .matches(CATCH)
            .count();
        if n > 0 {
            found.push((file.display().to_string(), n));
        }
    }
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].0.ends_with("src/main.rs") && found[0].1 == 1,
        "{found:?}"
    );
}

#[test]
fn the_node_crates_start_no_new_tasks() {
    let crates = root().join("crates");
    let mut grown = Vec::new();
    for name in NODE_CRATES {
        let mut files = Vec::new();
        rust_files(&crates.join(name).join("src"), &mut files);
        for file in files {
            let rel = file.strip_prefix(&crates).unwrap().display().to_string();
            let n = spawns(&std::fs::read_to_string(&file).unwrap());
            let allowed = CRATE_SPAWNS
                .iter()
                .find(|(f, _)| *f == rel)
                .map_or(0, |(_, n)| *n);
            if n > allowed {
                grown.push(format!("{rel}: {n} (at most {allowed})"));
            }
        }
    }
    assert!(
        grown.is_empty(),
        "start it through a named, supervised task: {grown:?}"
    );
}
