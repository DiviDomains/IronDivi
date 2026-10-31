// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! What the parent learned in B1, handed to every collector on its stdin.
//! It holds the per-run salt and the private values the redactor needs, so
//! it only ever travels over the pipe and is never written to a file.

use crate::redact::{Known, Redactor};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Node {
    pub pid: u32,
    pub uid: Option<u32>,
    /// `stat` field 22 (clock ticks since boot); macOS: start seconds
    pub start: Option<u64>,
    /// raw argv; secrets in it are masked whenever it is printed
    pub argv: Vec<String>,
    pub exe: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub datadir: Option<PathBuf>,
    pub conf: Option<PathBuf>,
    /// how the data dir was found: "path record", "argv absolute",
    /// "argv relative + cwd", "default (no -datadir)", or why it is unknown
    pub datadir_source: String,
    /// A5 readability check: `io`/`environ` readable
    pub readable: bool,
    pub binary_sha256_record: Option<String>,
    /// not irondivid but another irondivi component (divi-swapd …)
    pub component: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DataDir {
    pub n: usize,
    /// the base directory (`--datadir`, or the default base)
    pub path: PathBuf,
    /// where chain data lives (`path`, or `path/testnet` …)
    pub chain: PathBuf,
    pub network: String,
    pub conf: Option<PathBuf>,
    pub owner: Option<u32>,
    pub readable: bool,
    pub read_error: Option<String>,
    pub running_pid: Option<u32>,
    pub found_by: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ctx {
    pub salt: String,
    pub known: Known,
    pub datadirs: Vec<DataDir>,
    pub nodes: Vec<Node>,
    pub mirror_roots: Vec<PathBuf>,
    pub looked_at: Vec<String>,
    pub offline: bool,
    pub out_dir: PathBuf,
    /// set by `--fsync-test` / B2.6 rule; collectors decide the rest
    pub allow_fsync: bool,
    pub cap_sys_ptrace: bool,
    pub invoked_as: String,
    /// B6.5 `--rpc` calls, already checked by the parent
    pub rpc: Vec<crate::collectors::rpc::Req>,
    /// the refused `--rpc` calls, one line each, for rpc/summary.txt
    pub rpc_refused: Vec<String>,
    /// the data dir whose node answers them
    pub rpc_datadir: Option<usize>,
}

impl Ctx {
    pub fn redactor(&self) -> Redactor {
        let mut salt = [0u8; 32];
        if let Ok(b) = hex::decode(&self.salt) {
            if b.len() == 32 {
                salt.copy_from_slice(&b);
            }
        }
        Redactor::new(salt, &self.known)
    }

    pub fn node_for(&self, d: &DataDir) -> Option<&Node> {
        d.running_pid.and_then(|p| self.nodes.iter().find(|n| n.pid == p))
    }

    /// Every irondivid pid (never the other components)
    pub fn node_pids(&self) -> Vec<u32> {
        self.nodes.iter().filter(|n| n.component.is_none()).map(|n| n.pid).collect()
    }
}
