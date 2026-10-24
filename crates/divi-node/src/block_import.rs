// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Blocks imported at start from block files, as Divi Core imports
//! `bootstrap.dat` and `-loadblock` files (init.cpp:560-722): the file is
//! scanned for the network's message start, each record is a 4-byte size and
//! a block, and every block goes through the same checks as a block from a
//! peer.

use divi_crypto::compute_block_hash;
use divi_primitives::block::Block;
use divi_primitives::serialize::Decodable;
use divi_storage::{Chain, StorageError};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

/// Divi Core MAX_BLOCK_SIZE_CURRENT: a record larger than this is skipped
const MAX_BLOCK_SIZE: usize = 2_000_000;

/// The buffer is compacted once this much of it has been read past
const COMPACT_AT: usize = 8 * 1024 * 1024;

/// What an imported file gave
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportResult {
    /// Blocks accepted
    pub loaded: u32,
    /// Blocks whose parent was not known when they were read (skipped)
    pub out_of_order: u32,
    /// Blocks already stored (skipped)
    pub known: u32,
    /// Blocks refused by the checks
    pub refused: u32,
    /// Records that could not be read as a block
    pub unreadable: u32,
}

/// A file read through a window that grows as the scan needs more of it
struct Window {
    file: File,
    buf: Vec<u8>,
    /// File offset of buf[0]
    base: usize,
    eof: bool,
}

impl Window {
    /// Make `[from, from + len)` available if the file has it; false at the end
    fn have(&mut self, from: usize, len: usize) -> std::io::Result<bool> {
        if from > self.base + COMPACT_AT {
            self.buf.drain(..from - self.base);
            self.base = from;
        }
        while self.base + self.buf.len() < from + len && !self.eof {
            let mut chunk = vec![0u8; (1 << 20).max(len)];
            let n = self.file.read(&mut chunk)?;
            if n == 0 {
                self.eof = true;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
        Ok(self.base + self.buf.len() >= from + len)
    }

    fn slice(&self, from: usize, len: usize) -> &[u8] {
        &self.buf[from - self.base..from - self.base + len]
    }

    /// The offset of the next `byte` at or after `from`, reading on as needed
    fn find(&mut self, from: usize, byte: u8) -> std::io::Result<Option<usize>> {
        let mut at = from;
        loop {
            if !self.have(at, 1)? {
                return Ok(None);
            }
            let start = at - self.base;
            if let Some(i) = self.buf[start..].iter().position(|&b| b == byte) {
                return Ok(Some(at + i));
            }
            at = self.base + self.buf.len();
        }
    }
}

/// A refusal that stops the import of the file, as Divi Core stops on a
/// system error (`state.IsError()`, init.cpp:620-623): the node's own
/// storage failed, not the block
fn is_system_error(e: &StorageError) -> bool {
    matches!(
        e,
        StorageError::Database(_) | StorageError::Io(_) | StorageError::ChainState(_)
    )
}

/// Import the blocks of a block file into `chain`, as Divi Core's
/// LoadExternalBlockFile does (init.cpp:560-660) outside -reindex:
/// - scan for the network's message start; a record whose size is under 80
///   or over the largest block is skipped, and after any record that cannot
///   be read the scan goes on one byte further (a truncated or damaged file
///   gives the blocks before the damage; another network's file gives none)
/// - a block whose parent is not known is skipped (only -reindex keeps such
///   blocks for later)
/// - a block already stored is skipped
/// - any other block is checked and connected as a block from a peer; a
///   refused block is skipped, a storage failure stops the file
pub fn import_block_file(
    chain: &Chain,
    path: &Path,
    message_start: [u8; 4],
) -> std::io::Result<ImportResult> {
    let started = std::time::Instant::now();
    let mut window = Window {
        file: File::open(path)?,
        buf: Vec::new(),
        base: 0,
        eof: false,
    };
    let genesis = chain.params().genesis_hash;
    let mut result = ImportResult::default();
    let mut rewind = 0usize;
    // Locate each record header
    while let Some(at) = window.find(rewind, message_start[0])? {
        rewind = at + 1;
        if !window.have(at, 8)? {
            break; // no full header left
        }
        let header = window.slice(at, 8);
        if header[..4] != message_start {
            continue;
        }
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if !(80..=MAX_BLOCK_SIZE).contains(&size) {
            continue;
        }

        // Read the block, no further than its record's size
        let block_at = at + 8;
        let available = window.have(block_at, size)?;
        let len = if available {
            size
        } else {
            (window.base + window.buf.len()).saturating_sub(block_at)
        };
        let mut cursor = Cursor::new(window.slice(block_at, len));
        let block = match Block::decode(&mut cursor) {
            Ok(block) => block,
            Err(e) => {
                tracing::info!(
                    "Block import: record at offset {} of {} cannot be read: {}",
                    at,
                    path.display(),
                    e
                );
                result.unreadable += 1;
                continue;
            }
        };
        rewind = block_at + cursor.position() as usize;

        let hash = compute_block_hash(&block.header);
        if hash != genesis
            && chain
                .get_block_index(&block.header.prev_block)
                .map_err(std::io::Error::other)?
                .is_none()
        {
            tracing::debug!(
                "Block import: out of order block {}, parent {} not known",
                hash,
                block.header.prev_block
            );
            result.out_of_order += 1;
            continue;
        }
        if let Some(index) = chain
            .get_block_index(&hash)
            .map_err(std::io::Error::other)?
        {
            if chain
                .get_block(&hash)
                .map_err(std::io::Error::other)?
                .is_some()
            {
                result.known += 1;
                if hash != genesis && index.height % 1000 == 0 {
                    tracing::info!(
                        "Block import: already had block {} at height {}",
                        hash,
                        index.height
                    );
                }
                continue;
            }
        }
        match chain.accept_block(block) {
            Ok(_) => result.loaded += 1,
            Err(e) if is_system_error(&e) => {
                tracing::error!(
                    "Block import of {} stopped at block {}: {}",
                    path.display(),
                    hash,
                    e
                );
                break;
            }
            Err(e) => {
                tracing::info!("Block import: block {} refused: {}", hash, e);
                result.refused += 1;
            }
        }
    }
    if result.loaded > 0 {
        tracing::info!(
            "Loaded {} blocks from external file in {} ms",
            result.loaded,
            started.elapsed().as_millis()
        );
    }
    Ok(result)
}

/// Import `<data_dir>/bootstrap.dat`, then renamed to bootstrap.dat.old, and
/// then each `-loadblock` file in turn, as Divi Core does at start
/// (init.cpp:684-722). A file that cannot be opened is logged and passed.
pub fn import_at_start(
    chain: &Chain,
    data_dir: &Path,
    load_block: &[std::path::PathBuf],
    message_start: [u8; 4],
) -> ImportResult {
    let mut total = ImportResult::default();
    let mut add = |r: ImportResult| {
        total.loaded += r.loaded;
        total.out_of_order += r.out_of_order;
        total.known += r.known;
        total.refused += r.refused;
        total.unreadable += r.unreadable;
    };
    let bootstrap = data_dir.join("bootstrap.dat");
    if bootstrap.exists() {
        tracing::info!("Importing bootstrap.dat...");
        match import_block_file(chain, &bootstrap, message_start) {
            Ok(r) => {
                add(r);
                let old = data_dir.join("bootstrap.dat.old");
                if let Err(e) = std::fs::rename(&bootstrap, &old) {
                    tracing::warn!("Could not rename bootstrap.dat to bootstrap.dat.old: {}", e);
                }
            }
            Err(e) => tracing::warn!(
                "Warning: could not open bootstrap file {}: {}",
                bootstrap.display(),
                e
            ),
        }
    }
    for path in load_block {
        tracing::info!("Importing blocks file {}...", path.display());
        match import_block_file(chain, path, message_start) {
            Ok(r) => add(r),
            Err(e) => tracing::warn!(
                "Warning: could not open blocks file {}: {}",
                path.display(),
                e
            ),
        }
    }
    total
}
