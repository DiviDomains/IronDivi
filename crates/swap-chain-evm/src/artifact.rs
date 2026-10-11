// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Loads compiled bytecode out of the Foundry project at `contracts/htlc` for anvil
//! deployments in tests. The Foundry build (not a copy baked into this crate) is the
//! single source of truth for contract bytecode, so it is run fresh rather than checked
//! in as a generated artifact.

use std::path::PathBuf;
use std::process::Command;

use divi_swap::SwapError;

type Result<T> = std::result::Result<T, SwapError>;

/// `contracts/htlc` relative to this crate.
fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/htlc")
}

/// True if `forge` and `anvil` are both on `PATH`.
pub fn foundry_available() -> bool {
    which("forge") && which("anvil")
}

fn which(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Deployment bytecode of `name` (e.g. `"Erc20Htlc"` or `"MockErc20"`), running
/// `forge build` in `contracts/htlc` first.
pub fn bytecode(name: &str) -> Result<Vec<u8>> {
    let dir = contracts_dir();
    let status = Command::new("forge")
        .arg("build")
        .current_dir(&dir)
        .status()
        .map_err(|e| SwapError::Other(format!("spawn forge build: {e}")))?;
    if !status.success() {
        return Err(SwapError::Other("forge build failed".into()));
    }
    let path = dir
        .join("out")
        .join(format!("{name}.sol"))
        .join(format!("{name}.json"));
    let body = std::fs::read_to_string(&path)
        .map_err(|e| SwapError::Other(format!("read {}: {e}", path.display())))?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| SwapError::Other(format!("parse {}: {e}", path.display())))?;
    let hex_str = json["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| SwapError::Other(format!("{} lacks bytecode.object", path.display())))?
        .trim_start_matches("0x");
    hex::decode(hex_str).map_err(|e| SwapError::Other(format!("bad bytecode hex: {e}")))
}
