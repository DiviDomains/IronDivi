// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `Erc20Htlc`'s compiled deployment bytecode, checked in so deploying it needs nothing
//! beyond this crate — no `forge`, no network fetch. Everywhere else in this crate
//! (`artifact::bytecode`) builds fresh via `forge build`, because hp2 has `forge` and a
//! fresh build is the stronger guarantee; this file exists specifically for machines that
//! don't (the orchestrator's Mac, running `examples/sepolia_ops.rs`).
//!
//! Regenerate after any change to `contracts/htlc/src/Erc20Htlc.sol`:
//! ```sh
//! cd contracts/htlc && forge build --force
//! python3 -c "import json; print(json.load(open('out/Erc20Htlc.sol/Erc20Htlc.json'))['bytecode']['object'])" \
//!   > ../../crates/swap-chain-evm/src/erc20_htlc_bytecode.hex
//! ```
//! `tests::embedded_bytecode_matches_a_fresh_forge_build` (hp2 only, skipped without
//! `forge`) catches drift between the two.

/// `0x`-prefixed deployment bytecode of `Erc20Htlc`, exactly as `forge build` emits it.
pub const ERC20_HTLC_BYTECODE_HEX: &str = include_str!("erc20_htlc_bytecode.hex");

/// Decoded deployment bytecode, ready for [`crate::deploy_contract`].
pub fn erc20_htlc_bytecode() -> Vec<u8> {
    hex::decode(ERC20_HTLC_BYTECODE_HEX.trim().trim_start_matches("0x"))
        .expect("erc20_htlc_bytecode.hex is valid hex (checked in, not user input)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{bytecode, foundry_available};

    #[test]
    fn embedded_bytecode_matches_a_fresh_forge_build() {
        if !foundry_available() {
            eprintln!("skipping: forge not found on PATH");
            return;
        }
        let fresh = bytecode("Erc20Htlc").expect("forge build Erc20Htlc");
        assert_eq!(
            erc20_htlc_bytecode(),
            fresh,
            "crates/swap-chain-evm/src/erc20_htlc_bytecode.hex is stale — regenerate it \
             (see this module's doc comment) after the Erc20Htlc.sol change that caused this"
        );
    }
}
