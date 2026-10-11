// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Build-plan step 5b, remainder: live (read-only) connectivity to a public Monero
//! stagenet node, via `monero-simple-request-rpc`'s HTTP transport over
//! `monero-daemon-rpc`'s `MoneroDaemon<T>`. Gated behind the `live` feature, same
//! convention as `swap-chain-btc`/`swap-chain-divi`'s `#[cfg(feature = "live")] mod live`
//! (no `#[ignore]` needed — the feature gate alone keeps it out of a plain `cargo test`).
//!
//! Read-only only: no funds move from here. Funding the address
//! [`crate::monero_dkg`] derives, and proving an actual 2-of-2 cooperative spend, needs
//! stagenet mining time (permissionless but not instant) and is deliberately left for a
//! dedicated live pass — see `docs/plans/swap-poc/status/xmr.md`.

#[cfg(feature = "live")]
mod live {
    use monero_simple_request_rpc::SimpleRequestTransport;

    // Checked live 2026-10-11 against monero.fail's stagenet node list; node sets rotate,
    // so if this ever fails, check that list again before assuming a regression.
    const STAGENET_NODE: &str = "http://node.monerodevs.org:38089";

    /// The RPC client actually connects to a real public stagenet node and can read its
    /// chain state — proof this crate is "live-ready" (Bert's phrase) for step 5b's
    /// funding/spend work once that's scheduled, not just offline-mock-green.
    #[tokio::test]
    async fn connects_to_public_stagenet_node() {
        use monero_simple_request_rpc::prelude::ProvidesBlockchainMeta;

        let daemon = SimpleRequestTransport::new(STAGENET_NODE.to_owned())
            .await
            .expect("stagenet node should be reachable");

        let height = daemon
            .latest_block_number()
            .await
            .expect("stagenet node should report its height");

        // Stagenet launched years ago; any live node is well past genesis.
        assert!(
            height > 1_000_000,
            "suspiciously low stagenet height: {height}"
        );
    }
}
