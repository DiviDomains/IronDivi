# Lane ltc status

- done: `crates/swap-chain-ltc` implements `LtcBackend: ChainBackend` over Esplora HTTP
  (`litecoinspace.org/testnet/api`), modeled on `swap-chain-btc` (`tx.rs` copied verbatim —
  script/sighash/serialization are identical for Litecoin SegWit v0; `client.rs` copied
  verbatim — chain-agnostic Esplora client). New: `address.rs` for `tltc` bech32 (segwit v0)
  address encode/decode via the `bech32` crate directly, since `bitcoin::Address` only knows
  upstream `Network` variants (`bc`/`tb` HRPs), not Litecoin's `ltc`/`tltc`.
  `cargo fmt -p swap-chain-ltc -- --check`, `cargo clippy -p swap-chain-ltc --all-targets
  --all-features -- -D warnings`, `cargo test -p swap-chain-ltc --all-features` all green.
  All required tests present and passing, including `testnet_api_reachable` run live
  (`cargo test -p swap-chain-ltc --all-features -- --ignored testnet_api_reachable`): tip
  height ~4.9M, genesis hash at height 0 matches.
  `tools/swap-poc/check-ltc.sh` → PASS.
- running: nothing; idle until landed or redirected.
- left: `live_fund_claim_refund` (`#[ignore] --features live`) needs a funded Litecoin
  testnet address and env `SWAP_LTC_TEST_KEY_HEX` — orchestrator/Bert runs it from the Mac
  per lane rules (no secrets on hp2). Everything else in the brief is done.
- decisions:
  - Primary Esplora endpoint `https://litecoinspace.org/testnet/api` verified live
    2026-10-11 (`/blocks/tip/height` → 200, tip ~4.9M; `/v1/fees/recommended` → 200, all
    rates 1 sat/vB). No independent public secondary mirror of this API shape was found
    (checked bitaps, blockchair, sochain, blockcypher, atomicwallet, a `testnet4` path on
    the same host — none serve a working Esplora-compatible testnet LTC API).
    `esplora_falls_back_to_secondary` and `esplora_retries_on_429` exercise the fallback /
    retry logic itself against synthetic wiremock servers, so this is not a coverage gap;
    `esplora_endpoints("testnet")` returns a single-element vec. If a real secondary turns
    up later, add it there.
  - `testnet_api_reachable`'s "known block" is the Litecoin testnet4 genesis hash
    (`4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0`), fetched live from
    `/block-height/0` on the primary endpoint and hardcoded as the expected value — an
    invariant (genesis never changes), not a guess.
  - `FeePolicy::default()` floor is 1 sat/vB (brief: "Litecoin fees are sat/vB; floor 1"),
    vs. BTC's floor 2; `/v1/fees/recommended` is supported by litecoinspace.org and used the
    same way as the btc lane's mempool.space client.
  - `chain()` returns `Chain::Btc` (the engine has no `Chain::Ltc` variant yet — see needs
    below); documented in `lib.rs` doc comment so it's not mistaken for a real Bitcoin
    backend elsewhere.
  - `bech32 = "0.11"` added as a direct dependency (already pinned transitively via
    `bitcoin` in `Cargo.lock`, so this did not change any other crate's resolution) to reach
    `bech32::segwit::encode_v0/decode` directly with HRP `tltc`.
- needs: `Chain::Ltc` in `crates/divi-swap/src/types.rs` (orchestrator, wave 1e) so
  `LtcBackend::chain()` can return something real instead of borrowing `Chain::Btc`.
