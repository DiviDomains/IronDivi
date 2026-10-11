# Lane ltc status

- done:
  - **Wave 1**: `crates/swap-chain-ltc` implements `LtcBackend: ChainBackend` over Esplora
    HTTP (`litecoinspace.org/testnet/api`), modeled on `swap-chain-btc`. `address.rs` for
    `tltc` bech32 (segwit v0) address encode/decode via the `bech32` crate directly, since
    `bitcoin::Address` only knows upstream `Network` variants (`bc`/`tb` HRPs). `chain()`
    returns `Chain::Ltc` (real variant landed by the engine lane, `f273975`).
  - **Wave 2**: wired the real `LtcBackend` into `bin/divi-swapd` (`[ltc]` config section,
    `live_ltc()`, both-direction offers `divi-ltc-testnet`/`ltc-divi-testnet` in the deploy
    example) and `bin/divi-swap` CLI (`--ltc-key`, `CounterLive` enum generalizing
    `Balance`/`chain_balance` across btc/ltc). Mock e2e both directions confirmed via the
    engine lane's `bin/divi-swapd/tests/multichain.rs`. Landed `5159f29`; orchestrator
    follow-up `2d0f91f` commented out the deploy unit's `LoadCredential=maker-ltc` (no key
    provisioned yet) — expected, not something to undo.
  - **Wave 3** (this session): live-readiness dry run, no funded key needed.
    - New `crates/swap-chain-ltc/examples/ltc_live_dry_run.rs`: resolves the real primary
      Esplora endpoint (`tip_height`, `median_time_past`, and indirectly
      `/v1/fees/recommended` via `sat_per_vb`), then calls the production
      `LtcBackend::build_claim`/`build_refund` against a synthetic outpoint (claim/refund
      signing doesn't need the output to actually exist on-chain) and lets
      `verify_htlc_spend`'s consensus check run inside them — all signed, nothing
      broadcast. Uses `SWAP_LTC_TEST_KEY_HEX` if set (same var `live_fund_claim_refund`
      reads) else a fresh throwaway key. Also tries `build_funding` as a bonus: reports
      `InsufficientFunds` as the expected unfunded-address outcome rather than a failure, so
      once the key *is* funded this same run additionally proves a real funding tx builds
      and consensus-verifies (still not broadcasting) — at that point the only thing left is
      `cargo test -p swap-chain-ltc --features live -- --ignored live_fund_claim_refund`.
    - New `tools/swap-poc/check-ltc-live.sh`: thin wrapper, runs the example via `rcargo`,
      `pass`/`fail`/`finish` per `lib.sh` convention. **PASS**, run live against
      `litecoinspace.org/testnet/api` with both an unset and a set `SWAP_LTC_TEST_KEY_HEX`.
    - **Bug found and fixed by the dry run itself**: `build_funding_tx` in `tx.rs` panicked
      (`attempt to subtract with overflow`) for a coin list with *zero* UTXOs (not just too
      few sats) — a never-funded address, exactly what the dry run's throwaway key hits.
      Cause: `needed` was seeded to `0` and only updated inside the coin-selection loop; with
      zero coins the loop never runs, so the `total < needed` guard became `0 < 0` = false
      and fell through to `needed - amount` (`0 - amount`), underflowing. Fixed by seeding
      `needed` from the zero-input skeleton before the loop, so an empty coin list now
      correctly reports `InsufficientFunds`. Added regression test
      `funding_fails_cleanly_with_no_utxos_at_all` (mocked empty UTXO response).
      **This same bug pattern likely exists in `swap-chain-btc`'s `tx.rs`** (copied from
      there in Wave 1) — not this lane's path to fix; flagged for the orchestrator to relay
      to the btc lane.
  - All of: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test` clean for `swap-chain-ltc` (22 tests, 2 `#[ignore]`), `divi-swapd`,
    `divi-swap-cli`. `tools/swap-poc/check-ltc.sh` and `check-ltc-live.sh` both PASS.
- running: nothing; idle until landed or redirected.
- left: `live_fund_claim_refund` (`#[ignore] --features live`) needs a funded Litecoin
  testnet address and env `SWAP_LTC_TEST_KEY_HEX`; the daemon's `[ltc]` section needs a real
  key and (if deployed) a provisioned credential — orchestrator/Bert, from the Mac, per lane
  rules (no secrets, no funded keys on hp2). `check-ltc-live.sh` makes that the *only*
  remaining step once funded.
- decisions:
  - Primary Esplora endpoint `https://litecoinspace.org/testnet/api`; no independent public
    secondary mirror found (checked bitaps, blockchair, sochain, blockcypher, atomicwallet,
    a `testnet4` path on the same host). `esplora_endpoints("testnet")` returns a
    single-element vec; fallback/retry logic itself is covered by
    `esplora_falls_back_to_secondary`/`esplora_retries_on_429` against synthetic servers.
  - `testnet_api_reachable`'s "known block" is the Litecoin testnet4 genesis hash
    (`4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0`) — an invariant.
  - `FeePolicy::default()` floor is 1 sat/vB (brief), vs. BTC's floor 2.
  - `bech32 = "0.11"` is a direct dependency of `swap-chain-ltc` (already pinned
    transitively via `bitcoin`, so no other crate's resolution changed) for
    `bech32::segwit::encode_v0/decode` with HRP `tltc`.
  - daemon's `[divi]`+`[btc]` stay mandatory for `--backend live`; `[ltc]` is
    additive/optional. `MOCK_ONLY_CHAINS` keeps `Ltc` — `--backend mock` always simulates
    every counter chain the same way regardless of live-backend existence.
  - The dry-run example builds/signs claim+refund against a **synthetic** outpoint rather
    than a real one: those two methods sign a spend of a given outpoint/amount and never
    query the chain for it (only `build_funding` and `htlc_output` do), so this is a faithful
    exercise of the production signing + consensus-verification path, not a shortcut.
- needs: orchestrator to relay the `build_funding_tx` empty-UTXO-list underflow pattern to
  the btc lane (`crates/swap-chain-btc/src/tx.rs` has the identical `needed`-seeding logic,
  copied from there in Wave 1) — not this lane's path to fix.
