# Lane ltc status

- blocked-on-human: yes — fund the maker's LTC address so the reverse direction
  (`ltc-divi-testnet`) can run live. Exact ask: send testnet LTC (>= 0.0005 tLTC, ideally
  0.01 tLTC like the taker got) to `tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz`
  (`docs/plans/swap-poc/funding.md`, same key as `maker-btc`). The taker side
  (`tltc1qa826ffe73xnqsm64x6fvln7sl0zp3rgf5gnf3p`) is already funded (0.01 tLTC, confirmed
  tx `be211c99…9285`, block 4912514, orchestrator 2026-10-11) — the forward direction
  (`divi-ltc-testnet`) is runnable live now; nothing else in this lane is blocked.
- done:
  - **Wave 1**: `crates/swap-chain-ltc` implements `LtcBackend: ChainBackend` over Esplora
    HTTP (`litecoinspace.org/testnet/api`), modeled on `swap-chain-btc`. `address.rs` for
    `tltc` bech32 (segwit v0) address encode/decode via the `bech32` crate directly, since
    `bitcoin::Address` only knows upstream `Network` variants. `chain()` returns `Chain::Ltc`.
  - **Wave 2**: wired the real `LtcBackend` into `bin/divi-swapd` (`[ltc]` config section,
    `live_ltc()`, both-direction offers in the deploy example) and `bin/divi-swap` CLI
    (`--ltc-key`, `CounterLive` enum generalizing `Balance`/`chain_balance` across btc/ltc).
    Mock e2e both directions confirmed via the engine lane's
    `bin/divi-swapd/tests/multichain.rs`.
  - **Wave 3a**: live-readiness dry run, no funded key needed.
    `crates/swap-chain-ltc/examples/ltc_live_dry_run.rs` resolves the real primary Esplora
    endpoint and runs `LtcBackend::build_claim`/`build_refund` (production code, a synthetic
    outpoint, nothing broadcast); `tools/swap-poc/check-ltc-live.sh` wraps it. The dry run
    **found and fixed a real bug**: `build_funding_tx` panicked (integer underflow) for an
    address with *zero* UTXOs (not just too few sats) — `needed` was only computed inside
    the coin-selection loop, so an empty coin list left it at its `0` seed and
    `total(0) < needed(0)` wrongly passed. Fixed by seeding `needed` from the zero-input fee
    estimate before the loop; regression test `funding_fails_cleanly_with_no_utxos_at_all`.
    **The identical pattern is almost certainly also in `swap-chain-btc`'s `tx.rs`**
    (copied from there in Wave 1) — orchestrator asked to relay to the btc lane.
  - **Funding-reuse decision (orchestrator, `64ae2a0`, `docs/plans/swap-poc/funding.md`)**:
    testnets reuse the existing `taker-btc`/`maker-btc` 1Password keys as the LTC keys too
    (no `maker-ltc`/`taker-ltc` items). Verified `LtcBackend`'s address derivation agrees
    with the table exactly — added as a permanent regression,
    `address::tests::ltc_funding_addresses_match_funding_doc`, decoding each `tb1…` address
    from the table and re-encoding its witness program under HRP `tltc`, matching the listed
    `tltc1…` string. No discrepancy found; nothing to report beyond this confirmation.
    Updated the deploy example and service unit to match: `[ltc].key` is now
    `credential:maker-btc` (was the since-abandoned `credential:maker-ltc`); removed the
    service file's now-unnecessary commented `LoadCredential=maker-ltc` line (the orchestrator
    had already commented it out pending provisioning — now known it's never needed, since
    LTC reuses the already-loaded `maker-btc` credential).
  - **Wave 3b**: `tools/swap-poc/ltc-live.sh` — live-readiness driver modeled on
    `tools/swap-poc/e2e.sh` (the BTC rev-live/case-C driver), scoped to LTC:
    - Runs happy path and case C (both sides refund), in forward (`divi-ltc-testnet`, taker
      pays LTC) and/or reverse (`ltc-divi-testnet`, taker pays DIVI) direction, against a
      local `divi-swapd` with `[divi]`+`[btc]`+`[ltc]` sections (mirrors the daemon's
      unchanged `[divi]`+`[btc]`-mandatory baseline from Wave 2) and both offers configured.
    - `--scenario happy|case-c|all` (default all) x `--direction forward|reverse|both`
      (default both) x `--backend live|mock` (default live).
    - Keys: `op://…` references only, resolved by the binaries — never a raw hex key on
      this host. Per the funding decision, the LTC key refs are the `*-btc` ones (no new
      1Password items).
    - `--dry-run`: runs `quote` + `accept` (which is as far as `run` gets before `lock`)
      and stops — never calls `lock`. Safe unconditionally: the maker only calls
      `build_funding` on `TakerLockConfirmed -> MakerLocked` (`divi_swap::maker`'s staking
      invariant), strictly after the taker's own lock, so stopping before the taker ever
      locks means *neither* side has broadcast anything, confirmed by reading `maker.rs`.
    - Prints the two funding addresses and the minimum tLTC needed before doing anything
      else, scaled to how many selected runs will actually need taker vs. maker funds
      (e.g. `--direction forward` only prints the taker line, since only the taker leg
      spends LTC in that direction).
    - Exercised live (end-to-end, no mocking) in `--backend mock --dry-run`, both the
      default (all 4 scenario/direction combos) and a single-combo invocation: builds,
      starts a daemon per scenario, quotes, accepts, confirms no lock/broadcast, tears the
      daemon down cleanly between scenarios (verified no leaked process or listening port
      afterward).
  - All of: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test` clean for `swap-chain-ltc`, `divi-swapd`, `divi-swap-cli`.
    `tools/swap-poc/check-ltc.sh` and `check-ltc-live.sh` both PASS.
- running: nothing further queued; next step (live happy/case-c, forward direction) is the
  live command below, which needs the orchestrator's 1Password access — not runnable from
  hp2. Nothing else in this lane is pending.
- left / next steps:
  - **Runnable now (forward direction only funded)** — exact command, on the Mac:
    ```sh
    tools/swap-poc/ltc-live.sh --backend live --direction forward --dry-run   # sanity check first
    tools/swap-poc/ltc-live.sh --backend live --direction forward             # happy + case-c, ~8h total; background it
    ```
    Runs both `happy` and `case-c` (default `--scenario all`) against `divi-ltc-testnet`
    only; needs no `--scenario` flag unless only one is wanted. Taker LTC key resolves to
    `op://global_secret_store/IronDivi Swap POC - taker-btc/password` automatically.
  - **Blocked on maker funding** — once `tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz` holds
    coins, the reverse direction becomes runnable the same way:
    `tools/swap-poc/ltc-live.sh --backend live --direction reverse`.
  - After both directions' happy+case-c runs confirm, paste their `results.txt` txids into
    this file and `docs/plans/swap-poc/RESULTS.md` (orchestrator, per `multi-coin.md` wave 3).
  - `live_fund_claim_refund` (`#[ignore] --features live`, `crates/swap-chain-ltc`) is now
    also runnable with `SWAP_LTC_TEST_KEY_HEX` = the taker-btc key's hex (funded address);
    covers a third independent path (claim one HTLC, refund another) beyond what
    `ltc-live.sh` exercises through the daemon/CLI.
- decisions:
  - Primary Esplora endpoint `https://litecoinspace.org/testnet/api`; no independent public
    secondary mirror found. `esplora_endpoints("testnet")` returns a single-element vec;
    fallback/retry logic itself is covered by `esplora_falls_back_to_secondary`/
    `esplora_retries_on_429` against synthetic servers.
  - `testnet_api_reachable`'s "known block" is the Litecoin testnet4 genesis hash
    (`4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0`) — an invariant.
  - `FeePolicy::default()` floor is 1 sat/vB (brief), vs. BTC's floor 2.
  - `bech32 = "0.11"` is a direct dependency of `swap-chain-ltc` (already pinned
    transitively via `bitcoin`, so no other crate's resolution changed).
  - daemon's `[divi]`+`[btc]` stay mandatory for `--backend live`; `[ltc]` is
    additive/optional. `MOCK_ONLY_CHAINS` keeps `Ltc` — `--backend mock` always simulates
    every counter chain the same way regardless of live-backend existence.
  - `ltc-live.sh`'s default `E2E_LTC_SATS=100000` (0.001 tLTC) matches the lane brief's
    live-amount ceiling and `live_fund_claim_refund`'s `HTLC_SATS`; `+5000` litoshi fee
    buffer per run when computing the minimum funding to print.
  - `ltc-live.sh` deliberately does **not** reuse the standalone `quote`+`accept` call for
    the non-dry-run path: `divi-swap run` performs its own quote+accept+lock+poll as one
    swap, so calling `accept` first and then `run` would create two separate (one abandoned)
    swaps. Dry-run and full-run are separate code paths that happen to share the first two
    steps conceptually, not a shared swap id.
- needs: orchestrator to relay the `build_funding_tx` empty-UTXO-list underflow pattern to
  the btc lane (`crates/swap-chain-btc/src/tx.rs` has the identical `needed`-seeding logic,
  copied from there in Wave 1) — not this lane's path to fix.
