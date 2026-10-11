# Lane ltc status

- done:
  - **Wave 1**: `crates/swap-chain-ltc` implements `LtcBackend: ChainBackend` over Esplora
    HTTP (`litecoinspace.org/testnet/api`), modeled on `swap-chain-btc`. `address.rs` for
    `tltc` bech32 (segwit v0) address encode/decode via the `bech32` crate directly, since
    `bitcoin::Address` only knows upstream `Network` variants. `chain()` returns `Chain::Ltc`.
  - **Wave 2**: wired the real `LtcBackend` into `bin/divi-swapd` (`[ltc]` config section,
    `live_ltc()`, both-direction offers in the deploy example) and `bin/divi-swap` CLI
    (`--ltc-key`, `CounterLive` enum generalizing `Balance`/`chain_balance` across btc/ltc).
    Mock e2e both directions confirmed (the engine lane's
    `bin/divi-swapd/tests/multichain.rs`, plus a dedicated `e2e_mock_ltc_{forward,reverse}_
    {happy,refund}` suite that landed concurrently from another lane — all still passing).
  - **Wave 3a**: live-readiness dry run, no funded key needed.
    `crates/swap-chain-ltc/examples/ltc_live_dry_run.rs` resolves the real primary Esplora
    endpoint and runs `LtcBackend::build_claim`/`build_refund` (production code, a synthetic
    outpoint, nothing broadcast); `tools/swap-poc/check-ltc-live.sh` wraps it. The dry run
    **found and fixed a real bug**: `build_funding_tx` panicked (integer underflow) for an
    address with *zero* UTXOs — `needed` was only computed inside the coin-selection loop,
    so an empty list left it at `0` and `total(0) < needed(0)` wrongly passed. Fixed by
    seeding `needed` from the zero-input fee estimate before the loop; regression test
    `funding_fails_cleanly_with_no_utxos_at_all`. **The identical pattern is almost
    certainly also in `swap-chain-btc`'s `tx.rs`** (copied from there in Wave 1) —
    orchestrator asked to relay to the btc lane.
  - **Funding-reuse decision (orchestrator, `64ae2a0`, `docs/plans/swap-poc/funding.md`)**:
    testnets reuse the existing `taker-btc`/`maker-btc` 1Password keys as the LTC keys too
    (no `maker-ltc`/`taker-ltc` items). Verified `LtcBackend`'s address derivation agrees
    with the table exactly — permanent regression
    `address::tests::ltc_funding_addresses_match_funding_doc`. No discrepancy found.
    Updated the deploy example and service unit: `[ltc].key` is `credential:maker-btc`
    (was the since-abandoned `credential:maker-ltc`); removed the service file's
    now-unnecessary commented `LoadCredential=maker-ltc` line (LTC reuses the
    already-loaded `maker-btc` credential — never needed its own).
  - **Wave 3b**: `tools/swap-poc/ltc-live.sh` — happy path + case C (both sides refund),
    forward (`divi-ltc-testnet`) and/or reverse (`ltc-divi-testnet`) direction, against a
    local `divi-swapd` with `[divi]`+`[btc]`+`[ltc]` configured. `--scenario
    happy|case-c|all` x `--direction forward|reverse|both` x `--backend live|mock`.
    `op://…` key refs only (the `*-btc` ones per the funding decision), never a raw hex key
    on this host. `--dry-run` runs `quote`+`accept` and stops before `lock` — provably no
    broadcast either side, since the maker only calls `build_funding` on
    `TakerLockConfirmed -> MakerLocked`, strictly after the taker's own lock (checked
    against `maker.rs`). Prints both funding addresses and the minimum tLTC needed,
    scaled to the selected scenario/direction count.
  - **Wave 3c** (this session): `crates/swap-chain-ltc/examples/ltc_send.rs` — a plain
    P2WPKH-to-P2WPKH send (no HTLC), to move funds directly between the two testnet
    wallets without a faucet. Key from env `SWAP_LTC_KEY_HEX` only (never argv, never
    printed); `--to <tltc1…> --sats <n> [--dry-run]`; `--dry-run` builds, signs and
    consensus-verifies the tx and prints `txid`/`raw` without calling `broadcast`.
    - New `crates/swap-chain-ltc/src/send.rs::build_send_tx`, sharing coin selection and
      signing with `tx.rs`'s HTLC funding path: refactored `tx.rs` to expose
      `select_coins`/`skeleton`/`p2wpkh_sign` as `pub(crate)` (previously `build_funding_tx`
      had its own copy of this logic inline) so both paths share the exact same
      (already-fixed) empty-UTXO handling, instead of risking the same underflow bug
      twice. `LtcBackend::build_send(to, sats)` wraps it with the real UTXO fetch.
    - Tested (mock, as asked — no Litecoin regtest reachable from this host): 5 pure unit
      tests on `build_send_tx` directly (builds+verifies, dust-change folding, dust-amount
      rejection, empty-UTXO rejection, same-address rejection) plus a wiremock-backed
      `tests.rs::backend_send_selects_coins_and_change` exercising the full async
      `LtcBackend::build_send` path (UTXO fetch → build → sign) the same way
      `funding_selects_coins_and_change` does for HTLC funding. Also smoke-tested live
      (read-only UTXO fetch) with a throwaway, unfunded key against the real
      litecoinspace.org API in `--dry-run`: correctly reported `InsufficientFunds` rather
      than crashing, confirming the live code path end-to-end short of having real funds.
    - `ltc-live.sh --direction reverse --dry-run` (and `--direction both`) verified again
      end-to-end on `--backend mock` after this refactor: still accepts, still stops before
      lock, daemons still tear down cleanly (no leaked process/port).
  - All of: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test` clean for `swap-chain-ltc` (33 tests, 2 `#[ignore]`), `divi-swapd`,
    `divi-swap-cli`. `tools/swap-poc/check-ltc.sh` and `check-ltc-live.sh` both PASS.
- running: nothing further queued. Next action is the orchestrator's: run the maker-funding
  send (`ltc_send.rs`, `op://…/taker-btc` → `tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz`,
  0.004 tLTC) from the Mac, then both directions' live commands below.
- left / next steps (both directions now unblocked once the send above confirms):
  ```sh
  # Sanity check first, either direction (no funds, no risk — stops before lock):
  tools/swap-poc/ltc-live.sh --backend live --direction forward --dry-run
  tools/swap-poc/ltc-live.sh --backend live --direction reverse --dry-run

  # Forward is funded now (taker 0.01 tLTC, confirmed tx be211c99…9285, block 4912514):
  tools/swap-poc/ltc-live.sh --backend live --direction forward   # happy + case-c, ~8h; background it

  # Reverse needs the maker send above to land first, then:
  tools/swap-poc/ltc-live.sh --backend live --direction reverse   # happy + case-c, ~8h; background it
  ```
  Taker/maker LTC key refs resolve automatically to
  `op://global_secret_store/IronDivi Swap POC - {taker,maker}-btc/password`.
  After both directions' happy+case-c runs confirm, paste `results.txt` txids into this
  file and `docs/plans/swap-poc/RESULTS.md` (orchestrator, per `multi-coin.md` wave 3).
  `live_fund_claim_refund` (`#[ignore] --features live`) is also runnable now with
  `SWAP_LTC_TEST_KEY_HEX` = the taker-btc key's hex — a third independent live-path check
  beyond what `ltc-live.sh` exercises through the daemon/CLI.
- decisions:
  - Primary Esplora endpoint `https://litecoinspace.org/testnet/api`; no independent public
    secondary mirror found. `esplora_endpoints("testnet")` returns a single-element vec.
  - `testnet_api_reachable`'s "known block" is the Litecoin testnet4 genesis hash
    (`4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0`) — an invariant.
  - `FeePolicy::default()` floor is 1 sat/vB (brief), vs. BTC's floor 2.
  - `bech32 = "0.11"` is a direct dependency of `swap-chain-ltc` (already pinned
    transitively via `bitcoin`, so no other crate's resolution changed).
  - daemon's `[divi]`+`[btc]` stay mandatory for `--backend live`; `[ltc]` is
    additive/optional. `MOCK_ONLY_CHAINS` keeps `Ltc` — `--backend mock` always simulates
    every counter chain the same way regardless of live-backend existence.
  - `ltc-live.sh`'s default `E2E_LTC_SATS=100000` (0.001 tLTC) matches the lane brief's
    live-amount ceiling; `+5000` litoshi fee buffer per run.
  - `ltc-live.sh` deliberately does **not** reuse the standalone `quote`+`accept` call for
    the non-dry-run path: `divi-swap run` performs its own quote+accept+lock+poll as one
    swap, so calling `accept` first and `run` second would create two separate (one
    abandoned) swaps.
  - `build_send_tx` rejects a destination equal to the sender's own address up front
    (before even looking at coins) and rejects non-P2WPKH (non-20-byte-program)
    destinations — this tool's only job is moving funds between P2WPKH wallets, not a
    general-purpose send.
  - `ltc_send.rs`'s key comes from `SWAP_LTC_KEY_HEX`, distinct from
    `SWAP_LTC_TEST_KEY_HEX` (the live HTLC test's var): deliberately different names so a
    shell history or env dump can't confuse "the key I'm about to move funds with" and
    "the key the long-running funded HTLC test reads".
- needs: orchestrator to relay the `build_funding_tx` empty-UTXO-list underflow pattern to
  the btc lane (`crates/swap-chain-btc/src/tx.rs` has the identical `needed`-seeding logic,
  copied from there in Wave 1) — not this lane's path to fix.
