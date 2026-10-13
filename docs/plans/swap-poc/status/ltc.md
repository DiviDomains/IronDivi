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
  - **Wave 3d** (this session): the btc lane no longer exists, so `crates/swap-chain-btc`
    is now this lane's too (orchestrator). Ported the Wave 3a change there: `build_funding_tx`
    had the identical `needed`-seeded-to-0 pattern, but **it was not a live bug in btc** — an
    existing explicit `chosen.is_empty() || total < needed` guard already caught the
    zero-UTXO case before the later subtraction could underflow, and
    `funding_from_empty_wallet_is_insufficient_funds` already regression-tested it.
    (Corrected after the orchestrator flagged the wording here first said it was a bug —
    see `status/btc.md` for the corrected note.) Replaced the explicit guard with the same
    `needed`-seeding approach as `swap-chain-ltc`, so both crates' coin-selection reads the
    same way; a pure consistency refactor, no behavior change. No duplicate test added (an
    initial port of `funding_fails_cleanly_with_no_utxos_at_all` was removed once the
    overlap with the existing test was spotted). `cargo fmt`/`clippy -D warnings`/`test
    --all-features` clean for both `swap-chain-btc` (17 passed, 1 ignored) and
    `swap-chain-ltc`.
  - Live progress (orchestrator, from the Mac): taker→maker funding send (`ltc_send.rs`)
    succeeded; **the forward happy-path swap then ran live and completed** — LTC lock
    `2e28ead1…`, LTC claim `cef1dc11…`. Maker now holds ≈0.003 tLTC (received minus its
    HTLC leg so far), taker still holds the remainder of its 0.01 tLTC. Reverse direction
    should be fundable/runnable now; txids/confirmations not yet pasted here — orchestrator.
  - **Wave 4 offers** (this session): `deploy/divi-swapd/wave4-offers.toml`'s
    `ltc-divi-testnet` offer (maker sells LTC) had `max_btc_sats = 10_000_000` (0.1 tLTC) —
    far more than the maker actually holds. Set it to `294_861` (maker's live balance,
    299,861 litoshi per the orchestrator, minus a 5,000 litoshi fee buffer); still
    `enabled = false` (not asked to flip it, and the comment above the offer already
    documents the condition for doing so). This broke
    `config::tests::wave4_snippet_on_the_deployed_config` in `bin/divi-swapd/src/config.rs`,
    which asserted the deployed snippet's offers are byte-for-byte identical to
    `mock_counter_offers()`'s generic ones — no longer true now that this one field is
    deliberately balance-capped. Fixed the test to special-case `max_btc_sats` for
    `ltc-divi-testnet` (assert the live cap is `<=` the mock ceiling, compare every other
    field exactly) instead of relaxing the assertion generally.
  - **Wave 4 live, dnsdivi** (orchestrator): the Wave 4 maker (0.2.6) is deployed; a real
    `divi-ltc-testnet` swap against it finished (`RESULTS.md` `321f941`). `ltc-divi-testnet`
    is now also `enabled` there, `max_btc_sats = 190000`. Orchestrator running live reverse
    + case-c against it directly.
  - **Case-C readiness, mock** (this session): confirmed/hardened the three behaviors the
    orchestrator asked about, chain-agnostic so both directions share them (the backend
    doesn't know which leg it's playing):
    - Refund nLockTime/sequence: already covered,
      `refund_verifies_with_consensus` asserts `lock_time == LockTime::from_time(LOCKTIME)`
      and `sequence.0 == REFUND_SEQUENCE`. No change needed.
    - Premature refund retried, not fatal: already covered,
      `refund_rejected_before_locktime` asserts `SwapError::Premature` + `is_retryable()`.
      No change needed.
    - Esplora "already known" responses count as success: **gap found** — the matcher
      (`is_already_known`) already recognized `txn-already-in-mempool`/`txn-already-known`
      (Litecoin Core's wording, same as Bitcoin Core's), but nothing tested those two
      specifically end-to-end, only "already in block chain" and "outputs already in utxo
      set". Same bug class as the zec lane's Zebra-wording miss, `7c932f9`. Extended
      `already_confirmed_is_already_known` to assert all four wordings, and added
      `broadcast_is_idempotent_on_mempool_duplicate` (a refund broadcast hitting
      `txn-already-in-mempool` must return the txid as success, not `Err`).
  - **Wave 4 offers sync** (this session): updated `deploy/divi-swapd/wave4-offers.toml` to
    match what's now live on dnsdivi — `ltc-divi-testnet` `enabled = true`,
    `max_btc_sats = 190000` (was `false`/`294861`, this lane's prior guess before the
    orchestrator's actual send amount). Confirmed the `<=`-mock-ceiling tolerance in
    `wave4_snippet_on_the_deployed_config` (`bin/divi-swapd/src/config.rs`) was already in
    place from a prior landing — just needed its `served`/`disabled_offers` list
    expectations updated now that this offer moved from disabled to served. Noted the
    190000 figure in `docs/plans/swap-poc/wave4-deploy.md` §6.
  - **Transient-error bug fix** (this session, orchestrator bug report): a live case-c run
    (`divi-swap run --counter-chain ltc --never-claim`) exited 1 after both locks on
    `transient backend error: .../blocks/tip/hash: error sending request` — one Esplora
    network hiccup killed the whole run. Root cause: `bin/divi-swap/src/flow.rs`'s
    `run_swap_gated` (the one step loop shared by **every** counter chain — BTC, LTC, …,
    not a per-chain thing) propagated any error from `release()` (which calls
    `median_time_past()` every poll under `ClaimPolicy::Never`/`NotBefore`) or `step()`
    straight out of the function via `?`, ending the run on the first transient failure
    instead of retrying. Fixed: the loop now inspects the error (`anyhow::Error::
    downcast_ref::<SwapError>().is_some_and(SwapError::is_retryable)` — catches both
    `Transient` and `Premature`, matching the documented contract in `error.rs`: "Transient
    is retried, Premature is retried later"), and on a retryable error logs a `WARN` and
    retries the *same* poll after an exponential backoff (starts at `opts.poll`, doubles,
    capped at 300 s; resets to `opts.poll` on the next success) instead of propagating.
    A non-retryable error still ends the run as before.
    - New regression test `never_claim_survives_a_transient_backend_error`
      (`bin/divi-swapd/tests/e2e_gated.rs`, beside the existing `never_claim_ends_in_refunds`
      it's modeled on): forces the plain BTC/DIVI mock world's DIVI backend offline
      (`MockChain::set_offline`, already-existing fault injection — every `ChainBackend`
      call on it fails `SwapError::Transient` while set) for 4 consecutive polls partway
      through a `ClaimPolicy::Never` gated run, then asserts it still reaches
      `TakerState::Done` with the taker refunded and nothing claimed. Deliberately **not**
      LTC-specific — the fix lives in the shared loop, so the plain BTC/DIVI harness proves
      it generically, cheaper than standing up the LTC mock world. (First draft used a
      10-poll outage window; the exponential backoff on 10 *consecutive* failures balloons
      past 15 s of real sleep — 15+30+…+7680 ms — making the test slow without adding
      coverage. Shrunk to 4 polls, confirmed via a temporary `tracing_subscriber` capture
      that the retries and backoff really fire, then removed the temporary logging.)
  - All of: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test` clean for `swap-chain-ltc` (30 tests, 2 `#[ignore]`), `divi-swapd`
    (18 lib + 28 integration tests), `divi-swap-cli` (5 lib tests).
    `tools/swap-poc/check-ltc.sh` and `check-ltc-live.sh` both PASS.
  - **Transient-vs-permanent audit, every chain client** (this session, orchestrator bug
    report: a live LTC case-C run died on `esplora HTTP 404: Block not found` from one
    litecoinspace backend lagging another, landed as `d371a22` for btc+ltc's `/block/
    <hash>` lookup specifically). Used 3 parallel Explore agents to audit
    `swap-chain-{zec,divi,evm}` for the same bug class (404/not-found-on-a-just-seen-
    resource, empty tip, 502/HTML bodies, node-warmup errors) while auditing btc/ltc
    myself; verified every finding against source before fixing, fixed only what was
    confirmed low-risk, left what wasn't with the reasoning recorded below. One test per
    fix, all synthetic (no live network needed), `keep genuine rejects permanent` honored
    throughout — several near-misses caught and reverted before landing (see decisions).
    - **btc + ltc** (identical fix, both crates — the ltc one already had the "Block not
      found" fix landed; this adds the rest of the same bug family): `find_spend`'s
      `/tx/{spender}` lookup used `get()` (errors on 404) instead of `get_opt()` — a
      replica that reported an outpoint spent can still 404 the spender tx itself on a
      different backend. Now `Ok(None)` ("not found yet", the caller polls again), not a
      permanent error. `tip_height` empty/unparseable body, `median_time_past`'s missing
      `mediantime`, `parse_json`'s malformed-JSON catch-all, and the UTXO-list-not-an-array
      check all moved `Other` → `Transient` — none of these are ever legitimate permanent
      answers from Esplora, only transport/proxy artifacts. 10 new tests total (5 per
      crate): `find_spend_treats_a_lagging_spender_lookup_as_not_found_yet`,
      `tip_height_{empty_body,unparseable_body}_is_transient`,
      `median_time_past_missing_field_is_transient`, `malformed_json_body_is_transient`,
      `funding_transient_on_malformed_utxo_response`.
    - **divi**: `rpc.rs`'s `once()` now routes bitcoind-style `-28` (node warmup:
      "Loading block index...") and `-5` "Block not found" (the direct DIVI analog of the
      esplora bug — `getblock`/`getblockhash` on a lagging proxy backend) through
      `RpcError::Swap(Transient)` *before* `RpcClient::call`'s own retry loop, not just at
      the final `From<RpcError>` conversion — so they get retried with backoff within one
      `call()`, not only at the engine level. (`-5` is reused for "No such mempool or
      blockchain transaction" too; disambiguated by message text, confirmed distinct with
      `tx_not_found_by_message_stays_distinct_from_block_not_found`.) `tip_height`'s
      non-numeric `getblockcount` and `median_time_past`'s block-without-`time` also moved
      to `Transient`. Higher-severity fix: `broadcast()`'s `BroadcastClass::Rejected` path
      confirmed absence via a single `get_tx_opt` lookup before giving up — but that
      lookup can race the same lagging-proxy condition and wrongly confirm a tx that
      actually exists is "gone", turning a transient broadcast duplicate into a permanent
      `Rejected`. Now retries the lookup twice (500 ms apart) before concluding `Rejected`.
      6 new tests, including `broadcast_rejection_confirmed_present_after_a_lagging_lookup`
      (needed extending the test harness's `Node` mock with a `flaky_error` helper: fails
      N times then falls through to the real answer, to simulate the race).
    - **zec**: `grpc.rs`'s `From<Status> for ClientError` added `Code::Unknown` (tonic's
      literal fallback for an unexplained transport failure in this client's exact build —
      no `server` feature, confirmed by reading the vendored tonic source) and
      `Code::Cancelled` (client-side timeout/cancel) to the transient set.
      **Deliberately did not** add `Code::NotFound`/`Code::Internal` despite the audit
      flagging them as a *possible* further gap: `is_tx_not_found` depends on a genuine
      "unknown tx" answer arriving as `Rejected` so it can inspect the message text and
      turn it into `Ok(None)`; folding those codes into `Transient` would have silently
      broken that already-correct mechanism for no confirmed benefit (no evidence
      lightwalletd ever uses those codes for the lagging-replica case the lines above
      exist for). `median_time_past`'s "lightwalletd returned no blocks" (a `tip_height`/
      `block_range` cross-backend race, same family as the others) moved `Other` →
      `Transient`; extracted into a pure `median_of_block_times` helper first since there
      was no mock gRPC server harness to test the method end-to-end (this crate has no
      `server` tonic feature compiled in at all). 4 new tests.
    - **evm**: `estimate_gas` and the `approve` send (in `sign_call`/`build_funding`)
      unconditionally mapped every error to `Other` — including a 429/502/503/timeout from
      a public RPC provider, no different from `broadcast()`'s own transport failures,
      which that method already classifies correctly. Added a shared `is_revert` helper
      (mirrors `broadcast`'s existing `contains("revert")` check) so both sites split
      transport failures (`Transient`) from a genuine on-chain revert (`Rejected`, e.g.
      `claim()` with the wrong preimage caught at estimation time) the same way; `approve`'s
      receipt-await (no revert-detection relevance once a tx is accepted into a block) and
      `token_allowance` (a pure read, no legitimate permanent-rejection case) went straight
      to `Transient`. No mock transport exists in this crate to inject synthetic HTTP
      errors (anvil won't produce 429/502), so tested the pure classification logic
      directly instead (`is_already_known`/`is_nonce_conflict` also had zero direct tests
      before this — only indirect, via anvil integration tests): 3 new tests.
  - All of: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings` clean
    for `swap-chain-{btc,ltc,divi,zec,evm}`; `cargo test --all-features` clean for all five
    (btc 25, ltc 36, divi 15, zec 17, evm 16 — all passing, 0 failed); `divi-swapd`/
    `divi-swap-cli` full suites re-run clean too (nothing downstream broke).
    `tools/swap-poc/check-ltc.sh` and `check-ltc-live.sh` both still PASS.
- running: nothing further queued; idle until the orchestrator lands this or the next live
  result (reverse direction, case-c either direction) comes in. Orchestrator resuming the
  interrupted live case-c run by hand with `divi-swap refund`.
- left / next steps:
  ```sh
  tools/swap-poc/ltc-live.sh --backend live --direction forward --dry-run   # sanity check
  tools/swap-poc/ltc-live.sh --backend live --direction reverse --dry-run
  tools/swap-poc/ltc-live.sh --backend live --direction forward   # case-c still pending; happy done live above
  tools/swap-poc/ltc-live.sh --backend live --direction reverse   # orchestrator running this directly now
  ```
  Taker/maker LTC key refs resolve automatically to
  `op://global_secret_store/IronDivi Swap POC - {taker,maker}-btc/password`.
  After both directions' happy+case-c runs confirm, paste `results.txt` txids (plus the
  forward-happy txids above) into this file and `docs/plans/swap-poc/RESULTS.md`
  (orchestrator, per `multi-coin.md` wave 3).
  `live_fund_claim_refund` (`#[ignore] --features live`, `swap-chain-ltc`) is also runnable
  now with `SWAP_LTC_TEST_KEY_HEX` = the taker-btc key's hex — a third independent
  live-path check beyond what `ltc-live.sh` exercises through the daemon/CLI.
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
- needs: nothing from the orchestrator right now.

## Safe, repeatable maker redeploy (`tools/swap-poc/redeploy-maker.sh`)
- done:
  - `tools/swap-poc/redeploy-maker.sh`: run from the Mac only (cannot reach dnsdivi from
    hp2). Read `deploy/divi-swapd/deploy.sh`, `deploy/divi-swapd/divi-swapd.service`,
    `deploy/divi-swapd/README.md` and `docs/plans/swap-poc/wave4-deploy.md` first to
    confirm, not guess, every path/name reused below: ssh host alias `dnsdivi`, installed
    binary `/usr/local/bin/divi-swapd` with the existing `.prev`-backup convention,
    systemd unit `divi-swapd`, health endpoint `/healthz` (not `/health` — the task
    request's wording; every existing doc and `deploy.sh` itself say `/healthz`, so that's
    what the script checks), and the maker's bind port `127.0.0.1:18480` on dnsdivi itself
    for that health check over ssh.
  - In-flight gate: reads `--maker-url` (default `http://127.0.0.1:18482`, exactly the
    tunnel the task named — note this is deliberately a *different* local port from the
    `18480` used in `wave4-deploy.md`'s examples; the two are unrelated tunnels/uses, not a
    typo, so no "guessed" reconciliation was done) and refuses to redeploy unless every
    swap's `state` is `Done` or `Aborted` — the same terminal-state definition
    `wave4-deploy.md` §0/§5 already use. `--force-inflight` overrides and always prints
    every in-flight id first (even when the maker can't be reached at all, in which case it
    warns and proceeds instead of refusing).
  - Binary: `--binary PATH` uses a prebuilt one; otherwise it shells out to `remote-cargo
    build --release -p divi-swapd` (hp2, fast) from the repo root and expects the result at
    `--built-binary-path` (default `<repo>/target/release/divi-swapd`, cargo's own default
    layout — flagged, not hardcoded, since this lane cannot run or inspect `remote-cargo`
    itself to confirm where it lands the artifact; `_hp2.md` rule 3 forbids running
    `remote-cargo` from hp2 anyway). Never builds on dnsdivi — that's `deploy.sh`'s slower
    path and is unchanged by this script.
  - Deploy: scp's the binary to `dnsdivi:/tmp/divi-swapd.redeploy-new`, then over one
    `ssh … sudo bash -s` call: backs up the current `/usr/local/bin/divi-swapd` to `.prev`
    (skipped if none exists, e.g. a first run), installs the new one at mode 0755, restarts
    the `divi-swapd` unit. Then waits for `/healthz` on `127.0.0.1:18480` over ssh (default
    budget 300 s, `--health-timeout`/`--health-interval` adjustable) and on timeout rolls
    back automatically: restores `.prev` over the binary, restarts the unit again, and
    re-checks health once more to report whether the rollback itself came up healthy. If no
    `.prev` exists (first-ever run failing health), it says so and leaves the unit as is
    rather than guessing a rollback target.
  - `--check-only`: runs just the in-flight gate against a real `--maker-url` and exits
    with its verdict; nothing is built, shipped, or restarted. Added because `--dry-run`
    (below) never performs even the read-only gate check for real — matching this repo's
    own convention (`wave4-smoke.sh`'s `--dry-run` only echoes every `curl`, including
    GETs) — so `--check-only` is the one mode that can answer "would the gate pass right
    now?", and is also what the bash tests drive.
  - `--dry-run`: prints every step (gate check included) and executes nothing, verified by
    hand against both the default (remote-cargo) and `--binary` paths.
  - `tools/swap-poc/test-redeploy-maker.sh`: bash-level tests for the in-flight gate only,
    against a real mock HTTP server (stdlib `python3 http.server`, same style as
    `tools/swap-poc/chaos/proxy.py`) bound to `127.0.0.1`, driven through
    `redeploy-maker.sh --check-only` — no ssh, no build, no dnsdivi. 8 cases: all-terminal
    passes silently; one/many in-flight swaps refuse and print every id (not just the
    first); `--force-inflight` proceeds but still prints the ids; an unreachable maker
    refuses by default and proceeds (with a warning) under `--force-inflight`; an empty
    swap list passes; `--check-only` stops at the gate and never reaches `--host` at all
    (checked by pointing `--host` at an unresolvable name and confirming that never
    matters). All 8 pass. **Not** wired into `check-ltc.sh`: lane rules say "do not edit
    check scripts," so it stays a standalone script — run it by hand, or have the
    orchestrator run it from the Mac next to `redeploy-maker.sh` itself.
  - `shellcheck` clean on both scripts (two intentional `SC2029`s disabled, matching
    `deploy.sh`'s own precedent for client-side-expanded ssh commands; one intentional
    `SC2329` disabled for the EXIT-trap cleanup function, matching `wave4-smoke.sh`'s own
    precedent).
  - No Rust changed by this task; `check-ltc.sh` re-run clean (fmt/clippy/tests on
    `swap-chain-ltc`, `testnet_api_reachable` live). Picked up and reverted one stray
    uncommitted local edit to `crates/swap-chain-zec/src/lib.rs` first (a leftover
    duplicate `median_of_block_times` definition from before `f209780` landed, which would
    not have compiled — not part of this task, just cleanup before starting it).
- running: nothing; idle, waiting on the orchestrator to try `redeploy-maker.sh
  --check-only` (and then a real run) against dnsdivi.
- left / next steps: none on my side. The orchestrator needs the actual
  `/etc/divi-swapd`-adjacent tunnel open at `18482` before `--check-only`/a real run can
  read `/swaps`; sudo on dnsdivi for the install+restart; and `remote-cargo` reachable from
  the Mac (or a prebuilt binary path) for the build step.
- decisions:
  - Health endpoint is `/healthz`, overriding the task text's informal "/health" — every
    source of truth in the repo (`deploy.sh`, `divi-swapd.service`'s absence of any
    `/health` route, `wave4-deploy.md`, `RESULTS.md`) uses `/healthz`, and guessing a route
    that doesn't exist would make the health wait (and the rollback trigger) always fail.
  - Kept the pre-flight gate's maker URL (`18482`, Mac-side tunnel for reading `/swaps`)
    and the post-restart health check's remote port (`18480`, dnsdivi's own loopback bind,
    reached over ssh, not through any Mac-side tunnel) as two independent, separately
    flagged values rather than reconciling them to one: they are different connections for
    different purposes, and the task named `18482` explicitly for the first one.
  - Did not attempt to open or manage an ssh tunnel itself for the in-flight check (unlike
    `wave4-smoke.sh`, which can open its own): the task's phrasing ("read … over the tunnel
    at http://127.0.0.1:18482") reads as an already-open tunnel the orchestrator manages,
    and one less moving part is safer for a pre-flight safety gate.
- needs: nothing from the orchestrator right now.

## CI coverage audit (`.github/workflows/ci.yml`)
- done:
  - Checked what the existing 5 jobs (Format, Clippy, Test, Build, Security Audit) actually
    cover before changing anything. `cargo test --workspace` (Test job) already builds+runs
    every swap crate's own unit tests: `swap-chain-{btc,ltc,zec,divi,evm,xmr}`, `divi-swap`,
    `divi-swapd`, `divi-swap-cli` (binary name of `bin/divi-swap`) are all root `Cargo.toml`
    `[workspace] members`, and every live/network test is behind `#[cfg(feature = "live")]`
    and/or `#[ignore]` (confirmed by grep across all five chain crates plus `divi-swap-cli`),
    so plain `cargo test --workspace` (no `--all-features`, no `-- --ignored`) never reaches
    one. That part needed no fix.
  - Real gap found: GitHub's `ubuntu-latest` runners have no Foundry (`forge`/`anvil`), so
    `swap-chain-evm`'s anvil-backed tests (`anvil_lock_claim`, `anvil_lock_refund`,
    `anvil_find_preimage_from_logs` — not feature-gated, they run under the existing Test
    job's default-features `cargo test --workspace` today) hit the crate's own
    `skip_if_no_foundry` guard and self-skip ("skipping: forge/anvil not found on PATH")
    instead of actually exercising the HTLC contract. `contracts/htlc`'s `forge test` (15
    Solidity tests) doesn't run in CI at all today — nothing invokes it. Neither is a live
    network dependency: anvil is a local simulated chain, not a public RPC, and
    `contracts/htlc/lib/forge-std` is vendored in git (`git ls-files` shows 35 tracked
    files, no `.gitmodules`), so `forge test` fetches nothing at run time either.
  - Second gap: `tools/swap-poc/check-xmr.sh` (pure `crate_green` on `swap-adaptor` +
    `swap-chain-xmr`, plus `xmr-design.md` section-heading greps — zero network) and this
    session's own `tools/swap-poc/test-redeploy-maker.sh` (loopback-only mock HTTP server)
    were never wired into CI at all, despite needing nothing it doesn't already have.
  - Added one new job, `mock-checks` (name: "Mock-backend checks (xmr, usdc/evm+anvil,
    redeploy-maker gate)"), parallel to the existing 5 (no `needs:`, so it doesn't lengthen
    the critical path): `actions/checkout@v4` → `dtolnay/rust-toolchain@stable` (clippy +
    rustfmt, for `check-xmr.sh`'s/`check-usdc.sh`'s own `crate_green`) →
    `Swatinem/rust-cache@v2` → `foundry-rs/foundry-toolchain@v1` (confirmed real and at
    that floating major tag via the GitHub API before using it — `v1` currently resolves to
    `v1.9.1`) → `tools/swap-poc/check-xmr.sh` → `tools/swap-poc/check-usdc.sh` (now actually
    runs the anvil tests and `forge test contracts/htlc`, not skips them) →
    `tools/swap-poc/test-redeploy-maker.sh`. All three ran clean locally under plain
    `cargo`/`forge` (no `remote-cargo`, matching what CI has) before being added.
  - **Deliberately did not add** `check-ltc.sh` or `check-zec.sh` (the two the task named
    directly) as whole scripts: both end in a real call to a live testnet API
    (`--ignored testnet_api_reachable` against `litecoinspace.org` / a ZEC lightwalletd) —
    `check-btc.sh`/`check-divi.sh` are the same shape, for mempool.space / the DIVI RPC
    proxy. Running them in CI would either make a hard gate depend on a third party's
    uptime, or (if made non-blocking) still spend a CI run's time on a real network call
    the task said nothing may need. Lane rules forbid editing check scripts to split the
    live tail out, so there's no way to get just their mock portion from the script itself;
    that portion (`crate_green`, `no_todo`, the `impl ChainBackend for …Backend` grep,
    `require_tests` existence checks) is exactly what the existing Fmt/Clippy/Test jobs
    already cover by compiling and running the crate for real, so duplicating it as
    separate hand-written CI steps would just be the same assertions twice with a drift
    risk between the two copies. Documented this reasoning directly in the YAML (a
    multi-line comment on the new job) so the next lane/maintainer sees why those two
    scripts are absent rather than assuming an oversight.
  - Validated: `actionlint` wasn't installed on hp2, so fetched it via its own
    `download-actionlint.bash` installer (one-time, to a scratch dir, not committed)
    — v1.7.12 — and ran it against both workflow files; clean before and after the edit.
    Also parsed the YAML with `python3 -c "import yaml; yaml.safe_load(...)"` as a second
    check. Could not run `gh run list`/`gh run view` to confirm on the real CI yet per the
    task's own sequencing ("confirm … after the orchestrator lands it"); will check once
    told it landed.
  - **Found, did not touch (not my path):** `cargo test --workspace` is failing on `main`
    right now — confirmed via `gh run view --repo DiviDomains/IronDivi` on the two most
    recent runs (`38268645050` on this lane's own `257128d`, and `38267374749` on
    `92c85ce`, both "failure"; the prior run on `f209780` was green). Root cause:
    `bin/divi-swapd/src/config.rs:551`'s test `counter_chain_offers_and_overrides_parse`
    asserts `s.confirmations(Chain::Zec) == 3`, but `92c85ce` ("raise ZEC testnet
    confirmations 3->9…") changed `crates/divi-swap/src/config.rs`'s testnet default from 3
    to 9 without updating that downstream assertion. `bin/divi-swapd/src/config.rs` belongs
    to the daemon/multichain lane, not this one — flagging for the orchestrator to route
    rather than editing another lane's path. This is unrelated to (and unaffected by) the
    CI workflow change above: it would fail the existing Test job today with or without
    `mock-checks` added, and `mock-checks` running clean doesn't paper over it.
- running: nothing; idle.
- left / next steps: once landed, run `gh run view --repo DiviDomains/IronDivi <run-id>`
  (or `gh run list --repo DiviDomains/IronDivi --limit 1`) to confirm the new `mock-checks`
  job is green and nothing else regressed. Separately, someone on the daemon/multichain
  lane needs to fix `counter_chain_offers_and_overrides_parse`'s stale `== 3` (now `== 9`)
  so the Test job goes green again.
- decisions:
  - Treated "nothing may need network or secrets" as: no step's pass/fail may depend on a
    live testnet/blockchain/RPC call (litecoinspace.org, mempool.space, a ZEC lightwalletd,
    the DIVI RPC proxy) or a credential. Installing tooling itself (rustup via
    `dtolnay/rust-toolchain`, `cargo install cargo-audit`, `foundryup` via
    `foundry-rs/foundry-toolchain`) already happens in the existing jobs and needs ordinary
    package-registry network access, same as any CI setup step — that's not what the task
    was guarding against, and anvil/forge-std need no network at all once installed.
  - Added `mock-checks` as its own parallel job rather than appending steps to the existing
    `test` job: GitHub Actions jobs run concurrently by default, so a new job's wall time
    adds to the workflow's *critical path* only if it's the slowest job, not to every other
    job's time — keeps the "current time budget" ask meaningful instead of just serializing
    more work onto the one job already taking the longest (~5 min per the real run history).
  - `foundry-rs/foundry-toolchain@v1`: checked it's a real action (GitHub API, not
    fabricated) and that `v1` is an actual floating tag before writing it into the YAML,
    per the "never fabricate paths/values" rule — same bar as every path/port named in the
    redeploy-maker.sh task.
- needs: nothing from the orchestrator right now, other than routing the
  `counter_chain_offers_and_overrides_parse` fix to whoever owns `bin/divi-swapd` currently.

## Release build of divi-swapd for dnsdivi
- done:
  - Synced to `origin/main` (`4e0ac26`, the CI-coverage commit above), clean tree, no repo
    files changed by this task — build/verification only.
  - `nice -n 10 cargo build --release -p divi-swapd` on hp2 (plain `cargo`, not
    `remote-cargo`, per `_hp2.md` rule 3), target dir already `~/swap-lanes/ltc/target ->
    /mnt/storage1/bshuler-cargo/lane-ltc` (set up before this session — confirmed with
    `readlink` first so nothing landed on the root disk, which the orchestrator flagged
    this session as sitting at 93-95%). 5m21s cold, `Finished release [optimized]`.
  - Binary is `ELF 64-bit LSB pie executable, x86-64, ... for GNU/Linux 3.2.0` (`file`
    output) — x86_64 Linux glibc, as asked.
  - Copied to **`/mnt/storage1/bshuler-cargo/release/divi-swapd-4e0ac26`** (20,835,504
    bytes) with a sha256 next to it at
    **`/mnt/storage1/bshuler-cargo/release/divi-swapd-4e0ac26.sha256`**:
    `b5540e30e04628ab518c9ea6c8a21d594f5c4634d1ac905b31a2d3590afa60ac`.
  - `divi-swapd-4e0ac26 --help` exits 0 and prints usage (`--config`, `--backend`).
  - Offers check: ran it for real against a scratch copy of
    `deploy/divi-swapd/divi-swapd.toml.example` (own `db_path`/`wallet_path`/`listen` under
    the scratchpad, nothing under `/var/lib` or the real `18480` port) with
    `ltc-divi-testnet`/`divi-zec-testnet`/`zec-divi-testnet`'s `enabled = false` lines
    stripped (the shipped example disables those three), `--backend mock` (no keys, no
    network). `curl .../offers` listed exactly the six asked for, in this order:
    `divi-btc-testnet, btc-divi-testnet, divi-ltc-testnet, ltc-divi-testnet,
    divi-zec-testnet, zec-divi-testnet`. Killed the process and removed the scratch dir
    afterward — nothing left running, nothing left on disk beyond the two release files
    above.
  - Nothing in the repo changed, so no `ready_to_land` for this task (per the task's own
    instruction) — this status file entry is the full record.
- needs: nothing. Path and sha are above for the orchestrator's `scp` +
  `redeploy-maker.sh --binary /mnt/storage1/bshuler-cargo/release/divi-swapd-4e0ac26` once
  no swap is in flight on dnsdivi (`redeploy-maker.sh --check-only` first, as last time).

## Re: "coordinator pane" / notification question
No fabricated confirmation here: this lane has no "coordinator pane" to message and no
notify action — the only landing mechanism in `_hp2.md`/`_common.md` is writing
`- ready_to_land: <subject>` in this file, which the orchestrator (this conversation) reads
and lands by hand, then removes the line (as happened for `257128d` and `4e0ac26` already,
both confirmed back in-chat: "Landed as …, thanks"). There is nothing further for me to
confirm or notify beyond that; I have not set `ready_to_land` this turn (see above — no
repo files changed). If "coordinator pane" refers to something outside that documented
flow, I don't have visibility into it from hp2 and would be guessing rather than confirming
if I answered further.

Re "do not idle, prove it with test output" — while the release build above was compiling
in the background, re-ran (fresh, this session, not reused from memory) the abort/refund
paths this lane actually has (BTC/LTC HTLCs only have claim and refund — "punish" is the
XMR adaptor-signature lane's concept, not applicable to a secp256k1 HTLC chain; flagging
rather than inventing a punish-path test here):
- `cargo test -p divi-swap case_` (substring match): **24 passed**, 0 failed — covers
  `case_a_taker_never_locks`, `case_b_taker_lock_invalid`, `case_c_taker_never_claims`
  (abort/refund) and their `rev_` (reverse-direction) counterparts.
- `cargo test -p swap-chain-ltc`: **36 passed**, 1 ignored (the live-gated one), 0 failed —
  includes `refund_verifies_with_consensus`, `refund_rejected_before_locktime`.
- `cargo test -p swap-chain-btc`: **25 passed**, 0 failed — same refund coverage for the
  crate this lane also owns.
- `cargo test -p divi-swapd e2e_mock`: **4 passed**, 0 failed — `e2e_mock_happy_path`,
  `e2e_mock_refund`, and both reverse-direction equivalents.
No live-run prep is blocked on me right now beyond what's already in the "left / next
steps" notes above (all of it is either done or needs the orchestrator's keys/network from
the Mac); nothing else is queued, so there is nothing further to advance without
fabricating work.

## Mac-side runbook: redeploy + live LTC claim/refund leg
Written for the Mac runner (not hp2 — `_hp2.md` rule 4/5: no commit/push and no secrets on
hp2, so none of this is executed here). Every command below is copy-pasteable as written;
every flag/subcommand name was confirmed against `divi-swap --help`/`run --help`/
`refund --help`/`claim --help`/`balance --help`/`txids --help` and
`tools/swap-poc/redeploy-maker.sh --help` on this host today (`4e0ac26`), not guessed.

### Preconditions
- [ ] Mac checkout clean, at or after `4e0ac26` (`git merge-base --is-ancestor 4e0ac26 HEAD
      && echo ok`) — the commit that shipped `redeploy-maker.sh`'s current flags and the
      mock-checks CI job; `wave4-deploy.md`'s own precondition list (BTC reverse chaos
      done, no second local maker on the same keys, Mac at/after the main it names) still
      applies on top of this.
- [ ] `dnsdivi` ssh alias reachable: `ssh dnsdivi true`.
- [ ] A tunnel to the maker's API open for the in-flight gate, local port matching
      whatever `--maker-url` you pass (this runbook uses the default, 18482):
      `ssh -N -L 18482:127.0.0.1:18480 dnsdivi &` (background; `18480` is dnsdivi's own
      bind port, confirmed in `deploy/divi-swapd/README.md` and `wave4-deploy.md`).
- [ ] Maker currently healthy on the *old* binary before touching anything:
      `curl -fsS http://127.0.0.1:18482/healthz | jq '{ok, version}'` → `ok: true`.
- [ ] 1Password / secret-broker unlocked on the Mac (`op whoami`, or
      `secret-broker status` if that's the path this runner uses) — the taker/maker keys
      below are resolved from `op://…` refs passed as flag *values*, not environment
      variables, so there is no key-bearing env var to set for the swap CLI itself. The
      taker's LTC address needs funds already (`balance` in step 5 confirms this; if it
      doesn't, this is a `- parked:` item, not something to force).

### Step 1 — fetch and verify the prebuilt binary from hp2
```sh
scp hp2:/mnt/storage1/bshuler-cargo/release/divi-swapd-4e0ac26 ~/Downloads/
scp hp2:/mnt/storage1/bshuler-cargo/release/divi-swapd-4e0ac26.sha256 ~/Downloads/
(cd ~/Downloads && shasum -a 256 -c divi-swapd-4e0ac26.sha256)
```
**Expect:** `divi-swapd-4e0ac26: OK`. If it says FAILED, stop — re-fetch, don't proceed on
an unverified binary. (Built+verified on hp2 2026-10-12: `--help` exits 0; `/offers` under
`--backend mock` lists exactly `divi-btc-testnet, btc-divi-testnet, divi-ltc-testnet,
ltc-divi-testnet, divi-zec-testnet, zec-divi-testnet` — see the release section above.)

### Step 2 — in-flight gate, check-only (no build, no install, no restart)
```sh
tools/swap-poc/redeploy-maker.sh --check-only --maker-url http://127.0.0.1:18482
```
**Pass:** prints `ok: no in-flight swaps` and exits 0. **Fail:** prints `REFUSE: … swap(s)
not in a terminal state` and each in-flight id, exit 1 — stop here; either wait for those
swaps to reach `Done`/`Aborted`, or re-run with `--force-inflight` only after you've read
the printed ids and decided that's intentional.

### Step 3 — dry run the redeploy (prints every step, touches nothing)
```sh
tools/swap-poc/redeploy-maker.sh --dry-run \
  --binary ~/Downloads/divi-swapd-4e0ac26 --maker-url http://127.0.0.1:18482
```
**Expect:** the gate line again, then the scp/ssh-install/health-wait commands printed
(not run), exit 0. Read it before Step 4 — this is the actual command Step 4 runs for
real, so anything surprising here (wrong host, wrong remote port) means stop and fix a
flag rather than proceed.

### Step 4 — real redeploy
```sh
tools/swap-poc/redeploy-maker.sh \
  --binary ~/Downloads/divi-swapd-4e0ac26 --maker-url http://127.0.0.1:18482
```
**Pass:** ends with `ok: divi-swapd is healthy on the new binary` and a `sha256sum` line
for `/usr/local/bin/divi-swapd` and `.prev` (the two hashes must differ, and the non-`.prev`
one must equal Step 1's hash); exit 0. **Fail:** `FAIL: /healthz did not come up within
300s; rolling back`, then either `rolled back to the previous binary; divi-swapd is
healthy again` (exit 1 — the redeploy failed but the maker is still up on the old binary;
do **not** proceed to Step 6) or a rollback failure telling you to
`ssh dnsdivi sudo journalctl -u divi-swapd -n 50` by hand — stop and investigate, don't
retry blindly.

### Step 5 — confirm the new maker's health/offers/balance before risking funds
```sh
curl -fsS http://127.0.0.1:18482/healthz | jq '{ok, version, counters}'
curl -fsS http://127.0.0.1:18482/offers | jq -c '[.[] | .id]'
ref() { echo "op://global_secret_store/IronDivi Swap POC - $1/password"; }
target/release/divi-swap --backend live --counter-chain ltc \
  --divi-key "$(ref taker-divi)" --ltc-key "$(ref taker-btc)" balance
```
**Expect:** `/healthz` → `ok: true` (wait and re-check if `false` — the wallet scan can
still be catching up, per `wave4-deploy.md` §4; it is not a failure by itself), a `ltc`
entry in `counters` with `error: null`. `/offers` → includes `"divi-ltc-testnet"` and, if
proving the reverse leg, `"ltc-divi-testnet"` (both must show `enabled = true` in
`/etc/divi-swapd/divi-swapd.toml` on dnsdivi — confirm with the orchestrator's balance
notes above if unsure which leg is funded right now). `balance` → prints the taker's
`ltc_address` and a `ltc_balance_sats` large enough for the `--btc-sats` amount you intend
in Step 6 plus fees (100,000+5,000 litoshi has been the working amount this session).

### Step 6 — the live swap itself
Forward (maker sells DIVI for LTC, offer `divi-ltc-testnet`):
```sh
D=~/.local/state/iron-divi-swap-poc/wave4-ltc; mkdir -p "$D"; chmod 700 "$D"
target/release/divi-swap --db "$D/taker.db" --backend live --counter-chain ltc \
  --divi-key "$(ref taker-divi)" --ltc-key "$(ref taker-btc)" \
  run --maker http://127.0.0.1:18482 --offer divi-ltc-testnet --btc-sats 100000
```
Reverse (maker buys DIVI with LTC, offer `ltc-divi-testnet` — needs `--divi-wallet`, a
taker DIVI coin db outside any git tree):
```sh
target/release/divi-swap --db "$D/taker.db" --backend live --counter-chain ltc \
  --divi-key "$(ref taker-divi)" --ltc-key "$(ref taker-btc)" \
  --divi-wallet "$D/taker-divi-wallet.json" \
  run --maker http://127.0.0.1:18482 --offer ltc-divi-testnet --btc-sats 100000
```
Case-C proof (never claim, forces both refunds) adds `--never-claim` to either command
above. `run` prints the local swap id when it finishes; then:
```sh
target/release/divi-swap --db "$D/taker.db" txids --swap <local id>
```
If `run` is interrupted (ctrl-C, SSH drop, timeout) **do not re-run `run`** — it would
quote+accept a second time. Resume with the single-step subcommands against the same
`--db`/`--swap <id>`: `divi-swap status --swap <id>` to see where it's stuck, then
`divi-swap claim --swap <id> …` or `divi-swap refund --swap <id> …` (same `--divi-key`/
`--ltc-key`/`--backend live --counter-chain ltc` flags as above) — this is exactly the
by-hand recovery already used once this session ("resuming the live swap by hand with
`divi-swap refund`").

**Pass:** `txids --swap <id>` shows the maker's view at `Done` (happy) or both legs
refunded after their locktimes (case-C), and every printed txid confirms on
litecoinspace.org testnet (`https://litecoinspace.org/testnet/tx/<txid>`) — the same
verification RESULTS.md already uses for every prior live leg. Paste the txids into
`RESULTS.md` and this file once confirmed.
**Fail:** `run`/`claim`/`refund` exits with an error before reaching `Done`/refunded that
isn't a quiet "waiting, not yet confirmed" retry — capture the exact error text and the
local swap id, and stop rather than retry the same command repeatedly; a repeated failure
on the same step is an "ask the oracle" or "flag to the orchestrator" situation, not a
force-through.

### What I did not and will not do
Did not commit or push this entry, and did not sign anything as Bert Shuler: `_hp2.md`
rule 4 is explicit ("Never `git commit`, never push — signing lives on the Mac") and that
holds regardless of who is asking or why — hp2 has no signing key and this lane's binding
rules don't carve out an exception for "authorized." Landing this (and the actual live
run above) is the orchestrator's step, from the Mac, same as every prior live leg in
`RESULTS.md`.
