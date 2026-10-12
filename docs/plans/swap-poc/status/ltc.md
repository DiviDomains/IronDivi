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
