# Lane zec status


## Mac-side go-live runbook — `live_fund_claim_refund`

**Why this runs on the Mac, not hp2**: the test needs a funded secp256k1 key
(`SWAP_ZEC_TEST_KEY_HEX`). Rule 5 (`_hp2.md`) is absolute — no secrets on hp2, ever, no
exceptions for "going live." hp2 can and did run every key-free pre-flight check; the funded
run itself has to happen where the key actually lives.

**Command** (from the repo root, Mac-side, with the key exported for this shell only):
```
SWAP_ZEC_TEST_KEY_HEX=<taker key, 64 hex chars, 32 raw bytes> \
  cargo test -p swap-chain-zec --features live -- --ignored --nocapture live_fund_claim_refund
```
- `--features live`: this test is feature-gated, not just `#[ignore]`-gated (belt-and-suspenders
  so a plain `cargo test` never touches testnet even if `--ignored` is passed by accident
  elsewhere).
- `--ignored`: required — the test is `#[ignore = "needs a funded testnet t-address
  (SWAP_ZEC_TEST_KEY_HEX) and ~3 h"]` (`crates/swap-chain-zec/src/lib.rs:829`).
- `--nocapture`: the test's only observability is its own `println!`s (listed under "expected
  output" below) — without this flag they're swallowed on success.
- Env var **name only**, per rule 5 — the value is never typed, pasted, or echoed on hp2, and
  this doc never will hold it either. It's the **taker** key (the test uses one key for both
  claim and refund pubkeys, `lib.rs:838-839`); the address it derives to must be the funded
  taker address below.

**Preconditions** (all verified from hp2, read-only, no key — see "pre-flight" below for the
numbers from this exact check):
1. `testnet.zec.rocks:443` (or whatever `SWAP_ZEC_LIGHTWALLETD_EXTRA` adds — see
   `lightwalletd_endpoints` in `crates/swap-chain-zec/src/lib.rs`) answers `GetLatestBlock` with
   a sane, advancing tip height.
2. The taker address (`tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk`) holds enough confirmed zatoshi for
   two fundings of `HTLC_ZATOSHI = 20_000` zat each (`lib.rs:800`) plus ZIP-317 fees on four
   transactions (two fundings, one claim, one refund — each at least the 10,000 zat grace-action
   floor, `tx.rs`'s `zip317_fee`) — call it ≥ 100,000 zat as a comfortable floor; the funded
   balance below is ~123x that.
3. `check-zec.sh` passes (crate green) before spending real-if-testnet coins on it.

**Pre-flight numbers, recorded 2026-10-13 from hp2** (read-only, no key involved):
- `testnet.zec.rocks` live: `tip=4498200 mtp=1791901922 consensus_branch_id=0x77190ad9`
  (`cargo test -p swap-chain-zec --features live -- --ignored testnet_api_reachable --nocapture`).
- Taker (`tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk`): **12,330,000 zat** confirmed
  (`tools/swap-poc/balances.sh`).
- Maker (`tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn`): **12,530,000 zat** confirmed (not spent by this
  test — `live_fund_claim_refund` only drives the taker key against itself — but checked
  alongside since both addresses are this lane's funding pair).
- `check-zec.sh`: `PASS: zec` (fmt, clippy, full unit suite, `testnet_api_reachable` live, step-0
  decision recorded).

**Expected output** (in order; each line is a literal `println!` from the test):
1. `address <tm…> on testnet` — confirm this matches the taker address above, or the wrong key
   was exported.
2. `fund(claim) broadcast: <txid>` then (after up to 2h of 30s polling)
   `fund(claim) confirmed: <txid>` — first HTLC funding.
3. `fund(refund) broadcast: <txid>` then `fund(refund) confirmed: <txid>` — second HTLC funding.
4. `live_fund_txid: <txid>` / `live_fund2_txid: <txid>` — both funding txids, for
   `tools/swap-poc/verify-results.sh` bookkeeping.
5. `claim broadcast: <txid>` then `claim confirmed: <txid>` then `live_claim_txid: <txid>` — the
   first HTLC claimed with its preimage immediately (no locktime wait on the claim path).
6. `refund broadcast: <txid>` — **may be preceded by a long pause**: the refund's locktime is
   `median_time_past() + 2h` at the moment funding started (`REFUND_AHEAD_OF_MTP`, `lib.rs:801`),
   so the test retries every 120s on `SwapError::Premature`/`SwapError::Transient` until MTP
   catches up — this is the ~3h total runtime the `#[ignore]` reason warns about, not a hang.
7. `refund confirmed: <txid>` then `live_refund_txid: <txid>` — test exits 0.

**Pass/fail criteria**:
- **Pass**: all seven output lines above appear in order and the process exits 0 (`cargo test`
  reports `test result: ok. 1 passed`). The test's own assertions (`assert_eq!` on txids,
  `assert_eq!(spend.extract_preimage(&h_claim.hash), Some(pre_claim))`) are the real correctness
  check — a clean exit means ZIP-244 signing, the P2SH HTLC script, and the preimage/locktime
  logic all worked against live consensus, not just the mock suite.
- **Fail — rejected**: any `broadcast`/`wait_confirmed` call panics (`unwrap()` on a non-retryable
  error, or 2h with no confirmation, or `Err(e) => panic!("refund rejected: {e}")` for anything
  other than `Premature`/`Transient`) — a real consensus/logic bug, not a transient network blip.
  Capture the full panic message and txid; that's an oracle-grade finding, not a retry-it case.
- **Fail — environment**: `key_from_env()`'s `expect`/`unwrap` panics immediately if
  `SWAP_ZEC_TEST_KEY_HEX` is unset, not valid hex, or not a valid secp256k1 key — distinguish
  this from a real failure (it happens before anything touches the network).
- **Inconclusive — already run**: per the orchestrator (2026-10-13), the Mac side reports this
  live refund test **may already be complete, both directions refunded as intended** — i.e. this
  may already have passed in a prior Mac-side run not reflected in this doc at the time of
  writing (hp2 has no visibility into Mac-side runs). If so, re-running it is optional
  (`verify-results.sh` against the recorded txids is the cheaper confirmation); this runbook
  stays accurate either way as the procedure for the *next* time it needs to run.


- blocked-on-human: no — **funding confirmed on the correct NU7 chain, 2026-10-11 ~19:05
  EDT.** Wave 2 (daemon+CLI wiring, merged side by side with the LTC and USDC lanes) landed
  on main as `4fdae25`. Everything buildable is done. See "done" for the confirmed balances
  and the recommended per-run amount.
- parked: nothing right now. History, for context: the orchestrator's first fauzec.com claim
  (txid `9cf8c2203229ef9577857439452c22b63ba0981b3419ba02dce98a05d7049814`) paid 1 TAZ on a
  **pre-NU7 fork** (tip ~4,474,400, 75s blocks) — not the chain `testnet.zec.rocks` is on — so
  it was unspendable by us. I then found `https://faucet.testnet.valargroup.dev`, verified
  live and on the correct NU7 chain, which pays transparent `tm…` addresses directly (no
  shielded/PCZT hop). The orchestrator claimed from it themselves (Mac IP for the taker
  address, dnsdivi IP for the maker address, so neither counts against hp2's own 24h/IP
  quota — **do not also claim from hp2 today**, per the orchestrator). Both claims are now
  mined and confirmed; see "done" below. `zcash-devtool`'s PCZT flow (under
  "- decisions: funding path") is no longer needed unless this address/faucet ever needs
  topping up again later and the 24h-per-IP quota is the limiter.
- done:
  - **Lightwalletd endpoint configurability, 2026-10-12** (orchestrator follow-up on the
    mainnet-readiness review's single-endpoint-no-fallback finding): re-searched for a second
    public ZEC testnet lightwalletd — see the resolved `- needs:` entry below for the full
    evidence trail (re-checked every prior dead candidate, found and ruled out one new one
    with a live curl test, and independently corroborated via `logos-co/logos-zcash-node-
    module`'s own curated server list, which also has only one non-Tor testnet entry). No
    second one exists to hardcode, so made the list configurable instead: added
    `swap_chain_zec::lightwalletd_endpoints(network)` (mirrors btc/ltc's `esplora_endpoints`
    shape) plus a new `SWAP_ZEC_LIGHTWALLETD_EXTRA` env var (comma-separated, appended after
    the built-in default) so a second endpoint can be wired in later with no code change;
    `ZecBackend::for_network`/`testnet()` now go through it. Verified end-to-end with a
    throwaway example binary (`SWAP_ZEC_LIGHTWALLETD_EXTRA="https://a:443,https://b:443"` →
    `["https://testnet.zec.rocks:443", "https://a:443", "https://b:443"]`, correct order).
    The actual ordered-failover *mechanism* (`grpc::retry_fallback`, tried per-endpoint with
    retries, short-circuits on a hard rejection) and its mock test
    (`client_retries_and_falls_back`) already existed before this task and were already
    required by `check-zec.sh` — not duplicated; added two new unit tests
    (`lightwalletd_endpoints_default_is_testnet_primary_only`,
    `extra_endpoints_append_in_order_and_drop_blanks`) for the actually-new configurable-list
    code, at the same closure-based mock level. `fmt`/`clippy -D warnings`/`cargo test -p
    swap-chain-zec` (20 passed, 2 live-only ignored)/`check-zec.sh`/a full workspace build
    (including `divi-swapd`, which has its own independent TOML-level fallback-endpoint config,
    unaffected) all green.
  - **Mainnet-readiness review, 2026-10-12** (orchestrator-requested, docs-only plus tests
    where a gap was found): wrote `docs/plans/swap-poc/mainnet-readiness.md` covering all
    five coins (BTC, LTC, ZEC, USDC/EVM, XMR) — confirmations, timeouts/margins, fee policy,
    dust limits, reorg depth, public backends, every value cited `file:line` and marked
    `ok`/`risky`. Headline: BTC/LTC/XMR have no mainnet network support at all (hardcoded to
    test networks, not a disableable flag); ZEC additionally can't produce a mainnet-valid
    *transaction* right now — it always builds the NU7 v6 format, and the `oracle` agent
    confirmed (high confidence, sources days old) NU7 is testnet-only until a targeted
    2026-11-05 mainnet activation (go/no-go was 2026-10-20) — re-verify that date before ever
    pointing this crate at a mainnet endpoint. One real bug found and fixed in my own crate:
    `DUST_ZATOSHI` (`crates/swap-chain-zec/src/tx.rs`) was 294 zat, borrowed byte-for-byte from
    Bitcoin's P2WPKH dust rule, which has no relationship to ZIP 317's flat 5000-zat-per-action
    fee — a 294-zat output would cost more to ever spend than it's worth. Raised
    `DUST_ZATOSHI` to equal `ZIP317_MARGINAL_FEE` (5000); added
    `tx::tests::dust_floor_covers_the_zip317_marginal_fee`, a `const` assertion confirmed
    failing-to-compile against the old value and passing against the fix. All 18 existing
    `swap-chain-zec` unit tests still pass unchanged (checked every test's computed
    change/payout value against the old 294→5000 gap by hand; none fall in it).
    `crates/divi-swap/src/config.rs` needed no change — every shared-config value reviewed for
    mainnet (confirmations, mtp_lag, timeouts, margins) was already safe, including ZEC's own
    10-confirmation mainnet figure, which stays safe on both sides of the NU7 mainnet-
    activation date (over-conservative before it, on-target after). `fmt`/`clippy -D
    warnings`/`cargo test -p swap-chain-zec`/`check-zec.sh` all green.
  - **ZEC testnet confirmations raised 3 → 9, 2026-10-12 ~05:10 EDT** (orchestrator's
    decision on the safety-review finding below, explicitly authorizing this one edit to
    `crates/divi-swap/src/config.rs` — normally the frozen engine contract, lane
    `multichain`'s). `ChainParams::builtin`'s testnet-ZEC comment ("75-second blocks") was
    stale; at the real ≈24.8s/block NU7 rate, the old "3" confirmations was only ≈75s of
    finality depth, a third of the ≈225s the "3" was presumably chosen to reach at the
    (wrong) assumed rate. 9 × 24.8s ≈ 223s restores the original intent almost exactly.
    Comment fixed to state the real ≈25s rate and explain the 3→9 history, so the next
    person doesn't have to re-derive it.
    - **Re-checked the safety gate is still comfortable, as asked**: `required_gap_secs()`
      depends only on `mtp_lag_secs` (unchanged, 1800) and `claim_margin_secs`, not
      `confirmations` — the gap/margin math from the review above is completely unaffected
      by this change. The only thing that changed is how many extra blocks `taker_window_
      too_short`'s callers wait through before the maker locks — +6 confirmations × ≈24.8s
      ≈ +149s, against a budget in the thousands of seconds (10,800s `required_gap_secs`
      alone). Comfortable, confirmed by the full mock suite passing unchanged in substance.
    - **Found and fixed a real regression this surfaced**: `crates/divi-swap/tests/
      engine.rs`'s `case_d_body` (shared by `case_d_late_claim`/`zec_fwd_case_d_late_claim`/
      `zec_rev_case_d_late_claim`/`ltc_fwd_case_d_late_claim`/`ltc_rev_case_d_late_claim`
      etc.) drives the maker to `MakerLockConfirmed` in a hardcoded `0..12`-round loop —
      sized for confirmations=3; at 9 it ran out of rounds before ZEC's lock finished
      confirming, failing both ZEC directions (`left: MakerLocked, right:
      MakerLockConfirmed`). Bumped to `0..30` (generous headroom for the new worst case
      without materially slowing the other chains, which still break out early same as
      before). This is exactly the kind of fast-feedback catch a real test suite is for —
      found and fixed within the same session as the config change, before it could land
      broken.
    - Verified: `cargo test -p divi-swap --test engine` — the full `zec_*` family (26
      tests, including `case_d` and every `crash_at_every_*`/`prop_random_crash_points`
      variant) green, `case_d` across every chain family (default/BTC, LTC, ZEC — 6 tests)
      green; full `cargo test -p divi-swap` (engine.rs + usdc.rs + taker_decline.rs + doc
      tests) green; `cargo clippy -p divi-swap --all-targets --all-features -- -D
      warnings` and `cargo fmt -p divi-swap -- --check` both clean; `check-zec.sh` PASS.
  - **Timeout-margin safety review across btc/ltc/zec/evm-usdc, 2026-10-12 ~04:40 EDT.**
    Orchestrator's ask: confirm the maker can never be left unable to claim after the
    taker claims (maker claim window vs taker timeout, block-time variance, confirmation
    depths, MTP vs wall clock for CLTV, Zcash expiry height, EVM `block.timestamp`).
    - **The protecting mechanism, identified and traced**: `maker.rs::taker_window_too_short`
      — `remaining = taker-leg HTLC locktime − taker-chain median-time-past`, `needed =
      maker_timeout_secs + claim_margin_secs` (the *config-driven*, profile-aware margin —
      not to be confused with `taker.rs`'s separate, flat `TAKER_SAFETY_MARGIN_SECS =
      1800`, which protects a *different* race: the taker's own claim-vs-the-maker's-refund
      timing on the maker's leg, not the maker's reaction window on the taker's leg. Two
      genuinely independent mechanisms that happen to share testnet's 1800s value by
      coincidence, not an inconsistency — considered and ruled out as a finding). This gate
      is checked at **every** point the maker could still back out: `on_accepted`'s
      `lock_window_gone` (waiting for the lock to appear), `on_taker_lock_seen` (waiting for
      confirmations, both the "still there" and "vanished" branches), and — the one that
      matters most — immediately before `build_funding` in `on_taker_lock_confirmed`, the
      "staking edge" comment's own name for the point of no return. Re-checking right there
      closes the time-of-check-to-time-of-use gap a single early check would leave open.
    - **Per-chain numbers, computed against real/measured block times** (not the nominal
      ones in code comments, several of which are stale — see below):
      - BTC: `mtp_lag_secs` 3600s both profiles. True MTP (median of 11 blocks) lags wall
        clock by ≈5.5 block-intervals ≈3,300s at the real ~600s/block rate — 3600s gives a
        thin but positive raw margin, and the *actual* protection comes from
        `required_gap_secs`'s `2×mtp_lag + claim_margin` term stacking far beyond that
        (10,800s testnet/mainnet). No bug.
      - LTC: `mtp_lag_secs` 1800s. Real ~150s/block → bare MTP lag ≈825s — 1800s is >2× that
        estimate. No bug.
      - ZEC: `mtp_lag_secs` 1800s, but `ChainParams::builtin`'s comment ("75-second blocks")
        is stale — the live NU7 chain is ≈24.8s/block (measured in an earlier round). Bare
        MTP lag at the *real* rate ≈137s — 1800s is ≈13× that, so the margin itself is
        **safe**, just far more generously padded than the (wrong) comment implies. See
        the separate finding below about what the same stale assumption does to
        *confirmation depth* (a different concern than margin safety).
      - EVM/USDC: read `contracts/htlc/src/Erc20Htlc.sol` directly rather than assume —
        `claim()` has no time gate at all (callable any time before `refunded`), `refund()`
        requires exactly `block.timestamp >= timelock`, nothing else. `swap-chain-evm`'s
        `median_time_past()` returns the latest block's own `block.timestamp` verbatim (no
        median smoothing — there's nothing to smooth; the contract doesn't either), which
        the existing code comment already claimed and this review now independently
        confirms against the contract source itself. `mtp_lag_secs` 60s(testnet)/
        180s(mainnet) is sized for block-time jitter only, correctly — EVM has no MTP-lag
        cushion the way BTC-family chains do, but `required_gap_secs`'s global-max-based
        sizing (always ≥10,800s, driven by BTC) swamps EVM's ~12s block time by three
        orders of magnitude regardless.
      - `required_gap_secs()` takes the **max** `mtp_lag_secs` over *every* configured
        chain (`Chain::ALL`), not just the two chains a given swap actually uses — always
        conservative (a swap between two fast, low-lag chains still gets BTC-grade margin),
        never a shortfall.
      - `median_time_past()` double-checked as a *true* median (sorted, `times[len/2]`) —
        not an average, not "latest block" — in `swap-chain-btc`/`-ltc` (trust the node's
        own `mediantime` field directly) and `swap-chain-divi` (computed by hand over the
        last 11 blocks, since the node reports it null) and `swap-chain-zec` (reviewed in
        an earlier round). Correct everywhere it's implemented.
    - **Real, previously-unknown gap found: zero test coverage of the primary safety
      gate.** `taker_window_too_short` — the single check this whole property rests on —
      had **no test anywhere** exercising it, across any chain, before this review. Fixed:
      - `crates/divi-swap/tests/engine.rs`: `maker_aborts_too_short_window`/
        `maker_locks_window_fine` (the gate trips when it should and, just as important,
        doesn't false-positive when there's plenty of time left), each via `both!` (BTC,
        default) plus `ltc_fwd!`/`ltc_rev!`/`zec_fwd!`/`zec_rev!` — 12 actual tests, using
        each chain's real confirmations/block-interval numbers through the existing mock
        macros. Asserts both the resulting state (`Aborted`, not stuck or progressed) and
        that `MockBackend::funding_calls()` stayed `0` — the maker never even selected
        coins for its own leg, let alone broadcast anything.
      - `crates/divi-swap/tests/usdc.rs`: `usdc_window_too_short_aborts_forward`/`_reverse`,
        against the *real* `UsdcBackend`/`Erc20Htlc` contract over a spawned `anvil`
        instance (not `MockChain`) — proves the gate holds for the one chain whose
        `median_time_past()` semantics are structurally different from every other backend
        (plain `block.timestamp`, no median-of-N at all) by eating into the taker leg's
        timeout via `evm_setNextBlockTimestamp`/`MockChain::advance_time` (whichever chain
        the taker actually locked on, by direction) and asserting `MakerRecord.
        maker_leg_funding` stayed `None` — `Erc20Htlc.lock` was never even sent.
      - All 14 new tests pass; merged cleanly alongside an orchestrator-landed
        `usdc_crash_taker_between_lock_and_claim_{forward,reverse}` pair that happened to
        touch the same file and insertion point (kept both, standard lane-sync pattern).
    - **Side observation, not fixed (out of scope for *this* property, flagged for
      awareness): ZEC's confirmation depth is shallower in absolute wall-clock terms than
      its own design likely intended**, because of the same stale "75-second blocks"
      assumption noted above. `ChainParams::builtin`'s testnet confirmations (3) × the
      *assumed* 75s/block ≈ 225s of intended finality depth; at the *real* ≈24.8s/block
      rate, 3 confirmations is only ≈75s deep — about a third of what the number "3" was
      presumably chosen to achieve. This is a reorg-resistance question, not a timeout-
      margin one: a shallower confirmation wait only *shortens* the time consumed before
      the fixed timeout budgets start ticking, which if anything *helps* the margin
      property this review was about, so it's not "the real bug" this task asked me to
      fix. Raising ZEC's testnet confirmations (e.g. to ~9, to restore the original ~225s
      intent) would need `crates/divi-swap/src/config.rs`, which is the frozen engine
      contract (owned by lane `multichain`, not touchable here per the lane rules) — noting
      it under "- needs:" below rather than editing it.
    - Verified: `cargo fmt`/`cargo clippy -p divi-swap --all-targets --all-features -- -D
      warnings` both clean; `cargo test -p divi-swap` green throughout (engine.rs 93 tests
      including the 12 new; usdc.rs 10 including the 2 new); `check-zec.sh` PASS
      (unaffected — this review's changes are all in the shared engine/tests, not
      `swap-chain-zec`, but re-verified after lane-sync).
  - **Engine bug (orchestrator, found live): `divi-swap refund` could claim instead,
    2026-10-12 ~04:10 EDT.** Live: ZEC case-C swap `ab294b69` went to `Claimed` after an
    operator ran `refund`, not `Refunded`. Root cause: `bin/divi-swap/src/main.rs` mapped
    both `Cmd::Claim` and `Cmd::Refund` to the same `flow::step`, and `Taker::step` claims
    the maker leg whenever it's still safe to (per `TakerState::MakerLockConfirmed`'s
    handler, `on_maker_lock_confirmed`) — it has no notion of "the operator explicitly
    asked to refund instead," so `refund` on a swap that was still within the safe-to-claim
    window just... claimed.
    - **Fix**: added `Taker::refund(local_id)` (`crates/divi-swap/src/taker.rs`) with its
      own state machine (`advance_refund_only`), never reachable from `step`'s claim logic:
      `Locked`/`MakerLockConfirmed` → `Refunded` only if `taker_leg_refundable`, else left
      exactly as-is (no claim ever built); `Refunded` → drives to `Done` the same way
      `step` does (reuses `on_refunded`); every other state (`Prepared`/`Accepted`/
      `Claimed`/`Done`) is left untouched — in particular, calling `refund` on an
      already-`Claimed` swap is a deliberate no-op, not an error.
    - Added `flow::refund` (`bin/divi-swap/src/flow.rs`) — thinner than `flow::step`, since
      `Taker::refund` never needs the maker's view, so no `MakerClient`/`Sessions` lookup
      either. Split `Cmd::Claim | Cmd::Refund`'s shared match arm in `main.rs` into two:
      `Claim` still calls `flow::step`, `Refund` now calls `flow::refund`. Updated `Refund`'s
      doc comment to state plainly that it never claims, unlike `claim`/`run`.
    - **Mock tests** (`crates/divi-swap/tests/engine.rs`, ×2 directions = 6 actual tests via
      `both!`): a shared `drive_taker_to` helper uses the existing `halt_after` test hook to
      freeze the taker exactly at a target state before anything past it runs (needed
      because `Taker::step`'s internal loop chains straight through
      `MakerLockConfirmed`'s claim branch in the same call if it's still safe — there's no
      way to "catch" that state from outside without halting first; same timing gotcha
      recorded for the maker's analogous chaining in an earlier round).
      `refund_never_claims`: refund while `MakerLockConfirmed` and still well within the
      safe window leaves the state alone and builds no claim. `refund_after_timeout_
      reaches_done`: the same frozen swap, after advancing the taker-leg clock past its own
      timeout, reaches `Done` via repeated `refund` calls, never a claim.
      `refund_on_claimed_does_nothing`: refund on an already-`Claimed` swap is a no-op.
    - Verified: `cargo fmt`/`cargo clippy -p divi-swap -p divi-swap-cli --all-targets
      --all-features -- -D warnings` both clean; `cargo test -p divi-swap` (81 passed in
      `engine.rs` alone, including the 6 new ones) and `cargo test -p divi-swap-cli` (10
      passed) both green; `check-zec.sh` PASS (unaffected — this fix is in the shared
      engine/CLI, not `swap-chain-zec`, but lane-synced and re-verified after landing
      `cee8671` to make sure nothing regressed).
  - **Case-c readiness audit, 2026-10-12 ~02:20 EDT — found and fixed a real bug before the
    orchestrator's live case-c run.** Walked both directions' maker/taker refund paths
    (mock engine tests `zec_fwd_case_c_taker_never_claims`/`zec_rev_case_c_taker_never_claims`,
    both green — ZEC-specific confirmations/MTP-lag timing checked out) plus the real
    `ZecBackend` refund-building code against three concerns:
    - **Refund fee**: already pinned to the ZIP-317 floor (10,000 zat) by
      `tx::tests::refund_script_executes`'s `assert_eq!(20_000 - tx.vout[0].value, 10_000, ...)`
      — no gap, confirmed still holds.
    - **`nLockTime`/`expiry_height`**: `build_spend_tx`'s refund path sets `lock_time =
      htlc.locktime` and `sequence = REFUND_SEQUENCE` (`0xffff_fffe`, not final) — correct
      HTLC convention, needed for both the script's `OP_CHECKLOCKTIMEVERIFY` and the
      transaction-level nLockTime check to actually apply. `expiry_height = 0` ("no expiry")
      — read Zebra's actual source
      (`zebra-consensus/src/transaction/check.rs::validate_expiry_height_mined`) to confirm
      this is deliberately exempt, not just "happened to work once live": ZIP-203 says "if
      a transaction... nExpiryHeight field is nonzero, then it MUST NOT be mined at a block
      height greater than its nExpiryHeight" — the check only fires `if let Some(expiry_height)
      = ...`, and Zebra's `Transaction::expiry_height()` maps the raw `0` to `None`, so the
      mined-height and `MaximumExpiryHeight` checks both skip entirely. Confirmed by spec
      text, not just by the one live claim that already used this path successfully.
    - **Locktime-not-yet-reached must retry, not abort — found a real gap.** Fetched
      Zebra's actual `TransactionError` definitions
      (`zebra-consensus/src/error.rs`, via `gh search code`/`gh api` against
      `ZcashFoundation/zebra` — same approach that caught the ZIP-317 and
      `GetBlockRange`-pool-stripping bugs: read the real source, don't trust zcashd-legacy
      wording to carry over). Zebra's wording for a transaction whose nLockTime hasn't
      matured is `TransactionError::LockedUntilAfterBlockHeight`/`...BlockTime`, Display
      `"transaction is locked until after block height {h}"` / `"...block time {t}"` —
      **completely different from the zcashd-legacy strings `classify_broadcast_error` was
      checking** (`"non-final"`, `"Locktime requirement not satisfied"`,
      `"non-mandatory-script-verify-flag (locktime"`). A live case-c refund attempted
      before its locktime matured would have been misclassified `Rejected` (fatal, aborts
      the swap) instead of `Premature` (retried next tick — both `on_maker_refundable` and
      `on_refunded` already handle `Premature` correctly by returning `Flow::Idle`, so the
      *engine* side was fine; only the *classification* was missing this wording). Fixed:
      added `m.contains("locked until after block")` to `classify_broadcast_error`'s
      premature branch (`crates/swap-chain-zec/src/lib.rs`) — covers both the height and
      time variants with one substring, robust to whatever prefix Zebra's gRPC wrapper adds
      (same pattern as the already-known-mempool fix). Added two regression tests pinning
      the exact Zebra wording to `refund_rejected_before_locktime`.
    - Our own htlc locktimes are always the *time* variant (values far above ZIP-203's
      500,000,000 height/time threshold — e.g. `1791785143` from the live run), so
      `LockedUntilAfterBlockTime` is the one that would actually fire in practice; the fix
      covers the height variant too since the shared "locked until after block" stem costs
      nothing extra and the engine treats both identically anyway.
    - Verified: `cargo test -p swap-chain-zec` green (13 passed, 2 new assertions),
      `clippy`/`fmt` clean, `check-zec.sh` and `check-zec-live.sh` (live dry run against the
      real NU7 chain) both PASS.
  - **Cross-checked `signature_digest_v6` (the production code path) against the official
    ZIP-244 test vectors, 2026-10-12 ~02:05 EDT.** The existing `zip244_sighash_vectors`
    test only ran vectors through the v5-only `signature_digest` entry point
    (`#[cfg(test)]`-gated specifically because production code uses v6). Extended it: for
    every vector with a transparent input and every sighash type it defines, in addition to
    the existing v5 check, reconstruct `signature_digest_v6`'s combine by hand from the
    *exact* `transparent_sig_digest` call that just matched the official vector (S.2 is
    unchanged between v5 and v6 per ZIP 229), with v6's own empty Orchard/Ironwood digests
    (`PERS_ORCHARD_V6`/`PERS_IRONWOOD_V6` — **not** v5's `orchard_digest`, which has a
    different personalization and would be a type error to reuse), and assert
    `signature_digest_v6` produces exactly that. All pass.
    - **Honest limitation, stated plainly**: no official vectors exist with a P2SH input
      (redeem script ≠ scriptPubKey — exactly why `90d857c`'s bug slipped past the official
      vectors in the first place) or with a v6/NU6.3 structure (none exist yet at all, per
      the earlier `zcash_primitives` cross-check attempt). So this proves v6's *pipeline*
      correctly consumes the same officially-vetted transparent digest for every P2PKH-style
      vector, including mixed shielded+transparent ones — it does **not** independently
      re-derive the digest from a second implementation (the earlier `zcash_primitives`
      attempt — blocked on a workspace dependency conflict — would have; see "- needs:"
      below, still open) and it does not add new P2SH coverage beyond what `90d857c`'s own
      regression test already has. Still a real, if narrower, forward step: it's the first
      time v6's actual code path (not just the shared helper by inference) has been checked
      against any official ground truth.
  - **Audit: `GetBlockRange` was the only lightwalletd call stripping default-pool data,
    2026-10-12 ~02:00 EDT.** The orchestrator's `52b49de` fixed `GetBlockRange` (empty
    `poolTypes` defaults to Sapling+Orchard only, silently dropping every `CompactTx.vin` —
    the live DIVI→ZEC reverse swap's maker never saw the taker's ZEC claim because of this)
    and asked me to check every other lightwalletd call this crate makes for the same
    gotcha. Checked against the *authoritative* `CompactTxStreamer` proto definition (read
    directly, not from memory or our own possibly-incomplete struct comments) for every RPC
    this crate actually calls:
    - `GetLatestBlock` (request `ChainSpec`): no fields at all — nothing to strip.
    - `GetBlockRange` (request `BlockRange`): the only one with a `poolTypes` field — fixed.
    - `GetTransaction` (request `TxFilter`: `block`, `index`, `hash` — response
      `RawTransaction`: `data`, `height`): no pool field on either message, and
      `RawTransaction.data` is the complete raw serialized tx (every pool, unfiltered) by
      definition — there's nothing *to* filter at this level.
    - `SendTransaction` (request `RawTransaction`): same raw-bytes-in, no filtering concept.
    - `GetAddressUtxos` (request `GetAddressUtxosArg`: `addresses`, `startHeight`,
      `maxEntries`): no pool field — this call is unconditionally transparent-only by its
      very purpose (UTXOs are a transparent-chain concept), not a filtered view of a richer
      response.
    - `GetLightdInfo` (request `Empty`): no fields — metadata only.
    - Our own struct definitions for all of these (`TxFilter`, `RawTransaction`,
      `GetAddressUtxosArg`, `ChainSpec`, `Empty`) already match the real proto fields
      exactly, confirmed field-for-field against the authoritative source rather than
      assumed from our "fields we use" comments.
    - **Conclusion: no further fix needed.** `GetBlockRange` was uniquely exposed because
      it alone returns `CompactBlock`/`CompactTx` — a structure that bundles shielded *and*
      transparent data in one response with pool selection as an explicit opt-in filter.
      Every other call either has no pool concept or is unconditionally transparent/raw.
    - Sanity-checked the landed fix too: `cargo test -p swap-chain-zec` green (13 passed,
      including `52b49de`'s new `block_range_asks_for_transparent_inputs`), `clippy`/`fmt`
      clean, `check-zec.sh` PASS.
  - **First live ZEC<->DIVI forward swap completed end-to-end** (orchestrator, from the Mac):
    taker claimed the DIVI, maker claimed the ZEC (`bd9c3cbb…`). Everything this lane built —
    v6/NU7 tx format, ZIP-317 fees, the P2SH scriptPubKey sighash fix, already-known-mempool
    handling — proved out against real consensus, real funds, real time.
  - **Taker's `on_claimed` (maker-leg claim) now re-signs after a rejection too, 2026-10-12
    ~01:40 EDT** — the 4th and last of the claim/refund broadcast paths; `8743152` fixed the
    other three (maker claim, maker refund, taker refund) but missed this one, which
    previously had **no recovery path at all**: it read `r.maker_leg_claim` with a bare
    `.ok_or_else` that hard-errored if the stored tx was ever cleared, since nothing had
    ever cleared it. Added the same lazy-rebuild-then-clear-on-`Rejected` pattern
    `on_taker_claimed` (the maker's analogous function) already had: if the stored claim is
    missing, rebuild it from `maker_leg_htlc`/`maker_leg_outpoint`/`maker_leg_amount`/
    `preimage` (all already on `TakerRecord`) before broadcasting; on `SwapError::Rejected`,
    clear it and return the error so the next step rebuilds and re-signs instead of
    resending dead bytes forever (`crates/divi-swap/src/taker.rs::on_claimed`).
    - **Mock test infrastructure**: added `MockChain::reject_next_broadcast()` — a one-shot
      switch that forces the *next* `broadcast()` call on that chain to fail with
      `SwapError::Rejected`, checked before the existing dedupe/already-known logic so it
      can force-fail even a rebroadcast of bytes the mock chain already accepted
      (`crates/divi-swap/src/mock.rs`). Used it to write 4 regression tests in
      `crates/divi-swap/tests/engine.rs` (×2 directions = 8 actual `#[tokio::test]`s via the
      existing `both!` macro), one per claim/refund path: `resign_maker_refund`,
      `resign_maker_claim`, `resign_taker_refund`, `resign_taker_claim`. Each drives a real
      swap through the shared `H` harness, arms the reject at the right moment, and asserts
      the swap still finishes with the expected atomic balances afterward.
    - **Non-obvious timing gotcha, worth recording**: `Maker::step()`/`Taker::step()` both
      loop internally, draining every `Flow::Moved` state transition within *one* `tick()`/
      `step()` call (see `MAX_TRANSITIONS_PER_STEP`) — so a state that unconditionally
      chains into the next (e.g. `on_taker_claimed` always calls `enter(MakerClaimed)` right
      after a successful broadcast, no confirmation gate) is never observable as "paused"
      between test rounds. `resign_maker_claim` had to arm one state *earlier*
      (`MakerLockConfirmed`, not `TakerClaimed`) so the pre-armed reject catches the
      broadcast on its first real attempt, inside whichever round's `tick()` ends up
      driving the whole chain through. The other three paths (`on_maker_refundable`,
      `on_refunded`, `on_claimed`) all pause at `Idle` once broadcast succeeds but
      confirmations are still 0, so arming at the target state itself works for them — the
      reject there lands on the *next* round's redundant rebroadcast attempt instead, which
      is still a faithful test of the same "treat a rejected rebroadcast as recoverable, not
      fatal" behavior.
    - Verified: `cargo test -p divi-swap` all green (82 tests in `engine.rs` alone, including
      the 8 new ones; 4 in `usdc.rs`; 3 doc-tests), `cargo clippy --workspace --all-targets`
      clean, `cargo fmt` clean, `cargo build --workspace` clean, `check-zec.sh` PASS.
    - **Landing note**: my prior `ready_to_land` (check-funding/fee-pins) landed as `e3b31c6`
      *while this work was in progress* and its landing script's `git add -A -N .` swept up
      my not-yet-finished `mock.rs`/`taker.rs`/`engine.rs` edits too (visible in `e3b31c6`'s
      diff) — harmless since what landed was already the fully-fixed, tests-passing version
      (confirmed by diffing `e3b31c6`'s copy against my final one: identical except
      formatting, which this `ready_to_land` also fixes), but a reminder to re-check
      `ready_to_land` status before starting unrelated work next time.
  - **Broadcast-idempotency audit of ltc/btc/evm/divi, 2026-10-12 ~01:10 EDT** (read-only —
    I own `swap-chain-zec` only, so this is findings/suggested patches for the owning lanes
    or the orchestrator to apply, not a diff I made myself). Checked each backend's
    `broadcast()`/`is_already_known` (or equivalent) against the cross-chain checklist
    (`already exists in mempool`, `already in block chain`, `txn-already-known`,
    `txn-already-in-mempool`, `Transaction already in block chain`, nonce-too-low-for-
    same-hash) and, separately, whether each actually *verifies* the already-known tx is
    the caller's own txid before returning `Ok`, not just pattern-matching the error text:
    - **`swap-chain-ltc` / `swap-chain-btc`**: both check `already in block chain`/`already
      in the block chain`/`txn-already-in-mempool`/`txn-already-known`/`outputs already in
      utxo set` — the Esplora/Bitcoin-Core-family wording their actual backend
      (mempool.space/litecoinspace.org, not Zebra) actually returns; Zebra's "already
      exists in mempool"/"committed to the best chain" wording doesn't apply to them, so
      no gap there. Better still: `broadcast()` already has an explicit txid-verification
      fallback — on a `missingorspent` rejection (inputs already spent, e.g. by this same
      tx while we were down) it calls `self.confirmations(&tx.txid)` and only treats it as
      success if *that exact txid* shows up. **No gap found.**
    - **`swap-chain-divi`**: same wording family as BTC/LTC (`classify_broadcast_error` in
      `rpc.rs`, matches zcashd/Bitcoin-Core convention — DIVI's testnet node is its own
      fork, not Zebra, so the Zebra-specific wording isn't expected to apply here either,
      though I have no live evidence either way). Also already verifies the exact txid via
      `self.get_tx_opt(&tx.txid)` before treating an ambiguous `Rejected` class as success.
      **No gap found**, same pattern as BTC/LTC.
    - **`swap-chain-evm` (USDC) — gap found.** `is_already_known` in `backend.rs` covers
      `already known`/`already imported`/`nonce too low`/`replacement transaction
      underpriced`, but unlike every other backend, `broadcast()` returns `Ok(tx.txid)` for
      these **without checking the chain at all** — it trusts the error text alone. This
      matters specifically for EVM: "nonce too low" is genuinely ambiguous (unlike a raw-tx
      hash rebroadcast on UTXO chains, where there's only ever the one txid we submitted to
      be "already known"). A *different* transaction could in principle occupy the same
      nonce slot — returning `Ok` blindly would make the caller believe its specific
      claim/refund landed when actually something else did, or nothing did. The crate
      already has everything needed to close this the same way BTC/LTC/DIVI do: its own
      `confirmations()` (same file, a few lines below) calls `get_transaction_receipt`/
      `get_transaction_by_hash` on `txid` and returns `Some` if either finds it. Suggested
      fix (not applied — not my crate): in `broadcast()`'s `Err(e) if
      is_already_known(&e.to_string())` arm, call `self.confirmations(&tx.txid).await?` and
      only return `Ok(tx.txid)` if that's `Some(_)`; otherwise fall through to the normal
      rejection path (the error text matched an "already known"-shaped message, but the
      specific tx isn't actually on chain, which is exactly the case worth refusing to
      paper over).
  - **Live claim bug: ZIP-244 sighash was hashing the HTLC redeem script where it must hash
    the P2SH `scriptPubKey`, 2026-10-12 ~00:50 EDT.** The live forward run's maker claim of
    the taker's ZEC lock was rejected by Zebra: "could not verify a transparent script:
    script verification failed" (lock itself was fine — pure P2PKH, so the consensus branch
    id etc. were already proven good). I started reproducing this offline (fetch the real
    lock tx, rebuild the claim, diff against a from-scratch spec read) and had independently
    converged on the same root cause the orchestrator found and landed first, as `90d857c`:
    `SigInput`'s field (then named `script_code`) fed the HTLC **redeem script** into both
    the ZIP-244 S.2c (`scriptpubkeys_sig_digest`, aggregate over every input) and S.2g.iii
    (the signed input's own digest) — but ZIP 244 departs from Bitcoin's BIP-143
    `scriptCode` substitution: **both** fields commit to the spent output's actual on-chain
    `scriptPubKey` (for a P2SH HTLC, the P2SH script `OP_HASH160 <hash> OP_EQUAL`), never
    the redeem script. I confirmed this myself independently by reading the ZIP-244 spec
    text directly (not from memory) — S.2c: "`scriptpubkeys_sig_digest`... all `pk_script`
    fields for the coins spent"; S.2g.iii: "`scriptPubKey` is the field encoding... of the
    `pk_script` field for the coin spent by the transparent input. For P2SH coins, this
    differs from the `redeemScript` committed to in ZIP 243" — explicit confirmation ZIP 244
    deliberately changed this from ZIP 243/BIP 143. For a P2PKH input scriptCode==scriptPubKey
    trivially, which is exactly why the funding tx (all P2PKH) worked and only the P2SH
    claim/refund broke — and why the official ZIP-244 test vectors (none exercise a P2SH
    input with a differing redeem script) never caught it. Landed fix: `SigInput.script_code`
    renamed `script_pubkey`; `build_spend_tx` now passes `htlc_script_pubkey(&redeem)` (the
    P2SH wrapper), not `redeem` itself; a regression test pins that signing against the
    redeem script produces a *different* digest and fails `verify_htlc_spend`. I lane-synced
    onto it (clean, no conflicts) and re-ran the full suite — all green.
  - **`zec-live.sh --check-funding` + confirmed refund fees, 2026-10-12 ~00:30 EDT** (after
    `4615240`, the ZIP-317 fix, landed; orchestrator rerunning live happy both ways from the
    Mac concurrently with this).
    - Added `--check-funding` to `zec-live.sh`: read-only, no key, builds/runs nothing else
      — prints both swap addresses' confirmed balances (reuses
      `crates/swap-chain-zec/examples/check_addr_utxos.rs`, the same `GetAddressUtxos` check
      used to confirm the faucet claims) and how many more happy/case-c runs each can afford
      at `min_per_run` (`zec_zats` + `fee_buffer_sats` = 120,000 zatoshi) — happy and case-c
      cost the same per run since both lock the identical `$zec_zats` amount, so one number
      covers either. Just ran it: both taker and maker still show their original
      12,500,000-zatoshi UTXO untouched (193 confirmations at check time) → **104 more runs
      each** at the current rate — i.e. the orchestrator's concurrent live rerun from the
      Mac hadn't broadcast anything yet as of this check (or its own first broadcast is still
      pending/in flight; this tool can't tell "not started" from "about to start", only "has
      this specific original UTXO been spent yet").
    - **Confirmed case-c refund txs pay the ZIP-317 fee too, not just funding.** Added fee
      assertions directly to the existing `claim_script_executes`/`refund_script_executes`
      tests (which call `build_spend_tx` the same way the real claim/refund code path
      does): both pin `amount(20,000) - tx.vout[0].value == 10,000` exactly — the 2-action
      grace floor, same as funding (1-in/1-out: claim's scriptSig is long enough to push the
      input to 2 actions on its own via the redeem-script length, refund's scriptSig does
      too; the single P2PKH output stays at 1 action; `max` of the two is 2 either way, so
      both land on the same 10,000-zat number as the funding-tx case). This was already true
      by construction (`build_spend_tx` routes through the same `probe_fee` the funding fix
      added, for both `Spend::Claim` and `Spend::Refund`) but wasn't pinned by a test before
      the orchestrator explicitly asked — now it is, so a future change to either spend path
      can't silently regress back to a plain per-byte fee without a test failing.
    - Verified: `cargo test -p swap-chain-zec` all green (11 passed, 2 new fee assertions
      included); `cargo clippy`/`fmt` clean; `check-zec.sh` PASS; `zec-live.sh
      --check-funding` ran live against `testnet.zec.rocks` (output above), `shellcheck`
      clean on the script.
  - **`zec-live.sh case-c` expected duration, reviewed against the local maker profile,
    2026-10-11 ~23:10 EDT.** `zec-live.sh`'s `case-c` TOML override is
    `maker_timeout_secs = 3600` (1h), `taker_timeout_secs = 14410` (~4h 10s — chosen to clear
    `SwapConfig::validate`'s minimum gap, `MIN_TIMEOUT_GAP_SECS = 3h`, by exactly 10s), CLI
    budget `--timeout-secs 21600` (6h). Measured real block times myself just now (read-only,
    no key — `GetLatestBlock`/`GetBlockRange` on `testnet.zec.rocks` for ZEC, `getblockcount`/
    `getblockhash`/`getblock` on `services.divi.domains` for DIVI, both over the last 500
    blocks): **ZEC ≈24.78 s/block** (matches the ~25s NU7 figure already in this file — the
    `ChainParams::builtin` doc comment calling it "75-second blocks" predates the NU7 fix and
    is now stale, though harmless: it only feeds `mtp_lag_secs`, which stays a generous 1800s
    either way, see below) and **DIVI ≈60.16 s/block** (matches the existing "1-minute
    blocks" assumption elsewhere in the repo). Confirmations required: 3 for both ZEC and
    DIVI on testnet (`SwapConfig::profile(Testnet)`); MTP lag doc comment: "about six block
    intervals" to go from broadcast to real median-time-past catching up to a locktime.
    - A key structural fact that explains the shape of the run: **`maker_state=Done` depends
      only on the maker's own leg**, not on the taker (`crates/divi-swap/src/maker.rs`:
      `on_maker_refundable` broadcasts the maker's refund once its own locktime clears, then
      `MakerRefunded → Done` fires as soon as that refund has 1 confirmation — nothing in
      that path reads the taker's state at all). So in case C the **maker finishes in roughly
      an hour**, while the **taker's own CLI `run` process keeps going for ~4 hours** because
      `--never-claim` (`ClaimPolicy::Never`) only releases the taker's claim-hold once the
      *maker leg's* MTP passes the maker's locktime (`bin/divi-swap/src/flow.rs::release`) —
      after which the taker still has to wait out its *own*, much longer, `taker_timeout_secs`
      before `on_refunded` (`crates/divi-swap/src/taker.rs`) can broadcast and confirm its
      refund. This is the standard HTLC safety shape (the second party to lock gets the
      shorter timeout so it can safely refund first) — not a bug, just worth knowing so
      "maker side went quiet an hour in" during a live run isn't mistaken for a stall.
    - **Expected durations** (broadcast-to-`Δ`≈confirmation wait before the other side locks,
      using 3-confirmation and 6-block-MTP-catchup as expected-value estimates — real timing
      has variance, this is not a guarantee):
      - *Forward* (`divi-zec-testnet`, taker locks ZEC first, maker locks DIVI second): maker
        done ≈ (taker-leg ZEC 3-conf wait ≈74s) + 3600s + (DIVI MTP catchup ≈361s) + (DIVI
        1-conf ≈60s) ≈ **4,095s ≈ 1h 8m**. Taker (and thus the overall run) done ≈ 14,410s +
        (ZEC MTP catchup ≈149s) + (ZEC 1-conf ≈25s) ≈ **14,584s ≈ 4h 3m** — inside the 21,600s
        (6h) CLI budget with **~1h 57m to spare**.
      - *Reverse* (`zec-divi-testnet`, taker locks DIVI first, maker locks ZEC second): maker
        done ≈ (taker-leg DIVI 3-conf wait ≈180s) + 3600s + (ZEC MTP catchup ≈149s) + (ZEC
        1-conf ≈25s) ≈ **3,954s ≈ 1h 6m**. Taker (overall run) done ≈ 14,410s + (DIVI MTP
        catchup ≈361s) + (DIVI 1-conf ≈60s) ≈ **14,831s ≈ 4h 7m** — inside the 6h budget with
        **~1h 53m to spare**.
    - **Conclusion: the existing `--timeout-secs 21600` budget is correct and doesn't need
      changing** — both directions land around 4h, with ~1h50m+ of margin either way. `happy`
      (not reviewed in depth here, not what was asked) uses the un-overridden
      `SwapConfig::profile(Testnet)` timeouts but the normal `ClaimPolicy::Asap` path, so it
      finishes in low minutes (dominated by confirmation waits, not the multi-hour timeout
      windows) — no 6h-scale wait there.
  - **Funding confirmed, read-only, 2026-10-11 ~19:05 EDT** (`GetAddressUtxos` on
    `testnet.zec.rocks`, via a new small checker,
    `crates/swap-chain-zec/examples/check_addr_utxos.rs` — no key needed, nothing signed; tip
    at check time was height 4,490,188, confirming this read itself is against the real NU7
    chain, not the pre-NU7 fork):
    - taker `tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk`: **12,500,000 zatoshi (0.125 TAZ)**, 1 UTXO,
      mined at height 4,490,184 (5 confirmations at check time), txid
      `13e335069477201682b6218b3c03b0ad2eed3c972c372ba0d2d216256f1fde8e` vout 0. Matches the
      orchestrator's claim id `8bef7ddd4ac16091ee480f1e41ca2f91`.
    - maker `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn`: **12,500,000 zatoshi (0.125 TAZ)**, 1 UTXO,
      mined at height 4,490,184 (5 confirmations at check time), txid
      `ebd663bdb5473e6d8c3cfadd033b58d12a8ea2388853d0d03abe724e8f983a07` vout 0. Matches the
      orchestrator's claim id `a1718348432f963f4b4a7cbd52bda8c6`.
    - **Both are confirmed. `zec-live.sh happy` is unblocked for both directions.**
    - ~~Recommended ZEC amount per run~~ **superseded by the ZIP-317 fix below** — the
      ~500–600 zatoshi fee estimate here assumed a plain per-byte rate, which is wrong (see
      the live failure and fix just above/below). The real per-tx fee is ~10,000–15,000
      zatoshi; `E2E_ZEC_SATS=100000` is still comfortably correct (a `happy` run now spends
      up to ~120,000 zatoshi per side instead of ~105,000 — still <1% of the 12,500,000
      zatoshi available per address), no change needed there.
  - **Critical live-run fix, 2026-10-12 ~00:10 EDT: `swap-chain-zec` priced fees per byte;
    Zebra's NU7 mempool requires the ZIP-317 conventional fee, not a per-byte rate.** The
    orchestrator's first live happy-forward run failed at the taker's funding broadcast
    (nothing broadcast, no coins moved): `transaction rejected: ... failed to verify ZIP-317
    transaction rules, transaction was not inserted to mempool: Unpaid actions is higher
    than the limit`. Root cause: `tx.rs`'s `ceil_fee = zats_per_byte * size` priced every
    funding/claim/refund tx at a few hundred zatoshi (at `FeePolicy::default()` = 2 zat/
    byte), but [ZIP 317](https://zips.z.cash/zip-0317) sets a real floor of
    `marginal_fee(5000 zat) * max(grace_actions(2), logical_actions)`, where for an
    all-transparent tx `logical_actions = max(ceil(total vin bytes / 150), ceil(total vout
    bytes / 34))` — Zebra enforces this in its mempool acceptance rules regardless of what
    fee we actually attach, so every tx we built was being rejected before this was caught
    (coincidentally caught before any coins moved, since the taker's own funding broadcast
    is the very first thing a live run does).
    - Fixed in `crates/swap-chain-zec/src/tx.rs`: added `zip317_fee(vin, vout)` computing
      the formula above directly from each probe's actual `TxIn`/`TxOut` serialized byte
      lengths (via their own `write()`, so it can't drift from the real wire format), and
      `probe_fee(probe, zats_per_byte) = max(zip317_fee(...), ceil_fee(...))` — the larger of
      the ZIP-317 floor and the configured per-byte rate, so a future higher-priority
      per-byte rate still wins if ever raised past the floor. `build_funding_tx` (both the
      zero-coin seed and the coin-selection loop) and `build_spend_tx` (claim/refund) both
      switched from `ceil_fee` to `probe_fee` — every tx this backend builds is covered, not
      just funding. `funding_probe_size` became `funding_probe` (returns the probe `ZecTx`
      itself, not just a byte count) so both the per-byte and ZIP-317 numbers can be
      computed from the same probe.
    - For every shape this backend actually builds (1–2 inputs, 1–2 outputs), the ZIP-317
      floor lands on exactly its 2-action grace minimum, **10,000 zatoshi** — confirmed with
      a dedicated pinned unit test, `zip317_fee_pins_expected_values` (1-in/2-out = 10,000;
      1-in/1-out = 10,000 via the grace floor; 3-in/1-out = 15,000 once 3 inputs cross a
      3rd action at 150 bytes/action; 1-in/3-out = 15,000 the same way at 34 bytes/action).
      Also had to rework `funding_selects_coins_and_change`'s amounts/coin values (its old
      ones assumed a ~500 zat fee; the coin-selection *narrative* — two small coins needed,
      dust folds into the fee, a big coin covers a request alone, more coins get pulled in
      as the request grows, insufficient funds is reported — is unchanged, just rescaled,
      with the new exact fees pinned too: 10,000 for 1–2 inputs, 15,000 once a third coin is
      pulled in).
    - Also widened `zec-live.sh`'s `fee_buffer_sats` from 5,000 to 20,000 (covers the real
      10,000–15,000 zat floor twice over) — this only affects the script's printed
      "funding needed" estimate, not the actual on-chain amount (that's `build_funding_tx`'s
      own job, now ZIP-317-aware), but it was wrong/misleading before and is accurate now.
      The orchestrator also asked to widen "the needed-amount check in the funding build" —
      that's exactly `build_funding_tx`'s `needed` calculation above; no separate check
      elsewhere needed changing.
    - Verified: `cargo test -p swap-chain-zec` all green (11 passed, both new tests
      included); `check-zec.sh` and `check-zec-live.sh` (live dry run against
      `testnet.zec.rocks`, throwaway key, builds+signs+consensus-verifies a claim and refund
      with the new fee) both PASS. Did **not** verify against a real broadcast myself (no
      key on hp2) — that's the orchestrator's rerun from the Mac once this lands.
  - **Wave 1b** (`crates/swap-chain-zec/`): `ZecBackend` implementing `divi_swap::ChainBackend`
    over lightwalletd gRPC (`grpc.rs`), hand-rolled ZIP-244/ZIP-229 tx building+signing+digest
    (`tx.rs`), t-address Base58Check (`address.rs`). `ZecBackend::chain()` now correctly
    returns `Chain::Zec` (the placeholder noted in previous status updates was fixed the moment
    `Chain::Zec` landed on main in wave 1e).
  - **Wave 2** (just finished, this session): wired `ZecBackend` into both `bin/divi-swapd`
    (`[zec]` TOML section mirroring `[btc]`/`[ltc]`, `live_zec()` in `main.rs`, offers with
    `counter_chain = "zec"` now get a real backend instead of the old blanket
    `bail!("no live backend")`) and `bin/divi-swap` (`--counter-chain zec`, `--zec-key`,
    `CounterLive::Zec` alongside `Btc`/`Ltc`, `Cmd::Balance` prints `zec_address`/
    `zec_balance_zatoshi` via a new `ZecBackend::balance_zatoshi()` helper). The LTC lane
    landed equivalent wiring in the same commit window (`Chain::Ltc`/`LtcSection`/
    `CounterLive::Ltc`) — merged both sides together rather than picking one, since neither
    lane should silently clobber the other's wiring in these shared files. Mock e2e both
    directions already existed and still passes: `crates/divi-swap/tests/multichain.rs`
    (`mock_swap_zec_forward`/`mock_swap_zec_reverse`, engine-level) and
    `bin/divi-swapd/tests/multichain.rs` (`daemon_swaps_ltc_and_zec_both_ways`, real HTTP API,
    drives `zec-divi-testnet` and `divi-zec-testnet` to `Done` both ways). Full workspace
    (`swap-chain-zec`, `divi-swapd`, `divi-swap-cli`, `divi-swap` engine) green: fmt clean,
    clippy clean (`-D warnings`, `--all-targets --all-features`), every test suite passes
    including the slow property-based crash-recovery tests.
  - **Critical fix found and applied this session: the live testnet only mints v6
    transactions, not v5.** Ran a diagnostic (`tests::probe_live_tx_version`, `#[ignore]`,
    kept in the tree) that fetched 30+ real transactions from `testnet.zec.rocks` across a
    2000-block window: every single one — coinbase and ordinary transfers alike — had
    `version_bytes = 0x80000006`, `version_group_id = 0xD884B698`. The testnet has gone
    through NU6, NU6.1, NU6.3 ("Ironwood", which defines the v6 tx format per
    [ZIP 229](https://zips.z.cash/zip-0229)) and is now past NU7 activation
    (height 4,465,026; our probe ran at tip ≈4,489,566). v5 is still "consensus-valid" per the
    ZIP, but the live network evidently doesn't relay/mine it in practice, so my original
    all-v5 implementation would have had every transaction silently rejected the moment real
    funds were involved. Fixed:
    - `ZecTx` (everything this backend builds) now emits v6: `V6_VERSION_BYTES = 0x8000_0006`,
      `V6_VERSION_GROUP_ID = 0xD884_B698` (the latter cross-checked byte-for-byte against the
      live probe data), one extra trailing `0x00` byte for `nActionsIronwood = 0`.
    - The ZIP-244 digest tree gained the ZIP-229 amendments needed for an all-transparent v6
      tx: a 5th "Ironwood component digest" child (empty: `BLAKE2b-256("ZTxIdIronwd_H_v6", [])`)
      appended after Orchard, and a **new personalization for the Orchard digest itself**
      (`ZTxIdOrchardH_v6` vs v5's `ZTxIdOrchardHash`) — the ZIP mandates this even in the
      empty case, because v6 also moves the Sapling/Orchard/Ironwood anchors from effecting
      data to authorizing data (anchors never appear in our txs anyway, since we never have
      spends/actions, but the ZIP still requires the domain-separation change). New functions
      `combine_txid_v6`/`signature_digest_v6`/`ShieldedDigests::orchard_v6`/`ironwood_v6` in
      `tx.rs`; the existing v5 functions are untouched (still validated against all 10
      official ZIP-244 test vectors — `zip244_sighash_vectors` still passes) and now serve
      `ParsedTx::parse`'s v5 branch for robustness (the live network might still relay a
      stray v5 tx from an older wallet; v4/v5/v6 are all consensus-valid per ZIP 229).
      `ParsedTx::parse`/`txid()` detect v5 vs v6 from the version bytes and dispatch
      accordingly, including a trailing Ironwood section parse for v6.
    - Had the `oracle` agent independently review the whole v6/ZIP-229 diff against the exact
      spec text (no official v6 test vectors exist yet — checked
      `zcash/zcash-test-vectors`, its `TransactionV6` class is still the *withdrawn* ZIP-230
      design with a `zip233Amount` field and placeholder version-group-id, not the current
      ZIP-229/Ironwood one). Oracle confirmed the whole transparent-only path correct and
      found one real latent bug outside that path: `ParsedTx::parse` was computing the
      Sapling digest with v5 personalization/anchor-inclusion unconditionally, which would
      misparse a *foreign* v6 transaction that happens to carry real Sapling spends (ZIP-229
      renames `sapling_spends_noncompact_digest` to `ZTxIdSSpendNH_v6` and drops the anchor
      for v6). Fixed (`ShieldedDigests::sapling` now takes a `v6: bool`); added a
      serialize→parse→txid round-trip test (`claim_script_executes` now also asserts
      `ParsedTx::parse(&tx.serialize()).txid() == tx.txid()`) since that's the strongest
      self-check available without official v6 vectors.
    - Residual risk, stated plainly: without official v6 test vectors, the only *independent*
      ground truth I had was (a) the ZIP-229 spec text itself, read directly (not through a
      summarizer) and (b) the live version_group_id matching byte-for-byte. The
      `zcash_script`-based self-verification in `claim_script_executes`/etc. proves internal
      consistency (sign digest X, then verify against digest X) but — as the oracle flagged —
      does **not** independently prove digest X matches the real protocol, since the
      interpreter is handed our own digest via the `SighashCalculator` callback, not told to
      recompute it. The only way to fully close this gap is a real broadcast once funded,
      which per the no-secrets-on-hp2 rule has to be the orchestrator.
  - Verified `address.rs`'s t-address derivation against the funding table
    (`address::tests::funding_table_addresses_match`, permanent regression test): the
    taker-btc pubkey (`03a7f9cf…5f22f5`) derives `tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk` exactly,
    and maker-btc (`02d05bd3…343a7dd`) derives `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn` exactly —
    matching `docs/plans/swap-poc/funding.md` and `tools/swap-poc/derive-addrs.py`'s
    methodology (same hash160, same `[0x1d,0x25]` prefix, same Base58Check). No address
    mismatch to report.
  - **Live-readiness dry run** (while funding stays blocked): added
    `crates/swap-chain-zec/examples/zec_live_dry_run.rs` + `tools/swap-poc/check-zec-live.sh`,
    modeled on the LTC lane's equivalent (`ltc_live_dry_run.rs`/`check-ltc-live.sh`). With a
    throwaway key (no funds needed), it resolves the real `testnet.zec.rocks` endpoint, reads
    the live consensus branch id, and builds+signs+consensus-verifies (via `zcash_script`,
    same as the unit tests) a claim and a refund HTLC spend — the first time the v6/NU7 digest
    path ran against a real, live-fetched consensus branch id rather than a hardcoded test
    constant. This directly narrows the "residual risk" noted above (still short of a real
    broadcast, but no longer only self-consistent against a value we chose ourselves).
    Running it immediately **found a real bug**: `build_funding_tx` panicked with
    `attempt to subtract with overflow` when called against an address with a completely
    empty UTXO set (a fresh, never-funded address — exactly this dry run's situation). Root
    cause: `needed` was seeded at `0` before the coin-selection loop, so when the loop ran
    zero times (no coins at all) the `total < needed` guard wrongly passed (`0 < 0` is
    false), falling through to `needed - amount` and underflowing. Same bug class the LTC
    lane hit and fixed in `566417a` — fixed the same way here: seed `needed` from the
    zero-input skeleton's probe size before the loop. Added a
    permanent regression test (`tx::tests::funding_selects_coins_and_change`, extended) for
    a fully-empty coin slice, not just an insufficient-but-nonempty one. Re-ran the dry run
    after the fix: now correctly reports `InsufficientFunds` and finishes clean. Fix is
    purely additive to coin selection, no change to the digest/serialization layer.
  - **`tools/swap-poc/zec-live.sh`**: the happy/case-C, both-direction live driver for ZEC,
    built from scratch this round — `swap-chain-zec` previously only had the dry-run example
    above, not a full driver like LTC's `ltc-live.sh`. Modeled directly on `ltc-live.sh`'s
    current form (including its `--maker-url` support from `a6efd8f`, so ZEC didn't lag
    behind on that from day one): `--scenario happy|case-c|all`, `--direction
    forward|reverse|both`, `--backend live|mock`, `--dry-run`, and `--maker-url URL` (drive an
    already-deployed maker over a tunnel, building nothing locally, keeping the remote's own
    timeout profile). Same `op://…`-ref-only key discipline, same funding-address/amount
    printout, same `--dry-run` stop-before-lock safety invariant. ZEC-specific swaps: `[zec]`
    TOML section (`lightwalletd_url` instead of `esplora_url`/`network`), `--zec-key` CLI
    flag, offers `divi-zec-testnet`/`zec-divi-testnet`, ports 18496/18497 (LTC's live script
    uses 18494/18495, so they don't collide if ever run side by side), price
    `divi_sats_per_btc = 500000000000` (5,000 DIVI/ZEC, matching `mock_counter_offers`'s ZEC
    price). Verified with `--backend mock --dry-run` both directions (quote+accept
    round-trips cleanly against a local mock daemon, no coins/network needed) and with
    `--backend live --dry-run` (fails at the expected point — no secret-broker on hp2 — which
    confirms the `[zec]` config/flag wiring reaches real key resolution before anything
    risky). `shellcheck` clean.
- running: nothing
- broken: nothing
- left:
  - Fund the two addresses (blocked-on-human, see "parked") — first attempt landed on a stale
    pre-NU7 fork and doesn't count. Likely fastest path now: one `curl -X POST` per address to
    `faucet.testnet.valargroup.dev/api/claim` (pays `tm…` directly, no PCZT hop) — see
    "parked" for the exact call and why I left executing it to the orchestrator (shared,
    24h-per-IP-rate-limited resource).
  - `live_fund_claim_refund` (needs `SWAP_ZEC_TEST_KEY_HEX`; orchestrator's to run, no
    secrets on hp2) — once funded, this is the only way to get a true independent
    confirmation that the v6 digest fix above is byte-correct (see residual risk above).
  - `check-e2e-local.sh`-equivalent for zec (a shell-level `--backend mock` e2e per the master
    plan's literal wording) doesn't exist for any non-BTC chain yet, including LTC — this
    looks like a plan-vs-reality gap across both lanes, not something specific to zec; the
    Rust-level mock tests (engine + daemon HTTP) already cover "mock e2e per coin, both
    directions" in spirit. Flagging rather than building one unprompted, since LTC is in the
    same boat and a shared convention (if the orchestrator wants one) should probably be
    designed once, not per-lane.
- decisions: Step-0 API choice — lightwalletd gRPC at `testnet.zec.rocks:443`; full rationale below.
  - **Step 0 API choice**: primary (and, so far, only) public Zcash testnet API confirmed
    reachable from hp2 is **lightwalletd gRPC at `testnet.zec.rocks:443`** (TLS+ALPN h2
    handshake confirmed; it's the default testnet server in Zecwallet-lite's config and in
    `zcash-devtool`'s `-s zecrocks` preset — same server the orchestrator's funding tooling
    will use). Its `CompactTxStreamer` service covers every primitive the brief needs:
    `GetLatestBlock` (tip height), `GetBlockRange` (per-block `time` for median-time-past, and
    `CompactTx.vin` prevout/index for `find_spend` block-scanning — no outspend/address-spent
    index exists, so `find_spend` always scans, capped at 200 blocks per call like the btc
    lane's fallback path), `GetTransaction` (raw tx + height), `SendTransaction` (broadcast),
    `GetAddressUtxos` (transparent UTXOs by t-address — mined-only, no mempool visibility,
    which is fine since funding only ever wants confirmed coins anyway), `GetLightdInfo`
    (`consensusBranchId` hex string, read fresh per build — this is what let the v6 fix above
    be purely additive to the digest/serialization layer with zero config/hardcoding changes).
    Ruled out: Blockchair has no Zcash testnet support (404 on `/zcash/testnet/*`). The classic
    Insight-API testnet explorer (`explorer.testnet.z.cash`) and every `*.lightwalletd.com`
    hostname tried are DNS-dead now, despite being cited by current web search results — those
    results are stale. `rpcnodelist.com`'s Zcash-testnet listing is likewise stale/wrong.
    `lightwalletd.testnet.electriccoin.co` resolves but answers neither port 443 nor 9067 as a
    gRPC endpoint. CryptoAPIs.io (fronting blockexplorer.one) has testnet coverage but needs
    an API key — out per no-secrets-on-hp2. **No second working endpoint found** — `grpc.rs`
    is written generically over a `Vec<String>` with retry+fallback, ships with one entry.
  - **Tx/sighash layer is hand-rolled** against the ZIP-244 (v5) and ZIP-229 (v6) specs and
    the *official* ZIP-244 test vectors (`zcash/zcash-test-vectors` `zip_0244.json`, embedded
    in `zip244_vectors.rs`) rather than depending on `zcash_primitives`/`zcash_transparent`.
    The full `zcash_primitives` stack pulls orchard/sapling/jubjub/bellman-style curve crypto
    a transparent-only HTLC never touches; the lighter `zcash_transparent` crate only exposes
    `SighashType`/`SignableInput` plumbing — the actual digest tree lives in
    `zcash_primitives`, so depending on it wouldn't avoid writing the digest code by hand
    anyway. Kept the added dependency surface to `blake2b_simd` + `bs58` (tiny, pure Rust).
    v5 validated byte-for-byte against all 10 official vectors (txid + all six sighash-type
    variants); v6 has no official vectors yet (see the NU6.3/v6 fix above for how that gap
    was handled — spec-text review + oracle review + live version_group_id cross-check +
    round-trip test, pending a real broadcast for full confidence).
  - **Script self-verification uses the `zcash_script` crate** (pure Rust reimplementation of
    Zcash's transparent interpreter — no C++ FFI), via its
    `CallbackTransactionSignatureChecker`, supplying our own digest. The brief's literal
    fallback suggestion (the `bitcoin` crate's interpreter) doesn't work here:
    `bitcoin::consensus::verify_script` recomputes *Bitcoin's own* sighash internally with no
    hook to substitute ours, so every signature we produce would be checked against the wrong
    message. Dropped the `bitcoin` crate as a dependency entirely.
  - HTLC funding/claim/refund scriptCode convention: for the backend's own P2PKH funding
    inputs, scriptCode = that input's P2PKH `scriptPubKey`; for the P2SH HTLC claim/refund
    input, scriptCode = the HTLC redeem script (not the P2SH wrapper) — `zcash_script`
    independently derives the same redeem script from the scriptSig during P2SH execution.
  - **Funding path** (for the orchestrator, no secrets on hp2 so I can't run this myself):
    the obvious "op read a funded key" path doesn't exist yet for ZEC — the chain needs an
    actual testnet-ZEC transfer, and the only faucet that currently works
    (zcashd end-of-life 2026-07-18 broke the old ones) is **fauzec.com**
    (Zcash Foundation, Zebra-backed, 1 TAZ/address/24h, API currently skips the captcha). It
    only pays to **shielded** addresses (Unified or Sapling — `supported_address_kinds`:
    `["unified","sapling"]` per its `/.well-known/openapi.json`), never transparent, so the
    funds need one hop through a shielded wallet before they can reach our transparent swap
    addresses. **`zcash-devtool`** (github.com/zcash/zcash-devtool, built by the Zcash org,
    uses the same `testnet.zec.rocks` server as us via its `-s zecrocks` preset) does exactly
    this hop via its PCZT (Partially Created Zcash Transaction) commands. Exact steps:

    1. `git clone https://github.com/zcash/zcash-devtool && cd zcash-devtool`
    2. Create a throwaway funding wallet (NOT the swap's own maker/taker key — just a relay):
       `cargo run --release --all-features -- wallet -w ~/zec-funding init --name zec-funding -i ~/zec-funding/age-key.txt -n test -s zecrocks`
    3. `cargo run --release --all-features -- wallet -w ~/zec-funding list-addresses` → note
       the Unified Address (UA) printed.
    4. Claim from the faucet (`ClaimRequest` schema needs `network` + `address`; `memo` is
       optional but fails validation for transparent recipients — not our case here since
       we're claiming to the UA, not a t-address):
       ```
       curl -s -X POST https://fauzec.com/api/v1/claim \
         -H 'content-type: application/json' \
         -d '{"network":"testnet","address":"<UA from step 3>"}'
       ```
       Response has a `request_id`; poll until terminal:
       `curl -s https://fauzec.com/api/v1/status/testnet/<request_id>` — watch for
       `"state":"confirmed"` (or `"failed"` with an `error_code`; the schema lists
       `address_on_cooldown`/`ip_on_cooldown`/`faucet_dry` etc. as the likely failure modes if
       this address or IP already claimed in the last 24h).
    5. `cargo run --release --all-features -- wallet -w ~/zec-funding sync -s zecrocks` then
       `wallet -w ~/zec-funding balance` to confirm the 1 TAZ (100,000,000 zatoshi) landed.
    6. PCZT-send to each swap address (repeat per recipient; `--value` is in zatoshi, so
       2,000,000 = 0.02 TAZ — plenty for many HTLC test rounds with room to spare):
       ```
       cargo run --release --all-features -- pczt -w ~/zec-funding create \
         --address tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk --value 2000000 > taker.pczt
       cargo run --release --all-features -- pczt -w ~/zec-funding prove < taker.pczt > taker.proven
       cargo run --release --all-features -- pczt -w ~/zec-funding sign \
         --identity ~/zec-funding/age-key.txt < taker.pczt > taker.signed
       cargo run --release --all-features -- pczt combine -i taker.signed -i taker.proven > taker.combined
       cargo run --release --all-features -- pczt -w ~/zec-funding send -s zecrocks < taker.combined
       ```
       Then the same for `tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn` (maker).
    7. I can confirm funding landed myself, read-only, no key needed — `GetAddressUtxos` on a
       known public address is exactly what `ZecBackend::balance_zatoshi()` already does; just
       ping me or I'll notice on my next check.

    Separately (not blocking, just worth stating): since the network is past NU6.3/NU7, the
    PCZT-created send above will itself be a v6 transaction with real Sapling/Orchard content
    (shielded spend from the funding wallet) — that's `zcash-devtool`'s problem, not mine, and
    doesn't exercise anything in my code. The transaction my code needs to get right starting
    from that funded t-address onward (building the HTLC funding tx, claim, refund) is the
    part validated above.
- ~~needs: a second public testnet lightwalletd (or other read-only) endpoint, for
  fallback~~ **re-searched 2026-10-12, still none found — made configurable instead**
  (orchestrator's follow-up task on the mainnet-readiness finding). Re-checked every prior
  candidate plus new ones:
  - `lwd.testnet.zec.pro:443`: still Cloudflare `521` (origin down).
  - `testnet.zainod.zingolabs.dev`, `zaino(.testnet).zingolabs.dev`,
    `testnet.zaino.zingolabs.dev`: still NXDOMAIN.
  - `lightwalletd.testnet.electriccoin.co`: TLS handshake failure this time (`sslv3 alert
    handshake failure`), port 9067 times out — still dead, different symptom than last check.
  - New candidate found via web search and ruled out with evidence:
    `lightwalletd.testnet.cipherscan.app:443` resolves and TLS-handshakes, but serves a cert
    for `api.testnet.cipherscan.app` (SAN mismatch) — that's a REST API (`testnet.zecblock.com`
    after a redirect; `/v1/scan/lightwalletd` is a JSON-wrapped endpoint, not a public
    `CompactTxStreamer` gRPC port), not wire-compatible with this crate's hand-rolled gRPC
    client without a different protocol adapter entirely — out of scope.
  - Strongest evidence: cloned `logos-co/logos-zcash-node-module` (an actively maintained
    project whose entire purpose is curating a live-health-polled, multi-operator lightwalletd
    server list per network — exactly the kind of source that would know about a second one).
    Its own hardcoded testnet list (`rust-lib/src/servers.rs`, `TESTNET` const) has exactly
    **one** non-Tor entry: `testnet.zec.rocks`. Its second operator is a **Tor onion service**
    (`cnphkglrgl6xb4bz4zukbntfimrdqk3u4rf4mys2vhrvc73w3ulhb4id.onion:9067`) — not reachable via
    plain `curl --http2`, and hp2 has no `tor`/`torsocks` installed; installing one would be a
    new system dependency and a long-lived daemon, out of scope for this task without the
    orchestrator's say-so. Verified live, direct `curl --http2` `GetLatestBlock` call (empty
    `ChainSpec` frame, `\x00\x00\x00\x00\x00`) against `testnet.zec.rocks:443` still returns
    `grpc-status: 0` and a real `BlockID` — confirms the one known-good endpoint is still up
    and the test methodology is sound; every other candidate above failed before even getting
    that far. **Conclusion: no second plain-HTTPS public ZEC testnet lightwalletd endpoint is
    currently known to exist**, corroborated by an independent, actively-maintained project's
    own curated list, not just my own search.
  - Since no second endpoint exists to hardcode, made the list **configurable** instead (the
    task's explicit fallback instruction): `swap_chain_zec::lightwalletd_endpoints(network)`
    (`crates/swap-chain-zec/src/lib.rs`) mirrors the btc/ltc lanes' `esplora_endpoints(network)`
    shape and appends any comma-separated URLs from a new `SWAP_ZEC_LIGHTWALLETD_EXTRA` env var
    after the built-in default — so a second endpoint can be wired in, by whoever's running the
    daemon, the moment one turns up, with no code change and no rebuild. `ZecBackend::
    for_network`/`testnet()` now go through it. (Separately, `bin/divi-swapd`'s own
    `ZecSection::fallback_lightwalletd_url` TOML config already lets the *daemon* take a
    fallback list directly — unaffected, not touched, this task's new env var is for the
    library-level default only.)
  - **The ordered-failover mechanism this was all building toward already existed before this
    task**: `crates/swap-chain-zec/src/grpc.rs`'s `retry_fallback` already tries every endpoint
    in a `Vec<String>` in order, retrying transient errors and short-circuiting on a rejection,
    and every `LightwalletdClient` RPC method already routes through it; its mock test
    (`client_retries_and_falls_back`) was already required by `check-zec.sh` before this task.
    Didn't duplicate it with a second, harder-to-build gRPC-over-wiremock test (tonic requires
    real `grpc-status` HTTP/2 trailers that `wiremock`, built for plain REST like the btc/ltc
    lanes' `esplora_falls_back_to_secondary`, doesn't model) — added
    `lightwalletd_endpoints_default_is_testnet_primary_only` and
    `extra_endpoints_append_in_order_and_drop_blanks` instead, covering the actually-new code
    (the configurable list), at the same closure-based-mock level the existing failover test
    already uses successfully for this hand-rolled client.
- needs: a decision on the `zcash_primitives` cross-check (item 4 of the queue above) — it's
  blocked on a dependency conflict I can't fix within `crates/swap-chain-zec` alone (rule 2:
  never the root `Cargo.toml`). Two live options, from the worktree agent's report:
  (a) a workspace-root `[patch]`/version pin forcing stable `digest`/`bip32` so
  `zcash_primitives =0.30.1` resolves — agent says the actual cross-check test is otherwise
  ready to drop in once this unblocks it; (b) generate one independent P2SH
  (redeem≠scriptPubKey) ZIP-244 vector out-of-tree (a throwaway crate with its own lockfile,
  or the `zcash-test-vectors` generator) and embed the resulting digest bytes into
  `zip244_vectors.rs` as a new official-style vector — gets independence without touching
  this workspace's dependency graph at all. Current coverage without either: the official
  ZIP-244 v5 vectors (all-P2PKH, don't exercise this) plus `90d857c`'s regression unit test
  (asserts the redeem-script digest and the scriptPubKey digest differ, and that only the
  latter verifies) — self-consistent but not independently verified against a second
  implementation.
- ~~needs: a decision on ZEC testnet confirmations~~ **decided and done** — see "done" below
  (the orchestrator authorized editing `config.rs`, the normally-frozen engine contract,
  for this one change specifically).

## 2026-10-13 live on the redeployed maker (4e0ac26)
- result: PASS — live ZEC happy swap both directions against dnsdivi 4e0ac26, Done/Done each (fwd `ce1cef2f…`, rev `e000c971…`); rerun because the earlier case-C refund test predates 4e0ac26's ZEC maker changes; verify-results 137/137.
