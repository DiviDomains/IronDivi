# Lane engine — `crates/divi-swap/` (except the frozen contract)

Read `_common.md` first. You own `crates/divi-swap/src/{maker,taker,store,mock,secrets}.rs`, new
files you add under `crates/divi-swap/src/` and `crates/divi-swap/tests/`, and
`docs/plans/swap-poc/status/engine.md`. The **public signatures** of `Maker`, `Taker`, `Store`
are frozen (the daemon lane builds against them); the bodies are yours. Frozen files:
`types.rs htlc.rs backend.rs state.rs config.rs error.rs api.rs`.

**Build** the maker and taker state machines (plan §3.2, protocol in `api.rs` docs) and SQLite
persistence (`rusqlite`, file created mode 0600):
- Write-ahead: persist each transition and each **signed tx** before `broadcast`; on restart
  rebroadcast the persisted bytes (backends treat already-known as `Ok`). `step` is idempotent.
- **Staking invariant:** the maker calls `divi.build_funding` only on the
  `TakerLockConfirmed → MakerLocked` edge, after verifying the taker's BTC lock with
  `btc.htlc_output` (right script, amount ≥ quote, confirmations ≥ `btc_confirmations`).
- Maker: claim BTC as soon as `find_spend` on the DIVI HTLC yields a preimage; refund DIVI once
  DIVI MTP ≥ locktime (`Premature` ⇒ try again next tick). Taker: claim DIVI only after the
  maker's lock is verified (script, amount, the quote's hash) and confirmed, and only while
  DIVI MTP < maker locktime − safety margin; refund BTC once BTC MTP ≥ its locktime.
- Locktimes: BTC = BTC MTP + `taker_timeout_secs`, DIVI = DIVI MTP + `maker_timeout_secs`, and
  the maker refuses to lock if the remaining BTC window would break `SwapConfig::validate`'s gap.
- Quotes expire after `quote_expiry_secs`; an expired quote cannot be accepted.
- Extend `mock.rs` as you need (crash injection hooks, failing broadcasts); keep existing API.

**Acceptance** (`tools/swap-poc/check-engine.sh`): crate green, no `todo!` left, tests named
`happy_path`, `case_a_taker_never_locks`, `case_b_taker_lock_invalid` (wrong amount/script ⇒
Aborted, zero maker coin selection), `case_c_taker_never_claims` (maker refunds DIVI, taker
refunds BTC), `case_d_late_claim` (taker claims just before maker timeout; maker still claims
BTC), `crash_at_every_maker_state`, `crash_at_every_taker_state` (drop engine, reopen store,
continue to Done), `prop_random_crash_points` (proptest), 
`no_coin_selection_before_taker_lock_confirmed` (assert `MockBackend::funding_calls()`),
`timeout_invariant_enforced`, `quote_expires`, `store_round_trip`, `store_file_mode_0600`,
`broadcast_after_persist`.
