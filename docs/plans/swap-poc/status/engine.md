# engine lane status
- done: store (SQLite, 0600, write-ahead), maker + taker state machines, tests/engine.rs (12 scenarios incl. crash-at-every-state and proptest); check-engine.sh PASS
- running: nothing
- broken: nothing
- left: nothing for the lane; daemon lane builds against Maker/Taker/Store
- last_sha: f99dbb5
- needs: nothing — verified 2026-10-21 (builder L): `#[allow(clippy::double_must_use)]` is already on the `ChainBackend` trait at `crates/divi-swap/src/backend.rs:26`, directly above `#[async_trait]`
- decisions:
  - Gap check at maker lock: require btc_locktime - btc_mtp_now >= maker_timeout + claim_margin (SwapConfig::validate's literal gap would break as time elapses); otherwise Aborted with no coin selection.
  - Maker aborts from Accepted if no taker lock arrives within lock_wait (default 1800s wall clock, injectable clock).
  - Quotes are single-use; accept rejects expired quotes and duplicate hashes.
  - Taker verifies the maker's DIVI lock on chain itself and claims only while DIVI MTP + 1800s <= maker locktime.
  - Crash hooks: Maker/Taker::halt_after(state) return right after persisting the transition, before its side effect.
  - Maker and taker may share one DB file (separate tables).
- parked: none

## 2026-10-21 — profile-network-consistency (builder U)
- done: `check_profile_networks(profile, &[(Chain, network, Option<allow_mainnet>)])` in `crates/divi-swap/src/config.rs:226`; called from `DaemonConfig::validate` (so xmr and usdc, which had no profile check, are now covered next to the existing btc/ltc/zec gates) and from the CLI (`--profile`, default testnet; `guard_profile` runs before any key or network call, in `live_backends` and `live_xmr_taker`). Mainnet profile + test network, mainnet profile without allow_mainnet, and testnet profile + mainnet network are all refused. No confirmation, MTP, timeout or margin value was touched.
- proof: unit tests in `divi-swap` (4), `divi-swapd` config (3), `divi-swap-cli` (4); fmt, clippy -D warnings and `cargo test -p divi-swap -p divi-swapd -p divi-swap-cli` green on hp1.
- left: the CLI taker takes its terms from the maker and builds no `SwapConfig`, so `--profile` only gates the network flags; DIVI has no `network` field in the daemon and the CLI hardcodes DIVI testnet, so DIVI is not compared; USDC mainnet names (`ethereum`, `base`) are matched by name because `UsdcNetwork` has only the two Sepolia variants.
- needs: nothing
- decisions: default profile stays testnet in both binaries; existing per-coin gates keep their wording and run first.

## 2026-10-22 — taker-term-floors (builder V)
- done: `check_terms_against_profile(profile, (taker_chain, maker_chain), &OfferedTerms)` in `crates/divi-swap/src/config.rs:318` refuses a maker quote with a confirmation depth, taker timeout or maker timeout below the taker's own profile, or a taker−maker gap below `max(3 h, 2 × larger MTP lag of the pair + claim margin)`; errors name the term, offered value and floor. `Taker::with_profile_floor` arms it in `Taker::prepare` (`taker.rs:118`), i.e. before the preimage is generated, anything is stored, signed or funded; `divi-swap` sets it from `--profile` for `accept`/`lock`/`claim`/`run` (`bin/divi-swap/src/main.rs:571,655`). No confirmation, MTP, timeout or margin value changed (BTC mainnet stays 2).
- proof: unit tests in `divi-swap` config (per term, per profile, exact-floor, all-good) and `tests/taker_profile_floor.rs` (mainnet taker vs testnet maker, both directions; nothing persisted on refusal; same-profile and stronger makers accepted); fmt, clippy -D warnings, tests green on hp1.
- left: the maker-leg HTLC's real locktime is only checked against MTP + 1800 s (`taker.rs:404`), not against the profile's maker timeout; the XMR taker never reads the quote's timeouts or depths and enforces its own `XmrConfig` on the maker's setup (`divi-swap-xmr/src/taker.rs:499-510`) but only floors `t_cancel` at 2×margin, below the profile's `cancel_after_secs`; the mock XMR taker always uses `XmrConfig::testnet()`.
- needs: nothing
- decisions: enforced at `prepare` (optional field, so library users and tests are unchanged) rather than changing `flow::begin`'s signature; XMR skipped because its terms are not offered in the quote.

## 2026-10-22 — profile-floors-xmr-daemon (builder Z)
- done: `XmrConfig::for_profile`, `check_quote_terms` and `check_setup_timelocks` (`crates/divi-swap-xmr/src/lib.rs`, pure) and `XmrTaker::with_profile_floor` (`taker.rs`): `prepare` refuses a quote whose DIVI/XMR confirmation depths, `maker_timeout_secs` (= `cancel_after_secs`) or `taker_timeout_secs` (= cancel + punish) are below the profile's before any key, prime or stored document; `verify_setup` refuses `t_cancel` below `mtp + cancel_after_secs − sigs_wait_secs`, `t_punish − t_cancel` below `punish_after_secs` and `t_late − t_punish` below `late_after_secs`. `divi-swap --counter-chain xmr` arms it from `--profile` (live and mock); the mock taker takes `XmrConfig::for_profile(--profile)` rather than always `testnet()`. Daemon: `divi-swapd` has no taker path (maker only, `bin/divi-swapd/src/main.rs:143`), so gap 2 is moot. No confirmation, MTP lag, timeout or margin value changed; XMR mainnet still refused at runtime.
- proof: unit tests in `divi-swap-xmr` `lib.rs` (profile selection, per term per profile, at-floor and stronger accepted, testnet maker vs mainnet floor) and `tests/taker_profile_floor.rs` (refusal before anything persisted, no-floor taker keeps today's behaviour, same-profile and stronger makers pass); fmt, clippy -D warnings, tests green on hp1.
- left: the setup-time `t_cancel` floor tolerates `sigs_wait_secs` (1800 s) of clock drift between the maker reading its MTP and the taker reading hers — exact enforcement needs the maker to send its MTP in the setup (protocol change); the maker-leg HTLC locktime check of the hashlock taker (`taker.rs:404`) is unchanged.
- needs: nothing
- decisions: floor is opt-in (`with_profile_floor`), like V's, so library users and tests are unchanged; `t_punish`/`t_late` windows are exact differences, `t_cancel` gets the slack above; floor numbers are `XmrConfig::{testnet,mainnet}` values, none new.

## 2026-10-22 — maker-leg-locktime-floor (builder AA)
- done: `check_maker_leg_locktime(profile, (taker_chain, maker_chain), &OfferedTerms, taker_leg_locktime, maker_leg_locktime, accept_tolerance_secs)` in `crates/divi-swap/src/config.rs:393` (pure) and its call in `Taker::on_locked` (`crates/divi-swap/src/taker.rs:419`), run when the maker's lock is first seen and verified, after today's MTP + 1800 s check and before `MakerLockConfirmed` / any claim. Floor: `maker_leg_locktime >= taker_leg_locktime - (quote.taker_timeout - quote.maker_timeout) - 1800 (LOCKTIME_TOLERANCE_SECS, the drift `accepted` already allows) - max(MTP lag of the two chains, profile value)`. Below it: the same decided-once, persisted `claim_declined` outcome, with a reason naming the term, the locktime and the floor; the taker never claims and waits for its own refund.
- proof: unit test `maker_leg_locktime_floor_per_profile` (config.rs; testnet and mainnet x BTC/LTC/ZEC: at-floor and stronger accepted, one below refused naming both values) and `tests/taker_maker_leg_floor.rs`: `a_maker_that_quotes_strong_but_locks_short_is_declined_and_refunded` (hand-locked 1 h leg: declined, persisted, quiet across restart, preimage never revealed, taker refund completes), `an_honest_maker_still_completes_under_a_profile_floor` (testnet and mainnet), `without_a_profile_floor_a_short_maker_lock_is_unchanged`. fmt, clippy -D warnings, tests green on hp1; divi-swap tests 164 -> 168.
- left: the floor is anchored on the taker leg's locktime, so it bounds the maker's timeout up to the accept tolerance (1800 s) plus the MTP lag (3600 s) of slack, not exactly; exact enforcement needs the maker's MTP at lock time in the lock notice (protocol change). The reverse direction runs the same code path through `quote.taker_chain()/maker_chain()` but only the TakerPaysBtc direction has an integration test. XMR taker unchanged.
- needs: nothing
- decisions: opt-in via `with_profile_floor` (no profile means unchanged behaviour: without profile MTP lag is unknown and the cross-chain slack can't be bounded, so the quote-relative check is not clearly always correct); no confirmation count, MTP lag, timeout or margin value changed; no new constants.
