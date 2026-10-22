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
