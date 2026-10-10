# Lane rev-engine — direction-aware maker/taker engine

Read `_common.md` and `../reverse-direction.md` first. You own `crates/divi-swap/src/{maker,taker,store,mock}.rs`,
`crates/divi-swap/tests/`, and `docs/plans/swap-poc/status/rev-engine.md`. `api.rs` (with `Direction`) is
landed on main and frozen; public signatures of `Maker`/`Taker`/`Store` stay (adding methods is fine).

**Build:**
- Pick leg backends from `quote.direction`: taker leg = `direction.taker_chain()`, maker leg =
  `direction.maker_chain()`. No more hardwired `self.btc` for the taker leg / `self.divi` for the maker leg.
  Locktimes from each leg chain's MTP; the "window too short" check on the taker-leg chain clock.
- Record fields role-based (`taker_leg_htlc`, `maker_leg_funding`, …) with `#[serde(alias = "<old name>")]`
  so **existing forward records load** — the deployed dnsdivi `swaps.db` has them. Add a test with a
  literal JSON of a current forward MakerRecord and TakerRecord (copy from a store test round trip
  before you rename) that still loads and steps.
- Staking invariant for both directions: no `build_funding` on either backend before
  `TakerLockConfirmed → MakerLocked` (`MockBackend::funding_calls()` on both mocks).
- Add DECISIONS #9 row (timeout gap, from `reverse-direction.md`) to `docs/plans/swap-poc/DECISIONS.md`.

**Acceptance** (`tools/swap-poc/check-rev-engine.sh`): crate green, all forward tests still pass, and new
tests named `rev_happy_path`, `rev_case_a_taker_never_locks`, `rev_case_b_taker_lock_invalid`,
`rev_case_c_taker_never_claims`, `rev_case_d_late_claim`, `rev_crash_at_every_maker_state`,
`rev_crash_at_every_taker_state`, `rev_prop_random_crash_points`,
`rev_no_coin_selection_before_taker_lock_confirmed`, `rev_timeout_invariant_enforced`,
`forward_records_still_load`. Land on main at each green seam; the rev-cli lane rebases on you.
