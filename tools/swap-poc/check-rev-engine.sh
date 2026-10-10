#!/usr/bin/env bash
# Lane rev-engine acceptance. See docs/plans/swap-poc/lanes/rev-engine.md.
source "$(dirname "$0")/lib.sh"
crate_green divi-swap
no_todo crates/divi-swap/src
require_tests divi-swap \
  happy_path case_c_taker_never_claims crash_at_every_maker_state \
  rev_happy_path rev_case_a_taker_never_locks rev_case_b_taker_lock_invalid \
  rev_case_c_taker_never_claims rev_case_d_late_claim \
  rev_crash_at_every_maker_state rev_crash_at_every_taker_state rev_prop_random_crash_points \
  rev_no_coin_selection_before_taker_lock_confirmed rev_timeout_invariant_enforced \
  forward_records_still_load
grep -qE '^\| *9 *\|' docs/plans/swap-poc/DECISIONS.md && pass "DECISIONS #9" || fail "DECISIONS #9 (timeout gap) missing"
finish rev-engine
