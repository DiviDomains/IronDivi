#!/usr/bin/env bash
# Lane engine acceptance. See docs/plans/swap-poc/lanes/engine.md.
source "$(dirname "$0")/lib.sh"
crate_green divi-swap
no_todo crates/divi-swap/src
require_tests divi-swap \
  happy_path case_a_taker_never_locks case_b_taker_lock_invalid \
  case_c_taker_never_claims case_d_late_claim \
  crash_at_every_maker_state crash_at_every_taker_state prop_random_crash_points \
  no_coin_selection_before_taker_lock_confirmed timeout_invariant_enforced \
  quote_expires store_round_trip store_file_mode_0600 broadcast_after_persist
finish engine
