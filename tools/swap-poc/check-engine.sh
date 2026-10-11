#!/usr/bin/env bash
# Lane engine (wave 1e) acceptance. See docs/plans/swap-poc/lanes/engine.md.
source "$(dirname "$0")/lib.sh"
for p in divi-swap divi-swapd divi-swap-cli; do crate_green "$p"; done
no_todo crates/divi-swap/src
grep -qE '^\s*Ltc,' crates/divi-swap/src/types.rs && pass "Chain::Ltc" || fail "Chain::Ltc missing"
grep -qE '^\s*Zec,' crates/divi-swap/src/types.rs && pass "Chain::Zec" || fail "Chain::Zec missing"
require_tests divi-swap v025_records_still_load mock_swap_ltc_forward mock_swap_ltc_reverse \
  mock_swap_zec_forward mock_swap_zec_reverse old_config_toml_parses
if git diff --quiet origin/main -- crates/divi-swap/tests/fixtures/v0.2.5 2>/dev/null; then
  pass "v0.2.5 fixtures untouched"; else fail "crates/divi-swap/tests/fixtures/v0.2.5 was edited"; fi
finish engine
