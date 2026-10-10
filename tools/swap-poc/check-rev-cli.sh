#!/usr/bin/env bash
# Lane rev-cli acceptance. See docs/plans/swap-poc/lanes/rev-cli.md.
source "$(dirname "$0")/lib.sh"
crate_green divi-swapd
crate_green divi-swap-cli
no_todo bin/divi-swapd/src
no_todo bin/divi-swap/src
require_tests divi-swapd \
  healthz_ok offers_list e2e_mock_happy_path e2e_mock_refund \
  offers_list_has_both_directions e2e_mock_rev_happy_path e2e_mock_rev_refund \
  old_config_without_direction_parses
require_tests divi-swap-cli txids_reverse_keys
for sub in run balance txids; do
  if rcargo run -q -p divi-swap-cli -- "$sub" --help >/dev/null 2>&1; then pass "divi-swap $sub --help"; else fail "divi-swap $sub --help"; fi
done
rcargo run -q -p divi-swap-cli -- --help 2>/dev/null | grep -q -- '--divi-wallet' && pass "--divi-wallet" || fail "divi-swap --divi-wallet missing"
finish rev-cli
