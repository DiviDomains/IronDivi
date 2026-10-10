#!/usr/bin/env bash
# Lane daemon acceptance. See docs/plans/swap-poc/lanes/daemon.md.
source "$(dirname "$0")/lib.sh"
crate_green divi-swapd
crate_green divi-swap-cli
no_todo bin/divi-swapd/src
no_todo bin/divi-swap/src
require_tests divi-swapd \
  healthz_ok offers_list quote_expires_after_60s post_swaps_accepts_quote \
  get_swap_never_leaks_keys lock_notice_advances scheduler_resumes_on_restart \
  e2e_mock_happy_path e2e_mock_refund
if rcargo run -q -p divi-swapd -- --help >/dev/null 2>&1; then pass "divi-swapd --help"; else fail "divi-swapd --help"; fi
for sub in quote accept lock status claim refund run; do
  if rcargo run -q -p divi-swap-cli -- "$sub" --help >/dev/null 2>&1; then pass "divi-swap $sub --help"; else fail "divi-swap $sub --help"; fi
done
finish daemon
