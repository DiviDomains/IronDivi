#!/usr/bin/env bash
# Lane rev-tools acceptance. See docs/plans/swap-poc/lanes/rev-tools.md.
source "$(dirname "$0")/lib.sh"
for f in tools/swap-poc/e2e.sh tools/swap-poc/check-rev-live.sh; do
  if [[ -f "$f" ]] && shellcheck "$f" >/dev/null 2>&1; then pass "shellcheck $f"; else fail "shellcheck $f (or missing)"; fi
done
st="$(mktemp -d)"
for offer in divi-btc-testnet btc-divi-testnet; do
  if E2E_STATE_DIR="$st" timeout 900 tools/swap-poc/e2e.sh happy --backend mock --offer "$offer" >"$st/$offer.log" 2>&1; then
    pass "mock e2e $offer"; else fail "e2e.sh happy --backend mock --offer $offer (log $st/$offer.log)"; fi
done
python3 tools/swap-poc/chaos/driver.py --help 2>/dev/null | grep -q -- '--offer' && pass "chaos --offer" || fail "chaos driver --offer missing"
for p in tools/swap-poc/chaos/*.py; do
  python3 -m py_compile "$p" 2>/dev/null && pass "py_compile $p" || fail "py_compile $p"
done
finish rev-tools
