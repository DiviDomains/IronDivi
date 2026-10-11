#!/usr/bin/env bash
# Lane xmr acceptance. See docs/plans/swap-poc/lanes/xmr.md.
source "$(dirname "$0")/lib.sh"
crate_green divi-rpc
require_tests divi-rpc baretxid_differs_from_txid_for_signed_tx
doc=docs/plans/swap-poc/xmr-design.md
for s in Protocol "DIVI scripts" DLEQ Crates Stagenet "Build plan" Risks Recommendation; do
  grep -q "^## $s" "$doc" 2>/dev/null && pass "xmr-design.md: ## $s" || fail "xmr-design.md missing '## $s'"
done
finish xmr
