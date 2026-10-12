#!/usr/bin/env bash
# Lane xmr acceptance. See docs/plans/swap-poc/lanes/xmr.md.
#
# divi-rpc's baretxid fix (f8f7e9b) landed long ago and isn't re-checked here:
# another session owns crates/divi-rpc now, and gating this lane's acceptance on a
# crate it no longer touches just means unrelated in-flight work on that crate can
# fail this script. See docs/plans/swap-poc/status/xmr.md for the orchestrator's
# "let check-xmr.sh skip divi-rpc instead" instruction (2026-10-12).
source "$(dirname "$0")/lib.sh"
crate_green swap-adaptor
crate_green swap-chain-xmr
doc=docs/plans/swap-poc/xmr-design.md
for s in Protocol "DIVI scripts" DLEQ Crates Stagenet "Build plan" Risks Recommendation; do
  grep -q "^## $s" "$doc" 2>/dev/null && pass "xmr-design.md: ## $s" || fail "xmr-design.md missing '## $s'"
done
finish xmr
