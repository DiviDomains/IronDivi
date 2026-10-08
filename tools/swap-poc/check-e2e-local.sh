#!/usr/bin/env bash
# Lane e2e-local acceptance. See docs/plans/swap-poc/lanes/e2e-local.md.
source "$(dirname "$0")/lib.sh"
if [[ -f tools/swap-poc/e2e.sh ]]; then
  shellcheck tools/swap-poc/e2e.sh >/dev/null 2>&1 && pass "e2e.sh shellcheck" || fail "shellcheck tools/swap-poc/e2e.sh"
else fail "missing tools/swap-poc/e2e.sh"; fi
for k in happy_divi_lock happy_divi_claim casec_divi_lock casec_divi_refund cased_divi_claim; do
  t="$(status_field e2e-local "${k}_txid")"
  if [[ -n "$t" ]] && divi_confirmed "$t"; then pass "$k $t"; else fail "${k}_txid missing/unconfirmed ('$t')"; fi
done
for k in happy_btc_lock happy_btc_claim casec_btc_lock casec_btc_refund cased_btc_claim; do
  t="$(status_field e2e-local "${k}_txid")"
  if [[ -n "$t" ]] && btc_confirmed "$t"; then pass "$k $t"; else fail "${k}_txid missing/unconfirmed ('$t')"; fi
done
n="$(status_field e2e-local cased_claim_secs_before_timeout)"
[[ "$n" =~ ^[0-9]+$ ]] && pass "case D claimed ${n}s before maker timeout" || fail "cased_claim_secs_before_timeout missing"
finish e2e-local
