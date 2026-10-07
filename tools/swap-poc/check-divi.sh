#!/usr/bin/env bash
# Lane divi acceptance. See docs/plans/swap-poc/lanes/divi.md.
source "$(dirname "$0")/lib.sh"
crate_green swap-chain-divi
no_todo crates/swap-chain-divi/src
grep -q 'impl ChainBackend for DiviBackend' -r crates/swap-chain-divi/src \
  && pass "DiviBackend implements ChainBackend" || fail "no 'impl ChainBackend for DiviBackend'"
require_tests swap-chain-divi \
  claim_verifies_with_interpreter refund_verifies_with_interpreter \
  refund_rejected_before_locktime wrong_preimage_rejected \
  find_spend_scans_blocks funding_selects_coins_and_change rpc_errors_classified \
  live_fund_claim_refund
for k in live_fund_txid live_claim_txid live_refund_txid; do
  t="$(status_field divi "$k")"
  if [[ -n "$t" ]] && divi_confirmed "$t"; then pass "$k $t confirmed"; else fail "$k missing or unconfirmed in status/divi.md ('$t')"; fi
done
finish divi
