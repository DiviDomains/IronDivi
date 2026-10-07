#!/usr/bin/env bash
# Lane btc acceptance. See docs/plans/swap-poc/lanes/btc.md.
source "$(dirname "$0")/lib.sh"
crate_green swap-chain-btc
no_todo crates/swap-chain-btc/src
grep -q 'impl ChainBackend for BtcBackend' -r crates/swap-chain-btc/src \
  && pass "BtcBackend implements ChainBackend" || fail "no 'impl ChainBackend for BtcBackend'"
require_tests swap-chain-btc \
  claim_verifies_with_consensus refund_verifies_with_consensus \
  refund_rejected_before_locktime wrong_preimage_rejected \
  esplora_retries_on_429 esplora_falls_back_to_secondary find_spend_reads_witness \
  funding_selects_coins_and_change live_fund_claim_refund
for k in live_fund_txid live_claim_txid live_refund_txid; do
  t="$(status_field btc "$k")"
  if [[ -n "$t" ]] && btc_confirmed "$t"; then pass "$k $t confirmed"; else fail "$k missing or unconfirmed in status/btc.md ('$t')"; fi
done
finish btc
