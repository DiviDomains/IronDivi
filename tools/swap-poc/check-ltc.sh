#!/usr/bin/env bash
# Lane ltc acceptance. See docs/plans/swap-poc/lanes/ltc.md.
source "$(dirname "$0")/lib.sh"
crate_green swap-chain-ltc
no_todo crates/swap-chain-ltc/src
grep -q 'impl ChainBackend for LtcBackend' -r crates/swap-chain-ltc/src \
  && pass "LtcBackend implements ChainBackend" || fail "no 'impl ChainBackend for LtcBackend'"
require_tests swap-chain-ltc \
  claim_verifies_with_consensus refund_verifies_with_consensus \
  refund_rejected_before_locktime wrong_preimage_rejected \
  esplora_retries_on_429 esplora_falls_back_to_secondary find_spend_reads_witness \
  funding_selects_coins_and_change tltc_address_encoding testnet_api_reachable live_fund_claim_refund
if rcargo test -q -p swap-chain-ltc -- --ignored --exact testnet_api_reachable >/dev/null 2>&1 \
   || rcargo test -q -p swap-chain-ltc -- --ignored testnet_api_reachable >/dev/null 2>&1; then
  pass "testnet_api_reachable passes against the live API"; else fail "testnet_api_reachable fails against the live API"; fi
finish ltc
