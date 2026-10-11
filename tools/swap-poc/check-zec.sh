#!/usr/bin/env bash
# Lane zec acceptance. See docs/plans/swap-poc/lanes/zec.md.
source "$(dirname "$0")/lib.sh"
crate_green swap-chain-zec
no_todo crates/swap-chain-zec/src
grep -q 'impl ChainBackend for ZecBackend' -r crates/swap-chain-zec/src \
  && pass "ZecBackend implements ChainBackend" || fail "no 'impl ChainBackend for ZecBackend'"
require_tests swap-chain-zec \
  zip244_sighash_vectors claim_script_executes refund_script_executes \
  refund_rejected_before_locktime wrong_preimage_rejected t_address_encoding \
  funding_selects_coins_and_change find_spend_reads_scriptsig client_retries_and_falls_back \
  testnet_api_reachable live_fund_claim_refund
if rcargo test -q -p swap-chain-zec -- --ignored testnet_api_reachable >/dev/null 2>&1; then
  pass "testnet_api_reachable passes against the live API"; else fail "testnet_api_reachable fails against the live API"; fi
grep -qiE '^- *decisions:.*(api|rpc|grpc|blockchair|insight)' docs/plans/swap-poc/status/zec.md 2>/dev/null \
  && pass "step 0 API decision recorded" || fail "record the step-0 API choice under '- decisions:' in status/zec.md"
finish zec
