#!/usr/bin/env bash
# Orchestrator acceptance for the live reverse direction (taker sells DIVI for BTC).
# Reads docs/plans/swap-poc/status/rev-live.md and checks each recorded txid is confirmed.
# Any key may carry a `deployed_` prefix instead (runs through the deployed maker).
# The BTC leg is checked on $SWAP_BTC_NETWORK (default testnet: the reverse runs are on testnet3).
# shellcheck disable=SC1091
source "$(dirname "$0")/lib.sh"
export SWAP_BTC_NETWORK="${SWAP_BTC_NETWORK:-testnet}"

# check <key-stem> <divi|btc>: value of rev_<stem>_txid or deployed_rev_<stem>_txid, confirmed on that chain.
check() {
  local stem="$1" chain="$2" k tx=""
  for k in "rev_${stem}_txid" "deployed_rev_${stem}_txid"; do
    tx="$(status_field rev-live "$k")"
    [[ -n "$tx" ]] && break
  done
  if [[ -z "$tx" ]]; then fail "rev-live: rev_${stem}_txid (or deployed_) missing"; return; fi
  if [[ ! "$tx" =~ ^[0-9a-fA-F]{64}$ ]]; then fail "rev-live: rev_${stem}_txid not a txid: $tx"; return; fi
  if [[ "$chain" == divi ]] && divi_confirmed "$tx"; then pass "rev_${stem} $tx confirmed (divi)"
  elif [[ "$chain" == btc ]] && btc_confirmed "$tx"; then pass "rev_${stem} $tx confirmed (btc)"
  else fail "rev-live: rev_${stem} $tx not confirmed on $chain"; fi
}

check happy_divi_lock divi
check happy_btc_lock btc
check happy_btc_claim btc
check happy_divi_claim divi
check casec_divi_lock divi
check casec_btc_lock btc
check casec_btc_refund btc
check casec_divi_refund divi
finish rev-live
