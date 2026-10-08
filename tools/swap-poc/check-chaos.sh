#!/usr/bin/env bash
# Lane chaos acceptance. See docs/plans/swap-poc/lanes/chaos.md.
source "$(dirname "$0")/lib.sh"
F=docs/plans/swap-poc/status/chaos.md
for k in accepted taker_lock_seen taker_lock_confirmed maker_locked maker_lock_confirmed \
         taker_claimed maker_claimed maker_refundable maker_refunded rpc_outage esplora_429; do
  line="$(grep -E "^- *chaos_$k:" "$F" 2>/dev/null | head -1)"
  t="$(awk '{print $NF}' <<<"$line" | tr -d '`')"
  if [[ -z "$t" ]]; then fail "chaos_$k missing"; continue; fi
  if divi_confirmed "$t" || btc_confirmed "$t"; then pass "chaos_$k final $t confirmed"; else fail "chaos_$k final tx $t unconfirmed"; fi
done
grep -qE '^- *stuck:.*[a-z0-9]' "$F" 2>/dev/null && fail "stuck swaps listed in $F" || pass "no stuck swaps"
finish chaos
