#!/usr/bin/env bash
# C1 punish test (docs/plans/swap-poc/c1-punish-results.md): stall the PRIVATE maker on hp2
# (~/.local/state/c1-punish, port 18483 tunnelled to the Mac) the moment it records the taker's
# XMR lock, so it never offers redeem and never cancels or refunds. Never the dnsdivi maker.
#   c1-punish-watch.sh <run-dir>
set -euo pipefail
out=$1 maker=${MAKER:-http://127.0.0.1:18483}
while :; do
  st=$(curl -s -m 10 "$maker/xmr/swaps" | jq -r '.[0] | "\(.state) \(.xmr_lock_txid // "-")"' 2>/dev/null || true)
  # States are snake_case. Stall on anything past `locked`, or as soon as a lock is recorded.
  case "$st" in
    ""|"null -"|accepted\ -|locked\ -) ;;
    *)
      ssh -o BatchMode=yes hp2 'kill "$(cat ~/.local/state/c1-punish/maker.pid)"; sleep 2; pgrep -f -x "./divi-swapd --config divi-swapd.toml" || echo maker-stopped'
      echo "$(date -u +%FT%TZ) stalled maker at: $st" | tee -a "$out/stall.log"
      exit 0 ;;
  esac
  sleep 5
done
