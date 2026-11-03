#!/usr/bin/env bash
# C1 punish test (docs/plans/swap-poc/c1-punish-results.md): stall the PRIVATE maker on hp2
# (~/.local/state/c1-punish, port 18483 tunnelled to the Mac) the moment it records the taker's
# XMR lock, so it never offers redeem and never cancels or refunds. Never the dnsdivi maker.
#   [SKIP_IDS="id1 id2"] c1-punish-watch.sh <run-dir>   (SKIP_IDS: maker swap ids from earlier runs)
# It reads the maker's swaps with `divi-swapd --xmr-inflight --xmr-lock-txids` over the same ssh it
# uses for the kill: a read-only open of the swap store, nothing over HTTP (C3 removed
# `GET /xmr/swaps`; `GET /xmr/swaps/<id>` needs the swap token). The hp2 binary must know
# `--xmr-lock-txids`; an older one fails the poll, and so does anything but the documented output,
# so the script exits 1 after FAIL_LIMIT unreadable polls in a row instead of silently never stalling.
# POLL_SECS (default 5) and FAIL_LIMIT (default 12) exist for the test harness.
set -euo pipefail
out=$1
poll_secs=${POLL_SECS:-5} fail_limit=${FAIL_LIMIT:-12} fails=0

# poll: the first in-flight swap not in SKIP_IDS as "<state> <lock txid or ->"; prints nothing when
# there is none. Returns 1 unless the output has exactly the documented shape (header, count, one
# `<id> <state> <txid>` per swap), so a truncated or foreign output is never read as "no swaps".
poll() {
  local raw
  raw=$(ssh -o BatchMode=yes hp2 'cd ~/.local/state/c1-punish && ./divi-swapd --config divi-swapd.toml --xmr-inflight --xmr-lock-txids' 2>&1) || return 1
  awk -v skip="${SKIP_IDS:-}" '
    BEGIN { n = split(skip, s, " "); for (i = 1; i <= n; i++) skipped[s[i]] = 1 }
    NR == 1 { if (NF != 2 || $1 != "xmr_configured" || ($2 != "yes" && $2 != "no")) bad = 1; next }
    NR == 2 { if (NF != 2 || $1 != "in_flight" || $2 !~ /^[0-9]+$/) bad = 1; want = $2; next }
    { if (NF != 3) bad = 1; k++; if (!first && !($1 in skipped)) first = $2 " " $3 }
    END { if (NR < 2 || bad || k != want) exit 1; if (first) print first }
  ' <<<"$raw"
}

while :; do
  if st=$(poll); then
    fails=0
    # States are snake_case. Stall on anything past `locked`, or as soon as a lock is recorded.
    case "$st" in
      "" | accepted\ - | locked\ -) ;;
      *)
        ssh -o BatchMode=yes hp2 'kill "$(cat ~/.local/state/c1-punish/maker.pid)"; sleep 2; pgrep -f -x "./divi-swapd --config divi-swapd.toml" || echo maker-stopped'
        echo "$(date -u +%FT%TZ) stalled maker at: $st" | tee -a "$out/stall.log"
        exit 0 ;;
    esac
  else
    fails=$((fails + 1))
    echo "$(date -u +%FT%TZ) c1-punish-watch: could not read the hp2 maker's swaps ($fails/$fail_limit)" >&2
    if ((fails >= fail_limit)); then
      echo "c1-punish-watch: giving up: the maker was never stalled" >&2
      exit 1
    fi
  fi
  sleep "$poll_secs"
done
