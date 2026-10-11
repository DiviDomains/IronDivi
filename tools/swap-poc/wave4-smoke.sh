#!/usr/bin/env bash
# Read-only post-deploy smoke check for wave 4 (docs/plans/swap-poc/wave4-deploy.md §4), run
# from the Mac. Opens an ssh tunnel to dnsdivi's divi-swapd (127.0.0.1:18480 there) and checks:
#   1. /healthz: ok, a live LTC backend (counters.ltc.tip, no error); ZEC reported, not judged
#   2. /offers: every offer carries counter_chain (the wave-4 binary), divi-ltc-testnet is
#      served as taker_pays_btc on ltc
#   3. an LTC quote over HTTP says counter_chain "ltc"
#   4. a take without counter_chain (what a v0.2.5 taker CLI sends) is refused with 400 and
#      the fail-closed message, and /swaps does not grow
#   5. `divi-swap quote --counter-chain ltc` against the same tunnel says counter_chain "ltc"
#
# It takes no keys and makes no swap: quotes reserve nothing (60 s, single use), the take in
# step 4 is rejected before the quote is consumed, and `divi-swap quote` never builds a
# backend. Step 4 runs only after step 3 proved the daemon checks counter chains: a v0.2.5
# daemon would accept that take as a BTC swap, so against one the step is skipped (FAIL).
#
#   tools/swap-poc/wave4-smoke.sh [--dry-run] [--host dnsdivi] [--local-port 18581]
#                                 [--remote-port 18480] [--base URL] [--divi-swap PATH]
#
# --base URL skips the tunnel and talks to URL directly (an existing tunnel, or a local
# `divi-swapd --backend mock` for rehearsal). --dry-run prints every command and runs none.
# Needs: ssh (the `dnsdivi` alias), curl, jq, openssl, and a divi-swap binary built from main
# at or after 6037821 (default: target/release/divi-swap, else target/debug/divi-swap).
set -euo pipefail

usage() {
  sed -n '17,18p' "$0" | sed 's/^# *//' >&2
  exit 2
}

host=dnsdivi
local_port=18581
remote_port=18480
base=""
divi_swap=""
dry_run=0
while (($#)); do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --host) host="${2:?}"; shift 2 ;;
    --local-port) local_port="${2:?}"; shift 2 ;;
    --remote-port) remote_port="${2:?}"; shift 2 ;;
    --base) base="${2:?}"; shift 2 ;;
    --divi-swap) divi_swap="${2:?}"; shift 2 ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
done

ROOT="$(git rev-parse --show-toplevel)"
if [[ -z "$divi_swap" ]]; then
  divi_swap="$ROOT/target/release/divi-swap"
  [[ -x "$divi_swap" ]] || divi_swap="$ROOT/target/debug/divi-swap"
fi
tunnel=0
if [[ -z "$base" ]]; then
  tunnel=1
  base="http://127.0.0.1:$local_port"
fi
offer=divi-ltc-testnet
sats=100000

FAILS=0
pass() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
info() { echo "info: $*"; }
show() { printf '  [dry-run]'; printf ' %q' "$@"; echo; }

# A dummy old-client take body: no counter_chain, throwaway (unspendable) pubkeys and hash.
take_body() {
  local quote_id="$1" k1 k2
  k1="02$(printf '11%.0s' {1..32})"
  k2="02$(printf '22%.0s' {1..32})"
  printf '{"quote_id":"%s","hash":"%s","taker_btc_pubkey":"%s","taker_divi_pubkey":"%s"}' \
    "$quote_id" "$(openssl rand -hex 32)" "$k1" "$k2"
}

tmp=""
tunnel_pid=""
# shellcheck disable=SC2329  # invoked by the EXIT trap below
cleanup() {
  if [[ -n "$tunnel_pid" ]]; then kill "$tunnel_pid" 2>/dev/null || true; fi
  if [[ -n "$tmp" ]]; then rm -rf "$tmp"; fi
}
trap cleanup EXIT INT TERM

if ((dry_run)); then
  echo "DRY RUN: nothing below is executed."
  ((tunnel)) && show ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes \
    -L "$local_port:127.0.0.1:$remote_port" "$host"
  show curl -fsS "$base/healthz"
  show curl -fsS "$base/offers"
  show curl -fsS "$base/swaps"
  show curl -fsS "$base/offers/$offer/quote?btc_sats=$sats"
  show curl -sS -o BODY -w '%{http_code}' -X POST "$base/swaps" \
    -H 'content-type: application/json' -d "$(take_body QUOTE_ID)"
  show curl -fsS "$base/swaps"
  show "$divi_swap" --db TMPDIR/smoke.db --backend mock --counter-chain ltc \
    quote --maker "$base" --offer "$offer" --btc-sats "$sats"
  exit 0
fi

for t in curl jq openssl; do command -v "$t" >/dev/null || { echo "wave4-smoke: needs $t" >&2; exit 1; }; done
[[ -x "$divi_swap" ]] || { echo "wave4-smoke: no divi-swap at $divi_swap (cargo build --release -p divi-swap-cli)" >&2; exit 1; }
tmp="$(mktemp -d)"

if ((tunnel)); then
  ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes \
    -L "$local_port:127.0.0.1:$remote_port" "$host" &
  tunnel_pid=$!
fi
up=0
for _ in $(seq 1 30); do
  if curl -fsS -m 5 "$base/healthz" >/dev/null 2>&1; then up=1; break; fi
  if [[ -n "$tunnel_pid" ]] && ! kill -0 "$tunnel_pid" 2>/dev/null; then break; fi
  sleep 1
done
((up)) || { echo "wave4-smoke: $base/healthz unreachable (tunnel to $host:$remote_port?)" >&2; exit 1; }
echo "wave4-smoke: $base ($([[ $tunnel == 1 ]] && echo "tunnel to $host:$remote_port" || echo direct))"

# 1. health
h="$(curl -fsS -m 20 "$base/healthz")"
if [[ "$(jq -r .ok <<<"$h")" == true ]]; then pass "/healthz ok"
else fail "/healthz ok is $(jq -c '{ok, divi_scan}' <<<"$h") (wallet scan still running? re-run later)"; fi
if jq -e '.counters.ltc.tip | numbers' <<<"$h" >/dev/null && [[ "$(jq -r '.counters.ltc.error' <<<"$h")" == null ]]; then
  pass "LTC backend live (tip $(jq -r .counters.ltc.tip <<<"$h"))"
else fail "no healthy LTC backend in /healthz: $(jq -c '.counters // {}' <<<"$h")"; fi
if jq -e '.counters.zec' <<<"$h" >/dev/null; then info "ZEC backend running: $(jq -c .counters.zec <<<"$h")"
else info "ZEC backend not started (no enabled zec offer)"; fi

# 2. offers
o="$(curl -fsS -m 20 "$base/offers")"
info "offers: $(jq -c '[.[] | "\(.id):\(.counter_chain // "?")"]' <<<"$o")"
if jq -e 'length > 0 and all(.[]; has("counter_chain"))' <<<"$o" >/dev/null; then
  pass "every offer carries counter_chain (wave-4 binary)"
else fail "offers without counter_chain: the daemon is older than the wave-4 build"; fi
if jq -e --arg id "$offer" 'any(.[]; .id == $id and .counter_chain == "ltc" and .direction == "taker_pays_btc")' <<<"$o" >/dev/null; then
  pass "$offer served (taker_pays_btc, ltc)"
else fail "$offer missing, or not taker_pays_btc on ltc"; fi

# 3. LTC quote over HTTP
q="$(curl -fsS -m 20 "$base/offers/$offer/quote?btc_sats=$sats" 2>/dev/null || true)"
new_daemon=0
if [[ "$(jq -r '.counter_chain // empty' <<<"$q" 2>/dev/null)" == ltc ]]; then
  new_daemon=1
  pass "quote on $offer: counter_chain ltc, $(jq -r .divi_amount <<<"$q") DIVI sats for $sats litoshi, $(jq -r .btc_confirmations <<<"$q") LTC confs"
else fail "quote on $offer did not say counter_chain ltc: ${q:-<no answer>}"; fi

# 4. old-client take refused (only against a daemon proven to check counter chains)
if ((new_daemon)); then
  before="$(curl -fsS -m 20 "$base/swaps" | jq length)"
  code="$(curl -sS -m 20 -o "$tmp/take.json" -w '%{http_code}' -X POST "$base/swaps" \
    -H 'content-type: application/json' -d "$(take_body "$(jq -r .id <<<"$q")")")"
  after="$(curl -fsS -m 20 "$base/swaps" | jq length)"
  msg="$(jq -r '.error // empty' "$tmp/take.json" 2>/dev/null || true)"
  if [[ "$code" == 400 && "$msg" == *"does not name a counter chain"* ]]; then
    pass "take without counter_chain refused: 400"
  else fail "take without counter_chain: HTTP $code $(head -c 300 "$tmp/take.json")"; fi
  if [[ "$before" == "$after" ]]; then pass "no swap created (/swaps stays at $after)"
  else fail "/swaps grew from $before to $after: inspect the newest swap"; fi
else
  fail "skipped the old-client take: the daemon did not prove it checks counter chains (an old one would accept it)"
fi

# 5. the taker CLI's quote (no keys: `quote` builds no backend)
if out="$("$divi_swap" --db "$tmp/smoke.db" --backend mock --counter-chain ltc \
  quote --maker "$base" --offer "$offer" --btc-sats "$sats" 2>&1)" \
  && [[ "$(jq -r '.counter_chain // empty' <<<"$out" 2>/dev/null)" == ltc ]]; then
  pass "divi-swap quote --counter-chain ltc: counter_chain ltc"
else fail "divi-swap quote --counter-chain ltc: $(head -c 300 <<<"$out")"; fi

if ((FAILS == 0)); then echo "PASS: wave4-smoke"; exit 0; fi
echo "$FAILS check(s) failing"
exit 1
