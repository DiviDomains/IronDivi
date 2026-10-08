#!/usr/bin/env bash
# Real-testnet atomic swap scenarios, maker (divi-swapd) and taker (divi-swap) both local.
#   tools/swap-poc/e2e.sh <happy|case-c|case-d> [--backend live|mock]
# live: DIVI testnet + BTC signet, keys resolved from 1Password at runtime (op:// refs only).
# mock: plumbing only (daemon lifecycle, config, quote/accept) — mock chains are per-process,
#       so a swap cannot progress across the daemon/CLI boundary; flows are tested in-process.
# Run it as a background command; case-c takes ~3.5-4 h. Output ends with `- <key>_txid:` lines.
# Env: E2E_STATE_DIR (default ~/.local/state/iron-divi-swap-poc), E2E_BTC_SATS (default 10000).
set -euo pipefail

usage() { echo "usage: $0 <happy|case-c|case-d> [--backend live|mock]" >&2; exit 2; }
die() { echo "e2e: $*" >&2; exit 1; }

scenario="${1:-}"; [[ -n "$scenario" ]] || usage
shift || true
backend=live
while (($#)); do
  case "$1" in
    --backend) backend="${2:-}"; shift 2 || usage ;;
    *) usage ;;
  esac
done
[[ "$backend" == live || "$backend" == mock ]] || usage

ROOT="$(git rev-parse --show-toplevel)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

# Per-scenario daemon timings, port, taker flags and txid key prefix. Case C/D use a maker
# timeout of 3600 s: the taker refuses to claim inside a 1800 s safety margin, and validate()
# needs taker - maker >= 10800 s. Happy uses the unmodified testnet profile.
btc_sats="${E2E_BTC_SATS:-10000}"
timing=""
taker_flags=()
case "$scenario" in
  happy) port=18491; prefix=happy; timeout_secs=28800 ;;
  case-c)
    port=18492; prefix=casec; timeout_secs=21600
    timing=$'[swap]\nmaker_timeout_secs = 3600\ntaker_timeout_secs = 14410\n'
    taker_flags=(--never-claim) ;;
  case-d)
    port=18493; prefix=cased; timeout_secs=21600
    timing=$'[swap]\nmaker_timeout_secs = 3600\ntaker_timeout_secs = 14410\n'
    taker_flags=(--claim-not-before 2400) ;;
  *) usage ;;
esac

state="${E2E_STATE_DIR:-$HOME/.local/state/iron-divi-swap-poc}/$scenario-$backend"
case "$state" in "$ROOT"/*) die "state dir must be outside the repo: $state" ;; esac
mkdir -p "$state"
chmod 700 "$state"
log="$state/daemon.log"
base="http://127.0.0.1:$port"

vault="op://global_secret_store"
ref() { echo "$vault/IronDivi Swap POC - $1/password"; }

if [[ "$backend" == live ]]; then
  # Fail fast, once, before anything starts: an unanswered 1Password prompt is a park, not a retry.
  for k in maker-divi maker-btc taker-divi taker-btc; do
    if ! timeout 90 op read "$(ref "$k")" >/dev/null 2>&1; then
      die "cannot read the $k key from 1Password (locked, or authorization timeout). Unlock 1Password and rerun."
    fi
  done
fi

echo "e2e: building"
(cd "$ROOT" && cargo build -q -p divi-swapd -p divi-swap-cli)
swapd="$ROOT/target/debug/divi-swapd"
swap="$ROOT/target/debug/divi-swap"

cat >"$state/divi-swapd.toml" <<TOML
listen = "127.0.0.1:$port"
db_path = "$state/maker.db"
tick_secs = 5
$timing
[divi]
key = "$(ref maker-divi)"
wallet_path = "$state/maker-wallet.json"
scan_from_height = 339800

[btc]
key = "$(ref maker-btc)"
TOML

# A previous run's taker DB and sessions are the evidence for that swap; never mix runs.
if [[ -e "$state/taker.db" ]]; then
  stamp="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$state/old-$stamp"
  for f in "$state"/taker.db* "$state"/maker.db* "$state"/daemon.log; do
    [[ -e "$f" ]] && mv "$f" "$state/old-$stamp/"
  done
fi

daemon_pid=""
cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "e2e: scenario=$scenario backend=$backend maker=$base state=$state"
"$swapd" --config "$state/divi-swapd.toml" --backend "$backend" >>"$log" 2>&1 &
daemon_pid=$!

ready=""
for _ in $(seq 1 120); do
  kill -0 "$daemon_pid" 2>/dev/null || { tail -20 "$log" >&2; die "daemon exited during startup"; }
  if [[ "$(curl -s "$base/healthz" | jq -r '.ok // empty' 2>/dev/null)" == true ]]; then ready=1; break; fi
  sleep 2
done
[[ -n "$ready" ]] || { tail -20 "$log" >&2; die "daemon never became healthy"; }
echo "e2e: daemon healthy"

taker=("$swap" --db "$state/taker.db" --backend "$backend")
if [[ "$backend" == live ]]; then
  taker+=(--divi-key "$(ref taker-divi)" --btc-key "$(ref taker-btc)")
fi

if [[ "$backend" == mock ]]; then
  "${taker[@]}" quote --maker "$base" --offer divi-btc-testnet --btc-sats "$btc_sats"
  local_id="$("${taker[@]}" accept --maker "$base" --offer divi-btc-testnet --btc-sats "$btc_sats" | tail -1)"
  echo "e2e: mock plumbing ok (accepted $local_id); no swap is possible across mock processes"
  exit 0
fi

out="$state/taker-run.log"
"${taker[@]}" run --maker "$base" --offer divi-btc-testnet --btc-sats "$btc_sats" \
  --timeout-secs "$timeout_secs" "${taker_flags[@]}" 2>&1 | tee "$out"
local_id="$(tail -1 "$out" | awk '{print $1}')"
[[ -n "$local_id" ]] || die "taker run printed no swap id"

# The maker's last action (BTC claim, or DIVI refund) trails the taker; wait for it.
txids=""
for _ in $(seq 1 360); do
  txids="$("${taker[@]}" txids --swap "$local_id")"
  grep -q '^maker_state=Done' <<<"$txids" && break
  sleep 10
done
echo "$txids"
grep -q '^maker_state=Done' <<<"$txids" || die "maker did not reach Done"

get() { sed -n "s/^$1=//p" <<<"$txids" | head -1; }
{
  echo "- ${prefix}_btc_lock_txid: $(get btc_lock)"
  echo "- ${prefix}_divi_lock_txid: $(get divi_lock)"
  if [[ "$scenario" == case-c ]]; then
    echo "- ${prefix}_divi_refund_txid: $(get divi_spend_by_maker)"
    echo "- ${prefix}_btc_refund_txid: $(get btc_refund_by_taker)"
  else
    echo "- ${prefix}_divi_claim_txid: $(get divi_claim_by_taker)"
    echo "- ${prefix}_btc_claim_txid: $(get btc_claim_by_maker)"
  fi
  if [[ "$scenario" == case-d ]]; then
    secs="$(sed -n 's/.*claim_secs_before_timeout=\([0-9]*\).*/\1/p' "$out" | head -1)"
    echo "- cased_claim_secs_before_timeout: $secs"
  fi
} | tee "$state/results.txt"
echo "e2e: $scenario done; paste $state/results.txt into the status file once the txids confirm"
