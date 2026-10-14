#!/usr/bin/env bash
# XMR ↔ DIVI stagenet soak (plan item A8, docs/plans/swap-poc/xmr-mainnet-plan.md): drive many
# taker swaps against the deployed maker and record how each one ended. Stagenet only: it refuses
# any --xmr-network but stagenet, and the maker refuses mainnet on its own.
#
# Runs from the Mac with two tunnels already open (this script does not open them):
#   ssh -N -L 18482:127.0.0.1:18480 dnsdivi      # maker API
#   ssh -N -L 38088:127.0.0.1:38088 hp2          # taker's stagenet monero-wallet-rpc
# Needs `secret-broker serve` running: every taker process resolves its op:// refs, and without the
# broker each one is a Touch ID prompt.
#
#   tools/swap-poc/xmr-soak.sh --taker-bin PATH [--count N] [--parallel P] [--btc-sats S]
#       [--scenario happy|accept-only|lock-only] [--out DIR] [--dry-run]
#
# Scenarios (what the taker does; the maker always runs its normal daemon):
#   happy        `run`: lock XMR, redeem DIVI. Maker outcome redeemed → swept → done.
#   accept-only  `accept` (signatures sent; the maker locks DIVI), then nothing. Past t_cancel the
#                maker cancels and refunds itself. Maker outcome cancelled → refunded → done.
#   lock-only    step with `claim` until the taker's XMR lock is reported, then stop. Past t_cancel
#                the maker refunds, which reveals the key the taker needs to take her XMR back:
#                rerun `claim` on that swap afterwards (`--resume DIR`). Exercises both refunds.
#   --resume DIR steps every lock-only swap under DIR with `claim` until it is done.
#
# Output: DIR/results.tsv (n, scenario, local id, exit, outcome, seconds) and one log
# per swap. The maker's own view is the record of truth: compare with
#   curl -s 127.0.0.1:18482/xmr/swaps | jq -r '.[] | [.id,.state,.last_error] | @tsv'
set -euo pipefail

taker_bin="" count=20 parallel=4 btc_sats=200000 scenario=happy out="" dry=0 resume=""
maker=http://127.0.0.1:18482 offer=divi-xmr-stagenet network=stagenet
monerod=${XMR_MONEROD_URL:-http://node.monerodevs.org:38089}
wallet_rpc=http://127.0.0.1:38088
# The taker's own stagenet address (hp2 mining-wallet): where her refunds sweep to.
sweep=${XMR_TAKER_SWEEP:-5AbHxitM2WMiq1b957FpA6ZMHPPSex3XNH3UU9ox2tGpMHj9mNwCXCEXWMUVnfhnrQLyeh8vNDy6Mitu5d4L9Zjm9p8LaiS}
item="op://global_secret_store/IronDivi Swap POC"

while [ $# -gt 0 ]; do
  case "$1" in
    --taker-bin) taker_bin=$2; shift 2 ;;
    --count) count=$2; shift 2 ;;
    --parallel) parallel=$2; shift 2 ;;
    --btc-sats) btc_sats=$2; shift 2 ;;
    --scenario) scenario=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --resume) resume=$2; shift 2 ;;
    --maker) maker=$2; shift 2 ;;
    --xmr-network) network=$2; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "xmr-soak: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ "$network" = stagenet ] || { echo "xmr-soak: stagenet only" >&2; exit 2; }
case "$scenario" in happy|accept-only|lock-only) ;; *) echo "xmr-soak: bad --scenario" >&2; exit 2 ;; esac
[ -n "$taker_bin" ] && [ -x "$taker_bin" ] || { echo "xmr-soak: --taker-bin must be executable" >&2; exit 2; }
out=${resume:-${out:-$HOME/.local/state/iron-divi-swap-poc/xmr-soak/$(date -u +%Y%m%dT%H%M%SZ)}}
mkdir -p "$out"; chmod 700 "$out"

if [ "$dry" = 0 ]; then
  curl -sf -m 10 "$maker/healthz" | jq -e '.divi_scan.state == "done" or .divi_scan == null' >/dev/null \
    || { echo "xmr-soak: maker not ready at $maker (tunnel? wallet scan?)" >&2; exit 1; }
  # The wallet-rpc login name, once for the whole soak (not a secret, but kept out of the repo).
  rpc_user=$(secret get --name taker-xmr-wallet-rpc-username \
    --op-ref "$item - taker-xmr-wallet-rpc/username" </dev/null)
else
  rpc_user="dry-run"
fi

taker() { # taker <db> <args...>
  local db=$1; shift
  local cmd=("$taker_bin" --db "$db" --backend live --counter-chain xmr
    --divi-key "$item - taker-divi/password"
    --xmr-network "$network" --xmr-monerod-url "$monerod"
    --xmr-wallet-rpc-url "$wallet_rpc" --xmr-wallet-rpc-user "$rpc_user"
    --xmr-wallet-rpc-password "$item - taker-xmr-wallet-rpc/password"
    --xmr-sweep-address "$sweep" --xmr-lookback-blocks 720 "$@")
  if [ "$dry" = 1 ]; then echo "would run: ${cmd[*]}"; else "${cmd[@]}"; fi
}

one() { # one <n>: run swap n of the chosen scenario in its own db
  local n=$1 dir="$out/swap-$1" t0 rc=0 res lid="" outcome=""
  mkdir -p "$dir"; t0=$(date +%s)
  case "$scenario" in
    happy)
      res=$(taker "$dir/taker.db" run --maker "$maker" --offer "$offer" --btc-sats "$btc_sats" \
        --poll-secs 30 --timeout-secs 7200 2>"$dir/log") || rc=$?
      lid=${res%% *}; outcome=${res#* } ;;
    accept-only)
      lid=$(taker "$dir/taker.db" accept --maker "$maker" --offer "$offer" --btc-sats "$btc_sats" \
        2>"$dir/log") || rc=$?
      outcome=accepted-left ;;
    lock-only)
      lid=$(taker "$dir/taker.db" accept --maker "$maker" --offer "$offer" --btc-sats "$btc_sats" \
        2>"$dir/log") || rc=$?
      outcome=lock-pending
      if [ "$rc" = 0 ] && [ "$dry" = 0 ]; then
        for _ in $(seq 1 120); do
          taker "$dir/taker.db" claim --swap "$lid" >>"$dir/log" 2>&1 || true
          if taker "$dir/taker.db" status --swap "$lid" 2>>"$dir/log" | jq -e '.xmr_lock_txid != null' >/dev/null; then
            outcome=xmr-locked-left; break
          fi
          sleep 30
        done
      fi ;;
  esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$scenario" "$lid" "$rc" "${outcome:-}" \
    "$(( $(date +%s) - t0 ))" >>"$out/results.tsv"
  echo "swap $n ($scenario): exit $rc, ${outcome:-?}"
}

if [ -n "$resume" ]; then
  for dir in "$out"/swap-*; do
    local_id=$(awk -F'\t' -v n="${dir##*swap-}" '$1==n {print $3}' "$out/results.tsv")
    [ -n "$local_id" ] || continue
    for _ in $(seq 1 240); do
      st=$(taker "$dir/taker.db" claim --swap "$local_id" 2>>"$dir/log" || true)
      [ "$st" = Done ] && break
      sleep 60
    done
    echo "resume ${dir##*/}: ${st:-?}"
  done
  exit 0
fi

echo "xmr-soak: $count × $scenario, $parallel at a time, $btc_sats × 1e-8 XMR each, out $out"
n=0
while [ "$n" -lt "$count" ]; do
  for _ in $(seq 1 "$parallel"); do
    [ "$n" -lt "$count" ] || break
    n=$((n + 1)); one "$n" &
    sleep 5   # stagger quotes so they do not race the maker's DIVI coin selection all at once
  done
  wait
done
echo "xmr-soak: done; $out/results.tsv"
