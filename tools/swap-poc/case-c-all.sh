#!/usr/bin/env bash
# Live walk-away refund (case C) for every counter chain on an already-running maker, strictly
# serially: LTC forward, LTC reverse, ZEC forward, ZEC reverse. Each step is
#   tools/swap-poc/<coin>-live.sh --scenario case-c --direction <dir> --maker-url URL
# (which builds nothing, starts no daemon, reads only the taker keys and keeps the maker's own
# timeout profile). The next step starts only after the previous one exited 0; the first
# failure stops the run (resume with --from).
#
#   tools/swap-poc/case-c-all.sh [--maker-url URL] [--backend live|mock] [--dry-run | --print]
#                                [--from ltc/forward|ltc/reverse|zec/forward|zec/reverse]
#
# --maker-url  default http://127.0.0.1:18482 (the maker through an ssh tunnel, e.g.
#              `ssh -N -L 18482:127.0.0.1:18480 dnsdivi`).
# --dry-run    read-only funding prechecks, then each step with --dry-run (quote + accept only,
#              nothing locked; the maker aborts those Accepted swaps after 30 min).
# --print      print the plan and every command; run nothing, contact nothing.
# --backend mock  rehearsal (implies --dry-run, no keys, no funding): if nothing answers at
#              the maker URL on 127.0.0.1, a throwaway `divi-swapd --backend mock` is started
#              there for the run and stopped at the end.
#
# Funding precheck (live, before every step, read-only, no key): the coin the side that locks
# the counter chain needs — forward: the taker's, reverse: the maker's — must hold one run's
# amount + fee buffer (LTC: litecoinspace confirmed balance; ZEC: GetAddressUtxos via the zec
# lane's check_addr_utxos example). The DIVI side cannot be checked without a key or an address
# index and is the operator's to confirm. Addresses: docs/plans/swap-poc/funding.md.
#
# A live run takes about a day (each case C ends ~6 h after its lock, plus MTP lag): run it as a
# background job. Logs: $E2E_STATE_DIR (default ~/.local/state/iron-divi-swap-poc)/case-c-all-<UTC>-<pid>/.
set -euo pipefail

usage() {
  sed -n '9,10p' "$0" | sed 's/^# *//' >&2
  exit 2
}
die() { echo "case-c-all: $*" >&2; exit 1; }

maker_url="http://127.0.0.1:18482"
backend=live
dry_run=0
print_only=0
from=""
while (($#)); do
  case "$1" in
    --maker-url) maker_url="${2:-}"; shift 2 || usage; [[ -n "$maker_url" ]] || usage ;;
    --backend) backend="${2:-}"; shift 2 || usage ;;
    --dry-run) dry_run=1; shift ;;
    --print) print_only=1; shift ;;
    --from) from="${2:-}"; shift 2 || usage ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
done
[[ "$backend" == live || "$backend" == mock ]] || usage
maker_url="${maker_url%/}"
[[ "$backend" == mock ]] && dry_run=1   # a mock taker cannot move a remote maker's swap

steps=(ltc/forward ltc/reverse zec/forward zec/reverse)
if [[ -n "$from" ]]; then
  i=-1
  for k in "${!steps[@]}"; do [[ "${steps[$k]}" == "$from" ]] && i=$k; done
  ((i >= 0)) || die "--from must be one of: ${steps[*]}"
  steps=("${steps[@]:i}")
fi

ROOT="$(git rev-parse --show-toplevel)"
export PATH="$HOME/.local/bin:/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

# One run's need per locking side (amount + fee buffer), the same figures the per-coin scripts use.
ltc_need=$((${E2E_LTC_SATS:-100000} + 5000))
zec_need=$((${E2E_ZEC_SATS:-100000} + 20000))
ltc_taker=tltc1qa826ffe73xnqsm64x6fvln7sl0zp3rgf5gnf3p
ltc_maker=tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz
zec_taker=tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk
zec_maker=tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn

step_cmd() {   # step_cmd <coin> <dir> → the per-coin command as an array in $cmd
  cmd=("$ROOT/tools/swap-poc/$1-live.sh" --scenario case-c --direction "$2"
       --maker-url "$maker_url" --backend "$backend")
  ((dry_run)) && cmd+=(--dry-run)
  return 0
}

# Who locks the counter coin in this step, and what that address must hold.
locker() {   # locker <coin> <dir> → "<role> <address> <need> <unit>"
  case "$1/$2" in
    ltc/forward) echo "taker $ltc_taker $ltc_need litoshi" ;;
    ltc/reverse) echo "maker $ltc_maker $ltc_need litoshi" ;;
    zec/forward) echo "taker $zec_taker $zec_need zatoshi" ;;
    zec/reverse) echo "maker $zec_maker $zec_need zatoshi" ;;
  esac
}

balance() {   # balance <coin> <address> → confirmed smallest units on stdout (read-only, no key)
  case "$1" in
    ltc)
      curl -fsS -m 20 "https://litecoinspace.org/testnet/api/address/$2" \
        | jq -r '.chain_stats.funded_txo_sum - .chain_stats.spent_txo_sum' ;;
    zec)
      (cd "$ROOT" && cargo run -q -p swap-chain-zec --example check_addr_utxos -- "$2") \
        | sed -n -E "s/^$2: total ([0-9]+) zatoshi.*/\1/p" ;;
  esac
}

if ((print_only)); then
  echo "case-c-all: plan (nothing run): maker=$maker_url backend=$backend dry_run=$dry_run"
  for s in "${steps[@]}"; do
    coin="${s%/*}" dir="${s#*/}"
    read -r role addr need unit <<<"$(locker "$coin" "$dir")"
    [[ "$backend" == live ]] && echo "  precheck $s: $role $addr >= $need $unit (read-only)"
    step_cmd "$coin" "$dir"
    printf '  run     %s:' "$s"; printf ' %q' "${cmd[@]}"; echo
  done
  exit 0
fi

state="${E2E_STATE_DIR:-$HOME/.local/state/iron-divi-swap-poc}/case-c-all-$(date -u +%Y%m%dT%H%M%SZ)-$$"
case "$state" in "$ROOT"/*) die "state dir must be outside the repo: $state" ;; esac
mkdir -p "$state"; chmod 700 "$state"

healthy() { [[ "$(curl -s -m 10 "$maker_url/healthz" | jq -r '.ok // empty' 2>/dev/null)" == true ]]; }

# Mock rehearsal: bring a throwaway mock maker up at the URL if none answers there.
mock_pid=""
stop_mock() { if [[ -n "$mock_pid" ]]; then kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true; fi; }
trap stop_mock EXIT INT TERM
if [[ "$backend" == mock ]] && ! healthy; then
  [[ "$maker_url" =~ ^http://127\.0\.0\.1:([0-9]+)$ ]] \
    || die "--backend mock: nothing at $maker_url, and only a 127.0.0.1 URL can get a throwaway mock maker"
  port="${BASH_REMATCH[1]}"
  swapd="${E2E_BIN_DIR:-$ROOT/target/debug}/divi-swapd"
  [[ -x "$swapd" ]] || (cd "$ROOT" && cargo build -q -p divi-swapd)
  printf 'listen = "127.0.0.1:%s"\ndb_path = "%s/mock-maker.db"\n' "$port" "$state" >"$state/mock-maker.toml"
  "$swapd" --config "$state/mock-maker.toml" --backend mock >"$state/mock-maker.log" 2>&1 &
  mock_pid=$!
  for _ in $(seq 1 60); do healthy && break; sleep 0.5; done
  echo "case-c-all: started a throwaway mock maker at $maker_url (pid $mock_pid)"
fi
healthy || die "maker $maker_url is not healthy (tunnel down, or its DIVI wallet scan still running?)"

echo "case-c-all: maker=$maker_url backend=$backend dry_run=$dry_run steps=${steps[*]} logs=$state"
done_steps=()
for s in "${steps[@]}"; do
  coin="${s%/*}" dir="${s#*/}"
  log="$state/${coin}-${dir}.log"
  if [[ "$backend" == live ]]; then
    read -r role addr need unit <<<"$(locker "$coin" "$dir")"
    have="$(balance "$coin" "$addr")" || die "[$s] funding precheck failed (could not read $addr)"
    [[ "$have" =~ ^[0-9]+$ ]] || die "[$s] funding precheck: unreadable balance for $addr: '$have'"
    if ((have < need)); then
      die "[$s] $role $addr holds $have $unit < $need needed; fund it (funding.md), then rerun with --from $s${done_steps[*]:+ (done: ${done_steps[*]})}"
    fi
    echo "case-c-all: [$s] funding ok: $role $addr holds $have $unit (>= $need); DIVI side unchecked (no key/index)"
  fi
  step_cmd "$coin" "$dir"
  echo "case-c-all: [$s] start $(date -u +%FT%TZ): ${cmd[*]}"
  if ! "${cmd[@]}" 2>&1 | tee "$log"; then
    die "[$s] failed (log: $log); fix, then rerun with --from $s${done_steps[*]:+ (done: ${done_steps[*]})}"
  fi
  done_steps+=("$s")
  echo "case-c-all: [$s] done $(date -u +%FT%TZ)"
done
echo "case-c-all: all done: ${done_steps[*]} (logs and per-step results under $state and the per-coin state dirs)"
