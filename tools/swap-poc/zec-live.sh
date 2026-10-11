#!/usr/bin/env bash
# ZEC live-readiness driver (lane zec, wave 3): happy path and case C (both sides refund),
# both directions (divi-zec-testnet: taker pays ZEC; zec-divi-testnet: taker pays DIVI),
# against a local divi-swapd with a [zec] section. Modeled directly on
# tools/swap-poc/ltc-live.sh (same scenario/offer/state-dir shape, same 1Password-ref
# discipline, same --dry-run and --maker-url support), trimmed/renamed for ZEC.
#
#   tools/swap-poc/zec-live.sh [--scenario happy|case-c|all] [--direction forward|reverse|both]
#                              [--backend live|mock] [--dry-run] [--maker-url URL]
#
# --maker-url URL: drive an already-running maker instead of a local one (e.g. a deployed
# divi-swapd through an SSH tunnel), like e2e.sh/ltc-live.sh --maker-url. Nothing is built
# and no local divi-swapd is configured or started: the taker binary must already exist
# (E2E_BIN_DIR, else target/release, else target/debug). Only the taker keys are read. The
# remote maker keeps its own timeout profile (testnet: maker 10800 s / taker 21600 s, so
# case C ends ~6 h in plus MTP lag; the run timeout is raised to match). Before any swap it
# checks the remote is healthy, serves the requested offers on zec, and quotes
# counter_chain "zec". State dir: zec-<scenario>-deployed (zec-<scenario>-deployed-mock for
# a mock rehearsal). With --backend mock it needs --dry-run (a mock taker's chains are its
# own, so only quote + accept can be rehearsed, e.g. against `divi-swapd --backend mock`).
# On a remote maker, --dry-run leaves one Accepted swap per scenario/direction there; the
# maker aborts each after its lock wait (30 min). No coins move either way.
#
# Keys: op://… references only, resolved by divi-swapd/divi-swap themselves — never a raw
# hex key on this host. Per docs/plans/swap-poc/funding.md (orchestrator decision 64ae2a0),
# testnets reuse the existing BTC swap keys on every secp256k1 chain: no maker-zec/taker-zec
# 1Password items exist, so this script passes the *-btc refs as the ZEC key too.
#
# --dry-run stops after `accept` (quote + accept the offer) and never calls `lock`: the
# maker only calls build_funding on TakerLockConfirmed -> MakerLocked (divi_swap::maker, the
# staking invariant), well after the taker's lock, so stopping before the taker's own lock
# guarantees neither side has broadcast anything. Safe with --backend mock (no keys, no
# network) or --backend live (real keys, still nothing signed-and-sent).
#
# Without --dry-run this runs the full `divi-swap run` flow like e2e.sh and takes hours
# (case-c refund timelocks); run it as a background command.
set -euo pipefail

usage() {
  echo "usage: $0 [--scenario happy|case-c|all] [--direction forward|reverse|both] [--backend live|mock] [--dry-run] [--maker-url URL]" >&2
  exit 2
}
die() { echo "zec-live: $*" >&2; exit 1; }

scenario_arg=all
direction_arg=both
backend=live
dry_run=0
maker_url=""
while (($#)); do
  case "$1" in
    --scenario) scenario_arg="${2:-}"; shift 2 || usage ;;
    --direction) direction_arg="${2:-}"; shift 2 || usage ;;
    --backend) backend="${2:-}"; shift 2 || usage ;;
    --dry-run) dry_run=1; shift ;;
    --maker-url) maker_url="${2:-}"; shift 2 || usage; [[ -n "$maker_url" ]] || usage ;;
    *) usage ;;
  esac
done
[[ "$backend" == live || "$backend" == mock ]] || usage
case "$scenario_arg" in happy|case-c|all) ;; *) usage ;; esac
case "$direction_arg" in forward|reverse|both) ;; *) usage ;; esac
maker_url="${maker_url%/}"
if [[ -n "$maker_url" && "$backend" == mock ]] && ((!dry_run)); then
  die "--maker-url with --backend mock needs --dry-run (a mock taker cannot move a remote maker's swap)"
fi

scenarios=(happy case-c); [[ "$scenario_arg" == all ]] || scenarios=("$scenario_arg")
directions=(forward reverse); [[ "$direction_arg" == both ]] || directions=("$direction_arg")

ROOT="$(git rev-parse --show-toplevel)"
export PATH="$HOME/.local/bin:/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

zec_zats="${E2E_ZEC_SATS:-100000}"   # 0.001 TAZ: the live_fund_claim_refund / brief ceiling's neighborhood
fee_buffer_sats=5000
min_per_run=$((zec_zats + fee_buffer_sats))

# Funding addresses (docs/plans/swap-poc/funding.md, decision 64ae2a0): the BTC swap keys'
# hash160 re-encoded as Zcash t-addresses — asserted equal in
# crates/swap-chain-zec/src/address.rs::funding_table_addresses_match. No new 1Password
# items; taker/maker ZEC key refs below are the *-btc ones.
taker_zec_addr="tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk"
maker_zec_addr="tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn"

forward_runs=0 reverse_runs=0
for s in "${scenarios[@]}"; do
  for d in "${directions[@]}"; do
    [[ "$d" == forward ]] && forward_runs=$((forward_runs + 1))
    [[ "$d" == reverse ]] && reverse_runs=$((reverse_runs + 1))
  done
done

echo "zec-live: scenarios=${scenarios[*]} directions=${directions[*]} backend=$backend dry_run=$dry_run"
echo "zec-live: funding needed (testnet TAZ, keep every coin — never sweep back to a faucet):"
if ((forward_runs > 0)); then
  echo "  taker (divi-zec-testnet, taker pays ZEC): $taker_zec_addr >= $((min_per_run * forward_runs)) zatoshi" \
       "($forward_runs run(s) x $min_per_run)"
fi
if ((reverse_runs > 0)); then
  echo "  maker (zec-divi-testnet, taker pays DIVI): $maker_zec_addr >= $((min_per_run * reverse_runs)) zatoshi" \
       "($reverse_runs run(s) x $min_per_run)"
fi
[[ "$backend" == mock ]] && echo "zec-live: --backend mock needs no funding and no keys (in-process MockChain)"

vault="op://global_secret_store"
ref() { echo "$vault/IronDivi Swap POC - $1/password"; }
# No maker-zec/taker-zec items exist (funding.md): the ZEC leg reuses the BTC refs.
maker_zec_ref="$(ref maker-btc)"
taker_zec_ref="$(ref taker-btc)"

if [[ "$backend" == live ]]; then
  keys=(taker-divi taker-btc)
  [[ -n "$maker_url" ]] || keys+=(maker-divi maker-btc)   # a remote maker holds its own
  for k in "${keys[@]}"; do
    if ! secret get --name "irondivi-swap-poc-$k-password" --op-ref "$(ref "$k")" >/dev/null 2>&1; then
      die "cannot read the $k key (1Password locked, or secret-broker not running: secret-broker status)"
    fi
  done
fi

# One daemon per scenario (run_scenario sets/clears this); a top-level EXIT trap is the
# backstop if the script dies mid-scenario (Ctrl-C, an unexpected error).
daemon_pid=""
stop_daemon() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  daemon_pid=""
}
trap stop_daemon EXIT INT TERM

if [[ -n "$maker_url" ]]; then
  # Remote maker: build nothing; use the taker binary that is already there.
  bin_dir="${E2E_BIN_DIR:-}"
  if [[ -z "$bin_dir" ]]; then
    bin_dir="$ROOT/target/release"
    [[ -x "$bin_dir/divi-swap" ]] || bin_dir="$ROOT/target/debug"
  fi
  [[ -x "$bin_dir/divi-swap" ]] \
    || die "--maker-url builds nothing: no divi-swap in $bin_dir (cargo build --release -p divi-swap-cli, or set E2E_BIN_DIR)"
  echo "zec-live: remote maker $maker_url; taker binary $bin_dir/divi-swap (not rebuilt)"
elif [[ "${E2E_SKIP_BUILD:-0}" == 1 || -n "${E2E_BIN_DIR:-}" ]]; then
  echo "zec-live: using existing binaries in ${E2E_BIN_DIR:-target/debug}"
  bin_dir="${E2E_BIN_DIR:-$ROOT/target/debug}"
else
  echo "zec-live: building"
  (cd "$ROOT" && cargo build -q -p divi-swapd -p divi-swap-cli)
  bin_dir="$ROOT/target/debug"
fi
swapd="$bin_dir/divi-swapd"
swap="$bin_dir/divi-swap"

healthy_at() { [[ "$(curl -s -m 10 "$1/healthz" | jq -r '.ok // empty' 2>/dev/null)" == true ]]; }

# Remote maker: fail before any swap if it cannot run the requested ones.
if [[ -n "$maker_url" ]]; then
  healthy_at "$maker_url" || die "remote maker $maker_url is not healthy (tunnel down, or its DIVI wallet scan still running?)"
  remote_offers="$(curl -fsS -m 20 "$maker_url/offers")" || die "remote maker $maker_url: GET /offers failed"
  for d in "${directions[@]}"; do
    if [[ "$d" == forward ]]; then want=divi-zec-testnet; want_dir=taker_pays_btc
    else want=zec-divi-testnet; want_dir=taker_pays_divi; fi
    jq -e --arg id "$want" --arg dir "$want_dir" \
      'any(.[]; .id == $id and .counter_chain == "zec" and .direction == $dir)' <<<"$remote_offers" >/dev/null \
      || die "remote maker does not serve $want ($want_dir on zec); served: $(jq -c '[.[].id]' <<<"$remote_offers")"
    q="$(curl -fsS -m 20 "$maker_url/offers/$want/quote?btc_sats=$zec_zats" 2>/dev/null || true)"
    [[ "$(jq -r '.counter_chain // empty' <<<"$q" 2>/dev/null)" == zec ]] \
      || die "remote maker's quote on $want is not counter_chain zec (a pre-wave-2 daemon?): ${q:-<no answer>}"
  done
  echo "zec-live: remote maker healthy; serves $(printf '%s ' "${directions[@]}")on zec; keeping its own timeout profile"
fi

run_scenario() {
  local scenario="$1" port timing timeout_secs
  case "$scenario" in
    happy) port=18496; timing=""; timeout_secs=28800 ;;
    case-c)
      port=18497
      timing=$'[swap]\nmaker_timeout_secs = 3600\ntaker_timeout_secs = 14410\n'
      timeout_secs=21600 ;;
  esac
  # A remote maker keeps its own profile (testnet 10800/21600 s): case C's taker refund lands
  # ~6 h in plus MTP lag, so the run may take up to 10 h.
  local suffix="$backend"
  if [[ -n "$maker_url" ]]; then
    suffix=deployed
    [[ "$backend" == mock ]] && suffix=deployed-mock   # a rehearsal never shares the live taker db
    [[ "$scenario" == case-c ]] && timeout_secs=36000
  fi
  local state="${E2E_STATE_DIR:-$HOME/.local/state/iron-divi-swap-poc}/zec-$scenario-$suffix"
  case "$state" in "$ROOT"/*) die "state dir must be outside the repo: $state" ;; esac
  mkdir -p "$state"; chmod 700 "$state"

  if [[ -n "$maker_url" ]]; then
    echo "zec-live: [$scenario] remote maker at $maker_url (no local daemon)"
    for d in "${directions[@]}"; do
      run_direction "$scenario" "$d" "$state" "$maker_url" "$timeout_secs"
    done
    return 0
  fi

  if [[ "$backend" == live ]]; then
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
network = "testnet"
esplora_url = "https://mempool.space/testnet/api"
key = "$(ref maker-btc)"

[zec]
lightwalletd_url = "https://testnet.zec.rocks:443"
key = "$maker_zec_ref"

[[offers]]
id = "divi-zec-testnet"
direction = "taker_pays_btc"
counter_chain = "zec"
divi_sats_per_btc = 500000000000
min_btc_sats = 50000
max_btc_sats = 500000

[[offers]]
id = "zec-divi-testnet"
direction = "taker_pays_divi"
counter_chain = "zec"
divi_sats_per_btc = 500000000000
min_btc_sats = 50000
max_btc_sats = 500000
TOML
  else
    # Mock ignores [divi]/[btc]/[zec]/[[offers]] entirely and already adds both zec offers
    # (divi_swapd::mock_counter_offers, merged by main.rs's mock_offers()).
    cat >"$state/divi-swapd.toml" <<TOML
listen = "127.0.0.1:$port"
db_path = "$state/maker.db"
tick_secs = 5
$timing
TOML
  fi

  local base="http://127.0.0.1:$port"
  local log="$state/daemon.log"
  "$swapd" --config "$state/divi-swapd.toml" --backend "$backend" >>"$log" 2>&1 &
  daemon_pid=$!

  healthy() { [[ "$(curl -s -m 10 "$base/healthz" | jq -r '.ok // empty' 2>/dev/null)" == true ]]; }
  # /healthz waits for the first DIVI wallet scan, which takes several minutes live.
  local ready=""
  for _ in $(seq 1 "${E2E_HEALTH_TRIES:-900}"); do
    kill -0 "$daemon_pid" 2>/dev/null || { tail -20 "$log" >&2; stop_daemon; die "daemon exited during startup"; }
    if healthy; then ready=1; break; fi
    sleep 2
  done
  [[ -n "$ready" ]] || { tail -20 "$log" >&2; stop_daemon; die "daemon never became healthy"; }
  echo "zec-live: [$scenario] daemon healthy at $base"

  for d in "${directions[@]}"; do
    run_direction "$scenario" "$d" "$state" "$base" "$timeout_secs"
  done
  stop_daemon
}

run_direction() {
  local scenario="$1" direction="$2" scen_state="$3" base="$4" timeout_secs="$5"
  local offer taker_flags=()
  if [[ "$direction" == forward ]]; then offer=divi-zec-testnet; else offer=zec-divi-testnet; fi
  [[ "$scenario" == case-c ]] && taker_flags=(--never-claim)

  local state="$scen_state/$direction"
  mkdir -p "$state"; chmod 700 "$state"
  local taker=("$swap" --db "$state/taker.db" --backend "$backend" --counter-chain zec)
  if [[ "$backend" == live ]]; then
    taker+=(--divi-key "$(ref taker-divi)" --zec-key "$taker_zec_ref")
    if [[ "$direction" == reverse ]]; then
      taker+=(--divi-wallet "$(dirname "$scen_state")/zec-taker-divi-wallet.json")
    fi
  fi

  echo "zec-live: [$scenario/$direction] offer=$offer dry_run=$dry_run"

  if ((dry_run)); then
    # `run` does quote+accept+lock+poll as one swap; a dry run instead stops right after
    # accept (quote then accept, same as `run`'s first two steps) so nothing further ever
    # calls lock — never creates the swap `run` would go on to use.
    "${taker[@]}" quote --maker "$base" --offer "$offer" --btc-sats "$zec_zats"
    local local_id
    local_id="$("${taker[@]}" accept --maker "$base" --offer "$offer" --btc-sats "$zec_zats" | tail -1)"
    [[ -n "$local_id" ]] || die "[$scenario/$direction] accept printed no swap id"
    echo "zec-live: [$scenario/$direction] accepted $local_id (no broadcast yet)"
    echo "zec-live: [$scenario/$direction] --dry-run: stopping before lock (first broadcast). OK."
    return 0
  fi

  local out="$state/taker-run.log" local_id
  "${taker[@]}" run --maker "$base" --offer "$offer" --btc-sats "$zec_zats" \
    --timeout-secs "$timeout_secs" ${taker_flags[@]+"${taker_flags[@]}"} 2>&1 | tee "$out"
  local_id="$(tail -1 "$out" | awk '{print $1}')"
  [[ -n "$local_id" ]] || die "[$scenario/$direction] taker run printed no swap id"

  local txids=""
  for _ in $(seq 1 360); do
    txids="$("${taker[@]}" txids --swap "$local_id")"
    grep -q '^maker_state=Done' <<<"$txids" && break
    sleep 10
  done
  echo "$txids"
  grep -q '^maker_state=Done' <<<"$txids" || die "[$scenario/$direction] maker did not reach Done"
  echo "$txids" | tee "$state/results.txt" >/dev/null
  echo "zec-live: [$scenario/$direction] done; txids in $state/results.txt"
}

for s in "${scenarios[@]}"; do
  run_scenario "$s"
done
echo "zec-live: all requested scenarios/directions finished"
