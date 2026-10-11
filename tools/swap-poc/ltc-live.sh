#!/usr/bin/env bash
# LTC live-readiness driver (orchestrator, wave 3): happy path and case C (both sides
# refund), both directions (divi-ltc-testnet: taker pays LTC; ltc-divi-testnet: taker pays
# DIVI), against a local divi-swapd with an [ltc] section. Modeled on tools/swap-poc/e2e.sh
# (the BTC rev-live / case-C driver): same scenario/offer/state-dir shape, same 1Password-ref
# discipline, trimmed to LTC and extended with --dry-run.
#
#   tools/swap-poc/ltc-live.sh [--scenario happy|case-c|all] [--direction forward|reverse|both]
#                              [--backend live|mock] [--dry-run] [--maker-url URL]
#
# --maker-url URL: drive an already-running maker instead of a local one (e.g. the Wave 4
# dnsdivi divi-swapd through `ssh -N -L 18480:127.0.0.1:18480 dnsdivi`, URL
# http://127.0.0.1:18480), like e2e.sh --maker-url. Nothing is built and no local divi-swapd
# is configured or started: the taker binary must already exist (E2E_BIN_DIR, else
# target/release, else target/debug). Only the taker keys are read. The remote maker keeps its
# own timeout profile (testnet: maker 10800 s / taker 21600 s, so case C ends ~6 h in plus MTP
# lag; the run timeout is raised to match). Before any swap it checks the remote is healthy,
# serves the requested offers on ltc, and quotes counter_chain "ltc". State dir:
# ltc-<scenario>-deployed (ltc-<scenario>-deployed-mock for a mock rehearsal). With --backend mock it needs --dry-run (a mock taker's chains are
# its own, so only quote + accept can be rehearsed, e.g. against `divi-swapd --backend mock`).
# On a remote maker, --dry-run leaves one Accepted swap per scenario/direction there; the maker
# aborts each after its lock wait (30 min). No coins move either way.
#
# Keys: op://… references only, resolved by divi-swapd/divi-swap themselves — never a raw
# hex key on this host. Per docs/plans/swap-poc/funding.md (orchestrator decision 64ae2a0),
# testnets reuse the existing BTC swap keys on every secp256k1 chain: no maker-ltc/taker-ltc
# 1Password items exist, so this script passes the *-btc refs as the LTC key too.
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
die() { echo "ltc-live: $*" >&2; exit 1; }

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

ltc_sats="${E2E_LTC_SATS:-100000}"   # 0.001 tLTC: the live_fund_claim_refund / brief ceiling
fee_buffer_sats=5000
min_per_run=$((ltc_sats + fee_buffer_sats))

# Funding addresses (docs/plans/swap-poc/funding.md, decision 64ae2a0): the BTC swap keys'
# hash160 re-encoded as LTC P2WPKH — asserted equal in
# crates/swap-chain-ltc/src/address.rs::ltc_funding_addresses_match_funding_doc. No new
# 1Password items; taker/maker LTC key refs below are the *-btc ones.
taker_ltc_addr="tltc1qa826ffe73xnqsm64x6fvln7sl0zp3rgf5gnf3p"
maker_ltc_addr="tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz"

forward_runs=0 reverse_runs=0
for s in "${scenarios[@]}"; do
  for d in "${directions[@]}"; do
    [[ "$d" == forward ]] && forward_runs=$((forward_runs + 1))
    [[ "$d" == reverse ]] && reverse_runs=$((reverse_runs + 1))
  done
done

echo "ltc-live: scenarios=${scenarios[*]} directions=${directions[*]} backend=$backend dry_run=$dry_run"
echo "ltc-live: funding needed (testnet tLTC, keep every coin — never sweep back to a faucet):"
if ((forward_runs > 0)); then
  echo "  taker (divi-ltc-testnet, taker pays LTC): $taker_ltc_addr >= $((min_per_run * forward_runs)) litoshi" \
       "($forward_runs run(s) x $min_per_run)"
fi
if ((reverse_runs > 0)); then
  echo "  maker (ltc-divi-testnet, taker pays DIVI): $maker_ltc_addr >= $((min_per_run * reverse_runs)) litoshi" \
       "($reverse_runs run(s) x $min_per_run)"
fi
[[ "$backend" == mock ]] && echo "ltc-live: --backend mock needs no funding and no keys (in-process MockChain)"

vault="op://global_secret_store"
ref() { echo "$vault/IronDivi Swap POC - $1/password"; }
# No maker-ltc/taker-ltc items exist (funding.md): the LTC leg reuses the BTC refs.
maker_ltc_ref="$(ref maker-btc)"
taker_ltc_ref="$(ref taker-btc)"

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
  echo "ltc-live: remote maker $maker_url; taker binary $bin_dir/divi-swap (not rebuilt)"
elif [[ "${E2E_SKIP_BUILD:-0}" == 1 || -n "${E2E_BIN_DIR:-}" ]]; then
  echo "ltc-live: using existing binaries in ${E2E_BIN_DIR:-target/debug}"
  bin_dir="${E2E_BIN_DIR:-$ROOT/target/debug}"
else
  echo "ltc-live: building"
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
    if [[ "$d" == forward ]]; then want=divi-ltc-testnet; want_dir=taker_pays_btc
    else want=ltc-divi-testnet; want_dir=taker_pays_divi; fi
    jq -e --arg id "$want" --arg dir "$want_dir" \
      'any(.[]; .id == $id and .counter_chain == "ltc" and .direction == $dir)' <<<"$remote_offers" >/dev/null \
      || die "remote maker does not serve $want ($want_dir on ltc); served: $(jq -c '[.[].id]' <<<"$remote_offers")"
    q="$(curl -fsS -m 20 "$maker_url/offers/$want/quote?btc_sats=$ltc_sats" 2>/dev/null || true)"
    [[ "$(jq -r '.counter_chain // empty' <<<"$q" 2>/dev/null)" == ltc ]] \
      || die "remote maker's quote on $want is not counter_chain ltc (a pre-wave-4 daemon?): ${q:-<no answer>}"
  done
  echo "ltc-live: remote maker healthy; serves $(printf '%s ' "${directions[@]}")on ltc; keeping its own timeout profile"
fi

run_scenario() {
  local scenario="$1" port timing timeout_secs
  case "$scenario" in
    happy) port=18494; timing=""; timeout_secs=28800 ;;
    case-c)
      port=18495
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
  local state="${E2E_STATE_DIR:-$HOME/.local/state/iron-divi-swap-poc}/ltc-$scenario-$suffix"
  case "$state" in "$ROOT"/*) die "state dir must be outside the repo: $state" ;; esac
  mkdir -p "$state"; chmod 700 "$state"

  if [[ -n "$maker_url" ]]; then
    echo "ltc-live: [$scenario] remote maker at $maker_url (no local daemon)"
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

[ltc]
network = "testnet"
esplora_url = "https://litecoinspace.org/testnet/api"
key = "$maker_ltc_ref"

[[offers]]
id = "divi-ltc-testnet"
direction = "taker_pays_btc"
counter_chain = "ltc"
divi_sats_per_btc = 1000000000000
min_btc_sats = 50000
max_btc_sats = 500000

[[offers]]
id = "ltc-divi-testnet"
direction = "taker_pays_divi"
counter_chain = "ltc"
divi_sats_per_btc = 1000000000000
min_btc_sats = 50000
max_btc_sats = 500000
TOML
  else
    # Mock ignores [divi]/[btc]/[ltc]/[[offers]] entirely and already adds both ltc offers
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
  echo "ltc-live: [$scenario] daemon healthy at $base"

  for d in "${directions[@]}"; do
    run_direction "$scenario" "$d" "$state" "$base" "$timeout_secs"
  done
  stop_daemon
}

run_direction() {
  local scenario="$1" direction="$2" scen_state="$3" base="$4" timeout_secs="$5"
  local offer taker_flags=()
  if [[ "$direction" == forward ]]; then offer=divi-ltc-testnet; else offer=ltc-divi-testnet; fi
  [[ "$scenario" == case-c ]] && taker_flags=(--never-claim)

  local state="$scen_state/$direction"
  mkdir -p "$state"; chmod 700 "$state"
  local taker=("$swap" --db "$state/taker.db" --backend "$backend" --counter-chain ltc)
  if [[ "$backend" == live ]]; then
    taker+=(--divi-key "$(ref taker-divi)" --ltc-key "$taker_ltc_ref")
    if [[ "$direction" == reverse ]]; then
      taker+=(--divi-wallet "$(dirname "$scen_state")/ltc-taker-divi-wallet.json")
    fi
  fi

  echo "ltc-live: [$scenario/$direction] offer=$offer dry_run=$dry_run"

  if ((dry_run)); then
    # `run` does quote+accept+lock+poll as one swap; a dry run instead stops right after
    # accept (quote then accept, same as `run`'s first two steps) so nothing further ever
    # calls lock — never creates the swap `run` would go on to use.
    "${taker[@]}" quote --maker "$base" --offer "$offer" --btc-sats "$ltc_sats"
    local local_id
    local_id="$("${taker[@]}" accept --maker "$base" --offer "$offer" --btc-sats "$ltc_sats" | tail -1)"
    [[ -n "$local_id" ]] || die "[$scenario/$direction] accept printed no swap id"
    echo "ltc-live: [$scenario/$direction] accepted $local_id (no broadcast yet)"
    echo "ltc-live: [$scenario/$direction] --dry-run: stopping before lock (first broadcast). OK."
    return 0
  fi

  local out="$state/taker-run.log" local_id
  "${taker[@]}" run --maker "$base" --offer "$offer" --btc-sats "$ltc_sats" \
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
  echo "ltc-live: [$scenario/$direction] done; txids in $state/results.txt"
}

for s in "${scenarios[@]}"; do
  run_scenario "$s"
done
echo "ltc-live: all requested scenarios/directions finished"
