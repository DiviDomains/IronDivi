#!/usr/bin/env bash
# Live EVM USDC: happy path and case-c (both sides refund), both directions
# (divi-usdc-<network>: taker pays USDC; usdc-divi-<network>: taker pays DIVI), against a
# local divi-swapd with a [usdc] section. Modeled on tools/swap-poc/ltc-live.sh (the LTC/ZEC
# live-readiness driver): same --scenario/--direction/--dry-run shape and state-dir
# convention, extended with USDC's one-time deploy+fund preamble (idempotent — skip with
# --htlc/--skip-fund) and an Etherscan/Basescan link printed for every transaction sent.
# Runs against Ethereum Sepolia by default; --network base-sepolia switches the whole run to
# Base Sepolia instead (same secp256k1 key, same Ethereum address either way — only the RPC,
# HTLC deployment and USDC token address move).
#
#   tools/swap-poc/usdc-live.sh [--network sepolia|base-sepolia]
#     [--scenario happy|case-c|all] [--direction forward|reverse|both] [--htlc 0x...]
#     [--rpc-url URL] [--usdc-sats N] [--skip-fund] [--dry-run]
#
# No --backend mock: UsdcBackend has no synthetic MockChain counterpart in divi-swapd's mock
# mode (Chain::Usdc is not in divi_swapd::MOCK_ONLY_CHAINS, so a mock-backend maker cannot
# quote a usdc offer — see docs/plans/swap-poc/status/usdc.md). This lane's mock-equivalent
# rehearsal is tools/swap-poc/usdc-live-dry-run.sh: the same scenarios/directions against a
# throwaway anvil chain and throwaway keys instead of Sepolia/1Password, run through the
# real divi-swapd/divi-swap binaries, including case-c.
#
# --dry-run stops after `accept` (quote + accept the offer) and never calls `lock`, the same
# boundary e2e.sh/ltc-live.sh/zec-live.sh use: the maker only calls build_funding on
# TakerLockConfirmed -> MakerLocked, well after the taker's own lock, so stopping before the
# taker's lock guarantees neither side has broadcast anything *for that swap*. It still needs
# a real [usdc] daemon (no mock path) and so still runs the deploy+fund preamble and the
# live_*_lock_claim self-test below unless you also pass --htlc/--skip-fund (preamble) — the
# self-test always broadcasts, so --dry-run skips it outright.
#
# Keys: reused from the BTC swap keys per docs/plans/swap-poc/funding.md (no new 1Password
# items). `sepolia_ops` (crates/swap-chain-evm/examples/sepolia_ops.rs) takes a raw hex key
# via SWAP_EVM_KEY_HEX, so this script resolves `op://` refs to that with `op read` and
# unsets the variable immediately after each call; divi-swapd/divi-swap resolve their own
# `op://` key references internally (same as e2e.sh), so those get the reference string,
# never a resolved secret.
#
# State (config, logs, txids) goes to $E2E_STATE_DIR/usdc-live-<scenario>-<network>/<direction>
# (outside the repo, like e2e.sh/ltc-live.sh). The taker-divi wallet is shared with
# e2e.sh/ltc-live.sh/zec-live.sh (same taker-divi key) — never run more than one of these at
# once.
set -euo pipefail

usage() {
  echo "usage: $0 [--network sepolia|base-sepolia] [--scenario happy|case-c|all]" \
    "[--direction forward|reverse|both] [--htlc 0x...] [--rpc-url URL] [--usdc-sats N]" \
    "[--skip-fund] [--dry-run]" >&2
  exit 2
}
die() { echo "usdc-live: $*" >&2; exit 1; }

network="sepolia"
scenario_arg=all
direction_arg=both
htlc=""
rpc_url=""
usdc_sats=100000000 # 1 USDC-equivalent in engine sats (1e8/coin); must be a multiple of 100
skip_fund=""
dry_run=0
while (($#)); do
  case "$1" in
    --network) network="${2:-}"; shift 2 || usage ;;
    --scenario) scenario_arg="${2:-}"; shift 2 || usage ;;
    --direction) direction_arg="${2:-}"; shift 2 || usage ;;
    --htlc) htlc="${2:-}"; shift 2 || usage ;;
    --rpc-url) rpc_url="${2:-}"; shift 2 || usage ;;
    --usdc-sats) usdc_sats="${2:-}"; shift 2 || usage ;;
    --skip-fund) skip_fund=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    *) usage ;;
  esac
done
case "$scenario_arg" in happy|case-c|all) ;; *) usage ;; esac
case "$direction_arg" in forward|reverse|both) ;; *) usage ;; esac
scenarios=(happy case-c); [[ "$scenario_arg" == all ]] || scenarios=("$scenario_arg")
directions=(forward reverse); [[ "$direction_arg" == both ]] || directions=("$direction_arg")

ROOT="$(git rev-parse --show-toplevel)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
cd "$ROOT"

vault="op://global_secret_store"
ref() { echo "$vault/IronDivi Swap POC - $1/password"; }

# Mirrors swap_chain_evm::UsdcNetwork (crates/swap-chain-evm/src/network.rs) — keep in sync.
case "$network" in
  sepolia)
    default_rpc_url="https://ethereum-sepolia-rpc.publicnode.com"
    usdc_token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
    explorer="https://sepolia.etherscan.io"
    ;;
  base-sepolia)
    default_rpc_url="https://sepolia.base.org"
    usdc_token="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    explorer="https://sepolia.basescan.org"
    ;;
  *) die "--network must be sepolia or base-sepolia, got $network" ;;
esac
[[ -n "$rpc_url" ]] || rpc_url="$default_rpc_url"
# Prints a block-explorer link for one transaction hash, right where it was sent — so the
# orchestrator never has to go hunting for a txid to look up later.
print_tx() { echo "usdc-live: $1: $2"; echo "usdc-live:   $explorer/tx/$2"; }

# funding.md, 2026-10-11: EVM reuses the BTC swap keys (same secp256k1 pubkey — the Ethereum
# address derived from it is identical on every EVM chain, Sepolia or Base Sepolia, since
# address derivation does not depend on chain id).
taker_addr="0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C"
maker_addr="0x995669a244d511542ca314e4068c754E3F555bd2"

ops() { cargo run -q -p swap-chain-evm --features live --example sepolia_ops -- --network "$network" --rpc-url "$rpc_url" "$@"; }

forward_runs=0 reverse_runs=0
for s in "${scenarios[@]}"; do
  for d in "${directions[@]}"; do
    [[ "$d" == forward ]] && forward_runs=$((forward_runs + 1))
    [[ "$d" == reverse ]] && reverse_runs=$((reverse_runs + 1))
  done
done
total_runs=$((forward_runs + reverse_runs))
# The maker signs an EVM claim or refund on every run regardless of direction (it is always
# the counterparty on the USDC leg); only a reverse run puts the maker's own USDC up as
# collateral, so only reverse_runs sizes the USDC top-up.
eth_per_run=20000000000000000 # 0.02 ETH: generous headroom per swap (see gas numbers below)
usdc_units_per_run=$((usdc_sats / 100))
maker_eth_target=$((eth_per_run * (total_runs > 0 ? total_runs : 1)))
maker_usdc_target=$((usdc_units_per_run * (reverse_runs > 0 ? reverse_runs : 1)))

echo "usdc-live: scenarios=${scenarios[*]} directions=${directions[*]} network=$network dry_run=$dry_run"

echo "usdc-live: preflight — can 1Password resolve the keys this run needs?"
for k in taker-btc maker-btc maker-divi taker-divi; do
  if ! secret get --name "irondivi-swap-poc-$k-password" --op-ref "$(ref "$k")" >/dev/null 2>&1; then
    die "cannot read the $k key (1Password locked, or secret-broker not running). Rerun once it is up."
  fi
done

echo "usdc-live: building divi-swapd, divi-swap and swap-chain-evm's sepolia_ops example"
cargo build -q -p divi-swapd -p divi-swap-cli
cargo build -q -p swap-chain-evm --features live --example sepolia_ops

echo "usdc-live: preflight — does the taker have gas ETH on $network to deploy/fund with?"
taker_bal="$(ops balances --addr "$taker_addr")"
taker_eth="$(sed -n 's/^eth_wei: //p' <<<"$taker_bal")"
(( taker_eth > 0 )) || die "taker $taker_addr has no ETH on $network — fund it first (see funding.md)"

if [[ -z "$htlc" ]]; then
  echo "usdc-live: no --htlc given — deploying a fresh Erc20Htlc from the taker key"
  key_hex="$(op read "$(ref taker-btc)")"
  out="$(SWAP_EVM_KEY_HEX="$key_hex" ops deploy)"
  unset key_hex
  htlc="$(sed -n 's/^htlc_address: //p' <<<"$out")"
  deploy_tx="$(sed -n 's/^tx: //p' <<<"$out")"
  [[ -n "$htlc" ]] || die "deploy failed: $out"
  echo "usdc-live: deployed htlc=$htlc — record this in [usdc].htlc and the status file"
  [[ -n "$deploy_tx" ]] && print_tx "deploy Erc20Htlc" "$deploy_tx"
else
  echo "usdc-live: using existing htlc=$htlc"
fi

if [[ -z "$skip_fund" ]]; then
  echo "usdc-live: checking whether the maker needs gas ETH / USDC from the taker" \
    "(target: $maker_eth_target wei, $maker_usdc_target USDC base units for $total_runs run(s))"
  bal="$(ops balances --addr "$maker_addr")"
  maker_eth="$(sed -n 's/^eth_wei: //p' <<<"$bal")"
  maker_usdc="$(sed -n 's/^usdc_units: //p' <<<"$bal")"
  # Gas measured against anvil: approve ~29-46k, lock ~185-200k, claim ~74k, refund ~70k gas.
  if (( maker_eth < maker_eth_target )); then
    echo "usdc-live: funding maker with $maker_eth_target wei gas"
    key_hex="$(op read "$(ref taker-btc)")"
    tx="$(SWAP_EVM_KEY_HEX="$key_hex" ops send-eth --to "$maker_addr" --wei "$maker_eth_target" | sed -n 's/^tx: //p')"
    unset key_hex
    print_tx "fund maker ETH" "$tx"
  else
    echo "usdc-live: maker already has $maker_eth wei, skipping ETH funding"
  fi
  if (( maker_usdc < maker_usdc_target )); then
    echo "usdc-live: funding maker with $maker_usdc_target USDC base units"
    key_hex="$(op read "$(ref taker-btc)")"
    tx="$(SWAP_EVM_KEY_HEX="$key_hex" ops --token "$usdc_token" send-usdc --to "$maker_addr" --units "$maker_usdc_target" | sed -n 's/^tx: //p')"
    unset key_hex
    print_tx "fund maker USDC" "$tx"
  else
    echo "usdc-live: maker already has $maker_usdc USDC base units, skipping USDC funding"
  fi
fi

if ((dry_run)); then
  echo "usdc-live: --dry-run: skipping the live_*_lock_claim self-test (it always broadcasts)"
else
  case "$network" in
    sepolia) lock_claim_test=live_sepolia_lock_claim; lock_claim_rpc_var=SWAP_EVM_SEPOLIA_RPC ;;
    base-sepolia) lock_claim_test=live_base_sepolia_lock_claim; lock_claim_rpc_var=SWAP_EVM_BASE_SEPOLIA_RPC ;;
  esac
  echo "usdc-live: $lock_claim_test (self-contained UsdcBackend sanity check)"
  key_hex="$(op read "$(ref taker-btc)")"
  SWAP_EVM_TEST_KEY_HEX="$key_hex" env "$lock_claim_rpc_var=$rpc_url" \
    cargo test -p swap-chain-evm --features live -- --ignored "$lock_claim_test" --nocapture
  unset key_hex
fi

bin_dir="$ROOT/target/debug"
swapd="$bin_dir/divi-swapd"
swap="$bin_dir/divi-swap"

daemon_pid=""
stop_daemon() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  daemon_pid=""
}
trap stop_daemon EXIT INT TERM

run_scenario() {
  local scenario="$1" port timing timeout_secs
  case "$scenario" in
    happy) port=18494; timing=""; timeout_secs=28800 ;;
    case-c)
      port=18495
      timing=$'[swap]\nmaker_timeout_secs = 3600\ntaker_timeout_secs = 14410\n'
      timeout_secs=21600 ;;
  esac
  local state="${E2E_STATE_DIR:-$HOME/.local/state/iron-divi-swap-poc}/usdc-live-$scenario-$network"
  case "$state" in "$ROOT"/*) die "state dir must be outside the repo: $state" ;; esac
  mkdir -p "$state"; chmod 700 "$state"

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

[usdc]
network = "$network"
rpc_url = "$rpc_url"
htlc = "$htlc"
key = "$(ref maker-btc)"

[[offers]]
id = "divi-usdc-$network"
direction = "taker_pays_btc"
counter_chain = "usdc"
divi_sats_per_btc = 10000000000
min_btc_sats = 1000000
max_btc_sats = 1000000000

[[offers]]
id = "usdc-divi-$network"
direction = "taker_pays_divi"
counter_chain = "usdc"
divi_sats_per_btc = 10000000000
min_btc_sats = 1000000
max_btc_sats = 1000000000
TOML

  local base="http://127.0.0.1:$port"
  local log="$state/daemon.log"
  "$swapd" --config "$state/divi-swapd.toml" --backend live >>"$log" 2>&1 &
  daemon_pid=$!

  healthy() { [[ "$(curl -s -m 10 "$base/healthz" | jq -r '.ok // empty' 2>/dev/null)" == true ]]; }
  local ready=""
  for _ in $(seq 1 750); do
    kill -0 "$daemon_pid" 2>/dev/null || { tail -20 "$log" >&2; stop_daemon; die "daemon exited during startup"; }
    if healthy; then ready=1; break; fi
    sleep 2
  done
  [[ -n "$ready" ]] || { tail -20 "$log" >&2; stop_daemon; die "daemon never became healthy"; }
  echo "usdc-live: [$scenario] daemon healthy at $base"

  for d in "${directions[@]}"; do
    run_direction "$scenario" "$d" "$state" "$base" "$timeout_secs"
  done
  stop_daemon
}

run_direction() {
  local scenario="$1" direction="$2" scen_state="$3" base="$4" timeout_secs="$5"
  local offer taker_flags=()
  if [[ "$direction" == forward ]]; then offer="divi-usdc-$network"; else offer="usdc-divi-$network"; fi
  [[ "$scenario" == case-c ]] && taker_flags=(--never-claim)

  local state="$scen_state/$direction"
  mkdir -p "$state"; chmod 700 "$state"
  local taker=("$swap" --db "$state/taker.db" --backend live --counter-chain usdc
    --usdc-key "$(ref taker-btc)" --usdc-network "$network" --usdc-rpc-url "$rpc_url"
    --usdc-htlc "$htlc" --divi-key "$(ref taker-divi)")
  if [[ "$direction" == reverse ]]; then
    # Same key as e2e.sh/ltc-live.sh's taker, so share its already-scanned wallet (never run
    # more than one of these drivers at once).
    taker+=(--divi-wallet "$(dirname "$scen_state")/taker-divi-wallet.json")
  fi

  echo "usdc-live: [$scenario/$direction] offer=$offer dry_run=$dry_run"

  if ((dry_run)); then
    # `run` does quote+accept+lock+poll as one swap; a dry run instead stops right after
    # accept (quote then accept, same as `run`'s first two steps) so nothing further ever
    # calls lock — never creates the swap `run` would go on to use.
    "${taker[@]}" quote --maker "$base" --offer "$offer" --btc-sats "$usdc_sats"
    local local_id
    local_id="$("${taker[@]}" accept --maker "$base" --offer "$offer" --btc-sats "$usdc_sats" | tail -1)"
    [[ -n "$local_id" ]] || die "[$scenario/$direction] accept printed no swap id"
    echo "usdc-live: [$scenario/$direction] accepted $local_id (no broadcast yet)"
    echo "usdc-live: [$scenario/$direction] --dry-run: stopping before lock (first broadcast). OK."
    return 0
  fi

  local out="$state/taker-run.log" local_id
  "${taker[@]}" run --maker "$base" --offer "$offer" --btc-sats "$usdc_sats" \
    --timeout-secs "$timeout_secs" ${taker_flags[@]+"${taker_flags[@]}"} 2>&1 | tee "$out"
  local_id="$(tail -1 "$out" | awk '{print $1}')"
  [[ -n "$local_id" ]] || die "[$scenario/$direction] taker run printed no swap id"

  local txids=""
  for _ in $(seq 1 360); do
    txids="$("${taker[@]}" txids --swap "$local_id")"
    grep -q '^maker_state=Done' <<<"$txids" && break
    sleep 10
  done
  echo "$txids" | tee "$state/results.txt"
  grep -q '^maker_state=Done' <<<"$txids" || die "[$scenario/$direction] maker did not reach Done"

  echo "usdc-live: [$scenario/$direction] Etherscan/Basescan links for the USDC side:"
  # txids' "btc_*" keys hold the counter chain's txids regardless of which chain that
  # actually is (see bin/divi-swap/src/txids.rs); here the counter chain is always USDC.
  for k in btc_lock btc_claim_by_maker btc_claim_by_taker btc_refund_by_taker btc_spend_by_maker; do
    v="$(sed -n "s/^$k=//p" <<<"$txids")"
    [[ -n "$v" ]] && print_tx "$k" "$v"
  done
  echo "usdc-live: [$scenario/$direction] done; txids in $state/results.txt"
}

for s in "${scenarios[@]}"; do
  run_scenario "$s"
done
echo "usdc-live: all requested scenarios/directions finished"
