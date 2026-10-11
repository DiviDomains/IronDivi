#!/usr/bin/env bash
# Live EVM USDC: deploy Erc20Htlc (idempotent — skip with --htlc), fund the maker key with
# gas ETH and a little USDC, prove UsdcBackend live end to end (live_sepolia_lock_claim),
# then run one real DIVI<->USDC swap: offer divi-usdc-<network> (maker sells DIVI, taker
# pays USDC — the direction fundable today; the maker holds no USDC yet, see funding.md).
# Runs against Ethereum Sepolia by default; pass --network base-sepolia to run the same
# steps on Base Sepolia instead (same secp256k1 key, same Ethereum address on either chain
# — only the RPC endpoint, HTLC deployment and USDC token address change).
#
#   tools/swap-poc/usdc-live.sh [--network sepolia|base-sepolia] [--htlc 0x...] \
#     [--rpc-url URL] [--usdc-sats N] [--skip-fund]
#
# Keys: reused from the BTC swap keys per docs/plans/swap-poc/funding.md (no new 1Password
# items). `sepolia_ops` (crates/swap-chain-evm/examples/sepolia_ops.rs) takes a raw hex key
# via SWAP_EVM_KEY_HEX, so this script resolves `op://` refs to that with `op read` and
# unsets the variable immediately after each call; divi-swapd/divi-swap resolve their own
# `op://` key references internally (same as e2e.sh), so those get the reference string,
# never a resolved secret.
#
# State (config, logs, txids) goes to $E2E_STATE_DIR/usdc-live (outside the repo, like e2e.sh).
set -euo pipefail

usage() {
  echo "usage: $0 [--network sepolia|base-sepolia] [--htlc 0x...] [--rpc-url URL]" \
    "[--usdc-sats N] [--skip-fund]" >&2
  exit 2
}

network="sepolia"
htlc=""
rpc_url=""
usdc_sats=100000000 # 1 USDC-equivalent in engine sats (1e8/coin); must be a multiple of 100
skip_fund=""
while (($#)); do
  case "$1" in
    --network) network="${2:-}"; shift 2 || usage ;;
    --htlc) htlc="${2:-}"; shift 2 || usage ;;
    --rpc-url) rpc_url="${2:-}"; shift 2 || usage ;;
    --usdc-sats) usdc_sats="${2:-}"; shift 2 || usage ;;
    --skip-fund) skip_fund=1; shift ;;
    *) usage ;;
  esac
done

ROOT="$(git rev-parse --show-toplevel)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
cd "$ROOT"

die() { echo "usdc-live: $*" >&2; exit 1; }

vault="op://global_secret_store"
ref() { echo "$vault/IronDivi Swap POC - $1/password"; }

# Mirrors swap_chain_evm::UsdcNetwork (crates/swap-chain-evm/src/network.rs) — keep in sync.
case "$network" in
  sepolia)
    default_rpc_url="https://ethereum-sepolia-rpc.publicnode.com"
    usdc_token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
    ;;
  base-sepolia)
    default_rpc_url="https://sepolia.base.org"
    usdc_token="0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    ;;
  *) die "--network must be sepolia or base-sepolia, got $network" ;;
esac
[[ -n "$rpc_url" ]] || rpc_url="$default_rpc_url"

# funding.md, 2026-10-11: EVM reuses the BTC swap keys (same secp256k1 pubkey — the
# Ethereum address derived from it is identical on every EVM chain, Sepolia or Base
# Sepolia, since address derivation does not depend on chain id).
taker_addr="0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C"
maker_addr="0x995669a244d511542ca314e4068c754E3F555bd2"

ops() { cargo run -q -p swap-chain-evm --features live --example sepolia_ops -- --network "$network" --rpc-url "$rpc_url" "$@"; }

echo "usdc-live: preflight — can 1Password resolve the keys this run needs?"
for k in taker-btc maker-btc maker-divi; do
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
  [[ -n "$htlc" ]] || die "deploy failed: $out"
  echo "usdc-live: deployed htlc=$htlc — record this in [usdc].htlc and the status file"
else
  echo "usdc-live: using existing htlc=$htlc"
fi

if [[ -z "$skip_fund" ]]; then
  echo "usdc-live: checking whether the maker needs gas ETH / USDC from the taker"
  bal="$(ops balances --addr "$maker_addr")"
  maker_eth="$(sed -n 's/^eth_wei: //p' <<<"$bal")"
  maker_usdc="$(sed -n 's/^usdc_units: //p' <<<"$bal")"
  # ~0.02 ETH comfortably covers approve+lock+claim/refund at generous Sepolia gas prices
  # (measured against anvil: approve ~29-46k, lock ~185-200k, claim ~74k, refund ~70k gas).
  if (( maker_eth < 20000000000000000 )); then
    echo "usdc-live: funding maker with 0.02 ETH gas"
    key_hex="$(op read "$(ref taker-btc)")"
    SWAP_EVM_KEY_HEX="$key_hex" ops send-eth --to "$maker_addr" --wei 20000000000000000
    unset key_hex
  else
    echo "usdc-live: maker already has $maker_eth wei, skipping ETH funding"
  fi
  # A little USDC too, so the maker can also act as a seller in a reverse-direction run
  # later without a second funding round trip.
  if (( maker_usdc < 2000000 )); then
    echo "usdc-live: funding maker with 2 USDC"
    key_hex="$(op read "$(ref taker-btc)")"
    SWAP_EVM_KEY_HEX="$key_hex" ops --token "$usdc_token" send-usdc --to "$maker_addr" --units 2000000
    unset key_hex
  else
    echo "usdc-live: maker already has $maker_usdc USDC base units, skipping USDC funding"
  fi
fi

case "$network" in
  sepolia) lock_claim_test=live_sepolia_lock_claim; lock_claim_rpc_var=SWAP_EVM_SEPOLIA_RPC ;;
  base-sepolia) lock_claim_test=live_base_sepolia_lock_claim; lock_claim_rpc_var=SWAP_EVM_BASE_SEPOLIA_RPC ;;
esac
echo "usdc-live: $lock_claim_test (self-contained UsdcBackend sanity check)"
key_hex="$(op read "$(ref taker-btc)")"
SWAP_EVM_TEST_KEY_HEX="$key_hex" env "$lock_claim_rpc_var=$rpc_url" \
  cargo test -p swap-chain-evm --features live -- --ignored "$lock_claim_test" --nocapture
unset key_hex

offer_id="divi-usdc-$network"
echo "usdc-live: real swap — offer $offer_id (maker sells DIVI for USDC)"
state="${E2E_STATE_DIR:-$HOME/.local/state/iron-divi-swap-poc}/usdc-live"
case "$state" in "$ROOT"/*) die "state dir must be outside the repo: $state" ;; esac
mkdir -p "$state"
chmod 700 "$state"

if [[ -e "$state/taker.db" ]]; then
  stamp="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$state/old-$stamp"
  for f in "$state"/taker.db* "$state"/maker.db* "$state"/daemon.log; do
    [[ -e "$f" ]] && mv "$f" "$state/old-$stamp/"
  done
fi

port=18494
cat >"$state/divi-swapd.toml" <<TOML
listen = "127.0.0.1:$port"
db_path = "$state/maker.db"
tick_secs = 5

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
id = "$offer_id"
direction = "taker_pays_btc"
counter_chain = "usdc"
divi_sats_per_btc = 10000000000
min_btc_sats = 1000000
max_btc_sats = 1000000000
TOML

bin_dir="$ROOT/target/debug"
swapd="$bin_dir/divi-swapd"
swap="$bin_dir/divi-swap"

daemon_pid=""
cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

"$swapd" --config "$state/divi-swapd.toml" --backend live >>"$state/daemon.log" 2>&1 &
daemon_pid=$!

base="http://127.0.0.1:$port"
healthy() { [[ "$(curl -s -m 10 "$base/healthz" | jq -r '.ok // empty' 2>/dev/null)" == true ]]; }
ready=""
for _ in $(seq 1 750); do
  kill -0 "$daemon_pid" 2>/dev/null || { tail -20 "$state/daemon.log" >&2; die "daemon exited during startup"; }
  if healthy; then ready=1; break; fi
  sleep 2
done
[[ -n "$ready" ]] || { tail -20 "$state/daemon.log" >&2; die "daemon never became healthy"; }
echo "usdc-live: daemon healthy at $base"

taker=("$swap" --db "$state/taker.db" --backend live --counter-chain usdc \
  --usdc-key "$(ref taker-btc)" --usdc-network "$network" --usdc-rpc-url "$rpc_url" \
  --usdc-htlc "$htlc" --divi-key "$(ref taker-divi)")

out="$state/taker-run.log"
"${taker[@]}" run --maker "$base" --offer "$offer_id" --btc-sats "$usdc_sats" \
  --timeout-secs 28800 2>&1 | tee "$out"
local_id="$(tail -1 "$out" | awk '{print $1}')"
[[ -n "$local_id" ]] || die "taker run printed no swap id"

txids=""
for _ in $(seq 1 360); do
  txids="$("${taker[@]}" txids --swap "$local_id")"
  grep -q '^maker_state=Done' <<<"$txids" && break
  sleep 10
done
echo "$txids" | tee "$state/results.txt"
grep -q '^maker_state=Done' <<<"$txids" || die "maker did not reach Done"
echo "usdc-live: done; paste $state/results.txt into the status file once the txids confirm"
