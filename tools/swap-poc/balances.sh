#!/usr/bin/env bash
# Read-only balance dashboard: taker and maker balances for every coin this POC swaps, from
# public APIs only — no keys, no secrets, safe to run anywhere (including hp2).
#
#   tools/swap-poc/balances.sh [--check]
#
# --check: also exit nonzero if any balance is below the minimum its own live driver needs
# for one run (tools/swap-poc/{ltc,zec,usdc}-live.sh, e2e.sh for BTC — see MIN_* below for
# exactly which script/variable each number comes from). Every balance prints either way;
# --check only changes the exit code and adds a one-line summary of what's short.
#
# Addresses: docs/plans/swap-poc/funding.md (BTC testnet3/LTC testnet4/ZEC testnet/EVM —
# one secp256k1 key per role, re-encoded per chain) and docs/plans/swap-poc/RESULTS.md
# (DIVI testnet, its own address format — not secp256k1-reencoded like the others).
set -uo pipefail
export PATH="$HOME/.local/bin:/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
die() { echo "balances: $*" >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel)" || die "not inside a git repo"
cd "$ROOT" || die "cannot cd to $ROOT"

check=0
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) die "usage: $0 [--check]" ;;
esac

# ---- addresses (funding.md / RESULTS.md) ---------------------------------------------------
BTC_TAKER=tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg
BTC_MAKER=tb1quqkt7c06svzt68f2y9uwf2jzgpd48k6ku45zrt
LTC_TAKER=tltc1qa826ffe73xnqsm64x6fvln7sl0zp3rgf5gnf3p
LTC_MAKER=tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz
ZEC_TAKER=tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk
ZEC_MAKER=tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn
DIVI_TAKER=xy2MorbDhp35NxBHytHjv3LQo7fvHE4y3b
DIVI_MAKER=yH2vuZnVbVh1FopWEiFAMok93XKu6EUWG6
EVM_TAKER=0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C
EVM_MAKER=0x995669a244d511542ca314e4068c754E3F555bd2

BTC_ESPLORA=https://mempool.space/testnet/api          # BTC testnet3
LTC_ESPLORA=https://litecoinspace.org/testnet/api       # LTC testnet4 (swap_chain_ltc::LITECOINSPACE_TESTNET)
DIVI_RPC=https://services.divi.domains/api/testnet/rpc/ # DIVI testnet (same proxy tools/swap-poc/lib.sh uses)

# ---- per-run funding minimums, one source per coin -----------------------------------------
# BTC: e2e.sh's maker-readiness check, line ~191 (`E2E_BTC_SATS` default 10000 + 5000 fee buffer).
BTC_MIN=15000
# LTC: ltc-live.sh's `min_per_run` (`ltc_sats` default 100000 + `fee_buffer_sats` 5000).
LTC_MIN=105000
# ZEC: zec-live.sh's `min_per_run` (`zec_zats` default 100000 + `fee_buffer_sats` 20000).
ZEC_MIN=120000
# USDC: usdc-live.sh's per-run `eth_per_run` (0.02 ETH) and `usdc_units_per_run` at its
# default --usdc-sats (100000000 engine sats / 100 = 1 USDC base unit's worth * 1e6 = 1
# USDC); same thresholds on both networks, since the backend is network-agnostic.
USDC_ETH_MIN_WEI=20000000000000000
USDC_UNITS_MIN=1000000
# DIVI: no script defines a fixed minimum — the DIVI leg's size is quote-derived and scales
# with whichever offer runs (divi_sats_per_btc * counter amount), unlike the other chains'
# flat per-run litoshi/zatoshi/wei figures above. 100 tDIVI is a conservative "clearly
# enough for one typical swap" floor picked for this script, not pulled from any driver.
DIVI_MIN=10000000000

echo "balances: building swap-chain-evm's sepolia_ops and swap-chain-zec's check_addr_utxos"
cargo build -q -p swap-chain-evm --features live --example sepolia_ops
cargo build -q -p swap-chain-zec --example check_addr_utxos

SHORTFALLS=0
row() {
  # row <role> <coin> <addr> <have> <unit> <min>
  local role="$1" coin="$2" addr="$3" have="$4" unit="$5" min="$6" status
  if [[ ! "$have" =~ ^[0-9]+$ ]]; then
    status="UNKNOWN (lookup failed)"
  elif ((have >= min)); then
    status="ok"
  else
    status="SHORT (need >= $min)"
    SHORTFALLS=$((SHORTFALLS + 1))
  fi
  printf 'balances: %-6s %-14s %-44s %20s %-6s %s\n' "$role" "$coin" "$addr" "$have" "$unit" "$status"
}

esplora_balance() {
  # esplora_balance <base_url> <addr> -> confirmed sats, or "?" on failure
  local sum
  sum="$(curl -fsS -m 20 "$1/address/$2/utxo" 2>/dev/null |
    jq '[.[] | select(.status.confirmed) | .value] | add // 0' 2>/dev/null)"
  [[ "$sum" =~ ^[0-9]+$ ]] && echo "$sum" || echo "?"
}

divi_balance() {
  # divi_balance <addr> -> sats (tDIVI has 8 decimals, same as BTC), or "?" on failure
  local bal
  bal="$(curl -fsS -m 20 -X POST -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getaddressbalance\",\"params\":[\"$1\"]}" \
    "$DIVI_RPC" 2>/dev/null | jq -r '.result.balance // empty' 2>/dev/null)"
  [[ "$bal" =~ ^[0-9]+$ ]] && echo "$bal" || echo "?"
}

declare -A ZEC_BAL
zec_balances() {
  # zec_balances <addr>... -> fills ZEC_BAL[addr]=zatoshi (one call for every address, like
  # the checker itself is built for)
  local out
  out="$(cargo run -q -p swap-chain-zec --example check_addr_utxos -- "$@" 2>/dev/null)"
  for addr in "$@"; do
    local v
    v="$(sed -n -E "s/^${addr}: total ([0-9]+) zatoshi.*/\1/p" <<<"$out" | head -1)"
    if [[ -z "$v" ]]; then
      grep -q "^${addr}: no confirmed UTXOs" <<<"$out" && v=0 || v="?"
    fi
    ZEC_BAL["$addr"]="$v"
  done
}

declare -A EVM_ETH EVM_USDC
evm_balances() {
  # evm_balances <network> <addr> -> fills EVM_ETH["network:addr"]/EVM_USDC["network:addr"]
  local net="$1" addr="$2" out
  out="$(cargo run -q -p swap-chain-evm --features live --example sepolia_ops -- \
    --network "$net" balances --addr "$addr" 2>/dev/null)"
  EVM_ETH["$net:$addr"]="$(sed -n 's/^eth_wei: //p' <<<"$out")"
  EVM_USDC["$net:$addr"]="$(sed -n 's/^usdc_units: //p' <<<"$out")"
  [[ -n "${EVM_ETH[$net:$addr]}" ]] || EVM_ETH["$net:$addr"]="?"
  [[ -n "${EVM_USDC[$net:$addr]}" ]] || EVM_USDC["$net:$addr"]="?"
}

zec_balances "$ZEC_TAKER" "$ZEC_MAKER"
evm_balances sepolia "$EVM_TAKER"
evm_balances sepolia "$EVM_MAKER"
evm_balances base-sepolia "$EVM_TAKER"
evm_balances base-sepolia "$EVM_MAKER"

row taker btc-testnet3 "$BTC_TAKER" "$(esplora_balance "$BTC_ESPLORA" "$BTC_TAKER")" sats "$BTC_MIN"
row maker btc-testnet3 "$BTC_MAKER" "$(esplora_balance "$BTC_ESPLORA" "$BTC_MAKER")" sats "$BTC_MIN"
row taker ltc-testnet4 "$LTC_TAKER" "$(esplora_balance "$LTC_ESPLORA" "$LTC_TAKER")" lito "$LTC_MIN"
row maker ltc-testnet4 "$LTC_MAKER" "$(esplora_balance "$LTC_ESPLORA" "$LTC_MAKER")" lito "$LTC_MIN"
row taker divi-testnet "$DIVI_TAKER" "$(divi_balance "$DIVI_TAKER")" sats "$DIVI_MIN"
row maker divi-testnet "$DIVI_MAKER" "$(divi_balance "$DIVI_MAKER")" sats "$DIVI_MIN"
row taker zec-testnet "$ZEC_TAKER" "${ZEC_BAL[$ZEC_TAKER]}" zat "$ZEC_MIN"
row maker zec-testnet "$ZEC_MAKER" "${ZEC_BAL[$ZEC_MAKER]}" zat "$ZEC_MIN"
row taker sepolia-eth "$EVM_TAKER" "${EVM_ETH[sepolia:$EVM_TAKER]}" wei "$USDC_ETH_MIN_WEI"
row maker sepolia-eth "$EVM_MAKER" "${EVM_ETH[sepolia:$EVM_MAKER]}" wei "$USDC_ETH_MIN_WEI"
row taker sepolia-usdc "$EVM_TAKER" "${EVM_USDC[sepolia:$EVM_TAKER]}" units "$USDC_UNITS_MIN"
row maker sepolia-usdc "$EVM_MAKER" "${EVM_USDC[sepolia:$EVM_MAKER]}" units "$USDC_UNITS_MIN"
row taker base-sep-eth "$EVM_TAKER" "${EVM_ETH[base-sepolia:$EVM_TAKER]}" wei "$USDC_ETH_MIN_WEI"
row maker base-sep-eth "$EVM_MAKER" "${EVM_ETH[base-sepolia:$EVM_MAKER]}" wei "$USDC_ETH_MIN_WEI"
row taker base-sep-usdc "$EVM_TAKER" "${EVM_USDC[base-sepolia:$EVM_TAKER]}" units "$USDC_UNITS_MIN"
row maker base-sep-usdc "$EVM_MAKER" "${EVM_USDC[base-sepolia:$EVM_MAKER]}" units "$USDC_UNITS_MIN"

if ((check)); then
  if ((SHORTFALLS > 0)); then
    echo "balances: --check: $SHORTFALLS balance(s) below their live script's funding minimum"
    exit 1
  fi
  echo "balances: --check: all balances meet their live script's funding minimum"
fi
