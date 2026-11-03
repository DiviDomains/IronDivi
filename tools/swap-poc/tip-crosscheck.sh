#!/usr/bin/env bash
# Compare each chain's tip hash, as `divi-swap tip` prints it, with an independent public explorer.
# Read-only: `divi-swap tip` plus a few curl GETs; no keys, no funds, no secrets.
#
#   tools/swap-poc/tip-crosscheck.sh                 # test networks (DIVI/LTC/ZEC testnet, BTC signet)
#   MAINNET=1 tools/swap-poc/tip-crosscheck.sh       # mainnet as well (tip's own --allow-mainnet --profile mainnet,
#                                                    #   per invocation; reading a tip moves nothing)
#   XMR_MONEROD_URL=http://host:38081 XMR_NETWORK=stagenet tools/swap-poc/tip-crosscheck.sh
#
# Each row is compared BY HEIGHT (not "latest"), so a one-block race is not a mismatch: when the explorer
# is behind (no block at that height) or disagrees, it is asked once more after RACE_WAIT seconds.
# Rows: MATCH, MISMATCH, SKIP (no independent source; names each source tried), ERROR (tip itself failed).
# Exit 1 on any MISMATCH or ERROR; SKIP alone exits 0.
#
# Monero: `tip` prints monerod's block COUNT, so the top block is at height-1; that block's hash is compared.
# XMR_CROSS_URL: a second, independent monerod to compare against (before the explorer page).
# Env: DIVI_SWAP (binary), CURL (binary), RACE_WAIT (default 15), MAINNET, XMR_MONEROD_URL, XMR_NETWORK (stagenet).
set -uo pipefail

DIVI_SWAP="${DIVI_SWAP:-divi-swap}"
CURL="${CURL:-curl}"
RACE_WAIT="${RACE_WAIT:-15}"
XMR_NETWORK="${XMR_NETWORK:-stagenet}"

get() { "$CURL" -fsS -m 20 -A "Mozilla/5.0" "$1" 2>/dev/null; }
hex64() { tr 'A-F' 'a-f' | grep -oE '^[0-9a-f]{64}$' | head -1; }

# src_hash <chain> <network> <height> -> prints "<hash> <source>" for the first source that answers
# with a well-formed hash; prints "NONE <names of sources tried>" when none did; returns 2 when the
# pair has no source at all.
src_hash() {
  local chain="$1" net="$2" h="$3" tried="" name url h64 out
  local -a srcs=()
  case "$chain/$net" in
    btc/mainnet) srcs=("blockstream.info|https://blockstream.info/api/block-height/$h|plain"
                       "blockchain.info|https://blockchain.info/block-height/$h?format=json|bcinfo") ;;
    btc/signet)  srcs=("blockstream.info/signet|https://blockstream.info/signet/api/block-height/$h|plain") ;;
    btc/testnet) srcs=("blockstream.info/testnet|https://blockstream.info/testnet/api/block-height/$h|plain") ;;
    ltc/mainnet) srcs=("api.blockcypher.com|https://api.blockcypher.com/v1/ltc/main/blocks/$h|hashkey"
                       "api.blockchair.com|https://api.blockchair.com/litecoin/dashboards/block/$h|blockchair:$h") ;;
    zec/mainnet) srcs=("api.blockchair.com|https://api.blockchair.com/zcash/dashboards/block/$h|blockchair:$h"
                       "mainnet.zcashexplorer.app|https://mainnet.zcashexplorer.app/blocks/$h|xmrpage") ;;
    divi/mainnet) srcs=("chainz.cryptoid.info|https://chainz.cryptoid.info/divi/api.dws?q=getblockhash&height=$h|jsonstr") ;;
    xmr/*)
      local top=$((h - 1))
      [ -n "${XMR_CROSS_URL:-}" ] && srcs+=("monerod $XMR_CROSS_URL|$XMR_CROSS_URL/json_rpc#$top|monerod")
      case "$net" in
        stagenet) srcs+=("stagenet.xmrchain.net|https://stagenet.xmrchain.net/block/$top|xmrpage") ;;
        mainnet)  srcs+=("xmrchain.net|https://xmrchain.net/block/$top|xmrpage") ;;
      esac ;;
    *) return 2 ;;
  esac
  [ ${#srcs[@]} -eq 0 ] && return 2
  for s in "${srcs[@]}"; do
    IFS='|' read -r name url parse <<<"$s"
    tried="$tried${tried:+, }$name"
    case "$parse" in
      plain)     out="$(get "$url")" ;;
      bcinfo)    out="$(get "$url" | jq -r '.blocks[0].hash' 2>/dev/null)" ;;
      hashkey)   out="$(get "$url" | jq -r '.hash' 2>/dev/null)" ;;
      jsonstr)   out="$(get "$url" | jq -r '.' 2>/dev/null)" ;;
      blockchair:*) out="$(get "$url" | jq -r --arg h "${parse#blockchair:}" '.data[$h].block.hash' 2>/dev/null)" ;;
      monerod)   out="$("$CURL" -fsS -m 20 "${url%%#*}" -H 'content-type: application/json' \
                   -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_header_by_height\",\"params\":{\"height\":${url##*#}}}" 2>/dev/null \
                   | jq -r '.result.block_header.hash' 2>/dev/null)" ;;
      # an explorer HTML page lists the block's own hash first (checked on xmrchain.net and zcashexplorer.app)
      xmrpage)   out="$(get "$url" | grep -oiE '[0-9a-f]{64}' | head -1)" ;;
    esac
    h64="$(printf '%s' "$out" | hex64)"
    if [ -n "$h64" ]; then echo "$h64 $name"; return 0; fi
  done
  echo "NONE $tried"
}

BAD=0
row() { printf '%-8s %-7s %-8s %s\n' "$@"; }

check_line() {
  local chain="$1" net="$2" height="$3" hash="$4" r src sh
  hash="$(printf '%s' "$hash" | tr 'A-F' 'a-f')"
  if ! printf '%s' "$hash" | grep -qE '^[0-9a-f]{64}$'; then
    row ERROR "$chain" "$net" "tip printed no usable hash at height $height: $hash"; BAD=$((BAD + 1)); return
  fi
  r="$(src_hash "$chain" "$net" "$height")"; local rc=$?
  if [ "$rc" -eq 2 ]; then
    row SKIP "$chain" "$net" "height $height: no independent public explorer known for this network (code hash $hash)"; return
  fi
  if [ "${r%% *}" = NONE ]; then
    # explorer behind by a block, or down: one more try after the race window
    sleep "$RACE_WAIT"; r="$(src_hash "$chain" "$net" "$height")"
  fi
  sh="${r%% *}"; src="${r#* }"
  if [ "$sh" = NONE ]; then
    row SKIP "$chain" "$net" "height $height: no source answered (tried: $src) (code hash $hash)"
  elif [ "$sh" = "$hash" ]; then
    row MATCH "$chain" "$net" "height $height $hash ($src)"
  else
    sleep "$RACE_WAIT"; r="$(src_hash "$chain" "$net" "$height")"; sh="${r%% *}"; src="${r#* }"
    if [ "$sh" = "$hash" ]; then row MATCH "$chain" "$net" "height $height $hash ($src, after recheck)"
    else row MISMATCH "$chain" "$net" "height $height code=$hash $src=$sh"; BAD=$((BAD + 1)); fi
  fi
}

run_tip() { # <label> <args...>
  local label="$1" out rc line; shift
  out="$("$DIVI_SWAP" "$@" tip --chain all 2>&1)"; rc=$?
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    set -- $line
    if [ "$#" -eq 4 ] && printf '%s' "$3" | grep -qE '^[0-9]+$'; then check_line "$1" "$2" "$3" "$4"
    elif [ "$2" = skipped ] || [ "${2:-}" = "skipped" ]; then row SKIP "$1" "-" "$line"
    else row ERROR "${1:-?}" "${2:--}" "$line"; BAD=$((BAD + 1)); fi
  done <<<"$out"
  if [ "$rc" -ne 0 ] && [ "$BAD" -eq 0 ]; then row ERROR "$label" "-" "divi-swap tip exited $rc"; BAD=$((BAD + 1)); fi
}

xmr=()
[ -n "${XMR_MONEROD_URL:-}" ] && xmr=(--xmr-monerod-url "$XMR_MONEROD_URL" --xmr-network "$XMR_NETWORK")
run_tip testnets ${xmr[@]+"${xmr[@]}"}
if [ -n "${MAINNET:-}" ]; then
  run_tip mainnet --profile mainnet --allow-mainnet --divi-network mainnet --btc-network mainnet \
    --ltc-network mainnet --zec-network mainnet
fi
[ "$BAD" -eq 0 ] && echo "tip-crosscheck: no mismatch" || echo "tip-crosscheck: $BAD problem row(s)"
[ "$BAD" -eq 0 ]
