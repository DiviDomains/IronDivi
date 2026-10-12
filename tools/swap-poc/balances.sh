#!/usr/bin/env bash
# Read-only balance dashboard: taker and maker balances for every coin this POC swaps, from
# public APIs only — no keys, no secrets, no cargo (the Mac refuses local cargo under
# load), safe to run anywhere (including hp2 with cargo absent from PATH entirely).
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
#
# No Rust anywhere: BTC/LTC via Esplora REST (curl+jq); DIVI via its public
# `getaddressbalance` JSON-RPC (curl+jq, same proxy tools/swap-poc/lib.sh already uses);
# ZEC via a hand-framed gRPC unary call to lightwalletd's `CompactTxStreamer/
# GetAddressUtxos` (curl --http2 for the wire transport, python3 stdlib — no protobuf
# package — to encode the trivial request and decode the response: both are flat/one-level
# protobuf messages, cheap to hand-parse byte by byte); EVM balances via plain
# `eth_getBalance`/`eth_call` JSON-RPC (curl+python3; `eth_call` with the standard ERC-20
# `balanceOf(address)` selector `0x70a08231`).
set -uo pipefail
die() { echo "balances: $*" >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel)" || die "not inside a git repo"
cd "$ROOT" || die "cannot cd to $ROOT"
command -v curl >/dev/null || die "curl not found"
command -v jq >/dev/null || die "jq not found"
command -v python3 >/dev/null || die "python3 not found"

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

BTC_ESPLORA=https://mempool.space/testnet/api            # BTC testnet3
LTC_ESPLORA=https://litecoinspace.org/testnet/api        # LTC testnet4 (swap_chain_ltc::LITECOINSPACE_TESTNET)
DIVI_RPC=https://services.divi.domains/api/testnet/rpc/  # DIVI testnet (tools/swap-poc/lib.sh's proxy)
ZEC_LIGHTWALLETD=https://testnet.zec.rocks:443           # swap_chain_zec::TESTNET_LIGHTWALLETD
SEPOLIA_RPC=https://ethereum-sepolia-rpc.publicnode.com
BASE_SEPOLIA_RPC=https://sepolia.base.org
SEPOLIA_USDC=0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
BASE_SEPOLIA_USDC=0x036CbD53842c5426634e7929541eC2318f3dCF7e

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

# ---- a tiny protobuf/JSON-RPC decoder, python3 stdlib only, no cargo, no protobuf package --
PYHELPER="$(mktemp)"
TMP_REQ="$(mktemp)"
TMP_RESP="$(mktemp)"
cleanup() { rm -f "$PYHELPER" "$TMP_REQ" "$TMP_RESP" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
cat >"$PYHELPER" <<'PYEOF'
import sys


def read_varint(data, i):
    result = 0
    shift = 0
    while True:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, i


def parse_proto(data):
    """Flat scan of one protobuf message: (field_num, wire_type, value) tuples. value is
    an int for varint (wire 0) or raw bytes for length-delimited (wire 2) — the only two
    wire types the lightwalletd messages this script reads ever use."""
    i, n, out = 0, len(data), []
    while i < n:
        tag, i = read_varint(data, i)
        field_num, wire_type = tag >> 3, tag & 7
        if wire_type == 0:
            val, i = read_varint(data, i)
        elif wire_type == 2:
            length, i = read_varint(data, i)
            val = data[i : i + length]
            i += length
        elif wire_type == 1:
            val, i = data[i : i + 8], i + 8
        elif wire_type == 5:
            val, i = data[i : i + 4], i + 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")
        out.append((field_num, wire_type, val))
    return out


def grpc_request(addr):
    """cash.z.wallet.sdk.rpc.GetAddressUtxosArg { addresses: [addr] }, grpc-framed (1-byte
    compression flag + 4-byte big-endian length + the message)."""
    addr_bytes = addr.encode()
    msg = bytes([0x0A, len(addr_bytes)]) + addr_bytes
    frame = bytes([0]) + len(msg).to_bytes(4, "big") + msg
    sys.stdout.buffer.write(frame)


def zec_decode(path):
    """Sum GetAddressUtxosReply.value_zat (field 4) across every
    GetAddressUtxosReplyList frame in a raw CompactTxStreamer/GetAddressUtxos response."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        i, total = 0, 0
        while i < len(raw):
            length = int.from_bytes(raw[i + 1 : i + 5], "big")
            msg = raw[i + 5 : i + 5 + length]
            i += 5 + length
            for field_num, wire_type, val in parse_proto(msg):
                if field_num == 1 and wire_type == 2:
                    for sub_field, sub_wire, sub_val in parse_proto(val):
                        if sub_field == 4 and sub_wire == 0:
                            total += sub_val
        print(total)
    except Exception:
        print("?")


def hex_result_to_int(path):
    """A JSON-RPC response file whose top-level "result" is a 0x-prefixed hex quantity
    (eth_getBalance, or eth_call for a uint256-returning view like ERC-20 balanceOf)."""
    import json

    try:
        with open(path) as f:
            d = json.load(f)
        print(int(d["result"], 16))
    except Exception:
        print("?")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "grpc-request":
        grpc_request(sys.argv[2])
    elif cmd == "zec-decode":
        zec_decode(sys.argv[2])
    elif cmd == "hex-to-int":
        hex_result_to_int(sys.argv[2])
    else:
        sys.exit(f"unknown subcommand {cmd}")
PYEOF

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

zec_balance() {
  # zec_balance <addr> -> zatoshi across every confirmed UTXO, or "?" on failure
  python3 "$PYHELPER" grpc-request "$1" >"$TMP_REQ"
  if ! curl -fsS -m 20 --http2 -X POST \
    "$ZEC_LIGHTWALLETD/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetAddressUtxos" \
    -H 'content-type: application/grpc' -H 'te: trailers' \
    --data-binary "@$TMP_REQ" -o "$TMP_RESP" 2>/dev/null; then
    echo "?"
    return
  fi
  python3 "$PYHELPER" zec-decode "$TMP_RESP"
}

eth_balance() {
  # eth_balance <rpc_url> <addr> -> wei, or "?" on failure
  curl -fsS -m 20 -X POST "$1" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBalance\",\"params\":[\"$2\",\"latest\"]}" \
    -o "$TMP_RESP" 2>/dev/null
  python3 "$PYHELPER" hex-to-int "$TMP_RESP"
}

usdc_balance() {
  # usdc_balance <rpc_url> <token_addr> <holder_addr> -> base units, or "?" on failure.
  # eth_call to the standard ERC-20 balanceOf(address) selector (0x70a08231), address
  # left-padded to 32 bytes.
  local data="0x70a08231000000000000000000000000${3#0x}"
  curl -fsS -m 20 -X POST "$1" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"$2\",\"data\":\"$data\"},\"latest\"]}" \
    -o "$TMP_RESP" 2>/dev/null
  python3 "$PYHELPER" hex-to-int "$TMP_RESP"
}

row taker btc-testnet3 "$BTC_TAKER" "$(esplora_balance "$BTC_ESPLORA" "$BTC_TAKER")" sats "$BTC_MIN"
row maker btc-testnet3 "$BTC_MAKER" "$(esplora_balance "$BTC_ESPLORA" "$BTC_MAKER")" sats "$BTC_MIN"
row taker ltc-testnet4 "$LTC_TAKER" "$(esplora_balance "$LTC_ESPLORA" "$LTC_TAKER")" lito "$LTC_MIN"
row maker ltc-testnet4 "$LTC_MAKER" "$(esplora_balance "$LTC_ESPLORA" "$LTC_MAKER")" lito "$LTC_MIN"
row taker divi-testnet "$DIVI_TAKER" "$(divi_balance "$DIVI_TAKER")" sats "$DIVI_MIN"
row maker divi-testnet "$DIVI_MAKER" "$(divi_balance "$DIVI_MAKER")" sats "$DIVI_MIN"
row taker zec-testnet "$ZEC_TAKER" "$(zec_balance "$ZEC_TAKER")" zat "$ZEC_MIN"
row maker zec-testnet "$ZEC_MAKER" "$(zec_balance "$ZEC_MAKER")" zat "$ZEC_MIN"
row taker sepolia-eth "$EVM_TAKER" "$(eth_balance "$SEPOLIA_RPC" "$EVM_TAKER")" wei "$USDC_ETH_MIN_WEI"
row maker sepolia-eth "$EVM_MAKER" "$(eth_balance "$SEPOLIA_RPC" "$EVM_MAKER")" wei "$USDC_ETH_MIN_WEI"
row taker sepolia-usdc "$EVM_TAKER" "$(usdc_balance "$SEPOLIA_RPC" "$SEPOLIA_USDC" "$EVM_TAKER")" units "$USDC_UNITS_MIN"
row maker sepolia-usdc "$EVM_MAKER" "$(usdc_balance "$SEPOLIA_RPC" "$SEPOLIA_USDC" "$EVM_MAKER")" units "$USDC_UNITS_MIN"
row taker base-sep-eth "$EVM_TAKER" "$(eth_balance "$BASE_SEPOLIA_RPC" "$EVM_TAKER")" wei "$USDC_ETH_MIN_WEI"
row maker base-sep-eth "$EVM_MAKER" "$(eth_balance "$BASE_SEPOLIA_RPC" "$EVM_MAKER")" wei "$USDC_ETH_MIN_WEI"
row taker base-sep-usdc "$EVM_TAKER" "$(usdc_balance "$BASE_SEPOLIA_RPC" "$BASE_SEPOLIA_USDC" "$EVM_TAKER")" units "$USDC_UNITS_MIN"
row maker base-sep-usdc "$EVM_MAKER" "$(usdc_balance "$BASE_SEPOLIA_RPC" "$BASE_SEPOLIA_USDC" "$EVM_MAKER")" units "$USDC_UNITS_MIN"

if ((check)); then
  if ((SHORTFALLS > 0)); then
    echo "balances: --check: $SHORTFALLS balance(s) below their live script's funding minimum"
    exit 1
  fi
  echo "balances: --check: all balances meet their live script's funding minimum"
fi
