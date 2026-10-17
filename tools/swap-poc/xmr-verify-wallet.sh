#!/usr/bin/env bash
# xmr-verify-wallet.sh — MATCH-proof for the shared Monero swap wallets.
#
# Re-derives a divi_xmr_swap_<network> receiving address from its 25-word seed
# and checks it against the `address` field recorded in the SAME 1Password item.
# Prints the network, the public receiving address, and MATCH / NO MATCH only.
#
# Seed safety (binding — see secret-management.md §2/§4/§5/§6 in claude-standards):
#   - The seed is resolved AT RUNTIME via the sanctioned resolver:
#       secret get --name <item> --op-ref op://global_secret_store/<item>/seed_phrase
#     (once per process). It is NEVER passed on argv and NEVER written to disk.
#   - The seed reaches monero-wallet-cli on STDIN only. monero-wallet-cli stdout
#     is filtered to the address token; the private view key it prints on restore
#     is dropped. No seed / spend key / view key is ever printed.
#   - The throwaway wallet (its .keys file is a plaintext spend key under an empty
#     password) is created in a 0700 temp dir outside any git tree and wiped on exit.
#
# Usage:  ./xmr-verify-wallet.sh --network <mainnet|stagenet|testnet>
#         ./xmr-verify-wallet.sh            # defaults to stagenet (our test net)
#
# Exit: 0 verified (MATCH, or address derived with no stored address to compare),
#       1 NO MATCH, 2 bad usage, 3 missing tool, 9 seed could not be resolved.
set -euo pipefail

NETWORK="stagenet"
while [ $# -gt 0 ]; do
  case "$1" in
    --network)   NETWORK="${2:?--network needs a value}"; shift 2;;
    --network=*) NETWORK="${1#*=}"; shift;;
    -h|--help)   sed -n '2,/^set -/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (try --help)" >&2; exit 2;;
  esac
done

case "$NETWORK" in
  mainnet)  ITEM="divi_xmr_swap_mainnet";;
  testnet)  ITEM="divi_xmr_swap_testnet";;
  stagenet) ITEM="divi_xmr_swap_stagenet";;
  *) echo "unknown network: $NETWORK (mainnet|stagenet|testnet)" >&2; exit 2;;
esac

command -v secret            >/dev/null || { echo "missing tool: secret"            >&2; exit 3; }
command -v monero-wallet-cli >/dev/null || { echo "missing tool: monero-wallet-cli" >&2; exit 3; }

SEED_REF="op://global_secret_store/${ITEM}/seed_phrase"
ADDR_REF="op://global_secret_store/${ITEM}/address"

# Recorded address from the SAME item (public field; safe to read and print).
RECORDED="$(secret get --name "${ITEM}__address" --op-ref "$ADDR_REF" 2>/dev/null || true)"

# Throwaway wallet dir: 0700, outside any git tree, removed on exit.
WDIR="$(mktemp -d "${TMPDIR:-/tmp}/xmrverify.XXXXXX")"
chmod 700 "$WDIR"
cleanup() { rm -rf "$WDIR"; }
trap cleanup EXIT

# Resolve the seed ONCE and feed it on stdin only. The first blank line ends the
# seed line; the next answers the seed-offset-passphrase prompt (blank = none, so
# the base wallet is derived); the rest are harmless no-ops. --restore-height and
# --password are flags, never stdin, so prompt ORDER cannot misalign the seed.
#
# grep writes the (public) address token to a temp file rather than piping into
# `head`: that lets grep drain monero-wallet-cli's stdout to EOF, so the producer
# (`secret get`) is never hit by a SIGPIPE from an early reader close. `|| true`
# keeps `set -o pipefail` from aborting when no address matches (handled below).
# monero-wallet-cli: mainnet is the default and takes NO network flag; only
# --testnet / --stagenet exist. Build one always-non-empty args array (so the
# expansion is safe under `set -u` even on bash 3.2, which ships with macOS).
MW=(--offline --restore-deterministic-wallet --generate-new-wallet "$WDIR/w"
    --restore-height 0 --password '' --log-file "$WDIR/log" --log-level 0)
[ "$NETWORK" = testnet ]  && MW=(--testnet  "${MW[@]}")
[ "$NETWORK" = stagenet ] && MW=(--stagenet "${MW[@]}")

: > "$WDIR/addr"
{
  secret get --name "$ITEM" --op-ref "$SEED_REF" \
    || { echo "__SECRET_FAIL rc=$? (broker/op unavailable, or field not found)" >&2; exit 9; }
  printf '\n\n\n\n\n\n'
} | monero-wallet-cli "${MW[@]}" 2>/dev/null \
  | grep -aoE '[1-9A-HJ-NP-Za-km-z]{95}' > "$WDIR/addr" || true
DERIVED="$(head -n1 "$WDIR/addr" 2>/dev/null || true)"

echo "network=$NETWORK"
if [ -z "$DERIVED" ]; then
  echo "result=ERROR: address not derived (seed unavailable or prompt misalignment)"
  exit 9
fi
echo "address=$DERIVED"

if [ -z "$RECORDED" ]; then
  echo "result=no stored address to compare"
  exit 0
elif [ "$DERIVED" = "$RECORDED" ]; then
  echo "result=MATCH"
  exit 0
else
  echo "result=NO MATCH"
  exit 1
fi
