#!/bin/bash
# kill -9 of irondivid at seeded random points on regtest, next to Divi Core
# divid miners, and a check of chain, UTXO set, wallet and indexes after each
# restart. Prints one PASS/FAIL line per kill point (AS CORE/DIFFERS for the
# divid comparison); the exit code is the number of FAILs. See README.md.
#
#   run.sh <port-base>
#
# BIN       directory holding irondivid (default target/release)
# CORE_BIN  directory holding Divi Core's divid (default: divid on PATH)
# SEED      seed of the kill points (default: random, printed)
# WORK_ROOT a fresh directory is made under it and deleted (default $TMPDIR or /tmp)
# UNCLEAN_KILLS kill points per row (default 3); UNCLEAN_BLOCKS chain length (default 320)
# KEEP=1    keep the work directory (node logs) when a row fails
set -u

if [ $# -lt 1 ]; then
  echo "usage: $0 <port-base>" >&2
  exit 255
fi
BASE=$1
BIN=${BIN:-target/release}
if [ -z "${CORE_BIN:-}" ]; then
  d=$(command -v divid) || { echo "divid not found: set CORE_BIN" >&2; exit 255; }
  CORE_BIN=$(dirname "$d")
fi
IRD="$(cd "$BIN" && pwd)/irondivid"
DIVID="$(cd "$CORE_BIN" && pwd)/divid"
SEED=${SEED:-$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')}
ROOT=${WORK_ROOT:-${TMPDIR:-/tmp}}
HERE=$(cd "$(dirname "$0")" && pwd)
for b in "$IRD" "$DIVID"; do
  [ -x "$b" ] || { echo "not executable: $b" >&2; exit 255; }
done
mkdir -p "$ROOT"
WORK=$(mktemp -d "$ROOT/unclean-stop.XXXXXX") || exit 255
chmod 700 "$WORK"

CHILD=
rc=255
cleanup() {
  # Stop the check, then every node it started, then remove the datadirs
  [ -n "$CHILD" ] && kill -TERM "$CHILD" 2>/dev/null && wait "$CHILD" 2>/dev/null
  if [ -f "$WORK/pids" ]; then
    while read -r pid; do kill -TERM "$pid" 2>/dev/null; done < "$WORK/pids"
    for _ in $(seq 1 60); do
      alive=0
      while read -r pid; do kill -0 "$pid" 2>/dev/null && alive=1; done < "$WORK/pids"
      [ $alive = 0 ] && break
      sleep 1
    done
    while read -r pid; do kill -KILL "$pid" 2>/dev/null; done < "$WORK/pids"
  fi
  if [ "${KEEP:-0}" = 1 ] && [ "$rc" != 0 ]; then
    echo "# kept $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT
trap 'exit 255' INT TERM HUP

echo "# unclean-stop: seed $SEED, ports $BASE..$((BASE + 9)) (and $((BASE + 49)) unused) on 127.0.0.2, work directory $WORK"
echo "# irondivid $IRD, divid $DIVID"
# In the background, so a signal to this script runs the trap at once
timeout 840 python3 -I "$HERE/check.py" "$IRD" "$DIVID" "$BASE" "$WORK" "$SEED" &
CHILD=$!
wait "$CHILD"
rc=$?
CHILD=
[ $rc = 124 ] && echo "FAIL run did not finish within 14 minutes" && rc=255
exit $rc
