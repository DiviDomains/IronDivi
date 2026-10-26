#!/bin/bash
# Reorganisations across a split network of Divi Core divid and irondivid on
# regtest: competing chains on two sides, joined, and the tip, chain tips,
# mempool and one shared wallet compared on every node, then invalidateblock
# and reconsiderblock. Prints PASS/KNOWN/FAIL per row; the exit code is the
# number of FAILs. See README.md.
#
#   run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
#
# <irondivid-bin-dir> holds irondivid, <core-bin-dir> divid. Ports
# <port-base> .. <port-base>+11 are used. A fresh directory is made under
# [root] (default $TMPDIR or /tmp) and deleted, with all six nodes stopped,
# however the run ends.
set -u

if [ $# -lt 3 ]; then
  echo "usage: $0 <irondivid-bin-dir> <core-bin-dir> <port-base> [root]" >&2
  exit 255
fi
IRD="$(cd "$1" && pwd)/irondivid"
DIVID="$(cd "$2" && pwd)/divid"
BASE=$3
ROOT=${4:-${TMPDIR:-/tmp}}
HERE=$(cd "$(dirname "$0")" && pwd)
for b in "$IRD" "$DIVID"; do
  [ -x "$b" ] || { echo "not executable: $b" >&2; exit 255; }
done
mkdir -p "$ROOT"
WORK=$(mktemp -d "$ROOT/reorg-state.XXXXXX") || exit 255
chmod 700 "$WORK"

CHILD=
cleanup() {
  # Stop the check, then every node it started, then remove the datadirs
  [ -n "$CHILD" ] && kill -TERM "$CHILD" 2>/dev/null && wait "$CHILD" 2>/dev/null
  pids=$(cat "$WORK"/u*/pids 2>/dev/null)
  if [ -n "$pids" ]; then
    for pid in $pids; do kill -TERM "$pid" 2>/dev/null; done
    for _ in $(seq 1 60); do
      alive=0
      for pid in $pids; do kill -0 "$pid" 2>/dev/null && alive=1; done
      [ $alive = 0 ] && break
      sleep 1
    done
    for pid in $pids; do kill -KILL "$pid" 2>/dev/null; done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 255' INT TERM HUP

echo "# reorg-state: ports $BASE..$((BASE + 16)), work directory $WORK"
# Two runs of the network, one per spork case (see README.md); in the background, so a
# signal to this script runs the trap at once
total=0
for universe in 1 2; do
  echo "# universe $universe"
  mkdir -p "$WORK/u$universe"
  REORG_STATE_UNIVERSE=$universe timeout 1800 python3 -I "$HERE/check.py" "$IRD" "$DIVID" "$BASE" "$WORK/u$universe" &
  CHILD=$!
  wait "$CHILD"
  rc=$?
  CHILD=
  [ $rc = 124 ] && echo "FAIL  run: universe $universe did not finish within 30 minutes" && rc=255
  [ $rc = 255 ] && total=255
  [ $total != 255 ] && total=$((total + rc))
done
[ $total -gt 254 ] && total=254
exit $total
