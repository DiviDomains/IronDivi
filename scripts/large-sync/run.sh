#!/bin/bash
# A long, busy chain synced from scratch both ways: one seeded chain of about
# 3,000 regtest blocks is built on divid, then irondivid and divid sync it from
# each other, are stopped and killed during a sync, -reindex, and restore a
# wallet with -rescan; the outcomes are compared and the times printed. Prints
# PASS/KNOWN/FAIL per row; the exit code is the number of FAILs. See README.md.
#
#   run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
#
# <irondivid-bin-dir> holds irondivid, <core-bin-dir> divid. Ports
# <port-base> .. <port-base>+9 are used, and <port-base>+49 must have nothing listening. A fresh directory is made under
# [root] (default $TMPDIR or /tmp) and deleted, with both nodes stopped,
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
WORK=$(mktemp -d "$ROOT/large-sync.XXXXXX") || exit 255
chmod 700 "$WORK"

CHILD=
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
  if [ -n "${LARGE_SYNC_KEEP:-}" ]; then echo "# kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
trap 'exit 255' INT TERM HUP

echo "# large-sync: ports $BASE..$((BASE + 9)), work directory $WORK"
# In the background, so a signal to this script runs the trap at once
timeout 10800 python3 -I "$HERE/check.py" "$IRD" "$DIVID" "$BASE" "$WORK" &
CHILD=$!
wait "$CHILD"
rc=$?
CHILD=
[ $rc = 124 ] && echo "FAIL  run: did not finish within 3 hours" && rc=255
exit $rc
