#!/bin/bash
# Every number argument of the divid command table, sent the same values on Divi
# Core divid and irondivid side by side on one regtest chain: 2^31-1, 2^31,
# 2^31+41, 2^32+41, -1, 2^53+1, 1.5, 1e3, "5", true, null and a few more. Prints
# PASS/KNOWN/FAIL per (call, argument, value); the exit code is the number of FAILs.
#
#   run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
#
# <irondivid-bin-dir> holds irondivid, <core-bin-dir> divid. Ports
# <port-base> .. <port-base>+3 are used. A fresh directory is made under
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
WORK=$(mktemp -d "$ROOT/int-args.XXXXXX") || exit 255
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
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 255' INT TERM HUP

echo "# int-args: ports $BASE..$((BASE + 3)), work directory $WORK"
# In the background, so a signal to this script runs the trap at once
timeout 600 python3 -I "$HERE/check.py" "$IRD" "$DIVID" "$BASE" "$WORK" &
CHILD=$!
wait "$CHILD"
rc=$?
CHILD=
[ $rc = 124 ] && echo "FAIL  run: did not finish within 10 minutes" && rc=255
exit $rc
