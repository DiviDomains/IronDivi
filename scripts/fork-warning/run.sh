#!/bin/bash
# Divi Core's fork warning on regtest: divid and irondivid move to a long
# branch, invalidate it, restart and take blocks of their own branch; the
# "errors" of getinfo and getmininginfo, safe mode, the log line and
# -alertnotify are compared at each step. Prints PASS/KNOWN/FAIL per row; the
# exit code is the number of FAILs. See README.md.
#
#   run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
#
# <irondivid-bin-dir> holds irondivid, <core-bin-dir> divid. Ports
# <port-base> .. <port-base>+7 are used. A fresh directory is made under
# [root] (default $TMPDIR or /tmp) and deleted, with all four nodes stopped,
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
WORK=$(mktemp -d "$ROOT/fork-warning.XXXXXX") || exit 255
chmod 700 "$WORK"

CHILD=
cleanup() {
  # Stop the check, then every node it started, then remove the datadirs
  [ -n "$CHILD" ] && kill -TERM "$CHILD" 2>/dev/null && wait "$CHILD" 2>/dev/null
  pids=$(cat "$WORK"/pids 2>/dev/null)
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

echo "# fork-warning: ports $BASE..$((BASE + 7)), work directory $WORK"
# In the background, so a signal to this script runs the trap at once
timeout 900 python3 -I "$HERE/check.py" "$IRD" "$DIVID" "$BASE" "$WORK" &
CHILD=$!
wait "$CHILD"
rc=$?
CHILD=
[ $rc = 124 ] && echo "FAIL  run: did not finish within 15 minutes" && rc=255
exit $rc
