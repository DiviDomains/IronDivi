#!/bin/bash
# Three Divi Core divid and three irondivid nodes on one regtest network for
# HOURS, with traffic, restarts, a join and partitions, checked for agreement.
# See README.md.
#
#   SEED=<n> HOURS=<h> OUT=<dir> run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
#
# <irondivid-bin-dir> holds irondivid, <core-bin-dir> divid. Ports
# <port-base> .. <port-base>+13 are used. A fresh directory is made under
# [root] (default $TMPDIR or /tmp) for the datadirs and deleted, with every node
# stopped, however the run ends. What the run finds is written to OUT (default
# [root]/mixed-net-results), which is kept.
set -u

if [ $# -lt 3 ]; then
  echo "usage: SEED=<n> HOURS=<h> $0 <irondivid-bin-dir> <core-bin-dir> <port-base> [root]" >&2
  exit 255
fi
IRD="$(cd "$1" && pwd)/irondivid"
DIVID="$(cd "$2" && pwd)/divid"
BASE=$3
ROOT=${4:-${TMPDIR:-/tmp}}
HERE=$(cd "$(dirname "$0")" && pwd)
export SEED=${SEED:-1}
export HOURS=${HOURS:-1}
OUT=${OUT:-$ROOT/mixed-net-results}
for b in "$IRD" "$DIVID"; do
  [ -x "$b" ] || { echo "not executable: $b" >&2; exit 255; }
done
mkdir -p "$ROOT" "$OUT"
WORK=$(mktemp -d "$ROOT/mixed-net.XXXXXX") || exit 255
chmod 700 "$WORK"

CHILD=
cleanup() {
  # Stop the run, then every node it started, then remove the datadirs
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

LIMIT=$(python3 -c "print(int(float('$HOURS') * 3600 + 3600))")
echo "# mixed-net: seed $SEED, $HOURS h, ports $BASE..$((BASE + 13)), work $WORK, results $OUT"
timeout "$LIMIT" python3 -I "$HERE/net.py" "$IRD" "$DIVID" "$BASE" "$WORK" "$OUT" &
CHILD=$!
wait "$CHILD"
rc=$?
CHILD=
[ $rc = 124 ] && echo "FAIL  run: did not finish within $LIMIT s"
exit $rc
