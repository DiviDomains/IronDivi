#!/bin/bash
# Compare irondivid's mining and mempool RPC replies with Divi Core 3.0.0's
# divid on regtest, one row per call: SAME / DIFFERS / ABSENT. The exit code
# is the number of rows that are neither SAME nor a difference kept on purpose
# (docs/divid-differences.md). See README.md.
#
# Usage: run.sh <irondivid-bin-dir> <divid-bin-dir> <port-base> [<datadir-root>]
#   <irondivid-bin-dir>  directory holding irondivid
#   <divid-bin-dir>      directory holding Divi Core 3.0.0's divid
#   <port-base>          first of 4 consecutive ports (divid rpc + p2p, irondivid rpc + p2p)
#   <datadir-root>       where the temporary datadirs go (default: $TMPDIR or /tmp)
set -u

if [ $# -lt 3 ]; then
  echo "usage: $0 <irondivid-bin-dir> <divid-bin-dir> <port-base> [<datadir-root>]" >&2
  exit 255
fi
BIN_DIR=$(cd "$1" && pwd) || exit 255
DIVI_DIR=$(cd "$2" && pwd) || exit 255
PORT_BASE=$3
ROOT=${4:-${TMPDIR:-/tmp}}
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$BIN_DIR/irondivid" ] || { echo "no irondivid in $BIN_DIR" >&2; exit 255; }
[ -x "$DIVI_DIR/divid" ] || { echo "no divid in $DIVI_DIR" >&2; exit 255; }
mkdir -p "$ROOT"
WORK=$(mktemp -d "$ROOT/mining-replies.XXXXXX") || exit 255
chmod 700 "$WORK"

CHILD=
cleanup() {
  # Stop the comparison, then every node it started, then remove the datadirs
  [ -n "$CHILD" ] && kill -TERM "$CHILD" 2>/dev/null && wait "$CHILD" 2>/dev/null
  if [ -f "$WORK/pids" ]; then
    while read -r pid; do
      kill -TERM "$pid" 2>/dev/null
    done < "$WORK/pids"
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

# In the background, so a signal to this script runs the trap at once
timeout 900 python3 -I "$HERE/compare.py" "$BIN_DIR/irondivid" "$DIVI_DIR" "$PORT_BASE" "$WORK" &
CHILD=$!
wait "$CHILD"
rc=$?
CHILD=
[ $rc = 124 ] && echo "DIFFERS  run: did not finish within 15 minutes" && rc=255
exit $rc
