#!/bin/bash
# Check the RPC calls BasicSwap's Divi interface makes, against a fresh
# regtest irondivid. Prints PASS/FAIL per call; the exit code is the number
# of FAILs. See README.md.
#
# Usage: run.sh <irondivid-bin-dir> <port-base> [<datadir-root>]
#   <irondivid-bin-dir>  directory holding irondivid
#   <port-base>          first of 4 consecutive ports (two nodes, p2p + rpc)
#   <datadir-root>       where the temporary datadirs go (default: $TMPDIR or /tmp)
set -u

if [ $# -lt 2 ]; then
  echo "usage: $0 <irondivid-bin-dir> <port-base> [<datadir-root>]" >&2
  exit 255
fi
BIN_DIR=$(cd "$1" && pwd) || exit 255
PORT_BASE=$2
ROOT=${3:-${TMPDIR:-/tmp}}
HERE=$(cd "$(dirname "$0")" && pwd)

[ -x "$BIN_DIR/irondivid" ] || { echo "no irondivid in $BIN_DIR" >&2; exit 255; }
mkdir -p "$ROOT"
WORK=$(mktemp -d "$ROOT/swap-rpc.XXXXXX") || exit 255
chmod 700 "$WORK"

CHILD=
cleanup() {
  # Stop the check, then every node it started, then remove the datadirs
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
timeout 600 python3 -I "$HERE/check.py" "$BIN_DIR/irondivid" "$PORT_BASE" "$WORK" &
CHILD=$!
wait "$CHILD"
rc=$?
CHILD=
[ $rc = 124 ] && echo "FAIL  run: did not finish within 10 minutes" && rc=255
exit $rc
