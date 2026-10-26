#!/bin/bash
# The wallet rows of a masternode payment, on Divi Core divid and on irondivid:
# scripts/mn-life with its payment phase, masternode payments turned on in divid
# with -manual_fork, and then the rows compared (see README.md).
#
#   run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
#
# <port-base> .. <port-base>+15 are used on 127.0.0.2. A run takes about 50
# minutes and is stopped after 60. Exit code = FAILs (255: usage error,
# interrupted, or over the time limit).
set -u
if [ $# -lt 3 ]; then
  echo "usage: $0 <irondivid-bin-dir> <core-bin-dir> <port-base> [root]" >&2
  exit 255
fi
HERE=$(cd "$(dirname "$0")" && pwd)
MN_LIFE_PAYMENTS=1 MN_LIFE_REWARDS=1 exec "$HERE/../mn-life/run.sh" "$@"
