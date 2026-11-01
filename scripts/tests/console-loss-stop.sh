#!/bin/bash
# D1/D2 on hp3: a node whose terminal is gone (D1) or whose stdout/stderr are
# closed (D2) still stops cleanly on SIGTERM and logs why.
B=${IRONDIVID:-target/debug/irondivid}
T=$(mktemp -d)
up() { # wait up to 60 s for the node to log that it is running
  for _ in $(seq 60); do grep -q 'Starting RPC server' "$1/debug.log" 2>/dev/null && return 0; sleep 1; done; return 1; }
stop() { # SIGTERM, then wait up to 60 s for exit
  kill -TERM "$1"; for _ in $(seq 60); do kill -0 "$1" 2>/dev/null || return 0; sleep 1; done; echo "STILL RUNNING after 60 s"; return 1; }

echo "---- D2: stdout and stderr closed"
mkdir -p $T/d2
$B -regtest -datadir=$T/d2 -port=29444 -rpcport=29445 <&- >&- 2>&- &
P=$!; up $T/d2 || echo "D2 node did not come up"
echo "fd0-2: $(readlink /proc/$P/fd/0) $(readlink /proc/$P/fd/1) $(readlink /proc/$P/fd/2)"
stop $P; wait $P; echo "D2 exit=$?"
grep -E 'Received|lost|shutdown complete|panicked|Error' $T/d2/debug.log | tail -5

echo "---- D1: terminal closed (pty master gone), then SIGTERM"
mkdir -p $T/d1
script -qfc "$B -regtest -datadir=$T/d1 -port=29446 -rpcport=29447" /dev/null </dev/null >/dev/null 2>&1 &
S=$!; up $T/d1 || echo "D1 node did not come up"
P=$(pgrep -f "datadir=$T/d1" | grep -v "^$S\$" | while read p; do [ "$(cat /proc/$p/comm)" = irondivid ] && echo $p; done | head -1)
kill -KILL $S   # the terminal goes away, as on an SSH drop
sleep 3
kill -0 $P 2>/dev/null && echo "node alive after terminal loss (pid $P)"
stop $P; for _ in $(seq 10); do kill -0 $P 2>/dev/null || break; sleep 1; done
kill -0 $P 2>/dev/null && echo "D1 FAIL: node still running" || echo "D1 node gone"
grep -E 'Received|lost|shutdown complete|panicked|Error' $T/d1/debug.log | tail -6
rm -rf $T
