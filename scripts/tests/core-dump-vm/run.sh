#!/bin/bash
# D5 release gates, run as root inside a disposable VM:
#  A) core_pattern = systemd-coredump   B) core_pattern = plain "core"
# In each, a control process (sleep) must leave a core and irondivid must not.
B=/root/irondivid
segv_node() { # start irondivid, wait for RPC, SIGSEGV it (twice if needed)
  local d=$(mktemp -d); "$B" -regtest -datadir=$d -port=29450 -rpcport=29451 >/dev/null 2>&1 & local P=$!
  for _ in $(seq 90); do grep -q 'Starting RPC server' $d/debug.log 2>/dev/null && break; sleep 1; done
  echo "node limits: $(grep 'Max core' /proc/$P/limits)"
  kill -SEGV $P; sleep 2; kill -0 $P 2>/dev/null && kill -SEGV $P; wait $P; echo "irondivid exit=$?"; }
segv_ctl() { "$1" 300 & local C=$!; sleep 1; kill -SEGV $C; wait $C; echo "control exit=$?"; }
ulimit -c unlimited
echo "==== A: systemd-coredump"
echo "core_pattern: $(cat /proc/sys/kernel/core_pattern)"
cp /bin/sleep /root/ctl-sleep
segv_ctl /root/ctl-sleep; segv_node; sleep 5
coredumpctl list --no-pager 2>&1
echo "-- stored files:"; ls -la /var/lib/systemd/coredump/
coredumpctl info --no-pager irondivid 2>&1 | grep -E 'Storage|Signal|Executable|Size on Disk'
coredumpctl info --no-pager ctl-sleep 2>&1 | grep -E 'Storage|Signal|Size on Disk'
n=$(ls /var/lib/systemd/coredump/ | grep -c irondivid); c=$(ls /var/lib/systemd/coredump/ | grep -c ctl-sleep)
[ $c -ge 1 ] && [ $n -eq 0 ] && echo "D5-A PASS" || echo "D5-A FAIL (ctl=$c node=$n)"
echo "==== B: plain core"
sysctl -q kernel.core_pattern=core; sysctl -q kernel.core_uses_pid=1
echo "core_pattern: $(cat /proc/sys/kernel/core_pattern)"
W=$(mktemp -d); cd $W; touch /root/mark-b; sleep 1
segv_ctl /root/ctl-sleep; segv_node; sleep 2
echo "cores in cwd:"; ls -la $W; for f in $W/core*; do file $f; done
echo "other recent cores:"; find / -xdev -name 'core*' -type f -newer /root/mark-b 2>/dev/null | grep -v "^$W"
c=$(ls $W | grep -c '^core'); n=$({ for f in $W/core* $(find / -xdev -name 'core*' -type f -newer /root/mark-b 2>/dev/null | grep -v "^$W"); do file $f; done; } | grep -c irondivid)
[ $c -ge 1 ] && [ $n -eq 0 ] && echo "D5-B PASS" || echo "D5-B FAIL (ctl=$c node=$n)"
echo "D5VM-DONE"
