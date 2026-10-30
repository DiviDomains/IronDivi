#!/bin/bash
# D5: with cores allowed by the shell, a SIGSEGV'd irondivid must leave no core
# anywhere; a control process (sleep) under the same limit must leave one, so
# the test is known to be able to see a core.
B=${IRONDIVID:-target/debug/irondivid}
T=$(mktemp -d); cd "$T"
ulimit -c unlimited
echo "core_pattern: $(cat /proc/sys/kernel/core_pattern)"
mark=$T/mark; touch "$mark"; sleep 1
find_cores() {
  { find "$T" /var/crash /var/lib/apport/coredump /var/lib/systemd/coredump -newer "$mark" \
      \( -name 'core*' -o -name '*.crash' -o -name '*.zst' -o -name '*.lz4' \) 2>/dev/null
    sudo -n find /var/crash /var/lib/apport/coredump /var/lib/systemd/coredump -newer "$mark" -type f 2>/dev/null; } | sort -u; }

echo "---- control: sleep, SIGSEGV"
cp /bin/sleep "$T/ctl-sleep"; "$T/ctl-sleep" 300 & C=$!; sleep 1
grep -E 'Max core' /proc/$C/limits
kill -SEGV $C; wait $C; echo "control exit=$?"; sleep 2
echo "control cores:"; find_cores | tee $T/ctl; xargs rm -f < $T/ctl 2>/dev/null

touch "$mark"; sleep 1
echo "---- irondivid, SIGSEGV"
mkdir -p $T/d; $B -regtest -datadir=$T/d -port=29450 -rpcport=29451 >/dev/null 2>&1 & P=$!
for _ in $(seq 60); do grep -q 'Starting RPC server' $T/d/debug.log 2>/dev/null && break; sleep 1; done
grep -E 'Max core' /proc/$P/limits; echo "fd/0..2 ok"
# Rust's stack-overflow SIGSEGV handler absorbs the first signal (it resets the
# disposition to default and returns), so a second one is needed to crash it.
kill -SEGV $P; sleep 2; kill -0 $P 2>/dev/null && kill -SEGV $P
wait $P; echo "irondivid exit=$?"; sleep 2
echo "irondivid cores:"; find_cores | tee $T/nd
# A pipe core_pattern (apport, systemd-coredump) is invoked whatever RLIMIT_CORE
# says; the handler is what honours the zero limit. Only apport is tested here.
[ -s $T/nd ] && echo "D5 FAIL" || echo "D5 PASS"
cd /; rm -rf "$T"
