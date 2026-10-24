#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Bert Shuler
# IronDivi - https://github.com/DiviDomains/IronDivi
#
# Regtest check of irondivid next to Divi Core: every node starts from its
# divi.conf, and each check prints PASS or FAIL. Exit code = number of FAILs.
# See README.md.
#
#   run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
#
# <irondivid-bin-dir> holds irondivid and irondivi-cli, <core-bin-dir> divid
# and divi-cli. Ports <port-base> .. <port-base>+29 are used; the default
# regtest ports (51475, 51476) are only read from the start banner, never
# bound. A fresh directory is made under [root] (default $TMPDIR or /tmp) and
# deleted, with every node stopped, however the run ends.

set -u

if [ $# -lt 3 ]; then
    echo "usage: $0 <irondivid-bin-dir> <core-bin-dir> <port-base> [root]" >&2
    exit 255
fi
IRD="$(cd "$1" && pwd)/irondivid"
ICLI="$(cd "$1" && pwd)/irondivi-cli"
DIVID="$(cd "$2" && pwd)/divid"
DCLI="$(cd "$2" && pwd)/divi-cli"
BASE=$3
ROOT=${4:-${TMPDIR:-/tmp}}
for b in "$IRD" "$ICLI" "$DIVID" "$DCLI"; do
    [ -x "$b" ] || { echo "not executable: $b" >&2; exit 255; }
done

LIMIT=${INTEROP_LIMIT:-600} # seconds for the whole run
WAIT=10   # seconds for a block or a transaction to arrive
FAILS=0
W=$(mktemp -d "$ROOT/interop.XXXXXX")
PIDS=()

# ---------------------------------------------------------------- cleanup

stop_all() {
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
    for d in "$W"/core-*; do
        [ -d "$d" ] && "$DCLI" -datadir="$d" stop >/dev/null 2>&1
    done
    local deadline=$((SECONDS + 60))
    while [ $SECONDS -lt $deadline ]; do
        pgrep -f -- "-datadir=$W/" >/dev/null || break
        sleep 1
    done
    pkill -KILL -f -- "-datadir=$W/" 2>/dev/null
    for p in "${PIDS[@]}"; do kill -KILL "$p" 2>/dev/null; done
}
cleanup() {
    trap - EXIT INT TERM
    [ -n "${WATCHDOG:-}" ] && kill "$WATCHDOG" 2>/dev/null
    stop_all
    rm -rf "$W"
}
trap cleanup EXIT
trap 'echo "FAIL interrupted"; FAILS=$((FAILS + 1)); exit $FAILS' INT TERM
# The whole run is bounded: the watchdog ends it, and the trap cleans up
(
    trap 'kill $SLEEP 2>/dev/null; exit 0' TERM
    sleep $LIMIT &
    SLEEP=$!
    wait $SLEEP
    echo "FAIL the run took longer than $LIMIT s"
    kill -TERM $$
) &
WATCHDOG=$!

# ---------------------------------------------------------------- helpers

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
check() { # check <description> <command...>: PASS if the command succeeds
    local what=$1; shift
    if "$@"; then pass "$what"; else fail "$what"; fi
}
# Retry a command for up to <secs> seconds
within() {
    local secs=$1; shift
    local deadline=$((SECONDS + secs))
    while :; do
        "$@" >/dev/null 2>&1 && return 0
        [ $SECONDS -ge $deadline ] && return 1
        sleep 0.25
    done
}
json() { # json <python expression on j> : read JSON on stdin
    python3 -c "import json,sys; j=json.load(sys.stdin); print($1)"
}
# An error reply as "code message", from either CLI's "error: {...}" output
rpc_error() {
    sed -n 's/^error: //p' | python3 -c \
        "import json,sys; e=json.load(sys.stdin); print(e['code'], e['message'])" 2>/dev/null
}

PASSWORD=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')

A=$W/core-a B=$W/core-b X=$W/x
A_P2P=$BASE A_RPC=$((BASE + 1))
B_P2P=$((BASE + 2)) B_RPC=$((BASE + 3))
X_P2P=$((BASE + 10)) X_RPC=$((BASE + 11))
Z_P2P=$((BASE + 20)) Z_RPC=$((BASE + 21))
C=$W/core-c D=$W/core-d E=$W/core-e F=$W/core-f Y=$W/y P=$W/p
C_P2P=$((BASE + 4)) C_RPC=$((BASE + 5))
D_P2P=$((BASE + 6)) D_RPC=$((BASE + 7))
E_P2P=$((BASE + 8)) E_RPC=$((BASE + 9))
F_P2P=$((BASE + 14)) F_RPC=$((BASE + 15))
Y_P2P=$((BASE + 12)) Y_RPC=$((BASE + 13))
P_P2P=$((BASE + 22)) P_RPC=$((BASE + 23))

conf() { # conf <dir> <lines...>: a 0600 divi.conf with the RPC credentials
    local d=$1; shift
    mkdir -p "$d"
    (umask 077; {
        echo "regtest=1"
        echo "rpcuser=interop"
        echo "rpcpassword=$PASSWORD"
        printf '%s\n' "$@"
    } > "$d/divi.conf")
}

a() { "$DCLI" -datadir="$A" "$@"; }
d() { "$DCLI" -datadir="$D" "$@"; }
e() { "$DCLI" -datadir="$E" "$@"; }
f() { "$DCLI" -datadir="$F" "$@"; }
y() { "$ICLI" -datadir="$Y" -conf="$Y/divi.conf" "$@"; }
pw() { "$ICLI" -datadir="$P" -conf="$P/divi.conf" "$@"; }
b() { "$DCLI" -datadir="$B" "$@"; }
x() { "$ICLI" -datadir="$X" -conf="$X/divi.conf" "$@"; }
height_is() { [ "$($1 getblockcount 2>/dev/null)" = "$2" ]; }
same_tip() { [ "$($1 getbestblockhash 2>/dev/null)" = "$2" ]; }

X_PID=
start_x() { # irondivid from its divi.conf, in the foreground; extra options after
    setsid "$IRD" -datadir="$X" "$@" >>"$W/x.out" 2>&1 &
    X_PID=$!
    PIDS+=("$X_PID")
    within 120 x getblockcount
}
x_exits() { # wait for irondivid X to end, at most 60 s
    local deadline=$((SECONDS + 60))
    while pgrep -f -- "$IRD -datadir=$X" >/dev/null; do
        [ $SECONDS -ge $deadline ] && return 1
        sleep 0.5
    done
}
tree_hash() {
    (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)
}

echo "# interop: $("$IRD" -version 2>/dev/null | head -1) next to $("$DIVID" -version 2>/dev/null | head -1)"
echo "# ports $BASE..$((BASE + 29)), work directory $W"

# ---------------------------------------------------------------- default ports

D=$W/defaults
conf "$D" "server=0" "listen=0" "connect=127.0.0.1:$A_P2P" "staking=0"
setsid "$IRD" -datadir="$D" >>"$W/defaults.out" 2>&1 &
D_PID=$!
PIDS+=("$D_PID")
within 60 grep -q "P2P:" "$D/debug.log"
check "default regtest RPC port is divid's 51475" grep -qE "RPC: [0-9.]+:51475$" "$D/debug.log"
check "default regtest P2P port is divid's 51476" grep -qE "P2P: [0-9.]+:51476$" "$D/debug.log"
nothing_on_defaults() { ! ss -ltn | grep -qE ':5147[56] '; }
check "with server=0 and listen=0 nothing listens on 51475 or 51476" nothing_on_defaults
kill -TERM "$D_PID" 2>/dev/null

# ---------------------------------------------------------------- start

conf "$A" "daemon=1" "port=$A_P2P" "rpcport=$A_RPC" "bind=127.0.0.1" "listen=1" "staking=0"
conf "$B" "daemon=1" "port=$B_P2P" "rpcport=$B_RPC" "listen=0" "staking=0" "connect=127.0.0.1:$X_P2P"
conf "$X" "port=$X_P2P" "rpcport=$X_RPC" "bind=127.0.0.1" "listen=1" "staking=0" \
    "connect=127.0.0.1:$A_P2P" "pid=node.pid"
"$DIVID" -datadir="$A" >/dev/null 2>&1
check "Divi Core A starts from divi.conf" within 60 a getblockcount
check "irondivid starts from divi.conf (-datadir only)" start_x
"$DIVID" -datadir="$B" >/dev/null 2>&1
check "Divi Core B starts from divi.conf" within 60 b getblockcount

# Two nodes on one IP, one on each port: Divi Core C beside A. irondivid Y
# and Divi Core D are each given both as addnode= lines.
conf "$C" "daemon=1" "port=$C_P2P" "rpcport=$C_RPC" "bind=127.0.0.1" "listen=1" "staking=0"
conf "$D" "daemon=1" "port=$D_P2P" "rpcport=$D_RPC" "listen=0" "staking=0" \
    "addnode=127.0.0.1:$A_P2P" "addnode=127.0.0.1:$C_P2P"
conf "$Y" "port=$Y_P2P" "rpcport=$Y_RPC" "listen=0" "staking=0" \
    "addnode=127.0.0.1:$A_P2P" "addnode=127.0.0.1:$C_P2P"
"$DIVID" -datadir="$C" >/dev/null 2>&1
within 60 "$DCLI" -datadir="$C" getblockcount
"$DIVID" -datadir="$D" >/dev/null 2>&1
setsid "$IRD" -datadir="$Y" >>"$W/y.out" 2>&1 &
PIDS+=("$!")
Y_START=$SECONDS
check "irondivid Y (two addnode= lines on one IP) starts from divi.conf" within 120 y getblockcount

pid_file_is() { [ "$(cat "$X/node.pid" 2>/dev/null)" = "$1" ]; }
no_pid_file() { [ ! -e "$X/node.pid" ]; }
check "pid file without -daemon holds irondivid's pid" pid_file_is "$X_PID"

outbound_to() { # outbound_to <cli> <port>: an outbound peer on that port
    $1 getpeerinfo 2>/dev/null | json "any(p['addr'].endswith(':$2') and not p.get('inbound') for p in j)" | grep -q True
}
inbound() { $1 getpeerinfo 2>/dev/null | json "any(p.get('inbound') for p in j)" | grep -q True; }
x_dials_a() { outbound_to x $A_P2P && inbound a; }
b_dials_x() { outbound_to b $X_P2P && inbound x; }
check "irondivid dials Divi Core (outbound to A, A sees it inbound)" within 30 x_dials_a
check "Divi Core dials irondivid (B outbound to irondivid, irondivid sees it inbound)" within 30 b_dials_x

# ---------------------------------------------------------------- blocks both ways

a setgenerate 1 >/dev/null
TIP=$(a getbestblockhash)
check "block mined by Divi Core reaches irondivid within ${WAIT}s" within $WAIT same_tip x "$TIP"
check "irondivid relays it to its inbound Divi Core peer within ${WAIT}s" within $WAIT same_tip b "$TIP"

MINED=$(x setgenerate 1 2>&1)
TIP=$(x getbestblockhash)
if [ "$(echo "$MINED" | json 'j[0]' 2>/dev/null)" = "$TIP" ]; then
    pass "irondivid mines a block (setgenerate 1)"
    check "block mined by irondivid reaches Divi Core A (outbound) within ${WAIT}s" within $WAIT same_tip a "$TIP"
    check "block mined by irondivid reaches Divi Core B (inbound) within ${WAIT}s" within $WAIT same_tip b "$TIP"
else
    fail "irondivid mines a block (setgenerate 1): $(echo "$MINED" | head -c 200)"
    fail "block mined by irondivid reaches Divi Core A (outbound): nothing mined"
    fail "block mined by irondivid reaches Divi Core B (inbound): nothing mined"
fi

# Mature coins for Divi Core A (regtest coinbase maturity 20)
a setgenerate 40 >/dev/null
H=$(a getblockcount)
all_at() { height_is x "$1" && height_is b "$1"; }
check "all three nodes at height $H" within 60 all_at "$H"

# ---------------------------------------------------------------- Core's divi-cli

core_cli_on_x() { [ "$("$DCLI" -datadir="$X" getblockcount 2>/dev/null)" = "$1" ]; }
check "Divi Core's divi-cli talks to irondivid (getblockcount)" core_cli_on_x "$H"
for h in 99999 -1; do
    want=$(a getblockhash $h 2>&1 | rpc_error)
    got=$(x getblockhash $h 2>&1 | rpc_error)
    if [ -n "$want" ] && [ "$got" = "$want" ]; then
        pass "getblockhash $h: \"$got\" as divid"
    else
        fail "getblockhash $h: irondivid \"$got\", divid \"$want\""
    fi
done

# ---------------------------------------------------------------- sends both ways

XADDR=$(x getnewaddress)
XBAL=$(x getbalance)
T1=$(a sendtoaddress "$XADDR" 5000)
a setgenerate 1 >/dev/null
H=$(a getblockcount)
within 30 height_is x "$H"
BH=$(a gettransaction "$T1" | json "j['blockhash']")
balance_is() { [ "$(x getbalance)" = "$1" ]; }
x_tx_is() { [ "$(x gettransaction "$1" | json "'%s %s' % (j['amount'], j['blockhash'])")" = "$2" ]; }
has_coin() { $1 listunspent | json "any(u['txid'] == '$2' and u['amount'] == $3 for u in j)" | grep -q True; }
check "Divi Core -> irondivid 5000: irondivid's balance rose by 5000" balance_is "$(python3 -c "print('%.8f' % ($XBAL + 5000))")"
check "Divi Core -> irondivid: gettransaction amount and block agree" x_tx_is "$T1" "5000.0 $BH"
check "Divi Core -> irondivid: listunspent shows the coin" has_coin x "$T1" 5000

AADDR=$(a getnewaddress)
T2=$(x sendtoaddress "$AADDR" 1234.5 2>/dev/null)
in_a_mempool() { a getrawmempool | grep -q "${1:-none}"; }
check "irondivid -> Divi Core 1234.5 reaches Divi Core's mempool within ${WAIT}s" within $WAIT in_a_mempool "$T2"
a setgenerate 1 >/dev/null
H=$(a getblockcount)
within 30 height_is x "$H"
sides_agree() {
    local core mine
    core=$(a gettransaction "$1" | json "'%s %s' % (j['amount'], j['blockhash'])") || return 1
    mine=$(x gettransaction "$1" | json "'%s %s' % (-j['amount'], j['blockhash'])") || return 1
    [ "$core" = "$mine" ]
}
check "irondivid -> Divi Core: gettransaction amount and block agree" sides_agree "${T2:-none}"
check "irondivid -> Divi Core: Divi Core's listunspent shows the coin" has_coin a "${T2:-none}" 1234.5

# ---------------------------------------------------------------- RPC stop and SIGTERM

state() { echo "$(x getblockcount) $(x getbestblockhash) $(x getbalance) $(x listunspent | json 'len(j)')"; }
BEFORE=$(state)
x stop >/dev/null 2>&1
check "RPC stop ends irondivid within 60 s" x_exits
check "pid file removed at the clean stop" no_pid_file
start_x
state_is() { [ "$(state)" = "$1" ]; }
check "after RPC stop and restart: same height, tip, balance and coins" state_is "$BEFORE"

BAL=$(x getbalance)
a setgenerate 30 >/dev/null 2>&1 &
GEN=$!
above() { [ "$(x getblockcount 2>/dev/null || echo 0)" -gt "$1" ]; }
within 30 above $((H + 5))
kill -TERM "$X_PID"
check "SIGTERM while blocks arrive ends irondivid within 60 s" x_exits
wait $GEN
clean_end() { tail -n 20 "$X/debug.log" | grep -q 'shutdown complete'; }
check "SIGTERM shutdown completed cleanly" clean_end
check "pid file removed after SIGTERM" no_pid_file
start_x
TIP=$(a getbestblockhash)
check "after SIGTERM and restart: irondivid catches up to Divi Core's tip" within 60 same_tip x "$TIP"
check "after SIGTERM and restart: balance unchanged" balance_is "$BAL"
if grep -q ' ERROR ' "$X/debug.log"; then
    fail "no ERROR in irondivid's log: $(grep ' ERROR ' "$X/debug.log" | head -1 | cut -c1-200)"
else
    pass "no ERROR in irondivid's log"
fi

x stop >/dev/null 2>&1
x_exits
"$IRD" -datadir="$X" -daemon >>"$W/x.out" 2>&1
within 60 x getblockcount
DPID=$(pgrep -f -- "$IRD -datadir=$X -daemon" | head -1)
PIDS+=("${DPID:-0}")
check "pid file with -daemon holds the daemon's pid" pid_file_is "${DPID:-none}"
x stop >/dev/null 2>&1
x_exits
check "pid file removed at the clean stop (-daemon)" no_pid_file

# ---------------------------------------------------------------- one connection per address

outbound_count() { $1 getpeerinfo 2>/dev/null | json "sum(1 for p in j if not p.get('inbound'))"; }
# Let both nodes run their dial loops at least once more (irondivid every 30 s)
while [ $((SECONDS - Y_START)) -lt 40 ]; do sleep 1; done
N=$(outbound_count d)
if [ "$N" = 1 ]; then pass "divid: two addnode= lines on one IP make 1 outbound connection"
else fail "divid: two addnode= lines on one IP make 1 outbound connection (got $N)"; fi
N=$(outbound_count y)
if [ "$N" = 1 ]; then pass "irondivid: two addnode= lines on one IP make 1 outbound connection, as divid"
else fail "irondivid: two addnode= lines on one IP make 1 outbound connection, as divid (got $N)"; fi

# ---------------------------------------------------------------- words made with a passphrase

# A new irondivid wallet with only mnemonicpassphrase= set. The passphrase
# and the words stay in 0600 files and divi.conf files; nothing prints them.
(umask 077; head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/pass")
conf "$P" "port=$P_P2P" "rpcport=$P_RPC" "listen=0" "staking=0" "connect=127.0.0.1:$A_P2P" \
    "mnemonicpassphrase=$(cat "$W/pass")"
setsid "$IRD" -datadir="$P" >>"$W/p.out" 2>&1 &
PIDS+=("$!")
check "irondivid starts a new wallet with only mnemonicpassphrase= in divi.conf" within 120 pw getblockcount
(umask 077; pw dumphdinfo > "$W/hd.json" 2>/dev/null)
python3 - "$W" <<'PY'
import json, os, sys
w = sys.argv[1]
os.umask(0o077)
try:
    hd = json.load(open(os.path.join(w, "hd.json")))
except Exception:
    hd = {}
open(os.path.join(w, "words"), "w").write(hd.get("mnemonic", ""))
open(os.path.join(w, "words-pass"), "w").write(hd.get("mnemonicpassphrase", ""))
PY
same_passphrase() { cmp -s "$W/pass" "$W/words-pass"; }
check "irondivid's dumphdinfo reports the passphrase from divi.conf" same_passphrase
P_ADDR=$(pw getaddressesbyaccount "" 2>/dev/null | json 'j[0]' 2>/dev/null)

# Divi Core restores irondivid's words: E with the passphrase, F without it
conf "$E" "daemon=1" "port=$E_P2P" "rpcport=$E_RPC" "bind=127.0.0.1" "listen=1" "staking=0" \
    "connect=127.0.0.1:$A_P2P" "mnemonic=$(cat "$W/words")" "mnemonicpassphrase=$(cat "$W/pass")"
conf "$F" "daemon=1" "port=$F_P2P" "rpcport=$F_RPC" "listen=0" "staking=0" \
    "connect=127.0.0.1:$A_P2P" "mnemonic=$(cat "$W/words")"
"$DIVID" -datadir="$E" >/dev/null 2>&1
"$DIVID" -datadir="$F" >/dev/null 2>&1
within 120 e getblockcount
within 120 f getblockcount
is_mine() { [ -n "$2" ] && $1 validateaddress "$2" 2>/dev/null | json "j.get('ismine')" | grep -q True; }
not_mine() { [ -n "$2" ] && $1 validateaddress "$2" 2>/dev/null | json "j.get('ismine')" | grep -q False; }
check "Divi Core given irondivid's words and passphrase owns irondivid's first address" is_mine e "$P_ADDR"
check "Divi Core given the words without the passphrase does not" not_mine f "$P_ADDR"

# The words and the passphrase as grep patterns, read from a 0600 file so they
# are never on a command line
(umask 077; { cat "$W/words"; echo; cat "$W/pass"; echo; } > "$W/secrets")
secret_in_logs() { # the words or the passphrase in any log of <dirs...>
    [ -s "$W/words" ] && [ -s "$W/pass" ] || return 0
    find "$@" -type f \( -name 'debug.log*' -o -name 'db.log' -o -name '*.out' \) -print0 |
        xargs -0 -r grep -qF -f "$W/secrets"
}
# Logs are debug.log (and its rotations), Divi Core's db.log and each node's
# captured output. Database files (the wallet's own records) are not logs.
# Which log files hold which secret: names only, never the matching lines
where_secrets() {
    local f found=
    while IFS= read -r -d '' f; do
        grep -qxF -f <(cat "$W/words"; echo) <(grep -oF -f <(cat "$W/words"; echo) "$f") 2>/dev/null &&
            found="$found ${f#$W/}:words"
        grep -qF -f <(cat "$W/pass"; echo) "$f" 2>/dev/null && found="$found ${f#$W/}:passphrase"
    done < <(find "$@" -type f \( -name 'debug.log*' -o -name 'db.log' -o -name '*.out' \) -print0)
    echo "${found:- none}"
}
for side in irondivid "Divi Core"; do
    if [ "$side" = irondivid ]; then dirs=("$W"/p "$W"/p.out "$W"/x "$W"/y); else dirs=("$E" "$F"); fi
    if secret_in_logs "${dirs[@]}"; then
        fail "neither the words nor the passphrase appear in $side's logs (found in:$(where_secrets "${dirs[@]}"))"
    else
        pass "neither the words nor the passphrase appear in $side's logs"
    fi
done

# addnode onetry: dialled at once, by address and port, and not kept
outbound_to_e() { outbound_to y "$E_P2P"; }
y addnode "127.0.0.1:$E_P2P" onetry >/dev/null 2>&1
check "irondivid: addnode onetry dials at once (within ${WAIT}s)" within $WAIT outbound_to_e
not_added() { y getaddednodeinfo true 2>/dev/null | json "all(not n.get('addednode', '').endswith(':$E_P2P') for n in j)" | grep -q True; }
check "irondivid: an onetry node is not listed by getaddednodeinfo" not_added

# ---------------------------------------------------------------- Divi Core's files

b stop >/dev/null 2>&1
b_gone() { ! pgrep -f -- "-datadir=$B" >/dev/null; }
within 60 b_gone
HASH=$(tree_hash "$B")
for dir in "$B/regtest" "$B"; do
    OUT=$(timeout 30 "$IRD" -datadir="$dir" -port=$Z_P2P -rpcport=$Z_RPC 2>&1)
    RC=$?
    if [ $RC -ne 0 ] && [ $RC -ne 124 ] && echo "$OUT" | grep -q "is a Divi Core data directory"; then
        pass "Divi Core datadir ${dir#$W/} refused"
    else
        fail "Divi Core datadir ${dir#$W/} refused (exit $RC: $(echo "$OUT" | head -c 160))"
    fi
done
tree_is() { [ "$(tree_hash "$1")" = "$2" ]; }
check "Divi Core datadir left exactly as it was" tree_is "$B" "$HASH"

Z=$W/z
conf "$Z" "port=$Z_P2P" "rpcport=$Z_RPC" "bind=127.0.0.1" "connect=127.0.0.1:$A_P2P" "staking=0"
cp "$B/regtest/wallet.dat" "$Z/wallet.dat"
WSUM=$(sha256sum < "$Z/wallet.dat")
OUT=$(timeout 30 "$IRD" -datadir="$Z" -wallet=wallet.dat 2>&1)
RC=$?
if [ $RC -ne 0 ] && [ $RC -ne 124 ] && echo "$OUT" | grep -q "is a Divi Core wallet file"; then
    pass "-wallet=wallet.dat at Divi Core's wallet file: plain refusal"
else
    fail "-wallet=wallet.dat at Divi Core's wallet file: plain refusal (exit $RC: $(echo "$OUT" | head -c 160))"
fi
setsid "$IRD" -datadir="$Z" >>"$W/z.out" 2>&1 &
PIDS+=("$!")
within 60 "$ICLI" -datadir="$Z" -conf="$Z/divi.conf" getblockcount
"$ICLI" -datadir="$Z" -conf="$Z/divi.conf" stop >/dev/null 2>&1
z_gone() { ! pgrep -f -- "$IRD -datadir=$Z" >/dev/null; }
within 60 z_gone
check "wallet.dat in the datadir is named in a warning" grep -q "wallet.dat is a Divi Core wallet file" "$Z/debug.log"
wallet_dat_same() { [ "$(sha256sum < "$Z/wallet.dat")" = "$WSUM" ]; }
check "wallet.dat left unchanged" wallet_dat_same

# ---------------------------------------------------------------- end

echo "# $FAILS FAIL(s)"
exit $FAILS
