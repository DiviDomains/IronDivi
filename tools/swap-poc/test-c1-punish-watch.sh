#!/usr/bin/env bash
# Bash-level tests for c1-punish-watch.sh: it polls the private hp2 maker through
# `divi-swapd --xmr-inflight --xmr-lock-txids` over ssh and stalls (kills) the maker once an
# XMR lock is recorded. ssh is a stub on PATH that serves canned poll outputs in sequence and logs
# its argv, so no host, maker, build or dnsdivi is needed. Not wired into check-ltc.sh (lane rules
# forbid editing check scripts): run by hand, or have the orchestrator run it with the others.
#
#   tools/swap-poc/test-c1-punish-watch.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$HERE/c1-punish-watch.sh"

FAILS=0
pass() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# ssh stub. A call carrying --xmr-inflight pops the next file of $FAKE_DIR (01, 02, ...; the last
# one repeats) and prints it; its exit status is the file's `.rc` sibling if present. A call with
# `kill` is the stall. Every argv is logged.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/ssh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_SSH_LOG"
case "$*" in
  *--xmr-inflight*)
    n=$(($(cat "$FAKE_DIR/.n" 2>/dev/null || echo 0) + 1))
    f="$FAKE_DIR/$(printf %02d "$n")"
    [[ -f "$f" ]] || { n=$((n - 1)); f="$FAKE_DIR/$(printf %02d "$n")"; }
    echo "$n" >"$FAKE_DIR/.n"
    cat "$f"
    exit "$(cat "$f.rc" 2>/dev/null || echo 0)" ;;
  *kill*) echo maker-stopped ;;
esac
STUB
chmod +x "$tmp/bin/ssh"
export PATH="$tmp/bin:$PATH"
export FAKE_SSH_LOG="$tmp/ssh.log"

# case <name>: fresh poll dir and logs; then `poll <text>` adds the next canned output.
case_new() {
  export FAKE_DIR="$tmp/$1"
  rm -rf "$FAKE_DIR" "$tmp/out-$1"
  mkdir -p "$FAKE_DIR" "$tmp/out-$1"
  : >"$FAKE_SSH_LOG"
  NEXT=1
}
poll() { printf '%b' "$1" >"$FAKE_DIR/$(printf %02d "$NEXT")"; NEXT=$((NEXT + 1)); }
polls() { grep -c -e '--xmr-inflight' "$FAKE_SSH_LOG" || true; }
kills() { grep -c 'kill' "$FAKE_SSH_LOG" || true; }
# run <name> [timeout-secs]: runs the script quietly; sets RC. The default is a hang guard only (runs that should finish exit at once; 3s flaked on a loaded Mac, load avg 70).
run() {
  POLL_SECS=0.05 FAIL_LIMIT=3 timeout "${2:-30}" "$TARGET" "$tmp/out-$1" >"$tmp/stdout" 2>"$tmp/stderr"
  RC=$?
}

HDR='xmr_configured yes\n'
TX=3f0c5e7a9b1d44e2a6c8d0f2b4a6c8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1

# 1. Fires on a recorded lock; earlier polls with only accepted/locked-without-txid do not.
case_new fire
poll "${HDR}in_flight 1\nm1 accepted -\n"
poll "${HDR}in_flight 1\nm1 locked -\n"
poll "${HDR}in_flight 1\nm1 xmr_reported $TX\n"
run fire
[[ $RC -eq 0 ]] && pass "stalls and exits 0 once the lock is recorded" || fail "fire: exit $RC"
[[ "$(kills)" == 1 ]] && pass "kills the maker exactly once" || fail "fire: kills=$(kills)"
[[ "$(polls)" == 3 ]] && pass "did not stall on the accepted/locked polls before it (3 polls)" || fail "fire: polls=$(polls)"
grep -q "stalled maker at: xmr_reported $TX" "$tmp/out-fire/stall.log" 2>/dev/null &&
  pass "stall.log records the state and the lock txid" || fail "fire: stall.log"

# 2. Never fires on accepted/locked without a txid, however long it watches.
case_new quiet
poll "${HDR}in_flight 1\nm1 accepted -\n"
poll "${HDR}in_flight 1\nm1 locked -\n"
run quiet 1
[[ $RC -eq 124 ]] && pass "accepted/locked without a txid: keeps watching (timeout)" || fail "quiet: exit $RC"
[[ "$(kills)" == 0 ]] && pass "accepted/locked without a txid: never kills" || fail "quiet: kills=$(kills)"
[[ ! -e "$tmp/out-quiet/stall.log" ]] && pass "no stall.log written" || fail "quiet: stall.log exists"

# 3. An empty store (no in-flight swap) never fires.
case_new empty
poll "${HDR}in_flight 0\n"
run empty 1
[[ $RC -eq 124 && "$(kills)" == 0 ]] && pass "no in-flight swap: never kills" || fail "empty: exit $RC kills=$(kills)"

# 4. SKIP_IDS: an earlier run's swap with a lock is ignored...
case_new skip
poll "${HDR}in_flight 2\nold xmr_reported $TX\nm2 accepted -\n"
SKIP_IDS="old other" run skip 1
[[ $RC -eq 124 && "$(kills)" == 0 ]] && pass "SKIP_IDS: a skipped swap's lock never fires" || fail "skip: exit $RC kills=$(kills)"
# ...and the same output without the skip fires on it.
case_new noskip
poll "${HDR}in_flight 2\nold xmr_reported $TX\nm2 accepted -\n"
run noskip
[[ $RC -eq 0 && "$(kills)" == 1 ]] && pass "same output without SKIP_IDS fires" || fail "noskip: exit $RC kills=$(kills)"
# ...and the swap after the skipped one is the one that counts.
case_new skip2
poll "${HDR}in_flight 2\nold done_x $TX\nm2 xmr_reported $TX\n"
SKIP_IDS="old" run skip2
grep -q "stalled maker at: xmr_reported" "$tmp/out-skip2/stall.log" 2>/dev/null &&
  pass "SKIP_IDS: the first non-skipped swap decides" || fail "skip2: $(cat "$tmp/out-skip2/stall.log" 2>&1)"

# 5. Anything past locked fires even with no txid (cancelled, redeem_offered, ...).
case_new late
poll "${HDR}in_flight 1\nm1 cancelled -\n"
run late
[[ $RC -eq 0 && "$(kills)" == 1 ]] && pass "a state past locked fires" || fail "late: exit $RC kills=$(kills)"

# 6. An unreadable poll is loud and never fires: old binary (usage, exit 2), a count that does not
#    match the swap lines, a wrong field count, and a header that is not ours.
for bad in 'old|error: unexpected argument --xmr-lock-txids\n|2' \
  "count|${HDR}in_flight 2\nm1 xmr_reported $TX\n|0" \
  "plain|${HDR}in_flight 1\nm1 xmr_reported\n|0" \
  'foreign|<html>502</html>\n|0'; do
  IFS='|' read -r name text rc <<<"$bad"
  case_new "bad-$name"
  poll "$text"
  printf '%s' "$rc" >"$FAKE_DIR/01.rc"
  run "bad-$name"
  [[ $RC -eq 1 && "$(kills)" == 0 ]] && pass "unreadable poll ($name): exits 1 after FAIL_LIMIT, never kills" ||
    fail "bad-$name: exit $RC kills=$(kills)"
  [[ "$(polls)" == 3 ]] || fail "bad-$name: polls=$(polls), want FAIL_LIMIT=3"
  grep -q 'could not read the hp2 maker' "$tmp/stderr" && grep -q 'never stalled' "$tmp/stderr" ||
    fail "bad-$name: not loud on stderr"
done

# 7. A transient failure does not end the watch.
case_new flaky
poll 'ssh: connect timed out\n'
printf 255 >"$FAKE_DIR/01.rc"
poll "${HDR}in_flight 1\nm1 xmr_reported $TX\n"
run flaky
[[ $RC -eq 0 && "$(kills)" == 1 ]] && pass "one failed poll, then a lock: still stalls" || fail "flaky: exit $RC kills=$(kills)"

# 8. The poll is the supported read, over ssh to hp2 only: no HTTP listing, no other host.
case_new argv
poll "${HDR}in_flight 1\nm1 xmr_reported $TX\n"
run argv
grep -q -e 'hp2 .*--xmr-inflight --xmr-lock-txids' "$FAKE_SSH_LOG" && pass "polls with --xmr-inflight --xmr-lock-txids on hp2" || fail "argv: $(cat "$FAKE_SSH_LOG")"
if ! grep -v '^[[:space:]]*#' "$TARGET" | grep -q -e 'curl' -e 'xmr/swaps'; then pass "no curl and no /xmr/swaps outside comments"; else fail "script still calls curl or /xmr/swaps"; fi
if ! grep -q 'dnsdivi' "$FAKE_SSH_LOG" && ! grep -v '^[[:space:]]*#' "$TARGET" | grep -q 'dnsdivi'; then pass "never mentions or contacts dnsdivi"; else fail "dnsdivi referenced"; fi
if ! grep -v -e '^hp2 ' -e '^-o BatchMode=yes hp2 ' "$FAKE_SSH_LOG" | grep -q .; then pass "every ssh goes to hp2"; else fail "ssh to another host: $(cat "$FAKE_SSH_LOG")"; fi

echo
if ((FAILS)); then echo "test-c1-punish-watch: $FAILS FAILED"; exit 1; fi
echo "test-c1-punish-watch: all passed"
