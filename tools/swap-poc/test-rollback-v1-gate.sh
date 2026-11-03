#!/usr/bin/env bash
# Guard for "no rollback below aa0d50b while any V1 swap is not terminal": every swap the maker
# creates since aa0d50b is V1, so a non-terminal swap in /swaps IS a non-terminal V1 swap, and
# rollback-maker.sh (a real run, not --dry-run) must refuse before it touches the host. Covers every
# non-terminal SwapState (crates/divi-swap/src/state.rs), and names the bypasses: --force-inflight
# alone lets the gate through (even with the maker down or an old installed binary); nothing else in
# rollback-maker.sh skips it. ssh is a stub that logs argv and returns a clean XMR read, so the only
# thing that can refuse is the /swaps half. No host, build or dnsdivi needed.
#
#   tools/swap-poc/test-rollback-v1-gate.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK="$HERE/rollback-maker.sh"
for t in curl jq python3; do command -v "$t" >/dev/null || { echo "test-rollback-v1-gate: needs $t" >&2; exit 1; }; done

FAILS=0
pass() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

tmp="$(mktemp -d)"
server_pid=""
# shellcheck disable=SC2329  # invoked by the EXIT trap below
cleanup() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp/bin"
cat >"$tmp/bin/ssh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_SSH_LOG"
[[ -z "${FAKE_SSH_OUT:-}" ]] || printf '%b' "$FAKE_SSH_OUT"
exit "${FAKE_SSH_RC:-0}"
STUB
chmod +x "$tmp/bin/ssh"
export FAKE_SSH_LOG="$tmp/ssh.log"
: >"$FAKE_SSH_LOG"
export PATH="$tmp/bin:$PATH"
export FAKE_SSH_OUT='xmr_configured yes\nin_flight 0\n' FAKE_SSH_RC=0
export OPTOK=op-token-for-test-0123456789
printf '%s\n' "$OPTOK" >"$tmp/op.token"
export OPERATOR_TOKEN_FILE="$tmp/op.token"
NOHOST=nohost.invalid
PORT=18601

start_mock() { # start_mock <swaps-json>
  python3 - "$PORT" "$1" <<'PY' &
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

body = sys.argv[2].encode()
OPTOK = os.environ["OPTOK"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/ready":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # GET /swaps is operator-only: without the right X-Operator-Token it is a 404, never "no swaps"
        ok = self.path == "/swaps" and self.headers.get("X-Operator-Token") == OPTOK
        data = body if ok else b"nope"
        self.send_response(200 if ok else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
  server_pid=$!
  for _ in $(seq 1 50); do
    curl -fsS -m 2 "http://127.0.0.1:$PORT/ready" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "test-rollback-v1-gate: mock server never came up" >&2
  return 1
}
stop_mock() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  server_pid=""
}

rollback() { # rollback <args...>: real run against the mock maker; output in $out, status returned
  : >"$FAKE_SSH_LOG"
  out="$("$ROLLBACK" --maker-url "http://127.0.0.1:$PORT" --host "$NOHOST" "$@" 2>&1)"
}

# 1. every non-terminal maker state, alone in /swaps (a V1 swap is any swap made since aa0d50b):
#    rollback refuses, changes nothing, and the host sees no restore/restart.
for st in Quoted Accepted TakerLockSeen TakerLockConfirmed MakerLocked MakerLockConfirmed \
  TakerClaimed MakerClaimed MakerRefundable MakerRefunded; do
  start_mock "[{\"id\":\"v1-$st\",\"state\":\"$st\"},{\"id\":\"old\",\"state\":\"Done\"}]" || exit 1
  rollback
  rc=$?
  stop_mock
  if ((rc != 0)) && grep -q "v1-$st" <<<"$out" && grep -q "nothing was changed" <<<"$out" \
    && ! grep -Eq "systemctl|cp -p|install " "$FAKE_SSH_LOG"; then
    pass "rollback refuses with a swap in $st"
  else fail "rollback with $st: rc=$rc ssh=$(cat "$FAKE_SSH_LOG"): $out"; fi
done

# 2. only terminal swaps -> the gate passes (so the refusals above are the gate, not something else)
start_mock '[{"id":"a","state":"Done"},{"id":"b","state":"Aborted"}]' || exit 1
out="$("$ROLLBACK" --dry-run --maker-url "http://127.0.0.1:$PORT" --host "$NOHOST" 2>&1)"
rc=$?
stop_mock
if ((rc == 0)) && grep -q "systemctl restart divi-swapd" <<<"$out"; then pass "all-terminal swaps: rollback plan is produced"
else fail "all-terminal swaps: rc=$rc: $out"; fi

# 3. --dry-run never runs the gate (it only prints it) and never touches a host: not a way to
#    roll back, only a way to read the plan.
start_mock '[{"id":"v1-live","state":"MakerLockConfirmed"}]' || exit 1
: >"$FAKE_SSH_LOG"
out="$("$ROLLBACK" --dry-run --maker-url "http://127.0.0.1:$PORT" --host "$NOHOST" 2>&1)"
rc=$?
if ((rc == 0)) && [[ ! -s "$FAKE_SSH_LOG" ]] && grep -q "only printed, not run" <<<"$out"; then
  pass "--dry-run: prints the plan, runs no ssh (does not execute a rollback)"
else fail "--dry-run: rc=$rc ssh=$(cat "$FAKE_SSH_LOG"): $out"; fi

# 4. BYPASS --force-inflight: the one flag that skips the gate. It lists the id, warns, and the
#    restore script then reaches the host.
rollback --force-inflight
rc=$?
stop_mock
if grep -q "v1-live" <<<"$out" && grep -q "proceeding anyway (--force-inflight)" <<<"$out" \
  && grep -q "sudo bash -s" "$FAKE_SSH_LOG"; then
  pass "BYPASS --force-inflight: lists v1-live, warns, restore reaches the host"
else fail "--force-inflight: rc=$rc ssh=$(cat "$FAKE_SSH_LOG"): $out"; fi

# 5. maker down: refuses (cannot confirm there is no V1 swap) ...
rollback
rc=$?
if ((rc != 0)) && ! grep -q "sudo bash -s" "$FAKE_SSH_LOG"; then pass "maker down: rollback refuses, host untouched"
else fail "maker down: rc=$rc: $out"; fi
# ... and --force-inflight is again the only way past it.
rollback --force-inflight
if grep -q "sudo bash -s" "$FAKE_SSH_LOG"; then pass "BYPASS maker down + --force-inflight: restore reaches the host"
else fail "maker down + force: ssh=$(cat "$FAKE_SSH_LOG"): $out"; fi

# 6. installed binary too old for --xmr-inflight: refuses even with an all-terminal /swaps
start_mock '[{"id":"a","state":"Done"}]' || exit 1
out="$(FAKE_SSH_RC=2 FAKE_SSH_OUT='error: unexpected argument --xmr-inflight\n' \
  "$ROLLBACK" --maker-url "http://127.0.0.1:$PORT" --host "$NOHOST" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)); then pass "old binary without --xmr-inflight: rollback refuses"; else fail "old binary: rc=$rc: $out"; fi

# 6b. no operator token: /swaps cannot be read, so rollback refuses (never "no swaps") and the host
#     is untouched
start_mock '[{"id":"a","state":"Done"}]' || exit 1
OPERATOR_TOKEN_FILE="" rollback
rc=$?
stop_mock
if ((rc != 0)) && grep -q "no operator token" <<<"$out" && ! grep -q "sudo bash -s" "$FAKE_SSH_LOG"; then
  pass "no operator token: rollback refuses, host untouched"
else fail "no operator token: rc=$rc ssh=$(cat "$FAKE_SSH_LOG"): $out"; fi

# 7. rollback-maker.sh has exactly one flag that skips the gate
n="$(grep -c -e '--force-inflight' "$ROLLBACK")"
skips="$(grep -Eo -e '--(force|skip|no|yes)[a-z-]*' "$ROLLBACK" | sort -u | tr '\n' ' ')"
if [[ "$skips" == "--force-inflight " ]]; then pass "only bypass flag in rollback-maker.sh: --force-inflight ($n mentions)"
else fail "unexpected gate-skipping flags in rollback-maker.sh: $skips"; fi

if ((FAILS == 0)); then echo "PASS: test-rollback-v1-gate"; exit 0; fi
echo "$FAILS check(s) failing"
exit 1
