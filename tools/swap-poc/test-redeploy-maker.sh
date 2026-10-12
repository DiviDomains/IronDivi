#!/usr/bin/env bash
# Bash-level tests for redeploy-maker.sh's in-flight gate, against a real mock HTTP server
# (stdlib python, matching tools/swap-poc/chaos/proxy.py's style) — no ssh, no build, no
# dnsdivi needed. Not wired into check-ltc.sh: lane rules forbid editing check scripts: run
# by hand, or have the orchestrator run it from the Mac alongside redeploy-maker.sh itself.
#
#   tools/swap-poc/test-redeploy-maker.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$HERE/redeploy-maker.sh"

for t in curl python3; do command -v "$t" >/dev/null || { echo "test-redeploy-maker: needs $t" >&2; exit 1; }; done

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

# start_mock <body> <port> [status]: serves <body> (a JSON string) for any GET on /swaps.
start_mock() {
  local body="$1" port="$2" status="${3:-200}"
  python3 - "$port" "$status" "$body" <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
status = int(sys.argv[2])
body = sys.argv[3].encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
  server_pid=$!
  for _ in $(seq 1 50); do
    curl -fsS -m 2 "http://127.0.0.1:$port/swaps" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "test-redeploy-maker: mock server on $port never came up" >&2
  return 1
}

stop_mock() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  server_pid=""
}

PORT=18599

# 1. every swap terminal -> gate passes (--check-only exits 0, prints no in-flight ids)
start_mock '[{"id":"a","state":"Done"},{"id":"b","state":"Aborted"}]' "$PORT" || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc == 0)); then pass "all-terminal swaps: gate exits 0"; else fail "all-terminal swaps: gate exited $rc: $out"; fi
if ! grep -q "in-flight swap(s) found" <<<"$out"; then pass "all-terminal swaps: no in-flight ids printed"
else fail "all-terminal swaps: unexpectedly reported in-flight ids: $out"; fi

# 2. one non-terminal swap -> gate refuses and prints its id, without --force-inflight
start_mock '[{"id":"done-1","state":"Done"},{"id":"flight-1","state":"TakerLockSeen"}]' "$PORT" || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)); then pass "one in-flight swap: gate refuses (exit $rc)"; else fail "one in-flight swap: gate did not refuse: $out"; fi
if grep -q "flight-1" <<<"$out"; then pass "one in-flight swap: id flight-1 printed"
else fail "one in-flight swap: id not printed: $out"; fi

# 3. same list, with --force-inflight -> proceeds (exit 0) but still prints the id
start_mock '[{"id":"flight-2","state":"MakerLocked"}]' "$PORT" || exit 1
out="$("$TARGET" --check-only --force-inflight --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc == 0)); then pass "--force-inflight: gate proceeds (exit 0)"; else fail "--force-inflight: gate still refused: $out"; fi
if grep -q "flight-2" <<<"$out"; then pass "--force-inflight: id flight-2 still printed"
else fail "--force-inflight: id not printed: $out"; fi

# 4. multiple non-terminal swaps -> every id printed, not just the first
start_mock '[{"id":"flight-3","state":"TakerLockSeen"},{"id":"flight-4","state":"TakerLockConfirmed"},{"id":"done-2","state":"Done"}]' "$PORT" || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)); then pass "multiple in-flight: gate refuses"; else fail "multiple in-flight: gate did not refuse: $out"; fi
if grep -q "flight-3" <<<"$out" && grep -q "flight-4" <<<"$out"; then pass "multiple in-flight: both ids printed"
else fail "multiple in-flight: missing an id: $out"; fi

# 5. maker unreachable (nothing listening) -> refuses by default
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
if ((rc != 0)); then pass "unreachable maker: gate refuses"; else fail "unreachable maker: gate did not refuse: $out"; fi

# 6. maker unreachable + --force-inflight -> proceeds anyway, with a warning
out="$("$TARGET" --check-only --force-inflight --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
if ((rc == 0)); then pass "unreachable maker + --force-inflight: proceeds"; else fail "unreachable maker + --force-inflight: still refused: $out"; fi

# 7. empty swap list -> gate passes
start_mock '[]' "$PORT" || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc == 0)); then pass "empty swap list: gate exits 0"; else fail "empty swap list: gate exited $rc: $out"; fi

# 8. --check-only never builds or installs: with no remote-cargo and an unresolvable host,
#    a passing gate still exits 0 immediately (no later step runs).
start_mock '[{"id":"done-3","state":"Done"}]' "$PORT" || exit 1
out="$(PATH=/usr/bin:/bin "$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" --host no-such-host-xyz 2>&1)"
rc=$?
stop_mock
if ((rc == 0)); then pass "--check-only: stops after the gate, never touches --host"
else fail "--check-only: unexpectedly tried to go further: $out"; fi

if ((FAILS == 0)); then echo "PASS: test-redeploy-maker"; exit 0; fi
echo "$FAILS check(s) failing"
exit 1
