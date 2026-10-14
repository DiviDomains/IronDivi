#!/usr/bin/env bash
# Bash-level tests for redeploy-maker.sh's in-flight gate (/swaps and /xmr/swaps) and for
# the --dry-run plans of redeploy-maker.sh and rollback-maker.sh, against a real mock HTTP server
# (stdlib python, matching tools/swap-poc/chaos/proxy.py's style) — no ssh, no build, no
# dnsdivi needed. Not wired into check-ltc.sh: lane rules forbid editing check scripts: run
# by hand, or have the orchestrator run it from the Mac alongside redeploy-maker.sh itself.
#
#   tools/swap-poc/test-redeploy-maker.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$HERE/redeploy-maker.sh"
ROLLBACK="$HERE/rollback-maker.sh"

for t in curl jq python3; do command -v "$t" >/dev/null || { echo "test-redeploy-maker: needs $t" >&2; exit 1; }; done

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

# start_mock <body> <port> [status] [xmr_body] [xmr_status]: serves <body> (a JSON string)
# with <status> for GET /swaps, and <xmr_body>/<xmr_status> for GET /xmr/swaps (default: 404,
# a maker with no XMR engine, so the /swaps-only cases keep their meaning).
start_mock() {
  local body="$1" port="$2" status="${3:-200}" xmr_body="${4:-not found}" xmr_status="${5:-404}"
  python3 - "$port" "$status" "$body" "$xmr_status" "$xmr_body" <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
routes = {
    "/swaps": (int(sys.argv[2]), sys.argv[3].encode()),
    "/xmr/swaps": (int(sys.argv[4]), sys.argv[5].encode()),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        status, body = routes.get(self.path, (404, b"not found"))
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

# --- /xmr/swaps (B1b) ---------------------------------------------------------------------
TERMINAL='[{"id":"done-x","state":"Done"}]'

# 9. a non-terminal XMR swap -> refuses and prints its id, though /swaps is all terminal
start_mock "$TERMINAL" "$PORT" 200 '[{"id":"xmr-done","state":"done"},{"id":"xmr-flight-1","state":"xmr_reported"}]' 200 || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)); then pass "xmr in-flight: gate refuses (exit $rc)"; else fail "xmr in-flight: gate did not refuse: $out"; fi
if grep -q "xmr-flight-1" <<<"$out"; then pass "xmr in-flight: id xmr-flight-1 printed"
else fail "xmr in-flight: id not printed: $out"; fi
if ! grep -q "xmr-done" <<<"$out"; then pass "xmr in-flight: terminal xmr id not listed"
else fail "xmr in-flight: terminal id listed: $out"; fi

# 10. every XMR swap done/aborted/punished -> passes
start_mock "$TERMINAL" "$PORT" 200 '[{"id":"x1","state":"done"},{"id":"x2","state":"aborted"},{"id":"x3","state":"punished"}]' 200 || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc == 0)); then pass "xmr all terminal: gate exits 0"; else fail "xmr all terminal: gate exited $rc: $out"; fi

# 11. refunded is not terminal (XmrMakerState::is_terminal) -> refuses
start_mock "$TERMINAL" "$PORT" 200 '[{"id":"xmr-refunded","state":"refunded"}]' 200 || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)) && grep -q "xmr-refunded" <<<"$out"; then pass "xmr refunded: gate refuses and names it"
else fail "xmr refunded: rc=$rc: $out"; fi

# 12. /xmr/swaps 404 (no XMR engine) -> passes, and says why
start_mock "$TERMINAL" "$PORT" || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc == 0)) && grep -q "no XMR engine" <<<"$out"; then pass "xmr 404: gate passes with a note"
else fail "xmr 404: rc=$rc: $out"; fi

# 13. /xmr/swaps 500 -> refuses (cannot confirm), unless --force-inflight
start_mock "$TERMINAL" "$PORT" 200 'boom' 500 || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
out_forced="$("$TARGET" --check-only --force-inflight --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc_forced=$?
stop_mock
if ((rc != 0)) && grep -q "HTTP 500" <<<"$out"; then pass "xmr 500: gate refuses"
else fail "xmr 500: rc=$rc: $out"; fi
if ((rc_forced == 0)); then pass "xmr 500 + --force-inflight: proceeds"
else fail "xmr 500 + --force-inflight: still refused: $out_forced"; fi

# 14. /xmr/swaps 200 but not a list -> refuses rather than reading it as "no swaps"
start_mock "$TERMINAL" "$PORT" 200 '{"error":"nope"}' 200 || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)); then pass "xmr non-list body: gate refuses"; else fail "xmr non-list body: gate passed: $out"; fi

# 15. --force-inflight with an in-flight XMR swap -> proceeds, still lists it
start_mock "$TERMINAL" "$PORT" 200 '[{"id":"xmr-flight-2","state":"locked"}]' 200 || exit 1
out="$("$TARGET" --check-only --force-inflight --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc == 0)) && grep -q "xmr-flight-2" <<<"$out"; then pass "xmr --force-inflight: proceeds and lists the id"
else fail "xmr --force-inflight: rc=$rc: $out"; fi

# 16. in-flight on both lists -> both ids printed, labelled by list
start_mock '[{"id":"htlc-1","state":"MakerLocked"}]' "$PORT" 200 '[{"id":"xmr-3","state":"redeem_offered"}]' 200 || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)) && grep -q "/swaps .*htlc-1" <<<"$out" && grep -q "/xmr/swaps .*xmr-3" <<<"$out"; then
  pass "both lists in flight: both ids, labelled"
else fail "both lists in flight: rc=$rc: $out"; fi

# --- dry-run plans (B1): no ssh is run, so an unresolvable host is fine ------------------
NOHOST=no-such-host-xyz
# 17. redeploy --dry-run snapshots all three before installing; its rollback restores all three
out="$(PATH=/usr/bin:/bin "$TARGET" --dry-run --binary /nonexistent/divi-swapd --host "$NOHOST" 2>&1)"
rc=$?
if ((rc == 0)); then pass "redeploy --dry-run: exits 0 without ssh"; else fail "redeploy --dry-run: exit $rc: $out"; fi
snap_line="$(grep -n 'cp -p /etc/divi-swapd/divi-swapd.toml /var/backups/divi-swapd/' <<<"$out" | head -1 | cut -d: -f1)"
install_line="$(grep -n 'install -m 0755 /tmp/divi-swapd.redeploy-new /usr/local/bin/divi-swapd' <<<"$out" | head -1 | cut -d: -f1)"
if [[ -n "$snap_line" && -n "$install_line" ]] && ((snap_line < install_line)); then
  pass "redeploy --dry-run: snapshot comes before install"
else fail "redeploy --dry-run: snapshot/install order wrong or missing: $out"; fi
for want in "cp -p /usr/local/bin/divi-swapd /var/backups/divi-swapd/" \
  "cp -p /etc/systemd/system/divi-swapd.service /var/backups/divi-swapd/" \
  "/var/backups/divi-swapd/prev" "SHA256SUMS" \
  "mv -f /etc/divi-swapd/divi-swapd.toml.rollback /etc/divi-swapd/divi-swapd.toml" \
  "mv -f /etc/systemd/system/divi-swapd.service.rollback /etc/systemd/system/divi-swapd.service" \
  "systemctl daemon-reload"; do
  if grep -qF "$want" <<<"$out"; then pass "redeploy --dry-run: has '$want'"
  else fail "redeploy --dry-run: missing '$want': $out"; fi
done

# 18. rollback --dry-run restores all three, reloads, restarts, health-checks; no ssh
out="$(PATH=/usr/bin:/bin "$ROLLBACK" --dry-run --host "$NOHOST" 2>&1)"
rc=$?
if ((rc == 0)); then pass "rollback --dry-run: exits 0 without ssh"; else fail "rollback --dry-run: exit $rc: $out"; fi
for want in "cp -p /var/backups/divi-swapd/prev/divi-swapd /usr/local/bin/divi-swapd.rollback" \
  "cp -p /var/backups/divi-swapd/prev/divi-swapd.toml /etc/divi-swapd/divi-swapd.toml.rollback" \
  "cp -p /var/backups/divi-swapd/prev/divi-swapd.service /etc/systemd/system/divi-swapd.service.rollback" \
  "sha256sum -c --quiet SHA256SUMS" "systemctl daemon-reload" "systemctl restart divi-swapd" \
  "/healthz" "checking for in-flight swaps"; do
  if grep -qF "$want" <<<"$out"; then pass "rollback --dry-run: has '$want'"
  else fail "rollback --dry-run: missing '$want': $out"; fi
done

# 19. rollback --to an older snapshot, and a rejected --to
out="$("$ROLLBACK" --dry-run --host "$NOHOST" --to 20261014T120000Z 2>&1)"
rc=$?
if ((rc == 0)) && grep -qF "/var/backups/divi-swapd/20261014T120000Z/divi-swapd.toml" <<<"$out"; then
  pass "rollback --to TIMESTAMP: restores from that snapshot"
else fail "rollback --to TIMESTAMP: rc=$rc: $out"; fi
out="$("$ROLLBACK" --dry-run --host "$NOHOST" --to '../etc; rm -rf /' 2>&1)"
rc=$?
if ((rc != 0)) && ! grep -q "ssh" <<<"$out"; then pass "rollback --to junk: rejected before any command"
else fail "rollback --to junk: rc=$rc: $out"; fi

# 20. rollback's gate is the real one: an in-flight XMR swap refuses it before any restore
start_mock "$TERMINAL" "$PORT" 200 '[{"id":"xmr-flight-4","state":"swept"}]' 200 || exit 1
out="$(PATH=/usr/bin:/bin "$ROLLBACK" --maker-url "http://127.0.0.1:$PORT" --host "$NOHOST" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)) && grep -q "xmr-flight-4" <<<"$out" && ! grep -q "==> restore" <<<"$out"; then
  pass "rollback gate: refuses on an in-flight XMR swap before restoring"
else fail "rollback gate: rc=$rc: $out"; fi

if ((FAILS == 0)); then echo "PASS: test-redeploy-maker"; exit 0; fi
echo "$FAILS check(s) failing"
exit 1
