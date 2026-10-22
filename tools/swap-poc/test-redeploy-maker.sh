#!/usr/bin/env bash
# Bash-level tests for redeploy-maker.sh's in-flight gate (/swaps over HTTP, XMR swaps via
# `divi-swapd --xmr-inflight` over ssh) and for the --dry-run plans of redeploy-maker.sh and
# rollback-maker.sh. The HTTP side is a real mock server (stdlib python, matching
# tools/swap-poc/chaos/proxy.py's style); ssh is a stub on PATH that returns canned output and logs
# its argv, so no host, build or dnsdivi is needed. Not wired into check-ltc.sh: lane rules forbid
# editing check scripts: run by hand, or have the orchestrator run it alongside redeploy-maker.sh.
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

# ssh stub: logs argv to $FAKE_SSH_LOG, prints $FAKE_SSH_OUT (printf %b), exits $FAKE_SSH_RC.
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
ZERO='xmr_configured yes\nin_flight 0\n'
export FAKE_SSH_OUT="$ZERO" FAKE_SSH_RC=0

# start_mock <body> <port> [status]: serves <body> (a JSON string) with <status> for GET /swaps.
# There is deliberately no /xmr/swaps route: C3 removed it, and the gate must not ask for it.
start_mock() {
  local body="$1" port="$2" status="${3:-200}"
  python3 - "$port" "$status" "$body" <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
routes = {"/swaps": (int(sys.argv[2]), sys.argv[3].encode()), "/ready": (200, b"ok")}
import os
OPTOK = os.environ["OPTOK"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/swaps" and self.headers.get("X-Operator-Token") != OPTOK:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, body = routes.get(self.path, (405 if self.path.startswith("/xmr/") else 404, b"nope"))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
  server_pid=$!
  for _ in $(seq 1 50); do
    curl -fsS -m 2 "http://127.0.0.1:$port/ready" >/dev/null 2>&1 && return 0
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

# GET /swaps is operator-only (the mock 404s without X-Operator-Token): the gate is given the
# token through OPERATOR_TOKEN_FILE, and refuses (never "no swaps") when it has none or a wrong one.
export OPTOK=op-token-for-test-0123456789
printf '%s\n' "$OPTOK" >"$tmp/op.token"
export OPERATOR_TOKEN_FILE="$tmp/op.token"

PORT=18599

# 0. no / wrong operator token -> refuse with a reason that names the fix
start_mock '[]' "$PORT" || exit 1
out="$(OPERATOR_TOKEN_FILE="" "$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"; rc=$?
if ((rc != 0)) && grep -q "no operator token" <<<"$out"; then pass "no operator token: gate refuses and says why"
else fail "no operator token: rc=$rc out=$out"; fi
printf "zz-bad-9f3a\n" >"$tmp/wrong.token"
out="$("$TARGET" --check-only --operator-token-file "$tmp/wrong.token" --maker-url "http://127.0.0.1:$PORT" 2>&1)"; rc=$?
if ((rc != 0)) && grep -q "REFUSE" <<<"$out" && ! grep -q zz-bad-9f3a <<<"$out"; then pass "wrong operator token: gate refuses, token not echoed"
else fail "wrong operator token: rc=$rc out=$out"; fi
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" 2>&1)"; rc=$?
if ((rc == 0)); then pass "right operator token (env): gate reads the listing"; else fail "right token: rc=$rc out=$out"; fi
stop_mock

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

# 8. --check-only never builds or installs: its only ssh is the read-only --xmr-inflight read
: >"$FAKE_SSH_LOG"
start_mock '[{"id":"done-3","state":"Done"}]' "$PORT" || exit 1
out="$("$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" --host no-such-host-xyz 2>&1)"
rc=$?
stop_mock
nlog="$(wc -l <"$FAKE_SSH_LOG" | tr -d ' ')"
if ((rc == 0)) && [[ "$nlog" == 1 ]] && grep -q -e "--xmr-inflight" "$FAKE_SSH_LOG"; then
  pass "--check-only: stops after the gate; one ssh, the --xmr-inflight read"
else fail "--check-only: rc=$rc ssh calls=$nlog: $out"; fi
if grep -q "sudo -n -u divi-swapd /usr/local/bin/divi-swapd --config /etc/divi-swapd/divi-swapd.toml --xmr-inflight" "$FAKE_SSH_LOG"; then
  pass "--check-only: reads as the service user with the installed binary and config, never root"
else fail "--check-only: unexpected ssh argv: $(cat "$FAKE_SSH_LOG")"; fi

# --- XMR swaps via ssh `divi-swapd --xmr-inflight` ------------------------------------------
TERMINAL='[{"id":"done-x","state":"Done"}]'
check() { "$TARGET" --check-only --maker-url "http://127.0.0.1:$PORT" "$@" 2>&1; }

# 9. a non-terminal XMR swap -> refuses and prints its id, though /swaps is all terminal
start_mock "$TERMINAL" "$PORT" || exit 1
out="$(FAKE_SSH_OUT='xmr_configured yes\nin_flight 1\nxmr-flight-1 xmr_reported\n' check)"
rc=$?
stop_mock
if ((rc != 0)); then pass "xmr in-flight: gate refuses (exit $rc)"; else fail "xmr in-flight: gate did not refuse: $out"; fi
if grep -q "xmr .*xmr-flight-1 xmr_reported" <<<"$out"; then pass "xmr in-flight: id and state printed"
else fail "xmr in-flight: id not printed: $out"; fi

# 10. in_flight 0 on an XMR-enabled maker -> passes
start_mock "$TERMINAL" "$PORT" || exit 1
out="$(check)"
rc=$?
stop_mock
if ((rc == 0)) && grep -q "ok: no in-flight swaps" <<<"$out"; then pass "xmr none in flight: gate exits 0"
else fail "xmr none in flight: rc=$rc: $out"; fi

# 11. no XMR engine configured and nothing in the store -> passes, and says why
start_mock "$TERMINAL" "$PORT" || exit 1
out="$(FAKE_SSH_OUT='xmr_configured no\nin_flight 0\n' check)"
rc=$?
stop_mock
if ((rc == 0)) && grep -q "no XMR engine" <<<"$out"; then pass "xmr not configured: gate passes with a note"
else fail "xmr not configured: rc=$rc: $out"; fi

# 12. read failures all refuse (cannot confirm), unless --force-inflight
start_mock "$TERMINAL" "$PORT" || exit 1
for case in \
  "ssh fails:255:ssh: Could not resolve hostname" \
  "store missing:1:Error: no swap store at /var/lib/divi-swapd/swaps.db" \
  "old binary:2:error: unexpected argument '--xmr-inflight' found" \
  "empty output:0:" \
  "garbage output:0:hello\nworld\n" \
  "count mismatch:0:xmr_configured yes\nin_flight 2\nonly-one done_not\n" \
  "truncated:0:xmr_configured yes\n"; do
  name="${case%%:*}"; rest="${case#*:}"; crc="${rest%%:*}"; cout="${rest#*:}"
  out="$(FAKE_SSH_RC=$crc FAKE_SSH_OUT="$cout" check)"; rc=$?
  outf="$(FAKE_SSH_RC=$crc FAKE_SSH_OUT="$cout" check --force-inflight)"; rcf=$?
  if ((rc != 0)) && grep -q "REFUSE\|cannot read\|unreadable" <<<"$out"; then pass "xmr $name: gate refuses"
  else fail "xmr $name: rc=$rc: $out"; fi
  if ((rcf == 0)); then pass "xmr $name + --force-inflight: proceeds"; else fail "xmr $name + --force-inflight: rc=$rcf: $outf"; fi
done
stop_mock

# 13. an old installed binary gets a hint about the flag
start_mock "$TERMINAL" "$PORT" || exit 1
out="$(FAKE_SSH_RC=2 FAKE_SSH_OUT="error: unexpected argument '--xmr-inflight' found" check)"
stop_mock
if grep -q "too old" <<<"$out"; then pass "xmr old binary: says it is too old"; else fail "xmr old binary: no hint: $out"; fi

# 14. --force-inflight with an in-flight XMR swap -> proceeds, still lists it
start_mock "$TERMINAL" "$PORT" || exit 1
out="$(FAKE_SSH_OUT='xmr_configured yes\nin_flight 1\nxmr-flight-2 locked\n' check --force-inflight)"
rc=$?
stop_mock
if ((rc == 0)) && grep -q "xmr-flight-2" <<<"$out"; then pass "xmr --force-inflight: proceeds and lists the id"
else fail "xmr --force-inflight: rc=$rc: $out"; fi

# 15. in-flight on both lists -> both ids printed, labelled by source
start_mock '[{"id":"htlc-1","state":"MakerLocked"}]' "$PORT" || exit 1
out="$(FAKE_SSH_OUT='xmr_configured yes\nin_flight 1\nxmr-3 redeem_offered\n' check)"
rc=$?
stop_mock
if ((rc != 0)) && grep -q "/swaps .*htlc-1" <<<"$out" && grep -q "xmr .*xmr-3" <<<"$out"; then
  pass "both sources in flight: both ids, labelled"
else fail "both sources in flight: rc=$rc: $out"; fi

# 16. the gate never asks for the removed listing: the mock answers /xmr/* with 405, so a gate
#     that still read it would refuse the all-terminal case above; also assert no HTTP-ish XMR text
if ! grep -v '^[[:space:]]*#' "$TARGET" | grep -q 'curl.*xmr/swaps'; then pass "redeploy-maker.sh does not curl /xmr/swaps"
else fail "redeploy-maker.sh still references a curl of /xmr/swaps"; fi

# --- dry-run plans: zero ssh --------------------------------------------------------------
NOHOST=no-such-host-xyz
# 17. redeploy --dry-run snapshots all three before installing; its rollback restores all three
: >"$FAKE_SSH_LOG"
out="$("$TARGET" --dry-run --binary /nonexistent/divi-swapd --host "$NOHOST" 2>&1)"
rc=$?
if ((rc == 0)) && [[ ! -s "$FAKE_SSH_LOG" ]]; then pass "redeploy --dry-run: exits 0 and runs no ssh"
else fail "redeploy --dry-run: exit $rc, ssh log: $(cat "$FAKE_SSH_LOG"): $out"; fi
snap_line="$(grep -n 'cp -p /etc/divi-swapd/divi-swapd.toml /var/backups/divi-swapd/' <<<"$out" | head -1 | cut -d: -f1)"
install_line="$(grep -n 'install -m 0755 /tmp/divi-swapd.redeploy-new /usr/local/bin/divi-swapd' <<<"$out" | head -1 | cut -d: -f1)"
if [[ -n "$snap_line" && -n "$install_line" ]] && ((snap_line < install_line)); then
  pass "redeploy --dry-run: snapshot comes before install"
else fail "redeploy --dry-run: snapshot/install order wrong or missing: $out"; fi
scp_line="$(grep -n 'scp .*divi-swapd.redeploy-new' <<<"$out" | head -1 | cut -d: -f1)"
gate_line="$(grep -n 'sudo -n -u divi-swapd /tmp/divi-swapd.redeploy-new --config /etc/divi-swapd/divi-swapd.toml --xmr-inflight' <<<"$out" | head -1 | cut -d: -f1)"
if [[ -n "$scp_line" && -n "$gate_line" && -n "$snap_line" ]] && ((scp_line < gate_line && gate_line < snap_line)); then
  pass "redeploy --dry-run: ships the new binary, gates with it, then snapshots"
else fail "redeploy --dry-run: ship/gate/snapshot order wrong or missing ($scp_line/$gate_line/$snap_line): $out"; fi
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
: >"$FAKE_SSH_LOG"
out="$("$ROLLBACK" --dry-run --host "$NOHOST" 2>&1)"
rc=$?
if ((rc == 0)) && [[ ! -s "$FAKE_SSH_LOG" ]]; then pass "rollback --dry-run: exits 0 and runs no ssh"
else fail "rollback --dry-run: exit $rc, ssh log: $(cat "$FAKE_SSH_LOG"): $out"; fi
for want in "cp -p /var/backups/divi-swapd/prev/divi-swapd /usr/local/bin/divi-swapd.rollback" \
  "cp -p /var/backups/divi-swapd/prev/divi-swapd.toml /etc/divi-swapd/divi-swapd.toml.rollback" \
  "cp -p /var/backups/divi-swapd/prev/divi-swapd.service /etc/systemd/system/divi-swapd.service.rollback" \
  "sha256sum -c --quiet SHA256SUMS" "systemctl daemon-reload" "systemctl restart divi-swapd" \
  "/healthz" "checking for in-flight swaps" "--xmr-inflight"; do
  if grep -qF -e "$want" <<<"$out"; then pass "rollback --dry-run: has '$want'"
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
start_mock "$TERMINAL" "$PORT" || exit 1
: >"$FAKE_SSH_LOG"
out="$(FAKE_SSH_OUT='xmr_configured yes\nin_flight 1\nxmr-flight-4 swept\n' "$ROLLBACK" --maker-url "http://127.0.0.1:$PORT" --host "$NOHOST" 2>&1)"
rc=$?
stop_mock
if ((rc != 0)) && grep -q "xmr-flight-4" <<<"$out" && ! grep -q "==> restore" <<<"$out" \
  && [[ "$(wc -l <"$FAKE_SSH_LOG" | tr -d ' ')" == 1 ]]; then
  pass "rollback gate: refuses on an in-flight XMR swap before restoring (only the read ran)"
else fail "rollback gate: rc=$rc ssh=$(cat "$FAKE_SSH_LOG"): $out"; fi

if ((FAILS == 0)); then echo "PASS: test-redeploy-maker"; exit 0; fi
echo "$FAILS check(s) failing"
exit 1
