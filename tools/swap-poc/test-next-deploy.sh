#!/usr/bin/env bash
# End-to-end test of the operator-token handling in redeploy-maker.sh and rollback-maker.sh, as the
# next maker deploy will use them (docs/plans/swap-poc/next-deploy-plan.md). Not --dry-run and not
# --check-only alone: the real install, restart, /healthz and restore steps run against a fake host
# (ssh, scp, systemctl, install, date are stubs acting on a temp directory), while GET /swaps is a real
# local HTTP server that answers 404 unless X-Operator-Token matches, as the daemon does with
# operator_token_file set. No network beyond 127.0.0.1, no build, no dnsdivi, no secrets (the tokens
# below are throwaway test strings).
#
# Asserts: the token reaches curl on stdin and never in any argv (curl, ssh, scp, systemctl); a
# missing, unreadable or wrong token refuses before anything is installed or restored and is never
# echoed; an in-flight swap still refuses with the right token; deploy and rollback both work with
# the token. Last, it re-runs itself against two broken copies of the scripts and requires failures.
#
#   tools/swap-poc/test-next-deploy.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="${NEXT_DEPLOY_SCRIPTS_DIR:-$HERE}"   # the mutant self-check points this at a broken copy
REDEPLOY="$SCRIPTS/redeploy-maker.sh"
ROLLBACK="$SCRIPTS/rollback-maker.sh"
for t in curl jq python3; do command -v "$t" >/dev/null || { echo "test-next-deploy: needs $t" >&2; exit 1; }; done
REAL_CURL="$(command -v curl)"

OK=0
FAILS=0
pass() { echo "ok:   $*"; OK=$((OK + 1)); }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

T="$(mktemp -d)"
server_pid=""
# shellcheck disable=SC2329  # invoked by the EXIT trap below
cleanup() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT INT TERM
mkdir -p "$T/stub" "$T/host"

export FAKE_BIN="$T/host/divi-swapd" FAKE_LOG="$T/systemctl.log" FAKE_CLOCK="$T/clock"
export ARGV_LOG="$T/argv.log"            # every argv of every stubbed command, one line each
FAKE_TOML="$T/host/divi-swapd.toml" FAKE_UNIT="$T/host/divi-swapd.service" FAKE_BACKUP="$T/host/backups"
export OPTOK="op-token-test-7c41e9b2d05a83f1"      # throwaway; the mock server demands it
WRONG="op-token-wrong-0000aaaa1111bbbb"
PORT="${NEXT_DEPLOY_PORT:-18597}"
export SWAPS_FILE="$T/swaps.json"
printf '%s\n' "$OPTOK" >"$T/good.token"
printf '%s\n' "$WRONG" >"$T/wrong.token"
: >"$T/empty.token"

# --- the mock maker: GET /swaps is 404 unless X-Operator-Token matches ---------------------
python3 - "$PORT" <<'PY' &
import os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
tok, path = os.environ["OPTOK"], os.environ["SWAPS_FILE"]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/ready":
            code, body = 200, b"ok"
        elif self.path == "/swaps" and self.headers.get("X-Operator-Token") == tok:
            code, body = 200, open(path, "rb").read()
        else:
            code, body = 404, b""
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
server_pid=$!
for _ in $(seq 1 50); do
  "$REAL_CURL" -fsS -m 2 "http://127.0.0.1:$PORT/ready" >/dev/null 2>&1 && break
  sleep 0.1
done
"$REAL_CURL" -fsS -m 2 "http://127.0.0.1:$PORT/ready" >/dev/null 2>&1 || { echo "mock server never came up" >&2; exit 1; }

# --- the fake host --------------------------------------------------------------------------
cat >"$T/stub/ssh" <<'EOF'
#!/usr/bin/env bash
echo "ssh $*" >>"$ARGV_LOG"
shift                                    # host alias
case "$*" in *--xmr-inflight*) printf "xmr_configured no\nin_flight 0\n"; exit 0 ;; esac
if [ "${1:-}" = sudo ]; then shift; exec "$@"; fi
exec bash -c "$*"
EOF
cat >"$T/stub/scp" <<'EOF'
#!/usr/bin/env bash
echo "scp $*" >>"$ARGV_LOG"
exec cp "$1" "${2#*:}"
EOF
cat >"$T/stub/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >>"$ARGV_LOG"
echo "systemctl $* ($(cat "$FAKE_BIN" 2>/dev/null))" >>"$FAKE_LOG"
EOF
# curl: /swaps goes to the real curl against the mock (argv logged first); /healthz is fake.
cat >"$T/stub/curl" <<EOF
#!/usr/bin/env bash
echo "curl \$*" >>"\$ARGV_LOG"
url="\${*: -1}"
case "\$url" in
  */swaps) exec "$REAL_CURL" "\$@" ;;
  */healthz) if grep -q GOOD "\$FAKE_BIN" 2>/dev/null; then echo ok; else echo "curl: (7) refused" >&2; exit 7; fi ;;
  *) exit 6 ;;
esac
EOF
cat >"$T/stub/install" <<'EOF'
#!/usr/bin/env bash
args=(); while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done
exec /usr/bin/install "${args[@]}"
EOF
cat >"$T/stub/date" <<'EOF'
#!/usr/bin/env bash
n=$(($(cat "$FAKE_CLOCK" 2>/dev/null || echo 0) + 1)); echo "$n" >"$FAKE_CLOCK"
printf '20260101T0000%02dZ\n' "$n"
EOF
command -v sha256sum >/dev/null || printf '#!/usr/bin/env bash\nexec shasum -a 256 "$@"\n' >"$T/stub/sha256sum"
chmod +x "$T/stub/"*

reset_host() { # reset_host <installed-binary-contents>
  rm -rf "$T/host"; mkdir -p "$T/host"
  printf '%s\n' "$1" >"$FAKE_BIN"; printf 'toml\n' >"$FAKE_TOML"; printf 'unit\n' >"$FAKE_UNIT"
  : >"$FAKE_LOG"; : >"$ARGV_LOG"
  echo '[{"id":"s1","state":"Done"},{"id":"s2","state":"Aborted"}]' >"$SWAPS_FILE"
}
common=(--remote-bin "$FAKE_BIN" --remote-toml "$FAKE_TOML" --remote-unit "$FAKE_UNIT" --backup-dir "$FAKE_BACKUP"
  --maker-url "http://127.0.0.1:$PORT" --health-timeout 1 --health-interval 1)

deploy() { # deploy <new-binary-contents> [extra args]; output in $T/out
  printf '%s\n' "$1" >"$T/new"; shift
  PATH="$T/stub:$PATH" "$REDEPLOY" --binary "$T/new" "${common[@]}" "$@" >"$T/out" 2>&1
}
rollback() { # rollback [extra args]
  PATH="$T/stub:$PATH" "$ROLLBACK" "${common[@]}" "$@" >"$T/out" 2>&1
}
restarts() { grep -c 'restart divi-swapd' "$FAKE_LOG" 2>/dev/null || true; }
no_token_anywhere() { # the token must be in no argv and not in the script output
  ! grep -qF -e "$OPTOK" -e "$WRONG" "$ARGV_LOG" "$T/out"
}

# 1. deploy WITH the token file: gate reads /swaps, install, restart, healthy
echo "-- 1. deploy with a good operator token file"
reset_host "GOOD v1"
if deploy "GOOD v2" --operator-token-file "$T/good.token"; then pass "deploy with token exits 0"
else fail "deploy with token failed"; sed 's/^/      | /' "$T/out"; fi
grep -q "GOOD v2" "$FAKE_BIN" && pass "v2 installed" || fail "v2 not installed"
grep -q "ok: no in-flight swaps" "$T/out" && pass "gate read the listing through the token" || fail "gate did not read the listing"
grep -E '^curl .*/swaps' "$ARGV_LOG" | grep -q -e '--config -' && pass "curl got the header via --config - (stdin)" \
  || fail "curl /swaps was not given --config -: $(grep '/swaps' "$ARGV_LOG")"
no_token_anywhere && pass "token appears in no curl/ssh/scp/systemctl argv and not in the output" \
  || fail "token leaked: $(grep -F "$OPTOK" "$ARGV_LOG" "$T/out" | head -3)"
! grep -qiE 'X-Operator-Token' "$ARGV_LOG" && pass "no X-Operator-Token header text on any argv" || fail "header text on an argv"

# 2. the token from the environment (OPERATOR_TOKEN_FILE) works the same
echo "-- 2. token file given by environment"
reset_host "GOOD v1"
if OPERATOR_TOKEN_FILE="$T/good.token" deploy "GOOD v2"; then pass "env OPERATOR_TOKEN_FILE deploy exits 0"
else fail "env deploy failed"; fi

# 3. refusals: nothing installed, nothing restarted, token never echoed
refuse_case() { # refuse_case <label> <expect-grep> <extra args...>
  local label="$1" expect="$2"; shift 2
  reset_host "GOOD v1"
  deploy "GOOD v2" "$@"; local rc=$?
  ((rc != 0)) && pass "$label: deploy exits non-zero" || fail "$label: deploy exited 0"
  grep -q "$expect" "$T/out" && pass "$label: says '$expect'" || fail "$label: no '$expect' in: $(head -5 "$T/out")"
  grep -q "GOOD v1" "$FAKE_BIN" && ! grep -q "GOOD v2" "$FAKE_BIN" && pass "$label: installed binary untouched" || fail "$label: binary changed"
  [ "$(restarts)" = 0 ] && pass "$label: service not restarted" || fail "$label: service restarted"
  [ ! -d "$FAKE_BACKUP" ] && pass "$label: no snapshot taken" || fail "$label: snapshot dir created"
  no_token_anywhere && pass "$label: no token on any argv or in the output" || fail "$label: token leaked"
}
echo "-- 3. missing / empty / unreadable / wrong token"
refuse_case "no token"        "no operator token"
refuse_case "empty token file" "no operator token" --operator-token-file "$T/empty.token"
refuse_case "unreadable file" "no operator token" --operator-token-file "$T/does-not-exist"
refuse_case "wrong token"     "REFUSE"            --operator-token-file "$T/wrong.token"

# 4. the in-flight gate still refuses with the right token
echo "-- 4. in-flight swap, right token"
reset_host "GOOD v1"
echo '[{"id":"live-1","state":"TakerLockSeen"}]' >"$SWAPS_FILE"
deploy "GOOD v2" --operator-token-file "$T/good.token"; rc=$?
((rc != 0)) && grep -q "live-1" "$T/out" && grep -q "REFUSE" "$T/out" && pass "in-flight swap: refused, id listed" || fail "in-flight not refused (rc=$rc)"
grep -q "GOOD v1" "$FAKE_BIN" && [ "$(restarts)" = 0 ] && pass "in-flight swap: nothing installed or restarted" || fail "in-flight swap: host changed"
no_token_anywhere && pass "in-flight swap: token not leaked" || fail "in-flight swap: token leaked"

# 5. rollback with the token: restores the prev set (v1) after a v2 deploy
echo "-- 5. rollback-maker with the token"
reset_host "GOOD v1"
deploy "GOOD v2" --operator-token-file "$T/good.token" || fail "setup deploy failed"
: >"$ARGV_LOG"
if rollback --to prev --operator-token-file "$T/good.token"; then pass "rollback with token exits 0"
else fail "rollback with token failed"; sed 's/^/      | /' "$T/out"; fi
grep -q "GOOD v1" "$FAKE_BIN" && pass "rollback restored v1" || fail "v1 not restored: $(cat "$FAKE_BIN")"
grep -E '^curl .*/swaps' "$ARGV_LOG" | grep -q -e '--config -' && pass "rollback gate: token on stdin" || fail "rollback gate argv: $(grep /swaps "$ARGV_LOG")"
no_token_anywhere && pass "rollback: token on no argv and not in the output" || fail "rollback leaked the token"

# 6. rollback refuses without / with a wrong token, and with an in-flight swap; host untouched
rb_refuse() { # rb_refuse <label> <expect-grep> <extra args...>
  local label="$1" expect="$2"; shift 2
  reset_host "GOOD v1"; deploy "GOOD v2" --operator-token-file "$T/good.token" || fail "$label: setup deploy failed"
  : >"$FAKE_LOG"; : >"$ARGV_LOG"
  rollback --to prev "$@"; local rc=$?
  ((rc != 0)) && pass "$label: rollback exits non-zero" || fail "$label: rollback exited 0"
  grep -q "the in-flight gate refused; nothing was changed" "$T/out" && grep -q "$expect" "$T/out" \
    && pass "$label: gate refusal reported ('$expect')" || fail "$label: out: $(head -6 "$T/out")"
  grep -q "GOOD v2" "$FAKE_BIN" && [ "$(restarts)" = 0 ] && pass "$label: v2 still installed, no restart" || fail "$label: host changed"
  no_token_anywhere && pass "$label: token not leaked" || fail "$label: token leaked"
}
echo "-- 6. rollback refusals"
rb_refuse "rollback no token"    "no operator token"
rb_refuse "rollback wrong token" "REFUSE" --operator-token-file "$T/wrong.token"
reset_host "GOOD v1"; deploy "GOOD v2" --operator-token-file "$T/good.token"
echo '[{"id":"live-2","state":"MakerLocked"}]' >"$SWAPS_FILE"; : >"$FAKE_LOG"; : >"$ARGV_LOG"
rollback --to prev --operator-token-file "$T/good.token"; rc=$?
((rc != 0)) && grep -q "live-2" "$T/out" && grep -q "GOOD v2" "$FAKE_BIN" && [ "$(restarts)" = 0 ] \
  && pass "rollback in-flight swap: refused, host untouched" || fail "rollback in-flight not refused (rc=$rc)"

# 7. self-check: broken copies of the scripts must make this very test fail
if [[ -z "${NEXT_DEPLOY_MUTANT:-}" ]]; then
  echo "-- 7. fail-before: the same test against scripts with the token handling broken"
  run_mutant() { # run_mutant <name> <sed expr on redeploy-maker.sh> <expect-fail-grep>
    local name="$1" expr="$2" expect="$3" d="$T/mutant-$1"
    mkdir -p "$d"; cp "$HERE/redeploy-maker.sh" "$HERE/rollback-maker.sh" "$d/"
    sed -i.bak "$expr" "$d/redeploy-maker.sh"
    if cmp -s "$d/redeploy-maker.sh" "$HERE/redeploy-maker.sh"; then fail "mutant $name: sed changed nothing"; return; fi
    NEXT_DEPLOY_MUTANT=1 NEXT_DEPLOY_SCRIPTS_DIR="$d" NEXT_DEPLOY_PORT=$((PORT + 1)) "$HERE/test-next-deploy.sh" >"$T/mutant-$name.out" 2>&1
    local mrc=$?
    if ((mrc != 0)) && grep -q "$expect" "$T/mutant-$name.out"; then
      pass "mutant $name: the harness fails ($(grep -c '^FAIL' "$T/mutant-$name.out") FAIL lines, e.g. $(grep -m1 "$expect" "$T/mutant-$name.out" | cut -c1-90))"
    else fail "mutant $name: harness did not catch it (rc=$mrc)"; fi
  }
  # token passed as a curl argument instead of stdin
  run_mutant argv 's|curl -fsS -m 20 --config - "\$MAKER_URL/swaps"|curl -fsS -m 20 -H "X-Operator-Token: $op_tok" "$MAKER_URL/swaps"|' \
    "^FAIL: .*\(curl got the header\|token leaked\|token appears\)"
  # a missing token no longer refuses: the gate carries on with an empty one
  run_mutant notoken 's|if \[\[ -z "\$op_tok" \]\]; then|if false; then|' "^FAIL: no token: no 'no operator token'"
fi

echo "test-next-deploy: $OK ok / $FAILS fail"
if ((FAILS)); then echo "FAIL: test-next-deploy ($FAILS)"; exit 1; fi
echo "PASS: test-next-deploy"
