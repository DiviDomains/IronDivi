#!/usr/bin/env bash
# Exercises redeploy-maker.sh's install -> /healthz -> automatic rollback path for real
# (not --dry-run, which only prints it), against a fake host: ssh, scp, systemctl, curl and
# sha256sum are stubs on PATH that act on a temp directory standing in for dnsdivi. A fake
# binary is "healthy" iff its contents contain GOOD. No network, no build, no dnsdivi.
# Companion to test-redeploy-maker.sh (which covers the in-flight gate).
#
#   tools/swap-poc/test-redeploy-rollback.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/redeploy-maker.sh"
FAILS=0
pass() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/stub" "$T/host"
export FAKE_BIN="$T/host/divi-swapd" FAKE_LOG="$T/systemctl.log"

cat >"$T/stub/ssh" <<'EOF'
#!/usr/bin/env bash
shift                                    # host alias
if [ "${1:-}" = sudo ]; then shift; exec "$@"; fi   # `sudo bash -s` with the script on stdin
exec bash -c "$*"
EOF
cat >"$T/stub/scp" <<'EOF'
#!/usr/bin/env bash
exec cp "$1" "${2#*:}"
EOF
cat >"$T/stub/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $* ($(cat "$FAKE_BIN" 2>/dev/null))" >>"$FAKE_LOG"
EOF
cat >"$T/stub/curl" <<'EOF'
#!/usr/bin/env bash
url="${*: -1}"
case "$url" in
  */swaps) echo '[{"id":"s1","state":"Done"}]' ;;
  */healthz)
    if grep -q GOOD "$FAKE_BIN" 2>/dev/null; then echo ok; else echo "curl: (7) connection refused" >&2; exit 7; fi ;;
  *) exit 6 ;;
esac
EOF
cat >"$T/stub/sha256sum" <<'EOF'
#!/usr/bin/env bash
exec shasum -a 256 "$@"
EOF
chmod +x "$T/stub/"*

deploy() { # deploy <new-binary-contents>; prints output, returns the script's exit code
  printf '%s\n' "$1" >"$T/new"
  : >"$FAKE_LOG"
  PATH="$T/stub:$PATH" "$SCRIPT" --binary "$T/new" --remote-bin "$FAKE_BIN" \
    --maker-url http://fake --health-timeout 1 --health-interval 1 >"$T/out" 2>&1
  local rc=$?
  sed 's/^/      | /' "$T/out"
  return $rc
}

# 1. healthy new binary: installs, keeps the old one as .prev, exits 0
printf 'GOOD v1\n' >"$FAKE_BIN"
echo "-- case 1: healthy new binary (v1 -> v2)"
if deploy "GOOD v2"; then pass "healthy deploy exits 0"; else fail "healthy deploy exited non-zero"; fi
grep -q "GOOD v2" "$FAKE_BIN" && pass "v2 installed" || fail "v2 not installed"
grep -q "GOOD v1" "$FAKE_BIN.prev" && pass "v1 kept as .prev" || fail ".prev is not v1"

# 2. unhealthy new binary: health fails, rolls back to .prev, restarts, healthy again, exits 1
echo "-- case 2: unhealthy new binary (v2 -> BAD v3) must roll back"
if deploy "BAD v3"; then fail "unhealthy deploy exited 0"; else pass "unhealthy deploy exits non-zero"; fi
grep -q "FAIL: /healthz did not come up" "$T/out" && pass "health failure reported" || fail "no health failure line"
grep -q "GOOD v2" "$FAKE_BIN" && pass "rolled back: v2 is installed again" || fail "BAD v3 left installed"
grep -q "healthy again" "$T/out" && pass "post-rollback health check passed" || fail "no post-rollback health line"
[ "$(grep -c 'restart divi-swapd' "$FAKE_LOG")" = 2 ] && pass "service restarted twice (deploy + rollback)" \
  || fail "expected 2 restarts, got: $(cat "$FAKE_LOG")"

# 3. first deploy (no existing binary, so no .prev) of an unhealthy binary: says so, exits 1
echo "-- case 3: first-ever deploy of a bad binary (nothing to roll back to)"
rm -f "$FAKE_BIN" "$FAKE_BIN.prev"
if deploy "BAD v1"; then fail "first bad deploy exited 0"; else pass "first bad deploy exits non-zero"; fi
grep -q "no .prev to roll back to" "$T/out" && pass "missing .prev reported" || fail "missing .prev not reported"

if ((FAILS)); then echo "FAIL: test-redeploy-rollback ($FAILS)"; exit 1; fi
echo "PASS: test-redeploy-rollback"
