#!/usr/bin/env bash
# Hermetic test: usdc-live.sh resolves its keys through `secret get` only — once per item, never
# through the raw 1Password CLI, never leaking the value. No network, no keys, no 1Password:
# `secret` is a stub that records its argv and prints a FAKE key; `op` is a stub that exits 99
# and records that it was called; cargo/curl are stubs that log argv.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/usdc-live.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/home"
FAKE=deadbeef0123456789abcdef0123456789abcdef0123456789abcdefcafef00d

cat >"$tmp/bin/secret" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$tmp/secret.calls"
rc="\${STUB_SECRET_RC:-0}"
[[ "\$rc" == 0 ]] || exit "\$rc"
echo "$FAKE"
EOF
cat >"$tmp/bin/op" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$tmp/op.calls"; exit 99
EOF
# Child tools: log argv, answer just enough for the script to reach its "no ETH" stop.
cat >"$tmp/bin/cargo" <<EOF
#!/usr/bin/env bash
echo "cargo \$*" >>"$tmp/child.argv"
[[ "\$*" == *balances* ]] && echo "eth_wei: 0"
exit 0
EOF
cat >"$tmp/bin/curl" <<EOF
#!/usr/bin/env bash
echo "curl \$*" >>"$tmp/child.argv"; exit 0
EOF
chmod +x "$tmp"/bin/*

fail() { echo "FAIL: $*" >&2; exit 1; }
# HOME is a temp dir so the script's own PATH prefix ($HOME/.local/bin) cannot shadow the stubs.
run() { # run ARGS... ; leaves combined output in $tmp/out, rc in $rc
  : >"$tmp/secret.calls"; : >"$tmp/op.calls"; : >"$tmp/child.argv"
  rc=0
  (cd "$here" && HOME="$tmp/home" PATH="$tmp/bin:$PATH" "$script" "$@") >"$tmp/out" 2>&1 || rc=$?
}
calls() { wc -l <"$1" | tr -d ' '; }

# (a)+(b) --check-secrets, local mode: four items, each exactly once, zero op, zero children.
run --check-secrets
[[ $rc == 0 ]] || { cat "$tmp/out" >&2; fail "--check-secrets rc=$rc"; }
[[ "$(calls "$tmp/op.calls")" == 0 ]] || fail "raw op was called"
[[ "$(calls "$tmp/secret.calls")" == 4 ]] || fail "expected 4 secret get calls, got $(calls "$tmp/secret.calls")"
for k in taker-btc maker-btc maker-divi taker-divi; do
  [[ "$(grep -c -- "--name irondivi-swap-poc-$k-password " "$tmp/secret.calls")" == 1 ]] \
    || fail "$k not resolved exactly once"
done
[[ "$(calls "$tmp/child.argv")" == 0 ]] || fail "--check-secrets ran a child tool"

# (b) remote-maker mode needs only the two taker keys.
run --check-secrets --maker-url http://127.0.0.1:1 --htlc 0x0000000000000000000000000000000000000001
[[ $rc == 0 && "$(calls "$tmp/secret.calls")" == 2 && "$(calls "$tmp/op.calls")" == 0 ]] \
  || fail "maker-url mode: rc=$rc secret=$(calls "$tmp/secret.calls")"

# (a)+(b)+(d) the real preflight path: the taker-btc key is resolved once even though the
# script both preflights it and hands it to sepolia_ops; children are stubs and see no key in argv.
run --skip-fund
[[ $rc == 1 ]] || { cat "$tmp/out" >&2; fail "expected stop at no-ETH (rc 1), got $rc"; }
grep -q "has no ETH" "$tmp/out" || fail "did not reach the post-resolution stop"
[[ "$(calls "$tmp/op.calls")" == 0 ]] || fail "raw op was called in live path"
[[ "$(calls "$tmp/secret.calls")" == 4 ]] || fail "live path: expected 4 secret get calls, got $(calls "$tmp/secret.calls")"
[[ -s "$tmp/child.argv" ]] || fail "no child argv recorded (stub cargo not used?)"
if grep -rqF "$FAKE" "$tmp/child.argv" "$tmp/out" "$tmp/secret.calls"; then fail "key leaked into argv/output"; fi

# (c) exit 2/3/4 fail closed with a named message and no value anywhere.
for pair in "2:unavailable" "3:not found" "4:denied"; do
  rc_in="${pair%%:*}" word="${pair#*:}"
  STUB_SECRET_RC=$rc_in run --check-secrets
  [[ $rc == 1 ]] || fail "secret exit $rc_in: expected rc 1, got $rc"
  grep -q "taker-btc" "$tmp/out" || fail "secret exit $rc_in: message does not name the item"
  grep -q "$word" "$tmp/out" || fail "secret exit $rc_in: message lacks '$word'"
  grep -qF "$FAKE" "$tmp/out" && fail "secret exit $rc_in: value in output"
  [[ "$(calls "$tmp/op.calls")" == 0 ]] || fail "secret exit $rc_in: raw op called"
  [[ "$(calls "$tmp/secret.calls")" == 1 ]] || fail "secret exit $rc_in: did not stop at first failure"
done

# (a, static) the script itself contains no raw op read/inject/run call.
if grep -nE '(^|[^A-Za-z_-])op (read|inject|run)\b' "$script" | grep -v '^[0-9]*:[[:space:]]*#'; then
  fail "usdc-live.sh calls the raw op CLI"
fi
# (d, static) no set -x in the script.
if grep -nE '^[[:space:]]*set .*-[a-z]*x|set -x' "$script" | grep -v '^[0-9]*:[[:space:]]*#'; then
  fail "set -x in usdc-live.sh"
fi
echo "ok: test-usdc-live-secrets"
