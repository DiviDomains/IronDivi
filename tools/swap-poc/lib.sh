#!/usr/bin/env bash
# Shared helpers for tools/swap-poc/check-*.sh. Each check exits 0 only when its lane's
# acceptance criteria (docs/plans/atomic-swap-poc.md §5) pass, and prints every failure.
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2
FAILS=0
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
pass() { echo "ok:   $*"; }

# require_tests <package> <name>... — each named test must exist (substring of a listed test).
require_tests() {
  local pkg="$1"; shift
  local list
  list="$(cargo test -q -p "$pkg" --all-features -- --list 2>/dev/null | grep ': test$' || true)"
  for t in "$@"; do
    if grep -q -- "$t" <<<"$list"; then pass "test exists: $t"; else fail "missing test: $pkg::$t"; fi
  done
}

# crate_green <package> — fmt, clippy -D warnings (all targets, all features), tests pass.
crate_green() {
  local pkg="$1"
  if cargo fmt -p "$pkg" -- --check >/dev/null 2>&1; then pass "fmt $pkg"; else fail "cargo fmt -p $pkg"; fi
  if cargo clippy -q -p "$pkg" --all-targets --all-features -- -D warnings >/dev/null 2>&1; then
    pass "clippy $pkg"; else fail "cargo clippy -p $pkg --all-targets --all-features -D warnings"; fi
  if cargo test -q -p "$pkg" >/dev/null 2>&1; then pass "tests $pkg"; else fail "cargo test -p $pkg"; fi
}

# no_todo <path> — no todo!/unimplemented! left in the lane's code.
no_todo() {
  if grep -rnE 'todo!|unimplemented!' "$1" >/dev/null 2>&1; then
    fail "todo!/unimplemented! remain in $1: $(grep -rlE 'todo!|unimplemented!' "$1" | tr '\n' ' ')"
  else pass "no todo! in $1"; fi
}

# status_field <lane> <key> — value of a `key: value` line in the lane status file.
status_field() {
  grep -E "^- *$2:|^$2:" "docs/plans/swap-poc/status/$1.md" 2>/dev/null | head -1 | sed -E "s/^-? *$2: *//; s/[\` ]//g"
}

# divi_confirmed <txid> — tx known to the Divi testnet proxy with >= 1 confirmation.
divi_confirmed() {
  local c
  c="$(curl -s -m 20 -X POST -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getrawtransaction\",\"params\":[\"$1\",1]}" \
    https://services.divi.domains/api/testnet/rpc/ | jq -r '.result.confirmations // 0' 2>/dev/null)"
  [[ "${c:-0}" =~ ^[0-9]+$ ]] && (( c >= 1 ))
}

# btc_confirmed <txid> — tx confirmed on signet (mempool.space).
btc_confirmed() {
  [[ "$(curl -s -m 20 "https://mempool.space/signet/api/tx/$1/status" | jq -r '.confirmed' 2>/dev/null)" == "true" ]]
}

finish() {
  if (( FAILS == 0 )); then echo "PASS: $1"; exit 0; fi
  echo "$FAILS check(s) failing for $1"; exit 1
}
