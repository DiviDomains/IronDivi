#!/usr/bin/env bash
# Hermetic tests for deploy/divi-swapd/swap-watch/swap-watch.sh in `dry-run` mode: the XMR stuck-state
# and t_punish alerts read swap state through `divi-swapd --xmr-inflight --xmr-watch`, because
# GET /xmr/swaps no longer exists. `divi-swapd`, `curl` and `systemctl` are stubs on PATH; no
# network, host, database, Telegram or daemon is touched. State lives in a temp dir.
#
#   tools/swap-poc/test-swap-watch.sh                 test the script in this tree
#   SWAP_WATCH=/path/to/old.sh tools/swap-poc/test-swap-watch.sh
#                                                     run the same cases against another copy
#   BASE_REF=3fa41e7 (default) also proves the cases FAIL against that commit's script
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REL=deploy/divi-swapd/swap-watch/swap-watch.sh
TARGET="${SWAP_WATCH:-$ROOT/$REL}"
BASE_REF="${BASE_REF:-3fa41e7}"

FAILS=0
pass() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
mkdir -p "$tmp/bin"

# curl: /healthz ok, /xmr/swaps answers like the daemon today (405, empty body), and the
# operator-only /swaps listing: with --config (the header arrives on stdin) it is empty only
# when the header carries $OPTOK, else 404; argv is logged so a test can prove no token is in it.
cat >"$tmp/bin/curl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$CURL_ARGV_LOG"
case "$*" in
  */healthz*) echo '{"ok":true}' ;;
  */swaps*) case "$*" in
    */xmr/swaps*) ;;
    *--config*)
      hdr=$(cat)
      if grep -qF "X-Operator-Token: $OPTOK" <<<"$hdr"; then printf '[]\n200'; else printf '\n404'; fi ;;
    *) echo '[]' ;;
  esac ;;
esac
STUB
# divi-swapd: prints $FAKE_OUT (printf %b), exits $FAKE_RC; logs argv.
cat >"$tmp/bin/divi-swapd" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_LOG"
printf '%b' "${FAKE_OUT-}"
exit "${FAKE_RC:-0}"
STUB
cat >"$tmp/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
case "$1" in is-active) echo active ;; show) echo "Thu 2026-01-01 00:00:00 UTC" ;; esac
STUB
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH"
export FAKE_LOG="$tmp/swapd.log"
export CURL_ARGV_LOG="$tmp/curl-argv.log"
export OPTOK=op-token-for-test-0123456789
printf '%s\n' "$OPTOK" >"$tmp/op.token"

ID=abcdef0123456789abcdef0123456789
now=$(date +%s)

# run <script>: dry-run with the stubs; sets OUT (stdout) and RC.
run() {
  rm -rf "$tmp/state"; mkdir -p "$tmp/state"
  [ -n "${SEEN-}" ] && printf '%b' "$SEEN" >"$tmp/state/seen.tsv"
  : >"$FAKE_LOG"
  OUT=$(UNITS="" MONEROD_URL="" API="http://stub" STATE_DIR="$tmp/state" ENV_FILE="$tmp/none" \
    OPERATOR_TOKEN_FILE="${OPTOK_FILE-$tmp/op.token}" \
    SWAPD_BIN="${SWAPD_BIN_T:-$tmp/bin/divi-swapd}" SWAPD_USER="" SWAPD_CONFIG="$tmp/cfg.toml" \
    "$1" dry-run 2>&1)
  RC=$?
}
has() { grep -qF -- "$1" <<<"$OUT"; }
HDR='xmr_configured yes\nin_flight 1\n'

# ---- cases (each sets FAKE_OUT/SEEN, calls `check <script> ...`) ---------------------------------
case_stuck() { # a locked swap that entered its state 13 h ago
  FAKE_RC=0 FAKE_OUT="${HDR}${ID}\tlocked\t-\t\n"
  SEEN="xmr\t$ID\tlocked\t$((now - 46800))\t\n"
}
case_punish() { # cancelled, t_punish 10 min away
  FAKE_RC=0 FAKE_OUT="${HDR}${ID}\tcancelled\t$((now + 600))\t\n"
  SEEN=""
}

# 1. stuck XMR swap -> stuck problem
case_stuck; export FAKE_RC FAKE_OUT; run "$TARGET"
if ((RC == 0)) && has "problem: xmr swap abcdef01 stuck in locked for 13 h"; then
  pass "stuck XMR swap raises the stuck problem"
else fail "stuck XMR swap: rc=$RC out=$OUT"; fi
grep -qF -- "--xmr-inflight --xmr-watch" "$FAKE_LOG" || fail "divi-swapd was not called with --xmr-inflight --xmr-watch"
grep -qF -- "--config $tmp/cfg.toml" "$FAKE_LOG" || fail "divi-swapd was not given the config"

# 2. cancelled swap inside the punish margin -> punish problem
case_punish; export FAKE_RC FAKE_OUT; run "$TARGET"
if has "problem: xmr swap abcdef01 (cancelled) within 60 min of t_punish: refund not confirmed"; then
  pass "cancelled swap near t_punish raises the punish problem"
else fail "punish: out=$OUT"; fi

# 2b. same for refunded; far-away t_punish, null t_punish and non-cancelled states stay quiet
FAKE_OUT="xmr_configured yes\nin_flight 4\n${ID}\trefunded\t$((now + 60))\t\nbb\trefunded\t$((now + 90000))\t\ncc\tcancelled\t-\t\ndd\tlocked\t$((now + 5))\t\n"
export FAKE_OUT; SEEN=""; run "$TARGET"
if has "xmr swap abcdef01 (refunded) within 60 min" && ! has "xmr swap bb" && ! has "xmr swap cc" \
  && ! has "xmr swap dd" && has "1 problem(s)"; then
  pass "refunded near t_punish alerts; far, null and non-cancelled t_punish do not"
else fail "punish edges: out=$OUT"; fi

# 3. terminal swaps are ignored (the binary omits them; a leaked row is skipped too)
FAKE_OUT="xmr_configured yes\nin_flight 3\nd1\tdone\t$((now + 5))\t\na1\taborted\t-\tx\np1\tpunished\t$((now + 5))\tx\n"
export FAKE_OUT
SEEN="xmr\td1\tdone\t$((now - 99999))\t\nxmr\ta1\taborted\t$((now - 99999))\tx\nxmr\tp1\tpunished\t$((now - 99999))\tx\n"
run "$TARGET"
if has "0 problem(s)"; then pass "terminal swaps raise nothing"; else fail "terminal: out=$OUT"; fi
FAKE_OUT='xmr_configured yes\nin_flight 0\n'; SEEN=""; export FAKE_OUT; run "$TARGET"
if ((RC == 0)) && has "0 problem(s)"; then pass "no in-flight swaps: no problems"; else fail "empty: out=$OUT"; fi

# 4. the binary failing or missing -> "unreadable", never "no swaps"
FAKE_RC=2 FAKE_OUT="error: unexpected argument '--xmr-watch' found\n"; export FAKE_RC FAKE_OUT; SEEN=""; run "$TARGET"
if has "problem: XMR swap state unreadable: error: unexpected argument '--xmr-watch' found"; then
  pass "an old binary without --xmr-watch raises the unreadable problem"
else fail "old binary: out=$OUT"; fi
FAKE_RC=1 FAKE_OUT="Error: opening swap database /x/swaps.db\n"; export FAKE_RC FAKE_OUT; run "$TARGET"
if has "XMR swap state unreadable: Error: opening swap database"; then
  pass "an unreadable database raises the unreadable problem"
else fail "db error: out=$OUT"; fi
FAKE_RC=0 FAKE_OUT="garbage\n"; export FAKE_RC FAKE_OUT; run "$TARGET"
if has "XMR swap state unreadable"; then pass "output without the xmr_configured header is unreadable"
else fail "garbage: out=$OUT"; fi
FAKE_RC=0 FAKE_OUT=""; export FAKE_RC FAKE_OUT; SWAPD_BIN_T="$tmp/missing-divi-swapd" run "$TARGET"
if has "XMR swap state unreadable"; then pass "a missing binary raises the unreadable problem"
else fail "missing binary: out=$OUT"; fi

# 5. a repeated last_error (escaped tab/newline) alerts; a first-time one does not
ERR='boom\\tx\\ny'
FAKE_RC=0 FAKE_OUT="${HDR}${ID}\tlocked\t-\t${ERR}\n"; export FAKE_RC FAKE_OUT
SEEN="xmr\t$ID\tlocked\t$((now - 60))\t${ERR}\n"
run "$TARGET"
if has "problem: xmr swap abcdef01 (locked): boom"; then pass "a repeated last_error alerts"
else fail "repeat error: out=$OUT"; fi
SEEN=""; run "$TARGET"
if has "0 problem(s)"; then pass "a first-time last_error stays quiet"; else fail "first error: out=$OUT"; fi

# 6. dry-run changes no state
case_stuck; export FAKE_RC FAKE_OUT; run "$TARGET"
if [ "$(cat "$tmp/state/seen.tsv")" = "$(printf '%b' "$SEEN")" ]; then pass "dry-run leaves the seen state untouched"
else fail "dry-run changed seen.tsv"; fi

# 7. the hashlock listing is operator-only: token on stdin, never argv; a refusal is a problem
FAKE_RC=0 FAKE_OUT='xmr_configured yes\nin_flight 0\n'; export FAKE_RC FAKE_OUT; SEEN=""
: >"$CURL_ARGV_LOG"; run "$TARGET"
if has "0 problem(s)" && ! grep -qF "$OPTOK" "$CURL_ARGV_LOG"; then
  pass "the listing is read with the operator token on stdin, not on the command line"
else fail "listing ok: out=$OUT argv=$(cat "$CURL_ARGV_LOG")"; fi
OPTOK_FILE="$tmp/no-such-token" run "$TARGET"
if has "problem: hashlock swap listing unavailable: operator token file"; then
  pass "a missing operator token file is a problem, not 'no swaps'"
else fail "missing token file: out=$OUT"; fi
printf 'wrong\n' >"$tmp/wrong.token"
OPTOK_FILE="$tmp/wrong.token" run "$TARGET"
if has "problem: hashlock swap listing unavailable: listing refused (HTTP 404)"; then
  pass "a refused listing (wrong token or operator_token_file unset) is a problem"
else fail "refused listing: out=$OUT"; fi
if ! grep -qF wrong <<<"$OUT"; then pass "the token is not echoed in the alert"; else fail "token echoed: $OUT"; fi

# ---- the base script must NOT see these (the bug this test exists for) ---------------------------
if [ -z "${SWAP_WATCH:-}" ]; then
  if git -C "$ROOT" show "$BASE_REF:$REL" >"$tmp/base.sh" 2>/dev/null; then
    chmod +x "$tmp/base.sh"
    for c in stuck punish; do
      "case_$c"; export FAKE_RC FAKE_OUT; run "$tmp/base.sh"
      if has "0 problem(s)"; then pass "base $BASE_REF sees no XMR problem for the $c case (the bug)"
      else fail "base $BASE_REF unexpectedly saw: $OUT"; fi
    done
  else
    echo "skip: $BASE_REF not in this checkout; the fail-before proof was not run"
  fi
fi

echo
((FAILS == 0)) && echo "all passed" || echo "$FAILS failed"
exit $((FAILS > 0))
