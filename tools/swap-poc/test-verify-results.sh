#!/usr/bin/env bash
# Bash-level regression tests for verify-results.sh's chain-attribution heuristic, run
# against a small synthetic fixture via --parse-only (no network calls at all — safe
# anywhere, including hp2). Not wired into check-usdc.sh: lane rules forbid editing check
# scripts: run by hand, or have the orchestrator run it alongside verify-results.sh itself.
#
#   tools/swap-poc/test-verify-results.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="$HERE/verify-results.sh"

command -v python3 >/dev/null || { echo "test-verify-results: needs python3" >&2; exit 1; }

FAILS=0
pass() { echo "ok:   $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
fixture="$tmp/RESULTS.md"

# Fake, well-formed-looking 64-hex txids, one digit repeated so each is easy to eyeball in
# failure output. None of these need to resolve on any real chain — --parse-only never
# makes a network call.
h1="1111111111111111111111111111111111111111111111111111111111111111"
h1="${h1:0:64}"
h2="2222222222222222222222222222222222222222222222222222222222222222"
h2="${h2:0:64}"
h3="3333333333333333333333333333333333333333333333333333333333333333"
h3="${h3:0:64}"
h4="4444444444444444444444444444444444444444444444444444444444444444"
h4="${h4:0:64}"

cat >"$fixture" <<EOF
# Fixture

## Regression: backtick-quoted log content must not leak a chain label forward
- BTC network switched to testnet3. Redeploys:
  (\`a5b7a96\`: \`divi-swapd up\` 1 s after start, healthz reports \`divi_scan\`, no outage),
  05:42 UTC from \`504da62\` (includes \`53c2bb3\`); healthz \`ok:true\`.
- The first local live happy aborted on an Esplora \`/tx\` 404 race; fixed before any
  deployed run. Its 10,000 sats (HTLC \`9b62069b…:0\`, swap \`252aa984…\`) refunded after
  locktime: \`$h1\`.

## Regression: a line can state a later, different txid's label after this one's
- Refund with a crash: swap \`fdfdf352…\`, maker BTC refund
  \`$h2\` (testnet3 block 5158301), taker DIVI refund after
  the 6 h locktime \`d1a45509a64dbbd88fa7e5bde370db0f0935bf674d058873d88c10365f404346\` (the
  driver logs it as "taker BTC refund"; it is the DIVI leg).

## Regression: a parenthetical aside about a different chain must not beat the real label
- DIVI claim (maker, preimage read from the LTC spend) \`$h3\`.
- LTC claim (maker, preimage read from the DIVI spend) \`$h4\`.

## Regression: a computed-but-never-broadcast txid must be excluded, not checked
- CLTV-violation probe: node rejected \`64: non-mandatory-script-verify-flag\`, txid would
  have been \`1e184a6fdc4162ab9629e9b1da998cab48f22346400d27694b3158ffaee37f66\`.
EOF

out="$("$TARGET" --parse-only "$fixture")"
rc=$?

if ((rc == 0)); then pass "--parse-only exits 0"; else fail "--parse-only exited $rc"; fi

assert_chain() {
  local txid="$1" want="$2"
  local got
  got="$(echo "$out" | awk -F'\t' -v t="$txid" '$2 == t {print $1}')"
  if [[ "$got" == "$want" ]]; then
    pass "$txid -> $want"
  else
    fail "$txid: want '$want', got '${got:-<absent>}'"
  fi
}

# Backtick-quoted "divi-swapd up"/"divi_scan" must not leak into this BTC refund's label.
assert_chain "$h1" "btc"

# "maker BTC refund `h2` ... taker DIVI refund ..." on the same/continuing line: the DIVI
# word belongs to a *different*, later txid and must not win for h2.
assert_chain "$h2" "btc"
# The orchestrator's real-document txid this fixture also exercises (hardcoded override,
# since RESULTS.md's own prose flags the "BTC" word next to it as wrong).
assert_chain "d1a45509a64dbbd88fa7e5bde370db0f0935bf674d058873d88c10365f404346" "divi"

# "DIVI claim (maker, preimage read from the LTC spend)" / "LTC claim (..., DIVI spend)":
# the parenthetical names a *different* chain's earlier transaction, not this hash's own.
assert_chain "$h3" "divi"
assert_chain "$h4" "ltc"

# The rejected-probe txid must be reported excluded, not attributed to any chain at all.
excluded_line="$(echo "$out" | awk -F'\t' '$1 == "excluded" {print}')"
if [[ "$excluded_line" == excluded*1e184a6fdc4162ab9629e9b1da998cab48f22346400d27694b3158ffaee37f66* ]]; then
  pass "rejected probe txid reported excluded"
else
  fail "rejected probe txid not reported excluded: ${excluded_line:-<absent>}"
fi
if echo "$out" | grep -q "^divi	1e184a6f\|^btc	1e184a6f"; then
  fail "rejected probe txid was attributed to a chain instead of excluded"
else
  pass "rejected probe txid not attributed to any chain"
fi

if ((FAILS == 0)); then echo "PASS: test-verify-results"; exit 0; fi
echo "$FAILS check(s) failing"
exit 1
