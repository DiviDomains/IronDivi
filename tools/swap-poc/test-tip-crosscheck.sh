#!/usr/bin/env bash
# Hermetic self-test for tip-crosscheck.sh: a stubbed `divi-swap` and a stubbed curl; no network.
# Covers MATCH, MISMATCH, SKIP (no source), the 1-block race (explorer behind, then caught up), a tip error.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
A=$(printf 'a%.0s' {1..64}); B=$(printf 'b%.0s' {1..64}); C=$(printf 'c%.0s' {1..64})

# stub divi-swap: prints $T/tip.out and exits with $T/tip.rc
cat >"$T/divi-swap" <<EOF
#!/usr/bin/env bash
cat "$T/tip.out"; exit "\$(cat "$T/tip.rc")"
EOF
# stub curl: the last argument is the URL; the answer is the file named after it in $T/web (404 = exit 22);
# a file "<name>.once-missing" makes the first call fail, to simulate an explorer one block behind.
cat >"$T/curl" <<EOF
#!/usr/bin/env bash
url="\${@: -1}"; [ "\$url" = "-" ] && url="\${@: -3:1}"
f="$T/web/\$(printf '%s' "\$url" | tr -c 'A-Za-z0-9' '_')"
if [ -e "\$f.once-missing" ]; then rm "\$f.once-missing"; exit 22; fi
[ -e "\$f" ] && cat "\$f" || exit 22
EOF
chmod +x "$T/divi-swap" "$T/curl"; mkdir "$T/web"
web() { printf '%s' "$2" >"$T/web/$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"; }
run() { echo 0 >"$T/tip.rc"; DIVI_SWAP="$T/divi-swap" CURL="$T/curl" RACE_WAIT=0 "$HERE/tip-crosscheck.sh" "$@"; }

FAILS=0
expect() { # <label> <want-exit> <grep-pattern> <output>
  local out="$4"
  if [ "$2" != "$RC" ] || ! grep -qE -- "$3" <<<"$out"; then echo "FAIL: $1 (exit $RC, want $2; pattern $3)"; echo "$out"; FAILS=$((FAILS + 1)); else echo "ok:   $1"; fi
}

# MATCH (btc signet, plain explorer) + SKIP (divi testnet has no independent source)
printf 'divi testnet 10 %s\nbtc signet 20 %s\n' "$A" "$B" >"$T/tip.out"
web https://blockstream.info/signet/api/block-height/20 "$B"
out="$(run)"; RC=$?
expect "match exits 0" 0 "^MATCH +btc +signet" "$out"
expect "no-source is a skip, not a failure" 0 "^SKIP +divi +testnet.*no independent public explorer" "$out"

# MISMATCH (explorer returns a different hash, also after the recheck)
web https://blockstream.info/signet/api/block-height/20 "$C"
out="$(run)"; RC=$?
expect "mismatch exits 1" 1 "^MISMATCH +btc +signet.*code=$B.*=$C" "$out"

# 1-block race: the explorer has no block at that height on the first ask, the right one on the second
web https://blockstream.info/signet/api/block-height/20 "$B"
: >"$T/web/$(printf '%s' https://blockstream.info/signet/api/block-height/20 | tr -c 'A-Za-z0-9' '_').once-missing"
out="$(run)"; RC=$?
expect "explorer one block behind then caught up is a MATCH" 0 "^MATCH +btc +signet" "$out"

# explorer never has the block: SKIP naming the source, exit 0
rm "$T/web/$(printf '%s' https://blockstream.info/signet/api/block-height/20 | tr -c 'A-Za-z0-9' '_')"
out="$(run)"; RC=$?
expect "explorer never answers is a SKIP naming the source" 0 "^SKIP +btc +signet.*tried: blockstream.info/signet" "$out"

# mainnet fallback: first source (blockstream) down, second (blockchain.info) answers
printf 'btc mainnet 30 %s\n' "$A" >"$T/tip.out"
web "https://blockchain.info/block-height/30?format=json" "{\"blocks\":[{\"hash\":\"$A\"}]}"
out="$(MAINNET=1 run)"; RC=$?
expect "second source is used when the first is down" 0 "^MATCH +btc +mainnet.*blockchain.info" "$out"

# monero: tip prints the block COUNT; the top block is height-1
printf 'xmr stagenet 41 %s\n' "$A" >"$T/tip.out"
web https://stagenet.xmrchain.net/block/40 "<html>$A previous $B</html>"
out="$(XMR_MONEROD_URL=http://x run)"; RC=$?
expect "xmr compares block height-1" 0 "^MATCH +xmr +stagenet" "$out"

# a tip error line fails the run
printf 'ltc testnet error: no answer within 30s\n' >"$T/tip.out"
out="$(run)"; RC=$?
expect "tip error line exits 1" 1 "^ERROR +ltc" "$out"

[ "$FAILS" -eq 0 ] && echo "test-tip-crosscheck: all passed" || { echo "test-tip-crosscheck: $FAILS failed"; exit 1; }
