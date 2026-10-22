#!/usr/bin/env bash
# Proves the landing locations in a real nginx (docker nginx:1.27, container bn-nginx) in front of a mock
# divi-swapd. The "live snippet" is test/live-snippet.conf (the production text); landing-install.sh --apply
# is run against a copy of it, so the installer itself is tested, not just the fragment.
# Ports: nginx 18581, mock 18480 (the live snippet's upstream port). Needs docker, python3, curl.
set -u  # no pipefail: grep -q closes the pipe early
MOCK=; D=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); fail=0
MOCK_PORT=18480; NG=18581
cleanup() { docker rm -f bn-nginx >/dev/null 2>&1; [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
ok() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }

cp "$D/test/live-snippet.conf" "$T/divi-swapd.conf"; cp -p "$T/divi-swapd.conf" "$T/orig.conf"
SNIPPET="$T/divi-swapd.conf" WWW="$T/www" NGINX_TEST=true NGINX_RELOAD=true "$D/landing-install.sh" install --apply >/dev/null
ok "install leaves the live proxy block byte-identical (original is a prefix of the result)" \
   "cmp -n \$(stat -c %s $T/orig.conf) $T/orig.conf $T/divi-swapd.conf"
ok "install dry-run changes nothing" \
   "SNIPPET=$T/orig.conf WWW=$T/w2 $D/landing-install.sh install >/dev/null && [ ! -e $T/w2 ]"
cat > "$T/nginx.conf" <<NG
events {}
http { server { listen 127.0.0.1:$NG; include /etc/nginx/snippets/divi-swapd.conf; } }
NG
run_nginx() { # $1 mock health mode, $2 offers mode
  docker rm -f bn-nginx >/dev/null 2>&1; [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null
  python3 "$D/test/mock-swapd.py" $MOCK_PORT "$1" "$2" & MOCK=$!
  docker run -d --rm --name bn-nginx --network host -v "$T/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$T/divi-swapd.conf:/etc/nginx/snippets/divi-swapd.conf:ro" -v "$T/www:/var/www/divi-swap:ro" nginx:1.27 >/dev/null
  sleep 1.5
}
run_nginx ready several
docker exec bn-nginx nginx -t 2>&1 | tail -1
U=http://127.0.0.1:$NG
H=$(curl -si $U/swap/)
ok "/swap/ 200 html"                 "echo \"\$H\" | head -1 | grep -q ' 200 ' && echo \"\$H\" | grep -qi '^content-type: text/html'"
ok "/swap/ CSP"                      "echo \"\$H\" | grep -qi \"^content-security-policy: default-src 'none'; script-src 'self'\""
ok "/swap/ nosniff"                  "echo \"\$H\" | grep -qi '^x-content-type-options: nosniff'"
ok "/swap/ referrer-policy"          "echo \"\$H\" | grep -qi '^referrer-policy: no-referrer'"
curl -si $U/swap/ | head -c 600 >&2
ok "/swap/ body is the page"         "curl -s $U/swap/ | grep -c 'Atomic Swap Maker' | grep -qv 0"
ok "landing.js js type"              "curl -si $U/swap/landing.js | grep -qi '^content-type: application/javascript'"
ok "landing.css css type"            "curl -si $U/swap/landing.css | grep -qi '^content-type: text/css'"
ok "healthz proxied unchanged"       "curl -si $U/swap/healthz | grep -qi '^x-mock-path: /healthz' && curl -s $U/swap/healthz | grep -q 'ok.: true'"
ok "offers proxied unchanged"        "curl -si $U/swap/offers | grep -qi '^x-mock-path: /offers'"
ok "swaps/x proxied"                 "curl -si $U/swap/swaps/x | grep -qi '^x-mock-path: /swaps/x'"
ok "xmr/swaps proxied"               "curl -si $U/swap/xmr/swaps | grep -qi '^x-mock-path: /xmr/swaps'"
ok "POST xmr/swaps proxied"          "curl -si -X POST -d '{}' $U/swap/xmr/swaps | grep -qi '^x-mock-path: /xmr/swaps'"
ok "unknown /swap/nope reaches mock" "curl -si $U/swap/nope | grep -qi '^x-mock-path: /nope'"
ok "landing.js/js sibling traversal not served" "! curl -s $U/swap/landing.js/../x | grep -q 'function'"
echo "/swap (no slash): $(curl -si $U/swap | head -1 | tr -d '\r') Location: $(curl -si $U/swap | grep -i '^location' | tr -d '\r')"
ok "/swap redirects to /swap/ (nginx prefix-location behaviour)" "curl -si $U/swap | grep -qi '^location: .*/swap/'"
# rollback
SNIPPET="$T/divi-swapd.conf" WWW="$T/www" NGINX_TEST=true NGINX_RELOAD=true "$D/landing-install.sh" rollback --apply >/dev/null
ok "rollback restores the original snippet byte-for-byte" "cmp $T/orig.conf $T/divi-swapd.conf"
docker exec bn-nginx nginx -s reload >/dev/null 2>&1; sleep 1
ok "after rollback /swap/ reaches the mock (404 json), not the page" "curl -si $U/swap/ | grep -qi '^x-mock-path: /'"
[ $fail = 0 ] && echo ALL PASS || { echo SOME FAILED; exit 1; }
