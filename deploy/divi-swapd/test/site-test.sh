#!/usr/bin/env bash
# Proves the website in a real nginx (docker nginx, container bq-nginx) in front of a mock divi-swapd.
# The "live snippet" is test/live-snippet.conf (production text); site-install.sh --apply is run against a copy, so
# the installer itself is tested. Ports: nginx 18581, mock 18480 (the live snippet's upstream port).
#   site-test.sh            nginx + installer proof
#   site-test.sh --browser  also the headless-browser run (official Playwright image; set SHOTS=1 to save PNGs)
# Needs docker, python3, curl. Removes its containers on exit.
set -u
MOCK=; D=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); fail=0
MOCK_PORT=18480; NG=18581
NGINX_IMG=${NGINX_IMG:-nginx:1.27}
PW_IMG=${PW_IMG:-mcr.microsoft.com/playwright:v1.49.1-jammy}
PW_VER=${PW_VER:-1.49.1}
cleanup() { docker rm -f bq-nginx bq-pw >/dev/null 2>&1; [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
ok() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }

cp "$D/test/live-snippet.conf" "$T/divi-swapd.conf"; cp -p "$T/divi-swapd.conf" "$T/orig.conf"
ok "install dry-run changes nothing" "SNIPPET=$T/orig.conf WWW=$T/w2 BACKUP=$T/b2 $D/site-install.sh install >/dev/null && [ ! -e $T/w2 ] && [ ! -e $T/b2 ] && cmp $T/orig.conf $D/test/live-snippet.conf"
SNIPPET="$T/divi-swapd.conf" WWW="$T/www" NGINX_TEST=true NGINX_RELOAD=true "$D/site-install.sh" install --apply >/dev/null
ok "install leaves the live proxy block byte-identical (original is a prefix of the result)" \
   "cmp -n \$(stat -c %s $T/orig.conf) $T/orig.conf $T/divi-swapd.conf"
ok "install made a backup equal to the original" "cmp $T/orig.conf $T/divi-swapd.conf.pre-site"
ok "install refuses a second time" "! SNIPPET=$T/divi-swapd.conf WWW=$T/www NGINX_TEST=true NGINX_RELOAD=true $D/site-install.sh install --apply >/dev/null 2>&1"
ok "failing nginx -t restores the snippet" "cp $T/orig.conf $T/f.conf && SNIPPET=$T/f.conf WWW=$T/wf BACKUP=$T/f.bak NGINX_TEST=false NGINX_RELOAD=true $D/site-install.sh install --apply >/dev/null 2>&1; cmp $T/orig.conf $T/f.conf"
cat > "$T/nginx.conf" <<NGC
events {}
http { include /etc/nginx/mime.types; server { listen 127.0.0.1:$NG; include /etc/nginx/snippets/divi-swapd.conf; } }
NGC
run_nginx() { # $1 mock health mode, $2 offers mode
  docker rm -f bq-nginx >/dev/null 2>&1; [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null
  python3 "$D/test/mock-swapd.py" $MOCK_PORT "$1" "$2" & MOCK=$!
  docker run -d --rm --name bq-nginx --network host -v "$T/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$T/divi-swapd.conf:/etc/nginx/snippets/divi-swapd.conf:ro" -v "$T/www:/var/www/divi-swap:ro" $NGINX_IMG >/dev/null
  sleep 1.5
}
run_nginx ready several
ok "nginx -t passes in a real nginx" "docker exec bq-nginx nginx -t 2>&1 | grep -q 'test is successful'"
U=http://127.0.0.1:$NG
for pg in /swap/ /swap/site/how-to-swap.html /swap/site/safety.html /swap/site/status.html /swap/site/faq.html; do
  H=$(curl -si $U$pg)
  ok "$pg 200 html"      "echo \"\$H\" | head -1 | grep -q ' 200 ' && echo \"\$H\" | grep -qi '^content-type: text/html'"
  ok "$pg CSP"           "echo \"\$H\" | grep -qi \"^content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\""
  ok "$pg nosniff"       "echo \"\$H\" | grep -qi '^x-content-type-options: nosniff'"
  ok "$pg referrer"      "echo \"\$H\" | grep -qi '^referrer-policy: no-referrer'"
done
ok "site.js js type + nosniff" "curl -si $U/swap/site/site.js | grep -qi '^content-type: .*javascript' && curl -si $U/swap/site/site.js | grep -qi '^x-content-type-options: nosniff'"
ok "site.css css type"        "curl -si $U/swap/site/site.css | grep -qi '^content-type: text/css'"
ok "home body is the page"    "curl -s $U/swap/ | grep -q 'Trade DIVI'"
ok "/swap/site/ directory not listed" "! curl -s $U/swap/site/ | grep -q 'site.js'"
ok "traversal out of the site dir refused" "! curl -s --path-as-is $U/swap/site/../../../../etc/passwd | grep -q root"
ok "missing site file is 404 from nginx, not the mock" "curl -si $U/swap/site/nope.html | head -1 | grep -q ' 404 ' && ! curl -si $U/swap/site/nope.html | grep -qi x-mock-path"
ok "healthz unchanged"   "curl -si $U/swap/healthz | grep -qi '^x-mock-path: /healthz' && curl -s $U/swap/healthz | grep -q 'ok.: true'"
ok "offers unchanged"    "curl -si $U/swap/offers | grep -qi '^x-mock-path: /offers\$' || curl -si $U/swap/offers | tr -d '\r' | grep -qi '^x-mock-path: /offers\$'"
ok "offers/x/quote unchanged" "curl -si '$U/swap/offers/x/quote?btc_sats=1' | tr -d '\r' | grep -qi '^x-mock-path: /offers/x/quote?btc_sats=1\$'"
ok "swaps GET unchanged"      "curl -si $U/swap/swaps | tr -d '\r' | grep -qi '^x-mock-path: /swaps\$'"
ok "swaps/x unchanged"        "curl -si $U/swap/swaps/x | tr -d '\r' | grep -qi '^x-mock-path: /swaps/x\$'"
ok "xmr/swaps GET unchanged"  "curl -si $U/swap/xmr/swaps | tr -d '\r' | grep -qi '^x-mock-path: /xmr/swaps\$'"
ok "xmr/swaps POST unchanged" "curl -si -X POST -d '{}' $U/swap/xmr/swaps | tr -d '\r' | grep -qi '^x-mock-path: /xmr/swaps\$'"
ok "swaps POST unchanged"     "curl -si -X POST -d '{}' $U/swap/swaps | tr -d '\r' | grep -qi '^x-mock-path: /swaps\$'"
ok "unknown /swap/nope reaches the mock" "curl -si $U/swap/nope | tr -d '\r' | grep -qi '^x-mock-path: /nope\$'"
ok "API responses carry no site CSP (proxy untouched)" "! curl -si $U/swap/healthz | grep -qi '^content-security-policy'"
echo "/swap (no slash): $(curl -si $U/swap | head -1 | tr -d '\r') Location: $(curl -si $U/swap | grep -i '^location' | tr -d '\r')"
ok "/swap redirects to /swap/ (nginx prefix-location behaviour)" "curl -si $U/swap | grep -qi '^location: .*/swap/'"

if [ "${1:-}" = "--browser" ]; then
  OUT=${OUT:-$T/shots}; mkdir -p "$OUT"
  for sc in "ready several" "scanning several" "error hostile" "ready empty"; do
    set -- $sc; run_nginx $1 $2
    [ "$sc" = "ready several" ] && SH=1 || SH=0
    docker rm -f bq-pw >/dev/null 2>&1
    docker run --rm --name bq-pw --network host -e SHOTS=$SH -v "$D/test/browser-test.js:/work/browser-test.js:ro" -v "$OUT:/out" \
      -w /tmp $PW_IMG bash -c "npm i --silent --no-audit --no-fund playwright@$PW_VER >/dev/null 2>&1 && NODE_PATH=/tmp/node_modules node /work/browser-test.js $U /out '$1-$2'" \
      | tee "$T/pw.log" | tail -15
    ok "browser $1/$2" "grep -q '^BROWSER PASS' $T/pw.log"
  done
  [ -n "${SHOTS_DEST:-}" ] && { mkdir -p "$SHOTS_DEST"; cp "$OUT"/*.png "$SHOTS_DEST"/; ls "$SHOTS_DEST" | wc -l; }
fi

# rollback
run_nginx ready several
SNIPPET="$T/divi-swapd.conf" WWW="$T/www" NGINX_TEST=true NGINX_RELOAD=true "$D/site-install.sh" rollback --apply >/dev/null
ok "rollback restores the original snippet byte-for-byte" "cmp $T/orig.conf $T/divi-swapd.conf"
ok "rollback removes the site files" "[ ! -e $T/www/index.html ] && [ ! -e $T/www/site ]"
docker exec bq-nginx nginx -s reload >/dev/null 2>&1; sleep 1
ok "after rollback /swap/ reaches the mock, not the page" "curl -si $U/swap/ | tr -d '\r' | grep -qi '^x-mock-path: /\$'"
[ $fail = 0 ] && echo ALL PASS || { echo SOME FAILED; exit 1; }
