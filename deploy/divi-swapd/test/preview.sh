#!/usr/bin/env bash
# Serves the site plus a mock divi-swapd on 127.0.0.1:18490 until Ctrl-C. Open it with: ssh -L 18490:127.0.0.1:18490 hp1
# then http://127.0.0.1:18490/swap/  Uses the real site-install.sh against a temp copy of the live snippet.
set -eu
D=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d); MOCK_PORT=18480
trap 'docker rm -f bq-preview >/dev/null 2>&1; kill $MOCK 2>/dev/null; rm -rf "$T"' EXIT
cp "$D/test/live-snippet.conf" "$T/divi-swapd.conf"
SNIPPET="$T/divi-swapd.conf" WWW="$T/www" NGINX_TEST=true NGINX_RELOAD=true "$D/site-install.sh" install --apply >/dev/null
printf 'events {}\nhttp { include /etc/nginx/mime.types; server { listen 127.0.0.1:18490; include /etc/nginx/snippets/divi-swapd.conf; } }\n' > "$T/nginx.conf"
python3 "$D/test/mock-swapd.py" $MOCK_PORT "${1:-ready}" "${2:-several}" & MOCK=$!
docker run --rm --name bq-preview --network host -v "$T/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$T/divi-swapd.conf:/etc/nginx/snippets/divi-swapd.conf:ro" -v "$T/www:/var/www/divi-swap:ro" nginx:1.27
