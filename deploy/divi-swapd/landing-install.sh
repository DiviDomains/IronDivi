#!/usr/bin/env bash
# Install or roll back the read-only /swap/ landing page on the nginx host.
# Prints what it would do unless --apply is given. Run it ON the nginx host (needs root to apply).
#   landing-install.sh install  [--apply]
#   landing-install.sh rollback [--apply]
# Only the marked landing block is added to the live snippet; the existing `location /swap/ { ... }`
# proxy block is left byte-identical (it is NOT replaced by the repo nginx-swap.conf).
set -euo pipefail

SNIPPET=${SNIPPET:-/etc/nginx/snippets/divi-swapd.conf}
WWW=${WWW:-/var/www/divi-swap}
BACKUP=${BACKUP:-$SNIPPET.pre-landing}
HERE=$(cd "$(dirname "$0")" && pwd)
NGINX_TEST=${NGINX_TEST:-nginx -t}
NGINX_RELOAD=${NGINX_RELOAD:-systemctl reload nginx}

mode=${1:-}; apply=0
[ "${2:-}" = "--apply" ] && apply=1
run() { echo "+ $*"; [ "$apply" = 1 ] && eval "$@"; return 0; }

case "$mode" in
install)
  grep -q 'divi-swap landing page (BEGIN)' "$SNIPPET" 2>/dev/null && { echo "already installed in $SNIPPET"; exit 1; }
  run "install -d -m 0755 '$WWW'"
  run "install -m 0644 '$HERE/www/index.html' '$HERE/www/landing.js' '$HERE/www/landing.css' '$WWW/'"
  run "cp -p '$SNIPPET' '$BACKUP'"
  echo "+ append $HERE/landing.fragment to $SNIPPET"
  [ "$apply" = 1 ] && { echo; cat "$HERE/landing.fragment"; } >> "$SNIPPET"
  run "$NGINX_TEST"
  run "$NGINX_RELOAD"
  ;;
rollback)
  [ -f "$BACKUP" ] || { echo "no backup at $BACKUP"; exit 1; }
  run "cp -p '$BACKUP' '$SNIPPET'"
  run "$NGINX_TEST"
  run "$NGINX_RELOAD"
  echo "(page files in $WWW are inert once the locations are gone; remove with: rm -r $WWW)"
  ;;
*) echo "usage: $0 install|rollback [--apply]"; exit 2 ;;
esac
[ "$apply" = 1 ] || echo "(dry run: nothing changed; add --apply)"
