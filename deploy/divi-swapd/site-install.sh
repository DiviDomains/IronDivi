#!/usr/bin/env bash
# Install or roll back the read-only IronDivi Swaps website on the nginx host.
# Prints what it would do unless --apply is given. Run it ON the nginx host (needs root to apply).
#   site-install.sh install  [--apply]
#   site-install.sh rollback [--apply]
# Install backs up the live snippet, copies www/ to /var/www/divi-swap/, and APPENDS the marked block in
# site.fragment; the existing `location /swap/ { ... }` proxy block stays byte-identical.
# Rollback restores the backup, removes the site files, and reloads nginx.
set -euo pipefail

SNIPPET=${SNIPPET:-/etc/nginx/snippets/divi-swapd.conf}
WWW=${WWW:-/var/www/divi-swap}
BACKUP=${BACKUP:-$SNIPPET.pre-site}
HERE=$(cd "$(dirname "$0")" && pwd)
NGINX_TEST=${NGINX_TEST:-nginx -t}
NGINX_RELOAD=${NGINX_RELOAD:-systemctl reload nginx}

mode=${1:-}; apply=0
[ "${2:-}" = "--apply" ] && apply=1
run() { echo "+ $*"; [ "$apply" = 1 ] && eval "$@"; return 0; }

case "$mode" in
install)
  grep -q 'divi-swap website (read-only static site; BEGIN)' "$SNIPPET" 2>/dev/null && { echo "already installed in $SNIPPET"; exit 1; }
  [ -f "$BACKUP" ] && { echo "backup $BACKUP already exists; roll back or move it first"; exit 1; }
  run "cp -p '$SNIPPET' '$BACKUP'"
  run "install -d -m 0755 '$WWW' '$WWW/site'"
  run "install -m 0644 '$HERE/www/index.html' '$WWW/'"
  run "install -m 0644 '$HERE'/www/site/* '$WWW/site/'"
  echo "+ append $HERE/site.fragment to $SNIPPET"
  [ "$apply" = 1 ] && { echo; cat "$HERE/site.fragment"; } >> "$SNIPPET"
  if [ "$apply" = 1 ]; then
    if ! $NGINX_TEST; then echo "nginx -t failed: restoring the backup"; cp -p "$BACKUP" "$SNIPPET"; exit 1; fi
  else echo "+ $NGINX_TEST"; fi
  run "$NGINX_RELOAD"
  ;;
rollback)
  [ -f "$BACKUP" ] || { echo "no backup at $BACKUP"; exit 1; }
  run "cp -p '$BACKUP' '$SNIPPET'"
  run "$NGINX_TEST"
  run "$NGINX_RELOAD"
  run "rm -f '$WWW/index.html' && rm -rf '$WWW/site' && rmdir '$WWW' 2>/dev/null || true"
  run "rm -f '$BACKUP'"
  ;;
*) echo "usage: $0 install|rollback [--apply]"; exit 2 ;;
esac
[ "$apply" = 1 ] || echo "(dry run: nothing changed; add --apply)"
