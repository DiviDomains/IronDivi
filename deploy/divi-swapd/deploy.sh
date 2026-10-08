#!/usr/bin/env bash
# Idempotent deploy of divi-swapd to dnsdivi. Run from anywhere inside the repo.
#   deploy.sh [--dry-run] [deploy]       build on dnsdivi, install, restart, health-check
#   deploy.sh [--dry-run] provision-secrets   copy keys from 1Password to dnsdivi (stdin, never argv)
#   deploy.sh [--dry-run] rollback       restore the previous binary
# SSH goes only through the `dnsdivi` host alias.
set -euo pipefail

HOST=dnsdivi
SRC_DIR=/opt/divi-swapd/src
SVC=divi-swapd
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DRY=0
CMD=deploy

for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    deploy | provision-secrets | rollback) CMD="$a" ;;
    *) echo "usage: $0 [--dry-run] [deploy|provision-secrets|rollback]" >&2; exit 2 ;;
  esac
done

# Secret refs (not secret); written to dnsdivi as credential files.
# One "name|ref" per line (bash 3.2 on macOS has no associative arrays).
CRED_REFS="maker-divi|op://global_secret_store/IronDivi Swap POC - maker-divi/password
maker-btc|op://global_secret_store/IronDivi Swap POC - maker-btc/password"

step() { echo "==> $*"; }
run() {
  if ((DRY)); then echo "  [dry-run] $*"; else "$@"; fi
}
# remote <script>: run a script on dnsdivi under sudo bash (script on stdin).
remote() {
  local script="$1"
  if ((DRY)); then
    echo "  [dry-run] ssh $HOST sudo bash -s <<'SCRIPT'"
    while IFS= read -r line; do echo "      $line"; done <<<"$script"
    echo "  [dry-run] SCRIPT"
  else
    ssh "$HOST" sudo bash -s <<<"$script"
  fi
}

((DRY)) && echo "DRY RUN: nothing below is executed."

provision_secrets() {
  step "provision secrets to $HOST:/etc/divi-swapd/credentials (root:root 0400)"
  remote 'install -d -m 0700 -o root -g root /etc/divi-swapd /etc/divi-swapd/credentials'
  local name ref dest rcmd
  while IFS='|' read -r name ref; do
    dest="/etc/divi-swapd/credentials/$name"
    rcmd="sudo sh -c 'umask 0377 && cat > $dest' && sudo chown root:root $dest && sudo chmod 0400 $dest"
    if ((DRY)); then
      echo "  [dry-run] op read --no-newline '$ref' | ssh $HOST \"$rcmd\""
    else
      # Value flows op -> pipe -> ssh stdin; never argv, never a local file.
      # shellcheck disable=SC2029  # rcmd is built client-side on purpose
      op read --no-newline "$ref" </dev/null | ssh "$HOST" "$rcmd"
    fi
  done <<<"$CRED_REFS"
}

deploy() {
  step "sync source to $HOST:$SRC_DIR"
  remote "install -d -o ubuntu -g ubuntu $(dirname "$SRC_DIR") $SRC_DIR"
  run rsync -az --delete --exclude target --exclude .git "$REPO/" "$HOST:$SRC_DIR/"

  step "build release on $HOST (needs rustup toolchain for ubuntu)"
  if ((DRY)); then echo "  [dry-run] ssh $HOST 'cd $SRC_DIR && cargo build --release -p divi-swapd'"
  else
    # shellcheck disable=SC2029  # SRC_DIR is expanded client-side on purpose
    ssh "$HOST" "cd $SRC_DIR && cargo build --release -p divi-swapd"
  fi

  step "create service user and directories"
  remote "id -u $SVC >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin $SVC
install -d -m 0750 -o root -g $SVC /etc/divi-swapd
install -d -m 0700 -o root -g root /etc/divi-swapd/credentials"

  step "install binary (keeping previous as .prev) and config"
  remote "[ ! -f /usr/local/bin/divi-swapd ] || cp -p /usr/local/bin/divi-swapd /usr/local/bin/divi-swapd.prev
install -m 0755 $SRC_DIR/target/release/divi-swapd /usr/local/bin/divi-swapd
[ -f /etc/divi-swapd/divi-swapd.toml ] || install -m 0640 -o root -g $SVC $SRC_DIR/deploy/divi-swapd/divi-swapd.toml.example /etc/divi-swapd/divi-swapd.toml"

  step "install systemd unit, logrotate, nginx snippet"
  remote "install -m 0644 $SRC_DIR/deploy/divi-swapd/divi-swapd.service /etc/systemd/system/divi-swapd.service
install -m 0644 $SRC_DIR/deploy/divi-swapd/logrotate-divi-swapd /etc/logrotate.d/divi-swapd
install -m 0644 $SRC_DIR/deploy/divi-swapd/nginx-swap.conf /etc/nginx/snippets/divi-swapd.conf
nginx -t
systemctl daemon-reload"

  step "check credentials exist before starting"
  remote 'test -s /etc/divi-swapd/credentials/maker-divi && test -s /etc/divi-swapd/credentials/maker-btc || { echo "credentials missing: run deploy.sh provision-secrets" >&2; exit 1; }'

  step "start service and reload nginx"
  remote "systemctl enable $SVC
systemctl restart $SVC
systemctl reload nginx"

  step "health check"
  if ((DRY)); then echo "  [dry-run] ssh $HOST 'curl -fsS --retry 5 --retry-connrefused --retry-delay 2 http://127.0.0.1:18480/healthz'"
  else ssh "$HOST" "curl -fsS --retry 5 --retry-connrefused --retry-delay 2 http://127.0.0.1:18480/healthz"; echo; fi
  echo "Then verify the public path: curl https://<dnsdivi-host>/swap/healthz (nginx snippet must be included in the server block once)."
}

rollback() {
  step "restore previous binary"
  remote "test -f /usr/local/bin/divi-swapd.prev
cp -p /usr/local/bin/divi-swapd.prev /usr/local/bin/divi-swapd
systemctl restart $SVC"
}

case "$CMD" in
  deploy) deploy ;;
  provision-secrets) provision_secrets ;;
  rollback) rollback ;;
esac
