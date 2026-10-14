#!/usr/bin/env bash
# Restore divi-swapd on dnsdivi to a snapshot taken by tools/swap-poc/redeploy-maker.sh:
# binary, config and systemd unit together (never one without the others; a binary from
# before a config section exists silently ignores it, e.g. 0.2.6 and [xmr]), then
# daemon-reload, restart and wait for /healthz. Run from the Mac, like redeploy-maker.sh.
#
# A rollback restarts the maker, so it runs redeploy-maker.sh's in-flight gate first
# (`--check-only`, against /swaps and /xmr/swaps over the same tunnel). If the maker is down,
# the gate cannot read it and refuses: pass --force-inflight once you have checked by hand.
# The set it replaces is snapshotted first as <backup-dir>/<UTC timestamp>/, so a rollback
# can itself be undone with --to <that timestamp>; prev/ is left as it was.
#
#   tools/swap-poc/rollback-maker.sh [--dry-run] [--list] [--force-inflight]
#     [--to prev|TIMESTAMP]        snapshot to restore (default: prev, the set the last
#                                   redeploy replaced; TIMESTAMP as listed by --list)
#     [--maker-url URL]            default http://127.0.0.1:18482 (tunnel to dnsdivi's API)
#     [--host ALIAS]               ssh host alias (default: dnsdivi)
#     [--remote-port PORT]         maker's bind port on dnsdivi, for the health check (default: 18480)
#     [--remote-bin PATH]          installed binary (default: /usr/local/bin/divi-swapd)
#     [--remote-toml PATH]         installed config (default: /etc/divi-swapd/divi-swapd.toml)
#     [--remote-unit PATH]         installed unit (default: /etc/systemd/system/divi-swapd.service)
#     [--backup-dir PATH]          snapshot root on dnsdivi (default: /var/backups/divi-swapd)
#     [--service NAME]             systemd unit name (default: divi-swapd)
#     [--health-timeout SECONDS]   total time to wait for /healthz after restart (default: 300)
#     [--health-interval SECONDS]  poll interval while waiting (default: 5)
#
# --list prints the snapshots on the host and exits. --dry-run prints every command,
# including the gate's, and runs none (no ssh at all).
#
# Needs: curl, jq, ssh (the `dnsdivi` alias).
set -euo pipefail

usage() {
  sed -n '13,28p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAKER_URL="http://127.0.0.1:18482"
FORCE_INFLIGHT=0
TO=prev
LIST=0
HOST=dnsdivi
REMOTE_PORT=18480
REMOTE_BIN=/usr/local/bin/divi-swapd
REMOTE_TOML=/etc/divi-swapd/divi-swapd.toml
REMOTE_UNIT=/etc/systemd/system/divi-swapd.service
BACKUP_DIR=/var/backups/divi-swapd
SERVICE=divi-swapd
HEALTH_TIMEOUT=300
HEALTH_INTERVAL=5
DRY=0

while (($#)); do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --list) LIST=1; shift ;;
    --force-inflight) FORCE_INFLIGHT=1; shift ;;
    --to) TO="${2:?}"; shift 2 ;;
    --maker-url) MAKER_URL="${2:?}"; shift 2 ;;
    --host) HOST="${2:?}"; shift 2 ;;
    --remote-port) REMOTE_PORT="${2:?}"; shift 2 ;;
    --remote-bin) REMOTE_BIN="${2:?}"; shift 2 ;;
    --remote-toml) REMOTE_TOML="${2:?}"; shift 2 ;;
    --remote-unit) REMOTE_UNIT="${2:?}"; shift 2 ;;
    --backup-dir) BACKUP_DIR="${2:?}"; shift 2 ;;
    --service) SERVICE="${2:?}"; shift 2 ;;
    --health-timeout) HEALTH_TIMEOUT="${2:?}"; shift 2 ;;
    --health-interval) HEALTH_INTERVAL="${2:?}"; shift 2 ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
done

# --to goes into a root shell on the host: only the two shapes redeploy-maker.sh creates.
if [[ "$TO" != prev && ! "$TO" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
  echo "rollback-maker: --to must be 'prev' or a UTC timestamp like 20261014T120000Z (got: $TO)" >&2
  exit 2
fi

step() { echo "==> $*"; }
# remote <script>: as in redeploy-maker.sh and deploy.sh (script on stdin to sudo bash).
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

((DRY)) && echo "DRY RUN: nothing below is executed (the in-flight check is only printed, not run)."

if ((LIST)); then
  step "snapshots in $HOST:$BACKUP_DIR"
  remote "set -euo pipefail
cd $BACKUP_DIR
shopt -s nullglob
for d in */; do
  d=\${d%/}
  if (cd \$d && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1); then ok=complete; else ok=INCOMPLETE; fi
  echo \"\$d \$ok\"
done"
  exit 0
fi

# --- the in-flight gate (same as a redeploy's) ------------------------------------------
gate=("$HERE/redeploy-maker.sh" --check-only --maker-url "$MAKER_URL" --host "$HOST" --remote-port "$REMOTE_PORT")
((FORCE_INFLIGHT)) && gate+=(--force-inflight)
((DRY)) && gate+=(--dry-run)
"${gate[@]}" | grep -v '^DRY RUN:' || {
  # pipefail: the gate's own refusal fails the pipeline (grep only drops its duplicate banner).
  echo "rollback-maker: the in-flight gate refused; nothing was changed" >&2
  exit 1
}

# --- snapshot the current set, then restore the chosen one -------------------------------
SRC="$BACKUP_DIR/$TO"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SNAP="$BACKUP_DIR/$TS"
step "restore $REMOTE_BIN, $REMOTE_TOML and $REMOTE_UNIT from $HOST:$SRC" \
  "(current set saved first as $SNAP), daemon-reload, restart $SERVICE"
# Every file is checked before any is touched; each is copied next to its target and renamed
# over it (an in-place cp onto the running binary fails with "Text file busy").
remote "set -euo pipefail
for f in divi-swapd divi-swapd.toml divi-swapd.service SHA256SUMS; do
  [ -f $SRC/\$f ] || { echo \"$SRC is not a complete snapshot (missing \$f); nothing changed\" >&2; exit 1; }
done
(cd $SRC && sha256sum -c --quiet SHA256SUMS)
[ ! -e $SNAP ] || { echo '$SNAP already exists' >&2; exit 1; }
mkdir -m 0700 $SNAP
cp -p $REMOTE_BIN $SNAP/divi-swapd
cp -p $REMOTE_TOML $SNAP/divi-swapd.toml
cp -p $REMOTE_UNIT $SNAP/divi-swapd.service
printf '%s\n' 'bin $REMOTE_BIN' 'toml $REMOTE_TOML' 'unit $REMOTE_UNIT' >$SNAP/TARGETS
(cd $SNAP && sha256sum divi-swapd divi-swapd.toml divi-swapd.service TARGETS >SHA256SUMS)
cp -p $SRC/divi-swapd $REMOTE_BIN.rollback
mv -f $REMOTE_BIN.rollback $REMOTE_BIN
cp -p $SRC/divi-swapd.toml $REMOTE_TOML.rollback
mv -f $REMOTE_TOML.rollback $REMOTE_TOML
cp -p $SRC/divi-swapd.service $REMOTE_UNIT.rollback
mv -f $REMOTE_UNIT.rollback $REMOTE_UNIT
systemctl daemon-reload
systemctl restart $SERVICE
echo \"restored $SRC; previous set saved as $SNAP\""

# --- wait for health ----------------------------------------------------------------------
retries=$((HEALTH_TIMEOUT / HEALTH_INTERVAL))
health_cmd="curl -fsS --retry $retries --retry-connrefused --retry-delay $HEALTH_INTERVAL http://127.0.0.1:$REMOTE_PORT/healthz"
step "waiting for /healthz on $HOST (127.0.0.1:$REMOTE_PORT), up to ${HEALTH_TIMEOUT}s"
if ((DRY)); then
  echo "  [dry-run] ssh $HOST '$health_cmd'"
  exit 0
fi
# shellcheck disable=SC2029  # health_cmd is built client-side on purpose, as in deploy.sh
if ssh "$HOST" "$health_cmd"; then
  echo
  echo "ok: $SERVICE is healthy on $SRC (undo with --to $TS)"
  exit 0
fi
echo "FAIL: /healthz did not come up within ${HEALTH_TIMEOUT}s on $SRC. Inspect manually:" >&2
echo "  ssh $HOST sudo journalctl -u $SERVICE -n 50" >&2
echo "  (the set this replaced is $SNAP: --to $TS puts it back)" >&2
exit 1
