#!/usr/bin/env bash
# Safe, repeatable redeploy of divi-swapd to dnsdivi, run from the Mac (this cannot reach
# dnsdivi from hp2). Builds on `deploy/divi-swapd/deploy.sh`'s conventions (host alias
# `dnsdivi`, binary at /usr/local/bin/divi-swapd with a .prev backup, systemd unit
# `divi-swapd`, health at /healthz) but skips deploy.sh's slow "rsync source + build on
# dnsdivi" step: it builds (or takes a prebuilt) linux x86_64 binary and only ships that.
#
# Before touching anything, it reads the running maker's swap lists over an already-open
# tunnel and refuses to redeploy while any swap is not in a terminal state: `/swaps` entries
# must be `Done` or `Aborted` (docs/plans/swap-poc/wave4-deploy.md's own definition), and
# `/xmr/swaps` entries `done`, `aborted` or `punished` (XmrMakerState::is_terminal; a 404
# there means the maker runs no XMR engine). A restart mid-swap is a cut-over the old binary
# never had to survive.
#
#   tools/swap-poc/redeploy-maker.sh [--dry-run] [--check-only] [--force-inflight]
#     [--maker-url URL]            default http://127.0.0.1:18482 (tunnel to dnsdivi's API;
#                                   open it yourself, e.g. ssh -N -L 18482:127.0.0.1:18480 dnsdivi)
#     [--binary PATH]              use this prebuilt divi-swapd instead of building one
#     [--built-binary-path PATH]   where a remote-cargo build is expected to land
#                                   (default: <repo>/target/release/divi-swapd)
#     [--remote-cargo PATH]        remote-cargo executable (default: remote-cargo on PATH)
#     [--toml PATH]                also install this local file as the config (default: keep it)
#     [--unit PATH]                also install this local file as the unit (default: keep it)
#     [--host ALIAS]               ssh host alias (default: dnsdivi)
#     [--remote-port PORT]         maker's bind port on dnsdivi itself, for the post-restart
#                                   health check over ssh — NOT the tunnel port above
#                                   (default: 18480, matches deploy.sh and divi-swapd.service)
#     [--remote-bin PATH]          installed binary path on dnsdivi (default:
#                                   /usr/local/bin/divi-swapd)
#     [--remote-toml PATH]         installed config (default: /etc/divi-swapd/divi-swapd.toml)
#     [--remote-unit PATH]         installed unit (default: /etc/systemd/system/divi-swapd.service)
#     [--backup-dir PATH]          snapshot root on dnsdivi (default: /var/backups/divi-swapd)
#     [--service NAME]             systemd unit name (default: divi-swapd)
#     [--health-timeout SECONDS]   total time to wait for /healthz after restart (default: 300)
#     [--health-interval SECONDS]  poll interval while waiting (default: 5)
#
# --check-only runs just the in-flight gate (a real read against --maker-url) and exits with
# its verdict; nothing is built or installed. --dry-run prints every command, including the
# gate's, and runs none — it cannot tell you whether the gate would pass.
#
# Rollback set: before installing anything it snapshots the binary, config and unit together
# (all three must exist; run deploy.sh first otherwise) into <backup-dir>/<UTC timestamp>/
# with a SHA256SUMS manifest, then copies that snapshot to <backup-dir>/prev/ (the stable
# set) and the binary to <remote-bin>.prev as before. A failed health check restores all
# three from prev/, reloads systemd and restarts; tools/swap-poc/rollback-maker.sh does the
# same by hand (or from an older timestamp). The snapshot is whatever is on disk when this
# starts: a config edited by hand after the last restart is saved as if it were the running
# one, so ship config changes through --toml/--unit, not by editing in place.
#
# Needs: curl, jq, ssh (the `dnsdivi` alias), scp, and (unless --binary) `remote-cargo` on
# PATH. Any path above you cannot confirm for your environment is a flag with no silent
# fallback other than the ones named — pass it rather than trust the default.
set -euo pipefail

usage() {
  sed -n '15,40p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

MAKER_URL="http://127.0.0.1:18482"
FORCE_INFLIGHT=0
BINARY_PATH=""
BUILT_BINARY_PATH=""
REMOTE_CARGO="remote-cargo"
TOML_PATH=""
UNIT_PATH=""
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
CHECK_ONLY=0

while (($#)); do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --force-inflight) FORCE_INFLIGHT=1; shift ;;
    --maker-url) MAKER_URL="${2:?}"; shift 2 ;;
    --binary) BINARY_PATH="${2:?}"; shift 2 ;;
    --built-binary-path) BUILT_BINARY_PATH="${2:?}"; shift 2 ;;
    --remote-cargo) REMOTE_CARGO="${2:?}"; shift 2 ;;
    --toml) TOML_PATH="${2:?}"; shift 2 ;;
    --unit) UNIT_PATH="${2:?}"; shift 2 ;;
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

ROOT="$(git rev-parse --show-toplevel)"
[[ -n "$BUILT_BINARY_PATH" ]] || BUILT_BINARY_PATH="$ROOT/target/release/divi-swapd"
REMOTE_TMP=/tmp/divi-swapd.redeploy-new
REMOTE_TMP_TOML=/tmp/divi-swapd.redeploy-new.toml
REMOTE_TMP_UNIT=/tmp/divi-swapd.redeploy-new.service

step() { echo "==> $*"; }
run() {
  if ((DRY)); then printf '  [dry-run]'; printf ' %q' "$@"; echo; else "$@"; fi
}
# remote <script>: run a script on $HOST under sudo bash (script on stdin), matching
# deploy.sh's own remote() so operators reading both tools see the same shape.
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

# in_flight_ids: reads a /swaps JSON array on stdin, prints one non-terminal swap id per
# line. Terminal = state "Done" or "Aborted" (docs/plans/swap-poc/wave4-deploy.md §0/§5).
# Fails (jq's status) on anything that is not an array of swaps.
in_flight_ids() {
  jq -r '.[] | select(.state != "Done" and .state != "Aborted") | .id'
}

# xmr_in_flight_ids: the same for a /xmr/swaps array. Terminal = "done", "aborted" or
# "punished" (crates/divi-swap-xmr/src/maker.rs XmrMakerState::is_terminal; snake_case).
xmr_in_flight_ids() {
  jq -r '.[] | select(.state != "done" and .state != "aborted" and .state != "punished") | .id'
}

# unreadable <what> <detail>: the gate could not read a swap list. Returns 0 under
# --force-inflight (with a warning), 1 otherwise.
unreadable() {
  if ((FORCE_INFLIGHT)); then
    echo "WARN: could not read $1 ($2); proceeding anyway (--force-inflight)" >&2
    return 0
  fi
  echo "REFUSE: could not read $1 ($2); cannot confirm every swap is terminal." >&2
  echo "        Is the tunnel open? e.g. ssh -N -L 18482:127.0.0.1:$REMOTE_PORT $HOST" >&2
  echo "        Override with --force-inflight if you are certain it is safe." >&2
  return 1
}

# check_inflight: the safety gate. Returns 0 if it is safe to redeploy (every swap in both
# lists terminal, or --force-inflight), 1 otherwise. Always a real read, even under
# --check-only; under --dry-run it only prints what it would run.
check_inflight() {
  step "checking for in-flight swaps on the running maker ($MAKER_URL/swaps, $MAKER_URL/xmr/swaps)"
  if ((DRY)); then
    echo "  [dry-run] curl -fsS -m 20 $MAKER_URL/swaps"
    echo "  [dry-run] curl -sS -m 20 -w '%{http_code}' $MAKER_URL/xmr/swaps   (404 = no XMR engine)"
    echo "  [dry-run] refuse if any /swaps state is not Done/Aborted, or any /xmr/swaps state is"
    echo "            not done/aborted/punished, unless --force-inflight"
    return 0
  fi
  local swaps_json xmr_out xmr_code xmr_json ids xmr_ids="" n listed=""
  if ! swaps_json="$(curl -fsS -m 20 "$MAKER_URL/swaps" 2>&1)"; then
    unreadable "$MAKER_URL/swaps" "$swaps_json"
    return
  fi
  if ! ids="$(in_flight_ids <<<"$swaps_json" 2>&1)"; then
    unreadable "$MAKER_URL/swaps" "not a swap list: $ids"
    return
  fi

  # /xmr/swaps: -f would hide the 404 that means "no XMR engine", so read the status code.
  if ! xmr_out="$(curl -sS -m 20 -w '\n%{http_code}' "$MAKER_URL/xmr/swaps" 2>&1)"; then
    unreadable "$MAKER_URL/xmr/swaps" "$xmr_out"
    return
  fi
  xmr_code="${xmr_out##*$'\n'}"
  xmr_json="${xmr_out%$'\n'*}"
  case "$xmr_code" in
    200)
      if ! xmr_ids="$(xmr_in_flight_ids <<<"$xmr_json" 2>&1)"; then
        unreadable "$MAKER_URL/xmr/swaps" "not a swap list: $xmr_ids"
        return
      fi
      ;;
    404) echo "note: $MAKER_URL/xmr/swaps is 404 (no XMR engine configured); nothing to check there" ;;
    *)
      unreadable "$MAKER_URL/xmr/swaps" "HTTP $xmr_code: $xmr_json"
      return
      ;;
  esac

  [[ -z "$ids" ]] || listed+="$(sed 's/^/  \/swaps      /' <<<"$ids")"$'\n'
  [[ -z "$xmr_ids" ]] || listed+="$(sed 's/^/  \/xmr\/swaps  /' <<<"$xmr_ids")"$'\n'
  if [[ -z "$listed" ]]; then
    echo "ok: no in-flight swaps"
    return 0
  fi
  n="$(printf '%s' "$listed" | wc -l | tr -d ' ')"
  echo "in-flight swap(s) found ($n):"
  printf '%s' "$listed"
  if ((FORCE_INFLIGHT)); then
    echo "WARN: proceeding anyway (--force-inflight)" >&2
    return 0
  fi
  echo "REFUSE: $n swap(s) not in a terminal state (/swaps: Done/Aborted; /xmr/swaps:" \
    "done/aborted/punished). Rerun with --force-inflight to redeploy anyway." >&2
  return 1
}

((DRY)) && echo "DRY RUN: nothing below is executed (the in-flight check is only printed, not run)."

if ! check_inflight; then exit 1; fi
((CHECK_ONLY)) && exit 0

# --- acquire the binary -----------------------------------------------------------------
SRC_BIN=""
if [[ -n "$BINARY_PATH" ]]; then
  step "using prebuilt binary: $BINARY_PATH"
  if ((DRY)); then
    echo "  [dry-run] test -f $BINARY_PATH"
  else
    [[ -f "$BINARY_PATH" ]] || { echo "redeploy-maker: no file at $BINARY_PATH" >&2; exit 1; }
  fi
  SRC_BIN="$BINARY_PATH"
else
  step "building divi-swapd for linux x86_64 via $REMOTE_CARGO (expecting it at $BUILT_BINARY_PATH)"
  if ((DRY)); then
    echo "  [dry-run] (cd $ROOT && $REMOTE_CARGO build --release -p divi-swapd)"
  else
    command -v "$REMOTE_CARGO" >/dev/null 2>&1 || {
      echo "redeploy-maker: $REMOTE_CARGO not found on PATH (pass --binary <path>, or --remote-cargo <path>)" >&2
      exit 1
    }
    (cd "$ROOT" && "$REMOTE_CARGO" build --release -p divi-swapd)
    [[ -f "$BUILT_BINARY_PATH" ]] || {
      echo "redeploy-maker: build finished but no binary at $BUILT_BINARY_PATH" \
        "(pass --built-binary-path, or --binary <path> to skip the build)" >&2
      exit 1
    }
  fi
  SRC_BIN="$BUILT_BINARY_PATH"
fi
for f in "$TOML_PATH" "$UNIT_PATH"; do
  [[ -z "$f" || -f "$f" ]] || { echo "redeploy-maker: no file at $f" >&2; exit 1; }
done

# --- snapshot the running set ------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SNAP="$BACKUP_DIR/$TS"
step "snapshot $REMOTE_BIN, $REMOTE_TOML and $REMOTE_UNIT to $HOST:$SNAP (and $BACKUP_DIR/prev)"
remote "set -euo pipefail
for f in $REMOTE_BIN $REMOTE_TOML $REMOTE_UNIT; do
  [ -f \"\$f\" ] || { echo \"\$f missing: nothing complete to snapshot (run deploy.sh first)\" >&2; exit 1; }
done
install -d -m 0700 -o root -g root $BACKUP_DIR
[ ! -e $SNAP ] || { echo '$SNAP already exists' >&2; exit 1; }
mkdir -m 0700 $SNAP
cp -p $REMOTE_BIN $SNAP/divi-swapd
cp -p $REMOTE_TOML $SNAP/divi-swapd.toml
cp -p $REMOTE_UNIT $SNAP/divi-swapd.service
printf '%s\n' 'bin $REMOTE_BIN' 'toml $REMOTE_TOML' 'unit $REMOTE_UNIT' >$SNAP/TARGETS
(cd $SNAP && sha256sum divi-swapd divi-swapd.toml divi-swapd.service TARGETS >SHA256SUMS)
rm -rf $BACKUP_DIR/prev.new
cp -a $SNAP $BACKUP_DIR/prev.new
rm -rf $BACKUP_DIR/prev
mv $BACKUP_DIR/prev.new $BACKUP_DIR/prev
cp -p $REMOTE_BIN $REMOTE_BIN.prev
echo \"snapshot: $SNAP\""

# --- ship and install --------------------------------------------------------------------
step "copy $SRC_BIN to $HOST:$REMOTE_TMP"
run scp "$SRC_BIN" "$HOST:$REMOTE_TMP"
install_extra=""
if [[ -n "$TOML_PATH" ]]; then
  step "copy $TOML_PATH to $HOST:$REMOTE_TMP_TOML"
  run scp "$TOML_PATH" "$HOST:$REMOTE_TMP_TOML"
  # Same owner/group/mode as the file it replaces (deploy.sh: root:divi-swapd 0640).
  install_extra+="install -m 0640 -o root -g \"\$(stat -c %G $REMOTE_TOML)\" $REMOTE_TMP_TOML $REMOTE_TOML
rm -f $REMOTE_TMP_TOML
"
fi
if [[ -n "$UNIT_PATH" ]]; then
  step "copy $UNIT_PATH to $HOST:$REMOTE_TMP_UNIT"
  run scp "$UNIT_PATH" "$HOST:$REMOTE_TMP_UNIT"
  install_extra+="install -m 0644 -o root -g root $REMOTE_TMP_UNIT $REMOTE_UNIT
rm -f $REMOTE_TMP_UNIT
"
fi

step "install the new binary${TOML_PATH:+, config}${UNIT_PATH:+, unit} and restart $SERVICE"
remote "set -euo pipefail
test -s $REMOTE_TMP
${install_extra}install -m 0755 $REMOTE_TMP $REMOTE_BIN
rm -f $REMOTE_TMP
systemctl daemon-reload
systemctl restart $SERVICE"

# --- wait for health, roll back automatically on failure ---------------------------------
retries=$((HEALTH_TIMEOUT / HEALTH_INTERVAL))
health_cmd="curl -fsS --retry $retries --retry-connrefused --retry-delay $HEALTH_INTERVAL http://127.0.0.1:$REMOTE_PORT/healthz"
# Restores the prev/ set: verify the manifest, copy each file next to its target and rename
# over it (an in-place cp onto the running binary fails with "Text file busy").
restore_script="set -euo pipefail
P=$BACKUP_DIR/prev
for f in divi-swapd divi-swapd.toml divi-swapd.service SHA256SUMS; do
  [ -f \"\$P/\$f\" ] || { echo \"no complete rollback set in \$P (missing \$f): $SERVICE is left as is\" >&2; exit 1; }
done
(cd \$P && sha256sum -c --quiet SHA256SUMS)
cp -p \$P/divi-swapd $REMOTE_BIN.rollback
mv -f $REMOTE_BIN.rollback $REMOTE_BIN
cp -p \$P/divi-swapd.toml $REMOTE_TOML.rollback
mv -f $REMOTE_TOML.rollback $REMOTE_TOML
cp -p \$P/divi-swapd.service $REMOTE_UNIT.rollback
mv -f $REMOTE_UNIT.rollback $REMOTE_UNIT
systemctl daemon-reload
systemctl restart $SERVICE"
step "waiting for /healthz on $HOST (127.0.0.1:$REMOTE_PORT), up to ${HEALTH_TIMEOUT}s"
if ((DRY)); then
  echo "  [dry-run] ssh $HOST '$health_cmd'"
  echo "  [dry-run] on failure, restore binary + toml + unit from $BACKUP_DIR/prev:"
  remote "$restore_script"
  exit 0
fi

health_log="$(mktemp)"
trap 'rm -f "$health_log"' EXIT
# shellcheck disable=SC2029  # health_cmd is built client-side on purpose, as in deploy.sh
if ssh "$HOST" "$health_cmd" >"$health_log" 2>&1; then
  echo "ok: $SERVICE is healthy on the new binary (rollback set: $SNAP, $BACKUP_DIR/prev)"
  # shellcheck disable=SC2029  # built client-side on purpose
  ssh "$HOST" "sha256sum $REMOTE_BIN ${REMOTE_BIN}.prev 2>/dev/null" || true
  exit 0
fi

echo "FAIL: /healthz did not come up within ${HEALTH_TIMEOUT}s; rolling back binary + toml + unit" >&2
sed 's/^/  /' "$health_log" >&2 || true

rollback_status=0
remote "$restore_script" || rollback_status=$?

if ((rollback_status == 0)); then
  # shellcheck disable=SC2029  # built client-side on purpose
  if ssh "$HOST" "$health_cmd" >"$health_log" 2>&1; then
    echo "rolled back to the previous set ($SNAP); $SERVICE is healthy again" >&2
  else
    echo "rolled back to the previous set ($SNAP), but it is not healthy either; inspect $HOST manually" >&2
    sed 's/^/  /' "$health_log" >&2 || true
  fi
else
  echo "rollback itself failed; $SERVICE may be down on $HOST. Inspect manually:" >&2
  echo "  ssh $HOST sudo journalctl -u $SERVICE -n 50" >&2
fi
exit 1
