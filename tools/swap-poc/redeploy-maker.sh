#!/usr/bin/env bash
# Safe, repeatable redeploy of divi-swapd to dnsdivi, run from the Mac (this cannot reach
# dnsdivi from hp2). Builds on `deploy/divi-swapd/deploy.sh`'s conventions (host alias
# `dnsdivi`, binary at /usr/local/bin/divi-swapd with a .prev backup, systemd unit
# `divi-swapd`, health at /healthz) but skips deploy.sh's slow "rsync source + build on
# dnsdivi" step: it builds (or takes a prebuilt) linux x86_64 binary and only ships that.
#
# Before touching anything, it reads the running maker's swap list over an already-open
# tunnel and refuses to redeploy while any swap is not in a terminal state (`Done` or
# `Aborted` — docs/plans/swap-poc/wave4-deploy.md's own definition), since the new binary
# cannot know about in-flight HTLCs cut over mid-poll in ways the old one would have.
#
#   tools/swap-poc/redeploy-maker.sh [--dry-run] [--check-only] [--force-inflight]
#     [--maker-url URL]            default http://127.0.0.1:18482 (tunnel to dnsdivi's API;
#                                   open it yourself, e.g. ssh -N -L 18482:127.0.0.1:18480 dnsdivi)
#     [--binary PATH]              use this prebuilt divi-swapd instead of building one
#     [--built-binary-path PATH]   where a remote-cargo build is expected to land
#                                   (default: <repo>/target/release/divi-swapd)
#     [--remote-cargo PATH]        remote-cargo executable (default: remote-cargo on PATH)
#     [--host ALIAS]               ssh host alias (default: dnsdivi)
#     [--remote-port PORT]         maker's bind port on dnsdivi itself, for the post-restart
#                                   health check over ssh — NOT the tunnel port above
#                                   (default: 18480, matches deploy.sh and divi-swapd.service)
#     [--remote-bin PATH]          installed binary path on dnsdivi (default:
#                                   /usr/local/bin/divi-swapd)
#     [--service NAME]             systemd unit name (default: divi-swapd)
#     [--health-timeout SECONDS]   total time to wait for /healthz after restart (default: 300)
#     [--health-interval SECONDS]  poll interval while waiting (default: 5)
#
# --check-only runs just the in-flight gate (a real read against --maker-url) and exits with
# its verdict; nothing is built or installed. --dry-run prints every command, including the
# gate's, and runs none — it cannot tell you whether the gate would pass.
#
# Needs: curl, jq, ssh (the `dnsdivi` alias), scp, and (unless --binary) `remote-cargo` on
# PATH. Any path above you cannot confirm for your environment is a flag with no silent
# fallback other than the ones named — pass it rather than trust the default.
set -euo pipefail

usage() {
  sed -n '12,33p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

MAKER_URL="http://127.0.0.1:18482"
FORCE_INFLIGHT=0
BINARY_PATH=""
BUILT_BINARY_PATH=""
REMOTE_CARGO="remote-cargo"
HOST=dnsdivi
REMOTE_PORT=18480
REMOTE_BIN=/usr/local/bin/divi-swapd
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
    --host) HOST="${2:?}"; shift 2 ;;
    --remote-port) REMOTE_PORT="${2:?}"; shift 2 ;;
    --remote-bin) REMOTE_BIN="${2:?}"; shift 2 ;;
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
in_flight_ids() {
  jq -r '.[] | select(.state != "Done" and .state != "Aborted") | .id'
}

# check_inflight: the safety gate. Returns 0 if it is safe to redeploy (every swap terminal,
# or --force-inflight), 1 otherwise. Always a real read, even under --check-only; under
# --dry-run it only prints what it would run.
check_inflight() {
  step "checking for in-flight swaps on the running maker ($MAKER_URL/swaps)"
  if ((DRY)); then
    echo "  [dry-run] curl -fsS -m 20 $MAKER_URL/swaps"
    echo "  [dry-run] refuse if any swap's state is not Done/Aborted, unless --force-inflight"
    return 0
  fi
  local swaps_json ids n
  if ! swaps_json="$(curl -fsS -m 20 "$MAKER_URL/swaps" 2>&1)"; then
    if ((FORCE_INFLIGHT)); then
      echo "WARN: could not read $MAKER_URL/swaps ($swaps_json); proceeding anyway (--force-inflight)" >&2
      return 0
    fi
    echo "REFUSE: could not read $MAKER_URL/swaps ($swaps_json); cannot confirm every swap is terminal." >&2
    echo "        Is the tunnel open? e.g. ssh -N -L 18482:127.0.0.1:$REMOTE_PORT $HOST" >&2
    echo "        Override with --force-inflight if you are certain it is safe." >&2
    return 1
  fi
  ids="$(in_flight_ids <<<"$swaps_json")"
  if [[ -z "$ids" ]]; then
    echo "ok: no in-flight swaps"
    return 0
  fi
  n="$(wc -l <<<"$ids" | tr -d ' ')"
  echo "in-flight swap(s) found ($n):"
  while IFS= read -r id; do echo "  $id"; done <<<"$ids"
  if ((FORCE_INFLIGHT)); then
    echo "WARN: proceeding anyway (--force-inflight)" >&2
    return 0
  fi
  echo "REFUSE: $n swap(s) not in a terminal state (Done/Aborted). Rerun with --force-inflight" \
    "to redeploy anyway." >&2
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

# --- ship and install --------------------------------------------------------------------
step "copy $SRC_BIN to $HOST:$REMOTE_TMP"
run scp "$SRC_BIN" "$HOST:$REMOTE_TMP"

step "install binary (keeping the previous as .prev) and restart $SERVICE"
remote "test -s $REMOTE_TMP
[ ! -f $REMOTE_BIN ] || cp -p $REMOTE_BIN $REMOTE_BIN.prev
install -m 0755 $REMOTE_TMP $REMOTE_BIN
rm -f $REMOTE_TMP
systemctl restart $SERVICE"

# --- wait for health, roll back automatically on failure ---------------------------------
retries=$((HEALTH_TIMEOUT / HEALTH_INTERVAL))
health_cmd="curl -fsS --retry $retries --retry-connrefused --retry-delay $HEALTH_INTERVAL http://127.0.0.1:$REMOTE_PORT/healthz"
step "waiting for /healthz on $HOST (127.0.0.1:$REMOTE_PORT), up to ${HEALTH_TIMEOUT}s"
if ((DRY)); then
  echo "  [dry-run] ssh $HOST '$health_cmd'"
  echo "  [dry-run] on failure: cp -p $REMOTE_BIN.prev $REMOTE_BIN && systemctl restart $SERVICE"
  exit 0
fi

health_log="$(mktemp)"
trap 'rm -f "$health_log"' EXIT
# shellcheck disable=SC2029  # health_cmd is built client-side on purpose, as in deploy.sh
if ssh "$HOST" "$health_cmd" >"$health_log" 2>&1; then
  echo "ok: $SERVICE is healthy on the new binary"
  # shellcheck disable=SC2029  # built client-side on purpose
  ssh "$HOST" "sha256sum $REMOTE_BIN ${REMOTE_BIN}.prev 2>/dev/null" || true
  exit 0
fi

echo "FAIL: /healthz did not come up within ${HEALTH_TIMEOUT}s; rolling back" >&2
sed 's/^/  /' "$health_log" >&2 || true

rollback_status=0
remote "if [ ! -f $REMOTE_BIN.prev ]; then
  echo 'no .prev to roll back to (first deploy?): $SERVICE is left on the new, unhealthy binary' >&2
  exit 1
fi
cp -p $REMOTE_BIN.prev $REMOTE_BIN
systemctl restart $SERVICE" || rollback_status=$?

if ((rollback_status == 0)); then
  # shellcheck disable=SC2029  # built client-side on purpose
  if ssh "$HOST" "$health_cmd" >"$health_log" 2>&1; then
    echo "rolled back to the previous binary; $SERVICE is healthy again" >&2
  else
    echo "rolled back to the previous binary, but it is not healthy either; inspect $HOST manually" >&2
    sed 's/^/  /' "$health_log" >&2 || true
  fi
else
  echo "rollback itself failed; $SERVICE may be down on $HOST. Inspect manually:" >&2
  echo "  ssh $HOST sudo journalctl -u $SERVICE -n 50" >&2
fi
exit 1
