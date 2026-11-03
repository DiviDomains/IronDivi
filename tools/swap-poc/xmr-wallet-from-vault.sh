#!/usr/bin/env bash
# xmr-wallet-from-vault.sh — open an XMR swap wallet from its 1Password seed, on the Mac, in RAM only
# (plan row B5, docs/plans/swap-poc/xmr-wallet-from-vault.md).
#
# Starts a monero-wallet-rpc whose --wallet-dir is a RAM disk, restores the wallet from the vault
# seed over the RPC body on localhost, prints the address and height, then stays up (the taker and
# xmr-soak.sh talk to 127.0.0.1:<port>). On exit, success, failure or signal, the trap closes the
# wallet, stops wallet-rpc and wipes and detaches the RAM disk. Nothing of the wallet persists.
#
# Seed safety (secret-management.md §2): the seed comes from `secret get` into a shell variable and
# leaves it only inside the body of one POST on 127.0.0.1, fed to curl on stdin by a shell builtin.
# It is never in argv, a file, an environment variable, stdout, stderr or a log. The wallet file
# password is random per run and never stored, so a leftover .keys would not open either.
#
#   xmr-wallet-from-vault.sh --restore-height N [--network stagenet|testnet|mainnet] [--port 38088]
#       [--daemon-address HOST:PORT] [--ramdisk-mb 256] [--once] [--dry-run]
#       [--rpc-user-ref REF] [--rpc-pass-ref REF] [--seed-ref REF] [--item NAME]
#   xmr-wallet-from-vault.sh --self-test      # mock secret + mock wallet-rpc, see below
#
#   --once      restore, print, then exit (the trap wipes everything); default is to stay up
#   --dry-run   print the plan; no secret call, no process, no RAM disk
#   mainnet needs XMR_VAULT_ALLOW_MAINNET=1 in the environment.
#
# Exit: 0 ok, 2 bad usage, 3 missing tool, 9 secret unavailable, 10 wallet-rpc failed.
set -euo pipefail

NETWORK=stagenet PORT=38088 DAEMON="" HEIGHT="" MB=256 ONCE=0 DRY=0 ITEM="" SEED_REF=""
USER_REF="op://global_secret_store/IronDivi Swap POC - taker-xmr-wallet-rpc/username"
PASS_REF="op://global_secret_store/IronDivi Swap POC - taker-xmr-wallet-rpc/password"
SELF="${BASH_SOURCE[0]}"

usage() { sed -n '2,/^set -/p' "$SELF" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() { echo "xmr-wallet-from-vault: $*" >&2; exit "${2:-2}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --network) NETWORK="${2:?--network needs a value}"; shift 2;;
    --port) PORT="${2:?--port needs a value}"; shift 2;;
    --daemon-address) DAEMON="${2:?--daemon-address needs a value}"; shift 2;;
    --restore-height) HEIGHT="${2:?--restore-height needs a value}"; shift 2;;
    --ramdisk-mb) MB="${2:?--ramdisk-mb needs a value}"; shift 2;;
    --item) ITEM="${2:?--item needs a value}"; shift 2;;
    --seed-ref) SEED_REF="${2:?--seed-ref needs a value}"; shift 2;;
    --rpc-user-ref) USER_REF="${2:?--rpc-user-ref needs a value}"; shift 2;;
    --rpc-pass-ref) PASS_REF="${2:?--rpc-pass-ref needs a value}"; shift 2;;
    --once) ONCE=1; shift;;
    --dry-run) DRY=1; shift;;
    --self-test) exec "$(dirname "$SELF")/test-xmr-wallet-from-vault.sh";;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1 (try --help)";;
  esac
done

case "$NETWORK" in
  stagenet) NETFLAG=(--stagenet); : "${DAEMON:=node.monerodevs.org:38089}";;
  testnet)  NETFLAG=(--testnet);  : "${DAEMON:=127.0.0.1:28081}";;
  mainnet)  NETFLAG=(); : "${DAEMON:=127.0.0.1:18081}"
            [ "${XMR_VAULT_ALLOW_MAINNET:-}" = 1 ] || die "mainnet needs XMR_VAULT_ALLOW_MAINNET=1";;
  *) die "unknown network: $NETWORK (stagenet|testnet|mainnet)";;
esac
[ -n "$ITEM" ] || ITEM="divi_xmr_swap_$NETWORK"
[ -n "$SEED_REF" ] || SEED_REF="op://global_secret_store/$ITEM/seed_phrase"
case "$HEIGHT" in ''|*[!0-9]*) die "--restore-height N (digits) is required";; esac
case "$PORT$MB" in ''|*[!0-9]*) die "--port and --ramdisk-mb must be numbers";; esac

if [ "$DRY" = 1 ]; then
  cat <<EOF
plan (dry run, no secret call, nothing started):
  network        $NETWORK   daemon $DAEMON   restore height $HEIGHT
  ram disk       ${MB} MB ($(uname -s): $([ "$(uname -s)" = Darwin ] && echo 'hdiutil ram:// + newfs_hfs' || echo '/dev/shm dir'))
  wallet-rpc     127.0.0.1:$PORT, --wallet-dir on the ram disk, login from config file on the ram disk
  secret get     seed $SEED_REF; rpc login $USER_REF , $PASS_REF
  restore        restore_deterministic_wallet name=swap, random per-run file password, seed in the POST body only
  print          address and height only
  on exit        close_wallet, stop wallet-rpc, rm wallet dir, detach ram disk$([ "$ONCE" = 1 ] && echo '; --once: exit right after printing')
EOF
  exit 0
fi

for t in secret monero-wallet-rpc curl openssl; do
  command -v "$t" >/dev/null || die "missing tool: $t" 3
done

umask 077
DEV="" MNT="" RPC_PID=""
RPC="http://127.0.0.1:$PORT/json_rpc"

cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  set +e
  if [ -n "$MNT" ] && [ -f "$MNT/curl.cfg" ]; then
    curl -sS -m 10 -K "$MNT/curl.cfg" --digest -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"close_wallet"}' "$RPC" >/dev/null 2>&1
  fi
  if [ -n "$RPC_PID" ]; then
    kill "$RPC_PID" 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$RPC_PID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$RPC_PID" 2>/dev/null
    wait "$RPC_PID" 2>/dev/null
  fi
  if [ -n "$MNT" ]; then
    rm -rf "${MNT:?}"/* "${MNT:?}"/.[!.]* 2>/dev/null
    if [ -n "$DEV" ]; then
      umount "$MNT" 2>/dev/null || hdiutil detach -force "$DEV" >/dev/null 2>&1
      hdiutil detach -force "$DEV" >/dev/null 2>&1
    fi
    rmdir "$MNT" 2>/dev/null
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# RAM-backed directory, 0700. Darwin: a hdiutil RAM disk formatted HFS+ and mounted nobrowse.
# Anywhere else (the hp1 self-test): a dir under /dev/shm.
if [ "$(uname -s)" = Darwin ]; then
  MNT="$(mktemp -d "${TMPDIR:-/tmp}/xmrvault.XXXXXX")"
  DEV="$(hdiutil attach -nomount "ram://$((MB * 2048))" | awk '{print $1; exit}')"
  [ -n "$DEV" ] || die "could not create the RAM disk" 10
  newfs_hfs -v xmrvault "$DEV" >/dev/null
  mount -t hfs -o nobrowse,noowners "$DEV" "$MNT"
else
  MNT="$(mktemp -d "${XMR_VAULT_SHM:-/dev/shm}/xmrvault.XXXXXX")"
fi
chmod 700 "$MNT"
mkdir "$MNT/w"

# RPC login and the wallet file password. The login is the vault's taker-xmr-wallet-rpc pair, so the
# taker and xmr-soak.sh need no change. The wallet password is random per run and never kept.
rpc_user="$(secret get --name taker-xmr-wallet-rpc-username --op-ref "$USER_REF" </dev/null)" \
  || die "rpc user unavailable (broker down? secret-broker status)" 9
rpc_pass="$(secret get --name taker-xmr-wallet-rpc-password --op-ref "$PASS_REF" </dev/null)" \
  || die "rpc password unavailable" 9
wpass="$(openssl rand -hex 24)"
# Both files live on the RAM disk. Neither login nor password reaches argv.
printf 'rpc-login=%s:%s\n' "$rpc_user" "$rpc_pass" > "$MNT/rpc.conf"
printf 'user = "%s:%s"\n' "$rpc_user" "$rpc_pass" > "$MNT/curl.cfg"
unset rpc_user rpc_pass

monero-wallet-rpc ${NETFLAG[@]+"${NETFLAG[@]}"} --daemon-address "$DAEMON" \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port "$PORT" --wallet-dir "$MNT/w" \
  --config-file "$MNT/rpc.conf" --log-file "$MNT/rpc.log" --log-level 0 \
  --non-interactive >/dev/null 2>&1 &
RPC_PID=$!

rpc() { # rpc <json body on stdin> -> response on stdout
  curl -sS -m 120 -K "$MNT/curl.cfg" --digest -H 'Content-Type: application/json' \
    --data-binary @- "$RPC"
}

up=0
for _ in $(seq 1 60); do
  kill -0 "$RPC_PID" 2>/dev/null || die "wallet-rpc exited before it answered" 10
  if printf '%s' '{"jsonrpc":"2.0","id":"0","method":"get_version"}' | rpc >/dev/null 2>&1; then up=1; break; fi
  sleep 0.5
done
[ "$up" = 1 ] || die "wallet-rpc did not answer on 127.0.0.1:$PORT" 10

seed="$(secret get --name "$ITEM" --op-ref "$SEED_REF" </dev/null)" \
  || die "seed unavailable (broker down? secret-broker status)" 9
case "$seed" in ''|*[!a-z\ ]*) unset seed; die "seed from the vault is not 25 lowercase words" 9;; esac
resp="$(printf '{"jsonrpc":"2.0","id":"0","method":"restore_deterministic_wallet","params":{"filename":"swap","password":"%s","seed":"%s","restore_height":%s,"language":"English"}}' \
  "$wpass" "$seed" "$HEIGHT" | rpc)" || { unset seed; die "restore call failed" 10; }
unset seed wpass
case "$resp" in *'"error"'*) die "wallet-rpc refused the restore" 10;; esac

addr="$(printf '%s' '{"jsonrpc":"2.0","id":"0","method":"get_address"}' | rpc | tr -d ' \n' | sed -n 's/.*"address":"\([^"]*\)".*/\1/p')"
hgt="$(printf '%s' '{"jsonrpc":"2.0","id":"0","method":"get_height"}' | rpc | tr -d ' \n' | sed -n 's/.*"height":\([0-9]*\).*/\1/p')"
[ -n "$addr" ] || die "no address from wallet-rpc" 10
echo "address $addr"
echo "height ${hgt:-unknown}"

if [ "$ONCE" = 1 ]; then exit 0; fi
echo "wallet open on 127.0.0.1:$PORT; Ctrl-C closes it and wipes the RAM disk" >&2
wait "$RPC_PID" || true
