#!/bin/bash
# swap-watch.sh — Telegram DM to Bert when the swap maker (divi-swapd) is unhealthy or a swap is
# stuck, and once when everything is healthy again. Run every 5 minutes by swap-watch.timer.
# Modelled on fork-watch.sh (same bot, same send/repeat rules). Plan item B2 in
# docs/plans/swap-poc/xmr-mainnet-plan.md.
#
# Checks:
#   - the units in UNITS are active (divi-swapd, monerod-stagenet);
#   - GET /healthz answers ok, and its divi_scan is not still scanning SCAN_MAX seconds after the
#     daemon started;
#   - no swap (hashlock /swaps or XMR /xmr/swaps) has had the same last_error for two runs in a row
#     (one run's error is usually transient: a node timeout the next poll retries);
#   - no non-terminal swap has sat in the same state for longer than its limit: ACCEPTED_MAX for
#     an XMR swap in `accepted` (nothing locked yet; the maker forgets it after sigs_wait),
#     STUCK_MAX for every other non-terminal state (default 12 h: longer than t_cancel +
#     t_punish on the testnet profile, so a healthy refund path never fires it).
#   - no `cancelled`/`refunded` XMR swap is within PUNISH_MARGIN (default 1 h) of its t_punish:
#     past it the taker can take the DIVI;
#   - monerod's RPC answers and is synchronized (when MONEROD_URL is set).
# Secrets: /etc/swap-watch.env (root 0600): TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID. Never logged.
# State: /var/lib/swap-watch (when each swap entered its state; the last alert).
#
#   swap-watch.sh          one check
#   swap-watch.sh test     send a test message and exit
#   swap-watch.sh dry-run  print the problems it would alert on, send nothing, change no state

set -u
API="${API:-http://127.0.0.1:18480}"
MONEROD_URL="${MONEROD_URL-http://127.0.0.1:38089}"
UNITS="${UNITS:-divi-swapd monerod-stagenet}"
SCAN_MAX="${SCAN_MAX:-3600}"
ACCEPTED_MAX="${ACCEPTED_MAX:-3600}"
STUCK_MAX="${STUCK_MAX:-43200}"
PUNISH_MARGIN="${PUNISH_MARGIN:-3600}"
ALERT_EVERY="${ALERT_EVERY:-21600}"
STATE_DIR="${STATE_DIR:-/var/lib/swap-watch}"
ENV_FILE="${ENV_FILE:-/etc/swap-watch.env}"
mode="${1:-run}"

send() {
  [ "$mode" = dry-run ] && { echo "would send: $1"; echo 200; return; }
  # Token goes to curl on stdin, never on the command line (it would show in ps).
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TELEGRAM_BOT_TOKEN" |
    curl -sS -o /dev/null -w '%{http_code}' --max-time 20 --config - \
      --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" --data-urlencode "text=$1"
}

# dry-run reads the env file too when it can, so it checks what the timer's runs check
# (MONEROD_URL, UNITS); it never needs the token.
if [ "$mode" != dry-run ]; then
  [ -r "$ENV_FILE" ] || { echo "swap-watch: no $ENV_FILE" >&2; exit 1; }
fi
if [ -r "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi
[ "$mode" = dry-run ] || : "${TELEGRAM_BOT_TOKEN:?}" "${TELEGRAM_CHAT_ID:?}"
mkdir -p "$STATE_DIR"

if [ "$mode" = test ]; then
  code=$(send "🧪 $(hostname -s) swap-watch test: swap maker alerts reach this chat")
  echo "Telegram HTTP $code"; [ "$code" = 200 ]; exit
fi

problems=()
now=$(date +%s)
for u in $UNITS; do
  st=$(systemctl is-active "$u")
  [ "$st" = active ] || problems+=("$u is $st")
done

health=$(curl -sS -m 10 "$API/healthz" 2>/dev/null)
if ! jq -e '.ok == true' >/dev/null 2>&1 <<<"$health"; then
  problems+=("divi-swapd /healthz not ok: $(cut -c1-160 <<<"${health:-no answer}")")
else
  scan=$(jq -r '.divi_scan.state // "none"' <<<"$health")
  started=$(date -d "$(systemctl show -p ActiveEnterTimestamp --value divi-swapd)" +%s 2>/dev/null || echo "$now")
  if [ "$scan" != "done" ] && [ "$scan" != none ] && [ $((now - started)) -gt "$SCAN_MAX" ]; then
    problems+=("divi-swapd wallet scan still $scan $(((now - started) / 60)) min after start")
  fi
  for c in divi btc; do
    e=$(jq -r ".$c.error // empty" <<<"$health")
    [ -n "$e" ] && problems+=("divi-swapd $c backend: $(cut -c1-120 <<<"$e")")
  done
fi

if [ -n "$MONEROD_URL" ]; then
  info=$(curl -sS -m 10 "$MONEROD_URL/get_info" 2>/dev/null)
  if ! jq -e '.status == "OK"' >/dev/null 2>&1 <<<"$info"; then
    problems+=("monerod RPC not answering at $MONEROD_URL")
  elif ! jq -e '.synchronized == true' >/dev/null 2>&1 <<<"$info"; then
    problems+=("monerod not synchronized: height $(jq -r .height <<<"$info") of $(jq -r .target_height <<<"$info")")
  fi
fi

# One line per swap: kind id state last_error. Hashlock states are PascalCase, XMR snake_case.
swaps=$( {
  curl -sS -m 10 "$API/swaps" 2>/dev/null | jq -r '.[]? | ["htlc", .id, .state, (.last_error // "")] | @tsv'
  curl -sS -m 10 "$API/xmr/swaps" 2>/dev/null | jq -r '.[]? | ["xmr", .id, .state, (.last_error // "")] | @tsv'
} )
seen_file="$STATE_DIR/seen.tsv"   # kind id state since last_error
touch "$seen_file"
new_seen=""
while IFS=$'\t' read -r kind id state err; do
  [ -n "${id:-}" ] || continue
  case "$kind:$state" in
    htlc:Done|htlc:Aborted|xmr:done|xmr:aborted|xmr:punished) continue ;;
  esac
  prev=$(awk -F'\t' -v k="$kind" -v i="$id" '$1==k && $2==i' "$seen_file")
  prev_state=$(cut -f3 <<<"$prev"); since=$(cut -f4 <<<"$prev"); prev_err=$(cut -f5 <<<"$prev")
  [ "$prev_state" = "$state" ] && [ -n "$since" ] || since=$now
  new_seen+="$kind"$'\t'"$id"$'\t'"$state"$'\t'"$since"$'\t'"$err"$'\n'
  limit=$STUCK_MAX; [ "$kind:$state" = xmr:accepted ] && limit=$ACCEPTED_MAX
  age=$((now - since))
  [ "$age" -gt "$limit" ] && problems+=("$kind swap ${id:0:8} stuck in $state for $((age / 3600)) h $((age % 3600 / 60)) min")
  [ -n "$err" ] && [ "$err" = "$prev_err" ] && problems+=("$kind swap ${id:0:8} ($state): $(cut -c1-160 <<<"$err")")
done <<<"$swaps"
[ "$mode" = dry-run ] || printf '%s' "$new_seen" >"$seen_file"

# The one deadline that costs the maker money: a cancelled swap's Tx_refund must confirm before
# t_punish (unix seconds vs DIVI median time past, which lags wall time by up to ~30 min). The
# text is fixed per swap so it repeats on the ALERT_EVERY rule, not every run.
while read -r id state; do
  [ -n "${id:-}" ] && problems+=("xmr swap $id ($state) within $((PUNISH_MARGIN / 60)) min of t_punish: refund not confirmed")
done < <(curl -sS -m 10 "$API/xmr/swaps" 2>/dev/null | jq -r --argjson now "$now" --argjson m "$PUNISH_MARGIN" \
  '.[]? | select((.state == "cancelled" or .state == "refunded") and .t_punish != null
                 and .t_punish - $now < $m) | .id[:8] + " " + .state')

host=$(hostname -s)
if [ "$mode" = dry-run ]; then
  for p in "${problems[@]+"${problems[@]}"}"; do echo "problem: $p"; done; echo "${#problems[@]} problem(s)"; exit 0
fi
key=$(printf '%s\n' "${problems[@]+"${problems[@]}"}" | sed -E 's/[0-9]+//g' | sort | md5sum | cut -c1-32)
last_key=$(cat "$STATE_DIR/key" 2>/dev/null || echo none)
last_sent=$(cat "$STATE_DIR/sent" 2>/dev/null || echo 0)

if [ ${#problems[@]} -eq 0 ]; then
  if [ -f "$STATE_DIR/sent" ]; then
    code=$(send "✅ $host swap maker is healthy again")
    [ "$code" = 200 ] && rm -f "$STATE_DIR/sent" "$STATE_DIR/key" || echo "swap-watch: Telegram HTTP $code" >&2
  fi
  exit 0
fi
[ "$key" = "$last_key" ] && [ $((now - last_sent)) -lt "$ALERT_EVERY" ] && exit 0
msg="🚨 $host swap maker:"$'\n'$(printf -- '- %s\n' "${problems[@]}")
code=$(send "$msg")
if [ "$code" = 200 ]; then
  echo "$key" >"$STATE_DIR/key"; echo "$now" >"$STATE_DIR/sent"
else
  echo "swap-watch: Telegram HTTP $code" >&2; exit 1
fi
