#!/usr/bin/env bash
# Real-testnet atomic swap scenarios, maker (divi-swapd) and taker (divi-swap) both local.
#   tools/swap-poc/e2e.sh <happy|case-c|case-d> [--backend live|mock] [--offer OFFER] [--maker-url URL]
# --offer: divi-btc-testnet (default; taker pays BTC) or btc-divi-testnet (reverse; taker sells DIVI
#   for BTC). Reverse: state dir rev-<scenario>-<backend|deployed>, txid prefix rev_<happy|casec|cased>.
# --maker-url: use an already-running maker (e.g. the deployed one through an SSH tunnel) with its
#   own profile; no local divi-swapd is built, configured or started. State: <scenario>-deployed.
# live: DIVI testnet + BTC signet, keys resolved from 1Password at runtime (op:// refs only).
# mock: plumbing only (daemon lifecycle, config, quote/accept) — mock chains are per-process,
#       so a swap cannot progress across the daemon/CLI boundary; flows are tested in-process.
# Run it as a background command; case-c takes ~3.5-4 h. Output ends with `- <key>_txid:` lines.
# Env: SWAP_BTC_NETWORK (default signet), E2E_STATE_DIR (default ~/.local/state/iron-divi-swap-poc), E2E_BTC_SATS (default 10000).
set -euo pipefail
# SWAP_BTC_NETWORK=signet|testnet (testnet3); the taker CLI reads the same variable.
btc_network="${SWAP_BTC_NETWORK:-signet}"
export SWAP_BTC_NETWORK="$btc_network"

usage() { echo "usage: $0 <happy|case-c|case-d> [--backend live|mock] [--offer divi-btc-testnet|btc-divi-testnet] [--maker-url URL]" >&2; exit 2; }
die() { echo "e2e: $*" >&2; exit 1; }

scenario="${1:-}"; [[ -n "$scenario" ]] || usage
shift || true
backend=live
maker_url=""
offer=divi-btc-testnet
while (($#)); do
  case "$1" in
    --backend) backend="${2:-}"; shift 2 || usage ;;
    --offer) offer="${2:-}"; shift 2 || usage ;;
    --maker-url) maker_url="${2:-}"; shift 2 || usage; [[ -n "$maker_url" ]] || usage ;;
    *) usage ;;
  esac
done
[[ "$backend" == live || "$backend" == mock ]] || usage
[[ "$offer" == divi-btc-testnet || "$offer" == btc-divi-testnet ]] || usage
reverse=""; [[ "$offer" == btc-divi-testnet ]] && reverse=1
[[ -z "$maker_url" || "$backend" == live ]] || die "--maker-url needs --backend live"

ROOT="$(git rev-parse --show-toplevel)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

# Per-scenario daemon timings, port, taker flags and txid key prefix. Case C/D use a maker
# timeout of 3600 s: the taker refuses to claim inside a 1800 s safety margin, and validate()
# needs taker - maker >= 10800 s. Happy uses the unmodified testnet profile.
btc_sats="${E2E_BTC_SATS:-10000}"
timing=""
taker_flags=()
case "$scenario" in
  happy) port=18491; prefix=happy; timeout_secs=28800 ;;
  case-c)
    port=18492; prefix=casec; timeout_secs=21600
    timing=$'[swap]\nmaker_timeout_secs = 3600\ntaker_timeout_secs = 14410\n'
    taker_flags=(--never-claim) ;;
  case-d)
    port=18493; prefix=cased; timeout_secs=21600
    timing=$'[swap]\nmaker_timeout_secs = 3600\ntaker_timeout_secs = 14410\n'
    taker_flags=(--claim-not-before 2400) ;;
  *) usage ;;
esac
# A remote maker keeps its own (default testnet) profile: 10800/21600 s, so case C's BTC refund
# lands ~6 h in plus testnet MTP lag. Its txids get a deployed_ prefix.
if [[ -n "$maker_url" ]]; then
  timing=""
  prefix="deployed_$prefix"
  [[ "$scenario" == case-c ]] && timeout_secs=36000
fi

suffix="${maker_url:+deployed}"
# Reverse runs keep their own state dir and txid prefix; the shared taker DIVI wallet sits one level up.
if [[ -n "$reverse" ]]; then
  prefix="${prefix/#deployed_/deployed_rev_}"; [[ "$prefix" == *rev_* ]] || prefix="rev_$prefix"
  scen_dir="rev-$scenario"
else scen_dir="$scenario"; fi
state="${E2E_STATE_DIR:-$HOME/.local/state/iron-divi-swap-poc}/$scen_dir-${suffix:-$backend}"
case "$state" in "$ROOT"/*) die "state dir must be outside the repo: $state" ;; esac
mkdir -p "$state"
chmod 700 "$state"
log="$state/daemon.log"
base="${maker_url:-http://127.0.0.1:$port}"

vault="op://global_secret_store"
ref() { echo "$vault/IronDivi Swap POC - $1/password"; }

if [[ "$backend" == live ]]; then
  # Fail fast, once, before anything starts: an unanswered 1Password prompt is a park, not a retry.
  # Through the secret proxy (cache, then secret-broker), which also warms its cache for the
  # daemon and CLI; a raw 1Password CLI call from here would be a Touch ID dialog per key.
  keys=(taker-divi taker-btc)
  [[ -n "$maker_url" ]] || keys+=(maker-divi maker-btc)
  for k in "${keys[@]}"; do
    if ! secret get --name "irondivi-swap-poc-$k-password" --op-ref "$(ref "$k")" >/dev/null 2>&1; then
      die "cannot read the $k key (1Password locked, or secret-broker not running: secret-broker status). Rerun once it is up."
    fi
  done
fi

echo "e2e: building"
(cd "$ROOT" && cargo build -q -p divi-swapd -p divi-swap-cli)
swapd="$ROOT/target/debug/divi-swapd"
swap="$ROOT/target/debug/divi-swap"

[[ -n "$maker_url" ]] || cat >"$state/divi-swapd.toml" <<TOML
listen = "127.0.0.1:$port"
db_path = "$state/maker.db"
tick_secs = 5
$timing
[divi]
key = "$(ref maker-divi)"
wallet_path = "$state/maker-wallet.json"
scan_from_height = 339800

[btc]
network = "$btc_network"
esplora_url = "https://mempool.space/$btc_network/api"
key = "$(ref maker-btc)"
TOML

# A previous run's taker DB and sessions are the evidence for that swap; never mix runs.
if [[ -e "$state/taker.db" ]]; then
  stamp="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$state/old-$stamp"
  for f in "$state"/taker.db* "$state"/maker.db* "$state"/daemon.log; do
    [[ -e "$f" ]] && mv "$f" "$state/old-$stamp/"
  done
fi

daemon_pid=""
cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "e2e: scenario=$scenario backend=$backend maker=$base state=$state"
healthy() { [[ "$(curl -s -m 10 "$base/healthz" | jq -r '.ok // empty' 2>/dev/null)" == true ]]; }
if [[ -n "$maker_url" ]]; then
  healthy || die "remote maker $base is not healthy (tunnel down?)"
else
  "$swapd" --config "$state/divi-swapd.toml" --backend "$backend" >>"$log" 2>&1 &
  daemon_pid=$!

  # First start scans the DIVI wallet from scan_from_height (~15 min); later starts resume from the saved wallet.
  ready=""
  for _ in $(seq 1 750); do
    kill -0 "$daemon_pid" 2>/dev/null || { tail -20 "$log" >&2; die "daemon exited during startup"; }
    if healthy; then ready=1; break; fi
    sleep 2
  done
  [[ -n "$ready" ]] || { tail -20 "$log" >&2; die "daemon never became healthy"; }
fi
echo "e2e: daemon healthy"

taker=("$swap" --db "$state/taker.db" --backend "$backend")
if [[ "$backend" == live ]]; then
  taker+=(--divi-key "$(ref taker-divi)" --btc-key "$(ref taker-btc)")
fi
# Reverse: the taker locks DIVI, so it needs a DIVI wallet (outside the repo, mode 0600; the scan resumes from its cursor).
if [[ -n "$reverse" && "$backend" == live ]]; then  # the flag is rejected on mock
  taker_wallet="$(dirname "$state")/taker-divi-wallet.json"
  # Older CLIs (before rev-cli landed) lack the flag; fine for mock plumbing, fatal for a live run.
  if "$swap" --help 2>&1 | grep -q -- '--divi-wallet'; then
    taker+=(--divi-wallet "$taker_wallet")
  elif [[ "$backend" == live ]]; then
    die "this divi-swap build has no --divi-wallet; rebase onto main with rev-cli landed"
  fi
fi

# Reverse, live: the sides must be funded before anything locks. Fail now, with a reason, not hours in.
if [[ -n "$reverse" && "$backend" == live ]]; then
  offers_json="$(curl -s -m 10 "$base/offers")" || die "cannot list offers at $base"
  [[ "$(jq -r --arg o "$offer" '[.[] | select(.id == $o)] | length' <<<"$offers_json" 2>/dev/null)" == 1 ]] ||
    die "maker at $base does not advertise offer $offer (ids: $(jq -r '[.[].id] | join(",")' <<<"$offers_json" 2>/dev/null))"
  [[ "$(curl -s -m 10 "$base/healthz" | jq -r '.btc.tip // empty' 2>/dev/null)" =~ ^[0-9]+$ ]] ||
    die "maker's BTC backend is not reporting a tip (/healthz .btc.tip); it cannot fund the BTC leg"
  # The maker's BTC balance is not exposed by the API; set E2E_MAKER_BTC_ADDRESS to check it on Esplora.
  if [[ -n "${E2E_MAKER_BTC_ADDRESS:-}" ]]; then
    have="$(curl -s -m 20 "https://mempool.space/$btc_network/api/address/$E2E_MAKER_BTC_ADDRESS/utxo" | jq '[.[] | select(.status.confirmed) | .value] | add // 0' 2>/dev/null)"
    if [[ ! "${have:-0}" =~ ^[0-9]+$ ]] || ((have < btc_sats + 5000)); then
      die "maker has ${have:-0} confirmed BTC sats at $E2E_MAKER_BTC_ADDRESS, needs >= $((btc_sats + 5000))"
    fi
  fi
  # Taker DIVI: `divi-swap balance` prints a line with the spendable DIVI sats (first integer on the line mentioning divi).
  bal_out="$("${taker[@]}" balance 2>&1)" || die "divi-swap balance failed: ${bal_out:0:300}"
  have_divi="$(grep -i divi <<<"$bal_out" | grep -oE '[0-9]+' | head -1)"
  [[ "${have_divi:-0}" -gt 0 ]] || die "taker has no spendable DIVI (balance output: ${bal_out:0:300}); fund the taker DIVI wallet first"
  echo "e2e: preflight ok (offer $offer advertised, maker BTC backend up, taker DIVI balance $have_divi)"
fi

if [[ "$backend" == mock ]]; then
  "${taker[@]}" quote --maker "$base" --offer "$offer" --btc-sats "$btc_sats"
  local_id="$("${taker[@]}" accept --maker "$base" --offer "$offer" --btc-sats "$btc_sats" | tail -1)"
  echo "e2e: mock plumbing ok (accepted $local_id); no swap is possible across mock processes"
  exit 0
fi

out="$state/taker-run.log"
"${taker[@]}" run --maker "$base" --offer "$offer" --btc-sats "$btc_sats" \
  --timeout-secs "$timeout_secs" ${taker_flags[@]+"${taker_flags[@]}"} 2>&1 | tee "$out"
local_id="$(tail -1 "$out" | awk '{print $1}')"
[[ -n "$local_id" ]] || die "taker run printed no swap id"

# The maker's last action (BTC claim, or DIVI refund) trails the taker; wait for it.
txids=""
for _ in $(seq 1 360); do
  txids="$("${taker[@]}" txids --swap "$local_id")"
  grep -q '^maker_state=Done' <<<"$txids" && break
  sleep 10
done
echo "$txids"
grep -q '^maker_state=Done' <<<"$txids" || die "maker did not reach Done"

get() { sed -n "s/^$1=//p" <<<"$txids" | head -1; }
{
  if [[ -n "$reverse" ]]; then
    echo "- ${prefix}_divi_lock_txid: $(get divi_lock)"
    echo "- ${prefix}_btc_lock_txid: $(get btc_lock)"
    if [[ "$scenario" == case-c ]]; then
      echo "- ${prefix}_btc_refund_txid: $(get btc_spend_by_maker)"
      echo "- ${prefix}_divi_refund_txid: $(get divi_refund_by_taker)"
    else
      echo "- ${prefix}_btc_claim_txid: $(get btc_claim_by_taker)"
      echo "- ${prefix}_divi_claim_txid: $(get divi_claim_by_maker)"
    fi
  else
  echo "- ${prefix}_btc_lock_txid: $(get btc_lock)"
  echo "- ${prefix}_divi_lock_txid: $(get divi_lock)"
  if [[ "$scenario" == case-c ]]; then
    echo "- ${prefix}_divi_refund_txid: $(get divi_spend_by_maker)"
    echo "- ${prefix}_btc_refund_txid: $(get btc_refund_by_taker)"
  else
    echo "- ${prefix}_divi_claim_txid: $(get divi_claim_by_taker)"
    echo "- ${prefix}_btc_claim_txid: $(get btc_claim_by_maker)"
  fi
  fi
  if [[ "$scenario" == case-d ]]; then
    secs="$(sed -n 's/.*claim_secs_before_timeout=\([0-9]*\).*/\1/p' "$out" | head -1)"
    echo "- ${prefix}_claim_secs_before_timeout: $secs"
  fi
} | tee "$state/results.txt"
echo "e2e: $scenario done; paste $state/results.txt into the status file once the txids confirm"
