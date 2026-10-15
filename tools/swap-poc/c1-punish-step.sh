#!/usr/bin/env bash
# C1 punish test: with the private maker stalled, step the taker with `claim` every 5 min until
# Done (it broadcasts Tx_cancel after t_cancel and Tx_punish after t_punish). 12 h cap.
#   c1-punish-step.sh <taker-bin> <run-dir>     (run-dir from xmr-soak.sh --scenario lock-only)
set -euo pipefail
bin=$1 out=$2 dir=$2/swap-1
lid=$(awk -F'\t' '$1==1 {print $3}' "$out/results.tsv")
item="op://global_secret_store/IronDivi Swap POC"
user=$(secret get --name taker-xmr-wallet-rpc-username --op-ref "$item - taker-xmr-wallet-rpc/username" </dev/null)
end=$(( $(date +%s) + 12 * 3600 ))
while [ "$(date +%s)" -lt "$end" ]; do
  st=$("$bin" --db "$dir/taker.db" --backend live --counter-chain xmr \
    --divi-key "$item - taker-divi/password" --xmr-network stagenet \
    --xmr-monerod-url http://node.monerodevs.org:38089 --xmr-wallet-rpc-url http://127.0.0.1:38088 \
    --xmr-wallet-rpc-user "$user" --xmr-wallet-rpc-password "$item - taker-xmr-wallet-rpc/password" \
    --xmr-sweep-address 5AbHxitM2WMiq1b957FpA6ZMHPPSex3XNH3UU9ox2tGpMHj9mNwCXCEXWMUVnfhnrQLyeh8vNDy6Mitu5d4L9Zjm9p8LaiS \
    --xmr-lookback-blocks 720 claim --swap "$lid" 2>>"$dir/step.log" || true)
  echo "$(date -u +%FT%TZ) $st" >>"$out/step-states.log"
  [ "$st" = Done ] && { echo "taker Done"; exit 0; }
  sleep 300
done
echo "step: 12 h cap reached"; exit 1
