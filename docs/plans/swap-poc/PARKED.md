# Parked actions (need a human turn)

1. **Signet BTC for the taker key** (blocks plan 0.4 and the btc lane's live test; nothing else).
   Open https://bitcoinfaucet.uo1.net/ (or https://signetfaucet.com/), solve the captcha and send to
   `tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg` (key `IronDivi Swap POC - taker-btc`). ≥ 0.001 sBTC is enough
   for the proof; 0.01 for the whole POC. Then say "sBTC sent" in the orchestrator pane.
   Check: `curl -s https://mempool.space/signet/api/address/tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg | jq .chain_stats.funded_txo_sum`
