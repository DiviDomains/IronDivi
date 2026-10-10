# Parked actions (need a human turn)

1. ~~**Signet BTC for the taker key**~~ **RESOLVED 2026-10-08:** Bert funded 0.00197253 tBTC on testnet3 (`f5ee5dc8…206a`; DECISIONS #8). Return leftovers when done to `tb1qerzrlxcfu24davlur5sqmgzzgsal6wusda40er` (testnet3) — the faucet's return address.
   Original: (blocks plan 0.4 and the btc lane's live test; nothing else).
   Open https://bitcoinfaucet.uo1.net/ (or https://signetfaucet.com/), solve the captcha and send to
   `tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg` (key `IronDivi Swap POC - taker-btc`). ≥ 0.001 sBTC is enough
   for the proof; 0.01 for the whole POC. Then say "sBTC sent" in the orchestrator pane.
   Check: `curl -s https://mempool.space/signet/api/address/tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg | jq .chain_stats.funded_txo_sum`

2. ~~**1Password approval: dnsdivi SSH key and `op read` taker-btc**~~ **RESOLVED 2026-10-10:** keys now resolve
   through the secret proxy (`secret get`, `7038c70`) behind one secret-broker approval; all four keys read, `ssh dnsdivi`
   works, dnsdivi redeployed on testnet3, btc live funding broadcast and confirmed.
   Original (2026-10-08 23:23): both prompts went
   unanswered, so `ssh dnsdivi` failed ("agent signing failed") and the testnet3 live test could not read
   `IronDivi Swap POC - taker-btc`. No tx was broadcast and the dnsdivi binary is unchanged (still pre-`ef4a9c9`, signet).
   Blocks: the dnsdivi redeploy and testnet switch, btc live, e2e-local, chaos live, and Wave 3 e2e.
   Retried 2026-10-09 09:17: a foreground `op read` succeeded, but the test's own read hit "authorization timeout"
   (60 s, nobody at the Mac) and `ssh dnsdivi` still failed agent signing. Still no tx broadcast.
   Unblock: be at the keyboard to approve 1Password, then say "continue" in the orchestrator pane. Check:
   `ssh dnsdivi true && op read "op://global_secret_store/IronDivi Swap POC - taker-btc/password" >/dev/null && echo ok`
