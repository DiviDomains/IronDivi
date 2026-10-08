# btc lane status

- done: BtcBackend (ChainBackend) — Esplora client (backoff, 429 Retry-After, secondary fallback), P2WPKH funding with coin selection + change, P2WSH claim/refund, libbitcoinconsensus verification of every built tx, find_spend (outspend, block-scan fallback), broadcast classification; 15 wiremock unit tests green; fmt + clippy -D warnings clean; live_fund_claim_refund written (feature `live`, #[ignore])
- running: nothing
- broken: nothing in code; BLOCKED on human: taker-btc address has 0 signet sats (PARKED.md #1), so live_fund_claim_refund cannot run
- left: fund taker-btc (tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg, needs ≥ ~45,000 sats, PARKED.md #1), then run `cargo test -p swap-chain-btc --features live -- --ignored live_fund_claim_refund --nocapture` in the background (~3 h), record live_fund_txid / live_claim_txid / live_refund_txid below, run tools/swap-poc/check-btc.sh
- last_sha: (set at commit)
- decisions: HTLC in the live test uses the taker key as both claim and refund key (backend holds one key); HTLC fee policy Recommended{floor 2}; 501 from Esplora is not retried (it means "no outspend index" and triggers the block-scan fallback); change below dust is folded into the fee
- needs: nothing
- live_fund_txid:
- live_claim_txid:
- live_refund_txid:
