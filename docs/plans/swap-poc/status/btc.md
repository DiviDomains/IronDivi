# btc lane status

- done: BtcBackend (ChainBackend) — Esplora client (backoff, 429 Retry-After, secondary fallback), P2WPKH funding with coin selection + change, P2WSH claim/refund, libbitcoinconsensus verification of every built tx, find_spend (outspend, block-scan fallback), broadcast classification; 15 wiremock unit tests green; fmt + clippy -D warnings clean; live_fund_claim_refund written (feature `live`, #[ignore])
- running: live_fund_claim_refund on testnet3 (funding confirmed; claim broadcast bd22f564...; refund waits for MTP, ~3 h)
- broken: nothing
- left: fund taker-btc (tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg, needs ≥ ~45,000 sats, PARKED.md #1), then run `cargo test -p swap-chain-btc --features live -- --ignored live_fund_claim_refund --nocapture` in the background (~3 h), record live_fund_txid / live_claim_txid / live_refund_txid below, run tools/swap-poc/check-btc.sh
- last_sha: (set at commit)
- decisions: HTLC in the live test uses the taker key as both claim and refund key (backend holds one key); HTLC fee policy Recommended{floor 2}; 501 from Esplora is not retried (it means "no outspend index" and triggers the block-scan fallback); change below dust is folded into the fee
- needs: nothing
- live_fund_txid: 9a5d15905f8295f472c5d5233a0970ba34adaffe823b0d415df79f1498cb1fae
- live_fund2_txid: 051b72ada77d66e4ccc4af27c0af186c6baf40cf11669962298b89d4c950349c
- live_claim_txid:
- live_refund_txid:
