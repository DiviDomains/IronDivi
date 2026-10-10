# btc lane status

- done: BtcBackend (ChainBackend) — Esplora client (backoff, 429 Retry-After, secondary fallback), P2WPKH funding with coin selection + change, P2WSH claim/refund, libbitcoinconsensus verification of every built tx, find_spend (outspend, block-scan fallback), broadcast classification; 15 wiremock unit tests green; fmt + clippy -D warnings clean; live_fund_claim_refund written (feature `live`, #[ignore])
- running: nothing
- broken: nothing
- left: nothing; live_fund_claim_refund PASSED on testnet3 (1 passed, 6249 s) — 0.4 evidence below
- last_sha: (set at commit)
- decisions: HTLC in the live test uses the taker key as both claim and refund key (backend holds one key); HTLC fee policy Recommended{floor 2}; 501 from Esplora is not retried (it means "no outspend index" and triggers the block-scan fallback); change below dust is folded into the fee
- needs: nothing
- live_fund_txid: 9a5d15905f8295f472c5d5233a0970ba34adaffe823b0d415df79f1498cb1fae
- live_fund2_txid: 051b72ada77d66e4ccc4af27c0af186c6baf40cf11669962298b89d4c950349c
- live_claim_txid: bd22f564eb39af5e1b5f9d9d6021e64f8f939d951b878466eb583cfe49a91ae0
- live_refund_txid: 13509b955300b32e6910bf29517cb904c3600965cde644307a7e568a12f4ef55
