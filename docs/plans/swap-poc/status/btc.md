# btc lane status

- note (orchestrator, 2026-10-11): the btc lane no longer exists; `crates/swap-chain-btc` is
  now maintained by lane `ltc`. Fix landed: `build_funding_tx`'s coin-selection `needed` was
  seeded to `0` and only updated inside the loop, so a coin list with zero UTXOs at all (not
  just too few sats) left `total(0) < needed(0)` wrongly false and fell through to
  `needed - amount`, underflowing — the same bug the ltc lane's live dry run caught in its
  own copy of this logic (`crates/swap-chain-ltc/src/tx.rs`, copied from here originally).
  A prior quick patch here (`chosen.is_empty() || total < needed`) masked the panic without
  fixing the root cause; replaced with the proper fix (seed `needed` from the zero-input fee
  estimate before the loop), matching the ltc crate exactly. The pre-existing regression test
  `funding_from_empty_wallet_is_insufficient_funds` still covers it (so no duplicate test was
  added). `cargo fmt`/`clippy -D warnings`/`test -p swap-chain-btc --all-features` all green
  (17 passed, 1 ignored).
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
