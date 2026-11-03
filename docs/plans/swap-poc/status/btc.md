# btc lane status

- note (orchestrator, 2026-10-11): the btc lane no longer exists; `crates/swap-chain-btc` is
  now maintained by lane `ltc`. Change landed: `build_funding_tx`'s coin-selection `needed`
  was seeded to `0` and only updated inside the loop, so a coin list with zero UTXOs at all
  left `needed` at `0` too — in `swap-chain-ltc`'s copy of this logic (copied from here
  originally) that caused a live underflow panic (the ltc lane's live dry run caught it).
  **Here it was already handled**: an existing explicit `chosen.is_empty() || total < needed`
  guard caught the zero-UTXO case before the later `needed - amount` subtraction could ever
  underflow, and `funding_from_empty_wallet_is_insufficient_funds` already regression-tested
  it — so this was not a live bug in `swap-chain-btc`, just an inconsistency with the ltc fix.
  Replaced the explicit guard with the same seeding approach as `swap-chain-ltc` (seed
  `needed` from the zero-input fee estimate before the loop) so both crates' coin-selection
  reads the same way; no behavior change, same pre-existing test still covers it (so no
  duplicate test was added). `cargo fmt`/`clippy -D warnings`/`test -p swap-chain-btc
  --all-features` all green (17 passed, 1 ignored).
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

## Round: explicit mainnet wiring (builder P, 2026-10-21)

- done: `swap-chain-btc` accepts `network = "mainnet"` end to end — endpoints ``https://mempool.space/api` then `https://blockstream.info/api``, address HRP ``bc` (`Network::Bitcoin`)`
  via ``BtcBackend::new_on("mainnet", …)` / `for_network("mainnet", …)``; signet/testnet behaviour is byte-for-byte unchanged (pinned by test). The daemon's
  `[btc]` section gained `allow_mainnet` (default `false`): `network = "mainnet"` without it, an
  unknown network name, or a network that disagrees with the top-level `profile` is a config-load
  error with the same wording as `[zec]` (`bin/divi-swapd/src/config.rs` `validate_mainnet_gate`).
  `esplora_url` is now optional and falls back to the crate's defaults for `network`. The CLI
  gates `--btc-network mainnet` behind the shared `--allow-mainnet` flag before any key is resolved or any
  network call is made (`bin/divi-swap/src/main.rs` `guard_network`).
- proof (read-only, no wallet, no key, no funds):
  - BTC mainnet tip `https://mempool.space/api/blocks/tip/height` → `972518` (HTTP 200, 2026-10-21T19:10:40Z); verdict `verified`.
  - BTC mainnet tip `https://blockstream.info/api/blocks/tip/height` → `972518` (HTTP 200, 2026-10-21T19:10:41Z); verdict `verified`.
  - fee endpoint `https://mempool.space/api/v1/fees/recommended` answered at 2026-10-21T19:33:51Z (`halfHourFee` 2); verdict `verified`.
  - HRP source: BIP-173 "The human-readable part \"bc\" for mainnet, and \"tb\" for testnet" (https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki); verdict `verified`.
  - tests added: `mainnet_endpoints_are_non_empty_with_mempool_first`, `test_network_endpoints_are_unchanged`, `unknown_btc_network_is_rejected`, `mainnet_address_is_bc1q_and_test_networks_stay_tb1q` (crate); `btc_ltc_sections_default_to_test_networks_without_mainnet`, `btc_ltc_mainnet_without_allow_is_rejected`, `btc_ltc_mainnet_with_allow_and_matching_profile_is_ok_with_crate_default_endpoints`, `btc_ltc_network_disagreeing_with_profile_is_rejected`, `btc_ltc_bad_network_is_rejected` (daemon config); `btc_and_ltc_networks_default_to_the_test_networks`, `btc_ltc_mainnet_without_allow_mainnet_is_rejected_before_any_network_call`, `btc_ltc_bad_network_is_rejected_before_any_network_call`, `mainnet_guard_passes_with_allow_mainnet` (CLI).
  - `cargo fmt --check`, `cargo clippy -p swap-chain-btc -p swap-chain-ltc -p divi-swapd -p divi-swap
    --all-targets -- -D warnings`, and `cargo test` on the same four packages: green (counts in
    `~/swap-lanes/builders/P/STATUS.md` on hp1 and in the lane commit message).
- left: mainnet confirmations are still 2 (`crates/divi-swap/src/config.rs:44`, flagged `risky` above); no live mainnet run of any kind was made.
- needs: nothing. Mainnet funds remain the only money gate; nothing here turns `allow_mainnet` on.

## Round: BTC mainnet read-only smoke (builder W, 2026-10-22)

- done: ran `divi-swap` and `divi-swapd` against BTC mainnet with a throwaway zero-balance key (generated on hp3, mode 600, outside git, deleted). CLI `balance` with `--btc-network mainnet --allow-mainnet` printed `btc_address=bc1q…`, `btc_balance_sats=0` in 0.11 s via `https://mempool.space/api`; without `--allow-mainnet` it refuses before any network call. Daemon (`profile = "mainnet"`, `[btc] network = "mainnet" allow_mainnet = true`, default endpoints) logged "btc backend ready" network `mainnet`, `/healthz` `btc.tip` 972609. Corrected the stale §BTC "Public backends", "Address network" and findings rows in `mainnet-readiness.md`; added the two smoke rows. Confirmations stay 2 with the "risky: thin" rows exactly as they were (parked decision).
- proof: tip 972609 from both `https://mempool.space/api/blocks/tip/height` and `https://blockstream.info/api/blocks/tip/height` (HTTP 200, 2026-10-22T11:09Z, same tip hash `00000000000000000001a4b1e376cb4869d2bc5a86b9ec9fbf844c7f2bd8dcd7`); verdict `verified`. The secondary endpoint also reports the throwaway address with 0 funded txo. Gate first lines (verbatim) are in the readiness row. fmt clean, clippy `-D warnings` on the four packages clean, tests 178 passed / 0 failed / 1 ignored (docs-only change, so before = after).
- left: the CLI has no `tip` subcommand (tip checked by curl); the DIVI backend is built on `DiviNetwork::Testnet` whatever the profile, so a mainnet-profile daemon still talks to the DIVI testnet RPC (`bin/divi-swapd/src/main.rs:430-436`, `bin/divi-swap/src/main.rs:487-494`).
- needs: nothing.
- decisions: no code change, no confirmation/MTP/timeout/margin change.

## Round: DIVI network claim corrected (builder AH, 2026-10-22)

- done: the previous round's `left:` that the DIVI backend is built on `DiviNetwork::Testnet` whatever the profile is stale. `bin/divi-swapd/src/main.rs:433-440` builds it from `divi_cfg.network()?` and the config's `rpc_url()`, and `bin/divi-swap/src/main.rs` picks `divi_wallet::address::Network::Mainnet` when `--divi-network mainnet` (default testnet) and `swap_chain_divi::default_rpc(divi_network)`; both are behind `allow_mainnet`/`--allow-mainnet` and must agree with the profile (commit 97bc181). Also: the CLI now has `divi-swap tip` (see engine.md), so the BTC tip no longer needs a curl.
- proof: the two source locations above; live `divi-swap tip --chain divi` printed `divi testnet 360958` by default and `divi mainnet 4270016` with `--divi-network mainnet --allow-mainnet --profile mainnet` (cryptoid `getblockcount` 4270015 at 12:48:51Z).
- left: nothing.
- needs: nothing.
- decisions: history above is left as written; this round supersedes its `left:` line.
