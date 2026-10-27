# Single data source per chain — risk ranking and cheapest mitigation (Q6)

Date: 2026-10-22. Base `fb25f36`. Design only: no code, no config default and no confirmation count
is changed by this document. Answers `engine-review-brief.md` §7 question 6.

Third-party facts (who operates an endpoint, what an explorer returns) are in
`single-source-design.FACTS.md`; this file only states what the code does.

Two sources that collude (one operator, one upstream, the host's DNS) are covered in `colluding-endpoints.md`.

## 1. What each side asks a single source

The engine (`crates/divi-swap/src/backend.rs:41`, `ChainBackend`) calls five things on a backend.
Every answer comes from one backend object, which talks to one logical source.

| Question | Consumer | What a wrong answer does |
|---|---|---|
| `htlc_output` + `confirmations` of the *other* party's lock | maker `maker.rs:508-561`; taker `taker.rs:397` | the engine acts (locks its own leg, or claims) on a lock that is not real or not deep enough |
| `find_spend` of my own lock | maker `maker.rs:734` (`revealed_preimage`) | a hidden claim means the preimage is never seen |
| `median_time_past` | maker `maker.rs:281,494,572,726`; taker `taker.rs:191,363,406,465` | refund / claim attempted at the wrong moment, or a locktime that is too short |
| `broadcast` | all claim / refund / fund paths | a censored tx is reported as sent |
| `tip_height` / `tip_hash` | feed `confirmations`; `tip_hash` is read-only | confirmations inflated by a high tip |

Direction used below: the **taker** picks the preimage (`taker.rs:129`); the **maker** learns it only
from a spend of the maker leg (`maker.rs:734`). In the default direction the maker leg is DIVI and the
taker leg is the counter chain (BTC, LTC, ZEC, USDC). `reverse-direction.md` swaps the roles.

## 2. Truth table — source, config key, cross-check

All paths are under the repo root. "Mainnet default" is what a config that sets nothing gets.

### DIVI
- Source: one JSON-RPC proxy. Mainnet default `https://services.divi.domains/api/rpc/`
  (`crates/swap-chain-divi/src/lib.rs:51`; testnet `:47`). Key `[divi].rpc_url` (`bin/divi-swapd/src/config.rs:49`). **Implemented, opt-in (lane/divi-second-source): `[divi].fallback_rpc_url` (`bin/divi-swapd/src/config.rs:55`, wired at `bin/divi-swapd/src/main.rs:453-461`). Unset by default on every network, and unset is the same single-source code path as before.**
- confirmations: `getrawtransaction` `confirmations` field, `lib.rs:548`; `htlc_output` `lib.rs:555`.
- spend detection: `find_spend` `lib.rs:578` walks every block with `getblock` and then `getrawmempool` through the same proxy (no address/spent index).
- MTP: `lib.rs:358`, median of 11 block times fetched through the same proxy (the node's own `mediantime` is null).
- broadcast: `sendrawtransaction`, `lib.rs:488`.
- With `fallback_rpc_url` set (`DiviBackend::with_fallback_rpc`), `median_time_past`, `confirmations`, `htlc_output` and `find_spend` (`lib.rs:362,534,546,558`) read both endpoints and compare in `crates/swap-chain-divi/src/second_source.rs`. Disagreement, or exactly one endpoint unable to answer, is `SwapError::Transient`. Confirmations may differ by `CONFIRMATION_TOLERANCE` (1, tip lag) and MTP by `MTP_TOLERANCE_SECS` (600); within tolerance the lower value is used, so an inflation can only be clipped. A tx, output or spend only one endpoint knows, differing amounts, and a spend with a different txid, input or scriptSig (the preimage) are `Transient`. `broadcast` goes to both and succeeds if either accepts. **Lane divi-second-source-tip extends this to the tip and the wallet reads.** `tip_height`, `tip_hash`, `block_txids` and `get_tx` (so `scan_range`, `scan_blocks` and `add_funding_tx`) also read both endpoints (`crates/swap-chain-divi/src/lib.rs:361,370,244,259`). Tip height may differ by `TIP_TOLERANCE_BLOCKS` (2); the lower height is used, so a lie or a lag can only lower it. This matters because the maker starts its spend scan at the tip it read when it locked (`crates/divi-swap/src/maker.rs:628,780`): a tip read too high would skip the taker's claim and hide the preimage, while a tip read too low only rescans. Tip hashes, the txids in a block, and the wallet-relevant fields of a transaction (txid, spent outpoints, output index, script and amount) must match exactly, otherwise the read is `Transient`, so an invented, hidden or inflated coin cannot reach the wallet. `build_funding` (`lib.rs:388`) makes no RPC call and stays local: only the local wallet and key can pick coins, sign and derive the change address; the coins it picks come from the now cross-checked scan. The taker CLI sets the second endpoint with `--divi-fallback-rpc-url URL` (`bin/divi-swap/src/main.rs:75,503`; refused if equal to the default endpoint, unset is unchanged). Tests: `crates/swap-chain-divi/tests/second_source_tip.rs`.
- Not covered: two colluding endpoints, and a mainnet start rule that requires the key. Making it mandatory is an operator decision.
- Second source / cross-check: none in the daemon. `tools/swap-poc/tip-crosscheck.sh` compares tip hashes by hand; nothing in the engine reads it. Mainnet default: **none**.

### BTC
- Source: Esplora. Mainnet default list is two URLs (`crates/swap-chain-btc/src/lib.rs:69`). Keys `[btc].esplora_url`, `[btc].fallback_esplora_url` (`config.rs:92,94`).
- The second URL is **failover only**: `client.rs:127-172` moves on after a network error, HTTP 5xx or 429 on every attempt; it never compares two answers. A 200 that lies is accepted.
- confirmations `lib.rs:473`; `htlc_output` `:487`; `find_spend` `:515` (Esplora `outspend`, block scan if unsupported); MTP `:362` (`mediantime` of the tip block); broadcast `:453` (`POST /tx`); tip `:345`.
- Cross-check: none. Mainnet default: **none**.

### LTC
- Source: Esplora. Mainnet default list is **one** URL (`crates/swap-chain-ltc/src/lib.rs:75`). Keys `[ltc].esplora_url`, `fallback_esplora_url` (`config.rs:126,129`).
- Same failover-only client (`crates/swap-chain-ltc/src/client.rs:179`). Same call sites: tip `:419`, MTP `:436`, broadcast `:507`, confirmations `:527`, `htlc_output` `:541`, `find_spend` `:569`.
- Cross-check: exists. `crates/swap-chain-ltc/src/crosscheck.rs` compares the primary's hash at tip−6 with Blockbook or BlockCypher. Key `[ltc].crosscheck` (`config.rs:135`), CLI `--ltc-crosscheck` (`bin/divi-swap/src/main.rs:101`). **Default `off`** (`config.rs:313`), mainnet-only (`config.rs:704`). It runs **once at startup** (`bin/divi-swapd/src/main.rs:319`; `bin/divi-swap/src/main.rs:919`), compares one block hash, and an unreachable source only warns. It does not see confirmations, spends, MTP or broadcast.

### ZEC
- Source: lightwalletd gRPC (compact blocks). Mainnet default list is three hostnames under one domain (`crates/swap-chain-zec/src/lib.rs:62-64`); extra entries via env `SWAP_ZEC_LIGHTWALLETD_EXTRA` (`lib.rs:52`) or `[zec].lightwalletd_url` / `fallback_lightwalletd_url` (`config.rs:277,280`). Failover only (`grpc.rs:272-299`).
- tip `lib.rs:347`; MTP `:361` (11 compact blocks); broadcast `:470`; confirmations `:489`; `htlc_output` `:507`; `find_spend` `:536` (compact-block scan, then full tx fetch, capped by `MAX_SCAN_BLOCKS`).
- Cross-check: none (the source comment at `lib.rs:58-60` says to compare the tip by hand before real funds). Mainnet default: **none**.

### USDC / EVM
- Source: one JSON-RPC URL. Default per network (`crates/swap-chain-evm/src/network.rs:52`). Key `[usdc].rpc_url` (`config.rs:177`). **No fallback.**
- tip `backend.rs:283`; MTP `:304` (latest block timestamp, which is what the contract compares); broadcast `:437`; confirmations `:472` (receipt block vs tip); `htlc_output` `:496` (decodes the `Locked` log from the receipt); `find_spend` `:542` (`get_logs` for `Claimed`, then `Refunded`).
- Cross-check: none. Mainnet default: **none**.

### XMR
- Source: one `monerod` URL. Key `[xmr].monerod_url` (`config.rs:227`), no fallback. Used for lock scan (`live_rpc.rs:519`), confirmations (`monero_chain.rs:367`, `divi-swap-xmr/src/live.rs:499`), tip (`monero_chain.rs:235`), sweep relay (`monero_chain.rs:346`). The DIVI side of an XMR swap uses the DIVI row above.
- Cross-check: `tip-crosscheck.sh` only (`XMR_CROSS_URL`, a manual second monerod). Mainnet is not enabled: `[xmr].allow_mainnet` is for phase D of `xmr-mainnet-plan.md`.

## 3. Attack table

"Control needed" is what a lying source must control. "Loses" names who loses and what.

| Chain | Confirmations inflated / fake lock | Spend hidden | MTP shifted | Broadcast censored |
|---|---|---|---|---|
| DIVI | taker claims against a lock that is not real or is shallow; preimage leaves the taker and the maker keeps the counter leg. **Taker loses the counter-chain amount.** Control: the one proxy. | maker never sees the taker's claim, never claims the counter leg, and the taker refunds it. **Maker loses the DIVI leg.** Control: the one proxy. | refund tried early (rejected, retried) or late; a low MTP can delay a refund past the counter-leg timeout. Needs the proxy to also lie for ~11 blocks. | claim or refund never reaches the network; the timeout passes. Loss only if it lasts past the other side's refund. |
| LTC | a fake or shallow taker lock makes the maker lock DIVI. The maker's later claim of the taker leg is rejected by the real network, so the loss is the DIVI leg sitting locked until its timeout, plus fees; it becomes a real loss only if the lock is real but sits above the 6-confirmation depth and is reorged out. Control: the one Esplora. | when LTC is the maker leg (reverse direction), same loss as DIVI. | one block's `mediantime`; a single value, no cross-check. | same as DIVI. |
| ZEC | same as LTC, 10 confirmations. Compact blocks hide transaction detail, so `htlc_output` trusts the full-tx fetch from the same server. | same as LTC, reverse direction. | median of 11 compact-block times from one server. | same as DIVI. |
| USDC/EVM | a forged receipt and `Locked` log reads as a real lock; 12 confirmations are computed from the same RPC's tip. | `get_logs` for `Claimed` returns nothing; same loss as DIVI when USDC is the maker leg. | latest block timestamp is a single value from one RPC: shifts a contract-timelock decision by any amount. | `send_raw_transaction` swallowed; an `already known` reply is accepted as success. |
| BTC | as LTC. Two URLs, but a lie from the first is never compared to the second. | as LTC. | as LTC. | as LTC. |
| XMR | maker (the DIVI holder) is told the taker's XMR lock exists and proceeds. **Maker loses the DIVI leg.** | n/a for the XMR side: the maker sweeps with a recovered key. | n/a (no XMR timelock; the timelock is on DIVI). | sweep never relayed; loss only by delay. |

The loss that is permanent (not just a delay) is always the same shape: **a lie about the other party's
lock or about a spend of my own lock, on a chain where I am the funder or the claimer.** Lies about
MTP and broadcast are bounded by the timeout margins the engine already keeps.

## 4. Ranking (most dangerous first)

1. **DIVI** — it is on one leg of every swap, its mainnet source is a single proxy URL with no fallback key and no cross-check, and its `find_spend` and MTP both rebuild from many calls through that one proxy (`lib.rs:358,578`), so one lying proxy can hide a claim from the maker with no second view.
2. **LTC** — a single mainnet Esplora URL (`ltc/src/lib.rs:75`); the only cross-check is `off` by default and checks one block hash at startup, so it cannot see a fake lock or a hidden spend.
3. **ZEC** — three hostnames that share one operator domain (`zec/src/lib.rs:62-64`) and compact blocks that need a trusting full-tx fetch; no cross-check.
4. **USDC/EVM** — one RPC URL, no fallback, and MTP is a single timestamp; blunted only because a receipt and `Locked` log are hard to forge without controlling the whole RPC.
5. **BTC** — two operators in the default list, but failover-only, so a lie is not detected; most exposed to a well-resourced liar, least likely to be a single weak host.
6. **XMR** — one `monerod`, but mainnet is not enabled yet and the key material (view-key scan) limits what a liar can invent.

## 5. Cheapest mitigation per chain

Shared principle: **cross-check what an irreversible action rests on, not the tip.** The irreversible
actions are (a) the taker broadcasting a claim, (b) the maker locking its leg, (c) the maker declaring
"no spend seen" and refunding. Each needs one extra read from a second, independent source before it
proceeds; no timeout, margin or confirmation count changes.

| Rank | Chain | Cheapest mitigation | Cost | Code sites |
|---|---|---|---|---|
| 1 | DIVI | **Done, opt-in (lane/divi-second-source):** add `[divi].fallback_rpc_url` and a `DiviRpcQuorum` (implemented as `second_source.rs` plus a second `RpcClient` in `DiviBackend`): `find_spend`, `htlc_output` and `confirmations` ask both URLs and treat *disagreement* as `SwapError::Transient` (retry) — the engine already retries `Transient`. Operators can point the second URL at their own node. | ~1 day; one config key; mock RPC tests. Extended by lane divi-second-source-tip to the tip, block and wallet reads and a taker `--divi-fallback-rpc-url` flag. | `crates/swap-chain-divi/src/rpc.rs` (new client wrapper), `lib.rs:338-598`, `bin/divi-swapd/src/config.rs:39-80` |
| 2 | LTC | Make `[ltc].crosscheck` mandatory when `network = "mainnet"` (refuse to start with `off`) (**done**, lane/mainnet-two-sources), and call `crosscheck()` again before a claim (**Done, opt-in** (lane/ltc-crosscheck-before-claim): `[ltc].crosscheck_before_claim`, default off; a disagreement holds the claim as `Transient`, an unreachable source warns and the claim goes ahead); **extended (EI):** the claim-time check also compares the block at `tip - 1` and the claimed output's spend, and a spend seen by one side only or two different spenders holds the claim as `Transient`). Then add a second Esplora to the default list once one exists. | config + 10 lines; the module already exists. | `bin/divi-swapd/src/config.rs:704`, `crates/swap-chain-ltc/src/lib.rs:185`, `crates/swap-chain-ltc/src/crosscheck.rs` (`claim_crosscheck`) |
| 3 | ZEC | **Done, opt-in (lane/zec-second-operator, EH); mainnet: required:** `[zec].crosscheck_url` (default unset, off; taker flag `--zec-crosscheck-url`) names a lightwalletd run by a second *operator*. At startup and before every claim and refund is built, `crosscheck.rs` asks both for their tips, takes the lower one (a one-block lead is not a disagreement) and compares the hashes there and 6 blocks below. A different hash is `SwapError::Transient` naming both endpoints (at startup it refuses to start); an unreachable second operator, or one more than 6 blocks behind, holds the claim or refund as `Transient` (fail closed) and only warns at startup. A URL under the registrable domain of any primary endpoint is refused at config load. A mainnet profile refuses to start unless `crosscheck_url` is set, the endpoint list already spans two operators, or `[zec].allow_single_source = true`. | small; one config key plus a waiver; in-process gRPC stub tests. | `crates/swap-chain-zec/src/crosscheck.rs`, `lib.rs` (`with_crosscheck`, `build_claim`, `build_refund`), `bin/divi-swapd/src/config.rs` (`ZecSection::crosscheck_url`) |
| 4 | USDC/EVM | **Done, opt-in (lane/usdc-quorum-reads EC, lane/usdc-config-key EF):** `[usdc].fallback_rpc_url` (default unset; taker flag `--usdc-fallback-rpc-url`) calls `UsdcBackend::with_quorum_rpc`: `htlc_output`, `find_spend`, `confirmations` and `median_time_past` ask both nodes (`quorum.rs`); a lock or spend seen by one only, two different spends, or a lock at another amount is `SwapError::Transient`; of two confirmation counts or block times the smaller is used; the second node not answering is `Transient` (fail closed). The same URL as the primary is refused at config load. Unset, the backend is built and reads as before. Tip, sending, nonces, gas and balances stay on the one node. Not required on mainnet. | ~1 day; one config key; wiremock JSON-RPC tests. | `crates/swap-chain-evm/src/quorum.rs`, `backend.rs` (`*_on` reads, `with_quorum_rpc`), `bin/divi-swapd/src/config.rs` (`UsdcSection::fallback_rpc_url`), `bin/divi-swapd/src/main.rs` (`usdc_backend`) |
| 5 | BTC | **Done, opt-in (lane/btc-quorum-reads, EB):** `[btc].quorum_reads` (default off; taker flag `--btc-quorum-reads`) reuses the existing second URL as a *quorum read*: `find_spend`, `htlc_output` and `confirmations` ask the primary and the secondary Esplora concurrently (`quorum.rs`); a spend, output or confirmed tx seen by one only, two different spenders or witnesses, or two output values is `SwapError::Transient`; of two confirmation counts the lower is used; either endpoint failing is `Transient` (fail closed). Refused at startup with fewer than two different endpoints. Off, the second URL stays a failover and is not asked. **Extended (EI):** with the switch on, `tip_height` and `median_time_past` are the lower of the two, `tip_hash`/`tip_header` the lower tip once the other endpoint names the same block at that height (two blocks at one height are `Transient`), and `in_best_chain` must agree; either endpoint failing is `Transient`. Funding and broadcast are still primary-then-failover. | small; both URLs already configured. | `crates/swap-chain-btc/src/quorum.rs`, `lib.rs` (`*_on` reads), `client.rs` (`split_primary`), `bin/divi-swapd/src/config.rs` (`BtcSection::quorum_reads`) |
| 6 | XMR | Require `XMR_CROSS_URL`-style second monerod at phase D. | none now; part of the mainnet gate. | `crates/swap-chain-xmr/src/monero_chain.rs:235`, `tools/swap-poc/tip-crosscheck.sh:16` |

**The single cheapest change across all chains:** a generic *disagree ⇒ Transient* quorum wrapper
around the five read calls, enabled when a second endpoint is configured. It fits every row above
and needs no change to any timeout, margin, confirmation count or route.

## 6. What this lane implemented

Nothing. Rows 1 and 4 touch backend clients and config structs in shared files that have other
builders' work in flight, and rows 2–3 change what a mainnet config must contain (a mainnet opt-in
rule). None is small, config-gated and test-only, so by the brief they are design only.
`left:` lines are in the STATUS file and `status/engine.md`.
