# Colluding endpoints: what two sources cannot catch (T32-4)

Date: 2026-10-27. Base `118bc27` (INTEG step 29, the EF merge). This is a design note only: it
changes no code, config default, timeout, margin or confirmation count. Line numbers are at `118bc27`
unless a commit is named. Facts about third-party operators are in `colluding-endpoints.FACTS.md`;
this file says what the code does.

Read with `single-source-design.md` (one source per chain, Q6). That note asked "what if the one
source lies". This one asks the next question: **what if both sources lie together**, or one is
silent while the other lies.

## 0. Summary in five lines

1. Every two-source check in the tree is an *agreement* check: two identical answers pass. None
   checks that the two sources are run by different people, or checks a proof-of-work header or a
   Merkle proof locally. Two colluding sources are therefore exactly as strong as one.
2. The worst case is the **taker's view of the maker's lock**. The taker CLI's DIVI primary is hard
   wired to the project's own proxy (`bin/divi-swap/src/main.rs:651`), and in the default direction
   the maker leg is DIVI. A maker that runs, or can steer, that proxy can show a lock that does not
   exist, take the preimage from the taker's claim, and claim the taker's coins. Loss: the whole
   taker leg. Nothing local stops it today.
3. Second worst: a fabricated *taker* lock shown to the maker. `single-source-design.md` §3 calls that
   a delay; it is a full loss of the maker leg when the taker is in on the lie, because the taker
   holds the preimage and the maker-leg claim key (`crates/divi-swap/src/maker.rs:717`).
4. Locktimes, confirmation depth and EM's proposed deadline rule bound broadcast censorship and
   MTP shifts, but not a fabricated lock or a hidden spend: a liar fakes the depth along with the lock.
5. Cheapest real fixes, in order: refuse two URLs on one host/domain at startup; require an
   independent (ideally own) DIVI source on a mainnet *taker*; cap value per swap on mainnet until an
   own node exists; local header-chain and Merkle checks for BTC/LTC; an own DIVI node (DIVI is
   proof-of-stake, so the SPV shortcut does not exist there).

## 1. Inventory: what each chain reads from today

"Code says independent?" is whether anything in the code checks that the two sources differ by more
than their URL string.

| Chain | Sources (key → default) | Two-source mode | Code says independent? |
|---|---|---|---|
| DIVI | `[divi].rpc_url` (`bin/divi-swapd/src/config.rs:51`) → `https://services.divi.domains/api/rpc/` (`crates/swap-chain-divi/src/lib.rs:53`); `[divi].fallback_rpc_url` (`config.rs:57`), unset by default; deploy example points it at `http://127.0.0.1:51473`, an own node (`deploy/divi-swapd/divi-swapd.toml.example:21`) | every swap read and the tip on both, broadcast to both (`crates/swap-chain-divi/src/lib.rs:450-505,639-660`; rules in `second_source.rs`) | string compare after `trim` only (`config.rs:101`); required on a mainnet daemon unless `allow_single_source` (`config.rs:910-914`). **Taker CLI: primary is fixed to the default** (`bin/divi-swap/src/main.rs:651`), fallback optional (`:567-586`), not required on mainnet |
| BTC | `[btc].esplora_url`, `fallback_esplora_url` (`config.rs:119,121`) → mempool.space and blockstream.info (`crates/swap-chain-btc/src/lib.rs:49,51,71`) | failover by default; `[btc].quorum_reads` (`config.rs:127`, default off) agrees `confirmations`, `htlc_output`, `find_spend` (`swap-chain-btc/src/lib.rs:681-720`) | string compare after trailing `/` (`config.rs:148-162`) |
| LTC | `[ltc].esplora_url` (`config.rs:176`) → one URL, litecoinspace.org (`crates/swap-chain-ltc/src/lib.rs:59,76`); `[ltc].crosscheck` (`config.rs:187`) → Blockbook `litecoinblockexplorer.net` or BlockCypher (`crates/swap-chain-ltc/src/crosscheck.rs:31,34`) | at `118bc27`: tip−6 hash at start; `crosscheck_before_claim` (`config.rs:197`) repeats it before each claim (`swap-chain-ltc/src/lib.rs:185,717,757`). On lanes not yet merged: lock script/value (EL `4a8f213`), `find_spend` (EN `323618e`), tip−1 and the spend at claim time (EI `c6d3906`) | the two sources are different *products* by construction (Esplora vs Blockbook/BlockCypher); no host check. Required on a mainnet daemon unless waived (`config.rs:849`) |
| ZEC | `[zec].lightwalletd_url`, `fallback_lightwalletd_url` (`config.rs:362,365`) → three hosts under `zec.rocks` (`crates/swap-chain-zec/src/lib.rs:65-69`) | failover only at `118bc27` (`crates/swap-chain-zec/src/grpc.rs:275`). EH (`26f37c3`, not merged): `[zec].crosscheck_url` compares block hashes at start and before every claim and refund | EH is the **only** operator check in any lane: a second URL under a primary's registrable domain is refused (`26f37c3:crates/swap-chain-zec/src/crosscheck.rs:209,240`, "last two labels" of the host) |
| USDC/EVM | `[usdc].rpc_url` (`config.rs:238`) → publicnode (Ethereum) or `mainnet.base.org` (Base) (`crates/swap-chain-evm/src/network.rs:52-53`); `[usdc].fallback_rpc_url` (`config.rs:246`), unset by default | `htlc_output`, `find_spend`, `confirmations`, MTP on both (`crates/swap-chain-evm/src/backend.rs:540-546,813-837`); tip, nonces, gas, broadcast on one | string compare after trailing `/` (`config.rs:284-286`; CLI `bin/divi-swap/src/main.rs:493`); not required on mainnet |
| XMR | `[xmr].monerod_url`, one | none (mainnet not enabled) | n/a |

Things every row shares, which matter for collusion:

- **DNS and TLS are the host's.** All HTTP clients are `reqwest` with `rustls` and its bundled roots
  (`Cargo.toml:99`); ZEC's gRPC uses `tonic` with `tls-webpki-roots` (`crates/swap-chain-zec/Cargo.toml:37`).
  There is no certificate pinning anywhere in the backends (no `add_root_certificate` or similar in
  `crates/swap-chain-*/src`). So whoever controls the swap host's resolver, or can get a certificate
  issued for a hostname, can answer as **both** sources at once.
- **No local proof.** Every backend takes the source's JSON (or protobuf) at its word. Example, BTC:
  `htlc_output_on` reads `/tx/{txid}`, compares `scriptpubkey` with the locally built script and takes
  `value` and `status.confirmed` from the answer (`crates/swap-chain-btc/src/lib.rs:742-767`). No raw
  transaction is hashed against the txid, no Merkle proof is checked, no header's work is checked
  (there is no Merkle code in any `crates/swap-chain-*/src`).
- **Where the code assumes independence:** the agreement functions. Each returns the shared answer
  when the two match, and for counts takes the lower one: BTC `quorum::pair/agree_*`
  (`crates/swap-chain-btc/src/quorum.rs:33,45,63,91`), DIVI `second_source::pair/agree_*`
  (`crates/swap-chain-divi/src/second_source.rs:48,67,78,107,132,139`; tolerances `:24,29,36`), EVM
  `quorum::second/agree_*` (`crates/swap-chain-evm/src/quorum.rs:38,42,53,81,115`), LTC
  `CrossCheckOutcome` (`crates/swap-chain-ltc/src/crosscheck.rs:119`). "Lower wins" clips an
  inflation by **one** liar; two liars inflating together pass untouched.

Independence in practice, from the defaults (operator facts in the FACTS file):

- **DIVI:** the default proxy is on `divi.domains`, the project's own domain; the reference maker also
  runs for the project (dnsdivi, `deploy/divi-swapd/README.md:1`). For a taker using the CLI, the
  counterparty's organisation may be the only DIVI source the taker sees. This is the most important
  non-independence in the tree.
- **BTC:** two hostnames, two companies as far as the names go, but the same family of software
  (Esplora / electrs), so a shared bug is a shared lie.
- **LTC:** litecoinspace.org is a port of mempool.space's software announced by the Litecoin
  Foundation; Blockbook and BlockCypher are different products, which is the best default pairing in
  the tree.
- **ZEC:** three hostnames under one domain: one operator for practical purposes (`lib.rs:65-69`).
- **USDC:** the default primary is a shared public RPC; the fallback is whatever the operator sets.

## 2. Threat model: who can make both sources agree on a lie

Who can do it:

| Actor | How both sources lie at once | Needs |
|---|---|---|
| A. Same operator under two names | runs both endpoints | nothing extra; the commonest case (one company, two brands, or one company reselling another's node) |
| B. One upstream behind both | two front ends forwarding to one node or one indexer | operator of the shared upstream |
| C. One hosting provider / cloud | both endpoints on one provider, provider compromised or compelled | provider access |
| D. Network or DNS of the swap host | spoofs both hostnames (resolver poisoning, BGP, a captive network) and presents a certificate a bundled root accepts | the host's network path and a mis-issued or stolen certificate; with a plain `http://` fallback (the deploy examples use `http://127.0.0.1`) only the network path |
| E. The counterparty | is A, B or C for my sources, or pays one of them | for a taker using defaults against the project's maker on DIVI: possibly nothing (§1) |

"Silent while the other lies": every two-source mode treats one source not answering as `Transient`
(DIVI `second_source.rs:48`, BTC `quorum.rs:33`, EVM `quorum.rs:38`, ZEC EH holds), except LTC, where
an unreachable cross-check source warns and the claim goes ahead (`swap-chain-ltc/src/lib.rs:185-230`;
`deploy/divi-swapd/README.md:35`). So a liar that can knock the LTC cross-check source offline is back
to one source; elsewhere a silent second source is a stall, which is EM's bounded-hold problem
(`~/swap-lanes/builders/EM/STATUS.md`, decisions, not merged), not a lie getting through.

What each lie costs, per acting point. "MC" is the maker-leg chain (DIVI by default), "TC" the
taker-leg chain. Ranked by funds at risk, worst first.

| # | Acting point (code) | The lie | Who must lie to whom | Loss |
|---|---|---|---|---|
| 1 | **Taker claims the maker leg** after `htlc_output` shows it deep enough (`crates/divi-swap/src/taker.rs:552-571`) | a maker lock that does not exist, or a real one with fake depth | the maker (E) via the taker's MC sources | the claim tx carries the preimage; it only has to reach the maker (it goes out through the same liars). The maker claims the real taker leg. **Taker loses the whole taker leg.** The maker needs no reorg and no real lock. |
| 2 | **Maker locks the maker leg** after the taker lock is confirmed (`maker.rs:646-720`) | a taker lock that does not exist, or is short | the taker (E) via the maker's TC sources | the maker locks real DIVI; the taker, who holds the preimage and the maker-leg claim key (`maker.rs:717`), claims it. **Maker loses the whole maker leg.** (Corrects `single-source-design.md` §3, LTC row, which reads this as a delay: that holds only when the liar is not the taker.) |
| 3 | **Maker learns the preimage** from a spend of its lock (`maker.rs:1111-1127`, `find_spend`) | the taker's claim of the maker leg is hidden | the taker via the maker's MC sources | the maker never claims the taker leg; the taker refunds it at its locktime. **Maker loses the maker leg.** A *fake* spend does not work: the preimage is checked against the hash locally (`crates/divi-swap/src/types.rs:254-262`). |
| 4 | **Taker's claim deadline** (`taker.rs:561-571`, `ClaimDeadline::check`, `crates/divi-swap/src/config.rs:92-160`) | MC median time past reported low | the maker via the taker's MC sources | the taker claims when the maker can already refund; the maker refunds the maker leg and claims the taker leg with the preimage. **Taker loses the taker leg**, against a real lock, so it is cheaper for the attacker than #1. |
| 5 | **Claim broadcast** (maker `maker.rs:959,997`; taker `taker.rs:678`) | "sent" while the tx is swallowed (DIVI sends to both and succeeds if either accepts, `swap-chain-divi/src/lib.rs:639-660`; EVM accepts `already known`, `swap-chain-evm/src/backend.rs:122`) | anyone in A–D | the claim misses the counterparty's refund locktime; the counterparty refunds and, for a maker, has already taken the maker leg. **Full leg**, but only if the censorship lasts past the locktime margin. |
| 6 | **Refund** (maker `maker.rs:884`; taker `taker.rs:790`) and its timing (`refund_final`, `maker.rs:1104-1108`) | MTP high (refund sent early: rejected and retried) or low (refund late); refund swallowed | A–D | with the preimage still secret: funds stuck, not lost. With the preimage public: the counterparty's claim can win the race. |
| 7 | **Funding reads** (wallet scan, `build_funding`) | invented coins; a coin's value reported low | A–D | invented coins make an invalid tx (a stall). DIVI's signature hash takes no input amount (`crates/divi-wallet/src/signer.rs:33`), so a coin reported low makes the wallet sign a tx whose real fee is the difference: **coins go to the block producer**, bounded by the coin's value; the liar gains nothing unless it also produces the block. On BTC/LTC segwit the amount is signed, so this is a stall only. |
| 8 | **Maker's own locktime** is `MTP + maker_timeout` (`maker.rs:714-720`) | MTP low | A–D | the maker leg becomes refundable earlier than intended; it shortens the taker's window, which the taker checks on its own view (`taker.rs:574`, `check_maker_leg_locktime`). Not a maker loss. |

Rows 1–4 are the permanent-loss rows. They all have the same shape as in `single-source-design.md`:
a lie about **the other party's lock**, or about **a spend of my own lock**, read by the side that
is about to act. What is new here: in rows 1, 2 and 4 the liar is the counterparty, so the attack is
paid for out of the swap itself, and in row 1 the counterparty may already be the source.

## 3. What a quorum detects, and what it cannot, when both collude

| Lie | One source lying | Both lying, same answer | Bounded anyway by |
|---|---|---|---|
| fabricated lock (rows 1, 2) | caught: "seen by one only" is `Transient` (BTC `quorum.rs:63`, DIVI `second_source.rs:78`, EVM `quorum.rs:53`; LTC with EL) | **not caught** | nothing: depth is faked with the lock; the claim deadline reads the same liars |
| fake depth on a real lock | clipped to the lower count | **not caught** | only by real reorg odds; the liar does not need a reorg if the lock is fake |
| hidden spend (row 3) | caught (spend seen by one only) | **not caught** | the taker-leg refund locktime makes it a loss, not a bound |
| fake spend | caught | caught locally: wrong preimage fails the hash (`types.rs:254-262`) | n/a |
| fake tip (high) | DIVI and BTC-quorum take the lower tip (`second_source.rs:139`) | **not caught**; inflates confirmations where counted from the tip | — |
| fake MTP (rows 4, 6) | DIVI within 600 s (`second_source.rs:29`), EVM the lower (`quorum.rs:115`) | **not caught** | low MTP late-claim (row 4): not bounded. High or low refund MTP: the real network rejects an early refund, so it is a delay |
| stalled broadcast (row 5) | DIVI sends to both; others primary then failover | **not caught**, by any lane today; EO's two-source broadcast helps only if the second path is not a colluder | the counterparty's refund locktime minus the claim margin (`ClaimDeadline`, `config.rs:92-160`: BTC 3600 s, LTC/ZEC/DIVI/USDC 1800 s, from EM's audit) |
| one silent, one lying | `Transient` (stall) everywhere except LTC, where the claim goes on the primary alone | — | EM's proposed rule: for a still-secret preimage decline and refund; for a public preimage act on the primary at the deadline (EM STATUS, decisions 3) |

EM's deadline rule (proposed, `lane/bounded-hold` has no commit beyond `f777721` yet) ends a *hold*;
it does not detect a lie. It is safe against collusion for the same reason it is safe at all: it
never reveals a secret preimage on one source (H1 declines), and after the preimage is public a
colluder cannot make things worse by being believed. It does not help rows 1–4.

## 4. Proposed mitigations, cheapest first

| # | Mitigation | Cost | Closes | Leaves |
|---|---|---|---|---|
| M1 | **Startup independence check.** Refuse two sources on one host, one registrable domain, or one resolved IP; on mainnet refuse a plain `http://` second source unless it is loopback. Generalise EH's `operator_domain`/`check_second_operator` (`26f37c3:crates/swap-chain-zec/src/crosscheck.rs:209,240`) into one shared helper called from the four config checks (`config.rs:101,148,284`, and the LTC cross-check source) and the CLI (`bin/divi-swap/src/main.rs:582,493`). Use the public-suffix list, not EH's "last two labels", which reads `a.co.uk` and `b.co.uk` as one operator. | small; one helper, a dozen config tests; a PSL crate dependency (pinned) | actor A when the two names share a domain; the copy-paste mistake of one node under two URLs (today only exact string equality is refused) | two brands with different domains on one operator (A), B, C, D, E. An ASN check would add C but needs an IP-to-ASN dataset shipped and kept current: not worth it before M3/M5 |
| M2 | **Mainnet taker gate for DIVI.** The taker CLI refuses `--profile mainnet` without `--divi-fallback-rpc-url`, and warns that the default primary is run by the project (same as DU did for the daemon, `config.rs:910-914`). Better: let the taker set the primary too (`--divi-rpc-url`), so a taker with an own node never asks the project. | small; CLI flag and two tests | row 1 for the default direction against the project's maker — the worst row | a taker who points both at sources the maker controls |
| M3 | **Value caps on mainnet until an own node.** A per-swap cap and a total-in-flight cap per chain in the daemon (the offer already has `min/max_btc_sats`, `config.rs` `validate`); the taker CLI refuses an amount over a cap unless an own-node flag is set. | small code; the numbers are a money decision | nothing technically; it **bounds** rows 1–5 to the cap | all lies below the cap |
| M4 | **Disagreement history and alerting.** Count every agree-failure per source pair and chain (they are already logged as `Transient` with both URLs); expose the count on `/healthz`/status and alert on any. Two sources that never disagree in months, even on tip lag, are themselves a sign of one upstream. | small; no protocol change | turns a one-off lie that one source tells first into an operator alarm; spots B (identical lag patterns) | a pair that lies together from the first request |
| M5 | **Own node on the high-value path.** For the maker: an own DIVI node as `fallback_rpc_url` (already the deploy example, `divi-swapd.toml.example:21`), own `bitcoind`+electrs/Esplora, own Litecoin node. For a mainnet taker: an own DIVI node or a third party not related to the maker. | a host per chain, disk (a full BTC node is the large one), upkeep; no protocol change | A, B, C for every chain on which it runs; with a loopback URL, D as well | the own node's own peers (an eclipse attack on it is the remaining path, much harder); the node being out of date |
| M6 | **Local header and Merkle checks, BTC and LTC (SPV-style).** Keep a header chain locally from a shipped checkpoint, accept a reported tx only with a Merkle proof into a header on the most-work chain, and count confirmations from local headers. Esplora is documented to serve headers and Merkle proofs (not verified here; FACTS file); a header is 80 bytes, so the whole chain is small. | medium: a header store, proof verification, checkpoint upkeep, tests; per chain | rows 1–4 on BTC/LTC against any collusion short of producing real blocks: a fake lock now needs the work of N real blocks | DIVI (proof-of-stake: no work to check; a header chain needs stake validation, which is close to a full node — so M5 instead), ZEC (Equihash headers, possible but more code; compact blocks already carry headers), EVM (proof-of-stake beacon: light client is heavy — own node instead); a hidden spend (row 3) still needs a scan of every block in the window against local headers, which is the expensive part |
| M7 | **Third source, 2-of-3 or 3-of-3.** | another endpoint per chain; small code on top of the existing pair helpers | a colluding pair when the third is honest | three colluders; adds stalls when any one is down |
| M8 | **Broadcast through a different path** (EO), ideally P2P to the chain's own peers, not another HTTP API. | EO in progress for BTC/LTC | row 5 when the paths are independent | colluding broadcast paths; and it is useless if the reads already lie (rows 1–4) |

Recommended order: M1, M2, M3 and M4 now (all small, config or CLI only, no protocol change); M5 on
the maker's host before any mainnet value beyond the M3 cap; M6 for BTC/LTC only if takers are
expected without own nodes; M7 is dominated by M5.

## 5. Fail-first tests to write later

All with the existing wiremock / mock servers; no network. "Before" is `118bc27`.

**M1 independence check** (`bin/divi-swapd` config tests, CLI tests):
- `divi_fallback_on_the_same_host_is_refused`: `rpc_url = "https://n.example.org/a/"`,
  `fallback_rpc_url = "https://n.example.org/b/"`. Before: config loads. After: refused, message names
  both URLs and the shared host.
- `divi_fallback_with_a_trailing_slash_is_the_same_url`: `.../rpc/` vs `.../rpc`. Before: loads
  (`config.rs:101` trims spaces only). After: refused.
- `btc_quorum_on_one_registrable_domain_is_refused`: `a.example.co.uk` and `b.example.co.uk`. Before:
  loads. After: refused; and `a.co.uk` vs `b.co.uk` (different operators under a public suffix) loads.
- `usdc_fallback_on_the_same_ip_is_refused`: `http://127.0.0.1:8545` vs `http://localhost:8545`.
  Before: loads. After: refused (resolve both at load; a host that does not resolve is a warning, not a refusal).
- `mainnet_plain_http_second_source_off_loopback_is_refused`: mainnet profile,
  `fallback_rpc_url = "http://10.0.0.5:51473"`. Before: loads. After: refused; `http://127.0.0.1:51473` loads.

**M2 mainnet taker gate** (`bin/divi-swap` tests):
- `mainnet_taker_without_a_divi_second_source_is_refused`: `--profile mainnet`, no
  `--divi-fallback-rpc-url`. Before: runs. After: refused with the reason.
- `taker_divi_rpc_url_replaces_the_default_primary`: `--divi-rpc-url http://mock`; the mock counts
  requests. Before: the flag does not exist (clap error). After: the mock gets the reads, the default does not.

**M3 caps** (`divi-swap` engine, `MockBackend`):
- `maker_refuses_a_swap_over_the_mainnet_cap`: mainnet profile, cap 10 DIVI, quote for 11. Before:
  accepted. After: refused at quote/accept, nothing reserved.
- `in_flight_cap_counts_open_swaps`: two swaps of 6 under a 10 cap. Before: both lock. After: the second waits or is refused.

**M4 disagreement history** (`swap-chain-divi`, `swap-chain-btc`, `swap-chain-evm` unit tests):
- `a_disagreement_increments_the_pair_counter`: two wiremock sources, different `confirmations`.
  Before: no counter (does not compile). After: counter 1, `Transient` unchanged.
- `status_reports_disagreements_per_chain`: divi-swapd status route after one disagreement. Before:
  field absent. After: present with chain and both URLs (no secrets).

**M6 header/Merkle checks** (`swap-chain-btc`, later `swap-chain-ltc`):
- `a_lock_without_a_merkle_proof_is_not_a_lock`: both wiremock Esploras return the same `/tx` with
  `confirmed: true` and no valid proof. Before: `htlc_output` returns `Some` with confirmations.
  After: `None` (or `Transient`).
- `confirmations_come_from_local_headers`: both sources report tip +100 with headers that do not link
  to the checkpoint. Before: confirmations inflated by 100. After: counted from the local chain only.
- `a_header_chain_with_too_little_work_is_refused`: valid links, difficulty-1 headers on mainnet
  parameters. Before: n/a. After: refused.
- Engine level (`divi-swap`, `MockBackend` wrapping two identical liars): `taker_does_not_claim_a_lock_both_sources_invent`
  and `maker_does_not_lock_on_a_taker_lock_both_sources_invent`. Before: the taker signs a claim / the
  maker locks (these document rows 1 and 2 and stay red until M5 or M6 lands for that chain). After: no claim, no lock.

## 6. NEEDS HUMAN: decisions for Bert

1. **Taker DIVI source on mainnet**: refuse a mainnet taker that has only the project's own DIVI
   proxy (M2), or ship it as a warning and a documented risk? (Protocol/UX decision: refusing means a
   mainnet taker needs a second DIVI source before the first swap.)
2. **Value caps**: per-swap and total-in-flight caps per chain on mainnet until own nodes run (M3).
   The numbers are a money decision.
3. **Own nodes**: run an own DIVI node (and BTC/LTC nodes) on the maker's host as the mainnet second
   source (M5): which host, and who pays for the disk and upkeep?
4. **How strict the independence check is** (M1): refuse same host/domain/IP (recommended), or also
   require different network operators (ASN), which needs a dataset shipped and kept current.
5. **SPV checks for BTC/LTC** (M6): build them (medium work, checkpoint upkeep) or rely on own nodes
   only?
6. **Where disagreement alerts go** (M4): which channel the operator watches.
