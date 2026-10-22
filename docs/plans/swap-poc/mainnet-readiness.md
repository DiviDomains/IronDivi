# Mainnet-readiness review

Lane `zec`, 2026-10-12. Scope per the orchestrator's task: for each coin, list the mainnet
values the code would use *today*, mark each `ok` or `risky: <reason>`, cite `file:line` for
every value. Code changes are in-scope only for `crates/swap-chain-zec` and
`crates/divi-swap/src/config.rs`; every other crate gets a finding, not a patch.

Headline result: **three of the five coins (BTC, LTC, XMR) have no mainnet network support at
all** — their endpoint/address code only knows how to talk to a test network, by construction,
not by a disableable flag. (ZEC was in that group until 2026-10-21: it now has mainnet address
prefixes, a mainnet lightwalletd list, and picks v5/v6 by the NU6.3 activation height — see
ZEC §Facts. An earlier version of this paragraph blamed NU7; that was wrong.)
EVM is the only coin whose backend is architecturally mainnet-capable today (it just isn't
*pointed* at mainnet). None of this is a surprise regression — every one of these crates was
built, by design, against test networks (docs/plans/swap-poc/multi-coin.md) — but "mainnet
values the code would use today" for most of these coins is "none exist yet," which is itself
the finding.

One concrete bug *was* found and fixed in my own crate: ZEC's dust floor was borrowed byte-for-
byte from Bitcoin and didn't account for ZIP 317's flat per-action fee, so a dust-sized ZEC
output was spendable-by-the-old-rule but worth less than it would cost to ever spend. Fixed;
see ZEC §Dust limits.

## Decision: testnet-only is intended for this POC

The POC's definition of done (`docs/plans/atomic-swap-poc.md` §1) is "proven on public
testnets", and mainnet was never in its scope. So the missing mainnet support below is
deliberate, not a defect, and nothing in this repo should be run with real funds. Moving to
mainnet is a separate project, tracked as these work items (one per coin, plus shared):

- [x] **BTC:** mainnet `Network` + esplora endpoint list — done on `lane/btc-ltc-mainnet-wiring` (`swap-chain-btc/src/lib.rs:46-69,132-150`), gated by `[btc].allow_mainnet` / `--allow-mainnet`. Still open: raise mainnet confirmations above 2.
- [x] **LTC:** mainnet HRP and endpoint — done on `lane/btc-ltc-mainnet-wiring` (`swap-chain-ltc/src/lib.rs:50-69,133-152`), gated by `[ltc].allow_mainnet` / `--allow-mainnet`. Still open: no second mainnet mirror is known.
- [x] **ZEC:** add mainnet address prefixes and a lightwalletd endpoint, and pick the v5/v6 tx format by activation height — done in `71ed663` on `lane/zec-mainnet-readiness`: `address.rs:30-36`, `lib.rs:61-77`, `tx.rs:59-80`. The format switch is the **NU6.3** activation height (not NU7): see ZEC §Facts.
- [ ] **USDC/EVM:** ~~add Ethereum/Base mainnet `network.rs` variants with the canonical USDC addresses~~ (done 2026-10-21, behind `allow_mainnet`); an audited HTLC deployment is still open.
- [ ] **XMR:** mainnet backends, and remove the runtime refusal only after the above (`xmr_live.rs:174-191`). Sequenced plan with gates: `xmr-mainnet-plan.md`.
- [x] **Shared:** a mainnet timeout/confirmation profile — done: `Profile::{Mainnet,Testnet}`, `ChainParams::builtin` and `SwapConfig::profile` (`divi-swap/src/config.rs:17-56,97-120`), and `check_profile_networks` (`:226`), which `divi-swapd` (config load, `bin/divi-swapd/src/config.rs:677`) and `divi-swap` (`--profile`, before any network call, `bin/divi-swap/src/main.rs:440`) both call so the profile must agree with every configured coin's `network` and `allow_mainnet` (xmr and usdc included). Still open: an external security review, and staged low-value mainnet trials.

## BTC

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 2 | `crates/divi-swap/src/config.rs:44` | risky: thin — see below |
| MTP lag (mainnet) | 3600s | `crates/divi-swap/src/config.rs:44` | ok |
| Taker/maker timeout, claim margin | 24h / 12h / 3600s (shared, not BTC-specific) | `crates/divi-swap/src/config.rs:97-98,102` | ok |
| Fee policy | `Recommended { floor: 2 }` sat/vB, live `/v1/fees/recommended` `halfHourFee`, floor 2 | `crates/swap-chain-btc/src/lib.rs:60-74,138-154` | ok (live-estimated with a sane floor) |
| Dust limit | 294 sat | `crates/swap-chain-btc/src/tx.rs:27` | ok (standard P2WPKH relay floor) |
| Reorg depth assumption | = confirmations (2 blocks ≈ 20 min) | `crates/divi-swap/src/config.rs:44` | risky: thin for a trustless, no-recourse swap |
| Public backends | `mempool.space/signet`, `blockstream.info/signet`, `mempool.space/testnet`, `blockstream.info/testnet` — `esplora_endpoints()` only accepts `"signet"`/`"testnet"`, rejects anything else | `crates/swap-chain-btc/src/lib.rs:37-55` | **risky: no mainnet endpoint option exists** |
| Address network | `Address::p2wpkh(&pubkey, Network::Signet)` — hardcoded | `crates/swap-chain-btc/src/lib.rs:107` | **risky: backend is structurally signet/testnet-only** |

Findings (no code change — not my crate):
- `esplora_endpoints` (`lib.rs:48-55`) has no `"mainnet"` arm at all; adding one needs a
  mainnet Esplora pair (e.g. `mempool.space/api` + `blockstream.info/api`) and a
  `Network::Bitcoin` address path (`lib.rs:107`) — two independent hardcodes to generalize, not
  one.
- 2 confirmations (~20 min) is on the thin side of common practice for trustless, high-value
  transfers (exchanges commonly use 3-6; some bridges use 1-2). This is a judgment call the
  `btc` lane/orchestrator should weigh explicitly against the swap's intended value ceiling,
  not something this review can declare wrong outright — flagged `risky` because the tradeoff
  isn't written down anywhere, not because 2 is provably unsafe.

## LTC

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 6 | `crates/divi-swap/src/config.rs:46` | ok (≈15 min at 2.5 min/block) |
| MTP lag (mainnet) | 1800s | `crates/divi-swap/src/config.rs:46` | ok |
| Taker/maker timeout, claim margin | shared (see BTC) | `crates/divi-swap/src/config.rs:97-98,102` | ok |
| Fee policy | `Recommended { floor: 1 }` sat/vB, live `/v1/fees/recommended` against `litecoinspace.org`, floor 1 | `crates/swap-chain-ltc/src/lib.rs:63-78,137-151` | ok |
| Dust limit | 294 sat (litoshi) | `crates/swap-chain-ltc/src/tx.rs:31` | ok (same P2WPKH-shaped relay floor, correctly chain-agnostic since it's a byte-size rule) |
| Reorg depth assumption | = confirmations (6 blocks ≈ 15 min) | `crates/divi-swap/src/config.rs:46` | ok |
| Public backends | `litecoinspace.org/testnet/api` only — `esplora_endpoints()` only accepts `"testnet"`; no secondary mirror ("no independent secondary mirror of this API shape was found publicly", own comment) | `crates/swap-chain-ltc/src/lib.rs:44-58` | **risky: single endpoint, no fallback, no mainnet option** |
| Address network | `encode_segwit_v0(TLTC_HRP, ...)` hardcoded; `LTC_HRP` (mainnet prefix) is defined but **"unused in the POC; kept so the HRP is a single switch"** | `crates/swap-chain-ltc/src/lib.rs:111`, `crates/swap-chain-ltc/src/address.rs:20-22` | **risky: mainnet HRP constant exists but is dead code — not wired to anything** |

Findings (no code change — not my crate):
- LTC is the only coin with a single, unmirrored data source for its *entire* chain view — a
  single operator outage stalls every in-flight swap, before mainnet is even considered.
- The mainnet bech32 HRP constant already exists (`address.rs:20-22`) but nothing in
  `esplora_endpoints`/`for_network` can select it — closer to mainnet than BTC in that one
  piece already exists, but the endpoint side is just as missing.

## ZEC (my crate — code changed where a real gap was found)

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 10 | `crates/divi-swap/src/config.rs:50` | ok, see note |
| MTP lag (mainnet) | 1800s | `crates/divi-swap/src/config.rs:50` | ok (generously oversized relative to NU7's ~25s blocks; conservative, not unsafe) |
| Taker/maker timeout, claim margin | shared (see BTC) | `crates/divi-swap/src/config.rs:97-98,102` | ok |
| Fee policy | `FeePolicy::Fixed(2)` zat/byte, but every spend pays `max(rate*size, zip317_fee(...))` — the ZIP-317 conventional fee always wins for these tx sizes | `crates/swap-chain-zec/src/lib.rs:46-63`; `crates/swap-chain-zec/src/tx.rs:1188,1020-1030` | ok — ZIP-317-safe by construction regardless of the fixed rate |
| ZIP-317 constants | marginal fee 5000 zat/action, grace 2 actions, in-weight 150B, out-weight 34B | `crates/swap-chain-zec/src/tx.rs:1001,1004,1007,1009` | ok — pinned against Zebra's live NU7-testnet mempool rejection message, see `tx.rs:1727-1730` |
| **Dust limit** | **was** 294 zat (byte-based, borrowed from Bitcoin); **now** 5000 zat (= `ZIP317_MARGINAL_FEE`) | `crates/swap-chain-zec/src/tx.rs:50-56` | **was risky, now fixed** — see below |
| Transaction version | v5 below the network's **NU6.3** activation height, v6 at/above (mainnet 3428143, testnet 4134000), via `tx_version_for(network, tip+1)`; v6 is [ZIP 229](https://zips.z.cash/zip-0229) (Draft), deployed by NU6.3 ([ZIP 258](https://zips.z.cash/zip-0258), Final); NU7 adds no tx format | `crates/swap-chain-zec/src/tx.rs:37-80,679-760`; `lib.rs:239-244` | **fixed** — see Facts; naming settled (NU6.3; "Ironwood" is the pool) |
| Reorg depth assumption | = confirmations (10 blocks) | `crates/divi-swap/src/config.rs:50` | ok either side of NU7 mainnet activation — see note |
| Public backends | `MAINNET_LIGHTWALLETD` = `zec.rocks`, `na.zec.rocks`, `eu.zec.rocks` (:443, each TLS+ALPN h2 verified 2026-10-21); testnet still the single `testnet.zec.rocks` (20-min re-search found no second one) | `crates/swap-chain-zec/src/lib.rs:61-77` | **mainnet fixed; testnet single-endpoint remains** (env `SWAP_ZEC_LIGHTWALLETD_EXTRA` still extends) |
| CLI mainnet read-only smoke | 2026-10-21 hp3: `divi-swap --backend live --counter-chain zec --zec-network mainnet --allow-mainnet balance` with a throwaway zero-balance key: `zec_address=t1…` (after the fix below; it printed `tm…` before), `zec_balance_sats=0`, 0.10 s; without `--allow-mainnet` it refuses before any network call (0.01 s): "--zec-network mainnet moves real money: no mainnet without the explicit --allow-mainnet opt-in" | `bin/divi-swap/src/main.rs:244` | **verified**; bug fixed: the address was encoded with `encode()` (testnet-only) instead of the backend network, now `ZecBackend::encoded_address` |
| daemon mainnet read-only smoke | 2026-10-21T19:02Z hp3: `divi-swapd --backend live` with `profile = "mainnet"`, `[zec] network = "mainnet" allow_mainnet = true`, no `lightwalletd_url` (default primary `zec.rocks:443`): log "zec backend ready" address `t1…` network mainnet; `/healthz` zec tip **3525840** (>= L's 3525726); gate 2: `allow_mainnet = false` exits "[zec].network = \"mainnet\": zec mainnet moves real money: no mainnet without the explicit allow_mainnet opt-in"; gate 3: `profile = "testnet"` + mainnet exits "[zec].network = \"mainnet\" disagrees with profile = Testnet" | `bin/divi-swapd/src/main.rs:349-362` | **verified**, no funds |
| Address prefixes | testnet `tm…`/`t2…` `[0x1d,0x25]`/`[0x1c,0xba]`; mainnet `t1…`/`t3…` `[0x1c,0xb8]`/`[0x1c,0xbd]`; `encode_for`/`decode_for(network)` reject the other network | `crates/swap-chain-zec/src/address.rs:26-36` | **fixed** (librustzcash `zcash_protocol` constants; protocol-spec cross-check: could not verify) |
| Daemon/CLI network selection | `[zec].network` (default `testnet`) + `[zec].allow_mainnet` (default `false`), validated against the daemon's `profile` at config load; `--zec-network`/`--allow-mainnet` on the CLI, validated before any network call | `bin/divi-swapd/src/config.rs:175-213` (`ZecSection`), `:558-579` (`DaemonConfig::validate`'s zec check); `bin/divi-swapd/src/main.rs:349-362` (`live_zec`); `bin/divi-swap/src/main.rs:372-384` (`live_backends`'s zec guard) | **fixed** (builder L, 2026-10-21) |

### Dust limit — fixed this review

`DUST_ZATOSHI` (`tx.rs:51` before this change) was `294`, commented "same floor as Bitcoin
P2PKH dust" — copied from Bitcoin's byte-size-based relay rule. But ZEC's real fee floor under
ZIP 317 is a **flat 5000 zat per logical action** (`ZIP317_MARGINAL_FEE`, `tx.rs:1001`), not a
per-byte rate — so a 294-zat output is *technically* non-dust by the old byte rule, but costs
far more to ever spend (≥5000 zat marginal fee) than it is worth. That's a real "unsafe mainnet
value": a wallet could receive change or a claim payout worth less than the fee needed to move
it again, stranding it forever in all but name.

Fix: `DUST_ZATOSHI` is now defined as `ZIP317_MARGINAL_FEE` (`tx.rs:56`), so the floor tracks
the real fee regime instead of a borrowed, unrelated one. Added
`tx::tests::dust_floor_covers_the_zip317_marginal_fee` (`tx.rs:1784-1790`), a `const` assertion
that fails to *compile* (not just fails a test) if `DUST_ZATOSHI` ever regresses below the
marginal fee — confirmed failing against the old `294` value, confirmed passing against the
fix. All 18 existing `swap-chain-zec` unit tests still pass unchanged (every computed
`change`/`out_value` in those tests is either far above 5000 or exactly at the old
below-dust-folds-into-fee boundary of 250, which is below *either* threshold, so no test
assumed a value in the 294-5000 gap).

### Facts (checked 2026-10-21 against zips.z.cash, fetched with curl on hp2)

| Claim | Verdict | URL |
|---|---|---|
| ZIP 229 "Version 6 Transaction Format" (status Draft) defines v6; "This transaction format is deployed at NU6.3"; "If the transaction version number is 6 then the version group ID MUST be `0xD884B698`" | verified | https://zips.z.cash/zip-0229 |
| ZIP 230 "Withdrawn Version 6 Transaction Format" is Withdrawn and obsoleted by ZIP 229 — it is **not** the live spec (the earlier oracle citation of ZIP 230 was wrong) | verified | https://zips.z.cash/zip-0230 , https://zips.z.cash/ |
| Upgrade that deploys v6 is **NU6.3** (ZIP 258, Final); "Ironwood" is the shielded pool it introduces, not an upgrade name; there is no upgrade called "NU6.3 Ironwood" | verified | https://zips.z.cash/zip-0258 |
| NU6.3 consensus branch ID `0x37A5165B`; activation height testnet **4134000**, mainnet **3428143** | verified | https://zips.z.cash/zip-0258 |
| NU6.3 leaves v5 transactions valid ("version 5 and version 6 transactions remain valid" restrictions apply to both) | verified | https://zips.z.cash/zip-0258 |
| NU7 = ZIP 259 "Deployment of the NU7 Network Upgrade", status **Draft**; "NU7 introduces no new transaction format"; v4 becomes invalid, v5/v6 stay valid; branch ID `0x77190AD9`; blocks 75s→25s | verified | https://zips.z.cash/zip-0259 |
| NU7 testnet activation height 4465026 | verified (ZIP 259 text) | https://zips.z.cash/zip-0259 |
| NU7 mainnet activation height | **could not verify** — ZIP 259 says "TBD (To be set on OCT 20)"; no height, no date in the ZIP | https://zips.z.cash/zip-0259 |
| Mainnet NU7 date 2026-11-05 and the 2026-10-20 go/no-go outcome | **could not verify** — z.cash/upgrade/ names NU7 but gives no height, date or decision; ZIP 259 gives none either | https://z.cash/upgrade/ , https://zips.z.cash/zip-0259 |
| Mainnet transparent Base58Check prefixes `[0x1c,0xb8]` (t1) / `[0x1c,0xbd]` (t3); testnet `[0x1d,0x25]` / `[0x1c,0xba]` | verified in librustzcash constants; protocol.pdf §5.6.1.1 could not verify (no extractable text layer) | https://raw.githubusercontent.com/zcash/librustzcash/main/components/zcash_protocol/src/constants/mainnet.rs , .../testnet.rs |
| Mainnet chain tip is currently >= 3428143 (NU6.3 already live on mainnet) | **verified** 2026-10-21T16:40:06Z: tip 3525726 from `https://zec.rocks:443` (`crates/swap-chain-zec/src/lib.rs` `tests::mainnet_tip_reachable`, builder L) | https://zips.z.cash/zip-0258 |

**Consequence — the premise of this line item was wrong.** v6 is a NU6.3 feature, not NU7. The
backend therefore switches at the **NU6.3** height per network (`NU6_3_MAINNET_ACTIVATION_HEIGHT =
3428143`, `NU6_3_TESTNET_ACTIVATION_HEIGHT = 4134000`, `tx.rs:59,63`), and NU7's mainnet
height does not affect the transaction format at all. (The earlier text here that "every
transaction this backend builds would be rejected by mainnet until NU7" is withdrawn.) NU7 still
matters for fees/timing — 25s blocks, ZIP 317 revision, and v4 invalidation — but needs no
code change here. **Before pointing the crate at mainnet:** confirm the mainnet tip is above
3428143 (otherwise it builds v5, which is the correct fallback either way).

Status of tests: `tx_version_for_switches_at_each_networks_nu6_3_height`,
`v5_build_uses_v5_group_id_and_omits_the_ironwood_section`,
`v5_and_v6_builds_parse_back_with_matching_txid`, `v5_spend_and_funding_build_and_self_verify`;
the existing v6 vectors are unchanged.

### Confirmations/reorg depth — not risky, despite the NU7 timing

`ChainParams::builtin`'s ZEC mainnet confirmations (10, `config.rs:50`) was tuned against a
measured ~25s/block NU7 rate to land on ~225s of finality depth (see the "done" entry in
`docs/plans/swap-poc/status/zec.md` for the 3→9 testnet history of this same reasoning). Given
the Facts above — mainnet NU7 has no published height (ZIP 259: TBD), so mainnet is presumably
still at Zcash's traditional ~75s block time (not verified) — confirmations=10 against *today's*
mainnet would give ~750s of depth: three times the intended margin, not less. The number stays
safe on both sides of NU7 activation (whenever it is set): too conservative before it, on-target after. No finding, no fix needed.

## USDC/EVM

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 12 | `crates/divi-swap/src/config.rs:56` | ok — standard Ethereum-mainnet finality heuristic |
| MTP lag (mainnet) | 180s | `crates/divi-swap/src/config.rs:56` | ok ("no MTP smoothing on EVM... lag only needs to cover block-time jitter", own comment) |
| Taker/maker timeout, claim margin | shared (see BTC) | `crates/divi-swap/src/config.rs:97-98,102` | ok |
| Gas price | live `provider.estimate_eip1559_fees()` for `max_fee_per_gas`/`max_priority_fee_per_gas` | `crates/swap-chain-evm/src/backend.rs:249-256` | ok — dynamically sourced, not hardcoded |
| Gas limit | live `estimate_gas` + 20% headroom | `crates/swap-chain-evm/src/backend.rs:235-254` | ok |
| Dust/minimum amount | `amount_to_usdc_units` rejects non-whole-unit amounts (precision guard, not an economic floor); `usdc_offer_is_fundable(min_eth_wei, min_usdc_units)` takes its floors as **caller-supplied parameters** — no hardcoded floor in this crate | `crates/swap-chain-evm/src/backend.rs:56-64,85-97` | ok (correctly config-driven at this layer) — the actual default floor values (reported elsewhere as ~0.01 ETH / 10 USDC) live outside this crate; out of scope for this review |
| Public backends / network | `UsdcNetwork` now has `Sepolia`, `BaseSepolia`, `Ethereum` (`"ethereum"`, chain id 1) and `Base` (`"base"`, chain id 8453) with `is_mainnet()`; native Circle USDC `0xA0b8…eB48` / `0x8335…2913` from <https://developers.circle.com/stablecoins/usdc-contract-addresses> (2026-10-21); default RPCs `https://ethereum-rpc.publicnode.com` and `https://mainnet.base.org` (both answered `eth_chainId` 0x1 / 0x2105 on 2026-10-21T19:44Z); `FromStr` still rejects `"mainnet"` naming the four accepted strings; tests pin round-trip, `is_mainnet`, distinct chain ids/tokens/RPCs | `crates/swap-chain-evm/src/network.rs:19-100,119-170`, `crates/swap-chain-evm/src/lib.rs:46-54` | **ok** — verified, mainnet options exist but are inert without the gates below |
| Daemon/CLI network selection | `[usdc].allow_mainnet` (default false); mainnet `network` without it → `no mainnet without the explicit allow_mainnet opt-in`; mainnet `network` with `profile = "testnet"` → `disagrees with profile`; `live_usdc` logs `network` and `mainnet`. CLI: `--usdc-network ethereum\|base` needs `--allow-mainnet`, checked in `usdc_endpoints` before any key or network use | `bin/divi-swapd/src/config.rs:88-92,565-581`, `bin/divi-swapd/src/main.rs:326`, `bin/divi-swap/src/main.rs:338-343` | **ok** — verified by unit tests (`usdc_mainnet_*` in both bins) and a live smoke, see the next row |
| mainnet read-only facts | 2026-10-21 hp3 (no key, no funds): ethereum via `https://ethereum-rpc.publicnode.com` 19:44:40Z chain id 1, height 26243153, USDC `decimals()` = 6, `symbol()` = `USDC`; base via `https://mainnet.base.org` 19:44:42Z chain id 0x2105 = 8453, height 52911267, `decimals()` = 6, `symbol()` = `USDC`. Daemon smoke (`profile = "mainnet"`, `[usdc] network = "ethereum"`/`"base"`, `allow_mainnet = true`, throwaway zero-balance key, since deleted): `usdc backend ready` with `eth_wei` 0, `usdc_units` 0 on both. Gate refusals: no allow → `[usdc].network = "ethereum": usdc mainnet moves real money: no mainnet without the explicit allow_mainnet opt-in (mainnet-readiness.md §USDC/EVM)`; profile testnet → `[usdc].network = "ethereum" disagrees with profile = Testnet: …`; CLI → `--usdc-network ethereum moves real money: no mainnet without the explicit --allow-mainnet opt-in` | `bin/divi-swapd/src/main.rs:326` | **verified**, no funds; the HTLC address in the smoke was a placeholder (no audited mainnet `Erc20Htlc` deployment exists — still open) |

Findings (no code change — not my crate):
- Architecturally this is the *closest* coin to mainnet-ready: `UsdcBackend` itself is
  network-agnostic (own doc comment, `network.rs:9-13`) — it only ever sees an RPC URL, an HTLC
  address and a token address, all caller-supplied. Adding a mainnet `UsdcNetwork::Ethereum`
  variant (mainnet RPC URL, mainnet USDC contract address, chain id 1) is a much smaller change
  than BTC/LTC/ZEC's address-format rewrites — but it is still not done today, and the crate's
  own test (`network.rs:115`) actively pins that `"mainnet"` is rejected, so this is a decision,
  not an oversight.
- The actual minimum-offer-size floor values (reported in an earlier commit message as ~0.01
  ETH / 10 USDC) are not constants in `swap-chain-evm` — `usdc_offer_is_fundable` takes them as
  parameters (`backend.rs:89-90`), so wherever those literals actually live (believed to be
  `divi-swapd`, not checked as part of this review — out of scope for the `zec`/EVM crates this
  task covers) is where a mainnet-appropriateness check belongs.

## XMR

**Not part of the shared engine at all.** `Chain` (`crates/divi-swap/src/types.rs:22-33`) and
`Chain::ALL` (`types.rs:37`, 5 elements: Divi, Btc, Ltc, Zec, Usdc) have **no `Xmr` variant** —
none of `ChainParams::builtin`, `SwapConfig::profile`, `required_gap_secs`, or any of the
confirmations/timeout/margin machinery reviewed for the other four coins applies to XMR in any
form. `crates/swap-chain-xmr` is a free-standing, bespoke adaptor-signature swap
(`docs/plans/swap-poc/xmr-design.md`) with its own hand-rolled everything. Every value below is
local to that crate; there is no shared-config row to cite.

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (XMR side) | `SPENDABLE_AGE = 10` (Monero's real `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`, a protocol constant, not a tunable choice); a separate 1-confirmation check exists for "did the funding tx land" (`check_xmr_confirmed`), correctly distinct from spendability (`check_xmr_spendable`) | `crates/swap-chain-xmr/src/live_rpc.rs:63-70,78-107` | ok — matches Monero's own protocol minimum; discovered live after a real rejection (`"invalid_input": true`) against a 1-confirmation output |
| Confirmations (DIVI side of this swap) | `check_divi_confirmed` / `check_divi_confirmed_n` use `DIVI_CONFIRMATIONS_MAINNET = 10`, a mirror of the shared engine's DIVI mainnet depth (`swap-chain-xmr` cannot import `divi-swap`); the drift-alarm test `mainnet_divi_confirmations_matches_the_engines_config` re-reads `crates/divi-swap/src/config.rs` and fails if the two diverge | `crates/swap-chain-xmr/src/live_rpc.rs:212,216,231,570` | ok — matches the engine's DIVI leg depth for every other coin; drift is caught by a test |
| Timeouts/margins (`t_refund`, `t_punish`, `lock_time`) | no built-in schedule anywhere — plain function **parameters** on every template builder | `crates/swap-chain-xmr/src/swap_templates.rs:74-81,140-150`; `crates/swap-chain-xmr/src/multisig.rs:108-124` | **risky: no mainnet-safe margin scheme exists to review** — see below |
| Fee policy | `fee_rate: FeeRate` is a parameter; the one live example sources it from the daemon's live `get_fee_estimate` RPC | `crates/swap-chain-xmr/src/monero_sweep.rs:83-91`; `crates/swap-chain-xmr/examples/xmr_live.rs:435-450` | ok — dynamically sourced, not hardcoded, when actually used live |
| Dust limit | not applicable — Monero RingCT outputs have no byte-size "dust" relay rule the way UTXO chains do; nothing resembling one exists in this crate | — | n/a |
| Reorg depth assumption | = `SPENDABLE_AGE` (10 blocks) on the XMR side; `DIVI_CONFIRMATIONS_MAINNET` (10) on the DIVI side, same mirror and drift-alarm test as the row above | `crates/swap-chain-xmr/src/live_rpc.rs:212,570` | ok |
| Public backends / network selection | Network is chosen by `[xmr].network` + `allow_mainnet` (default false; mainnet refused without it) in the daemon and `--xmr-network` + `--xmr-allow-mainnet` in the CLI; the node URL is configuration (`[xmr].monerod_url` / `--xmr-monerod-url`), the stagenet default being `MONEROD_RPC_DEFAULT = "http://node.monerodevs.org:38089"`. **New nettype guard:** before any wallet work, `live_xmr_engine` and `live_xmr_taker` ask the node `get_info` and refuse to start unless its `nettype` equals the configured network (and, for mainnet, `allow_mainnet` is set). Public mainnet restricted nodes that answered `get_info` with `nettype = "mainnet"` on 2026-10-21 (`verified`, see `status/xmr.md`): `node.monerodevs.org:18089`, `xmr-node.cakewallet.com:18081` | `bin/divi-swapd/src/config.rs:172-179`; `bin/divi-swap/src/main.rs:122-130`; guard: `crates/swap-chain-xmr/src/live_rpc.rs:79,111,120`, `crates/divi-swap-xmr/src/live.rs:533,552`, called at `bin/divi-swapd/src/main.rs:189`, `bin/divi-swap/src/main.rs:705` | ok for network selection and node/network mismatch; **mainnet use stays gated on `xmr-mainnet-plan.md` phase D** |

Findings (no code change — not my crate, and the real gap here isn't a wrong constant):
- The DIVI-side confirmation gap found in the first review is closed: the check now mirrors `DIVI_CONFIRMATIONS_MAINNET` (10) with a drift-alarm test.
- The complete absence of a `t_refund`/`t_punish` computation (as opposed to accepting them as
  parameters) means there is no single "mainnet value" to cite or pin for XMR's timeout
  margins — only the two live examples' demo numbers exist (`height + 5`, `height + 7`
  DIVI blocks — `crates/swap-chain-xmr/examples/xmr_live_refund.rs:299`,
  `crates/swap-chain-xmr/examples/xmr_live_punish.rs:276`), and both are explicitly flagged
  in-file as deliberately short demo conveniences, not production margins
  (`xmr_live_refund.rs:10`: "deliberately **short** DIVI timelocks... not production safe
  margins"). Building a real schedule (analogous to `required_gap_secs` for the shared engine)
  is a feature the `xmr` lane would need to design, not a constant this review can pin.
- `examples/xmr_live.rs:174-191` still refuses anything but stagenet (an example, deliberately). The production paths no longer have a mainnet *option* gap: network selection exists and a node on the wrong network is refused at start. What remains before mainnet is the phase-D design work (timeouts/margins) and review, not wiring.

## Summary table

| Coin | Mainnet endpoint exists? | Mainnet address/tx format exists? | Any code fixed this review? |
|---|---|---|---|
| BTC | **yes** (`lane/btc-ltc-mainnet-wiring`): `esplora_endpoints("mainnet")` = `mempool.space/api` then `blockstream.info/api` (`crates/swap-chain-btc/src/lib.rs:46-49,67-69`); both answered `/blocks/tip/height` = 972518 at 2026-10-21T19:10Z (`verified`) | **yes**: `bitcoin_network()` maps `mainnet`→`Network::Bitcoin` (`lib.rs:54-63`), `BtcBackend::new_on(network, …)` builds the `bc1q` address (`lib.rs:132-150`); signet/testnet3 `tb1q` unchanged (test `mainnet_address_is_bc1q_and_test_networks_stay_tb1q`) | **yes — wired behind `[btc].allow_mainnet` (default false, `bin/divi-swapd/src/config.rs:55-59,565-593`) and `--btc-network mainnet` + `--allow-mainnet` (`bin/divi-swap/src/main.rs:70-78,384-412`)** |
| LTC | **yes** (`lane/btc-ltc-mainnet-wiring`): `esplora_endpoints("mainnet")` = `litecoinspace.org/api` only (`crates/swap-chain-ltc/src/lib.rs:50-52,67-69`; no independent mirror known); answered `/blocks/tip/height` = 3199195 at 2026-10-21T19:10Z (`verified`) | **yes**: `hrp_for()` maps `mainnet`→`LTC_HRP` = `ltc` (`lib.rs:55-63`; source: litecoin `src/chainparams.cpp` `bech32_hrp = "ltc"` / `"tltc"`, https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp), `LtcBackend::new_on` builds the `ltc1q` address (`lib.rs:133-152`) and `build_send` rejects a destination whose HRP is not the backend's (`lib.rs:234-241`) | **yes — wired behind `[ltc].allow_mainnet` (default false, `config.rs:89-93,565-593`) and `--ltc-network mainnet` + `--allow-mainnet` (`main.rs:79-86,384-412`)** |
| ZEC | yes (`swap-chain-zec/src/lib.rs:61-77`) | yes (`address.rs:26-36`); v5/v6 chosen by NU6.3 height (`tx.rs:59-80`) | **yes — dust floor (`tx.rs:50-56`), test added and verified failing→passing** |
| USDC/EVM | yes, behind `allow_mainnet` (`swap-chain-evm/src/network.rs:19-100`; `ethereum`, `base`) | backend is network-agnostic | yes — variants, daemon/CLI gates and tests added (lane `usdc-mainnet-wiring`) |
| XMR | **yes, by configuration**: `[xmr].network`/`allow_mainnet` and `--xmr-network`/`--xmr-allow-mainnet` select the network and `monerod_url` the node; a mainnet restricted node answered `get_info` (`nettype = "mainnet"`, 2026-10-21, `verified`); the nettype guard refuses a node on the wrong network (`live.rs:533,552`) | yes — Monero addresses are parsed per network (`live::parse_address`); DIVI leg uses the shared mainnet depth (10) | **yes — nettype guard added (`lane/xmr-nettype-guard`)**; mainnet itself stays gated on `xmr-mainnet-plan.md` phase D |

All citations above were re-read from the working tree at the stated line numbers as of this
review (2026-10-12); `crates/divi-swap/src/config.rs` and `crates/swap-chain-zec/src/tx.rs`
line numbers reflect the one landed change (the dust-floor fix).
