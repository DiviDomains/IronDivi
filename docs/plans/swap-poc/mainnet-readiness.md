# Mainnet-readiness review

Lane `zec`, 2026-10-12. Scope per the orchestrator's task: for each coin, list the mainnet
values the code would use *today*, mark each `ok` or `risky: <reason>`, cite `file:line` for
every value. Code changes are in-scope only for `crates/swap-chain-zec` and
`crates/divi-swap/src/config.rs`; every other crate gets a finding, not a patch.

Headline result: **three of the five coins (BTC, LTC, XMR) have no mainnet network support at
all** — their endpoint/address code only knows how to talk to a test network, by construction,
not by a disableable flag. **ZEC additionally cannot produce a mainnet-valid transaction right
now even if it had an endpoint**: it hardcodes the NU7 v6 transaction format, and NU7 is
testnet-only until 2026-11-05 (confirmed via the `oracle` agent, see ZEC §Confirmations/reorg).
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

- [ ] **BTC:** add a mainnet `Network` and esplora endpoint list (`swap-chain-btc/src/lib.rs:48-55,107`); raise mainnet confirmations above 2.
- [ ] **LTC:** wire the mainnet HRP and endpoints (`swap-chain-ltc/src/lib.rs:52-58,111`).
- [ ] **ZEC:** add mainnet address prefixes and a lightwalletd endpoint, and pick the v5/v6 tx format by activation height (mainnet NU7 2026-11-05) (`swap-chain-zec/src/address.rs:18-21`, `tx.rs:34-48`).
- [ ] **USDC/EVM:** add Ethereum/Base mainnet `network.rs` variants with the canonical USDC addresses, and an audited HTLC deployment.
- [ ] **XMR:** mainnet backends, and remove the runtime refusal only after the above (`xmr_live.rs:174-191`).
- [ ] **Shared:** a mainnet timeout/confirmation profile in `divi-swap/src/config.rs`, an external security review, and staged low-value mainnet trials.

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
| Transaction version | **always** v6 (NU7/ZIP-229-ish; the real spec per the `oracle` agent is ZIP 230, "Withdrawn", and the real upgrade name is **NU7**, not the crate's internal nickname "NU6.3 Ironwood" — citation worth double-checking, see note) | `crates/swap-chain-zec/src/tx.rs:34-48,644-648` | **risky: critical, time-boxed** — see below |
| Reorg depth assumption | = confirmations (10 blocks) | `crates/divi-swap/src/config.rs:50` | ok either side of NU7 mainnet activation — see note |
| Public backends | `TESTNET_LIGHTWALLETD = "https://testnet.zec.rocks:443"` — the only one; **"No working fallback has been found yet"** (own comment) | `crates/swap-chain-zec/src/lib.rs:35-38` | **risky: single endpoint, no fallback, no mainnet option** |
| Address prefixes | `tm…`/`t2…` only (testnet Base58Check version bytes); **no mainnet prefix constants exist in this file at all** | `crates/swap-chain-zec/src/address.rs:18-21` | **risky: structurally cannot produce a mainnet address** |

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

### Transaction version — critical, time-boxed finding (no code change: this is a protocol
calendar fact, not a wrong constant)

`crates/swap-chain-zec` **always** builds Zcash v6 transactions
(`V6_VERSION_GROUP_ID`/`V6_VERSION_BYTES`, `tx.rs:37-48`; `build_tx`/the funding/claim/refund
builders never produce v5, `tx.rs:644-648`). This is *correct* against Zcash testnet today,
which has run NU7-only since activating it — but it is a live, current problem for mainnet:

> Escalated to the `oracle` agent (hard consensus/protocol-activation question, per lane rule
> 7). Verbatim finding, high confidence, sources from the last few days: **NU7 (the upgrade
> that introduces the v6 transaction format) is testnet-only right now. Zcash testnet activated
> it 2026-10-04 at block 4,465,026; mainnet activation is targeted for 2026-11-05 (go/no-go
> decision 2026-10-20), not yet live.** Pre-NU7 mainnet nodes enforce NU5-era consensus rules
> and would reject a v6 transaction outright.

Practical effect: **every transaction this backend builds today would be rejected by Zcash
mainnet**, independent of and in addition to the missing-endpoint/missing-address-prefix gaps
above. This is strictly more severe than "no mainnet RPC configured" — it means the backend
cannot be *made* mainnet-functional today even by someone willing to hand-configure a mainnet
endpoint and mainnet address prefixes themselves, because the wire format itself is rejected.
It is also self-resolving on a known date: nothing to fix in code *now*, since hardcoding v6 is
the right behavior for the network this crate actually targets (testnet) and the only
"mainnet-safe value" is a date (2026-11-05, not yet confirmed final) that this crate has no way
to observe at build time (and shouldn't guess at). **Action for whoever flips this crate to
mainnet: re-verify NU7 mainnet activation is actually live before pointing it at a mainnet
endpoint — do not rely on this document's date without rechecking.**

Secondary, low-severity note from the same oracle check: the crate's own comments cite "ZIP
229" and nickname the upgrade "NU6.3 Ironwood" (`tx.rs:37,44`; `lib.rs:530`;
`docs/plans/swap-poc/status/zec.md`'s own "NU6.3/NU7" phrasing). The oracle's read is that the
real spec is **ZIP 230** (marked "Withdrawn" — the format shipped but the standalone ZIP was
folded elsewhere) and the official upgrade name is **NU7**; "NU6.3" appears to be this
codebase's internal nickname, not the real one. The `V6_VERSION_GROUP_ID` *value* itself was
independently confirmed against live testnet transactions (`tx.rs:38`) and is not in question —
only the ZIP-number citation in the doc comments might be wrong. Not fixed here: changing a
citation without being fully certain risks swapping one wrong citation for another; flagging
for whoever next touches these comments to confirm against zips.z.cash directly.

### Confirmations/reorg depth — not risky, despite the NU7 timing above

`ChainParams::builtin`'s ZEC mainnet confirmations (10, `config.rs:50`) was tuned against a
measured ~25s/block NU7 rate to land on ~225s of finality depth (see the "done" entry in
`docs/plans/swap-poc/status/zec.md` for the 3→9 testnet history of this same reasoning). Given
the oracle finding above — mainnet is still pre-NU7 today, running at Zcash's traditional ~75s
block time — using confirmations=10 against *today's* mainnet would actually give ~750s of
depth: three times the intended margin, not less. The number stays safe on both sides of the
2026-11-05 activation: too conservative before it, on-target after. No finding, no fix needed.

## USDC/EVM

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 12 | `crates/divi-swap/src/config.rs:56` | ok — standard Ethereum-mainnet finality heuristic |
| MTP lag (mainnet) | 180s | `crates/divi-swap/src/config.rs:56` | ok ("no MTP smoothing on EVM... lag only needs to cover block-time jitter", own comment) |
| Taker/maker timeout, claim margin | shared (see BTC) | `crates/divi-swap/src/config.rs:97-98,102` | ok |
| Gas price | live `provider.estimate_eip1559_fees()` for `max_fee_per_gas`/`max_priority_fee_per_gas` | `crates/swap-chain-evm/src/backend.rs:249-256` | ok — dynamically sourced, not hardcoded |
| Gas limit | live `estimate_gas` + 20% headroom | `crates/swap-chain-evm/src/backend.rs:235-254` | ok |
| Dust/minimum amount | `amount_to_usdc_units` rejects non-whole-unit amounts (precision guard, not an economic floor); `usdc_offer_is_fundable(min_eth_wei, min_usdc_units)` takes its floors as **caller-supplied parameters** — no hardcoded floor in this crate | `crates/swap-chain-evm/src/backend.rs:56-64,85-97` | ok (correctly config-driven at this layer) — the actual default floor values (reported elsewhere as ~0.01 ETH / 10 USDC) live outside this crate; out of scope for this review |
| Public backends / network | `UsdcNetwork` enum: **only** `Sepolia`/`BaseSepolia`; `FromStr` rejects anything else; the crate's own test asserts `"mainnet".parse::<UsdcNetwork>().is_err()` | `crates/swap-chain-evm/src/network.rs:24-62,68-75,115` | **risky: no mainnet network option exists — confirmed by the crate's own test** |

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
| **Confirmations (DIVI side of this swap)** | hardcoded `>= 1` | `crates/swap-chain-xmr/src/live_rpc.rs:53-60` | **risky: inconsistent — 10x thinner than the shared engine's DIVI mainnet depth** (`divi_confirmations: 10`, `config.rs:100`) used for every other coin's DIVI leg |
| Timeouts/margins (`t_refund`, `t_punish`, `lock_time`) | no built-in schedule anywhere — plain function **parameters** on every template builder | `crates/swap-chain-xmr/src/swap_templates.rs:74-81,140-150`; `crates/swap-chain-xmr/src/multisig.rs:108-124` | **risky: no mainnet-safe margin scheme exists to review** — see below |
| Fee policy | `fee_rate: FeeRate` is a parameter; the one live example sources it from the daemon's live `get_fee_estimate` RPC | `crates/swap-chain-xmr/src/monero_sweep.rs:83-91`; `crates/swap-chain-xmr/examples/xmr_live.rs:435-450` | ok — dynamically sourced, not hardcoded, when actually used live |
| Dust limit | not applicable — Monero RingCT outputs have no byte-size "dust" relay rule the way UTXO chains do; nothing resembling one exists in this crate | — | n/a |
| Reorg depth assumption | = `SPENDABLE_AGE` (10 blocks) on the XMR side; **1 confirmation** on the DIVI side (same gap as above) | `crates/swap-chain-xmr/src/live_rpc.rs:70,53-60` | risky, same finding as DIVI-side confirmations |
| Public backends | `MONEROD_RPC_DEFAULT = "http://node.monerodevs.org:38089"` (public, **restricted**, **stagenet**), documented fallback `stagenet.xmr-tw.org:38081` (also stagenet); the one live example actively **refuses to run** unless `nettype == "stagenet" && !mainnet` | `crates/swap-chain-xmr/src/live_rpc.rs:29-36`; `crates/swap-chain-xmr/examples/xmr_live.rs:174-191` | **risky: no mainnet endpoint; code explicitly guards against ever being pointed at one** |

Findings (no code change — not my crate, and the real gap here isn't a wrong constant):
- The DIVI-side 1-confirmation check (`check_divi_confirmed`, `live_rpc.rs:53-60`) is the
  single clearest "missing/unsafe value" in this coin's review, and it *would* be in scope for
  a pinning test if this were my crate — it isn't (`swap-chain-xmr` belongs to lane `xmr`). The
  fix shape, for whoever owns that crate: either take the DIVI confirmation depth as a
  parameter sourced from `SwapConfig`/`ChainParams::builtin(Chain::Divi, ...)` the same way the
  other four coins do, or hardcode the same mainnet value (10) directly — right now it's
  neither, just an independent `1`.
- The complete absence of a `t_refund`/`t_punish` computation (as opposed to accepting them as
  parameters) means there is no single "mainnet value" to cite or pin for XMR's timeout
  margins — only the two live examples' demo numbers exist (`height + 5`, `height + 7`
  DIVI blocks — `crates/swap-chain-xmr/examples/xmr_live_refund.rs:299`,
  `crates/swap-chain-xmr/examples/xmr_live_punish.rs:276`), and both are explicitly flagged
  in-file as deliberately short demo conveniences, not production margins
  (`xmr_live_refund.rs:10`: "deliberately **short** DIVI timelocks... not production safe
  margins"). Building a real schedule (analogous to `required_gap_secs` for the shared engine)
  is a feature the `xmr` lane would need to design, not a constant this review can pin.
- Both the stagenet-only endpoint and the mainnet refusal in `xmr_live.rs` are deliberate
  safety guards, not oversights — but they confirm there is currently no path to even
  *attempting* XMR on mainnet, independent of the protocol-readiness questions above.

## Summary table

| Coin | Mainnet endpoint exists? | Mainnet address/tx format exists? | Any code fixed this review? |
|---|---|---|---|
| BTC | no (`swap-chain-btc/src/lib.rs:48-55`) | no (`lib.rs:107`, hardcoded `Network::Signet`) | no — finding only |
| LTC | no (`swap-chain-ltc/src/lib.rs:52-58`) | no (`lib.rs:111`, mainnet HRP defined but unwired) | no — finding only |
| ZEC | no (`swap-chain-zec/src/lib.rs:35-38`) | no (`address.rs:18-21`); **also wire-format-incompatible with mainnet until 2026-11-05** (`tx.rs:34-48`) | **yes — dust floor (`tx.rs:50-56`), test added and verified failing→passing** |
| USDC/EVM | no (`swap-chain-evm/src/network.rs:24-62`, own test pins the rejection) | backend is network-agnostic; just needs a config variant | no — finding only |
| XMR | no, and actively refused at runtime (`xmr_live.rs:174-191`) | no mainnet refusal guard needed — not in the shared engine at all | no — finding only (not my crate) |

All citations above were re-read from the working tree at the stated line numbers as of this
review (2026-10-12); `crates/divi-swap/src/config.rs` and `crates/swap-chain-zec/src/tx.rs`
line numbers reflect the one landed change (the dust-floor fix).
