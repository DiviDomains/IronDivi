# Mainnet-readiness review

## Left before a funded mainnet swap (as of 2026-10-22, e9873c4)

Every line is already named elsewhere in the docs or status files; nothing here is new. Tag, then item, then where it is recorded.

- `Bert decision` — the DIVI mainnet confirmation count: **DECIDED 2026-10-23 (card 330b2472 option a): Bert chose 17; the mainnet profile now uses 17 (`crates/divi-swap/src/config.rs:114`), testnet stays 3** (it was 10; the review had recommended keeping 10 for the first funded swap, with 20 as the option for more margin). Pointers: `divi-confirmations.md` §5, `status/divi.md` (left, 2026-10-22).
- `Bert decision` — BTC mainnet confirmations stay at 2 (`crates/divi-swap/src/config.rs:54`); raising them is parked. Pointer: the BTC item below ("Still open: raise mainnet confirmations above 2") and §BTC.
- `Bert decision` — the XMR mainnet swap itself, and written acceptance of any unfixed finding if one is raised (the Gate C list is empty today). Pointer: `xmr-mainnet-plan.md` §Phase C and the 2026-10-21 decision-log entry.
- `outside audit` — the USDC `Erc20Htlc` deployment: the internal pre-audit is done, an outside audit is not. Pointer: `usdc-htlc-preaudit.md`, the USDC/EVM item below.
- `outside audit` — the external security review of the shared engine and of the XMR crates (`crates/divi-swap-xmr`, `crates/swap-chain-xmr`). Pointer: the "Shared" profile item below, `xmr-mainnet-plan.md` §Phase C, `xmr-review-brief.md`; the shared-engine brief for the reviewer is `engine-review-brief.md`.
- `ops` — the human walk-through of `xmr-runbook.md` (an agent walk-through is done, the human one is open). Pointer: `xmr-mainnet-plan.md` B3.
- `ops` — mainnet key custody for the maker: new 1Password items `IronDivi Swap - maker-divi-xmr-mainnet` and `IronDivi Swap - maker-xmr-wallet-mainnet`, a separate mainnet host, created at Bert's keyboard in phase D. Pointer: `xmr-mainnet-plan.md` B4 and §B4 key custody.
- `ops` — separate mainnet infrastructure and an explicit DIVI mainnet RPC for the XMR leg (`[xmr].divi_rpc_url` / `--xmr-divi-rpc-url`). Pointer: `xmr-mainnet-plan.md` §Phase D.
- `ops` — LTC mainnet has one Esplora data source (`litecoinspace.org/api`); no independent Esplora mirror exists and the tip-hash cross-check (`[ltc].crosscheck`) is opt-in, not a second data source. Pointer: the LTC item below, `status/ltc.md` §"LTC second-mirror survey".
- `ops` — the DIVI worst-reorg length is `could not verify`: `getchaintips` is unavailable on the public endpoint, so it needs a node we control or the operator allowing it. Pointer: `status/divi.md` (left), `divi-confirmations.md` §5.
- `funds` — the first funded mainnet swap and the staged low-value trials: dust-sized first, Bert at the keyboard, per-run confirmation, then a raised cap. Pointer: `xmr-mainnet-plan.md` §Phase D, the DIVI and "Shared" items below.

Lane `zec`, 2026-10-12. Scope per the orchestrator's task: for each coin, list the mainnet
values the code would use *today*, mark each `ok` or `risky: <reason>`, cite `file:line` for
every value. Code changes are in-scope only for `crates/swap-chain-zec` and
`crates/divi-swap/src/config.rs`; every other crate gets a finding, not a patch.

Headline result (as written 2026-10-12; **superseded 2026-10-22**: BTC, LTC, ZEC, USDC, XMR and DIVI now have gated mainnet wiring, see the top section and §Summary table): **three of the five coins (BTC, LTC, XMR) have no mainnet network support at
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
- [x] **LTC:** mainnet HRP and endpoint — done on `lane/btc-ltc-mainnet-wiring` (`swap-chain-ltc/src/lib.rs:50-69,136-159`), gated by `[ltc].allow_mainnet` / `--allow-mainnet`. Still open (re-surveyed 2026-10-22, builder AC survey 2026-10-22: `docs/plans/swap-poc/status/ltc.md` §"LTC second-mirror survey"): no independent Esplora-compatible LTC mainnet API exists; the only other operators found serve Blockbook/BlockCypher shapes (`verified`, curl outputs in the survey). Those two are now usable as an opt-in independent tip-hash cross-check (`[ltc].crosscheck`, builder AE, `verified` live 2026-10-22); it is not a second data source.
- [x] **ZEC:** add mainnet address prefixes and a lightwalletd endpoint, and pick the v5/v6 tx format by activation height — done in `71ed663` on `lane/zec-mainnet-readiness`: `address.rs:26-41`, `lib.rs:61-77`, `tx.rs:59-79`. The format switch is the **NU6.3** activation height (not NU7): see ZEC §Facts.
- [ ] **USDC/EVM:** ~~add Ethereum/Base mainnet `network.rs` variants with the canonical USDC addresses~~ (done 2026-10-21, behind `allow_mainnet`); an audited HTLC deployment is still open — pre-audit done 2026-10-22, see usdc-htlc-preaudit.md; outside audit still open.
- [ ] **XMR:** mainnet backends — the hard runtime refusal became an explicit opt-in on 2026-10-14 (`[xmr].allow_mainnet` / `--xmr-allow-mainnet`, default off; `live::profile_for`, `crates/divi-swap-xmr/src/live.rs:527`); only the example still refuses anything but stagenet (`xmr_live.rs:174-191`). Still open: phase D staged trials. Sequenced plan with gates: `xmr-mainnet-plan.md`.
  - **Known gap (2026-10-24, `lane/usdc-spendable`): no accept-time funds check for XMR.** `Maker::accept` refuses a swap the maker cannot fund (`InsufficientFunds`) by reading `ChainBackend::spendable` on the maker-leg chain. BTC, LTC, DIVI, ZEC and USDC (ERC-20 `balanceOf`, refused outright below the 0.01 ETH lock-gas floor) implement it. XMR keeps the trait default `None` ("cannot tell, do not refuse") because the maker runs no Monero wallet RPC to read a balance from, so an underfunded XMR maker is not refused at accept and fails only when it tries to lock.
- [x] **DIVI:** the DIVI leg's network is selectable and gated like the other coins — done on `lane/divi-mainnet-wiring`: `[divi].network` (`testnet` default | `mainnet`) and `[divi].allow_mainnet` (default `false`) in `divi-swapd` (`bin/divi-swapd/src/config.rs:39-80,745-760`), `--divi-network` in `divi-swap` (`bin/divi-swap/src/main.rs:74,429-491`), a mainnet RPC default `swap_chain_divi::MAINNET_RPC` (`crates/swap-chain-divi/src/lib.rs:51-60`), and the profile check now covers DIVI. See §DIVI. Still open: the first funded mainnet swap and the review of the DIVI mainnet confirmation count.
- [x] **Shared:** a mainnet timeout/confirmation profile — done: `Profile::{Mainnet,Testnet}`, `ChainParams::builtin` and `SwapConfig::profile` (`divi-swap/src/config.rs:21-72,80-130`), and `check_profile_networks` (`:236`), which `divi-swapd` (config load, `bin/divi-swapd/src/config.rs:747`) and `divi-swap` (`--profile`, before any network call, `bin/divi-swap/src/main.rs:491`) both call so the profile must agree with every configured coin's `network` and `allow_mainnet` (xmr and usdc included) and, since `lane/divi-mainnet-wiring`, DIVI (`[divi].network` / `--divi-network`). Still open: an external security review, and staged low-value mainnet trials.
- [x] **Shared:** taker enforces its profile on maker terms — done: `check_terms_against_profile` (`crates/divi-swap/src/config.rs:318`, `OfferedTerms` `:271`) refuses a quote whose confirmation depths, taker/maker timeouts or taker−maker gap are below the taker's own `SwapConfig::profile` / `ChainParams::builtin` values; `Taker::prepare` calls it before a preimage is made or anything is signed or funded (`crates/divi-swap/src/taker.rs:121`), and `divi-swap` arms it from `--profile` (`bin/divi-swap/src/main.rs:828,916`). Hashlock pairs only (BTC/LTC/ZEC/USDC ↔ DIVI, both directions). **XMR taker — done (builder Z):** `XmrTaker::with_profile_floor(profile)` (`crates/divi-swap-xmr/src/taker.rs:285`) arms `XmrConfig::check_quote_terms` (`crates/divi-swap-xmr/src/lib.rs`), called at the top of `XmrTaker::prepare` (`taker.rs:313`, before any key, Paillier prime or stored document) against the quote's `divi_confirmations`, `btc_confirmations` (= XMR depth), `maker_timeout_secs` (= `cancel_after_secs`) and `taker_timeout_secs` (= cancel + punish), and `XmrConfig::check_setup_timelocks` in `verify_setup` (`taker.rs:526`) against the setup's `t_cancel` (profile `cancel_after_secs`, less `sigs_wait_secs` of clock slack since the maker read its MTP), `t_punish − t_cancel` and `t_late − t_punish`; `divi-swap --counter-chain xmr` sets it from `--profile` (`bin/divi-swap/src/main.rs:987-993,1075`) and the mock taker now uses `XmrConfig::for_profile(--profile)` instead of always `testnet()`. XMR mainnet is an explicit opt-in, refused unless `allow_mainnet` / `--xmr-allow-mainnet` is set (`live::profile_for`, `crates/divi-swap-xmr/src/live.rs:527`; opt-in since 2026-10-14, xmr-mainnet-plan.md). **Daemon taker — no path:** `divi-swapd` is maker-only (`bin/divi-swapd/src/main.rs:141` builds `XmrMaker`; no `Taker`/`XmrTaker` in `bin/divi-swapd/src`; the `Taker::new` uses are in `bin/divi-swapd/tests/`), so there is nothing to floor. Before that, the maker-leg HTLC's locktime is checked against MTP + 1800 s (`crates/divi-swap/src/taker.rs:406`). The maker leg's real on-chain locktime is floored too: when the taker first sees the maker's lock (`on_locked`, `crates/divi-swap/src/taker.rs:366`) `check_maker_leg_locktime` (`crates/divi-swap/src/config.rs:393`) refuses a locktime below `taker-leg locktime − (taker_timeout − maker_timeout) − accept tolerance − max MTP lag` before the preimage is revealed (decided once, persisted as `claim_declined`; `crates/divi-swap/tests/taker_maker_leg_floor.rs`); armed by the same `--profile`. **Exact floor (builder AF):** the maker now states the maker-chain MTP it built its lock from (`SwapView::maker_mtp_at_lock`, optional on the wire, `crates/divi-swap/src/api.rs`; persisted as `MakerRecord::maker_mtp_at_lock`, set where the locktime is computed, `maker.rs:582`), and when present `check_maker_leg_locktime_exact` (`crates/divi-swap/src/config.rs:437`, call `taker.rs:438`) requires `maker_leg_locktime >= stated_mtp + maker_timeout_secs` exactly, after first bounding the stated MTP by what the taker can see itself (not below `taker-leg locktime − taker_timeout − 1800 s − MTP lag`, not above its own read of the maker chain's MTP + MTP lag; otherwise declined as implausible, same `claim_declined`). A maker that omits the field (old maker) keeps the tolerant floor above exactly as before. Both directions are tested (`crates/divi-swap/tests/taker_maker_leg_exact.rs`). Residual: a maker that also understates its MTP down to the lower bound is bounded only by the tolerant floor.

## BTC

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 2 | `crates/divi-swap/src/config.rs:54` | risky: thin — see below |
| MTP lag (mainnet) | 3600s | `crates/divi-swap/src/config.rs:54` | ok |
| Taker/maker timeout, claim margin | 24h / 12h / 3600s (shared, not BTC-specific) | `crates/divi-swap/src/config.rs:82-92,102` | ok |
| Fee policy | `Recommended { floor: 2 }` sat/vB, live `/v1/fees/recommended` `halfHourFee`, floor 2 | `crates/swap-chain-btc/src/lib.rs:78-94,174-190` | ok (live-estimated with a sane floor) |
| Dust limit | 294 sat | `crates/swap-chain-btc/src/tx.rs:27` | ok (standard P2WPKH relay floor) |
| Reorg depth assumption | = confirmations (2 blocks ≈ 20 min) | `crates/divi-swap/src/config.rs:54` | risky: thin for a trustless, no-recourse swap |
| Public backends | `esplora_endpoints()` accepts `"mainnet"` (`mempool.space/api` then `blockstream.info/api`), `"signet"` and `"testnet"`; anything else is rejected. Both mainnet endpoints answered the same tip 972609 on 2026-10-22 (see smoke rows) | `crates/swap-chain-btc/src/lib.rs:46-76` | ok (two independent public mirrors; mainnet is behind `allow_mainnet`, default off) |
| Address network | `bitcoin_network()` maps `"mainnet"` to `Network::Bitcoin` (`bc1`), signet/testnet to the `tb1` HRP; `new_on`/`for_network` build the address with it. Throwaway key on mainnet gave `bc1q…` | `crates/swap-chain-btc/src/lib.rs:54-63,132-142,159` | ok (verified by smoke below) |
| CLI mainnet read-only smoke | 2026-10-22 hp3 (nice, no funds; recorded before the DIVI wiring, it now also needs `--divi-network mainnet`): `divi-swap --backend live --counter-chain btc --profile mainnet --btc-network mainnet --allow-mainnet --divi-key credential:… --btc-key credential:… balance` with a throwaway zero-balance key: `btc_address=bc1q…`, `btc_balance_sats=0`, 0.11 s, endpoint `https://mempool.space/api` (first in `esplora_endpoints("mainnet")`); same address shows 0 funded txo on both `mempool.space/api` and `blockstream.info/api` (curl). Tip 972609 from `/blocks/tip/height` on both endpoints, same hash `00000000000000000001a4b1e376cb4869d2bc5a86b9ec9fbf844c7f2bd8dcd7`. Without `--allow-mainnet` it refuses before any key or network call (0.01 s): "Error: --btc-network mainnet moves real money: no mainnet without the explicit --allow-mainnet opt-in". The CLI has no `tip` subcommand (subcommands: quote, accept, lock, status, claim, refund, run, balance, txids); the tip is cross-checked by curl only | `bin/divi-swap/src/main.rs:297-307,939-957` | **verified** |
| daemon mainnet read-only smoke | 2026-10-22T11:09Z hp3 (recorded before the DIVI wiring; it now also needs `[divi] network = "mainnet" allow_mainnet = true`): `divi-swapd` live with `profile = "mainnet"`, `[btc] network = "mainnet" allow_mainnet = true`, no `esplora_url` (defaults resolve), 127.0.0.1:18571: log "btc backend ready" address `bc1q…` network `mainnet`; `/healthz` 200 (the daemon serves health at `<path_prefix>/healthz`: router nested under `path_prefix` at `bin/divi-swapd/src/routes.rs:212,234-237`, default prefix empty `bin/divi-swapd/src/config.rs:463-465`; this run used the default so `/healthz`, a deployment with `path_prefix = "swap/"` answers `/swap/healthz`) `btc.tip` 972609 `error` null; `/offers` lists the one btc offer; `/swaps` `[]`. Gates (first line, verbatim): `allow_mainnet = false` → "Error: [btc].network = \"mainnet\": btc mainnet moves real money: no mainnet without the explicit allow_mainnet opt-in (mainnet-readiness.md §BTC)"; `profile = \"testnet\"` + mainnet → "Error: [btc].network = \"mainnet\" disagrees with profile = Testnet: the swap timing profile and the btc backend must run on the same network"; `profile = \"mainnet\"` + signet → "Error: [btc].network = \"signet\" disagrees with profile = Mainnet: the swap timing profile and the btc backend must run on the same network". Live mode needs both `[divi]` and `[btc]` (`bin/divi-swapd/src/main.rs:386`); at the time of this smoke the DIVI backend was built on `DiviNetwork::Testnet` regardless of profile; since `lane/divi-mainnet-wiring` it follows `[divi].network` / `--divi-network` and must agree with the profile, so this smoke now also needs `[divi] network = "mainnet" allow_mainnet = true` (see §DIVI) | `bin/divi-swapd/src/config.rs:570,653`, `bin/divi-swapd/src/main.rs:282` | **verified** |
| CLI tip smoke (`divi-swap tip`) | 2026-10-22T12:48Z hp3, read-only, no funds, no key (a throwaway in-memory key is built and dropped): `divi-swap --profile mainnet --allow-mainnet --btc-network mainnet --divi-network mainnet tip --chain btc` prints `btc mainnet 972616`; independent `https://blockstream.info/api/blocks/tip/height` read the same tip (972616). Without `--allow-mainnet` it refuses before any network call. Repeatable: `tools/swap-poc/tip-crosscheck.sh` (`MAINNET=1` for mainnet) runs `tip` and compares every chain's hash, by height, with an independent explorer. |

Findings (no code change — not my crate):
- The earlier finding that `esplora_endpoints` had no `"mainnet"` arm and the address was hardcoded to `Network::Signet` is resolved by builder P (37d085a + 0d12f57): `lib.rs:54-76` and `lib.rs:132-142,159`. The two hardcodes are gone; mainnet needs `allow_mainnet` / `--allow-mainnet`.
- 2 confirmations (~20 min) is on the thin side of common practice for trustless, high-value
  transfers (exchanges commonly use 3-6; some bridges use 1-2). This is a judgment call the
  `btc` lane/orchestrator should weigh explicitly against the swap's intended value ceiling,
  not something this review can declare wrong outright — flagged `risky` because the tradeoff
  isn't written down anywhere, not because 2 is provably unsafe.

## LTC

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 6 | `crates/divi-swap/src/config.rs:56` | ok (≈15 min at 2.5 min/block) |
| MTP lag (mainnet) | 1800s | `crates/divi-swap/src/config.rs:56` | ok |
| Taker/maker timeout, claim margin | shared (see BTC) | `crates/divi-swap/src/config.rs:82-92,102` | ok |
| Fee policy | `Recommended { floor: 1 }` sat/vB, live `/v1/fees/recommended` against `litecoinspace.org`, floor 1 | `crates/swap-chain-ltc/src/lib.rs:83-100,190-205` | ok |
| Dust limit | 294 sat (litoshi) | `crates/swap-chain-ltc/src/tx.rs:31` | ok (same P2WPKH-shaped relay floor, correctly chain-agnostic since it's a byte-size rule) |
| Reorg depth assumption | = confirmations (6 blocks ≈ 15 min) | `crates/divi-swap/src/config.rs:56` | ok |
| Public backends | `esplora_endpoints()` accepts `"mainnet"` (`https://litecoinspace.org/api`) and `"testnet"` (`https://litecoinspace.org/testnet/api`); anything else is rejected. Still a single endpoint per network, no secondary mirror (own comment; 2026-10-22 survey found no Esplora-compatible independent operator, `verified`, see status/ltc.md) | `crates/swap-chain-ltc/src/lib.rs:50-81` | **risky: single data source** (one endpoint, no fallback; mainnet option behind `allow_mainnet`). Mitigated, opt-in: single data source + independent tip-hash cross-check (`[ltc].crosscheck = "blockbook"` or `"blockcypher"`, `--ltc-crosscheck`, default `off`; `crates/swap-chain-ltc/src/crosscheck.rs`). Live run 2026-10-22 on hp3: both sources `Agree` at height 3199584, hash `d5076e35…6e61` (`verified`, status/ltc.md round AE). Guards a lying or forked primary at depth 6; it is not a UTXO source and adds no availability |
| Address network | `hrp_for()` maps `"mainnet"` to `LTC_HRP` (`ltc`) and `"testnet"` to `TLTC_HRP`; `new_on` encodes the address with it. `LTC_HRP` is wired (no longer dead code). Throwaway key on mainnet gave `ltc1q…` | `crates/swap-chain-ltc/src/lib.rs:60-69,136-149,156`, `crates/swap-chain-ltc/src/address.rs:20-23` | ok (verified by smoke below) |
| CLI mainnet read-only smoke | 2026-10-22 hp3 (nice, no funds; recorded before the DIVI wiring, it now also needs `--divi-network mainnet`): `divi-swap --backend live --counter-chain ltc --profile mainnet --ltc-network mainnet --allow-mainnet --divi-key credential:… --ltc-key credential:… balance` with a throwaway zero-balance key: `ltc_address=ltc1q…`, `ltc_balance_sats=0`, 0.19 s, endpoint `https://litecoinspace.org/api` (only entry); curl of the same address shows 0 funded txo. Tip 3199562 from `/blocks/tip/height`, hash `e4ea2dad32c47a9ccd3b09579df343f4ec817e406b43bdfcf056343d970bea7b`. Without `--allow-mainnet` it refuses before any key or network call (0.02 s): "Error: --ltc-network mainnet moves real money: no mainnet without the explicit --allow-mainnet opt-in". No secondary endpoint exists to check (`lib.rs:75`). The CLI has no `tip` subcommand; tip by curl only | `bin/divi-swap/src/main.rs:297-307,939-957` | **verified** |
| daemon mainnet read-only smoke | 2026-10-22T11:09Z hp3 (recorded before the DIVI wiring; it now also needs `[divi] network = "mainnet" allow_mainnet = true`): `divi-swapd` live with `profile = "mainnet"`, `[btc]` and `[ltc]` both `network = "mainnet" allow_mainnet = true`, no URL overrides, one enabled ltc offer, 127.0.0.1:18572: log "ltc backend ready" address `ltc1q…` network `mainnet`; `/healthz` 200 (the daemon serves health at `<path_prefix>/healthz`: router nested under `path_prefix` at `bin/divi-swapd/src/routes.rs:212,234-237`, default prefix empty `bin/divi-swapd/src/config.rs:463-465`; this run used the default so `/healthz`, a deployment with `path_prefix = "swap/"` answers `/swap/healthz`) `counters.ltc.tip` 3199562 `error` null (btc tip 972609); `/offers` lists the ltc offer. The `[ltc]` backend starts only with a `[divi]` + `[btc]` pair and an enabled ltc offer (`bin/divi-swapd/src/main.rs:386,406-409`), so an LTC-only config runs in mock mode. Gates (first line, verbatim): `[ltc] allow_mainnet = false` → "Error: [ltc].network = \"mainnet\": ltc mainnet moves real money: no mainnet without the explicit allow_mainnet opt-in (mainnet-readiness.md §LTC)"; `profile = \"testnet\"` + `[ltc]` mainnet (btc on signet so the btc check passes first) → "Error: [ltc].network = \"mainnet\" disagrees with profile = Testnet: the swap timing profile and the ltc backend must run on the same network"; `profile = \"mainnet\"` + `[ltc] network = \"testnet\"` → "Error: [ltc].network = \"testnet\" disagrees with profile = Mainnet: the swap timing profile and the ltc backend must run on the same network" | `bin/divi-swapd/src/config.rs:570,656`, `bin/divi-swapd/src/main.rs:298` | **verified** |
| CLI tip smoke (`divi-swap tip`) | 2026-10-22T12:48Z hp3, read-only, no funds, no key (a throwaway in-memory key is built and dropped): `divi-swap --profile mainnet --allow-mainnet --ltc-network mainnet --divi-network mainnet tip --chain ltc` prints `ltc mainnet 3199600`; independent `https://litecoinspace.org/api/blocks/tip/height` and BlockCypher `v1/ltc/main` read the same tip (3199600). Without `--allow-mainnet` it refuses before any network call. |

Findings (no code change — not my crate):
- LTC is the only coin with a single, unmirrored data source for its *entire* chain view — a
  single operator outage stalls every in-flight swap. Unchanged: `esplora_endpoints("mainnet")` returns one URL (`lib.rs:75`). 2026-10-22: a survey of public LTC APIs found no independent Esplora-compatible operator; non-Esplora tip cross-check sources exist (litecoinblockexplorer.net Blockbook, api.blockcypher.com) and agree with litecoinspace on block 3199000 (`verified`); 2026-10-22 (builder AE): the opt-in tip-hash cross-check (`[ltc].crosscheck`, default `off`) now covers integrity of the tip (a lying or forked primary) but not availability: single data source + independent tip-hash cross-check (opt-in); an unreachable cross-check source only logs a warning (`verified`, status/ltc.md round AE).
- The earlier findings that the mainnet HRP was dead code and that nothing could select mainnet are resolved by builder P (37d085a + 0d12f57): `hrp_for` and `esplora_endpoints` take `"mainnet"` (`lib.rs:60-81`), gated by `allow_mainnet` / `--allow-mainnet`.

## ZEC (my crate — code changed where a real gap was found)

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 10 | `crates/divi-swap/src/config.rs:60` | ok, see note |
| MTP lag (mainnet) | 1800s | `crates/divi-swap/src/config.rs:60` | ok (generously oversized relative to NU7's ~25s blocks; conservative, not unsafe) |
| Taker/maker timeout, claim margin | shared (see BTC) | `crates/divi-swap/src/config.rs:82-92,102` | ok |
| Fee policy | `FeePolicy::Fixed(2)` zat/byte, but every spend pays `max(rate*size, zip317_fee(...))` — the ZIP-317 conventional fee always wins for these tx sizes | `crates/swap-chain-zec/src/lib.rs:118-133`; `crates/swap-chain-zec/src/tx.rs:1108-1114,1279-1281` | ok — ZIP-317-safe by construction regardless of the fixed rate |
| ZIP-317 constants | marginal fee 5000 zat/action, grace 2 actions, in-weight 150B, out-weight 34B | `crates/swap-chain-zec/src/tx.rs:1084,1087,1091,1093` | ok — pinned against Zebra's live NU7-testnet mempool rejection message, see `tx.rs:1921-1926` |
| **Dust limit** | **was** 294 zat (byte-based, borrowed from Bitcoin); **now** 5000 zat (= `ZIP317_MARGINAL_FEE`) | `crates/swap-chain-zec/src/tx.rs:81-87` | **was risky, now fixed** — see below |
| Transaction version | v5 below the network's **NU6.3** activation height, v6 at/above (mainnet 3428143, testnet 4134000), via `tx_version_for(network, tip+1)`; v6 is [ZIP 229](https://zips.z.cash/zip-0229) (Draft), deployed by NU6.3 ([ZIP 258](https://zips.z.cash/zip-0258), Final); NU7 adds no tx format | `crates/swap-chain-zec/src/tx.rs:37-79,679-814`; `lib.rs:239-244` | **fixed** — see Facts; naming settled (NU6.3; "Ironwood" is the pool) |
| Reorg depth assumption | = confirmations (10 blocks) | `crates/divi-swap/src/config.rs:60` | ok either side of NU7 mainnet activation — see note |
| Public backends | `MAINNET_LIGHTWALLETD` = `zec.rocks`, `na.zec.rocks`, `eu.zec.rocks` (:443, each TLS+ALPN h2 verified 2026-10-21); testnet still the single `testnet.zec.rocks` (20-min re-search found no second one) | `crates/swap-chain-zec/src/lib.rs:61-77` | **mainnet fixed; testnet single-endpoint remains** (env `SWAP_ZEC_LIGHTWALLETD_EXTRA` still extends) |
| CLI mainnet read-only smoke | 2026-10-21 hp3: `divi-swap --backend live --counter-chain zec --zec-network mainnet --allow-mainnet balance` with a throwaway zero-balance key: `zec_address=t1…` (after the fix below; it printed `tm…` before), `zec_balance_sats=0`, 0.10 s; without `--allow-mainnet` it refuses before any network call (0.01 s): "--zec-network mainnet moves real money: no mainnet without the explicit --allow-mainnet opt-in" | `bin/divi-swap/src/main.rs:244` | **verified**; bug fixed: the address was encoded with `encode()` (testnet-only) instead of the backend network, now `ZecBackend::encoded_address` |
| daemon mainnet read-only smoke | 2026-10-21T19:02Z hp3: `divi-swapd --backend live` with `profile = "mainnet"`, `[zec] network = "mainnet" allow_mainnet = true`, no `lightwalletd_url` (default primary `zec.rocks:443`): log "zec backend ready" address `t1…` network mainnet; `/healthz` zec tip (the daemon serves health at `<path_prefix>/healthz`: router nested under `path_prefix` at `bin/divi-swapd/src/routes.rs:212,234-237`, default prefix empty `bin/divi-swapd/src/config.rs:463-465`; the log of this run does not record the prefix; a deployment with `path_prefix = "swap/"` answers `/swap/healthz`) **3525840** (>= L's 3525726); gate 2: `allow_mainnet = false` exits "[zec].network = \"mainnet\": zec mainnet moves real money: no mainnet without the explicit allow_mainnet opt-in"; gate 3: `profile = "testnet"` + mainnet exits "[zec].network = \"mainnet\" disagrees with profile = Testnet" | `bin/divi-swapd/src/main.rs:365-378` | **verified**, no funds |
| Address prefixes | testnet `tm…`/`t2…` `[0x1d,0x25]`/`[0x1c,0xba]`; mainnet `t1…`/`t3…` `[0x1c,0xb8]`/`[0x1c,0xbd]`; `encode_for`/`decode_for(network)` reject the other network | `crates/swap-chain-zec/src/address.rs:26-41` | **fixed** (librustzcash `zcash_protocol` constants; protocol-spec cross-check: could not verify) |
| Daemon/CLI network selection | `[zec].network` (default `testnet`) + `[zec].allow_mainnet` (default `false`), validated against the daemon's `profile` at config load; `--zec-network`/`--allow-mainnet` on the CLI, validated before any network call | `bin/divi-swapd/src/config.rs:265-283` (`ZecSection`), `:707-735` (`DaemonConfig::validate`'s zec check); `bin/divi-swapd/src/main.rs:365-378` (`live_zec`); `bin/divi-swap/src/main.rs:522` (`live_backends`'s zec guard) | **fixed** (builder L, 2026-10-21) |
| CLI tip smoke (`divi-swap tip`) | 2026-10-22T12:48Z hp3, read-only, no funds, no key (a throwaway in-memory key is built and dropped): `divi-swap --profile mainnet --allow-mainnet --zec-network mainnet --divi-network mainnet tip --chain zec` prints `zec mainnet 3526687`; independent `https://api.blockchair.com/zcash/stats` read 3526693 at 12:48:56Z, 6 blocks ahead of the lightwalletd view the swap code sees (explorer lead, not a disagreement of chain: the code reads the node it would act on). Without `--allow-mainnet` it refuses before any network call. |

### Dust limit — fixed this review

`DUST_ZATOSHI` (`tx.rs:51` before this change) was `294`, commented "same floor as Bitcoin
P2PKH dust" — copied from Bitcoin's byte-size-based relay rule. But ZEC's real fee floor under
ZIP 317 is a **flat 5000 zat per logical action** (`ZIP317_MARGINAL_FEE`, `tx.rs:1084`), not a
per-byte rate — so a 294-zat output is *technically* non-dust by the old byte rule, but costs
far more to ever spend (≥5000 zat marginal fee) than it is worth. That's a real "unsafe mainnet
value": a wallet could receive change or a claim payout worth less than the fee needed to move
it again, stranding it forever in all but name.

Fix: `DUST_ZATOSHI` is now defined as `ZIP317_MARGINAL_FEE` (`tx.rs:87`), so the floor tracks
the real fee regime instead of a borrowed, unrelated one. Added
`tx::tests::dust_floor_covers_the_zip317_marginal_fee` (`tx.rs:1974-1980`), a `const` assertion
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

`ChainParams::builtin`'s ZEC mainnet confirmations (10, `config.rs:60`) was tuned against a
measured ~25s/block NU7 rate to land on ~225s of finality depth (see the "done" entry in
`docs/plans/swap-poc/status/zec.md` for the 3→9 testnet history of this same reasoning). Given
the Facts above — mainnet NU7 has no published height (ZIP 259: TBD), so mainnet is presumably
still at Zcash's traditional ~75s block time (not verified) — confirmations=10 against *today's*
mainnet would give ~750s of depth: three times the intended margin, not less. The number stays
safe on both sides of NU7 activation (whenever it is set): too conservative before it, on-target after. No finding, no fix needed.

## USDC/EVM

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (mainnet) | 12 | `crates/divi-swap/src/config.rs:66` | ok — standard Ethereum-mainnet finality heuristic |
| MTP lag (mainnet) | 180s | `crates/divi-swap/src/config.rs:66` | ok ("no MTP smoothing on EVM... lag only needs to cover block-time jitter", own comment) |
| Taker/maker timeout, claim margin | shared (see BTC) | `crates/divi-swap/src/config.rs:82-92,102` | ok |
| Gas price | live `provider.estimate_eip1559_fees()` for `max_fee_per_gas`/`max_priority_fee_per_gas` | `crates/swap-chain-evm/src/backend.rs:255-257` | ok — dynamically sourced, not hardcoded |
| Gas limit | live `estimate_gas` + 20% headroom | `crates/swap-chain-evm/src/backend.rs:234-259` | ok |
| Dust/minimum amount | `amount_to_usdc_units` rejects non-whole-unit amounts (precision guard, not an economic floor); `usdc_offer_is_fundable(min_eth_wei, min_usdc_units)` takes its floors as **caller-supplied parameters** — no hardcoded floor in this crate | `crates/swap-chain-evm/src/backend.rs:56-64,85-97` | ok (correctly config-driven at this layer) — the actual default floor values (reported elsewhere as ~0.01 ETH / 10 USDC) live outside this crate; out of scope for this review |
| Public backends / network | `UsdcNetwork` now has `Sepolia`, `BaseSepolia`, `Ethereum` (`"ethereum"`, chain id 1) and `Base` (`"base"`, chain id 8453) with `is_mainnet()`; native Circle USDC `0xA0b8…eB48` / `0x8335…2913` from <https://developers.circle.com/stablecoins/usdc-contract-addresses> (2026-10-21); default RPCs `https://ethereum-rpc.publicnode.com` and `https://mainnet.base.org` (both answered `eth_chainId` 0x1 / 0x2105 on 2026-10-21T19:44Z); `FromStr` still rejects `"mainnet"` naming the four accepted strings; tests pin round-trip, `is_mainnet`, distinct chain ids/tokens/RPCs | `crates/swap-chain-evm/src/network.rs:25-105,108-170`, `crates/swap-chain-evm/src/lib.rs:46-54` | **ok** — verified, mainnet options exist but are inert without the gates below |
| Daemon/CLI network selection | `[usdc].allow_mainnet` (default false); mainnet `network` without it → `no mainnet without the explicit allow_mainnet opt-in`; mainnet `network` with `profile = "testnet"` → `disagrees with profile`; `live_usdc` logs `network` and `mainnet`. CLI: `--usdc-network ethereum\|base` needs `--allow-mainnet`, checked in `usdc_endpoints` before any key or network use | `bin/divi-swapd/src/config.rs:162-179,680-695`, `bin/divi-swapd/src/main.rs:327`, `bin/divi-swap/src/main.rs:380-402` | **ok** — verified by unit tests (`usdc_mainnet_*` in both bins) and a live smoke, see the next row |
| mainnet read-only facts | 2026-10-21 hp3 (no key, no funds): ethereum via `https://ethereum-rpc.publicnode.com` 19:44:40Z chain id 1, height 26243153, USDC `decimals()` = 6, `symbol()` = `USDC`; base via `https://mainnet.base.org` 19:44:42Z chain id 0x2105 = 8453, height 52911267, `decimals()` = 6, `symbol()` = `USDC`. Daemon smoke (`profile = "mainnet"`, `[usdc] network = "ethereum"`/`"base"`, `allow_mainnet = true`, throwaway zero-balance key, since deleted): `usdc backend ready` with `eth_wei` 0, `usdc_units` 0 on both. Gate refusals: no allow → `[usdc].network = "ethereum": usdc mainnet moves real money: no mainnet without the explicit allow_mainnet opt-in (mainnet-readiness.md §USDC/EVM)`; profile testnet → `[usdc].network = "ethereum" disagrees with profile = Testnet: …`; CLI → `--usdc-network ethereum moves real money: no mainnet without the explicit --allow-mainnet opt-in` | `bin/divi-swapd/src/main.rs:327` | **verified**, no funds; the HTLC address in the smoke was a placeholder (no audited mainnet `Erc20Htlc` deployment exists — still open) |

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

## DIVI

Lane `divi-mainnet-wiring` (builder X), 2026-10-22, base `9565e95`. No funds, no keys that hold money, no swaps, no broadcast.

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Hardcodes before this lane (base `9565e95`) | daemon `DiviNetwork::Testnet` (`bin/divi-swapd/src/main.rs:434`); `DiviSection` had no network or opt-in (`bin/divi-swapd/src/config.rs:39-49`); CLI testnet URL + `Network::Testnet` (`bin/divi-swap/src/main.rs:497,499`, pre-lane lines; now `divi_network` `:74` and `live_backends` `:494`); `guard_profile` returned `Ok` for DIVI (`:448`, pre-lane line; the DIVI arm of `guard_profile` is now `:473-483`); `TESTNET_RPC` was the only endpoint const (`crates/swap-chain-divi/src/lib.rs:47`) | as listed | was risky: a mainnet profile with real BTC silently ran DIVI on testnet |
| Mainnet RPC endpoint | `https://services.divi.domains/api/rpc/` (no `/mainnet/` segment; `/api/mainnet/rpc/` is HTTP 404) | `crates/swap-chain-divi/src/lib.rs:51` | **verified** (see facts) |
| Address prefix | mainnet P2PKH version 30 (`D…`), testnet 139; WIF mainnet 212 | `crates/divi-wallet/src/address.rs:25-40` | **verified** — `validateaddress` on the mainnet endpoint accepted the smoke key's `D…` address |
| Daemon selection | `[divi].network` (default `testnet`) + `[divi].allow_mainnet` (default `false`) + optional `rpc_url` (default per network via `swap_chain_divi::default_rpc`); mainnet without the opt-in, an unknown network, or a network that disagrees with `profile` (either direction) is refused at config load. DIVI is checked after the counter coins, so their errors come first | `bin/divi-swapd/src/config.rs:39-80,745-760`, `bin/divi-swapd/src/main.rs:430-438` | ok |
| CLI selection | `--divi-network testnet\|mainnet` (default `testnet`), mainnet only with `--allow-mainnet`, validated by `guard_network` and `guard_profile` before any key or network call; the xmr arm is excluded (its DIVI side follows `--xmr-network`) | `bin/divi-swap/src/main.rs:74,429-491,494-528` | ok |
| Confirmations / MTP lag / timeouts | unchanged by this lane; mainnet 10 (`crates/divi-swap/src/config.rs:113`), reviewed with on-chain evidence in [divi-confirmations.md](divi-confirmations.md), decision pending | `crates/divi-swap/src/config.rs` | not touched |
| CLI mainnet read-only smoke | 2026-10-22 hp3 (nice, no funds): `divi-swap --backend live --counter-chain btc --profile mainnet --btc-network mainnet --divi-network mainnet --allow-mainnet --divi-key credential:divi --btc-key credential:btc balance` with a throwaway zero-balance key: `divi_address=DUBTqCx1vTjJR7iCJ4xu8bRk97vKFAwKsh`, `divi_balance_sats=0`, `btc_address=bc1q5akypsf99065egfmkp8suxc9sz6ftxe0pgyy84`, `btc_balance_sats=0`, 0.13 s. Without `--allow-mainnet`: "Error: --btc-network mainnet moves real money: no mainnet without the explicit --allow-mainnet opt-in" (btc is checked first); with only DIVI on mainnet and no opt-in: "Error: --divi-network mainnet moves real money: no mainnet without the explicit --allow-mainnet opt-in" | `bin/divi-swap/src/main.rs:422-484,487-521` | **verified** |
| daemon mainnet read-only smoke | 2026-10-22T11:48Z hp3: `divi-swapd --backend live` with `profile = "mainnet"`, `[divi] network = "mainnet" allow_mainnet = true`, `[btc] network = "mainnet" allow_mainnet = true`, no URL overrides, 127.0.0.1:18572, `path_prefix = "swap/"`: log "divi backend ready" address `DUBTqCx1vTjJR7iCJ4xu8bRk97vKFAwKsh` network `Mainnet`, "btc backend ready" network `mainnet`, "divi-swapd up"; `/swap/healthz` 200 (`path_prefix = "swap/"` mounts the router under `/swap`, `bin/divi-swapd/src/routes.rs:234-237`; with the default empty prefix it is `/healthz`) `divi.tip` 4269956 `error` null, `btc.tip` 972614 `error` null. Stopped by PID. Gates (first line, verbatim): `[divi].network = "mainnet"` without `allow_mainnet` → "Error: [divi].network = \"mainnet\": divi mainnet moves real money: no mainnet without the explicit allow_mainnet opt-in (mainnet-readiness.md §DIVI)"; `profile = "testnet"` + `[divi]` mainnet → "Error: [divi].network = \"mainnet\" disagrees with profile = Testnet: the swap timing profile and the divi backend must run on the same network"; `profile = "mainnet"` + `[divi]` on the testnet default → "Error: [divi].network = \"testnet\" disagrees with profile = Mainnet: the swap timing profile and the divi backend must run on the same network" | `bin/divi-swapd/src/config.rs:745-760`, `bin/divi-swapd/src/main.rs:430-438` | **verified** |

### Facts (read-only, from hp3, 2026-10-22)

| Claim | Verdict | Source |
|---|---|---|
| The DIVI mainnet RPC is `https://services.divi.domains/api/rpc/`: `getblockchaininfo` returned HTTP 200 with `chain = "main"`, blocks 4269931, bestblockhash `bfc62832c70c995eec93c262eed2dd79d1407acb82d8c535e29089cce1c6a9c0`; `getblockcount` 4269931 | **verified** | `curl -s -H content-type:application/json -d '{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}' https://services.divi.domains/api/rpc/` |
| `https://services.divi.domains/api/mainnet/rpc/` (guessed sibling of the testnet path) does not exist | **verified** HTTP 404 | same curl against that URL |
| The testnet URL answers a different chain: `chain = "test"`, blocks 360876 | **verified** | same curl against `.../api/testnet/rpc/` |
| `D…` is the mainnet prefix: `validateaddress` of the smoke key's `DUBTqCx1vTjJR7iCJ4xu8bRk97vKFAwKsh` → `isvalid: true`, scriptPubKey `76a914fcbd7fb10bd98da72e24b7f7b54ab4fcb743d47788ac` | **verified** | `validateaddress` against `https://services.divi.domains/api/rpc/` |
| The endpoint is a single public proxy with no independent mirror checked | **could not verify** a second mainnet endpoint | — |

Confirmation count review: see [divi-confirmations.md](divi-confirmations.md). Open item: **DIVI mainnet confirmation count: decision pending (see divi-confirmations.md).**

Smoke key: generated on hp3 for this run only, zero balance (`balance` printed 0 on both chains), mode 600 outside the git tree, never printed, deleted afterwards. Nothing was broadcast.

## XMR

**Not part of the shared engine at all.** `Chain` (`crates/divi-swap/src/types.rs:22-48`) and
`Chain::ALL` (`types.rs:41-48`, 6 elements: Divi, Btc, Ltc, Zec, Usdc, Xmr) *had* no `Xmr` variant
when this review was written; **corrected 2026-10-22:** `Chain::Xmr` exists now (`types.rs:36`),
`ChainParams::builtin` has an Xmr row (`crates/divi-swap/src/config.rs:69`: 10 confirmations, 1800 s)
and `check_profile_networks` covers xmr. The XMR swap still does not use the hashlock engine's
`SwapConfig::profile` / `required_gap_secs` machinery: `crates/divi-swap-xmr` has its own
`XmrConfig::for_profile` (`lib.rs:205`). `crates/swap-chain-xmr` is a free-standing, bespoke adaptor-signature swap
(`docs/plans/swap-poc/xmr-design.md`) with its own hand-rolled everything. Every value below is
local to that crate; there is no shared-config row to cite.

| Dimension | Value | file:line | Verdict |
|---|---|---|---|
| Confirmations (XMR side) | `SPENDABLE_AGE = 10` (Monero's real `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`, a protocol constant, not a tunable choice); a separate 1-confirmation check exists for "did the funding tx land" (`check_xmr_confirmed`), correctly distinct from spendability (`check_xmr_spendable`) | `crates/swap-chain-xmr/src/live_rpc.rs:63-70,78-107` | ok — matches Monero's own protocol minimum; discovered live after a real rejection (`"invalid_input": true`) against a 1-confirmation output |
| Confirmations (DIVI side of this swap) | `check_divi_confirmed` / `check_divi_confirmed_n` use `DIVI_CONFIRMATIONS_MAINNET = 10`, a mirror of the shared engine's DIVI mainnet depth (`swap-chain-xmr` cannot import `divi-swap`); the drift-alarm test `mainnet_divi_confirmations_matches_the_engines_config` re-reads `crates/divi-swap/src/config.rs` and fails if the two diverge | `crates/swap-chain-xmr/src/live_rpc.rs:212,216,231,570` | ok — matches the engine's DIVI leg depth for every other coin; drift is caught by a test |
| Timeouts/margins (`t_refund`, `t_punish`, `lock_time`) | no built-in schedule anywhere — plain function **parameters** on every template builder | `crates/swap-chain-xmr/src/swap_templates.rs:74-81,140-150`; `crates/swap-chain-xmr/src/multisig.rs:108-124` | **risky: no mainnet-safe margin scheme exists to review** — see below |
| Fee policy | `fee_rate: FeeRate` is a parameter; the live sweep sources it from the daemon's `get_fee_estimate` RPC (`monero_chain::sweep`, `crates/swap-chain-xmr/src/monero_chain.rs:294-311`; the example caller is `xmr_live.rs:435-450`) | `crates/swap-chain-xmr/src/monero_sweep.rs:83-91`; `crates/swap-chain-xmr/examples/xmr_live.rs:435-450` | ok — dynamically sourced, not hardcoded, when actually used live |
| Dust limit | not applicable — Monero RingCT outputs have no byte-size "dust" relay rule the way UTXO chains do; nothing resembling one exists in this crate | — | n/a |
| Reorg depth assumption | = `SPENDABLE_AGE` (10 blocks) on the XMR side; `DIVI_CONFIRMATIONS_MAINNET` (10) on the DIVI side, same mirror and drift-alarm test as the row above | `crates/swap-chain-xmr/src/live_rpc.rs:212,570` | ok |
| Public backends / network selection | Network is chosen by `[xmr].network` + `allow_mainnet` (default false; mainnet refused without it) in the daemon and `--xmr-network` + `--xmr-allow-mainnet` in the CLI; the node URL is configuration (`[xmr].monerod_url` / `--xmr-monerod-url`), the stagenet default being `MONEROD_RPC_DEFAULT = "http://node.monerodevs.org:38089"`. **New nettype guard:** before any wallet work, `live_xmr_engine` and `live_xmr_taker` ask the node `get_info` and refuse to start unless its `nettype` equals the configured network (and, for mainnet, `allow_mainnet` is set). Public mainnet restricted nodes that answered `get_info` with `nettype = "mainnet"` on 2026-10-21 (`verified`, see `status/xmr.md`): `node.monerodevs.org:18089`, `xmr-node.cakewallet.com:18081` | `bin/divi-swapd/src/config.rs:218-248`; `bin/divi-swap/src/main.rs:150-152`; guard: `crates/swap-chain-xmr/src/live_rpc.rs:79,111,120`, `crates/divi-swap-xmr/src/live.rs:527,552`, called at `bin/divi-swapd/src/main.rs:188`, `bin/divi-swap/src/main.rs:1022` | ok for network selection and node/network mismatch; **mainnet use stays gated on `xmr-mainnet-plan.md` phase D** |

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
  is a feature the `xmr` lane would need to design, not a constant this review can pin. **Superseded for the production engine (corrected 2026-10-22; xmr-mainnet-plan.md A3, done 2026-10-14):** `crates/divi-swap-xmr` derives the schedule from `ChainTiming` and `min_cancel_secs` / `min_punish_secs` / `min_redeem_margin_secs` (`crates/divi-swap-xmr/src/lib.rs:116-387`), selected by `XmrConfig::for_profile` (`lib.rs:205`); the sentence above stays true only of the two `swap-chain-xmr` examples.
- `examples/xmr_live.rs:174-191` still refuses anything but stagenet (an example, deliberately). The production paths no longer have a mainnet *option* gap: network selection exists and a node on the wrong network is refused at start. What remains before mainnet is not wiring and no longer the timeout schedule (xmr-mainnet-plan.md A3, done 2026-10-14; the "design work (timeouts/margins)" this line named): it is the phase-D trials and the human items in the "Left before a funded mainnet swap" section.

## Summary table

| Coin | Mainnet endpoint exists? | Mainnet address/tx format exists? | Any code fixed this review? |
|---|---|---|---|
| BTC | **yes** (`lane/btc-ltc-mainnet-wiring`): `esplora_endpoints("mainnet")` = `mempool.space/api` then `blockstream.info/api` (`crates/swap-chain-btc/src/lib.rs:46-49,67-69`); both answered `/blocks/tip/height` = 972518 at 2026-10-21T19:10Z (`verified`) | **yes**: `bitcoin_network()` maps `mainnet`→`Network::Bitcoin` (`lib.rs:54-63`), `BtcBackend::new_on(network, …)` builds the `bc1q` address (`lib.rs:132-150`); signet/testnet3 `tb1q` unchanged (test `mainnet_address_is_bc1q_and_test_networks_stay_tb1q`) | **yes — wired behind `[btc].allow_mainnet` (default false, `bin/divi-swapd/src/config.rs:82-89,733-747`) and `--btc-network mainnet` + `--allow-mainnet` (`bin/divi-swap/src/main.rs:70-76,494-528`)** |
| LTC | **yes** (`lane/btc-ltc-mainnet-wiring`): `esplora_endpoints("mainnet")` = `litecoinspace.org/api` only (`crates/swap-chain-ltc/src/lib.rs:50-52,73-75`; no independent Esplora mirror exists as of 2026-10-22, see status/ltc.md survey); answered `/blocks/tip/height` = 3199195 at 2026-10-21T19:10Z (`verified`) | **yes**: `hrp_for()` maps `mainnet`→`LTC_HRP` = `ltc` (`lib.rs:60-69`; source: litecoin `src/chainparams.cpp` `bech32_hrp = "ltc"` / `"tltc"`, https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp), `LtcBackend::new_on` builds the `ltc1q` address (`lib.rs:136-159`) and `build_send` rejects a destination whose HRP is not the backend's (`lib.rs:253-259`) | **yes — wired behind `[ltc].allow_mainnet` (default false, `config.rs:116-123,733-747`) and `--ltc-network mainnet` + `--allow-mainnet` (`main.rs:285-301,487-521`)** |
| ZEC | yes (`swap-chain-zec/src/lib.rs:61-77`) | yes (`address.rs:26-41`); v5/v6 chosen by NU6.3 height (`tx.rs:59-79`) | **yes — dust floor (`tx.rs:81-87`), test added and verified failing→passing** |
| USDC/EVM | yes, behind `allow_mainnet` (`swap-chain-evm/src/network.rs:25-105`; `ethereum`, `base`) | backend is network-agnostic | yes — variants, daemon/CLI gates and tests added (lane `usdc-mainnet-wiring`) |
| XMR | **yes, by configuration**: `[xmr].network`/`allow_mainnet` and `--xmr-network`/`--xmr-allow-mainnet` select the network and `monerod_url` the node; a mainnet restricted node answered `get_info` (`nettype = "mainnet"`, 2026-10-21, `verified`); the nettype guard refuses a node on the wrong network (`live.rs:527,552`) | yes — Monero addresses are parsed per network (`live::parse_address`); DIVI leg uses the shared mainnet depth (10) | **yes — nettype guard added (`lane/xmr-nettype-guard`)**; mainnet itself stays gated on `xmr-mainnet-plan.md` phase D |
| DIVI | **yes** (`lane/divi-mainnet-wiring`): `swap_chain_divi::MAINNET_RPC` = `https://services.divi.domains/api/rpc/` (`crates/swap-chain-divi/src/lib.rs:51`); `getblockchaininfo` `chain = "main"`, blocks 4269931 at 2026-10-22 (`verified`); the sibling `/api/mainnet/rpc/` is a 404 | **yes**: `D…` (version 30, `crates/divi-wallet/src/address.rs:25`); the endpoint's `validateaddress` accepted the smoke key's `D…` address (`verified`) | **yes — `[divi].network`/`allow_mainnet`, `--divi-network`, profile check and tests added (lane `divi-mainnet-wiring`); read-only smoke recorded** |

All citations above were re-read from the working tree at the stated line numbers as of this
review (2026-10-12); `crates/divi-swap/src/config.rs` and `crates/swap-chain-zec/src/tx.rs`
line numbers reflect the one landed change (the dust-floor fix).
