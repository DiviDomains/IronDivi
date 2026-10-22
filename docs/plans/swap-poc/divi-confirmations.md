# DIVI mainnet confirmation count — review (2026-10-22, builder AD)

Lane `divi-confirmations-review`, base `97bc181`. Read-only: no funds, keys, swaps or broadcasts. **Nothing in code
or config was changed; the recommendation below is a proposal for Bert, not applied.**

## 1. Current values

| Item | Value | file:line |
|---|---|---|
| Mainnet profile, DIVI lock | `divi_confirmations: 10` | `crates/divi-swap/src/config.rs:113` |
| Testnet profile, DIVI lock | `divi_confirmations: 3` | `crates/divi-swap/src/config.rs:123` |
| Same figure as chain parameter (built-in) | `Chain::Divi => (mainnet 10 / testnet 3, mtp lag 1800 s)`, comment "1-minute blocks" | `crates/divi-swap/src/config.rs:62` |
| DIVI MTP lag is always the mainnet built-in (1800 s) | `chain_params(Chain::Divi)` | `crates/divi-swap/src/config.rs:144-147` |
| Lookup by chain | `SwapConfig::confirmations(chain)` → `chain_params` | `crates/divi-swap/src/config.rs:161-162` |
| Offer terms carry the count | `OfferedTerms.divi_confirmations` | `crates/divi-swap/src/config.rs:279,288` |
| Taker refuses an offer below its profile floor | `divi_confirmations` vs `floor.confirmations(chain)` | `crates/divi-swap/src/config.rs:323-343` |
| Daemon override (TOML `[swap] divi_confirmations`) | `c.divi_confirmations = o.divi_confirmations.unwrap_or(..)`; `[swap.chains.divi]` is rejected | `bin/divi-swapd/src/config.rs:589,592` |
| Used by the maker/taker flow | `self.cfg.confirmations(counter)`, `cfg.divi_confirmations` | `crates/divi-swap/src/maker.rs:241`, `crates/divi-swap-xmr/src/maker.rs:1423,1556`, `crates/divi-swap-xmr/src/taker.rs:783` |
| XMR leg mirrors the mainnet figure, checked by a test | `DIVI_CONFIRMATIONS_MAINNET` parsed from config.rs | `crates/swap-chain-xmr/src/live_rpc.rs:212,550-573` |
| Chain constants | target spacing 60 s; coinbase maturity 20 | `crates/divi-storage/src/difficulty.rs:47`, `crates/divi-primitives/src/lib.rs:82` |

Readiness doc today: `mainnet-readiness.md` §DIVI says the count is "unchanged by this lane / not touched"; its BTC/LTC/ZEC
rows cite stale `config.rs` line numbers (the profile is at `:107-126`).

## 2. Evidence (public mainnet RPC `https://services.divi.domains/api/rpc/`, 2026-10-22 ~12:20Z, from hp3/Mac, read-only)

| Question | Request → response (trimmed) | Verdict |
|---|---|---|
| Chain, tip | `getblockchaininfo` → `chain:"main", blocks:4269973, headers:4269973, bestblockhash:528c41e6…593b` | **verified** |
| Block interval, last 1000 blocks (tip 4268976..4269976) | `getblockhash` + `getblockheader` for every height, gap = `time[h]-time[h-1]` (script: 4 threads, 0 missing). n=1000: **mean 59.5 s, median 40.5 s, p95 209 s, p99 318 s, max 625 s, min −40 s**; span 59 525 s (≈16.5 h) | **verified** |
| Timestamps are not monotonic | 173 of 1000 gaps are negative (min −40 s). Headers expose only `bits, merkleroot, nonce, previousblockhash, time, version` — no height/confirmations/mediantime | **verified** (MTP must be computed client side, as `status/divi.md` already decided) |
| Confirmations field | `getblock <hash of 4269000>` → `confirmations:977` while tip was 4269976 (consistent, no reorg of that block) | **verified** |
| Non-active forks | `getchaintips` → `{"error":{"code":-32603,"message":"Backend unavailable"}}` (three attempts, one with 120 s timeout) | **could not verify** |
| Reorg / orphan depth history | not exposed by any allowed call; `getchaintips` unavailable | **could not verify** |
| Finality mechanism | `getblockfinality`, `chainlock`, `getchainlock` → `Method not allowed`; `getmasternodecount` → all zeros (`total:0, enabled:0`); `listmasternodes` → `[]`; `getmasternodewinners` → winners `Unknown`, 0 votes. `help`, `getinfo`, `getstakinginfo` → `Method not allowed` | **verified**: no chainlock/finality RPC and no active masternode set on this endpoint; the only protection is cumulative work/stake depth |
| Second independent endpoint | none checked | **could not verify** |

Notes: the endpoint is a filtering proxy (unlisted methods return `-32601 Method not allowed`); `help` is blocked, so the
RPC list was probed by name, not enumerated.

## 3. Expected time to N confirmations (mean 59.5 s per block; "all-slow" = every block at the p95 gap, 209 s)

| N | expected (N × 59.5 s) | median-based (N × 40.5 s) | all-slow bound (N × 209 s) |
|---|---|---|---|
| 1 | ~1 min | ~0.7 min | 3.5 min |
| 2 | ~2 min | ~1.4 min | 7 min |
| 3 | ~3 min | ~2 min | 10.5 min |
| 5 | ~5 min | ~3.4 min | 17 min |
| 10 | ~10 min | ~6.8 min | 35 min |
| 20 | ~20 min | ~13.5 min | 70 min |

(The first block after broadcast also waits for inclusion, so wall-clock is slightly above N × mean. The mean exceeds the
60 s target mostly because of the long tail: median 40 s, max 625 s.)

## 4. Comparison with the other legs (mainnet profile)

| Leg | Confirmations | Block time | Wall clock | file:line |
|---|---|---|---|---|
| BTC | 2 | 10 min | ~20 min | `crates/divi-swap/src/config.rs:54,112` |
| LTC | 6 | 2.5 min | ~15 min | `config.rs:56` |
| ZEC | 10 | ~25 s | ~4 min | `config.rs:60` |
| **DIVI** | **10** | **~60 s (measured mean 59.5)** | **~10 min** | `config.rs:62,113` |
| USDC | 12 | ~12 s | ~2.4 min | `config.rs:66` |
| XMR | 10 | 2 min | ~20 min | `config.rs:69` |

DIVI at 10 is the same block count as ZEC/XMR, and its wall-clock sits below BTC (20 min) and LTC (15 min). It is half
the chain's own coinbase maturity (20 blocks, `divi-primitives/src/lib.rs:82`), which is the chain's rule for "deep enough
to spend freshly minted coins".

## 5. Recommendation (proposal for Bert — NOT applied)

**Keep `divi_confirmations = 10` for the mainnet profile for the first funded swap.** Reasons: (a) no finality
mechanism exists on the public endpoint, so depth is the only protection, and 10 blocks is ~10 min on average but up to
~35 min if every block is slow; going lower buys little time and removes margin against the chain's wide gap tail and its
non-monotonic timestamps; (b) it equals the ZEC/XMR counts and gives roughly BTC/LTC wall-clock parity; (c) the 12 h/24 h
timeouts leave ample room for the wait (the wait is <1% of the maker timeout). **Option if Bert wants more margin:** 20
(= coinbase maturity, ~20 min, BTC wall-clock parity); cost is an extra ~10 min per lock. **Open evidence gap:** the
public endpoint cannot give `getchaintips`, so the observed worst reorg is unknown; before raising or lowering the count,
run `getchaintips` against a node we control (or ask the endpoint operator to allow it). Decision belongs to Bert.
