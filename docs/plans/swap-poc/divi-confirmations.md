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

## Derived from the spec and mainnet data (2026-10-22, builder BW)

Closes the evidence gap named above. **Nothing is changed**: DIVI mainnet `divi_confirmations` stays 10 (`crates/divi-swap/src/config.rs:113`). Data and scripts: `~/swap-lanes/builders/BW/data/` on hp1 (not in git).

### 1. What the spec says (Divi Core 3.0.0 source, clone at `9e2f76c`, 2023-07-06)

| rule | value | Divi Core cite | IronDivi |
|---|---|---|---|
| Max reorg depth | **a fork is rejected when `ActiveChain().Height() - nHeight >= nMaxReorgDepth`**; mainnet 100, `-maxreorg` overrides | `ChainExtensionService.cpp:309-311`; default `chainparams.cpp:180` (also :289, :396) | **not implemented**: `divi-network/src/sync.rs:810-812` says "There is no max-reorg-depth rule in this codebase" |
| Same depth used elsewhere | block serving, minter | `main.cpp:235-239`, `CoinMinter.cpp:67` | – |
| Checkpoints | mainnet holds heights 0 and 100 only (last timestamp 2018-09-27); static, no code adds more | `chainparams.cpp:107-110`; enforced `ChainExtensionService.cpp:321-346` | `storage/src/chain.rs:2077-2087` `get_checkpoint_hash` returns `None` |
| Block time vs MTP | `time-too-old` if not later than parent MTP | `ChainExtensionService.cpp:314` | – |
| Coinbase and coinstake maturity | 20 blocks | `chainparams.cpp:184`; `UtxoCheckingAndUpdating.cpp:75` | `COINBASE_MATURITY` = 20, `divi-primitives/src/lib.rs:82` |
| Min stake age | 1 h | `chainparams.cpp:195`; `ProofOfStakeGenerator.cpp:84` | **could not verify** that production code enforces it (only a test uses 3600, `pos_generator.rs:162`) |
| Stake target | value × timeWeight / COIN / 400 | `ProofOfStakeCalculator.cpp:19-24` | – |
| Stake modifier | interval 60 s, ratio 3 | `StakeModifierIntervalHelpers.h`; `ChainExtensionService.cpp:135-178`; `PoSStakeModifierService.cpp` | – |
| Block value / payee | `bad-cb-amount`, `bad-cb-payee` | `BlockConnectionService.cpp:85-96`; `BlockIncentivesPopulator.cpp:43,70,156-186` | – |

Consequence: the only reorg limit is 100 blocks, and only on Divi Core nodes. **There is no finality gadget** and no rule that makes a shallower reorg impossible. Anything below 100 is a probability question, not a guarantee. LAST_POW_BLOCK is 100 (`chainparams.cpp:189`); block time 60 s.

### 2. Observed reorgs (the number the earlier section lacked)

`getchaintips` on two Divi Core 3.0.0 containers on hp1 (ours, read-only RPC): `ifx4oj` (primary) 13 694 tips; `ieiy2i` (second opinion) 16 618 tips. The oldest tip is at height 2 487 937 (2023-06-21): the index covers about three years, not just the log window.

| `ifx4oj` status | branchlen 1 | branchlen 2 | longer |
|---|---|---|---|
| valid-fork (fully validated side chain) | 3 402 | 95 | none |
| invalid | 96 | 2 | none |
| valid-headers (headers only, never connected) | 10 047 | 50 | 1 at branchlen 62 |

- **Deepest validated reorg candidate: 2 blocks.** The one 62-long tip (height 2 580 255, 2023-08-23 13:30 UTC) is `valid-headers`: headers only, never validated, so it is not a reorg.
- `ieiy2i` has one extra branchlen-3 `valid-headers` tip (height 4 045 040, about 2026-05-21), also headers only.
- `debug.log` windows (ifx4oj 2026-10-18 14:07, ieiy2i 2026-10-17 13:45, both to 2026-10-22 ~21:53): `grep -ci "reorganiz|disconnect"` = 0 on both.
- Caveat: a side chain shows up only if the block was relayed to these nodes, so depth 2 is a lower bound on what happened network-wide.

### 3. Attacker model (what `z` blocks protect against)

Rosenfeld 2012, "Analysis of hashrate-based double spending", arXiv:1402.2009 §3.1: the attacker finds each block with probability q (honest p = 1 − q), the blocks he has when the payment gets z confirmations are k ~ NegBin(z, p); from a deficit d = z − k he ever gets strictly ahead with probability (q/p)^(d+1). Nakamoto 2008 §11 (Poisson) is the whitepaper variant; my script reproduces its figures (q = 0.1: z = 5 → 9.137e-4, z = 6 → 2.428e-4). Script `race.py`, output `race.out`.

Caveat: q here is the attacker's share of the **staking** coins (what wins a PoS race), not of total supply, and the model is an approximation for a stake-weighted race; read it as the shape of the risk, not an exact figure.

P(a payment with z confirmations is reversed):

| z | q = 0.10 | q = 0.25 | q = 0.33 | q = 0.40 |
|---|---|---|---|---|
| 1 | 3.1e-2 | 0.208 | 0.380 | 0.587 |
| 3 | 3.0e-3 | 0.094 | 0.251 | 0.483 |
| 6 | 1.10e-4 | 3.24e-2 | 0.147 | 0.381 |
| 10 | 1.5e-6 | 8.56e-3 | 0.0776 | 0.291 |
| 15 | 7.6e-9 | 1.74e-3 | 0.0367 | 0.214 |

Smallest z for a target risk:

| target | q = 0.10 | q = 0.25 | q = 0.33 | q = 0.40 |
|---|---|---|---|---|
| < 1 % | 2 | 10 | 25 | 77 |
| < 0.1 % | 4 | **17** | 42 | 128 |
| < 0.01 % | 7 | 25 | 59 | 181 |
| < 1e-6 | 11 | 40 | 95 | 289 |

Largest attacker share q that a given z still holds against:

| z | < 0.1 % | < 0.01 % |
|---|---|---|
| 6 | 14.1 % | 9.9 % |
| 10 | 19.6 % | 15.3 % |
| 15 | 23.9 % | 19.9 % |
| 17 | 25.1 % | 21.2 % |
| 20 | 26.7 % | 23.0 % |

### 4. Result

- **Derived number: 17 confirmations** (target: reversal < 0.1 %, attacker with 25 % of staking coins). It is a function of the assumed q and target; the table above is the real output, pick another row for another assumption.
- **Does 6 hold?** Against *natural* forks, yes with a wide margin: the deepest observed is 2, Core rejects ≥ 100. Against a *deliberate* attacker, only up to about 14 % staking share at 0.1 % (about 10 % at 0.01 %); at q = 25 % it is 3.2 %. **6 does not hold at q = 0.25.**
- **The current 10** holds to about 19.6 % at 0.1 %, and at q = 0.25 is 0.86 %.
- Cost of a higher count: each confirmation is about 60 s per lock (17 ≈ 17 min against 10 min today), see the cost line in the sections above.
- The 100-block max-reorg rule is not a finality guarantee for any z < 100 and does not exist in IronDivi nodes.
- **Not decided here.** The code value stays 10. The decision (keep 10, or move toward 17) belongs to Bert.

- **Decided 2026-10-23:** Bert chose 17 (2026-10-23, card 330b2472 option a); mainnet implemented, testnet stays 3.

## IronDivi enforcement of these rules (2026-10-22, builder BY)

Question: does IronDivi's production code enforce the Divi Core rules the confirmation math above relies on? Answer by rule below. Evidence is a test where one could be built (`crates/divi-storage/tests/swap_consensus_assumptions.rs`: 2 enforced tests that pass, 2 `#[ignore]`d tests that fail when run with `--include-ignored`) and a code read with file:line otherwise. No production code was changed. Base `20260fa`.

Hops common to every row (peer-arrival path): `crates/divi-network/src/sync.rs` (block message / IBD batch) → `Node::accept_block` `crates/divi-node/src/node.rs:872` → `Chain::accept_block` `crates/divi-storage/src/chain.rs:967` → `check_block_header` `chain.rs:2090` → on-tip: `check_block_context` `chain.rs:2120` / side chain: minimal checks `chain.rs:1060-1080` → checkpoint step 7a → `activate_best_chain_inner` (~`chain.rs:2680`) → `reorganize_chain` `chain.rs:1420` → `connect_block` `chain.rs:2779`. Side-chain blocks get only the parent and MTP checks until a reorg connects them.

| rule | Divi Core cite | IronDivi validation-path cite | verdict | path / evidence |
|---|---|---|---|---|
| Min stake age (1 h) | `chainparams.cpp:195`; `ProofOfStakeGenerator.cpp:84` | `pos_validation.rs:218 check_pos_time_requirements` (no caller outside its own tests and the `lib.rs:67` re-export); constant is 60 s, `pos_validation.rs:34` | **NOT ENFORCED** (code-read) | `validate_proof_of_stake` `chain.rs:2468` never calls it; weight is `min(age, 7d-1h)` with no age floor, `pos_validation.rs:195-200`. No PoS test built (needs a signed coinstake and a ground stake hash). |
| Block time later than parent MTP | `ChainExtensionService.cpp:314` | `chain.rs:2125-2131` (tip), `chain.rs:1073-1079` (side chain); MTP `chain.rs:933-963` | **ENFORCED** | accept_block → check_block_context `chain.rs:2120` → MTP check. Tests: `block_not_later_than_parent_mtp_is_rejected_on_the_tip`, `..._on_a_side_chain`. |
| Coinbase / coinstake maturity (20) | `chainparams.cpp:184`; `UtxoCheckingAndUpdating.cpp:75` | `connect_block` `chain.rs:2779+` has no maturity check; only mempool admission `divi-node/src/node.rs:947-967`; `COINBASE_MATURITY` = 20 `divi-primitives/src/lib.rs:82` | **NOT ENFORCED** at block level | Test `block_spending_an_immature_coinbase_is_rejected` (ignored): mainnet block 2 spending the 1-confirmation coinbase of block 1 is accepted. |
| Stake target formula | `ProofOfStakeCalculator.cpp:19-24` | `pos_validation.rs:114-130 stake_target_hit`, called via `compute_and_verify_proof_of_stake` `chain.rs:2566` from `validate_proof_of_stake` `chain.rs:2468` | **PARTIAL** (code-read) | Formula present and checked, but only for PoS blocks that extend the tip when not in IBD (`chain.rs:2132-2139`); blocks on a side chain are not checked until reorg. The target's `bits` is taken from the peer unchecked (see nBits below). Not tested. |
| nBits / difficulty retarget (needed by the target) | `ChainExtensionService`/`pow.cpp` (not in BW's table; could not verify cite) | `get_next_bits` `chain.rs:773` called only from the staker `divi-node/src/staker.rs:680`; `accept_block` never compares `block.header.bits` | **NOT ENFORCED** (code-read) | A peer can set trivially easy bits on a PoS block; `check_block_header` `chain.rs:2090` checks version, time and merkle root only. |
| Stake modifier (60 s, ratio 3) | `StakeModifierIntervalHelpers.h`; `ChainExtensionService.cpp:135-178` | `MODIFIER_INTERVAL`=60, `MODIFIER_INTERVAL_RATIO`=3 `stake_modifier.rs:19-20`; used by `get_stake_modifier_for_validation` `chain.rs:2329` ← `validate_proof_of_stake` `chain.rs:2548` | **PARTIAL** (code-read) | Computed and fed into the stake hash on the same tip / non-IBD path as the target. Bit-for-bit match with Core: could not verify (no test vectors, no network). |
| Max reorg depth (100) | `ChainExtensionService.cpp:309-311` | none; `sync.rs:810-812` says "There is no max-reorg-depth rule in this codebase"; `reorganize_chain` `chain.rs:1420` has no limit | **NOT ENFORCED** | Test `fork_deeper_than_max_reorg_depth_is_rejected` (ignored): a 99-block fork with more work off genesis reorganises a 100-block mainnet chain. |
| Checkpoints (heights 0 and 100) | `chainparams.cpp:107-110`; `ChainExtensionService.cpp:321-346` | `get_checkpoint_hash` `chain.rs:2077-2087` returns `None`; step 7a in `accept_block` only checks when `Some` | **NOT ENFORCED** (code-read) | Genesis is hard-coded in `Chain::new`, so height 0 holds by construction. Height-100 hash: not in BW's data (`crosscheck_heights.txt`), so no test written; could not verify the hash. |
| Block value / payee | `BlockConnectionService.cpp:85-96`; `BlockIncentivesPopulator.cpp:43,70,156-186` | `validate_block_value` `chain.rs:3206` ("mints too much" when `actual_mint > expected_mint`; skips heights ≤ 100), `validate_treasury_payments` `chain.rs:3058`, `validate_lottery_payments` `chain.rs:3331`; all called from `connect_block` `chain.rs:2800-2804` | **PARTIAL** (code-read) | Over-minting and treasury / lottery payees are checked at connect time, so on a side chain only at reorg. No equivalent of Core's exact `bad-cb-amount` equality was proven. Not tested. |
| PoW hash on a PoW-era block | – | `accept_block` has no PoW hash check; `sync.rs:87 validate_header` checks it for height ≤ `LAST_POW_BLOCK` only on the header-sync path | **PARTIAL** (code-read) | Extra finding, not one of the brief's rows; PoW blocks end at height 100. |

### Impact of the gaps on a swap party that reads DIVI through IronDivi

The swap confirmation math (17 at a 25 % attacker; the mainnet code value since 87bd69d) assumes the network enforces Divi Core's rules, so a fork is expensive and at most 100 deep. An IronDivi node does not check several of those rules on blocks it receives from peers.

- **Cheaper fork (nBits not checked, stake target only on the tip, no min stake age).** An attacker who serves blocks to an IronDivi node can claim easy `bits` and a young stake. The race model's `q` no longer bounds the attacker, since cost no longer scales with stake. Any peer that can reach the node can feed it a fork that Divi Core would reject. Whether such a fork also wins the work comparison (`compare_chain_work`, `chain.rs:2630`) depends on how chain work is derived from the declared bits; could not verify that here (the `chain_work` assignment was not traced), and the ignored reorg test shows a heavier fork does win.
- **Deeper reorg (no max-reorg rule).** IronDivi will reorganise any depth (proved at 100 deep). Divi Core refuses at 100. A confirmation count that is safe on Core is not safe on IronDivi once an attacker can win the work comparison above.
- **Immature spends (no maturity check).** A fake fork block can spend a coin that Core would call immature. This cannot move a swap lock by itself, but it makes forks cheaper to build.
- **MTP / `t_cancel` manipulation.** The MTP rule IS enforced on both the tip and side-chain paths, so a single block cannot jump MTP backwards. But a forked chain that IronDivi accepts carries its own timestamps, and MTP on that chain is whatever the attacker's blocks make it (each block still has to exceed the previous MTP and be at most 2 h in the future, `chain.rs:2090`). A party that reads MTP from IronDivi alone can therefore see a `t_cancel` window that Core does not.
- **Do the swap engine's defences cover it?** Largely, when `[divi].fallback_rpc_url` is a real Divi Core node. `swap-chain-divi/src/second_source.rs` reads every swap-relevant value on both endpoints and treats a disagreement as `Transient` (retry, never a decision): confirmation counts differing by more than 1, MTP by more than 600 s, tips by more than 2 blocks (`second_source.rs:17-31`); where they agree it takes the more conservative value. A fork shown only by IronDivi is therefore caught by confirmations and MTP. Confirmations on IronDivi alone are NOT a defence: an attacker who controls the IronDivi node's view controls its confirmation depth. The cover fails if the fallback is IronDivi too, or if the attacker can feed both.
- **Operating rule (one sentence):** read DIVI for a swap through Divi Core, or through IronDivi only with `[divi].fallback_rpc_url` set to an independent Divi Core node (the engine already refuses to act when the two disagree), and never act on IronDivi's confirmation count or MTP alone.

Each NOT ENFORCED row has a fix in `crates/divi-storage/src/chain.rs` (reorg depth in `reorganize_chain`, maturity in `connect_block`, bits in `accept_block`/`check_block_context`, checkpoints in `get_checkpoint_hash`) or `crates/divi-storage/src/pos_validation.rs` (min stake age). None is made here (lane rule: no production edits).
