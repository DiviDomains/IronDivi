# XMR ↔ DIVI adaptor swap: brief for the outside security review

Status 2026-10-14: **brief for Phase C** of `xmr-mainnet-plan.md`. The reviewer has not seen the
project before; everything below points at code. Every `path:line` is against commit
`99e8864` (see §8).

## 1. Purpose and scope

IronDivi runs a maker daemon (`divi-swapd`) that sells DIVI for XMR to a CLI taker (`divi-swap`)
with an adaptor-signature swap. No HTLC exists on Monero, so the design is the COMIT /
xmr-btc-swap shape: a DIVI 2-of-2 with presigned children, one ECDSA adaptor signature per
child, and a cross-group DLEQ proof tying each party's secp256k1 adaptor point to its Monero
spend-key share. The design write-up is `docs/plans/swap-poc/xmr-design.md`.

**Gate C** (`xmr-mainnet-plan.md:54-58`): every finding is fixed or accepted in writing by
Bert. No mainnet or real-funds swap runs before then (`xmr-mainnet-plan.md:72-74`).

| In scope | Out of scope |
|---|---|
| `crates/swap-adaptor/` (adaptor sigs, DLEQ wrapper, NUMS generators) | The BTC/LTC/ZEC/USDC hashlock lanes |
| `crates/swap-chain-xmr/` (DIVI scripts and templates, Monero lock/scan/sweep) | DIVI consensus itself (`DiviProject/Divi`) |
| `crates/divi-swap-xmr/` (maker and taker state machines, wire types, live adapters) | Third-party crates' internals (`ecdsa_fun`, `sigma_fun`, `monero-wallet`), except how we call them |
| `bin/divi-swapd/` XMR routes, config, startup checks | Host hardening, deploy scripts, 1Password custody (plan §B4) |
| `bin/divi-swap/` XMR taker flow and mainnet gating | Pricing and offer economics |

Questions the plan asks for are in §5. Findings may also be about anything in the "in" column.

## 2. Protocol

### Parties and roles

| Role | Holds | Wants | Code |
|---|---|---|---|
| Maker (`divi-swapd`) | DIVI | XMR | `crates/divi-swap-xmr/src/maker.rs` |
| Taker (`divi-swap` CLI) | XMR | DIVI | `crates/divi-swap-xmr/src/taker.rs` |

The maker locks first on DIVI. A roles-swapped direction exists only as a test harness
(`crates/swap-chain-xmr/src/role_swap_e2e.rs:61`); the daemon does not serve it.

### Keys and secrets per swap

| Secret | Owner | Public half | Purpose | Generated |
|---|---|---|---|---|
| `a` DIVI key | maker | `maker_divi_pubkey` | 2-of-2, first key | `maker.rs:431` (`SecretKey::new_random`) |
| `b` DIVI key | taker | `taker_divi_pubkey` | 2-of-2, second key | `taker.rs:204` (`prepare`) |
| `s_m` < 2^252 | maker | `Y` (secp), `S_m` (ed25519) | encsig key for Tx_refund; Monero spend share | `maker.rs:428` |
| `s_t` < 2^252 | taker | `X` (secp), `S_t` (ed25519) | encsig key for Tx_redeem; Monero spend share | `taker.rs:202` |
| view key `v` | maker chooses, sent to taker | — | scanning the Monero 2-of-2 | `maker.rs:430`, wire `api.rs:90-92` |

Monero lock address: spend key `S = S_m + S_t` (`crypto.rs:59`), view key `v`, legacy address
(`crates/swap-chain-xmr/src/monero_chain.rs:99-105`). Whoever learns both `s_m` and `s_t`
sweeps with `s_m + s_t` (maker `maker.rs:819`, taker `taker.rs:644`).

The same 2-of-2 redeem script `OP_2 <a> <b> OP_2 OP_CHECKMULTISIG`
(`crates/swap-chain-xmr/src/multisig.rs:51-61`, maker key first) is used for both Tx_lock's and
Tx_cancel's outputs (`taker.rs:269`, `:282`).

### Message order (HTTP, maker is the server)

| # | Call | Sender → receiver | Content | Handler |
|---|---|---|---|---|
| 0 | `GET /offers/:id/quote` | taker → maker | quote id, amounts, expiry 60 s | `routes.rs:72`, `maker.rs:345` |
| 1 | `POST /xmr/swaps` | taker → maker | `SetupRequest`: `b`, payout script, `X`, `S_t`, DLEQ proof | `api.rs:53-71`, `maker.rs:385` |
| 2 | reply | maker → taker | `SetupReply`: `a`, `Y`, `S_m`, DLEQ proof, `v`, amounts, lock outpoint, `t_cancel`, `t_punish`, unsigned Tx_cancel + maker sig, refund script | `api.rs:74-116`, `taker.rs:243` |
| 3 | `POST /xmr/swaps/:id/sigs` | taker → maker | taker sig on Tx_cancel, Tx_refund encsig under `Y` | `api.rs:148-155`, `maker.rs:516` |
| — | maker signs Tx_punish, persists, broadcasts Tx_lock | | maker's punish sig appears in the swap view | `maker.rs:573-582`, `api.rs:196-198` |
| 4 | taker locks XMR, then `POST /xmr/swaps/:id/xmr-lock` | taker → maker | Monero txid (a hint; the maker verifies by scan) | `taker.rs:479-528`, `maker.rs:591` |
| 5 | `GET /xmr/swaps/:id` | taker polls | `RedeemOffer`: unsigned Tx_redeem + maker encsig under `X` | `api.rs:166-173`, `maker.rs:777-799` |
| 6 | taker completes and broadcasts Tx_redeem | DIVI chain | reveals `s_t` | `taker.rs:533-561`, `swap_templates.rs:109` |
| 7 | maker recovers `s_t`, sweeps XMR | | | `maker.rs:745-764`, `:806-828` |

Abort path: after `t_cancel` either side broadcasts Tx_cancel (`maker.rs:767-776`,
`taker.rs:458-477`); the maker completes Tx_refund, revealing `s_m` (`maker.rs:831-874`); the
taker recovers `s_m` and sweeps her XMR back (`taker.rs:593-617`, `:626-660`). If the maker
never refunds, after `t_punish` the taker broadcasts Tx_punish and takes the DIVI; her XMR stays
locked forever (`taker.rs:619-622`).

Two ordering rules carry the maker's safety (`maker.rs:18-26`): Tx_lock goes out only after the
taker's Tx_cancel signature and Tx_refund encsig verified; the Tx_redeem encsig is produced only
after the XMR lock has `xmr_confirmations` and while `t_cancel` is more than `redeem_margin`
away. The taker's rule: no XMR lock before she holds a valid maker signature on Tx_punish
(`taker.rs:487-510`) and Tx_lock is confirmed with the right script and amount (`:516-521`).

### On-chain transactions

| Tx | Spends | Pays | Signatures | nLockTime | Built at |
|---|---|---|---|---|---|
| Tx_lock | maker's coins | `lock_amount = divi_amount + fee` to the 2-of-2 | maker's wallet, plain | 0, inputs final | `maker.rs:436-446`, `divi_chain.rs:186-270` |
| Tx_cancel | Tx_lock output | same 2-of-2, `lock_amount − fee` (honest maker; value not checked by taker) | both plain | `t_cancel` | `maker.rs:451`, checked `taker.rs:277-287` |
| Tx_redeem | Tx_lock output | taker payout, `lock_amount − fee` | maker encsig under `X`, taker plain | 0 | `maker.rs:786-797`, `swap_templates.rs:87` |
| Tx_refund | Tx_cancel output | maker refund script, cancel value − fee | taker encsig under `Y`, maker plain | `t_cancel` | `api.rs:120-145`, `swap_templates.rs:141`, `:163` |
| Tx_punish | Tx_cancel output | taker payout, cancel value − fee | both plain | `t_punish` | `api.rs:120-145` |

All spends: version `CURRENT_TX_VERSION`, one input with sequence `REFUND_SEQUENCE` (non-final
so `nLockTime` binds), one output (`maker.rs:245`, `swap_templates.rs:74-81`). Legacy
`SIGHASH_ALL` sighash, no segwit (`crypto.rs:82-92`); txids therefore cover scriptSigs.
Timelocks are absolute `nLockTime` in unix seconds, compared against DIVI median time past; no
CSV/CLTV in any script. Fees are fixed at setup; the presigned children cannot be fee-bumped
(`lib.rs:157-160`).

### Timelock schedule

`t_cancel = MTP(setup) + cancel_after_secs` (`maker.rs:447-449`, checked add);
`t_punish = t_cancel + punish_after_secs` (`maker.rs:450`). There is no separate `t_refund`:
Tx_refund carries `t_cancel` (`api.rs:120-145`). The maker's MTP is the median of the last 11
DIVI block times read from its DIVI RPC (`divi_chain.rs:163`).

Cutoffs in the engines:

| Rule | Where |
|---|---|
| Taker refuses setup unless `t_cancel ≥ MTP + 2·margin` and `t_punish ≥ t_cancel + margin` | `taker.rs:288-293` |
| Taker locks XMR only while `MTP + 2·margin < t_cancel` | `taker.rs:525-528` |
| Maker offers redeem only while `MTP + margin < t_cancel` | `maker.rs:785` |
| Taker redeems only while `MTP + margin < t_cancel` | `taker.rs:544-547` |
| Maker abandons an accepted swap after `sigs_wait_secs` (nothing broadcast) | `maker.rs:708-711` |

### Config values and the derived minimums

`XmrConfig` (`lib.rs:66-86`); `validate_for` refuses any schedule below the minimums derived
from `ChainTiming` (`lib.rs:92-107`, minimums `:180-215`, check `:225-262`). `XmrMaker::new`
calls it (`maker.rs:304`).

| Field | Testnet `lib.rs:142` | Mainnet `lib.rs:162` |
|---|---|---|
| `cancel_after_secs` | 21 600 (6 h) | 43 200 (12 h) |
| `punish_after_secs` | 10 800 (3 h) | 43 200 (12 h) |
| `redeem_margin_secs` | 3 600 | 7 200 |
| `divi_confirmations` | 3 | 10 (`crates/divi-swap/src/config.rs:103`) |
| `xmr_confirmations` | 10 | 10 (`live_rpc.rs:91` `SPENDABLE_AGE`) |
| `divi_fee_sats` per presigned tx | 100 000 | 1 000 000 |
| `sigs_wait_secs` / `quote_expiry_secs` | 1 800 / 60 | 1 800 / 60 |

`ChainTiming::live()` (`lib.rs:113-125`): DIVI 60 s blocks, XMR 120 s, ×3 slow-block factor,
DIVI MTP lag 1 800 s (`crates/divi-swap/src/config.rs:52`), 300 s reaction time.

| Minimum | Formula | Testnet | Mainnet |
|---|---|---|---|
| `redeem_margin` `lib.rs:180` | lag + reaction + divi_wait(divi_conf) | 2 640 | 3 900 |
| `cancel_after` `lib.rs:194` | lag + sigs_wait + 2·reaction + divi_wait + max(reaction + xmr_wait + margin, 2·margin) | 12 240 | 20 400 |
| `punish_after` `lib.rs:211` | max(lag + 2·reaction + divi_wait(divi_conf + 1), margin) | 3 600 | 7 200 |

Testnet and mainnet both use `ChainTiming::live()`. `tests/schedule.rs` checks every validated
schedule against an independent worst-case timeline.

Network selection: `live::profile_for(network, allow_mainnet)` (`live.rs:504-514`); mainnet
needs `[xmr].allow_mainnet` (`bin/divi-swapd/src/config.rs:137`, default false) or
`--xmr-allow-mainnet` (`bin/divi-swap/src/main.rs:107-113`), plus a non-default DIVI RPC URL
(`bin/divi-swapd/src/main.rs:183-187`, `bin/divi-swap/src/main.rs:618-626`).

## 3. Cryptographic primitives

| Primitive | Where | Library or hand-rolled |
|---|---|---|
| ECDSA adaptor sign / verify / decrypt / recover | `crates/swap-adaptor/src/adaptor.rs:36-130` | `ecdsa_fun::adaptor` (wrapper only). Nonces: `Synthetic<Sha256, GlobalRng<ThreadRng>>` (`:28`); transcript `HashTranscript<Sha256, ChaCha20Rng>` (`:29`) |
| Plain DIVI ECDSA sign / verify | `crypto.rs:95-117`, `multisig.rs:83-98` | `divi-crypto` (`sign_hash`, `verify_hash`); DER + `SIGHASH_ALL` byte |
| Encsig on a DIVI tx | `swap_templates.rs:87-107` (Tx_redeem), `:141-161` (Tx_refund) | sighash from `divi_wallet::signer::sighash`; `ecdsa_fun` signs the 32-byte digest |
| Completion of an encsig | `swap_templates.rs:109-139`, `:163-192` | decrypt, then verify the result before use (`BadCompletion`) |
| Secret recovery from chain | `crypto.rs:144-170` → `swap_templates.rs:194-205` | parses the DER sig at a fixed scriptSig position, `recover_decryption_key`, then the engines check `ed_pub(s) == share` (`maker.rs:760-762`, `taker.rs:612-614`) |
| Cross-group DLEQ (secp256k1 / ed25519) | `crates/swap-adaptor/src/dleq.rs:64-137` | `sigma_fun::ext::dl_secp256k1_ed25519_eq::CrossCurveDLEQ`, transcript `HashTranscript<Sha256, ChaCha20Rng>` (`:30`) |
| DLEQ generators `H_P`, `H_Q` | `dleq.rs:31-58`, `:109-116`; used via `crates/divi-swap-xmr/src/nums.rs:16` | **hand-rolled** try-and-increment SHA-256 of a fixed label, pinned bytes, re-derived by test `dleq.rs:229` |
| Clamped secret (< 2^252, non-zero) | `dleq.rs:142-154` | hand-rolled rejection loop |
| Scalar bridges | secp↔ed `crypto.rs:39-51` (byte reverse); dalek-ng → dalek `crates/swap-chain-xmr/src/monero_key_share.rs:50`; → Monero `monero_sweep.rs:64` | hand-rolled re-encodes |
| Monero key sum | `crypto.rs:59-62` (points), `maker.rs:819`, `taker.rs:644` (scalars) | `curve25519-dalek-ng` add |
| Monero scan | `live_rpc.rs:314-328` | `monero-wallet` `Scanner` + `.not_additionally_locked()` |
| Monero sweep | `monero_chain.rs:249-345`, `monero_sweep.rs:83` | `monero-wallet` send, decoys from monerod, `OsRng` (`monero_chain.rs:38`) |
| Swap randomness | `maker.rs:427-431`, `taker.rs:196` | `rand::thread_rng` |

The dalek-ng (`sigma_fun`) and dalek (`monero-wallet`) scalar types are bridged by byte
re-encoding, not by a shared type.

Crate versions resolved in `Cargo.lock`:

| Crate | Version | Used by |
|---|---|---|
| `secp256kfun` | 0.12.1 | swap-adaptor |
| `ecdsa_fun` (feature `adaptor`) | 0.12.0 | swap-adaptor |
| `sigma_fun` (feature `ed25519`) | 0.9.0 | swap-adaptor, divi-swap-xmr |
| `curve25519-dalek-ng` | 4.1.1 | swap-adaptor, divi-swap-xmr |
| `curve25519-dalek` | 4.1.3 | swap-chain-xmr |
| `monero-wallet` | 0.2.0 | swap-chain-xmr, divi-swap-xmr |
| `dkg` / `ciphersuite` | 0.6.1 / 0.4.2 | swap-chain-xmr (`monero_key_share.rs`) |
| `rand` / `rand_chacha` | 0.8.8 / 0.3.1 | all three swap crates |
| `sha2` | 0.10.9 | swap-adaptor |

## 4. Trust boundaries and attack surface

### Network endpoints (maker)

| Route | Handler | Notes |
|---|---|---|
| `GET /offers/:id/quote` | `maker.rs:345-380` | unauthenticated; persists a quote record per call (`:376-379`) |
| `POST /xmr/swaps` | `maker.rs:385` | unauthenticated; runs `build_funding`, which reserves maker coins (`divi_chain.rs:268`) |
| `GET /xmr/swaps` | `maker.rs:627` | lists every swap's view, no secrets (`api.rs:177`) |
| `GET /xmr/swaps/:id` | `maker.rs:619` | includes `RedeemOffer` and `maker_punish_sig` |
| `POST /xmr/swaps/:id/sigs` | `maker.rs:516` | idempotent replay of the same sigs |
| `POST /xmr/swaps/:id/xmr-lock` | `maker.rs:591-612` | first txid wins; maker verifies by scan, not by txid |

Routes are mounted at `bin/divi-swapd/src/routes.rs:68-83`; error mapping `:96-110`. There is no
authentication or rate limiting on any of them. Swap ids are UUIDs.

### Input validation

| Receiver | Checks | Where |
|---|---|---|
| Maker on setup | quote claim (no concurrent double use), unused, unexpired, xmr quote, DLEQ verifies, `b` is a point, payout is P2PKH/P2SH | `maker.rs:386-423` |
| Maker on sigs | taker's Tx_cancel sig verifies; Tx_refund encsig verifies under `Y` | `maker.rs:536-571` |
| Taker on setup reply | same quote; DLEQ; XMR amount; `a` is a point; `lock_amount ≥ divi + fee`; `fee ≤` own config; Tx_cancel shape (1 in / 1 out, prevout, sequence, lock_time, output script); timelock room; maker's Tx_cancel sig; rebuilt Tx_refund txid matches | `taker.rs:254-325` |
| Taker before XMR lock | maker's Tx_punish sig verifies; Tx_lock output script and amount; DIVI confirmations; timelock | `taker.rs:487-528` |
| Taker on redeem offer | spends the lock outpoint, lock_time 0, pays her payout ≥ quote, encsig verifies under `X` | `taker.rs:563-590` |

### Malicious counterparties and nodes

| Adversary | What it controls | Relevant code |
|---|---|---|
| Taker | every field of `SetupRequest`/`SigsRequest`, timing, which tx she broadcasts, any Monero output to the lock address | `maker.rs:385-612`, `:742-874` |
| Maker | every field of `SetupReply` including Tx_cancel's value, `t_cancel`/`t_punish` (lower bounds only), `v`, `RedeemOffer` | `taker.rs:243-330`, `:479-622` |
| monerod | block contents, heights, confirmations, fee estimate, decoys | `live.rs:391-435`, `monero_chain.rs:209-345`, `live_rpc.rs:314-350` |
| monero-wallet-rpc (taker) | where the taker's XMR actually goes | `monero_chain.rs:119-200` (digest auth) |
| DIVI RPC | MTP, spends, confirmations, UTXOs, broadcast results | `divi_chain.rs:163-300` |

`find_lock` returns the first output it finds for the lock address
(`monero_chain.rs:206-238`), scans blocks only (no mempool), and takes confirmations from
monerod. The scan cursor is persisted per lock address with a 3-block rescan margin
(`live.rs:51`, `:391-435`).

### Persistence and crash recovery

State is a SQLite store; files mode 0600 (`crates/divi-swap/src/store.rs:348`). The maker record
holds `a`, `s_m`, `v` and all presigned txs (`maker.rs:99-186`). Every transition is persisted
before its side effect (`maker.rs:28-29`, `:580`, `:867`). The taker's XMR lock and both sweeps
go through a journal written before the send; an entry without a txid refuses a resend
(`live.rs:327-390`, `:437-500`; module doc `live.rs:9-32`). `crash_and_restart_at_every_round`
(`tests/engine.rs:338`) restarts both engines at every round.

### Concurrency

Maker: one async mutex per swap, pruned when unheld (`maker.rs:282`, `:649-655`), plus a
quote-claim set for concurrent `setup` (`maker.rs:286`, `:290-302`). `tick` steps open swaps one
after another (`maker.rs:657-665`); `step` runs up to 16 transitions (`:675`). Taker: one global
gate for all her swaps (`taker.rs:173`).

## 5. Questions for the reviewer, in priority order

1. **Tx_cancel txid stability.** Tx_refund and Tx_punish spend the *signed* Tx_cancel by txid
   (`api.rs:120-145`). After step 2 the taker holds the maker's Tx_cancel signature and her own
   key; after step 3 the maker holds both signatures. Can either party re-sign its own half with
   a fresh nonce and get a different, relay-standard Tx_cancel mined after `t_cancel`? If so,
   what happens to each engine (`maker.rs:745-764` treats any non-matching spender as
   Tx_redeem; `taker.rs:458-477` broadcasts the original and errors on rejection) and to the
   funds? Compare `xmr-design.md:540-568`, which treats malleability as miner-only and
   liveness-only. Same question for third-party S-flip: `crypto.rs:101-117` does not check
   low-S on the counterparty's plain signature.
2. **Tx_cancel output value.** The taker checks Tx_cancel's input, sequence, lock_time and
   output script, not its output value (`taker.rs:277-287`). Tx_punish's payout derives from
   it with a saturating subtraction (`api.rs:130`). Does a maker-chosen tiny value defeat
   the punish deterrent?
3. **DLEQ soundness and binding.** Are the pinned NUMS generators (`dleq.rs:31-58`, derivation
   in the test at `dleq.rs:229`) acceptable, and is `sigma_fun 0.9.0`'s
   `CrossCurveDLEQ` sound for our use? The proof transcript carries no swap id, network or
   role (`dleq.rs:30`): can a proof or `(X, S_t)` pair be replayed across swaps or networks to
   any effect? Is the byte-reverse bridge (`crypto.rs:39-51`) and the clamp (`dleq.rs:142-154`)
   correct for both curves?
4. **Adaptor signatures.** Review the `ecdsa_fun` usage (`adaptor.rs`), especially nonce
   generation (`:28`) and that each encsig is over the exact sighash the other side
   completes. Is ECDSA-adaptor's lack of a tight security proof (`xmr-design.md:503-508`) a
   blocker? Is `recover` (`crypto.rs:144-170`) safe against a counterparty who completes with
   a different but valid signature, e.g. high-S or a non-canonical DER?
5. **Nonce reuse.** Each DIVI key signs Tx_cancel plain, one child plain, and one child
   encrypted (maker: Tx_punish plain, Tx_refund plain, Tx_redeem encrypted; taker: Tx_cancel
   plain, Tx_redeem plain, Tx_refund encrypted). Any nonce relation across plain
   (`divi-crypto`) and adaptor (`ecdsa_fun`) signatures with the same key?
6. **Timelock races.** MTP vs wall clock, `redeem_margin` vs confirmation depth, and the
   race between Tx_redeem and Tx_cancel and between Tx_refund and Tx_punish
   (`lib.rs:175-215`, the cutoffs table in §2). There is no upper bound on the maker's
   `t_cancel`/`t_punish` at the taker (`taker.rs:288-293`): what can a maker do with very
   long timelocks?
7. **Fee and stuck transactions.** Presigned fees are fixed and unbumpable (`lib.rs:157-160`).
   What happens to each path if Tx_cancel, Tx_refund or Tx_redeem does not confirm before the
   next deadline? Does refund revealing `s_m` before it is buried allow the taker to sweep
   and still punish (`lib.rs:203-215`)?
8. **Refund reveals key; punish.** Confirm Tx_refund reveals exactly `s_m` and nothing that
   endangers the maker; confirm the taker cannot get both the DIVI (punish) and her XMR back.
   Check `on_cancelled` on both sides (`maker.rs:831-874`, `taker.rs:593-622`).
9. **Monero side.** First-match `find_lock` (`monero_chain.rs:206-238`) when either party
   sends extra outputs to the lock address; `Scanner` vs `GuaranteedScanner`
   (`live_rpc.rs:320`) and the burning-bug class; maker-chosen view key (`maker.rs:430`);
   trusting monerod's confirmations (`live.rs:410-417`); maker moves to `Done` after one
   sweep confirmation (`maker.rs:717-722`).
10. **Replay across swaps and networks.** Quote single use (`maker.rs:386-400`, `:491`), swap
    ids, and whether anything ties a swap to DIVI mainnet vs testnet beyond the configured
    RPC URL.
11. **Mainnet opt-in bypass.** Can a mainnet XMR swap run against a DIVI testnet node, or
    the reverse, without `allow_mainnet`? Startup checks: `bin/divi-swapd/src/main.rs:180-198`,
    `bin/divi-swap/src/main.rs:615-626`, `live.rs:504-522`.
12. **Denial of service.** Unauthenticated `setup` reserves maker coins
    (`divi_chain.rs:268`); abort at `maker.rs:708-711`; unbounded quote records.

## 6. Known limitations (already accepted or open in the plan)

| Item | State | Where |
|---|---|---|
| A4: maker sweeps to a test wallet on stagenet; needs a maker-only wallet | open | `xmr-mainnet-plan.md` A4 |
| A5: maker on a public restricted monerod; own node syncing | code done, switch-over pending | plan A5, `live.rs:51` |
| A8: stagenet soak (≥ 20 swaps, all outcomes, restarts) | open | plan A8 |
| Taker uses one global gate for her swaps | accepted | `taker.rs:173`, plan A7 |
| Maker `tick` is sequential across swaps | accepted | `maker.rs:657-665`, plan A7 |
| B3 human runbook walk-through | open | plan B3, `xmr-runbook.md` |
| B4 key custody; `wallet_rpc_url` still required by the maker config | design only | plan §B4, `bin/divi-swapd/src/config.rs:141` |
| Presigned fees cannot be bumped | by design | `lib.rs:157-160` |
| Punish leaves the taker's XMR locked forever | by design | `RESULTS.md:342-350` |
| Aborted swaps do not release the coins `setup` reserved; no xmr code calls `release` | open | `crates/swap-chain-divi/src/wallet.rs:168`, `maker.rs:708-711` |
| No auth or rate limit on quote/setup | open | `routes.rs:68-83` |
| No Tx_cancel output-key rotation (`a'`, `b'`) | differs from design | `taker.rs:269`, `xmr-design.md:221-224` |

## 7. Test evidence

Run on the Linux host:

```sh
cargo test -p divi-swap-xmr -p divi-swap-cli -p divi-swapd
```

For the primitives and templates add `-p swap-adaptor -p swap-chain-xmr`.

| Tests | Covers |
|---|---|
| `crates/swap-adaptor/src/adaptor.rs:139-230` | encrypt/verify/decrypt round trip, key recovery, wrong-key rejection |
| `crates/swap-adaptor/src/dleq.rs:164-300`, `crates/divi-swap-xmr/src/nums.rs:25` | DLEQ verifies, fails under other generators, NUMS re-derivation, binding |
| `crates/swap-chain-xmr/src/tests.rs:50-191` | 2-of-2 script, signature order, nLockTime finality |
| `crates/swap-chain-xmr/src/swap_templates.rs:219-413` | adaptor templates on real DIVI sighashes |
| `crates/swap-chain-xmr/src/{happy_path_e2e,refund_path_e2e,role_swap_e2e}.rs` | DLEQ → Monero keys → DIVI templates, both outcomes and the swapped roles |
| `crates/swap-chain-xmr/src/monero_dkg.rs:93`, `:114` | Monero 2-of-2 key, stagenet address |
| `crates/divi-swap-xmr/src/lib.rs:271-389` | mainnet profile pinned, minimums enforced |
| `crates/divi-swap-xmr/tests/schedule.rs:69`, `:140` | 3 888 timings × 150 schedules against a worst-case timeline; minimal schedule is tight |
| `crates/divi-swap-xmr/tests/engine.rs:192-578` | happy, taker walks away, taker never locks, maker stalls → punish, crash at every round, no redeem sig before XMR confirms, adversarial inputs (`:418`), no XMR lock without punish sig (`:511`), stuck scan isolation (`:578`) |
| `crates/divi-swap-xmr/src/live.rs:529-724` | mainnet opt-in, scan cursor, lock/sweep journals, dead monerod |
| `bin/divi-swapd/tests/e2e_xmr.rs:159-297` | daemon + taker over HTTP with mock chains: happy, refund, route separation |
| `bin/divi-swap/src/main.rs:768` | taker refuses mainnet without the opt-in and a DIVI RPC |

Live runs on DIVI testnet and Monero stagenet, with txids, are in `RESULTS.md:307-367`: redeem,
refund and punish paths and the roles-swapped direction (2026-10-12, harnesses in
`crates/swap-chain-xmr/examples/`), and one swap served by the deployed `divi-swapd`
(2026-10-14). The engine tests use mock chains (`crates/divi-swap-xmr/src/mock.rs`); no test
exercises a malleated Tx_cancel or a Tx_cancel with a reduced output value.

## 8. Logistics

| Item | Value |
|---|---|
| Reviewer | _TBD_ |
| Engagement dates | _TBD_ – _TBD_ |
| Commit under review | `e6a6fad` (on `main`): the first commit with this brief and the corrected `xmr-design.md` malleability note. The Rust tree is unchanged since `99e8864` (`ab36dbc` plus the swap-view `t_cancel`/`t_punish` fields and swap-watch alerting) |
| Repository access | GitHub `DiviDomains/IronDivi` (`git remote -v`), read access _TBD_ |
| Findings format | one entry per finding: severity, `path:line`, scenario, suggested fix |
| Findings go to | Bert; each closed as fixed (commit) or accepted in writing, recorded in `xmr-mainnet-plan.md` decision log |
| Deadline for Gate C | _TBD_ |
