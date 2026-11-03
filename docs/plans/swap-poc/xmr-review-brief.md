# XMR ↔ DIVI adaptor swap: brief for the outside security review

Status 2026-10-14: **brief for Phase C** of `xmr-mainnet-plan.md`. The reviewer has not seen the
project before; everything below points at code. Every `path:line` is against commit
`99e8864` (see §8).

> **2026-10-22 re-anchor:** the `path:line` refs below were re-checked against `signed/main`
> `4ea4f94` (116 commits after `99e8864`; C1–C8 restructured `maker.rs` and `taker.rs`) and
> point at that tree now. Where a ref's target no longer exists the text says `gone` and names
> its replacement. The prose of §2 still describes the pre-C1 protocol; see the note at the top
> of §2.

## 1. Purpose and scope

IronDivi runs a maker daemon (`divi-swapd`) that sells DIVI for XMR to a CLI taker (`divi-swap`)
with an adaptor-signature swap. No HTLC exists on Monero, so the design is the COMIT /
xmr-btc-swap shape: a DIVI 2-of-2 with presigned children, one ECDSA adaptor signature per
child, and a cross-group DLEQ proof tying each party's secp256k1 adaptor point to its Monero
spend-key share. The design write-up is `docs/plans/swap-poc/xmr-design.md`.

**Gate C** (`xmr-mainnet-plan.md` §Phase C): every **unfixed** finding is accepted in writing by
Human; a finding fixed in code leaves the gate with its commit reference (Human, 2026-10-21). Open today:
none (C1–C8 are all fixed — see the plan's Fixed table). No mainnet or real-funds swap
runs before then (`xmr-mainnet-plan.md` §Phase D).

| In scope | Out of scope |
|---|---|
| `crates/swap-adaptor/` (adaptor sigs, DLEQ wrapper, NUMS generators) | The BTC/LTC/ZEC/USDC hashlock lanes |
| `crates/swap-chain-xmr/` (DIVI scripts and templates, Monero lock/scan/sweep) | DIVI consensus itself (`DiviProject/Divi`) |
| `crates/divi-swap-xmr/` (maker and taker state machines, wire types, live adapters) | Third-party crates' internals (`ecdsa_fun`, `sigma_fun`, `monero-wallet`), except how we call them |
| `bin/divi-swapd/` XMR routes, config, startup checks | Host hardening, deploy scripts, 1Password custody (plan §B4) |
| `bin/divi-swap/` XMR taker flow and mainnet gating | Pricing and offer economics |

Questions the plan asks for are in §5. Findings may also be about anything in the "in" column.

## 2. Protocol

> **2026-10-22 note (stale narrative):** this section was written against the pre-C1 protocol
> (a maker-signed `Tx_punish`, one 2-of-2 script for both outputs, no joint key). Post-C1 the
> protocol adds a joint cancel key `J` and a `/xmr/swaps/:id/j` round (`maker.rs:719` `j_round`,
> `taker.rs:387` `j_step`, route `routes.rs:226`), `LockScript`/`CancelScript` in
> `crates/swap-chain-xmr/src/lock_scripts.rs:67,116`, a `t_late` branch, and 120 `Tx_cancel`
> encodings. `xmr-c1-design.md` and §7 are authoritative where they differ. The refs below were
> re-pointed to the nearest current code; the descriptions were not rewritten.

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
| `a` DIVI key | maker | `maker_divi_pubkey` | 2-of-2, first key | `maker.rs:672` (`SecretKey::new_random`) |
| `b` DIVI key | taker | `taker_divi_pubkey` | 2-of-2, second key | `taker.rs:322` (`prepare`) |
| `s_m` < 2^252 | maker | `Y` (secp), `S_m` (ed25519) | encsig key for Tx_refund; Monero spend share | `maker.rs:669` |
| `s_t` < 2^252 | taker | `X` (secp), `S_t` (ed25519) | encsig key for Tx_redeem; Monero spend share | `taker.rs:318` |
| view key `v` | maker chooses, sent to taker | — | scanning the Monero 2-of-2 | `maker.rs:671`, wire `api.rs:129-131` |

Monero lock address: spend key `S = S_m + S_t` (`crypto.rs:59`), view key `v`, legacy address
(`crates/swap-chain-xmr/src/monero_chain.rs:99-105`). Whoever learns both `s_m` and `s_t`
sweeps with `s_m + s_t` (maker `maker.rs:1450`, taker `taker.rs:960`).

The same 2-of-2 redeem script `OP_2 <a> <b> OP_2 OP_CHECKMULTISIG`
(`crates/swap-chain-xmr/src/multisig.rs:51-61`, maker key first) is used for both Tx_lock's and
Tx_cancel's outputs (was `taker.rs:269`, `:282`: gone, replaced by `LockScript`/`CancelScript` built in `verify_setup` at `taker.rs:489-500`, defined in `crates/swap-chain-xmr/src/lock_scripts.rs:67,116`).

### Message order (HTTP, maker is the server)

| # | Call | Sender → receiver | Content | Handler |
|---|---|---|---|---|
| 0 | `GET /offers/:id/quote` | taker → maker | quote id, amounts, expiry 60 s | `routes.rs:214`, `maker.rs:516` |
| 1 | `POST /xmr/swaps` | taker → maker | `SetupRequest`: `b`, payout script, `X`, `S_t`, DLEQ proof | `api.rs:55-84`, `maker.rs:613-714` |
| 2 | reply | maker → taker | `SetupReply`: `a`, `Y`, `S_m`, DLEQ proof, `v`, amounts, lock outpoint, `t_cancel`, `t_punish`, `maker_mtp` (optional: the DIVI MTP `t_cancel` was derived from; omitted by older makers, ignored by older takers), unsigned Tx_cancel + maker sig, refund script | `api.rs:111-165`, `taker.rs:450-545` |
| 3 | `POST /xmr/swaps/:id/sigs` | taker → maker | taker sig on Tx_cancel, Tx_refund encsig under `Y` | `api.rs:205-213`, `maker.rs:956` |
| — | maker signs Tx_punish, persists, broadcasts Tx_lock | | maker's punish sig appears in the swap view | gone: post-C1 the maker signs no Tx_punish and the view has no punish sig; the taker signs her own at `taker.rs:933-936` (was `maker.rs:573-582`, `api.rs:196-198`) |
| 4 | taker locks XMR, then `POST /xmr/swaps/:id/xmr-lock` | taker → maker | Monero txid (a hint; the maker verifies by scan) | `taker.rs:768-824`, `maker.rs:1051` |
| 5 | `GET /xmr/swaps/:id` | taker polls | `RedeemOffer`: unsigned Tx_redeem + maker encsig under `X` | `api.rs:224-231`, `maker.rs:268-276` |
| 6 | taker completes and broadcasts Tx_redeem | DIVI chain | reveals `s_t` | `taker.rs:795-824`, `swap_templates.rs:109` |
| 7 | maker recovers `s_t`, sweeps XMR | | | `maker.rs:1311-1335`, `:1437-1459` |

Abort path: after `t_cancel` either side broadcasts Tx_cancel (`maker.rs:1353-1366`,
`taker.rs:727-765`); the maker completes Tx_refund, revealing `s_m` (`maker.rs:1490-1547`); the
taker recovers `s_m` and sweeps her XMR back (`taker.rs:885-940`, `:942-976`). If the maker
never refunds, after `t_punish` the taker broadcasts Tx_punish and takes the DIVI; her XMR stays
locked forever (`taker.rs:925-937`).

Two ordering rules carry the maker's safety (`maker.rs:19-26`): Tx_lock goes out only after the
taker's Tx_cancel signature and Tx_refund encsig verified; the Tx_redeem encsig is produced only
after the XMR lock has `xmr_confirmations` and while `t_cancel` is more than `redeem_margin`
away. The taker's rule (pre-C1; 2026-10-22: the maker's Tx_punish signature no longer exists, see the note at the top of section 2): no XMR lock before she holds a valid maker signature on Tx_punish
(was `taker.rs:487-510`: gone, nothing of the maker's punish signature remains in `taker.rs`) and Tx_lock is confirmed with the right script and amount (`taker.rs:778-783`).

### On-chain transactions

| Tx | Spends | Pays | Signatures | nLockTime | Built at |
|---|---|---|---|---|---|
| Tx_lock | maker's coins | `lock_amount = divi_amount + fee` to the 2-of-2 | maker's wallet, plain | 0, inputs final | `maker.rs:845-870`, `divi_chain.rs:198-282` |
| Tx_cancel | Tx_lock output | same 2-of-2, `lock_amount − fee` (honest maker; value not checked by taker) | both plain | `t_cancel` | `maker.rs:876`, checked `taker.rs:503-514` |
| Tx_redeem | Tx_lock output | taker payout, `lock_amount − fee` | maker encsig under `X`, taker plain | 0 | `maker.rs:1376-1387`, `swap_templates.rs:87` |
| Tx_refund | Tx_cancel output | maker refund script, cancel value − fee | taker encsig under `Y`, maker plain | `t_cancel` | `api.rs:169-194`, `swap_templates.rs:141`, `:163` |
| Tx_punish | Tx_cancel output | taker payout, cancel value − fee | both plain | `t_punish` | `api.rs:169-194` |

All spends: version `CURRENT_TX_VERSION`, one input with sequence `REFUND_SEQUENCE` (non-final
so `nLockTime` binds), one output (`maker.rs:307`, `swap_templates.rs:74-81`). Legacy
`SIGHASH_ALL` sighash, no segwit (`crypto.rs:82-92`); txids therefore cover scriptSigs.
Timelocks are absolute `nLockTime` in unix seconds, compared against DIVI median time past; no
CSV/CLTV in any script. Fees are fixed at setup; the presigned children cannot be fee-bumped
(`lib.rs:185-186`).

### Timelock schedule

`t_cancel = MTP(setup) + cancel_after_secs` (`maker.rs:345-347`, checked add);
`t_punish = t_cancel + punish_after_secs` (`maker.rs:348-350`). There is no separate `t_refund`:
Tx_refund carries `t_cancel` (`api.rs:169-194`). The maker's MTP is the median of the last 11
DIVI block times read from its DIVI RPC (`divi_chain.rs:175`).

Cutoffs in the engines:

| Rule | Where |
|---|---|
| Taker refuses setup unless `t_cancel ≥ MTP + 2·margin` and `t_punish ≥ t_cancel + margin` | `taker.rs:515-524` |
| Taker locks XMR only while `MTP + 2·margin < t_cancel` | `taker.rs:787-790` |
| Maker offers redeem only while `MTP + margin < t_cancel` | `maker.rs:1375` |
| Taker redeems only while `MTP + margin < t_cancel` | `taker.rs:806-809` |
| Maker abandons an accepted swap after `sigs_wait_secs` (nothing broadcast) | `maker.rs:1223-1231` |

### Config values and the derived minimums

`XmrConfig` (`lib.rs:85-110`); `validate_for` refuses any schedule below the minimums derived
from `ChainTiming` (`lib.rs:116-131`, minimums `:344-393`, check `:401-444`). `XmrMaker::new`
calls it (`maker.rs:461`).

| Field | Testnet `lib.rs:166` | Mainnet `lib.rs:187` |
|---|---|---|
| `cancel_after_secs` | 21 600 (6 h) | 43 200 (12 h) |
| `punish_after_secs` | 10 800 (3 h) | 43 200 (12 h) |
| `redeem_margin_secs` | 3 600 | 7 200 |
| `divi_confirmations` | 3 | 17 (`crates/divi-swap/src/config.rs:114`; was 10 until 2026-10-23) |
| `xmr_confirmations` | 10 | 10 (`live_rpc.rs:242` `SPENDABLE_AGE`) |
| `divi_fee_sats` per presigned tx | 100 000 | 1 000 000 |
| `sigs_wait_secs` / `quote_expiry_secs` | 1 800 / 60 | 1 800 / 60 |

`ChainTiming::live()` (`lib.rs:137-149`): DIVI 60 s blocks, XMR 120 s, ×3 slow-block factor,
DIVI MTP lag 1 800 s (`crates/divi-swap/src/config.rs:62`), 300 s reaction time.

| Minimum | Formula | Testnet | Mainnet |
|---|---|---|---|
| `redeem_margin` `lib.rs:344` | lag + reaction + divi_wait(divi_conf) | 2 640 | 3 900 |
| `cancel_after` `lib.rs:358` | lag + sigs_wait + 2·reaction + divi_wait + max(reaction + xmr_wait + margin, 2·margin) | 12 240 | 20 400 |
| `punish_after` `lib.rs:375` | max(lag + 2·reaction + divi_wait(divi_conf + 1), margin) | 3 600 | 7 200 |

Testnet and mainnet both use `ChainTiming::live()`. `tests/schedule.rs` checks every validated
schedule against an independent worst-case timeline.

Network selection: `live::profile_for(network, allow_mainnet)` (`live.rs:527-537`); mainnet
needs `[xmr].allow_mainnet` (`bin/divi-swapd/src/config.rs:225`, default false) or
`--xmr-allow-mainnet` (`bin/divi-swap/src/main.rs:148-154`), plus a non-default DIVI RPC URL
(`bin/divi-swapd/src/main.rs:182-186`, `bin/divi-swap/src/main.rs:1000-1009`).

## 3. Cryptographic primitives

| Primitive | Where | Library or hand-rolled |
|---|---|---|
| ECDSA adaptor sign / verify / decrypt / recover | `crates/swap-adaptor/src/adaptor.rs:36-130` | `ecdsa_fun::adaptor` (wrapper only). Nonces: `Synthetic<Sha256, GlobalRng<ThreadRng>>` (`:28`); transcript `HashTranscript<Sha256, ChaCha20Rng>` (`:29`) |
| Plain DIVI ECDSA sign / verify | `crypto.rs:95-117`, `multisig.rs:83-98` | `divi-crypto` (`sign_hash`, `verify_hash`); DER + `SIGHASH_ALL` byte |
| Encsig on a DIVI tx | `swap_templates.rs:87-107` (Tx_redeem), `:141-161` (Tx_refund) | sighash from `divi_wallet::signer::sighash`; `ecdsa_fun` signs the 32-byte digest |
| Completion of an encsig | `swap_templates.rs:109-139`, `:163-192` | decrypt, then verify the result before use (`BadCompletion`) |
| Secret recovery from chain | `crypto.rs:147-193` → `swap_templates.rs:194-205` | parses the DER sig at a fixed scriptSig position, `recover_decryption_key`, then the engines check `ed_pub(s) == share` (`maker.rs:1331`, `taker.rs:917-921`) |
| Cross-group DLEQ (secp256k1 / ed25519) | `crates/swap-adaptor/src/dleq.rs:64-137` | `sigma_fun::ext::dl_secp256k1_ed25519_eq::CrossCurveDLEQ`, transcript `HashTranscript<Sha256, ChaCha20Rng>` (`:30`) |
| DLEQ generators `H_P`, `H_Q` | `dleq.rs:31-58`, `:109-116`; used via `crates/divi-swap-xmr/src/nums.rs:16` | **hand-rolled** try-and-increment SHA-256 of a fixed label, pinned bytes, re-derived by test `dleq.rs:229` |
| Clamped secret (< 2^252, non-zero) | `dleq.rs:142-154` | hand-rolled rejection loop |
| Scalar bridges | secp↔ed `crypto.rs:39-51` (byte reverse); dalek-ng → dalek `crates/swap-chain-xmr/src/monero_key_share.rs:50`; → Monero `monero_sweep.rs:64` | hand-rolled re-encodes |
| Monero key sum | `crypto.rs:59-62` (points), `maker.rs:1450`, `taker.rs:960` (scalars) | `curve25519-dalek-ng` add |
| Monero scan | `live_rpc.rs:480-494` | `monero-wallet` `Scanner` + `.not_additionally_locked()` |
| Monero sweep | `monero_chain.rs:268-359`, `monero_sweep.rs:83` | `monero-wallet` send, decoys from monerod, `OsRng` (`monero_chain.rs:38`) |
| Swap randomness | `maker.rs:668-672`, `taker.rs:308` | `rand::thread_rng` |

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
| `GET /offers/:id/quote` | `maker.rs:516-553` | unauthenticated; persists a quote record per call (`:548-551`) |
| `POST /xmr/swaps` | `maker.rs:613-714` | unauthenticated; runs `build_funding`, which reserves maker coins (`divi_chain.rs:280`) |
| `GET /xmr/swaps` | `maker.rs:1087` | lists every swap's view, no secrets (`api.rs:235`) |
| `GET /xmr/swaps/:id` | `maker.rs:1079` | includes `RedeemOffer` and `maker_punish_sig` |
| `POST /xmr/swaps/:id/sigs` | `maker.rs:956` | idempotent replay of the same sigs |
| `POST /xmr/swaps/:id/xmr-lock` | `maker.rs:1051-1072` | first txid wins; maker verifies by scan, not by txid |

Routes are mounted at `bin/divi-swapd/src/routes.rs:212-230`; error mapping `:259-263`. (2026-10-22: the sentence that follows is stale since C3, commit 92b933b: `/offers/:id/quote` and `POST /xmr/swaps` carry a per-IP rate limit, `routes.rs:214,222`, and the other `/xmr/swaps/:id/*` routes need the swap token. Original text:) There is no
authentication or rate limiting on any of them. Swap ids are UUIDs.

### Input validation

| Receiver | Checks | Where |
|---|---|---|
| Maker on setup | quote claim (no concurrent double use), unused, unexpired, xmr quote, DLEQ verifies, `b` is a point, payout is P2PKH/P2SH | `maker.rs:614-651` |
| Maker on sigs | taker's Tx_cancel sig verifies; Tx_refund encsig verifies under `Y` | `maker.rs:816`, `:985` |
| Taker on setup reply | same quote; DLEQ; XMR amount; `a` is a point; `lock_amount ≥ divi + fee`; `fee ≤` own config; Tx_cancel shape (1 in / 1 out, prevout, sequence, lock_time, output script); timelock room; maker's Tx_cancel sig; rebuilt Tx_refund txid matches | `taker.rs:450-545` |
| Taker before XMR lock | maker's Tx_punish sig verifies; Tx_lock output script and amount; DIVI confirmations; timelock | `taker.rs:768-792` (2026-10-22: the Tx_punish-sig check is gone post-C1; the taker signs Tx_punish herself, `taker.rs:933-936`) |
| Taker on redeem offer | spends the lock outpoint, lock_time 0, pays her payout ≥ quote, encsig verifies under `X` | `taker.rs:826-853` |

### Malicious counterparties and nodes

| Adversary | What it controls | Relevant code |
|---|---|---|
| Taker | every field of `SetupRequest`/`SigsRequest`, timing, which tx she broadcasts, any Monero output to the lock address | `maker.rs:613-764`, `:1285-1394` |
| Maker | every field of `SetupReply` including Tx_cancel's value, `t_cancel`/`t_punish` (lower bounds only), `v`, `RedeemOffer` | `taker.rs:450-545`, `:768-940` |
| monerod | block contents, heights, confirmations, fee estimate, decoys | `live.rs:412-458`, `monero_chain.rs:226-359`, `live_rpc.rs:480-494` |
| monero-wallet-rpc (taker) | where the taker's XMR actually goes | `monero_chain.rs:119-200` (digest auth) |
| DIVI RPC | MTP, spends, confirmations, UTXOs, broadcast results | `divi_chain.rs:175-301` |

`find_lock` returns the first output it finds for the lock address
(`monero_chain.rs:216-258`), scans blocks only (no mempool), and takes confirmations from
monerod. The scan cursor is persisted per lock address with a 3-block rescan margin
(`live.rs:51`, `:412-458`).

### Persistence and crash recovery

State is a SQLite store; files mode 0600 (`crates/divi-swap/src/store.rs:371`). The maker record
holds `a`, `s_m`, `v` and all presigned txs (`maker.rs:127-234`). Every transition is persisted
before its side effect (`maker.rs:35-37`, `:1039`, `:1538`). The taker's XMR lock and both sweeps
go through a journal written before the send; an entry without a txid refuses a resend
(`live.rs:341-410`, `:460-523`; module doc `live.rs:9-32`). `crash_and_restart_at_every_round`
(`crates/divi-swap-xmr/tests/engine.rs:402`) restarts both engines at every round.

### Concurrency

Maker: one async mutex per swap, pruned when unheld (`maker.rs:417`, `:1109-1115`), plus a
quote-claim set for concurrent `setup` (`maker.rs:421`, `:440-452`). `tick` steps open swaps one
after another (`maker.rs:1114-1135`); `step` runs up to 16 transitions (`:1190`). Taker: one global
gate for all her swaps (`taker.rs:252`).

## 5. Questions for the reviewer, in priority order

1. **Tx_cancel txid stability — is the C1 fix sound?** We have answered the question below
   ourselves: yes, both counterparties and any staker can malleate Tx_cancel (and stakers can
   malleate Tx_lock). The proposed fix is `xmr-c1-design.md`; its §8 lists what we want you to
   check. The original question, kept for context: Tx_refund and Tx_punish spend the *signed* Tx_cancel by txid
   (`api.rs:169-194`). After step 2 the taker holds the maker's Tx_cancel signature and her own
   key; after step 3 the maker holds both signatures. Can either party re-sign its own half with
   a fresh nonce and get a different, relay-standard Tx_cancel mined after `t_cancel`? If so,
   what happens to each engine (`maker.rs:1311-1335` treats any non-matching spender as
   Tx_redeem; `taker.rs:727-765` broadcasts the original and errors on rejection; 2026-10-22: pre-C1 behaviour, now `lock_scripts::lock_spend_branch` classifies the spender and `taker.rs:857-882`/`maker.rs:1463-1487` follow the encoding that was mined, see `xmr-c1-design.md`) and to the
   funds? Compare `xmr-design.md:548-581 (was :540-568 at e6a6fad; re-anchored 2026-10-22, now also carries the C1 correction)`, which treats malleability as miner-only and
   liveness-only. Same question for third-party S-flip: `crypto.rs:101-117` does not check
   low-S on the counterparty's plain signature.
1b. **Tx_lock txid stability (C7).** Tx_cancel is presigned against Tx_lock's txid before
   Tx_lock confirms, and Tx_lock spends the maker's P2PKH coins, whose scriptSigs any staker can
   change (no SIGPUSHONLY or LOW_S in Divi consensus). The taker is safe (she locks XMR only after
   the exact `lock_outpoint` confirms), but the maker's DIVI is then stuck in the 2-of-2. Our fix
   is a maker-only `t_late` branch (`xmr-c1-design.md` §4.3). Is its window sound for an offline
   taker?
2. **Tx_cancel output value.** The taker checks Tx_cancel's input, sequence, lock_time and
   output script, not its output value (`taker.rs:503-514`). Tx_punish's payout derives from
   it with a saturating subtraction (`api.rs:179`). Does a maker-chosen tiny value defeat
   the punish deterrent?
3. **DLEQ soundness and binding.** Are the pinned NUMS generators (`dleq.rs:31-58`, derivation
   in the test at `dleq.rs:229`) acceptable, and is `sigma_fun 0.9.0`'s
   `CrossCurveDLEQ` sound for our use? The proof transcript carries no swap id, network or
   role (`dleq.rs:30`): can a proof or `(X, S_t)` pair be replayed across swaps or networks to
   any effect? Is the byte-reverse bridge (`crypto.rs:39-51`) and the clamp (`dleq.rs:142-154`)
   correct for both curves?
4. **Adaptor signatures.** Review the `ecdsa_fun` usage (`adaptor.rs`), especially nonce
   generation (`:28`) and that each encsig is over the exact sighash the other side
   completes. Is ECDSA-adaptor's lack of a tight security proof (`xmr-design.md:505-510 (was :503-508; re-anchored 2026-10-22)`) a
   blocker? Is `recover` (`crypto.rs:147-193`) safe against a counterparty who completes with
   a different but valid signature, e.g. high-S or a non-canonical DER?
5. **Nonce reuse.** Each DIVI key signs Tx_cancel plain, one child plain, and one child
   encrypted (maker: Tx_punish plain, Tx_refund plain, Tx_redeem encrypted; taker: Tx_cancel
   plain, Tx_redeem plain, Tx_refund encrypted). Any nonce relation across plain
   (`divi-crypto`) and adaptor (`ecdsa_fun`) signatures with the same key?
6. **Timelock races.** MTP vs wall clock, `redeem_margin` vs confirmation depth, and the
   race between Tx_redeem and Tx_cancel and between Tx_refund and Tx_punish
   (`lib.rs:217-338`, the cutoffs table in §2). There is no upper bound on the maker's
   `t_cancel`/`t_punish` at the taker (`taker.rs:515-524`): what can a maker do with very
   long timelocks?
7. **Fee and stuck transactions.** Presigned fees are fixed and unbumpable (`lib.rs:185-186`).
   What happens to each path if Tx_cancel, Tx_refund or Tx_redeem does not confirm before the
   next deadline? Does refund revealing `s_m` before it is buried allow the taker to sweep
   and still punish (`lib.rs:367-379`)?
8. **Refund reveals key; punish.** Confirm Tx_refund reveals exactly `s_m` and nothing that
   endangers the maker; confirm the taker cannot get both the DIVI (punish) and her XMR back.
   Check `on_cancelled` on both sides (`maker.rs:1490-1547`, `taker.rs:885-940`).
9. **Monero side.** First-match `find_lock` (`monero_chain.rs:216-258`) when either party
   sends extra outputs to the lock address; `Scanner` vs `GuaranteedScanner`
   (`live_rpc.rs:486`) and the burning-bug class; maker-chosen view key (`maker.rs:671`);
   trusting monerod's confirmations (`live.rs:433-440`); maker moves to `Done` after one
   sweep confirmation (`maker.rs:1237-1245`).
10. **Replay across swaps and networks.** Quote single use (`maker.rs:637-639`, `:674`), swap
    ids, and whether anything ties a swap to DIVI mainnet vs testnet beyond the configured
    RPC URL.
11. **Mainnet opt-in bypass.** Can a mainnet XMR swap run against a DIVI testnet node, or
    the reverse, without `allow_mainnet`? Startup checks: `bin/divi-swapd/src/main.rs:179-196`,
    `bin/divi-swap/src/main.rs:997-1009`, `live.rs:523-537`.
12. **Denial of service.** C3 is fixed (reservation release/expiry, quote cap, per-IP limit,
    per-swap token); try to defeat it: reservations that survive an abort, quote flooding past the
    cap, token bypass via routes or the keying phase.

## 6. Known limitations (already accepted or open in the plan)

| Item | State | Where |
|---|---|---|
| A4: maker sweeps to a test wallet on stagenet; needs a maker-only wallet | open | `xmr-mainnet-plan.md` A4 |
| A5: maker on a public restricted monerod; own node syncing | code done, switch-over pending | plan A5, `live.rs:51` |
| A8: stagenet soak (≥ 20 swaps, all outcomes, restarts) | open | plan A8 |
| Taker uses one global gate for her swaps | accepted | `taker.rs:252`, plan A7 |
| Maker `tick` is sequential across swaps | accepted | `maker.rs:1114-1135`, plan A7 |
| B3 human runbook walk-through | open | plan B3, `xmr-runbook.md` |
| B4 key custody; `wallet_rpc_url` still required by the maker config | design only | plan §B4, `bin/divi-swapd/src/config.rs:231` (2026-10-22: `wallet_rpc_url` is now `Option<String>`, so "still required" is stale) |
| Presigned fees cannot be bumped | by design | `lib.rs:185-186` |
| Punish leaves the taker's XMR locked forever | by design | `RESULTS.md:342-350` |
| Aborted swaps released no coins; no auth or rate limit on quote/setup (C3) | fixed 2026-10-21 | tests `an_aborted_setup_releases_its_coins_and_a_locked_swap_keeps_them`, `the_swap_token_gates_a_swap`, `the_quote_store_is_bounded` in `crates/divi-swap-xmr/tests/engine.rs`; `xmr_swap_routes_need_the_swap_token`, `xmr_setup_is_rate_limited_per_ip` in `bin/divi-swapd/tests/e2e_xmr.rs` |
| Listing, dust `find_lock`, one-confirmation done, unchecked timelock add (C6) | fixed 2026-10-21 | `find_lock_skips_dust_to_the_lock_address`, `done_waits_for_the_profiles_confirmation_depth`, `setup_refuses_overflowing_timelocks` in `engine.rs`; `deadlines_are_checked_and_bounded` in `maker.rs` |
| No Tx_cancel output-key rotation (`a'`, `b'`) | differs from design | `taker.rs:489-500`, `xmr-design.md:223-226 (was :221-224; re-anchored 2026-10-22)` |

## 7. Test evidence

Run on the Linux host:

```sh
cargo test -p divi-swap-xmr -p divi-swap-cli -p divi-swapd
```

For the primitives and templates add `-p swap-adaptor -p swap-chain-xmr`.

| Tests | Covers |
|---|---|
| `crates/swap-adaptor/src/adaptor.rs:139-230` | encrypt/verify/decrypt round trip, key recovery, wrong-key rejection |
| `crates/swap-adaptor/src/dleq.rs:155-286`, `crates/divi-swap-xmr/src/nums.rs:25` | DLEQ verifies, fails under other generators, NUMS re-derivation, binding |
| `crates/swap-chain-xmr/src/tests.rs:50-191` | 2-of-2 script, signature order, nLockTime finality |
| `crates/swap-chain-xmr/src/swap_templates.rs:219-413` | adaptor templates on real DIVI sighashes |
| `crates/swap-chain-xmr/src/{happy_path_e2e,refund_path_e2e,role_swap_e2e}.rs` | DLEQ → Monero keys → DIVI templates, both outcomes and the swapped roles |
| `crates/swap-chain-xmr/src/monero_dkg.rs:93`, `:114` | Monero 2-of-2 key, stagenet address |
| `crates/divi-swap-xmr/src/lib.rs:449-776` | mainnet profile pinned, minimums enforced |
| `crates/divi-swap-xmr/tests/schedule.rs:69`, `:140` | 3 888 timings × 150 schedules against a worst-case timeline; minimal schedule is tight |
| `crates/divi-swap-xmr/tests/engine.rs:256-608` | happy, taker walks away, taker never locks, maker stalls → punish, crash at every round, no redeem sig before XMR confirms, adversarial inputs (`:482`), no XMR lock without punish sig (was `:511`; gone post-C1, no maker punish signature exists), stuck scan isolation (`:698`) |
| `crates/divi-swap-xmr/src/live.rs:603-896` | mainnet opt-in, scan cursor, lock/sweep journals, dead monerod |
| `bin/divi-swapd/tests/e2e_xmr.rs:162-345` | daemon + taker over HTTP with mock chains: happy, refund, route separation |
| `bin/divi-swap/src/main.rs:1501` | taker refuses mainnet without the opt-in and a DIVI RPC |

Live runs on DIVI testnet and Monero stagenet, with txids, are in `RESULTS.md:307-367`: redeem,
refund and punish paths and the roles-swapped direction (2026-10-12, harnesses in
`crates/swap-chain-xmr/examples/`), and one swap served by the deployed `divi-swapd`
(2026-10-14). The engine tests use mock chains (`crates/divi-swap-xmr/src/mock.rs`). The C1/C7
malleation cases are covered by `xmr-c1-design.md` §7 (tests 5a/5b/7 on regtest, 1–4 and 6 on
stagenet, all PASS); the reduced-value `Tx_cancel` check (C2, `taker.rs:509`) has the unit regression
test `the_taker_checks_tx_cancels_output_value`, and the maker's `t_late` branch (C7) has
`a_malleated_tx_lock_is_reclaimed_after_t_late` and `the_late_branch_stays_idle_on_the_normal_path`
(all in `crates/divi-swap-xmr/tests/engine.rs`). C4 (DIVI RPC chain check) and C5 (`t_cancel`/`t_punish`
upper bounds) are fixed with tests `divi_chain_check_accepts_a_match_and_refuses_a_mismatch` and
`the_taker_bounds_t_cancel_and_t_punish_from_above` in the same file.

## 8. Logistics

| Item | Value |
|---|---|
| Reviewer | _TBD_ |
| Engagement dates | _TBD_ – _TBD_ |
| Commit under review | `e6a6fad` (on `main`): the first commit with this brief and the corrected `xmr-design.md` malleability note. (2026-10-22: the Rust tree has changed since; `signed/main` `4ea4f94` is the current anchor, C1–C8 restructured `maker.rs`/`taker.rs`. Original statement:) The Rust tree is unchanged since `99e8864` (`ab36dbc` plus the swap-view `t_cancel`/`t_punish` fields and swap-watch alerting) |
| Repository access | GitHub `DiviDomains/IronDivi` (`git remote -v`), read access _TBD_ |
| Findings format | one entry per finding: severity, `path:line`, scenario, suggested fix |
| Findings go to | Human; each closed as fixed (commit) or accepted in writing, recorded in `xmr-mainnet-plan.md` decision log |
| Deadline for Gate C | _TBD_ |
