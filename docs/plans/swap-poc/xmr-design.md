# DIVI↔XMR adaptor-signature swap — design

Lane `xmr` (`docs/plans/swap-poc/lanes/xmr.md`). Monero has no scripting (no CLTV, no
multisig-in-script, no hashlocks you can point at from outside); you cannot build an HTLC on
it the way `crates/divi-swap/src/htlc.rs` builds one on DIVI/BTC. The established way around
that — the COMIT/Farcaster Bitcoin↔Monero protocol (Gugger, 2020; `comit-network/xmr-btc-swap`,
now archived in favor of the community forks `eigenwallet/core` and `UnstoppableSwap`) — replaces
the hashlock with an **ECDSA adaptor signature** whose secret is cross-committed into a Monero
multisig spend key via a **cross-group discrete-log-equality (DLEQ) proof**. This doc adapts that
protocol to DIVI's actual, verified consensus rules (not the Rust reimplementation in
`crates/divi-script`, which is ahead of what the live C++ node enforces — see
[Risks](#risks)) and keeps the engine's `Maker`/`Taker` vocabulary (`crates/divi-swap/src/state.rs`)
instead of the literature's Alice/Bob.

## Protocol

### Roles

- **Maker** quotes DIVI for XMR (symmetric to the existing BTC lane: Maker always holds the DIVI
  leg). **Taker** holds XMR and wants DIVI.
- Unlike the hashlock swap, **both legs lock into a 2-of-2 output**, not just one. Neither party's
  on-chain lock is independently spendable; every subsequent transaction is pre-signed
  (or adaptor-presigned) by both parties before the corresponding lock confirms. This is why the
  protocol needs five transaction templates per leg instead of the two (claim/refund) the hashlock
  design uses.

### Key material (setup, off-chain)

Each party generates, before anything touches a chain:

| Key | Curve | Purpose |
|---|---|---|
| `a` (Maker) / `b` (Taker) | secp256k1 | DIVI-side 2-of-2 multisig key, one per party |
| `v_m, s_m` (Maker) / `v_t, s_t` (Taker) | ed25519 | Monero view/spend key shares — the output is a 2-of-2 shared spend key `S = s_m·G + s_t·G` (Monero native multisig, not a script) |
| `x` (Taker, if Taker is the XMR seller*) | **both** curves | the adaptor secret: one scalar, interpreted as both a secp256k1 and an ed25519 private key |

\* Direction matters: whichever party's Monero-side spend key share doubles as the Bitcoin-side
(DIVI-side) adaptor secret is the party who *reveals* their secret by completing the DIVI
transaction. In the canonical protocol the XMR-locking party (Taker, here) plays that role, mapping
onto the original Alice (has Monero) / Bob (has Bitcoin) roles: Taker ~ Alice, Maker ~ Bob.

Taker proves, with the DLEQ proof (see [DLEQ](#dleq)), that the secp256k1 public point `X` it hands
to Maker and the ed25519 component of its Monero spend-key share commit to the *same* scalar `x`,
without revealing `x`. Maker checks the proof before locking anything.

### Transaction templates (DIVI side)

All five are built and exchanged as unsigned templates right after both parties commit to the deal
(before either leg locks), so every party knows the full shape — and every timelock — before
funds move:

| Tx | Spends | Signed by | `nLockTime` | Purpose |
|---|---|---|---|---|
| `Tx_lock` | Maker's coins | Maker alone | none | Pays into the 2-of-2 `{a, b}` output. Ordinary DIVI tx, not part of the presigned set. |
| `Tx_cancel` | `Tx_lock` output | both, at setup (plain 2-of-2 sig, no adaptor) | `t_cancel` | Moves the locked DIVI into a second 2-of-2 output `{a', b'}` so that if the swap stalls before Taker locks XMR, either party can get back to a refundable state without racing. Needed because `Tx_lock`'s own output has no escape hatch of its own — see below. |
| `Tx_refund` | `Tx_cancel` output | Maker: adaptor-signed with point `X`; Taker: plain | `t_refund` (≥ `t_cancel`) | Pays Maker's leg back to Maker. Taker can only complete *Maker's* adaptor signature if Taker learns the decryption — which Taker already knows, being the adaptor-secret holder. **Maker publishing `Tx_refund` reveals nothing new** (Maker already had a plain signature from Taker); this path is for Maker-initiated abort. |
| `Tx_punish` | `Tx_cancel` output | Taker: adaptor-signed with point `X`; Maker: plain | `t_punish` (≥ `t_refund` + margin) | Pays **all** of the cancelled output to Maker. Only valid if `Tx_refund` was never published. Deters Taker from locking XMR and then stalling: Maker eventually sweeps everything. |
| `Tx_redeem` | `Tx_lock` (or `Tx_cancel`) output | Taker: adaptor-signed with point `X`; Maker: plain | none | Pays Maker's leg to **Taker**. Taker can only produce a valid signature by completing the adaptor with `x` — and broadcasting it **reveals `x`** (ECDSA adaptor signatures leak the secret to anyone who can read the two signatures off-chain vs. the completed one on-chain; see below). This is the step that lets Maker learn `x` and sweep the Monero side. |

`Tx_lock` has **no in-script timelock at all** — unlike the existing BTC/DIVI HTLC
(`crates/divi-swap/src/htlc.rs`), which needs `OP_CHECKLOCKTIMEVERIFY` *inside* the script because
one output has to support two differently-timed spend paths from unspecified future transactions.
Here every spend of a locked output is a **specific, fully-known presigned transaction**, so the
timelock lives in that transaction's own `nLockTime` field and DIVI's base
"a transaction with a future `nLockTime` and a non-final input `nSequence` cannot be mined" rule
(present since Bitcoin's genesis, inherited by every fork, DIVI included) enforces it — **no
opcode, no softfork, no relative-locktime support needed.** This sidesteps the CSV gap documented
in [Risks](#risks).

### Happy path

1. Exchange key material + DLEQ proof; build and exchange unsigned `Tx_cancel/_refund/_punish/_redeem`
   templates; both sign the plain (non-adaptor) halves; Taker produces the adaptor-signed halves
   for `Tx_refund`/`Tx_punish` keyed to point `X`, Maker produces the adaptor-signed half for
   `Tx_redeem` keyed to the same `X`.
2. Maker broadcasts `Tx_lock` (DIVI). Taker waits for confirmations, then locks the matching XMR
   amount into the 2-of-2 Monero output (`s_m + s_t`).
3. Maker waits for the Monero lock's confirmations (Monero stagenet/mainnet wants far more than
   DIVI — 10 confirmations is the figure COMIT/xmr-btc-swap ships with, vs. DIVI's existing 1–6;
   see [Build plan](#build-plan)), then **completes** Taker's adaptor signature on `Tx_redeem`
   using its own secret share of `X` and broadcasts it.
4. Taker observes `Tx_redeem` on-chain, extracts `x` from the gap between the adaptor-encrypted
   and completed ECDSA signatures (standard adaptor-signature decryption — the whole point of the
   construction), and uses `x` to complete its half of the Monero spend key `s_t`, sweeping the
   XMR output.

### Failure cases

- **Taker never locks XMR** (step 2 never happens): after `t_cancel`, either party broadcasts
  `Tx_cancel`; after `t_refund`, Maker broadcasts `Tx_refund` to get the DIVI back. No secret is
  exposed because Maker already held a plain signature — this path never touches the adaptor.
- **Maker locks DIVI, Taker locks XMR, Maker then stalls** (never does step 3): after `t_punish`,
  Taker broadcasts `Tx_punish`, taking all of the cancelled DIVI. This is the deterrent that makes
  stalling after both locks strictly worse than completing the swap for Maker.
- **Maker completes `Tx_redeem` but Taker is offline / can't extract `x` in time**: no new risk —
  `x` is sitting in a public, permanent DIVI transaction; Taker (or anyone who archived that txid)
  can extract it and sweep the Monero output at any later time, as long as the Monero output
  itself hasn't separately timed out (Monero multisig outputs have no on-chain timelock of their
  own, so this risk is bounded only by how long Taker is willing to wait — a liveness, not a
  safety, concern).
- **Monero chain reorg / 51%-style deep reorg after Taker locks XMR but before Maker's DIVI-side
  `t_punish`**: out of scope for this design (Monero gives no finality guarantee beyond
  confirmation count; COMIT's own writeup treats this as accepted residual risk, mitigated only
  by confirmation count, same as every Monero application).
- **Taker reveals `x` some other way (coerced, leaked) before Maker locks**: Maker's lock hadn't
  happened yet, so there's nothing to steal; the DLEQ proof only binds `x` to `X`/`S`, it doesn't
  protect `x` once known. Not a protocol failure.

## DIVI scripts

### What's actually enforced on-chain, verified against the real C++ node (not this repo's Rust reimplementation)

Lane `xmr` cloned `github.com/DiviProject/Divi` (`master`, commit `9e2f76c`) to check this
directly rather than trust `crates/divi-script`, which is a from-scratch reimplementation several
steps ahead of what ships:

- **`OP_CHECKLOCKTIMEVERIFY` (BIP65) works.** `divi/src/script/StackManager.cpp:984`
  (`SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY && opcode == OP_CHECKLOCKTIMEVERIFY` →
  `LockTimeCheckOp`). This is the opcode the existing BTC/DIVI HTLC already proved live
  (`RESULTS.md`), confirmed again by reading the source.
- **`OP_CHECKSEQUENCEVERIFY` (BIP112) does *not* work — it is a plain upgradable NOP.**
  `divi/src/script/StackManager.cpp:938` puts `OP_NOP3` (Bitcoin's pre-BIP112 name for the same
  opcode number) in `upgradableOpCodes`, dispatched to `DisabledOp` (line 117), which just returns
  `true` (succeeds, no check) unless `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` is set. There is no
  `case` for it anywhere that does a sequence check.
- **BIP68 relative-locktime (the *consensus*-level nSequence rule BIP112 depends on,
  independent of any opcode) is also absent**, not merely unused: `divi/src/defaultValues.h:13`
  defines `LOCKTIME_VERIFY_SEQUENCE` and `STANDARD_LOCKTIME_VERIFY_FLAGS` (byte-for-byte copied
  from Bitcoin Core's constant names), but `grep -rl STANDARD_LOCKTIME_VERIFY_FLAGS divi/src/*.cpp`
  returns **nothing** — the flag is defined and never read. No relative timelocks exist on DIVI,
  script-level or consensus-level.
- `crates/divi-script/src/interpreter.rs:586` *does* implement `OP_CHECKSEQUENCEVERIFY`
  correctly per BIP112 — this is get-ahead-of-upstream work in this repo, not something the live
  network (or any counterparty's node) enforces today. **Do not design around it.**
- `OP_CHECKMULTISIG`/`OP_CHECKMULTISIGVERIFY` are both implemented (`interpreter.cpp:129`,
  dispatched like Bitcoin). Bare multisig outputs are typically filtered by `IsStandard`-style
  relay policy on Bitcoin-family nodes; this design wraps the 2-of-2 in P2SH (below) to stay clear
  of that without needing to check DIVI's specific standardness rules.

The upshot, already used in [Protocol](#protocol): **this design needs no relative timelocks at
all.** Every DIVI-side lock, cancel, refund, and punish transaction is a *specific presigned
transaction object* with its own `nLockTime`, not a single output script with multiple
differently-timed branches — so BIP65/opcode-level CLTV support is unnecessary too, except
optionally as a defensive fallback (below). The only on-chain primitives this design actually
needs from DIVI are: P2SH, `OP_CHECKMULTISIG`, ECDSA signature verification, and the base
"non-final tx with future `nLockTime` can't be mined" rule — all four already proven live by the
existing BTC↔DIVI HTLC lane.

### Script shapes

`Tx_lock`'s output and `Tx_cancel`'s output are both plain 2-of-2 P2SH:

```
scriptPubKey: OP_HASH160 <ripemd160(sha256(redeemScript))> OP_EQUAL
redeemScript: OP_2 <pubkey_A> <pubkey_B> OP_2 OP_CHECKMULTISIG
```

`pubkey_A`/`pubkey_B` differ between `Tx_lock`'s output (`a`, `b`) and `Tx_cancel`'s output
(`a'`, `b'` — fresh keys per leg, standard practice so the cancelled state isn't spendable by the
same keys as the original lock, closing a key-reuse foot-gun rather than a protocol requirement).
`Tx_refund`/`Tx_punish`/`Tx_redeem` spend via the usual P2SH multisig scriptSig
(`OP_0 <sig_A> <sig_B> <redeemScript>`); no `OP_IF`/`OP_ELSE` branching script is needed anywhere,
unlike `htlc.rs`'s hashlock.

**Defensive option, not required for correctness:** `Tx_cancel`'s redeem script could instead be
`OP_IF <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_2 <a'> <b'> OP_2 OP_CHECKMULTISIG OP_ENDIF`
(CLTV-gated multisig) to additionally block early broadcast of `Tx_refund`/`Tx_punish` *at the
script level*, in case a future DIVI build hardens `nLockTime` enforcement in a way this design
didn't anticipate. Not adopted here: it adds one proven-but-unnecessary opcode dependency and
complicates the redeem-script hash both parties must agree on, for a belt the base protocol
doesn't need a suspender for.

## DLEQ

### What needs proving

Taker picks scalar `x`. It must be a valid secp256k1 private key (order
`n ≈ 2^256 − 4.3×10^38`) **and** a valid ed25519 private key component (order
`ℓ ≈ 2^252 + δ`, `δ` small). Taker reveals `X = x·G_secp256k1` to Maker and uses `x` as (part of)
its Monero spend-key share, so the ed25519 point is `x·G_ed25519` folded into the shared spend
public key `S`. Maker must be convinced `X` and (Taker's share of) `S` commit to the same `x`
**without learning `x`** — otherwise Maker has no guarantee that completing `Tx_redeem`'s adaptor
signature actually hands Taker a usable Monero key share.

### Why it's hard

Mismatched group orders (`n ≠ ℓ`) mean you can't just "use the same scalar" naively — a scalar
valid mod `n` might reduce to something different mod `ℓ`, so a bare Schnorr-style
equality-of-discrete-logs proof doesn't carry across. The accepted construction (Maxwell/Poelstra
sketch → COMIT's formalization → re-implemented in `secp256kfun`):

1. **Clamp `x` to the smaller range.** Pick `x < 2^252` (strictly inside `ℓ`'s range and far inside
   `n`'s), so it's unambiguously a valid scalar on *both* curves — no reduction ambiguity.
2. **Bit-commit on both curves.** Decompose `x` into 252 bits; for each bit, Pedersen-commit it on
   *both* secp256k1 and ed25519 (separate blinding factors, same bit).
3. **Prove each commitment is a bit** (0 or 1) via an OR-proof (Borromean-ring-signature style),
   and **prove the secp256k1 and ed25519 commitments for bit `i` commit to the same value** via a
   second sigma protocol per bit.
4. **Prove the weighted sum of bit-commitments equals `X`** (secp256k1 side) **and the
   corresponding ed25519 point** — closing the loop from "252 individually-proven-equal bits" to
   "the actual public keys Maker and the Monero multisig will use."

This is a batch of 252 small sigma-protocol proofs, not one cheap operation — expect proof
generation/verification to be the most CPU-visible part of swap setup (COMIT's own writeup flags
this; budget for it in [Build plan](#build-plan)'s acceptance tests rather than assuming it's
free).

### Candidate implementation

`secp256kfun`'s `sigma_fun::ext::dl_secp256k1_ed25519_eq` module
(`github.com/LLFourn/secp256kfun`, pushed 2026-05-12, 112★, not archived) is this exact proof,
written by the same author (Lloyd Fournier) who formalized it for COMIT, and is the direct
successor to COMIT's own proof-of-concept (`comit-network/cross-curve-dleq`, **archived since
2021**, 1★ — superseded, do not depend on it). Recommended as the DLEQ dependency: it is maintained,
narrowly scoped to this exact problem, and avoids pulling in `farcaster_core`'s much larger,
stale surface (see [Crates](#crates)) just for this one proof.

## Crates

| Crate | Role | Maturity (checked 2026-10-11) |
|---|---|---|
| [`monero-serai`](https://github.com/serai-dex/serai/tree/develop/coins/monero) | Monero-side primitives: ed25519/ristretto arithmetic, RPC client, FROST-based multisig, transaction construction, CLSAG. | **Primary pick.** Actively developed (`serai-dex/serai` pushed 2026-10-10, 421★, not archived), purpose-built for exactly this (a DEX that needs Monero multisig outputs), but still `0.1.x-alpha` — pin an exact rev, expect API churn, budget review time per bump. Split into `monero-wallet`/`monero-rpc`/`monero-serai` sub-crates; use only what's needed rather than the deprecated monolithic wallet surface. |
| [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek) | ed25519 scalar/point arithmetic underneath the DLEQ proof's Monero-side commitments. | Mature, widely audited, the de facto standard (used by `monero-serai` itself, Signal, etc.). Lowest-risk dependency in this whole design. |
| [`secp256kfun`](https://github.com/LLFourn/secp256kfun) (+ its `sigma_fun` sub-crate) | secp256k1 arithmetic, ECDSA adaptor signatures, and the cross-group DLEQ proof ([DLEQ](#dleq)). | Actively maintained (pushed 2026-05-12, 112★), written by the DLEQ proof's original author. `0.7.x` — pre-1.0, API has moved before; vendor/pin a rev and re-verify against its test vectors each bump, same caution as `monero-serai`. |
| `divi-script`/`divi-primitives` (this repo) | P2SH redeem scripts, ECDSA sighash, tx (de)serialization for `Tx_lock`/`_cancel`/`_refund`/`_punish`/`_redeem`. | Already in-repo; reuse `crates/divi-swap/src/htlc.rs`'s `push_data`/`script_num` helpers for the multisig redeem script rather than re-deriving them. |
| ~~`farcaster_core`~~ | Would otherwise be the obvious "just depend on the whole protocol" pick — it implements swap deals, ECDSA adaptor sigs, and the cross-group DLEQ in one crate. | **Not recommended.** Last pushed 2023-04-10 (3.5 years stale as of this writing), 40★, LGPL-3.0 (copyleft — check compatibility with this repo's AGPL-3.0 before even considering it). Reading its source as a worked reference is still valuable; depending on it is not. |

No crate here is a drop-in "Bitcoin-Monero swap" library to just call — `monero-serai` +
`secp256kfun`/`sigma_fun` are the building blocks; the transaction templates, adaptor-signature
wiring, and timelock schedule in [Protocol](#protocol) are this design's own composition of them,
same as `eigenwallet/core` (the actively-maintained fork of COMIT's archived `xmr-btc-swap`,
pushed 2026-10-11, 312★) composes its own equivalents. `eigenwallet/core` is the best current
reference implementation to read against once building starts.

## Stagenet

Monero stagenet (not testnet — Monero's "testnet" is effectively unmaintained; stagenet is the
live, supported pre-production network) gives a free, no-faucet-needed environment: stagenet
"mining" is permissionless (unlike BTC signet), so a throwaway wallet can mine its own blocks for
spendable XMR rather than waiting on a faucet — sidesteps the exact CAPTCHA/faucet blocker that
parked the BTC lane's signet funding (`DECISIONS.md` #5).

- **Public stagenet nodes** (from `monero.fail/?chain=monero&network=stagenet`, checked
  2026-10-11 — verify liveness before use, public node sets rotate):
  `node.monerodevs.org:38089`, `node2.monerodevs.org:38089`, `node3.monerodevs.org:38089`,
  `stagenet.xmr-tw.org:38081`, `xmr-lux.boldsuck.org:38081`.
- **`monero-wallet-rpc`** (the JSON-RPC daemon this design's Rust backend would drive, analogous
  to how `swap-chain-btc` drives an Esplora endpoint) needs `--stagenet` and either a local
  `monerod --stagenet` or one of the public nodes above via `--daemon-address`. Multisig wallet
  flows (`prepare_multisig` / `make_multisig` / `exchange_multisig_keys`) are exposed over this
  same RPC — no separate tooling needed for the 2-of-2 Monero output in [Protocol](#protocol).
  No secrets involved in standing this up (throwaway stagenet wallets only), consistent with the
  "no secrets on hp2" rule.
- Monero confirmation depth is the dominant latency term versus DIVI: COMIT's own deployment used
  **10 confirmations** on the Monero leg (vs. 1–2 on the Bitcoin leg in the existing swap's
  profile); stagenet block time matches mainnet (~2 min), so a happy-path acceptance test's Monero
  leg alone is ~20 minutes wall-clock minimum — budget for this explicitly in test design rather
  than discovering it at CI timeout.

## Build plan

Staged so each step is independently testable before the next depends on it; none of this
touches `crates/divi-swap/src/{types,htlc,backend,state,config,error,api}.rs` (frozen contract)
except by filing a `- needs:` request if the engine's `ChainBackend` trait turns out not to fit
an account-less-but-multisig chain (plausible — flag it when reached, don't guess now).

1. **DIVI prerequisite** (done this lane, see commit): `baretxid` fix in `crates/divi-rpc`.
2. **Multisig redeem script + presigned-tx skeleton**, DIVI-side only, no Monero/adaptor yet:
   build `Tx_lock`/`Tx_cancel` P2SH 2-of-2 scripts and spends with two throwaway keys and plain
   (non-adaptor) signatures, prove the `nLockTime` schedule is enforced on a local/testnet DIVI
   node (mirrors `crates/swap-chain-btc/src/tx.rs`'s structure). *Acceptance:* `Tx_cancel`
   broadcast before `t_cancel` is rejected by the node; after, accepted.
3. **ECDSA adaptor signatures in isolation**: implement encrypt/decrypt/verify against
   `secp256kfun`, no DIVI or Monero involved yet. *Acceptance:* round-trip test — adaptor-sign,
   complete with the secret, verify the completed signature is a normal valid ECDSA signature over
   the DIVI sighash; and the inverse (extract the secret from a completed signature + its
   encrypted counterpart).
4. **Cross-group DLEQ in isolation**: wire `sigma_fun`'s proof, generate/verify a proof for a
   clamped `x`, derive the matching secp256k1 point and ed25519 scalar from the same `x`.
   *Acceptance:* proof verifies for a correctly-constructed witness; a tampered witness (bit
   flipped on one side only) is rejected.
5. **Monero 2-of-2 multisig on stagenet**: drive `monero-wallet-rpc`'s multisig RPCs end-to-end
   with two throwaway stagenet wallets, confirm a jointly-signed spend. *Acceptance:* XMR sent to
   the 2-of-2 output is spendable only with both shares' cooperation (mirrors Monero's own
   multisig test suite, just confirming this repo's RPC usage matches).
6. **Wire adaptor secret ↔ DLEQ ↔ Monero spend share**: step 3's secret is step 4's `x`, which is
   step 5's spend-key contribution. *Acceptance:* full key-material exchange produces a Monero
   multisig wallet whose missing spend-key share is exactly the secret step 3's adaptor signature
   will reveal.
7. **Full DIVI-side transaction set** (`Tx_refund`/`Tx_punish`/`Tx_redeem`) with adaptor
   signatures in place of the plain multisig signatures from step 2 where [Protocol](#protocol)
   calls for them. *Acceptance:* each of the three failure-case branches in
   [Protocol](#protocol#failure-cases) reproduced on a local/testnet DIVI node with throwaway keys.
8. **End-to-end happy path**, DIVI testnet + Monero stagenet, throwaway keys both sides.
   *Acceptance:* Maker's DIVI and Taker's XMR both move, `x` extracted from `Tx_redeem` and used to
   sweep the Monero output, matching [Protocol](#protocol)'s happy path step by step.
9. **Engine integration proposal**: write up how (or whether) this fits `ChainBackend` — likely
   "it doesn't, cleanly" given `ChainBackend::build_claim`/`build_refund` assume a single-key spend
   of a hash-locked output, not a multi-transaction presigned adaptor-signature dance with its own
   state machine (`Tx_lock → Tx_cancel → {Tx_refund | Tx_punish | Tx_redeem}` doesn't map onto
   `MakerLocked → MakerLockConfirmed → TakerClaimed`-style states 1:1). Flag this as a `- needs:`
   for the orchestrator rather than forcing a fit, same posture the plan already takes for
   USDC's account-based mismatch (`multi-coin.md`, wave 1c).

Steps 1–6 need no DIVI/Monero network coordination between parties and can run with mocks; 7–8 are
where real stagenet/testnet coordination (two throwaway identities, timed broadcasts) becomes
unavoidable. This lane produces the design and the prerequisite fix only — per `multi-coin.md`
wave 1d, steps 2+ are a later plan, not a deliverable of this turn.

## Risks

- **ECDSA adaptor signatures are the shakier primitive here, not Schnorr's clean security proof.**
  Unlike post-Taproot Schnorr adaptor signatures (simple, provably secure under standard
  assumptions), DIVI has no Schnorr (no SegWit, no Taproot — confirmed absent above), so this
  design is stuck with ECDSA adaptor signatures, which COMIT's own writeup describes as lacking as
  clean a security proof and explicitly calls "not audited or thoroughly reviewed" in their
  reference implementation. Residual risk carried forward, not solved by this design.
- **DIVI relative-timelock gap** ([DIVI scripts](#divi-scripts)) forces the presigned-nLockTime
  design in [Protocol](#protocol) rather than the more flexible CSV-gated single-output pattern
  some swap implementations use. Verified correct and sufficient, but it is less forgiving of
  schedule mistakes — every `t_cancel < t_refund < t_punish` ordering is fixed at setup with no
  script-level backstop if one party's clock assumptions are wrong (mitigate the same way the
  existing BTC/DIVI HTLC lane does: generous margins, `median_time_past` not wall clock).
- **Both maintained candidate crates (`monero-serai`, `secp256kfun`) are pre-1.0** and under
  active development, meaning API churn risk across the multi-stage build plan above; pin exact
  revs, don't float on a branch.
- **Monero confirmation depth dominates swap duration** (~20 min minimum on stagenet, worse on
  mainnet with the 10-confirmation target) — a much longer exposure window than the existing
  BTC/DIVI swap, during which Taker's locked XMR sits unclaimable-by-Maker and unrefundable-by-Taker
  simultaneously (by design — that's the atomicity), so operational tooling (monitoring, alerting
  on stalled swaps) matters more here than it does for the faster BTC leg.
- **farcaster_core's staleness is itself informative**: a reasonably well-specified protocol with a
  dedicated crate still went three-plus years without updates, suggesting either the problem is
  harder to keep maintained than it looks, or demand is thin, or both. Budget this lane's
  downstream build (steps 2–9) as a multi-week effort, not a quick wire-up, even with the crates in
  [Crates](#crates) doing the cryptographic heavy lifting.
- **No live-chain acceptance test exists yet** (this turn delivers design + the DIVI prerequisite
  only, per scope) — everything above is verified against the real DIVI source and the current
  crate ecosystem, but not yet against a running swap. Steps 7–8 of the build plan are where that
  verification actually happens.

## Recommendation

Build it, staged exactly as in [Build plan](#build-plan), using `monero-serai` for the Monero side
and `secp256kfun`/`sigma_fun` for the adaptor signatures and DLEQ proof — both are the most
actively maintained options and were each authored specifically for this problem. Treat
`farcaster_core` and `eigenwallet/core` as references to read, not dependencies to pull: the
former is stale, the latter is a full application (GUI, networking, its own state machine) that
would bring far more than this repo's `ChainBackend`-shaped engine needs. Do **not** depend on
DIVI relative timelocks (CSV/BIP68) anywhere — they do not exist on the live network regardless of
what `crates/divi-script` implements — the presigned-`nLockTime` transaction design in
[Protocol](#protocol) already avoids needing them and should stay that way even if CSV support
lands in a future Divi Core release. Treat the ECDSA-adaptor-signature security gap as an accepted,
inherited risk (same one every ECDSA-adaptor-based swap in production today carries), not something
this lane can close. The next lane to pick this up should start at build-plan step 2 (the DIVI-side
presigned multisig skeleton) since it needs no Monero or adaptor-signature machinery yet and gives
the earliest on-chain confidence signal.
