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

**Corrected 2026-10-11** (consulted the `oracle` against the actual reference implementation,
`comit-network/xmr-btc-swap`'s `swap/src/protocol/{alice,bob}/state.rs`, after noticing this
section's table contradicted its own explanatory text): the original draft used a single shared
secret `x` for everything. The real construction needs **two** — one per party — and the
signer/completer roles below were wrong in three of the four presigned transactions. Fixed
throughout; `Tx_cancel` was the one row that was already right.

### Roles

- **Maker** quotes DIVI for XMR (symmetric to the existing BTC lane: Maker always holds the DIVI
  leg). **Taker** holds XMR and wants DIVI. Maps onto the literature's Bob (Maker, has
  Bitcoin/DIVI) and Alice (Taker, has Monero).
- Both legs lock into a 2-of-2 output, not just one. Neither party's on-chain lock is
  independently spendable; every subsequent transaction is pre-signed (or adaptor-presigned) by
  both parties before the corresponding lock confirms.
- The swap is symmetric by design: completing it hands Maker the XMR (combine `s_m` + the `s_t`
  he learns) and Taker the DIVI; aborting it hands Taker her XMR back (combine `s_t` + the `s_m`
  she learns) and Maker his DIVI back. Either way, whichever party's *DIVI-chain* action
  completes is what reveals the scalar the other party needs on the *Monero* chain — that
  coupling is the entire point of using adaptor signatures instead of a hashlock.

### Key material (setup, off-chain)

| Key | Curve | Purpose |
|---|---|---|
| `a` (Maker) / `b` (Taker) | secp256k1 | DIVI-side 2-of-2 multisig key, one per party |
| `v, s_m` (Maker) / `s_t` (Taker) | ed25519 | Monero spend-key shares — the output is a 2-of-2 shared spend key `S = s_m·G + s_t·G` (Monero native multisig, not a script); `v` is the (for now, simplified — see `## Stagenet`) shared view key |
| `s_t` doubles as an adaptor secret, point `X = s_t·G_secp` | both curves | lets Maker encrypt his `Tx_redeem` signature under `X`; only Taker (who holds `s_t`) can complete it |
| `s_m` doubles as a *second*, independent adaptor secret, point `Y = s_m·G_secp` | both curves | lets Taker encrypt her `Tx_refund` signature under `Y`; only Maker (who holds `s_m`) can complete it |

Each party's Monero spend-key share is *also* their DIVI-side adaptor secret for the transaction
that reveals it to the other party. **Two DLEQ proofs are needed, not one** (the original draft's
bug): Taker proves `s_t` is simultaneously the discrete log of `X` (secp256k1) and her ed25519
Monero share; Maker proves `s_m` is simultaneously the discrete log of `Y` and his ed25519 Monero
share. Without Maker's proof, Taker has no guarantee that completing `Tx_refund` actually hands
her a usable Monero scalar — the abort path would be unsafe for her without it.

### Transaction templates (DIVI side)

All four presigned transactions are built and exchanged as unsigned templates right after both
parties commit to the deal (before either leg locks), so every party knows the full shape — and
every timelock — before funds move:

| Tx | Spends | Pays | Signed by | Completed + broadcast by | Reveals | `nLockTime` |
|---|---|---|---|---|---|---|
| `Tx_lock` | Maker's coins | the 2-of-2 `{a,b}` output | Maker alone | Maker | nothing | none |
| `Tx_cancel` | `Tx_lock` | a fresh 2-of-2 `{a',b'}` output | both, plainly, no adaptor | either party | nothing | `t_cancel` |
| `Tx_redeem` | `Tx_lock`/`Tx_cancel` | Taker | Maker: adaptor-encrypted under `X`; Taker: plain | **Taker** (decrypts with `s_t`) | `s_t`, to Maker | none |
| `Tx_refund` | `Tx_cancel` | Maker | Taker: adaptor-encrypted under `Y`; Maker: plain | **Maker** (decrypts with `s_m`) | `s_m`, to Taker | `t_refund` (≥ `t_cancel`) |
| `Tx_punish` | `Tx_cancel` | **Taker** | both, plainly, no adaptor (Maker signs at setup, Taker holds it) | **Taker** | nothing | `t_punish` (≥ `t_refund` + margin) |

Why each one is shaped this way:

- **`Tx_cancel`** just moves the lock to a fresh 2-of-2 so it has an escape hatch — `Tx_lock`'s
  own output doesn't need one since it's never spent by anything *except* `Tx_cancel`.
- **`Tx_redeem`** is the happy path: Taker wants this to go through (it pays her the DIVI), so
  *she* is the one who completes Maker's encrypted signature (she already holds the decryption
  key `s_t`) and broadcasts. Maker, watching the chain, now has both the encrypted and completed
  versions of his own signature and recovers `s_t` — letting him combine it with his own `s_m`
  to take the Monero. This is the step that actually completes the swap in both directions.
- **`Tx_refund`** is the mirror image, for abort: Maker wants his DIVI back, so *he* completes
  Taker's encrypted signature (he holds `s_m`) and broadcasts. Taker, watching the chain, recovers
  `s_m` and combines it with her own `s_t` to reclaim her *own* locked XMR — without this, if
  Maker could reclaim his DIVI with a plain signature, Taker's Monero would be permanently
  stranded in the 2-of-2 output with no way for her to recover it alone.
- **`Tx_punish`** needs no adaptor at all: it's a plain presigned transaction, signed by Maker at
  setup and held by Taker, that pays *everything* to Taker if Maker locks DIVI, Taker locks XMR,
  and Maker then goes silent (never completes `Tx_redeem`, never lets `Tx_refund` resolve things
  either). Taker seizes Maker's DIVI as compensation; her own XMR stays stuck (she never learns
  `s_m` in this branch, since nothing reveals it) — the real cost that falls on Maker for
  stalling after both sides have committed, deterring exactly that behavior.

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

1. Exchange key material + **both** DLEQ proofs (Taker proves `s_t`↔`X`; Maker proves `s_m`↔`Y`).
   Build and exchange unsigned `Tx_cancel`/`_refund`/`_punish`/`_redeem` templates; both sign the
   plain halves (`Tx_cancel` fully, plus each party's plain half of `_refund`/`_redeem`, plus
   Maker's plain signature for `Tx_punish` handed to Taker); Maker produces the adaptor-encrypted
   half of `Tx_redeem` keyed to `X`; Taker produces the adaptor-encrypted half of `Tx_refund`
   keyed to `Y`.
2. Maker broadcasts `Tx_lock` (DIVI). Taker waits for confirmations, then locks the matching XMR
   amount into the 2-of-2 Monero output (public key `S = s_m·G + s_t·G`, known to both from step
   1's DLEQ proofs).
3. Taker, once the Monero lock has enough confirmations (Monero stagenet/mainnet wants far more
   than DIVI — 10 confirmations is the figure COMIT/xmr-btc-swap ships with, vs. DIVI's existing
   1–6; see [Build plan](#build-plan)), **completes** Maker's adaptor-encrypted signature on
   `Tx_redeem` using her own `s_t` and broadcasts it — claiming the DIVI.
4. Maker observes the completed `Tx_redeem` on-chain, recovers `s_t` from the gap between the
   adaptor-encrypted and completed ECDSA signatures (standard adaptor-signature decryption), and
   combines it with his own `s_m` to spend the full Monero output.

### Failure cases

- **Taker never locks XMR** (step 2 never happens): after `t_cancel`, either party broadcasts
  `Tx_cancel`; after `t_refund`, Maker completes Taker's adaptor-encrypted signature on
  `Tx_refund` (using his own `s_m`) and broadcasts it to get his DIVI back. This reveals `s_m` to
  Taker, but she has nothing locked yet, so it's inert — no harm, just an unused side effect of
  reusing the same transaction shape regardless of how early the abort happens.
- **Maker locks DIVI, Taker locks XMR, Maker then stalls** (never does step 3, nor does he ever
  let `Tx_refund` resolve): after `t_punish`, Taker broadcasts the plain, pre-signed `Tx_punish`,
  taking all of the cancelled DIVI. No secret moves; her own XMR stays locked forever in this
  branch (she never learns `s_m`) — the deterrent cost that falls on Maker, not her, for stalling.
- **Maker locks DIVI, Taker locks XMR, then Maker broadcasts `Tx_refund` instead of completing
  `Tx_redeem`** (he changes his mind after Taker already committed): Taker recovers `s_m` from
  the chain, combines it with her own `s_t`, and reclaims her own XMR herself — she isn't left
  stranded by Maker backing out, since this is exactly the mechanism `Tx_refund`'s adaptor
  encryption exists for.
- **Taker completes `Tx_redeem` but Maker is offline / can't recover `s_t` in time**: no new
  risk — `s_t` is sitting in a public, permanent DIVI transaction; Maker (or anyone who archived
  that txid) can recover it and spend the Monero output at any later time, as long as the Monero
  output itself hasn't separately timed out (Monero multisig outputs have no on-chain timelock of
  their own, so this risk is bounded only by how long Maker is willing to wait — a liveness, not
  a safety, concern). Same reasoning applies symmetrically to Maker completing `Tx_refund` and
  Taker being slow to recover `s_m`.
- **Monero chain reorg / 51%-style deep reorg after Taker locks XMR but before Maker's DIVI-side
  `t_punish`**: out of scope for this design (Monero gives no finality guarantee beyond
  confirmation count; COMIT's own writeup treats this as accepted residual risk, mitigated only
  by confirmation count, same as every Monero application).
- **A party reveals their own secret some other way (coerced, leaked) before the other party has
  locked anything of theirs against it**: the DLEQ proofs only bind each secret to its public
  points, they don't protect the secret once known by other means; with nothing locked yet
  there's nothing to steal. Not a protocol failure.

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

**Two instances of the same proof run, one per party** (`## Protocol`'s fix — the original draft
only had Taker's half): Taker picks scalar `s_t`, Maker picks scalar `s_m`; each must be a valid
secp256k1 private key (order `n ≈ 2^256 − 4.3×10^38`) **and** a valid ed25519 private key
component (order `ℓ ≈ 2^252 + δ`, `δ` small). Taker reveals `X = s_t·G_secp256k1` to Maker (the
point `Tx_redeem`'s adaptor signature is encrypted under) and uses `s_t` as her Monero spend-key
share, so the ed25519 point `s_t·G_ed25519` folds into the shared spend public key `S`. Maker
reveals `Y = s_m·G_secp256k1` to Taker (the point `Tx_refund`'s adaptor signature is encrypted
under) and uses `s_m` as his Monero spend-key share, folding `s_m·G_ed25519` into the same `S`.
Each party must be convinced the *other's* revealed point and Monero-side share commit to the
same secret **without learning that secret** — otherwise completing the corresponding adaptor
signature (`Tx_redeem` for Maker, `Tx_refund` for Taker) wouldn't be guaranteed to hand the
completer a usable Monero scalar. Skipping Maker's proof (as the original draft did) leaves the
abort path (`Tx_refund`) unsafe for Taker specifically — she'd have no guarantee `Y` corresponds
to anything she could actually use to recover her XMR.

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
- **Two viable paths for the 2-of-2 Monero output, not one** (corrected after reading
  `monero-wallet`'s actual docs — checked 2026-10-11): (a) **`monero-wallet-rpc`** (the JSON-RPC
  daemon this design's Rust backend would otherwise drive, analogous to how `swap-chain-btc`
  drives an Esplora endpoint) exposes Monero's own interactive multisig flow
  (`prepare_multisig` / `make_multisig` / `exchange_multisig_keys`), needs `--stagenet` and
  either a local `monerod --stagenet` or one of the public nodes above via `--daemon-address`,
  and produces an output any standard Monero wallet could eventually co-sign; or (b)
  `monero-wallet`'s own `multisig` feature uses a **different, FROST-based 2-of-2** (faster,
  single Rust dependency, no RPC round-trips for key exchange) — but the result is only
  spendable by software speaking that same FROST protocol, which is fine here since both swap
  parties already run this codebase. (b) is the simpler build; still needs a stagenet
  `monerod`/`monero-wallet-rpc` reachable for broadcast and output scanning either way. Decide
  between them at build-plan step 5, not before — both satisfy [Protocol](#protocol) identically.
  No secrets involved in standing either up (throwaway stagenet wallets only), consistent with
  the "no secrets on hp2" rule.
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
5. **Monero 2-of-2 multisig on stagenet**: pick one of the two paths in [Stagenet](#stagenet)
   (default to `monero-wallet`'s native FROST multisig unless interop with stock Monero wallets
   turns out to matter) and drive it end-to-end with two throwaway stagenet wallets, confirm a
   jointly-signed spend. *Acceptance:* XMR sent to the 2-of-2 output is spendable only with both
   shares' cooperation.
6. **Wire adaptor secret ↔ DLEQ ↔ Monero spend share**: done, `crates/swap-chain-xmr/src/
   monero_key_share.rs`. Note the correction in `## Protocol`/`## DLEQ`: this runs **twice**,
   once per party, via additive `Interpolation::Constant` 2-of-2 keys (not step 5's PedPoP/FROST
   path — that produces Lagrange-aggregated shares, which can't be made to equal a pre-chosen
   DLEQ secret; see the module's doc comment for the full reasoning). *Acceptance:* each party's
   DLEQ secret becomes their literal Monero key share (not a derived aggregate) and both converge
   on the same additive group key — done, tested.
7. **Full DIVI-side transaction set** (`Tx_redeem`/`Tx_refund`/`Tx_punish`) with adaptor
   signatures in place of the plain multisig signatures from step 2 where [Protocol](#protocol)
   calls for them — per the correction above, `Tx_redeem` carries *Maker's* adaptor signature
   (encrypted under Taker's `X`, completed by Taker), `Tx_refund` carries *Taker's* (encrypted
   under Maker's `Y`, completed by Maker), and `Tx_punish` needs no adaptor at all (plain,
   Maker-signed-at-setup, Taker-held). *Acceptance:* each of the failure-case branches in
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
