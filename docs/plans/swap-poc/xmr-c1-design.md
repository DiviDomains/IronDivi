# C1 — Tx_cancel malleation: design of the fix (2026-10-14)

Status: **reviewed 2026-10-15, Bert chose option A (see Ruling below). Built, gaps in §9 being closed.** Original status: design, awaiting review. Bert's rule (2026-10-14): a large protocol
change is written up and reviewed before code. This one is large: it changes `Tx_lock`'s script,
adds a two-party signing component, and changes the wire messages of steps 2 and 3. Mainnet stays
blocked (`xmr-mainnet-plan.md` C1) until this is implemented and passes the stagenet tests below.

## Ruling (Bert, 2026-10-15): option A, the full C1 fix

Bert reviewed this document and chose **option A, the full C1 fix**. The A spec, as ruled:
1. the interim hardening (§4.4) lands first;
2. the joint cancel key J uses **Lindell-2017 2P-ECDSA**;
3. presign is **exhaustive across all 120 staker variants** of `Tx_cancel` (§4.1).

What is built (`61ca99a`, maker binary sha256 `929c9b54…` = `1841a12`) is compared against this spec in
§9 (gap analysis). The gaps get closed. **Mainnet stays blocked until the new build passes stagenet.**

## 1. The flaw

`Tx_refund` and `Tx_punish` spend the *signed* `Tx_cancel` by txid (`crates/divi-swap-xmr/src/api.rs:120-144`).
DIVI has no segwit, so that txid covers the scriptSig. Anyone who can produce a different valid
scriptSig for `Tx_cancel` gives it a new txid. Both presigned children are then invalid, and the
coins sit in the `{a', b'}` 2-of-2, which neither side can spend alone.

Who can do it:

- **The taker.** She holds `maker_cancel_sig` from step 2 and her own key `b`. She can re-sign
  her half with a fresh nonce.
- **The maker.** He holds `taker_cancel_sig` from step 3 and his own key `a`. He can do the same.
- **Any staker.** This is anyone with coins on a PoS chain, so it is not a narrow set. Real Divi's
  consensus flags are P2SH | DERSIG | REQUIRE_COINSTAKE, plus CLTV once the Aug-2023 fork is
  active (`divi-cpp-ref/divi/src/script/standard.h`, `BlockTransactionChecker.cpp:117-121`).
  MINIMALDATA, NULLDUMMY, SIGPUSHONLY and CLEANSTACK are relay policy only, and LOW_S is not
  even that: Divi 3.0.0's `STANDARD_SCRIPT_VERIFY_FLAGS` omit it, so a high-S signature relays
  like any other (proved on regtest 2026-10-15, `c1-regtest-results.md` tests 5a and 7). Any
  relay node can therefore S-flip a signature, and a staker can put any of these in a block:
  - an S-flip of either signature;
  - non-minimal push opcodes;
  - any value as the CHECKMULTISIG dummy element (unbounded);
  - extra items pushed below the stack (unbounded).

Whoever malleates gains leverage, not the coins directly.

- **Maker malleates:** he makes the taker's punish impossible. If he also stops before
  redeeming, her XMR is locked forever under `S_m + S_t`. She cannot get it back without `s_m`.
- **Taker malleates:** she makes the maker's refund impossible and punish impossible too. Then
  she can ransom him. Worse, in combination with a working punish in some variants, she turns an
  aborted trade into a free option on the price.

`xmr-design.md` §Risks described malleability as miner-only and liveness-only. It is neither.

## 2. What does not work

**Dropping Tx_cancel (refund and punish spend Tx_lock directly).** This is refuted. `Tx_refund`
reveals `s_m` the moment it is in the mempool. If `Tx_redeem` is still valid at that point, the
taker reads `s_m`, sweeps the XMR, and double-spends the refund with redeem. She ends up with
both coins. `Tx_cancel` exists to **kill the redeem path before anything is revealed**. The
rationale in `xmr-design.md` ("escape hatch") understated this and is corrected.

**Low-S checks and standard relay only.** On Divi these do not even stop third-party relayers:
LOW_S is not a standard flag there (2026-10-15 regtest finding), so any node can S-flip. They
would not stop the two counterparties (a fresh nonce is low-S) or stakers (they mine non-standard
transactions) in any case.

## 3. The two constraints any fix must meet

1. **Kill before reveal.** The redeem path must be dead on chain before any transaction that
   reveals `s_m` (refund) can confirm.
2. **No one can steer the kill transaction's txid alone.** Neither party, acting alone, can
   produce a valid kill transaction with a txid the presigned children do not cover. Staker
   variants must be either a finite set that the children are signed over, or harmless.

## 4. Proposed fix

### 4.1 Tx_lock

`Tx_lock`'s output becomes P2SH of a three-branch script (the `t_late` branch is §4.3):

```
OP_DUP OP_1 OP_EQUAL
OP_IF                                                       # selector bytes exactly [0x01]
    OP_DROP OP_2 <a> <b> OP_2 OP_CHECKMULTISIG              # redeem (happy path)
OP_ELSE
    OP_DUP OP_2 OP_EQUAL
    OP_IF                                                   # selector bytes exactly [0x02]
        OP_DROP OP_DEPTH OP_1 OP_EQUALVERIFY                # guard: only σ_J left
        <t_cancel> OP_CHECKLOCKTIMEVERIFY OP_DROP <J> OP_CHECKSIG   # cancel
    OP_ELSE
        OP_3 OP_EQUALVERIFY                                 # selector bytes exactly [0x03]
        <t_late> OP_CHECKLOCKTIMEVERIFY OP_DROP <A> OP_CHECKSIG     # maker escape (§4.3)
    OP_ENDIF
OP_ENDIF
```

Why the selectors are `OP_EQUAL` tests, not bare `OP_IF`: Divi has no MINIMALIF, so a bare
`OP_IF` accepts infinitely many encodings of true *and* of false (any all-zero byte string, or
one ending in 0x80, is false). `OP_EQUAL` compares exact bytes, so the cancel selector `[0x02]`
has exactly five encodings (`OP_2`, a 1-byte direct push, `PUSHDATA1/2/4`).

Why only the cancel branch has a depth guard: nothing is presigned against `Tx_redeem`'s txid
or the `t_late` spend's txid, so their variants (including CHECKMULTISIG's unbounded dummy
element) are harmless. The cancel branch uses `OP_CHECKSIG`, which has no dummy element.

P2SH scriptSigs must be push-only even without SIGPUSHONLY (`interpreter.cpp`, the P2SH block
of `VerifyScript`), so no `OP_NOP`s or computed values can be inserted.

- `J` is a joint key held 2-of-2 by maker and taker through two-party ECDSA (2P-ECDSA). Neither
  party knows its private key.
- The two parties run the 2P-ECDSA signing protocol **once**, at setup, on **one** message: the
  sighash of `Tx_cancel`. The protocol must make it impossible for either party to get a second
  signature under `J`.
- Result: there is exactly one valid signature `σ_J` (up to S-flip). Neither party can re-sign,
  because neither holds `J`'s key.

**The OP_DEPTH guard** closes the unbounded staker variants (extra pushes below the stack). The
remaining staker variants of `Tx_cancel`'s scriptSig `<σ_J> <0x02> <redeem script>` are a finite
set, by our count:

- `σ_J`: S-flip (2) × push encoding (direct, `PUSHDATA1/2/4`: 4) = 8.
- selector `[0x02]`: 5 encodings.
- redeem script (> 75 bytes): `PUSHDATA1/2/4` = 3.

That is 8 × 5 × 3 = 120 variants. The implementation computes the set and a test pins it.

Two ways to deal with this finite set; the review should pick one:

- **(a) Presign the children over every variant.** For each variant of `Tx_cancel`, the taker
  gives an adaptor-encrypted `Tx_refund` signature and the maker gives a `Tx_punish`
  signature. This is the cost of a few dozen extra signatures in step 3.
- **(b) Make the variants harmless with a unilateral punish branch (§4.2) and a refund that
  needs no presignature.** This alternative is not yet worked out and is listed for the
  reviewer.

With (a), whichever variant of `Tx_cancel` confirms, both parties already hold a matching child.

### 4.2 Tx_cancel's output: a unilateral punish branch

```
OP_IF
    OP_2 <a'> <b'> OP_2 OP_CHECKMULTISIG                   # refund (adaptor, as today)
OP_ELSE
    <t_punish> OP_CHECKLOCKTIMEVERIFY OP_DROP <B> OP_CHECKSIG   # punish: taker alone
OP_ENDIF
```

Punish no longer needs a maker presignature. The taker signs it herself, after the fact, against
whatever `Tx_cancel` txid actually confirmed. This removes punish from the malleation problem
entirely. Refund still needs the taker's adaptor signature, which is why §4.1 is needed.

### 4.3 Second finding: staker malleation of Tx_lock itself

The presigned `Tx_cancel` spends `Tx_lock` by txid, and it is built before `Tx_lock` confirms.
`Tx_lock`'s inputs are the maker's P2PKH coins, which are malleable by any staker. SIGPUSHONLY is
not mandatory, so OP_NOPs give unboundedly many variants. If `Tx_lock` confirms with a different
txid:

- The taker never locks XMR. She waits for the expected `lock_outpoint` to confirm
  (`taker.rs:513-524`). So she loses nothing.
- The maker's DIVI is in the `{a, b}` 2-of-2 with no valid `Tx_cancel`. The taker can ransom it.

**Mitigation:** the third, maker-unilateral branch of `Tx_lock` in §4.1, with
`t_late > t_punish + margin`.

This is safe for a taker who is online. She locks XMR only after she sees the exact
`lock_outpoint` confirmed, and she can broadcast `Tx_cancel` herself from `t_cancel` on. The
worst case for an offline taker is real loss, not just a lost punish claim: if she is offline
from `t_cancel` through `t_late` and the maker never broadcasts `Tx_cancel`, the maker takes the
DIVI through the `t_late` branch without revealing `s_m`, and her XMR stays locked forever.
`t_late − t_cancel` is her defensive window and must be sized like today's `t_punish` margin
(and watched by swap-watch).

The maker also detects a malleated `Tx_lock` on confirmation and aborts before step 4.

### 4.4 Interim hardening (no new cryptography)

If 2P-ECDSA takes too long, there is a smaller step:

- Add the unilateral punish branch (§4.2).
- The maker **withholds `maker_cancel_sig`** in step 2. He sends it, or broadcasts `Tx_cancel`
  himself, only after `t_cancel`.

Effect:

- **Maker-side malleation is fully closed.** Punish is unilateral, so a maker-malleated
  `Tx_cancel` still lets the taker punish.
- **Taker-side malleation is narrowed but not closed.** Once `maker_cancel_sig` is public, the
  taker can still re-sign her half and race the maker's broadcast. She wins that race only if she
  stakes the block or bribes a staker. If she wins, the maker's refund is dead and she punishes:
  the free price option of §1.
- Staker malleation is unchanged.

This narrows the risk but does not close it. Whether to ship it first is Bert's decision. It does
not unblock mainnet on its own.

## 5. Requirements for the 2P-ECDSA component (no crate chosen)

- 2-of-2 ECDSA on secp256k1, producing a standard DER signature that DIVI's `OP_CHECKSIG` accepts.
- Secure against a malicious counterparty, for both key generation and signing.
- **At most one signature per key.** The key `J` is per swap. The signing session takes exactly
  one message. No API that can produce a second signature may exist.
- Coexists with the secp256kfun adaptor-signature construction used for redeem and refund, and
  with the cross-curve DLEQ. They use separate keys; no shared nonces.
- Bounded rounds that fit into the existing steps 1-3 of the HTTP protocol, or adds at most one
  round.
- Audited or widely used, with a license compatible with AGPL-3.0.
- An abort mid-signing leaves no usable partial signature for either side. Before `σ_J` exists,
  the maker has not broadcast `Tx_lock`, so an abort costs nothing.

Candidate families to evaluate (not chosen): Lindell 2017 2P-ECDSA, Doerner et al. (OT-based),
and Castagnos-Laguillaumie-based class-group variants. Picking one is part of the review.

## 6. Wire and engine changes (sketch)

- Step 1/2: add the 2P-ECDSA key generation for `J`, plus maker `A` and taker `B` unilateral keys.
- Step 2: no `maker_cancel_sig`. Instead, the 2P-ECDSA signing of `Tx_cancel` runs.
- Step 3: the taker sends refund adaptor signatures for every `Tx_cancel` variant (option (a)).
  No `Tx_punish` presignature is needed in either direction.
- `maker.rs:745-764` (treats any non-matching spender of the lock as `Tx_redeem`) must instead
  match the spender's scriptSig branch: redeem, cancel or late.
- `taker.rs:458-477` must accept whichever `Tx_cancel` variant confirmed and pick the matching
  child.
- A `maker_punish_sig` disappears from `XmrSwapView`.

## 7. Stagenet test plan for the fix

All on stagenet and DIVI testnet, test coins only.

1. **Happy path:** ≥ 5 swaps redeemed.
2. **Accept-only abort:** maker locks, taker never locks XMR. The maker refunds via `Tx_cancel`
   → `Tx_refund`.
3. **Lock-only abort:** both lock, nobody redeems. Cancel, then refund.
4. **Punish:** both lock, maker cancels but never refunds. The taker punishes unilaterally after
   `t_punish`.
5. **Malleated Tx_cancel:** broadcast a deliberately malleated `Tx_cancel` (S-flip, and a
   non-minimal push), mined by our own testnet staker. Prove the matching child still confirms.
6. **Counterparty re-sign attempt:** a test harness tries to produce a second `σ_J`. It must fail
   at the API.
7. **Malleated Tx_lock:** confirm a malleated `Tx_lock` on testnet. The taker never locks XMR,
   and the maker recovers via the `t_late` branch.
8. **Unit tests:** pin the variant count of §4.1, and check that a script with an extra stack
   item fails the OP_DEPTH guard.

## 8. Open questions for the reviewer

1. Is the OP_DEPTH guard plus the push-encoding list really the complete staker variant set
   under Divi's mandatory flags (our count: 120, §4.1)? Check the `OP_EQUAL` selector scheme
   that replaces bare `OP_IF` selectors, since Divi has no MINIMALIF.
2. Option (a) versus (b) in §4.1.
3. Is there a construction that meets both constraints of §3 without 2P-ECDSA on a chain with
   CLTV but no CSV and no segwit?
4. Is `t_late` sound against a taker who deliberately delays her XMR lock?

## 9. Gap analysis: built (`61ca99a`, maker sha256 `929c9b54…`) versus option A (2026-10-15)

Option A, as ruled: interim hardening first, Lindell-2017 2P-ECDSA for `J`, exhaustive presign
over all 120 staker variants. What is built and live on the stagenet maker is §4.1–4.3 with option
(a), `J` from cggmp21. Gap by gap:

**G1. Interim hardening (§4.4) first: subsumed, no separate build.** An earlier controller order
said not to build interim-only, so it never shipped as its own step. Its two parts:
- The unilateral punish branch (§4.2) is built and passed live (§7 test 4, `c1-punish-results.md`).
- "The maker withholds `maker_cancel_sig`" is superseded. That signature no longer exists, because
  `Tx_cancel` is signed only by `J`.

Withholding `σ_J` instead would hurt the taker. Without it she cannot broadcast `Tx_cancel` from
`t_cancel` on, which is her defence in §4.3. `σ_J`'s own variants are covered by G3 instead. No
code change. Bert can overrule this and ask for the interim build as its own step.

**G2. `J` uses cggmp21, not Lindell 2017: CLOSED in code (2026-10-15), stagenet rerun pending.**
`crates/divi-swap-xmr/src/jsig.rs` is now Lindell 2017 (malicious-secure with abort), wire scheme
`lindell17-v1`. The maker is P1 (holds the Paillier key and `x1`), the taker is P2 (holds `x2`), and
`J = x1·x2·G`.

**Why not ZenGo `multi-party-ecdsa` 0.8.1.** That crate was the first candidate. We dropped it for
three reasons:
- Its `curv-kzen` 0.9 dependency no longer compiles on current Rust (`div_ceil` clash).
- Its PDL proof is unsound against its prover. In `party_one::pdl_proof` the prover generates its
  own `(Ñ, h1, h2)`, so it knows `log_{h1} h2`. A malicious P1 could encrypt something other than
  `x1` and read P2's share out of the one decryption in signing.
- The response `s1` of its PDL-with-slack proof is unbounded, and the proof's fields are private,
  so our wrapper could neither check the bound nor rebuild the proof against a verifier-chosen `Ñ`.

**What we built instead.** It uses the audited primitives `cggmp21 =0.6.3` already pulls in:
`fast-paillier`, `paillier-zk` (Kudelski-audited along with cggmp21) and `generic-ec`. Hashing is
SHA-256, and every Fiat–Shamir challenge and commitment is bound to the session id and its own tag.

| Msg | From | Content |
|---|---|---|
| T1 | taker | Ring-Pedersen `Ñ = p̃q̃`, `t = r²`, `s = t^λ`, and Πprm (128 rounds, s ∈ ⟨t⟩). The taker then drops `p̃, q̃, λ`. |
| M1 | maker | `com(Q1, pok(x1), nonce)` |
| T2 | taker | `Q2`, Schnorr `pok(x2)` |
| M2 | maker | Opens `Q1`. Sends `N0`, `c_key = Enc(x1)`, Πmod(N0) (Paillier–Blum), Πfac(N0) (no small factor), and Πlog\*(`c_key` encrypts `log_G Q1`, in range). Πfac and Πlog\* are proved against the **taker's** `Ñ`. |
| M3 | maker | `com(m, R1, pok(k1), nonce)`. This commits to the sighash too. |
| T3 | taker | `R2`, `pok(k2)` |
| M4 | maker | Opens `R1`. |
| T4 | taker | `c3 = Enc(ρq + k2⁻¹m) ⊕ (k2⁻¹·r·x2) ⊙ c_key` |
| M5 | maker | `σ = (r, k1⁻¹·Dec(c3))`, low-S, checked under `J`. The taker checks it under `J` again. |

How this closes the two soundness holes:
- **Prover-chosen `Ñ`.** The taker, who verifies the proofs, generates `Ñ` and proves it with Πprm.
  So no proof is ever checked against parameters only the prover chose. This is the GG18/CGGMP
  pattern.
- **Mask width.** Πlog\* bounds the plaintext `x1′` of `c_key` to `|x1′| < 2^{ℓ+ε} = 2^486`, with
  `x1′ ≡ x1 (mod q)`. In `c3`, `v·x1′` therefore carries an unknown multiple of `q`, at most
  `2^{256+486}`. That multiple is what a cheating maker could read. `ρ` is uniform in
  `[0, 2^822)`, where 822 = ℓ + ε + 256 + 80. So `ρq` hides it with statistical distance at most
  `2^{487−822} = 2^−335`. The plaintext stays below `2^1079`, far below `N0/2` (N0 ≥ 3071 bits).

**Checks before `J` is accepted.**
- Moduli are odd and 3071–4096 bits.
- `s` and `t` are units, not 1.
- Commitment openings, Schnorr proofs, and Πprm, Πmod, Πfac and Πlog\* on the exact wire values.
- No point is the identity, and `J ≠ 0`.

**One signature per key.** Every transition moves the secrets out of the old state. Any error, or
the signature itself, leaves the session `Done`, and there is no re-sign API. A second `M3` aborts.
Lindell's rule "P1 aborts forever after a failed signature" therefore holds trivially.

**Signing order.** Only the maker (P1) computes `σ_J`. It sends `σ_J` to the taker in M5, and the
taker verifies it against `J` and the sighash. The 120 refund encsigs and the `Tx_lock` broadcast
follow, as before. An abort before `Tx_lock` still costs nothing.

**Wire.**
- `SetupRequest.j_scheme = "lindell17-v1"`. A cggmp21-era taker sends no scheme, and the maker
  refuses it cleanly at setup.
- The maker caches its last `j` reply and answers an identical retry with it (G4 iii).

**Primes.** Both moduli still need safe primes (Πmod wants a Blum modulus), so the maker's prime
pool stays. G4 (vi) is corrected accordingly.

**Tests.** There are 7 `jsig` unit tests:
- the two-party happy path in both message orders;
- a bad Πprm, a tampered `c_key`, a bad `Q1` opening;
- a sighash mismatch caught by the commitment, a tampered `c3`, a tampered `σ`;
- out-of-order and second-`M3` aborts.

The engine also has `a_retried_j_round_gets_the_same_reply`, which covers the retry cache and the
scheme gate. All divi-swap-xmr tests pass on hp2.

**G3. Exhaustive presign over 120 variants: built.** We checked four things:
- (a) `cancel_variants` makes S-flip × 4 signature pushes × 5 selector encodings × 3
  redeem-script pushes, and `cancel_variants_are_exactly_120` pins the count.
  `cancel_branch_rejects_extra_pushes` is test 8's OP_DEPTH half.
- (b) The maker verifies all 120 encrypted `Tx_refund` signatures, matched by txid, before it
  broadcasts `Tx_lock` (`maker.rs` ~817-856). The taker computes the same set.
- (c) Answer to §8 Q1: DERSIG is consensus on Divi, so `r` and `s` have one encoding each, and
  ECDSA's only re-signing-free variant is the S-flip. The hashtype byte is hashed into the
  sighash, so it cannot change. P2SH forces a push-only scriptSig. The OP_DEPTH guard fixes the
  item count. That makes the set complete.
- (d) With Lindell, `σ_J` comes out low-S (`min(s, q−s)`), so the variant set is unchanged.

No gap.

**G4. Outside the A spec. These are listed here; only (iii) is closed now:**
- (i) §7 tests 5 and 7 ran on a private Divi 3.0.0 regtest, not on testnet with our own staker.
- (ii) Pre-C1 records are not readable.
- (iii) A retried `j` message (a lost HTTP reply) breaks keying. **Closed with G2:** the maker
  replays its last reply to an identical retry.
- (iv) A maker restart mid-keying aborts that swap. That costs nothing, because it happens before
  `Tx_lock`.
- (v) The malleated-`Tx_lock` path still scans under the swap lock while `tick` is sequential.
- (vi) C3's pool drain: both Paillier moduli are still safe-prime products, so the maker's pool
  stays. Pool drain under load gets re-measured on stagenet.

**Exit:** the Lindell build passes the unit tests (6, 8), is deployed to the stagenet maker, and
§7 tests 1–4 and 6 pass live again. Mainnet stays blocked until then.
