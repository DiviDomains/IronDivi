# C1 — Tx_cancel malleation: design of the fix (2026-10-14)

Status: **design, awaiting review. Not implemented.** Bert's rule (2026-10-14): a large protocol
change is written up and reviewed before code. This one is large: it changes `Tx_lock`'s script,
adds a two-party signing component, and changes the wire messages of steps 2 and 3. Mainnet stays
blocked (`xmr-mainnet-plan.md` C1) until this is implemented and passes the stagenet tests below.

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
  LOW_S, MINIMALDATA, NULLDUMMY, SIGPUSHONLY and CLEANSTACK are relay policy only. A staker can
  therefore put any of these in a block:
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

**Low-S checks and standard relay only.** These stop third-party relayers, not the two
counterparties (a fresh nonce is low-S) and not stakers (they mine non-standard transactions).

## 3. The two constraints any fix must meet

1. **Kill before reveal.** The redeem path must be dead on chain before any transaction that
   reveals `s_m` (refund) can confirm.
2. **No one can steer the kill transaction's txid alone.** Neither party, acting alone, can
   produce a valid kill transaction with a txid the presigned children do not cover. Staker
   variants must be either a finite set that the children are signed over, or harmless.

## 4. Proposed fix

### 4.1 Tx_lock

`Tx_lock`'s output becomes P2SH of a two-branch script:

```
OP_DEPTH <n> OP_EQUALVERIFY          # guard: exactly the expected number of stack items
OP_IF
    OP_2 <a> <b> OP_2 OP_CHECKMULTISIG                     # redeem (happy path), unchanged
OP_ELSE
    <t_cancel> OP_CHECKLOCKTIMEVERIFY OP_DROP <J> OP_CHECKSIG   # cancel
OP_ENDIF
```

- `J` is a joint key held 2-of-2 by maker and taker through two-party ECDSA (2P-ECDSA). Neither
  party knows its private key.
- The two parties run the 2P-ECDSA signing protocol **once**, at setup, on **one** message: the
  sighash of `Tx_cancel`. The protocol must make it impossible for either party to get a second
  signature under `J`.
- Result: there is exactly one valid signature `σ_J` (up to S-flip). Neither party can re-sign,
  because neither holds `J`'s key.

**The OP_DEPTH guard** closes the unbounded staker variants (extra pushes below the stack). The
remaining staker variants are a finite set:

- S-flip of `σ_J`: 2 variants.
- Push encodings of `σ_J`, the branch selector and the redeem script: PUSHDATA1/2/4 versus
  direct push, plus OP_0/OP_FALSE encodings of the selector. A small fixed number.

The exact count is computed in the implementation and pinned by a test.

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

**Mitigation:** add a third, maker-unilateral branch to `Tx_lock`:

```
<t_late> OP_CHECKLOCKTIMEVERIFY OP_DROP <A> OP_CHECKSIG     # t_late > t_punish + margin
```

This is safe for the taker. She locks XMR only after she sees the exact `lock_outpoint`
confirmed, and she is required to cancel, and punish if needed, before `t_late`. A taker who goes
offline past `t_late` loses her punish claim, which is the same failure mode as today's
`t_punish` deadline.

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
   under Divi's mandatory flags? Divi also has no MINIMALIF, so check `OP_IF` argument encodings.
2. Option (a) versus (b) in §4.1.
3. Is there a construction that meets both constraints of §3 without 2P-ECDSA on a chain with
   CLTV but no CSV and no segwit?
4. Is `t_late` sound against a taker who deliberately delays her XMR lock?
