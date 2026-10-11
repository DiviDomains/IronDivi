# USDC (EVM account chain) — fitting the swap engine

Lane `usdc`, wave 1c (`docs/plans/swap-poc/multi-coin.md`). Delivers: the contract
(`contracts/htlc/src/Erc20Htlc.sol`), its client (`crates/swap-chain-evm`), and this proposal
for how an account-based chain fits (or doesn't) `divi_swap::ChainBackend`. The orchestrator
decides between the two options below before wave 2 wires `swap-chain-evm` into `divi-swapd`.

## The contract

`Erc20Htlc` (one deployment serves every swap, like the UTXO chains' one redeem-script
template): `lock(token, amount, receiver, hashlock, timelock) -> id` escrows `amount` of
`token` from the caller, `id = keccak256(abi.encode(sender, receiver, token, amount, hashlock,
timelock))`. `claim(id, preimage)` pays `receiver` if `sha256(preimage) == hashlock`.
`refund(id)` pays `sender` back once `block.timestamp >= timelock`. Same hashlock function
(SHA-256 over a 32-byte preimage) and the same claim/refund split as the UTXO HTLCs in
`divi_swap::htlc`, so a preimage generated for one leg of a swap works unchanged on the other.

No owner, no upgrade path, no fee. State is written before the external token transfer in
every path (checks-effects-interactions), so a malicious or reentrant ERC-20 cannot double
spend an escrow. `SafeTransfer` (a ~10-line local library, not a pinned framework) tolerates
tokens that return no value on success (USDT-style) while still reverting on an explicit
`false` or a revert.

## Why `ChainBackend` does not fit directly

`ChainBackend` (`crates/divi-swap/src/backend.rs`) is shaped around UTXOs: `build_funding`
does coin selection and returns one `Funding { tx, outpoint, amount }`; `htlc_output` reads
one output's scriptPubKey and value; `find_spend` scans blocks for a transaction that spends
a given `Outpoint` and recovers the preimage from scriptSig/witness pushes. An account chain
has none of UTXOs, scriptPubKeys, or witnesses — it has one mutable `swaps` mapping and events.

Three mismatches, in increasing order of how much they actually matter:

1. **No coin selection.** `build_funding`'s job on BTC/DIVI is choosing inputs; on EVM there's
   nothing to choose — the amount is exact and the only question is "is the balance (and,
   separately, the allowance) enough". Not a real mismatch, just a no-op coin selector.

2. **No scriptSig/witness, but the preimage is still recoverable generically.**
   `SpendInfo::extract_preimage` does not know anything about Bitcoin script — it just scans
   the `witness` and `script_sig` byte arrays for a 32-byte string whose SHA-256 matches the
   hashlock (`crates/divi-swap/src/types.rs:201`). A `Claimed(id, preimage)` log's `preimage`
   field can be placed in `SpendInfo.witness` as a single-item vector and `extract_preimage`
   finds it with zero changes to `divi-swap`. It is a type-shape abuse (an EVM log paraded as
   a Bitcoin witness stack) but it is a *contained* one: it lives entirely inside
   `swap-chain-evm`'s own `ChainBackend` impl, and it is exactly as effective as the real
   thing because the function it feeds was already written generically.

3. **The real mismatch: `build_funding` cannot stay "does not broadcast".** Locking requires
   two on-chain transactions — `approve(htlc, amount)` then `lock(...)` — because ERC-20 has
   no "transfer and lock atomically on someone else's contract" primitive; the contract's
   `transferFrom` needs a prior allowance. `ChainBackend::build_funding`'s contract is
   explicit that it signs but does **not** broadcast, so the engine can persist the signed
   bytes before broadcasting (write-ahead) and rebroadcast the *identical* bytes after a
   crash (`backend.rs:42`). That invariant holds for one transaction; it does not generalize
   to "sign two transactions, the second of which depends on the first having already landed
   on chain", because the engine has nowhere to persist "I broadcast tx 1 but crashed before
   tx 2" and rebroadcasting *both* signed payloads after a crash is not safe if tx 1 already
   landed (re-submitting an already-mined approve is harmless; re-submitting a lock whose
   approve dependency may or may not have landed yet is a race).
   `build_claim` and `build_refund` do **not** have this problem — claiming and refunding are
   single self-contained transactions with no on-chain precondition the caller doesn't already
   control, so they map onto the engine's write-ahead model exactly like BTC/DIVI.

`median_time_past` and `tip_height`/`confirmations` are not mismatches at all once you notice
what they're actually for. The engine compares a backend's `median_time_past()` against an
`HtlcParams.locktime` to decide whether a refund is minable yet. On BTC/DIVI that has to be
MTP specifically because that is what `OP_CHECKLOCKTIMEVERIFY` enforces at consensus. On EVM,
the contract's own `require(block.timestamp >= timelock)` is the consensus rule, and
`block.timestamp` of the pending/latest block *is* what a transaction will be checked against
— so "latest block timestamp" is not an approximation standing in for MTP, it is the correct
analog: the same quantity the chain itself will use.

## Option A — map onto `ChainBackend`, keep `approve` out of the write-ahead path

Treat `approve` as idempotent infrastructure the backend keeps current outside of
`build_funding`'s signed-tx contract, rather than as part of the swap's persisted state:

- On `EvmBackend::build_funding`, check `allowance(self, htlc)` for the token; if it is
  already `>= amount`, build and sign only the `lock` call and return it as the `Funding` —
  this is the common case after the first swap on a given token, so most funding calls touch
  one transaction, same as the UTXO chains.
- If allowance is short, broadcast an `approve` for (at least) `amount` and wait for it to be
  mined *before* returning from `build_funding`, which then returns only the `lock` tx for the
  engine to persist and broadcast under the normal write-ahead rule.
- This is safe to crash around and retry without any new persisted state: `approve` carries no
  swap-specific data (no hashlock, no timelock, no receiver) and setting the same allowance
  twice is a no-op, so "did I already send it" never needs an answer — re-entering
  `build_funding` after a crash just re-checks the allowance and re-sends `approve` only if it
  is still short.
- `Outpoint` becomes `{ txid: lock tx hash, vout: Locked-event log index }` (always `0` in
  practice, since `lock` only ever emits one `Locked` log, but keeping the field preserves the
  type instead of special-casing it to zero).
- `htlc_output(htlc, at)` recomputes `swap_id(...)` from `htlc`'s fields plus the caller's own
  address, reads `swaps(id)` from the contract, and returns `LockedOutput { amount,
  confirmations }` if it exists and is neither claimed nor refunded — `confirmations` from
  `tip_height() - receipt.block_number + 1`.
- `find_spend(outpoint, from_height)` queries `Claimed`/`Refunded` logs for the swap id at
  `outpoint.txid` from `from_height`, and on a `Claimed` hit returns a `SpendInfo` with the
  preimage packed into `witness` (point 2 above); a `Refunded` hit returns one with an empty
  `witness` (refund spends carry no preimage on BTC/DIVI either —
  `crates/divi-swap/src/types.rs:287` already tests exactly this shape).

**Changes needed in `divi-swap`:** none to make this compile and run. One cosmetic addition
the orchestrator may still want: `Chain::Usdc` (or similar) added to the `Chain` enum
(`types.rs:21`) so the engine can label swaps by chain the same way it does `Divi`/`Btc` — that
is wave 1e's job, not a prerequisite for this option to work.

## Option B — a second trait for account chains

Define e.g. `AccountChainBackend` with `lock`/`claim`/`refund` that broadcast-and-confirm
internally (no build/broadcast split) and return an idempotent receipt; `state(id)` instead
of `htlc_output`; `find_preimage(id)` instead of `find_spend` + `extract_preimage`. This
removes both of Option A's type-shape compromises (no `Outpoint`/`vout` fiction, no preimage
stuffed into a `witness` field) and gives account chains a crash-safety story that matches how
they actually fail (query by id, not rebroadcast identical bytes) instead of bending to fit
one that doesn't.

Its cost is on the engine side, not the chain side: everywhere `divi-swap` holds a
`Box<dyn ChainBackend>` (state machine transitions, `maker.rs`/`taker.rs` driving both legs of
a swap, the API layer reporting status) would need either a second code path or a unifying
enum/trait above both backend kinds, maker and taker would need to know which kind of leg they
are driving, and persisted state (`state.rs`) would need a variant for "confirmed by polling an
id" alongside "confirmed by watching an outpoint". That is a wave 1e/2-sized change, and it is
a one-off for USDC today — except it probably is not a one-off: XMR's adaptor-signature swap
(wave 1d, `lanes/xmr.md`) is a *third* shape that will not fit `ChainBackend` either (no
scripts on Monero at all), so if the orchestrator is going to build a second backend
abstraction, it is worth designing it to hold both USDC and XMR rather than deciding per-coin.

## Recommendation

**Option A** for wave 2: map `swap-chain-evm` onto `ChainBackend` as described above. It needs
zero changes to the frozen engine contract, so USDC can be wired into `divi-swapd` the moment
the orchestrator's wave 1e lands, on the same footing as LTC/ZEC. Its two compromises (the
`vout` always being `0`, and the preimage riding in a `witness`-shaped field) are both
contained entirely inside this crate's own `ChainBackend` impl — nothing elsewhere in the
engine, and no other backend, needs to know an EVM chain is even involved.

Option B is the more honest long-term shape for account chains, and the orchestrator should
keep it in reserve rather than reject it: if XMR's design (wave 1d) also turns out to want an
id-keyed, broadcast-and-confirm backend shape, that is the point to build one second trait that
serves both USDC and XMR, instead of Option A's per-chain workarounds accumulating one at a
time. Until that pressure actually shows up, Option A ships USDC with no engine change and no
blocked dependency on a design decision for a chain (XMR) that hasn't landed its own design yet.

- needs (orchestrator, not blocking USDC wave 2): `Chain::Usdc` variant in
  `crates/divi-swap/src/types.rs` `Chain` enum, when wave 1e generalizes the engine to
  DIVI-vs-any-counter-chain.
