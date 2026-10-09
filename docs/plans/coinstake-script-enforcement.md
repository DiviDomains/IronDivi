# Coinstake script enforcement (parked)

Status: parked, 2026-10-09. Gated on evidence, not on code.

## Background

Divi Core verifies every input script of every block transaction, coinstakes
included, under `MANDATORY_SCRIPT_VERIFY_FLAGS` (P2SH | DERSIG |
REQUIRE_COINSTAKE). A script failure rejects the block.

IronDivi's block connection (`crates/divi-storage/src/chain.rs`, the
`SCRIPT VALIDATION FAILED (non-fatal)` block) differs in three ways:

1. Coinstake inputs are never script-verified (`if !is_coinstake && ...`).
2. A failure on any other input only logs a warning.
3. Nothing is verified during IBD.

The vault-enforcement change that shipped alongside this note closed the parts
that did not need evidence first:

- `OP_REQUIRE_COINSTAKE` now passes when the spending transaction is a
  coinstake (`SignatureChecker::check_coinstake`), matching Core's
  `CoinstakeCheckOp`, and `REQUIRE_COINSTAKE` is in `ScriptFlags::standard()`.
- `validate_coinstake_vault_rules` matches Core's `CheckCoinstakeForVaults`:
  every input is summed, the vault must be paid back input + stake reward, and
  a split counts only when both halves are at least 10,000 DIVI.

## What is parked

Removing the coinstake skip and making script failures fatal.

Why it is parked: until now the interpreter rejected every vault manager
spend under the flag, so no one has seen what full verification says about
real coinstakes. Turning it on blind could make the node reject a valid block
and fork itself off the network.

## Gate (do these first, in order)

1. **Log evidence.** Count `SCRIPT VALIDATION FAILED (non-fatal)` lines in the
   live node logs over a long window. Expect zero. Any hit is a parity bug to
   fix before going further.
2. **Shadow-verify coinstakes.** Remove the `!is_coinstake` skip but keep the
   warning non-fatal. Run it on a synced node for a long window and again
   expect zero warnings, including on vault stakes from other stakers.
3. **Vault-stake canary.** On testnet or regtest, stake from a vault with the
   manager key and confirm both our node and a Divi Core node accept the block.
   Then build a coinstake that breaks the vault script and confirm both reject it.
4. Only then make the failure fatal (`StorageError::InvalidBlock`).

## Exposure while parked

Divi Core peers still enforce the full rule, so a bad block from or to this
node is rejected by the network. The cost is a lost stake attempt or a
temporary local fork, not lost coins.
