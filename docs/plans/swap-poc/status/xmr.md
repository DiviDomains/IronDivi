# Lane xmr status

- done: xmr-design.md written (all 8 required sections); baretxid fix in crates/divi-rpc/src/wallet.rs
  (helper `bare_txid()` mirrors Divi Core's `CTransaction::GetBareTxid()` — scriptSig cleared on
  every input except coinbase, verified against github.com/DiviProject/Divi master 9e2f76c);
  wired into both `get_raw_transaction` and `decode_raw_transaction`; added test
  `baretxid_differs_from_txid_for_signed_tx` plus a coinbase-equality test.
  `tools/swap-poc/check-xmr.sh` → PASS (fmt, clippy -D warnings, 75 tests green in divi-rpc, all 8
  design-doc sections present).
- running: nothing
- broken: none
- left: nothing for this wave (1d). Follow-on build-plan steps (2–9 in xmr-design.md) are a later
  plan per multi-coin.md.
- decisions: bare_txid implemented in divi-rpc only (not divi-primitives), per brief's path
  restriction — free fn `bare_txid(&Transaction) -> Hash256` in wallet.rs, clones the tx and
  clears `script_sig` on each input unless `tx.is_coinbase()` (Core's special case, verified in
  `divi/src/primitives/transaction.cpp` and `divi/src/test/BareTxid_tests.cpp` upstream).
  xmr-design.md recommends `monero-serai` + `secp256kfun`/`sigma_fun` (both actively maintained,
  checked via GitHub API 2026-10-11) over the stale `farcaster_core` (last push 2023) or archived
  `comit-network/cross-curve-dleq`. Confirmed directly from Divi Core source
  (`StackManager.cpp`/`defaultValues.h`) that DIVI has CLTV but **no** CSV/BIP68 relative
  timelocks (opcode is a no-op NOP, and the BIP68 flag is defined but never read) — design uses
  only presigned-tx `nLockTime`, no relative locks needed.
- needs: nothing from the orchestrator yet; build-plan step 9 (engine integration) flags that
  `ChainBackend` likely doesn't fit this protocol's multi-tx adaptor-signature state machine —
  noted in xmr-design.md's Build plan, not yet a concrete ask.
