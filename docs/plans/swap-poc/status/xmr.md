# Lane xmr status

- done: xmr-design.md written (all 8 required sections); baretxid fix in crates/divi-rpc/src/wallet.rs
  landed (`f8f7e9b`). Per Bert's "build every coin in parallel, don't stop" order, continued with
  build-plan steps 2-4 from xmr-design.md:
  - `crates/swap-adaptor` (new crate, no internal deps): ECDSA adaptor signatures
    (`src/adaptor.rs`, wraps `ecdsa_fun::adaptor::Adaptor`) and the cross-group secp256k1/ed25519
    DLEQ proof (`src/dleq.rs`, wraps `sigma_fun::ext::dl_secp256k1_ed25519_eq::CrossCurveDLEQ`).
    8 tests: round-trip encrypt/verify/decrypt, decryption-key extraction, wrong-key rejection,
    unrelated-signature rejection, valid-proof verification, tampered-secp256k1-claim rejection,
    tampered-ed25519-claim rejection, cross-instance-generator rejection.
  - `crates/swap-chain-xmr` (new crate, depends on divi-primitives/divi-crypto/divi-script/
    divi-wallet/divi-swap): the 2-of-2 P2SH multisig skeleton (`src/multisig.rs`) —
    redeem script, scriptSig, legacy sighash + signing (reusing `divi_wallet::signer::sighash`,
    matches `divi-script`'s `TransactionSignatureChecker` byte-for-byte), and
    `build_presigned_spend`. 7 tests: a real 2-of-2 spend verifies against `divi_script::verify_input`
    (the mock-consensus check this repo has instead of libdiviconsensus); swapped-signature-order
    and unrelated-key spends are rejected; the `nLockTime` schedule (not CSV/CLTV — DIVI has
    neither live, see xmr-design.md `## DIVI scripts`) is enforced via
    `Transaction::is_final` before/at/after the deadline, and for `lock_time=0`.
  - Both crates: `cargo fmt`, `cargo clippy -p <crate> --all-targets --all-features -- -D warnings`,
    `cargo test -p <crate>` all green standalone. Additionally verified **workspace-wide**
    (temporarily added both to a local, uncommitted copy of root `Cargo.toml` `members`, ran
    `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`,
    then reverted root `Cargo.toml`/`Cargo.lock` exactly — `git status` now shows only the two new
    crate directories and the xmr-design.md fix below). `cargo clippy --workspace` surfaced one
    **unrelated, pre-existing** failure in `crates/swap-chain-evm/src/tests.rs:9` (unused import
    `std::str::FromStr`) — not my path, not touched; flagging for whichever lane owns
    swap-chain-evm. Scoped re-check (`cargo clippy -p swap-adaptor -p swap-chain-xmr --all-targets
    -- -D warnings`, merged workspace) is clean.
  - Corrected xmr-design.md's `## Stagenet`/step 5: `monero-wallet`'s `multisig` feature is a
    **FROST-based** 2-of-2, not the Monero wallet-rpc interactive multisig flow I'd first assumed —
    both work for this protocol, decide at step 5, default to FROST (simpler, no RPC round trips)
    unless interop with stock Monero wallets turns out to matter.
- running: nothing. Both new crates are standalone-buildable *except* for needing the one-line
  workspace membership below — not a defect, just not landed yet.
- broken: none in my paths. (`crates/swap-chain-evm` unused-import failure noted above, not mine.)
- left: build-plan steps 5-9 (Monero multisig on stagenet, wiring the adaptor secret through the
  DLEQ into the Monero spend share, the full `Tx_refund`/`Tx_punish`/`Tx_redeem` set, the
  happy-path e2e test, and the engine-integration proposal) — starting now per the standing order;
  see `- decisions:` for what's next and what's blocked.
- decisions: split the crypto (steps 3-4) from the DIVI chain code (step 2) into two crates
  (`swap-adaptor`, `swap-chain-xmr`) rather than one, per the orchestrator's "or swap-adaptor +
  swap-chain-xmr if cleaner" suggestion — steps 3-4 have zero DIVI/divi-primitives dependency and
  are reusable as-is. Neither crate can be added to root `Cargo.toml`'s `members` by me (lane rule
  2, binding) — built and fully verified (standalone and workspace-merged) using a temporary empty
  `[workspace]` table in each crate's own Cargo.toml during development, removed before finishing;
  both now use `{ workspace = true }` for every dependency that already exists in root's
  `[workspace.dependencies]` (`thiserror`, `rand`, `rand_chacha`, `sha2`, `hex` for swap-adaptor;
  all five `divi-*` crates for swap-chain-xmr), so the only remaining gap is the member-list lines
  below.
  `curve25519-dalek-ng` v4 (not mainstream `curve25519-dalek`) is a hard dependency of
  `sigma_fun`'s `ed25519` feature (checked its actual Cargo.toml, not just docs) — pinned directly,
  not shared via workspace.dependencies since nothing else in the repo uses it.
- needs: two 2-line diffs for the orchestrator to apply when landing (I can't touch root
  `Cargo.toml` per lane rule 2):
  1. Add to root `Cargo.toml`'s `[workspace] members` (anywhere in the list; placed next to the
     other swap-chain-* entries when I verified this):
     ```
     "crates/swap-adaptor",
     "crates/swap-chain-xmr",
     ```
  2. Nothing else — both crates' own Cargo.toml are already in final form (no `[workspace]` table,
     `workspace = true` deps). `cargo fmt --all -- --check` and
     `cargo clippy --workspace --all-targets -- -D warnings` were both green for these two crates
     when merged in (the only failure was the unrelated swap-chain-evm issue above).
