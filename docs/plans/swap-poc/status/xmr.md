# Lane xmr status

- done: baretxid fix (`f8f7e9b`) and build-plan steps 2-4 — `crates/swap-adaptor` (ECDSA adaptor
  signatures + cross-group DLEQ) and `crates/swap-chain-xmr` (DIVI 2-of-2 multisig skeleton) —
  landed in `3e99c00`. Per Bert's "never stop, build every coin end to end" order, continued
  immediately with the first slice of step 7 (adaptor signatures replacing a plain multisig
  signature):
  - new `crates/swap-chain-xmr/src/adaptor_bridge.rs`: converts a `swap-adaptor`
    (`ecdsa_fun`/`secp256kfun`) completed adaptor signature into a DIVI scriptSig signature, and
    a `secp256kfun::Point` into the `[u8; 33]` compressed pubkey format the redeem script needs.
    Pure re-encoding, no crypto conversion — confirmed both libraries speak the same curve and
    the same low-S convention (`ecdsa_fun`'s `sign`/`decrypt_signature` both
    `conditional_negate` to low-S, matching DIVI's `SCRIPT_VERIFY_LOW_S`; checked the actual
    source, not just docs).
  - **2 new tests, the load-bearing proof for the whole design**: a transaction with one
    plain-multisig signature (party A, `divi-crypto`) and one adaptor-completed signature (party
    B, `swap-adaptor`) passes `divi_script::verify_input` exactly like an ordinary 2-of-2 spend —
    i.e. DIVI's own `OP_CHECKMULTISIG` cannot tell an adaptor-completed signature from a normal
    one, with zero special support needed on the DIVI side. Second test: decrypting under the
    *wrong* key produces a signature that does *not* satisfy the script (the atomicity property
    the whole swap depends on — only the real decryption key produces something DIVI accepts).
  - Both crates re-verified green (fmt/clippy -D warnings/test, standalone and merged into a
    local throwaway copy of root `Cargo.toml`) with the new module and the new
    `swap-chain-xmr -> swap-adaptor` path dependency. 9 tests in swap-chain-xmr now (was 7), 8 in
    swap-adaptor (unchanged).
  - Also corrected `xmr-design.md` (`3e99c00`, already landed): `monero-wallet`'s `multisig`
    feature is FROST-based, not the Monero wallet-rpc interactive flow I'd first assumed.
- running: nothing.
- broken: none in my paths.
- left: build-plan steps 5-9 — Monero multisig on stagenet, wiring the adaptor secret through the
  DLEQ into the Monero spend share, the rest of the `Tx_cancel`/`Tx_refund`/`Tx_punish`/`Tx_redeem`
  set, the happy-path e2e test, and the engine-integration proposal. Researched the current
  Monero-side crate landscape for step 5 (see `- decisions:`) — `monero-serai` itself is dead
  (crates.io shows `0.0.0`, effectively yanked); its maintainer moved the Monero-specific code to
  a new org, `monero-oxide` (`monero-wallet` v0.2.0, non-alpha, pushed 2026-09-22). Its `multisig`
  feature needs `modular-frost` (serai-dex/serai) — but `modular-frost` itself only *signs* given
  existing `ThresholdKeys`; actual key generation was split out of the old `dkg` crate into
  `dkg-musig`/`dkg-pedpop` (checked docs.rs directly, not just the `develop` branch tree, which no
  longer shows the protocol code at all post-split). `dkg-pedpop` (PedPoP, audited by Cypher Stack
  2023-03) is the one that matters here: three rounds, `KeyGenMachine -> SecretShareMachine ->
  KeyMachine -> ThresholdKeys`, broadcast `Commitments` then point-to-point
  `SecretShare`/`EncryptedMessage`. This is a concrete enough shape to implement against next —
  exact method signatures (`round1`/`round2`-equivalent calls) still need reading from source
  before writing code, not guessed. That's the next unit of work once root `Cargo.toml` is wired
  (see `- needs:`).
  Checked all 5 public stagenet nodes xmr-design.md cites are still live (checked 2026-10-11,
  ~19:50): `node[123].monerodevs.org:38089`, `stagenet.xmr-tw.org:38081`,
  `xmr-lux.boldsuck.org:38081` all answered `get_info` with `status: OK`, `nettype: stagenet`,
  same height (2227130) — healthy, in sync, ready to point step 5's RPC client at once that
  code can build.
- decisions: kept the split from the last update (`swap-adaptor` crypto-only, `swap-chain-xmr`
  DIVI-side) and added the bridge module to `swap-chain-xmr` rather than a third crate, since it's
  DIVI-scriptSig-shaped output, not generic crypto.
  Hit a repo-mechanics snag worth recording: after `3e99c00` landed, `tools/swap-poc/lane-sync.sh`
  failed twice. First, `crates/{swap-adaptor,swap-chain-xmr}/Cargo.lock` were staged in my index
  as empty-blob placeholders (`git ls-files -s` showed the all-zero/empty SHA `e69de29b...`) even
  though I'd never run `git add` — looked like an editor-tooling auto intent-to-add, and it broke
  `git stash`'s internal tree merge ("Entry not uptodate. Cannot merge."); fixed with
  `git reset -- <paths>` before retrying. Second, `stash pop` partially failed
  ("could not restore untracked files from stash... already exists") because the landing had
  *already* checked out older versions of `swap-chain-xmr/{Cargo.toml,src/lib.rs}` at the same
  paths my stash wanted to restore newer versions into; stash pop silently kept the merge's
  (older, pre-`adaptor_bridge`) version for those two tracked files rather than conflict-marking
  them. Recovered by diffing `HEAD` against the dropped stash's recorded blobs and manually
  re-applying the two small deltas (the `swap-adaptor` path dependency, the `adaptor_bridge`
  module declaration) rather than trusting a second stash-pop attempt. Also deleted
  `crates/{swap-adaptor,swap-chain-xmr}/target/` and their standalone `Cargo.lock`s, left over
  from pre-landing standalone verification and now just cruft now that the crates are (almost)
  real workspace members — exactly the class of leak `df6a1dd`/`e1418fe` already had to clean up
  for other lanes, so getting ahead of it here.
- needs: **the previous landing (`3e99c00`) did not add `crates/swap-adaptor` or
  `crates/swap-chain-xmr` to root `Cargo.toml`'s `[workspace] members`** — both crates currently
  fail to build at all (`cargo build -p swap-chain-xmr` / `-p swap-adaptor`: "current package
  believes it's in a workspace when it's not"). This blocks *all* downstream work on them,
  including mine. The fix is the same 2-line add as before (I still can't make it myself, lane
  rule 2): insert into root `Cargo.toml`'s `members` array, anywhere, e.g. next to the other
  swap-chain-* entries:
  ```
  "crates/swap-adaptor",
  "crates/swap-chain-xmr",
  ```
  Both crates' own Cargo.toml are already in final form otherwise (no `[workspace]` table,
  `workspace = true` deps where root has them, direct `{ path = "../swap-adaptor" }` for the one
  cross-new-crate dependency). Re-verified green (fmt, clippy --workspace -D warnings, test) with
  both temporarily added to a throwaway local copy of root `Cargo.toml`, then reverted — same
  technique as last time, diff is clean.
