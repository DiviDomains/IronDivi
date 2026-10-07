# Rules every swap POC lane follows

You are a lane of `docs/plans/atomic-swap-poc.md`, running in your own git worktree
(`~/code/IronDivi-swap-<lane>`, branch `swap/<lane>`) as a pane in the "Swap POC" Avada tab.
The orchestrator is another pane. Bert may type into your pane; answer him, then carry on.

1. **Memory is your status file**, `docs/plans/swap-poc/status/<lane>.md`. Read it first: if it
   exists you are a restart — continue from it. Rewrite it at every seam with lines
   `- done: …`, `- running: …`, `- broken: …`, `- left: …`, `- last_sha: …`, plus any keys
   your brief asks for (`- live_fund_txid: …`). Commit it with your code.
2. **Own your paths only** (listed in your brief) plus your status file. Never edit the root
   `Cargo.toml`, `Cargo.lock`, another lane's paths, or the frozen contract in
   `crates/divi-swap/src/{types,htlc,backend,state,config,error,api}.rs` and the public
   signatures in `maker.rs`/`taker.rs`/`store.rs`. Need a dependency or a contract change?
   Write it under `- needs:` in your status file and keep going around it; the orchestrator
   will land it on `main` and you rebase.
3. **Stop condition is a script:** `tools/swap-poc/check-<lane>.sh` exits 0 only when you are
   done. A Stop hook re-prompts you while it fails. Do not edit check scripts.
4. **Land on `main` at each verified seam:** `cargo fmt && cargo clippy -p <crate> --all-targets
   --all-features -- -D warnings && cargo test -p <crate>` green → `git commit` (author is
   already Bert via git config; **no AI attribution, no Co-Authored-By**) →
   `git pull --rebase origin main` → `git push origin HEAD:main`. Never `--no-gpg-sign`, never
   `gh auth switch`. If signing or push blocks on 1Password, write the message to
   `docs/plans/swap-poc/parked/<lane>-<n>.msg`, add `- parked: git commit -F <that file>` to your
   status file, and keep working.
5. **Secrets:** keys come from `op read` at runtime via `divi_swap::secrets::SecretRef`
   (refs below). Never print, log, commit or write a key to disk — not in tests, not in the
   scratchpad. Tests use freshly generated throwaway keys.
6. **Waiting** for blocks or timelocks: run the wait as a background command
   (`run_in_background: true`) or `Monitor`; never sleep-loop in your context.
7. **Hard questions** (a bug that survived two attempts, a consensus/signing doubt) → the
   `oracle` agent with the full problem in the prompt. Do not ask Bert; take the sane default,
   note it under `- decisions:` in your status file.
8. **Read the Wave 0 proofs** before writing chain code: `crates/swap-chain-*/examples/*_cltv_proof.rs`
   and the txids in `docs/plans/swap-poc/RESULTS.md` show the exact shapes the live chains accept.

## Key references (1Password, vault `global_secret_store`, field `password` = 32-byte hex)
- `op://global_secret_store/IronDivi Swap POC - maker-divi/password`
- `op://global_secret_store/IronDivi Swap POC - taker-divi/password`
- `op://global_secret_store/IronDivi Swap POC - maker-btc/password`
- `op://global_secret_store/IronDivi Swap POC - taker-btc/password`
Each item also has non-secret `pubkey` and `divi_testnet_address` fields.
