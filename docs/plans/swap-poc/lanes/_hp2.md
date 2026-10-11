# Rules for multi-coin lanes running on hp2

You are a lane of `docs/plans/swap-poc/multi-coin.md`, a Claude session on **hp2** (Linux,
32 cores) in the checkout `~/swap-lanes/<coin>`. Bert watches you through an Avada pane on his
Mac and may type into it; answer him, then carry on. Read `_common.md` too — its rules apply
**except where this file overrides them** (rules 4 and 5 there).

1. **Status file** `docs/plans/swap-poc/status/<coin>.md` is your memory. Read it first; if it
   exists you are a restart. Rewrite it at every seam (`- done:`, `- running:`, `- broken:`,
   `- left:`, `- decisions:`, `- needs:`).
2. **Own your paths only** (your brief lists them) plus your status file. The engine contract
   (`crates/divi-swap/src/{types,htlc,backend,state,config,error,api}.rs`) belongs to lane
   `engine` (wave 1e), which is generalizing it for new chains right now. Need a change there? Write it under
   `- needs:` and work around it. You **may** edit your own crate's `Cargo.toml` and the
   resulting `Cargo.lock` changes; never the root `Cargo.toml`.
3. **Build with plain `cargo` on hp2** (it is the build box). Keep it niced:
   `nice -n 10 cargo …`. Do not run `remote-cargo`.
4. **Never `git commit`, never push.** Signing lives on the Mac. At each verified seam
   (`cargo fmt`, `cargo clippy -p <crate> --all-targets --all-features -- -D warnings`,
   `cargo test -p <crate>` all green) write `- ready_to_land: <conventional commit subject>` in
   your status file. The orchestrator lands it signed on `main`, then removes that line. After it
   is gone, run `tools/swap-poc/lane-sync.sh` to pull `main` under your work. Keep working while
   you wait; don't block on landing.
5. **No secrets on hp2, ever.** No 1Password, no funded keys. Tests use freshly generated keys.
   Live tests are `#[ignore]` + `--features live` and read their key from the env var named in
   your brief; the orchestrator runs them from the Mac. You may call public testnet APIs
   read-only (and broadcast throwaway-key transactions if a faucet-free path exists).
6. **Stop condition:** `tools/swap-poc/check-<coin>.sh` exits 0 (a Stop hook re-prompts while it
   fails; do not edit check scripts). If everything left needs a human (testnet coins, a key),
   write `- parked: <what unblocks it>` and `- blocked-on-human: yes`.
7. **Hard questions** (consensus/sighash doubts, a bug that survived two attempts) → the
   `oracle` agent with the full problem in the prompt. Don't ask Bert; take the sane default and
   record it under `- decisions:`.
8. **Waiting:** background commands, never sleep loops in your context.
9. Before writing chain code read `crates/swap-chain-btc/` (closest model: `tx.rs`, `client.rs`,
   `tests.rs`) and `crates/divi-swap/src/{backend,htlc,types}.rs`.
10. Commits that eventually land are authored by Bert; never put AI attribution in code, docs or
    commit subjects.
