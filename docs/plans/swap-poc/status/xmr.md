# Lane xmr status

- done: baretxid fix (`f8f7e9b`); build-plan steps 2-4 (`3e99c00`); step 7's bridge
  (`0139101`); root `Cargo.toml` wiring (`c73478e`, `cf80ac0`); step 5a (`02e6f0c`);
  step 5b (`23265e7`); step 6 (`6f4c32a`); step 7 + the two-secret protocol correction
  (`f54edba`); step 8, mock happy-path e2e (`1587eee`); step 9, engine-integration
  proposal (`3f2aefa`). **All nine build-plan steps from `xmr-design.md` landed.**
  New this round, per the orchestrator's "don't go idle, the live run is this lane's
  job now" directive (decision: Option B for engine integration, `6095675` landed):
  - Downloaded the official monerod v0.18.5.3 release into
    `/mnt/storage1/bshuler-xmr` (outside the repo), verified against
    `getmonero.org`'s signed `hashes.txt` (PGP-checked against `binaryFate`'s key from
    `monero-project/monero`'s own GitHub, then SHA256-checked the binary) before
    extracting or running anything.
  - `monerod --stagenet --prune-blockchain` running in the background (`nice 10`,
    `--max-concurrency 4`, RPC bound to `127.0.0.1:38081` only — confirmed via `ss
    -tlnp`, no external exposure). **Never mainnet** — `nettype: stagenet` confirmed
    live via `get_info`.
  - `monero-wallet-rpc` running alongside it (RPC on `127.0.0.1:38088` only), with a
    freshly generated throwaway wallet (`mining-wallet`,
    `5AbHxitM2WMiq1b957FpA6ZMHPPSex3XNH3UU9ox2tGpMHj9mNwCXCEXWMUVnfhnrQLyeh8vNDy6Mitu5d4L9Zjm9p8LaiS`)
    to mine to once sync completes — see `- running:` for why mining hasn't started
    yet, and `- left:` for the correction to last round's premature "done".
  - `crates/swap-chain-xmr/examples/xmr_live.rs`: the live happy-path harness against
    local stagenet `monerod` + DIVI testnet, built and run for real (not just
    `cargo check`) this round. `cargo build`/`clippy -D warnings`/`fmt --check` all
    clean; `cargo test -p swap-chain-xmr` still 19/19 green (no regressions in the
    nine build-plan steps' tests). Running it live against the actual local `monerod`
    produces real output: generates fresh Maker/Taker DIVI keys and the real additive
    Monero key share (reusing `monero_key_share`, not mocked), derives and prints both
    addresses that need funding, persists state to
    `/mnt/storage1/bshuler-xmr/xmr_live_state.json` (outside the repo) so it resumes
    correctly across runs, and checks real funding/sync status via real RPC calls
    (`services.divi.domains` for DIVI, local `monerod` for Monero) rather than mocking
    either side. `Tx_redeem` build-and-broadcast is wired to the same
    `swap_templates::{maker_encrypts_tx_redeem, taker_completes_tx_redeem}` the nine
    build-plan steps already prove offline, gated on both legs reporting funded — not
    yet exercised this round since neither leg has real coin yet (see `- needs:`).
    The final Monero sweep (the actual spend of the 2-of-2 output once `s_t` is
    recovered) is deliberately left as the next increment — it needs
    `monero_wallet::scan::Scanner`/decoy selection against a real deposit that doesn't
    exist yet either, so writing it now couldn't be tested against anything real.
- running: `monerod` (PID varies across restarts) and `monero-wallet-rpc`,
  both in the background on hp2, both still alive as of this round. `monerod` is
  still syncing stagenet from genesis (height ~101,000 of target ~2,227,200, ~4.5%,
  climbing steadily — outgoing peer count 4, no stall). Mining has **not** started:
  starting it before the node is fully synced would mine on top of a stale/incomplete
  local chain tip, and those blocks would almost certainly be orphaned the moment sync
  catches up past them — pure wasted CPU, not "self-mining avoids the faucet
  CAPTCHA" the orchestrator asked for. Will issue `start_mining` (2 threads, to the
  mining-wallet address above) once `get_info`'s `synchronized` field goes `true`,
  tracked and continued across future rounds on this same running daemon.
- broken: none in my paths.
- left: last round's status mistakenly marked "generate throwaway stagenet wallet and
  mine" as fully done — only the wallet-generation half was actually done; the
  `start_mining` RPC call was never issued. Corrected here; see `- running:` for the
  real state and why it's gated on sync completion, not skipped.
- decisions: none new this round (engine-integration decision already landed as
  `6095675`, Option B, per the orchestrator).
- needs: **DIVI testnet funding**, to actually exercise `Tx_redeem` build-and-broadcast
  live (per the orchestrator: "Use fresh DIVI keys that I will fund with tDIVI. When
  it needs DIVI funding, print the P2SH/address ... as needs:"). From this round's
  real `xmr_live` run:
  - DIVI P2SH testnet address (Maker's `Tx_lock`, needs ~1 tDIVI — comfortably covers
    the swap amount plus fees on every subsequent presigned spend):
    `8wRwFgKCKCVfxUmUAkMd3VLNRdwqUyhwut`
  - Monero stagenet address (the 2-of-2 lock, Taker's leg) — no action needed from the
    orchestrator here, this lane is self-mining toward it once `monerod` finishes
    syncing: `53hWE4DtPhFAvGj998ShM5D47iQ7hC6L2FhtiNiaHzX54b51c6UH3DMiP4xsAjmVrWByCdYZ3MpbsYEiTX1WR4oL4q2uGum`
  Once DIVI lands on the P2SH address, record its txid as `divi_lock_txid` in
  `/mnt/storage1/bshuler-xmr/xmr_live_state.json` and re-run the example (`cargo run -p
  swap-chain-xmr --example xmr_live --features live`) to pick it up — it polls for
  confirmation and proceeds automatically once both legs are funded.
  (examples/xmr_live.rs + dev-dependencies; build, clippy, fmt, tests and check-xmr.sh clean)
- live_run_plan: the exact happy-path live run, for whoever executes it (needs funded
  keys — **none of this runs from hp2**, per lane rule 5). Supersedes this status file's
  earlier mentions of self-mining stagenet XMR via `getblocktemplate`/`submitblock` —
  a real faucet exists and is simpler; use it instead.

  **Coins needed** (both worthless test-network coins, no real value):
  - A small amount of DIVI testnet coin for Maker's `Tx_lock` — 1 tDIVI is comfortably
    enough to cover the swap amount plus fees on every subsequent presigned spend.
  - 0.01 sXMR (stagenet XMR) for Taker to lock — one faucet request's worth (see below).

  **Faucet**: `https://cypherfaucet.com/xmr-stagenet` (checked live 2026-10-11; listed
  on getmonero.org, so a legitimate, maintained one, not a dead link). Enter a stagenet
  address, solve a CAPTCHA, receive 0.01 sXMR; capped at once per hour per
  address/IP. **The CAPTCHA means this step needs a human** — same exact blocker shape
  as `DECISIONS.md` #5 (the BTC lane's signet faucet), so whoever runs this live pass
  needs to visit the faucet page themselves once. A developer API exists for
  programmatic requests but needs contacting the operator for access — not pursued
  here since one manual drip is all this needs.
  - Fallback if the faucet is ever down/insufficient: self-mine via a locally-run
    `monerod --stagenet`'s `start_mining` JSON-RPC call to any address, no faucet
    needed (stagenet mining is permissionless) — but mined (coinbase) outputs need
    **60 confirmations (~2 h)** before spendable, vs. 10 confirmations (~20 min) for an
    ordinary received output like the faucet's. The faucet path is strictly faster
    when it's available; only fall back to mining if it isn't.

  **Keys**: all freshly generated for this one run, thrown away afterward, exactly like
  every other test in this lane — no 1Password entries needed (these coins have no
  value to protect). Generate at run time, not ahead of time:
  - Maker's and Taker's DIVI secp256k1 keypairs (`divi_crypto::keys::SecretKey::new_random()`
    or equivalent) — these are the `{a', b'}` pair in `xmr-design.md`'s notation.
  - Taker's own simple stagenet wallet (to receive the faucet drip before locking it
    into the 2-of-2) — any stagenet wallet works; `monero-wallet-cli --stagenet
    --generate-new-wallet <path>` is the straightforward option if a GUI isn't wanted.
  - The DLEQ secrets `s_t`/`s_m` and the resulting Monero 2-of-2 spend-key shares —
    generated by the swap code itself (`swap_adaptor::dleq::random_clamped_secret`,
    `crates/swap-chain-xmr/src/monero_key_share.rs`), not supplied externally.
  Run this whole thing from the orchestrator's Mac (or wherever holds `secret get`
  access and isn't hp2), not here — matches how every other lane's `live` tests work.

  **Commands / sequence** (numbers match `xmr-design.md`'s `## Protocol` `### Happy
  path` steps where they line up):
  1. Generate Maker/Taker DIVI keypairs; build the redeem script and its P2SH testnet
     address: `swap_chain_xmr::multisig::{redeem_script, script_pubkey}` for the
     scriptPubKey, `divi_wallet::Address::p2sh(hash, Network::Testnet)` for the
     human-readable address to fund.
  2. Run both DLEQ proofs (`swap_adaptor::dleq`), derive the additive Monero
     `ThresholdKeys` (`monero_key_share::additive_two_of_two_keys`), and the Monero
     stagenet address for the 2-of-2 lock output — identical code path to
     `crates/swap-chain-xmr/src/monero_dkg.rs`'s `group_key_derives_a_real_stagenet_address`
     test, just with `monero_key_share`'s keys instead of that test's PedPoP ones, and
     `Network::Stagenet` (already what that test uses).
  3. Visit `cypherfaucet.com/xmr-stagenet`, solve the CAPTCHA, send 0.01 sXMR to
     Taker's *own* stagenet wallet address (not the 2-of-2 address yet — a real swap's
     Taker already holds her XMR in her own wallet before locking it, so this mirrors
     that). Wait 10 confirmations (~20 min).
  4. From Taker's wallet, send the XMR into the 2-of-2 Monero address from step 2 —
     this is the actual "Taker locks XMR" step in `## Protocol`'s happy path step 2.
     Wait 10 confirmations (~20 min).
  5. Ask whoever holds `dnsdivi` SSH access (per `DECISIONS.md` #1, the established
     source for every other lane's live testnet DIVI) to run, from a dnsdivi node
     wallet: `divi-cli -conf=<testnet.conf> sendtoaddress <maker-p2sh-testnet-address>
     <amount>` — Maker's `Tx_lock`. Wait for 1-6 confirmations (DIVI testnet's existing
     profile, same as the BTC/DIVI lane's live runs).
  6. Build and broadcast `Tx_redeem` directly off `Tx_lock`'s output (the design
     permits spending `Tx_redeem` from either `Tx_lock` or `Tx_cancel` — skip
     `Tx_cancel` for this minimal happy-path run; it's already proven separately,
     offline, by `swap_templates::tests::tx_punish_is_plain_and_pays_taker` and
     `happy_path_e2e.rs`'s own use of it): `swap_templates::maker_encrypts_tx_redeem`
     then `taker_completes_tx_redeem`, broadcast the result via the same DIVI testnet
     RPC proxy (`services.divi.domains`) the BTC/DIVI lane's live tests already use.
     Wait for confirmation.
  7. Maker recovers `s_t` from the confirmed `Tx_redeem`
     (`swap_templates::recover_secret_from_chain`), combines it with his own `s_m`
     exactly as `happy_path_e2e.rs` checks arithmetically offline, and sweeps the full
     Monero 2-of-2 output to a fresh stagenet address of his own, with the now-fully-
     known private spend key (no multisig cooperation needed once Maker holds both
     halves) — the actual proof that the live run completed the swap, not just that
     the mock arithmetic checks out.
