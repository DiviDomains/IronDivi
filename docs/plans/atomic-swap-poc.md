# Atomic Swap POC — Build, Deploy, Test Plan

Status: **plan, not started** (written 2026-10-07). This file is the bridge between
sessions: every lane reads it at start and writes progress to `docs/plans/swap-poc/status/`.

## 1. Goal and definition of done

A non-custodial DIVI ↔ BTC atomic swap engine (HTLC, SHA256 hashlock, CLTV refunds),
with no self-run nodes in production, deployed on **dnsdivi**, proven on public testnets.

Done means all of these, each with evidence (txids, logs, commit shas) in
`docs/plans/swap-poc/RESULTS.md`:

1. **Happy path:** a real DIVI-testnet ↔ BTC-signet swap driven by the deployed
   `divi-swapd` on dnsdivi (maker) and a local `divi-swap` CLI (taker). Both claims confirmed.
2. **Case C (taker never claims):** maker's DIVI refunded after the maker timeout; taker's
   BTC refunded after the taker timeout.
3. **Case D (late claim):** taker claims DIVI just before the maker timeout; maker still claims BTC.
4. **Crash recovery:** `divi-swapd` killed mid-swap at each state, restarted, swap completes or refunds.
5. **Staking claim holds:** maker's DIVI is not reserved until the BTC lock has its confirmations
   (asserted in engine tests: no coin selection before state `TakerLockConfirmed`).
6. CI green (`cargo fmt --check`, `clippy -D warnings`, tests), pushed to `main`.

Out of scope for this POC: LTC, ZEC, USDC, XMR, the IronDivi staker's reserved-coin list
(the engine holds its own testnet key, not a staking wallet), reputation, fees, order book UI.

## 2. Facts established before planning (2026-10-07 probes)

| Probe | Result | Consequence |
|---|---|---|
| `services.divi.domains/api/testnet/rpc/` | Live, height 339,792, `chain: test` | DIVI testnet backend works without our own node |
| `sendrawtransaction` on testnet proxy | Allowed (returned `TX decode failed` for junk, not "method not allowed") | Engine can broadcast |
| `getrawtransaction <non-wallet tx> 1` | Works | txindex is on |
| `getaddressutxos` / `getaddresstxids` on an active testnet address | **Empty result** | **Address index missing or not populated on testnet** |
| `getspentinfo` | `Unable to get spent info` | **Spent index missing on testnet** |
| `getaddressmempool` | Method not allowed by proxy | Can't watch mempool by address |
| CLTV in C++ (`BlockTransactionChecker.cpp:119`) and IronDivi (`crates/divi-storage/src/fork_activation.rs:64`) | Opcode + flag present; activates by median time past after the Aug-23 timestamp | Expected active on testnet; **still proven live in Wave 0** |
| IronDivi `divi-script` | Has `OP_CHECKLOCKTIMEVERIFY`, interpreter, P2SH addresses (testnet P2SH version byte in `divi-wallet/src/address.rs:33`) | Reuse for HTLC script building and local verification |
| BTC test APIs | mempool.space signet (325,405), testnet4 (155,569), testnet3 + blockstream OK | Default **signet** via mempool.space Esplora API |
| Divi testnet faucet | Exists on vps1 `:19150` (Tailscale only, unreachable from this Mac without tailnet) | Testnet DIVI source; Wave 0 confirms balance |
| Commit signing | `gpg.format=ssh` via 1Password `op-ssh-sign` | Unattended commits can hit a Touch ID prompt — see §6 |

**Design decision forced by the index gap:** the DIVI backend does **not** depend on address
or spent indexes. The engine always knows the txids and outpoints it cares about (it built the
lock, or was told the taker's lock txid), so it watches by:
- confirmations: `getrawtransaction <txid> 1` → `confirmations`;
- spend detection (taker's claim revealing the secret): scan each new block
  (`getblockcount` → `getblock <hash> 2` or per-tx `getrawtransaction`) for an input spending the
  HTLC outpoint. One block per minute, a few txs per block: cheap, and identical on mainnet.

Enabling `-addressindex -spentindex` on the testnet node behind the proxy is a nice-to-have
(infra ticket), not a dependency.

## 3. Architecture

New workspace members in this repo (Rust, same CI):

```
crates/divi-swap/          core: HTLC script, swap state machine, ChainBackend trait,
                           persistence (SQLite), secret handling, timeouts config
crates/swap-chain-divi/    ChainBackend for DIVI via JSON-RPC proxy; tx build + local signing
                           reusing divi-script / divi-crypto / divi-wallet
crates/swap-chain-btc/     ChainBackend for BTC via Esplora HTTP (mempool.space / blockstream);
                           rust-bitcoin for tx build + signing
bin/divi-swapd/            maker daemon: HTTP API (offers, quotes 60 s expiry, accept),
                           scheduler (claim/refund deadlines), health endpoint
bin/divi-swap/             taker + operator CLI: accept offer, lock, claim, refund, status
```

### 3.1 Contract (frozen in Wave 0 — lanes build against it, never change it alone)

```rust
#[async_trait] pub trait ChainBackend: Send + Sync {
    fn chain(&self) -> Chain;
    async fn tip_height(&self) -> Result<u64>;
    async fn median_time_past(&self) -> Result<u32>;
    async fn fund_htlc(&self, htlc: &HtlcParams, amount: Amount) -> Result<Outpoint>;
    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>>;  // None = unknown
    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>>;
    async fn claim(&self, htlc: &HtlcParams, at: &Outpoint, preimage: &[u8; 32]) -> Result<Txid>;
    async fn refund(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Txid>;
}
// SpendInfo carries the witness/scriptSig so the engine can extract the preimage.
```

HTLC redeem script (both chains, P2SH on DIVI; P2WSH on BTC signet):

```
OP_IF   OP_SHA256 <h32> OP_EQUALVERIFY <claim_pubkey>
OP_ELSE <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pubkey>
OP_ENDIF OP_CHECKSIG
```

Locktimes are **unix timestamps** compared against median time past. BTC MTP lags wall
clock by ~1 h; DIVI MTP lags ~6 min. Timeouts are **config, not constants**:

| Profile | Taker (BTC) lock | Maker (DIVI) lock | Confirmations BTC / DIVI |
|---|---|---|---|
| `mainnet` | 24 h | 12 h | 2 / 10 |
| `testnet` | 6 h | 3 h | 1 / 3 |

Invariant enforced in code and tests: `taker_timeout − maker_timeout ≥ max(3 h, 2 × BTC MTP lag + claim margin)`.

### 3.2 State machine (maker side)

`Quoted → Accepted → TakerLockSeen → TakerLockConfirmed → MakerLocked → MakerLockConfirmed →`
`{ TakerClaimed(preimage) → MakerClaimed → Done | MakerRefundable → MakerRefunded → Done }`

Every transition is persisted before the side effect is broadcast (write-ahead), and every
broadcast is idempotent on restart (look up txid / spend before re-sending). Coin selection
for the maker lock happens **only** on entering `MakerLocked` — that is the staking promise.

### 3.3 Secrets

- Engine keys (testnet DIVI WIF, BTC signet xprv) live in 1Password; resolved at runtime with
  `op read` into memory. Never on disk, never on argv, never logged. On dnsdivi: systemd unit
  with `LoadCredential`/an `op` service-account token per `secret-management.md`.
- Swap preimages are generated by the taker, stored only in the swap DB (mode 600), and are
  not secret after the claim.

## 4. Orchestration

**Mechanism:** one **Avada Terminal** tab, "Swap POC". The orchestrator (Opus) runs in its first
pane; each lane is another pane in the same tab, in its own git worktree, running an interactive
**Sonnet** session via the narrow profile (`context-budget.md` §2.5 rule 13), launched with
`claude_auto` (`working-with-human.md` §9). Human can watch and type into any of them. The
orchestrator creates and waits on panes with `avada ctl` (exact commands:
`docs/plans/swap-poc/orchestrator.md`).

Rules every lane follows:

- **Owns paths, not files it shares.** A lane edits only the directories listed for it. Wave 0
  pre-registers every workspace member and every dependency in the root `Cargo.toml`, and commits
  `Cargo.lock`, so lanes never touch either. A lane that needs a new dependency writes it to its
  status file; the orchestrator adds it.
- **Lands on `main` at each verified seam:** `cargo fmt && cargo clippy -p <crate> -D warnings &&
  cargo test -p <crate>` green → commit (as Human, no AI attribution) → `git pull --rebase origin main`
  → `git push origin HEAD:main`.
- **Status file** `docs/plans/swap-poc/status/<lane>.md`: done / running / broken / left, last sha.
- **Stop condition is a script, not a vibe.** `tools/swap-poc/check-<lane>.sh` exits 0 only when the
  lane's acceptance criteria pass. The lane's conditional Stop hook re-prompts only while it fails,
  capped at 15 re-prompts (`context-budget.md` §2.5 rule 15).
- **Hard questions** (a bug that survived two attempts, a consensus/signing doubt) go to the
  `oracle` agent with the full problem in the prompt, not to a model switch.
- **Long waits** (signet blocks, refund timeouts) use `run_in_background` / `Monitor`; never sleep loops.
- **Restart, don't compact:** a lane that compacts twice is relaunched fresh from its status file.

**Orchestrator** (Opus, one session, low turn count): runs Wave 0, launches lanes, reviews at
each wave gate (diff review + `cargo test --workspace`), resolves contract changes, runs Wave 3.
It waits on lanes with a Monitor on the status files, not by polling.

## 5. Waves

### Wave 0 — foundations and go/no-go (orchestrator, sequential, ~half a day)

| # | Task | Exit criterion |
|---|---|---|
| 0.1 | Confirm push works with `git push origin main` (no-op) — the repo-local credential helper (§6) must be present. Scaffold all five members, register in workspace, add deps (`bitcoin`, `reqwest` rustls, `rusqlite` bundled, `axum`, `tokio`, `async-trait`, `clap`), commit `Cargo.lock` | `cargo build --workspace` green, pushed |
| 0.2 | Write `divi-swap` types + `ChainBackend` trait + `HtlcParams` + state enum + config profiles (§3.1–3.2) | compiles; doc-tested script template |
| 0.3 | **Live CLTV proof on Divi testnet** (go/no-go): build an HTLC P2SH with IronDivi crates, fund it from the testnet key, (a) claim with preimage, (b) second HTLC refunded after a 10 min locktime | both txids confirmed; recorded in RESULTS.md. If refund is rejected → stop, escalate to oracle (CLTV not active / sighash mismatch) |
| 0.4 | Same on BTC signet with rust-bitcoin + mempool.space. Refund locktime **≥ 2 h** ahead of current MTP (signet MTP lags wall clock ~1 h; a 10 min lock is rejected for over an hour and looks like a CLTV bug). Run the refund wait in the background. | both txids confirmed |
| 0.5 | Fund engine keys: testnet DIVI from the vps1 faucet (`:19150`, via tailnet or ssh) or the dnsdivi testnet node wallets; signet BTC from a public signet faucet | maker ≥ 5,000 tDIVI, taker ≥ 0.01 sBTC. **If no faucet dispenses, this is the one question for Human** |
| 0.6 | Store keys in 1Password (`IronDivi Swap POC` items), resolver in `divi-swap::secrets` | `op read` at runtime works; nothing on disk |
| 0.7 | Write lane briefs `docs/plans/swap-poc/lanes/*.md` and `tools/swap-poc/check-*.sh` | each check script fails before work starts (proves it can fail) |

### Wave 1 — parallel lanes (5 Avada panes, Sonnet)

| Lane | Owns | Acceptance (`check-<lane>.sh`) |
|---|---|---|
| **divi** | `crates/swap-chain-divi/` | Unit: script/sighash vectors verified by IronDivi's interpreter (`divi-script`) for claim and refund. Integration (ignored by default, `--features live`): fund/claim/refund on testnet using the block-scan spend finder. |
| **btc** | `crates/swap-chain-btc/` | Unit: P2WSH claim/refund verified with `bitcoinconsensus`. Integration (`live`): fund/claim/refund on signet; Esplora client retries + 429 backoff; blockstream fallback. |
| **engine** | `crates/divi-swap/` (except frozen contract) | State machine driven by an in-memory `MockBackend`: happy path, cases A–D, crash at every state + restart, timeout invariant, "no coin selection before `TakerLockConfirmed`". Property test on random crash points. |
| **daemon** | `bin/divi-swapd/`, `bin/divi-swap/` | HTTP API (`POST /offers`, `GET /offers/:id/quote` 60 s expiry, `POST /swaps`, `GET /swaps/:id`, `/healthz`); CLI taker flow; end-to-end run against two `MockBackend`s in one test. |
| **deploy** | `deploy/divi-swapd/` | systemd unit (dedicated unprivileged user, `ProtectSystem=strict`, `NoNewPrivileges` — copy the divi-chatbot unit pattern described in `~/code/divi-infrastructure/DEPLOYMENT.md`), nginx location, log rotation at 10 MB, secret loading, `deploy.sh` that is idempotent and dry-runnable. `shellcheck` clean; dry run prints the plan. Does **not** touch dnsdivi. |

Lanes are independent once Wave 0 lands: engine and daemon build against `MockBackend`,
chain lanes against the trait. Gate: orchestrator merges nothing — lanes push to `main` themselves;
the gate is `cargo test --workspace` + clippy green on `main` and every check script passing.

### Wave 2 — integration on testnets (2 Avada panes)

| Lane | Work | Acceptance |
|---|---|---|
| **e2e-local** | Run maker `divi-swapd` and taker CLI **locally** against real testnet + signet. Happy path, case C, case D. Script: `tools/swap-poc/e2e.sh <scenario>`; runs in background with a Monitor on the swap DB state. | Three scenarios complete; txids in RESULTS.md. Case C takes ~6 h wall clock — runs in the background while the next item proceeds. |
| **chaos** | Kill/restart `divi-swapd` at each state transition during real testnet swaps; proxy outage (block the RPC host) mid-swap; Esplora 429s. | Every run ends `Done` (claimed or refunded); no stuck funds. |

### Wave 3 — deploy to dnsdivi and prove there (orchestrator; needs Human present once)

1. **Parked for a human turn:** SSH to dnsdivi uses the 1Password SSH agent key (`dnsdivi_ssh`);
   service secret provisioning needs `op`. Batch both into one sitting (`working-with-human.md` §8).
2. `deploy.sh` → build release, install unit, start, `curl https://<host>/swap/healthz`.
3. Rerun `e2e.sh happy` with the **deployed** maker; then case C in the background.
4. Write RESULTS.md, update the promo page's "Status" line only if every §1 item is proven.

## 6. Known blockers and how lanes handle them

| Blocker | Handling |
|---|---|
| **Commit signing needs 1Password** (`op-ssh-sign`) | Launch lanes while Human is present and 1Password is unlocked so the agent's approval is remembered. If a signing prompt can't be answered, the lane parks per `secret-management.md` §7.1: stage, write the message to `docs/plans/swap-poc/parked/<lane>-<n>.msg` (outside nothing secret), keep working, and leave one command (`git commit -F <file>`). Never `--no-gpg-sign`. |
| **Push 403 / `Repository not found`** — default gh account is `bshuler`, repo needs `DiviDomains` | Already applied to this clone (2026-10-07), shared by every worktree: repo-local `credential.https://github.com.helper` that answers `username=DiviDomains` and `password=$(gh auth token -u DiviDomains)` (token from gh's keyring at call time; never on disk or argv). **Never `gh auth switch`** — it is global and races between lanes. Fresh clone: `git config --local --replace-all credential.https://github.com.helper ''` then `--add` the helper shown by `git config --local --get-all credential.https://github.com.helper` here. |
| Testnet address/spent index missing | Block-scan design (§2); no dependency. |
| No testnet DIVI | Wave 0.5; only legitimate question to Human. |
| Signet faucets rate-limit | Try several in Wave 0.4; keep taker sats small (0.001 per swap) and reuse refunds. |
| Divi sighash differs from Bitcoin legacy | Proven in 0.3 against the live chain before lanes start. |
| services.divi.domains proxy blocks a needed method | Lane writes it to status; orchestrator adds it to the proxy allowlist (`~/code/divi-infrastructure/divi-rpc-proxy/`) or switches to the dnsdivi local testnet RPC (`51475`, localhost only). |
| vps1 memory | Nothing runs on vps1; engine is dnsdivi only. |

## 7. After the POC (not in this plan)

LTC (same code path, litecoinspace Esplora), ZEC transparent HTLC (verify zec.rocks gRPC / Blockchair
first), USDC on Sepolia/Base (Solidity HTLC), XMR adaptor-signature swap (needs bare-txid semantics
settled first: IronDivi `crates/divi-rpc/src/wallet.rs:1255` echoes txid as baretxid), IronDivi staker
reserved-coin list, free-option mitigations (deposit, reputation).

## 8. Launch checklist (for the orchestrator session)

```sh
cd ~/code/IronDivi
claude_auto --model opus "Read docs/plans/atomic-swap-poc.md. You are the orchestrator. Run Wave 0, then launch Wave 1 lanes per §4."
```

## 9. IronDivi Swaps website (Human 2026-10-22 17:00: "i want a website to be in the plan for IronDivi Swaps")

Status 2026-10-22 21:30: **wording approved** (Human: "keep it not published yet"): the pages keep "the taker app is not
published yet" until §10 or §11 ships something a person can download. Landed as `72ec52d`, still NOT installed;
installing it is its own yes/no card.
Earlier status 2026-10-22: built and tested on branch `lane/swap-website` (five pages, install/rollback script, docker nginx and headless-browser proof), NOT installed; the taker app has no public download so the how-to page says so. Was: planned, builder dispatched. Going live is a separate yes/no card for Human, not part of this item.
The one-page `/swap/` landing page (`622220d`, `deploy/divi-swapd/www/`) stays built and **not installed**;
the website replaces it.

**Where.** Static files served by the existing nginx on dnsdivi at `https://divi.cx/swap/` from
`/var/www/divi-swap/`. The live `location /swap/` proxy block stays byte-identical; the site adds only its own
locations, and every API path (`healthz`, `offers`, `offers/:id/quote`, `swaps*`, `xmr/*`) still reaches
`divi-swapd` unchanged. No new daemon route, no restart; rollback = restore the snippet backup and reload nginx
(the `landing-install.sh` install/rollback pattern).

**Pages (plain words, testnet wording on every page until a mainnet card says otherwise).**
1. **Home**: what IronDivi Swaps is (trade DIVI for BTC/LTC/ZEC/XMR/USDC without an exchange holding your
   coins), a "practice network only" banner, live status from `/healthz` (ready / catching up with progress /
   unreachable), and the current offers from `/offers`.
2. **How to swap**: how to get the `divi-swap` taker app (only what really exists; if it is not published, say
   so), then a step-by-step testnet walkthrough with the real CLI commands (quote, accept, lock, status, claim,
   refund), and the faucet link `https://services.divi.domains/testnet/faucet`.
3. **How it works and safety**: the hashlock swap and the XMR adaptor swap in plain words; who can take the
   coins back and when (timelocks, refunds), the confirmation counts the code really uses (cite them), what
   happens if either side disappears, and what the site never does (no keys, no wallet, no sign-in).
4. **Status**: per-chain tips and errors, the DIVI scan progress, and the maker version, from `/healthz`.
5. **FAQ**: limits and rates (from `/offers`), fees, risks, testnet vs mainnet, where the source is.

**Rules.** Static HTML/CSS and plain same-origin JS only: no dependencies, CDN, web fonts, analytics or forms.
Strict CSP (self only), API data inserted with `textContent` only (offers are untrusted), readable at phone width,
works with JS off (the status and offers sections then say so).

**Done for this item** = built, tested and landed signed: a mock `divi-swapd` plus a real nginx in docker proves
the pages and that the API paths are unchanged, `node --test` covers the render logic including hostile
strings, headless-browser screenshots at phone and desktop width are committed under `docs/`, and the
orchestrator has looked at it in a real browser through an ssh tunnel. Nothing is installed on dnsdivi.

**Other swap lanes, open option only (Human: "For the other 3 lanes, maybe"; no work started):**

| Lane | Website? Pro | Con |
|---|---|---|
| Divi KDF (Komodo DeFi) | Komodo Wallet already has a GUI, so one page of DIVI setup steps would get people trading with little build work. | The iguana weak-seed hard gate is still open; a public page would invite mainnet funds before that is fixed. |
| Divi BasicSwap | BasicSwap already has its own web UI, so a short "trade DIVI on BasicSwap" guide is cheap. | The public BasicSwap cannot list DIVI until the upstream pull request is merged, so the page would describe something nobody can do yet. |
| DEX Test | One page could compare all the DIVI swap routes side by side. | It duplicates the other pages and is one more thing to keep accurate while no route is on mainnet. |

## 10. A swap library other developers can use (Human 2026-10-22 21:30: "we will publish a library others can use to integrte")

Status 2026-10-22: **planned only.** Nothing built, nothing public.

**Scope.** The taker side of a DIVI swap, as a library a wallet or app embeds: list offers and get a quote from a
maker, run a swap end to end (lock, watch, claim) and get coins back on timeout (refund), with the state saved so a
restart resumes. Pairs: DIVI with BTC, LTC, ZEC, USDC and XMR, the same as `divi-swap` today. Testnet by default;
mainnet only with the same explicit opt-in the CLI has. The maker (`divi-swapd`) is not part of the library.

**Built from what exists.** `crates/divi-swap` (engine, state machine, store with the schema marker),
`crates/swap-adaptor` (XMR adaptor signatures) and `crates/swap-chain-{divi,btc,ltc,zec,evm,xmr}` (chain backends).
The `divi-swap` CLI becomes the first user of the library, so the library is proven by the same tests.

**API surface (first cut).**
- `MakerClient`: `offers()`, `quote(offer, amount)`, `swap_status(id)`.
- `Swap`: `start(quote, keys)`, `step()` (advance one state; safe to call again after a crash), `claim()`,
  `refund()`, `status()`, events for each state change.
- `Store` trait with the SQLite store as default and an in-memory one for tests; the app can bring its own
  (IndexedDB in browsers, the platform store on phones).
- `ChainBackend` trait per coin, with the existing Esplora/RPC/light-client backends as defaults.
- Keys: the library never stores or exports a key. The wallet hands in a signer callback (sign this tx / this
  message), so keys stay inside the wallet that already guards them.

**Language and packaging.**
1. Rust crate (core).
2. WebAssembly + TypeScript package for the web wallet, the browser extension and the Telegram Mini App (all are
   JavaScript). XMR needs a Monero wallet that may not fit in a browser; the first JS release may leave XMR out
   and say so.
3. Kotlin and Swift bindings (UniFFI or the C ABI the mobile wallet already uses for its crypto library).

**License (decision for Human, a yes/no card before the repo goes public).** IronDivi is AGPL-3.0 with a commercial
license; AGPL in a library makes most wallets unable to use it. Recommended: the library alone under a permissive
license (MIT or Apache-2.0); Human owns the code so he can relicense it. Alternatives: keep AGPL + commercial, or
LGPL.

**Steps to a public repo.**
- [ ] 10.1 Split the library into its own crate set with the API above; `divi-swap` CLI uses it (private repo).
- [ ] 10.2 WASM/TypeScript package and the mobile bindings build and pass the same swap tests on testnet (private).
- [ ] 10.3 New **private** repo with a fresh history (no IronDivi history, no deploy files, no hostnames or
  keys); secret scan; license files; README with a testnet example.
- [ ] 10.4 Security review of the library (key handling, refund timing, untrusted maker data).
- [ ] 10.5 **CARD (Human yes/no): license choice.**
- [ ] 10.6 **CARD (Human yes/no): make the library repo public.** A new repo only. The swap code lives in the private swap repo (`bshuler/IronDivi`) and stays there until this card; the public `DiviDomains/IronDivi` node repo is not changed by it.
- [ ] 10.7 **CARD (Human yes/no): publish the packages** (crates.io, npm, Maven/Swift package), testnet default.

## 11. Swap built into every IronDivi wallet (Human 2026-10-22 21:30: "publish this integrated into all the wallets, IronDivi Web, Browser, Telegram")

Status 2026-10-22: **planned only.** Nothing built, nothing released. Each wallet uses the §10 library; no wallet
gets its own copy of the swap logic.

**The wallets (found 2026-10-22 by reading the repos).**

| # | Wallet | Where the code is | Notes |
|---|---|---|---|
| 1 | IronDivi Web wallet | `DiviDomains/divi-infrastructure` `divi-wallet/` (live at `https://services.divi.domains/wallet/`) | Plain JS PWA; shares `packages/divi-vault` and `packages/shared-ui` with the Telegram Mini App. |
| 2 | Browser extension | `bshuler/irondivi-browser-extension` | Chrome, Firefox and Safari (Safari ships inside a small macOS app). TypeScript. |
| 3 | Telegram Mini App | `divi-infrastructure` `services/telegram-wallet-app/` | Vite JS app opened from Telegram. |
| 4 | Telegram bot | `divi-infrastructure` `services/telegram-bot/` | Chat commands; swap as commands (quote, status, claim, refund) per the bot command-parity design. |
| 5 | Mobile wallet | `bshuler/divi-mobile-wallet` | Android (Kotlin/Compose) and iOS (SwiftUI), native C crypto, SPV. |
| 6 | Command line | IronDivi `irondivi-cli` / `irondivid` wallet, and the `divi-swap` CLI | `divi-swap` is already the swap app; the node wallet gets swap RPCs that call the library. |

Not in the list: the PrivateDivi extension (`divi-infrastructure/pdivi-extension`) is a different coin; the old
Divi Core desktop app is not an IronDivi wallet. There is no IronDivi desktop wallet today; if one is built, swap
ships in it too.

**What each wallet gets.** A Swap screen (or bot commands): pick a coin, see the quote, confirm, watch progress,
claim; refund offered automatically after the timeout; swaps resume after the app restarts. Testnet first with the
same "practice network" banner as the website; mainnet only after the existing mainnet cards.

**Steps per wallet (W = 1..6 above).**
- [ ] 11.W.1 Integrate the §10 library behind a testnet-only switch (private branch).
- [ ] 11.W.2 End-to-end test: a full swap and a refund against the testnet maker, in that wallet's own test rig
  (Playwright for web, extension and Mini App; bot test harness; Android/iOS UI tests; CLI scripts).
- [ ] 11.W.3 Security review of the wallet's swap screen (approval prompts, what a web page can trigger in the
  extension, untrusted maker data).
- [ ] 11.W.4 **CARD (Human yes/no): release this wallet with swap** (web deploy, each browser store, Telegram app
  deploy, each phone store, CLI release). One card per wallet and store.

**Order.** Web wallet and Telegram Mini App together (shared packages), then the browser extension, then the
Telegram bot, then mobile, then the CLI RPCs. Any release before §10.6 means the wallet ships the library inside
its own build; the library repo still stays private until its own card.
