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

**Mechanism:** one headless background session per lane, each in its own git worktree, running
**Sonnet** via the narrow profile (`context-budget.md` §2.5 rule 13), launched with `claude_auto`
(`working-with-bert.md` §9). The orchestrator starts each with Bash `run_in_background` so it is
notified on exit and never polls. Exact launch command: `docs/plans/swap-poc/orchestrator.md`.

Rules every lane follows:

- **Owns paths, not files it shares.** A lane edits only the directories listed for it. Wave 0
  pre-registers every workspace member and every dependency in the root `Cargo.toml`, and commits
  `Cargo.lock`, so lanes never touch either. A lane that needs a new dependency writes it to its
  status file; the orchestrator adds it.
- **Lands on `main` at each verified seam:** `cargo fmt && cargo clippy -p <crate> -D warnings &&
  cargo test -p <crate>` green → commit (as Bert, no AI attribution) → `git pull --rebase origin main`
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
| 0.5 | Fund engine keys: testnet DIVI from the vps1 faucet (`:19150`, via tailnet or ssh) or the dnsdivi testnet node wallets; signet BTC from a public signet faucet | maker ≥ 5,000 tDIVI, taker ≥ 0.01 sBTC. **If no faucet dispenses, this is the one question for Bert** |
| 0.6 | Store keys in 1Password (`IronDivi Swap POC` items), resolver in `divi-swap::secrets` | `op read` at runtime works; nothing on disk |
| 0.7 | Write lane briefs `docs/plans/swap-poc/lanes/*.md` and `tools/swap-poc/check-*.sh` | each check script fails before work starts (proves it can fail) |

### Wave 1 — parallel lanes (5 background sessions, Sonnet)

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

### Wave 2 — integration on testnets (2 background sessions)

| Lane | Work | Acceptance |
|---|---|---|
| **e2e-local** | Run maker `divi-swapd` and taker CLI **locally** against real testnet + signet. Happy path, case C, case D. Script: `tools/swap-poc/e2e.sh <scenario>`; runs in background with a Monitor on the swap DB state. | Three scenarios complete; txids in RESULTS.md. Case C takes ~6 h wall clock — runs in the background while the next item proceeds. |
| **chaos** | Kill/restart `divi-swapd` at each state transition during real testnet swaps; proxy outage (block the RPC host) mid-swap; Esplora 429s. | Every run ends `Done` (claimed or refunded); no stuck funds. |

### Wave 3 — deploy to dnsdivi and prove there (orchestrator; needs Bert present once)

1. **Parked for a human turn:** SSH to dnsdivi uses the 1Password SSH agent key (`dnsdivi_ssh`);
   service secret provisioning needs `op`. Batch both into one sitting (`working-with-bert.md` §8).
2. `deploy.sh` → build release, install unit, start, `curl https://<host>/swap/healthz`.
3. Rerun `e2e.sh happy` with the **deployed** maker; then case C in the background.
4. Write RESULTS.md, update the promo page's "Status" line only if every §1 item is proven.

## 6. Known blockers and how lanes handle them

| Blocker | Handling |
|---|---|
| **Commit signing needs 1Password** (`op-ssh-sign`) | Launch lanes while Bert is present and 1Password is unlocked so the agent's approval is remembered. If a signing prompt can't be answered, the lane parks per `secret-management.md` §7.1: stage, write the message to `docs/plans/swap-poc/parked/<lane>-<n>.msg` (outside nothing secret), keep working, and leave one command (`git commit -F <file>`). Never `--no-gpg-sign`. |
| **Push 403 / `Repository not found`** — default gh account is `bshuler`, repo needs `DiviDomains` | Already applied to this clone (2026-10-07), shared by every worktree: repo-local `credential.https://github.com.helper` that answers `username=DiviDomains` and `password=$(gh auth token -u DiviDomains)` (token from gh's keyring at call time; never on disk or argv). **Never `gh auth switch`** — it is global and races between lanes. Fresh clone: `git config --local --replace-all credential.https://github.com.helper ''` then `--add` the helper shown by `git config --local --get-all credential.https://github.com.helper` here. |
| Testnet address/spent index missing | Block-scan design (§2); no dependency. |
| No testnet DIVI | Wave 0.5; only legitimate question to Bert. |
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
