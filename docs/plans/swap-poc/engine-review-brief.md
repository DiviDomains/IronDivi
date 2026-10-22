# Shared swap engine — outside security-review brief

State of this document: 2026-10-22, builder AT, written against commit **88c85b2**
(`private/signed/main`). Every `path:line` below was opened on that commit. A statement that could
not be checked is marked `could not verify`. If the tree has moved, re-anchor with
`git diff 88c85b2..HEAD -- crates/divi-swap crates/swap-chain-* bin/` and re-open the cited lines.
Since 88c85b2, `private/signed/main` (d433f25) changed three in-scope files that were **not** re-verified here: `bin/divi-swap/src/main.rs`, `bin/divi-swapd/src/main.rs`, `crates/divi-swap/src/store.rs` (a fourth change, in out-of-scope `crates/swap-chain-xmr/src/live_rpc.rs`, is irrelevant). Line numbers into those files may have shifted.
This is a docs-only brief: nothing in code, confirmation counts, timeouts or margins was changed.
No funds, keys, wallets or swaps were used to produce it.

Shape follows `xmr-review-brief.md`. The XMR adaptor-swap crates are **out of scope here**; they have
their own brief.

## 1. Purpose and scope

We want an outside reviewer to look for ways to lose funds, or to be tricked into a bad swap, in the
shared HashLock (HTLC) engine that moves DIVI against BTC, LTC, ZEC and USDC (EVM). The first funded
mainnet swap is gated on this review (`mainnet-readiness.md`, "Left before a funded mainnet swap").

| In scope | Path | LOC | `#[test]` fns (grep) |
|---|---|---|---|
| Engine: state machine, HTLC script, maker, taker, profile/floor checks, config, persistence, secrets, mock | `crates/divi-swap` | 8214 | 92 |
| Daemon (maker HTTP service, scheduler, config, mainnet gates) | `bin/divi-swapd` | 5394 | 89 |
| CLI (taker; package `divi-swap-cli`) | `bin/divi-swap` | 3142 | 46 |
| Chain backends | `crates/swap-chain-btc` | 2212 | 34 |
| | `crates/swap-chain-ltc` | 2955 | 55 |
| | `crates/swap-chain-zec` | 4482 | 38 |
| | `crates/swap-chain-evm` (USDC) | 2195 | 25 |
| | `crates/swap-chain-divi` | 2197 | 22 |

LOC is raw `.rs` lines. Real `cargo test` counts are in §6.

| Out of scope | Why |
|---|---|
| `crates/divi-swap-xmr`, `crates/swap-chain-xmr` | `xmr-review-brief.md` |
| The `Erc20Htlc` Solidity contract | internal pre-audit `usdc-htlc-preaudit.md`; outside audit still open (readiness line 10). The Rust backend that talks to it **is** in scope. |
| `divi-core` consensus, node, wallet | not part of the swap engine |
| Key custody (1Password, `secret` / `secret-broker`) | only the call site `secrets.rs:52` is in scope |

## 2. Protocol summary

Roles. The **taker** generates a 32-byte random preimage (`htlc.rs:137`, `rand::random`) and sends
only its SHA-256 `hash`. The **maker** quotes and cannot choose the hash. Each quote has a
`Direction`; `quote.taker_chain()` carries the taker leg and `quote.maker_chain()` the maker leg
(`api.rs`, `Quote`). Both directions use identical logic (the engine tests run each twice, `FWD` and
`REV`).

HTLC script (`htlc.rs:116-128`):
`OP_IF OP_SHA256 <h> OP_EQUALVERIFY <claim_pk> OP_ELSE <locktime> OP_CLTV OP_DROP <refund_pk> OP_ENDIF OP_CHECKSIG`.
Locktimes are unix times (`LOCKTIME_THRESHOLD` 500,000,000, `htlc.rs:49`), compared to median time
past (MTP). The refund input uses sequence `0xfffffffe` (`htlc.rs:53`). `HtlcParams::validate`
(`htlc.rs:73-91`) rejects height-style locktimes and uncompressed keys. There is **no
`OP_SIZE` check** on the preimage; see Q3.

Sequence (who funds first):

1. Maker `quote` (`maker.rs:205`) — no coins reserved.
2. Taker `prepare` (`taker.rs:120`) — checks the quote against its own profile floor
   (`taker.rs:121-128`), generates and persists the preimage.
3. Maker `accept` (`maker.rs:252`) — records `Accepted`; builds the **taker-leg** HTLC with
   `locktime = taker-chain MTP + taker_timeout` (`maker.rs:277-285`).
4. Taker `accepted` (`taker.rs:160`) — re-checks hash, both keys, quote match, and that the locktime
   is within ±1800 s of its own taker-chain MTP + `taker_timeout` (`taker.rs:191-194`).
5. Taker `lock` (`taker.rs:202`) — **taker funds first**, write-ahead (tx persisted, then broadcast),
   then notifies the maker (`maker.rs:322`, `notify_lock`).
6. Maker `on_taker_lock_confirmed` (`maker.rs:553-584`) — re-reads amount and confirmations from the
   chain, checks the window is long enough, builds the **maker-leg** HTLC with
   `locktime = maker-chain MTP + maker_timeout`, records `maker_mtp_at_lock`.
7. Maker `on_maker_locked` (`maker.rs:586-606`) — coin selection and funding broadcast happen **only
   on this edge** (`MakerLocked`).
8. Taker `on_locked` (`taker.rs:366-459`) — verifies the maker HTLC (hash, keys), amount and
   confirmations on the chain (`htlc_output`), declines if too close to expiry, applies the two
   maker-leg floors (§3.5), then `on_maker_lock_confirmed` (`taker.rs:461`) and `on_claimed`
   (`taker.rs:484`): the taker claims the maker leg, **revealing the preimage on chain**.
9. Maker `revealed_preimage` (`maker.rs:725-741`) finds the spend with `find_spend`, extracts the
   preimage (hash-verified) and claims the taker leg (`on_taker_claimed`, `maker.rs:660`).
10. Refunds: after its locktime each side refunds its own leg (`maker.rs:619` `on_maker_refundable`;
    `taker.rs:266` `refund`, `taker.rs:523` `on_refunded`). The taker leg has the **longer** timeout.

Maker states (`state.rs:89-111`): Quoted → Accepted → TakerLockSeen → TakerLockConfirmed →
MakerLocked → MakerLockConfirmed → {TakerClaimed → MakerClaimed → Done | MakerRefundable →
MakerRefunded → Done}, with `Aborted` exits before `MakerLocked`. Taker states: Prepared → Accepted →
Locked → MakerLockConfirmed → Claimed → Done, or Refunded → Done.

Timeout schedule (`config.rs:104-130`, `required_gap_secs` at `:175`): mainnet taker 24 h / maker
12 h, claim margin 3600 s, quote expiry 60 s; testnet 6 h / 3 h, margin 1800 s. Required gap
between legs = `max(3 h, 2 × max MTP lag + claim_margin)`; `SwapConfig::validate` (`config.rs:189-208`)
refuses a config below it.

Confirmation counts, from `ChainParams::builtin` (`config.rs:50-75`):

| Chain | Mainnet | Testnet |
|---|---|---|
| BTC | 2 | 1 |
| LTC | 6 | 2 |
| ZEC | 10 | 9 |
| DIVI | 10 | 3 |
| USDC | 12 | 3 |
| XMR (out of scope) | 10 | 10 |

## 3. Security invariants

Each row: the invariant, the enforcing code, the proving test. "none" means no test; that is itself
a finding for the reviewer. Integration tests are in `crates/divi-swap/tests/`; unit tests sit next
to the code.

### 3.1 Taker profile floors

| Invariant | Code | Test |
|---|---|---|
| A taker with a profile floor refuses a quote whose confirmation depths, timeouts or timeout gap are below its profile | `check_terms_against_profile` `config.rs:318-375`, called from `taker.rs:121-128` | `each_confirmation_depth_below_the_floor_is_refused_per_profile` (`config.rs:703`), `a_shorter_timeout_than_the_floor_is_refused_per_profile` (`:734`), `a_timeout_gap_below_the_floor_is_refused_per_profile` (`:765`), `a_taker_timeout_below_the_maker_timeout_is_refused_not_wrapped` (`:797`), `terms_exactly_at_the_profile_floor_are_accepted` (`:667`) |
| A mainnet taker refuses a testnet maker, in both directions, and nothing is persisted on refusal | same | `mainnet_taker_refuses_a_testnet_maker_in_either_direction`, `refusal_happens_before_anything_is_persisted` (`tests/taker_profile_floor.rs:60,75`) |
| A stronger maker is fine; a taker built **without** a floor takes the terms as offered (opt-in, see Q5) | `taker.rs:101` `with_profile_floor` | `taker_accepts_a_maker_on_its_own_profile`, `testnet_taker_accepts_a_stronger_mainnet_maker`, `a_taker_without_a_floor_takes_the_terms_as_offered` (`taker_profile_floor.rs:83,92,99`) |

### 3.2 Maker-leg locktime floor and MTP bound

| Invariant | Code | Test |
|---|---|---|
| Tolerant floor: `maker_locktime ≥ taker_locktime − quoted gap − 1800 − max MTP lag` | `check_maker_leg_locktime` `config.rs:393-419`; applied `taker.rs:423` | `maker_leg_locktime_floor_per_profile` (`config.rs:841`); `a_maker_that_quotes_strong_but_locks_short_is_declined_and_refunded` (`tests/taker_maker_leg_floor.rs:128`) |
| Exact floor when the maker states `maker_mtp_at_lock`: stated MTP bounded below by `taker_locktime − taker_timeout − tol − lag` and above by `observed_maker_mtp + lag`; locktime ≥ `stated_mtp + maker_timeout` | `check_maker_leg_locktime_exact` `config.rs:437-483`; applied `taker.rs:438` | `maker_leg_locktime_exact_floor_at_below_above_per_profile_and_direction` (`config.rs:891`), `maker_leg_locktime_exact_refuses_an_implausible_stated_mtp` (`:916`), `a_maker_that_states_its_mtp_but_locks_short_inside_the_old_tolerance_is_now_declined`, `an_implausible_stated_mtp_is_refused_with_a_named_reason` (`tests/taker_maker_leg_exact.rs:200,289`) |
| Taker declines to claim, persisting `claim_declined`, if the maker-leg locktime is under 1800 s (`TAKER_SAFETY_MARGIN_SECS`, `taker.rs:34`) past the maker chain MTP | `taker.rs:407` | `taker_declines_a_maker_lock_too_close_to_its_locktime` (`tests/taker_decline.rs:54`) |
| Maker refuses to lock when the taker leg's remaining window is under `maker_timeout + claim_margin` | `lock_window_gone` / `taker_window_too_short` `maker.rs:481-493` | `maker_aborts_too_short_window`, `rev_maker_aborts_too_short_window`, `maker_locks_window_fine` (+`rev_`) (`tests/engine.rs:1184,1189`) |

Note: the exact floor trusts the maker's *self-stated* MTP, bounded only by the plausibility window
above. See Q2.

### 3.3 Timelock ordering between legs

| Invariant | Code | Test |
|---|---|---|
| `taker_timeout > maker_timeout` by at least the required gap; a config that violates it does not load | `SwapConfig::validate` `config.rs:189-208`; maker `with_counters` `maker.rs:102` | `lag_dominates_gap` (`config.rs:498`), `both_profiles_valid` (`:492`), `timeout_invariant_enforced` + `rev_` (`tests/engine.rs:752`) |
| Taker-leg locktime accepted by the taker only within ±1800 s of its own MTP + taker_timeout | `taker.rs:191-194` | `could not verify` a dedicated test for the ±1800 bound (covered only indirectly by the engine happy path) |
| Locktimes are built from the chain's own MTP, not wall-clock | `maker.rs:277`, `maker.rs:553-584` | engine mock tests (`tests/engine.rs`); `could not verify` against a real chain whose MTP lags wall-clock |

### 3.4 Confirmation counts per chain

| Invariant | Code | Test |
|---|---|---|
| Maker waits `confirmations(taker_chain)` on the taker leg before locking; taker waits `confirmations(maker_chain)` on the maker leg before claiming | `taker_leg_confs` / `maker_leg_confs` `maker.rs:464-470`, check at `maker.rs:528`; `taker.rs:397-405` | `no_coin_selection_before_taker_lock_confirmed` + `rev_` (`tests/engine.rs:721`) |
| Counts come from `ChainParams::builtin` for the chosen profile; a chain **missing** from `cfg.chains` falls back to the *mainnet* built-in | `config.rs:50-75`; `cfg.confirmations()` | `each_confirmation_depth_below_the_floor_is_refused_per_profile` (`config.rs:703`). Fallback behaviour: `could not verify` a test |
| The count the chain backend returns is trusted; BTC/LTC derive it from the same explorer's tip (`confs_from_status`) | `swap-chain-btc/src/lib.rs:473-513`; `swap-chain-ltc/src/lib.rs:527-566` | none against a lying backend (§4) |

### 3.5 Mainnet opt-in (`allow_mainnet`)

| Invariant | Code | Test |
|---|---|---|
| A mainnet profile with any test network is refused; a testnet profile with any mainnet network is refused; a mainnet profile needs `allow_mainnet = true` | `check_profile_networks` `config.rs:236-265`, `is_mainnet_network` `:215` | `mainnet_profile_refuses_a_test_network_for_every_coin` (`config.rs:606`), `testnet_profile_refuses_a_mainnet_network_for_every_coin` (`:620`), `mainnet_profile_without_allow_mainnet_is_refused` (`:638`) |
| Daemon applies it at config load, per coin | `bin/divi-swapd/src/config.rs:614-760` (`validate_mainnet_gate` and the per-coin checks; `check_profile_networks` call at `:747`) | `divi_mainnet_without_allow_mainnet_is_rejected` (`bin/divi-swapd/src/config.rs:843`) and the sibling BTC/LTC/ZEC/USDC config tests in that file |
| CLI applies it before any network call | `bin/divi-swap/src/main.rs:492`, `:688` | `could not verify` a CLI-level test by name |
| Daemon default bind is loopback | `bin/divi-swapd/src/config.rs:320` (`127.0.0.1:8480`); bind at `main.rs:540` | none |

### 3.6 Preimage handling

| Invariant | Code | Test |
|---|---|---|
| Only the taker knows the preimage until its own claim; the maker learns it from the chain spend | `htlc.rs:137`; taker stores it in `TakerRecord` (`taker.rs:120-156`); maker takes it from `revealed_preimage` `maker.rs:725-741` | `preimage_hash_matches` (`htlc.rs`) proves hash correspondence only. **No test proves the preimage never leaves the taker before `Claimed`.** |
| A preimage extracted from a spend must hash to the swap hash | `maker.rs:725-741` (`extract_preimage(&r.hash)`) | engine happy path and `case_d_late_claim` (`tests/engine.rs:573`) |
| `SwapView` carries the preimage only after `taker_claimed` | `api.rs:286-306`, `maker.rs:750` `view_of` | `could not verify` a test that a pre-claim view has `preimage: None` beyond the happy path |
| The CLI does not print or log the preimage | `grep preimage bin/divi-swap/src/*.rs` finds no use outside a test fixture (`txids.rs:126-133`) | none; `could not verify` the full text of the taker status output |
| The preimage is stored in plaintext SQLite (§3.8) | `store.rs` | — |
| The HTLC has no `OP_SIZE` length check | `htlc.rs:116-128` | none; see Q3 |

### 3.7 Secret handling (no seed, WIF or RPC password in logs or argv)

| Invariant | Code | Test |
|---|---|---|
| Keys and passwords are resolved into memory at startup via `secret get --name <name> --op-ref <ref>` (arguments are non-secret names/refs) or a systemd credential file; the value is `Zeroizing` and errors never contain it | `secrets.rs:52-96` | `parse_refs`, `cache_names` (`secrets.rs:124,132`) test parsing only; **no test asserts a secret is absent from argv or logs** |
| Daemon `tracing::` calls log addresses, networks and counts, not key material | `bin/divi-swapd/src/main.rs:226,246,281,297,341,375,441,543`. Note `main.rs:341` logs `token = %token_str`, which is the **ERC-20 contract address**, not a credential. | none; `could not verify` every `tracing::` call in the backends and `divi-swap` bins (only the daemon `main.rs` was read) |
| Error strings from `secret get` include its stderr | `secrets.rs:64-68` | `could not verify` that stderr from `secret` can never contain a value |

### 3.8 Persistence and crash recovery

| Invariant | Code | Test |
|---|---|---|
| Every signed tx is persisted before broadcast; steps are idempotent so a restart re-broadcasts the same bytes | `taker.rs:202-233`, `maker.rs:586-606`, `Store::put_*` `store.rs:198-330` | `broadcast_after_persist` (`tests/engine.rs:862`), `crash_at_every_maker_state`, `crash_at_every_taker_state` (+`rev_`) (`:595,618`), `prop_random_crash_points`, `rev_prop_random_crash_points` (`:675,686`) |
| A rejected broadcast (`Rejected`) causes a re-sign, for each of the four spend kinds | `taker.rs:484-521`, `maker.rs:619-690` | `resign_maker_refund`, `resign_maker_claim`, `resign_taker_refund`, `resign_taker_claim` (+`rev_`) (`tests/engine.rs:1002-1017`) |
| Refund never claims; refund after timeout reaches Done; refund on an already-claimed swap does nothing | `taker.rs:266`, `taker.rs:294` | `refund_never_claims`, `refund_after_timeout_reaches_done`, `refund_on_claimed_does_nothing` (+`rev_`) (`tests/engine.rs:1101-1111`) |
| Old records still load | `serde(default)` fields | `forward_records_still_load` (`tests/engine.rs:1203`), `v025_records_still_load` (`tests/multichain.rs:243`) |
| Store file and its WAL/SHM files are mode 0600; `synchronous=FULL`, `journal_mode=WAL` | `store.rs:171-182`, `:366-376` | `store_file_mode_0600` (`store.rs:517`) |
| State transitions are validated; coins are reserved only on the `TakerLockConfirmed → MakerLocked` edge | `state.rs:76-111`, `maker.rs:408` `enter` | `no_coins_before_maker_locked`, `terminal_states_have_no_exits` (`state.rs`) |
| Maker and taker steps are serialized by a `tokio` mutex | `gate`: `maker.rs:324,363`; `taker.rs:161,203,239,267` | none directly |
| **`Maker::accept` takes the gate** (fixed on lane/maker-accept-serialized, see status/engine.md 2026-10-22; was F1) | `maker.rs:252-319` | `tests/maker_accept_race.rs` (fails on the base, passes with the gate) |
| The preimage, hashes and keys are stored in plaintext in the DB (file mode 0600 only) | `store.rs` schema | `could not verify` host-level disk encryption on any deployment |

### 3.9 Daemon HTTP surface, auth and rate limits

Routes (`bin/divi-swapd/src/routes.rs:200-240`):

| Route | Auth | Rate limit |
|---|---|---|
| `GET /healthz`, `GET /offers` | none | none |
| `GET /offers/:id/quote` | none | per-IP, 20 per 60 s (`routes.rs:46-55`, `:122`) |
| `POST /swaps` (accept), `POST /swaps/:id/lock` | **none** | per-IP, 20 per 60 s, one shared write bucket (`WRITE_LIMIT_PER_WINDOW`); fixed on lane/route-rate-limits, see status/engine.md 2026-10-22 |
| `GET /swaps` (**lists every swap**), `GET /swaps/:id` | **none** | per-IP, 300 per 60 s, one shared read bucket (`READ_LIMIT_PER_WINDOW`); fixed on lane/route-rate-limits, see status/engine.md 2026-10-22 |
| `POST /xmr/swaps` (setup, XMR only) | none | per-IP |
| `/xmr/swaps/:id` and `/j`, `/sigs`, `/xmr-lock` (XMR only) | swap token in `X-Swap-Token` (`swap_token_gate`, `routes.rs:138`); a missing, wrong or unknown token returns the same 404 as an unknown id | per-IP on setup only |

The "C3 token" covers the XMR routes **only**. The hashlock engine routes above have no
authentication: anyone who can reach the port can list swaps, read a `SwapView` by id, and call
`accept` and `lock`. A `SwapView` (`api.rs:286-306`) holds the quote, both HTLC descriptions (hash,
public keys, locktimes), state, `last_error`, and the preimage after the taker has revealed it. It
holds no key. Impact of unauthenticated reads and of `lock`: Q4.

Rate limiter (`routes.rs:55-100`): fixed window per IP, at most 10,000 tracked IPs; when full and the
IP is new it **refuses** (fails closed). Key is the socket peer unless `trust_proxy_headers = true`
(`routes.rs:102-120`); with it, the **last** `X-Forwarded-For` entry (the one the proxy wrote), fixed on lane/route-rate-limits, see status/engine.md 2026-10-22.

| Invariant | Code | Test |
|---|---|---|
| Limiter counts per IP per window | `routes.rs:55-100` | `the_limiter_counts_per_ip_per_window` (`routes.rs:414`) |
| Proxy headers are ignored unless trusted; garbage falls back to the peer | `routes.rs:102-120` | `proxy_headers_are_ignored_unless_trusted`, `trusted_proxy_headers_pick_the_client_and_garbage_falls_back` (`routes.rs:437,455`) |
| Request errors map to statuses; secrets never in `ApiError` | `routes.rs:259-285` | `could not verify` |

Deployment (`DECISIONS.md` #10): the maker is public at `https://divi.cx/swap/` behind nginx.
`deploy/divi-swapd/nginx-swap.conf:8-9` sets `X-Real-IP $remote_addr` and
`X-Forwarded-For $proxy_add_x_forwarded_for`. With `trust_proxy_headers` **off** (the default; only a
commented example exists in `divi-swapd.toml.example:5`) every client shares the proxy's address and
one 20-per-minute bucket (see F4). With it **on**, `$proxy_add_x_forwarded_for` *appends* to a
client-supplied `X-Forwarded-For`, and the limiter used to read the **first** entry, which a client controls (fixed on lane/route-rate-limits, see status/engine.md 2026-10-22: the snippet now sets `X-Forwarded-For $remote_addr` and the limiter reads the last entry).
`deploy/divi-swapd/README.md:67-70` already says to use `$remote_addr` instead. Whether the live
deployment sets `trust_proxy_headers`: `could not verify` (no access to the host).

## 4. Threat model

For each adversary: what they can do, what stops them, what the reviewer should attack.

**Malicious maker.**
- Quotes strong terms and locks weak or short: stopped by the taker floors (§3.1), the two maker-leg
  floors (§3.2) and the claim-decline margin. Residual: the exact floor relies on a self-stated MTP
  (Q2).
- Locks the wrong amount, wrong hash or wrong keys: the taker re-reads the output with `htlc_output`
  (`taker.rs:397-405`); every backend compares `scriptPubKey` (BTC `lib.rs:487`, LTC `:541`, ZEC
  `:507`, DIVI `:550`) or, for EVM, the `Locked` event's sender, receiver, token, hashlock and
  timelock (`swap-chain-evm/src/backend.rs:496-541`).
- Never locks: taker refunds after its locktime (`taker.rs:266`).
- Learns the preimage early: it is never sent to the maker; the only path is an on-chain spend.

**Malicious taker.**
- Quotes then never funds: maker reserves no coins before `TakerLockConfirmed` (§3.8); quotes expire
  in 60 s on mainnet.
- Funds, then claims the maker leg and does not let the maker claim: the maker reads the preimage from
  the chain spend (`maker.rs:725`) and claims within its window (`taker_window_too_short`).
- Replays a hash or a quote: `accept` refuses a used quote and a reused hash, and now atomically: fixed on lane/maker-accept-serialized, see status/engine.md 2026-10-22 (F1). No unique index on the hash.
- Funds too little or with too few confirmations: the maker re-checks amount and confirmations on
  `TakerLockConfirmed` (`maker.rs:553-584`).

**Lying or stale chain backend (a single explorer, node or gRPC server).**
- Every chain view comes from one source per chain. A backend that over-reports `confirmations`, hides
  a spend, or reports a wrong MTP can make the engine act early or late. The engine does not
  cross-check any source except the **LTC tip hash** (`swap-chain-ltc/src/crosscheck.rs`, opt-in, tip
  hash at `H-6` only, "it changes no confirmation count, lag or timeout").
- LTC mainnet has one Esplora URL (`swap-chain-ltc/src/lib.rs:75`, `mainnet-readiness.md:97-98`).
- BTC MTP is the tip block's `mediantime` from Esplora (`swap-chain-btc/src/lib.rs:362-372`); the
  engine trusts it for every locktime.
- `htlc_output` does not report whether the output is already spent; spend discovery is a separate
  `find_spend`.
- `could not verify` ZEC and EVM MTP derivation against an independent node.

**Reorg.**
- Depth is the only protection (no finality signal). DIVI uses 10 confirmations; the open question is
  whether 20 is wiser (`divi-confirmations.md`, §5). The deepest DIVI reorg could not be observed (the
  public endpoint offers no `getchaintips`): `could not verify`.
- After `MakerLockConfirmed` the maker does not re-broadcast its funding tx if it is reorged out:
  `on_maker_lock_confirmed` (`maker.rs:608-617`) only looks for a revealed preimage and a timeout. The
  taker side re-broadcasts in `on_locked` (`taker.rs:366-459`). No test covers a reorg of the maker
  lock after confirmation: `could not verify` the scheduler does not recover this elsewhere.
- Locktimes use MTP, which can lag the tip; the required gap includes `2 × max MTP lag`.
- The proposed maker re-broadcast after a reorg is written up in `maker-rebroadcast-design.md` (design only, no code).

**Hung endpoint / outage.**
- Errors are `SwapError::Transient` and the step is retried; no state is advanced on an error. A long
  outage near a locktime is the risk (taker: `claim_declined`; maker: `MakerRefundable`).
- `could not verify` per-request timeouts for each backend client.

## 5. Known findings and open decisions

Linked, not restated.

| Item | Where |
|---|---|
| DIVI mainnet confirmations 10 vs 20 | `divi-confirmations.md` §5 (proposal for Bert; not decided, **not applied**) |
| XMR `L` (`maker_mtp_trail_secs`) value | `status/engine.md`, round "xmr-prepare-mtp-floor (builder AP)" (`needs: Bert`); XMR crates, not this scope |
| LTC has a single data source | `mainnet-readiness.md:97-98` |
| Deepest DIVI reorg unknown | `divi-confirmations.md` §2 and §5 |
| USDC contract outside audit | `usdc-htlc-preaudit.md`, `mainnet-readiness.md:10` |

New observations from this review (each also a `left:` line in `status/engine.md`); none is fixed:

- **F1 — `Maker::accept` was not serialized (fixed on lane/maker-accept-serialized, see status/engine.md 2026-10-22; the text below is the finding as reviewed; what remains: no unique index on the hash, by design, see the status round).** `maker.rs:252-319` does not take `gate`. It checks
  `qr.used` and scans `list_maker_swaps()` for the hash, then awaits `median_time_past()`
  (`maker.rs:276`), then writes `qr.used = true`. Two concurrent accepts of one quote can both pass.
  `maker_swaps` has no unique index on the hash. The daemon route calls it straight
  (`routes.rs:340-345`). Our assessment, to be confirmed (Q1): the taker holds the preimage and coins
  reserve only at `MakerLocked`, so this reads as a duplicate-record and accounting defect rather than
  a theft path. No test: `could not verify` any test of quote reuse.
  2026-10-22 (lane/accept-gate-bounds): the gate's chain read is now bounded and `maker_swaps` has a unique index on the hash; see status/engine.md 2026-10-22 accept-gate-bounds.
- **F2 — no maker re-broadcast after the maker lock confirms.** See §4 (Reorg).
- **F3 — no `OP_SIZE` preimage-length check in the script** (`htlc.rs:116-128`). Exploitable with the V0 script: the taker (any client, not ours) picks a non-32-byte preimage; every script leg claims with it but our maker code is 32-byte only, so the maker cannot claim the taker leg. Partly fixed on lane/preimage-size, see status/engine.md 2026-10-22: `ScriptVersion::V1` (`OP_SIZE 32 OP_EQUALVERIFY`) exists and is proven; it is not yet used for new swaps (needs `maker.rs`/`store.rs`, left). Q3 answered.
- **F4 — rate limiting.** Default config puts every client behind nginx in one bucket; the shipped nginx
  snippet was wrong for `trust_proxy_headers = true` (§3.9). Only `quote` was limited; `accept`, `lock`,
  `GET /swaps` and `GET /swaps/:id` now are too, and the limit keys on the address nginx sets (fixed on lane/route-rate-limits, see status/engine.md 2026-10-22).
- **F5 — hashlock engine routes are unauthenticated**, including a full swap listing (§3.9).
- **F6 — confirmation fallback.** A chain absent from `cfg.chains` takes the *mainnet* built-in count
  (more conservative than testnet; confirm it can never be less conservative). Result: pinned on lane/conf-fallback-reorg-design, see status/engine.md 2026-10-22.
- **F7 — plaintext preimage and keys-adjacent data in SQLite**, protected by file mode only.

## 6. Build and test

On a Linux host with a Rust toolchain (the repo pins it). Run cargo only on a build host and run
`df -h /` first; the target dir is large.

```sh
git checkout 88c85b2
export CARGO_BUILD_JOBS=12
nice -n 10 cargo test --no-fail-fast \
  -p divi-swap -p divi-swapd -p divi-swap-cli \
  -p swap-chain-btc -p swap-chain-ltc -p swap-chain-zec -p swap-chain-evm -p swap-chain-divi
cargo fmt --all --check
```

Results on 88c85b2, hp3 (recorded 2026-10-22):

`cargo test --no-fail-fast` exited 0. `cargo fmt --all --check` exited 0. Passed / failed / ignored,
per package (unit, integration and doc-tests):

| Package | Passed | Failed | Ignored | Notes |
|---|---|---|---|---|
| `divi-swap` | 178 | 0 | 0 | lib 44; `engine` 93; `multichain` 10; `usdc` 10; `taker_*` 16; doc-tests 5 |
| `divi-swapd` | 89 | 0 | 0 | lib 52; bin 1; `api` 8; `e2e` 4; `e2e_gated` 4; `e2e_ltc` 8; `e2e_xmr` 8; `multichain` 1; `scan` 3 |
| `divi-swap-cli` | 46 | 0 | 0 | lib 9; bin 37 |
| `swap-chain-btc` | 32 | 0 | 1 | |
| `swap-chain-ltc` | 51 | 0 | 2 | |
| `swap-chain-zec` | 33 | 0 | 4 | |
| `swap-chain-evm` | 23 | 0 | 0 | |
| `swap-chain-divi` | 20 | 0 | 1 | `tests/live.rs` ran 0 tests |
| **Total** | **472** | **0** | **8** | |

The 8 ignored tests are the live-network or external-service tests (`#[ignore]`); they were not run
and are not counted as passed. The earlier grep-based `#[test]` counts in §1 are lower than the real
counts because the `both!` macro in `tests/engine.rs` generates a forward and a `rev_` test from each
body. `divi-swapd`'s `e2e_xmr` runs XMR paths whose crates are out of scope here.

Tests that need external services skip or fail on a host without them; those are listed above and
are not counted as passed. Nothing in the run touches a network beyond `cargo` downloading crates,
no funds, no keys.

## 7. Questions for the reviewer

1. **F1 (fixed on lane/maker-accept-serialized, see status/engine.md 2026-10-22; `accept` now holds `gate`; left: no unique index on the hash):** confirm `Maker::accept` cannot be turned into a loss of funds by concurrent accepts of one
   quote, or one hash. Is a unique index on the hash plus taking `gate` the right fix?
2. **Self-stated MTP:** `check_maker_leg_locktime_exact` bounds a maker's stated `maker_mtp_at_lock` to
   a plausibility window. Can a maker pick a stated value inside the window that shortens its own
   locktime below what the taker needs to claim safely?

   **Answer (2026-10-22): no.** The stated MTP only ever adds a refusal; it never relaxes the tolerant floor or the 1800 s claim margin, both of which are checked against the taker's own reads (`taker.rs:407`, `:421`, `:466`). The lowest in-window value (`taker_locktime − taker_timeout − tol − lag`) makes the exact floor equal the tolerant floor, i.e. exactly what a maker that states nothing gets; higher values only raise it, and out-of-window values are refused. Worst remaining claim window (locktime − observed maker-chain MTP) across all mainnet hashlock pairs, with taker-chain MTP lagging by its full lag and the maximum accept drift, is `maker_timeout − 2×1800 − 2×max lag`: 32400 s for any pair containing BTC (lag 3600), 36000 s for DIVI/LTC/ZEC pairs, against a margin of 1800 s (profile claim margin 3600 s). No change to `taker.rs`. Pinned by `tests/taker_stated_mtp_window.rs`.
3. **No `OP_SIZE`:** is omitting a preimage-length check safe here, given the taker generates the
   preimage and the script is SHA-256 only? Any cross-chain concern (a longer preimage is valid on one
   chain and not on another)?
   **Answer (2026-10-22): no, not safe.** Our taker generates 32 bytes, but the maker never sees that code: a hostile taker chooses the preimage and the hash. A non-32-byte preimage claims the maker leg on a script chain (DIVI P2SH takes up to 520 bytes), while the maker's claim path (`claim_script_sig`, `extract_preimage`, `build_claim`) only handles 32 bytes, and the EVM contract takes `bytes32`. Fixed in the V1 script; see F3 and status/engine.md.
4. **Unauthenticated routes:** `GET /swaps` and `GET /swaps/:id` expose swap ids, HTLC keys and states,
   and `POST /swaps/:id/lock` accepts a notice from anyone. What can an observer or griefer do with
   that? Is a token on the hashlock routes warranted before mainnet?
5. **Opt-in floors:** a taker built without `with_profile_floor` takes the maker's terms as offered.
   Is any shipped entry point (CLI, daemon) able to construct one on mainnet?

   **Answer (2026-10-22): no.** Every taker construction in shipped code is in `bin/divi-swap/src/main.rs` (`Taker::new` at `:928` and `:1016`, `XmrTaker::new` at `:1087` and `:1169`) and each chains `.with_profile_floor(cli.profile)`. `divi-swapd` builds no taker (it is maker-only); `flow.rs`/`xmr_flow.rs` only receive a built `&Taker`. `--profile` defaults to `testnet` (`:116`), and `guard_profile` (`:453`) refuses a mainnet chain under a testnet profile (and the reverse), so a mainnet taker always carries the mainnet floor. The only floor-less construction sites are tests and examples. Pinned by `tests/taker_floor_entry_points.rs`, which fails if a new construction site appears or one drops the floor.
6. **Single data source per chain:** which chain's single-source assumption is the most dangerous
   (lying confirmations, hidden spend, wrong MTP), and what is the cheapest mitigation?
   **Answer (2026-10-22):** DIVI is the most dangerous, then LTC, ZEC, USDC/EVM, BTC, XMR. DIVI sits on one leg of every swap, its mainnet source is one proxy URL with no fallback key and no cross-check, and a proxy that hides the taker's claim makes the maker lose the DIVI leg (`maker.rs:734` reads the preimage only from that spend). LTC is next: one mainnet Esplora URL, and the existing cross-check is `off` by default and compares one block hash once at startup. The BTC and ZEC second endpoints are failover only, so a lying 200 is never compared with anything. Cheapest mitigation: a "disagree is Transient" read against a second endpoint for `htlc_output`, `confirmations`, `find_spend` and `median_time_past` (the engine already retries `Transient`), DIVI first; for LTC, make `[ltc].crosscheck` mandatory on mainnet. Nothing implemented in this round; sites, costs and the truth and attack tables are in `single-source-design.md`.
7. **Reorg after maker lock (F2):** is the absence of a maker re-broadcast after `MakerLockConfirmed`
   acceptable given 24 h / 12 h timeouts?
8. **Confirmation depths:** are the mainnet counts (BTC 2, LTC 6, ZEC 10, DIVI 10, USDC 12) adequate
   against the reorg risk of each chain, and is the DIVI 10-vs-20 choice material?
9. **Preimage at rest:** is plaintext storage in a mode-0600 SQLite file, with WAL, acceptable for the
   deployed maker, which holds the preimage only after the taker reveals it?
10. **Rate limiting behind a proxy:** is fixed-window per-IP limiting on `quote` alone enough to protect
    the maker, given `accept` and `lock` are unlimited?
