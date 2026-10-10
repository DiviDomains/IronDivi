# Reverse direction — taker sells DIVI for BTC (`taker_pays_divi`)

Bert, 2026-10-10: "add the reverse direction, sell divi for btc". Same HTLC protocol, legs swapped.

## Protocol (offer `btc-divi-testnet`, `Direction::TakerPaysDivi`)

1. Taker gets a quote (`btc_sats` = BTC the taker **receives**; `divi_amount` = DIVI it pays), makes the
   preimage, and accepts with the hash.
2. **Taker locks DIVI** (taker leg, `taker_timeout_secs` after DIVI MTP, refund key = taker DIVI key,
   claim key = maker DIVI key).
3. Maker verifies the DIVI lock (script, amount ≥ quote, `divi_confirmations`), and **only then**
   selects BTC coins and **locks BTC** (maker leg, `maker_timeout_secs` after BTC MTP, claim key =
   taker BTC key, refund key = maker BTC key). Staking invariant generalised: the maker calls
   `build_funding` on **no** backend before `TakerLockConfirmed → MakerLocked`.
4. Taker verifies the BTC lock (script, amount, the quote's hash, `btc_confirmations`) and claims BTC
   with the preimage while BTC MTP < maker locktime − safety margin.
5. Maker reads the preimage from the BTC spend (`BtcBackend::find_spend`, esplora outspend) and
   claims DIVI. Refunds: maker refunds BTC once BTC MTP ≥ its locktime; taker refunds DIVI once
   DIVI MTP ≥ its locktime.

Everything that was "BTC side"/"DIVI side" in the engine becomes "taker leg"/"maker leg"; the chain of
each leg comes from `quote.direction` (`Direction::taker_chain()/maker_chain()`, landed on main).

## Timeout gap (DECISIONS #9)

Forward: `taker - maker ≥ max(3 h, 2·lag + margin)` with `lag` = BTC MTP lag (3600 s testnet3) and
margin 1800 s. In reverse the maker leg is on BTC and the taker leg on DIVI. The dangerous window is
the taker claiming BTC at the last allowed moment (BTC MTP just under maker locktime − 1800 s, which
on testnet3 can be up to `lag` behind wall clock) and the maker then needing to see the spend and
claim DIVI before DIVI MTP reaches the taker locktime. DIVI MTP lag is minutes, so the gap needed is
`lag_btc + margin + DIVI confirmation time` ≤ `2·lag + margin` = 2.5 h < 3 h. **The same profiles
(testnet 6 h/3 h, mainnet 24 h/12 h) and `SwapConfig::validate` hold unchanged**; the maker's
"window too short" check runs on the **taker-leg** chain's clock (DIVI here).

## Lanes (worktrees `~/code/IronDivi-swap-rev-<lane>`, branches `swap/rev-<lane>`)

| Lane | Owns | Brief | Check |
|---|---|---|---|
| rev-engine | `crates/divi-swap/src/{maker,taker,store,mock}.rs`, `crates/divi-swap/tests/` | `lanes/rev-engine.md` | `check-rev-engine.sh` |
| rev-cli | `bin/divi-swap/`, `bin/divi-swapd/` | `lanes/rev-cli.md` | `check-rev-cli.sh` |
| rev-tools | `tools/swap-poc/{e2e.sh,chaos/}`, `.github/workflows/` swap bits | `lanes/rev-tools.md` | `check-rev-tools.sh` |

The orchestrator owns `api.rs` and the rest of the frozen contract, deploy, the live runs and
RESULTS.md (`check-rev-live.sh`).

### Fixed interfaces between lanes

- Offers: `divi-btc-testnet` (`taker_pays_btc`, unchanged) and **`btc-divi-testnet`** (`taker_pays_divi`,
  same rate/limits; `btc_sats` is always the BTC amount).
- `divi-swap txids --swap ID` prints `direction=<taker_pays_btc|taker_pays_divi>`, `taker_state=`,
  `maker_state=`, and per direction:
  - forward (unchanged): `btc_lock divi_lock divi_claim_by_taker btc_claim_by_maker divi_spend_by_maker btc_refund_by_taker`
  - reverse: `divi_lock btc_lock btc_claim_by_taker divi_claim_by_maker btc_spend_by_maker divi_refund_by_taker`
- Taker DIVI wallet (reverse needs DIVI coins on the taker): `divi-swap --divi-wallet PATH
  [--divi-scan-from HEIGHT]` (wallet JSON outside the repo, mode 0600; scan resumes from its cursor).
- `e2e.sh <happy|case-c|case-d> --offer btc-divi-testnet` → state dir `rev-<scenario>-<backend|deployed>`,
  txid prefix `rev_<happy|casec|cased>` (`deployed_rev_…` with `--maker-url`).
