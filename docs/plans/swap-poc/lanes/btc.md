# Lane btc — `crates/swap-chain-btc/`

Read `_common.md` first. You own `crates/swap-chain-btc/` and `docs/plans/swap-poc/status/btc.md`.

**Build** `BtcBackend`, implementing `divi_swap::ChainBackend` for BTC **signet** with
`rust-bitcoin` 0.32 over Esplora HTTP: primary `https://mempool.space/signet/api`, secondary
configurable (default `https://blockstream.info/signet/api`). Constructor takes the endpoints,
a `bitcoin::secp256k1::SecretKey` (resolved by the caller), and a fee policy (sat/vB from
`/v1/fees/recommended` with a floor, or fixed).

- Funding coins come from the key's P2WPKH address via `/address/:a/utxo` (Esplora has an
  address index). HTLC is P2WSH of `HtlcParams::redeem_script()`; claim witness
  `[sig, preimage, 0x01, script]`, refund witness `[sig, <empty>, script]` with
  `lock_time = htlc.locktime` and sequence `REFUND_SEQUENCE`. Verify every tx you build with
  `bitcoin::consensus::verify_script` (libbitcoinconsensus) before returning it.
- `median_time_past` from `/block/:tip` `mediantime`. Signet MTP lags wall clock ~1 h — a refund
  is `Premature` until MTP passes the locktime (`non-final` from the node).
- **find_spend:** `/tx/:txid/outspend/:vout` (Esplora) → spending tx's witness; fall back to
  scanning blocks from `from_height` if outspend is unavailable.
- **Client:** retries with exponential backoff on network errors, 5xx and **429** (honour
  `Retry-After`), then falls back to the secondary endpoint. Classify broadcast errors like the
  divi lane: already-known ⇒ `Ok`, `non-final`/`Locktime requirement not satisfied` ⇒
  `Premature`, network ⇒ `Transient`, else `Rejected`.

**Acceptance** (`tools/swap-poc/check-btc.sh`): crate green; tests named
`claim_verifies_with_consensus`, `refund_verifies_with_consensus`,
`refund_rejected_before_locktime`, `wrong_preimage_rejected`, `esplora_retries_on_429`,
`esplora_falls_back_to_secondary`, `find_spend_reads_witness`,
`funding_selects_coins_and_change` (wiremock for HTTP), and an `#[ignore]`/`--features live`
`live_fund_claim_refund` on signet with the `taker-btc` key: fund two HTLCs, claim one, refund
the other with a locktime **≥ 2 h ahead of current MTP** (wait in the background; ~3 h).
Record confirmed txids as `- live_fund_txid:`, `- live_claim_txid:`, `- live_refund_txid:`.
Keep amounts tiny (≤ 20,000 sats per HTLC); sBTC is scarce.
