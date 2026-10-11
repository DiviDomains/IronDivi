# Lane ltc — `crates/swap-chain-ltc/`

Read `_hp2.md` and `_common.md` first. You own `crates/swap-chain-ltc/` and
`docs/plans/swap-poc/status/ltc.md`.

**Build** `LtcBackend`, implementing `divi_swap::ChainBackend` for **Litecoin testnet** over
Esplora HTTP (primary `https://litecoinspace.org/testnet/api` — verify it first; record the
working base URL, and a secondary if one exists, under `- decisions:`). Model it on
`crates/swap-chain-btc` (copy and adapt; do not depend on that crate's internals unless they are
public and fit). Litecoin uses the same script and SegWit v0 rules as Bitcoin: HTLC is P2WSH of
`HtlcParams::redeem_script()`, funding from the key's P2WPKH address (bech32 hrp `tltc`),
claim witness `[sig, preimage, 0x01, script]`, refund witness `[sig, <empty>, script]` with
`lock_time = htlc.locktime`. Verify every built tx with `bitcoin::consensus::verify_script`
(the interpreter is identical for these script types). Constructor takes endpoints, a
`bitcoin::secp256k1::SecretKey`, and a fee policy (Litecoin fees are sat/vB; floor 1).
Until the engine has `Chain::Ltc` (orchestrator, wave 1e), have `chain()` return a value your
brief-local code can switch later — note it under `- needs: Chain::Ltc` and keep going.

**Acceptance** (`tools/swap-poc/check-ltc.sh`): crate green; `impl ChainBackend for LtcBackend`;
tests named `claim_verifies_with_consensus`, `refund_verifies_with_consensus`,
`refund_rejected_before_locktime`, `wrong_preimage_rejected`, `esplora_retries_on_429`,
`esplora_falls_back_to_secondary`, `find_spend_reads_witness`,
`funding_selects_coins_and_change`, `tltc_address_encoding` (wiremock for HTTP); a test
`testnet_api_reachable` (`#[ignore]`, read-only, hits the real testnet API: tip height + a known
block) that you have run and passed; and an `#[ignore]` + `--features live` test
`live_fund_claim_refund` that reads the funded key from env `SWAP_LTC_TEST_KEY_HEX` (the
orchestrator runs it from the Mac). Keep live amounts ≤ 0.001 tLTC per HTLC.
