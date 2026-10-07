# Lane divi — `crates/swap-chain-divi/`

Read `_common.md` first. You own `crates/swap-chain-divi/` and `docs/plans/swap-poc/status/divi.md`.

**Build** `DiviBackend`, implementing `divi_swap::ChainBackend` for DIVI testnet over the JSON-RPC
proxy `https://services.divi.domains/api/testnet/rpc/` (no auth). Constructor takes the RPC URL,
a `divi_crypto::keys::SecretKey` (resolved by the caller), network, and a fee policy.

- **Script/signing:** reuse `divi-script`, `divi-crypto`, `divi-wallet`. P2SH of
  `HtlcParams::redeem_script()`; sighash via `divi_wallet::signer::sighash` with the **redeem
  script** as script code (not the P2SH scriptPubKey); claim/refund scriptSigs from
  `divi_swap::htlc::{claim_script_sig, refund_script_sig}`; refund input sequence
  `REFUND_SEQUENCE`, tx `lock_time = htlc.locktime`. Verify every spend you build with
  `divi_script::verify_input` before returning it.
- **Coins without an address index** (plan §2): the proxy has txindex but no address/spent
  index. Keep a small wallet: the backend learns its UTXOs from (a) txids it is told about
  (`add_funding_tx(txid)`, used to seed it from the faucet send) and (b) change outputs of
  transactions it builds, and (c) block scanning from a start height for outputs paying its
  P2PKH. Persist known UTXOs in a small JSON/SQLite file whose path the caller supplies
  (public data only). `build_funding` selects coins + change; a reserved UTXO is not reused
  until its tx is seen or the reservation is dropped.
- **find_spend:** scan blocks from `from_height` to tip (`getblockhash` → `getblock <hash> 2`
  if allowed, else per-tx `getrawtransaction`), then mempool (`getrawmempool` + per-tx) for an
  input spending the outpoint; return its scriptSig. **htlc_output** via `getrawtransaction 1`.
- **broadcast:** `sendrawtransaction`; "already in block chain"/"txn-already-known" ⇒ `Ok`;
  `non-final`/`Locktime requirement not satisfied`/`64: non-final` ⇒ `SwapError::Premature`;
  network/5xx/429 ⇒ `Transient`; anything else ⇒ `Rejected`. Retry transient RPC with backoff.
  If the proxy refuses a method you need, write it under `- needs:`.

**Acceptance** (`tools/swap-poc/check-divi.sh`): crate green; tests named
`claim_verifies_with_interpreter`, `refund_verifies_with_interpreter`,
`refund_rejected_before_locktime`, `wrong_preimage_rejected`, `find_spend_scans_blocks`,
`funding_selects_coins_and_change`, `rpc_errors_classified` (wiremock), and an
`#[ignore]`/`--features live` test `live_fund_claim_refund` that funds two HTLCs from the
`maker-divi` key, claims one and refunds the other (10 min locktime — run the wait in the
background). Record its confirmed txids in your status file as `- live_fund_txid:`,
`- live_claim_txid:`, `- live_refund_txid:`. The `maker-divi` key address is funded with
tDIVI already (see RESULTS.md); if it runs low, add `- needs: tDIVI` and the orchestrator refills.
