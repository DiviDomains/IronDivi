# Lane zec — `crates/swap-chain-zec/`

Read `_hp2.md` and `_common.md` first. You own `crates/swap-chain-zec/` and
`docs/plans/swap-poc/status/zec.md`.

**Step 0 — feasibility (record results under `- decisions:` before writing the backend).** The
backend needs, on Zcash **testnet**: tip height + median time past, raw tx by txid with
confirmations, broadcast of a raw tx, UTXOs of a transparent address, and blocks by height (for
`find_spend`). Probe candidate APIs read-only (zec.rocks lightwalletd gRPC, Blockchair testnet,
any public testnet zcashd JSON-RPC / Insight API) and pick one primary + one fallback. If no
public testnet API gives UTXOs-by-address, the backend may track its own coins from a funding
txid list (document it).

**Build** `ZecBackend`, implementing `divi_swap::ChainBackend` for Zcash testnet **transparent**
outputs only. HTLC is P2SH of `HtlcParams::redeem_script()` (same script as DIVI/BTC; Zcash
transparent script = Bitcoin script with CLTV). Transactions are **v5 (NU5+)** with the
**ZIP-244** signature digest (and current consensus branch id — read it from the chain, don't
hard-code a stale one). Prefer the `zcash_primitives` / `zcash_transparent` crates from
librustzcash for tx building and sighash over hand-rolling; if their dependency weight is
unreasonable, hand-roll and prove against the official ZIP-244 test vectors. Testnet t-address
P2PKH prefix `tm…`, P2SH `t2…`.

**Acceptance** (`tools/swap-poc/check-zec.sh`): crate green; `impl ChainBackend for ZecBackend`;
tests named `zip244_sighash_vectors` (official vectors), `claim_script_executes`,
`refund_script_executes`, `refund_rejected_before_locktime`, `wrong_preimage_rejected`,
`t_address_encoding`, `funding_selects_coins_and_change`, `find_spend_reads_scriptsig`,
`client_retries_and_falls_back`; `testnet_api_reachable` (`#[ignore]`, read-only, run and passed);
and `#[ignore]` + `--features live` `live_fund_claim_refund` reading env `SWAP_ZEC_TEST_KEY_HEX`.
Script execution tests may use the `bitcoin` crate's interpreter for the script part (Zcash's
transparent interpreter matches for these opcodes) with the ZIP-244 digest as the signed message.
