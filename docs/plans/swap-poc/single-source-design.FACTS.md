# FACTS — third-party claims behind single-source-design.md

This lane had no network access, so none of these could be checked against the vendor. Verdict
"could not verify" is a verdict; the URL is where to check. No claim here changes a code path.

| Claim | Verdict | Source URL | What the design says now |
|---|---|---|---|
| The BTC default list (mempool.space, Blockstream) is two separate operators | could not verify | https://mempool.space/docs/faq , https://blockstream.info | "two operators in the default list" is read from the hostnames in `swap-chain-btc/src/lib.rs:69`; the ranking does not depend on it (failover is not a quorum either way) |
| The three default Zcash mainnet lightwalletd hostnames share one operator | could not verify | https://zec.rocks | "share one operator domain" is read from the hostnames; the rank-3 reasoning holds if they are separate, because there is still no comparison between them |
| litecoinspace.org is the only Esplora-API LTC mainnet source | could not verify | https://litecoinspace.org | repeated from the comment in `swap-chain-ltc/src/crosscheck.rs`; rank 2 rests on the code (one default URL), not on this |
| Blockbook and BlockCypher are independent of the primary for LTC | could not verify | https://api.blockcypher.com/v1/ltc/main , https://litecoinblockexplorer.net | design proposes using the existing module unchanged |
| The default EVM RPC is a public shared endpoint | could not verify | https://ethereum-rpc.publicnode.com | from `swap-chain-evm/src/network.rs:52` |
| Blockbook `GET /api/v2/tx/{txid}` shows each output's `spent` and `spentTxId`, both omitted when empty (EI, claim-time spend check) | verified 2026-10-27 against the Go type that serialises the response | https://github.com/trezor/blockbook/blob/master/api/types.go (`type Vout`: `json:"spent,omitempty"`, `json:"spentTxId,omitempty"`) | `crosscheck.rs` reads `vout[n].spent` / `spentTxId`; absent `spent` is unspent; spent without `spentTxId` is "spender not named" and agrees with any primary spender |
| BlockCypher `GET /txs/{hash}` outputs carry `spent_by`, "only returned for outputs that have been spent"; outputs are limited to 20 by default | verified 2026-10-27 | https://www.blockcypher.com/dev/bitcoin/#txoutput | `crosscheck.rs` reads `outputs[vout].spent_by`; an output index past the list is "unavailable", not unspent |
