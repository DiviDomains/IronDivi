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
