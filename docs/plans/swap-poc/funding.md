# Testnet funding addresses (multi-coin, 2026-10-11)

Decision: the testnet runs reuse the existing secp256k1 swap keys for every secp256k1 chain,
so no new 1Password items are needed. LTC P2WPKH and ZEC transparent P2PKH use the same
hash160 as the BTC address; EVM uses the same public key. Pass the BTC refs as the
LTC/ZEC/EVM key refs:

- taker: `op://global_secret_store/IronDivi Swap POC - taker-btc/password`
- maker: `op://global_secret_store/IronDivi Swap POC - maker-btc/password`

Derived from public keys only (pubkeys read from on-chain BTC witnesses; the `tb1…`
re-encoding is asserted to match before printing). Script: `tools/swap-poc/derive-addrs.py`.

| role | BTC testnet3 | LTC testnet | ZEC testnet (TAZ) | Sepolia (ETH gas + USDC) |
|---|---|---|---|---|
| taker | tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg | tltc1qa826ffe73xnqsm64x6fvln7sl0zp3rgf5gnf3p | tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk | 0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C |
| maker | tb1quqkt7c06svzt68f2y9uwf2jzgpd48k6ku45zrt | tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz | tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn | 0x995669a244d511542ca314e4068c754E3F555bd2 |

Keep every testnet coin; never sweep back to a faucet.
XMR (ed25519, stagenet) gets its own wallet when its lane reaches live readiness.

## ZEC testnet: faucet on the wrong fork (2026-10-11)

NU7 activated on Zcash testnet at height 4,465,026 (Oct 4) and cut blocks to 25 s.
`testnet.zec.rocks`, the server `swap-chain-zec` uses, follows the NU7 chain (tip ~4,489,850
on Oct 11). fauzec.com still runs a pre-NU7 node: its claim to our funding wallet (txid
`9cf8c2203229ef9577857439452c22b63ba0981b3419ba02dce98a05d7049814`, 1 TAZ) was mined at
4,474,361 on a chain whose tip was ~4,474,400 (75 s blocks). zexplorer.app shows the same
stale chain. A wallet synced against zec.rocks from height 4,474,000 never sees it, so those
coins do not exist on the chain we swap on.

Funding wallet (shielded, for splitting TAZ to the two t-addrs above): hp2
`~/zec-faucet-wallet/wallet2` (zcash-devtool, birthday 4,474,000, age identity alongside).
Its unified address:
`utest1shuxck4zpa4rn9aa3ydyxnhgdc9aq66kr4x9dy95tegfm25ujh9uu5xvlnrhey42cd364kry7wgs4fkmwre69jaqw0jxzjelfxa4ltkzcpj2tevtq3gu924gczq4g26hf4dsxu9gwg499fmxlh80ypf23ty45vdjcphrz507gk9n07cz62pjcamnqt87v3jh79f53a3y8dxag0kjq4l`.
TAZ sent straight to the taker/maker t-addrs works just as well. Needs a source on the
NU7 chain.
