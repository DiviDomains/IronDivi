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
