# rev-live — live reverse direction (taker sells DIVI for BTC) through the deployed maker

Maker: divi-swapd on dnsdivi (main 4ae2ed8), offer `btc-divi-testnet`, DIVI testnet + BTC testnet3.

## Happy path — swap e6c45f05-c097-414c-bbb7-a56b7023f871 (maker d1a89c48-c7b9-485d-9760-8689e0e49dfb), Done/Done

- deployed_rev_happy_divi_lock_txid: 3747b6ff4af9efdbf9bf5705124cc38c3859d78a3df7ff2b8ca39dadf74dfbab
- deployed_rev_happy_btc_lock_txid: ceb4005ba73c1087e3d20bdaa70998f3646ff6e26feb6a825b84ff642a7a1e39
- deployed_rev_happy_btc_claim_txid: f2d7a3b2cba490a698f3c10dfcdd7b787b5b61dbc603b410f01fe0305ca73c93
- deployed_rev_happy_divi_claim_txid: 130dd4b512a0eba0ab392890513c5e638c83b0ff0ecbc34c3183031c61923d13

## Case C (both sides refund) — swap 643682e4-4cbf-41f0-b8d9-9e57b4925b1d (maker 5cb25549-a0f8-4d23-967d-2501e09ad1cd), Done/Done

Taker locked DIVI, maker locked BTC, taker never claimed (claim policy `Never`); maker refunded its BTC after its 3 h
timelock, taker refunded its DIVI after its 6 h timelock. Txids read from the taker db and maker `/swaps/<id>`
(e2e.sh's final `txids` call failed: `target/debug` was removed mid-run by something outside this run).

- deployed_rev_casec_divi_lock_txid: aa45b212101f5686005db2bbc7d205cb6cab3a4e56be680350545e5b84b68152
- deployed_rev_casec_btc_lock_txid: f1da64e17d6ddc9bc58f0ca0ce06a73788d7b4b885c060452726b14234bd83a3
- deployed_rev_casec_btc_refund_txid: 13e030b56b2311fe07d799a9e77a73bd6fbcc1579880ec4ff7629bb37e204114
- deployed_rev_casec_divi_refund_txid: ac3bab46e1ba29e3b56c702822e02370b17254987be7e244d341f71514028260
