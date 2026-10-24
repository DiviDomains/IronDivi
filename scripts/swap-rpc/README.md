# BasicSwap RPC check

This script checks that irondivid answers the RPC calls BasicSwap's Divi interface makes, in the order BasicSwap makes them, with the reply fields and types BasicSwap reads. It checks shapes, not values. It runs on a fresh regtest node and needs no other node, no coins and no network.

```
scripts/swap-rpc/run.sh <irondivid-bin-dir> <port-base> [<datadir-root>]
```

- `<irondivid-bin-dir>`: the directory holding `irondivid`, for example `target/release`.
- `<port-base>`: the first of 4 consecutive free ports. Node 1 uses p2p `base`, rpc `base+1`; node 2 uses `base+2` and `base+3`.
- `<datadir-root>`: where the temporary datadirs go (default `$TMPDIR` or `/tmp`).

The script prints one `PASS`/`FAIL` line per check and ends with `FAILS <n>`. The exit code is the number of FAILs, and 255 means a usage error or that the run went over 10 minutes. A trap stops every node and deletes the datadirs on every exit, including Ctrl-C. A run takes about 10 seconds.

It needs bash and python3 (standard library only). Nothing is printed of the generated words, passphrases or seeds; the wallet passphrase only exists in memory.

## What runs

1. **The seeder node.** BasicSwap's wallet-init start: `irondivid -datadir=<dir> -noconnect -nodnsseed -nolisten`, with only `mnemonicpassphrase=<random>` in divi.conf.
2. **The swap node.** BasicSwap's normal start, `irondivid -datadir=<dir>`. Its divi.conf is the one the test harness writes, plus `mnemonic=<the seeder's words>`, as prepare.py seeds divid. It mines with `setgenerate`, then makes every call below. It sends coins to the seeder's address, which stands in for a swap address the wallet only watches.

## The checks and the BasicSwap lines they stand for

BasicSwap paths are relative to the BasicSwap Divi branch at 1fbe2bab (`basicswap/...`, `tests/...`). In this table, `divi.py` is `basicswap/interface/divi/divi.py` and `btc.py` is `basicswap/interface/btc/btc.py`.

| check | BasicSwap source |
|---|---|
| start: `-noconnect -nodnsseed -nolisten`, `mnemonicpassphrase=` only | `bin/prepare.py:931` (initialise_wallets daemon args), `bin/run.py:97,158` (startDaemon) |
| dumphdinfo: new words + `-mnemonicpassphrase` make the seed | Divi Core `GenerateNewHDChain`; the seed id is read by `divi.py:86` (getWalletSeedID) |
| getconnectioncount: 0 with `-noconnect` | `bin/prepare.py:931` |
| start: `irondivid -datadir=<dir>` with BasicSwap's divi.conf | `tests/basicswap/extended/test_divi.py:95-130` (prepareDataDir), `interface/divi/core.py:214-230` (mnemonic=), `btc.py:506` (testDaemonRPC) |
| getnetworkinfo: version (a string in divid), relayfee >= 0.0001 | `btc.py:522` (getDaemonVersion), `btc.py:1283` (get_fee_rate relayfee) |
| getblockchaininfo: chain, blocks, headers, bestblockhash | `divi.py:546,570` (getBlockHeaderAt, getBlockchainInfo: blocks/headers when there is no verificationprogress) |
| getwalletinfo: balance, no unlocked_until (unencrypted) | `btc.py:955-957` (getWalletInfo encrypted/locked), `btc.py:4773-4787` (isWalletEncrypted/Locked) |
| listlockunspent: array | `btc.py:957` |
| dumphdinfo: the mnemonic= seed | `divi.py:86` (getWalletSeedID / checkExpectedSeed) |
| setgenerate 101 / setgenerate 1: block hashes | `tests/basicswap/extended/test_divi.py:185,219` |
| getblockcount | `btc.py:542` (getChainHeight) |
| getwalletinfo: spendable balance > 0 | `divi.py:640` (getSpendableBalance) |
| getnewaddress + validateaddress: ismine | `btc.py:1176` (getNewAddress), `divi.py:515` (isAddressMine) |
| estimatesmartfee 2: feerate >= 0.0001 | `btc.py:1272` (get_fee_rate) |
| listunspent: txid, vout, amount, address | `divi.py:216,333` (coin selection) |
| lockunspent false + gettxout value + listlockunspent | `divi.py:246,251,318,364,368` |
| getrawchangeaddress, createrawtransaction, signrawtransaction, decoderawtransaction, sendrawtransaction | `divi.py:279,285,137,403,652,659,655`, `btc.py:2971` (publishTx) |
| lockunspent true | `divi.py:256,373,661` |
| getrawtransaction txid 1 / 0 / none | `divi.py:444` (getTransaction), `divi.py:673` (getBLockTxo), `btc.py:676` (getMempoolTx) |
| sendtoaddress (amount as a JSON number) | `divi.py:645` (withdrawCoin) |
| importaddress + validateaddress: iswatchonly | `divi.py:524` (importWatchOnlyAddress), `divi.py:515` (isAddressMine) |
| getaddressutxos {addresses}: address, txid, outputIndex, script, satoshis, height | `divi.py:470` (getLockTxHeight) |
| gettransaction: confirmations, blockhash | `divi.py:624` (findConfirmedTxnByHash) |
| getblockhash + getblock hash true: hash, height, time, previousblockhash, tx | `divi.py:536-537,588,600` |
| getbestblockhash + getblockheader: time, previousblockhash | `divi.py:610-613` (getChainMedianTime) |
| signrawtransaction hex [] [wif]: complete | `divi.py:142` (signTxWithKey) |
| request without a jsonrpc member: answered | divi-cli and BasicSwap clients that send only method/params/id |
| encryptwallet + getwalletinfo: unlocked_until 0 | `divi.py:696` (encryptWallet), `btc.py:4779` |
| walletpassphrase pw 100000000: unlocked_until > 0, seed unchanged | `btc.py:5114` (unlockWallet), `divi.py:86` |
| walletlock + getwalletinfo: unlocked_until 0 | `btc.py:5130` (lockWallet) |
| stop: the node exits | BasicSwap stops the daemons it manages |

When a check needs what an earlier one failed to produce (coins, a txid), it fails with `needs <x> from an earlier check` instead of calling the node.
