# Wallet RPCs on a locked wallet, next to Divi Core

`scripts/locked-stake` covers mining on a locked wallet when the stake key is from the HD seed. This script covers:
- a stake coin on an imported (non-HD) key, alone and next to HD coins;
- the other wallet RPCs that answer differently when the wallet is locked, unlocked for staking only, or not
  encrypted.

`run.sh` starts, on regtest and on 127.0.0.2:
- one Divi Core 3.0.0 `divid`;
- one irondivid restored from divid's phrase (`WALLET_MNEMONIC` in its environment).

The two are not connected. Each mines its own chain with the same calls, so the heights stay equal. Both run with
`keypool=3`, so a locked wallet runs out of keypool keys within a few calls.

```sh
scripts/locked-wallet-rpcs/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/locked-wallet-rpcs/run.sh target/release ~/divi-3.0.0/bin 53850 /var/tmp
```

- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (p2p and RPC of divid, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, with both nodes
  stopped.
- `LOCKED_WALLET_RPCS_LOGS`: a folder to copy both debug.logs to at the end. divid logs "CreateCoinStake : failed to
  sign coinstake" when a stake fails at the signing.
- `LOCKED_WALLET_RPCS_TIMEOUT`: seconds before the run is stopped (900).

A run takes about a minute. It needs bash and python3 (standard library only). The secrets are made fresh for each
run: the wallet passphrase, the imported key (a random 32-byte secret, as a regtest WIF) and the RPC passwords (in
0600 `divi.conf` files). The passphrase and key are sent only in RPC request bodies. None of them, nor the phrase, is
printed, written elsewhere or put on a command line.

## Rows

Each row is one call on both nodes. Compared:
- its outcome: `ok`, or the error code and text;
- the block count;
- the wallet after it: the balance plus the immature balance (their sum, since each side stakes other coins and so
  has other stake outputs still immature), the transaction count, the keypool size, the encryption status, and
  whether it is unlocked.

A row that differs is a `FAIL`; the exit code is the number of FAILs.

In order:
1. **Not encrypted:**
   - `walletlock` and `walletpassphrase`: -15;
   - 60 work blocks;
   - `importprivkey` of a fresh key (no rescan);
   - the whole mature balance sent to that key (`sendtoaddress … sweep_funds`, a send without change);
   - work blocks up to 100.
   
   At 100 the wallet's stake coins are the HD coinbases of heights 1 to 80 and the one coin on the imported key (40
   deep).
2. `encryptwallet`. The wallet is then locked.
3. **Locked:**
   - `getnewaddress` and `getrawchangeaddress` until each keypool is empty (-12);
   - `keypoolrefill` with and without a size;
   - `dumpprivkey`, `dumphdinfo`, `dumpwallet`, `importprivkey`, `signmessage` and `sendtoaddress`;
   - `walletpassphrase` with a wrong passphrase.
4. **Locked, stakes:**
   - `setgenerate 1` with HD and imported coins. divid tries its stake set in outpoint order, so each node is checked
     against its own lowest-outpoint coin: -1 when it is on an HD key, -25 when it is on the imported key. The two
     nodes have different txids, so their answers may differ.
   - then, with every other coin locked (`lockunspent`), `setgenerate 1` and `generateblock` with only the imported
     coin: -25.
5. **Staking only (`walletpassphrase … true`):**
   - a stake with only the imported coin, which is made;
   - then, the coins unlocked, the same calls as in 3;
   - a second staking-only unlock;
   - a stake block.
6. `walletlock`, and `getnewaddress` again.

## What Divi Core does (core-src 9e2f76c)

- **Keys that need a full unlock.** `EnsureWalletIsUnlocked` answers -13 "Error: Please enter the wallet passphrase
  with walletpassphrase first." unless the wallet is fully unlocked (rpcserver.cpp:1124-1128). Staking only counts as
  not unlocked. Called by:
  - keypoolrefill (rpcwallet.cpp:2564);
  - importprivkey, dumpprivkey and dumphdinfo (rpcdump.cpp:59, :184, :218);
  - signmessage (rpcwallet.cpp:1385);
  - sendtoaddress (rpcwallet.cpp:1360).
- **dumpwallet** is not in divid 3.0.0's RPC table: -32601 "Method not found".
- **getnewaddress / getrawchangeaddress** top the keypool up only when the wallet is not locked, then take its oldest
  key. An empty pool is -12 "Error: Keypool ran out, please call keypoolrefill first" (rpcwallet.cpp:296-307,
  :566-573; wallet.cpp:2122-2156). Staking only is not locked, so it tops up.
- **walletpassphrase:**
  - a wrong passphrase is -14 (rpcwallet.cpp:2616-2617);
  - on an unencrypted wallet, -15 (:2596-2597);
  - a second staking-only unlock is -17 (:2611-2614);
  - an unlock tops the keypool up (:2620).
- **walletlock** on an unencrypted wallet is -15 (rpcwallet.cpp:2676-2677).
- **Stake coins.** The stake set is the spendable, unlocked coins, at least 10 deep, or 20 for a coinstake output
  (wallet.cpp:1433-1462). It is held in a `std::set<StakableCoin>` ordered by outpoint (StakableCoin.h:20-23) and
  tried in that order (PoSTransactionCreator.cpp:261). It is shuffled only with `-vault` (:63-72, :99). The first coin
  that finds a kernel is signed for (:368-371):
  - **An HD key:** `CWallet::GetKey` throws "GetKey: DecryptHDChainSeed failed" while locked (wallet.cpp:536-545),
    which the RPC server answers as -1 (rpcserver.cpp:1107-1108).
  - **An imported key:** `CCryptoKeyStore::GetKey` returns false while locked (crypter.cpp:307-323). The log says
    "CreateCoinStake : failed to sign coinstake", no block is made, and the answer is -25.
  - Staking only, the master key is loaded, so both kinds sign.
- **The staking balance** that bounds the stake set is the balance less the locked coins (wallet.cpp:1377-1385). With
  more locked than the mature balance holds, it goes negative and no coin is selected ("no coins available for
  staking"). The script therefore locks only the HD coins that are at least one block deep.
- **A send** reserves a change key whether or not it has change (`createChangeOutput`, wallet.cpp:1786, :1909-1910).
  Reserving tops the keypool up when the wallet is not locked (wallet.cpp:2129-2130), and the key is returned when no
  change is needed (:1813-1816). So any send on an unlocked wallet leaves the keypool full.

## Known differences

`KNOWN` in `check.py` (a row name with a reason) is for an accidental divid behaviour; it is empty.
