# Mining on a locked wallet, next to Divi Core

random-sequences seed 9 reached, by chance, a `setgenerate` on an encrypted HD wallet that was locked, past the last
work block:
- divid answered -1 "GetKey: DecryptHDChainSeed failed";
- irondivid answered -25 "failed to generate a valid block".

This script reaches that state and its neighbours on purpose, with no random seed.

`run.sh` starts, on regtest and on 127.0.0.2:
- one Divi Core 3.0.0 `divid`;
- one irondivid restored from divid's phrase (`WALLET_MNEMONIC` in its environment).

The two are not connected. Each mines its own chain with the same calls, so the heights stay equal. Both run with
`keypool=3`, so a locked wallet runs out of keypool keys within a few blocks.

```sh
scripts/locked-stake/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/locked-stake/run.sh target/release ~/divi-3.0.0/bin 53850 /var/tmp
```

- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (p2p and RPC of divid, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, with both nodes
  stopped.
- `LOCKED_STAKE_TIMEOUT`: seconds before the run is stopped (900).

A run takes about a minute. It needs bash and python3 (standard library only). The wallet passphrase is made at random
and sent only in RPC requests. RPC passwords are random and kept in each node's 0600 `divi.conf`. Neither they nor the
phrase are printed, written elsewhere or put on a command line.

## Rows

Each row is one call on both nodes. Compared:
- its outcome: `ok`, or the error code and text;
- the block count;
- the wallet after it, from `getwalletinfo`: balance, immature balance, transaction count, keypool size, encryption
  status, and whether it is unlocked.

A row that differs is a `FAIL`, printed with both outcomes and both states; the exit code is the number of FAILs.

In order:
1. `encryptwallet`. The wallet is then locked.
2. **Locked, work blocks:**
   - `setgenerate 1` with keys in the keypool;
   - `generateblock`;
   - `setgenerate 6`, more than the keypool holds;
   - `setgenerate 1` on the empty keypool;
   - `getnewaddress` on the empty keypool.
3. **Unlocked:** `walletpassphrase` fully; work blocks up to 100 (the last work block on regtest); one stake block.
4. **Locked, stake blocks:** `walletlock`; `setgenerate 1` twice; `generateblock`; `getnewaddress`.
5. **Staking only:**
   - `walletpassphrase … true`;
   - stake blocks;
   - a send, which is refused;
   - `walletpassphrase … true` again;
   - `walletlock`;
   - a locked stake block.
6. **A full unlock over a staking-only one:** `walletpassphrase … true`, then `walletpassphrase` fully for 2 s. After
   the 2 s the wallet is staking-only again, and a stake block is made.

## What Divi Core does (core-src 9e2f76c)

- `setgenerate` calls `minter.createNewBlock()` until the height is reached. A block not made is -25 "failed to
  generate a valid block" (rpcmining.cpp:52-118). `generateblock` makes its one block through the same call
  (rpcmining.cpp:200-208).
- **A work block** (up to 100) pays a key from the keypool (CoinMinter.cpp:142-159, reservekey.cpp:16-30).
  - A locked wallet hands out a pregenerated key without topping the keypool up (`ReserveKeyFromKeyPool`,
    wallet.cpp:2122-2156).
  - With the keypool empty no key is reserved, so no block is made: -25.
- **A stake block** (CoinMinter.cpp:128-140, PoSTransactionCreator.cpp:318-387) selects the stake coins and finds the
  kernel; neither needs a private key. The coinstake pays back to the kernel's own script, so it needs no new key
  (PoSTransactionCreator.cpp:162-170). It is then signed with the kernel's key (`SignSignature`, :368-371):
  - **A key of the HD seed:** `CWallet::GetKey` derives it on the fly, and the seed is encrypted. It throws
    `std::runtime_error("GetKey: DecryptHDChainSeed failed")` (wallet.cpp:536-545). The RPC server answers any thrown
    exception as -1 with its text (rpcserver.cpp:1107-1108).
  - **An imported key:** `CCryptoKeyStore::GetKey` returns false while locked. The signing fails, so no block is made:
    -25.
- **The background miner** stakes only when `CanStakeCoins()`, that is not locked (CoinMinter.cpp:65-82,
  wallet.cpp:1483-1486), so a locked wallet never reaches the signing there. Had it thrown, MinterThread would log
  "runtime error" and end (miner.cpp:147-167).
- **Staking only** (`walletpassphrase … true`) unlocks the keys and sets `walletStakingOnly` (wallet.cpp:777-806). So
  `GetKey` works and stake blocks are made. The keypool is topped up (rpcwallet.cpp:2620). Sends are refused with -13.
  A second staking-only unlock is -17 "Error: Wallet is already unlocked for staking." (rpcwallet.cpp:2611-2614).

## Known differences

`KNOWN` in `check.py` (a row name with a reason) is for an accidental divid behaviour; it is empty.
