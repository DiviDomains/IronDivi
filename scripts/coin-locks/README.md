# Coin locks, block reversal and wallet switching next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain,
so both wallets own the same coins under the same outpoints. It then compares, call by call:

- `lockunspent` and `listlockunspent`;
- what a lock does to `listunspent`, the balances, `getcoinavailability`, `getstakingstatus`, `sendtoaddress`,
  `sendmany` and `fundvault`;
- the locks across `encryptwallet`, `walletlock`/`walletpassphrase`, `invalidateblock`/`reconsiderblock` and a
  restart;
- `reverseblocktransactions` on several blocks;
- `loadwallet` with several files.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/coin-locks/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/coin-locks/run.sh target/release ~/divi-3.0.0/bin 53850 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+4` on 127.0.0.1. These are divid's p2p and RPC ports, then
  irondivid's, then a port nothing listens on, which irondivid dials once the two nodes must keep their transactions
  apart.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about two minutes and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. It needs bash and python3 (standard library only).

Secrets:
- The phrase is read from divid's `dumphdinfo` reply and handed to irondivid in its environment
  (`WALLET_MNEMONIC`).
- The wallet passphrase is made at random and sent only in RPC requests.
- RPC passwords are made at random and kept in each node's 0600 `divi.conf`.
- None of them is printed, written to a file or put on a command line.

`COIN_LOCKS_INJECT=<row name>` changes irondivid's reply of that row before it is compared, to show that a difference
is caught.

## Nodes and coins

divid listens; irondivid dials it (`connect=`). Both run with `staking=0`.

1. divid mines 40 blocks; the coinbases belong to both wallets.
2. divid makes one `sendmany` to three new addresses of the wallet (7, 11 and 13 DIVI) and to an address nobody holds
   a key for (5 DIVI). irondivid sees it, and one block confirms it.
   - The coins compared below are the three wallet outputs, the 5 DIVI output (another wallet's coin), the coinbase
     the `sendmany` spent (a spent coin), a random txid (unknown) and output 99 of the `sendmany` (out of range).
3. From the restart on, irondivid dials the unused port, so each node's sends stay its own.

## Rows

**lockunspent / listlockunspent.**
- Each row is followed by `listlockunspent` on both nodes, compared item by item in divid's order (its
  `std::set<COutPoint>`: the txid as a number, then the output).
- `false` with each kind of coin: a wallet coin, another wallet's coin, a spent coin, an unknown txid, an output out
  of range, the same coin again, and one coin twice in one list.
- Bad objects: a missing txid or vout; a vout that is negative, text, real or null; a txid that is a number, not
  hex, short hex (`ab`), odd-length hex, empty or upper case; an extra member; an item that is not an object; an
  array.
- A good coin followed by a bad object: divid locks the good one before it refuses the list.
- `false []` and `false` with no list; argument errors (`"false"`, an object for the list, none, three arguments);
  `listlockunspent` with an argument.
- `true` with an unknown txid, a locked coin, a coin not locked, no list and `[]`.

**With coins locked.**
- `listunspent`, `listunspent 0`, `getbalance`, `getbalance * 0`, `getcoinavailability` (plain and verbose), and the
  balances of `getwalletinfo`.
- With every coin locked, and then with one coin free: `getbalance`, `getcoinavailability`, `getstakingstatus`,
  `sendtoaddress`, `sendmany` and `fundvault`. The amounts are covered only with locked coins, or by the free coin.
  - For a send, divid's and irondivid's transactions differ (each node's own coin choice), so the outcome is
    compared: made or refused (code and message). A transaction made must spend no locked coin.

**Encryption, blocks, restart.**
- The locks after `encryptwallet`, after `lockunspent` on a locked wallet, after `walletlock`, after
  `walletpassphrase`, and after `walletpassphrase ... true` (staking only).
- `invalidateblock` of the block holding the locked coins, then `listlockunspent`, `listunspent 0`, `getbalance`
  and `getrawmempool`; then `reconsiderblock`.
- A restart of both nodes; divid keeps locks in memory only.

**reverseblocktransactions.**
- Called on the tip, block 30, an unknown hash, `xyz`, `0x` followed by the tip, a number, and no argument.
- After each: `getblockcount`, `getbestblockhash`, `getbalance`, `getrawmempool` and `gettxoutsetinfo`. Its
  `bytes_serialized` and `hash_serialized` come from each node's own files, so they are not compared, and irondivid's
  extra `bogosize` is left out.
- `reconsiderblock` brings the tip back.
- The genesis block comes last of all (see below).

**loadwallet.**
- Called with `wallet.dat` (the loaded wallet), a `backupwallet` copy in the wallet's folder, a name with no file,
  and a `backupwallet` copy outside the datadir; then with a number and with no argument.
- After the four file calls: `getwalletinfo` (its balances, `txcount`, `keypoolsize`, `encryption_status`) and
  `getbalance`; after `wallet.dat` also `getnewaddress`.
- Then a restart of both nodes, and the same rows again.

**Member order.** The members of a `listunspent` item, of `gettxoutsetinfo`, of `getcoinavailability` and of a
`listlockunspent` item, in the order each node writes them.

## KNOWN differences

| Row | Reason |
|---|---|
| `member order: listunspent item`, `member order: gettxoutsetinfo`, `member order: getcoinavailability` | irondivid writes the members of every reply object in name order: serde_json without `preserve_order`, for all replies. The other rows compare members as sets, as the other reply scripts do. |
| `one wallet coin locked: getstakingstatus`, `every coin locked: getstakingstatus`, `one coin free: getstakingstatus` | divid's `lockedCoinBalance` takes off the credit of the *whole transaction* once for each locked output of it (`wallet.cpp:2236-2252`). So `staking_balance` falls below the coins left, even below 0 (`-3734.99990160` with every coin locked). `HasAgedCoins` (`wallet.cpp:1468`) and `enoughcoins` (`rpcmisc.cpp:1066`) follow it. irondivid takes off each locked coin's own value. |
| `loadwallet copy.dat (a backupwallet copy)`, `loadwallet missing.dat (no such file)`, `loadwallet a file outside the datadir`, and the `getwalletinfo`/`getbalance` rows after them that differ | divid switches wallets (`init.cpp:260-279`). For a name with no file it creates a new, empty wallet, and it opens a file outside its datadir. irondivid keeps the wallet it started with: that wallet is wired into the block, mempool and reorg callbacks and the staker at start (`docs/divid-differences.md`, `crates/divi-rpc/tests/divid_differences.rs`). It refuses any other name and says how to start with another wallet. `loadwallet wallet.dat`, the wallet it runs, answers null as divid does. |

## Not run

- **`getstakingstatus` while output 99 of a wallet transaction is locked.** divid's `lockedCoinBalance` reads
  `vout[99]` past the end of the transaction's outputs (`wallet.cpp:2244`) and the node stops. The `getstakingstatus`
  rows are run only while every lock names a real output.
