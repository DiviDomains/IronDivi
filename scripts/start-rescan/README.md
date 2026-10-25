# What the wallet scans at start, next to Divi Core

`run.sh` starts four regtest nodes on one chain:
- Divi Core 3.0.0's `divid` as an owner (it mines) and as a manager (`vault=1`);
- an irondivid owner and manager restored from the same two phrases, so each irondivid wallet holds the same keys as its divid twin.

All four run `-walletnotify` (the txid is appended to a log of the node's own). The run stops and starts the nodes in the situations below and, after each start, compares what every twin pair answers and which transactions it was notified of. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25 minutes).

```sh
scripts/start-rescan/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/start-rescan/run.sh target/release ~/divi-3.0.0/bin 55500 /var/tmp
```

- `<port-base>`: eight ports on 127.0.0.2, the p2p and RPC port of each node in turn. The divid owner listens; the others dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 9 minutes. Needs bash and python3 (standard library only). The phrases are read from the divid nodes' `dumphdinfo` replies and handed to irondivid in its environment (`WALLET_MNEMONIC`); none is printed or put on a command line.

## Steps

The wallets hold two vaults (both registered on the managers) and a plain coin. After each step: `getbalance` (three forms), `listunspent`, `listtransactions * 100 0 true`, `gettransaction` of every transaction the run made, `getcoinavailability`, `getwalletinfo`, `getstakingstatus`, on the owner pair and the manager pair, and the `-walletnotify` calls since the last stop: how many, and for which transactions (a transaction told twice counts twice). When a count differs the run prints the order of calls on each side and each transaction that differs, with what it is in the chain.

1. **A plain restart.**
2. **A payment in the last block** to an address the wallet has, then a restart.
3. **A payment in the last block to a vault the wallet learns only at the start:** `removevault` takes vault 2 out of the running wallet, the owner pays it, one block is mined, the nodes restart (the wallet file registers the vault again, `scripts/vault-records`).
4. **The same, one block before the last:** a start scans no further back than the last block.
5. **Options that scan again:** `-rescan`, `-zapwallettxes=1` and `=2` (not options of divid 3.0.0, which ignores them; irondivid takes them as no-ops, `scripts/wallet-start`), `-salvagewallet` (sets `-rescan`, `init.cpp:763-766`).
6. **A wallet file from an older height put back** (`backupwallet`, then a payment, a payment to a registered vault and four blocks, then the copy over each wallet).
7. **A reorganisation while the wallets run:** the last block, with its coinbase and a payment, is replaced by a branch two blocks long; the views and the notifications; then a restart.
8. **A wallet file from before that reorganisation put back** on the chain after it. This is the start after a reorg the wallet did not see: the old tip is in the wallet file, the new chain is on disk.

A stop *during* a reorganisation cannot be made on purpose, since both nodes write the chain and the wallet in one process; step 8 gives the same state at the next start (the wallet's last block is not in the active chain).

## What Divi Core does

- A start scans from the wallet's stored best block, or from the last block of that block's chain still in the active chain, that block included, and with no best block from genesis (`wallet.cpp:244-269` `getNextUnsycnedBlockIndexInMainChain` and `ApproximateFork`, `:279-313` `verifySyncToActiveChain`). `-rescan` starts from genesis (`init.cpp:1242`).
- A wallet file made by `backupwallet` has no fresh best block, so a start from it scans from genesis.
- `-walletnotify` is called for every transaction the wallet adds, whether it is new or already held, new or updated (`wallet.cpp:1283`, `init.cpp:1130-1141`). So a restart tells of the transactions of the last block again, and so does every rescan.
- A disconnected block's transactions are each told of (`BLOCK_DISCONNECT`); the mempool taking the non-coinbase ones back tells of them again (`wallet.cpp:1314-1351`).

## KNOWN differences

By design:
- `getcoinavailability`: irondivid adds `total_vaults` and `vaults`; divid has `Vaulted`, `Stakable` and `Spendable` only (`rpcwallet.cpp:818-987`). Compared without them.
- `getstakingstatus`: irondivid adds `staking status text`; `mnsync` is true on irondivid and false on a divid regtest node with no masternodes (`rpcmisc.cpp:1068`).

## Proving a difference is caught

`START_RESCAN_INJECT=<row name>` changes irondivid's reply of that row before it is compared. `START_RESCAN_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
