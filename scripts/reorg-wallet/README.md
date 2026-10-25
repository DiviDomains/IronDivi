# Wallet changes across a reorganisation, next to Divi Core

`run.sh` starts five regtest nodes:
- Divi Core 3.0.0's `divid` as an owner (the first miner) and as a manager (`vault=1`);
- an irondivid owner and manager restored from the same two phrases, so each irondivid wallet holds the same keys as its divid twin;
- a second `divid` miner holding the owner's keys (its `divi.conf` has the owner's phrase, mode 0600), cut off from the others until a round joins it.

All of them but the second miner run `-walletnotify` (the txid is appended to a log of the node's own). Each round puts a branch on the four wallet nodes, builds a longer one on the second miner, joins the two with `addnode ... onetry`, and compares every twin pair and the notify logs. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25 minutes).

```sh
scripts/reorg-wallet/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/reorg-wallet/run.sh target/release ~/divi-3.0.0/bin 55500 /var/tmp
```

- `<port-base>`: ten ports on 127.0.0.2, the p2p and RPC port of each node in turn. The divid owner listens; the others dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 12 minutes. Needs bash and python3 (standard library only). Keys and phrases are never printed or put on a command line.

## Rounds

Two registered vaults and a plain coin first. After each step: `getbalance` (three forms), `getunconfirmedbalance`, `listunspent`, `listtransactions * 100 0 true`, `gettransaction` of every transaction the run made, `getcoinavailability`, `getwalletinfo`, `getstakingstatus` on the owner pair and the manager pair, the mempools of each pair, and the `-walletnotify` calls since the last mark (a transaction told twice counts twice; when a count differs the run prints each side's order and the transactions that differ). Each round is compared before, on the first branch, and after the reorganisation.

1. **Double spend:** the first branch holds a payment from the owner to the manager (raw, so the owner's wallet did not make it with `sendtoaddress`); the second miner spends the same coin to the owner's own address and mines four blocks.
2. **A chain of three:** a spends a coin, b spends a's change, c spends b's change, each in its own block; the second branch double-spends the coin a spent, so a is dropped and b and c lose their input.
3. **Orphaned stakes:** three blocks staked by the owner replaced by four of the second miner's.
4. **A vault:** the owner funds a registered vault; the manager stakes a block of its vault coins; the second miner double-spends the funding's inputs and mines five blocks. The manager's coinstake is orphaned and the funding dropped.
5. **A kill:** four payments with a block each, then `kill -9` of both managers and a start. divid stops with a block index error and is started with `-reindex`.

## What Divi Core does

- A disconnected block: the mempool takes its non-coinbase, non-coinstake transactions back (`AcceptToMemoryPool`, which tells the wallet), then the wallet is told of every transaction of the block (`ChainTipManager.cpp:162-190`; coinbase and coinstake included), and the best block is flushed (`:174`).
- The new branch: transactions the mempool holds that conflict with a block's are removed and the wallet is told of them (`CONFLICTED_TX`), then of the block's transactions (`ChainTipManager.cpp:143-150`).
- A wallet transaction with no block is at depth 0 when the mempool holds it and -1 when it does not (`MerkleTxConfirmationNumberCalculator.cpp:48-53`); `gettransaction` shows `walletconflicts` from the wallet's spent-output tracker (`rpcwallet.cpp:263-266`). A wallet transaction is never forgotten: `getwalletinfo` `txcount` is the wallet map (`rpcwallet.cpp:2894-2906`).
- `-walletnotify` is called for every `addToWallet`, whatever the reason (`wallet.cpp:1283`).

So a payment the new branch drops is told of three times (disconnect, mempool, conflicted), and one it mines again four times (block, disconnect, mempool, block).

## KNOWN differences

By design:
- `getcoinavailability`: irondivid adds `total_vaults` and `vaults` (`rpcwallet.cpp:818-987`); `getstakingstatus`: `staking status text`, and `mnsync` (`rpcmisc.cpp:1068`).
- **A kill.** divid cannot be started after `kill -9`: its block index is flushed only with its state (`FlushChainState.cpp:25-52`), and after an unprepared shutdown it stops with "Block database corruption detected" (`BlockIndexLoading.cpp:262-276`); irondivid starts (`scripts/unclean-stop`). With `-reindex` divid scans from the wallet's best block, written only when it flushes (`FlushChainState.cpp:50-53`), and tells of every wallet transaction since; irondivid saves its scan height with each block and tells of the last block only. The balances, lists and views agree.

## Proving a difference is caught

`REORG_WALLET_INJECT=<row name>` changes irondivid's reply of that row before it is compared. `REORG_WALLET_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
