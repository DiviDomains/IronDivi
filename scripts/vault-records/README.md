# Vaults and their records across a wallet's life, next to Divi Core

`run.sh` starts four regtest nodes on one chain:
- Divi Core 3.0.0's `divid` as a vault owner (it mines), and as a vault manager (`vault=1`);
- an irondivid owner and an irondivid manager (`vault=1`), restored from the two divid phrases, so each irondivid wallet holds the same keys as its divid twin and sees the same vault coins.

It puts the wallets through the steps below and, after each one, compares what every twin pair answers. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25 minutes).

```sh
scripts/vault-records/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/vault-records/run.sh target/release ~/divi-3.0.0/bin 55500 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: twelve ports on 127.0.0.2, `<port-base>` to `<port-base>+11`: the p2p and RPC port of the divid owner, the divid manager, the irondivid owner, the irondivid manager, and (for a few rows) a fresh divid and a fresh irondivid wallet. The divid owner listens; the others dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 8 minutes. However it ends, all nodes are stopped and their directories deleted. Needs bash and python3 (standard library only). The two phrases are read from the divid nodes' `dumphdinfo` replies and handed to irondivid in its environment (`WALLET_MNEMONIC`); the manager key of the fresh-wallet rows comes from `dumpprivkey` and goes straight into `importprivkey`. None of them is printed or put on a command line.

## The vaults

Three vaults share one manager key. The owner pays each its first coin, the managers `addvault` vaults 1 and 2 with it, and the owner pays vaults 1 and 2 a second coin that the managers see as it arrives. Vault 3 is paid but never added.

- Vault 1 is the one `removevault` is called on.
- Vault 2 stays registered all along.
- Vault 3 is a vault the manager never registered, until the last step.

## Steps

After each step, the views of each twin pair (owner against owner, manager against manager):
- `getbalance` with no arguments, with `* 1 true`, and with `* 0`;
- `listunspent`, and `listtransactions * 100 0 true`;
- `gettransaction` of every transaction the run made;
- `getcoinavailability`, and `getcoinavailability true`;
- `getwalletinfo` (divid's fields);
- `getstakingstatus` (every member, then the members' order).

1. **Registered:** the views; a `backupwallet` of all four wallets (kept for step 6); a restart of all four; the views; each manager spends a plain coin of its own (`sendtoaddress`).
2. **removevault** of vault 1 on both managers: the views; the managers spend a plain coin; each manager stakes one block (`setgenerate 1`) with its plain coins locked, and the run asks whether the coinstake spends a coin of vault 1; `removevault` again.
3. **Every way the wallet comes back,** each preceded by `removevault` of vault 1, each followed by the views: a restart, `-rescan`, `-reindex`, `-zapwallettxes=1`, `-zapwallettxes=2` (divid 3.0.0 has no such option and ignores it; irondivid takes it as a no-op, `scripts/wallet-start`). Then the managers spend a plain coin; vault 2 is removed so that only vault 1 is left, and each manager stakes a block (vault 1's coin must be the one spent, on both).
4. **`backupwallet` made after `removevault`,** all four wallets stopped and started from the copy; the views.
5. **A copy made before `removevault`** (step 1's) put back in place of each wallet, started, the views; a stake with vault 1 the only vault left.
6. **Fresh wallets:** divid 3.0.0 has neither `dumpwallet` nor `importwallet` (`rpcserver.cpp:420-464`), so the manager's key goes from `dumpprivkey` into `importprivkey` of a fresh divid and a fresh irondivid wallet; the views; `addvault` of vault 2 with a new coin (the coin paid while the managers have vault 2 removed in memory); the views; a restart; the views; `-rescan`; the views.
7. **Vaults funded while the managers are down:** vault 1 (removed), vault 2 (registered) and vault 3 (never added) are each paid while both managers are stopped; the managers start; the views; `addvault` of vault 3 with its coin; the views; a stake with vault 1 the only vault left.

## How a row compares

The same outcome: a result, or an error with the same code and message. For a result, every field and value must match.

Left out of the comparison: `time`, `timereceived` and `blocktime`, which come from the moment a node saw a transaction, and the notes `comment`, `to` and `FromAccount`, which only the sending node has. List items are compared sorted. A stake is compared by whether it is accepted by all four nodes and whether its coinstake spends a coin of vault 1; which of several stakable vaults a manager picks is not fixed, so vault 1 is asked about only when it must not be staked or is the only one left.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## What Divi Core does, and irondivid with it

- `addvault` stores the vault script in the wallet file (`wallet.cpp:671-678`, `AddCScript`; `walletdb.cpp:141-144`) and adds the funding transaction (`wallet.cpp:693-706`). Only that transaction: a second coin paid before `addvault` is found by a rescan.
- `removevault` erases the script from memory (`wallet.cpp:707-716`). The `cscript` record stays in the wallet file, and the next start loads it (`walletdb.cpp:402-409`, `wallet.cpp:680-691`, whatever `-vault` says). A restart, `-rescan`, `-reindex` or a start from a copy therefore manages the vault again, with the coins and transactions the wallet file still holds.
- A vault output is the manager's own only while its script is in memory (`wallet_ismine.cpp:84-97`), so after `removevault` its coins are in no balance, no `listunspent`, no `getcoinavailability`, and the manager does not stake them.
- irondivid does the same. `removevault` takes the vault out of the running wallet and its coins out of the coin set and leaves both on disk; the next start loads them.

## KNOWN differences

By design:
- `getcoinavailability`: irondivid adds `total_vaults` and `vaults`; divid has `Vaulted`, `Stakable` and `Spendable` only (`rpcwallet.cpp:818-987`). Compared without them.
- `getstakingstatus`: irondivid adds `staking status text`; `mnsync` is true on irondivid (no masternode sync of its own) and false on a divid regtest node with no masternodes (`rpcmisc.cpp:1068`).
- **After `removevault`, until the next start: `gettransaction`'s `amount` of the removed vault's funding transactions, and `getstakingstatus`' `staking_balance` and `enoughcoins`.** divid keeps each transaction's credit and balance in a cache (`CachedTransactionDeltasCalculator.cpp:108-118`, `CachedUtxoBalanceCalculator.cpp:11-32`) that `removevault` never clears (`wallet.cpp:707-716`), so it still counts the removed vault's coins in those three fields while `getbalance`, `listunspent` and `getcoinavailability` already leave them out. irondivid works the fields out from the wallet as it is, so they agree with those three; the value divid shows is a stale number, not state. The next start gives the same numbers on both, since the vault is registered again.

Copying divid's stale numbers would count coins a manager can no longer stake, and would put them in the coin set that the rows `manager sendtoaddress of a plain coin` rely on (a manager spends its own plain coins while it holds a registered vault, after `removevault` and after the restarts).

Not in the run, and not the same on both sides: a start scans the chain above the wallet's last scanned block on irondivid; divid scans from its stored best block, which is the last block itself after a clean stop (`wallet.cpp:258-269`, `:279-313`; "Scanning... from height N to N"). A coin paid to a vault that was unregistered in the running wallet (after `removevault`), when it is the last block at the stop, is found by divid at the next start, because the vault is registered again by then, and not by irondivid. The run keeps such a coin out of the last block (step 6 mines two blocks after it); any later block hides it, since a start scans no further back than the last block.

## Proving a difference is caught

`VAULT_RECORDS_INJECT=<row name>` changes irondivid's reply of that row before it is compared, for example `VAULT_RECORDS_INJECT='registered: owner getbalance []'`. That row prints `FAIL` and the run exits 1.

`VAULT_RECORDS_DUMP=<dir>` writes both replies of every row that differs to `<dir>`, for looking into a FAIL.
