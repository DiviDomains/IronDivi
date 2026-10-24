# Account RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain,
makes the same account changes on both, moves coins between the wallet's addresses, and compares the account replies
field by field, before and after sends and a restart of both nodes. It also asks both for the calls divid does not
have (`listaddressgroupings`, `getmempoolentry`, `abandontransaction`). Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/accounts-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/accounts-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes 15 to 30 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The phrase is read from divid's `dumphdinfo`
reply and handed to irondivid in its environment (`WALLET_MNEMONIC`); it is never printed, written to a file or put
on a command line.

`estimatefee` and `estimatepriority` are compared in `scripts/util-replies`, not here.

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain, and both wallets own the same keys. Both run
with `staking=0`.

1. Each node mines 20 blocks; the coinbases are both wallets'. Each node mining the same number of blocks keeps the two
   wallets' HD key counters equal: a wallet restored from a phrase does not know which keys the other node gave to its
   coinbases (Divi Core has no `MarkReserveKeysAsUsed` either), so if only divid mined, the next key each hands out
   would differ. Every later block is also mined once by each node.
2. Addresses are handed out by the same call on both, and must be the same: `getnewaddress ""` (A0),
   `getnewaddress acctB` (B0), `getaccountaddress acctC` (C0, a new account). An address nobody holds a key for (W,
   random bytes) is used for the "not in the wallet" rows.
3. The account rows (`before sends:`).
4. `setaccount B0 acctD` on both (B0 was acctB's current address, so acctB gets a new one), the `setaccount` error
   rows, then the account rows again (`after setaccount:`).
5. divid sends 7 to B0, 3 to A0 and 1 to W; one block from each node confirms them; then a send of 2 to C0 stays in
   the mempool. The account rows and balances again (`after sends:`).
6. The calls divid does not have, then balances and history again (`after abandontransaction:`).
7. Both nodes are stopped and started again; the account rows and balances again (`after restart:`).

## Rows

| call | forms |
|---|---|
| `getnewaddress` | `""`, `acctB` (same address on both); `*`, `5`, `a b` |
| `getaccount` | A0, B0, C0, W, `xyz`, none, `123`, `A0 1` |
| `getaccountaddress` | `acctC` (new account); `""`, `acctB`, `acctC`, `acctD`, none, `*`, `5`, `a b` |
| `getaddressesbyaccount` | `""`, `acctB`, `acctC`, `acctD`, `nosuch`, none, `5`, `a b`, `*` |
| `setaccount` | `B0 acctD` (a move of an account's current address); `W x`, `xyz x`, none, `A0 *`, `A0 5`, `A0 a b`, `A0` |
| `listaccounts` | none, `0`, `1`, `9999999`, `0 true`, `1 false`, `x`, `1 2 3` |
| `getreceivedbyaccount` | `""`, `acctB`, `acctC`, `acctD`, `nosuch`, `acctD` with minconf 0, 1 and 9999999, `"" 0`, none, `acctD "1"`, `*` |
| `listreceivedbyaccount` | none, `0`, `0 true`, `1 false`, `9999999 true`, `0 true true`, `x` |
| `getbalance` | none, `* 0`, `""`, `acctB`, `acctD`, `acctD 0` |
| `listtransactions` | `* 100 0`, `acctD 100 0` |
| `listaddressgroupings` | none, `1`, `x` |
| `getmempoolentry` | the mempool send, a confirmed send, an unknown txid, `zz`, none |
| `abandontransaction` | the mempool send, a confirmed send, an unknown txid, none |

How a row compares: the same outcome (a result, or an error with the same code and message); for a result every field
and value, list items in divid's order. `getaddressesbyaccount` and `listreceivedbyaccount` lists are compared after
sorting (by address, by account). Left out of the comparison, because they come from the moment a node saw a
transaction and the two nodes see a relayed one seconds apart: `time` and `timereceived`; and the send notes
(`comment`, `to`, `FromAccount`), which only the node that made the send has.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

None differ. The calls divid does not have are KNOWN rows only because both nodes refuse them the same way
(-32601 "Method not found"; they are not in `rpcserver.cpp`'s table, `:324-467`): `listaddressgroupings`,
`getmempoolentry`, `abandontransaction`. Such a row is a `FAIL` if irondivid answers it. So the balance and
`listtransactions` rows after `abandontransaction` show that nothing was abandoned on either node.

## Proving a difference is caught

`ACCOUNTS_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`ACCOUNTS_REPLIES_INJECT='before sends: listaccounts []'`: that row prints `FAIL` and the run exits 1.
`ACCOUNTS_REPLIES_DUMP=<dir>` writes both replies of every compared row to `<dir>`, for looking into a FAIL.
