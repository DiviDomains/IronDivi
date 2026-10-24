# Wallet RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain,
makes the same sends, receives and watch-only import on both, and compares the wallet replies field by field, before
and after a restart of both nodes. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/wallet-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 30 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The phrase is read from divid's `dumphdinfo`
reply and handed to irondivid in its environment (`WALLET_MNEMONIC`); it is never printed, written to a file or put
on a command line.

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain, and both wallets own the same keys. Both run
with `staking=0`.

1. divid mines 40 blocks; the coinbases are both wallets'.
2. divid hands out an address with `getnewaddress acct1`, and irondivid gives it the same account (`setaccount`;
   the same call on divid would also give `""` a new current address there only, since only divid handed it out); an address nobody holds a key for
   (random bytes) is imported on both with `importaddress <addr> watch false`.
3. Four sends, each made on divid first and then on irondivid once it has seen divid's (so each wallet has one copy it
   made and one it only saw): `sendtoaddress` to the account's address; `sendtoaddress` to the watched address with
   `metadata` comment and comment-to; `sendfrom "" ...` with comment and comment-to; `sendmany ""` to both addresses
   with a comment. One block confirms them, then one more pair of sends stays in the mempool.
4. The replies below; both nodes are stopped and started again; the replies again (`after restart:` rows).

## Rows

| call | forms |
|---|---|
| `getbalance` | none, `*`, `* 0`, `* 1 true`, `""`, `"" 1 true`, `"" 0`, `acct1`, `acct1 0`, `watch 1 true`, `watch 1 false` |
| `getunconfirmedbalance` | |
| `listtransactions` | `* 100 0 true`, `* 100 0 false`, `* 3 2 true`, `watch 10 0 true`, `acct1 10 0 true`, `"" 100 0 false` |
| `gettransaction` | each of the ten sends, with includeWatchonly, on both nodes |
| notes | each node's own copy of each send: `comment`, `to`, `FromAccount` (divid's mapValue) |
| `listsinceblock` | none; block 10 with target 1 and includeWatchonly |
| `listreceivedbyaddress`, `listreceivedbyaccount` | none, `0 true true`, `1 false false` |
| `getreceivedbyaddress`, `getreceivedbyaccount` | the account's address, `acct1` |
| `listaccounts` | none, `0 true` |
| `getaddressesbyaccount` | `acct1` |
| `listunspent` | none, `0`, `1 9999999 [address]` |
| `getwalletinfo` | divid's fields; irondivid's extra fields in their own row |

How a row compares: the same outcome (a result, or an error with the same code and message); for a result every field
and value, list items in divid's order. Left out of the comparison, because they come from the moment a node saw a
transaction and the two nodes see a relayed one seconds apart: `time` and `timereceived`. The notes (`comment`, `to`,
`FromAccount`) exist only on the node that made the send, so they are compared in the notes rows, one node's own copy
against the other's. `txids` lists in `listreceivedby*` are compared as sets (divid writes them in its wallet map's
order). `listsinceblock`, `listreceivedby*` and `listunspent` items are compared after sorting by txid/vout or name.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

All by design (extra fields; the run checks they are still the only ones):

- `getwalletinfo`: irondivid adds `walletname`, `keypoololdest`, `paytxfee`, `hdmasterkeyid`
  (docs/divid-differences.md R4).
- `listreceivedbyaddress`: irondivid adds `label` (divid's ListReceived, `rpcwallet.cpp:1793-1912`, has `account`).
- `listunspent`: irondivid adds `ischange`, `solvable` (divid: `rpcrawtransaction.cpp:320-334`).

No other row differs from divid.

## Proving a difference is caught

`WALLET_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`WALLET_REPLIES_INJECT='getbalance []'`: that row prints `FAIL` and the run exits 1.
`WALLET_REPLIES_DUMP=<dir>` writes both replies of every compared row to `<dir>`, for looking into a FAIL.
