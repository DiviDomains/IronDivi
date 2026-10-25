# Wallet transaction times next to Divi Core

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` wallet that mines and sends;
- **C**, a `divid` wallet;
- **I**, an irondivid restored from C's phrase, so C and I own the same coins and see the same transactions.

For each kind of wallet transaction it compares `time` (divid's GetTxTime, the smart time) and `timereceived`
(nTimeReceived) of C and I, in `gettransaction`, `listtransactions` and `listsinceblock`, then again after a restart
and after `-rescan`. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/smart-time/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/smart-time/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2, the p2p and RPC port of S, C and I. S listens; C
  and I dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 5 minutes and is stopped after 10 minutes. However it ends, all three nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). C's phrase is read from its `dumphdinfo` reply
and handed to irondivid in its environment (`WALLET_MNEMONIC`); it is never printed, written to a file or put on a
command line.

## What divid does (Divi Core 3.0.0, `divi/src/`)

- `nTimeReceived` is set once, to the adjusted time, when a transaction first enters the wallet
  (SpentOutputTracker.cpp:39-48). That holds for a rescan too: a transaction the wallet already holds keeps it
  (addToWallet only updates, wallet.cpp:1242-1260); none of 3.0.0's code sets it to a block time.
- `nTimeSmart` is set once, at that same moment (wallet.cpp:1253-1256), by smartWalletTxTimestampEstimation
  (wallet.cpp:1052-1086): the received time for a transaction not in a block; for one first seen in a block, its
  block time, but no later than the received time (or a later entry of the wallet up to five minutes ahead), and no
  earlier than the latest earlier entry of the wallet, in the wallet's own order (nOrderPos).
- Replies: `time` is GetTxTime (nTimeSmart, else nTimeReceived), `timereceived` is nTimeReceived
  (rpcwallet.cpp:267-268). `listtransactions` follows nOrderPos (OrderedTxItems, wallet.cpp:1034-1050), not the smart
  time.

## Steps and rows

1. S mines blocks 1-50 and C blocks 51-100 (coinbases of the twins' wallet), then S mines 25 more.
2. Each case below gives two rows: how `time`, `timereceived` and `blocktime` relate (`<`, `=`, `>`, or "within TOL"
   when a block time and a clock time are within TOL of each other), and the values themselves.
   - a coinbase of the twins' wallet;
   - a receive in the mempool, then the same receive mined 10 s later (divid keeps the received time);
   - a receive first seen in a block (S mines it with `generateblock {"extratx": [...], "ignoreMempool": true}`
     without relaying it first, the coin it spends locked so S's own stake does not take it);
   - a receive in a block dated behind the wallet's latest entry: once the clock is 40 s past the tip, a receive in
     the mempool is the latest entry; then S, its clock set 20 s back with `setmocktime`, mines a block with another
     receive (also: that receive's `time` is not before the latest entry's);
   - a send from C, in the mempool, then mined;
   - a coinstake of the twins' wallet (C stakes with `setgenerate`);
   - a receive in a block dated ahead of the clock (S's clock set 90 s ahead for that one block; last, as S's next
     blocks would wait for the clock).
3. `listtransactions * 1000 0 true` and `listsinceblock`: every entry's `time` and `timereceived`, and the order of
   the `listtransactions` entries.
4. Both twins restarted, then restarted with `-rescan`: every case's times as before the restart (on each node),
   and the lists again.

**Tolerance:** times read from a node's clock (`timereceived`, and `time` when it comes from `timereceived`) may
differ between C and I by `TOL` = 3 s: the twins hear of a transaction a moment apart (relay, then each node's own
processing, and the second each reads its clock in). Block times are compared exactly.

## KNOWN differences

None: every row matches divid.

## Proving a difference is caught

`SMART_TIME_INJECT=<row name>` marks that row as differing, e.g.
`SMART_TIME_INJECT='a send, mined: time and timereceived (within 3 s)'`: that row prints `FAIL` and the run exits 1.
