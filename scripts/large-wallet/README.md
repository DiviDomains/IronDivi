# A large wallet, next to Divi Core

`run.sh` builds one large wallet on Divi Core 3.0.0 `divid` and on an irondivid restored from divid's phrase, side by
side on one regtest chain, with a divid miner of its own. Then it compares the list calls' paging and order over the
whole history, the totals, coin selection over many small coins, and a restart and a `-rescan` restart (with their
wall time). Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `ORDER`: the same members or list items as divid's, in another order (a FAIL, counted in `FAILS`;
  `scripts/lib/member_order.py`);
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with the wall times and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 60 minutes).

```sh
scripts/large-wallet/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/large-wallet/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (divid, irondivid and the miner, p2p and RPC).
  The copies use the first four; `<port-base>+9` is used as a peer that does not exist.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `LARGE_WALLET_SEED` (11) seeds every choice. The sizes are `LARGE_WALLET_ADDRESSES` (500),
  `LARGE_WALLET_RECEIVE_TXS` (300, ten outputs each), `LARGE_WALLET_SEND_PAIRS` (100) and `LARGE_WALLET_STAKES`
  (300). `LARGE_WALLET_DUMP=<dir>` writes both replies of every row that differs.

A run takes about 6 minutes and is stopped after 60. However it ends, every node is stopped and every directory
deleted. Needs bash and python3 (standard library only). The phrase is read from divid's `dumphdinfo` reply and
handed to irondivid in its environment (`WALLET_MNEMONIC`) at its first start only; it is never printed, written to a
file or put on a command line. Every key is a throwaway of the run.

## The wallet

Every operation is made with each node's own RPCs, from one seeded list:

- **Addresses:** 500 over six accounts (`""`, `alpha`, `beta`, `gamma`, `small`, `savings`). Each is handed out by
  `getnewaddress <account>` on both nodes, and the two must give the same address.
- **Receives:** 300 miner transactions of ten outputs each, 3,000 receives in all. Six outputs of each go to the
  `small` account, with 0.01 to 0.99 DIVI, so about 1,800 coins under 1 DIVI; four larger ones go elsewhere. Both
  nodes have each transaction before the next is sent: a wallet lists what it learns in the order it learns it, and
  relay can hand two nodes a burst in two orders.
- **Sends:** 100 pairs, 200 sends. Each is made on divid first, then on irondivid once it has divid's (as
  `scripts/wallet-replies`), so each wallet holds one copy it made and one it only saw. They are `sendtoaddress` to
  the miner, `sendtoaddress` with `metadata` comment and comment-to, to the miner or to the wallet's own addresses,
  and `sendmany`, with a block after every ten pairs. One pair is left unconfirmed.
- **Stakes:** divid stakes the twins' coins for 300 blocks (`setgenerate 1` each).
- **Locks:** 60 coins locked with `lockunspent false` on both.

## Rows

Core paths are under `divi/src/` of the Divi Core source at v3.0.0. How a row compares, as in
`scripts/wallet-replies`: the same outcome; for a result every field and value, list items in divid's order. Left out:
`time` and `timereceived` (the moment a node saw a transaction); the notes `comment`, `to` and `FromAccount`, which
exist only on the node that made the send and are compared one node's own copy against the other's. Lists that divid
writes in a map's order are compared sorted.

| part | rows |
|---|---|
| paging and order | `listtransactions * 100000 0` (the whole history, about 3,600 entries); pages of 700 over all of it; `from` past the end and 5 before it, `count 0` (with `from` 0 and 50), `count -1`, `from -1`, `count 1`; the account `""` (500 and all), `small` (all, and 50 from 300), `savings` 20, an account with no addresses |
| notes | each node's own copy of each of the 101 send pairs: `comment`, `to`, `FromAccount` |
| `listsinceblock` | none, and from blocks at heights half, tip-60, tip-5 and the tip |
| `listreceivedbyaddress`, `listreceivedbyaccount` | none, `0 true`, `1 false`, `6 true`, `100 false` |
| `listunspent` | none, `0`, `1 5`, `10 50`, `200 9999999`, `1 9999999 [three addresses]`, `0 9999999 [one address]`; `listlockunspent` |
| totals | `getbalance` none, `*`, `* 0`, `* 6`, each account with minconf 1 and 0; `getunconfirmedbalance`; `listaccounts`; `getwalletinfo`; `getstakingstatus`, without `staking status` (whether the node itself tried to stake in the last minutes, `rpcmisc.cpp:1071-1072`; only divid stakes here) |
| coin selection | on fresh, unconnected copies of both: `sendfrom small 5`; `sendfrom small` amounts that need about 300 and about 900 of its coins (taken largest first when none covers the amount alone, `MinimumFeeCoinSelectionAlgorithm.cpp:127-140`). 900 inputs go over divid's 100,000-byte limit (`:93`, `defaultValues.h:54`): -4 `Insufficient funds to meet coin selection algorithm requirements.` Last, `sendtoaddress 2000` from every coin. Compared: the coins spent, how many, the fee, the outputs |
| restart, `-rescan` | both stopped and started (then with `-rescan`): height, `getbalance`, the number of `listtransactions` entries, then every row above again. Printed, not compared: the wall time from start to the first RPC answer and to the tip, and irondivid's time over divid's |

## KNOWN

- `getstakingstatus` (before the restart): with coins locked, divid's staking balance takes off, for each locked coin,
  the wallet's credit from the whole transaction, not the coin's value: `lockedCoinBalance` adds
  `getCredit(*walletTx)` (`wallet.cpp:2236-2252`). Locked coins of a transaction that paid the wallet several outputs
  take off too much; the balance can go below 0, which also makes `enoughcoins` and `mintablecoins` false
  (`rpcmisc.cpp:1063-1066`, `wallet.cpp:1377-1385`, `:1466-1469`). irondivid takes off the locked coins' values. divid
  is wrong here by accident. `lockunspent` is not kept across a restart, so the rows after it match.
- Extra fields, by design (each named in a `fields divid lacks` row): `getwalletinfo` `walletname`, `keypoololdest`,
  `paytxfee`, `hdmasterkeyid` (`docs/divid-differences.md` R4); `listreceivedbyaddress` `label`; `listunspent`
  `ischange`, `solvable` (as `scripts/wallet-replies`); `getstakingstatus` `staking status text` (as
  `scripts/received`, `scripts/start-rescan`).
