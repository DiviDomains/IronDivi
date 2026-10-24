# Address index, spent index and lottery RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid that follows divid's regtest chain, both with
`-addressindex -spentindex`. divid mines past the last proof-of-work block into the lottery, pays two of its addresses,
spends one of their coins, and leaves one payment in the mempool. The script then compares the address index, spent
index and lottery replies field by field. A fresh pair without the indexes follows, for the refusals. Each row prints
one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/index-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/index-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's). Both
  pairs of nodes use the same four ports, one pair after the other.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 15 seconds and is stopped after 10 minutes. However it ends, every node is stopped and its directory
deleted. Needs bash and python3 (standard library only). RPC passwords are made for the run and written only to each
node's `divi.conf`, which only the user can read; nothing secret is printed or put on a command line.

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain. Both run with `staking=0`, and the first pair
with `addressindex=1`, `spentindex=1` and `txindex=1`.

1. divid mines 40 blocks and hands out two addresses, A and B. A third address, N, is made from random bytes, so
   nobody pays it.
2. Three payments, 10 to A, 5 to B and 3 to A, go in block 41 (`start`). A raw transaction spends A's 10 DIVI coin
   to B in block 42 (`end`).
3. divid mines one block at a time to 112: proof of stake from 101 on, and lottery blocks at 101 and 111.
4. One more payment to A stays in the mempool. Then the replies below.
5. Both nodes are stopped. A fresh pair without the indexes starts; divid mines 26 blocks with one payment to a new
   address; then the `no index:` rows.

## Rows

For each of `getaddressbalance`, `getaddressdeltas`, `getaddresstxids`, `getaddressutxos` and `getaddressmempool`:

| forms | |
|---|---|
| good | A; `{addresses: [A]}`; `[A, B]`; `[B, A]`; `[A, B]` with `start`/`end`; `start` alone; `chainInfo`; `[A, B]` with `start`, `end`, `chainInfo`; N; `{addresses: []}`; `start` as text; `chainInfo` as text; A with only_vaults true and false |
| wrong | no argument; three arguments; `notanaddress`; a number; `addresses` not a list; `{}`; a bad address in the list; a number in the list; only_vaults as text; `start` 0; `end` before `start`; `end` past the tip with `chainInfo` |
| no index | A; `[A, N]`; `notanaddress` |

The other calls:

- `getspentinfo`:
  - good: the spent coin; an unspent output; an index past the outputs; an unknown txid; a mempool transaction's
    output; a negative index;
  - wrong: no argument; two arguments; a string; no `index`; `index` as text; a txid that is not hex; a short txid;
  - no index: an output; no `index`.
- `getlotteryblockwinners`:
  - good: no argument; the tip; 111, 105, 101, 100, 50; past the tip;
  - wrong: text; a real; two arguments;
  - not sent to divid: -1, and a chain below block 101 (KNOWN, below).

divid 3.0.0 has no `getaddressmempool` (rpcserver.cpp:411-417), and neither has irondivid. Its rows compare the two
"Method not found" replies, so a node that starts to answer it shows up.

How a row compares:
- Both must have the same outcome: a result, or an error with the same code and message.
- For a result, every field name, type and value must match, and list items must come in divid's order: the order of
  divid's address index, and for several addresses the order they are given in.
- divid answers a wrong argument count with the call's help text. That text is not compared; both must refuse with -1.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

- **Address index off:** `no index:` rows of `getaddressbalance`, `getaddressdeltas`, `getaddresstxids` and
  `getaddressutxos` (8 rows). divid answers -5 "No information available for address" (rpcmisc.cpp:658, :662).
  irondivid answers -5 with a text that names the option to set (docs/divid-differences.md R7). An address that is
  not valid is still refused first with divid's -5 "Invalid address".
- **`getlotteryblockwinners -1`:** not sent to divid. divid reads the block at height -1, a null pointer
  (rpclottery.cpp:48-51), and stops. irondivid answers for genesis; the row shows irondivid's answer only.
- **`no index: getlotteryblockwinners, chain below block 101`:** not sent to divid. Before the first lottery block
  (101 on regtest), divid takes the missing block 101 as the last lottery block (LotteryWinnersCalculator.cpp:63-68)
  and stops on its null pointer (rpclottery.cpp:53-56); a 26-block regtest chain makes divid end with a segmentation
  fault. irondivid answers an error; the row shows it only.

No other row differs from divid.

## Proving a difference is caught

`INDEX_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared. For example,
`INDEX_REPLIES_INJECT='getaddressbalance address'` makes that row print `FAIL`, and the run exits 1.
`INDEX_REPLIES_DUMP=<dir>` writes both replies of every differing row to `<dir>`, for looking into a FAIL.
