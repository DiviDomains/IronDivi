# Large transactions, full blocks and long unconfirmed chains next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` miner on regtest and two followers of it, a `divid` and an irondivid, funded
with the same coins. It reaches divid's size and sigops limits on purpose, fills blocks, and builds long chains of
unconfirmed transactions, then compares the answers, the mempools and the blocks each follower makes. Each row prints
one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 60 minutes).

```sh
scripts/large-transactions/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/large-transactions/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (the miner's p2p and RPC, then divid's, then
  irondivid's). `<port-base>+49` must have nothing listening: a follower started alone is pointed at it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end (kept with
  `KEEP=1`).
- `LARGE_TRANSACTIONS_SMALL` (1500): the number of 1-DIVI coins each follower gets.
- `LARGE_TRANSACTIONS_PARTS` (`1,2,3,4,5`): the parts below to run, by number.
- `LARGE_TRANSACTIONS_DUMP=<dir>`: each FAILing row's two values are written there as JSON.
- `LARGE_TRANSACTIONS_INJECT=<row name>`: changes irondivid's value of that row, which then FAILs (the proof that a
  difference is caught).

However it ends, every node is stopped. Needs bash and python3 (standard library only). RPC passwords are made at
random for each run and kept in each node's 0600 `divi.conf`; every key is a throwaway of the run's own wallets, and
none is printed.

## Set-up

The miner mines 110 blocks and sends each follower the same coins: ten of 100 DIVI, 1,500 of 1 DIVI, and one of 50
DIVI. It sends itself 45 coins of 100 DIVI for the raw transactions it signs (locked, so it does not stake them),
makes 3,000 payee addresses, and mines 25 more blocks. Then all three stop and their data directories are kept as
templates. Each part below starts from fresh copies.

## Rows

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

| part | rows (each compared between the two followers) |
|---|---|
| 1. a transaction's size | the miner signs transactions of exactly 99,999, 100,000 and 100,001 bytes (mostly P2SH outputs, which count no sigops); each follower, alone, gets each by `sendrawtransaction`: the outcome and whether it is in the mempool. divid: at 100,000 and over, not standard, `64: tx-size` (`MempoolConsensus.cpp:69-75`); over 100,000, CheckTransaction first, `16: bad-tx` (`BlockCheckingHelpers.cpp:110-113`, `MempoolConsensus.cpp:276-277`) |
| 1. a transaction's sigops | bare 1-of-1 multisig outputs (20 legacy sigops each) and P2PKH outputs (1 each) to exactly 8,000 and 8,001: 8,000 is taken, 8,001 is `64: bad-txns-too-many-sigops` (`MempoolConsensus.cpp:364-378`, MAX_TX_SIGOPS_CURRENT `defaultValues.h:61`) |
| 2. a block's sigops | three transactions of 7,000 sigops in the mempool (21,000: under block assembly's 40,000, `BlockMemoryPoolTransactionCollector.cpp:270`, over CheckBlock's legacy 20,000, `BlockCheckingHelpers.cpp:87-95`); `setgenerate 1` on each: its outcome, the height after, and what is left in the mempool |
| 3. full blocks | twelve transactions of 90,000 to 95,500 bytes in both mempools (over 1 MB, the block is at most `-blockmaxsize`, 750,000 by default, `BlockMemoryPoolTransactionCollector.cpp:18-27`); the miner stops and each follower mines until its mempool is empty: per block the mempool transactions it takes, in the block's order, and how many are left |
| 4. raw chains | chains of 30, 60 and 120 unconfirmed transactions, each spending the one before, signed by the miner: how many each mempool takes, and that the last depends on the one before (divid has no limit on chains, `MempoolConsensus.cpp:325-351`); then blocks until the mempools are empty. A chain's transactions all have the same priority and fee rate, so the block's order is that of divid's heap among equal candidates: the mempool in txid order, then libstdc++'s `make_heap`/`pop_heap`/`push_heap` (`BlockMemoryPoolTransactionCollector.cpp:149-167`, `:276-337`) |
| 4. a wallet chain | each follower alone, with `-spendzeroconfchange` and every coin but the 50-DIVI one locked, `sendtoaddress <payee> 0.01` 120 times, each spending the last one's change: the first that fails, if any (divid's wallet has no limit either), and the mempool; then every coin unlocked (locked coins do not stake, `AvailableUtxoCalculator.cpp:91`) and blocks until it is empty: as each wallet signs its own transactions, their txids, and so their order in a block, are their own; only how many each block takes is compared |
| 5. wallet fan-outs | each follower alone, with only the 100-DIVI coins unlocked, `sendmany ""` of 100, 500, 1,000, 2,700, 2,900, 2,935 (the most that fit: about 99,980 bytes), 2,936 and 3,000 outputs of 0.01: the outcome (the wallet's "Transaction too large" at 100,000 bytes, `wallet.cpp:1595-1597`, `:1813-1815`; -4, `rpcwallet.cpp:795-800`), the inputs, outputs, the fee in satoshis and whether it is in the mempool. The fee comes from coin selection's size estimate (`MinimumFeeCoinSelectionAlgorithm.cpp:58`, `:87-95`), and stays unless the signed size needs more (`wallet.cpp:1595-1603`), so it does not depend on the signatures' lengths |
| 5. sends of many small coins | with only the 1-DIVI coins unlocked, `sendtoaddress` of 1,499, 499 and 99 DIVI: the same; coin selection stops once the inputs reach 100,000 bytes (`MinimumFeeCoinSelectionAlgorithm.cpp:93`) |
| 5. the balance | after the wallet sends, the balance plus the fees paid (each wallet's signatures differ in length by a byte or so, so sizes differ by a little) and how many sends are in the mempool; then blocks until the mempools are empty, how many each block takes |

How a row compares: the outcome (`ok`, or an error with its code and message), and the values named. A wallet's
transaction is compared by its inputs, outputs, fee and mempool presence, never by its keys or txid.

## KNOWN differences

None.
