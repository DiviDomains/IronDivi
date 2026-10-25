# The mempool during invalidateblock and reconsiderblock, next to Divi Core

random-sequences found, now and then, a mempool difference in the middle of an `invalidate` step that a replay of
its steps did not repeat. This script builds such cases on purpose: one kind of send at a time, placed where an
invalidate of a chosen depth takes it off the chain (or leaves it in the mempool), with both mempools sampled around
each call.

`run.sh` starts two pairs on regtest, on 127.0.0.2:
- **pair C:** two Divi Core 3.0.0 `divid` nodes connected to each other, with `debug=mempool`;
- **pair I:** two irondivid nodes connected to each other, restored from the phrases of their divid twins, with
  `debug=1`.

```sh
scripts/invalidate-mempool/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/invalidate-mempool/run.sh target/release ~/divi-3.0.0/bin 53850 /var/tmp
```

- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2 (p2p and RPC of C1, C2, I1, I2).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, with all four
  nodes stopped.

| Variable | Meaning |
|---|---|
| `SEED` | the order of the rows (1) |
| `ROWS` | `all` (default), or a comma-separated list of `kind:depth:placement` |
| `RESEND_WAIT` | seconds to wait after the settle before one more sample (0) |
| `INVALIDATE_MEMPOOL_LOGS` | a folder to copy the four logs to at the end |
| `INVALIDATE_MEMPOOL_TIMEOUT` | seconds before the run is stopped (2400) |

All rows take about 3 minutes. It needs bash and python3 (standard library only). The phrases are read from the
divid nodes' `dumphdinfo` and handed to irondivid in its environment; they and the random RPC passwords (in 0600
`divi.conf` files) are never printed, written elsewhere or put on a command line.

## Setup

1. Node 1 mines 60 work blocks, node 2 mines 40, node 1 stakes 30 (the last work block on regtest is 100). From then
   on node 1 makes every block, so it holds a coinstake output of every age.
2. Node 2 sends node 1 150 coins of 25 DIVI, so the rows that need an old coin have plain coins. The pairs stake from
   different coins (the stake choice depends on hashes), so a coinbase or coinstake output's exact age differs
   between them.

## Rows

Each row is a kind, a depth (1 to 3) and a placement, on node 1 of both pairs:

| Kind | The send |
|---|---|
| `plain` | `sendtoaddress` of 10 DIVI to node 2, from one old coin (every other coin locked) |
| `child` | `sendtoaddress` of 10 DIVI to itself (`parent`), then a raw transaction spending that 10 DIVI output (`child`) |
| `age20` | a raw transaction spending node 1's coinstake output with 20 confirmations (mature for the mempool, not yet for the wallet) |
| `age21` | the same with 21 confirmations (just mature for the wallet) |
| `vault` | `fundvault` of 10 DIVI from node 1 to a vault managed by node 2, from one old coin |
| `locktime` | a raw transaction with nLockTime the current height and sequence 0xfffffffe: final for the next block only |
| `large` | a raw transaction spending eight old coins, fee 0.01 |

An "old coin" is a plain coin, or a coinbase or coinstake output with at least 25 confirmations, so no invalidate of
depth 1 to 3 can make it immature. `age20` and `age21` coins are read from the block at that height, as `listunspent`
leaves out what the wallet counts as immature (under 21 confirmations).

| Placement | Where the send is when the invalidate comes |
|---|---|
| `mempool` | unconfirmed: `depth` blocks are mined first |
| `top` | in the tip block |
| `deep` | in the lowest block the invalidate takes off |
| `split` | (child only) the parent in the lowest block taken off, the child unconfirmed |

For each row:
1. Both pairs mine until every mempool is empty, so the two chains keep one height.
2. The send is made and placed.
3. `invalidateblock` on node 1 at the block `depth` below the tip, then `reconsiderblock`; the pairs settle.

Both nodes' mempools are sampled, by the label of each transaction:
- before;
- right after `invalidateblock`;
- right after `reconsiderblock`;
- once both nodes are on one tip with equal or still mempools;
- with `RESEND_WAIT`, once more after that wait.

Also compared:
- the outcome of each call;
- each input's class: `mature`, or the confirmations of a coinbase or coinstake output a 1 to 3 deep invalidate can
  make immature.

A row whose samples agree is `PASS`. Otherwise it is `DIFFERS` with every sample, and with the divid and irondivid log
lines on the row's transactions (divid's `debug=mempool` names an AcceptToMemoryPool refusal). The exit code is the
number of `DIFFERS` rows; a row that cannot be built ends the run with `FAIL`.

## What Divi Core does (core-src 9e2f76c)

- **invalidateblock** (rpcblockchain.cpp:612-647) marks the block failed and disconnects the tip until the block is
  off the chain (InvalidateBlock, BlockInvalidationHelpers.cpp). It then runs ActivateBestChain (`updateActiveChain`,
  ChainExtensionService.cpp:643-654), which could move onto a side branch with more work than the new tip.
  **reconsiderblock** (rpcblockchain.cpp:649-684, ChainExtensionService.cpp:662-689) clears the failure flags and runs
  ActivateBestChain, which connects the blocks again.
- **disconnectTip**, per block (ChainTipManager.cpp:155-191):
  1. Each transaction of the block goes to AcceptToMemoryPool with `fLimitFree` false, before UpdateTip. So the
     chain's height is still the disconnected block's, while the coins view is at its parent. The block's
     transactions go in block order, parents before children. A coinbase or coinstake, or one that is refused, is
     removed with its mempool descendants (`remove(tx, removed, true)`, txmempool.cpp:91-137).
  2. `removeCoinbaseSpends` at the disconnected block's height (txmempool.cpp:139-162). It drops each mempool
     transaction with an input that is neither in the mempool nor in the coins view, or that is a coinbase or
     coinstake output with fewer than 20 confirmations at the next block (COINBASE_MATURITY 20, chainparams.cpp:479).
- **AcceptToMemoryPool**'s checks that can refuse a disconnected transaction (MempoolConsensus.cpp:268-422):
  - IsStandardTx: version, size and scripts, and **IsFinalTx at `chain.Height() + 1`** (MempoolConsensus.cpp:61).
    During disconnectTip that is the disconnected block's height + 1, so a height lock the block met always passes.
    A time lock is checked against the clock (TransactionFinalityHelpers.cpp:8-24).
  - Already in the pool, or its outputs already in the coins view (MempoolConsensus.cpp:297-300, :329-334).
  - An input spent by another mempool transaction, or missing (:335-353).
  - Too many sigops.
  - Fees: with `fLimitFree` false, only "insufficient priority" when the fee is below the relay fee and the priority
    is at or below AllowFree's threshold (COIN × 1440 / 250, MemPoolEntry.h:18-39; CheckFeesPaidAreAcceptable,
    MempoolConsensus.cpp:236-266). The free-relay rate limiter (`-limitfreerelay`) applies only with `fLimitFree`.
  - CheckInputs' maturity at the coins view's best block + 1 (UtxoCheckingAndUpdating.cpp:64-78), that is the
    disconnected block's height.
- **connectTip** (ChainTipManager.cpp:105-151): `removeConfirmedTransactions` takes out the block's transactions and
  the mempool transactions in conflict with them (txmempool.cpp:183-199). Nothing in connectTip or disconnectTip
  checks a mempool transaction's lock time again.
- **The wallet** is told of each disconnected block (SyncTransactions BLOCK_DISCONNECT, ChainTipManager.cpp:189) and
  does not touch the mempool. Divi Core 3.0.0 has no ResendWalletTransactions. Its wallet sends are offered to the
  mempool again only at start (SubmitUnconfirmedWalletTransactionsToMempool, init.cpp:1262-1275), without relaying
  them.
- **The only resend** is the mempool rebroadcast (PeriodicallyRebroadcastMempoolTxs, main.cpp:1280-1294), called from
  SendMessages (main.cpp:1313). At a random time within 30 minutes of the previous check, if the tip moved since the
  last rebroadcast, up to 32 mempool transactions that spend no other mempool transaction are announced to every peer
  (main.cpp:1245-1278). A transaction one node dropped and its peer kept reaches the first node again only through
  this, so a difference that lasts until then is timing.

**Timer- or order-dependent:**
- The rebroadcast's random time.
- The coins each side's wallet and staker pick, which depend on txids and block hashes. Among equal coins, divid's
  coin selection takes the first in txid order (MinimumFeeCoinSelectionAlgorithm.cpp:127-139).
- Whether a send spends a coin that a 1 to 3 deep invalidate makes immature depends on that pick. That is why a
  replay of a random-sequences episode does not repeat a maturity difference. This script picks every coin by its age
  instead.

## Cases from random-sequences

`cases/seed18-base.json` and `cases/seed18-fix.json` are the steps of the random-sequences episodes that ended in a
mempool difference in the middle of an invalidate (seed 18, on a8525c0 and on its fix). They run as replays:

```sh
REPLAY=scripts/invalidate-mempool/cases/seed18-fix.json RANDOM_SEQUENCES_DEBUG=1 RANDOM_SEQUENCES_LOGS=/var/tmp/logs \
  scripts/random-sequences/run.sh target/release ~/divi-3.0.0/bin 53850 /var/tmp
```

## Known differences

`KNOWN` in `check.py` (a kind and placement with a reason) is for an accidental divid behaviour; it is empty.
