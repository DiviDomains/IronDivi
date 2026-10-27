# Transaction finality and script flags in blocks, next to Divi Core

`run.sh` builds a regtest chain on three nodes, two Divi Core 3.0.0 `divid` (A and B) and one irondivid (I), and
compares B with I on where a transaction's lock time and sequences, and the script flags, decide whether a block is
taken. A mines most proof-of-work blocks and irondivid five, then they stake.

| group | rows |
|---|---|
| 1. coinbase and coinstake | the lock time, sequences and version each node writes, for a proof-of-work coinbase and a proof-of-stake coinbase and coinstake |
| 2. mempool and staker | `createrawtransaction` with a lock time parameter (divid takes two parameters only); transactions made with `createrawtransaction` and `signrawtransaction` (the lock and sequences set in the bytes) at each boundary, sent to B and to I, which then each make a block: what the mempool said and whether the block holds it (height lock at the next block's height and one below, final sequences, one input final of two, time locks ahead and past, 500,000,000 and 499,999,999); a height lock refused now, taken one block later and mined |
| 3. blocks on the tip | A, cut off, stakes the block; copies holding one transaction each are offered to B and I by a raw peer: height locks at the block's height, one below and one above, final sequences, 499,999,999; time locks at the block's time, one below and one above, 500,000,000, at the parent's median time past; a coinbase and a coinstake with a lock; script cases: high S, hash type 0x05, a signature that is not strict DER, a multisig dummy that is not null, a pay-to-key with a hybrid key, CHECKLOCKTIMEVERIFY by height and by time (at the script's lock, one below, the input final, a lock of the other kind, not final) |
| 4. mempool | the script cases of group 3 (other coins) sent to B and I while A is away, so nothing is relayed between them |
| 5. side chain | a sibling of the tip block holding a transaction that is not final: offered, offered again, a block on it, then a final sibling; per offer the reject, the connection, whether the node asks the sender for blocks; then what it holds (`getblock`) and its chain tips |

Each row prints `PASS` (the same as divid), `KNOWN` (a difference listed below) or `FAIL`. The run ends with
`FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25 minutes).

```sh
scripts/tx-finality/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2: p2p and RPC of A, I and B.
- `[root]`: a fresh directory is made under it and deleted at the end, with every node stopped.

A run takes about 3 minutes. `TX_FINALITY_TRACE=1` also prints each node's full reject text. The block and raw peer
helpers are those of `scripts/block-rules`.

## What Divi Core does

- `IsFinalTx` (TransactionFinalityHelpers.cpp:8-25): lock 0 is final; a lock below 500,000,000 is a height and is
  final when below the height given, otherwise a time, final when below the time given; else final only when every
  input has the sequence 0xffffffff.
- A block: the block's height and the block's own time (not the median time past), for every transaction, coinbase
  and coinstake included (ContextualCheckBlock, ChainExtensionService.cpp:357-385). AcceptBlock runs it on every
  block as it arrives, a block of a side chain too (:493), and a block it refuses stays in the block index marked
  failed: sent again it is ignored, a block on it is refused as `bad-prevblk` with a score of 100 (:405-426).
- The mempool: the next block's height and the current time (MempoolConsensus.cpp:61).
- The staker: the block's height and the time when it collects the transactions
  (BlockMemoryPoolTransactionCollector.cpp:201), before it searches the kernel, whose time can then be up to the hash
  drift below that (ProofOfStakeGenerator.cpp:45-65). irondivid compares with the time of the block it makes, so it
  never puts in a transaction that its own block would make non-final; it cannot be shown here, as the mempool takes
  a time lock only once it is below the current time.
- Script flags for a block: P2SH, DERSIG and REQUIRE_COINSTAKE, with CHECKLOCKTIMEVERIFY and LIMIT_TRANSFER once the
  block's median time past reaches 2023-08-23 (BlockTransactionChecker.cpp:116-121), on regtest from the start. The
  coinstake's kernel adds STRICTENC, MINIMALDATA and NULLDUMMY (script/standard.h:31-36). The mempool also adds
  LIMIT_TRANSFER, DISCOURAGE_UPGRADABLE_NOPS, STRICTENC, MINIMALDATA and NULLDUMMY (no LOW_S): of the script cases a
  block takes, the mempool takes high S too and refuses the hash type, the dummy and the hybrid key.
