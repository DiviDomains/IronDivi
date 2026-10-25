# Blocks broken one rule at a time, next to Divi Core

`run.sh` builds a regtest chain on three nodes, two Divi Core 3.0.0 `divid` (A and B) and one irondivid (I), and
offers B and I, from a raw peer, blocks that break one consensus rule each. For each block it compares the two
on:

- **taken or refused**, and whether the node's **tip moved** (a tip that moved is put back with `invalidateblock`);
- **the `reject` message**, if any: command, code and reason (up to the first space, colon or bracket);
- **what it does to the peer**: whether it closed the connection (a score of 100, or a local peer dropped at the
  ban score), and whether it banned the address. Regtest peers from 127.0.0.1 are dropped, not banned
  (`net.cpp` "not banning local peer"), so `banned` is false on both; the score shows as the connection closed
  or not.

A valid block is then offered (taken), and after the rows a valid block from another peer must reach all three.

Each row prints one line: `PASS` (the same as divid), `KNOWN` (differs, listed below with the divid line) or `FAIL`.
The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25
minutes).

```sh
scripts/block-rules/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2: p2p and RPC of A, I and B.
- `[root]`: a fresh directory is made under it and deleted at the end, with every node stopped.

A run takes about 6 minutes. `BLOCK_RULES_TRACE=1` also prints each node's full reject text.

## How a block is broken

A is cut off (restarted with no peer), makes the block at the height alone, so it owns the coins the cases spend, and
each copy is built from that block, with the merkle root, the coinstake signature and the block signature made
again with A's keys where the case leaves them valid. All cases are built on one tip. Where the block has
a transaction to carry, A sent one before it staked.

| group | cases (block 112) |
|---|---|
| structure | bad merkle root; a repeated transaction with the merkle root unchanged; no coinbase; two coinbases; the coinstake not second; a second coinstake; a coinbase that pays in a proof-of-stake block; a coinbase that does not begin with the height; a coinbase script of 101 bytes; a proof-of-work block after height 100 (with two transactions, see below) |
| signatures | block signed by another key; no block signature; a coinstake signature damaged |
| time and bits | a time 1000 s and 600 s ahead; at the median time past; before it; bits changed; bits for a lower target |
| stake input | already spent; made by the block before; in no block yet |
| transactions | an input spent twice within the block; an input that does not exist; more out than in; an immature coinbase; an immature coinstake output; not final; no inputs; no outputs; over 100,000 bytes; a negative output; an output over the money limit; an empty output |
| size | over 2,000,000 bytes; 21,000 signature operations |
| amount | the coinstake paying one satoshi too much |
| treasury block 150 | the treasury paid one satoshi less and more, paid to another address, left out; the charity left out |
| lottery block (first from 170 with winners) | the first winner paid one satoshi less, paid to another address; the last winner left out |
| side chain | 15 of the above built on the tip block's parent, so the node holds them as a side chain |
| side chain with a bad proof | a sibling of the tip block whose coinstake signature is damaged, then two blocks built on it so that this side chain would be the longer; per block: the reject, the connection, the tip, whether the node asks the sender for blocks (a new peer is first given 2 s to be sent what a node sends it unasked); then whether each block is held (`getblock`), what `getchaintips` gained, and whether another peer was told of any of them |

A masternode payee rule is not active: DeprecateMasternodes holds from 2023-08-23 on every network
(`BlockConnectionService.cpp:321-326`).

## Divi Core stops on a one-transaction proof-of-work block after height 100

A block at height 112 that is proof of work (no coinstake) and has the coinbase alone makes divid 3.0.0 exit
(the connection is refused afterwards), where the same block with a second transaction is refused with a score of 100
(`PoW-ended`, `BlockConnectionService.cpp:53-55`); the likely cause is `block.vtx[1]` in
`CheckMintTotalsAndBlockPayees` (`BlockConnectionService.cpp:77`), which reads past the end. irondivid refuses both. The
script offers the two-transaction form so the comparison can go on.

## Kernel luck

On regtest the stake target is easy, so changing a block's time, which the kernel hashes, leaves the proof valid about
half the time. A time case therefore draws divid's `reject` when the proof still holds and none when it does not;
irondivid does the same, since it checks the proof first, as divid does.

## KNOWN: a side-chain block that stakes a coin only its own branch made

divid refuses a block of a side chain whose coinstake stakes a coin that no connected block made: its proof is read
from the transaction index, which holds only the blocks it has connected (`TransactionDiskAccessor.cpp:56-72`,
`BlockProofVerifier.cpp:56-57`), and the block is not stored. irondivid keeps it until the branch is connected, so that
a fork that restakes its own coins can be followed (`crates/divi-network` `test_deep_side_chain_reorg_across_inv_batches`).
The row `unknown-coin side chain: the sibling is held` shows it as KNOWN.
